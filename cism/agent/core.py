"""``LangGraphAgent``: the LangGraph-backed core, satisfying
``cism.tui.events.Agent`` exactly as ``FakeAgent`` does.

This is the first real implementer of the seam the TUI already depends on
— the translation layer between LangGraph's own step loop and the frozen
``AgentEvent`` dataclasses the TUI consumes. Two independent loops meet at
exactly one point, ``self.events``: this class's internal run loop pushes,
whatever drains the queue (a TUI pump worker, or a test) only ever pulls.
Nothing here mutates a widget or knows one exists.

Wiring this into ``demo_replay.py`` or the live app is a separate, later
step — this module is tested standalone.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_core.messages.tool import ToolCall

from cism.agent.graph import build_graph
from cism.agent.guardrails import GuardrailSeam
from cism.agent.llm import DummyChatModel, build_chat_model
from cism.agent.logging import get_agent_logger
from cism.agent.state import Phase, PhaseStateMachine
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap
from cism.depg import ExtractorRegistry, GenericExtractor
from cism.tui.events import (
    AgentEvent,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Interrupted,
    ModelInfo,
    Narration,
    NarrationRedacted,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SessionState,
    ToolFailed,
    ToolFinished,
    ToolStarted,
)

__all__ = ["LangGraphAgent"]


def _bind_tools_if_supported(llm: BaseChatModel, tools: ToolRegistry) -> BaseChatModel:
    """The think node needs a model bound to the registry's tool schemas to
    get real tool selection out of it, but ``DummyChatModel`` was never
    built to support that — it hand-constructs ``tool_calls`` and inherits
    ``BaseChatModel.bind_tools``'s default, which raises ``NotImplementedError``.
    Rather than special-case that one class by name (or touch it to add a
    no-op override, which isn't this module's file to change), any model
    that can't be bound is used unbound — so the dummy default keeps working
    exactly as before, and any future non-tool-calling model degrades the
    same way instead of crashing agent construction."""
    try:
        return llm.bind_tools(tools.all())
    except NotImplementedError:
        return llm


def _llm_from_env() -> tuple[BaseChatModel, str, str, str]:
    """Real connector if the environment describes one, Dummy otherwise.
    Never raises: an unconfigured environment is a valid, common case
    (every test in this repo runs in one), not an error."""
    base_url = os.environ.get("CISM_LLM_BASE_URL", "")
    model = os.environ.get("CISM_LLM_MODEL", "")
    key_env_var = os.environ.get("CISM_LLM_KEY_ENV_VAR", "CISM_API_KEY")
    if base_url and model:
        return build_chat_model(base_url, key_env_var, model), base_url, model, key_env_var
    return DummyChatModel(), "local (dummy)", "", ""


class LangGraphAgent:
    """Satisfies ``cism.tui.events.Agent``. All dependencies default to the
    dummy/no-op stubs so the loop can be validated with no lab, no weights,
    and no network; pass real ones in once they exist."""

    def __init__(
        self,
        llm: BaseChatModel | None = None,
        tools: ToolRegistry | None = None,
        guardrails: GuardrailSeam | None = None,
        extractors: ExtractorRegistry | None = None,
        target: str = "",
        endpoint: str = "",
        model_name: str = "",
        key_env_var: str = "",
    ) -> None:
        self.events: asyncio.Queue[AgentEvent] = asyncio.Queue()
        if llm is None:
            self._llm, self._endpoint, self._model_name, self._key_env_var = _llm_from_env()
        else:
            self._llm = llm
            self._endpoint = endpoint
            self._model_name = model_name
            self._key_env_var = key_env_var
        self._tools = tools or ToolRegistry([dummy_nmap, dummy_msfconsole])
        self._guardrails = guardrails or GuardrailSeam.no_op()
        self._extractors = extractors or ExtractorRegistry({}, GenericExtractor())
        bound_llm = _bind_tools_if_supported(self._llm, self._tools)
        self._graph = build_graph(bound_llm, self._tools, self._guardrails, self._extractors)
        self._phase = PhaseStateMachine(Phase.RECON)
        self._target = target
        self._task: asyncio.Task[None] | None = None
        self._log = get_agent_logger()
        #: The last DEPGUpdated payload emitted, so depg_update running on
        #: every loop iteration doesn't flood the TUI with identical events
        #: on iterations where nothing about the graph actually changed.
        self._last_depg: tuple[tuple[DEPGNode, ...], tuple[DEPGEdge, ...]] = ((), ())

    async def start(self) -> None:
        """Announce the session before any run, so the status bar reflects
        what's actually running (dummy or real) even if nothing is
        submitted yet."""
        await self.events.put(self._session())

    def _session(self) -> SessionState:
        return SessionState(
            model=self._model_name or "dummy",
            models_available=(
                (ModelInfo(self._model_name, loaded=True),) if self._model_name else ()
            ),
            endpoint=self._endpoint,
            key_env_var=self._key_env_var,
            key_present=bool(os.environ.get(self._key_env_var)) if self._key_env_var else False,
        )

    async def submit(self, text: str) -> None:
        """Schedules the run as its own task and returns immediately, per
        the Agent protocol's "must not block" contract. A new submission
        cancels one already in flight — same discipline the TUI's own
        worker groups apply on its side. ``/api``/``/model`` are answered
        directly instead of being scheduled as a graph run."""
        if text.startswith("/"):
            name, _, argument = text[1:].partition(" ")
            if name in ("api", "model"):
                await self._configure(name, argument.strip())
                return
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = asyncio.create_task(self._run(text))

    async def _configure(self, name: str, argument: str) -> None:
        if argument and not self._key_env_var:
            await self.events.put(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=(
                        "No live endpoint is configured for this run (still on "
                        "the dummy backend) — nothing to re-point. Set "
                        "CISM_LLM_BASE_URL/CISM_LLM_MODEL or restart with "
                        "--base-url/--model."
                    ),
                    done=True,
                )
            )
            return

        if argument:
            endpoint = argument if name == "api" else self._endpoint
            model_name = argument if name == "model" else self._model_name
            try:
                llm = build_chat_model(endpoint, self._key_env_var, model_name)
            except ValueError as exc:
                await self.events.put(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=str(exc), done=True
                    )
                )
                return
            self._llm = llm
            self._endpoint = endpoint
            self._model_name = model_name
            bound_llm = _bind_tools_if_supported(self._llm, self._tools)
            self._graph = build_graph(
                bound_llm, self._tools, self._guardrails, self._extractors
            )

        await self.events.put(self._session())

    async def interrupt(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            await self.events.put(Interrupted(reason="user interrupt"))

    async def aclose(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()

    async def _run(self, text: str) -> None:
        run_id = uuid.uuid4().hex
        self._log.info("run %s started", run_id)
        await self.events.put(
            RunStarted(run_id=run_id, phase=self._phase.current.to_wire())
        )

        guarded = self._guardrails.input.run(text)
        if not guarded.allowed:
            await self.events.put(
                Narration(
                    entry_id=f"{run_id}-input-blocked",
                    text=f"Input rejected: {guarded.reason or 'blocked by input guardrail'}",
                    done=True,
                )
            )
            await self.events.put(RunFinished(run_id=run_id, ok=False))
            return

        initial_state: dict[str, Any] = {
            "messages": [HumanMessage(content=guarded.value)],
            "phase": self._phase.current,
            "depg_nodes": {},
            "depg_edges": [],
            "run_id": run_id,
            "target": self._target,
        }

        pending_calls: dict[str, ToolCall] = {}
        streamed: dict[str, str] = {"text": ""}
        ok = True
        try:
            async for stream_mode, payload in self._graph.astream(
                initial_state, stream_mode=["updates", "messages"]
            ):
                if stream_mode == "messages":
                    chunk, metadata = payload
                    # "messages" mode carries two shapes: token-level chat
                    # model deltas from "think" (what we want to narrate
                    # progressively), and the complete final message every
                    # node returns (including "respond"'s already-guarded
                    # answer) — LangGraph emits both over this channel. Only
                    # the "think" node is a real streaming source here, so
                    # anything else is a duplicate of state we already
                    # translate via the "updates" branch below and must be
                    # skipped, or "respond"'s text would double up in
                    # ``streamed["text"]`` and desync the guardrail-mismatch
                    # comparison below.
                    if metadata.get("langgraph_node") != "think":
                        continue
                    content = getattr(chunk, "content", "")
                    if content:
                        streamed["text"] += content
                        await self.events.put(
                            Narration(entry_id=f"{run_id}-final", text=content, done=False)
                        )
                    continue
                for node, update in payload.items():
                    if not update:
                        continue
                    await self._translate(node, update, run_id, pending_calls, streamed)
        except Exception as exc:  # a graph-loop failure is content, not a crash
            ok = False
            await self.events.put(
                Narration(entry_id=f"{run_id}-error", text=f"run failed: {exc}", done=True)
            )

        await self.events.put(RunFinished(run_id=run_id, ok=ok))

    async def _translate(
        self,
        node: str,
        update: dict[str, Any],
        run_id: str,
        pending_calls: dict[str, ToolCall],
        streamed: dict[str, str],
    ) -> None:
        if node == "think":
            for message in update.get("messages", []):
                for call in getattr(message, "tool_calls", None) or []:
                    pending_calls[call["id"]] = call

        elif node == "act":
            for message in update.get("messages", []):
                call_id = message.tool_call_id
                call = pending_calls.pop(call_id, None)
                tool_name = message.name or (call["name"] if call else "unknown")
                args = str(call["args"]) if call else ""
                await self.events.put(ToolStarted(call_id=call_id, tool=tool_name, args=args))
                if getattr(message, "status", "success") == "error":
                    await self.events.put(
                        ToolFailed(call_id=call_id, reason=str(message.content))
                    )
                else:
                    await self.events.put(
                        ToolFinished(call_id=call_id, summary=str(message.content))
                    )

        elif node == "phase_router":
            new_phase = update.get("phase")
            if new_phase is not None and new_phase != self._phase.current:
                self._phase.transition(new_phase)
                await self.events.put(PhaseChanged(phase=new_phase.to_wire()))

        elif node == "depg_update":
            nodes = update.get("depg_nodes") or {}
            edges = update.get("depg_edges") or []
            payload = (
                tuple(n.to_event() for n in nodes.values()),
                tuple(e.to_event() for e in edges),
            )
            if payload != self._last_depg:
                self._last_depg = payload
                await self.events.put(DEPGUpdated(nodes=payload[0], edges=payload[1]))

        elif node == "respond":
            for message in update.get("messages", []):
                entry_id = f"{run_id}-final"
                final_text = str(message.content)
                if final_text != streamed["text"]:
                    await self.events.put(
                        NarrationRedacted(entry_id=entry_id, reason=final_text)
                    )
                else:
                    await self.events.put(Narration(entry_id=entry_id, text="", done=True))
                streamed["text"] = ""
