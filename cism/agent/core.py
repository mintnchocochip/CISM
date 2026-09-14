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
import dataclasses
import os
import time
import uuid
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_core.messages.tool import ToolCall
from langgraph.checkpoint.memory import MemorySaver

from cism.agent.graph import build_graph
from cism.agent.guardrails import GuardrailChain, GuardrailSeam
from cism.agent.llm import DummyChatModel, build_chat_model, discover_context_window
from cism.agent.logging import get_agent_logger, read_run_events
from cism.agent.profiles import PhaseProfiles, default_profiles
from cism.agent.state import IllegalPhaseTransition, Phase, PhaseStateMachine
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap
from cism.depg import EXTRACTORS, ExtractorRegistry, GenericExtractor, LLMExtractor
from cism.memory import DEFAULT_SALIENCE_TERMS
from cism.tui.events import (
    AgentEvent,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Interrupted,
    MemoryUpdated,
    ModelInfo,
    Narration,
    NarrationRedacted,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SessionState,
    TokenDelta,
    ToolFailed,
    ToolFinished,
    ToolStarted,
    decode,
    encode,
)
from cism.tui.events import _next_seq  # same-package access to the shared seq counter

__all__ = ["LangGraphAgent"]

#: Pacing between events during /replay — fast enough to feel immediate,
#: slow enough to read as a sequence rather than a flash. Deliberately not
#: the original run's real elapsed gaps: those can be tens of seconds
#: (a real tool timeout) and replay is for reviewing what happened, not
#: for reliving how long it took.
_REPLAY_STEP_DELAY = 0.05


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
        profiles: PhaseProfiles | None = None,
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
        default_extractor = (
            GenericExtractor() if self._endpoint == "local (dummy)" else LLMExtractor(self._llm)
        )
        self._extractors = extractors or ExtractorRegistry(EXTRACTORS, default_extractor)
        self._profiles = profiles or default_profiles(self._tools)
        #: In-process only — this is session memory (lives as long as this
        #: LangGraphAgent instance does), not restart-survival, which is a
        #: separate, explicitly deferred concern (see the design docs). A
        #: fixed thread_id keys every _run() into the same checkpointed
        #: thread, so a graph rebuilt mid-session (the /ablate path in
        #: _run()) must reuse both this checkpointer and this thread_id or
        #: ablating a tool for one run would also silently wipe memory.
        self._checkpointer = MemorySaver()
        self._thread_id = uuid.uuid4().hex
        #: True once the checkpointed thread has been seeded once — see
        #: _run()'s initial_state construction: depg_nodes/depg_edges/
        #: memory_items are only ever given an empty starting value the
        #: first time, since after that the checkpointer already holds
        #: whatever the previous run left there and re-supplying `{}`
        #: would overwrite it back to empty on every single run.
        self._thread_seeded = False
        self._graph = build_graph(
            self._llm,
            self._tools,
            self._guardrails,
            self._extractors,
            self._profiles,
            checkpointer=self._checkpointer,
        )
        self._phase = PhaseStateMachine(Phase.RECON)
        self._target = target
        self._task: asyncio.Task[None] | None = None
        self._log = get_agent_logger()
        #: The last DEPGUpdated payload emitted, so depg_update running on
        #: every loop iteration doesn't flood the TUI with identical events
        #: on iterations where nothing about the graph actually changed.
        self._last_depg: tuple[tuple[DEPGNode, ...], tuple[DEPGEdge, ...]] = ((), ())
        #: Running session total for TokenDelta.total — never reset, unlike
        #: ctx_used (a point-in-time snapshot of the most recent call).
        self._token_total = 0
        #: Best-effort, refreshed by _refresh_context_window(); the status
        #: bar's own fallback (StatusBar.ctx_max's default) until then.
        self._context_window = 32_768
        #: Tool and/or guardrail-stage names to leave out of *the next*
        #: _run() only — see _ablate()/_run(). A plain set of names, not
        #: split by kind: a name is unambiguous (tool names and guardrail
        #: stage names don't collide in practice) and the next run just
        #: filters both the registry and every guardrail chain against it.
        self._ablated: set[str] = set()

    async def _refresh_context_window(self) -> None:
        """Best-effort — see discover_context_window's own docstring for
        why this can't be more than that. A stale value from a previous
        model is harmless (just a wrong ctx_max) so no lock is needed
        against a concurrent /model or /api switch."""
        if self._endpoint == "local (dummy)" or not self._model_name:
            return
        discovered = await discover_context_window(self._endpoint, self._model_name)
        if discovered:
            self._context_window = discovered

    async def _emit(self, event: AgentEvent) -> None:
        """The one place any ``AgentEvent`` reaches the outside world:
        written to the on-disk audit log (cism/agent/logging.py, TTL'd so
        it can't grow forever) and put on the TUI's queue, in that order.
        Every event this module produces is routed through here instead of
        calling the queue directly, so the audit log is always exactly what
        the TUI saw — never a hand-picked subset that can drift out of
        sync.

        Logged via ``events.encode`` (the same round-trip format
        ``cism/tui/replay.py`` already reads), not a plain
        ``dataclasses.asdict`` — that's what lets ``/replay`` (``_replay``
        below) turn a slice of this same log straight back into real
        events via ``events.decode``, instead of needing a second,
        parallel serialisation to stay in sync with this one."""
        self._log.info(type(event).__name__, extra={"data": encode(event)})
        await self.events.put(event)

    async def start(self) -> None:
        """Announce the session before any run, so the status bar reflects
        what's actually running (dummy or real) even if nothing is
        submitted yet. Context-window discovery runs first so that initial
        SessionState already carries a real ModelInfo.context where one is
        available, rather than reporting 0 and correcting itself later."""
        await self._refresh_context_window()
        await self._emit(self._session())

    def _session(self) -> SessionState:
        return SessionState(
            model=self._model_name or "dummy",
            models_available=(
                (ModelInfo(self._model_name, context=self._context_window, loaded=True),)
                if self._model_name
                else ()
            ),
            endpoint=self._endpoint,
            key_env_var=self._key_env_var,
            key_present=bool(os.environ.get(self._key_env_var)) if self._key_env_var else False,
        )

    async def submit(self, text: str) -> None:
        """Schedules the run as its own task and returns immediately, per
        the Agent protocol's "must not block" contract. A new submission
        cancels one already in flight — same discipline the TUI's own
        worker groups apply on its side. ``/api``/``/model``/``/target``/
        ``/phase``/``/ablate`` are answered directly instead of being
        scheduled as a graph run. ``/replay`` *is* scheduled the same way a
        real run is — it plays back over time and a later submit() should
        be able to cut it off the same way."""
        if text.startswith("/"):
            name, _, argument = text[1:].partition(" ")
            if name in ("api", "model"):
                await self._configure(name, argument.strip())
                return
            if name == "target":
                await self._set_target(argument.strip())
                return
            if name == "phase":
                await self._set_phase(argument.strip())
                return
            if name == "ablate":
                await self._ablate(argument.strip())
                return
            if name == "replay":
                if self._task is not None and not self._task.done():
                    self._task.cancel()
                self._task = asyncio.create_task(self._replay(argument.strip()))
                return
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = asyncio.create_task(self._run(text))

    async def _set_target(self, argument: str) -> None:
        """Bare ``/target`` reports the current value; ``/target <value>``
        replaces it. Takes effect on the *next* submit(), same timing note
        as ``_configure`` — an in-progress run already has its own copy in
        ``initial_state``."""
        if argument:
            self._target = argument
        await self._emit(
            Narration(
                entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                text=f"target  {self._target or '(none)'}",
                done=True,
            )
        )

    async def _set_phase(self, argument: str) -> None:
        """Bare ``/phase`` reports the current phase. ``/phase <name>``
        goes through ``PhaseStateMachine.transition`` — the same choke
        point ``phase_router`` uses — so a manual move is bound by the same
        legality rules as an automated one; state.py's own docstring calls
        that the deliberate single choke point for every phase change."""
        if not argument:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=f"phase  {self._phase.current.to_wire()}",
                    done=True,
                )
            )
            return
        try:
            requested = Phase[argument.upper().replace("-", "_")]
        except KeyError:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=f"unknown phase {argument!r}",
                    done=True,
                )
            )
            return
        try:
            self._phase.transition(requested)
        except IllegalPhaseTransition as exc:
            await self._emit(
                Narration(entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=str(exc), done=True)
            )
            return
        await self._emit(PhaseChanged(phase=requested.to_wire()))

    async def _ablate(self, argument: str) -> None:
        """Bare ``/ablate`` reports what is currently pending. ``/ablate
        <name>`` toggles ``<name>`` — a registered tool name or a stage
        ``.name`` from any of the three guardrail chains — in or out of
        the pending set, which ``_run`` consumes (and always clears) on
        the very next run. There is deliberately no separate "clear"
        command: toggling the same name again is that."""
        if not argument:
            listing = ", ".join(sorted(self._ablated)) or "(none)"
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=f"ablated  {listing}", done=True
                )
            )
            return

        known_tools = {t.name for t in self._tools.all()}
        known_stages = {
            stage.name
            for chain in (self._guardrails.input, self._guardrails.action, self._guardrails.output)
            for stage in chain.stages
        }
        if argument not in known_tools and argument not in known_stages:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=f"no such tool or guardrail stage: {argument!r}",
                    done=True,
                )
            )
            return

        if argument in self._ablated:
            self._ablated.discard(argument)
            verb = "restored"
        else:
            self._ablated.add(argument)
            verb = "ablated — takes effect on the next run only"
        await self._emit(
            Narration(entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=f"{argument}  {verb}", done=True)
        )

    async def _replay(self, run_id: str) -> None:
        """Plays a past run's exact recorded events (from the audit log,
        cism/agent/logging.py) back into this session's queue — not a
        re-execution, no tool or model call happens. seq is rebased to
        continue this session's own numbering (the recorded values are
        stale — from whenever that run actually happened); ts is left
        alone, since it's genuinely historical. Bracketed by narrations so
        it reads as clearly-not-live in the transcript, and closes by
        re-asserting the real current phase, in case the replayed run
        shows a different one — the status bar should not end up lying
        about what phase this session is actually in."""
        if not run_id:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text="usage: /replay <run_id>", done=True
                )
            )
            return

        records = read_run_events(run_id)
        if not records:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=f"no recorded run found for {run_id!r}",
                    done=True,
                )
            )
            return

        replay_id = f"replay-{run_id}"
        await self._emit(
            Narration(entry_id=f"{replay_id}-start", text=f"— replaying run {run_id} —", done=True)
        )
        for record in records:
            # dataclasses.replace with a fresh _next_seq() each time, not
            # rebase()'s offset+index: that only reserves *one* number from
            # the shared global counter, so anything _emit'd afterwards
            # (the end-of-replay markers below) would collide with the
            # numbers handed out here by plain arithmetic instead of by
            # actually advancing the counter.
            event = dataclasses.replace(decode(record["data"]), seq=_next_seq())
            await self.events.put(event)
            await asyncio.sleep(_REPLAY_STEP_DELAY)
        await self._emit(
            Narration(entry_id=f"{replay_id}-end", text="— end replay —", done=True)
        )
        await self._emit(PhaseChanged(phase=self._phase.current.to_wire()))

    async def _configure(self, name: str, argument: str) -> None:
        if argument and not self._key_env_var:
            await self._emit(
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
                await self._emit(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=str(exc), done=True
                    )
                )
                return
            self._llm = llm
            self._endpoint = endpoint
            self._model_name = model_name
            # This reassignment takes effect on the *next* submit(), not one
            # already in flight: an in-progress _run()'s astream() iteration
            # was already handed the old self._graph object and keeps
            # pulling from it regardless of what self._graph points to now.
            self._graph = build_graph(
                self._llm,
                self._tools,
                self._guardrails,
                self._extractors,
                self._profiles,
                checkpointer=self._checkpointer,
            )
            await self._refresh_context_window()

        await self._emit(self._session())

    async def interrupt(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            await self._emit(Interrupted(reason="user interrupt"))

    async def aclose(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()

    async def _run(self, text: str) -> None:
        run_id = uuid.uuid4().hex

        # Consumed and cleared right here, before anything can await and
        # let a concurrent /ablate change it mid-run — "the next run"
        # means exactly this one, decided once, at the start.
        ablated, self._ablated = self._ablated, set()
        graph = self._graph
        guardrails = self._guardrails
        if ablated:
            tools = ToolRegistry([t for t in self._tools.all() if t.name not in ablated])
            guardrails = GuardrailSeam(
                input=GuardrailChain(
                    [s for s in self._guardrails.input.stages if s.name not in ablated]
                ),
                action=GuardrailChain(
                    [s for s in self._guardrails.action.stages if s.name not in ablated]
                ),
                output=GuardrailChain(
                    [s for s in self._guardrails.output.stages if s.name not in ablated]
                ),
            )
            graph = build_graph(
                self._llm,
                tools,
                guardrails,
                self._extractors,
                self._profiles,
                checkpointer=self._checkpointer,
            )

        await self._emit(
            RunStarted(run_id=run_id, phase=self._phase.current.to_wire())
        )
        if ablated:
            await self._emit(
                Narration(
                    entry_id=f"{run_id}-ablate",
                    text=f"ablated for this run only: {', '.join(sorted(ablated))}",
                    done=True,
                )
            )

        guarded = guardrails.input.run(text)
        if not guarded.allowed:
            await self._emit(
                Narration(
                    entry_id=f"{run_id}-input-blocked",
                    text=f"Input rejected: {guarded.reason or 'blocked by input guardrail'}",
                    done=True,
                )
            )
            await self._emit(RunFinished(run_id=run_id, ok=False))
            return

        initial_state: dict[str, Any] = {
            "messages": [HumanMessage(content=guarded.value)],
            "phase": self._phase.current,
            "phase_changed": False,
            "run_id": run_id,
            "target": self._target,
        }
        if not self._thread_seeded:
            # Only the very first run of this session needs these seeded —
            # they have no reducer (unlike messages/add_messages), so
            # supplying them on every run would overwrite whatever the
            # checkpointer already carried forward from the previous run
            # right back to empty, silently undoing cross-run memory.
            initial_state["depg_nodes"] = {}
            initial_state["depg_edges"] = []
            initial_state["memory_items"] = {}
            self._thread_seeded = True
        run_config = {"configurable": {"thread_id": self._thread_id}}

        pending_calls: dict[str, ToolCall] = {}
        streamed: dict[str, str] = {"text": ""}
        ok = True
        try:
            async for stream_mode, payload in graph.astream(
                initial_state, run_config, stream_mode=["updates", "messages"]
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
                        await self._emit(
                            Narration(entry_id=f"{run_id}-final", text=content, done=False)
                        )
                    usage = getattr(chunk, "usage_metadata", None)
                    if usage:
                        # usage_metadata only arrives on a trailing,
                        # content-empty chunk (see build_chat_model's
                        # stream_usage docstring) — input_tokens already
                        # reflects the whole conversation resent this call,
                        # so it (plus this call's own output) is the real
                        # context-window occupancy, not something to sum
                        # across calls the way total/delta are.
                        turn_tokens = usage.get("input_tokens", 0) + usage.get(
                            "output_tokens", 0
                        )
                        self._token_total += turn_tokens
                        await self._emit(
                            TokenDelta(
                                delta=turn_tokens,
                                total=self._token_total,
                                ctx_used=turn_tokens,
                                ctx_max=self._context_window,
                            )
                        )
                    continue
                for node, update in payload.items():
                    if not update:
                        continue
                    await self._translate(node, update, run_id, pending_calls, streamed)
        except Exception as exc:  # a graph-loop failure is content, not a crash
            ok = False
            await self._emit(
                Narration(entry_id=f"{run_id}-error", text=f"run failed: {exc}", done=True)
            )

        await self._emit(RunFinished(run_id=run_id, ok=ok))

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
                had_calls = False
                for call in getattr(message, "tool_calls", None) or []:
                    pending_calls[call["id"]] = call
                    had_calls = True
                if had_calls:
                    # This turn routes to "act", not "respond" — any text it
                    # streamed alongside the tool call (real models sometimes
                    # emit a sentence of preamble next to a call) is not the
                    # run's final answer. Clear it now so it doesn't linger
                    # and get concatenated with a later think turn's text,
                    # which would desync the guardrail-mismatch comparison
                    # in the "respond" branch below and trigger a
                    # false-positive NarrationRedacted. Only the final
                    # answer turn (no tool_calls) leaves streamed["text"]
                    # intact for that comparison.
                    streamed["text"] = ""

        elif node == "act":
            for message in update.get("messages", []):
                call_id = message.tool_call_id
                call = pending_calls.pop(call_id, None)
                tool_name = message.name or (call["name"] if call else "unknown")
                args = str(call["args"]) if call else ""
                await self._emit(ToolStarted(call_id=call_id, tool=tool_name, args=args))
                if getattr(message, "status", "success") == "error":
                    detail = message.additional_kwargs.get("guardrail_detail") or str(message.content)
                    await self._emit(ToolFailed(call_id=call_id, reason=detail))
                else:
                    await self._emit(
                        ToolFinished(call_id=call_id, summary=str(message.content))
                    )

        elif node == "phase_router":
            new_phase = update.get("phase")
            if new_phase is not None and new_phase != self._phase.current:
                self._phase.transition(new_phase)
                await self._emit(PhaseChanged(phase=new_phase.to_wire()))

        elif node == "depg_update":
            nodes = update.get("depg_nodes") or {}
            edges = update.get("depg_edges") or []
            payload = (
                tuple(n.to_event() for n in nodes.values()),
                tuple(e.to_event() for e in edges),
            )
            if payload != self._last_depg:
                self._last_depg = payload
                await self._emit(DEPGUpdated(nodes=payload[0], edges=payload[1]))

        elif node == "memory_update":
            items = update.get("memory_items") or {}
            rows = tuple(item.to_event(time.time()) for item in items.values())
            await self._emit(MemoryUpdated(rows=rows, terms=DEFAULT_SALIENCE_TERMS))

        elif node == "respond":
            for message in update.get("messages", []):
                entry_id = f"{run_id}-final"
                final_text = str(message.content)
                if final_text != streamed["text"]:
                    await self._emit(
                        NarrationRedacted(entry_id=entry_id, reason=final_text)
                    )
                else:
                    await self._emit(Narration(entry_id=entry_id, text="", done=True))
                streamed["text"] = ""
