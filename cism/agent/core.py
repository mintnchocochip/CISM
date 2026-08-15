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
import uuid
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_core.messages.tool import ToolCall

from cism.agent.graph import build_graph
from cism.agent.guardrails import GuardrailSeam
from cism.agent.llm import DummyChatModel
from cism.agent.logging import get_agent_logger
from cism.agent.state import Phase, PhaseStateMachine
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap
from cism.tui.events import (
    AgentEvent,
    Interrupted,
    Narration,
    PhaseChanged,
    RunFinished,
    RunStarted,
    ToolFailed,
    ToolFinished,
    ToolStarted,
)

__all__ = ["LangGraphAgent"]


class LangGraphAgent:
    """Satisfies ``cism.tui.events.Agent``. All dependencies default to the
    dummy/no-op stubs so the loop can be validated with no lab, no weights,
    and no network; pass real ones in once they exist."""

    def __init__(
        self,
        llm: BaseChatModel | None = None,
        tools: ToolRegistry | None = None,
        guardrails: GuardrailSeam | None = None,
        target: str = "",
    ) -> None:
        self.events: asyncio.Queue[AgentEvent] = asyncio.Queue()
        self._llm = llm or DummyChatModel()
        self._tools = tools or ToolRegistry([dummy_nmap, dummy_msfconsole])
        self._guardrails = guardrails or GuardrailSeam.no_op()
        self._graph = build_graph(self._llm, self._tools, self._guardrails)
        self._phase = PhaseStateMachine(Phase.RECON)
        self._target = target
        self._task: asyncio.Task[None] | None = None
        self._log = get_agent_logger()

    async def start(self) -> None:
        """Nothing to warm up for a dummy backend. A real model/tool
        backend would open its connections here."""

    async def submit(self, text: str) -> None:
        """Schedules the run as its own task and returns immediately, per
        the Agent protocol's "must not block" contract. A new submission
        cancels one already in flight — same discipline the TUI's own
        worker groups apply on its side."""
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = asyncio.create_task(self._run(text))

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
        ok = True
        try:
            async for step in self._graph.astream(initial_state, stream_mode="updates"):
                for node, update in step.items():
                    if not update:
                        continue
                    await self._translate(node, update, run_id, pending_calls)
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

        elif node == "respond":
            for message in update.get("messages", []):
                await self.events.put(
                    Narration(entry_id=f"{run_id}-final", text=str(message.content), done=True)
                )
