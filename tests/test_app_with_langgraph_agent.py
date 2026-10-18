"""The TUI driven by the real LangGraph-backed core, not a replay log.

This proves the wiring — CISMApp(LangGraphAgent()) renders a real run —
not the agent's internals, which tests/test_langgraph_agent.py already
covers in isolation.
"""

from __future__ import annotations

from cism.agent import LangGraphAgent
from cism.tui.app import CISMApp
from cism.tui.widgets.transcript import NarrationEntry, ToolEntry

from conftest import drain, settle


async def test_a_submitted_turn_runs_through_the_real_agent_and_renders(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="10.0.0.5")
    app = CISMApp(agent)

    async with app.run_test(size=(120, 34)) as pilot:
        await settle(pilot)

        await pilot.press(*"scan 10.0.0.5")
        await pilot.press("enter")
        await drain(pilot, agent)

        # 2026-10-18: phase no longer auto-advances (operator approval via
        # /phase required), and MAX_AI_TURNS dropped 4 -> 2 the same day --
        # dummy_msfconsole (ENUMERATION-only) is proposed on AI turn 2 but
        # the turn cap stops the run before act() ever runs it, so only
        # dummy_nmap's call actually executes.
        tool_entries = app.transcript.query(ToolEntry)
        assert len(tool_entries) == 1

        narrations = app.transcript.query(NarrationEntry)
        assert narrations
        assert "enumeration" in narrations.last().text

        assert app.phase == "recon"
