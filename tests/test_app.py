"""Keybinds, slash commands, modals, and the pump's handling of bad input."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest
from conftest import drain, replay_all, settle

from cism.tui.events import (
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    MemoryRow,
    MemoryUpdated,
    Narration,
    PhaseChanged,
    PhaseProposed,
    ScopeChanged,
    ToolFailed,
    ToolFinished,
    ToolStarted,
)
from cism.tui.app import CISMApp
from cism.tui.redact import MASK
from cism.tui.replay import FakeAgent
from cism.tui.widgets.banner import Banner
from cism.tui.widgets.depg_modal import DEPGModal, DEPGTree
from cism.tui.widgets.memory_modal import MemoryModal, MemoryTable
from cism.tui.widgets.phase_modal import PhaseApprovalModal
from cism.tui.widgets.slash import COMMANDS, SlashOverlay
from cism.tui.widgets.transcript import NarrationEntry, ToolEntry, UserTurn


@dataclass(frozen=True)
class NotAnEvent:
    """Something the TUI has never heard of."""

    payload: str = "?"


# -- the pump ---------------------------------------------------------------


async def test_unknown_events_are_dropped_not_raised(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(NotAnEvent())
        agent.events.put_nowait(Narration("e1", "still alive"))
        await settle(pilot)
        assert app.unknown_events == 1
        assert app.transcript.query_one(NarrationEntry).text == "still alive"


async def test_a_handler_that_raises_does_not_kill_the_pump(quiet_app) -> None:
    """E1 (AUDIT.md): _apply raising used to escape try/finally with no
    except, permanently freezing the UI after one bad event."""
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        real_apply = app._apply
        calls = []

        def _flaky_apply(event):
            calls.append(event)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return real_apply(event)

        app._apply = _flaky_apply
        agent.events.put_nowait(Narration("e1", "first — will raise"))
        agent.events.put_nowait(Narration("e2", "second — must still land"))
        await settle(pilot)

        assert app.unknown_events == 1
        assert app.transcript.query_one(NarrationEntry).text == "second — must still land"


async def test_output_for_an_unknown_call_id_is_ignored(quiet_app) -> None:
    from cism.tui.events import ToolFinished, ToolOutput

    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ToolOutput("ghost", "data"))
        agent.events.put_nowait(ToolFinished("ghost", "done"))
        agent.events.put_nowait(Narration("e1", "ok"))
        await settle(pilot)
        assert app.unknown_events == 0
        assert app.transcript.tool("ghost") is None


async def test_full_replay_builds_the_expected_transcript(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        assert app.phase == "exploitation"
        assert len(app.depg_nodes) == 11
        assert len(app.memory_rows) == 10
        assert app.memory_terms is not None
        tools = [e.tool for e in app.transcript.query(ToolEntry)]
        assert tools == ["nmap", "whatweb", "nuclei", "msfconsole", "curl"]


# -- keybinds ---------------------------------------------------------------


# NOTE: unlike its sibling below, this uses ``quiet_app`` (not the full demo
# replay) and pushes only tool events, with no narration after the tool call.
# ``action_toggle_output`` now toggles ``last_collapsible()``, and in the demo
# log's actual tail a narration entry (``n-wrap``) is created *after* the last
# tool call, so replaying the full log would make ctrl+o hit that narration
# entry instead of the curl tool entry, defeating this test's purpose. Here
# the tool call is deliberately kept as the most-recently-created collapsible
# entry, so this still verifies ctrl+o reaches ``last_tool()`` when it is also
# ``last_collapsible()`` -- see
# ``test_ctrl_o_toggles_the_last_narration_when_it_is_more_recent`` for the
# narration-is-more-recent case.
async def test_ctrl_o_toggles_the_last_tool_output(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ToolStarted("c-curl", "curl", "-s http://10.0.0.5/"))
        agent.events.put_nowait(ToolFinished("c-curl", "done", 3))
        await settle(pilot)
        last = app.transcript.last_tool()
        assert last is not None and last.tool == "curl"
        await pilot.press("ctrl+o")
        await settle(pilot, 8)
        assert last.expanded is True
        await pilot.press("ctrl+o")
        await settle(pilot, 8)
        assert last.expanded is False


async def test_clicking_a_tool_entry_toggles_it_without_hanging(quiet_app) -> None:
    """Regression test: ToolMeta.on_click -> action_toggle -> posts
    ToolEntry.Toggled(meta), which ToolEntry's own on_tool_entry_toggled used
    to re-post as a *new* ToolEntry.Toggled back onto itself after stopping
    the original — an infinite self-directed message loop that livelocked
    the whole app (matches a real user report: TUI froze after clicking a
    blocked/scope-guard tool entry's summary line). A failed (guardrail-
    blocked) entry is used here since that's the scenario that was reported,
    though the bug was never actually specific to failure status."""
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ToolStarted("c-nikto", "nikto", "target='google.com'"))
        agent.events.put_nowait(
            ToolFailed("c-nikto", "[scope-guard] 'google.com' is outside the declared engagement scope")
        )
        await settle(pilot)
        entry = app.transcript.tool("c-nikto")
        assert entry is not None and entry.failed

        await asyncio.wait_for(pilot.click(".tool-meta"), timeout=5)
        await asyncio.wait_for(settle(pilot), timeout=5)
        assert entry.expanded is True

        await asyncio.wait_for(pilot.click(".tool-meta"), timeout=5)
        await asyncio.wait_for(settle(pilot), timeout=5)
        assert entry.expanded is False


async def test_ctrl_o_toggles_the_last_narration_when_it_is_more_recent(
    app_and_agent,
) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        last = app.transcript.last_collapsible()
        from cism.tui.widgets.transcript import NarrationEntry

        assert isinstance(last, NarrationEntry)
        await pilot.press("ctrl+o")
        await settle(pilot, 8)
        assert last.expanded is False
        await pilot.press("ctrl+o")
        await settle(pilot, 8)
        assert last.expanded is True


async def test_ctrl_d_opens_and_escape_closes_the_depg_view(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(120, 34)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        assert isinstance(app.screen, DEPGModal)
        await pilot.press("escape")
        await settle(pilot, 8)
        assert not isinstance(app.screen, DEPGModal)


async def test_ctrl_d_twice_in_a_row_pushes_only_one_modal(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(120, 34)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        assert isinstance(app.screen, DEPGModal)
        assert len(app.screen_stack) == 2


async def test_ctrl_m_twice_in_a_row_pushes_only_one_modal(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(120, 34)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+m")
        await settle(pilot, 12)
        await pilot.press("ctrl+m")
        await settle(pilot, 12)
        assert isinstance(app.screen, MemoryModal)
        assert len(app.screen_stack) == 2


async def test_ctrl_m_opens_and_escape_closes_the_memory_view(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(120, 34)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+m")
        await settle(pilot, 12)
        assert isinstance(app.screen, MemoryModal)
        await pilot.press("escape")
        await settle(pilot, 8)
        assert not isinstance(app.screen, MemoryModal)


async def test_phase_proposed_pushes_an_approval_modal(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        agent.events.put_nowait(PhaseProposed("enumeration"))
        await drain(pilot, agent)
        assert isinstance(app.screen, PhaseApprovalModal)
        assert app.screen.current == "recon"
        assert app.screen.proposed == "enumeration"
        assert app.status.phase_proposal == "enumeration"


async def test_approving_the_phase_modal_sends_the_phase_command(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        agent.events.put_nowait(PhaseProposed("enumeration"))
        await drain(pilot, agent)
        await asyncio.wait_for(pilot.click("#phase-approval-approve"), timeout=5)
        await asyncio.wait_for(settle(pilot), timeout=5)
        assert not isinstance(app.screen, PhaseApprovalModal)
        assert "/phase enumeration" in agent.submissions


async def test_dismissing_the_phase_modal_leaves_the_proposal_pending(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        agent.events.put_nowait(PhaseProposed("enumeration"))
        await drain(pilot, agent)
        await pilot.press("escape")
        await settle(pilot, 8)
        assert not isinstance(app.screen, PhaseApprovalModal)
        assert not any("/phase" in s for s in agent.submissions)
        # The proposal itself is untouched — still pending, same as the
        # status bar always showed before the modal existed.
        assert app.status.phase_proposal == "enumeration"


async def test_a_phase_proposal_does_not_stack_a_modal_on_top_of_depg(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        assert isinstance(app.screen, DEPGModal)

        agent.events.put_nowait(PhaseProposed("enumeration"))
        await drain(pilot, agent)
        assert isinstance(app.screen, DEPGModal)
        assert len(app.screen_stack) == 2
        # The status bar still reflects the proposal even though the
        # operator never saw the modal for it.
        assert app.status.phase_proposal == "enumeration"


async def test_a_manual_phase_change_closes_an_open_approval_modal(quiet_app) -> None:
    """A /phase typed directly while the modal for a different proposal is
    still open resolves it some other way — the modal must not linger
    asking about a decision that's already made."""
    app, agent = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        agent.events.put_nowait(PhaseProposed("enumeration"))
        await drain(pilot, agent)
        assert isinstance(app.screen, PhaseApprovalModal)

        agent.events.put_nowait(PhaseChanged("enumeration"))
        await drain(pilot, agent)
        assert not isinstance(app.screen, PhaseApprovalModal)
        assert app.status.phase_proposal == ""


def _depg_node(node_id: str, state: str = "resolved") -> DEPGNode:
    return DEPGNode(id=node_id, cause_class="open-port", target="10.0.0.5", generality=0.5, state=state)


async def test_depg_updated_refreshes_the_open_modal_in_place(quiet_app) -> None:
    """E4: a second DEPGUpdated arriving while the modal is open must
    update the same modal instance, not push a new one on top of it."""
    app, agent = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        agent.events.put_nowait(DEPGUpdated(nodes=(_depg_node("a"),), edges=()))
        await drain(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        modal = app.screen
        assert isinstance(modal, DEPGModal)

        agent.events.put_nowait(
            DEPGUpdated(nodes=(_depg_node("a"), _depg_node("b")), edges=())
        )
        await drain(pilot, agent)

        assert app.screen is modal
        assert len(modal.nodes) == 2


async def test_depg_modal_refresh_preserves_the_selected_node(quiet_app) -> None:
    """E4: the cursor must stay on the node the operator selected across a
    live update, not snap back to the first root on every event."""
    app, agent = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        agent.events.put_nowait(
            DEPGUpdated(nodes=(_depg_node("a"), _depg_node("b")), edges=())
        )
        await drain(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        modal = app.screen
        assert isinstance(modal, DEPGModal)
        tree = modal.query_one(DEPGTree)
        tree.move_cursor(modal._tree_nodes_by_id["b"])
        await settle(pilot, 4)

        agent.events.put_nowait(
            DEPGUpdated(
                nodes=(_depg_node("a"), _depg_node("b"), _depg_node("c")), edges=()
            )
        )
        await drain(pilot, agent)

        assert tree.cursor_node is not None
        assert tree.cursor_node.data.id == "b"


async def test_depg_modal_refresh_falls_back_when_the_selected_node_is_gone(
    quiet_app,
) -> None:
    """If the selected node was pruned away, refresh must not crash or
    leave the cursor pointing at a now-nonexistent tree node."""
    app, agent = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        agent.events.put_nowait(
            DEPGUpdated(nodes=(_depg_node("a"), _depg_node("b")), edges=())
        )
        await drain(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        modal = app.screen
        assert isinstance(modal, DEPGModal)
        tree = modal.query_one(DEPGTree)
        tree.move_cursor(modal._tree_nodes_by_id["b"])
        await settle(pilot, 4)

        agent.events.put_nowait(DEPGUpdated(nodes=(_depg_node("a"),), edges=()))
        await drain(pilot, agent)

        assert app.screen is modal
        assert len(modal.nodes) == 1


def _memory_row(row_id: str, tier: str = "T1") -> MemoryRow:
    return MemoryRow(id=row_id, tier=tier, phase_tag="recon", salience=1.0, age_s=1.0, snippet=row_id)


async def test_memory_updated_refreshes_the_open_modal_in_place(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        agent.events.put_nowait(MemoryUpdated(rows=(_memory_row("m1"),)))
        await drain(pilot, agent)
        await pilot.press("ctrl+m")
        await settle(pilot, 12)
        modal = app.screen
        assert isinstance(modal, MemoryModal)

        agent.events.put_nowait(
            MemoryUpdated(rows=(_memory_row("m1"), _memory_row("m2")))
        )
        await drain(pilot, agent)

        assert app.screen is modal
        assert len(modal.rows) == 2


async def test_pump_coalesces_a_burst_of_depg_updated_to_the_last_one(quiet_app) -> None:
    """E5: three DEPGUpdated events queued back-to-back before the pump
    gets to any of them must apply only the last — the first two are
    already stale (each carries full state, not a delta)."""
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(DEPGUpdated(nodes=(_depg_node("a"),), edges=()))
        agent.events.put_nowait(DEPGUpdated(nodes=(_depg_node("a"), _depg_node("b")), edges=()))
        agent.events.put_nowait(
            DEPGUpdated(nodes=(_depg_node("a"), _depg_node("b"), _depg_node("c")), edges=())
        )
        await drain(pilot, agent)

        assert len(app.depg_nodes) == 3


async def test_pump_coalescing_does_not_skip_a_different_event_type(quiet_app) -> None:
    """A PhaseChanged sitting between two DEPGUpdated events must still be
    applied — coalescing only ever collapses a run of the *same* type."""
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(DEPGUpdated(nodes=(_depg_node("a"),), edges=()))
        agent.events.put_nowait(ScopeChanged(action="add", target="10.0.0.5"))
        agent.events.put_nowait(DEPGUpdated(nodes=(_depg_node("a"), _depg_node("b")), edges=()))
        await drain(pilot, agent)

        notes = [str(getattr(c, "text", "")) for c in app.transcript.children]
        assert any("scope: added 10.0.0.5" in n for n in notes)
        assert len(app.depg_nodes) == 2


async def test_escape_interrupts_a_running_node(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ToolStarted("c1", "nmap", "-sV"))
        await settle(pilot)
        assert app.indicator.active is True
        await pilot.press("escape")
        await settle(pilot)
        assert app.indicator.active is False


async def test_ctrl_c_requires_two_presses(app_and_agent, monkeypatch) -> None:
    app, _ = app_and_agent
    exits: list[int] = []
    async with app.run_test(size=(100, 30)) as pilot:
        monkeypatch.setattr(app, "exit", lambda *a, **k: exits.append(1))
        await pilot.press("ctrl+c")
        await settle(pilot, 5)
        assert exits == []
        assert "ctrl+c again" in app.status.notice
        await pilot.press("ctrl+c")
        await settle(pilot, 5)
        assert exits == [1]


# -- the slash overlay ------------------------------------------------------


async def test_slash_opens_the_overlay_with_every_command(quiet_app) -> None:
    app, _ = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("/")
        await settle(pilot, 8)
        assert app.overlay.open is True
        assert len(app.overlay.matches) == len(COMMANDS)


async def test_typing_filters_the_overlay_fuzzily(quiet_app) -> None:
    app, _ = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("/")
        await pilot.press("m", "e")
        await settle(pilot, 8)
        names = [c.name for c in app.overlay.matches]
        assert names[0] == "mem"


async def test_arrow_keys_move_the_overlay_selection(quiet_app) -> None:
    app, _ = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("/")
        await settle(pilot, 8)
        first = app.overlay.selected()
        await pilot.press("down")
        await settle(pilot, 5)
        assert app.overlay.selected() is not first


async def test_escape_closes_the_overlay_without_interrupting(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ToolStarted("c1", "nmap", ""))
        await settle(pilot)
        await pilot.press("/")
        await settle(pilot, 8)
        await pilot.press("escape")
        await settle(pilot, 5)
        assert app.overlay.open is False
        assert app.indicator.active is True


async def test_picking_a_command_with_an_argument_completes_the_composer(
    quiet_app,
) -> None:
    app, _ = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("/")
        await pilot.press("p", "h")
        await settle(pilot, 8)
        assert app.overlay.selected().name == "phase"
        await pilot.press("enter")
        await settle(pilot, 8)
        assert app.overlay.open is False
        assert app.composer.text == "/phase "


async def test_picking_a_bare_command_runs_it(quiet_app) -> None:
    app, _ = quiet_app
    async with app.run_test(size=(120, 34)) as pilot:
        await pilot.press("/")
        await pilot.press("d", "e", "p", "g")
        await settle(pilot, 8)
        await pilot.press("enter")
        await settle(pilot, 12)
        assert isinstance(app.screen, DEPGModal)


# -- slash commands ---------------------------------------------------------


async def test_local_commands_are_not_forwarded_to_the_agent(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        agent.submissions.clear()
        await pilot.press(*"/help")
        await pilot.press("escape")
        await pilot.press("enter")
        await settle(pilot, 10)
        assert agent.submissions == []
        notes = [e.text for e in app.transcript.query(NarrationEntry)]
        assert any("/phase <name>" in note for note in notes)


async def test_agent_commands_are_forwarded(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        agent.submissions.clear()
        await pilot.press(*"/phase exploitation")
        await pilot.press("escape")
        await pilot.press("enter")
        await settle(pilot, 10)
        assert agent.submissions == ["/phase exploitation"]


async def test_clear_empties_the_transcript(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        assert len(app.transcript.children) > 0
        await pilot.press(*"/clear")
        await pilot.press("escape")
        await pilot.press("enter")
        await settle(pilot, 10)
        assert len(app.transcript.children) == 0
        assert app.transcript.last_tool() is None


async def test_export_writes_the_transcript(export_app, tmp_path) -> None:
    app, agent = export_app
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press(*"/export")
        await pilot.press("escape")
        await pilot.press("enter")
        await settle(pilot, 12)
        written = tmp_path / "cism-transcript.txt"
        assert written.exists()
        body = written.read_text(encoding="utf-8")
        assert "⏺ nmap(-sV -p- 10.0.0.5)" in body
        assert "Starting Nmap" in body
        assert "PTES: exploitation" in body


async def test_report_writes_markdown_json_and_graph_files(export_app, tmp_path) -> None:
    app, agent = export_app
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press(*"/report")
        await pilot.press("escape")
        await pilot.press("enter")
        await settle(pilot, 12)
        written = list(tmp_path.glob("*.md")) + list(tmp_path.glob("*.json")) + list(tmp_path.glob("*.dot"))
        assert len(written) == 3
        notes = [str(getattr(c, "text", "")) for c in app.transcript.children]
        assert any("report written" in n for n in notes)


async def test_export_to_an_unwritable_path_reports_the_error_without_crashing(
    export_app, tmp_path
) -> None:
    app, agent = export_app
    bad_path = tmp_path / "does-not-exist" / "out.txt"
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        for ch in f"/export {bad_path}":
            await pilot.press(ch)
        await pilot.press("enter")
        await settle(pilot, 12)
        assert not bad_path.exists()
        notes = [c for c in app.transcript.children if "failed" in str(getattr(c, "text", ""))]
        assert notes


async def test_scope_changed_renders_as_a_transcript_note(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ScopeChanged("add", "scanme.nmap.org"))
        agent.events.put_nowait(ScopeChanged("remove", "10.0.0.0/24"))
        await settle(pilot)
        texts = [n.text for n in app.transcript.query(NarrationEntry)]
        assert "scope: added scanme.nmap.org" in texts
        assert "scope: removed 10.0.0.0/24" in texts


async def submit_command(pilot, line: str) -> None:
    """Type a slash command and run it, dismissing the overlay first."""
    await pilot.press(*line)
    await pilot.press("escape")
    await pilot.press("enter")
    await settle(pilot, 10)


async def test_models_renders_locally_without_touching_the_agent(
    app_and_agent,
) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(110, 32)) as pilot:
        await replay_all(pilot, agent)
        agent.submissions.clear()
        await submit_command(pilot, "/models")
        assert agent.submissions == []
        notes = "\n".join(e.text for e in app.transcript.query(NarrationEntry))
        assert "qwen2.5-7b-instruct" in notes
        assert "phi-3.5-mini" in notes


async def test_model_switch_is_forwarded_and_updates_the_status_bar(
    app_and_agent,
) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(110, 32)) as pilot:
        await replay_all(pilot, agent)
        assert app.status.model == "qwen2.5-7b-instruct"
        await submit_command(pilot, "/model phi-3.5-mini")
        await drain(pilot, agent)
        assert agent.submissions[-1] == "/model phi-3.5-mini"
        assert app.status.model == "phi-3.5-mini"


async def test_target_is_forwarded_and_shown(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(110, 32)) as pilot:
        await replay_all(pilot, agent)
        await submit_command(pilot, "/target windows iis")
        await drain(pilot, agent)
        assert agent.submissions[-1] == "/target windows iis"
        assert app.status.target_os == "windows"
        assert app.status.target_stack == ("iis",)


async def test_bare_api_reports_endpoint_and_key_variable_only(
    app_and_agent,
) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(110, 32)) as pilot:
        await replay_all(pilot, agent)
        agent.submissions.clear()
        await submit_command(pilot, "/api")
        assert agent.submissions == []
        notes = "\n".join(e.text for e in app.transcript.query(NarrationEntry))
        assert "$CISM_API_KEY" in notes
        assert "not set" in notes


async def test_api_url_is_forwarded(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(110, 32)) as pilot:
        await replay_all(pilot, agent)
        await submit_command(pilot, "/api https://infer.example/v1")
        await drain(pilot, agent)
        assert agent.submissions[-1] == "/api https://infer.example/v1"
        assert app.endpoint == "https://infer.example/v1"


async def test_a_key_pasted_into_api_is_refused_and_never_recorded(
    export_app, tmp_path
) -> None:
    """The key must not reach the transcript, the history, or the export."""
    secret = "sk-proj-AbCd1234EfGh5678IjKl9012MnOp"
    app, agent = export_app
    async with app.run_test(size=(110, 32)) as pilot:
        await replay_all(pilot, agent)
        agent.submissions.clear()
        await submit_command(pilot, f"/api {secret}")

        assert agent.submissions == []

        turns = " ".join(t.turn_text for t in app.transcript.query(UserTurn))
        assert secret not in turns
        assert MASK in turns

        assert all(secret not in item for item in app.composer.history)

        notes = "\n".join(e.text for e in app.transcript.query(NarrationEntry))
        assert "CISM_API_KEY" in notes
        assert secret not in notes

        await submit_command(pilot, "/export")
        body = (tmp_path / "cism-transcript.txt").read_text(encoding="utf-8")
        assert secret not in body


async def test_a_key_pasted_into_any_command_is_refused(quiet_app) -> None:
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    app, agent = quiet_app
    async with app.run_test(size=(110, 32)) as pilot:
        await settle(pilot, 8)
        agent.submissions.clear()
        await submit_command(pilot, f"/model {secret}")
        assert agent.submissions == []
        turns = " ".join(t.turn_text for t in app.transcript.query(UserTurn))
        assert secret not in turns


async def test_an_ordinary_command_argument_is_not_masked(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(110, 32)) as pilot:
        await settle(pilot, 8)
        await submit_command(pilot, "/phase exploitation")
        assert agent.submissions[-1] == "/phase exploitation"
        turns = " ".join(t.turn_text for t in app.transcript.query(UserTurn))
        assert "exploitation" in turns
        assert MASK not in turns


async def test_a_plain_turn_is_echoed_and_forwarded(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press(*"scan the host")
        await pilot.press("enter")
        await settle(pilot, 10)
        assert agent.submissions == ["scan the host"]
        turns = [t.turn_text for t in app.transcript.query(UserTurn)]
        assert turns == ["scan the host"]


# -- modal contents ---------------------------------------------------------


async def test_depg_tree_is_built_from_the_edges(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(140, 40)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        tree = app.screen.query_one(DEPGTree)
        roots = tree.root.children
        assert [node.data.id for node in roots] == ["n-http", "n-ssh", "n-jetty"]
        admin = roots[0].children[0]
        assert admin.data.id == "n-admin"
        assert "w=0.61" in admin.label.plain  # E6: tagged, not a bare number
        assert admin.data.state == "blocked"


async def test_depg_selection_drives_the_evidence_table(app_and_agent) -> None:
    from textual.widgets import DataTable

    app, agent = app_and_agent
    async with app.run_test(size=(140, 40)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        table = app.screen.query_one("#depg-evidence", DataTable)
        assert table.row_count == 2  # n-http has two evidence rows
        await pilot.press("down")
        await settle(pilot, 8)
        assert table.row_count == 2  # n-admin also has two


async def test_depg_decision_path_is_the_root_to_node_trail(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(140, 40)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        modal = app.screen
        # n-dbcred sits at the deepest point of the jetty branch.
        trail = [node.id for node in modal.path_to("n-dbcred")]
        assert trail == ["n-jetty", "n-webinf", "n-dbcred"]
        chosen = [n.decision.chose for n in modal.path_to("n-dbcred") if n.decision]
        assert chosen == ["jetty:8080", "CVE-2021-28164", "read web.xml"]


async def test_depg_decision_table_follows_the_cursor(app_and_agent) -> None:
    from textual.widgets import DataTable

    app, agent = app_and_agent
    async with app.run_test(size=(140, 40)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        table = app.screen.query_one("#depg-decisions", DataTable)
        assert table.row_count == 1  # n-http is a root: one decision
        # Walk down to n-admin, a child of n-http.
        await pilot.press("down")
        await settle(pilot, 8)
        assert table.row_count == 2  # root's decision plus its own


async def test_depg_path_of_a_root_is_just_itself(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(140, 40)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        assert [n.id for n in app.screen.path_to("n-http")] == ["n-http"]
        assert app.screen.path_to("no-such-node") == []


async def test_memory_table_is_sortable(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(140, 40)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+m")
        await settle(pilot, 12)
        modal = app.screen
        table = modal.query_one(MemoryTable)
        assert table.row_count == 10
        by_decayed = [row.id for row in modal._sorted_rows()]
        await pilot.press("4")  # sort by age
        await settle(pilot, 8)
        by_age = [row.id for row in modal._sorted_rows()]
        assert by_age != by_decayed
        assert by_age == sorted(
            by_age, key=lambda i: -next(r.age_s for r in modal.rows if r.id == i)
        )


async def test_memory_footer_shows_the_live_equation(app_and_agent) -> None:
    from textual.widgets import Static

    app, agent = app_and_agent
    async with app.run_test(size=(140, 40)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+m")
        await settle(pilot, 12)
        footer = app.screen.query_one("#memory-equation", Static)
        text = footer.render().plain
        assert text.startswith("S = ")
        assert "e^(−0.0012·" in text


async def test_modals_do_not_persist_between_openings(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(140, 40)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 10)
        await pilot.press("escape")
        await settle(pilot, 8)
        await pilot.press("ctrl+m")
        await settle(pilot, 10)
        assert isinstance(app.screen, MemoryModal)
        assert len(app.screen_stack) == 2


# -- startup banner ---------------------------------------------------------


async def test_banner_is_shown_before_the_first_prompt(quiet_app) -> None:
    app, _ = quiet_app
    async with app.run_test(size=(110, 32)) as pilot:
        await settle(pilot)
        assert len(app.query(Banner)) == 1


async def test_banner_is_retired_by_the_first_submission(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(110, 32)) as pilot:
        await settle(pilot)
        await pilot.press(*"scan it")
        await pilot.press("enter")
        await settle(pilot)
        assert len(app.query(Banner)) == 0
        assert agent.submissions == ["scan it"]


async def test_a_slash_command_also_retires_the_banner(app_and_agent) -> None:
    """A command is still a first prompt — the splash has had its turn."""
    app, _ = app_and_agent
    async with app.run_test(size=(110, 32)) as pilot:
        await settle(pilot)
        await submit_command(pilot, "/models")
        assert len(app.query(Banner)) == 0


async def test_dismissing_an_already_dismissed_banner_is_a_no_op(app_and_agent) -> None:
    app, _ = app_and_agent
    async with app.run_test(size=(110, 32)) as pilot:
        await settle(pilot)
        for _ in range(3):
            await pilot.press(*"hi")
            await pilot.press("enter")
            await settle(pilot)
        assert len(app.query(Banner)) == 0


async def test_banner_is_not_part_of_the_exported_transcript(export_app, tmp_path) -> None:
    """It is a sibling of the transcript, not an entry in it, so /export
    never picks it up."""
    app, agent = export_app
    async with app.run_test(size=(110, 32)) as pilot:
        await replay_all(pilot, agent)
        await submit_command(pilot, "/export")
        body = (tmp_path / "cism-transcript.txt").read_text(encoding="utf-8")
        assert "Cyber Investigation State Memory" not in body
        assert "█" not in body


async def test_banner_drops_the_wordmark_on_a_narrow_terminal(quiet_app) -> None:
    app, _ = quiet_app
    async with app.run_test(size=(28, 20)) as pilot:
        await settle(pilot)
        rendered = app.query_one(Banner).render().plain
        assert "█" not in rendered
        assert "CISM" in rendered


@pytest.mark.parametrize("width", (110, 60, 40, 30, 24, 16))
async def test_banner_never_renders_a_line_wider_than_the_widget(
    demo_steps, width
) -> None:
    """Every line is either a form that fits or omitted — a ragged wrap in
    the splash is the thing this guards against."""
    app = CISMApp(FakeAgent(demo_steps, speed=0, autostart=False))
    async with app.run_test(size=(width, 20)) as pilot:
        await settle(pilot)
        banner = app.query_one(Banner)
        for line in banner.render().plain.split("\n"):
            assert len(line) <= banner.size.width, (width, line)


# -- pump resilience --------------------------------------------------------


async def test_a_failing_agent_start_does_not_kill_the_event_pump(quiet_app) -> None:
    """agent.start() sits outside the per-event try, but the pump is the only
    writer of transcript state — if it dies the UI paints fine and never
    shows another event, which looks exactly like a hung agent."""
    app, agent = quiet_app

    async def boom() -> None:
        raise RuntimeError("context probe exploded")

    agent.start = boom
    async with app.run_test(size=(100, 30)) as pilot:
        await settle(pilot)
        assert app.start_failed is True

        agent.events.put_nowait(Narration("e1", "pump still alive"))
        await settle(pilot)
        texts = [e.text for e in app.transcript.query(NarrationEntry)]
        assert "pump still alive" in texts
        assert any("did not start cleanly" in t for t in texts)


async def test_banner_is_retired_when_a_run_starts_without_a_submission(
    app_and_agent,
) -> None:
    """Replay and demo sessions produce transcript content with nobody
    typing; the splash must not sit above a finished run."""
    app, agent = app_and_agent
    async with app.run_test(size=(110, 32)) as pilot:
        await replay_all(pilot, agent)
        assert len(app.query(Banner)) == 0
