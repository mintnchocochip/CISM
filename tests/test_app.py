"""Keybinds, slash commands, modals, and the pump's handling of bad input."""

from __future__ import annotations

from dataclasses import dataclass

from conftest import replay_all, settle

from cism.tui.events import Narration, ToolStarted
from cism.tui.widgets.depg_modal import DEPGModal, DEPGTree
from cism.tui.widgets.memory_modal import MemoryModal, MemoryTable
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


async def test_ctrl_o_toggles_the_last_tool_output(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        last = app.transcript.last_tool()
        assert last is not None and last.tool == "curl"
        await pilot.press("ctrl+o")
        await settle(pilot, 8)
        assert last.expanded is True
        await pilot.press("ctrl+o")
        await settle(pilot, 8)
        assert last.expanded is False


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
        assert "0.61" in admin.label.plain
        assert admin.data.state == "blocked"


async def test_depg_selection_drives_the_evidence_table(app_and_agent) -> None:
    from textual.widgets import DataTable

    app, agent = app_and_agent
    async with app.run_test(size=(140, 40)) as pilot:
        await replay_all(pilot, agent)
        await pilot.press("ctrl+d")
        await settle(pilot, 12)
        table = app.screen.query_one(DataTable)
        assert table.row_count == 2  # n-http has two evidence rows
        await pilot.press("down")
        await settle(pilot, 8)
        assert table.row_count == 2  # n-admin also has two


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
