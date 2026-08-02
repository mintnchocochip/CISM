"""Keybinds, slash commands, modals, and the pump's handling of bad input."""

from __future__ import annotations

from dataclasses import dataclass

from conftest import drain, replay_all, settle

from cism.tui.events import Narration, ToolStarted
from cism.tui.redact import MASK
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
        assert "0.61" in admin.label.plain
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
