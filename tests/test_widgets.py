"""Transcript entries, composer, spinner, and status bar behaviour."""

from __future__ import annotations

import pytest
from conftest import FOLLOW_TICKS, replay_all, settle

from cism.tui.events import Narration, PhaseChanged, ToolFailed, ToolStarted
from cism.tui.widgets._fmt import capacity, elapsed, tokens
from cism.tui.widgets.composer import Composer
from cism.tui.widgets.spinner import VERBS, WorkingIndicator
from cism.tui.widgets.status import StatusBar
from cism.tui.widgets.transcript import (
    NarrationEntry,
    PhaseRule,
    ToolEntry,
    Transcript,
    UserTurn,
)


# -- formatting -------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, "0"), (999, "999"), (1200, "1.2k"), (12420, "12.4k"), (2_400_000, "2.4M")],
)
def test_token_formatting(value: int, expected: str) -> None:
    assert tokens(value) == expected


def test_capacity_renders_a_round_window_without_a_decimal() -> None:
    assert capacity(32768) == "32k"
    assert capacity(131072) == "128k"


@pytest.mark.parametrize(
    ("value", "expected"), [(0, "0s"), (12, "12s"), (59, "59s"), (184, "3m04s")]
)
def test_elapsed_formatting(value: float, expected: str) -> None:
    assert elapsed(value) == expected


# -- transcript entries -----------------------------------------------------


async def test_user_turn_uses_the_prompt_glyph(app_and_agent) -> None:
    app, _ = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        turn = app.transcript.add_user_turn("scan 10.0.0.5")
        await settle(pilot, 5)
        assert isinstance(turn, UserTurn)
        assert turn.render().plain == "> scan 10.0.0.5"


async def test_multiline_user_turn_indents_continuations(app_and_agent) -> None:
    app, _ = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        turn = app.transcript.add_user_turn("first\nsecond")
        await settle(pilot, 5)
        assert turn.render().plain == "> first\n  second"


async def test_narration_streams_into_one_widget(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        for chunk in ("Single ", "host ", "on the lab."):
            agent.events.put_nowait(Narration("e1", chunk))
        await settle(pilot)
        entries = app.transcript.query(NarrationEntry)
        assert len(entries) == 1
        assert entries.first().text == "Single host on the lab."


async def test_narration_widget_identity_is_stable_across_chunks(
    quiet_app,
) -> None:
    """The point of the buffer: appending must not rebuild the widget."""
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "first "))
        await settle(pilot)
        original = app.transcript.query_one(NarrationEntry)
        agent.events.put_nowait(Narration("e1", "second"))
        await settle(pilot)
        assert app.transcript.query_one(NarrationEntry) is original
        assert original.text == "first second"


async def test_narration_entry_is_expanded_by_default(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "hello", done=True))
        await settle(pilot)
        entry = app.transcript.query_one(NarrationEntry)
        assert entry.expanded is True


async def test_toggling_a_finished_narration_entry_collapses_it(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "hello", done=True))
        await settle(pilot)
        entry = app.transcript.query_one(NarrationEntry)
        entry.toggle()
        await settle(pilot, 5)
        assert entry.expanded is False
        entry.toggle()
        await settle(pilot, 5)
        assert entry.expanded is True


async def test_toggling_a_still_streaming_narration_entry_does_nothing(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "hello", done=False))
        await settle(pilot)
        entry = app.transcript.query_one(NarrationEntry)
        entry.toggle()
        await settle(pilot, 5)
        assert entry.expanded is True


async def test_redact_replaces_shown_text_with_a_withheld_notice(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "some streamed text"))
        await settle(pilot)
        entry = app.transcript.narration("e1")
        entry.redact("blocked: contains a secret")
        await settle(pilot, 5)
        assert entry.text == "blocked: contains a secret"
        assert entry.done is True
        assert entry.redacted is True


async def test_last_collapsible_picks_the_more_recent_of_tool_and_narration(
    quiet_app,
) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ToolStarted("c1", "nmap", "-sV"))
        await settle(pilot)
        agent.events.put_nowait(Narration("e1", "hello", done=True))
        await settle(pilot)
        last = app.transcript.last_collapsible()
        assert isinstance(last, NarrationEntry)

        agent.events.put_nowait(ToolStarted("c2", "curl", ""))
        await settle(pilot)
        last = app.transcript.last_collapsible()
        assert isinstance(last, ToolEntry)
        assert last.call_id == "c2"


async def test_tool_output_is_collapsed_by_default(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        entry = app.transcript.tool("c-nmap")
        assert entry is not None
        assert entry.expanded is False
        assert entry.body_text.startswith("Starting Nmap")


async def test_toggling_a_tool_entry_expands_it(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        entry = app.transcript.tool("c-nmap")
        assert entry is not None
        entry.toggle()
        await settle(pilot, 8)
        assert entry.expanded is True
        assert entry.has_class("-expanded")
        entry.toggle()
        await settle(pilot, 5)
        assert entry.expanded is False


async def test_tool_summary_line_carries_lines_summary_and_tier(
    app_and_agent,
) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(200, 30)) as pilot:
        await replay_all(pilot, agent)
        entry = app.transcript.tool("c-nmap")
        assert entry is not None
        rendered = entry._meta.render().plain
        assert rendered.startswith("  ⎿  ")
        assert "1247 lines" in rendered
        assert "6 open ports" in rendered
        assert "relevance T1 (0.91)" in rendered


async def test_long_summary_wraps_with_a_hanging_indent(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(60, 30)) as pilot:
        await replay_all(pilot, agent)
        entry = app.transcript.tool("c-nmap")
        assert entry is not None
        lines = entry._meta.render().plain.splitlines()
        assert len(lines) > 1
        assert lines[0].startswith("  ⎿  ")
        for line in lines[1:]:
            assert line.startswith("     ")
            assert not line.startswith("      ")


async def test_failed_tool_is_marked(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        entry = app.transcript.tool("c-msf")
        assert entry is not None
        assert entry.failed is True
        assert entry.has_class("-failed")
        assert "msfrpcd not reachable" in entry._meta.render().plain


async def test_failed_tool_keeps_the_traceback_collapsed(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ToolStarted("c-x", "tool", ""))
        agent.events.put_nowait(ToolFailed("c-x", "boom", "Traceback...\n  line\n"))
        await settle(pilot)
        entry = app.transcript.tool("c-x")
        assert entry is not None
        assert entry.expanded is False
        assert "Traceback" in entry.body_text


async def test_phase_rule_fills_the_width_and_centres_the_label(
    quiet_app,
) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(PhaseChanged("exploitation", "PTES"))
        await settle(pilot)
        rule = app.transcript.query_one(PhaseRule)
        rendered = rule.render().plain
        assert "PTES: exploitation" in rendered
        assert rendered.startswith("─") and rendered.endswith("─")
        assert len(rendered) == rule.size.width


# -- autoscroll -------------------------------------------------------------


async def test_transcript_follows_the_bottom(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        await replay_all(pilot, agent)
        await pilot.pause(FOLLOW_TICKS)
        transcript = app.transcript
        assert transcript.following is True
        assert transcript.scroll_y == transcript.max_scroll_y


async def test_scrolling_up_pauses_autoscroll(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        await replay_all(pilot, agent)
        transcript = app.transcript
        for _ in range(3):
            transcript.scroll_up(animate=False)
        await pilot.pause(FOLLOW_TICKS)
        assert transcript.following is False

        held = transcript.scroll_y
        transcript.add_note("more content arrives")
        await pilot.pause(FOLLOW_TICKS)
        assert transcript.scroll_y == held


async def test_returning_to_the_bottom_resumes_autoscroll(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        await replay_all(pilot, agent)
        transcript = app.transcript
        for _ in range(3):
            transcript.scroll_up(animate=False)
        await pilot.pause(FOLLOW_TICKS)
        assert transcript.following is False
        transcript.scroll_end(animate=False, immediate=True)
        await pilot.pause(FOLLOW_TICKS)
        assert transcript.following is True


# -- composer ---------------------------------------------------------------


async def test_enter_submits_and_clears(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        await pilot.press(*"hello")
        await pilot.press("enter")
        await settle(pilot)
        assert app.composer.text == ""
        assert agent.submissions == ["hello"]


async def test_shift_enter_inserts_a_newline(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        await pilot.press(*"ab")
        await pilot.press("shift+enter")
        await pilot.press(*"cd")
        await settle(pilot)
        assert app.composer.text == "ab\ncd"
        assert agent.submissions == []


async def test_history_recall_walks_backwards_and_forwards(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        await pilot.press(*"one")
        await pilot.press("enter")
        await pilot.press(*"two")
        await pilot.press("enter")
        await settle(pilot)

        await pilot.press("up")
        await settle(pilot, 5)
        assert app.composer.text == "two"
        await pilot.press("up")
        await settle(pilot, 5)
        assert app.composer.text == "one"
        await pilot.press("down")
        await settle(pilot, 5)
        assert app.composer.text == "two"
        await pilot.press("down")
        await settle(pilot, 5)
        assert app.composer.text == ""


async def test_empty_submission_is_ignored(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        await pilot.press("enter")
        await settle(pilot)
        assert agent.submissions == []
        assert app.composer.history == []


# -- spinner and status -----------------------------------------------------


async def test_indicator_renders_the_specified_line(app_and_agent) -> None:
    app, _ = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        indicator = app.indicator
        indicator.start("recon", token_base=0)
        indicator.set_tokens(1200)
        await settle(pilot, 3)
        rendered = indicator.render().plain
        assert rendered.endswith("· esc to interrupt)")
        assert "↑1.2k tokens" in rendered
        assert indicator.verb in VERBS["recon"]


async def test_indicator_verb_list_follows_the_phase(app_and_agent) -> None:
    app, _ = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        indicator = app.indicator
        indicator.start("recon")
        assert indicator.verb in VERBS["recon"]
        indicator.set_phase("exploitation")
        await settle(pilot, 3)
        assert indicator.verb in VERBS["exploitation"]


async def test_indicator_glyph_cycles(app_and_agent) -> None:
    app, _ = app_and_agent
    async with app.run_test(size=(100, 24)) as pilot:
        indicator = app.indicator
        indicator.start("recon")
        seen = set()
        for _ in range(6):
            seen.add(indicator.render().plain[0])
            indicator._tick()
        assert len(seen) > 1


async def test_status_bar_matches_the_specified_format(quiet_app) -> None:
    app, _ = quiet_app
    async with app.run_test(size=(160, 24)) as pilot:
        status = app.status
        status.phase = "recon"
        status.ctx_used = 12420
        status.ctx_max = 32768
        status.depg_nodes = 47
        status.mem_t1 = 8
        status.mem_t2 = 31
        status.mem_t3 = 5
        await settle(pilot, 3)
        assert status.render().plain == (
            "qwen2.5-7b-instruct · phase: recon · ctx 12.4k/32k (38%)"
            " · depg 47 nodes · mem T1:8 T2:31 T3:5 · ⏵⏵ auto"
        )


async def test_status_bar_tracks_replayed_state(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(120, 24)) as pilot:
        await replay_all(pilot, agent)
        assert app.status.phase == "exploitation"
        assert app.status.depg_nodes == 11
        assert app.status.mem_t1 == 4
        assert app.status.mem_t2 == 4
        assert app.status.mem_t3 == 2
        assert app.status.ctx_used == 12420
