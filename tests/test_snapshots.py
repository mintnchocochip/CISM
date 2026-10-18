"""SVG snapshots pinning the visual target.

These are the regression net for the look itself: transcript spacing, the
``⏺``/``⎿`` gutters, the composer border in both focus states, the working
line, and both modal overlays.

Update deliberately, after looking at the diff::

    pytest tests/test_snapshots.py --snapshot-update
"""

from __future__ import annotations

from conftest import DEMO_LOG, freeze_indicator, quiesce, replay_all, settle

from cism.tui.app import CISMApp
from cism.tui.events import Narration, ToolStarted
from cism.tui.replay import FakeAgent, load_log

TERMINAL = (110, 32)


def make_app(*, autostart: bool = True) -> CISMApp:
    return CISMApp(FakeAgent(load_log(DEMO_LOG), speed=0, autostart=autostart))


def test_startup_shows_the_banner(snap_compare) -> None:
    """Before the first prompt: the wordmark, the identity lines and the
    hint, over an empty transcript. Everything below is still just the
    composer and the status line — the terminal is the frame."""

    async def run_before(pilot) -> None:
        await settle(pilot, 10)
        quiesce(pilot.app)
        await settle(pilot, 4)

    assert snap_compare(
        make_app(autostart=False), terminal_size=TERMINAL, run_before=run_before
    )


def test_transcript_after_a_full_run(snap_compare) -> None:
    async def run_before(pilot) -> None:
        await replay_all(pilot, pilot.app.agent)
        quiesce(pilot.app)
        await settle(pilot, 6)

    assert snap_compare(make_app(), terminal_size=TERMINAL, run_before=run_before)


def test_composer_focused(snap_compare) -> None:
    """The border takes the accent when the composer holds focus."""

    async def run_before(pilot) -> None:
        await settle(pilot, 8)
        quiesce(pilot.app)
        pilot.app.composer.focus_input()
        await pilot.press(*"scan 10.0.0.5 and tell me what is exposed")
        await settle(pilot, 8)

    assert snap_compare(
        make_app(autostart=False), terminal_size=TERMINAL, run_before=run_before
    )


def test_composer_unfocused(snap_compare) -> None:
    async def run_before(pilot) -> None:
        await settle(pilot, 8)
        quiesce(pilot.app)
        pilot.app.transcript.focus()
        await settle(pilot, 8)

    assert snap_compare(
        make_app(autostart=False), terminal_size=TERMINAL, run_before=run_before
    )


def test_working_indicator_mid_run(snap_compare) -> None:
    """Spinner glyph, phase verb, elapsed, and token counter above the composer."""

    async def run_before(pilot) -> None:
        app = pilot.app
        app.agent.events.put_nowait(Narration("e1", "Sweeping the full port range."))
        app.agent.events.put_nowait(ToolStarted("c1", "nmap", "-sV -p- 10.0.0.5"))
        await settle(pilot, 12)
        app.indicator.set_tokens(1200)
        freeze_indicator(app, elapsed=12.0)
        await settle(pilot, 4)

    assert snap_compare(
        make_app(autostart=False), terminal_size=TERMINAL, run_before=run_before
    )


def test_tool_output_expanded(snap_compare) -> None:
    async def run_before(pilot) -> None:
        app = pilot.app
        await replay_all(pilot, app.agent)
        quiesce(app)
        app.transcript.tool("c-nmap").toggle()
        await settle(pilot, 8)
        # Scroll home rather than to the entry: a fixed offset keeps the
        # snapshot stable regardless of when the expanded body finishes layout.
        app.transcript.scroll_home(animate=False, immediate=True)
        await settle(pilot, 8)

    assert snap_compare(make_app(), terminal_size=TERMINAL, run_before=run_before)


def test_failed_tool_entry(snap_compare) -> None:
    async def run_before(pilot) -> None:
        app = pilot.app
        await replay_all(pilot, app.agent)
        quiesce(app)
        app.transcript.tool("c-msf").scroll_visible(animate=False, top=True)
        await settle(pilot, 10)

    assert snap_compare(make_app(), terminal_size=TERMINAL, run_before=run_before)


def test_slash_overlay(snap_compare) -> None:
    async def run_before(pilot) -> None:
        await settle(pilot, 8)
        quiesce(pilot.app)
        await pilot.press("/")
        await settle(pilot, 10)

    assert snap_compare(
        make_app(autostart=False), terminal_size=TERMINAL, run_before=run_before
    )


def test_depg_modal(snap_compare) -> None:
    async def run_before(pilot) -> None:
        await replay_all(pilot, pilot.app.agent)
        quiesce(pilot.app)
        await pilot.press("ctrl+d")
        await settle(pilot, 14)

    assert snap_compare(make_app(), terminal_size=(140, 38), run_before=run_before)


def test_memory_modal(snap_compare) -> None:
    async def run_before(pilot) -> None:
        await replay_all(pilot, pilot.app.agent)
        quiesce(pilot.app)
        await pilot.press("ctrl+m")
        await settle(pilot, 14)

    assert snap_compare(make_app(), terminal_size=(140, 38), run_before=run_before)
