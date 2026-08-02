"""Shared fixtures: replay-backed apps that settle deterministically."""

from __future__ import annotations

from pathlib import Path

import pytest

from cism.tui.app import CISMApp
from cism.tui.replay import FakeAgent, ReplayStep, load_log
from cism.tui.widgets.transcript import NarrationEntry

ROOT = Path(__file__).resolve().parents[1]
DEMO_LOG = ROOT / "demo" / "recon_run.jsonl"

#: A fixed instant so spinner snapshots do not depend on wall-clock time.
FROZEN_NOW = 1000.0

#: Long enough for the transcript's follow timer to tick at least twice.
FOLLOW_TICKS = 0.2


@pytest.fixture
def demo_steps() -> list[ReplayStep]:
    return load_log(DEMO_LOG)


@pytest.fixture
def app_and_agent(demo_steps: list[ReplayStep]) -> tuple[CISMApp, FakeAgent]:
    """An app whose replay starts as soon as the pump does."""
    agent = FakeAgent(demo_steps, speed=0)
    return CISMApp(agent), agent


@pytest.fixture
def quiet_app(demo_steps: list[ReplayStep]) -> tuple[CISMApp, FakeAgent]:
    """An app with an idle agent, for tests that push their own events."""
    agent = FakeAgent(demo_steps, speed=0, autostart=False)
    return CISMApp(agent), agent


@pytest.fixture
def export_app(demo_steps: list[ReplayStep], tmp_path) -> tuple[CISMApp, FakeAgent]:
    agent = FakeAgent(demo_steps, speed=0)
    return CISMApp(agent, export_dir=tmp_path), agent


async def settle(pilot, times: int = 12) -> None:
    """Let queued messages, mounts, layout, and coalesced repaints drain.

    The real pause matters: narration is flushed on a coalescing timer, so
    message-loop turns alone are not enough to guarantee the text has been
    painted.
    """
    for _ in range(times):
        await pilot.pause()
    await pilot.pause(NarrationEntry.FLUSH_INTERVAL * 2)
    for _ in range(4):
        await pilot.pause()


async def drain(pilot, agent: FakeAgent) -> None:
    """Block until the pump has applied every event currently queued."""
    await agent.events.join()
    await settle(pilot)


async def replay_all(pilot, agent: FakeAgent) -> None:
    """Play the whole log and wait for the UI to reflect all of it."""
    await agent.wait()
    await drain(pilot, agent)


def quiesce(app: CISMApp) -> None:
    """Stop everything time-driven.

    Three timers would otherwise make a snapshot depend on when it was taken:
    the spinner's frame clock, the transcript's follow check (which keeps
    re-scrolling to the bottom, even underneath a modal), and the composer's
    cursor blink.
    """
    app.transcript._following = False
    app.composer.input.cursor_blink = False
    indicator = app.indicator
    if indicator._timer is not None:
        indicator._timer.stop()
        indicator._timer = None


def freeze_indicator(app: CISMApp, elapsed: float = 12.0) -> None:
    """Pin the working indicator to one frame at a fixed elapsed time."""
    quiesce(app)
    indicator = app.indicator
    indicator._now = lambda: FROZEN_NOW
    indicator._started = FROZEN_NOW - elapsed
    indicator._last_rotate = FROZEN_NOW
    indicator._frame = 2
    indicator._verb_index = 3
    indicator.refresh()
