"""A fake agent that replays a recorded event log.

This is what makes the TUI demoable with no lab, no model weights, and no
network. It satisfies :class:`cism.tui.events.Agent` exactly, so the app
cannot tell it apart from the real LangGraph-backed core.

The log is JSONL, one :func:`cism.tui.events.encode` payload per line, with an
optional ``"delay"`` key giving the pause *before* that event is emitted.
Narration lines may instead carry ``"stream"``, which is expanded into a
sequence of :class:`Narration` chunks so playback looks like live generation.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator

from .events import AgentEvent, Interrupted, Narration, decode

DEFAULT_DELAY = 0.0
CHUNK_PATTERN = re.compile(r"\S+\s*")


class ReplayLogError(ValueError):
    """Raised when a replay log cannot be parsed.

    Deliberately raised at load time, before the app mounts, so a broken demo
    log fails loudly instead of half-starting.
    """


class ReplayStep:
    """One line of the log: a delay, then either an event or a stream."""

    __slots__ = ("delay", "payload", "stream", "entry_id", "rate")

    def __init__(self, payload: dict[str, Any], line_number: int) -> None:
        data = dict(payload)
        self.delay = float(data.pop("delay", DEFAULT_DELAY))
        self.rate = float(data.pop("rate", 0.012))
        self.stream = data.pop("stream", None)
        self.entry_id = data.get("entry_id")
        if self.stream is not None:
            if not self.entry_id:
                raise ReplayLogError(
                    f"line {line_number}: 'stream' requires an 'entry_id'"
                )
            self.payload = None
            return
        try:
            decode(data)
        except KeyError as error:
            raise ReplayLogError(
                f"line {line_number}: unknown event type {error}"
            ) from error
        except TypeError as error:
            raise ReplayLogError(f"line {line_number}: {error}") from error
        self.payload = data

    def events(self) -> Iterator[tuple[float, AgentEvent]]:
        """Yield ``(pause_before, event)`` pairs for this step."""
        if self.payload is not None:
            yield self.delay, decode(self.payload)
            return
        chunks = CHUNK_PATTERN.findall(self.stream)
        for index, chunk in enumerate(chunks):
            pause = self.delay if index == 0 else self.rate
            yield pause, Narration(entry_id=self.entry_id, text=chunk)
        yield self.rate, Narration(entry_id=self.entry_id, text="", done=True)


def load_log(path: str | Path) -> list[ReplayStep]:
    """Parse a JSONL replay log. Raises :class:`ReplayLogError` on any problem."""
    path = Path(path)
    if not path.exists():
        raise ReplayLogError(f"replay log not found: {path}")
    steps: list[ReplayStep] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            raise ReplayLogError(f"line {number}: {error}") from error
        if not isinstance(payload, dict):
            raise ReplayLogError(f"line {number}: expected an object")
        steps.append(ReplayStep(payload, number))
    if not steps:
        raise ReplayLogError(f"replay log is empty: {path}")
    return steps


class FakeAgent:
    """Replays a log into the event queue. Satisfies the ``Agent`` protocol.

    ``speed`` scales every delay: ``2.0`` plays twice as fast, ``0`` removes
    all pauses (used by the tests so they do not sleep).
    """

    def __init__(
        self,
        steps: list[ReplayStep],
        *,
        speed: float = 1.0,
        autostart: bool = True,
        loop_forever: bool = False,
    ) -> None:
        self.events: asyncio.Queue[AgentEvent] = asyncio.Queue()
        self.steps = steps
        self.speed = speed
        self.autostart = autostart
        self.loop_forever = loop_forever
        self.submissions: list[str] = []
        self._task: asyncio.Task[None] | None = None
        self._finished = asyncio.Event()

    @classmethod
    def from_path(cls, path: str | Path, **kwargs: Any) -> "FakeAgent":
        return cls(load_log(path), **kwargs)

    # -- Agent protocol ----------------------------------------------------

    async def start(self) -> None:
        if self.autostart:
            self._spawn()

    async def submit(self, text: str) -> None:
        self.submissions.append(text)
        if self._task is None or self._task.done():
            self._spawn()

    async def interrupt(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.events.put(Interrupted(reason="interrupted by user"))

    async def aclose(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # -- playback ----------------------------------------------------------

    def _spawn(self) -> None:
        self._finished.clear()
        self._task = asyncio.create_task(self._play())

    async def wait(self) -> None:
        """Block until playback has finished. Used by tests and by ``--once``."""
        await self._finished.wait()

    async def _play(self) -> None:
        try:
            while True:
                for step in self.steps:
                    for pause, event in step.events():
                        if pause and self.speed > 0:
                            await asyncio.sleep(pause / self.speed)
                        await self.events.put(event)
                if not self.loop_forever:
                    break
        finally:
            self._finished.set()


def rebase(events: list[AgentEvent], offset: int) -> list[AgentEvent]:
    """Renumber a batch of events. Used when splicing two logs together."""
    return [replace(event, seq=offset + index) for index, event in enumerate(events)]
