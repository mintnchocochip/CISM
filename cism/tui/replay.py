"""A fake agent that replays a recorded event log — makes the TUI demoable
with no lab, model weights, or network. Satisfies :class:`cism.tui.events.
Agent` exactly. The log is JSONL, one :func:`encode` payload per line, with
an optional ``"delay"`` before that event; a ``"stream"`` key expands into
:class:`Narration` chunks so playback looks like live generation."""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator

from .events import (
    AgentEvent,
    Interrupted,
    ModelInfo,
    Narration,
    SessionState,
    decode,
)

DEFAULT_DELAY = 0.0
CHUNK_PATTERN = re.compile(r"\S+\s*")

#: What the fake session claims it can load.
DEMO_MODELS: tuple[ModelInfo, ...] = (
    ModelInfo("qwen2.5-7b-instruct", "7B", 32768, True),
    ModelInfo("qwen2.5-3b-instruct", "3B", 32768),
    ModelInfo("phi-3.5-mini", "3.8B", 131072),
    ModelInfo("llama-3.2-3b", "3B", 131072),
)


class ReplayLogError(ValueError):
    """Raised when a replay log cannot be parsed — at load time, before the
    app mounts, so a broken demo log fails loudly instead of half-starting."""


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
    ``speed`` scales every delay; ``0`` removes all pauses (used by tests)."""

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
        self.models = DEMO_MODELS
        self.model = DEMO_MODELS[0].name
        self.endpoint = "local (llama.cpp)"
        self.key_env_var = "CISM_API_KEY"
        self.target_os = ""
        self.target_stack: tuple[str, ...] = ()
        self._task: asyncio.Task[None] | None = None
        self._finished = asyncio.Event()

    @classmethod
    def from_path(cls, path: str | Path, **kwargs: Any) -> "FakeAgent":
        return cls(load_log(path), **kwargs)

    # -- Agent protocol ----------------------------------------------------

    async def start(self) -> None:
        # Announce the session before playback, so the status bar is populated even if never played.
        await self.events.put(self._session())
        if self.autostart:
            self._spawn()

    async def submit(self, text: str) -> None:
        self.submissions.append(text)
        if text.startswith("/"):
            await self._configure(text)
            return
        if self._task is None or self._task.done():
            self._spawn()

    async def _configure(self, line: str) -> None:
        """Answer session-config commands so the demo is interactive — the
        fake just reports the state the TUI should now display."""
        name, _, argument = line[1:].strip().partition(" ")
        argument = argument.strip()

        if name == "model" and argument:
            match = next(
                (m for m in self.models if m.name.startswith(argument)), None
            )
            if match is None:
                await self.events.put(
                    Narration(
                        entry_id=f"cfg-{len(self.submissions)}",
                        text=f"no such model: {argument}",
                        done=True,
                    )
                )
                return
            self.model = match.name
            self.models = tuple(
                ModelInfo(m.name, m.params, m.context, m.name == match.name)
                for m in self.models
            )
        elif name == "target" and argument:
            parts = argument.split()
            self.target_os = parts[0]
            self.target_stack = tuple(parts[1:])
        elif name == "api" and argument:
            self.endpoint = argument

        await self.events.put(self._session())

    def _session(self) -> SessionState:
        return SessionState(
            model=self.model,
            models_available=self.models,
            endpoint=self.endpoint,
            key_env_var=self.key_env_var,
            key_present=bool(os.environ.get(self.key_env_var)),
            target_os=self.target_os,
            target_stack=self.target_stack,
        )

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
