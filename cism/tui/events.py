"""The event contract between the CISM agent core and the terminal UI.

The TUI is a *pure consumer*. The agent pushes frozen dataclasses onto an
``asyncio.Queue``; the TUI drains that queue and mutates widgets. Nothing in
``cism.tui`` ever calls back into LangGraph, llama.cpp, or the scorer.

Every event carries a monotonically increasing ``seq`` and a wall-clock ``ts``
so a run can be recorded, diffed, and replayed deterministically.
"""

from __future__ import annotations

import asyncio
import itertools
import math
import time
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Iterable, Literal, Protocol, TypeAlias, runtime_checkable

__all__ = [
    "AgentEvent",
    "Agent",
    "DEPGEdge",
    "DEPGNode",
    "DEPGUpdated",
    "EVENT_TYPES",
    "Evidence",
    "Interrupted",
    "MemoryRow",
    "MemoryUpdated",
    "Narration",
    "PhaseChanged",
    "RunFinished",
    "RunStarted",
    "SalienceTerms",
    "TokenDelta",
    "ToolFailed",
    "ToolFinished",
    "ToolOutput",
    "ToolStarted",
    "decode",
    "encode",
    "reset_sequence",
]

_seq = itertools.count(1)


def _next_seq() -> int:
    return next(_seq)


def reset_sequence() -> None:
    """Restart sequence numbering. Used by the replayer and by tests."""
    global _seq
    _seq = itertools.count(1)


# --------------------------------------------------------------------------
# value objects
# --------------------------------------------------------------------------

NodeState: TypeAlias = Literal["blocked", "resolved", "untested"]
Tier: TypeAlias = Literal["T1", "T2", "T3"]


@dataclass(frozen=True, slots=True)
class Evidence:
    """One observation attached to a DEPG node."""

    timestamp: str
    tool: str
    exit_signal: str
    tier: Tier


@dataclass(frozen=True, slots=True)
class DEPGNode:
    """A node in the Dependency / Error Propagation Graph.

    ``generality`` is gamma: how far a cause-class is expected to transfer to
    sibling targets. ``downstream`` counts nodes whose reachability depends on
    this one being resolved.
    """

    id: str
    cause_class: str
    target: str
    generality: float
    state: NodeState
    downstream: int = 0
    evidence: tuple[Evidence, ...] = ()

    def label(self) -> str:
        return (
            f"[{self.cause_class}] {self.target} "
            f"— generality γ={self.generality:.2f} ({self.downstream} downstream)"
        )


@dataclass(frozen=True, slots=True)
class DEPGEdge:
    """A directed propagation edge. ``weight`` is the propagation coefficient."""

    parent: str
    child: str
    weight: float


@dataclass(frozen=True, slots=True)
class MemoryRow:
    """One retained memory item, as shown in the memory view."""

    id: str
    tier: Tier
    phase_tag: str
    salience: float
    age_s: float
    snippet: str
    hits: int = 0


@dataclass(frozen=True, slots=True)
class SalienceTerms:
    """Current coefficients of the salience decay model.

    The score for a row is::

        S = w_tier * s0 * exp(-lambda * age) + beta * hits

    The memory view renders this equation with these values substituted so the
    decay behaviour is legible during a demo.
    """

    tier_weight: dict[str, float]
    decay_lambda: float
    hit_bonus: float

    def score(self, row: MemoryRow) -> float:
        w = self.tier_weight.get(row.tier, 1.0)
        return w * row.salience * math.exp(-self.decay_lambda * row.age_s) + (
            self.hit_bonus * row.hits
        )

    def equation(self, row: MemoryRow | None = None) -> str:
        """The equation with live term values substituted."""
        if row is None:
            weights = " ".join(f"{k}={v:g}" for k, v in sorted(self.tier_weight.items()))
            return (
                f"S = w_tier · s₀ · e^(−λ·age) + β·hits"
                f"   λ={self.decay_lambda:g}  β={self.hit_bonus:g}  w_tier[{weights}]"
            )
        w = self.tier_weight.get(row.tier, 1.0)
        decay = math.exp(-self.decay_lambda * row.age_s)
        return (
            f"S = {w:g}·{row.salience:.2f}·e^(−{self.decay_lambda:g}·{row.age_s:.0f}s)"
            f" + {self.hit_bonus:g}·{row.hits}"
            f" = {w:g}·{row.salience:.2f}·{decay:.3f} + {self.hit_bonus * row.hits:.3f}"
            f" = {self.score(row):.3f}"
        )


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Event:
    seq: int = field(default_factory=_next_seq, kw_only=True)
    ts: float = field(default_factory=time.time, kw_only=True)


@dataclass(frozen=True, slots=True)
class RunStarted(_Event):
    run_id: str
    phase: str = "recon"
    framework: str = "PTES"


@dataclass(frozen=True, slots=True)
class RunFinished(_Event):
    run_id: str
    ok: bool = True


@dataclass(frozen=True, slots=True)
class Narration(_Event):
    """A chunk of model narration.

    ``entry_id`` groups chunks into one transcript entry. Chunks append to the
    existing entry in place; the widget is never rebuilt. ``done`` marks the
    final chunk for that entry.
    """

    entry_id: str
    text: str
    done: bool = False


@dataclass(frozen=True, slots=True)
class ToolStarted(_Event):
    call_id: str
    tool: str
    args: str = ""


@dataclass(frozen=True, slots=True)
class ToolOutput(_Event):
    """Raw tool output, streamed into the collapsed body of a tool entry."""

    call_id: str
    chunk: str


@dataclass(frozen=True, slots=True)
class ToolFinished(_Event):
    call_id: str
    summary: str = ""
    lines: int = 0
    tier: Tier | None = None
    score: float | None = None


@dataclass(frozen=True, slots=True)
class ToolFailed(_Event):
    call_id: str
    reason: str
    traceback: str = ""


@dataclass(frozen=True, slots=True)
class PhaseChanged(_Event):
    phase: str
    framework: str = "PTES"


@dataclass(frozen=True, slots=True)
class DEPGUpdated(_Event):
    nodes: tuple[DEPGNode, ...] = ()
    edges: tuple[DEPGEdge, ...] = ()


@dataclass(frozen=True, slots=True)
class MemoryUpdated(_Event):
    rows: tuple[MemoryRow, ...] = ()
    terms: SalienceTerms | None = None


@dataclass(frozen=True, slots=True)
class TokenDelta(_Event):
    """Token accounting. ``delta`` is tokens since the last event."""

    delta: int = 0
    total: int = 0
    ctx_used: int = 0
    ctx_max: int = 32_768


@dataclass(frozen=True, slots=True)
class Interrupted(_Event):
    reason: str = "user interrupt"


AgentEvent: TypeAlias = (
    RunStarted
    | RunFinished
    | Narration
    | ToolStarted
    | ToolOutput
    | ToolFinished
    | ToolFailed
    | PhaseChanged
    | DEPGUpdated
    | MemoryUpdated
    | TokenDelta
    | Interrupted
)

EVENT_TYPES: dict[str, type] = {
    cls.__name__: cls
    for cls in (
        RunStarted,
        RunFinished,
        Narration,
        ToolStarted,
        ToolOutput,
        ToolFinished,
        ToolFailed,
        PhaseChanged,
        DEPGUpdated,
        MemoryUpdated,
        TokenDelta,
        Interrupted,
    )
}

_VALUE_TYPES: dict[str, type] = {
    "Evidence": Evidence,
    "DEPGNode": DEPGNode,
    "DEPGEdge": DEPGEdge,
    "MemoryRow": MemoryRow,
    "SalienceTerms": SalienceTerms,
}


# --------------------------------------------------------------------------
# serialisation — used by the JSONL replay log
# --------------------------------------------------------------------------


def _plain(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        out: dict[str, Any] = {"__t": type(value).__name__}
        for f in fields(value):
            out[f.name] = _plain(getattr(value, f.name))
        return out
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


_TUPLE_FIELDS = {"nodes", "edges", "rows", "evidence"}


def _revive(value: Any) -> Any:
    if isinstance(value, dict) and "__t" in value:
        cls = _VALUE_TYPES[value["__t"]]
        kwargs = {k: _revive(v) for k, v in value.items() if k != "__t"}
        for name in _TUPLE_FIELDS & kwargs.keys():
            if isinstance(kwargs[name], list):
                kwargs[name] = tuple(kwargs[name])
        return cls(**kwargs)
    if isinstance(value, list):
        return [_revive(v) for v in value]
    if isinstance(value, dict):
        return {k: _revive(v) for k, v in value.items()}
    return value


def encode(event: AgentEvent) -> dict[str, Any]:
    """Serialise an event to a JSON-safe dict."""
    payload: dict[str, Any] = {"type": type(event).__name__}
    for f in fields(event):
        payload[f.name] = _plain(getattr(event, f.name))
    return payload


def decode(payload: dict[str, Any]) -> AgentEvent:
    """Rebuild an event from :func:`encode` output.

    Raises ``KeyError`` on an unknown event type so a malformed replay log
    fails loudly at load time rather than half-way through a demo.
    """
    data = dict(payload)
    type_name = data.pop("type")
    cls = EVENT_TYPES[type_name]
    kwargs = {k: _revive(v) for k, v in data.items()}
    for name in _TUPLE_FIELDS:
        if isinstance(kwargs.get(name), list):
            kwargs[name] = tuple(kwargs[name])
    return cls(**kwargs)  # type: ignore[return-value]


# --------------------------------------------------------------------------
# the agent seam
# --------------------------------------------------------------------------


@runtime_checkable
class Agent(Protocol):
    """What the TUI requires of an agent.

    The real LangGraph-backed core and the replay fake both satisfy this. The
    TUI holds nothing else: no graph handle, no model handle, no tool registry.
    """

    events: asyncio.Queue[AgentEvent]

    async def start(self) -> None:
        """Begin any background work. Called once, after the app mounts."""

    async def submit(self, text: str) -> None:
        """Accept a user turn. Must not block; emit events instead."""

    async def interrupt(self) -> None:
        """Cancel the running node. Should emit :class:`Interrupted`."""

    async def aclose(self) -> None:
        """Release resources. Called on app shutdown."""


async def drain(queue: asyncio.Queue[AgentEvent]) -> Iterable[AgentEvent]:
    """Pop every event currently queued, blocking for at least one."""
    first = await queue.get()
    batch = [first]
    while True:
        try:
            batch.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            return batch
