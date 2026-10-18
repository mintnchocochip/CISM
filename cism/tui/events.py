"""The event contract between the CISM agent core and the terminal UI.

The TUI is a pure consumer: the agent pushes frozen dataclasses onto an
``asyncio.Queue`` and the TUI drains it, never calling back into LangGraph,
llama.cpp, or the scorer. Every event carries a monotonic ``seq`` and a
wall-clock ``ts`` so a run can be recorded, diffed, and replayed."""

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
    "Decision",
    "EVENT_TYPES",
    "Evidence",
    "ModelInfo",
    "SessionState",
    "Interrupted",
    "MemoryRow",
    "MemoryUpdated",
    "Narration",
    "NarrationRedacted",
    "PhaseChanged",
    "PhaseProposed",
    "RunFinished",
    "RunStarted",
    "SalienceTerms",
    "ScopeChanged",
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

NodeState: TypeAlias = Literal["blocked", "resolved", "untested", "contested"]
Tier: TypeAlias = Literal["T1", "T2", "T3"]


@dataclass(frozen=True, slots=True)
class Evidence:
    """One observation attached to a DEPG node."""

    timestamp: str
    tool: str
    exit_signal: str
    tier: Tier


@dataclass(frozen=True, slots=True)
class Decision:
    """A choice the agent made on the way to a node. ``score_gap`` is the
    margin over the runner-up — small means it nearly went elsewhere."""

    timestamp: str
    chose: str
    alternatives: int = 0
    score_gap: float = 0.0
    tokens: int = 0
    rationale: str = ""


@dataclass(frozen=True, slots=True)
class ModelInfo:
    """One model the session can switch to."""

    name: str
    params: str = ""
    context: int = 0
    loaded: bool = False


@dataclass(frozen=True, slots=True)
class DEPGNode:
    """A node in the Dependency / Error Propagation Graph. ``generality`` is
    gamma: how far a cause-class transfers to sibling targets. ``downstream``
    counts nodes whose reachability depends on this one resolving."""

    id: str
    cause_class: str
    target: str
    generality: float
    state: NodeState
    downstream: int = 0
    evidence: tuple[Evidence, ...] = ()
    #: The choice that made this node current — not the whole decision trail.
    decision: Decision | None = None
    #: The specific fact distinguishing this node from siblings that share
    #: cause_class and target (e.g. which port, for a batch of open-port
    #: nodes on the same host) — see derive_node_id. Defaulted/trailing so
    #: existing positional construction keeps working; "" renders as before.
    signal: str = ""

    def label(self) -> str:
        signal = f" ({self.signal})" if self.signal else ""
        return (
            f"[{self.cause_class}] {self.target}{signal} "
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
    """Current coefficients of the salience decay model:
    ``S = w_tier * s0 * exp(-lambda * age) + beta * hits``."""

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
    #: H3 metrics surface — folded onto the event that already closes every
    #: run, rather than a second log line, so the 1:1 event<->log-line
    #: invariant (see cism.agent.logging) stays exactly true.
    tool_calls: int = 0
    tool_failures: int = 0
    guardrail_blocks: int = 0
    extraction_fallbacks: int = 0
    tokens_total: int = 0


@dataclass(frozen=True, slots=True)
class Narration(_Event):
    """A chunk of model narration. ``entry_id`` groups chunks into one
    transcript entry, appended in place; ``done`` marks the final chunk."""

    entry_id: str
    text: str
    done: bool = False


@dataclass(frozen=True, slots=True)
class NarrationRedacted(_Event):
    """Replaces what's shown for ``entry_id`` with a withheld notice — for
    when the output guardrail's verdict differs from what already streamed."""

    entry_id: str = ""
    reason: str = ""


@dataclass(frozen=True, slots=True)
class NarrationRetracted(_Event):
    """Cuts the last ``chars`` characters shown for ``entry_id`` — a
    discarded retry attempt's leaked output. Unlike NarrationRedacted, the
    entry stays live; more chunks (the accepted attempt's) still follow."""

    entry_id: str = ""
    chars: int = 0


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
class PhaseProposed(_Event):
    """phase_router detected readiness to move into `phase` but, unlike the
    old auto-apply behavior, hasn't applied it — the operator confirms via
    /phase <name> (which emits PhaseChanged) or it just sits pending."""

    phase: str
    framework: str = "PTES"


@dataclass(frozen=True, slots=True)
class ScopeChanged(_Event):
    """A /scope add or remove that actually changed the live scope; listing
    and no-op/error paths use a plain Narration instead."""

    action: str  # "add" or "remove"
    target: str


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


@dataclass(frozen=True, slots=True)
class SessionState(_Event):
    """Model, endpoint, and target environment. ``key_env_var`` names the
    API key variable; ``key_present`` says whether it's set — the key
    itself never travels here, since transcripts get exported."""

    model: str = ""
    models_available: tuple[ModelInfo, ...] = ()
    endpoint: str = "local"
    key_env_var: str = ""
    key_present: bool = False
    target_os: str = ""
    target_stack: tuple[str, ...] = ()


AgentEvent: TypeAlias = (
    RunStarted
    | RunFinished
    | Narration
    | NarrationRedacted
    | ToolStarted
    | ToolOutput
    | ToolFinished
    | ToolFailed
    | PhaseChanged
    | PhaseProposed
    | ScopeChanged
    | DEPGUpdated
    | MemoryUpdated
    | TokenDelta
    | Interrupted
    | SessionState
)

EVENT_TYPES: dict[str, type] = {
    cls.__name__: cls
    for cls in (
        RunStarted,
        RunFinished,
        Narration,
        NarrationRedacted,
        ToolStarted,
        ToolOutput,
        ToolFinished,
        ToolFailed,
        PhaseChanged,
        PhaseProposed,
        ScopeChanged,
        DEPGUpdated,
        MemoryUpdated,
        TokenDelta,
        Interrupted,
        SessionState,
    )
}

_VALUE_TYPES: dict[str, type] = {
    "Evidence": Evidence,
    "Decision": Decision,
    "ModelInfo": ModelInfo,
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


_TUPLE_FIELDS = {
    "nodes",
    "edges",
    "rows",
    "evidence",
    "models_available",
    "target_stack",
}


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
