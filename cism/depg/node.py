"""The agent-side working node of the Dependency / Error Propagation Graph
— the mutable copy the agent updates, distinct from :class:`cism.tui.
events.DEPGNode`, the frozen wire format. ``id`` is a derived identity key,
not a tool_call_id (see :func:`derive_node_id`); ``state`` is only ever
written by :meth:`cism.depg.graph.Graph.settle`."""

from __future__ import annotations

from dataclasses import dataclass, field

from cism.depg.evidence import Evidence
from cism.tui.events import Decision, DEPGNode, NodeState

__all__ = ["Node", "derive_node_id"]


def derive_node_id(cause_class: str, target: str, signal: str) -> str:
    """Two observations merge only when all three match — this is what stops
    "port 22" and "port 80" on the same host colliding into one node just
    because they share a cause_class and target."""
    return f"{cause_class}:{target}:{signal}"


@dataclass(slots=True)
class Node:
    """A cause/target pair the agent is tracking, plus what it knows so far."""

    id: str
    cause_class: str
    target: str
    signal: str
    evidence: list[Evidence] = field(default_factory=list)
    decision: Decision | None = None
    state: NodeState = "untested"
    generality: float = 0.0
    downstream: int = 0
    phase: str = ""
    #: GradedSupport's continuous score (reducer.py) — unused/stale under
    #: BinarySupport. Default matches _UNTESTED_PRIOR: an ungraded node reads
    #: as "unproven", not "impossible".
    reachability: float = 0.3

    def to_event(self) -> DEPGNode:
        return DEPGNode(
            id=self.id,
            cause_class=self.cause_class,
            target=self.target,
            generality=self.generality,
            state=self.state,
            downstream=self.downstream,
            evidence=tuple(e.to_event() for e in self.evidence),
            decision=self.decision,
            signal=self.signal,
        )
