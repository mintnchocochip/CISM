"""The agent-side working node of the Dependency / Error Propagation Graph.

This is the mutable copy the agent updates as a run progresses. It is a
different object from :class:`cism.tui.events.DEPGNode`, which is the
frozen, whole-state-replacement wire format the TUI consumes. ``to_event()``
is the only place this module touches ``cism.tui.events`` — nothing else in
this package may import from ``cism.tui`` or ``cism.agent``, so DEPG stays
independently testable and evolvable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cism.tui.events import Decision, DEPGNode, Evidence, NodeState

__all__ = ["Node"]


@dataclass(slots=True)
class Node:
    """A cause/target pair the agent is tracking, plus what it knows so far."""

    id: str
    cause_class: str
    target: str
    generality: float = 0.0
    state: NodeState = "untested"
    downstream: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    #: The choice that made this node current, if any.
    decision: Decision | None = None

    def to_event(self) -> DEPGNode:
        """Project this working node into the TUI's wire-format dataclass."""
        return DEPGNode(
            id=self.id,
            cause_class=self.cause_class,
            target=self.target,
            generality=self.generality,
            state=self.state,
            downstream=self.downstream,
            evidence=tuple(self.evidence),
            decision=self.decision,
        )
