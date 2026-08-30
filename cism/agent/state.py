"""The PTES-derived phase model and the LangGraph state schema.

``PhaseStateMachine.transition`` is the single choke point every phase
change in the graph must go through — ``nodes.py`` never assigns
``state["phase"]`` directly. That is deliberate: it is what makes future
phase locking a change to one method rather than a change to the graph.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Any, TypedDict

from langgraph.graph.message import add_messages

from cism.depg.edge import Edge
from cism.depg.node import Node
from cism.memory import MemoryItem

__all__ = [
    "AgentState",
    "IllegalPhaseTransition",
    "PHASE_TRANSITIONS",
    "Phase",
    "PhaseStateMachine",
]


class Phase(Enum):
    RECON = 1
    ENUMERATION = 2
    VULNERABILITY_DISCOVERY = 3
    EXPLOITATION = 4
    POST_EXPLOITATION = 5
    REPORTING = 6

    def to_wire(self) -> str:
        """The string form ``PhaseChanged.phase`` (cism.tui.events) expects."""
        return self.name.lower().replace("_", "-")


#: Legal next phases per phase, including staying put. Not a strict linear
#: sequence: real engagements pivot (post-exploitation on one host often
#: kicks off recon on another; a failed exploit sends you back to
#: vulnerability discovery), so those moves are legal — everything else
#: raises rather than being silently allowed.
PHASE_TRANSITIONS: dict[Phase, frozenset[Phase]] = {
    Phase.RECON: frozenset({Phase.RECON, Phase.ENUMERATION}),
    Phase.ENUMERATION: frozenset(
        {Phase.ENUMERATION, Phase.VULNERABILITY_DISCOVERY, Phase.RECON}
    ),
    Phase.VULNERABILITY_DISCOVERY: frozenset(
        {Phase.VULNERABILITY_DISCOVERY, Phase.EXPLOITATION, Phase.ENUMERATION}
    ),
    Phase.EXPLOITATION: frozenset(
        {Phase.EXPLOITATION, Phase.POST_EXPLOITATION, Phase.VULNERABILITY_DISCOVERY}
    ),
    Phase.POST_EXPLOITATION: frozenset(
        {Phase.POST_EXPLOITATION, Phase.REPORTING, Phase.RECON}
    ),
    Phase.REPORTING: frozenset({Phase.REPORTING}),
}


class IllegalPhaseTransition(ValueError):
    """Raised when a requested phase move is not in ``PHASE_TRANSITIONS``."""

    def __init__(self, current: Phase, requested: Phase) -> None:
        super().__init__(
            f"cannot transition from {current.name} to {requested.name}"
        )
        self.current = current
        self.requested = requested


@dataclass(slots=True)
class PhaseStateMachine:
    """Owns the current phase. ``transition`` is the only way it changes."""

    current: Phase = Phase.RECON

    def can_transition(self, to: Phase) -> bool:
        return to in PHASE_TRANSITIONS[self.current]

    def transition(self, to: Phase) -> Phase:
        if not self.can_transition(to):
            raise IllegalPhaseTransition(self.current, to)
        self.current = to
        return self.current


class AgentState(TypedDict):
    """The LangGraph state schema threaded through every node."""

    messages: Annotated[list[Any], add_messages]
    phase: Phase
    phase_changed: bool
    depg_nodes: dict[str, Node]
    depg_edges: list[Edge]
    memory_items: dict[str, MemoryItem]
    run_id: str
    target: str
