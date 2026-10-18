"""The PTES-derived phase model and the LangGraph state schema.
``PhaseStateMachine.transition`` is the single choke point every phase
change must go through — ``nodes.py`` never assigns ``state["phase"]`` directly."""

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


#: Legal next phases per phase, including staying put. Not strictly linear —
#: real engagements pivot back (post-exploitation to recon, a failed exploit
#: back to vuln discovery) — everything else raises.
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
    #: Wire-format name of the next phase once phase_router has detected
    #: readiness, or None — the move itself is no longer applied
    #: automatically (2026-10-18: operator wants to approve it first via
    #: /phase <name>, which clears this). Persists across turns until
    #: approved or the run ends.
    phase_proposal: str | None
    #: True only on the one step phase_proposal was just set — the signal
    #: for the one-shot checkpoint/narration/memory side effects below,
    #: since phase_proposal itself stays truthy for many turns while
    #: outstanding and must not re-trigger them each time.
    phase_proposal_is_new: bool
    depg_nodes: dict[str, Node]
    depg_edges: list[Edge]
    memory_items: dict[str, MemoryItem]
    run_id: str
    target: str
    context_window: int
    #: set by think() each turn; how many older messages it dropped from the
    #: prompt to fit context_window (B2, AUDIT.md) — 0 when nothing was dropped.
    compacted: int
    #: True only when real (non-dummy) tools are bound — route_after_think
    #: uses this to gate the phase-change checkpoint stop (2026-10-18) to
    #: live engagements only. The scripted dummy-tool demo path
    #: deliberately races through multiple phase changes in one submit()
    #: with no human in the loop (AUDIT.md: a phase-advance-rate cap was
    #: tried and reverted for exactly this reason) — nothing to checkpoint
    #: there, since there's no real model decision to pause and redirect.
    live_tools: bool
