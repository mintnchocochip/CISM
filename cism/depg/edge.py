"""The agent-side working edge — see :mod:`cism.depg.node` for why this is
a separate, mutable type from ``cism.tui.events.DEPGEdge``."""

from __future__ import annotations

from dataclasses import dataclass

from cism.tui.events import DEPGEdge

__all__ = ["Edge"]


@dataclass(slots=True)
class Edge:
    """A directed propagation edge. ``weight`` is the propagation coefficient."""

    parent: str
    child: str
    weight: float = 1.0

    def to_event(self) -> DEPGEdge:
        """Project this working edge into the TUI's wire-format dataclass."""
        return DEPGEdge(parent=self.parent, child=self.child, weight=self.weight)
