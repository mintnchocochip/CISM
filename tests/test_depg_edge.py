"""cism/depg/edge.py: the agent-side Edge and its projection into the
TUI's frozen DEPGEdge wire format."""

from __future__ import annotations

from cism.depg.edge import Edge
from cism.tui.events import DEPGEdge


def test_to_event_projects_parent_child_and_weight() -> None:
    edge = Edge(parent="p1", child="c1", weight=0.75)

    event = edge.to_event()

    assert event == DEPGEdge(parent="p1", child="c1", weight=0.75)


def test_weight_defaults_to_one() -> None:
    edge = Edge(parent="p1", child="c1")

    assert edge.weight == 1.0
    assert edge.to_event().weight == 1.0
