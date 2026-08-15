"""cism/depg/: Node and Edge round-trip into the TUI's wire format."""

from __future__ import annotations

from cism.depg import Edge, Node
from cism.tui.events import DEPGEdge, DEPGNode, Decision, Evidence


def test_node_to_event_round_trips_scalar_fields() -> None:
    node = Node(
        id="n1",
        cause_class="unpatched-service",
        target="10.0.0.5:8080",
        generality=0.72,
        state="untested",
        downstream=3,
    )
    event = node.to_event()
    assert isinstance(event, DEPGNode)
    assert event.id == "n1"
    assert event.cause_class == "unpatched-service"
    assert event.target == "10.0.0.5:8080"
    assert event.generality == 0.72
    assert event.state == "untested"
    assert event.downstream == 3
    assert event.evidence == ()
    assert event.decision is None


def test_node_to_event_carries_evidence_as_a_tuple() -> None:
    ev = Evidence(timestamp="12:06:14", tool="nuclei", exit_signal="200", tier="T1")
    node = Node(id="n1", cause_class="c", target="t", evidence=[ev])
    event = node.to_event()
    assert event.evidence == (ev,)


def test_node_to_event_passes_decision_through() -> None:
    decision = Decision(timestamp="12:06:02", chose="jetty:8080", alternatives=5, score_gap=0.28)
    node = Node(id="n1", cause_class="c", target="t", decision=decision)
    assert node.to_event().decision is decision


def test_edge_to_event_round_trips() -> None:
    edge = Edge(parent="n1", child="n2", weight=0.4)
    event = edge.to_event()
    assert isinstance(event, DEPGEdge)
    assert event == DEPGEdge(parent="n1", child="n2", weight=0.4)


def test_node_and_edge_are_mutable() -> None:
    """Unlike the frozen wire-format dataclasses, these are the agent's
    working copy and must be updatable in place."""
    node = Node(id="n1", cause_class="c", target="t")
    node.state = "resolved"
    node.downstream += 1
    assert node.state == "resolved"
    assert node.downstream == 1
