"""cism/depg/graph.py: Graph as the agent's mutable working copy of DEPG —
what happens when the same node id is proposed twice, what counts as a
root, and what to_event() hands the TUI.
"""

from __future__ import annotations

from cism.depg import Edge, Graph, Node
from cism.tui.events import Evidence


def test_a_new_graph_is_empty() -> None:
    graph = Graph()
    assert graph.nodes == {}
    assert graph.edges == []


def test_upserting_a_new_id_adds_it_to_the_graph() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="n1", cause_class="c", target="t"))
    assert "n1" in graph.nodes


def test_upserting_an_existing_id_accumulates_evidence_instead_of_replacing_it() -> None:
    graph = Graph()
    ev1 = Evidence(timestamp="12:00:00", tool="nmap", exit_signal="a", tier="T3")
    ev2 = Evidence(timestamp="12:00:05", tool="nmap", exit_signal="b", tier="T3")
    graph.upsert_node(Node(id="n1", cause_class="c", target="t", evidence=[ev1]))
    graph.upsert_node(Node(id="n1", cause_class="c", target="t", evidence=[ev2]))

    assert graph.nodes["n1"].evidence == [ev1, ev2]


def test_upserting_an_existing_id_can_advance_state_away_from_untested() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="n1", cause_class="c", target="t", state="untested"))
    graph.upsert_node(Node(id="n1", cause_class="c", target="t", state="resolved"))

    assert graph.nodes["n1"].state == "resolved"


def test_upserting_an_existing_id_never_regresses_an_already_advanced_state() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="n1", cause_class="c", target="t", state="resolved"))
    graph.upsert_node(Node(id="n1", cause_class="c", target="t", state="blocked"))

    assert graph.nodes["n1"].state == "resolved"


def test_add_edge_deduplicates_on_parent_and_child_keeping_the_latest_weight() -> None:
    graph = Graph()
    graph.add_edge(Edge(parent="a", child="b", weight=1.0))
    graph.add_edge(Edge(parent="a", child="b", weight=0.5))

    assert graph.edges == [Edge(parent="a", child="b", weight=0.5)]


def test_roots_excludes_any_node_with_an_incoming_edge() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="t"))
    graph.upsert_node(Node(id="b", cause_class="c", target="t"))
    graph.add_edge(Edge(parent="a", child="b"))

    assert [n.id for n in graph.roots()] == ["a"]


def test_to_event_projects_every_node_and_edge_to_wire_format() -> None:
    graph = Graph()
    node = Node(id="a", cause_class="c", target="t")
    edge = Edge(parent="a", child="a")
    graph.upsert_node(node)
    graph.add_edge(edge)

    nodes, edges = graph.to_event()

    assert nodes == (node.to_event(),)
    assert edges == (edge.to_event(),)
