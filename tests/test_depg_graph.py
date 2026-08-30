"""cism/depg/graph.py: Graph as the agent's mutable working copy of DEPG —
what happens when the same node id is proposed twice, what counts as a
root, and what to_event() hands the TUI.
"""

from __future__ import annotations

from cism.depg import Edge, Graph, Node
from cism.depg.evidence import Evidence


def test_a_new_graph_is_empty() -> None:
    graph = Graph()
    assert graph.nodes == {}
    assert graph.edges == []


def test_upserting_a_new_id_adds_it_to_the_graph() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="n1", cause_class="c", target="t", signal="s"))
    assert "n1" in graph.nodes


def test_upserting_an_existing_id_accumulates_evidence_instead_of_replacing_it() -> None:
    graph = Graph()
    ev1 = Evidence(timestamp="12:00:00", tool="nmap", exit_signal="a", tier="T3")
    ev2 = Evidence(timestamp="12:00:05", tool="nmap", exit_signal="b", tier="T3")
    graph.upsert_node(Node(id="n1", cause_class="c", target="t", signal="s", evidence=[ev1]))
    graph.upsert_node(Node(id="n1", cause_class="c", target="t", signal="s", evidence=[ev2]))

    assert graph.nodes["n1"].evidence == [ev1, ev2]


def test_add_edge_deduplicates_on_parent_and_child_keeping_the_latest_weight() -> None:
    graph = Graph()
    graph.add_edge(Edge(parent="a", child="b", weight=1.0))
    graph.add_edge(Edge(parent="a", child="b", weight=0.5))

    assert graph.edges == [Edge(parent="a", child="b", weight=0.5)]


def test_roots_excludes_any_node_with_an_incoming_edge() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a"))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b"))

    assert [n.id for n in graph.roots()] == ["a"]


def test_to_event_projects_every_node_and_edge_to_wire_format() -> None:
    graph = Graph()
    parent = Node(id="a", cause_class="c", target="t", signal="a")
    child = Node(id="b", cause_class="c", target="t", signal="b")
    edge = Edge(parent="a", child="b")
    graph.upsert_node(parent)
    graph.upsert_node(child)
    graph.add_edge(edge)

    nodes, edges = graph.to_event()

    assert nodes == (parent.to_event(), child.to_event())
    assert edges == (edge.to_event(),)


def test_settle_resolves_a_root_with_alive_evidence() -> None:
    graph = Graph()
    ev = Evidence(timestamp="t", tool="nmap", exit_signal="x", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="s", evidence=[ev]))

    graph.settle()

    assert graph.nodes["a"].state == "resolved"


def test_settle_blocks_a_root_with_dead_evidence() -> None:
    graph = Graph()
    ev = Evidence(timestamp="t", tool="nmap", exit_signal="x", tier="T3", verdict="dead")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="s", evidence=[ev]))

    graph.settle()

    assert graph.nodes["a"].state == "blocked"


def test_a_strong_child_survives_a_dead_parent_as_contested() -> None:
    graph = Graph()
    parent_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="dead")
    child_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T1", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[parent_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b", evidence=[child_ev]))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.settle()

    assert graph.nodes["a"].state == "blocked"
    assert graph.nodes["b"].state == "contested"


def test_a_pure_inference_child_is_blocked_when_its_only_parent_dies() -> None:
    graph = Graph()
    parent_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="dead")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[parent_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.settle()

    assert graph.nodes["b"].state == "blocked"


def test_a_child_with_one_dead_and_one_live_parent_survives() -> None:
    graph = Graph()
    dead_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="dead")
    live_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[dead_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b", evidence=[live_ev]))
    graph.upsert_node(Node(id="x", cause_class="c", target="t", signal="x"))
    graph.add_edge(Edge(parent="a", child="x"))
    graph.add_edge(Edge(parent="b", child="x"))

    graph.settle()

    assert graph.nodes["x"].state == "untested"


def test_a_revived_parent_lets_a_blocked_inference_child_recover() -> None:
    graph = Graph()
    dead_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="dead")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[dead_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b"))
    graph.settle()
    assert graph.nodes["b"].state == "blocked"

    alive_ev = Evidence(timestamp="t2", tool="x", exit_signal="y", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[alive_ev]))
    graph.settle()

    assert graph.nodes["a"].state == "resolved"
    assert graph.nodes["b"].state == "untested"


def test_a_self_inflicted_block_survives_an_upstream_fix() -> None:
    graph = Graph()
    alive_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[alive_ev]))
    own_failure = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T3", verdict="dead")
    graph.upsert_node(Node(id="d", cause_class="c", target="t", signal="d", evidence=[own_failure]))
    graph.add_edge(Edge(parent="a", child="d"))

    graph.settle()

    assert graph.nodes["d"].state == "blocked"


def test_settle_only_walks_the_dirty_frontier() -> None:
    """An unrelated node's state is untouched by settling a different one."""
    graph = Graph()
    graph.upsert_node(Node(id="untouched", cause_class="c", target="t1", signal="s"))
    graph.settle()
    assert graph.nodes["untouched"].state == "untested"

    ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="other", cause_class="c", target="t2", signal="o", evidence=[ev]))
    graph.settle()

    assert graph.nodes["untouched"].state == "untested"
    assert graph.nodes["other"].state == "resolved"


def test_add_edge_rejects_a_cycle() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a"))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.add_edge(Edge(parent="b", child="a"))

    assert Edge(parent="b", child="a") not in graph.edges


def test_last_for_target_tracks_the_most_recently_touched_node() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="10.0.0.5", signal="a"))
    graph.upsert_node(Node(id="b", cause_class="c", target="10.0.0.5", signal="b"))

    assert graph.last_for_target["10.0.0.5"] == "b"
