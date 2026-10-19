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
    ev1 = Evidence(timestamp="12:00:00", tool="nmap", exit_signal="a", tier="T3", source="deterministic")
    ev2 = Evidence(timestamp="12:00:05", tool="nmap", exit_signal="b", tier="T3", source="deterministic")
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
    ev = Evidence(timestamp="t", tool="nmap", exit_signal="x", tier="T2", source="deterministic", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="s", evidence=[ev]))

    graph.settle()

    assert graph.nodes["a"].state == "resolved"


def test_settle_blocks_a_root_with_dead_evidence() -> None:
    graph = Graph()
    ev = Evidence(timestamp="t", tool="nmap", exit_signal="x", tier="T3", source="deterministic", verdict="dead")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="s", evidence=[ev]))

    graph.settle()

    assert graph.nodes["a"].state == "blocked"


def test_a_strong_child_survives_a_dead_parent_as_contested() -> None:
    graph = Graph()
    parent_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", source="deterministic", verdict="dead")
    child_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T1", source="deterministic", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[parent_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b", evidence=[child_ev]))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.settle()

    assert graph.nodes["a"].state == "blocked"
    assert graph.nodes["b"].state == "contested"


def test_a_pure_inference_child_is_blocked_when_its_only_parent_dies() -> None:
    graph = Graph()
    parent_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", source="deterministic", verdict="dead")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[parent_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.settle()

    assert graph.nodes["b"].state == "blocked"


def test_a_child_with_one_dead_and_one_live_parent_survives() -> None:
    graph = Graph()
    dead_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", source="deterministic", verdict="dead")
    live_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", source="deterministic", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[dead_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b", evidence=[live_ev]))
    graph.upsert_node(Node(id="x", cause_class="c", target="t", signal="x"))
    graph.add_edge(Edge(parent="a", child="x"))
    graph.add_edge(Edge(parent="b", child="x"))

    graph.settle()

    assert graph.nodes["x"].state == "untested"


def test_a_revived_parent_lets_a_blocked_inference_child_recover() -> None:
    graph = Graph()
    dead_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", source="deterministic", verdict="dead")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[dead_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b"))
    graph.settle()
    assert graph.nodes["b"].state == "blocked"

    alive_ev = Evidence(timestamp="t2", tool="x", exit_signal="y", tier="T2", source="deterministic", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[alive_ev]))
    graph.settle()

    assert graph.nodes["a"].state == "resolved"
    assert graph.nodes["b"].state == "untested"


def test_a_self_inflicted_block_survives_an_upstream_fix() -> None:
    graph = Graph()
    alive_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", source="deterministic", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[alive_ev]))
    own_failure = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T3", source="deterministic", verdict="dead")
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

    ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", source="deterministic", verdict="alive")
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


def _blocked(id: str, target: str = "t") -> Node:
    node = Node(id=id, cause_class="c", target=target, signal=id, state="blocked")
    return node


def test_prune_collapses_a_fully_blocked_chain_into_one_marker() -> None:
    graph = Graph()
    graph.nodes = {"a": _blocked("a"), "b": _blocked("b"), "c": _blocked("c")}
    graph.add_edge(Edge(parent="a", child="b"))
    graph.add_edge(Edge(parent="b", child="c"))

    graph.prune()

    assert set(graph.nodes) - {"a", "b", "c"}
    assert not ({"a", "b", "c"} & set(graph.nodes))
    (marker,) = graph.nodes.values()
    assert marker.cause_class == "dead-region"
    assert marker.state == "blocked"
    assert "a" in marker.evidence[-1].exit_signal
    assert "b" in marker.evidence[-1].exit_signal
    assert "c" in marker.evidence[-1].exit_signal


def test_prune_leaves_a_region_alone_if_it_still_feeds_a_live_node() -> None:
    graph = Graph()
    graph.nodes = {
        "a": _blocked("a"),
        "b": _blocked("b"),
        "live": Node(id="live", cause_class="c", target="t", signal="live", state="resolved"),
    }
    graph.add_edge(Edge(parent="a", child="b"))
    graph.add_edge(Edge(parent="b", child="live"))

    graph.prune()

    assert {"a", "b", "live"} == set(graph.nodes)


def test_prune_rewires_a_live_ancestor_edge_onto_the_marker() -> None:
    graph = Graph()
    graph.nodes = {
        "live": Node(id="live", cause_class="c", target="t", signal="live", state="resolved"),
        "a": _blocked("a"),
        "b": _blocked("b"),
    }
    graph.add_edge(Edge(parent="live", child="a"))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.prune()

    remaining_ids = set(graph.nodes) - {"live"}
    (marker_id,) = remaining_ids
    assert Edge(parent="live", child=marker_id) in [
        Edge(parent=e.parent, child=e.child) for e in graph.edges
    ]


def test_prune_is_idempotent_on_an_already_settled_marker() -> None:
    """2026-10-18, live: calling prune() again on a graph whose only blocked
    node is already a dead-region marker re-wrapped it in a brand new
    marker every time -- across a long engagement (prune runs once per
    tick) the same marker got nested 8 levels deep, ballooning its id and
    evidence string on every tick for the rest of the run."""
    graph = Graph()
    graph.nodes = {"a": _blocked("a"), "b": _blocked("b")}
    graph.add_edge(Edge(parent="a", child="b"))
    graph.prune()
    (marker_id,) = graph.nodes
    first_marker = graph.nodes[marker_id]

    graph.prune()

    assert set(graph.nodes) == {marker_id}
    assert graph.nodes[marker_id] is first_marker


def test_prune_still_absorbs_a_new_dead_node_attached_to_an_existing_marker() -> None:
    graph = Graph()
    graph.nodes = {"a": _blocked("a"), "b": _blocked("b")}
    graph.add_edge(Edge(parent="a", child="b"))
    graph.prune()
    (marker_id,) = graph.nodes

    graph.upsert_node(_blocked("c"))
    graph.add_edge(Edge(parent=marker_id, child="c"))
    graph.prune()

    (new_marker_id,) = graph.nodes
    assert new_marker_id != marker_id
    assert "c" in graph.nodes[new_marker_id].evidence[-1].exit_signal


def test_compute_metrics_counts_transitive_descendants_once_in_a_diamond() -> None:
    graph = Graph()
    for node_id in ("a", "b", "c", "d"):
        graph.upsert_node(Node(id=node_id, cause_class="c", target="t", signal=node_id))
    graph.add_edge(Edge(parent="a", child="b"))
    graph.add_edge(Edge(parent="a", child="c"))
    graph.add_edge(Edge(parent="b", child="d"))
    graph.add_edge(Edge(parent="c", child="d"))

    graph.compute_metrics()

    assert graph.nodes["a"].downstream == 3
    assert graph.nodes["b"].downstream == 1
    assert graph.nodes["d"].downstream == 0


def test_compute_metrics_generality_is_the_cross_target_transfer_fraction() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a1", cause_class="open-port", target="10.0.0.1", signal="a1"))
    graph.upsert_node(Node(id="a2", cause_class="open-port", target="10.0.0.2", signal="a2"))
    graph.upsert_node(Node(id="b1", cause_class="rare-finding", target="10.0.0.1", signal="b1"))

    graph.compute_metrics()

    assert graph.nodes["a1"].generality == 1.0
    assert graph.nodes["a2"].generality == 1.0
    assert graph.nodes["b1"].generality == 0.5


def test_compute_metrics_generality_collapses_to_one_on_a_single_target_run() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a"))

    graph.compute_metrics()

    assert graph.nodes["a"].generality == 1.0


def test_compute_metrics_ignores_nodes_a_prior_prune_already_collapsed() -> None:
    graph = Graph()
    graph.nodes = {"a": _blocked("a"), "b": _blocked("b")}
    graph.add_edge(Edge(parent="a", child="b"))
    graph.prune()

    graph.compute_metrics()

    (marker,) = graph.nodes.values()
    assert marker.downstream == 0
