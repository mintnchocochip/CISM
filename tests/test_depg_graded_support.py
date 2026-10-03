"""cism/depg/reducer.py: GradedSupport's noisy-OR reachability score (AUDIT.md
A3) — the validation properties AUDIT.md calls for (monotonicity, boundary,
clamp, idempotence), plus the tier-provenance discount and settle()'s graded
path end to end via Graph.
"""

from __future__ import annotations

from cism.depg import Edge, Graph, GradedSupport, Node
from cism.depg.evidence import Evidence


def _node(**kwargs) -> Node:
    defaults = dict(id="n", cause_class="c", target="t", signal="s")
    defaults.update(kwargs)
    return Node(**defaults)


def _ev(verdict: str, tier: str = "T2", source: str = "deterministic") -> Evidence:
    return Evidence(timestamp="t", tool="x", exit_signal="y", tier=tier, source=source, verdict=verdict)


def test_no_evidence_no_parents_scores_the_untested_prior() -> None:
    state, score = GradedSupport().evaluate(_node(), [])
    assert state == "untested"
    assert score == 0.3


def test_own_dead_evidence_scores_zero_regardless_of_parents() -> None:
    node = _node(evidence=[_ev("dead")])
    parent = _node(id="p", reachability=1.0)
    state, score = GradedSupport().evaluate(node, [(parent, 1.0)])
    assert state == "blocked"
    assert score == 0.0


def test_alive_t1_deterministic_with_no_parents_resolves_at_full_score() -> None:
    node = _node(evidence=[_ev("alive", tier="T1", source="deterministic")])
    state, score = GradedSupport().evaluate(node, [])
    assert state == "resolved"
    assert score == 1.0


def test_llm_asserted_tier_scores_lower_than_the_same_deterministic_tier() -> None:
    deterministic = _node(evidence=[_ev("alive", tier="T1", source="deterministic")])
    llm = _node(evidence=[_ev("alive", tier="T1", source="llm")])
    _, det_score = GradedSupport().evaluate(deterministic, [])
    _, llm_score = GradedSupport().evaluate(llm, [])
    assert llm_score < det_score


def test_unverified_source_is_also_discounted_like_llm() -> None:
    llm = _node(evidence=[_ev("alive", tier="T3", source="llm")])
    unverified = _node(evidence=[_ev("alive", tier="T3", source="unverified")])
    deterministic = _node(evidence=[_ev("alive", tier="T3", source="deterministic")])
    _, llm_score = GradedSupport().evaluate(llm, [])
    _, unverified_score = GradedSupport().evaluate(unverified, [])
    _, det_score = GradedSupport().evaluate(deterministic, [])
    assert llm_score == unverified_score
    assert llm_score < det_score


def test_alive_evidence_with_a_fully_dead_parent_is_contested_not_blocked() -> None:
    node = _node(evidence=[_ev("alive", tier="T1")])
    dead_parent = _node(id="p", reachability=0.0)
    state, score = GradedSupport().evaluate(node, [(dead_parent, 1.0)])
    assert state == "contested"
    assert score == 0.0  # a single fully-dead parent at weight 1.0 contributes no support


def test_no_evidence_with_a_fully_dead_parent_is_blocked() -> None:
    node = _node()
    dead_parent = _node(id="p", reachability=0.0)
    state, score = GradedSupport().evaluate(node, [(dead_parent, 1.0)])
    assert state == "blocked"
    assert score <= 0.15


def test_score_is_monotonic_adding_a_live_parent_never_lowers_it() -> None:
    node = _node()
    dead_parent = _node(id="p1", reachability=0.0)
    live_parent = _node(id="p2", reachability=1.0)

    _, before = GradedSupport().evaluate(node, [(dead_parent, 1.0)])
    _, after = GradedSupport().evaluate(node, [(dead_parent, 1.0), (live_parent, 1.0)])

    assert after >= before


def test_score_is_monotonic_increasing_edge_weight_never_lowers_it() -> None:
    node = _node()
    parent = _node(id="p", reachability=1.0)

    _, low_weight = GradedSupport().evaluate(node, [(parent, 0.2)])
    _, high_weight = GradedSupport().evaluate(node, [(parent, 0.9)])

    assert high_weight >= low_weight


def test_score_clamps_to_one_even_with_many_strong_parents() -> None:
    node = _node(evidence=[_ev("alive", tier="T1")])
    parents = [(_node(id=f"p{i}", reachability=1.0), 1.0) for i in range(5)]

    _, score = GradedSupport().evaluate(node, parents)

    assert score <= 1.0


def test_score_clamps_to_zero_floor_even_with_an_out_of_range_weight() -> None:
    node = _node()
    parent = _node(id="p", reachability=1.0)

    _, score = GradedSupport().evaluate(node, [(parent, -5.0)])

    assert score >= 0.0


def test_edge_weight_changes_the_score_unlike_binary_support() -> None:
    """The bug AUDIT.md A3 flags: BinarySupport ignores Edge.weight entirely.
    Both "a" and "b" get real evidence (not a hand-set .reachability, which
    settle() would just recompute and overwrite since "a" is dirty too) —
    the weight difference must still show up after a full settle() drains
    the frontier to its fixed point, regardless of visit order."""
    graph_low = Graph()
    graph_low.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[_ev("alive", tier="T1")]))
    graph_low.upsert_node(Node(id="b", cause_class="c", target="t", signal="b", evidence=[_ev("alive", tier="T1")]))
    graph_low.add_edge(Edge(parent="a", child="b", weight=0.1))
    graph_low.settle(support=GradedSupport())

    graph_high = Graph()
    graph_high.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[_ev("alive", tier="T1")]))
    graph_high.upsert_node(Node(id="b", cause_class="c", target="t", signal="b", evidence=[_ev("alive", tier="T1")]))
    graph_high.add_edge(Edge(parent="a", child="b", weight=1.0))
    graph_high.settle(support=GradedSupport())

    assert graph_high.nodes["b"].reachability > graph_low.nodes["b"].reachability


def test_settle_with_graded_support_resolves_a_root_with_alive_evidence() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="s", evidence=[_ev("alive", tier="T1")]))

    graph.settle(support=GradedSupport())

    assert graph.nodes["a"].state == "resolved"
    assert graph.nodes["a"].reachability == 1.0


def test_settle_with_graded_support_is_idempotent() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="s", evidence=[_ev("alive", tier="T2")]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b", weight=0.7))

    graph.settle(support=GradedSupport())
    first_state = graph.nodes["b"].state
    first_score = graph.nodes["b"].reachability

    graph.settle(support=GradedSupport())

    assert graph.nodes["b"].state == first_state
    assert graph.nodes["b"].reachability == first_score


def test_binary_support_stays_the_default_and_ignores_weight() -> None:
    """graph.settle() with no support argument must still be BinarySupport —
    GradedSupport is opt-in only until validated against a real run."""
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[_ev("alive", tier="T2")]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b", weight=0.01))

    graph.settle()

    assert graph.nodes["b"].state == "untested"
    assert graph.nodes["b"].reachability == 0.3
