"""cism/depg/reducer.py: state is derived, never latched — the five branches,
plus resurrection and sticky self-failure."""

from __future__ import annotations

from cism.depg.evidence import Evidence
from cism.depg.node import Node
from cism.depg.reducer import BinarySupport, reduce_state


def _node(**kwargs) -> Node:
    defaults = dict(id="n", cause_class="c", target="t", signal="s")
    defaults.update(kwargs)
    return Node(**defaults)


def _ev(verdict: str) -> Evidence:
    return Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", source="deterministic", verdict=verdict)


def test_own_dead_evidence_blocks_regardless_of_parents() -> None:
    node = _node(evidence=[_ev("dead")])
    assert reduce_state(node, [], BinarySupport()) == "blocked"


def test_alive_with_support_resolves() -> None:
    node = _node(evidence=[_ev("alive")])
    parent = _node(id="p", state="resolved")
    assert reduce_state(node, [parent], BinarySupport()) == "resolved"


def test_alive_with_no_live_parent_is_contested_not_blocked() -> None:
    node = _node(evidence=[_ev("alive")])
    parent = _node(id="p", state="blocked")
    assert reduce_state(node, [parent], BinarySupport()) == "contested"


def test_pure_inference_with_support_is_untested() -> None:
    node = _node()
    parent = _node(id="p", state="resolved")
    assert reduce_state(node, [parent], BinarySupport()) == "untested"


def test_pure_inference_with_no_live_parent_is_blocked() -> None:
    node = _node()
    parent = _node(id="p", state="blocked")
    assert reduce_state(node, [parent], BinarySupport()) == "blocked"


def test_inconclusive_evidence_is_a_no_op() -> None:
    node = _node(evidence=[_ev("alive"), _ev("inconclusive")])
    assert reduce_state(node, [], BinarySupport()) == "resolved"


def test_a_revived_parent_lets_a_pure_inference_recover() -> None:
    node = _node()
    revived_parent = _node(id="p", state="resolved")
    assert reduce_state(node, [revived_parent], BinarySupport()) == "untested"


def test_own_direct_failure_stays_blocked_even_with_a_live_parent() -> None:
    node = _node(evidence=[_ev("dead")])
    parent = _node(id="p", state="resolved")
    assert reduce_state(node, [parent], BinarySupport()) == "blocked"


def test_no_parents_at_all_counts_as_supported() -> None:
    node = _node(evidence=[_ev("alive")])
    assert reduce_state(node, [], BinarySupport()) == "resolved"
