"""cism/tui/widgets/depg_modal.py: a contested node must not crash rendering
and must resolve to a distinct style, not silently fall back to another
state's color."""

from __future__ import annotations

from cism.tui.events import DEPGEdge, DEPGNode
from cism.tui.widgets.depg_modal import DEPGModal, STATE_CLASS


def test_contested_has_its_own_style_class() -> None:
    assert "contested" in STATE_CLASS
    assert STATE_CLASS["contested"] not in (
        STATE_CLASS["blocked"], STATE_CLASS["resolved"], STATE_CLASS["untested"],
    )


def _node(node_id: str) -> DEPGNode:
    return DEPGNode(id=node_id, cause_class="open-port", target="10.0.0.5", generality=0.0, state="untested")


def test_a_node_with_two_incoming_edges_keeps_both_instead_of_dropping_one() -> None:
    """E2 (AUDIT.md): the highest-weight edge becomes the primary parent
    (tie-broken on parent id); the rest are kept in _extra_parents rather
    than silently discarded."""
    nodes = (_node("a"), _node("b"), _node("c"))
    edges = (
        DEPGEdge(parent="a", child="c", weight=0.3),
        DEPGEdge(parent="b", child="c", weight=0.7),
    )
    modal = DEPGModal(nodes, edges)

    assert modal._parent_of["c"] == "b"
    assert modal.path_to("c")[0].id == "b"
    assert modal._extra_parents["c"] == [("a", 0.3)]


def test_a_weight_tie_is_broken_deterministically_by_parent_id() -> None:
    nodes = (_node("a"), _node("b"), _node("c"))
    edges = (
        DEPGEdge(parent="b", child="c", weight=0.5),
        DEPGEdge(parent="a", child="c", weight=0.5),
    )
    modal = DEPGModal(nodes, edges)

    assert modal._parent_of["c"] == "a"
    assert modal._extra_parents["c"] == [("b", 0.5)]


def test_a_pure_cycle_with_no_root_still_renders_every_node() -> None:
    """E3 (AUDIT.md): a component where every node has a parent (a cycle
    with no external entry point) used to vanish from the view entirely."""
    nodes = (_node("a"), _node("b"), _node("c"))
    edges = (
        DEPGEdge(parent="a", child="b", weight=0.5),
        DEPGEdge(parent="b", child="c", weight=0.5),
        DEPGEdge(parent="c", child="a", weight=0.5),
    )
    modal = DEPGModal(nodes, edges)

    assert modal._parent_of.keys() == {"a", "b", "c"}
    roots = [node for node in modal.nodes if node.id not in modal._parent_of]
    assert roots == []
