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


def test_a_node_with_two_incoming_edges_nests_under_the_same_parent_path_to_reports() -> None:
    """A second, later edge onto the same child wins in _parent_of (last
    edge wins) — the tree must nest the child under that same parent, not
    the first one, or the visible tree and the decision-path breadcrumb
    would disagree about where the node sits."""
    nodes = (_node("a"), _node("b"), _node("c"))
    edges = (
        DEPGEdge(parent="a", child="c", weight=0.5),
        DEPGEdge(parent="b", child="c", weight=0.5),
    )
    modal = DEPGModal(nodes, edges)

    assert modal._parent_of["c"] == "b"
    assert modal.path_to("c")[0].id == "b"

    tree_children = {}
    for edge in modal.edges:
        if modal._parent_of.get(edge.child) != edge.parent:
            continue
        tree_children.setdefault(edge.parent, []).append(edge.child)

    assert tree_children == {"b": ["c"]}
