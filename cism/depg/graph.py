"""The agent's working copy of the whole graph: nodes keyed by id, edges as
a list, plus the handful of operations every caller needs (merge a node in,
project to wire events). Centralizing these here means callers like
``depg_update`` never reimplement "have I seen this id before" themselves.
"""

from __future__ import annotations

from cism.depg.edge import Edge
from cism.depg.node import Node
from cism.tui.events import DEPGEdge, DEPGNode

__all__ = ["Graph"]


class Graph:
    def __init__(
        self,
        nodes: dict[str, Node] | None = None,
        edges: list[Edge] | None = None,
    ) -> None:
        self.nodes: dict[str, Node] = dict(nodes) if nodes else {}
        self.edges: list[Edge] = list(edges) if edges else []

    @classmethod
    def from_state(cls, nodes: dict[str, Node], edges: list[Edge]) -> Graph:
        """Seeds a working copy from ``AgentState``'s ``depg_nodes``/
        ``depg_edges`` by copying rather than aliasing, so mutating the
        working copy never touches the state snapshot a caller may still be
        holding onto."""
        return cls(dict(nodes), list(edges))

    def upsert_node(self, node: Node) -> Node:
        """Inserts a new node, or merges onto an existing one with the same
        id: evidence accumulates, a newer decision replaces the old one, and
        state only ever advances away from "untested" — an extractor never
        gets to regress a node that's already been marked resolved/blocked."""
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node

        existing.evidence.extend(node.evidence)
        if node.decision is not None:
            existing.decision = node.decision
        if existing.state == "untested" and node.state != "untested":
            existing.state = node.state
        return existing

    def add_edge(self, edge: Edge) -> None:
        """De-dupes on ``(parent, child)``; a later weight for the same pair
        replaces the earlier one instead of creating a duplicate edge."""
        for i, existing in enumerate(self.edges):
            if existing.parent == edge.parent and existing.child == edge.child:
                self.edges[i] = edge
                return
        self.edges.append(edge)

    def roots(self) -> list[Node]:
        """Nodes with no incoming edge."""
        children = {e.child for e in self.edges}
        return [n for node_id, n in self.nodes.items() if node_id not in children]

    def to_event(self) -> tuple[tuple[DEPGNode, ...], tuple[DEPGEdge, ...]]:
        """The sole projection point from this mutable working copy to the
        frozen wire-format tuples ``DEPGUpdated`` carries."""
        return (
            tuple(n.to_event() for n in self.nodes.values()),
            tuple(e.to_event() for e in self.edges),
        )
