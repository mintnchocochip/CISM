"""cism/depg/graph.py — the agent's mutable working copy of the DEPG: node
identity/merge, edges with cycle rejection, and the dirty-frontier state
settle. Pruning of fully-dead regions is Task 5, in this same file.
"""

from __future__ import annotations

from collections import deque

from cism.depg.edge import Edge
from cism.depg.node import Node
from cism.depg.reducer import BinarySupport, SupportPolicy, reduce_state
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
        self.last_for_target: dict[str, str] = {}
        self._children: dict[str, list[str]] = {}
        self._parents: dict[str, list[str]] = {}
        self._dirty: set[str] = set()
        for edge in self.edges:
            self._index_edge(edge)

    @classmethod
    def from_state(cls, nodes: dict[str, Node], edges: list[Edge]) -> Graph:
        """Seeds a working copy by copying rather than aliasing, so mutating
        it never touches the state snapshot a caller may still be holding."""
        return cls(dict(nodes), list(edges))

    def upsert_node(self, node: Node) -> Node:
        """Routes by identity key: a matching id accumulates evidence; a new
        id is inserted as-is. Either way the node is marked dirty for the
        next settle() and becomes the target's most recently touched node."""
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            existing = node
        else:
            existing.evidence.extend(node.evidence)
            if node.decision is not None:
                existing.decision = node.decision
        self.last_for_target[node.target] = node.id
        self._dirty.add(node.id)
        return existing

    def add_edge(self, edge: Edge) -> None:
        """De-dupes on ``(parent, child)``, replacing the weight in place. A
        new edge that would create a cycle is silently dropped — a DAG is
        what makes settle() a single well-defined topological pass."""
        for i, existing in enumerate(self.edges):
            if existing.parent == edge.parent and existing.child == edge.child:
                self.edges[i] = edge
                self._dirty.add(edge.child)
                return
        if self._reaches(edge.child, edge.parent):
            return
        self.edges.append(edge)
        self._index_edge(edge)
        self._dirty.add(edge.child)

    def _index_edge(self, edge: Edge) -> None:
        self._children.setdefault(edge.parent, []).append(edge.child)
        self._parents.setdefault(edge.child, []).append(edge.parent)

    def _reaches(self, start: str, goal: str) -> bool:
        seen = {start}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            if current == goal:
                return True
            for child in self._children.get(current, []):
                if child not in seen:
                    seen.add(child)
                    queue.append(child)
        return False

    def settle(self, support: SupportPolicy | None = None) -> None:
        """Recomputes state only for nodes the dirty set can reach, stopping
        a branch the instant a node's state doesn't change — cost is O(the
        subgraph that actually moved), not O(the whole graph)."""
        support = support or BinarySupport()
        frontier = deque(self._dirty)
        queued = set(frontier)
        self._dirty.clear()
        while frontier:
            node_id = frontier.popleft()
            queued.discard(node_id)
            node = self.nodes.get(node_id)
            if node is None:
                continue
            parents = [self.nodes[p] for p in self._parents.get(node_id, []) if p in self.nodes]
            new_state = reduce_state(node, parents, support)
            if new_state == node.state:
                continue
            node.state = new_state
            for child in self._children.get(node_id, []):
                if child not in queued:
                    queued.add(child)
                    frontier.append(child)

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
