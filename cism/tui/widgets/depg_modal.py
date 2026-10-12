"""The DEPG view: a modal overlay, not a persistent pane.

Tree indentation *is* the layout. There is deliberately no force-directed or
2D graph rendering — an ASCII tree is legible in a terminal recording, a
spring layout is not.

The left half is the graph; the right half is a table of evidence rows for
whichever node the tree cursor is on. Moving the cursor drives the table.
"""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Static, Tree
from textual.widgets.tree import TreeNode

from ..events import DEPGEdge, DEPGNode

STATE_CLASS = {
    "blocked": "node--blocked",
    "resolved": "node--resolved",
    "untested": "node--untested",
    "contested": "node--contested",
}


class DEPGTree(Tree[DEPGNode]):
    """A Tree whose labels are coloured by node state and annotated by weight."""

    COMPONENT_CLASSES = Tree.COMPONENT_CLASSES | {
        "node--blocked",
        "node--resolved",
        "node--untested",
        "node--contested",
        "node--weight",
        "node--gamma",
    }

    def __init__(self) -> None:
        super().__init__("depg", id="depg-tree")
        self.show_root = False
        self.guide_depth = 3

    def node_label(
        self,
        node: DEPGNode,
        weight: float | None,
        extra_parents: list[tuple[DEPGNode, float]] | None = None,
    ) -> Text:
        """``[cause-class] target (signal) — generality γ=0.72 (3 downstream)``,
        plus ``(+2 more: web@0.41, dns@0.30)`` when this node has other
        incoming edges beyond the one it's nested under (E2, AUDIT.md).

        The signal is what distinguishes siblings sharing a cause_class and
        target (e.g. one open-port node per port on the same host) — without
        it, a batch of them renders as indistinguishable duplicate lines."""
        style = self.get_component_rich_style(STATE_CLASS[node.state])
        gamma = self.get_component_rich_style("node--gamma")
        weight_style = self.get_component_rich_style("node--weight")

        label = Text()
        if weight is not None:
            label.append(f"w={weight:.2f} ", style=weight_style)
        target = f"{node.target} ({node.signal})" if node.signal else node.target
        label.append(f"[{node.cause_class}] {target}", style=style)
        label.append(
            f" — generality γ={node.generality:.2f} ({node.downstream} downstream)",
            style=gamma,
        )
        if extra_parents:
            # E6: every incoming edge's weight is shown, not just the
            # surviving parent's bare number above — same w= tag, so the
            # two read as the same kind of value at a glance.
            joined = ", ".join(f"{p.cause_class}@w={w:.2f}" for p, w in extra_parents)
            label.append(f" (+{len(extra_parents)} more: {joined})", style=weight_style)
        return label


class DEPGModal(ModalScreen[None]):
    """Escape closes. Arrow keys move the tree; the table follows."""

    BINDINGS = [
        Binding("escape", "dismiss_modal", "close", show=False),
        Binding("ctrl+d", "dismiss_modal", "close", show=False, priority=True),
    ]

    EVIDENCE_COLUMNS = ("timestamp", "tool", "exit signal", "tier")

    def __init__(
        self, nodes: tuple[DEPGNode, ...], edges: tuple[DEPGEdge, ...]
    ) -> None:
        super().__init__()
        self._index(nodes, edges)

    def _index(self, nodes: tuple[DEPGNode, ...], edges: tuple[DEPGEdge, ...]) -> None:
        """Builds every lookup table derived from (nodes, edges) — called
        from __init__, and again from refresh_data (E4) when the modal is
        updated in place rather than rebuilt from scratch."""
        self.nodes = nodes
        self.edges = edges
        self._by_id = {node.id: node for node in nodes}

        # E2: a child can have several incoming edges; keep all of them,
        # deterministically ranked (highest weight first, parent id as
        # tiebreak) instead of whichever edge happened to come last.
        incoming: dict[str, list[tuple[str, float]]] = {}
        for edge in edges:
            incoming.setdefault(edge.child, []).append((edge.parent, edge.weight))
        self._parent_of: dict[str, str] = {}
        self._primary_weight: dict[str, float] = {}
        self._extra_parents: dict[str, list[tuple[str, float]]] = {}
        for child, parents in incoming.items():
            ranked = sorted(parents, key=lambda pw: (-pw[1], pw[0]))
            self._parent_of[child] = ranked[0][0]
            self._primary_weight[child] = ranked[0][1]
            if len(ranked) > 1:
                self._extra_parents[child] = ranked[1:]

    DECISION_COLUMNS = ("time", "chose", "over", "Δ", "cost")

    def compose(self) -> ComposeResult:
        with Vertical(id="depg-frame"):
            yield Static(self._title(), id="depg-title", classes="modal-title")
            with Horizontal(id="depg-split"):
                with Vertical(id="depg-left"):
                    yield DEPGTree()
                with Vertical(id="depg-right"):
                    yield Static("decision path", classes="modal-title")
                    yield DataTable(id="depg-decisions", cursor_type="none")
                    yield Static("evidence", classes="modal-title")
                    yield DataTable(id="depg-evidence", cursor_type="row")
            yield Static("↑↓ select node · esc to close", classes="modal-hint")

    def _title(self) -> str:
        blocked = sum(1 for n in self.nodes if n.state == "blocked")
        resolved = sum(1 for n in self.nodes if n.state == "resolved")
        contested = sum(1 for n in self.nodes if n.state == "contested")
        untested = len(self.nodes) - blocked - resolved - contested
        return (
            f"dependency / error propagation graph — {len(self.nodes)} nodes"
            f"  ({blocked} blocked, {resolved} resolved, {untested} untested,"
            f" {contested} contested)"
        )

    def on_mount(self) -> None:
        evidence = self.query_one("#depg-evidence", DataTable)
        for column in self.EVIDENCE_COLUMNS:
            evidence.add_column(column, key=column)
        decisions = self.query_one("#depg-decisions", DataTable)
        for column in self.DECISION_COLUMNS:
            decisions.add_column(column, key=column)
        self._build_tree()

    # -- the path that produced a node -------------------------------------

    def path_to(self, node_id: str) -> list[DEPGNode]:
        """Every node from a root down to ``node_id``, in order. Walks parent
        links and stops on a repeat so a cyclic graph can't hang the view."""
        chain: list[DEPGNode] = []
        seen: set[str] = set()
        current = node_id
        while current in self._by_id and current not in seen:
            seen.add(current)
            chain.append(self._by_id[current])
            current = self._parent_of.get(current, "")
        chain.reverse()
        return chain

    # -- tree construction -------------------------------------------------

    def refresh_data(self, nodes: tuple[DEPGNode, ...], edges: tuple[DEPGEdge, ...]) -> None:
        """E4: called in place on an already-mounted modal (instead of the
        caller pushing a brand new one) when a DEPGUpdated event arrives
        while this modal is open. Rebuilding the tree is unavoidable —
        Textual's Tree has no structural diff API, and this stays a plain
        ASCII tree on purpose (see the module docstring) — but the cursor
        would otherwise snap back to the first root on every single update
        during a live run, which is what actually made this feel broken."""
        tree = self.query_one(DEPGTree)
        selected_id = (
            tree.cursor_node.data.id
            if tree.cursor_node is not None and tree.cursor_node.data is not None
            else None
        )
        self._index(nodes, edges)
        self.query_one("#depg-title", Static).update(self._title())
        self._build_tree()
        if selected_id is not None:
            restored = self._tree_nodes_by_id.get(selected_id)
            if restored is not None:
                tree.move_cursor(restored)
                self._show_node(restored.data)

    def _build_tree(self) -> None:
        tree = self.query_one(DEPGTree)
        tree.clear()
        self._tree_nodes_by_id: dict[str, TreeNode[DEPGNode]] = {}
        children: dict[str, list[tuple[str, float]]] = {}
        for child, parent in self._parent_of.items():
            children.setdefault(parent, []).append((child, self._primary_weight[child]))

        roots = [node for node in self.nodes if node.id not in self._parent_of]
        seen: set[str] = set()
        for node in roots:
            self._add_node(tree, tree.root, node, None, children, seen)

        # E3: a component with no in-degree-0 node (a pure cycle) has every
        # member in self._parent_of, so it's never reached from a root —
        # attach whatever's left under a synthetic root instead of dropping it.
        orphaned = [node for node in self.nodes if node.id not in seen]
        if orphaned:
            marker = tree.root.add(f"⟲ orphaned / cyclic ({len(orphaned)})")
            for node in orphaned:
                self._add_node(tree, marker, node, None, children, seen)

        tree.root.expand_all()
        if tree.root.children:
            tree.cursor_line = 0
            self._show_node(roots[0] if roots else self.nodes[0])
        tree.focus()

    def _add_node(
        self,
        tree: DEPGTree,
        parent: TreeNode[DEPGNode],
        node: DEPGNode,
        weight: float | None,
        children: dict[str, list[tuple[str, float]]],
        seen: set[str],
    ) -> None:
        if node.id in seen:
            return
        seen.add(node.id)
        extra = [
            (self._by_id[p], w)
            for p, w in self._extra_parents.get(node.id, [])
            if p in self._by_id
        ]
        label = tree.node_label(node, weight, extra or None)
        kids = children.get(node.id, ())
        branch = parent.add(label, data=node) if kids else parent.add_leaf(
            label, data=node
        )
        self._tree_nodes_by_id[node.id] = branch
        for child_id, child_weight in kids:
            child = self._by_id.get(child_id)
            if child is not None:
                self._add_node(tree, branch, child, child_weight, children, seen)

    # -- selection drives the table ---------------------------------------

    def on_tree_node_highlighted(self, message: Tree.NodeHighlighted[DEPGNode]) -> None:
        if message.node.data is not None:
            self._show_node(message.node.data)

    def _show_node(self, node: DEPGNode) -> None:
        self._show_decisions(node)
        self._show_evidence(node)

    def _show_decisions(self, node: DEPGNode) -> None:
        """The choices that led here, root first."""
        table = self.query_one("#depg-decisions", DataTable)
        table.clear()
        for step in self.path_to(node.id):
            decision = step.decision
            if decision is None:
                continue
            table.add_row(
                decision.timestamp,
                decision.chose,
                str(decision.alternatives),
                f"{decision.score_gap:+.2f}",
                f"{decision.tokens}t",
            )

    def _show_evidence(self, node: DEPGNode) -> None:
        table = self.query_one("#depg-evidence", DataTable)
        table.clear()
        for item in node.evidence:
            table.add_row(item.timestamp, item.tool, item.exit_signal, item.tier)

    def action_dismiss_modal(self) -> None:
        self.dismiss(None)
