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

    def node_label(self, node: DEPGNode, weight: float | None) -> Text:
        """``[cause-class] target (signal) — generality γ=0.72 (3 downstream)``.

        The signal is what distinguishes siblings sharing a cause_class and
        target (e.g. one open-port node per port on the same host) — without
        it, a batch of them renders as indistinguishable duplicate lines."""
        style = self.get_component_rich_style(STATE_CLASS[node.state])
        gamma = self.get_component_rich_style("node--gamma")
        weight_style = self.get_component_rich_style("node--weight")

        label = Text()
        if weight is not None:
            label.append(f"{weight:.2f} ", style=weight_style)
        target = f"{node.target} ({node.signal})" if node.signal else node.target
        label.append(f"[{node.cause_class}] {target}", style=style)
        label.append(
            f" — generality γ={node.generality:.2f} ({node.downstream} downstream)",
            style=gamma,
        )
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
        self.nodes = nodes
        self.edges = edges
        self._by_id = {node.id: node for node in nodes}
        self._parent_of = {edge.child: edge.parent for edge in edges}

    DECISION_COLUMNS = ("time", "chose", "over", "Δ", "cost")

    def compose(self) -> ComposeResult:
        with Vertical(id="depg-frame"):
            yield Static(self._title(), classes="modal-title")
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

    def _build_tree(self) -> None:
        tree = self.query_one(DEPGTree)
        tree.clear()
        children: dict[str, list[tuple[str, float]]] = {}
        has_parent: set[str] = set()
        for edge in self.edges:
            # A node with two incoming edges must nest under the same single
            # parent _parent_of resolves it to, or the tree and the path_to() breadcrumb disagree.
            if self._parent_of.get(edge.child) != edge.parent:
                continue
            children.setdefault(edge.parent, []).append((edge.child, edge.weight))
            has_parent.add(edge.child)

        roots = [node for node in self.nodes if node.id not in has_parent]
        seen: set[str] = set()
        for node in roots:
            self._add_node(tree, tree.root, node, None, children, seen)
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
        label = tree.node_label(node, weight)
        kids = children.get(node.id, ())
        branch = parent.add(label, data=node) if kids else parent.add_leaf(
            label, data=node
        )
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
