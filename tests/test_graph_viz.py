"""cism/report/graph_viz.py: DOT export + best-effort SVG rendering of a
Report's DEPG — the panel-presentable counterpart to the TUI's
deliberately-ASCII tree."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from cism.report import build_dot, build_report, write_graph
from cism.tui.events import DEPGEdge, DEPGNode


def _node(node_id: str, state: str, cause_class: str = "open-port", generality: float = 0.5) -> DEPGNode:
    return DEPGNode(
        id=node_id, cause_class=cause_class, target="10.0.0.5", generality=generality, state=state,
    )


def test_build_dot_includes_every_node_and_valid_edge() -> None:
    report = build_report(
        run_id="run-1",
        target="10.0.0.5",
        nodes=(_node("a", "resolved"), _node("b", "blocked", "outdated-server")),
        edges=(DEPGEdge(parent="a", child="b", weight=0.8),),
        memory=(),
    )

    dot = build_dot(report)

    assert dot.startswith("digraph depg {")
    assert '"a"' in dot and '"b"' in dot
    assert '"a" -> "b"' in dot
    assert "0.80" in dot


def test_build_dot_drops_edges_to_nodes_not_in_the_report() -> None:
    """An edge referencing a node id the report doesn't carry (e.g. pruned
    away) must not produce a dangling reference in the DOT source."""
    report = build_report(
        run_id="run-1",
        target="10.0.0.5",
        nodes=(_node("a", "resolved"),),
        edges=(DEPGEdge(parent="a", child="ghost", weight=0.5),),
        memory=(),
    )

    dot = build_dot(report)

    assert "ghost" not in dot
    assert "->" not in dot


def test_build_dot_colors_by_state() -> None:
    report = build_report(
        run_id="run-1",
        target="10.0.0.5",
        nodes=(_node("a", "resolved"), _node("b", "blocked")),
        edges=(),
        memory=(),
    )

    dot = build_dot(report)

    resolved_line = next(line for line in dot.splitlines() if '"a"' in line)
    blocked_line = next(line for line in dot.splitlines() if '"b"' in line)
    assert "#2e7d32" in resolved_line
    assert "#c62828" in blocked_line


def test_build_dot_clamps_extreme_edge_weight_to_a_sane_pen_width() -> None:
    report = build_report(
        run_id="run-1",
        target="10.0.0.5",
        nodes=(_node("a", "resolved"), _node("b", "resolved")),
        edges=(DEPGEdge(parent="a", child="b", weight=99.0),),
        memory=(),
    )

    dot = build_dot(report)

    assert "penwidth=6.0" in dot


def test_write_graph_always_writes_dot_file(tmp_path) -> None:
    report = build_report(run_id="run-1", target="x", nodes=(_node("a", "resolved"),), edges=(), memory=())

    with patch("cism.report.graph_viz.subprocess.run", side_effect=FileNotFoundError):
        dot_path = write_graph(report, tmp_path)

    assert dot_path.exists()
    assert dot_path.name == "run-1.dot"
    assert not dot_path.with_suffix(".svg").exists()


def test_write_graph_renders_svg_when_dot_binary_succeeds(tmp_path) -> None:
    report = build_report(run_id="run-1", target="x", nodes=(_node("a", "resolved"),), edges=(), memory=())

    def _fake_run(argv, **kwargs):
        # Simulate `dot -Tsvg in.dot -o out.svg` actually writing the file.
        out_path = argv[argv.index("-o") + 1]
        with open(out_path, "w") as f:
            f.write("<svg></svg>")
        return subprocess.CompletedProcess(argv, 0)

    with patch("cism.report.graph_viz.subprocess.run", side_effect=_fake_run):
        dot_path = write_graph(report, tmp_path)

    assert dot_path.with_suffix(".svg").exists()


def test_write_graph_survives_dot_binary_erroring(tmp_path) -> None:
    report = build_report(run_id="run-1", target="x", nodes=(_node("a", "resolved"),), edges=(), memory=())

    with patch(
        "cism.report.graph_viz.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, ["dot"]),
    ):
        dot_path = write_graph(report, tmp_path)

    assert dot_path.exists()
    assert not dot_path.with_suffix(".svg").exists()
