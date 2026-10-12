"""Renders a Report's DEPG as an actual graph diagram — not the TUI's ASCII
tree (``cism/tui/widgets/depg_modal.py``), which is deliberately
terminal-only: legible in a terminal recording, a spring layout isn't. A
rendered diagram is for the opposite reader — someone looking at a screen,
not a terminal — which is exactly the case a review/demo panel is.

Deliberately a thin DOT-string builder plus a subprocess call to the
system ``dot`` binary, not the ``graphviz`` pip package: this stays
dependency-free the same way ``cism/report/build.py`` does, and the
``graphviz`` apt package is one line in the Dockerfile either way.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from cism.report.build import Report
from cism.tui.events import DEPGNode

__all__ = ["build_dot", "write_graph"]

#: State -> (border color, fill color). Chosen to also read correctly to a
#: red/green color-blind viewer: resolved/blocked differ in lightness and
#: border style, not hue alone.
_STATE_STYLE: dict[str, tuple[str, str]] = {
    "resolved": ("#2e7d32", "#e8f5e9"),
    "contested": ("#f9a825", "#fff8e1"),
    "untested": ("#607d8b", "#eceff1"),
    "blocked": ("#c62828", "#ffebee"),
}
_DEFAULT_STYLE = ("#607d8b", "#eceff1")

_DOT_TIMEOUT_S = 30.0


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _node_label(node: DEPGNode) -> str:
    lines = [node.cause_class]
    if node.signal:
        # DOT labels are one line unless \n is escaped literally in the
        # source text (not a real newline) — \\l left-aligns each line
        # instead of centering it, which reads better for prose-like signals.
        lines.append(node.signal[:60])
    lines.append(f"γ={node.generality:.2f}  ↓{node.downstream}")
    return "\\l".join(_escape(line) for line in lines) + "\\l"


def build_dot(report: Report) -> str:
    """A standalone ``.dot`` source: state colors the node, edge weight
    becomes line thickness, so the strongest propagation paths are visible
    without reading every number on the page."""
    all_nodes: dict[str, DEPGNode] = {n.id: n for n in (*report.findings, *report.open_items)}

    lines = [
        "digraph depg {",
        '  rankdir="LR";',
        '  bgcolor="white";',
        '  labelloc="t"; label="CISM engagement — '
        + _escape(str(report.target) if report.target else "unscoped target")
        + '";',
        '  fontname="Helvetica";',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11];',
        '  edge [fontname="Helvetica", fontsize=9, color="#90a4ae"];',
    ]
    for node in all_nodes.values():
        border, fill = _STATE_STYLE.get(node.state, _DEFAULT_STYLE)
        lines.append(
            f'  "{_escape(node.id)}" [label="{_node_label(node)}", '
            f'color="{border}", fillcolor="{fill}", penwidth=2];'
        )
    for edge in report.edges:
        if edge.parent not in all_nodes or edge.child not in all_nodes:
            continue
        # Clamped, not raw: a stray weight far outside [0, 1] (bad data, a
        # future policy change) must never make `dot` choke on an absurd
        # pen width instead of just drawing a thick-looking line.
        width = max(1.0, min(edge.weight * 4.0, 6.0))
        lines.append(
            f'  "{_escape(edge.parent)}" -> "{_escape(edge.child)}" '
            f'[label="{edge.weight:.2f}", penwidth={width:.1f}];'
        )
    lines.append("}")
    return "\n".join(lines)


def write_graph(report: Report, out_dir: Path) -> Path:
    """Writes ``<run_id>.dot`` always, and ``<run_id>.svg`` alongside it
    when the system ``dot`` binary is available and succeeds. Rendering is
    best-effort, not required: a caller that wants to know whether the SVG
    actually landed checks the returned path's ``.with_suffix(".svg")``
    rather than this function raising over an optional renderer being
    absent (dev machines without graphviz installed shouldn't lose the
    rest of /report over it)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    dot_path = out_dir / f"{report.run_id}.dot"
    dot_path.write_text(build_dot(report), encoding="utf-8")
    svg_path = dot_path.with_suffix(".svg")
    try:
        subprocess.run(
            ["dot", "-Tsvg", str(dot_path), "-o", str(svg_path)],
            check=True,
            capture_output=True,
            timeout=_DOT_TIMEOUT_S,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    return dot_path
