"""§4.2 (BACKLOG.md): a report walks the final DEPG + memory state and
emits both a human-readable Markdown write-up and a structured JSON dump —
decided as "both" rather than picking one, since the two have different
readers (an operator reading a demo write-up vs. downstream tooling).

Pulls from exactly the three sources BACKLOG.md names: DEPG nodes (resolved
findings + their evidence), the memory store (narrative context), and phase
history. Deliberately depends on nothing outside ``cism.tui.events`` (the
existing wire-format vocabulary agent code already shares with the TUI) —
not ``cism.agent``, so a TUI caller can build a report straight from the
event stream it already holds without pulling in the agent layer. Phase
history and run metrics are therefore caller-supplied plain data, not
re-derived from the audit log here."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cism.tui.events import DEPGEdge, DEPGNode, MemoryRow

__all__ = ["Report", "build_report"]


@dataclass(frozen=True, slots=True)
class PhaseTransition:
    timestamp: str
    phase: str


@dataclass(frozen=True, slots=True)
class RunMetrics:
    ok: bool
    tool_calls: int = 0
    tool_failures: int = 0
    guardrail_blocks: int = 0
    extraction_fallbacks: int = 0
    tokens_total: int = 0


@dataclass(frozen=True, slots=True)
class Report:
    run_id: str
    generated_at: str
    target: str
    phase_history: tuple[PhaseTransition, ...]
    findings: tuple[DEPGNode, ...]
    """Resolved nodes — the headline result of the engagement."""
    open_items: tuple[DEPGNode, ...]
    """Everything else the DEPG tracked (blocked/contested/untested) —
    context for why a node didn't resolve, not a finding to act on."""
    edges: tuple[DEPGEdge, ...]
    memory_context: tuple[MemoryRow, ...]
    metrics: RunMetrics | None

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "target": self.target,
            "phase_history": [asdict(p) for p in self.phase_history],
            "findings": [asdict(n) for n in self.findings],
            "open_items": [asdict(n) for n in self.open_items],
            "edges": [asdict(e) for e in self.edges],
            "memory_context": [asdict(m) for m in self.memory_context],
            "metrics": asdict(self.metrics) if self.metrics else None,
        }

    def to_markdown(self) -> str:
        lines: list[str] = [
            f"# CISM engagement report — {self.target or 'unscoped target'}",
            "",
            f"- Run: `{self.run_id}`",
            f"- Generated: {self.generated_at}",
        ]
        if self.metrics:
            m = self.metrics
            lines.append(
                f"- Outcome: {'completed' if m.ok else 'did not complete cleanly'} — "
                f"{m.tool_calls} tool call(s), {m.tool_failures} failure(s), "
                f"{m.guardrail_blocks} guardrail block(s)"
                + (f", {m.extraction_fallbacks} extraction fallback(s)" if m.extraction_fallbacks else "")
            )
        lines.append("")

        if self.phase_history:
            lines.append("## Phase progression")
            for p in self.phase_history:
                lines.append(f"- `{p.timestamp}` → **{p.phase}**")
            lines.append("")

        lines.append("## Findings")
        if not self.findings:
            lines.append("_No DEPG node reached `resolved` this run._")
        for node in self.findings:
            lines.extend(_node_section(node, heading_level=3))
        lines.append("")

        if self.open_items:
            lines.append("## Other observed activity (not resolved)")
            for node in self.open_items:
                lines.extend(_node_section(node, heading_level=3))
            lines.append("")

        if self.memory_context:
            lines.append("## Narrative context")
            for row in self.memory_context:
                lines.append(f"- `[{row.tier}]` ({row.phase_tag}) {row.snippet}")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"


def _node_section(node: DEPGNode, *, heading_level: int) -> list[str]:
    h = "#" * heading_level
    lines = [f"{h} [{node.state}] {node.cause_class} — {node.target}"]
    if node.signal:
        lines[-1] += f" ({node.signal})"
    if node.decision is not None:
        lines.append(f"- Decision: chose **{node.decision.chose}** — {node.decision.rationale}".rstrip(" —"))
    for ev in node.evidence:
        lines.append(f"- `{ev.timestamp}` **{ev.tool}** [{ev.tier}]: {ev.exit_signal}")
    lines.append("")
    return lines


def build_report(
    *,
    run_id: str,
    target: str,
    nodes: dict[str, Any] | tuple[DEPGNode, ...],
    edges: tuple[DEPGEdge, ...],
    memory: tuple[MemoryRow, ...],
    phase_history: tuple[PhaseTransition, ...] = (),
    metrics: RunMetrics | None = None,
) -> Report:
    """``nodes`` takes either the agent-side ``dict[str, Node]`` (has
    ``.to_event()``) or an already-encoded ``tuple[DEPGNode, ...]`` — the two
    call sites that actually have DEPG state (core.py's live state, and a
    replayed DEPGUpdated) hold one or the other, not both.

    ``phase_history``/``metrics`` are plain data the caller already has —
    the TUI accumulates ``PhaseChanged`` events as they arrive and reads
    the counters straight off ``RunFinished`` (see cism.tui.app); nothing
    here re-derives them from a log file."""
    node_events = tuple(
        n.to_event() if hasattr(n, "to_event") else n
        for n in (nodes.values() if isinstance(nodes, dict) else nodes)
    )
    findings = tuple(n for n in node_events if n.state == "resolved")
    open_items = tuple(n for n in node_events if n.state != "resolved")

    return Report(
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        target=target,
        phase_history=phase_history,
        findings=findings,
        open_items=open_items,
        edges=tuple(edges),
        memory_context=tuple(memory),
        metrics=metrics,
    )


def write_report(report: Report, out_dir: Path) -> tuple[Path, Path]:
    """Writes ``<run_id>.md`` and ``<run_id>.json`` to ``out_dir``, creating
    it if needed. Returns the two paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"{report.run_id}.md"
    json_path = out_dir / f"{report.run_id}.json"
    md_path.write_text(report.to_markdown(), encoding="utf-8")
    json_path.write_text(json.dumps(report.to_json(), indent=2, default=str), encoding="utf-8")
    return md_path, json_path
