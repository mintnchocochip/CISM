"""cism/report/build.py: walks DEPG nodes + memory into a Markdown/JSON
report. §4.2 (BACKLOG.md)."""

from __future__ import annotations

from cism.report import PhaseTransition, RunMetrics, build_report, write_report
from cism.tui.events import DEPGNode, Evidence, MemoryRow


def _node(state: str, cause_class: str = "open-port") -> DEPGNode:
    return DEPGNode(
        id=f"{cause_class}:10.0.0.5:80",
        cause_class=cause_class,
        target="10.0.0.5",
        generality=0.5,
        state=state,
        evidence=(Evidence(timestamp="t1", tool="nmap", exit_signal="80/tcp open", tier="T2"),),
    )


def test_resolved_nodes_land_in_findings_and_others_in_open_items() -> None:
    report = build_report(
        run_id="run-1",
        target="10.0.0.5",
        nodes=(_node("resolved"), _node("blocked", "outdated-server")),
        edges=(),
        memory=(),
    )

    assert len(report.findings) == 1
    assert report.findings[0].cause_class == "open-port"
    assert len(report.open_items) == 1
    assert report.open_items[0].cause_class == "outdated-server"


def test_accepts_agent_side_nodes_dict_via_to_event() -> None:
    class _FakeNode:
        def to_event(self) -> DEPGNode:
            return _node("resolved")

    report = build_report(
        run_id="run-1", target="x", nodes={"n1": _FakeNode()}, edges=(), memory=()
    )
    assert len(report.findings) == 1


def test_markdown_includes_findings_evidence_and_phase_history() -> None:
    report = build_report(
        run_id="run-1",
        target="10.0.0.5",
        nodes=(_node("resolved"),),
        edges=(),
        memory=(MemoryRow(id="m1", tier="T2", phase_tag="recon", salience=1.0, age_s=1.0, snippet="found stuff"),),
        phase_history=(PhaseTransition(timestamp="t0", phase="recon"),),
        metrics=RunMetrics(ok=True, tool_calls=2, tool_failures=0, guardrail_blocks=0, extraction_fallbacks=0, tokens_total=100),
    )

    md = report.to_markdown()

    assert "open-port" in md
    assert "80/tcp open" in md
    assert "recon" in md
    assert "found stuff" in md
    assert "2 tool call" in md


def test_json_round_trips_findings_count() -> None:
    report = build_report(
        run_id="run-1", target="x", nodes=(_node("resolved"), _node("untested")), edges=(), memory=()
    )

    payload = report.to_json()

    assert len(payload["findings"]) == 1
    assert len(payload["open_items"]) == 1
    assert payload["run_id"] == "run-1"


def test_write_report_writes_both_files(tmp_path) -> None:
    report = build_report(run_id="run-1", target="x", nodes=(_node("resolved"),), edges=(), memory=())

    md_path, json_path = write_report(report, tmp_path)

    assert md_path.exists() and json_path.exists()
    assert md_path.name == "run-1.md"
    assert json_path.name == "run-1.json"
