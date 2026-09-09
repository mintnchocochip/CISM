"""cism/agent/logging.py: JSONL audit logging with a 3-day retention TTL.

Separate from the AgentEvent stream and DEPG evidence — this is disk
logging for audit/troubleshooting, and it must not accumulate forever.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

from cism.agent.logging import get_agent_logger, read_run_events


def _touch(path: Path) -> None:
    path.write_text("stale\n", encoding="utf-8")


def test_writes_jsonl_lines_to_the_live_file(tmp_path: Path) -> None:
    logger = get_agent_logger(name="test.logging.1", log_dir=tmp_path)
    logger.info("hello %s", "world")
    for handler in logger.handlers:
        handler.flush()

    content = (tmp_path / "agent.log").read_text(encoding="utf-8").strip()
    record = json.loads(content)
    assert record["message"] == "hello world"
    assert record["level"] == "INFO"
    assert record["component"] == "test.logging.1"


def test_startup_sweep_deletes_files_older_than_the_retention_window(tmp_path: Path) -> None:
    today = date.today()
    stale = tmp_path / f"agent.log.{(today - timedelta(days=5)).isoformat()}"
    recent = tmp_path / f"agent.log.{(today - timedelta(days=1)).isoformat()}"
    unrelated = tmp_path / "not-a-log.txt"
    for path in (stale, recent, unrelated):
        _touch(path)

    get_agent_logger(name="test.logging.2", log_dir=tmp_path)

    assert not stale.exists()
    assert recent.exists()
    assert unrelated.exists()


def test_writes_the_data_field_alongside_the_message(tmp_path: Path) -> None:
    logger = get_agent_logger(name="test.logging.5", log_dir=tmp_path)
    logger.info("ToolFinished", extra={"data": {"tool": "nmap", "summary": "1 open port"}})
    for handler in logger.handlers:
        handler.flush()

    content = (tmp_path / "agent.log").read_text(encoding="utf-8").strip()
    record = json.loads(content)
    assert record["message"] == "ToolFinished"
    assert record["data"] == {"tool": "nmap", "summary": "1 open port"}


def test_omits_the_data_field_when_none_was_given(tmp_path: Path) -> None:
    logger = get_agent_logger(name="test.logging.6", log_dir=tmp_path)
    logger.info("plain message")
    for handler in logger.handlers:
        handler.flush()

    content = (tmp_path / "agent.log").read_text(encoding="utf-8").strip()
    record = json.loads(content)
    assert "data" not in record


def test_sweep_ignores_files_without_a_parseable_date_suffix(tmp_path: Path) -> None:
    junk = tmp_path / "agent.log.not-a-date"
    _touch(junk)

    get_agent_logger(name="test.logging.3", log_dir=tmp_path)

    assert junk.exists()


def test_calling_twice_for_the_same_directory_does_not_duplicate_handlers(
    tmp_path: Path,
) -> None:
    first = get_agent_logger(name="test.logging.4", log_dir=tmp_path)
    before = len(first.handlers)
    second = get_agent_logger(name="test.logging.4", log_dir=tmp_path)
    assert second is first
    assert len(second.handlers) == before


def _emit(logger, message: str, data: dict) -> None:
    logger.info(message, extra={"data": data})
    for handler in logger.handlers:
        handler.flush()


def test_read_run_events_returns_nothing_for_an_unknown_run_id(tmp_path: Path) -> None:
    logger = get_agent_logger(name="test.logging.7", log_dir=tmp_path)
    _emit(logger, "RunStarted", {"run_id": "run-a"})
    _emit(logger, "RunFinished", {"run_id": "run-a"})

    assert read_run_events("run-b", log_dir=tmp_path) == []


def test_read_run_events_returns_exactly_one_runs_slice_in_order(tmp_path: Path) -> None:
    logger = get_agent_logger(name="test.logging.8", log_dir=tmp_path)
    _emit(logger, "SessionState", {"model": "x"})  # before any run — must be excluded
    _emit(logger, "RunStarted", {"run_id": "run-a"})
    _emit(logger, "ToolStarted", {"call_id": "c1", "tool": "nmap"})
    _emit(logger, "ToolFinished", {"call_id": "c1", "summary": "done"})
    _emit(logger, "RunFinished", {"run_id": "run-a"})
    _emit(logger, "RunStarted", {"run_id": "run-b"})  # a later, unrelated run
    _emit(logger, "RunFinished", {"run_id": "run-b"})

    records = read_run_events("run-a", log_dir=tmp_path)

    assert [r["message"] for r in records] == [
        "RunStarted",
        "ToolStarted",
        "ToolFinished",
        "RunFinished",
    ]


def test_read_run_events_returns_a_partial_slice_when_theres_no_run_finished(
    tmp_path: Path,
) -> None:
    logger = get_agent_logger(name="test.logging.9", log_dir=tmp_path)
    _emit(logger, "RunStarted", {"run_id": "run-a"})
    _emit(logger, "ToolStarted", {"call_id": "c1", "tool": "nmap"})

    records = read_run_events("run-a", log_dir=tmp_path)

    assert [r["message"] for r in records] == ["RunStarted", "ToolStarted"]


def test_read_run_events_spans_a_rotated_backup_and_the_live_file(tmp_path: Path) -> None:
    today = date.today()
    rotated = tmp_path / f"agent.log.{(today - timedelta(days=1)).isoformat()}"
    rotated.write_text(
        json.dumps({"message": "RunStarted", "data": {"run_id": "run-a"}}) + "\n",
        encoding="utf-8",
    )
    logger = get_agent_logger(name="test.logging.10", log_dir=tmp_path)
    _emit(logger, "RunFinished", {"run_id": "run-a"})

    records = read_run_events("run-a", log_dir=tmp_path)

    assert [r["message"] for r in records] == ["RunStarted", "RunFinished"]
