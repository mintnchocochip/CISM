"""cism/agent/logging.py: JSONL logging with a 1-day retention TTL.

Separate from the AgentEvent stream and DEPG evidence — this is disk
logging for troubleshooting, and it must not accumulate forever.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

from cism.agent.logging import get_agent_logger


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


def test_startup_sweep_deletes_files_older_than_one_day(tmp_path: Path) -> None:
    today = date.today()
    stale = tmp_path / f"agent.log.{(today - timedelta(days=3)).isoformat()}"
    yesterday = tmp_path / f"agent.log.{(today - timedelta(days=1)).isoformat()}"
    unrelated = tmp_path / "not-a-log.txt"
    for path in (stale, yesterday, unrelated):
        _touch(path)

    get_agent_logger(name="test.logging.2", log_dir=tmp_path)

    assert not stale.exists()
    assert yesterday.exists()
    assert unrelated.exists()


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
