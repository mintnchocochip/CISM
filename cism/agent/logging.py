"""Operational/debug logging for the agent loop — graph steps, tool calls,
guardrail decisions.

Deliberately separate from two other things that look similar but are not:
the ``AgentEvent`` stream (the UI-facing protocol in ``cism/tui/events.py``)
and DEPG evidence (domain state in ``cism/depg/``). This is disk logging for
troubleshooting, with a 1-day retention TTL so it cannot accumulate forever.

Retention is enforced two ways: ``TimedRotatingFileHandler`` rotates the
live file at midnight and keeps at most one rotated backup, and a startup
sweep deletes any rotated file dated more than a day ago. The sweep exists
because the handler only rotates (and prunes) on a write after the boundary
has passed — a process that wasn't running at midnight would otherwise
leave stale files sitting around indefinitely.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import date, datetime, timedelta
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

__all__ = ["get_agent_logger"]

_LOG_BASENAME = "agent.log"
_ROTATED_SUFFIX = re.compile(r"\.(\d{4}-\d{2}-\d{2})$")
_RETENTION = timedelta(days=1)


class _JsonlFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": datetime.fromtimestamp(record.created).isoformat(timespec="seconds"),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(base)


def _sweep_stale_files(log_dir: Path, today: date) -> None:
    for path in log_dir.glob(f"{_LOG_BASENAME}.*"):
        match = _ROTATED_SUFFIX.search(path.name)
        if not match:
            continue
        try:
            file_date = date.fromisoformat(match.group(1))
        except ValueError:
            continue
        if today - file_date > _RETENTION:
            path.unlink(missing_ok=True)


def get_agent_logger(
    name: str = "cism.agent",
    log_dir: Path | None = None,
) -> logging.Logger:
    """A logger writing JSONL lines to a daily-rotated, TTL'd file.

    Safe to call repeatedly — handlers are only attached once per
    ``(name, log_dir)`` pair.
    """
    # Resolved lazily (not at import time) so it honours HOME as it stands
    # when a logger is actually requested, not whatever it was at import.
    directory = log_dir or (Path.home() / ".cism" / "logs")
    directory.mkdir(parents=True, exist_ok=True)
    _sweep_stale_files(directory, date.today())

    logger = logging.getLogger(name)
    marker = f"_cism_log_dir_{directory}"
    if getattr(logger, marker, False):
        return logger

    handler = TimedRotatingFileHandler(
        directory / _LOG_BASENAME,
        when="midnight",
        backupCount=1,
        encoding="utf-8",
    )
    handler.setFormatter(_JsonlFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    setattr(logger, marker, True)
    return logger
