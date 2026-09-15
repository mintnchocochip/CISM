"""Operational/audit logging for the agent loop. ``LangGraphAgent._emit``
mirrors every ``AgentEvent`` it queues to the TUI through this logger too —
one JSONL line per event, independent of what the TUI renders. Retention
is a 3-day TTL: ``TimedRotatingFileHandler`` rotates at midnight and a
startup sweep deletes anything older, since the handler alone only prunes
on a write after the boundary passes."""

from __future__ import annotations

import json
import logging
import re
from datetime import date, datetime, timedelta
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

__all__ = ["get_agent_logger", "read_run_events"]

_LOG_BASENAME = "agent.log"
_ROTATED_SUFFIX = re.compile(r"\.(\d{4}-\d{2}-\d{2})$")
_RETENTION = timedelta(days=3)
_BACKUP_COUNT = 3


def _default_log_dir() -> Path:
    # Resolved lazily so it honours HOME as it stands when called, not at import.
    return Path.home() / ".cism" / "logs"


class _JsonlFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": datetime.fromtimestamp(record.created).isoformat(timespec="seconds"),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        data = getattr(record, "data", None)
        if data is not None:
            base["data"] = data
        return json.dumps(base, default=str)


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
    directory = log_dir or _default_log_dir()
    directory.mkdir(parents=True, exist_ok=True)
    _sweep_stale_files(directory, date.today())

    logger = logging.getLogger(name)
    marker = f"_cism_log_dir_{directory}"
    if getattr(logger, marker, False):
        return logger

    handler = TimedRotatingFileHandler(
        directory / _LOG_BASENAME,
        when="midnight",
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(_JsonlFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    setattr(logger, marker, True)
    return logger


def _log_files_oldest_first(log_dir: Path) -> list[Path]:
    """Rotated backups (oldest first), then the live file — write order,
    for a caller reconstructing a run's timeline across midnight rotation."""
    rotated = sorted(
        (p for p in log_dir.glob(f"{_LOG_BASENAME}.*") if _ROTATED_SUFFIX.search(p.name)),
        key=lambda p: _ROTATED_SUFFIX.search(p.name).group(1),  # type: ignore[union-attr]
    )
    live = log_dir / _LOG_BASENAME
    return [*rotated, *([live] if live.exists() else [])]


def read_run_events(run_id: str, log_dir: Path | None = None) -> list[dict]:
    """Every audit-log record for ``run_id``, ``RunStarted`` through
    ``RunFinished`` inclusive, in write order. Returns ``[]`` for a run
    that isn't found (rotated out, typo'd id, never happened) — an
    expected outcome, not an error. A still-in-flight or crashed run
    returns whatever was collected. Decoding ``record["data"]`` back into
    an ``AgentEvent`` is the caller's job, to keep this module free of any
    TUI dependency."""
    directory = log_dir or _default_log_dir()
    collecting = False
    collected: list[dict] = []
    for path in _log_files_oldest_first(directory):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            data = record.get("data")
            if not isinstance(data, dict):
                continue
            if record.get("message") == "RunStarted" and data.get("run_id") == run_id:
                collecting = True
                collected = []  # a repeated run_id (vanishingly unlikely) restarts at its real start
            if collecting:
                collected.append(record)
            if collecting and record.get("message") == "RunFinished" and data.get("run_id") == run_id:
                return collected
    return collected
