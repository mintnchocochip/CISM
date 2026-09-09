"""Operational/audit logging for the agent loop.

``LangGraphAgent._emit`` (cism/agent/core.py) writes every ``AgentEvent`` it
puts on the TUI's queue through this logger too — one JSONL line per event,
in the same order the TUI sees them, each carrying the event's full field
set under ``data``. This is the audit trail: what ran, what a tool returned,
which guardrail blocked what, every phase change, in a form you can grep or
feed to a script, independent of whatever the TUI happened to render.

Deliberately separate from two other things that look similar but are not:
the ``AgentEvent`` stream itself (the UI-facing protocol in
``cism/tui/events.py`` — this just mirrors it to disk) and DEPG evidence
(domain state in ``cism/depg/``). Retention is a 3-day TTL so it cannot
accumulate forever — bump ``_RETENTION`` (and ``backupCount`` to match) if
that window is too short.

Retention is enforced two ways: ``TimedRotatingFileHandler`` rotates the
live file at midnight and keeps at most ``backupCount`` rotated backups, and
a startup sweep deletes any rotated file dated older than ``_RETENTION``.
The sweep exists because the handler only rotates (and prunes) on a write
after the boundary has passed — a process that wasn't running at midnight
would otherwise leave stale files sitting around indefinitely.
"""

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
    # Resolved lazily (not at import time) so it honours HOME as it stands
    # when actually called, not whatever it was at import.
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
    """Rotated backups (oldest date first), then the live file — the same
    order the lines inside them were actually written in, which is what a
    caller reconstructing one run's timeline across a midnight rotation
    needs."""
    rotated = sorted(
        (p for p in log_dir.glob(f"{_LOG_BASENAME}.*") if _ROTATED_SUFFIX.search(p.name)),
        key=lambda p: _ROTATED_SUFFIX.search(p.name).group(1),  # type: ignore[union-attr]
    )
    live = log_dir / _LOG_BASENAME
    return [*rotated, *([live] if live.exists() else [])]


def read_run_events(run_id: str, log_dir: Path | None = None) -> list[dict]:
    """Every audit-log record for ``run_id``, from its ``RunStarted``
    through its ``RunFinished`` inclusive, in the order they were written.

    Returns ``[]`` when the run isn't found — rotated past the retention
    window, a typo'd id, or it never happened — an expected, common outcome
    for a caller (``LangGraphAgent._replay``) to report as "no such run",
    not an error. A run with no ``RunFinished`` yet (still in flight, or the
    process died mid-run) still returns whatever was collected — partial,
    real history beats discarding it over one missing line.

    Each returned record is exactly one audit-log JSON object (``message``,
    ``data``, ...) — decoding ``record["data"]`` back into a real
    ``AgentEvent`` (via ``cism.tui.events.decode``) is the caller's job,
    kept out of this module so it stays free of any dependency on the TUI
    event schema.
    """
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
