#!/usr/bin/env python3
"""Convert a captured cism agent.log into a JSONL replay log that
cism/tui/replay.py's load_log()/FakeAgent can play back through the real
TUI -- the agent.log's own "data" field for each AgentEvent-shaped line is
already exactly events.encode()'s own output, so this just adds a "delay"
key (the real inter-event gap, capped) and drops everything that isn't a
known AgentEvent type (plain log lines like "tool exited non-zero")."""

import json
import sys
from pathlib import Path

KNOWN_TYPES = {
    "RunStarted", "RunFinished", "Narration", "NarrationRedacted",
    "ToolStarted", "ToolOutput", "ToolFinished", "ToolFailed",
    "PhaseChanged", "PhaseProposed", "ScopeChanged", "DEPGUpdated",
    "MemoryUpdated", "TokenDelta", "Interrupted", "SessionState",
}

MAX_GAP = 6.0  # cap any single real gap (e.g. the operator being away) at this many seconds


def main() -> int:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    kept, skipped = 0, 0
    prev_ts = None
    with src.open(encoding="utf-8") as f_in, dst.open("w", encoding="utf-8") as f_out:
        for raw in f_in:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                skipped += 1
                continue
            data = entry.get("data")
            if not isinstance(data, dict) or data.get("type") not in KNOWN_TYPES:
                skipped += 1
                continue
            ts = data.get("ts", entry.get("ts"))
            delay = 0.0 if prev_ts is None else min(max(ts - prev_ts, 0.0), MAX_GAP)
            prev_ts = ts
            out = dict(data)
            out["delay"] = round(delay, 3)
            f_out.write(json.dumps(out) + "\n")
            kept += 1
    print(f"wrote {kept} replay steps to {dst} ({skipped} non-event lines skipped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
