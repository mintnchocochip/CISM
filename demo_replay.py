#!/usr/bin/env python
"""Run the CISM TUI against a recorded event log.

No lab, no model weights, no network — the whole surface is demoable from a
JSONL file::

    python demo_replay.py
    python demo_replay.py --speed 3
    python demo_replay.py --log demo/recon_run.jsonl --loop
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cism.tui.app import CISMApp
from cism.tui.replay import FakeAgent, ReplayLogError, load_log

DEFAULT_LOG = Path(__file__).parent / "demo" / "recon_run.jsonl"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--log", type=Path, default=DEFAULT_LOG, help="JSONL event log to replay"
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="playback speed multiplier (0 removes every pause)",
    )
    parser.add_argument(
        "--loop", action="store_true", help="replay the log continuously"
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="do not start playback until the first user turn",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        steps = load_log(args.log)
    except ReplayLogError as error:
        # Fail before the app mounts so a broken log never half-starts a demo.
        print(f"replay log error: {error}", file=sys.stderr)
        return 2

    agent = FakeAgent(
        steps,
        speed=args.speed,
        autostart=not args.wait,
        loop_forever=args.loop,
    )
    CISMApp(agent).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
