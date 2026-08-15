#!/usr/bin/env python
"""Run the CISM TUI against the real LangGraph-backed agent core.

Unlike ``demo_replay.py`` this does not replay a recorded log — it drives
``cism.agent.LangGraphAgent`` live, through the same ``Agent`` protocol.
Still a skeleton underneath, though: a canned ``DummyChatModel`` and two
dummy tools, no real model, no real scanners, guardrails wired as
pass-throughs. See ``cism/agent/`` for what's behind it and the design spec
at ``docs/superpowers/specs/2026-08-15-agent-workflow-skeleton-design.md``
for what isn't built yet.

Requires the ``agent`` extra::

    .venv/bin/pip install -e ".[dev,agent]"
    python run_agent.py
    python run_agent.py --target 10.0.0.5
"""

from __future__ import annotations

import argparse

from cism.agent import LangGraphAgent
from cism.tui.app import CISMApp


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target", default="", help="initial target context, e.g. 10.0.0.5"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    agent = LangGraphAgent(target=args.target)
    CISMApp(agent).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
