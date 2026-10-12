#!/usr/bin/env python
"""§6.3 (BACKLOG.md): a standard benchmark harness — runs one full live
engagement and reports a fixed set of numbers from the resulting DEPG/
event stream: findings count, time-to-first-finding, and phase-completion
time (when each phase was first reached, relative to session start).

Deliberately a thin, standalone script rather than a mode of
``run_agent.py``: a benchmark run has no TUI and a different success
condition (did the numbers come out, not did a human watch it), so
sharing ``run_agent.py``'s ``main()`` would mean threading a
"headless" branch through code whose only other job is building the TUI.

Usage::

    python scripts/benchmark.py --target 172.28.0.3 --scope 172.28.0.3/32 \\
        --base-url http://localhost:8189/v1 --model lfm2.5-8b-a1b \\
        --backend llamacpp --turn "run nmap against the target"

Run it twice against an unchanged codebase before trusting a number it
reports to judge a future change — BACKLOG.md's own bar for this harness.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cism.agent import LangGraphAgent
from cism.agent.guardrails import (
    DangerousFlagGuardStage,
    GuardrailChain,
    GuardrailSeam,
    InputGuardStage,
    OutputRedactionStage,
    ScopeGuardStage,
    ToolOutputScreenStage,
    parse_scope,
)
from cism.agent.llm import build_chat_model
from cism.agent.logging import get_agent_logger
from cism.agent.tools import CATALOG, build_toolkit, hydra
from cism.agent.tools.sandbox import BubblewrapRunner, set_default_runner
from cism.depg import EXTRACTORS, ExtractorRegistry, LlamaCppExtractionBackend, LLMExtractor
from cism.tui.events import DEPGUpdated, PhaseChanged, RunFinished, drain


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True)
    ap.add_argument("--scope", required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--key-env-var", default="CISM_API_KEY")
    ap.add_argument("--key-file", default="")
    ap.add_argument("--max-tokens", type=int, default=2048)
    ap.add_argument("--backend", default="openai", choices=["openai", "llamacpp"])
    ap.add_argument(
        "--turn",
        action="append",
        dest="turns",
        default=[],
        help="a message to submit; repeat for multiple turns. Default: one recon prompt.",
    )
    ap.add_argument("--out", default="", help="write the JSON report here too")
    return ap.parse_args(argv)


async def _run(args: argparse.Namespace) -> dict:
    if args.key_file:
        os.environ[args.key_env_var] = Path(args.key_file).read_text().strip()

    scope = parse_scope(args.scope)
    set_default_runner(BubblewrapRunner())
    tools, _ = build_toolkit(CATALOG, [hydra], EXTRACTORS)
    guardrails = GuardrailSeam(
        input=GuardrailChain([InputGuardStage()]),
        action=GuardrailChain([ScopeGuardStage(scope), DangerousFlagGuardStage()]),
        output=GuardrailChain([OutputRedactionStage()]),
        tool_output=GuardrailChain([ToolOutputScreenStage()]),
    )
    llm = build_chat_model(args.base_url, args.key_env_var, args.model, max_tokens=args.max_tokens)
    # Without this, --backend llamacpp only picks the context-window probe
    # (LangGraphAgent._backend_kind) — the LLM-extraction fallback still
    # defaults to ChatModelExtractionBackend (generic LangChain
    # with_structured_output), never the backend actually tuned against a
    # real llama-server (90s timeout, raw /completion + json_schema; see
    # cism/depg/extractors.py). Mirrors run_agent.py's _llamacpp_extractors.
    extractors = None
    if args.backend == "llamacpp":
        backend = LlamaCppExtractionBackend(args.base_url)
        extractors = ExtractorRegistry(
            {**EXTRACTORS, "dummy_nmap": EXTRACTORS["nmap"]},
            LLMExtractor(backend, logger=get_agent_logger()),
        )
    agent = LangGraphAgent(
        llm=llm,
        tools=tools,
        guardrails=guardrails,
        extractors=extractors,
        target=args.target,
        endpoint=args.base_url,
        model_name=args.model,
        key_env_var=args.key_env_var,
        backend=args.backend,
    )

    turns = args.turns or ["recon and enumerate the target, then look for vulnerabilities"]

    start = time.monotonic()
    phase_completion: dict[str, float] = {}
    time_to_first_finding: float | None = None
    final_nodes: tuple = ()

    await agent.start()
    for turn in turns:
        await agent.submit(turn)
        finished = False
        while not finished:
            for event in await asyncio.wait_for(drain(agent.events), timeout=180.0):
                if isinstance(event, PhaseChanged) and event.phase not in phase_completion:
                    phase_completion[event.phase] = time.monotonic() - start
                elif isinstance(event, DEPGUpdated):
                    final_nodes = event.nodes
                    if time_to_first_finding is None and event.nodes:
                        time_to_first_finding = time.monotonic() - start
                elif isinstance(event, RunFinished):
                    finished = True
    await agent.aclose()

    resolved = [n for n in final_nodes if n.state == "resolved"]
    return {
        "target": args.target,
        "backend": args.backend,
        "model": args.model,
        "findings_count": len(resolved),
        "nodes_total": len(final_nodes),
        "time_to_first_finding_s": time_to_first_finding,
        "phase_completion_s": phase_completion,
        "total_time_s": time.monotonic() - start,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = asyncio.run(_run(args))
    print(json.dumps(report, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
