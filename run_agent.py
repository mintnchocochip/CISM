#!/usr/bin/env python
"""Run the CISM TUI against the real LangGraph-backed agent core.

Unlike ``demo_replay.py`` this does not replay a recorded log — it drives
``cism.agent.LangGraphAgent`` live, through the same ``Agent`` protocol.

With no flags, the agent falls back to whatever ``CISM_LLM_BASE_URL``/
``CISM_LLM_MODEL`` say (or ``DummyChatModel`` if neither is set — see
``cism/agent/core.py``). To point at a real OpenAI-compatible server
(llama.cpp, vLLM, LM Studio, real OpenAI, or Ollama's ``/v1`` endpoint)
without touching the environment::

    .venv/bin/pip install -e ".[dev,agent]"
    python run_agent.py --base-url http://localhost:11434/v1 --model qwen2.5:3b
    python run_agent.py --target 10.0.0.5 --base-url http://localhost:11434/v1 --model qwen2.5:3b

By default, tool calls run against ``dummy_nmap``/``dummy_msfconsole`` — no
real subprocess ever runs. Pass ``--live-tools`` to run the real catalog
(nmap/curl/hydra/...) instead, sandboxed via ``bwrap`` (bubblewrap) and
checked against a real ``ScopeGuardStage``/``DangerousFlagGuardStage``
action chain — this requires ``--scope`` (comma-separated CIDRs/domains
you're authorized against) and a working ``bwrap`` install::

    python run_agent.py --live-tools --scope 10.0.0.0/24,example.internal \\
        --base-url http://localhost:11434/v1 --model qwen2.5:3b

See ``cism/agent/`` for what's behind it and the design specs at
``docs/superpowers/specs/2026-08-29-real-llm-connector-wiring-design.md``
and ``docs/superpowers/specs/2026-09-08-live-tools-and-guardrail-wiring-design.md``.
"""

from __future__ import annotations

import argparse
import shutil
import sys

from cism.agent import LangGraphAgent
from cism.agent.guardrails import (
    DangerousFlagGuardStage,
    GuardrailChain,
    GuardrailSeam,
    PassThroughStage,
    ScopeGuardStage,
    parse_scope,
)
from cism.agent.llm import build_chat_model
from cism.agent.tools import CATALOG, ToolRegistry, build_toolkit, hydra
from cism.agent.tools.sandbox import BubblewrapRunner, set_default_runner
from cism.depg import EXTRACTORS
from cism.tui.app import CISMApp


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target", default="", help="initial target context, e.g. 10.0.0.5"
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="OpenAI-compatible endpoint, e.g. http://localhost:11434/v1",
    )
    parser.add_argument("--model", default="", help="model name/id on that server")
    parser.add_argument(
        "--key-env-var",
        default="CISM_API_KEY",
        help="name of the env var holding the API key (default: CISM_API_KEY)",
    )
    parser.add_argument(
        "--live-tools",
        action="store_true",
        help=(
            "run real tools (nmap/curl/hydra), sandboxed via bwrap (bubblewrap), "
            "instead of the dummy stubs"
        ),
    )
    parser.add_argument(
        "--scope",
        default="",
        help=(
            "engagement scope for --live-tools: comma-separated CIDRs/domains, "
            "e.g. 10.0.0.0/24,example.internal"
        ),
    )
    args = parser.parse_args(argv)
    if args.base_url and not args.model:
        parser.error("--base-url requires --model")
    if args.live_tools and not args.scope.strip():
        parser.error("--live-tools requires --scope (comma-separated CIDRs/domains)")
    return args


def _enable_live_tools(scope_spec: str) -> tuple[ToolRegistry, GuardrailSeam]:
    """Opts a live run into real tools: BubblewrapRunner as the process
    default Runner, the real CATALOG+hydra toolkit, and a real
    ScopeGuardStage/DangerousFlagGuardStage action chain built from
    scope_spec. Refuses (SystemExit) rather than degrading silently: no
    bwrap means no sandboxing, and an empty scope means ScopeGuardStage
    would block every call anyway — neither check mutates global state
    before both have passed."""
    if shutil.which("bwrap") is None:
        raise SystemExit(
            "--live-tools requires bubblewrap (bwrap) to be installed — "
            "install it, or omit --live-tools to use the dummy tools."
        )
    scope = parse_scope(scope_spec)
    if not scope.cidrs and not scope.domains:
        raise SystemExit(f"--scope {scope_spec!r} contained no usable CIDR or domain")

    set_default_runner(BubblewrapRunner())
    tools, _ = build_toolkit(CATALOG, [hydra], EXTRACTORS)
    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([ScopeGuardStage(scope), DangerousFlagGuardStage()]),
        output=GuardrailChain([PassThroughStage()]),
    )
    print(
        f"LIVE TOOLS ENABLED — real nmap/curl/hydra will run, sandboxed via bwrap "
        f"(bubblewrap), scoped to {scope_spec!r}. Ensure you have authorization for "
        f"any target you use.",
        file=sys.stderr,
    )
    return tools, guardrails


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    tools, guardrails = _enable_live_tools(args.scope) if args.live_tools else (None, None)

    if args.base_url:
        llm = build_chat_model(args.base_url, args.key_env_var, args.model)
        agent = LangGraphAgent(
            llm=llm,
            tools=tools,
            guardrails=guardrails,
            target=args.target,
            endpoint=args.base_url,
            model_name=args.model,
            key_env_var=args.key_env_var,
        )
    else:
        agent = LangGraphAgent(tools=tools, guardrails=guardrails, target=args.target)

    if agent._endpoint == "local (dummy)":
        print(
            "No real endpoint configured — running against the dummy backend.\n"
            "Pass --base-url/--model, or set CISM_LLM_BASE_URL/CISM_LLM_MODEL.",
            file=sys.stderr,
        )

    CISMApp(agent).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
