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

See ``cism/agent/`` for what's behind it and the design spec at
``docs/superpowers/specs/2026-08-29-real-llm-connector-wiring-design.md``.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys

from cism.agent import LangGraphAgent
from cism.agent.guardrails import EngagementScope
from cism.agent.llm import build_chat_model
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


def _parse_scope(value: str) -> EngagementScope:
    """Comma-separated CIDRs/domains -> EngagementScope. A bare IP widens
    to /32 the same way scope.py's own contains_network already treats
    one (ipaddress.ip_network(..., strict=False)); anything else that
    isn't parseable as a network is treated as a domain — contains_host
    does its own lowercase/suffix matching on those, so no further
    validation of domain shape happens here."""
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    domains: list[str] = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            cidrs.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            domains.append(token)
    return EngagementScope(cidrs=tuple(cidrs), domains=tuple(domains))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.base_url:
        llm = build_chat_model(args.base_url, args.key_env_var, args.model)
        agent = LangGraphAgent(
            llm=llm,
            target=args.target,
            endpoint=args.base_url,
            model_name=args.model,
            key_env_var=args.key_env_var,
        )
    else:
        agent = LangGraphAgent(target=args.target)

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
