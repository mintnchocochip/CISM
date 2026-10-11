#!/usr/bin/env python
"""Run the CISM TUI against the real LangGraph-backed agent core (unlike
``demo_replay.py``, which replays a recorded log).

With no flags, falls back to ``CISM_LLM_BASE_URL``/``CISM_LLM_MODEL`` (or
``DummyChatModel`` if neither is set). To point at a real OpenAI-compatible
server (llama.cpp, vLLM, LM Studio, OpenAI, Ollama's ``/v1``)::

    .venv/bin/pip install -e ".[dev,agent]"
    python run_agent.py --base-url http://localhost:11434/v1 --model qwen2.5:3b
    python run_agent.py --target 10.0.0.5 --base-url http://localhost:11434/v1 --model qwen2.5:3b

By default, tool calls run against ``dummy_nmap``/``dummy_msfconsole`` — no
real subprocess ever runs. Pass ``--live-tools`` to run the real catalog
sandboxed via ``bwrap``, checked by a real ScopeGuardStage/
DangerousFlagGuardStage action chain plus input length capping, output
redaction, and tool-output injection screening; requires ``--scope`` and ``bwrap``::

    python run_agent.py --live-tools --scope 10.0.0.0/24,example.internal \\
        --base-url http://localhost:11434/v1 --model qwen2.5:3b
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from cism.agent import LangGraphAgent
from cism.agent.guardrails import (
    DangerousFlagGuardStage,
    GuardrailChain,
    GuardrailSeam,
    InputGuardStage,
    OutputRedactionStage,
    PrivacyGateway,
    PrivacySwapOutStage,
    ScopeGuardStage,
    ToolOutputScreenStage,
    parse_scope,
)
from cism.agent.llm import build_chat_model
from cism.agent.logging import get_agent_logger
from cism.agent.tools import CATALOG, ToolRegistry, build_toolkit, hydra
from cism.agent.tools.sandbox import BubblewrapRunner, set_default_runner
from cism.depg import EXTRACTORS, ExtractorRegistry, GenericExtractor, LLMExtractor, LlamaCppExtractionBackend
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
        "--key-file",
        default="",
        help=(
            "path to a file containing the API key, read at startup into "
            "--key-env-var. Prefer this over -e/--env-file in a container run: "
            "those bake the literal value into Config.Env, which `docker "
            "inspect` shows in full; a bind-mounted secret file only ever "
            "exposes its path there, never its contents"
        ),
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help=(
            "cap on completion tokens, passed through to the server. Reasoning "
            "models (e.g. LFM2.5) spend tokens thinking before they answer, so "
            "too low a cap truncates the reply before a tool call is emitted — "
            "2048+ is a safe default for those."
        ),
    )
    parser.add_argument(
        "--backend",
        default="openai",
        choices=["openai", "llamacpp"],
        help="how DEPG findings get extracted: 'openai' (default, needs function calling) or 'llamacpp' (json_schema-constrained /completion call)",
    )
    parser.add_argument(
        "--graded-propagation",
        action="store_true",
        help=(
            "use GradedSupport's continuous reachability score instead of "
            "BinarySupport's any-non-blocked-parent flood fill when settling "
            "the DEPG (opt-in; AUDIT.md's bar for flipping this default is "
            "validation against several real runs, not one)"
        ),
    )
    parser.add_argument(
        "--anonymize",
        action="store_true",
        help=(
            "Privacy Gateway (opt-in): the model only ever sees <ip-N>/<host-N> "
            "placeholders for the target's real IP/scope domains, in its prompt "
            "and in tool output fed back to it. The operator (this TUI) and the "
            "actual sandboxed tool calls still see/use the real values the whole "
            "time — this only ever changes what the model reads and writes."
        ),
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


def _enable_live_tools(
    scope_spec: str, privacy: PrivacyGateway | None = None
) -> tuple[ToolRegistry, GuardrailSeam]:
    """Opts a live run into real tools: BubblewrapRunner as the default
    Runner, the real CATALOG+hydra toolkit, and a real guardrail seam —
    ScopeGuardStage/DangerousFlagGuardStage on actions, a length cap on
    input, redaction on the final answer, and injection screening on tool
    output fed back to the model (C1, AUDIT.md). Refuses (SystemExit)
    rather than degrading silently if bwrap or a usable scope is missing."""
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
    # Privacy Gateway's swap-out, if enabled, must run first — scope/
    # dangerous-flag checks need the real value a call will actually run
    # against, not a placeholder that means nothing outside the gateway.
    action_stages = []
    if privacy is not None:
        action_stages.append(PrivacySwapOutStage(privacy))
    action_stages += [ScopeGuardStage(scope), DangerousFlagGuardStage()]
    guardrails = GuardrailSeam(
        input=GuardrailChain([InputGuardStage()]),
        action=GuardrailChain(action_stages),
        output=GuardrailChain([OutputRedactionStage()]),
        tool_output=GuardrailChain([ToolOutputScreenStage()]),
    )
    print(
        f"LIVE TOOLS ENABLED — real nmap/curl/hydra will run, sandboxed via bwrap "
        f"(bubblewrap), scoped to {scope_spec!r}. Ensure you have authorization for "
        f"any target you use.",
        file=sys.stderr,
    )
    return tools, guardrails


def _llamacpp_extractors(base_url: str) -> ExtractorRegistry:
    """Same regex extractors LangGraphAgent defaults to, but the LLM
    fallback goes through LlamaCppExtractionBackend."""
    backend = LlamaCppExtractionBackend(base_url)
    tool_extractors = {**EXTRACTORS, "dummy_nmap": EXTRACTORS["nmap"]}
    return ExtractorRegistry(
        tool_extractors, LLMExtractor(backend, logger=get_agent_logger())
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.key_file:
        os.environ[args.key_env_var] = Path(args.key_file).read_text().strip()

    privacy = None
    if args.anonymize:
        domains = parse_scope(args.scope).domains if args.scope.strip() else frozenset()
        privacy = PrivacyGateway(domains=domains)

    tools, guardrails = (
        _enable_live_tools(args.scope, privacy) if args.live_tools else (None, None)
    )

    if args.base_url:
        llm_kwargs = {"max_tokens": args.max_tokens} if args.max_tokens else {}
        llm = build_chat_model(args.base_url, args.key_env_var, args.model, **llm_kwargs)
        extractors = _llamacpp_extractors(args.base_url) if args.backend == "llamacpp" else None
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
            graded_propagation=args.graded_propagation,
            privacy=privacy,
        )
    else:
        agent = LangGraphAgent(
            tools=tools, guardrails=guardrails, target=args.target, privacy=privacy
        )

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
