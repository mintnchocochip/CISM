"""Dummy tools: canned output, no subprocess, no network.

These exist so the graph's tool-calling loop can be validated end to end
with no lab and no real offensive tooling installed — the same philosophy
``cism/tui/replay.py`` already applies to the TUI side. Swapping these for
real tools later is a matter of registering different ``BaseTool``
instances; see :mod:`cism.agent.tools.registry`.

Note: the nmap tool's flags parameter is named ``options``, not ``args`` —
``args`` collides with LangChain's own tool-call plumbing and raises at
call time.
"""

from __future__ import annotations

from langchain_core.tools import tool

__all__ = ["dummy_msfconsole", "dummy_nmap"]


@tool
def dummy_nmap(target: str, options: str = "-sV") -> str:
    """Run a dummy nmap scan against a target and return canned output."""
    return f"[dummy] nmap {options} {target} -> 3 open ports (22,80,443)"


@tool
def dummy_msfconsole(module: str, target: str) -> str:
    """Run a dummy msfconsole module against a target and return a canned result."""
    return f"[dummy] msfconsole use {module} against {target} -> session not opened (stub)"
