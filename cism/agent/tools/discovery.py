"""Host/network discovery and DNS/subdomain tools. Real, subprocess-backed
implementations — unlike ``dummy.py``, these execute actual binaries via
:func:`cism.agent.tools.sandbox.run_sandboxed` and are opt-in (see
``cism/agent/tools/catalog.py``), never ``LangGraphAgent()``'s bare default.
"""

from __future__ import annotations

import shlex

from langchain_core.tools import tool

from cism.agent.tools.sandbox import run_sandboxed

__all__ = ["DISCOVERY_TOOLS", "nmap"]


@tool
def nmap(target: str, options: str = "-sV") -> str:
    """Run nmap against a target and return its raw scan output."""
    return run_sandboxed(["nmap", *shlex.split(options), target])


DISCOVERY_TOOLS = [nmap]
