"""Common Linux utilities, wired through the same sandboxed runner as the
security tools — a plain passthrough shape, no scratch-dir pre-writes or
special framing needed.
"""

from __future__ import annotations

import shlex

from langchain_core.tools import tool

from cism.agent.tools.sandbox import run_sandboxed

__all__ = ["LINUX_TOOLS", "curl"]


@tool
def curl(url: str, options: str = "-sS") -> str:
    """Fetch a URL with curl and return its response."""
    return run_sandboxed(["curl", *shlex.split(options), url])


LINUX_TOOLS = [curl]
