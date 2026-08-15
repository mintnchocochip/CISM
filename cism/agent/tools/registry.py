"""The tool registry: a hard allowlist, not a convenience wrapper.

This is the only way a tool is ever reachable from the graph. There is no
dynamic lookup by arbitrary name and no fallback — ``get`` on a name that
was not explicitly registered raises, so a bug here fails loudly instead of
silently widening what the agent can execute.

Whether a future tool is a hand-written wrapper around a real binary (nmap,
msfconsole) or an existing LangChain/community tool the agent is allowed to
reuse as-is, it becomes reachable the same way: constructed into a
``ToolRegistry``. Neither ``graph.py`` nor ``nodes.py`` changes when the
dummy tools here are swapped for real ones — only the registry's
construction site does.
"""

from __future__ import annotations

from langchain_core.tools import BaseTool

__all__ = ["ToolRegistry"]


class ToolRegistry:
    def __init__(self, tools: list[BaseTool]) -> None:
        self._tools: dict[str, BaseTool] = {t.name: t for t in tools}

    def all(self) -> list[BaseTool]:
        return list(self._tools.values())

    def get(self, name: str) -> BaseTool:
        return self._tools[name]

    def __contains__(self, name: str) -> bool:
        return name in self._tools
