"""The tool registry: a hard allowlist, not a convenience wrapper — the
only way a tool is reachable from the graph. ``get`` on an unregistered
name raises rather than falling back, so a bug fails loudly instead of
silently widening what the agent can execute."""

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
