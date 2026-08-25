"""The pluggable seam that turns a tool call's result into DEPG nodes/edges.

This is deliberately the only place that knows how to read a specific
tool's output. Swapping in real cause-class heuristics later (regexing real
nmap/msfconsole output, say) means adding a new :class:`CauseExtractor` and
registering it — nothing in ``cism/agent/`` changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from langchain_core.messages import ToolMessage
from langchain_core.messages.tool import ToolCall

from cism.depg.edge import Edge
from cism.depg.graph import Graph
from cism.depg.node import Node
from cism.tui.events import Evidence

__all__ = ["CauseExtractor", "Extraction", "ExtractorRegistry", "GenericExtractor"]

_SUMMARY_LIMIT = 80


@dataclass(frozen=True, slots=True)
class Extraction:
    """What one extractor call proposes adding to the graph."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)


class CauseExtractor(Protocol):
    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction: ...


class GenericExtractor:
    """The fallback: every successful tool call becomes exactly one untested
    node, cause_class taken from the tool's own name. No real interpretation
    of the output happens here, so the evidence tier stays at the weakest
    (T3) rather than implying a confidence that hasn't been earned yet."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        tool_name = message.name or "unknown-tool"
        node = Node(
            id=message.tool_call_id,
            cause_class=tool_name,
            target=target,
            evidence=[
                Evidence(
                    timestamp=datetime.now().strftime("%H:%M:%S"),
                    tool=tool_name,
                    exit_signal=_summarize(message.content),
                    tier="T3",
                )
            ],
        )
        return Extraction(nodes=[node])


class ExtractorRegistry:
    """Dict-keyed-by-tool-name lookup, mirroring :class:`ToolRegistry`'s
    shape — but unlike ``ToolRegistry.get()``, which raises on an
    unregistered name because that's a programming bug, an unrecognized
    tool here is expected: it just means no specialized extractor exists
    yet, so the default degrades gracefully instead of failing the run."""

    def __init__(self, extractors: dict[str, CauseExtractor], default: CauseExtractor) -> None:
        self._extractors = dict(extractors)
        self._default = default

    def get(self, tool_name: str) -> CauseExtractor:
        return self._extractors.get(tool_name, self._default)


def _summarize(content: object) -> str:
    text = str(content)
    if len(text) <= _SUMMARY_LIMIT:
        return text
    return text[: _SUMMARY_LIMIT - 1] + "…"
