"""The pluggable seam that turns a tool call's result into DEPG nodes/edges
— the only place that knows how to read a specific tool's output. Adding a
new tool's heuristics means a new :class:`CauseExtractor`, registered;
nothing in ``cism/agent/`` changes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from langchain_core.messages import ToolMessage
from langchain_core.messages.tool import ToolCall

from cism.depg.edge import Edge
from cism.depg.evidence import Evidence
from cism.depg.graph import Graph
from cism.depg.node import Node, derive_node_id
from cism.depg.normalize import hash_signal

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
    """The fallback: every tool call becomes exactly one node, cause_class
    from the tool's name. No real output interpretation happens, so the
    evidence tier stays at the weakest (T3). Failures are captured too
    (verdict="dead"), not silently skipped."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        tool_name = message.name or "unknown-tool"
        failed = getattr(message, "status", "success") == "error"
        content = str(message.content)
        signal = hash_signal(content)
        call_id = call["id"] if call else message.tool_call_id
        node = Node(
            id=derive_node_id(tool_name, target, signal),
            cause_class=tool_name,
            target=target,
            signal=signal,
            evidence=[
                Evidence(
                    timestamp=_now_str(),
                    tool=tool_name,
                    exit_signal=_summarize(content),
                    tier="T3",
                    verdict="dead" if failed else "alive",
                    call_id=call_id,
                )
            ],
        )
        return Extraction(nodes=[node])


class ExtractorRegistry:
    """Dict-keyed-by-tool-name lookup. Unlike ``ToolRegistry.get()``, which
    raises on an unregistered name, an unrecognized tool here just means no
    specialized extractor exists yet — it degrades to the default."""

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


def _now_str() -> str:
    return datetime.now().strftime("%H:%M:%S")
