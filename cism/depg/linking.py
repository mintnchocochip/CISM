"""Precondition-linking: which prior node a new tool call actually depended
on. See the design spec's edge-creation section for why the fallback is a
last resort, not the primary rule.
"""

from __future__ import annotations

from langchain_core.messages.tool import ToolCall

from cism.depg.graph import Graph
from cism.depg.node import Node

__all__ = ["find_precondition"]


def find_precondition(graph: Graph, target: str, call: ToolCall | None) -> Node | None:
    """Looks for a same-target node whose own signal or latest evidence
    mentions something this call's own arguments reference (e.g. hydra's
    service="ssh" matching nmap's "22/tcp open ssh" evidence). Falls back to
    the most recently touched node on this target when nothing matches — a
    guess of last resort, since a wrong edge is worse than a missing one.
    """
    tokens = _reference_tokens(call)
    candidates = [n for n in graph.nodes.values() if n.target == target]

    for node in reversed(candidates):
        haystack = node.signal
        if node.evidence:
            haystack += " " + node.evidence[-1].exit_signal
        if any(token and token in haystack for token in tokens):
            return node

    fallback_id = graph.last_for_target.get(target)
    if fallback_id and fallback_id in graph.nodes:
        return graph.nodes[fallback_id]
    return None


def _reference_tokens(call: ToolCall | None) -> list[str]:
    if call is None:
        return []
    args = call.get("args") or {}
    return [str(v) for v in args.values() if isinstance(v, str)]
