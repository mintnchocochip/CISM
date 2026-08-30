"""The state reducer: state is derived, never latched. See design spec §5."""

from __future__ import annotations

from typing import Protocol

from cism.depg.node import Node
from cism.tui.events import NodeState

__all__ = ["BinarySupport", "SupportPolicy", "reduce_state"]


class SupportPolicy(Protocol):
    def supported(self, node: Node, parents: list[Node]) -> bool: ...


class BinarySupport:
    """Basic policy: a parent is live or dead, edge weight ignored. The seam
    a graded gamma-propagation policy replaces later without touching
    reduce_state or its callers."""

    def supported(self, node: Node, parents: list[Node]) -> bool:
        return not parents or any(p.state != "blocked" for p in parents)


def _latest_direct_verdict(node: Node) -> str | None:
    for evidence in reversed(node.evidence):
        if evidence.verdict in ("alive", "dead"):
            return evidence.verdict
    return None


def reduce_state(node: Node, parents: list[Node], support: SupportPolicy) -> NodeState:
    verdict = _latest_direct_verdict(node)
    ok = support.supported(node, parents)

    if verdict == "dead":
        return "blocked"
    if verdict == "alive" and ok:
        return "resolved"
    if verdict == "alive":
        return "contested"
    if verdict is None and ok:
        return "untested"
    return "blocked"
