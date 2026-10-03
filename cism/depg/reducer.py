"""The state reducer: state is derived, never latched. See design spec §5."""

from __future__ import annotations

from typing import Protocol

from cism.depg.evidence import Evidence
from cism.depg.node import Node
from cism.tui.events import NodeState

__all__ = ["BinarySupport", "GradedSupport", "SupportPolicy", "reduce_state"]


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


def _latest_direct_evidence(node: Node) -> Evidence | None:
    for evidence in reversed(node.evidence):
        if evidence.verdict in ("alive", "dead"):
            return evidence
    return None


#: alive+tier -> intrinsic score before any parent is considered.
_TIER_WEIGHT: dict[str, float] = {"T1": 1.0, "T2": 0.8, "T3": 0.5}
#: No evidence yet -> not impossible, just unproven.
_UNTESTED_PRIOR = 0.3
#: source != "deterministic": only the quote is verified (_grounded, extractors.py),
#: not the T1/T2/T3 severity call itself — discount it.
_LLM_DISCOUNT = 0.85
_RESOLVED_THRESHOLD = 0.6
_BLOCKED_THRESHOLD = 0.15
#: settle()'s convergence bound for GradedSupport's continuous score.
CONVERGENCE_EPSILON = 1e-3


def _intrinsic_score(evidence: Evidence | None) -> float:
    if evidence is None:
        return _UNTESTED_PRIOR
    if evidence.verdict == "dead":
        return 0.0
    score = _TIER_WEIGHT[evidence.tier]
    if evidence.source != "deterministic":
        score *= _LLM_DISCOUNT
    return score


def _discretize(verdict: str | None, score: float) -> NodeState:
    if verdict == "dead":
        return "blocked"
    if verdict == "alive":
        return "resolved" if score >= _RESOLVED_THRESHOLD else "contested"
    return "untested" if score > _BLOCKED_THRESHOLD else "blocked"


class GradedSupport:
    """Noisy-OR reachability over weighted edges (AUDIT.md A3), replacing
    BinarySupport's any-non-blocked-parent flood fill. Opt-in via
    graph.settle(support=GradedSupport()) — BinarySupport stays the default
    until this is validated against a real run.

    r(node) = s0(node) * (1 - prod_over_parents(1 - weight * r(parent))):
    a node needs *any* weighted-live precondition, same "any" shape as
    BinarySupport.supported, just continuous instead of boolean. s0 = 0
    (dead) always wins regardless of parents, matching reduce_state.
    """

    def evaluate(
        self, node: Node, weighted_parents: list[tuple[Node, float]]
    ) -> tuple[NodeState, float]:
        evidence = _latest_direct_evidence(node)
        s0 = _intrinsic_score(evidence)
        if weighted_parents:
            miss = 1.0
            for parent, weight in weighted_parents:
                miss *= 1.0 - max(0.0, min(weight, 1.0)) * parent.reachability
            score = s0 * (1.0 - miss)
        else:
            score = s0
        score = max(0.0, min(score, 1.0))
        state = _discretize(evidence.verdict if evidence else None, score)
        return state, score


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
