"""Precondition-linking: which prior node a new tool call actually depended
on. See the design spec's edge-creation section for why the fallback is a
last resort, not the primary rule.
"""

from __future__ import annotations

import re

from langchain_core.messages.tool import ToolCall

from cism.depg.graph import Graph
from cism.depg.node import Node

__all__ = ["find_precondition"]

#: Letter-led word tokens (http, ssh, ftp, ...) out of a compound arg value
#: like a URL — e.g. "http://10.0.0.5/admin" must still yield "http" so it
#: can match nmap's "80/tcp http" evidence. Starting on a letter (not a
#: digit) keeps IP-address octets from being pulled out as spurious tokens.
_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")


def find_precondition(graph: Graph, target: str, call: ToolCall | None) -> Node | None:
    """Finds a same-target node whose signal or latest evidence mentions
    something this call's args reference (e.g. hydra's service="ssh"
    matching nmap's "22/tcp open ssh"). Falls back to the most recently
    touched node on this target — a wrong edge is worse than a missing one.

    Two passes, exact before loose: nmap names one service "ccproxy-ftp",
    which contains "ftp" as a plain substring of a different, unrelated
    service — a single substring pass would let hydra's service="ftp" call
    match that node instead of the real ftp one. Exact whole-word equality
    is tried first and wins whenever it finds anything; substring is only a
    fallback for tokens (like a version string) that are never a whole word
    on their own."""
    tokens = _reference_tokens(call)
    normalized = {t.lower() for t in tokens if t}
    candidates = [n for n in graph.nodes.values() if n.target == target]

    for node in reversed(candidates):
        if normalized & _words(_haystack(node)):
            return node

    for node in reversed(candidates):
        haystack = _haystack(node)
        if any(token and token in haystack for token in tokens):
            return node

    fallback_id = graph.last_for_target.get(target)
    if fallback_id and fallback_id in graph.nodes:
        return graph.nodes[fallback_id]
    return None


def _haystack(node: Node) -> str:
    haystack = node.signal
    if node.evidence:
        haystack += " " + node.evidence[-1].exit_signal
    return haystack


def _words(text: str) -> set[str]:
    """Whitespace-only split, not tokenized further — "ccproxy-ftp" must
    stay one word so it can't exact-match the substring "ftp"."""
    return set(text.lower().split())


def _reference_tokens(call: ToolCall | None) -> list[str]:
    """Whole arg values (e.g. "ssh" matching directly) plus their letter-led
    sub-words, so a compound value like "http://10.0.0.5" still contributes
    "http" instead of only ever being compared as one unmatchable string."""
    if call is None:
        return []
    args = call.get("args") or {}
    tokens: list[str] = []
    for v in args.values():
        if not isinstance(v, str):
            continue
        tokens.append(v)
        tokens.extend(_WORD_RE.findall(v))
    return tokens
