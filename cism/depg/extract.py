"""The pluggable seam that turns a tool call's result into DEPG nodes/edges
— the only place that knows how to read a specific tool's output. Adding a
new tool's heuristics means a new :class:`CauseExtractor`, registered;
nothing in ``cism/agent/`` changes."""

from __future__ import annotations

import re
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

#: 2026-10-18, live: curl and dnsenum have no hand-written CauseExtractor
#: (see EXTRACTORS, extractors.py) and fell through to LLMExtractor's own
#: fallback — which failed 3/3 times in one real engagement (backend
#: unavailable) — landing here every time. A real DB credential leaked via
#: an exposed .bak file then became a bare content-hash node, permanently
#: unreadable and stuck at T3 no matter what the raw tool output actually
#: contained. These patterns give any tool without a dedicated extractor,
#: and any tool whose LLM fallback just failed, a deterministic shot at a
#: grounded, legible finding instead of silently losing it. Regex match
#: against real output is the same evidentiary class as HydraExtractor's
#: own success regex — grounded, but (unlike an actual login attempt) not
#: independently verified as live, hence T2 not T1.
_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    # PHP-style config constants: define('DB_PASSWORD', 'secret')
    re.compile(
        r"""define\s*\(\s*['"]([A-Z_]*?(?:PASS|PWD|SECRET|API[_-]?KEY|TOKEN)[A-Z_]*)['"]"""
        r"""\s*,\s*['"]([^'"]*)['"]""",
        re.IGNORECASE,
    ),
    # Generic assignment: password=secret, api_key: "secret", DB_PASS = 'x'.
    # The key's own optional prefix (DB_, user_, ...) and the credential
    # word are one non-greedy run, not "a leading char, then the word" --
    # that first form eats the one character a bare "password"/"api_key"
    # (no prefix at all) needs the alternation itself to start on.
    re.compile(
        r"""\b(\w*?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)\w*?)"""
        r"""\s*[:=]\s*['"]?([^\s'";,)]+)""",
        re.IGNORECASE,
    ),
)


def _scan_for_credentials(content: str) -> list[tuple[str, str]]:
    """``(cause_class, signal)`` pairs for every credential-shaped
    key/value this regex scan finds in `content` — order-preserving,
    de-duplicated by key so the same constant repeated in output (e.g. a
    config file echoed twice) doesn't produce two nodes."""
    found: dict[str, str] = {}
    for pattern in _CREDENTIAL_PATTERNS:
        for key, value in pattern.findall(content):
            found.setdefault(key.strip(), value.strip())
    return [("credential-found", f"{key}={value}") for key, value in found.items()]


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
    (verdict="dead"), not silently skipped.

    Before falling all the way to that opaque node, it also runs a cheap
    deterministic credential-pattern scan (_scan_for_credentials) over the
    raw content — a real finding a tool without its own extractor (or
    whose LLM-backed extraction just failed) would otherwise lose outright."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        tool_name = message.name or "unknown-tool"
        failed = getattr(message, "status", "success") == "error"
        content = str(message.content)
        call_id = call["id"] if call else message.tool_call_id

        credential_nodes = [
            Node(
                id=derive_node_id(cause_class, target, signal),
                cause_class=cause_class,
                target=target,
                signal=signal,
                evidence=[
                    Evidence(
                        timestamp=_now_str(),
                        tool=tool_name,
                        exit_signal=signal,
                        tier="T2",
                        source="deterministic",
                        verdict="dead" if failed else "alive",
                        call_id=call_id,
                    )
                ],
            )
            for cause_class, signal in (() if failed else _scan_for_credentials(content))
        ]
        if credential_nodes:
            return Extraction(nodes=credential_nodes)

        signal = hash_signal(content)
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
                    source="unverified",
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
