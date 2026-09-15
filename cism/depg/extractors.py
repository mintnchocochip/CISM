"""Real cause-class extractors: regex-based NmapExtractor/HydraExtractor
parsing each tool's default plain-text output, plus LLMExtractor as the
fallback for any tool without a hand-written parser, and EXTRACTORS, the
tool-name -> extractor dict for the two regex-based ones."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.messages.tool import ToolCall
from pydantic import BaseModel

from cism.depg.evidence import Evidence
from cism.depg.extract import CauseExtractor, Extraction, GenericExtractor
from cism.depg.graph import Graph
from cism.depg.node import Node, derive_node_id

__all__ = ["EXTRACTORS", "ExtractedFinding", "ExtractedFindings", "HydraExtractor", "LLMExtractor", "NmapExtractor"]

_OPEN_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", re.MULTILINE)
_HYDRA_SUCCESS_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)")


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _call_id(call: ToolCall | None, message: ToolMessage) -> str:
    return call["id"] if call else message.tool_call_id


class NmapExtractor:
    """One node per open port — a single scan can and should produce several
    nodes, not one node per call."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        content = str(message.content)
        call_id = _call_id(call, message)
        nodes = []
        for port, proto, service in _OPEN_PORT_RE.findall(content):
            signal = f"{port}/{proto}"
            nodes.append(
                Node(
                    id=derive_node_id("open-port", target, signal),
                    cause_class="open-port",
                    target=target,
                    signal=signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(),
                            tool="nmap",
                            exit_signal=f"{signal} {service}",
                            tier="T2",
                            verdict="alive",
                            call_id=call_id,
                        )
                    ],
                )
            )
        return Extraction(nodes=nodes)


class HydraExtractor:
    """Success becomes a confirmed credential (T1); failure or an error
    status becomes a tombstone (T3) so the agent doesn't retry the identical
    attempt."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        call_id = _call_id(call, message)
        content = str(message.content)
        failed = getattr(message, "status", "success") == "error"
        service = (call["args"].get("service") if call else None) or "unknown"
        match = None if failed else _HYDRA_SUCCESS_RE.search(content)

        if match:
            user, password = match.groups()
            signal = f"{user}:{password}"
            node = Node(
                id=derive_node_id("credential-found", target, signal),
                cause_class="credential-found",
                target=target,
                signal=signal,
                evidence=[
                    Evidence(
                        timestamp=_now(),
                        tool="hydra",
                        exit_signal=content[:80],
                        tier="T1",
                        verdict="alive",
                        call_id=call_id,
                    )
                ],
            )
        else:
            signal = f"{service}:no-match"
            node = Node(
                id=derive_node_id("credential-attempt", target, signal),
                cause_class="credential-attempt",
                target=target,
                signal=signal,
                evidence=[
                    Evidence(
                        timestamp=_now(),
                        tool="hydra",
                        exit_signal=content[:80],
                        tier="T3",
                        verdict="dead",
                        call_id=call_id,
                    )
                ],
            )
        return Extraction(nodes=[node])


_PROMPT = (
    "You are extracting security findings from a penetration-testing tool's "
    "raw output.\n"
    "For each distinct finding, report: cause_class (a short label, e.g. "
    "'open-port', 'outdated-server-header'), signal (the specific fact, e.g. "
    "'443/tcp'), tier (T1=confirmed exploit/credential, T2=strong structured "
    "evidence like an open port or version string, T3=weak/unstructured "
    "evidence), verdict ('alive' if this finding is still relevant, 'dead' if "
    "the check failed or found nothing), evidence_quote (an exact substring "
    "of the output below that backs this claim), and summary (one short "
    "sentence).\n"
    "If there is nothing worth reporting, return an empty findings list.\n\n"
    "Tool output:\n{output}"
)


class ExtractedFinding(BaseModel):
    cause_class: str
    signal: str
    tier: Literal["T1", "T2", "T3"]
    verdict: Literal["alive", "dead"]
    evidence_quote: str
    summary: str


class ExtractedFindings(BaseModel):
    findings: list[ExtractedFinding]


class LLMExtractor:
    """Fallback CauseExtractor for any tool without a hand-written one.
    Grounding is mechanical (a substring check), never another LLM call: a
    finding whose evidence_quote isn't in the tool's own output gets its
    tier clamped to T3 rather than dropped. Any exception falls back to
    GenericExtractor's plain one-weak-T3-node behavior."""

    def __init__(self, llm: BaseChatModel) -> None:
        self._llm = llm
        self._fallback = GenericExtractor()

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        try:
            structured = self._llm.with_structured_output(ExtractedFindings)
            result = structured.invoke([HumanMessage(content=_PROMPT.format(output=message.content))])
        except Exception:
            return self._fallback.extract(call, message, graph, target)

        content = str(message.content)
        call_id = call["id"] if call else message.tool_call_id
        nodes = []
        for finding in result.findings:
            tier = finding.tier if finding.evidence_quote in content else "T3"
            nodes.append(
                Node(
                    id=derive_node_id(finding.cause_class, target, finding.signal),
                    cause_class=finding.cause_class,
                    target=target,
                    signal=finding.signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(),
                            tool=message.name or "unknown-tool",
                            exit_signal=finding.summary,
                            tier=tier,
                            verdict=finding.verdict,
                            call_id=call_id,
                        )
                    ],
                )
            )
        return Extraction(nodes=nodes) if nodes else self._fallback.extract(call, message, graph, target)


EXTRACTORS: dict[str, CauseExtractor] = {
    "nmap": NmapExtractor(),
    "hydra": HydraExtractor(),
}
