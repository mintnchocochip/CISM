"""Real cause-class extractors: regex-based NmapExtractor/HydraExtractor
parsing each tool's default plain-text output, plus LLMExtractor as the
fallback for any tool without a hand-written parser, and EXTRACTORS, the
tool-name -> extractor dict for the two regex-based ones.

LLMExtractor's structured-output call is pluggable (ExtractionBackend):
ChatModelExtractionBackend for LangChain models, LlamaCppExtractionBackend
for a llama.cpp server via json_schema. See AUDIT.md G1."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Literal, Protocol

import httpx
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.messages.tool import ToolCall
from pydantic import BaseModel

from cism.depg.evidence import Evidence
from cism.depg.extract import CauseExtractor, Extraction, GenericExtractor
from cism.depg.graph import Graph
from cism.depg.node import Node, derive_node_id

__all__ = [
    "EXTRACTORS",
    "ChatModelExtractionBackend",
    "ExtractedFinding",
    "ExtractedFindings",
    "ExtractionBackend",
    "HydraExtractor",
    "LLMExtractor",
    "LlamaCppExtractionBackend",
    "NmapExtractor",
]

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
                            source="deterministic",
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
                        source="deterministic",
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
                        source="deterministic",
                        verdict="dead",
                        call_id=call_id,
                    )
                ],
            )
        return Extraction(nodes=[node])


_MAX_PROMPT_CHARS = 6000

_PROMPT = (
    "You are extracting security findings from the raw output of {tool}, a "
    "penetration-testing tool.\n"
    "For each distinct finding, report: cause_class (a short label, e.g. "
    "'open-port', 'outdated-server-header'), signal (the specific fact, e.g. "
    "'443/tcp'), tier (T1=confirmed exploit/credential, T2=strong structured "
    "evidence like an open port or version string, T3=weak/unstructured "
    "evidence), verdict ('alive' if this finding is still relevant, 'dead' if "
    "the check failed or found nothing), evidence_quote (an exact substring "
    "of the output below that backs this claim, copied verbatim), and "
    "summary (one short sentence).\n"
    "Example: the line \"Server: Apache/2.2.8\" is cause_class "
    "'outdated-server-header', signal 'Apache/2.2.8', tier T2, verdict "
    "'alive', evidence_quote 'Server: Apache/2.2.8'.\n"
    "If there is nothing worth reporting, return an empty findings list.\n\n"
    "{tool} output{truncated_note}:\n{output}"
)


def _normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def _grounded(quote: str, content: str) -> bool:
    """Whitespace-insensitive substring check — a small model reproducing a
    quote with collapsed spaces or a dropped newline shouldn't lose a tier
    over formatting. An empty quote is never grounded."""
    normalized_quote = _normalize_whitespace(quote)
    if not normalized_quote:
        return False
    return normalized_quote in _normalize_whitespace(content)


class ExtractedFinding(BaseModel):
    cause_class: str
    signal: str
    tier: Literal["T1", "T2", "T3"]
    verdict: Literal["alive", "dead"]
    evidence_quote: str
    summary: str


class ExtractedFindings(BaseModel):
    findings: list[ExtractedFinding]


class ExtractionBackend(Protocol):
    """Turns a prompt into ExtractedFindings, or None on failure."""

    def extract(self, prompt: str) -> ExtractedFindings | None: ...


class ChatModelExtractionBackend:
    """Wraps a BaseChatModel's with_structured_output — the pre-existing
    behavior, now behind the ExtractionBackend seam."""

    def __init__(self, llm: BaseChatModel) -> None:
        self._llm = llm

    def extract(self, prompt: str) -> ExtractedFindings | None:
        try:
            structured = self._llm.with_structured_output(ExtractedFindings)
            return structured.invoke([HumanMessage(content=prompt)])
        except Exception:
            return None


class LlamaCppExtractionBackend:
    """Posts to a llama.cpp server's /completion with a json_schema
    constraint, so an unconstrained/non-tool-calling model still can't
    emit anything but valid ExtractedFindings JSON. Not live-tested — no
    llama.cpp server was reachable while building this."""

    def __init__(self, base_url: str, *, n_predict: int = 1024, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._n_predict = n_predict
        self._timeout = timeout

    def extract(self, prompt: str) -> ExtractedFindings | None:
        try:
            response = httpx.post(
                f"{self._base_url}/completion",
                json={
                    "prompt": prompt,
                    "json_schema": ExtractedFindings.model_json_schema(),
                    "n_predict": self._n_predict,
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            content = response.json().get("content", "")
            return ExtractedFindings.model_validate_json(content)
        except (httpx.HTTPError, ValueError):
            return None


class LLMExtractor:
    """Fallback CauseExtractor for any tool without a hand-written one.
    Grounding is mechanical (a substring check), not another LLM call. A
    backend returning None falls back to GenericExtractor — logged, not
    swallowed."""

    def __init__(self, backend: ExtractionBackend, *, logger: logging.Logger | None = None) -> None:
        self._backend = backend
        self._fallback = GenericExtractor()
        self._log = logger

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        content = str(message.content)
        tool = message.name or "unknown-tool"
        prompt_output = content
        truncated_note = ""
        if len(prompt_output) > _MAX_PROMPT_CHARS:
            prompt_output = prompt_output[:_MAX_PROMPT_CHARS]
            truncated_note = " (truncated)"

        prompt = _PROMPT.format(tool=tool, truncated_note=truncated_note, output=prompt_output)
        result = self._backend.extract(prompt)
        if result is None:
            if self._log is not None:
                self._log.warning(
                    "extraction backend unavailable, falling back to GenericExtractor",
                    extra={"data": {"tool": tool}},
                )
            return self._fallback.extract(call, message, graph, target)

        call_id = call["id"] if call else message.tool_call_id
        nodes = []
        for finding in result.findings:
            tier = finding.tier if _grounded(finding.evidence_quote, content) else "T3"
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
                            source="llm",
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
