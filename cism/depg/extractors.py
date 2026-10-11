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
    "GobusterExtractor",
    "HydraExtractor",
    "LLMExtractor",
    "LlamaCppExtractionBackend",
    "NmapExtractor",
    "SqlmapExtractor",
]

_OPEN_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", re.MULTILINE)
_HYDRA_SUCCESS_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)")
#: sqlmap's own grammar for a confirmed injection point — "Parameter: id
#: (GET)" followed by a "Type: ..." line (with or without a blank line
#: between them, hence the optional \n\s* rather than a fixed gap).
_SQLMAP_PARAM_RE = re.compile(r"Parameter:\s*(\S+)\s*\((\w+)\)\s*\n\s*Type:\s*(.+)")
_GOBUSTER_HIT_RE = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)", re.MULTILINE)


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


class SqlmapExtractor:
    """One node per confirmed injectable parameter (T1 — sqlmap only reports
    "Parameter: X" after actually confirming injection, not on a guess).
    No match becomes a single dead tombstone, same anti-retry purpose as
    HydraExtractor's failure case."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        content = str(message.content)
        call_id = _call_id(call, message)
        matches = _SQLMAP_PARAM_RE.findall(content)
        if not matches:
            signal = "no-injection-found"
            return Extraction(nodes=[
                Node(
                    id=derive_node_id("sql-injection-attempt", target, signal),
                    cause_class="sql-injection-attempt",
                    target=target,
                    signal=signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(), tool="sqlmap", exit_signal=content[:80],
                            tier="T3", source="deterministic", verdict="dead", call_id=call_id,
                        )
                    ],
                )
            ])
        nodes = []
        for param, method, inj_type in matches:
            signal = f"{param} ({method})"
            nodes.append(
                Node(
                    id=derive_node_id("sql-injection", target, signal),
                    cause_class="sql-injection",
                    target=target,
                    signal=signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(), tool="sqlmap",
                            exit_signal=f"{signal}: {inj_type.strip()}",
                            tier="T1", source="deterministic", verdict="alive", call_id=call_id,
                        )
                    ],
                )
            )
        return Extraction(nodes=nodes)


#: gobuster's default status-code filter already excludes 404, but that
#: default isn't guaranteed (an operator can widen it with -s), so this
#: extractor never trusts the tool's own filtering for what counts as
#: "found" — a 404 is explicitly not a finding here either way.
_GOBUSTER_NOT_FOUND = frozenset({"404"})


class GobusterExtractor:
    """One node per discovered path. Nothing found is not itself a fact
    worth tracking (unlike hydra/sqlmap, there's no single "the attempt
    failed" claim to tombstone against retrying)."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        content = str(message.content)
        call_id = _call_id(call, message)
        nodes = []
        for path, status in _GOBUSTER_HIT_RE.findall(content):
            if status in _GOBUSTER_NOT_FOUND:
                continue
            signal = f"{path} ({status})"
            nodes.append(
                Node(
                    id=derive_node_id("exposed-path", target, signal),
                    cause_class="exposed-path",
                    target=target,
                    signal=signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(), tool="gobuster", exit_signal=signal,
                            tier="T2", source="deterministic", verdict="alive", call_id=call_id,
                        )
                    ],
                )
            )
        return Extraction(nodes=nodes)


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
    emit anything but valid ExtractedFindings JSON. Live-tested 2026-10-11
    against a real llama-server + LFM2.5-8B-A1B-Q4_K_M — the endpoint and
    grammar constraint both work; see the ``timeout`` note below for the
    one real issue that run surfaced."""

    def __init__(self, base_url: str, *, n_predict: int = 1024, timeout: float = 90.0) -> None:
        # §2.2 live-test (2026-10-11, real llama-server + LFM2.5-8B-A1B-Q4_K_M):
        # a real nikto-sized prompt under this schema's GBNF grammar
        # constraint took noticeably longer than simple unconstrained
        # completions: 30s produced a silent-to-user (but logged, G1)
        # fallback to GenericExtractor on the very first live call.
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
        #: H3: how many times this extractor has dropped to GenericExtractor
        #: because the real backend returned None — read by LangGraphAgent
        #: into its per-run metrics line.
        self.fallback_count = 0

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
            self.fallback_count += 1
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
    "sqlmap": SqlmapExtractor(),
    "gobuster": GobusterExtractor(),
}
