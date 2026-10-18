"""Real cause-class extractors: regex-based NmapExtractor/HydraExtractor
parsing each tool's default plain-text output, plus LLMExtractor as the
fallback for any tool without a hand-written parser, and EXTRACTORS, the
tool-name -> extractor dict for the regex-based ones.

LLMExtractor's structured-output call is pluggable (ExtractionBackend):
ChatModelExtractionBackend for LangChain models, LlamaCppExtractionBackend
for a llama.cpp server via json_schema. See AUDIT.md G1."""

from __future__ import annotations

import json
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
    "NiktoExtractor",
    "NmapExtractor",
    "SqlmapExtractor",
    "Wafw00fExtractor",
    "WhatwebExtractor",
]

_OPEN_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", re.MULTILINE)
_HYDRA_SUCCESS_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)")
#: sqlmap's own grammar for a confirmed injection point — "Parameter: id
#: (GET)" followed by a "Type: ..." line (with or without a blank line
#: between them, hence the optional \n\s* rather than a fixed gap).
_SQLMAP_PARAM_RE = re.compile(r"Parameter:\s*(\S+)\s*\((\w+)\)\s*\n\s*Type:\s*(.+)")
_GOBUSTER_HIT_RE = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)", re.MULTILINE)
#: nikto's own banner line — same high-value-signal shape as nmap's service
#: column, worth its own node rather than folding into the generic findings below.
_NIKTO_SERVER_RE = re.compile(r"^\+ Server:\s*(.+)$", re.MULTILINE)
#: nikto 2.6's stable per-finding reference id, e.g. "+ [600050] Apache/2.4.25
#: appears to be outdated." The same id repeats across unrelated findings
#: (e.g. one "missing security header" id for every header it checks), so the
#: id alone can't be the dedup/distinguishing key — the full matched text is
#: (see NiktoExtractor's signal). Everything *without* this tag (Target
#: IP/Hostname/Port, Start/End Time, "No CGI Directories found", the
#: requests/host-count summary lines) is scan housekeeping, not a finding,
#: and is deliberately left unmatched rather than swept in as noise.
_NIKTO_FINDING_RE = re.compile(r"^\+ \[(\d+)\]\s*(.+)$", re.MULTILINE)
#: whatweb's own grammar: "<url> [<status>] <comma-separated Plugin[value]
#: pairs>" per line — one line per URL/redirect hop it actually followed.
_WHATWEB_LINE_RE = re.compile(r"^(\S+)\s+\[(\d+[^\]]*)\]\s+(.+)$", re.MULTILINE)
#: gobuster's live progress indicator and whatweb's colorized plugin names
#: both put a raw ANSI escape (and, for gobuster, a bare \r) directly before
#: real content on the same terminal "line" — confirmed live against DVWA
#: 2026-10-12: gobuster found 5 real paths (including an exposed
#: setup.php) that _GOBUSTER_HIT_RE silently matched zero of, because
#: MULTILINE's ^ anchors right after \n, and the character sitting there
#: was \r, not "/". \r is replaced with \n rather than dropped — gobuster
#: sometimes rewrites the *same* visual line twice with no \n in between
#: ("Progress: ...\rPROGRESS: ...\r/docs ..."), and simply deleting \r
#: would glue that next real hit onto the end of the progress text
#: instead of giving it its own line to be ^-anchored on. ANSI escapes
#: are dropped outright: they carry no content, only styling. Applied
#: only for matching below, never to the evidence/summary text the
#: operator actually reads.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clean(text: str) -> str:
    return _ANSI_RE.sub("", text.replace("\r", "\n"))


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
        content = _clean(str(message.content))
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


class WhatwebExtractor:
    """whatweb had no dedicated extractor until now, so every call fell
    through to LLMExtractor — a second model call per invocation, on the
    same small backend already busy running the engagement. Confirmed
    live against DVWA 2026-10-12: that second call returned zero
    findings and the result degraded to GenericExtractor's opaque hash
    signal (e.g. `whatweb:<target>:50d29fa22d6e`), even though whatweb had
    just reported the server, its version, and "DVWA" by name. whatweb's
    own grammar is exactly as stable as nikto's/nmap's; one node per URL
    line it actually scanned (it follows redirects, so a single call
    often reports more than one)."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        content = _clean(str(message.content))
        call_id = _call_id(call, message)
        nodes = []
        for url, status, plugins in _WHATWEB_LINE_RE.findall(content):
            signal = f"{status.strip()}: {plugins.strip()}"
            nodes.append(
                Node(
                    id=derive_node_id("web-fingerprint", target, signal),
                    cause_class="web-fingerprint",
                    target=target,
                    signal=signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(), tool="whatweb", exit_signal=f"{url.strip()}: {signal}",
                            tier="T2", source="deterministic", verdict="alive", call_id=call_id,
                        )
                    ],
                )
            )
        return Extraction(nodes=nodes)


class NiktoExtractor:
    """nikto had no dedicated extractor until now, despite being the main
    VULN-phase tool — it fell through LLMExtractor and, on any backend
    hiccup, further to GenericExtractor, producing one opaque hash-signal
    node (cause_class=="nikto") instead of real findings. nikto's own
    output has the same stable-grammar shape nmap's does; there was no
    real reason to depend on a local model for it at all."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        content = str(message.content)
        call_id = _call_id(call, message)
        nodes = []

        server_match = _NIKTO_SERVER_RE.search(content)
        if server_match:
            signal = server_match.group(1).strip()
            nodes.append(
                Node(
                    id=derive_node_id("server-banner", target, signal),
                    cause_class="server-banner",
                    target=target,
                    signal=signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(), tool="nikto", exit_signal=f"Server: {signal}",
                            tier="T2", source="deterministic", verdict="alive", call_id=call_id,
                        )
                    ],
                )
            )

        for ref_id, text in _NIKTO_FINDING_RE.findall(content):
            # Truncated, not the bare ref_id: the same id repeats across
            # several distinct findings (see _NIKTO_FINDING_RE's comment),
            # so the full text is what actually distinguishes siblings.
            signal = f"[{ref_id}] {text.strip()}"[:160]
            nodes.append(
                Node(
                    id=derive_node_id("nikto-finding", target, signal),
                    cause_class="nikto-finding",
                    target=target,
                    signal=signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(), tool="nikto", exit_signal=signal,
                            tier="T2", source="deterministic", verdict="alive", call_id=call_id,
                        )
                    ],
                )
            )
        return Extraction(nodes=nodes)


class Wafw00fExtractor:
    """wafw00f is forced to ``-f json -o -`` in catalog.yaml, so parsing is
    a straight ``json.loads`` of wafw00f's own result schema — never the
    fragile, dynamically column-padded text table its default output
    builds. One node: whether a WAF sits in front of the target (and
    which), directly useful going into EXPLOITATION — expect filtering and
    rate-limiting, or don't. Malformed/empty JSON (a crashed or killed
    run) becomes zero nodes, not a crash here."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        call_id = _call_id(call, message)
        content = str(message.content)
        try:
            results = json.loads(content)
        except json.JSONDecodeError:
            return Extraction(nodes=[])
        if not isinstance(results, list):
            return Extraction(nodes=[])

        detected = [r for r in results if isinstance(r, dict) and r.get("detected")]
        if detected:
            names = sorted({str(r.get("firewall", "unknown")) for r in detected})
            cause_class, signal = "waf-detected", ", ".join(names)
        else:
            cause_class, signal = "waf-absent", "no-waf-detected"

        node = Node(
            id=derive_node_id(cause_class, target, signal),
            cause_class=cause_class,
            target=target,
            signal=signal,
            evidence=[
                Evidence(
                    timestamp=_now(), tool="wafw00f", exit_signal=signal,
                    tier="T2", source="deterministic", verdict="alive", call_id=call_id,
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
    "Only report what the output below actually contains — never invent a "
    "finding, a version number, or a path that isn't literally present. "
    "If the same underlying fact appears on more than one line (e.g. the "
    "same missing header repeated for several paths), report it once, not "
    "once per line.\n"
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

    def __init__(
        self,
        base_url: str,
        *,
        n_predict: int = 1024,
        timeout: float = 90.0,
        logger: logging.Logger | None = None,
    ) -> None:
        # §2.2 live-test (2026-10-11, real llama-server + LFM2.5-8B-A1B-Q4_K_M):
        # a real nikto-sized prompt under this schema's GBNF grammar
        # constraint took noticeably longer than simple unconstrained
        # completions: 30s produced a silent-to-user (but logged, G1)
        # fallback to GenericExtractor on the very first live call.
        # 2026-10-18, live: curl's own extraction failed 3/3 times this
        # way with nothing beyond "unavailable" recorded anywhere -- no
        # way to tell a timeout from a schema-validation failure from a
        # connection error after the fact. `logger` makes that visible.
        # 2026-10-18, live: every single call failed with a 404 all
        # engagement long -- --base-url is the OpenAI-compatible endpoint
        # (".../v1", scripts/run_tui*.sh's own default), but llama.cpp's
        # native /completion lives at the server root, not nested under
        # /v1. The 2026-10-11 live test this class's docstring describes
        # predates --base-url carrying a /v1 suffix at all, so it never
        # hit this. Every tool result silently fell back to
        # GenericExtractor's opaque hash node instead of a real
        # structured finding for the whole run.
        base_url = base_url.rstrip("/")
        if base_url.endswith("/v1"):
            base_url = base_url[: -len("/v1")]
        self._base_url = base_url
        self._n_predict = n_predict
        self._timeout = timeout
        self._log = logger

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
        except (httpx.HTTPError, ValueError) as exc:
            if self._log is not None:
                self._log.warning(
                    "llamacpp extraction backend call failed",
                    extra={"data": {"error_type": type(exc).__name__, "error": str(exc)}},
                )
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
    "nikto": NiktoExtractor(),
    "wafw00f": Wafw00fExtractor(),
    "whatweb": WhatwebExtractor(),
}
