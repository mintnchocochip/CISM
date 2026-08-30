"""Real cause-class extractors: nmap open-port findings and hydra credential
attempts. Both parse a tool's own default plain-text output — nmap's tabular
port lines and hydra's "login:/password:" success line are regular enough
that a regex beats requiring -oX/machine-readable flags the tool wrapper
doesn't currently request.
"""

from __future__ import annotations

import re
from datetime import datetime

from langchain_core.messages import ToolMessage
from langchain_core.messages.tool import ToolCall

from cism.depg.evidence import Evidence
from cism.depg.extract import Extraction
from cism.depg.graph import Graph
from cism.depg.node import Node, derive_node_id

__all__ = ["HydraExtractor", "NmapExtractor"]

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
