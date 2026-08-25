"""The first real (non-pass-through) guardrail stage: blocks a tool call
whose target falls outside a declared engagement scope.

This is a heuristic safety net, not a formal guarantee — it can only check
targets it can actually find inside ``call["args"]``. A call with no
target-shaped argument at all (``ss``, ``john``, a ``tcpdump`` invocation
naming only an interface) is allowed through rather than blocked, since
refusing every local/argless tool would make this guardrail useless for
legitimate local work. ``responder`` is the sharpest known blind spot: it
has no target argument in any shape, since it answers broadcast-domain-wide
rather than addressing a host.

Deliberately not derived from ``AgentState``/``LangGraphAgent``'s existing
``target: str`` field — that field is free text used today only for DEPG
node labeling (see ``cism/depg/extract.py``); the README's own example
value is ``"linux nginx php"``, not a host or CIDR.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails.chain import GuardrailResult

__all__ = ["EngagementScope", "ScopeGuardStage"]

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Tools with an unambiguous, single "this is the target" argument. Only
#: that argument is checked for these — an options/service/module string on
#: the same call is never mistaken for a target.
_TARGET_ARG_BY_TOOL: dict[str, str] = {
    "nmap": "target",
    "masscan": "target",
    "hydra": "target",
    "medusa": "target",
    "curl": "url",
    "wget": "url",
    "gobuster": "url",
    "ffuf": "url",
    "ssh": "host",
    "scp": "host",
}

#: user[:pass]@host — impacket-style / ssh-style composite arguments.
_USER_HOST_RE = re.compile(r"[^\s@]+@([\w.-]+)")

#: A bare word must look like an actual domain (has a dot, valid label
#: chars) to be treated as a host candidate during the fallback scan — this
#: is what keeps a service name ("ssh"), a flag ("-t"), or a module path
#: ("exploit/windows/smb/ms17_010_eternalblue") from being mistaken for one.
_BARE_DOMAIN_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)


@dataclass(frozen=True, slots=True)
class EngagementScope:
    cidrs: tuple[IPNetwork, ...] = ()
    domains: tuple[str, ...] = ()

    def contains_host(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return any(addr in net for net in self.cidrs)

        lowered = host.lower()
        return any(lowered == d or lowered.endswith(f".{d}") for d in self.domains)


class ScopeGuardStage:
    name = "scope-guard"

    def __init__(self, scope: EngagementScope) -> None:
        self._scope = scope

    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        for host in _candidate_hosts(call):
            if not self._scope.contains_host(host):
                return GuardrailResult(
                    allowed=False,
                    value=call,
                    reason=f"{host!r} is outside the declared engagement scope",
                )
        return GuardrailResult(allowed=True, value=call)


def _candidate_hosts(call: ToolCall) -> list[str]:
    args = call.get("args") or {}

    key = _TARGET_ARG_BY_TOOL.get(call.get("name", ""))
    if key is not None:
        value = args.get(key)
        if isinstance(value, str):
            host = _extract_host(value)
            return [host] if host else []
        return []

    hosts: list[str] = []
    for value in args.values():
        if isinstance(value, str):
            host = _extract_host(value)
            if host:
                hosts.append(host)
    return hosts


def _extract_host(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if ":" in value:
        host_part, _, port_part = value.rpartition(":")
        if port_part.isdigit() and host_part:
            return _extract_host(host_part)

    if "://" in value:
        hostname = urlparse(value).hostname
        return hostname

    match = _USER_HOST_RE.search(value)
    if match:
        return match.group(1)

    if _BARE_DOMAIN_RE.fullmatch(value):
        return value.lower()

    return None
