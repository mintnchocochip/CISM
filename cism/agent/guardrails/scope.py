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
import shlex
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
    "curl": "target",
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

#: Above this, a bare digit string is far more likely to be an encoded
#: IPv4 address than a legitimate small numeric argument this agent's
#: tools actually take (ports 0-65535, nmap timing 0-5, thread counts
#: capped at 16 — see credentials.py's _MAX_THREADS) — 169.254.169.254
#: encodes to 2852039166, far above it.
_MIN_NUMERIC_IPV4 = 0xFFFF  # 65535


def _parse_numeric_ipv4(value: str) -> str | None:
    """curl/getaddrinfo resolve a bare decimal or hex integer as an IPv4
    address (``http://2852039166/`` == ``http://169.254.169.254/``) —
    ``ipaddress.ip_address`` rejects this spelling outright, which is
    exactly the gap that let this encoding slip past the scope guard
    unchecked. Returns the canonical dotted-quad form, or None."""
    if re.fullmatch(r"[0-9]+", value):
        n = int(value)
    elif re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        n = int(value, 16)
    else:
        return None
    if not (_MIN_NUMERIC_IPV4 < n <= 0xFFFFFFFF):
        return None
    return str(ipaddress.IPv4Address(n))

#: nmap flags whose own argument is a plain number that nmap itself never
#: treats as a target to scan (a rate, a timeout in ms, a retry count, a
#: port-count) — the value immediately following one of these in a
#: shlex-split `extra` string must never be treated as a host candidate,
#: no matter how large it is. Real, legitimate values here (e.g.
#: --max-rate 500000, --host-timeout 900000) are routinely well above
#: _MIN_NUMERIC_IPV4, and skipping detection here is safe specifically
#: because nmap never uses one of these flags' argument as a scan
#: target, not because the value itself is assumed harmless.
_NUMERIC_ARG_FLAGS: frozenset[str] = frozenset({
    "--min-rate", "--max-rate", "--max-retries", "--host-timeout",
    "--scan-delay", "--max-scan-delay", "--min-hostgroup", "--max-hostgroup",
    "--min-parallelism", "--max-parallelism", "--top-ports",
})

#: Never a legitimate pentest target regardless of declared scope, unlike
#: RFC1918 ranges generally (which ARE often the actual point of an
#: internal-network engagement, so blocking those would break legitimate
#: use) — the cloud metadata service is a classic SSRF pivot to steal
#: instance credentials.
_ALWAYS_DENIED_HOSTS: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS/GCP/Azure instance metadata
    "metadata.google.internal",
    "metadata",  # GCP's own short-form metadata hostname, resolvable via the VM's default DNS search domain with no dot at all
    "fd00:ec2::254",  # AWS IMDSv2 IPv6
})


def _is_always_denied(host: str) -> bool:
    """Check if a host is in the hard-deny list, canonicalizing IP addresses.

    IP-shaped hosts are parsed and compared via their canonical string form
    to prevent bypasses via alternate case or expansion (e.g., FD00:EC2::254
    vs fd00:ec2::254 vs fd00:ec2:0:0:0:0:0:254). Non-IP entries are checked
    via exact string match.

    A CIDR that reduces to exactly one address (a /32 or /128) is treated
    the same as that bare address — ``169.254.169.254/32`` is just another
    way to spell ``169.254.169.254``, and must not slip past the hard-deny
    by being written as a single-address network instead of a bare IP.
    A wider CIDR that merely *contains* a denied host is NOT hard-denied
    here (that would make huge swaths of address space unusable); it is
    still subject to the normal in-scope/out-of-scope network check.
    """
    if "/" in host:
        try:
            network = ipaddress.ip_network(host, strict=False)
        except ValueError:
            return False
        if network.num_addresses != 1:
            return False
        return str(network.network_address) in _ALWAYS_DENIED_HOSTS

    if host in _ALWAYS_DENIED_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if str(addr) in _ALWAYS_DENIED_HOSTS:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped) in _ALWAYS_DENIED_HOSTS
    return False


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

    def contains_network(self, network_str: str) -> bool:
        """Check whether an entire network (CIDR notation) is a subnet of —
        or exactly equal to — one of the declared scope CIDRs.

        Fails closed: a network that can't be parsed, that mixes IP
        versions against a declared CIDR, or that only *partially*
        overlaps a declared CIDR (rather than being fully contained by
        it) is NOT in scope. Scanning a network that's only partly
        authorized is exactly the kind of over-broad action this guard
        exists to stop.
        """
        try:
            network = ipaddress.ip_network(network_str, strict=False)
        except ValueError:
            return False

        for net in self.cidrs:
            if network.version != net.version:
                continue
            if network.subnet_of(net):
                return True
        return False


class ScopeGuardStage:
    name = "scope-guard"

    def __init__(self, scope: EngagementScope) -> None:
        self._scope = scope

    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        for host in _candidate_hosts(call):
            if _is_always_denied(host):
                return GuardrailResult(
                    allowed=False,
                    value=call,
                    reason=f"{host!r} is outside the declared engagement scope",
                )
            in_scope = (
                self._scope.contains_network(host)
                if "/" in host
                else self._scope.contains_host(host)
            )
            if not in_scope:
                return GuardrailResult(
                    allowed=False,
                    value=call,
                    reason=f"{host!r} is outside the declared engagement scope",
                )
        return GuardrailResult(allowed=True, value=call)


def _scan_all_args(args: dict) -> list[str]:
    hosts: list[str] = []
    for value in args.values():
        if isinstance(value, str):
            host = _extract_host(value)
            if host:
                hosts.append(host)
    return hosts


def _candidate_hosts(call: ToolCall) -> list[str]:
    args = call.get("args") or {}
    hosts: list[str] = []

    key = _TARGET_ARG_BY_TOOL.get(call.get("name", ""))
    value = args.get(key) if key is not None else None
    if key is not None and isinstance(value, str):
        host = _extract_host(value)
        if host:
            hosts.append(host)
    else:
        # Either no per-tool target-arg mapping exists for this tool
        # (the original fallback case), OR one does but the mapped key
        # isn't actually present as a string on this call — e.g. a tool
        # declared in _TARGET_ARG_BY_TOOL under a name build_catalog
        # never emits (build_catalog always names the target field
        # "target", never "url"/"host"). Falling back to scanning every
        # arg here, rather than checking nothing, means a future catalog
        # addition can't accidentally switch scope-checking off entirely.
        hosts.extend(_scan_all_args(args))

    extra = args.get("extra")
    if isinstance(extra, str):
        try:
            tokens = shlex.split(extra)
        except ValueError:
            tokens = [extra]
        for i, token in enumerate(tokens):
            if (
                i > 0
                and tokens[i - 1] in _NUMERIC_ARG_FLAGS
                and re.fullmatch(r"[0-9]+", token)
            ):
                continue
            host = _extract_host(token)
            if host:
                hosts.append(host)

    flattened: list[str] = []
    for host in hosts:
        flattened.extend(host.split(",") if "," in host else [host])
    return flattened


def _strip_trailing_dot(value: str) -> str:
    """A trailing "." is a valid, semantically-identical way to write an
    absolute DNS name (e.g. "metadata.google.internal." names the exact
    same host as "metadata.google.internal"). Normalize it away wherever a
    hostname-shaped string is produced, so the bare-domain match and the
    _is_always_denied/contains_host domain-suffix checks all see the same
    form regardless of which way the model wrote it — whether the dot
    showed up in a bare token, inside a URL's authority, or in a
    user@host composite. Only ONE trailing dot is meaningful in DNS; a
    value that is just "." is left alone rather than reduced to an empty
    string.
    """
    if value.endswith(".") and value != ".":
        return value[:-1]
    return value


def _extract_host(value: str) -> str | None:
    value = _strip_trailing_dot(value)

    if "," in value:
        parts = value.split(",")
        hosts = [h for p in parts if (h := _extract_host(p))]
        if not hosts:
            return None
        if len(hosts) < len(parts):
            # Some, but not all, comma-separated parts are host-shaped —
            # not "clearly a port list" (nothing would parse) and not
            # "clearly a clean multi-host list" (everything parses).
            # Block outright rather than silently keeping just the
            # parts we recognize: an unrecognized part might be
            # host-shaped in an encoding this parser doesn't know about
            # yet. The sentinel has no comma in it, so it survives
            # _candidate_hosts's comma-flattening step untouched, and it
            # never matches any declared scope/hard-deny entry.
            return "<unparseable-multi-target>"
        return ",".join(hosts)

    # CIDR notation ("10.0.0.0/24") — recognized before the bare-IP check
    # below so a whole network isn't silently dropped as "not host-shaped"
    # and left completely unchecked by the scope guard.
    if "/" in value and "://" not in value:
        host_part, _, suffix = value.rpartition("/")
        if suffix.isdigit() and host_part:
            try:
                return str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                pass
            # Not a numeric CIDR literal — nmap's own "hostname/prefixlen"
            # target syntax reaches here. This guard cannot itself
            # resolve DNS to know what such a target expands to, so
            # recognizing it as host-shaped (rather than dropping it) is
            # what lets EngagementScope.contains_network fail closed on
            # it below — a hostname/prefix combo is always out of scope,
            # even for an otherwise-declared-in-scope domain, since
            # prefix-expanding a hostname is exactly the kind of
            # scope-widening this guard cannot safely verify.
            host = _extract_host(host_part)
            return f"{host}/{suffix}" if host is not None else "<unparseable-cidr>"
        # Contains a "/" but doesn't end in a bare number (a file path,
        # a Metasploit module path) — not CIDR notation. Fall through to
        # the checks below, unchanged from before this task.

    numeric_ipv4 = _parse_numeric_ipv4(value)
    if numeric_ipv4 is not None:
        return numeric_ipv4

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
        if not hostname:
            return value
        hostname = _strip_trailing_dot(hostname)
        return _extract_host(hostname) or hostname

    match = _USER_HOST_RE.search(value)
    if match:
        return _strip_trailing_dot(match.group(1))

    if _BARE_DOMAIN_RE.fullmatch(value):
        return value.lower()

    if value.lower() in _ALWAYS_DENIED_HOSTS:
        return value.lower()

    return None
