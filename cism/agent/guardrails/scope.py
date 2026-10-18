"""ScopeGuardStage: blocks a tool call whose target falls outside a
declared engagement scope. Heuristic, not a formal guarantee — it can
only check targets it finds inside call["args"]; an argless call
(``ss``, ``john``, ``responder``) is allowed through rather than
blocked, or every local tool would be useless."""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, replace
from urllib.parse import urlparse

from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails.chain import GuardrailResult

__all__ = ["EngagementScope", "parse_scope", "ScopeGuardStage"]

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Tools with one unambiguous target argument. If it's absent,
#: _candidate_hosts falls back to scanning every string arg; `extra` is
#: always checked too, on either path.
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
    "wafw00f": "target",
}

#: user[:pass]@host — impacket-style / ssh-style composite arguments.
_USER_HOST_RE = re.compile(r"[^\s@]+@([\w.-]+)")

#: A bare word must look like a real domain (dot + valid chars) to count as
#: a host candidate — keeps a service name, flag, or module path from matching.
_BARE_DOMAIN_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)

#: Above this, a bare digit string is more likely an encoded IPv4 address
#: than a legit small numeric arg (port, nmap timing, thread count) —
#: 169.254.169.254 encodes to 2852039166, far above it.
_MIN_NUMERIC_IPV4 = 0xFFFF  # 65535


def _parse_numeric_ipv4(value: str) -> str | None:
    """curl/getaddrinfo resolve a bare int as IPv4 (2852039166 ==
    169.254.169.254); ipaddress.ip_address rejects that spelling.
    Returns the canonical dotted-quad form, or None."""
    if re.fullmatch(r"[0-9]+", value):
        n = int(value)
    elif re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        n = int(value, 16)
    else:
        return None
    if not (_MIN_NUMERIC_IPV4 < n <= 0xFFFFFFFF):
        return None
    return str(ipaddress.IPv4Address(n))


def _is_long_flag_numeric_argument(tokens: list[str], i: int) -> bool:
    """True when tokens[i] is a --long-flag's own numeric value (a rate,
    timeout, payload length), not a positional target — these routinely
    exceed _MIN_NUMERIC_IPV4 legitimately. Restricted to `--`-prefixed
    predecessors: a single dash is often an argless short flag, where the
    following number really is a positional target (``nmap -sV
    2852039166`` scans 169.254.169.254)."""
    return (
        i > 0
        and tokens[i - 1].startswith("--")
        and re.fullmatch(r"[0-9]+", tokens[i]) is not None
    )

#: Never legitimate regardless of declared scope (unlike RFC1918 ranges,
#: often the actual point of an internal engagement) — the cloud metadata
#: service is a classic SSRF credential-theft pivot.
_ALWAYS_DENIED_HOSTS: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS/GCP/Azure instance metadata
    "metadata.google.internal",
    "metadata",  # GCP's dotless short-form, resolvable via the VM's default search domain
    "fd00:ec2::254",  # AWS IMDSv2 IPv6
})


def _is_always_denied(host: str) -> bool:
    """Hard-deny check, IP-canonicalized so case/expansion tricks (e.g.
    FD00:EC2::254 vs fd00:ec2::254) can't bypass it. A /32 or /128 CIDR
    is treated as its bare address; a wider CIDR that merely contains a
    denied host is not hard-denied, just normally scope-checked."""
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
    #: 6.2: a real denylist, checked *first* in contains_host/
    #: contains_network — a host matching both an included and an excluded
    #: entry is out of scope. Without this, a flag named "exclude" that
    #: only ever added to the allowlist would be an active footgun: an
    #: operator typing --exclude <host> reasonably expects that host
    #: blocked, not newly allowed.
    excluded_cidrs: tuple[IPNetwork, ...] = ()
    excluded_domains: tuple[str, ...] = ()

    def _host_matches(self, host: str, cidrs: tuple[IPNetwork, ...], domains: tuple[str, ...]) -> bool:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return any(addr in net for net in cidrs)
        lowered = host.lower()
        return any(lowered == d or lowered.endswith(f".{d}") for d in domains)

    def contains_host(self, host: str) -> bool:
        if self._host_matches(host, self.excluded_cidrs, self.excluded_domains):
            return False
        return self._host_matches(host, self.cidrs, self.domains)

    def _network_matches(self, network: IPNetwork, cidrs: tuple[IPNetwork, ...]) -> bool:
        for net in cidrs:
            if network.version != net.version:
                continue
            if network.subnet_of(net):
                return True
        return False

    def contains_network(self, network_str: str) -> bool:
        """Whether a whole CIDR is a subnet of (or equal to) a declared
        scope CIDR. Fails closed on unparseable input, mixed IP
        versions, or only-partial overlap."""
        try:
            network = ipaddress.ip_network(network_str, strict=False)
        except ValueError:
            return False
        if self._network_matches(network, self.excluded_cidrs):
            return False
        return self._network_matches(network, self.cidrs)

    def add(self, other: EngagementScope) -> EngagementScope:
        """Union of both scopes, de-duplicated, order-preserving.
        Immutable — returns a new EngagementScope."""
        cidrs = self.cidrs + tuple(c for c in other.cidrs if c not in self.cidrs)
        domains = self.domains + tuple(d for d in other.domains if d not in self.domains)
        excluded_cidrs = self.excluded_cidrs + tuple(
            c for c in other.excluded_cidrs if c not in self.excluded_cidrs
        )
        excluded_domains = self.excluded_domains + tuple(
            d for d in other.excluded_domains if d not in self.excluded_domains
        )
        return replace(
            self,
            cidrs=cidrs,
            domains=domains,
            excluded_cidrs=excluded_cidrs,
            excluded_domains=excluded_domains,
        )

    def excluding(self, exclusions: EngagementScope) -> EngagementScope:
        """Returns a new scope with ``exclusions``' cidrs/domains folded
        into this scope's denylist (not its allowlist)."""
        return replace(
            self,
            excluded_cidrs=self.excluded_cidrs
            + tuple(c for c in exclusions.cidrs if c not in self.excluded_cidrs),
            excluded_domains=self.excluded_domains
            + tuple(d for d in exclusions.domains if d not in self.excluded_domains),
        )

    def without(self, token: str) -> tuple[EngagementScope, bool]:
        """Removes one exact CIDR/domain (same parsing as parse_scope).
        Returns (new_scope, True) if present, or (self, False) unchanged
        if not."""
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            network = None
        if network is not None and network in self.cidrs:
            return replace(self, cidrs=tuple(c for c in self.cidrs if c != network)), True
        lowered = token.strip().lower()
        if lowered in self.domains:
            return replace(self, domains=tuple(d for d in self.domains if d != lowered)), True
        return self, False

    def entries(self) -> tuple[str, ...]:
        """Every declared CIDR/domain as one flat tuple, CIDRs first, for /scope listing."""
        return tuple(str(c) for c in self.cidrs) + self.domains


def parse_scope(value: str) -> EngagementScope:
    """Comma-separated CIDRs/domains -> EngagementScope. A bare IP widens
    to /32; anything else unparseable as a network becomes a domain.
    Shared by --scope and /scope add."""
    cidrs: list[IPNetwork] = []
    domains: list[str] = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            cidrs.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            domains.append(token.lower())
    return EngagementScope(cidrs=tuple(cidrs), domains=tuple(domains))


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
                    reason=f"{host!r} is hard-denied regardless of declared engagement scope",
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

    def expand(self, addition: EngagementScope) -> None:
        """Adds addition's CIDRs/domains to the live scope — the only way scope changes after startup."""
        self._scope = self._scope.add(addition)

    def contract(self, token: str) -> bool:
        """Removes one CIDR/domain from the live scope; returns whether it was present."""
        self._scope, removed = self._scope.without(token)
        return removed

    @property
    def scope(self) -> EngagementScope:
        return self._scope


def _scan_all_args(args: dict) -> list[str]:
    # Indiscriminate scan over every string arg (used only when this tool
    # has no _TARGET_ARG_BY_TOOL entry) — most non-host-shaped values here
    # are legitimately not hosts (flag values, free text), so staying
    # lenient (skip, don't deny) is correct. _candidate_hosts' other branch
    # below handles the "this exact arg is supposed to be the target"
    # case, where failing closed on an unparseable value is the right call.
    hosts: list[str] = []
    for key, value in args.items():
        # `extra` gets its own dedicated token-by-token pass in _candidate_hosts.
        if key != "extra" and isinstance(value, str):
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
        hosts.append(_extract_host(value) or "<unparseable-target>")
    else:
        # No per-tool mapping, or the mapped key isn't present on this call —
        # scan every arg so a new catalog tool can't end up unchecked.
        hosts.extend(_scan_all_args(args))

    extra = args.get("extra")
    if isinstance(extra, str):
        try:
            tokens = shlex.split(extra)
        except ValueError:
            tokens = [extra]
        for i, token in enumerate(tokens):
            if _is_long_flag_numeric_argument(tokens, i):
                # Exception: no legitimate rate/timeout/length decodes to the metadata address.
                decoded = _parse_numeric_ipv4(token)
                if decoded is None or not _is_always_denied(decoded):
                    continue
            host = _extract_host(token)
            if host:
                hosts.append(host)

    flattened: list[str] = []
    for host in hosts:
        flattened.extend(host.split(",") if "," in host else [host])
    return flattened


def _strip_trailing_dot(value: str) -> str:
    """A trailing "." is a valid absolute-DNS-name spelling; normalize it
    away so every check sees the same form. A bare "." is left as-is."""
    if value.endswith(".") and value != ".":
        return value[:-1]
    return value


def _extract_host(value: str) -> str | None:
    value = _strip_trailing_dot(value)

    # A scheme marks this as one single URL target, never a comma-separated
    # host list -- checked before the comma split below so a comma that's
    # just part of the URL's own path/query (e.g. a UNION-based SQLi
    # payload's "SELECT user,password") is never mistaken for a second
    # target. Confirmed live 2026-10-18: a real UNION SQLi curl call
    # against an in-scope URL was blocked outright as
    # "<unparseable-multi-target>", because "user,password" in the query
    # string split into two non-host-shaped fragments. --target/--scope
    # values (what the comma-split below exists for) never carry "://".
    if "://" in value:
        hostname = urlparse(value).hostname
        if not hostname:
            return value
        hostname = _strip_trailing_dot(hostname)
        return _extract_host(hostname) or hostname

    if "," in value:
        parts = value.split(",")
        hosts = [h for p in parts if (h := _extract_host(p))]
        if not hosts:
            return None
        if len(hosts) < len(parts):
            # Some but not all comma-separated parts are host-shaped — block
            # outright rather than silently keep only the recognized parts.
            return "<unparseable-multi-target>"
        return ",".join(hosts)

    # CIDR checked before the bare-IP path so a whole network isn't left unchecked.
    if "/" in value and "://" not in value:
        host_part, _, suffix = value.rpartition("/")
        # Exactly one "/" — more means a path (e.g. a schemeless REST URL), not a network.
        if suffix.isdigit() and host_part and value.count("/") == 1:
            try:
                return str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                pass
            # nmap's own hostname/prefixlen syntax. Can't resolve DNS, so
            # recognizing it as host-shaped lets contains_network fail closed on it.
            host = _extract_host(host_part)
            return f"{host}/{suffix}" if host is not None else "<unparseable-cidr>"
        # A schemeless "host/path" URL (curl defaults these to http://) or a
        # filesystem/module path. Recurse on the first segment: a real host
        # gets checked; a bare path segment yields None, unchanged.
        first_segment = value.split("/", 1)[0]
        return _extract_host(first_segment) if first_segment else None

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

    match = _USER_HOST_RE.search(value)
    if match:
        return _strip_trailing_dot(match.group(1))

    if _BARE_DOMAIN_RE.fullmatch(value):
        return value.lower()

    if value.lower() in _ALWAYS_DENIED_HOSTS:
        return value.lower()

    return None
