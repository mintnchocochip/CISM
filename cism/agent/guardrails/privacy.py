"""Privacy Gateway (§5.1, BACKLOG.md): an opt-in, per-run anonymization
layer so the *model* only ever sees placeholders for real IPs/hostnames in
scope — the operator (TUI) and the actual sandboxed subprocess calls still
work on real values the whole time. Two halves, two different seams:

- Swap-in (real -> placeholder): applied directly inside ``think()`` to
  the system prompt's target line and to prior ToolMessage content when
  building the prompt (cism.agent.nodes.make_think_node's existing C1
  seam) — not something a GuardrailStage handles, since it touches the
  system prompt string too, which isn't a chain payload at all.
- Swap-out (placeholder -> real): PrivacySwapOutStage below, a normal
  action-chain GuardrailStage. It must run *before* ScopeGuardStage/
  DangerousFlagGuardStage in that chain, so they validate the real
  value a tool call would actually run against — this gateway hides
  values from the model, not from the guardrails checking what's about
  to execute.

Scoped per engagement: never share one PrivacyGateway across runs, or a
mapping built for one target could leak into another's transcript."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails.chain import GuardrailResult

__all__ = ["PrivacyGateway", "PrivacySwapOutStage"]

#: The lookaround guards reject a match inside a longer dotted run (e.g.
#: "1.2.3.4.5", a version-looking string) that would otherwise match on a
#: 4-octet slice of it — \b alone doesn't see past the extra ".digit".
_IPV4_RE = re.compile(r"(?<!\d\.)\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\.\d)")


class PrivacyGateway:
    """Owns one run's real<->placeholder mapping. ``domains`` seeds known
    in-scope hostnames up front — matched as literal substrings rather
    than detected by a generic hostname regex, since "anything dot-shaped"
    would also mangle filenames, version strings, etc. in tool output."""

    def __init__(self, domains: frozenset[str] = frozenset()) -> None:
        self._real_to_placeholder: dict[str, str] = {}
        self._placeholder_to_real: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._domains = frozenset(d for d in domains if d)

    def _placeholder_for(self, real: str, kind: str) -> str:
        existing = self._real_to_placeholder.get(real)
        if existing is not None:
            return existing
        self._counters[kind] = self._counters.get(kind, 0) + 1
        placeholder = f"<{kind}-{self._counters[kind]}>"
        self._real_to_placeholder[real] = placeholder
        self._placeholder_to_real[placeholder] = real
        return placeholder

    def anonymize(self, text: str) -> str:
        """real -> placeholder. Idempotent: re-running it on already
        anonymized text is a no-op, since the placeholders it produces
        don't themselves look like an IP or a known domain."""
        if not text:
            return text

        def _sub_ip(match: re.Match[str]) -> str:
            candidate = match.group(0)
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return candidate  # e.g. "999.999.999.999" or a version string
            return self._placeholder_for(candidate, "ip")

        anonymized = _IPV4_RE.sub(_sub_ip, text)
        for domain in self._domains:
            if domain in anonymized:
                anonymized = anonymized.replace(domain, self._placeholder_for(domain, "host"))
        return anonymized

    def deanonymize(self, text: str) -> str:
        """placeholder -> real. A placeholder this gateway never minted
        (typo'd by the model, or from a different run) passes through
        unchanged rather than raising — an unresolvable tool argument is
        the tool's problem to report, not this gateway's to crash on."""
        if not text or not self._placeholder_to_real:
            return text
        for placeholder, real in self._placeholder_to_real.items():
            if placeholder in text:
                text = text.replace(placeholder, real)
        return text


@dataclass(slots=True)
class PrivacySwapOutStage:
    """action chain: restores real values into a tool call's args before
    anything downstream (scope/dangerous-flag checks, then the real
    subprocess) sees them. Never blocks — restoring a value can't itself
    make a call more dangerous than the real value already was."""

    gateway: PrivacyGateway
    name: str = "privacy-swap-out"

    def check(self, value: ToolCall) -> GuardrailResult[ToolCall]:
        args = value.get("args") or {}
        restored = {
            k: self.gateway.deanonymize(v) if isinstance(v, str) else v for k, v in args.items()
        }
        if restored == args:
            return GuardrailResult(allowed=True, value=value, stage=self.name)
        new_call: ToolCall = {**value, "args": restored}  # type: ignore[typeddict-item]
        return GuardrailResult(allowed=True, value=new_call, stage=self.name)
