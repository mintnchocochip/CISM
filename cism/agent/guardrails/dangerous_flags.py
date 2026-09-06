"""A new stage in the action GuardrailChain, alongside ScopeGuardStage:
blocks a tool call whose free-form `extra` flags string can read or write
outside the sandbox's scratch directory (an arbitrary local path, or
arbitrary code execution via nmap's NSE scripting).

This is a heuristic safety net, not a formal guarantee — same framing as
ScopeGuardStage. Extend _DANGEROUS_FLAG_TOKENS as new catastrophic flags
are found.
"""

from __future__ import annotations

import shlex

from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails.chain import GuardrailResult

__all__ = ["DangerousFlagGuardStage"]

_SHARED_DANGEROUS_TOKENS: frozenset[str] = frozenset({"-K", "--config"})

_PER_TOOL_DANGEROUS_TOKENS: dict[str, frozenset[str]] = {
    "nmap": frozenset({
        "--script", "-oN", "-oX", "-oG", "-oA", "-iL", "--excludefile",
    }),
    "curl": frozenset({
        "-o", "-O", "--output", "--remote-name",
        "-T", "--upload-file",
        "-F", "--form", "-d", "--data", "--data-binary", "--data-urlencode", "--data-raw",
        "-D", "--dump-header", "-c", "--cookie-jar",
    }),
}


def _hits(token: str, denylist: frozenset[str]) -> set[str]:
    """Return the denylisted flags that `token` matches.

    Exact match always counts (``head == f``). For short (single-dash)
    flags we also match when the token merely *starts with* the flag, since
    curl/nmap accept an attached value with no separating space or ``=``
    (``-o/tmp/pwn``, ``-d@/etc/passwd``, ``-K/etc/curlrc``). Long
    (``--xxx``) flags are never matched via ``startswith`` here — only via
    the ``=``-split exact match on `head` — so a long option name is never
    mistaken for a short flag's attached-value form, and one long flag is
    never mistaken as a prefix of another (`--form` vs `--format`, say).
    """
    head = token.split("=", 1)[0]
    return {
        f for f in denylist
        if head == f or (not f.startswith("--") and token.startswith(f))
    }


class DangerousFlagGuardStage:
    name = "dangerous-flag-guard"

    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        extra = str((call.get("args") or {}).get("extra", ""))
        try:
            tokens = shlex.split(extra) if extra else []
        except ValueError:
            return GuardrailResult(
                allowed=False,
                value=call,
                reason="could not parse `extra` as shell-style tokens (unbalanced quote?)",
            )
        denylist = _SHARED_DANGEROUS_TOKENS | _PER_TOOL_DANGEROUS_TOKENS.get(call.get("name", ""), frozenset())
        hit: set[str] = set()
        for token in tokens:
            hit |= _hits(token, denylist)
        if hit:
            return GuardrailResult(
                allowed=False,
                value=call,
                reason=f"blocked flag(s) {sorted(hit)}: can read/write outside the sandbox's scratch dir",
            )
        return GuardrailResult(allowed=True, value=call)
