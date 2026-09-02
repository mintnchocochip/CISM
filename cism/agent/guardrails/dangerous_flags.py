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

_DANGEROUS_FLAG_TOKENS: frozenset[str] = frozenset(
    {
        "--script",  # nmap: arbitrary NSE Lua execution
        "-oN", "-oX", "-oG", "-oA",  # nmap: write scan report to an attacker-influenced path
        "-o", "-O", "--output", "--remote-name",  # curl/nikto/etc: write response to an arbitrary local path
        "-T", "--upload-file",  # curl: read an arbitrary local file, send its contents
        "-K", "--config",  # curl: treat a local file's contents as more curl flags
    }
)


class DangerousFlagGuardStage:
    name = "dangerous-flag-guard"

    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        extra = str((call.get("args") or {}).get("extra", ""))
        try:
            tokens = set(shlex.split(extra)) if extra else set()
        except ValueError:
            return GuardrailResult(
                allowed=False,
                value=call,
                reason="could not parse `extra` as shell-style tokens (unbalanced quote?)",
            )
        hit = tokens & _DANGEROUS_FLAG_TOKENS
        if hit:
            return GuardrailResult(
                allowed=False,
                value=call,
                reason=f"blocked flag(s) {sorted(hit)}: can read/write outside the sandbox's scratch dir",
            )
        return GuardrailResult(allowed=True, value=call)
