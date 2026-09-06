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
        "-x", "--proxy", "--resolve", "--connect-to",
        "--unix-socket", "--abstract-unix-socket", "--interface",
        "-b", "--cookie", "-w", "--write-out", "--trace", "--trace-ascii",
        "--stderr", "--output-dir", "--create-dirs", "--netrc-file",
        "--etag-save", "--etag-compare", "-J", "--remote-header-name",
        "--remote-name-all", "--cert", "--key", "--cacert",
    }),
}


def _hits(token: str, denylist: frozenset[str]) -> set[str]:
    """Return the denylisted flags that `token` invokes.

    Three matching modes, one per real curl/nmap parsing behavior this
    heuristic must not lose to:

    1. Exact match (``head == f``) — always counts, for any flag length.
    2. Long-flag *abbreviation* (curl accepts any unambiguous prefix of a
       long option, e.g. ``--conf`` for ``--config``): a denylisted long
       flag counts as hit when it STARTS WITH the token's head (the
       reverse of the classic "prefix" check — this direction has no
       false-positive risk analogous to `--form`/`--format`, since we're
       asking whether the user's abbreviation is a prefix of the real
       flag, not whether the real flag is a prefix of what they typed).
    3. Short-flag *cluster* membership: curl lets short options bundle
       into one token, with a value-taking flag consuming the rest of
       the token as its value (``-sSo/tmp/pwn`` == ``-s -S -o /tmp/pwn``).
       A denylisted 2-character short flag (``-o``, ``-d``, ...) counts
       as hit if its letter appears ANYWHERE after the leading ``-``, not
       just at position 0. This is deliberately over-eager: the rare
       case where an unlisted value-taking flag's own bundled value
       happens to contain a denylisted letter (e.g. ``-A"only-if-o..."``)
       is a false positive that fails CLOSED (a recoverable block), never
       the reverse of a real file write escaping unnoticed. A denylisted
       flag with 3+ characters (e.g. nmap's ``-iL``) does not bundle this
       way in practice and keeps the plain attached-value check instead.
    """
    head = token.split("=", 1)[0]
    hits: set[str] = set()
    for f in denylist:
        if head == f:
            hits.add(f)
        elif f.startswith("--"):
            if len(head) > 2 and f.startswith(head):
                hits.add(f)
        elif len(f) == 2 and head.startswith("-") and not head.startswith("--"):
            if f[1] in head[1:]:
                hits.add(f)
        elif token.startswith(f):
            hits.add(f)
    return hits


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
