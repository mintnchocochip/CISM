"""A new stage in the action GuardrailChain, alongside ScopeGuardStage:
blocks a tool call whose free-form `extra` flags string can read or write
outside the sandbox's scratch directory (an arbitrary local path, or
arbitrary code execution via nmap's NSE scripting).

This is a heuristic safety net, not a formal guarantee — same framing as
ScopeGuardStage. Extend _SHARED_DANGEROUS_TOKENS (flags dangerous for
every tool) or _PER_TOOL_DANGEROUS_TOKENS (flags dangerous only for the
tool that actually has them) as new catastrophic flags are found.
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
        "-iR", "-oS", "--datadir", "--resume", "--stylesheet", "--webxml",
        "--script-args-file", "--script-help", "--servicedb", "--versiondb",
        "--proxies", "--append-output",
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


#: Tools whose real argument parser accepts a LONG option written with a
#: single leading dash. nmap calls getopt_long_only(), so `-script` and
#: `--script` are the same option to the real binary (live-verified
#: against nmap 7.94SVN: `nmap -script=nonexistent-xyz -sn 127.0.0.1`
#: starts the script engine, `nmap -excludef /tmp/nope` really opens the
#: exclude file). curl is deliberately NOT in this set: it accepts long
#: options only with `--`, so normalizing curl's genuine short flags into
#: long ones would misread `-s` (silent) as an abbreviation of
#: `--stderr` and block one of its most common invocations.
_SINGLE_DASH_LONG_OPTION_TOOLS: frozenset[str] = frozenset({"nmap"})

#: Minimum total length of a single-dash head before it is also evaluated
#: as a long option (i.e. at least 2 characters after the dash). The floor
#: exists only to keep `-p` — the single most common nmap flag there is —
#: from normalizing to `--p` and colliding with `--proxies`; one character
#: after the dash is ambiguous with nmap's real short options, two is not.
#:
#: 2 chars after the dash is the tightest floor that costs nothing. Swept
#: against nmap's full documented option surface (55 long options, 43 short
#: flags from `nmap -h`), a floor of 3 blocks exactly zero additional short
#: flags and zero additional long options versus a looser floor of 5, while
#: catching four more abbreviations that the real binary really resolves to
#: a denylisted long option — live-verified against nmap 7.94SVN:
#:   `-sty <path>` -> `--stylesheet` (`nmap -sty /etc/nonexistent-xyz -oX -
#:                    -sL 127.0.0.1` emits `<?xml-stylesheet href=...?>`)
#:   `-ser <path>` -> `--servicedb`  (triggers its documented implicit -F)
#:   `-we` / `-web` -> `--webxml`
#:   `-ap` / `-app` -> `--append-output`
#: Genuine short flags stay unaffected because matching is exact-or-prefix
#: and case-sensitive: `-sV` -> `--sV` prefixes nothing (`--script` is
#: lowercase), likewise `-sC`, `-Pn`, `-T4`, `-p-`, `-d3`, `-PS22`.
_MIN_SINGLE_DASH_LONG_HEAD = 3


def _hits(token: str, denylist: frozenset[str], *, single_dash_long: bool = False) -> set[str]:
    """Return the denylisted flags that `token` invokes.

    ``single_dash_long`` additionally evaluates a single-dash head as its
    ``--``-prefixed equivalent, for tools whose parser really accepts that
    spelling (see _SINGLE_DASH_LONG_OPTION_TOOLS).

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
    long_head: str | None = None
    if (
        single_dash_long
        and head.startswith("-")
        and not head.startswith("--")
        and len(head) >= _MIN_SINGLE_DASH_LONG_HEAD
    ):
        long_head = "--" + head[1:]
    hits: set[str] = set()
    for f in denylist:
        if head == f:
            hits.add(f)
        elif f.startswith("--"):
            if len(head) > 2 and f.startswith(head):
                hits.add(f)
            elif long_head is not None and f.startswith(long_head):
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
        tool = call.get("name", "")
        denylist = _SHARED_DANGEROUS_TOKENS | _PER_TOOL_DANGEROUS_TOKENS.get(tool, frozenset())
        single_dash_long = tool in _SINGLE_DASH_LONG_OPTION_TOOLS
        hit: set[str] = set()
        for token in tokens:
            hit |= _hits(token, denylist, single_dash_long=single_dash_long)
        if hit:
            return GuardrailResult(
                allowed=False,
                value=call,
                reason=f"blocked flag(s) {sorted(hit)}: can read/write outside the sandbox's scratch dir",
            )
        return GuardrailResult(allowed=True, value=call)
