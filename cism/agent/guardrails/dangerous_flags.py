"""DangerousFlagGuardStage: blocks a tool call whose free-form `extra`
flags string can read/write outside the sandbox scratch dir, or run
arbitrary code (e.g. nmap NSE scripting). Heuristic denylist, not a
formal guarantee — extend _SHARED_DANGEROUS_TOKENS/_PER_TOOL_DANGEROUS_TOKENS
as new catastrophic flags are found."""

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


#: Tools whose real parser accepts a long option with a single leading dash
#: (nmap's getopt_long_only: `-script` == `--script`). curl is excluded — it
#: only accepts long options with `--`, so this would misread `-s` as `--stderr`.
_SINGLE_DASH_LONG_OPTION_TOOLS: frozenset[str] = frozenset({"nmap"})

#: Minimum chars after the dash before a single-dash head is also evaluated as
#: a long option — keeps `-p` from normalizing to `--p` and colliding with
#: `--proxies`. 3 is the tightest floor that still catches real nmap
#: abbreviations (`-sty` -> `--stylesheet`, `-ser` -> `--servicedb`, `-we` ->
#: `--webxml`, `-ap` -> `--append-output`) without false-matching genuine
#: short flags like `-sV`/`-Pn`/`-T4` (matching is case-sensitive prefix).
_MIN_SINGLE_DASH_LONG_HEAD = 3


def _hits(token: str, denylist: frozenset[str], *, single_dash_long: bool = False) -> set[str]:
    """The denylisted flags `token` invokes, via three matching modes:
    exact match; long-flag abbreviation (curl accepts any unambiguous
    prefix, e.g. `--conf` for `--config`); and short-flag cluster
    membership (curl bundles short options into one token, so a
    denylisted letter counts if it appears anywhere after the leading
    `-` — deliberately over-eager, since a false positive just blocks,
    it never lets a real write slip through). `single_dash_long` also
    evaluates a single-dash head as its `--`-prefixed equivalent, for
    tools that really accept that spelling."""
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
