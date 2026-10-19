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
    # §4.1: sqlmap's RCE/file-primitive flags are the catastrophic case
    # allow_raw exists to guard against — these turn "test for SQLi" into
    # "get a shell" / "read or write an arbitrary file" on the DB host.
    "sqlmap": frozenset({
        "--os-shell", "--os-cmd", "--os-pwn", "--sql-shell",
        "--file-read", "--file-write", "--file-dest", "--eval",
        "-c", "--config", "--tamper",
    }),
    "gobuster": frozenset({"-o", "--output"}),
    # nc (cism/agent/tools/network.py) has no `extra`/raw-flags field at
    # all, so a real call can never reach this guard with a flag in the
    # first place -- this only matters if the model hallucinates an
    # `extra` kwarg the schema doesn't define, which the guard still
    # catches before the resulting TypeError. -l/-k are the only way this
    # tool could become a listener (reverse-shell catcher / relay). No
    # entry for an exec flag: OpenBSD nc has no -e at all to block.
    "nc": frozenset({"-l", "-k"}),
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

#: curl's data/form flags are the one case in this file where the real risk
#: lives in the VALUE, not the flag: `-d "literal post body"` is harmless,
#: `-d @/etc/passwd` is a local-file-read-and-exfil primitive. Blocking the
#: flag outright (as every other entry here does) punishes the harmless,
#: common case — verifying credentials/form data the agent already found —
#: for no safety gain, since sqlmap's own `--data` already covers the
#: dangerous shape just as hard. Scoped to curl only, and only to a flag
#: used standalone, not bundled into a short-flag cluster (e.g. "-sSd...")
#: — that shape is rare enough from a model that failing closed there costs
#: nothing real, and it lets the rest of _hits()'s bundling logic stay
#: exactly as-is.
#: 2026-10-18, live (manual DVWA crack, replicating what the agent would
#: need): -b/--cookie was flat-blocked like every other entry in this
#: file, but a literal `-b "PHPSESSID=...; security=low"` is the ONLY way
#: to carry a session forward across two curl calls (GET login.php for a
#: fresh PHPSESSID + CSRF token, then POST the login with that same
#: cookie attached) -- essential, benign, and curl already reveals the
#: Set-Cookie value for free via -i/--include, which isn't blocked. The
#: real risk is curl's *other* reading of this flag: with no "=" in the
#: value at all, curl treats it as a filename to read cookies from (no
#: "@" marker needed, unlike -d/-F) -- `-b /etc/passwd` is a bare local-
#: file-read. _dangerous_data_value below gates on that, not on "@".
_CURL_VALUE_AWARE_FLAGS: frozenset[str] = frozenset({
    "-d", "--data", "--data-binary", "--data-urlencode", "--data-raw",
    "-F", "--form", "-b", "--cookie",
})
_CURL_FORM_FLAGS: frozenset[str] = frozenset({"-F", "--form"})
_CURL_COOKIE_FLAGS: frozenset[str] = frozenset({"-b", "--cookie"})
#: --data-urlencode has its own file-read shape distinct from -d/--data's
#: "whole value starts with @" rule: a BARE `name@file` (no `=` at all) also
#: reads a local file and URL-encodes it — the `@` need not be the value's
#: first character, just unseparated from a preceding field name by any
#: `=`. A plain `value.startswith("@")` check (as used for every other
#: data flag) misses this entirely, letting e.g.
#: `--data-urlencode "x@/etc/passwd"` through as if it were a harmless
#: literal — curl still reads the file. See _dangerous_data_value.
_CURL_URLENCODE_FLAGS: frozenset[str] = frozenset({"--data-urlencode"})


def _curl_value_aware_flag(token: str) -> tuple[str, str | None] | None:
    """If `token` is one of curl's value-aware data/form flags — exact,
    `=`-joined, an unambiguous long-flag abbreviation, or a short flag with
    an attached value (`-d@file`) — returns ``(canonical_flag, value)``.
    ``value`` is ``None`` when nothing is attached to this token at all (a
    bare flag like plain `-d`), meaning the real value is the *next*
    token. Returns ``None`` for anything that isn't one of these flags,
    including a short flag bundled with other letters (e.g. "-sSd...") —
    that deliberately falls through to the normal, always-block path."""
    head = token.split("=", 1)[0]
    attached = token[len(head) + 1 :] if "=" in token else None
    if head in _CURL_VALUE_AWARE_FLAGS:
        if attached is not None:
            return head, attached
        if len(head) == 2 and token != head:
            return head, token[len(head) :]
        return head, None
    if len(head) > 2:
        matches = [f for f in _CURL_VALUE_AWARE_FLAGS if len(f) > 2 and f.startswith(head)]
        if len(matches) == 1:
            return matches[0], attached
    for flag in _CURL_VALUE_AWARE_FLAGS:
        if len(flag) == 2 and token.startswith(flag) and token != flag:
            return flag, token[len(flag) :]
    return None


def _dangerous_data_value(flag: str, value: str) -> bool:
    """`-F`/`--form`'s own syntax is `name=@file` (upload) or `name=<file`
    (read) — the `@`/`<` marks the right side of that assignment, not the
    flag's value as a whole, unlike `-d`/`--data`/`--data-binary`/
    `--data-raw`, where the value itself is the file reference.

    `--data-urlencode` is a third, distinct shape: curl's own parser picks
    `name=content` (always literal, even if `content` itself contains an
    `@`) the moment a `=` appears *before* any `@` in the value — a leading
    `=` forces this reading even when the rest starts with `@` (the
    documented way to pass a literal value like `=user@example.com`).
    Otherwise, if an `@` appears with no earlier `=`, that's curl's
    `[name]@filename` file-read form, whether or not `@` is the value's
    very first character. `value.startswith("@")` alone — correct for the
    other data flags — misses the bare `name@file` case entirely."""
    if flag in _CURL_COOKIE_FLAGS:
        # curl's own rule for -b/--cookie, distinct from every other flag
        # here: ANY value with no "=" at all is read as a filename to load
        # cookies from -- no "@" marker needed, unlike -d/-F. A real
        # cookie string always has at least one "name=value" pair.
        return "=" not in value
    if flag in _CURL_FORM_FLAGS:
        _, _, rhs = value.partition("=")
        return rhs.startswith("@") or rhs.startswith("<")
    if flag in _CURL_URLENCODE_FLAGS:
        if value.startswith("="):
            return False
        at, eq = value.find("@"), value.find("=")
        if at == -1:
            return False
        return eq == -1 or at < eq
    return value.startswith("@")


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
        skip_next = False
        for index, token in enumerate(tokens):
            if skip_next:
                skip_next = False
                continue
            if tool == "curl":
                matched = _curl_value_aware_flag(token)
                if matched is not None:
                    flag, value = matched
                    if value is None:
                        if index + 1 < len(tokens):
                            value = tokens[index + 1]
                            skip_next = True
                        else:
                            value = None  # nothing to verify as safe -- fail closed
                    if value is None or _dangerous_data_value(flag, value):
                        hit.add(flag)
                    continue
            hit |= _hits(token, denylist, single_dash_long=single_dash_long)
        if hit:
            return GuardrailResult(
                allowed=False,
                value=call,
                reason=f"blocked flag(s) {sorted(hit)}: can read/write outside the sandbox's scratch dir",
            )
        return GuardrailResult(allowed=True, value=call)
