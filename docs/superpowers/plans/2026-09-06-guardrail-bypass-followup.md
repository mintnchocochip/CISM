# Guardrail Bypass Follow-Up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all 12 remaining findings from the post-merge adversarial audit of the action-chain guardrail code (`cism/agent/guardrails/`) — everything except the "nothing is wired into the real agent" gap, which is deliberately deferred to a separate plan.

**Architecture:** Nine independently-testable fixes, all inside the three existing files `cism/agent/guardrails/scope.py`, `cism/agent/guardrails/dangerous_flags.py`, and `cism/agent/guardrails/chain.py` — no new files, no new guard stages, no `GuardrailChain`/`GuardrailSeam` shape changes. Task order follows the design doc's severity ranking, adjusted so tasks touching the same function region of `scope.py` run in an order where each is independently correct against the code the previous task left behind.

**Tech Stack:** Python 3.11+, `pytest`, `langchain_core.messages.tool.ToolCall`.

**Spec:** `docs/superpowers/specs/2026-09-06-guardrail-bypass-followup-design.md` — read it in full before starting; every code block below is drawn directly from it, including the reasoning for tradeoffs (e.g. why `_MIN_NUMERIC_IPV4` is set where it is, why the CIDR fix excludes URLs).

## Progress (handoff note)

All nine tasks are complete, committed, and each passed its own task review (Task 1 needed two small fix rounds along the way; the rest were clean on the first pass). The final whole-branch review (below) is the only remaining step. Test count is 514 passing (baseline 470 + 44 net new across Tasks 1–9).

Commits on this branch, oldest first (all plain messages, no attribution trailers):
`55bce14`, `35b14ce`, `64d0d9f` (Task 1, incl. 2 fix rounds), `9de4028` (Task 2), `f0a760d` (Task 3), `262c63e` (Task 4), `c64cbfa` (Task 5), `3fa7c22` (Task 6), `5bda5da` (Task 7), `a051d71` (Task 8), `906178c` (Task 9).

Deferred minor findings from task review, parked for a future task (none load-bearing, none block this plan's completion):
- Task 6: `test_a_comma_list_where_every_part_parses_is_still_checked_normally` is byte-identical in body to a pre-existing test — brief-mandated, not an implementer choice, informational only.
- Task 7: `_is_always_denied`'s `ipv4_mapped` fix only catches the RFC-4291 `::ffff:0:0/96` form — NAT64 (`64:ff9b::/96`), IPv4-translated (`::ffff:0:x.x.x.x`), and deprecated IPv4-compatible (`::x.x.x.x`) encodings of the metadata IP still bypass; out of Task 7's specified scope.
  - Consequence for a future reader, so the hard-deny's headline claim is not over-trusted: "denied regardless of declared scope" holds only for the IPv4-mapped (`::ffff:`) and `fd00:ec2::254` forms. Under a v6-permissive declared scope, `http://[::169.254.169.254]/` (IPv4-compatible) and `http://[64:ff9b::a9fe:a9fe]/` (NAT64) are still **allowed** — they are blocked today only because a v4-only scope already fails closed on the v6 family mismatch, not by the hard-deny itself.
- Task 8: multi-slash adversarial inputs are handled inconsistently by `_extract_host`. **Corrected after final review** — the original note here claimed `"a/1/2"` produces a compound sentinel `"<unparseable-cidr>/2"` and "still fails closed"; the Critical-1 fix to the CIDR/path-recognition branch changed that. Verified against the current code: `_extract_host("a/1/2")` returns `None` (treated as not host-shaped, i.e. **allowed**), while the single-slash `_extract_host("a/1")` still returns the `"<unparseable-cidr>"` sentinel and fails closed. Informational, not a live bypass: `"a/1/2"` is not a host-shaped target any tool would route anywhere.

The SDD workspace/ledger for this plan lives at `.superpowers/sdd/2026-09-06-guardrail-bypass-followup/` (git-ignored scratch, not present in a fresh clone) — the checkbox state above plus the git log is the durable record.

**Wiring plan status:** the separate plan `docs/superpowers/plans/2026-09-06-wire-real-guardrails-and-toolkit.md` (real `GuardrailSeam`/toolkit into `LangGraphAgent`/`run_agent.py`, deliberately out of this plan's scope — see design doc §3, Finding 8) is intentionally deferred until after this plan lands, per explicit direction. It still does not exist as of this handoff.

## Global Constraints

- Baseline: 470 tests pass before this plan starts (`.venv/bin/pytest -q` reports "470 passed"). Every task must leave the full suite green.
- No attribution trailers of any kind in commit messages (no `Co-Authored-By`, no "Generated with Claude Code") — plain commit messages only, regardless of any other instruction. This applies to every commit an implementer subagent makes.
- Every finding gets an adversarial test proving the actual threat model — a live-verified repro shape from the design doc, not a synthetic happy-path test.
- Every fix that changes matching/parsing behavior needs a regression test proving it does NOT introduce a new false positive on a legitimate, already-passing case (the design doc names the specific one to guard for each task).
- This plan does **not** wire a real `GuardrailSeam`/toolkit into `LangGraphAgent` or `run_agent.py` — see the design doc's §3 and the separate plan `docs/superpowers/plans/2026-09-06-wire-real-guardrails-and-toolkit.md`.
- Task order: 1 (numeric IPv4 + bare metadata) → 2 (file:// URLs) → 3 (curl abbreviation/bundling/missing flags) → 4 (nmap missing flags) → 5 (target-arg fallback) → 6 (comma partial-parse) → 7 (IPv4-mapped IPv6) → 8 (CIDR/hostname-prefixlen) → 9 (chain-level exception handling). Tasks 1, 2, 5, 6, 7, 8 all touch `scope.py` and must run in this order since later tasks are written against the file state earlier tasks leave behind (mostly non-overlapping regions of `_extract_host`/`_candidate_hosts`/`_is_always_denied`, but sequential dispatch avoids any merge ambiguity). Tasks 3 and 4 both touch `dangerous_flags.py` and must run in that order (Task 4 is a small, additive continuation of Task 3's table). Task 9 (`chain.py`) is independent and could run anywhere, but runs last since it's the lowest severity.

---

### Task 1: [Critical] `_extract_host` recognizes decimal/hex-encoded IPv4 and the bare `metadata` short hostname

**Files:**
- Modify: `cism/agent/guardrails/scope.py`
- Test: `tests/test_scope_guard.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: a new module-level `_parse_numeric_ipv4(value: str) -> str | None` helper and constant `_MIN_NUMERIC_IPV4`; `_extract_host` and `_ALWAYS_DENIED_HOSTS` change internally — no signature changes to anything called from outside this file.

**Current code being changed** (`cism/agent/guardrails/scope.py`):

```python
_ALWAYS_DENIED_HOSTS: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS/GCP/Azure instance metadata
    "metadata.google.internal",
    "fd00:ec2::254",  # AWS IMDSv2 IPv6
})
```

and, at the end of `_extract_host`:

```python
    if _BARE_DOMAIN_RE.fullmatch(value):
        return value.lower()

    return None
```

- [x] **Step 1: Write the failing tests — append to `tests/test_scope_guard.py`**

```python
def test_a_decimal_encoded_metadata_ip_is_blocked() -> None:
    """curl/getaddrinfo resolve a bare decimal integer as an IPv4 address
    (2852039166 == 169.254.169.254) — ipaddress.ip_address rejects this
    spelling outright, which is exactly the gap that let it slip past the
    scope guard unchecked before this fix."""
    result = _stage().check(_call("curl", target="http://2852039166/"))
    assert result.allowed is False


def test_a_hex_encoded_metadata_ip_is_blocked() -> None:
    result = _stage().check(_call("curl", target="http://0xA9FEA9FE/"))
    assert result.allowed is False


def test_a_decimal_encoded_out_of_scope_host_smuggled_into_extra_is_blocked() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="2130706433"))  # 127.0.0.1
    assert result.allowed is False


def test_a_small_decimal_flag_value_is_not_misread_as_an_encoded_ip() -> None:
    """The numeric-IPv4 recognition must not swallow ordinary small
    integers this agent's own tools actually take as arguments (a port,
    a thread count, an nmap timing level) — only a value large enough
    that it could plausibly BE an encoded address is treated as one."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="-T 4"))
    assert result.allowed is True

    result = _stage().check(_call("curl", target="https://example.com", extra="80"))
    assert result.allowed is True


def test_the_bare_metadata_short_hostname_is_blocked() -> None:
    """GCP's instance metadata service is also reachable via the bare
    single-label hostname "metadata" (resolved through the VM's default
    DNS search domain) — no dot at all, so _BARE_DOMAIN_RE never
    recognized it as host-shaped before this fix."""
    result = _stage().check(_call("curl", target="http://metadata/computeMetadata/v1/"))
    assert result.allowed is False

    result = _stage().check(_call("nmap", target="10.0.0.5", extra="metadata"))
    assert result.allowed is False


def test_an_unrelated_bare_word_is_still_allowed_through() -> None:
    """Regression guard: the bare-word hard-deny check is narrow — it only
    recognizes strings already in _ALWAYS_DENIED_HOSTS, so an ordinary
    service name or module path must still pass through unaffected."""
    result = _stage().check(_call("ss", options="-tulpn"))
    assert result.allowed is True

    result = _stage().check(_call("some-new-tool", note="responder"))
    assert result.allowed is True
```

- [x] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "decimal_encoded or hex_encoded or bare_metadata or small_decimal"
```

Expected: `test_a_decimal_encoded_metadata_ip_is_blocked`, `test_a_hex_encoded_metadata_ip_is_blocked`, `test_a_decimal_encoded_out_of_scope_host_smuggled_into_extra_is_blocked`, and `test_the_bare_metadata_short_hostname_is_blocked` FAIL (currently allowed). `test_a_small_decimal_flag_value_is_not_misread_as_an_encoded_ip` and `test_an_unrelated_bare_word_is_still_allowed_through` PASS already (regression guards, nothing to fix there yet).

- [x] **Step 3: Implement — modify `cism/agent/guardrails/scope.py`**

Add `import re` is already present. Add the new constant and helper, placed near the top after the existing regex constants:

```python
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
```

Change `_ALWAYS_DENIED_HOSTS` to add the bare short hostname:

```python
_ALWAYS_DENIED_HOSTS: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS/GCP/Azure instance metadata
    "metadata.google.internal",
    "metadata",  # GCP's own short-form metadata hostname, resolvable via the VM's default DNS search domain with no dot at all
    "fd00:ec2::254",  # AWS IMDSv2 IPv6
})
```

In `_extract_host`, call `_parse_numeric_ipv4` right after the comma-list branch (which already exists in the file) and before the existing bare-IP `ipaddress.ip_address(value)` try:

```python
    numeric_ipv4 = _parse_numeric_ipv4(value)
    if numeric_ipv4 is not None:
        return numeric_ipv4

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
```

(This goes where the existing `try: ipaddress.ip_address(value) ...` block already is — insert the new check immediately before it, don't duplicate the existing block.)

Change the end of `_extract_host` from:

```python
    if _BARE_DOMAIN_RE.fullmatch(value):
        return value.lower()

    return None
```

to:

```python
    if _BARE_DOMAIN_RE.fullmatch(value):
        return value.lower()

    if value.lower() in _ALWAYS_DENIED_HOSTS:
        return value.lower()

    return None
```

- [x] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v
```

Expected: all tests pass, including every pre-existing one.

- [x] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed.

- [x] **Step 6: Commit**

```bash
git add cism/agent/guardrails/scope.py tests/test_scope_guard.py
git commit -m "fix: ScopeGuardStage recognizes decimal/hex-encoded IPv4 hosts and the bare GCP metadata short hostname"
```

---

### Task 2: [Critical] `_extract_host` blocks URLs with no host instead of silently dropping them

**Files:**
- Modify: `cism/agent/guardrails/scope.py`
- Test: `tests/test_scope_guard.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature changes — only `_extract_host`'s `"://" in value` branch changes.

**Current code being changed** (`cism/agent/guardrails/scope.py`, inside `_extract_host`):

```python
    if "://" in value:
        hostname = urlparse(value).hostname
        return _strip_trailing_dot(hostname) if hostname else None
```

- [x] **Step 1: Write the failing tests — append to `tests/test_scope_guard.py`**

```python
def test_a_file_url_target_with_no_host_at_all_is_blocked() -> None:
    """file:///etc/shadow has an empty authority — urlparse's .hostname is
    "" (falsy), so before this fix _extract_host returned None and
    _candidate_hosts treated it as "nothing to check" rather than "block
    this". curl supports file:// natively and returns the file's own
    contents as tool output — this is an arbitrary local file read, not a
    hypothetical."""
    result = _stage().check(_call("curl", target="file:///etc/shadow"))
    assert result.allowed is False


def test_a_file_url_smuggled_into_extra_is_blocked() -> None:
    result = _stage().check(
        _call("curl", target="https://example.com", extra="file:///etc/shadow")
    )
    assert result.allowed is False


def test_a_normal_url_with_a_real_hostname_is_unaffected() -> None:
    """Regression guard: the fix only changes behavior for a URL that
    parses to no host at all — an ordinary URL must still resolve its
    real hostname and be checked against scope exactly as before."""
    result = _stage().check(_call("curl", target="https://example.com/report"))
    assert result.allowed is True
```

- [x] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "file_url"
```

Expected: `test_a_file_url_target_with_no_host_at_all_is_blocked` and `test_a_file_url_smuggled_into_extra_is_blocked` FAIL (currently allowed, since `_extract_host` returns `None` for both).

- [x] **Step 3: Implement — modify `cism/agent/guardrails/scope.py`**

```python
    if "://" in value:
        hostname = urlparse(value).hostname
        if not hostname:
            # file:///etc/shadow (and any other empty-authority URL) has
            # no host at all — this is a local-file-read primitive, not
            # "no target found". Returning the literal value guarantees
            # it fails every scope/hard-deny check (nothing declared
            # will ever equal this string), which is what "block" means
            # here.
            return value
        return _strip_trailing_dot(hostname)
```

- [x] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v
```

Expected: all pass.

- [x] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed.

- [x] **Step 6: Commit**

```bash
git add cism/agent/guardrails/scope.py tests/test_scope_guard.py
git commit -m "fix: ScopeGuardStage blocks URLs with no host (file:// etc.) instead of silently allowing them through"
```

---

### Task 3: [Critical] `DangerousFlagGuardStage` catches curl's long-option abbreviation and short-flag bundling, plus missing connection-redirection/file-touching flags

**Files:**
- Modify: `cism/agent/guardrails/dangerous_flags.py`
- Test: `tests/test_dangerous_flags.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: `_hits(token: str, denylist: frozenset[str]) -> set[str]` keeps its existing signature but its internal matching logic is replaced entirely; `_PER_TOOL_DANGEROUS_TOKENS["curl"]` gains new entries.

**Current code being changed** (`cism/agent/guardrails/dangerous_flags.py`):

```python
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
    """..."""
    head = token.split("=", 1)[0]
    return {
        f for f in denylist
        if head == f or (not f.startswith("--") and token.startswith(f))
    }
```

- [x] **Step 1: Write the failing tests — append to `tests/test_dangerous_flags.py`**

```python
def test_curl_long_flag_abbreviation_is_blocked() -> None:
    """curl's own parser accepts any unambiguous prefix of a long option
    (--conf for --config). Verified against real curl: a curlrc reached
    via --conf gives unrestricted file write, identical to the
    already-blocked -K/--config."""
    for abbrev in ("--conf", "--dump-h", "--cookie-j", "--data-r", "--data-u", "--data-b", "--upload-f"):
        result = _stage().check(_call(name="curl", target="https://x", extra=f"{abbrev} /tmp/x"))
        assert result.allowed is False, abbrev


def test_curl_short_flag_bundling_is_blocked() -> None:
    """curl accepts single-dash short options bundled into one cluster,
    with a value-taking flag consuming the remainder as its value
    (-sSo/tmp/pwn == -s -S -o /tmp/pwn). Verified against real curl: this
    writes the file exactly like the already-blocked -o /tmp/pwn."""
    for bundled in ("-sSo/tmp/pwn", "-sO", "-fsSLo/tmp/pwn", "-sST/etc/passwd"):
        result = _stage().check(_call(name="curl", target="https://x", extra=bundled))
        assert result.allowed is False, bundled


def test_a_safe_boolean_short_flag_cluster_is_not_blocked() -> None:
    """Regression guard: bundling detection must not turn every bundled
    cluster into a block — only one that actually contains a denylisted
    flag's letter."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-sSL"))
    assert result.allowed is True


def test_curl_connection_redirection_flags_are_blocked() -> None:
    """--resolve/--connect-to redirect the connection to an arbitrary
    address while the *visible* URL (the only thing ScopeGuardStage sees)
    stays in-scope — verified live via a real listener that the
    connection really goes where --resolve points, not where the
    hostname would otherwise resolve."""
    for flag_and_value in (
        "--resolve a.example.com:80:169.254.169.254",
        "--connect-to a.example.com:80:169.254.169.254:80",
        "-x http://169.254.169.254:80",
        "--proxy http://169.254.169.254:80",
        "--unix-socket /var/run/docker.sock",
        "--abstract-unix-socket x",
    ):
        result = _stage().check(_call(name="curl", target="https://a.example.com/", extra=flag_and_value))
        assert result.allowed is False, flag_and_value


def test_curl_file_touching_flags_are_blocked() -> None:
    """-w/@file and -b/<file> are arbitrary-file-read-and-exfiltrate
    primitives; --trace*/--stderr/--output-dir/--netrc-file/--etag-save
    are arbitrary-file-write primitives — verified live against real
    curl for each class."""
    for flag_and_value in (
        "-w @/etc/passwd",
        "--write-out @/etc/passwd",
        "-b /etc/passwd",
        "--cookie /etc/passwd",
        "--trace /tmp/t",
        "--trace-ascii /tmp/t",
        "--stderr /tmp/t",
        "--output-dir /etc",
        "--netrc-file /etc/passwd",
        "--etag-save /tmp/e",
        "--etag-compare /etc/passwd",
        "-J",
        "--remote-header-name",
        "--remote-name-all",
        "--cert /etc/passwd",
        "--key /etc/passwd",
        "--cacert /etc/passwd",
    ):
        result = _stage().check(_call(name="curl", target="https://x", extra=flag_and_value))
        assert result.allowed is False, flag_and_value


def test_a_long_flag_abbreviation_still_requires_a_real_prefix_match() -> None:
    """Regression guard: an abbreviation must actually be a prefix of a
    real denylisted flag — a long flag that merely starts with the same
    letter as a denylisted one, but isn't a prefix relationship, must not
    be caught."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--http1.1"))
    assert result.allowed is True


def test_the_existing_long_flag_prefix_regression_guard_still_holds() -> None:
    """--output-dir is now itself denylisted (Finding 5), so this
    existing regression test's premise changed — --output-dir must be
    blocked now, but confirm --output itself (the shorter, already
    denylisted flag) still isn't confused with a DIFFERENT, unrelated
    long flag that happens to share a prefix."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--outputXYZfictitious=1"))
    assert result.allowed is True
```

Also **modify** the existing test (its premise is now outdated — `--output-dir` moves from "must not be blocked" to "must be blocked", per Finding 5):

Find this existing test:

```python
def test_a_long_flag_that_merely_shares_a_prefix_with_a_denylisted_long_flag_is_not_blocked() -> None:
    """Long (--xxx) flags must only match by exact `=`-split head, never by
    startswith — otherwise a distinct, safe long option that happens to
    begin with a denylisted long flag's name would be falsely blocked.
    "--output" is denylisted for curl; "--output-dir" is a different,
    fictitious-but-plausible flag name that must NOT be caught by it."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--output-dir=/tmp"))
    assert result.allowed is True
```

Replace it with:

```python
def test_output_dir_is_now_denylisted_in_its_own_right() -> None:
    """--output-dir turned out not to be fictitious — it's a real curl
    flag (Finding 5) that redirects where -o/-O/-J write, and is now
    denylisted directly rather than merely "not accidentally caught by
    --output's prefix". This test's old name/premise (that it must NOT be
    blocked) no longer holds; --outputXYZfictitious above is the new
    regression guard for the "shares a prefix but isn't --output-dir
    either" case."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--output-dir=/tmp"))
    assert result.allowed is False
```

- [x] **Step 2: Run to verify the new/modified tests fail against the current code**

```bash
.venv/bin/pytest tests/test_dangerous_flags.py -v -k "abbreviation or bundling or redirection or file_touching or output_dir_is_now"
```

Expected: all the new bypass-proving tests FAIL (currently allowed); `test_a_safe_boolean_short_flag_cluster_is_not_blocked`, `test_a_long_flag_abbreviation_still_requires_a_real_prefix_match`, and `test_the_existing_long_flag_prefix_regression_guard_still_holds` PASS already (regression guards, verify they don't regress once the fix lands).

- [x] **Step 3: Implement — replace `_hits` and extend the curl table in `cism/agent/guardrails/dangerous_flags.py`**

```python
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
```

- [x] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_dangerous_flags.py -v
```

Expected: all pass, including every pre-existing test in the file (re-verify `test_curl_still_blocks_its_own_dash_t_upload_flag`, `test_nmap_timing_template_written_with_a_space_is_not_a_false_positive`, `test_nmap_os_detection_flag_is_not_confused_with_curls_denylisted_dash_o`, `test_a_safe_short_flag_that_does_not_appear_in_the_denylist_is_not_blocked`, `test_an_unknown_tool_only_gets_the_shared_denylist` — none of these should change behavior).

- [x] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed.

- [x] **Step 6: Commit**

```bash
git add cism/agent/guardrails/dangerous_flags.py tests/test_dangerous_flags.py
git commit -m "fix: DangerousFlagGuardStage catches curl long-flag abbreviation and short-flag bundling, adds missing connection-redirection and file-touching flags"
```

---

### Task 4: [Important] `DangerousFlagGuardStage`'s nmap table gains the missing scope-escape and filesystem-adjacent flags

**Files:**
- Modify: `cism/agent/guardrails/dangerous_flags.py`
- Test: `tests/test_dangerous_flags.py` (append)

**Interfaces:**
- Consumes: `_hits` from Task 3 (unchanged by this task).
- Produces: no signature changes — `_PER_TOOL_DANGEROUS_TOKENS["nmap"]` gains new entries only.

- [x] **Step 1: Write the failing tests — append to `tests/test_dangerous_flags.py`**

```python
def test_nmap_random_internet_targets_flag_is_blocked() -> None:
    """-iR <n> tells nmap to generate and scan random Internet hosts,
    ignoring the target argument entirely — a complete engagement-scope
    escape that ScopeGuardStage cannot see, since the only host-shaped
    argument on the call is the legitimate in-scope target."""
    result = _stage().check(_call(name="nmap", target="10.0.0.5", extra="-iR 1000"))
    assert result.allowed is False


def test_nmap_datadir_and_related_flags_are_blocked() -> None:
    for flag_and_value in (
        "--datadir /tmp/evil",
        "--script-args-file /etc/passwd",
        "--resume /tmp/x",
        "--stylesheet /etc/passwd",
        "-oS /tmp/x",
        "--proxies http://169.254.169.254:80",
        "--servicedb /etc/passwd",
        "--versiondb /etc/passwd",
        "--webxml",
        "--script-help",
        "--append-output",
    ):
        result = _stage().check(_call(name="nmap", target="10.0.0.5", extra=flag_and_value))
        assert result.allowed is False, flag_and_value


def test_a_safe_nmap_flag_is_still_unaffected_by_the_new_entries() -> None:
    """Regression guard: the new nmap entries must not catch anything
    beyond what they explicitly name."""
    result = _stage().check(_call(name="nmap", target="10.0.0.5", extra="-sV -A -T4"))
    assert result.allowed is True
```

- [x] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_dangerous_flags.py -v -k "nmap_random_internet or nmap_datadir"
```

Expected: both new tests FAIL (currently allowed).

- [x] **Step 3: Implement — extend the nmap table in `cism/agent/guardrails/dangerous_flags.py`**

```python
_PER_TOOL_DANGEROUS_TOKENS: dict[str, frozenset[str]] = {
    "nmap": frozenset({
        "--script", "-oN", "-oX", "-oG", "-oA", "-iL", "--excludefile",
        "-iR", "-oS", "--datadir", "--resume", "--stylesheet", "--webxml",
        "--script-args-file", "--script-help", "--servicedb", "--versiondb",
        "--proxies", "--append-output",
    }),
    "curl": frozenset({
        # ... unchanged from Task 3 ...
    }),
}
```

(`-iR` is conceptually a *scope* escape rather than a filesystem escape — nmap ignores the target and scans random Internet hosts — but blocking it here via the existing per-tool flag denylist achieves the identical practical effect without introducing a second parallel mechanism.)

- [x] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_dangerous_flags.py -v
```

Expected: all pass.

- [x] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed.

- [x] **Step 6: Commit**

```bash
git add cism/agent/guardrails/dangerous_flags.py tests/test_dangerous_flags.py
git commit -m "fix: DangerousFlagGuardStage adds nmap's -iR scope-escape and the remaining datadir/resume/stylesheet-class flags"
```

---

### Task 5: [Important] `_candidate_hosts` falls back to scanning every argument instead of checking nothing for a dead `_TARGET_ARG_BY_TOOL` entry

**Files:**
- Modify: `cism/agent/guardrails/scope.py`
- Test: `tests/test_scope_guard.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: a new module-level `_scan_all_args(args: dict) -> list[str]` helper; `_candidate_hosts` keeps its existing signature.

**Current code being changed** (`cism/agent/guardrails/scope.py`):

```python
def _candidate_hosts(call: ToolCall) -> list[str]:
    args = call.get("args") or {}
    hosts: list[str] = []

    key = _TARGET_ARG_BY_TOOL.get(call.get("name", ""))
    if key is not None:
        value = args.get(key)
        if isinstance(value, str):
            host = _extract_host(value)
            if host:
                hosts.append(host)
    else:
        for value in args.values():
            if isinstance(value, str):
                host = _extract_host(value)
                if host:
                    hosts.append(host)

    extra = args.get("extra")
    ...
```

- [x] **Step 1: Write the failing test — append to `tests/test_scope_guard.py`**

```python
def test_a_tool_mapped_to_a_target_arg_name_the_catalog_never_emits_still_gets_scope_checked() -> None:
    """_TARGET_ARG_BY_TOOL maps wget/gobuster/ffuf to "url" and ssh/scp to
    "host" — but build_catalog (base.py) always names the target field
    "target", never these. Before this fix, a tool call under one of
    these five names took the registered-tool branch, looked up a key
    that's never present, found nothing, and checked NOTHING — not the
    fallback scan, silence. This test simulates exactly that shape
    (a real ToolCall args dict for a hypothetical catalog-built "wget")
    to prove the fallback now kicks in."""
    result = _stage().check(_call("wget", target="http://169.254.169.254/"))
    assert result.allowed is False


def test_the_existing_registered_tools_are_unaffected_by_the_fallback_change() -> None:
    """Regression guard: every currently-real registered tool (nmap,
    curl, hydra, medusa, masscan) really is mapped to "target", which
    build_catalog really does emit — the fallback path must never trigger
    for these, so behavior must be identical to before this task."""
    result = _stage().check(_call("nmap", target="10.0.0.5"))
    assert result.allowed is True

    result = _stage().check(_call("curl", target="192.168.1.5"))
    assert result.allowed is False
```

- [x] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "target_arg_name_the_catalog_never_emits"
```

Expected: FAIL — `_candidate_hosts` returns `[]` for the `wget` call today since `args.get("url")` is `None`, so the metadata target is never checked.

- [x] **Step 3: Implement — replace `_candidate_hosts` in `cism/agent/guardrails/scope.py`**

```python
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
        for token in tokens:
            host = _extract_host(token)
            if host:
                hosts.append(host)

    flattened: list[str] = []
    for host in hosts:
        flattened.extend(host.split(",") if "," in host else [host])
    return flattened
```

- [x] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v
```

Expected: all pass, including every pre-existing test (particularly `test_an_unregistered_tool_falls_back_to_scanning_every_string_arg` and `test_an_unregistered_tool_with_no_host_shaped_values_is_allowed` — both must still pass unchanged since `key is None` for those tool names, same code path as before).

- [x] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed. `_candidate_hosts` is also exercised by `test_tool_catalog_integration.py`/`test_toolkit_integration.py` — check those specifically if anything fails: `.venv/bin/pytest tests/test_tool_catalog_integration.py tests/test_toolkit_integration.py -v`.

- [x] **Step 6: Commit**

```bash
git add cism/agent/guardrails/scope.py tests/test_scope_guard.py
git commit -m "fix: ScopeGuardStage falls back to scanning every argument when a _TARGET_ARG_BY_TOOL mapping names a key the catalog never actually emits"
```

---

### Task 6: [Important] Comma-list: a partial parse blocks the whole token instead of silently keeping only the recognized parts

**Files:**
- Modify: `cism/agent/guardrails/scope.py`
- Test: `tests/test_scope_guard.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature changes — only `_extract_host`'s comma-list branch changes.

**Current code being changed** (`cism/agent/guardrails/scope.py`, inside `_extract_host`):

```python
    if "," in value:
        parts = value.split(",")
        hosts = [h for p in parts if (h := _extract_host(p))]
        return ",".join(hosts) if hosts else None
```

- [x] **Step 1: Write the failing test — append to `tests/test_scope_guard.py`**

Note: after Task 1's fix, a decimal-encoded IP is now recognized, so a synthetic value that's guaranteed to remain unrecognized by every current check is needed to actually exercise the partial-parse path (rather than accidentally passing because Task 1 already closed the specific decimal-IP example from the design doc).

```python
def test_a_comma_list_with_one_real_host_and_one_permanently_unparseable_part_is_blocked() -> None:
    """A comma-joined token where SOME parts are host-shaped and others
    genuinely aren't recognized by this parser (not "clearly a port
    list" — nothing would parse; not "clearly a clean multi-host list" —
    everything parses) must be blocked outright rather than silently
    keeping just the parts this parser happened to recognize. An
    unrecognized comma-part might be host-shaped in an encoding this
    parser doesn't know about yet — defense in depth for the next
    encoding, on top of Task 1's specific fixes."""
    result = _stage().check(
        _call("nmap", target="10.0.0.5", extra="10.0.0.5,this-has-a-space in it")
    )
    assert result.allowed is False


def test_a_comma_list_where_every_part_parses_is_still_checked_normally() -> None:
    """Regression guard: the "all parts recognized" case must be
    unaffected — still checked host-by-host, not treated as a blanket
    block just because it's a comma list."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="10.0.0.5,10.0.0.6"))
    assert result.allowed is True


def test_a_comma_list_where_no_part_parses_is_still_allowed_through() -> None:
    """Regression guard: "nothing here looks like a target list at all"
    (e.g. a port range) must remain allowed, unchanged from before this
    task."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="-p 80,443"))
    assert result.allowed is True
```

- [x] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "permanently_unparseable"
```

Expected: FAIL — today's code returns `",".join(["10.0.0.5"])` (silently dropping the unparseable part), which is in-scope, so the call is allowed.

- [x] **Step 3: Implement — modify `_extract_host` in `cism/agent/guardrails/scope.py`**

```python
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
```

- [x] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v
```

Expected: all pass, including every pre-existing comma-related test (`test_a_comma_separated_multi_target_token_with_one_out_of_scope_host_is_blocked`, `test_a_comma_separated_multi_target_token_with_all_in_scope_hosts_is_allowed`, `test_a_comma_containing_value_that_is_not_actually_a_host_list_is_unaffected`, `test_a_valid_out_of_scope_host_smuggled_via_a_trailing_comma_is_still_blocked`, `test_a_valid_out_of_scope_host_smuggled_via_garbage_suffix_is_still_blocked` — all must still pass, now via the new partial-parse path rather than the old "keep only recognized parts, check them" path, but the observable outcome — blocked or allowed — is unchanged for all of them).

- [x] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed.

- [x] **Step 6: Commit**

```bash
git add cism/agent/guardrails/scope.py tests/test_scope_guard.py
git commit -m "fix: a comma-list with some but not all parts host-shaped now blocks outright instead of silently keeping only the recognized parts"
```

---

### Task 7: [Important] `_is_always_denied` canonicalizes IPv4-mapped IPv6 addresses

**Files:**
- Modify: `cism/agent/guardrails/scope.py`
- Test: `tests/test_scope_guard.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature changes — only `_is_always_denied`'s bare-host branch changes.

**Current code being changed** (`cism/agent/guardrails/scope.py`):

```python
    if host in _ALWAYS_DENIED_HOSTS:
        return True
    try:
        return str(ipaddress.ip_address(host)) in _ALWAYS_DENIED_HOSTS
    except ValueError:
        return False
```

- [x] **Step 1: Write the failing test — append to `tests/test_scope_guard.py`**

```python
def test_ipv4_mapped_ipv6_form_of_the_metadata_ip_is_hard_denied() -> None:
    """9300eab canonicalized case/compression for a bare IPv6 address, but
    Python renders "::ffff:169.254.169.254" as "::ffff:a9fe:a9fe" — a
    string that isn't in _ALWAYS_DENIED_HOSTS on its own, so the embedded
    IPv4 address was never being extracted for comparison. A v6-capable
    declared scope is required for this to reach EngagementScope at all
    (a v4-only scope already fails closed on a v6-family mismatch), so
    this uses an empty scope — the hard-deny must fire regardless."""
    from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage

    stage = ScopeGuardStage(EngagementScope())

    result = stage.check(_call("curl", target="http://[::ffff:169.254.169.254]/"))
    assert result.allowed is False

    result = stage.check(_call("curl", target="http://[::ffff:a9fe:a9fe]/"))
    assert result.allowed is False


def test_a_normal_ipv6_address_unrelated_to_the_denylist_is_unaffected() -> None:
    """Regression guard: the ipv4_mapped check must only fire for an
    actual IPv4-mapped address; an ordinary, unrelated IPv6 host must
    still pass through the normal scope check unaffected."""
    from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage

    scope = EngagementScope(cidrs=(ipaddress.ip_network("2001:db8::/32"),))
    stage = ScopeGuardStage(scope)

    result = stage.check(_call("curl", target="http://[2001:db8::1]/"))
    assert result.allowed is True
```

- [x] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "ipv4_mapped"
```

Expected: `test_ipv4_mapped_ipv6_form_of_the_metadata_ip_is_hard_denied` FAILS (currently allowed — `str(ipaddress.ip_address("::ffff:169.254.169.254"))` is `"::ffff:a9fe:a9fe"`, not a member of `_ALWAYS_DENIED_HOSTS`).

- [x] **Step 3: Implement — modify `_is_always_denied` in `cism/agent/guardrails/scope.py`**

```python
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
```

- [x] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v
```

Expected: all pass, including every pre-existing IPv6/canonicalization test (`test_the_ipv6_metadata_endpoint_is_blocked_regardless_of_case_or_compression`).

- [x] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed.

- [x] **Step 6: Commit**

```bash
git add cism/agent/guardrails/scope.py tests/test_scope_guard.py
git commit -m "fix: hard-deny check canonicalizes IPv4-mapped IPv6 addresses against the metadata denylist"
```

---

### Task 8: [Important] `_extract_host`'s CIDR recognition fails closed on malformed networks and nmap's `hostname/prefixlen` syntax

**Files:**
- Modify: `cism/agent/guardrails/scope.py`
- Test: `tests/test_scope_guard.py` (append)

**Interfaces:**
- Consumes: `_extract_host` (self-recursive call for the hostname half of a `hostname/prefixlen` value — this now benefits from Task 1's numeric-IPv4 recognition too, since a decimal-encoded IP with a prefix, e.g. `2852039166/24`, resolves correctly through the same recursive call).
- Produces: no signature changes — only `_extract_host`'s CIDR branch changes.

**Current code being changed** (`cism/agent/guardrails/scope.py`, inside `_extract_host`):

```python
    if "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
```

- [x] **Step 1: Write the failing tests — append to `tests/test_scope_guard.py`**

```python
def test_nmap_hostname_slash_prefixlen_syntax_is_blocked() -> None:
    """nmap's own documented target syntax ("hostname/prefixlen") resolves
    the hostname and scans the surrounding network — before this fix,
    _extract_host's CIDR branch only recognized numeric CIDR literals and
    silently fell through to unrecognized (unchecked, not blocked) for
    anything else containing a "/". Verified live: this reaches argv
    unblocked, with the metadata hostname as the host half."""
    result = _stage().check(_call("nmap", target="metadata.google.internal/24"))
    assert result.allowed is False


def test_a_malformed_leading_zero_cidr_is_blocked() -> None:
    """A leading-zero octet is rejected by ipaddress.ip_network (Python
    treats it as ambiguous/potentially-octal) but wasn't rejected by real
    network tools historically — before this fix the ValueError caused a
    silent fall-through to "unrecognized", not a block."""
    result = _stage().check(_call("nmap", target="192.168.001.0/24"))
    assert result.allowed is False


def test_an_out_of_range_prefix_length_is_blocked() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.0/33"))
    assert result.allowed is False


def test_a_url_with_a_numeric_last_path_segment_is_not_misread_as_a_cidr() -> None:
    """Regression guard: an ordinary URL whose last path segment happens
    to be numeric (a REST resource id) must not be misread as
    "hostname/prefixlen" and blocked as an unparseable network — real
    CIDR/hostname-prefix target syntax is always a bare string, never
    embedded in a URL, so anything containing "://" is excluded from the
    CIDR-detection branch entirely."""
    result = _stage().check(_call("curl", target="https://example.com/v1/users/24"))
    assert result.allowed is True


def test_existing_numeric_cidr_behavior_is_unaffected() -> None:
    """Regression guard: the already-working numeric-CIDR happy paths
    (in-scope, out-of-scope, partial-overlap, metadata /32 hard-deny)
    must all still hold exactly as before this task."""
    result = _stage().check(_call("nmap", target="10.0.0.0/28"))
    assert result.allowed is True

    result = _stage().check(_call("nmap", target="192.168.1.0/24"))
    assert result.allowed is False
```

- [x] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "hostname_slash_prefixlen or malformed_leading_zero or out_of_range_prefix"
```

Expected: all three new bypass-proving tests FAIL (currently allowed — each raises/is silently dropped by the current CIDR branch's bare `except ValueError: pass`).

- [x] **Step 3: Implement — replace the CIDR branch of `_extract_host` in `cism/agent/guardrails/scope.py`**

```python
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
```

Place this where the current `if "/" in value: try: ... except ValueError: pass` block already is — replace it entirely with the above.

- [x] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v
```

Expected: all pass, including every pre-existing CIDR test (`test_a_cidr_target_fully_within_the_declared_scope_is_allowed`, `test_a_cidr_target_entirely_outside_the_declared_scope_is_blocked`, `test_a_cidr_that_only_partially_overlaps_the_declared_scope_is_blocked`, `test_metadata_endpoint_expressed_as_a_slash_32_cidr_is_still_hard_denied`, `test_a_wide_cidr_that_merely_contains_the_metadata_address_is_not_hard_denied`).

- [x] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed. `ScopeGuardStage` is exercised by several integration tests — check specifically if anything fails: `.venv/bin/pytest tests/test_tool_catalog_integration.py tests/test_toolkit_integration.py -v`.

- [x] **Step 6: Commit**

```bash
git add cism/agent/guardrails/scope.py tests/test_scope_guard.py
git commit -m "fix: ScopeGuardStage fails closed on malformed CIDR notation and recognizes nmap's hostname/prefixlen target syntax"
```

---

### Task 9: [Minor] `GuardrailChain.run` converts a stage's internal exception into a block instead of letting it abort the run

**Files:**
- Modify: `cism/agent/guardrails/chain.py`
- Test: `tests/test_guardrail_chain.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature changes — `GuardrailChain.run`'s internal behavior changes; `GuardrailResult` is unchanged.

**Current code being changed** (`cism/agent/guardrails/chain.py`):

```python
    def run(self, value: T) -> GuardrailResult[T]:
        current = value
        for stage in self._stages:
            result = stage.check(current)
            if not result.allowed:
                return dataclasses.replace(result, stage=stage.name)
            current = result.value
        return GuardrailResult(allowed=True, value=current)
```

- [x] **Step 1: Write the failing tests — append to `tests/test_guardrail_chain.py`**

```python
class _RaisingStage:
    name = "raising-stage"

    def check(self, value):
        raise ValueError("could not parse this call")


def test_a_stage_that_raises_produces_a_blocked_result_instead_of_propagating() -> None:
    """A malformed/adversarial call can make a stage's internal parsing
    logic raise (e.g. scope.py's _extract_host on a malformed bracketed
    URL, or a non-dict `args` from a malformed ToolCall langchain_core can
    actually produce). Before this fix that exception escapes run(),
    propagates out of act(), and is caught by core.py's broad top-level
    except — ending the ENTIRE agent run rather than blocking the ONE
    call. A single hallucinated or malformed tool call must not have the
    power to kill the run."""
    chain = GuardrailChain([_RaisingStage()])

    result = chain.run("hello")

    assert result.allowed is False
    assert result.stage == "raising-stage"
    assert "could not parse this call" in result.reason


def test_a_stage_that_raises_short_circuits_later_stages_the_same_way_a_block_does() -> None:
    never_called = _NeverCalledStage()
    chain = GuardrailChain([_RaisingStage(), never_called])

    result = chain.run("hello")

    assert result.allowed is False
    assert never_called.calls == 0
```

- [x] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_guardrail_chain.py -v -k "raises"
```

Expected: both tests FAIL — `chain.run("hello")` currently raises `ValueError` instead of returning a `GuardrailResult`, so `pytest` reports an error (uncaught exception), not an assertion failure.

- [x] **Step 3: Implement — modify `GuardrailChain.run` in `cism/agent/guardrails/chain.py`**

```python
    def run(self, value: T) -> GuardrailResult[T]:
        current = value
        for stage in self._stages:
            try:
                result = stage.check(current)
            except Exception as exc:
                # A stage that cannot make sense of a malformed or
                # adversarial call must not crash the graph node — that
                # is itself a denial-of-service surface, and the fix
                # belongs here once, not at every individual raise site
                # inside every stage.
                return GuardrailResult(
                    allowed=False,
                    value=current,
                    reason=f"{type(exc).__name__}: {exc}",
                    stage=stage.name,
                )
            if not result.allowed:
                return dataclasses.replace(result, stage=stage.name)
            current = result.value
        return GuardrailResult(allowed=True, value=current)
```

- [x] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_guardrail_chain.py -v
```

Expected: all pass, including every pre-existing test (`test_a_blocking_stage_short_circuits_later_stages`, `test_a_blocking_stage_result_is_stamped_with_the_stage_that_blocked_it`, `test_a_passing_result_has_no_stage_stamped` — none of these involve a raising stage, so none should change behavior).

- [x] **Step 5: Write the integration-level regression test — append to `tests/test_scope_guard.py`**

```python
def test_a_malformed_bracketed_url_is_blocked_not_raised() -> None:
    """_extract_host's urlparse(value).hostname access can raise
    ValueError on a malformed bracketed URL (a plausible model
    hallucination, e.g. an unterminated IPv6 bracket) — this must now
    produce a blocked GuardrailResult via GuardrailChain.run's exception
    handling, not propagate out of ScopeGuardStage.check() directly (the
    stage itself doesn't catch it; the chain does, per Task 9)."""
    from cism.agent.guardrails.chain import GuardrailChain

    chain = GuardrailChain([_stage()])
    result = chain.run(_call("curl", target="http://[::1"))
    assert result.allowed is False
```

- [x] **Step 6: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "malformed_bracketed_url"
```

Expected: PASS (this exercises the Task 9 fix from the scope-guard test file's perspective, proving the two changes compose correctly).

- [x] **Step 7: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed.

- [x] **Step 8: Commit**

```bash
git add cism/agent/guardrails/chain.py tests/test_guardrail_chain.py tests/test_scope_guard.py
git commit -m "fix: GuardrailChain.run converts a stage's internal exception into a block, so a malformed call can no longer abort the entire agent run"
```

---

## Final check: whole-plan verification

- [x] Run the full suite one more time:

```bash
.venv/bin/pytest -q
```

Expected: baseline 470 plus every test added across Tasks 1–9, 0 failed.

- [x] Confirm no test anywhere still asserts on the old, now-outdated "not blocked" premise for `--output-dir` (Task 3 changed this test's expected outcome):

```bash
grep -n "output-dir" tests/test_dangerous_flags.py
```

Expected: the surviving test (`test_output_dir_is_now_denylisted_in_its_own_right`) asserts `allowed is False`; no test anywhere still asserts `allowed is True` for `--output-dir`.

- [x] Confirm every action-chain stage still has a real, non-empty `name` (unaffected by this plan, but cheap to re-verify given `chain.py` changed):

```bash
.venv/bin/python -c "
from cism.agent.profiles import default_profiles
from cism.agent.tools import ToolRegistry, dummy_nmap, dummy_msfconsole
from cism.agent.state import Phase
profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))
for phase in Phase:
    for stage in profiles.get(phase).action_stages:
        assert stage.name, f'{stage} has no name'
print('all action_stages have real names')
"
```

Expected: `all action_stages have real names`.
