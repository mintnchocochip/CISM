# Guardrail Bypass Follow-Up — Design

Phase 3 in the same series as [2026-09-04-bubblewrap-sandbox-runner-design.md](2026-09-04-bubblewrap-sandbox-runner-design.md) (the OS-level boundary) and [2026-09-04-phase-tool-guardrail-design.md](2026-09-04-phase-tool-guardrail-design.md) (the first guardrail-hardening pass). That pass's own final whole-branch review found two Critical bypasses, fixed both, and a scoped re-review of the fix then found that each fix closed only its literal repro string — an adjacent variant of the same bypass class survived. This document is the result of a dedicated, adversarial, live-verified audit run after that branch was otherwise complete, ordered to find *everything else* of the same shape before it ships.

## 1. Why

The prior document's own framing still holds: a call-time re-check, independent of what the LLM was told or bound to, because a prompt injection or a plain model mistake can't be trusted to stay inside intended bounds. The audit below asks the same question harder: **`ScopeGuardStage` and `DangerousFlagGuardStage` model a fraction of `curl`'s and `nmap`'s real argument grammar — where does that fraction actually stop, and does a realistic invocation (not a contrived one) fall outside it?**

Every finding below was verified live against the actual shipped code (and, where possible, against real `curl`) — a repro command and its actual output, not a code-reading guess.

## 2. Goals

- Close every finding from the audit (13 total: 6 Critical, 5 Important, 2 Minor) except the wiring gap (§6, deliberately deferred — see below).
- Preserve every existing passing test; every fix that changes matching behavior gets a fail-closed default, not a new false-positive it doesn't also fix.
- Keep the same architecture: no new guard stages, no new `GuardrailChain` shape. These are fixes to `_extract_host`/`_candidate_hosts` (scope.py) and `_hits`/the per-tool denylist tables (dangerous_flags.py), plus one small addition to `GuardrailChain.run` itself (§5.12/§5.13).

## 3. Non-goals (explicitly deferred)

- **Wiring `GuardrailSeam` (real `ScopeGuardStage`/`DangerousFlagGuardStage`) into `LangGraphAgent`'s construction, and wiring a real (non-dummy) `ToolRegistry` into `run_agent.py`.** Audit Finding 8 confirmed neither is wired today — `core.py:96` defaults to `GuardrailSeam.no_op()`, and `run_agent.py` never passes a `tools=` argument, so `LangGraphAgent`'s default registry stays `[dummy_nmap, dummy_msfconsole]` even with a real LLM configured. This means none of the findings below are live against a real target *today*. Explicitly kept as a separate plan (`docs/superpowers/plans/2026-09-06-wire-real-guardrails-and-toolkit.md`) so it can be reviewed and sequenced on its own — this document only hardens the guard logic itself.
- **The architectural pivot to an allowlist grammar for `extra`.** The audit's own conclusion is that a denylist can't durably close this bug class (curl 8.5 alone has ~250 long options). This document patches every finding found — a bounded, reviewable amount of work — rather than attempting that pivot now. Noted as future work if a fourteenth variant surfaces after this ships.
- **Egress control, the input/output `GuardrailChain` legs, indirect prompt injection via tool output, DEPG/memory poisoning, resource-limit/DoS guardrails.** Same reasoning as the prior document's §3 — unchanged, not revisited here.

## 4. Audit findings (reference — full detail, including live repro transcripts, given in the follow-up plan's task briefs)

| # | Finding | Severity | File |
|---|---|---|---|
| 1a | `_extract_host` fails open on decimal/hex-encoded IPv4 (`2852039166`, `0xA9FEA9FE`) | Critical | `scope.py` |
| 1b | `_extract_host` fails open on GCP's bare `metadata` short hostname | Critical | `scope.py` |
| 2 | `_extract_host` fails open on `file://` and other empty-authority URLs (arbitrary local file read) | Critical | `scope.py` |
| 3 | `_hits()` misses curl's own long-option prefix abbreviation (`--conf` for `--config`) | Critical | `dangerous_flags.py` |
| 4 | `_hits()` misses curl short-flag *bundling* (`-sSo/tmp/pwn` == `-s -S -o /tmp/pwn`) | Critical | `dangerous_flags.py` |
| 5 | curl's connection-redirection family (`--resolve`, `--connect-to`, `-x`/`--proxy`, `--unix-socket`) and file-touching family (`-b`, `-w`, `--trace*`, `--netrc-file`, …) absent from the denylist | Critical | `dangerous_flags.py` |
| 6 | nmap's `-iR` (random-Internet-hosts scope escape), `--datadir`, and related flags absent from the denylist | Important | `dangerous_flags.py` |
| 7 | `_TARGET_ARG_BY_TOOL` names argument keys (`url`, `host`) `build_catalog` can never emit — a silent scope-check-off trap for the next tool added | Important | `scope.py` |
| 8 | Nothing wires a real `GuardrailSeam`/toolkit into `LangGraphAgent` | Important | *(deferred, §3)* |
| 9 | Comma-list flattening silently drops a comma-part it can't parse, rather than treating a partial parse as suspicious | Important | `scope.py` |
| 10 | `_is_always_denied` doesn't canonicalize IPv4-mapped IPv6 (`::ffff:169.254.169.254`) | Important | `scope.py` |
| 11 | `_extract_host`'s CIDR recognition fails open on malformed CIDR and nmap's own `hostname/prefixlen` target syntax | Important | `scope.py` |
| 12 | `_extract_host` can raise `ValueError` (malformed bracketed URL); `GuardrailChain.run` doesn't catch it — the run aborts instead of the call being blocked | Minor | `scope.py` / `chain.py` |
| 13 | A malformed `ToolCall` shape (non-dict `args`, missing `name`) raises inside a stage instead of blocking | Minor | `chain.py` |

Findings 12 and 13 share one root cause and one fix (§5.12).

## 5. Fixes

### 5.1–5.2 [Critical] `_extract_host`: recognize decimal/hex IPv4, and the bare `metadata` short hostname (Findings 1a, 1b)

**The bug:** `ipaddress.ip_address()` only accepts canonical dotted-quad text — it rejects `"2852039166"` and `"0xA9FEA9FE"` outright, even though `curl`/`getaddrinfo` resolve both as `169.254.169.254`. Separately, `_BARE_DOMAIN_RE` requires a dot, so a single-label hostname (GCP's own `metadata`, resolvable via the VM's default DNS search domain with no dot at all) is never recognized as host-shaped.

**Fix, decimal/hex IPv4** — a small parser, deliberately gated well above any legitimate small-integer argument this agent's tools take (ports 0–65535, nmap timing 0–5, thread counts capped at 16 — see `credentials.py`'s `_MAX_THREADS`), so a real target IP's numeric encoding (always in the hundreds of millions to billions) is recognized while an ordinary flag value never is:

```python
#: Above this, a bare digit string is far more likely to be an encoded
#: IPv4 address than a legitimate small numeric argument this agent's
#: tools actually take (ports 0-65535, nmap timing 0-5, thread counts
#: capped at 16) — 169.254.169.254 encodes to 2852039166, far above it.
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

Called from `_extract_host` right after the comma/CIDR branches, before the existing `ipaddress.ip_address(value)` try.

**Fix, bare `metadata`:** add `"metadata"` to `_ALWAYS_DENIED_HOSTS`, and give `_extract_host` a final fallback (after the existing `_BARE_DOMAIN_RE` check) that recognizes *any* exact hard-denied entry even without a dot — future-proofing the same fix for any single-label entry added later, not just this one:

```python
if value.lower() in _ALWAYS_DENIED_HOSTS:
    return value.lower()
return None
```

This is deliberately narrow — it only recognizes bare words *already* in the hard-deny list, so it introduces zero new false positives for other bare words (`ssh`, `responder`, a Metasploit module path).

### 5.3 [Critical] `_extract_host`: block (not silently drop) URLs with no host (Finding 2)

**The bug:** `urlparse("file:///etc/shadow").hostname` is `""` — falsy, so `_extract_host` returns `None`, and `_candidate_hosts` treats "no host found" as "nothing to check", not "block this". `curl` supports `file://` natively; live-verified: `curl file:///etc/shadow` returns the file's contents as the tool's own output.

**Fix:** a URL with no host is not "no candidate" — it is a local-file/protocol-smuggling primitive that must fail the scope check outright:

```python
if "://" in value:
    hostname = urlparse(value).hostname
    if not hostname:
        # file:///etc/shadow (and any other empty-authority URL) has no
        # host at all — this is a local-file-read primitive, not "no
        # target found". Returning the literal value guarantees it fails
        # every scope/hard-deny check (nothing declared will ever equal
        # this string), which is what "block" means here.
        return value
    return _strip_trailing_dot(hostname)
```

### 5.4–5.6, and short-flag matching rewrite [Critical] `dangerous_flags.py`: abbreviation, bundling, and missing flags (Findings 3, 4, 5)

**The bug (abbreviation, Finding 3):** curl's own parser accepts any *unambiguous prefix* of a long option (`--conf` → `--config`). `_hits()`'s long-flag check is exact-match only (`head == f`), so every long flag on the denylist is bypassed by truncating it. Live-verified: `curl --conf /tmp/rc` (a curlrc setting `output = ...`) writes an arbitrary file exactly like the already-blocked `-K`.

**The bug (bundling, Finding 4):** curl accepts single-dash short options bundled into one cluster, with a value-taking flag consuming the remainder as its value (`-sSo/tmp/pwn` == `-s -S -o /tmp/pwn`). `token.startswith(f)` only catches the case where the denylisted flag is the *first* thing in the token — a flag bundled after another (`-sSo...`, `-sO`, `-fsSLo...`) is missed entirely. Live-verified against real curl: `curl -sSo/tmp/pwn https://...` writes the file.

**The bug (missing flags, Finding 5):** several curl primitives of the exact same class as what's already denylisted are simply absent: `--resolve`/`--connect-to` (redirect the connection to an arbitrary address while the *visible* URL — the only thing `ScopeGuardStage` sees — stays in-scope), `-x`/`--proxy`, `--unix-socket`/`--abstract-unix-socket` (Unix-socket takeover, e.g. `/var/run/docker.sock`), `-b`/`--cookie`, `-w`/`--write-out` (both arbitrary-file-read-and-exfiltrate via `@path`), `--trace`/`--trace-ascii`/`--stderr`/`--output-dir`/`--netrc-file`/`--etag-save` (arbitrary file write), `-J`/`--remote-name-all`, `--cert`/`--key`/`--cacert`. All live-verified against real curl (file write, file read, and a redirected-connection proof via a local listener).

**Fix — one rewritten `_hits()`, handling both abbreviation and bundling, plus an extended table:**

```python
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

**Fix — extended tables** (additions only; existing entries unchanged):

```python
_PER_TOOL_DANGEROUS_TOKENS: dict[str, frozenset[str]] = {
    "nmap": frozenset({
        "--script", "-oN", "-oX", "-oG", "-oA", "-iL", "--excludefile",
        # §5.7 (Finding 6):
        "-iR", "-oS", "--datadir", "--resume", "--stylesheet", "--webxml",
        "--script-args-file", "--script-help", "--servicedb", "--versiondb",
        "--proxies", "--append-output",
    }),
    "curl": frozenset({
        "-o", "-O", "--output", "--remote-name",
        "-T", "--upload-file",
        "-F", "--form", "-d", "--data", "--data-binary", "--data-urlencode", "--data-raw",
        "-D", "--dump-header", "-c", "--cookie-jar",
        # §5.6 (Finding 5) — connection redirection:
        "-x", "--proxy", "--resolve", "--connect-to",
        "--unix-socket", "--abstract-unix-socket", "--interface",
        # §5.6 (Finding 5) — file read/write:
        "-b", "--cookie", "-w", "--write-out", "--trace", "--trace-ascii",
        "--stderr", "--output-dir", "--create-dirs", "--netrc-file",
        "--etag-save", "--etag-compare", "-J", "--remote-header-name",
        "--remote-name-all", "--cert", "--key", "--cacert",
    }),
}
```

`-iR` (Finding 6) is conceptually a *scope* escape (nmap ignores the target and scans random Internet hosts) rather than a filesystem escape, but blocking it via the existing per-tool flag denylist achieves the identical practical effect (the call is blocked) without introducing a second parallel mechanism — noted here so the placement isn't mistaken for a miscategorization.

### 5.7 [Important] `_TARGET_ARG_BY_TOOL`: fall back to the all-args scan instead of checking nothing (Finding 7)

**The bug:** `_TARGET_ARG_BY_TOOL` maps `wget`→`"url"`, `gobuster`→`"url"`, `ffuf`→`"url"`, `ssh`/`scp`→`"host"` — but `cism/agent/tools/base.py`'s catalog-built tools always name the target field `"target"`, never these. If any of these five names is ever added to `catalog.yaml`, `_candidate_hosts` takes the registered-tool branch, looks up a key that's never present, finds `None`, and checks *nothing* — not the fallback scan, silence. Live-verified: adding `wget` to the mapping with a real `args={"target": "http://169.254.169.254/"}` call reaches the metadata host unblocked, while the identical `curl` call (correct mapping) is blocked.

**Fix:** fall back to the all-args scan when the mapped key isn't present as a string, instead of checking nothing:

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

For every currently-real registered tool (`nmap`, `curl`, `hydra`, `medusa`, `masscan` — all mapped to `"target"`, which `base.py` really does emit), behavior is unchanged: the mapped key is present as a string, so the `if` branch runs exactly as before.

### 5.8 [Important] Comma-list: a partial parse blocks the whole token (Finding 9)

**The bug:** `hosts = [h for p in parts if (h := _extract_host(p))]` silently keeps only the parts it recognizes. `"10.0.0.5,2130706433"` (before §5.1's fix) dropped the second part entirely rather than blocking on it — the exact "one recognized host launders an unrecognized one past the check" shape Task 1 of the prior plan closed for the *unanimity* bug; this is the same shape from the opposite direction (partial success instead of partial failure).

**Fix:** distinguish three outcomes — nothing parses (unchanged: not a target list at all, e.g. a port range, allowed through as today), everything parses (unchanged: a clean multi-host list, checked normally), and *some but not all* parts parse (new: block outright, since an unrecognized comma-part might be host-shaped in an encoding this parser doesn't know about yet — exactly what §5.1 closes for two specific encodings, and defense-in-depth against the next one):

```python
if "," in value:
    parts = value.split(",")
    hosts = [h for p in parts if (h := _extract_host(p))]
    if not hosts:
        return None
    if len(hosts) < len(parts):
        return "<unparseable-multi-target>"
    return ",".join(hosts)
```

The sentinel deliberately contains no comma (so `_candidate_hosts`'s comma-flattening step doesn't re-split it back into parts, which would defeat the guaranteed block) and never matches any declared scope/hard-deny entry.

### 5.9 [Important] `_is_always_denied`: canonicalize IPv4-mapped IPv6 (Finding 10)

**The bug:** the prior plan's fix (`str(ipaddress.ip_address(host))`) canonicalizes case and compression, but Python renders `::ffff:169.254.169.254` as `::ffff:a9fe:a9fe` — a string that isn't in `_ALWAYS_DENIED_HOSTS`. The embedded IPv4 address is never extracted for comparison.

**Fix:**

```python
def _is_always_denied(host: str) -> bool:
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
```

### 5.10–5.11 [Important] `_extract_host`: fail closed on malformed/hostname CIDR, without misreading URL paths (Finding 11)

**The bug:** the current CIDR branch (`if "/" in value: try: return str(ipaddress.ip_network(value, strict=False)) except ValueError: pass`) silently falls through to the rest of the function on *any* parse failure — a leading-zero octet (`192.168.001.0/24`), an out-of-range prefix (`/33`), or nmap's own documented `hostname/prefixlen` target syntax (`metadata.google.internal/24`, which resolves the host and scans the surrounding network) all end up unrecognized and therefore unchecked, not blocked. Live-verified: `nmap metadata.google.internal/24` reaches argv unblocked.

**Fix:** split on the *last* `/` first; if what follows is a bare digit string (a prefix-length shape) and a URL scheme isn't present, treat this as CIDR-intended and never silently fall through — either it parses as a numeric network (unchanged happy path), or its host half resolves through the normal host-recognition path (closing the `hostname/prefixlen` case), or it's genuinely unparseable and blocks:

```python
if "/" in value and "://" not in value:
    host_part, _, suffix = value.rpartition("/")
    if suffix.isdigit() and host_part:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
        # Not a numeric CIDR literal — nmap's own "hostname/prefixlen"
        # target syntax reaches here. This guard cannot itself resolve
        # DNS to know what such a target expands to, so recognizing it
        # as host-shaped (rather than dropping it) is what lets
        # EngagementScope.contains_network fail closed on it below —
        # a hostname/prefix combo is always out of scope, even for an
        # otherwise-declared-in-scope domain, since prefix-expanding a
        # hostname is exactly the kind of scope-widening this guard
        # cannot safely verify without doing DNS resolution itself.
        host = _extract_host(host_part)
        return f"{host}/{suffix}" if host is not None else "<unparseable-cidr>"
    # Contains a "/" but doesn't end in a bare number (a file path, a
    # Metasploit module path) — not CIDR notation. Fall through below,
    # unchanged from before this task.
```

The `"://" not in value` guard is required: without it, a completely ordinary URL whose last path segment happens to be numeric (`https://api.example.com/v1/users/24`) would be misread as `hostname/prefixlen` and blocked as an unparseable network — real CIDR/`hostname/prefixlen` target syntax is always a bare string, never embedded in a URL, so excluding anything containing `"://"` closes that false-positive with no loss of the fix's actual target.

`EngagementScope.contains_network` and `_is_always_denied`'s existing numeric-CIDR handling need no further changes: both already fail closed (`return False`) on a `ValueError` from `ipaddress.ip_network`, which is exactly what a malformed numeric CIDR (leading zero, out-of-range prefix) or a `hostname/prefixlen` string now produces when handed to them — the fix above only had to stop `_extract_host` from silently discarding these shapes before they ever reached that existing fail-closed logic.

Accepted, documented tradeoff: a legitimate but unusual argument value that happens to be a bare `"/"`-containing, digit-suffixed, non-URL string whose host half doesn't resolve (e.g., a literal file path ending in a numeric directory name, passed to a flag not already on the dangerous-flag denylist) would now be blocked as `<unparseable-cidr>` rather than silently ignored. Given every currently-denylisted path-taking flag (`-iL`, `-oN`, `--excludefile`, `-o`, `-T`, …) is already independently blocked by `DangerousFlagGuardStage` regardless of what `ScopeGuardStage` does with its argument, this tradeoff has no known live false-positive today — noted for the record per the project's established "bias toward blocking" principle (§4.3 of the prior design doc: "a wrongly-blocked call is fully recoverable while an actual file write/read is not").

### 5.12 [Minor] `GuardrailChain.run`: a stage exception blocks, it doesn't abort the run (Findings 12, 13)

**The bug:** `_extract_host` can raise `ValueError` on a malformed bracketed URL (`urlparse("http://[::1").hostname` raises rather than returning `None`); a malformed `ToolCall` (non-dict `args` — which `langchain_core`'s own `parse_tool_call` can actually produce, live-verified, when a model emits a JSON array instead of an object for `arguments`) raises `AttributeError`/`KeyError` inside a stage's `check()`. Neither is fail-open (the call does not proceed), but the exception is unhandled by `GuardrailChain.run`, so it propagates out of `act()` and is caught by `core.py`'s broad top-level `except`, ending the *entire agent run* rather than blocking the *one call*. A single hallucinated or malformed tool call currently has the power to kill the run — a denial-of-service on the agent itself, not a security bypass, but still a defect in a chain whose whole job is to turn "we don't understand this call" into "block it," not "crash."

**Fix — one place, matching the codebase's own stated principle** ("One place each fix lives" — prior design doc §2): wrap the stage call itself, so *any* current or future stage's internal failure degrades to a block, never a crash:

```python
class GuardrailChain(Generic[T]):
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

The exception's `str()` becomes the stage's `reason` — per the prior plan's Task 2 convention, this is *never* LLM-facing (only the fixed generic `"blocked by action guardrail"` string is); it reaches only `additional_kwargs["guardrail_detail"]`/`ToolFailed`, exactly like any other stage's rich reason, so no new information-leak surface is introduced by including the raw exception text here.

## 6. Testing

Every finding gets a live-verified adversarial test reproducing the exact audited shape, not a synthetic happy-path test:

- **§5.1–5.2:** decimal (`http://2852039166/`) and hex (`0xA9FEA9FE`) encodings of the metadata IP, blocked; the bare word `metadata`, blocked; a legitimate small numeric flag value (a port, a thread count) unaffected.
- **§5.3:** `file:///etc/shadow` as a bare `target`, blocked; a normal `http://`/`https://` URL with a real hostname unaffected.
- **§5.4–5.6:** `--conf`/`--dump-h`/`--cookie-j` abbreviations of denylisted long flags, blocked; `-sSo/tmp/pwn`, `-sO`, `-fsSLo/tmp/pwn` bundling variants, blocked; each newly-added curl flag (`--resolve`, `--connect-to`, `-x`, `--unix-socket`, `-b`, `-w`, `--trace`, `--netrc-file`, …) individually blocked; a legitimate unrelated long flag (e.g. `--http1.1`) and a legitimate boolean short-flag cluster (`-sSL`) unaffected.
- **§5.7:** `-iR`, `--datadir`, and the other newly-added nmap flags individually blocked.
- **§5.7 (target-arg fallback):** a hypothetical tool registered under one of the five dead `_TARGET_ARG_BY_TOOL` names still gets its target scope-checked via the fallback scan.
- **§5.8:** a comma list with one recognized and one still-unrecognized (synthetic, e.g. a value guaranteed to never parse) part is blocked; the existing all-parse and zero-parse cases are unaffected (regression guards).
- **§5.9:** `::ffff:169.254.169.254` blocked against the hard-deny.
- **§5.10–5.11:** `metadata.google.internal/24` blocked; a malformed numeric CIDR (`192.168.001.0/24`, `10.0.0.0/33`) blocked; a URL with a numeric-looking last path segment (`https://a.example.com/24`) is unaffected (regression guard, proves the `"://" not in value` guard).
- **§5.12:** a malformed bracketed URL (`http://[::1`) and a non-dict `args` shape both produce a blocked `GuardrailResult` from `GuardrailChain.run` rather than raising; the run continues rather than aborting.

## 7. Priority summary

| # | Finding | Severity |
|---|---|---|
| 1a | Decimal/hex IPv4 encoding fail-open | Critical |
| 1b | Bare `metadata` hostname fail-open | Critical |
| 2 | `file://`/empty-authority URL fail-open | Critical |
| 3 | curl long-flag abbreviation bypass | Critical |
| 4 | curl short-flag bundling bypass | Critical |
| 5 | curl connection-redirection/file-touching flags missing | Critical |
| 6 | nmap `-iR`/`--datadir`/etc. missing | Important |
| 7 | `_TARGET_ARG_BY_TOOL` dead-entry trap | Important |
| 9 | Comma-list partial-parse silently dropped | Important |
| 10 | IPv4-mapped IPv6 canonicalization gap | Important |
| 11 | CIDR/`hostname/prefixlen` fail-open | Important |
| 12/13 | Stage exception aborts the run instead of blocking | Minor |

(Finding 8 — nothing wired — is Important but deliberately out of scope here; see §3 and the separate wiring plan.)
