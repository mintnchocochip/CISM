# Action-Chain Guardrail Hardening — Design

Phase 2 of 2. Phase 1 ([2026-09-04-bubblewrap-sandbox-runner-design.md](2026-09-04-bubblewrap-sandbox-runner-design.md)) is the hard OS-level boundary; this document is the soft policy layer in front of it — the `action` `GuardrailChain` a call passes through before it ever reaches a subprocess.

This started as one new stage (`PhaseToolGuardStage`, closing the capability-vs-phase gap). While reviewing it, an explicit ask to check for more of the same class of problem turned up several: one currently-exploitable scope-bypass in already-shipped code, one currently-active information leak to the LLM in already-shipped code, and one denylist-completeness gap. All are written up here together because they're the same underlying concern — **is this chain actually hard to defeat, or does it only stop the obvious case** — and an implementer working through them benefits from seeing them as one coherent audit rather than a fix landing separately from the design that prompted the question.

**Findings are ordered by severity, not by build order.** Each has its own Design/Testing subsection under §4; §6 gives the priority summary.

## 1. Why

`ScopeGuardStage` and `DangerousFlagGuardStage` already establish the pattern this document extends: a call-time re-check, independent of what the LLM was told or bound to, because a prompt injection (from a scanned target's own banner text, an HTTP response header, a DNS TXT record — anything the agent reads back as tool output) or a plain model mistake can't be trusted to stay inside intended bounds. The audit below asks the same question of the existing two stages that motivated building a third: **where does this heuristic actually stop, and what did we assume about the caller that a compromised caller wouldn't respect?**

## 2. Goals

- Close the scope-bypass and information-leak findings below, not just add the originally-planned stage.
- No finding's fix requires trusting the LLM to behave — every fix holds even if the calling model is actively adversarial (via injection or otherwise).
- Every guard's rich internal reasoning stays available to the human operator (via logs / `ToolFailed`), and never reaches the model's own context.
- One place each fix lives — extending existing stages/modules where the concern already lives there, not scattering parallel checks.

## 3. Non-goals (explicitly deferred, with the reason)

- **Egress control (proxy allowlist + nftables) and the input/output `GuardrailChain` legs.** Both already named as follow-ons in earlier discussion; nothing here changes that.
- **Indirect prompt injection via tool output itself** — a scanned target's banner, HTTP response, or DNS record containing adversarial text that the agent reads back as `ToolMessage` content on its next `think` turn. This is real and related (it's *why* every fix below must not trust the caller), but detecting/sanitizing malicious content arriving as legitimate tool output is a much larger problem (content classification, not argument inspection) that belongs with the output-chain follow-on, not bolted onto this document.
- **DEPG/memory poisoning via the same injected content persisting across runs.** Same reasoning — named so it isn't forgotten, not solved here.
- **Resource-limit/DoS guardrails** (e.g. nmap `--min-rate` + `-p-` flooding a target or local network). Plausibly intentional given the tool's actual purpose (aggressive scanning is sometimes the point); not addressed here.
- **A fully declarative per-tool denylist in `catalog.yaml`.** §4.3 makes `DangerousFlagGuardStage` tool-aware via a Python dict, not a new YAML schema field — smaller, and the catalog's `flags`/`allow_raw` split already covers the "what can this tool be told to do" axis; a third YAML-configurable axis for "what's dangerous" is more machinery than four tool-specific entries justify right now.

## 4. Findings & Design

### 4.1 [Critical] Scope-check bypass via `extra` (fixes already-shipped `ScopeGuardStage`)

**The bug:** `ScopeGuardStage._candidate_hosts` (`cism/agent/guardrails/scope.py`) only inspects the argument named in `_TARGET_ARG_BY_TOOL` (`target` for `nmap`/`curl`) when that mapping exists — it never looks at `extra` at all. `render_argv` (`base.py`) places `extra`'s tokens *before* `target` in argv. Result, verified against the real code path:

```python
curl.invoke({"target": "https://good.example.com", "extra": "https://evil-target.com"})
# argv = ["curl", "https://evil-target.com", "https://good.example.com"]
# curl fetches BOTH urls. ScopeGuardStage only ever checked "target".
```

Same shape for `nmap`: `extra: "10.0.0.99"` adds a second, completely unvetted scan target — no dangerous flag needed, just a bare host string. This affects both current `allow_raw` tools (`nmap`, `curl`); `nikto`/`whatweb`/`dnsenum` aren't exposed (no `allow_raw`, no `extra` field exists for them at all).

**Fix:** `_candidate_hosts` always additionally scans `shlex.split(extra)` token-by-token, merging with whatever the primary target-arg branch found, rather than returning early from that branch:

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
    if isinstance(extra, str):
        try:
            tokens = shlex.split(extra)
        except ValueError:
            tokens = [extra]
        for token in tokens:
            host = _extract_host(token)
            if host:
                hosts.append(host)

    return hosts
```

`check()` already rejects on the *first* out-of-scope host found across whatever `_candidate_hosts` returns — no change needed there.

**In scope for this same fix, not deferred:** `_extract_host` doesn't recognize a comma-separated multi-target token (`10.0.0.5,10.0.0.99` as one shlex token, valid nmap syntax) as host-shaped at all — it returns `None` today, meaning it's silently *not checked*, not incorrectly allowed by a broken check. Since §4.1's whole point is closing gaps in what `_candidate_hosts` inspects, leaving this one open would be inconsistent with the finding it sits right next to. Fix, in `_extract_host`, before the existing checks:

```python
def _extract_host(value: str) -> str | None:
    if "," in value:
        parts = value.split(",")
        hosts = [_extract_host(p) for p in parts]
        return value if all(hosts) else None  # all comma-parts host-shaped, or don't treat this as one host
    ...  # existing checks unchanged
```

Returning `value` (not one of the parts) signals "this token contains host(s)" back to `_candidate_hosts`, which then needs a small companion change: when a candidate contains a comma, split it into individual hosts for the scope check rather than checking the whole comma-joined string as one host literal (which would never match any single declared CIDR/domain). `_candidate_hosts` already appends whatever `_extract_host` returns to its `hosts` list — that list gets flattened: any entry containing `,` is split before being checked against scope, each part checked independently, same as if they'd arrived as separate tokens.

### 4.2 [Critical] Guardrail-block reason leaks to the LLM (fixes already-shipped behavior in `nodes.py`)

**The bug:** `act()` in `nodes.py` does `content=f"blocked by action guardrail: {guard.reason or 'no reason given'}"` — this string becomes a `ToolMessage` that re-enters the LLM's own context on the next turn. Every stage's `reason` is specific: `ScopeGuardStage` names the exact rejected host; `DangerousFlagGuardStage` lists the exact denylisted flags that matched. An adversarial or injected model has a live oracle today — it can probe and read back exactly which flags/hosts are blocked, then find an unlisted equivalent.

**Fix, three parts:**

1. `GuardrailResult` (`chain.py`) gains a `stage: str = ""` field. Not set by individual stages — `GuardrailChain.run()` stamps it from `stage.name` whenever a stage blocks:

```python
# cism/agent/guardrails/chain.py

@dataclass(frozen=True, slots=True)
class GuardrailResult(Generic[T]):
    allowed: bool
    value: T
    reason: str = ""
    stage: str = ""  # new — which stage produced this result, set by GuardrailChain.run(), never by a stage itself

class GuardrailChain(Generic[T]):
    def run(self, value: T) -> GuardrailResult[T]:
        current = value
        for stage in self._stages:
            result = stage.check(current)
            if not result.allowed:
                return dataclasses.replace(result, stage=stage.name)  # changed: was `return result`
            current = result.value
        return GuardrailResult(allowed=True, value=current)
```

One place (`GuardrailChain.run`), so it's structurally consistent for every stage, present and future, with no per-stage discipline required. (`import dataclasses` added to `chain.py`.)

2. `act()`'s LLM-facing content becomes a fixed, generic string with zero interpolation, and the rich detail moves to `additional_kwargs` instead of being discarded:

```python
# cism/agent/nodes.py — inside act(), the `if not guard.allowed:` branch

if not guard.allowed:
    results.append(
        ToolMessage(
            content="blocked by action guardrail",  # changed: was f"blocked by action guardrail: {guard.reason or ...}"
            tool_call_id=call["id"],
            name=call["name"],
            status="error",
            additional_kwargs={"guardrail_detail": f"[{guard.stage}] {guard.reason}"},  # new
        )
    )
    continue
```

No host, no flag names, no capability, no phase, no stage name in `content` — nothing that differentiates *why*, which is exactly what would let a probing model map the ruleset. Verified empirically against this repo's actual `ChatOpenAI` (`langchain_openai`, used by `build_chat_model` in `cism/agent/llm.py`): `additional_kwargs` is dropped entirely by the real OpenAI-wire message conversion (confirmed via `langchain_core`'s `convert_to_openai_messages`) — it never reaches the model, by construction, not by convention.

3. `core.py`'s `_translate` (the `node == "act"` branch) reads the new field instead of `message.content` when present:

```python
# cism/agent/core.py — inside _translate(), the `elif node == "act":` branch

if getattr(message, "status", "success") == "error":
    detail = message.additional_kwargs.get("guardrail_detail") or str(message.content)
    await self.events.put(ToolFailed(call_id=call_id, reason=detail))
```

Falls back to `str(message.content)` for genuine (non-guardrail) tool-execution errors, whose `content` is still the real exception message today (§4.2 only changes the guardrail-block path in `act()`, not the `except Exception` path) — so the operator/TUI still sees full detail for every failure type, unchanged from today's behavior for non-guardrail errors and *richer* than today for guardrail ones (today's generic wrapper text is replaced by the actual stage name + reason).

This applies uniformly to `ScopeGuardStage`, `DangerousFlagGuardStage`, and `PhaseToolGuardStage` (§4.4) — one fix point, not three.

### 4.3 [High] `DangerousFlagGuardStage` becomes tool-aware; closes a real gap, fixes a real false positive

**Gap found:** the current denylist (`_DANGEROUS_FLAG_TOKENS`, one flat set shared across every tool) doesn't cover curl's other well-known local-file-read/write primitives: `-F`/`--form` (`@path` reads and uploads an arbitrary local file — same class of risk as the already-denylisted `-T`/`--upload-file`, just a different flag), `-d`/`--data`/`--data-binary`/`--data-urlencode` (all support `@path` to read a local file as the request body), `-D`/`--dump-header` and `-c`/`--cookie-jar` (arbitrary local file write, same class as the already-denylisted `-o`). None of these are in the current list.

**False positive found:** the denylist is tool-agnostic, but `-T` is curl-specific (`--upload-file`); nmap's own `-T<0-5>` timing template is a *different* flag that happens to share the letter. If a model ever writes it space-separated (`-T 4` rather than the idiomatic `-T4`), `shlex.split` produces a bare `"-T"` token that today incorrectly triggers the curl-only rule for an nmap call.

**Fix:** split the denylist into a small shared baseline plus a per-tool table, checked against `call["name"]`:

```python
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

def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
    ...  # tokens = shlex.split(extra), same fail-closed try/except as today
    denylist = _SHARED_DANGEROUS_TOKENS | _PER_TOOL_DANGEROUS_TOKENS.get(call.get("name", ""), frozenset())
    hit = tokens & denylist
    ...
```

`-iL`/`--excludefile` added to nmap's set for the same reason `-K`/`--config` is already denylisted for curl: both let a flag's *argument* be treated as more instructions/targets read from an arbitrary local path.

### 4.4 [High] `PhaseToolGuardStage` — capability-vs-phase re-check (original scope, unchanged from prior discussion)

Independent re-check that a called tool is actually offered in the current phase, built from `PhaseProfile.tool_names | {"tool_help"}` (the same source `default_profiles()` already computes for binding — can't drift from it by construction, since it's the same value, not a parallel derivation). Full detail as previously discussed:

```python
# cism/agent/guardrails/phase_tool.py

class PhaseToolGuardStage:
    name = "phase-tool-guard"

    def __init__(self, phase: Phase, allowed_tool_names: frozenset[str], tool_capabilities: dict[str, Capability]) -> None:
        self._phase = phase
        self._allowed = allowed_tool_names
        self._capabilities = tool_capabilities  # for the internal reason string only — §4.2 keeps it out of LLM-facing content

    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        name = call["name"]
        if name not in self._allowed:
            capability = self._capabilities.get(name, "unknown")
            return GuardrailResult(
                allowed=False,
                value=call,
                reason=f"{name!r} [capability={capability}] is not offered in phase {self._phase.to_wire()}",
            )
        return GuardrailResult(allowed=True, value=call)
```

Uses `Phase.to_wire()` (`self.name.lower().replace("_", "-")`, e.g. `Phase.RECON.to_wire() == "recon"`), not `self._phase.value` — `Phase` (`cism/agent/state.py`) is an `Enum` whose `.value` is a plain int (`Phase.RECON = 1`), which would have produced `"...phase 1"` instead of a readable name. `to_wire()` is the existing convention this codebase already uses everywhere else a `Phase` needs a string form (e.g. `PhaseChanged.phase`).

Built inside `default_profiles()` (`profiles.py`), attached via each `PhaseProfile.action_stages`:

```python
tool_capabilities = {name: spec.capability for name, spec in catalog.items()} | {"hydra": "executes"}
for phase in Phase:
    tool_names = ...  # exactly what's already computed for this phase
    profiles[phase] = PhaseProfile(
        tool_names=tool_names,
        action_stages=(PhaseToolGuardStage(phase, tool_names | {"tool_help"}, tool_capabilities),),
    )
```

No change to `GuardrailChain`, `nodes.py`'s stage-composition line, or `PhaseProfile`'s shape.

### 4.5 [Medium] `hydra` → `sandboxed_tool` conversion

Needed for §4.4's `tool_capabilities` lookup to have real data for hydra (currently a plain `@tool`, `.metadata` is `None`).

```python
# cism/agent/tools/credentials.py

@sandboxed_tool(binary="hydra", capability="executes", timeout=120.0)
def hydra(
    scratch: Path,
    target: str,
    service: str,
    usernames: list[str] | None = None,
    userlist: str | None = None,
    passwords: list[str] | None = None,
    passwordlist: str | None = None,
    threads: int = 4,
) -> list[str]:
    """Run hydra against one target/service with explicit credential lists
    or a named wordlist. Exactly one of usernames/userlist and one of
    passwords/passwordlist must be given; threads is capped at 16 —
    real safety here is the scope guardrail and the run timeout, not
    argv tricks."""
    argv = ["-t", str(min(threads, _MAX_THREADS))]
    argv += _cred_flag("-L", usernames, userlist, scratch / "users.txt")
    argv += _cred_flag("-P", passwords, passwordlist, scratch / "pass.txt")
    argv += [target, service]
    return argv
```

Returns only the argv tail; `sandboxed_tool` owns `run_sandboxed`, the scratch dir, and the `binary` prefix. `_materialize`/`_cred_flag`/`_WORDLISTS` unchanged. `run_sandboxed`/`scratch_dir` imports drop from `credentials.py`. Retires the defensive `(tool.metadata or {})` guard in `_binaries_of` (left in place, not removed — still handles metadata missing a `binary` key in principle). `_DECORATED_TOOL_PHASES` in `profiles.py` is unaffected — capability and phase-availability are separate axes; `executes` still defaults to zero phases and hydra still needs its explicit override.

### 4.6 [Medium] Hard-deny the cloud metadata endpoint regardless of declared scope

**Gap:** `EngagementScope.contains_host` checks only the declared `cidrs`/`domains` — nothing stops `169.254.169.254` (the cloud metadata service, reachable from inside most cloud VMs/containers) from being treated as in-scope if it ever ends up inside a broad declared CIDR (e.g. a wide `169.254.0.0/16` range) — a classic SSRF pivot to steal instance credentials, standard practice elsewhere to block unconditionally. Unlike blocking RFC1918 ranges generally (which would break legitimate internal-network pentests — often the actual point of an engagement), the metadata endpoint is never a legitimate target regardless of scope.

**Fix, small and self-contained, in `scope.py`:**

```python
_ALWAYS_DENIED_HOSTS: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS/GCP/Azure instance metadata
    "metadata.google.internal",
    "fd00:ec2::254",  # AWS IMDSv2 IPv6
})

class ScopeGuardStage:
    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        for host in _candidate_hosts(call):
            if host in _ALWAYS_DENIED_HOSTS or not self._scope.contains_host(host):
                return GuardrailResult(allowed=False, value=call, reason=f"{host!r} is outside the declared engagement scope")
        return GuardrailResult(allowed=True, value=call)
```

Deliberately reuses the same reason text (no separate "metadata endpoint" message) — per §4.2, the LLM never sees *why* a host was rejected anyway, so there's no reason to give the always-denied case a distinguishable internal message that a log-reading human couldn't already tell apart from the `_ALWAYS_DENIED_HOSTS` membership check itself.

## 5. Testing

Every finding gets an adversarial test proving the actual threat model, not just the happy path:

- **§4.1:** `curl.invoke`/`nmap.invoke` with a benign `target` and a second, out-of-scope host smuggled into `extra` (bare positional, and via a flag argument) — both blocked. A comma-separated smuggled multi-target token (`extra="10.0.0.5,10.0.0.99"`, one in scope and one not) — blocked, proving the split-and-check-each-part fix.
- **§4.2:** for each of the three action-chain stages, trigger a block and assert `ToolMessage.content` is exactly the fixed generic string — contains none of: the rejected host, the specific flag tokens, the capability value, the phase name. Separately assert `message.additional_kwargs["guardrail_detail"]` *does* contain the rich detail, and that `core.py`'s `ToolFailed.reason` surfaces it unchanged from current behavior.
- **§4.3:** `curl` calls with each newly-added flag (`-F`, `-d`, `-D`, `-c`, ...) individually blocked; an `nmap` call with `extra="-T 4"` (space-separated) is *not* blocked (the false-positive fix); a `curl` call with `-T` still *is* blocked (regression check that the fix didn't weaken curl's own coverage).
- **§4.4:** happy path (bound tool passes); adversarial (a `ToolCall` naming a tool that exists in the registry but isn't offered in this phase, simulating a hallucinated/injected call); unknown tool name blocked; `tool_help` exempted in every phase; `default_profiles()`'s guard `allowed_tool_names` asserted equal to that phase's own `tool_names | {"tool_help"}` by construction.
- **§4.5:** existing `test_tool_argv.py` hydra tests adapted to the new invocation path; `credentials.hydra.metadata == {"capability": "executes", "binary": "hydra"}`.
- **§4.6:** a call targeting `169.254.169.254` blocked even when constructed with a `EngagementScope` whose declared CIDR would otherwise contain it.

## 6. Priority summary

| # | Finding | Severity | Status before this design |
|---|---|---|---|
| 4.1 | Scope bypass via `extra` | Critical | Live bug in shipped code |
| 4.2 | Guardrail reason leaks to LLM | Critical | Live leak in shipped code |
| 4.3 | Denylist gaps + tool-agnostic false positive | High | Partial coverage, one false positive |
| 4.4 | `PhaseToolGuardStage` | High | Did not exist (original scope of this doc) |
| 4.5 | `hydra` → `sandboxed_tool` | Medium | Supports 4.4 |
| 4.6 | Cloud metadata hard-deny | Medium | Did not exist |
