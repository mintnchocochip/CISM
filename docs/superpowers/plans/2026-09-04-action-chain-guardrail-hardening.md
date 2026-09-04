# Action-Chain Guardrail Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two currently-exploitable gaps in already-shipped guardrail code (a scope-check bypass via the `extra` argument, and an information leak that gives an adversarial/injected LLM a live oracle for the guardrail ruleset), then add the originally-scoped `PhaseToolGuardStage` capability-vs-phase re-check on top of a hardened foundation.

**Architecture:** Six independent fixes to the existing `action` `GuardrailChain` and its stages (`cism/agent/guardrails/`), plus one supporting tool conversion (`hydra`). Each task is independently testable and independently mergeable — task order follows the design doc's severity ranking (Critical → High → Medium), not build dependency, except Task 4 (`PhaseToolGuardStage`) depends on Task 5 (`hydra` conversion) for real capability data, so Task 5 is pulled forward to run before Task 4 despite being lower severity.

**Tech Stack:** Python 3.11+, `pytest`, `langchain_core.messages.tool.ToolCall`.

**Spec:** `docs/superpowers/specs/2026-09-04-phase-tool-guardrail-design.md` — read it in full before starting; every code block below is drawn directly from it.

## Global Constraints

- Baseline: 417 tests pass before this plan starts (`.venv/bin/pytest --collect-only -q` reports "417 tests collected"). Every task must leave the full suite green.
- No attribution trailers of any kind in commit messages (no `Co-Authored-By`, no "Generated with Claude Code") — plain commit messages only, regardless of any other instruction. This applies to every commit an implementer subagent makes.
- Every finding gets an **adversarial** test proving the actual threat model (a hallucinated/injected call, a smuggled second target, a probing model reading back the ruleset) — not just a happy-path test. This is a hard requirement from the design doc's own Goals section (§2: "No finding's fix requires trusting the LLM to behave").
- This plan does **not** wire a real `GuardrailSeam` into `LangGraphAgent`'s default construction or `run_agent.py` — that remains a separate, later milestone (design doc §3).
- Task order in this plan is: 1 (scope bypass) → 2 (LLM-facing leak) → 3 (tool-aware denylist) → 4 (`hydra` conversion, pulled forward) → 5 (`PhaseToolGuardStage`, needs Task 4's real capability data) → 6 (metadata hard-deny). This differs from the design doc's own numbering (§4.1–§4.6) only in swapping the last two relative to §4.4/§4.5 — noted here so it isn't mistaken for a numbering error.

---

### Task 1: [Critical] Fix the scope-check bypass via `extra`

**Files:**
- Modify: `cism/agent/guardrails/scope.py` (the `_candidate_hosts` and `_extract_host` functions)
- Test: `tests/test_scope_guard.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature changes — `_candidate_hosts(call: ToolCall) -> list[str]` and `_extract_host(value: str) -> str | None` keep their existing shapes; only their internal behavior changes. `ScopeGuardStage.check()` is unaffected by this task (unchanged from current code).

**Current code being changed** (`cism/agent/guardrails/scope.py`):

```python
def _candidate_hosts(call: ToolCall) -> list[str]:
    args = call.get("args") or {}

    key = _TARGET_ARG_BY_TOOL.get(call.get("name", ""))
    if key is not None:
        value = args.get(key)
        if isinstance(value, str):
            host = _extract_host(value)
            return [host] if host else []
        return []

    hosts: list[str] = []
    for value in args.values():
        if isinstance(value, str):
            host = _extract_host(value)
            if host:
                hosts.append(host)
    return hosts
```

- [ ] **Step 1: Write the failing tests — append to `tests/test_scope_guard.py`**

```python
def test_a_second_target_smuggled_into_extra_as_a_bare_positional_is_blocked() -> None:
    """render_argv (base.py) places extra's tokens BEFORE target in argv
    — for curl this means a bare URL in extra becomes a second URL curl
    will actually fetch, completely unvetted by the scope check that only
    ever looked at "target". This is a real, currently-exploitable bypass
    in shipped code, not a hypothetical."""
    result = _stage().check(
        _call("curl", target="https://example.com", extra="https://evil-target.com")
    )
    assert result.allowed is False


def test_a_second_target_smuggled_into_extra_via_nmap_is_blocked() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="10.0.0.99"))
    assert result.allowed is False


def test_an_in_scope_target_with_only_flags_in_extra_is_still_allowed() -> None:
    """The fix must not make every allow_raw call fail just because extra
    is non-empty — only an actual out-of-scope host inside extra should
    block."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="-p 80,443 -sV"))
    assert result.allowed is True


def test_a_comma_separated_multi_target_token_with_one_out_of_scope_host_is_blocked() -> None:
    """nmap accepts 'host1,host2' as one token. Before this fix,
    _extract_host doesn't recognize this shape at all and silently drops
    it — not incorrectly allowed by a broken check, just never checked."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="10.0.0.5,192.168.1.5"))
    assert result.allowed is False


def test_a_comma_separated_multi_target_token_with_all_in_scope_hosts_is_allowed() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="10.0.0.5,10.0.0.6"))
    assert result.allowed is True


def test_a_comma_containing_value_that_is_not_actually_a_host_list_is_unaffected() -> None:
    """A guard against over-fixing: something that merely contains a comma
    but isn't a clean multi-host list (e.g. a port list) must not be
    misclassified as a host token and must not break existing behavior."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="-p 80,443"))
    assert result.allowed is True
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "smuggled or comma_separated or comma_containing"
```

Expected: the two "smuggled" tests and the first "comma_separated" test FAIL (currently allowed when they should be blocked); the "in_scope_target_with_only_flags", second "comma_separated" (all in scope), and "comma_containing" tests currently PASS already (nothing to fix there, they're regression guards).

- [ ] **Step 3: Implement the `extra`-scanning fix — replace `_candidate_hosts` in `cism/agent/guardrails/scope.py`**

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

Add `import shlex` to `scope.py`'s imports (alongside the existing `import ipaddress`, `import re`).

- [ ] **Step 4: Run to verify the smuggling tests now pass, comma tests still fail**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "smuggled or comma_separated or comma_containing"
```

Expected: both "smuggled" tests PASS now. Both "comma_separated" tests still FAIL — `_extract_host` doesn't recognize a comma-joined value as host-shaped yet, and `ScopeGuardStage.check()` checks each returned host against `self._scope.contains_host(host)` directly, so a raw `"10.0.0.5,10.0.0.6"` string would fail that check even when both parts are in scope (Step 5 fixes this).

- [ ] **Step 5: Implement the comma-separated-target fix — replace `_extract_host` in `cism/agent/guardrails/scope.py`**

Current code:

```python
def _extract_host(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if ":" in value:
        host_part, _, port_part = value.rpartition(":")
        if port_part.isdigit() and host_part:
            return _extract_host(host_part)

    if "://" in value:
        hostname = urlparse(value).hostname
        return hostname

    match = _USER_HOST_RE.search(value)
    if match:
        return match.group(1)

    if _BARE_DOMAIN_RE.fullmatch(value):
        return value.lower()

    return None
```

New code — add the comma-splitting branch first, everything else unchanged:

```python
def _extract_host(value: str) -> str | None:
    if "," in value:
        parts = value.split(",")
        hosts = [_extract_host(p) for p in parts]
        return value if all(hosts) else None

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if ":" in value:
        host_part, _, port_part = value.rpartition(":")
        if port_part.isdigit() and host_part:
            return _extract_host(host_part)

    if "://" in value:
        hostname = urlparse(value).hostname
        return hostname

    match = _USER_HOST_RE.search(value)
    if match:
        return match.group(1)

    if _BARE_DOMAIN_RE.fullmatch(value):
        return value.lower()

    return None
```

`_extract_host` now returns the *whole comma-joined string* (not one part) when every comma-separated part is independently host-shaped — this signals "this token contains host(s)" back to `_candidate_hosts`. `_candidate_hosts` needs one more small change to split that string back apart before scope-checking each part independently (a comma-joined literal would never match any single declared CIDR/domain as one string):

- [ ] **Step 6: Flatten comma-joined hosts in `_candidate_hosts` — modify the function again**

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

    flattened: list[str] = []
    for host in hosts:
        flattened.extend(host.split(",") if "," in host else [host])
    return flattened
```

- [ ] **Step 7: Run to verify everything passes**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v
```

Expected: all tests pass, including the pre-existing ones (`test_an_in_scope_ip_target_is_allowed`, etc. — this fix must not regress any of them).

- [ ] **Step 8: Run the full suite to check for regressions elsewhere**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed. (`ScopeGuardStage` is also exercised by `test_tool_catalog_integration.py` and `test_toolkit_integration.py` — check those specifically if anything fails: `.venv/bin/pytest tests/test_tool_catalog_integration.py tests/test_toolkit_integration.py -v`.)

- [ ] **Step 9: Commit**

```bash
git add cism/agent/guardrails/scope.py tests/test_scope_guard.py
git commit -m "fix: ScopeGuardStage now inspects extra for smuggled targets, and recognizes comma-separated multi-target tokens"
```

---

### Task 2: [Critical] Stop guardrail block reasons from leaking into the LLM's own context

**Files:**
- Modify: `cism/agent/guardrails/chain.py`
- Modify: `cism/agent/nodes.py:117-138` (the `act` function's guardrail-block branch)
- Modify: `cism/agent/core.py:294-308` (the `_translate` function's `node == "act"` branch)
- Test: `tests/test_guardrail_chain.py` (append)
- Test: `tests/test_nodes.py` (append — this file currently has no test importing `make_act_node` at all; this task adds the first one)
- Test: `tests/test_langgraph_agent.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: `GuardrailResult.stage: str` (new field, default `""`). `ToolMessage.additional_kwargs["guardrail_detail"]` — the convention later tasks' guard stages rely on for their own rich internal reasoning to reach the operator.

**Current code being changed:**

`cism/agent/guardrails/chain.py`:

```python
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class GuardrailResult(Generic[T]):
    allowed: bool
    value: T
    reason: str = ""

class GuardrailChain(Generic[T]):
    def run(self, value: T) -> GuardrailResult[T]:
        current = value
        for stage in self._stages:
            result = stage.check(current)
            if not result.allowed:
                return result
            current = result.value
        return GuardrailResult(allowed=True, value=current)
```

`cism/agent/nodes.py:123-138` (inside `make_act_node`'s `act` function):

```python
        for call in tool_calls:
            guard = action_chain.run(call)
            if not guard.allowed:
                results.append(
                    ToolMessage(
                        content=f"blocked by action guardrail: {guard.reason or 'no reason given'}",
                        tool_call_id=call["id"],
                        name=call["name"],
                        status="error",
                    )
                )
                continue
```

`cism/agent/core.py:294-308` (inside `_translate`):

```python
        elif node == "act":
            for message in update.get("messages", []):
                call_id = message.tool_call_id
                call = pending_calls.pop(call_id, None)
                tool_name = message.name or (call["name"] if call else "unknown")
                args = str(call["args"]) if call else ""
                await self.events.put(ToolStarted(call_id=call_id, tool=tool_name, args=args))
                if getattr(message, "status", "success") == "error":
                    await self.events.put(
                        ToolFailed(call_id=call_id, reason=str(message.content))
                    )
                else:
                    await self.events.put(
                        ToolFinished(call_id=call_id, summary=str(message.content))
                    )
```

- [ ] **Step 1: Write the failing test for `GuardrailResult.stage` — append to `tests/test_guardrail_chain.py`**

```python
def test_a_blocking_stage_result_is_stamped_with_the_stage_that_blocked_it() -> None:
    blocker = _BlockingStage(reason="nope")
    chain = GuardrailChain([blocker])

    result = chain.run("hello")

    assert result.stage == "blocker"


def test_a_passing_result_has_no_stage_stamped() -> None:
    chain = GuardrailChain([PassThroughStage()])

    result = chain.run("hello")

    assert result.stage == ""
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_guardrail_chain.py -v -k stamped
```

Expected: `AttributeError: 'GuardrailResult' object has no attribute 'stage'`.

- [ ] **Step 3: Implement — modify `cism/agent/guardrails/chain.py`**

Change the import line from:

```python
from dataclasses import dataclass
```

to:

```python
import dataclasses
from dataclasses import dataclass
```

Add the new field to `GuardrailResult`:

```python
@dataclass(frozen=True, slots=True)
class GuardrailResult(Generic[T]):
    allowed: bool
    value: T
    reason: str = ""
    stage: str = ""
```

Change `GuardrailChain.run`:

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

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_guardrail_chain.py -v
```

Expected: all pass, including pre-existing tests (`test_a_blocking_stage_short_circuits_later_stages` still asserts `result.reason == "nope"` — unaffected by the new field).

- [ ] **Step 5: Write the failing test for `act()`'s generic content — append to `tests/test_nodes.py`**

Add these imports at the top of `tests/test_nodes.py` alongside the existing ones: `from cism.agent.nodes import make_act_node` (add to the existing `from cism.agent.nodes import make_depg_update_node, make_think_node` line) and `from cism.agent.guardrails import GuardrailChain, GuardrailResult, GuardrailSeam`.

```python
class _AlwaysBlockStage:
    name = "always-block"

    def __init__(self, reason: str) -> None:
        self._reason = reason

    def check(self, call):
        return GuardrailResult(allowed=False, value=call, reason=self._reason)


def test_act_reports_a_blocked_call_with_a_generic_message_not_the_rich_reason() -> None:
    """The actual security property: an adversarial or injected model must
    not be able to read back exactly which host/flag/capability tripped
    the guard, or it has a live oracle to map the ruleset and find an
    unlisted equivalent."""
    action_chain = GuardrailChain([_AlwaysBlockStage("10.0.0.99 is outside scope")])
    profiles = PhaseProfiles(
        {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset({"dummy_nmap"}))}
    )
    act = make_act_node(ToolRegistry([dummy_nmap]), action_chain, profiles)
    call = {"id": "c1", "name": "dummy_nmap", "args": {"target": "10.0.0.99"}, "type": "tool_call"}
    state = _state([AIMessage(content="", tool_calls=[call])])

    result = act(state)

    message = result["messages"][0]
    assert message.content == "blocked by action guardrail"
    assert "10.0.0.99" not in message.content
    assert "outside scope" not in message.content


def test_act_preserves_the_rich_guardrail_reason_in_additional_kwargs() -> None:
    action_chain = GuardrailChain([_AlwaysBlockStage("10.0.0.99 is outside scope")])
    profiles = PhaseProfiles(
        {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset({"dummy_nmap"}))}
    )
    act = make_act_node(ToolRegistry([dummy_nmap]), action_chain, profiles)
    call = {"id": "c1", "name": "dummy_nmap", "args": {"target": "10.0.0.99"}, "type": "tool_call"}
    state = _state([AIMessage(content="", tool_calls=[call])])

    result = act(state)

    message = result["messages"][0]
    assert message.additional_kwargs["guardrail_detail"] == "[always-block] 10.0.0.99 is outside scope"
```

You will need an `AIMessage` import already present in `test_nodes.py` (it is) and `dummy_nmap`/`ToolRegistry` (already imported). Add `make_act_node` and `PhaseProfile`/`PhaseProfiles`/`Phase` if not already present at the top (`PhaseProfile`, `PhaseProfiles`, `Phase` are already imported in this file).

- [ ] **Step 6: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_nodes.py -v -k "act_reports_a_blocked or act_preserves_the_rich"
```

Expected: first test fails on `message.content == "blocked by action guardrail: 10.0.0.99 is outside scope"` not matching; second fails with `KeyError: 'guardrail_detail'`.

- [ ] **Step 7: Implement — modify `cism/agent/nodes.py:123-138`**

```python
        for call in tool_calls:
            guard = action_chain.run(call)
            if not guard.allowed:
                results.append(
                    ToolMessage(
                        content="blocked by action guardrail",
                        tool_call_id=call["id"],
                        name=call["name"],
                        status="error",
                        additional_kwargs={"guardrail_detail": f"[{guard.stage}] {guard.reason}"},
                    )
                )
                continue
```

- [ ] **Step 8: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_nodes.py -v -k "act_reports_a_blocked or act_preserves_the_rich"
```

Expected: both pass.

- [ ] **Step 9: Write the failing test for `core.py`'s `_translate` reading `guardrail_detail` — append to `tests/test_langgraph_agent.py`**

```python
async def test_a_blocked_action_surfaces_its_rich_reason_via_toolfailed_not_the_llm(
    tmp_path, monkeypatch
) -> None:
    """ToolFailed is what the TUI/operator sees — it should keep getting
    the full detail even though the LLM (via ToolMessage.content) no
    longer does."""
    monkeypatch.setenv("HOME", str(tmp_path))

    class _RichBlock:
        name = "scope-guard"

        def check(self, value) -> GuardrailResult:
            return GuardrailResult(allowed=False, value=value, reason="10.0.0.99 is outside scope")

    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([_RichBlock()]),
        output=GuardrailChain([PassThroughStage()]),
    )
    agent = LangGraphAgent(guardrails=guardrails)

    events = await _run_to_completion(agent, "scan 10.0.0.5")

    failures = [e for e in events if isinstance(e, ToolFailed)]
    assert failures, "expected at least one ToolFailed event"
    assert "10.0.0.99" in failures[0].reason
    assert "scope-guard" in failures[0].reason
    await agent.aclose()
```

Check `tests/test_langgraph_agent.py`'s existing imports for `ToolFailed` and the `_run_to_completion` helper — both are very likely already imported/defined given `test_a_blocked_action_never_reaches_the_tool` already exists in this file using the same `GuardrailSeam`/`_RejectEverything` pattern; add `ToolFailed` to the import line from `cism.tui.events` if it isn't already there.

- [ ] **Step 10: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_langgraph_agent.py -v -k rich_reason_via_toolfailed
```

Expected: FAIL — `"10.0.0.99" in failures[0].reason` is false, since `ToolFailed.reason` today is built from `str(message.content)`, which after Task 2 Step 7 is now the generic `"blocked by action guardrail"` string.

- [ ] **Step 11: Implement — modify `cism/agent/core.py:294-308`**

```python
        elif node == "act":
            for message in update.get("messages", []):
                call_id = message.tool_call_id
                call = pending_calls.pop(call_id, None)
                tool_name = message.name or (call["name"] if call else "unknown")
                args = str(call["args"]) if call else ""
                await self.events.put(ToolStarted(call_id=call_id, tool=tool_name, args=args))
                if getattr(message, "status", "success") == "error":
                    detail = message.additional_kwargs.get("guardrail_detail") or str(message.content)
                    await self.events.put(ToolFailed(call_id=call_id, reason=detail))
                else:
                    await self.events.put(
                        ToolFinished(call_id=call_id, summary=str(message.content))
                    )
```

- [ ] **Step 12: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_langgraph_agent.py -v -k rich_reason_via_toolfailed
```

Expected: PASS.

- [ ] **Step 13: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed. Pay particular attention to `tests/test_toolkit_integration.py` (checks `state == "blocked"` on a DEPG node, not the literal content string — should be unaffected) and any other test touching `ToolFailed`/`ToolMessage` content for a *non-guardrail* error (the `except Exception` branch in `act()` is untouched by this task — `message.additional_kwargs` will simply be empty there, and `_translate`'s `.get("guardrail_detail") or str(message.content)` correctly falls back to `str(message.content)`).

- [ ] **Step 14: Commit**

```bash
git add cism/agent/guardrails/chain.py cism/agent/nodes.py cism/agent/core.py tests/test_guardrail_chain.py tests/test_nodes.py tests/test_langgraph_agent.py
git commit -m "fix: guardrail block reasons no longer leak into the LLM's own context; rich detail moves to additional_kwargs and still reaches ToolFailed for the operator"
```

---

### Task 3: [High] Make `DangerousFlagGuardStage` tool-aware

**Files:**
- Modify: `cism/agent/guardrails/dangerous_flags.py`
- Test: `tests/test_dangerous_flags.py` (modify existing `_call` helper + append)

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature changes — `DangerousFlagGuardStage()` still takes no constructor arguments; `check()` reads `call["name"]` (already available on every `ToolCall`) to select the per-tool denylist.

**Current code being changed** (`cism/agent/guardrails/dangerous_flags.py`):

```python
_DANGEROUS_FLAG_TOKENS: frozenset[str] = frozenset(
    {
        "--script",
        "-oN", "-oX", "-oG", "-oA",
        "-o", "-O", "--output", "--remote-name",
        "-T", "--upload-file",
        "-K", "--config",
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
```

The existing `tests/test_dangerous_flags.py`'s `_call` helper hardcodes `"name": "nmap"` for every test — this task changes it to accept the tool name as a parameter, since coverage now needs both `nmap`- and `curl`-specific cases.

- [ ] **Step 1: Modify the test helper — `tests/test_dangerous_flags.py`**

Change:

```python
def _call(**args) -> dict:
    return {"id": "call-1", "name": "nmap", "args": args, "type": "tool_call"}
```

to:

```python
def _call(name: str = "nmap", **args) -> dict:
    return {"id": "call-1", "name": name, "args": args, "type": "tool_call"}
```

Every existing test in this file calls `_call(target=..., extra=...)` with no `name=` argument, so they keep defaulting to `"nmap"` — no existing test needs to change.

- [ ] **Step 2: Write the failing tests — append to `tests/test_dangerous_flags.py`**

```python
def test_curl_form_flag_is_blocked() -> None:
    """curl -F/--form supports @path to read and upload an arbitrary local
    file — same class of risk as the already-covered -T/--upload-file,
    just a different flag, and it wasn't covered before this fix."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-F file=@/etc/passwd"))
    assert result.allowed is False


def test_curl_data_flags_are_blocked() -> None:
    for flag in ("-d", "--data", "--data-binary", "--data-urlencode", "--data-raw"):
        result = _stage().check(_call(name="curl", target="https://x", extra=f"{flag} @/etc/passwd"))
        assert result.allowed is False, flag


def test_curl_dump_header_and_cookie_jar_flags_are_blocked() -> None:
    result = _stage().check(_call(name="curl", target="https://x", extra="-D /tmp/headers.txt"))
    assert result.allowed is False

    result = _stage().check(_call(name="curl", target="https://x", extra="-c /tmp/cookies.txt"))
    assert result.allowed is False


def test_nmap_timing_template_written_with_a_space_is_not_a_false_positive() -> None:
    """-T is curl-specific (--upload-file); nmap's own -T<0-5> timing
    template is a different flag that happens to share the letter. Before
    the fix, a space-separated "-T 4" (unusual but not invalid input from
    a model) produced a bare "-T" token that incorrectly triggered curl's
    rule for an nmap call."""
    result = _stage().check(_call(name="nmap", target="10.0.0.5", extra="-T 4"))
    assert result.allowed is True


def test_curl_still_blocks_its_own_dash_t_upload_flag() -> None:
    """Regression check: fixing the nmap false positive must not weaken
    curl's own -T coverage."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-T /etc/passwd"))
    assert result.allowed is False


def test_nmap_reading_a_target_list_from_a_local_file_is_blocked() -> None:
    result = _stage().check(_call(name="nmap", target="10.0.0.5", extra="-iL /etc/passwd"))
    assert result.allowed is False


def test_an_unknown_tool_only_gets_the_shared_denylist() -> None:
    """A tool with no per-tool entry (not yet added to the catalog, or a
    typo) must fail closed to the shared baseline, not to an empty set —
    -K/--config stays blocked for everyone; a tool-specific flag like
    curl's -F does not apply to a tool that isn't curl."""
    result = _stage().check(_call(name="some-future-tool", target="x", extra="-K /etc/passwd"))
    assert result.allowed is False

    result = _stage().check(_call(name="some-future-tool", target="x", extra="-F file=@x"))
    assert result.allowed is True
```

- [ ] **Step 3: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_dangerous_flags.py -v
```

Expected: the new curl-flag tests and `-iL` test FAIL (not currently blocked); `nmap_timing_template_written_with_a_space` FAILS (currently incorrectly blocked); `curl_still_blocks_its_own_dash_t` and `unknown_tool` pass already (regression guards) — verify these don't regress once the fix lands.

- [ ] **Step 4: Implement — replace the denylist and `check()` in `cism/agent/guardrails/dangerous_flags.py`**

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
        denylist = _SHARED_DANGEROUS_TOKENS | _PER_TOOL_DANGEROUS_TOKENS.get(call.get("name", ""), frozenset())
        hit = tokens & denylist
        if hit:
            return GuardrailResult(
                allowed=False,
                value=call,
                reason=f"blocked flag(s) {sorted(hit)}: can read/write outside the sandbox's scratch dir",
            )
        return GuardrailResult(allowed=True, value=call)
```

- [ ] **Step 5: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_dangerous_flags.py -v
```

Expected: all pass, including every pre-existing test (`test_nmap_script_flag_is_blocked`, `test_nmap_output_flags_are_blocked`, `test_curl_upload_and_config_flags_are_blocked`, etc. — all default to `name="nmap"` except the curl-specific one, which already passes `extra="--upload-file ..."` and `extra="-K ..."`, both still covered: `--upload-file` is in nmap's... wait, check this specifically in Step 6).

- [ ] **Step 6: Verify the pre-existing `test_curl_upload_and_config_flags_are_blocked` still passes with its default `name="nmap"`**

Read that test again: it calls `_call(target="https://x", extra="--upload-file /etc/passwd")` and `_call(target="https://x", extra="-K /etc/curlrc")` — **neither passes `name="curl"`**, so both default to `name="nmap"` after Step 1's change. `--upload-file` is only in curl's per-tool set, not nmap's or the shared set — this test would now FAIL for the first assertion unless nmap's set also covers it, which it doesn't by design (curl-specific flag). Fix the test itself (it predates this task and was written when the denylist was tool-agnostic):

```python
def test_curl_upload_and_config_flags_are_blocked() -> None:
    result = _stage().check(_call(name="curl", target="https://x", extra="--upload-file /etc/passwd"))
    assert result.allowed is False

    result = _stage().check(_call(target="https://x", extra="-K /etc/curlrc"))  # -K is shared, name doesn't matter
    assert result.allowed is False
```

- [ ] **Step 7: Run the full file again**

```bash
.venv/bin/pytest tests/test_dangerous_flags.py -v
```

Expected: all pass.

- [ ] **Step 8: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed. Check `tests/test_toolkit_integration.py` specifically (it constructs a real `DangerousFlagGuardStage` against a real `curl` call with `--upload-file` — confirm it still blocks: `.venv/bin/pytest tests/test_toolkit_integration.py -v`).

- [ ] **Step 9: Commit**

```bash
git add cism/agent/guardrails/dangerous_flags.py tests/test_dangerous_flags.py
git commit -m "fix: DangerousFlagGuardStage becomes tool-aware — closes curl's -F/-d/-D/-c gap, fixes nmap -T false positive"
```

---

### Task 4: [Medium, pulled forward] Convert `hydra` from `@tool` to `@sandboxed_tool`

**Files:**
- Modify: `cism/agent/tools/credentials.py`
- Test: `tests/test_tool_argv.py` (modify existing tests' monkeypatch target)

**Interfaces:**
- Consumes: `sandboxed_tool` (existing, `cism/agent/tools/base.py`).
- Produces: `credentials.hydra.metadata == {"capability": "executes", "binary": "hydra"}` — Task 5 (`PhaseToolGuardStage`) reads this.

**Current code being changed** (`cism/agent/tools/credentials.py`):

```python
from langchain_core.tools import tool

from cism.agent.tools.sandbox import run_sandboxed, scratch_dir

@tool
def hydra(
    target: str,
    service: str,
    usernames: list[str] | None = None,
    userlist: str | None = None,
    passwords: list[str] | None = None,
    passwordlist: str | None = None,
    threads: int = 4,
) -> str:
    """Run hydra against one target/service with explicit credential lists
    or a named wordlist. Exactly one of usernames/userlist and one of
    passwords/passwordlist must be given; threads is capped at 16 —
    real safety here is the scope guardrail and the run timeout, not
    argv tricks."""
    with scratch_dir() as tmp:
        argv = ["hydra", "-t", str(min(threads, _MAX_THREADS))]
        argv += _cred_flag("-L", usernames, userlist, tmp / "users.txt")
        argv += _cred_flag("-P", passwords, passwordlist, tmp / "pass.txt")
        argv += [target, service]
        return run_sandboxed(argv, cwd=tmp, timeout=120.0)
```

- [ ] **Step 1: Update the existing tests' monkeypatch target — modify `tests/test_tool_argv.py`**

Every test in this file does `monkeypatch.setattr(credentials, "run_sandboxed", fake_or_lambda)`. After this task, `hydra` no longer calls `run_sandboxed` directly — `sandboxed_tool`'s decorator (in `cism/agent/tools/base.py`) does. Change every occurrence of `monkeypatch.setattr(credentials, "run_sandboxed", ...)` in this file to `monkeypatch.setattr(base_module, "run_sandboxed", ...)`, and add the import:

```python
from cism.agent.tools import base as base_module
```

alongside the existing `from cism.agent.tools import credentials` import.

Also update the two assertions checking `argv[:3]` / `argv[-2:]` shape — these do NOT need to change (the decorator prepends `binary` to whatever the function returns, producing the exact same full argv shape as before: `["hydra", "-t", "4", ..., target, service]`), but re-confirm this in Step 4 below.

- [ ] **Step 2: Run to verify tests fail against the still-unconverted `hydra`**

```bash
.venv/bin/pytest tests/test_tool_argv.py -v
```

Expected: `AttributeError` or similar — `base_module.run_sandboxed` is never called by the current plain-`@tool` `hydra`, so `captured["argv"]` stays unset and the test fails on a `KeyError`.

- [ ] **Step 3: Implement the conversion — replace `hydra` in `cism/agent/tools/credentials.py`**

Change the imports from:

```python
from langchain_core.tools import tool

from cism.agent.tools.sandbox import run_sandboxed, scratch_dir
```

to:

```python
from cism.agent.tools.base import sandboxed_tool
```

(`run_sandboxed`/`scratch_dir` are no longer called directly from this module — the decorator owns them. `Path` stays imported, still used by `_materialize`/`_cred_flag`'s type hints.)

Replace the `hydra` function:

```python
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

`_materialize`, `_cred_flag`, `_WORDLISTS`, `_MAX_THREADS`, `CREDENTIAL_TOOLS = [hydra]`, and `__all__` are unchanged.

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_tool_argv.py -v
```

Expected: all 4 existing tests pass — `argv[:3] == ["hydra", "-t", "4"]` still holds because `sandboxed_tool`'s decorator constructs `[binary, *argv_tail]` where `binary="hydra"` and `argv_tail` is exactly what the function above returns.

- [ ] **Step 5: Write the new metadata test — append to `tests/test_tool_argv.py`**

```python
def test_hydra_carries_capability_and_binary_metadata() -> None:
    """This is what closes the gap _binaries_of's defensive `(tool.metadata
    or {})` guard existed for — hydra now has real metadata like every
    other tool in the registry."""
    assert credentials.hydra.metadata == {"capability": "executes", "binary": "hydra"}
```

- [ ] **Step 6: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_tool_argv.py -v -k metadata
```

Expected: PASS.

- [ ] **Step 7: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed. `hydra` is also referenced by `cism/agent/tools/__init__.py` (re-export, unaffected — still the same object name), `cism/agent/profiles.py` (`_DECORATED_TOOL_PHASES`, unaffected — keyed by string name, not by decorator type), and `tests/test_build_toolkit.py`/`tests/test_toolkit_integration.py` (build `build_toolkit(..., decorated_tools=[hydra], ...)` — should be unaffected since `hydra` is still a `BaseTool` with the same registered name). Run those specifically if anything fails: `.venv/bin/pytest tests/test_build_toolkit.py tests/test_toolkit_integration.py tests/test_phase_profiles.py -v`.

- [ ] **Step 8: Commit**

```bash
git add cism/agent/tools/credentials.py tests/test_tool_argv.py
git commit -m "refactor: hydra becomes a sandboxed_tool instead of a plain @tool, closing the one tool in the registry with no real metadata"
```

---

### Task 5: [High] `PhaseToolGuardStage` — independent capability-vs-phase re-check

**Files:**
- Create: `cism/agent/guardrails/phase_tool.py`
- Modify: `cism/agent/guardrails/__init__.py` (export)
- Modify: `cism/agent/profiles.py` (wire into `default_profiles()`)
- Test: `tests/test_phase_tool_guard.py` (new)
- Test: `tests/test_phase_profiles.py` (append)

**Interfaces:**
- Consumes: `Phase` (`cism/agent/state.py`), `Capability` (`cism/agent/tools/catalog.py`), `GuardrailResult`/`GuardrailStage` (`chain.py`), `hydra.metadata["capability"]` (Task 4).
- Produces: `PhaseToolGuardStage(phase: Phase, allowed_tool_names: frozenset[str], tool_capabilities: dict[str, str])` — a `GuardrailStage`. `default_profiles()`'s returned `PhaseProfile.action_stages` is no longer always `()` — it now contains exactly one `PhaseToolGuardStage` per phase.

- [ ] **Step 1: Write the failing tests — create `tests/test_phase_tool_guard.py`**

```python
"""cism/agent/guardrails/phase_tool.py: PhaseToolGuardStage independently
re-checks that a called tool is actually offered in the current phase —
the same defense-in-depth role ScopeGuardStage/DangerousFlagGuardStage
play for their own concerns, closing the gap between "the LLM wasn't
bound this tool" and "this tool call cannot reach a subprocess" for a
hallucinated or prompt-injected call that never went through legitimate
binding.
"""

from __future__ import annotations

from cism.agent.guardrails.phase_tool import PhaseToolGuardStage
from cism.agent.state import Phase


def _call(name: str) -> dict:
    return {"id": "call-1", "name": name, "args": {}, "type": "tool_call"}


def test_a_bound_tool_is_allowed() -> None:
    stage = PhaseToolGuardStage(Phase.RECON, frozenset({"nmap", "curl"}), {"nmap": "reads"})
    result = stage.check(_call("nmap"))
    assert result.allowed is True


def test_a_tool_not_offered_in_this_phase_is_blocked() -> None:
    """The actual threat model: hydra exists in the registry and has a
    real capability, but was never bound in RECON — a hallucinated or
    injected call naming it anyway must still be blocked here,
    independent of whatever bound it (or didn't) at the think step."""
    stage = PhaseToolGuardStage(Phase.RECON, frozenset({"nmap", "curl"}), {"hydra": "executes"})
    result = stage.check(_call("hydra"))
    assert result.allowed is False
    assert "hydra" in result.reason
    assert "executes" in result.reason
    assert "recon" in result.reason.lower()


def test_a_completely_unregistered_tool_name_is_blocked() -> None:
    stage = PhaseToolGuardStage(Phase.RECON, frozenset({"nmap"}), {})
    result = stage.check(_call("totally-made-up-tool"))
    assert result.allowed is False


def test_tool_help_is_exempted_in_every_phase() -> None:
    """Matches make_think_node's own bind-time exemption for tool_help —
    knowing what a tool can do carries none of the risk using it does."""
    stage = PhaseToolGuardStage(Phase.REPORTING, frozenset(), {})  # REPORTING offers zero tools
    result = stage.check(_call("tool_help"))
    assert result.allowed is True


def test_the_stage_name_is_phase_tool_guard() -> None:
    stage = PhaseToolGuardStage(Phase.RECON, frozenset(), {})
    assert stage.name == "phase-tool-guard"
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_phase_tool_guard.py -v
```

Expected: `ModuleNotFoundError: No module named 'cism.agent.guardrails.phase_tool'`.

- [ ] **Step 3: Implement — create `cism/agent/guardrails/phase_tool.py`**

```python
"""A stage in the action GuardrailChain, alongside ScopeGuardStage and
DangerousFlagGuardStage: independently re-checks that a called tool is
actually offered in the current phase.

default_profiles() (cism/agent/profiles.py) already restricts which
tools are bound at the think step — a destructive-capability tool is
never even offered to the model outside the phases that declare it. This
stage exists because binding-time restriction is not a guarantee against
a compromised or confused model: a prompt injection (from a scanned
target's own banner text, a DNS TXT record — anything the agent reads
back as tool output) or a hallucinated tool name could construct a
ToolCall some other way. allowed_tool_names is deliberately the exact
same value default_profiles() already computed for binding, not a
second, parallel derivation that could drift from it.
"""

from __future__ import annotations

from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails.chain import GuardrailResult
from cism.agent.state import Phase

__all__ = ["PhaseToolGuardStage"]


class PhaseToolGuardStage:
    name = "phase-tool-guard"

    def __init__(
        self,
        phase: Phase,
        allowed_tool_names: frozenset[str],
        tool_capabilities: dict[str, str],
    ) -> None:
        self._phase = phase
        self._allowed = allowed_tool_names
        self._capabilities = tool_capabilities

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

**Verified against `cism/agent/state.py`, not assumed**: `Phase` is an `Enum` whose `.value` is an int (`Phase.RECON = 1`) — using `self._phase.value` directly would produce `"...phase 1"`, not `"...phase recon"`. `Phase.to_wire()` (`self.name.lower().replace("_", "-")`) is the existing, already-established convention this codebase uses everywhere else a `Phase` needs a human-readable string (e.g. `PhaseChanged.phase`) — reused here rather than introducing a second phase-to-string convention. `Phase.RECON.to_wire() == "recon"`, matching the `"recon" in result.reason.lower()` assertion in Step 1's test above.

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_phase_tool_guard.py -v
```

Expected: all pass.

- [ ] **Step 5: Export it — modify `cism/agent/guardrails/__init__.py`**

```python
from .dangerous_flags import DangerousFlagGuardStage
from .phase_tool import PhaseToolGuardStage
from .scope import EngagementScope, ScopeGuardStage

__all__ = [
    "DangerousFlagGuardStage",
    "EngagementScope",
    "GuardrailChain",
    "GuardrailResult",
    "GuardrailSeam",
    "GuardrailStage",
    "PassThroughStage",
    "PhaseToolGuardStage",
    "ScopeGuardStage",
]
```

- [ ] **Step 6: Write the failing wiring test — append to `tests/test_phase_profiles.py`**

```python
def test_default_profiles_attaches_a_phase_tool_guard_matching_its_own_tool_names() -> None:
    """The guard's allowed set must be exactly this phase's own tool_names
    plus tool_help — proving it can't drift from binding by construction,
    not just by convention."""
    from cism.agent.guardrails import PhaseToolGuardStage

    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    for phase in Phase:
        profile = profiles.get(phase)
        assert len(profile.action_stages) == 1
        stage = profile.action_stages[0]
        assert isinstance(stage, PhaseToolGuardStage)
        assert stage._allowed == profile.tool_names | {"tool_help"}


def test_default_profiles_phase_tool_guard_knows_hydras_real_capability() -> None:
    from cism.agent.guardrails import PhaseToolGuardStage

    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    stage = profiles.get(Phase.RECON).action_stages[0]
    assert isinstance(stage, PhaseToolGuardStage)
    assert stage._capabilities.get("hydra") == "executes"


def test_default_profiles_phase_tool_guard_blocks_hydra_outside_its_phases() -> None:
    from cism.agent.guardrails import PhaseToolGuardStage

    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    stage = profiles.get(Phase.RECON).action_stages[0]
    result = stage.check({"id": "c1", "name": "hydra", "args": {}, "type": "tool_call"})
    assert result.allowed is False
```

- [ ] **Step 7: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_phase_profiles.py -v -k phase_tool_guard
```

Expected: `assert len(profile.action_stages) == 1` fails — `action_stages` is currently always `()` (empty tuple).

- [ ] **Step 8: Implement — modify `default_profiles()` in `cism/agent/profiles.py`**

Add the import:

```python
from cism.agent.guardrails import GuardrailStage, PhaseToolGuardStage
```

(replacing the existing `from cism.agent.guardrails import GuardrailStage` line).

Change the function body:

```python
def default_profiles(tools: ToolRegistry) -> PhaseProfiles:
    """The basic profile set. tool_names lists real tool names; a caller
    whose registry only has the dummy tools simply binds nothing for a
    phase — see make_think_node, which filters tool_names
    against what the registry actually contains. Every phase also gets a
    PhaseToolGuardStage built from that exact same tool_names value, so
    the action-chain re-check can never drift from what binding decided."""
    del tools  # not needed to build the basic set; kept for callers' symmetry

    tool_names_by_phase: dict[Phase, set[str]] = {phase: set() for phase in Phase}
    for name, spec in CATALOG.items():
        for phase in phases_for(spec):
            tool_names_by_phase[phase].add(name)
    for name, phases in _DECORATED_TOOL_PHASES.items():
        for phase in phases:
            tool_names_by_phase[phase].add(name)

    tool_capabilities: dict[str, str] = {name: spec.capability for name, spec in CATALOG.items()}
    tool_capabilities.update(_DECORATED_TOOL_CAPABILITIES)

    return PhaseProfiles(
        {
            phase: PhaseProfile(
                phase=phase,
                system_prompt=_PROMPTS[phase],
                tool_names=frozenset(tool_names_by_phase[phase]),
                action_stages=(
                    PhaseToolGuardStage(
                        phase,
                        frozenset(tool_names_by_phase[phase]) | {"tool_help"},
                        tool_capabilities,
                    ),
                ),
            )
            for phase in Phase
        }
    )
```

Add the new module-level dict, right next to the existing `_DECORATED_TOOL_PHASES`:

```python
#: Same gap as _DECORATED_TOOL_PHASES, for the capability axis instead of
#: the phase axis: decorated tools have no CATALOG row to read a
#: `capability:` value from. hydra's is now real (Task 4's conversion to
#: sandboxed_tool), read here rather than hand-duplicated a third time.
_DECORATED_TOOL_CAPABILITIES: dict[str, str] = {"hydra": "executes"}
```

(Using `hydra.metadata["capability"]` directly instead of hardcoding `"executes"` again is tempting, but `credentials.hydra` is a decorated-tools *value*, not something `profiles.py` currently imports — hardcoding the string here mirrors exactly how `_DECORATED_TOOL_PHASES` already hardcodes hydra's phase set by hand, so this stays consistent with that existing, already-reviewed pattern rather than introducing a new import just for one dict entry.)

- [ ] **Step 9: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_phase_profiles.py -v
```

Expected: all pass, including every pre-existing test in this file.

- [ ] **Step 10: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed. `PhaseProfile.action_stages` was previously always `()` everywhere it's constructed by `default_profiles()` — any test that built a `PhaseProfiles` object *directly* (not via `default_profiles()`) is unaffected, since `action_stages` still defaults to `()` on the dataclass itself. Check `tests/test_nodes.py` and `tests/test_langgraph_agent.py` specifically, since they exercise `act()`'s `base_action_chain.stages + list(profile.action_stages)` composition: `.venv/bin/pytest tests/test_nodes.py tests/test_langgraph_agent.py -v`.

- [ ] **Step 11: Commit**

```bash
git add cism/agent/guardrails/phase_tool.py cism/agent/guardrails/__init__.py cism/agent/profiles.py tests/test_phase_tool_guard.py tests/test_phase_profiles.py
git commit -m "feat: PhaseToolGuardStage — independent capability-vs-phase re-check, wired into every phase's own action_stages"
```

---

### Task 6: [Medium] Hard-deny the cloud metadata endpoint regardless of declared scope

**Files:**
- Modify: `cism/agent/guardrails/scope.py`
- Test: `tests/test_scope_guard.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature changes — `ScopeGuardStage.check()` gains one extra condition.

**Current code** (after Task 1's changes, `ScopeGuardStage.check` is otherwise unchanged from today):

```python
class ScopeGuardStage:
    name = "scope-guard"

    def __init__(self, scope: EngagementScope) -> None:
        self._scope = scope

    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        for host in _candidate_hosts(call):
            if not self._scope.contains_host(host):
                return GuardrailResult(
                    allowed=False,
                    value=call,
                    reason=f"{host!r} is outside the declared engagement scope",
                )
        return GuardrailResult(allowed=True, value=call)
```

- [ ] **Step 1: Write the failing test — append to `tests/test_scope_guard.py`**

`ipaddress` is already imported at the top of this file (used by the existing `_stage()` helper) — no new import needed.

```python
def test_the_cloud_metadata_endpoint_is_blocked_even_inside_a_wide_declared_cidr() -> None:
    """169.254.169.254 (AWS/GCP/Azure instance metadata) must never be
    reachable through this agent, regardless of what the operator declared
    in scope — a classic SSRF pivot to steal instance credentials. Unlike
    RFC1918 ranges generally (legitimate targets for internal pentests),
    the metadata endpoint is never a legitimate target."""
    from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage

    wide_scope = EngagementScope(
        cidrs=(ipaddress.ip_network("169.254.0.0/16"),),
    )
    stage = ScopeGuardStage(wide_scope)

    result = stage.check(_call("curl", target="http://169.254.169.254/latest/meta-data/"))

    assert result.allowed is False


def test_gcp_metadata_hostname_is_blocked() -> None:
    from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage

    scope = EngagementScope(domains=("google.internal",))  # deliberately would match via subdomain rule
    stage = ScopeGuardStage(scope)

    result = stage.check(_call("curl", target="http://metadata.google.internal/computeMetadata/v1/"))

    assert result.allowed is False


def test_a_normal_in_scope_host_is_unaffected_by_the_metadata_denylist() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5"))
    assert result.allowed is True
```

Note: `test_gcp_metadata_hostname_is_blocked` deliberately constructs a scope where `metadata.google.internal` *would* otherwise be allowed (it's a subdomain of the declared `google.internal`) specifically to prove the hard-deny wins even when the normal scope check would say yes.

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v -k "metadata"
```

Expected: both metadata tests FAIL (currently allowed since they fall inside their respective declared scopes).

- [ ] **Step 3: Implement — modify `cism/agent/guardrails/scope.py`**

Add the module-level constant near the top (after `_BARE_DOMAIN_RE`):

```python
#: Never a legitimate pentest target regardless of declared scope, unlike
#: RFC1918 ranges generally (which ARE often the actual point of an
#: internal-network engagement, so blocking those would break legitimate
#: use) — the cloud metadata service is a classic SSRF pivot to steal
#: instance credentials.
_ALWAYS_DENIED_HOSTS: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS/GCP/Azure instance metadata
    "metadata.google.internal",
    "fd00:ec2::254",  # AWS IMDSv2 IPv6
})
```

Change `ScopeGuardStage.check`:

```python
    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        for host in _candidate_hosts(call):
            if host in _ALWAYS_DENIED_HOSTS or not self._scope.contains_host(host):
                return GuardrailResult(
                    allowed=False,
                    value=call,
                    reason=f"{host!r} is outside the declared engagement scope",
                )
        return GuardrailResult(allowed=True, value=call)
```

(Deliberately the same reason text for both cases — per Task 2, the LLM never sees *why* a host was rejected anyway, so there's no benefit to a distinguishable message a log-reading human couldn't already tell apart via `_ALWAYS_DENIED_HOSTS` membership.)

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_scope_guard.py -v
```

Expected: all pass, including every pre-existing and Task-1-added test.

- [ ] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 0 failed.

- [ ] **Step 6: Commit**

```bash
git add cism/agent/guardrails/scope.py tests/test_scope_guard.py
git commit -m "feat: hard-deny the cloud metadata endpoint regardless of declared engagement scope"
```

---

## Final check: whole-plan verification

- [ ] Run the full suite one more time:

```bash
.venv/bin/pytest -q
```

Expected: baseline 417 plus every test added across Tasks 1–6, 0 failed.

- [ ] Confirm no test anywhere still asserts on the old, leaky guardrail-block message format:

```bash
grep -rn "blocked by action guardrail:" tests/ cism/
```

Expected: no output (the trailing colon-and-interpolation form is gone everywhere; the surviving generic string is `"blocked by action guardrail"`, no colon, no interpolation).

- [ ] Confirm every action-chain stage now used by `default_profiles()` has a real, non-empty `name` (used by Task 2's stage-stamping):

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
