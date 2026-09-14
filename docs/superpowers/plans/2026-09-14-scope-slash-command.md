# /scope slash command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `/scope` slash command (bare = list, `add`, `remove`) that lets the live TUI session extend or shrink its declared engagement scope without restarting, with every real change audited as a real event.

**Architecture:** `EngagementScope` (already an immutable frozen dataclass) gains pure `.add`/`.without`/`.entries` methods. `ScopeGuardStage` (already holds a private, mutable `self._scope`) gains `.expand`/`.contract`/`.scope` as the one place scope actually mutates at runtime. `LangGraphAgent.submit()` dispatches `/scope` to a new `_set_scope` handler, following the exact shape `_set_target`/`_set_phase` already use. A new `ScopeChanged` event renders as a transcript note and flows through the existing audit-log choke point automatically.

**Tech Stack:** Python 3.12, pytest (async via `pytest-asyncio`, `mode=Mode.AUTO`), LangGraph, Textual.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-14-scope-slash-command-design.md`.
- No new widget — `ScopeChanged` renders via the existing `transcript.add_note()`.
- `/scope` requires `--live-tools` (a real `ScopeGuardStage` in the action chain); without it, a plain `Narration` explains why, never a silent no-op.
- Every actual scope mutation (`add`/`remove` that changed something) emits a real `ScopeChanged` `AgentEvent` — audited automatically via `LangGraphAgent._emit`. Listing and no-op/error paths use `Narration` instead, matching `_set_phase`'s existing split.
- Domain tokens are compared lowercase (matches `EngagementScope.contains_host`'s existing `.lower()` comparison).
- Run the full suite (`pytest -q -n auto`) after every task — it must stay green throughout.

---

### Task 1: `EngagementScope`/`ScopeGuardStage` mutation methods + shared `parse_scope`

**Files:**
- Modify: `cism/agent/guardrails/scope.py`
- Modify: `cism/agent/guardrails/__init__.py`
- Test: `tests/test_scope_guard.py`

**Interfaces:**
- Produces: `EngagementScope.add(other: EngagementScope) -> EngagementScope`, `EngagementScope.without(token: str) -> tuple[EngagementScope, bool]`, `EngagementScope.entries() -> tuple[str, ...]`, `ScopeGuardStage.expand(addition: EngagementScope) -> None`, `ScopeGuardStage.contract(token: str) -> bool`, `ScopeGuardStage.scope` (read property), `parse_scope(value: str) -> EngagementScope` (module-level function in `cism.agent.guardrails.scope`, re-exported from `cism.agent.guardrails`).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_scope_guard.py` (the file already has `import ipaddress` and `from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage` at the top, and a `_stage()` helper returning a stage scoped to `10.0.0.0/24` + `example.com` — reuse both, don't redefine):

```python
def test_add_unions_cidrs_and_domains_without_duplicates() -> None:
    a = EngagementScope(
        cidrs=(ipaddress.ip_network("10.0.0.0/24"),), domains=("example.com",)
    )
    b = EngagementScope(
        cidrs=(
            ipaddress.ip_network("10.0.0.0/24"),
            ipaddress.ip_network("192.168.1.0/24"),
        ),
        domains=("scanme.nmap.org",),
    )
    combined = a.add(b)
    assert combined.cidrs == (
        ipaddress.ip_network("10.0.0.0/24"),
        ipaddress.ip_network("192.168.1.0/24"),
    )
    assert combined.domains == ("example.com", "scanme.nmap.org")


def test_without_removes_a_declared_cidr() -> None:
    scope = EngagementScope(cidrs=(ipaddress.ip_network("10.0.0.0/24"),))
    remaining, removed = scope.without("10.0.0.0/24")
    assert removed is True
    assert remaining.cidrs == ()


def test_without_removes_a_declared_domain_case_insensitively() -> None:
    scope = EngagementScope(domains=("example.com",))
    remaining, removed = scope.without("Example.com")
    assert removed is True
    assert remaining.domains == ()


def test_without_a_token_not_in_scope_reports_false_and_leaves_scope_unchanged() -> None:
    scope = EngagementScope(domains=("example.com",))
    remaining, removed = scope.without("scanme.nmap.org")
    assert removed is False
    assert remaining is scope


def test_entries_lists_cidrs_then_domains() -> None:
    scope = EngagementScope(
        cidrs=(ipaddress.ip_network("10.0.0.0/24"),), domains=("example.com",)
    )
    assert scope.entries() == ("10.0.0.0/24", "example.com")


def test_scope_guard_expand_widens_what_is_allowed() -> None:
    stage = _stage()
    assert stage.check(_call("nmap", target="scanme.nmap.org")).allowed is False

    stage.expand(EngagementScope(domains=("scanme.nmap.org",)))
    assert stage.check(_call("nmap", target="scanme.nmap.org")).allowed is True


def test_scope_guard_contract_narrows_what_is_allowed() -> None:
    stage = _stage()
    assert stage.contract("example.com") is True
    assert stage.check(_call("curl", target="https://example.com/")).allowed is False


def test_scope_guard_contract_reports_false_for_an_unknown_token() -> None:
    assert _stage().contract("not-in-scope.example") is False


def test_scope_guard_scope_property_reflects_mutations() -> None:
    stage = _stage()
    stage.expand(EngagementScope(domains=("scanme.nmap.org",)))
    assert "scanme.nmap.org" in stage.scope.domains
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_scope_guard.py -v`
Expected: FAILs with `AttributeError: 'EngagementScope' object has no attribute 'add'` (and similar for `.without`, `.entries`, `.expand`, `.contract`, `.scope`).

- [ ] **Step 3: Implement the methods**

In `cism/agent/guardrails/scope.py`, change the import line:

```python
from dataclasses import dataclass
```
to:
```python
from dataclasses import dataclass, replace
```

Add these three methods to `EngagementScope`, directly after `contains_network` (still inside the class, before the blank lines that precede `class ScopeGuardStage:`):

```python
    def add(self, other: EngagementScope) -> EngagementScope:
        """Union of both scopes' CIDRs and domains, de-duplicated,
        order-preserving. Immutable — returns a new EngagementScope rather
        than mutating either operand; ScopeGuardStage.expand is the only
        place a live scope is actually replaced."""
        cidrs = self.cidrs + tuple(c for c in other.cidrs if c not in self.cidrs)
        domains = self.domains + tuple(d for d in other.domains if d not in self.domains)
        return replace(self, cidrs=cidrs, domains=domains)

    def without(self, token: str) -> tuple[EngagementScope, bool]:
        """Removes one exact CIDR or domain — the same per-token parsing
        parse_scope uses for a single value, not a substring/suffix match.
        Returns (new_scope, True) if token was actually present, or
        (self, False) if it wasn't (self returned unchanged, not a copy),
        so a caller can tell "removed" from "wasn't there" without a
        separate contains check."""
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            network = None
        if network is not None and network in self.cidrs:
            return replace(self, cidrs=tuple(c for c in self.cidrs if c != network)), True
        lowered = token.strip().lower()
        if lowered in self.domains:
            return replace(self, domains=tuple(d for d in self.domains if d != lowered)), True
        return self, False

    def entries(self) -> tuple[str, ...]:
        """Every declared CIDR and domain as one flat tuple of strings, for
        listing (``/scope`` with no argument) — CIDRs first, in declared
        order, then domains."""
        return tuple(str(c) for c in self.cidrs) + self.domains
```

Add these to `ScopeGuardStage`, directly after `check` (still inside the class, before the blank lines that precede `def _scan_all_args`):

```python
    def expand(self, addition: EngagementScope) -> None:
        """Adds every CIDR/domain in ``addition`` to the live scope this
        stage checks against — the only way scope changes after startup
        (see cism.agent.core.LangGraphAgent._set_scope, the /scope add
        command's handler)."""
        self._scope = self._scope.add(addition)

    def contract(self, token: str) -> bool:
        """Removes one CIDR/domain from the live scope. Returns whether it
        was actually present — see EngagementScope.without."""
        self._scope, removed = self._scope.without(token)
        return removed

    @property
    def scope(self) -> EngagementScope:
        return self._scope
```

Add this module-level function, directly after `_is_always_denied` and before the `@dataclass(frozen=True, slots=True)` line that starts `EngagementScope` (it needs `EngagementScope` to exist, so actually place it directly *after* the `EngagementScope` class definition ends and before `class ScopeGuardStage:` instead — right after the three new methods above):

```python
def parse_scope(value: str) -> EngagementScope:
    """Comma-separated CIDRs/domains -> EngagementScope. A bare IP widens
    to /32 the same way EngagementScope.contains_network already treats
    one (ipaddress.ip_network(..., strict=False)); anything else that
    isn't parseable as a network is treated as a domain —
    EngagementScope.contains_host does its own lowercase/suffix matching
    on those, so no further validation of domain shape happens here.
    Shared by run_agent.py's --scope flag and the /scope add slash
    command — both need identical CIDR-vs-domain parsing."""
    cidrs: list[IPNetwork] = []
    domains: list[str] = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            cidrs.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            domains.append(token)
    return EngagementScope(cidrs=tuple(cidrs), domains=tuple(domains))
```

Update `__all__` at the top of `cism/agent/guardrails/scope.py`:
```python
__all__ = ["EngagementScope", "ScopeGuardStage"]
```
to (case-insensitive alphabetical, matching this file's existing order):
```python
__all__ = ["EngagementScope", "parse_scope", "ScopeGuardStage"]
```

In `cism/agent/guardrails/__init__.py`, change:
```python
from .scope import EngagementScope, ScopeGuardStage
```
to:
```python
from .scope import EngagementScope, ScopeGuardStage, parse_scope
```
and add `"parse_scope"` to `__all__` (keep it alphabetically sorted with the rest of that list — it goes right after `"PhaseToolGuardStage"` and before `"ScopeGuardStage"`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_scope_guard.py -v`
Expected: PASS, all tests including the pre-existing ones in this file.

- [ ] **Step 5: Commit**

```bash
git add cism/agent/guardrails/scope.py cism/agent/guardrails/__init__.py tests/test_scope_guard.py
git commit -m "feat: add EngagementScope/ScopeGuardStage mutation and shared parse_scope"
```

---

### Task 2: Repoint `run_agent.py` at the shared `parse_scope`

**Files:**
- Modify: `run_agent.py`
- Test: `tests/test_run_agent.py`

**Interfaces:**
- Consumes: `parse_scope` from Task 1 (`cism.agent.guardrails`).

- [ ] **Step 1: Update the failing tests first**

In `tests/test_run_agent.py`, change the import line:
```python
from run_agent import _parse_scope, parse_args
```
to:
```python
from cism.agent.guardrails import parse_scope
from run_agent import parse_args
```

Then replace every `_parse_scope(` call with `parse_scope(` in the five tests that use it (`test_parse_scope_single_cidr`, `test_parse_scope_bare_ip_widens_to_slash_32`, `test_parse_scope_domain`, `test_parse_scope_mixed_comma_list_preserves_order_per_kind`, `test_parse_scope_all_blank_tokens_returns_empty_scope`) — e.g.:
```python
def test_parse_scope_single_cidr() -> None:
    scope = parse_scope("10.0.0.0/24")
    assert scope.cidrs == (ipaddress.ip_network("10.0.0.0/24"),)
    assert scope.domains == ()
```
(same mechanical rename for the other four).

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_run_agent.py -v`
Expected: FAILs with `ImportError: cannot import name '_parse_scope' from 'run_agent'` (since `run_agent.py` hasn't changed yet — the import line itself fails at collection).

- [ ] **Step 3: Remove the duplicate definition from `run_agent.py`**

Change the import block:
```python
from cism.agent.guardrails import (
    DangerousFlagGuardStage,
    EngagementScope,
    GuardrailChain,
    GuardrailSeam,
    PassThroughStage,
    ScopeGuardStage,
)
```
to:
```python
from cism.agent.guardrails import (
    DangerousFlagGuardStage,
    EngagementScope,
    GuardrailChain,
    GuardrailSeam,
    PassThroughStage,
    ScopeGuardStage,
    parse_scope,
)
```

Delete the entire `_parse_scope` function definition (its docstring plus body — everything from `def _parse_scope(value: str) -> EngagementScope:` through the `return EngagementScope(cidrs=tuple(cidrs), domains=tuple(domains))` line).

In `_enable_live_tools`, change:
```python
    scope = _parse_scope(scope_spec)
```
to:
```python
    scope = parse_scope(scope_spec)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_run_agent.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add run_agent.py tests/test_run_agent.py
git commit -m "refactor: run_agent.py uses the shared guardrails.parse_scope"
```

---

### Task 3: `ScopeChanged` event + transcript rendering

**Files:**
- Modify: `cism/tui/events.py`
- Modify: `cism/tui/app.py`
- Test: `tests/test_events.py`
- Test: `tests/test_app.py`

**Interfaces:**
- Produces: `ScopeChanged(action: str, target: str)` (frozen dataclass event, in `cism.tui.events`, part of the `AgentEvent` union).
- Consumes (Task 4 will use this): nothing from Task 4 — this task is self-contained and Task 4 depends on it.

- [ ] **Step 1: Write the failing tests**

In `tests/test_events.py`, add `ScopeChanged` to the import list from `cism.tui.events` (keep alphabetical order — it goes between `SalienceTerms` and `TokenDelta`):
```python
from cism.tui.events import (
    EVENT_TYPES,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Evidence,
    Interrupted,
    MemoryRow,
    MemoryUpdated,
    Narration,
    NarrationRedacted,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SalienceTerms,
    ScopeChanged,
    TokenDelta,
    ToolFailed,
    ToolFinished,
    ToolOutput,
    ToolStarted,
    decode,
    encode,
)
```

Add `ScopeChanged("add", "scanme.nmap.org")` to the `SIMPLE_EVENTS` list (anywhere in the list — put it right after the `PhaseChanged(...)` entry):
```python
SIMPLE_EVENTS = [
    RunStarted("run-1", "recon"),
    RunFinished("run-1", True),
    Narration("e1", "hello", False),
    NarrationRedacted("e1", "blocked: contains a secret"),
    ToolStarted("c1", "nmap", "-sV"),
    ToolOutput("c1", "chunk"),
    ToolFinished("c1", "6 open ports", 1247, "T1", 0.91),
    ToolFailed("c1", "timeout", "traceback text"),
    PhaseChanged("exploitation", "PTES"),
    ScopeChanged("add", "scanme.nmap.org"),
    TokenDelta(12, 1200, 4096, 32768),
    Interrupted("user interrupt"),
]
```

Add `"ScopeChanged"` to the set in `test_every_event_type_is_registered`:
```python
def test_every_event_type_is_registered() -> None:
    assert set(EVENT_TYPES) == {
        "RunStarted",
        "RunFinished",
        "Narration",
        "NarrationRedacted",
        "ToolStarted",
        "ToolOutput",
        "ToolFinished",
        "ToolFailed",
        "PhaseChanged",
        "ScopeChanged",
        "DEPGUpdated",
        "MemoryUpdated",
        "TokenDelta",
        "Interrupted",
        "SessionState",
    }
```

In `tests/test_app.py`, add a new test (near the other transcript-note tests — anywhere at module level is fine) — first add `ScopeChanged` to the existing `from cism.tui.events import (...)` import block in that file:
```python
from cism.tui.events import Narration, ScopeChanged, ToolFailed, ToolFinished, ToolStarted
```
then:
```python
async def test_scope_changed_renders_as_a_transcript_note(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ScopeChanged("add", "scanme.nmap.org"))
        agent.events.put_nowait(ScopeChanged("remove", "10.0.0.0/24"))
        await settle(pilot)
        texts = [n.text for n in app.transcript.query(NarrationEntry)]
        assert "scope: added scanme.nmap.org" in texts
        assert "scope: removed 10.0.0.0/24" in texts
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_events.py tests/test_app.py -k "scope_changed or every_event_type or simple_events" -v`
Expected: FAILs with `ImportError: cannot import name 'ScopeChanged' from 'cism.tui.events'`.

- [ ] **Step 3: Implement the event and its rendering**

In `cism/tui/events.py`, add `"ScopeChanged"` to `__all__` — the existing list has `"SalienceTerms"` immediately followed by `"TokenDelta"`; insert `"ScopeChanged"` as a new line between those two.

Add the dataclass directly after `PhaseChanged` (before `DEPGUpdated`):
```python
@dataclass(frozen=True, slots=True)
class ScopeChanged(_Event):
    """A /scope add or /scope remove that actually changed the live
    engagement scope — see cism.agent.guardrails.scope.ScopeGuardStage.
    Listing (/scope with no argument) and no-op/error paths use a plain
    Narration instead; this event exists specifically so every real scope
    change is audited (LangGraphAgent._emit logs every AgentEvent)."""

    action: str  # "add" or "remove"
    target: str
```

Add `ScopeChanged` to the `AgentEvent` union (directly after `PhaseChanged` in that `|`-chain):
```python
AgentEvent: TypeAlias = (
    RunStarted
    | RunFinished
    | Narration
    | NarrationRedacted
    | ToolStarted
    | ToolOutput
    | ToolFinished
    | ToolFailed
    | PhaseChanged
    | ScopeChanged
    | DEPGUpdated
    | MemoryUpdated
    | TokenDelta
    | Interrupted
    | SessionState
)
```

Add `ScopeChanged` to the `EVENT_TYPES` tuple (directly after `PhaseChanged`):
```python
EVENT_TYPES: dict[str, type] = {
    cls.__name__: cls
    for cls in (
        RunStarted,
        RunFinished,
        Narration,
        NarrationRedacted,
        ToolStarted,
        ToolOutput,
        ToolFinished,
        ToolFailed,
        PhaseChanged,
        ScopeChanged,
        DEPGUpdated,
        MemoryUpdated,
        TokenDelta,
        Interrupted,
        SessionState,
    )
}
```

In `cism/tui/app.py`, add `ScopeChanged` to the import block from `.events` (keep it near `PhaseChanged` in that import list), then add a branch in `_apply`, directly after the `elif isinstance(event, PhaseChanged):` block and before `elif isinstance(event, DEPGUpdated):`:
```python
        elif isinstance(event, ScopeChanged):
            verb = "added" if event.action == "add" else "removed"
            transcript.add_note(f"scope: {verb} {event.target}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_events.py tests/test_app.py -v`
Expected: PASS, all tests in both files.

- [ ] **Step 5: Commit**

```bash
git add cism/tui/events.py cism/tui/app.py tests/test_events.py tests/test_app.py
git commit -m "feat: add ScopeChanged event and its transcript rendering"
```

---

### Task 4: `/scope` command handling + slash-command discovery

**Files:**
- Modify: `cism/agent/core.py`
- Modify: `cism/tui/widgets/slash.py`
- Test: `tests/test_langgraph_agent.py`

**Interfaces:**
- Consumes: `ScopeGuardStage` (Task 1, `.scope`/`.expand`/`.contract`), `parse_scope` (Task 1), `ScopeChanged` (Task 3).
- Produces: `LangGraphAgent._set_scope(argument: str) -> None` (private handler, mirrors `_set_target`/`_set_phase`).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_langgraph_agent.py`. This file already imports `GuardrailChain, GuardrailResult, GuardrailSeam, PassThroughStage` from `cism.agent.guardrails` — add `EngagementScope, ScopeGuardStage, parse_scope` to that same import line. Also add `ScopeChanged` to the existing `from cism.tui.events import (...)` block (alphabetically, between `RunStarted` and `SessionState`).

```python
def _live_tools_agent(scope: EngagementScope | None = None) -> LangGraphAgent:
    """A LangGraphAgent whose action chain has a real ScopeGuardStage, the
    way run_agent.py's --live-tools wires one up — /scope only does
    anything when one of these exists."""
    stage = ScopeGuardStage(scope or EngagementScope(domains=("example.com",)))
    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([stage]),
        output=GuardrailChain([PassThroughStage()]),
    )
    return LangGraphAgent(guardrails=guardrails)


async def test_scope_without_live_tools_explains_why(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()  # GuardrailSeam.no_op() — no ScopeGuardStage

    await agent.submit("/scope")
    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "--live-tools" in event.text
    await agent.aclose()


async def test_bare_scope_lists_current_entries(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = _live_tools_agent(
        EngagementScope(domains=("example.com",), cidrs=())
    )

    await agent.submit("/scope")
    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "example.com" in event.text
    await agent.aclose()


async def test_bare_scope_on_an_empty_scope_says_so(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = _live_tools_agent(EngagementScope())

    await agent.submit("/scope")
    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "empty" in event.text.lower()
    await agent.aclose()


async def test_scope_add_emits_a_scope_changed_event_per_target(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = _live_tools_agent(EngagementScope())

    await agent.submit("/scope add scanme.nmap.org,10.0.0.0/24")
    first = await asyncio.wait_for(agent.events.get(), timeout=1)
    second = await asyncio.wait_for(agent.events.get(), timeout=1)

    assert isinstance(first, ScopeChanged) and first.action == "add"
    assert isinstance(second, ScopeChanged) and second.action == "add"
    targets = {first.target, second.target}
    assert targets == {"10.0.0.0/24", "scanme.nmap.org"}
    await agent.aclose()


async def test_scope_add_actually_widens_the_live_guard(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    stage = ScopeGuardStage(EngagementScope())
    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([stage]),
        output=GuardrailChain([PassThroughStage()]),
    )
    agent = LangGraphAgent(guardrails=guardrails)

    await agent.submit("/scope add scanme.nmap.org")
    await asyncio.wait_for(agent.events.get(), timeout=1)

    assert "scanme.nmap.org" in stage.scope.domains
    await agent.aclose()


async def test_scope_add_with_nothing_usable_reports_an_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = _live_tools_agent()

    await agent.submit("/scope add")
    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "target" in event.text.lower()
    await agent.aclose()


async def test_scope_remove_emits_a_scope_changed_event(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = _live_tools_agent(EngagementScope(domains=("example.com",)))

    await agent.submit("/scope remove example.com")
    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, ScopeChanged)
    assert event.action == "remove"
    assert event.target == "example.com"
    await agent.aclose()


async def test_scope_remove_of_an_unknown_target_says_so(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = _live_tools_agent(EngagementScope(domains=("example.com",)))

    await agent.submit("/scope remove not-in-scope.example")
    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert not isinstance(event, ScopeChanged)
    assert "not-in-scope.example" in event.text
    await agent.aclose()


async def test_scope_unknown_subcommand_reports_an_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = _live_tools_agent()

    await agent.submit("/scope wat")
    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "add" in event.text and "remove" in event.text
    await agent.aclose()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_langgraph_agent.py -k scope -v`
Expected: every test times out or fails — `/scope` isn't intercepted yet, so `submit("/scope ...")` falls through to `self._run(text)`, which never puts a `Narration`/`ScopeChanged` matching these assertions onto the queue in time (the `asyncio.wait_for(..., timeout=1)` calls will raise `TimeoutError`, or later assertions will fail on the wrong event type).

- [ ] **Step 3: Implement `_set_scope` and wire it into `submit()`**

In `cism/agent/core.py`, add `ScopeGuardStage` and `parse_scope` to the existing `from cism.agent.guardrails import GuardrailChain, GuardrailSeam` line:
```python
from cism.agent.guardrails import GuardrailChain, GuardrailSeam, ScopeGuardStage, parse_scope
```
Add `ScopeChanged` to the existing multi-line `from cism.tui.events import (...)` block (alphabetically, between `RunStarted` and `SessionState`).

In `submit()`, add a new branch directly after the `if name == "phase":` block and before `if name == "ablate":`:
```python
            if name == "scope":
                await self._set_scope(argument.strip())
                return
```
Also update `submit()`'s own docstring line listing the directly-answered commands:
```
        ``/api``/``/model``/``/target``/
        ``/phase``/``/ablate`` are answered directly instead of being
```
to:
```
        ``/api``/``/model``/``/target``/
        ``/phase``/``/ablate``/``/scope`` are answered directly instead of being
```

Add this new method directly after `_set_phase` (before `_ablate`):
```python
    def _scope_guard(self) -> ScopeGuardStage | None:
        """The live ScopeGuardStage in the action chain, if --live-tools
        wired one up (run_agent.py._enable_live_tools) — None under the
        default no-op guardrails, which is exactly when /scope has
        nothing real to change."""
        for stage in self._guardrails.action.stages:
            if isinstance(stage, ScopeGuardStage):
                return stage
        return None

    async def _set_scope(self, argument: str) -> None:
        """Bare ``/scope`` lists the currently declared engagement scope.
        ``/scope add <target[,target...]>`` and ``/scope remove
        <target[,target...]>`` mutate the live ScopeGuardStage in place —
        the only way to change scope without restarting the process,
        since --scope is otherwise baked in once at launch (see
        run_agent.py). Every actual change is a real ScopeChanged
        AgentEvent (audited + shown in the transcript, one per target
        actually affected); listing and no-op/error paths are a plain
        Narration instead, the same split _set_phase already uses."""
        guard = self._scope_guard()
        if guard is None:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text="/scope requires --live-tools (no ScopeGuardStage is active)",
                    done=True,
                )
            )
            return

        subcommand, _, rest = argument.partition(" ")
        rest = rest.strip()

        if not argument:
            listing = ", ".join(guard.scope.entries()) or (
                "(empty — every live-tool call will be blocked)"
            )
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=f"scope  {listing}", done=True
                )
            )
            return

        if subcommand == "add":
            if not rest:
                await self._emit(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                        text="/scope add requires a target (CIDR or domain)",
                        done=True,
                    )
                )
                return
            addition = parse_scope(rest)
            if not addition.cidrs and not addition.domains:
                await self._emit(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                        text=f"{rest!r} is not a usable CIDR or domain",
                        done=True,
                    )
                )
                return
            guard.expand(addition)
            for token in addition.entries():
                await self._emit(ScopeChanged(action="add", target=token))
            return

        if subcommand == "remove":
            if not rest:
                await self._emit(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                        text="/scope remove requires a target",
                        done=True,
                    )
                )
                return
            for token in (t.strip() for t in rest.split(",") if t.strip()):
                if guard.contract(token):
                    await self._emit(ScopeChanged(action="remove", target=token))
                else:
                    await self._emit(
                        Narration(
                            entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                            text=f"{token!r} is not currently in scope",
                            done=True,
                        )
                    )
            return

        await self._emit(
            Narration(
                entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                text=f"unknown /scope subcommand {subcommand!r} — use add, remove, or no argument to list",
                done=True,
            )
        )
```

In `cism/tui/widgets/slash.py`, add a new entry to `COMMANDS` (directly after the `"phase"` entry):
```python
    SlashCommand("scope", "[add|remove] <target>", "view or extend the live engagement scope"),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_langgraph_agent.py -k scope -v`
Expected: PASS, all 10 new tests.

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest -q -n auto`
Expected: PASS, every test in the repo (this is the last task — this is the final full-suite gate for the feature).

- [ ] **Step 6: Commit**

```bash
git add cism/agent/core.py cism/tui/widgets/slash.py tests/test_langgraph_agent.py
git commit -m "feat: add /scope slash command (list, add, remove)"
```
