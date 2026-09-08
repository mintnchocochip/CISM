# Wiring Real Tools, `BubblewrapRunner`, and a Real `GuardrailSeam` into `run_agent.py` — Design

## 1. Why

Two prior design docs each named the same gap and deferred it:

- [2026-09-04-bubblewrap-sandbox-runner-design.md §4.6](2026-09-04-bubblewrap-sandbox-runner-design.md): *"`BubblewrapRunner` is built and fully tested in this phase but is not wired into any default construction path... `set_default_runner(BubblewrapRunner())` becomes a real call site only in the later live-tools-wiring milestone."*
- [2026-09-06-guardrail-bypass-followup-design.md §3, Finding 8](2026-09-06-guardrail-bypass-followup-design.md): *"Nothing wires a real `GuardrailSeam`/toolkit into `LangGraphAgent`... `core.py:96` defaults to `GuardrailSeam.no_op()`, and `run_agent.py` never passes a `tools=` argument, so `LangGraphAgent`'s default registry stays `[dummy_nmap, dummy_msfconsole]` even with a real LLM configured. This means none of the findings below are live against a real target today."*

Both docs point at the same missing plan (`docs/superpowers/plans/2026-09-06-wire-real-guardrails-and-toolkit.md`), which was never committed to this repo. As of today, `cism/agent/core.py` and `run_agent.py` contain zero references to `Runner`/`BubblewrapRunner`, and `LangGraphAgent`'s defaults (`ToolRegistry([dummy_nmap, dummy_msfconsole])`, `GuardrailSeam.no_op()`) are exactly what every one of the ~552 existing tests exercises — confirmed by grep and by reading `core.py` directly. This document is that missing plan's design: the last step that makes the entire guardrail-hardening body of work (scope checks, dangerous-flag checks, phase-tool checks, `BubblewrapRunner`'s filesystem confinement) actually reachable from a live run, rather than only from tests.

## 2. Goals

- `run_agent.py` gains an explicit opt-in, `--live-tools`, that wires:
  - The real tool registry (`CATALOG` + `hydra`) via the existing `build_toolkit()`.
  - `BubblewrapRunner` as the process-wide default `Runner`, via the existing `set_default_runner()`.
  - A real `GuardrailSeam.action` chain (`ScopeGuardStage` + `DangerousFlagGuardStage`) built from a user-declared engagement scope.
- `LangGraphAgent`'s own constructor defaults are untouched — it keeps defaulting to dummy tools and `GuardrailSeam.no_op()`. Only `run_agent.py`, the one real entrypoint, opts in explicitly. This keeps every existing test's behavior unchanged.
- Fail closed, not open, at every step: missing `bwrap`, missing/empty `--scope`, or an unparseable scope all refuse to start rather than degrading silently (unsandboxed execution, or a guard that accidentally allows everything).

## 3. Non-goals (explicitly deferred, with the reason)

- **`GuardrailSeam.input`/`.output` legs.** Stay `PassThroughStage`. Out of scope per both prior docs' own §3 ("the input/output `GuardrailChain` legs... unchanged, not revisited here") — indirect prompt injection via tool output and similar are separate, larger pieces of work.
- **`PhaseToolGuardStage` wiring.** Already done — `default_profiles()` (called unconditionally by `LangGraphAgent.__init__`) already builds one per phase from the real `CATALOG`. Nothing new needed here.
- **Network egress control.** Named as deferred in the `BubblewrapRunner` design (§3) for its own, larger reasons (L7 proxy vs. netns+nftables). Unchanged.
- **A `--live-tools` default-on behavior, or deriving scope from `--target`.** Considered and rejected — see the two decisions below.

## 4. Design

### 4.1 New CLI flags

```
--live-tools              opt into real tools, sandboxed via bwrap (bubblewrap)
--scope CIDR|domain[,...]  engagement scope, e.g. --scope 10.0.0.0/24,example.internal
                           required when --live-tools is passed
```

`--scope` without `--live-tools` is accepted but unused (no error) — YAGNI: nothing in this design gives it meaning on its own, so no need to forbid it either. `--live-tools` without `--scope` is a `parser.error(...)`, same style as the existing `--base-url` requires `--model` check already in `parse_args`.

**Why a separate `--scope`, not derived from `--target`:** `--target` is already documented, in `scope.py`'s own module docstring, as deliberately unsuitable for this — *"free text used today only for DEPG node labeling... the README's own example value is `'linux nginx php'`, not a host or CIDR."* Reusing it would silently misparse that free text as a scope. A dedicated flag also lets a user authorize a broader range (`10.0.0.0/24`) than the single host they start investigating (`--target 10.0.0.5`).

### 4.2 `_parse_scope(value: str) -> EngagementScope`

```python
def _parse_scope(value: str) -> EngagementScope:
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
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

Mirrors the exact `ipaddress.ip_network(..., strict=False)` pattern `scope.py`'s own `contains_network` already uses, so a bare IP (`10.0.0.5`) widens to `/32` the same way the rest of this codebase already treats one. Anything that isn't parseable as a network is treated as a domain — `EngagementScope.contains_host` does its own lowercase/suffix matching on those, so no further validation of domain shape is needed here.

An all-blank/unparseable result (e.g. `--scope " , "`) is a `SystemExit` in `_enable_live_tools` (§4.3), not here — `_parse_scope` itself always returns a value; the emptiness check belongs with the other startup-refusal checks, so they read as one list rather than being split across two functions.

### 4.3 `_enable_live_tools(scope_spec: str) -> tuple[ToolRegistry, GuardrailSeam]`

```python
def _enable_live_tools(scope_spec: str) -> tuple[ToolRegistry, GuardrailSeam]:
    if shutil.which("bwrap") is None:
        raise SystemExit(
            "--live-tools requires bubblewrap (bwrap) to be installed — "
            "install it, or omit --live-tools to use the dummy tools."
        )
    scope = _parse_scope(scope_spec)
    if not scope.cidrs and not scope.domains:
        raise SystemExit(f"--scope {scope_spec!r} contained no usable CIDR or domain")

    set_default_runner(BubblewrapRunner())
    tools, _ = build_toolkit(CATALOG, [hydra], EXTRACTORS)
    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([ScopeGuardStage(scope), DangerousFlagGuardStage()]),
        output=GuardrailChain([PassThroughStage()]),
    )
    print(
        f"LIVE TOOLS ENABLED — real nmap/curl/hydra will run, sandboxed via bwrap "
        f"(bubblewrap), scoped to {scope_spec!r}. Ensure you have authorization for "
        f"any target you use.",
        file=sys.stderr,
    )
    return tools, guardrails
```

The scope-emptiness check runs *before* `set_default_runner`/`build_toolkit`, so a bad `--scope` value refuses to start without leaving any global state mutated — consistent with the bwrap-missing check above it.

### 4.4 Wiring into `main()`

```python
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    tools, guardrails = _enable_live_tools(args.scope) if args.live_tools else (None, None)

    if args.base_url:
        llm = build_chat_model(args.base_url, args.key_env_var, args.model)
        agent = LangGraphAgent(
            llm=llm, tools=tools, guardrails=guardrails, target=args.target,
            endpoint=args.base_url, model_name=args.model, key_env_var=args.key_env_var,
        )
    else:
        agent = LangGraphAgent(tools=tools, guardrails=guardrails, target=args.target)
    ...
```

`tools=None`/`guardrails=None` fall through to `LangGraphAgent`'s existing defaults exactly as they do today — this is a strict additive change to `main()`, not a rewrite of the existing `--base-url` branch logic.

### 4.5 Error handling summary

| Condition | Behavior |
|---|---|
| `--live-tools` without `--scope` | `parser.error` at argument-parsing time (exit 2) |
| `--live-tools --scope ...` but `bwrap` not installed | `SystemExit` from `_enable_live_tools`, before any global state changes (exit 1) |
| `--scope` parses to zero CIDRs/domains | `SystemExit` from `_enable_live_tools`, before any global state changes (exit 1) |
| `--live-tools --scope <valid>`, `bwrap` present | Real tools + `BubblewrapRunner` + real `ScopeGuardStage`/`DangerousFlagGuardStage` wired in; warning banner printed; TUI launches |
| No `--live-tools` | Byte-for-byte the same behavior as today |

## 5. Testing

Same convention as the existing `tests/test_run_agent.py` (pure-logic only — launching the real TUI is explicitly out of scope for automated tests there):

- `--live-tools` without `--scope` → `SystemExit`, message mentions `--scope`.
- `--live-tools --scope ...` parses cleanly; `args.live_tools is True`.
- No `--live-tools` → `--scope` accepted but inert; existing tests (`test_no_flags_leaves_base_url_and_model_empty`, etc.) unaffected.
- `_parse_scope`: a bare CIDR, a bare IP (→ `/32`), a domain, a mixed comma list, and an all-blank string (→ empty `EngagementScope`, the emptiness check itself lives in `_enable_live_tools`, tested separately below).
- `_enable_live_tools`: `shutil.which` monkeypatched to return `None` for `"bwrap"` → `SystemExit` mentioning bubblewrap; confirm `set_default_runner` was never called (monkeypatch it to a spy).
- `_enable_live_tools` with an all-blank `scope_spec` (bwrap monkeypatched present) → `SystemExit` mentioning the scope string; confirm `set_default_runner` was never called.
- `_enable_live_tools` with `shutil.which` monkeypatched to return a fake path and a valid `scope_spec` → returns a `ToolRegistry` and a `GuardrailSeam` whose `action.stages` contains one `ScopeGuardStage` and one `DangerousFlagGuardStage`; the fixture restores the process's global default runner afterward (via `cism.agent.tools.sandbox.set_default_runner(SubprocessRunner())` in teardown, or by capturing/restoring the module's private `_default_runner`) so this test cannot leak into any other test in the suite.
