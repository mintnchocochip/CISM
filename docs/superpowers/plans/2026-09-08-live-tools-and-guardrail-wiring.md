# Live-Tools and Guardrail Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `run_agent.py` a `--live-tools` flag that wires the real tool registry (`CATALOG` + `hydra`), `BubblewrapRunner` as the process default `Runner`, and a real `GuardrailSeam.action` chain (`ScopeGuardStage` + `DangerousFlagGuardStage`) built from a new `--scope` flag — closing the gap named as Finding 8 in `docs/superpowers/specs/2026-09-06-guardrail-bypass-followup-design.md` and left open in `docs/superpowers/specs/2026-09-04-bubblewrap-sandbox-runner-design.md` §4.6.

**Architecture:** All new logic lives in `run_agent.py` — two new CLI flags, a pure parsing helper (`_parse_scope`), and one wiring helper (`_enable_live_tools`) that either refuses to start (missing `bwrap`, empty scope) or returns the real `(ToolRegistry, GuardrailSeam)` pair for `main()` to pass into `LangGraphAgent`. `LangGraphAgent`'s own constructor defaults (`[dummy_nmap, dummy_msfconsole]`, `GuardrailSeam.no_op()`) are untouched, so every existing test keeps its current behavior.

**Tech Stack:** Python 3.12, argparse, `ipaddress` stdlib module, pytest + `monkeypatch`/`capsys`.

## Global Constraints

- `LangGraphAgent`'s defaults (`tools=None` → `[dummy_nmap, dummy_msfconsole]`, `guardrails=None` → `GuardrailSeam.no_op()`) must not change — only `run_agent.py` opts in explicitly.
- `--live-tools` without `--scope` is a `parser.error` (exit 2), matching the existing `--base-url` requires `--model` check already in `parse_args`.
- `_enable_live_tools` must not mutate any global state (`set_default_runner`) before every refusal check has passed — a bad `--scope` value must leave the process in the same state as if `--live-tools` had never been passed.
- No mocked-away happy-path test: the happy-path test in Task 3 calls the real `set_default_runner`/`build_toolkit`, not fakes, so it actually proves the wiring — only `shutil.which` is monkeypatched (to avoid a hard dependency on `bwrap` being installed wherever this suite runs).
- Every test that touches the process-global default runner must use `monkeypatch.setattr(sandbox_module, "_default_runner", sandbox_module._default_runner)` to register automatic restoration — the exact idiom already used in `tests/test_sandbox.py`. Do not invent a different reset mechanism.

---

### Task 1: `--live-tools`/`--scope` CLI flags

**Files:**
- Modify: `run_agent.py:31-50` (`parse_args`)
- Test: `tests/test_run_agent.py`

**Interfaces:**
- Produces: `parse_args(argv).live_tools: bool` (default `False`), `parse_args(argv).scope: str` (default `""`).

- [ ] **Step 1: Write the failing tests — append to `tests/test_run_agent.py`**

```python
def test_live_tools_without_scope_is_an_error(capsys) -> None:
    with pytest.raises(SystemExit):
        parse_args(["--live-tools"])
    assert "--scope" in capsys.readouterr().err


def test_live_tools_and_scope_together_parse_cleanly() -> None:
    args = parse_args(["--live-tools", "--scope", "10.0.0.0/24"])
    assert args.live_tools is True
    assert args.scope == "10.0.0.0/24"


def test_scope_without_live_tools_is_not_an_error() -> None:
    args = parse_args(["--scope", "10.0.0.0/24"])
    assert args.live_tools is False
    assert args.scope == "10.0.0.0/24"


def test_no_flags_leaves_live_tools_false_and_scope_empty() -> None:
    args = parse_args([])
    assert args.live_tools is False
    assert args.scope == ""
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `.venv/bin/pytest tests/test_run_agent.py -v`
Expected: the four new tests FAIL — `error: unrecognized arguments: --live-tools` (or `AttributeError: 'Namespace' object has no attribute 'live_tools'`).

- [ ] **Step 3: Implement — modify `parse_args` in `run_agent.py`**

Replace the whole function (currently `run_agent.py:31-50`):

```python
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target", default="", help="initial target context, e.g. 10.0.0.5"
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="OpenAI-compatible endpoint, e.g. http://localhost:11434/v1",
    )
    parser.add_argument("--model", default="", help="model name/id on that server")
    parser.add_argument(
        "--key-env-var",
        default="CISM_API_KEY",
        help="name of the env var holding the API key (default: CISM_API_KEY)",
    )
    parser.add_argument(
        "--live-tools",
        action="store_true",
        help=(
            "run real tools (nmap/curl/hydra), sandboxed via bwrap (bubblewrap), "
            "instead of the dummy stubs"
        ),
    )
    parser.add_argument(
        "--scope",
        default="",
        help=(
            "engagement scope for --live-tools: comma-separated CIDRs/domains, "
            "e.g. 10.0.0.0/24,example.internal"
        ),
    )
    args = parser.parse_args(argv)
    if args.base_url and not args.model:
        parser.error("--base-url requires --model")
    if args.live_tools and not args.scope.strip():
        parser.error("--live-tools requires --scope (comma-separated CIDRs/domains)")
    return args
```

- [ ] **Step 4: Run to verify the tests pass**

Run: `.venv/bin/pytest tests/test_run_agent.py -v`
Expected: all tests PASS (the 4 new plus the 4 pre-existing).

- [ ] **Step 5: Commit**

```bash
git add run_agent.py tests/test_run_agent.py
git commit -m "feat: add --live-tools/--scope flags to run_agent.py"
```

---

### Task 2: `_parse_scope` — CIDR/domain list to `EngagementScope`

**Files:**
- Modify: `run_agent.py` (add `import ipaddress`, the `EngagementScope` import, and `_parse_scope`)
- Test: `tests/test_run_agent.py`

**Interfaces:**
- Consumes: `cism.agent.guardrails.EngagementScope` (dataclass, fields `cidrs: tuple[IPv4Network | IPv6Network, ...] = ()`, `domains: tuple[str, ...] = ()`).
- Produces: `_parse_scope(value: str) -> EngagementScope`, used by Task 3.

- [ ] **Step 1: Write the failing tests — append to `tests/test_run_agent.py`**

```python
import ipaddress

from run_agent import _parse_scope


def test_parse_scope_single_cidr() -> None:
    scope = _parse_scope("10.0.0.0/24")
    assert scope.cidrs == (ipaddress.ip_network("10.0.0.0/24"),)
    assert scope.domains == ()


def test_parse_scope_bare_ip_widens_to_slash_32() -> None:
    scope = _parse_scope("10.0.0.5")
    assert scope.cidrs == (ipaddress.ip_network("10.0.0.5/32"),)
    assert scope.domains == ()


def test_parse_scope_domain() -> None:
    scope = _parse_scope("example.internal")
    assert scope.domains == ("example.internal",)
    assert scope.cidrs == ()


def test_parse_scope_mixed_comma_list_preserves_order_per_kind() -> None:
    scope = _parse_scope("10.0.0.0/24, example.internal , 10.0.0.9")
    assert scope.cidrs == (
        ipaddress.ip_network("10.0.0.0/24"),
        ipaddress.ip_network("10.0.0.9/32"),
    )
    assert scope.domains == ("example.internal",)


def test_parse_scope_all_blank_tokens_returns_empty_scope() -> None:
    scope = _parse_scope(" , , ")
    assert scope.cidrs == ()
    assert scope.domains == ()
```

(Move the top-level `import ipaddress` to the file's own import block in Step 3 rather than leaving it inline in the test file — shown inline above only to mark where it's first needed.)

- [ ] **Step 2: Run to verify the new tests fail**

Run: `.venv/bin/pytest tests/test_run_agent.py -v`
Expected: `ImportError: cannot import name '_parse_scope' from 'run_agent'`.

- [ ] **Step 3: Implement — modify `run_agent.py`**

Add to the top import block (after `import argparse`, before `import sys`):

```python
import ipaddress
```

Add to the `from cism...` import block, alphabetically with the others:

```python
from cism.agent.guardrails import EngagementScope
```

Add this function directly below `parse_args`:

```python
def _parse_scope(value: str) -> EngagementScope:
    """Comma-separated CIDRs/domains -> EngagementScope. A bare IP widens
    to /32 the same way scope.py's own contains_network already treats
    one (ipaddress.ip_network(..., strict=False)); anything else that
    isn't parseable as a network is treated as a domain — contains_host
    does its own lowercase/suffix matching on those, so no further
    validation of domain shape happens here."""
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

- [ ] **Step 4: Run to verify the tests pass**

Run: `.venv/bin/pytest tests/test_run_agent.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add run_agent.py tests/test_run_agent.py
git commit -m "feat: add _parse_scope, CIDR/domain list to EngagementScope"
```

---

### Task 3: `_enable_live_tools` — the real wiring, fail-closed

**Files:**
- Modify: `run_agent.py` (add the remaining imports and `_enable_live_tools`)
- Test: `tests/test_run_agent.py`

**Interfaces:**
- Consumes: `_parse_scope` (Task 2); `cism.agent.tools.sandbox.{BubblewrapRunner, set_default_runner}`; `cism.agent.tools.{CATALOG, ToolRegistry, build_toolkit, hydra}`; `cism.agent.guardrails.{DangerousFlagGuardStage, GuardrailChain, GuardrailSeam, PassThroughStage, ScopeGuardStage}`; `cism.depg.EXTRACTORS`.
- Produces: `_enable_live_tools(scope_spec: str) -> tuple[ToolRegistry, GuardrailSeam]`, used by Task 4's `main()`.

- [ ] **Step 1: Write the failing tests — append to `tests/test_run_agent.py`**

```python
from cism.agent.guardrails import DangerousFlagGuardStage, ScopeGuardStage
from cism.agent.tools import ToolRegistry
from cism.agent.tools.sandbox import BubblewrapRunner

import run_agent


def test_enable_live_tools_without_bwrap_refuses(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module, "_default_runner", sandbox_module._default_runner)
    monkeypatch.setattr("shutil.which", lambda name: None)
    called: list[object] = []
    monkeypatch.setattr(run_agent, "set_default_runner", lambda runner: called.append(runner))

    with pytest.raises(SystemExit) as exc_info:
        run_agent._enable_live_tools("10.0.0.0/24")

    assert "bwrap" in str(exc_info.value)
    assert called == []


def test_enable_live_tools_with_empty_scope_refuses(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module, "_default_runner", sandbox_module._default_runner)
    monkeypatch.setattr(
        "shutil.which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None
    )
    called: list[object] = []
    monkeypatch.setattr(run_agent, "set_default_runner", lambda runner: called.append(runner))

    with pytest.raises(SystemExit) as exc_info:
        run_agent._enable_live_tools(" , ")

    assert "scope" in str(exc_info.value).lower()
    assert called == []


def test_enable_live_tools_wires_real_tools_and_a_real_guardrail_seam(
    monkeypatch, capsys
) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module, "_default_runner", sandbox_module._default_runner)
    monkeypatch.setattr(
        "shutil.which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None
    )

    tools, guardrails = run_agent._enable_live_tools("10.0.0.0/24,example.internal")

    assert isinstance(tools, ToolRegistry)
    assert "nmap" in tools
    assert "curl" in tools
    assert "hydra" in tools
    assert "tool_help" in tools
    assert isinstance(sandbox_module._default_runner, BubblewrapRunner)
    stage_types = {type(stage) for stage in guardrails.action.stages}
    assert stage_types == {ScopeGuardStage, DangerousFlagGuardStage}
    assert guardrails.input.stages and guardrails.output.stages  # still pass-through, but present
    assert "LIVE TOOLS ENABLED" in capsys.readouterr().err
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `.venv/bin/pytest tests/test_run_agent.py -v`
Expected: `AttributeError: module 'run_agent' has no attribute '_enable_live_tools'` (and no attribute `set_default_runner` for the two tests that monkeypatch it — that import doesn't exist in `run_agent` yet either).

- [ ] **Step 3: Implement — modify `run_agent.py`**

Add to the top import block (alongside `import ipaddress`):

```python
import shutil
```

Extend the `from cism...` import block to:

```python
from cism.agent import LangGraphAgent
from cism.agent.guardrails import (
    DangerousFlagGuardStage,
    EngagementScope,
    GuardrailChain,
    GuardrailSeam,
    PassThroughStage,
    ScopeGuardStage,
)
from cism.agent.llm import build_chat_model
from cism.agent.tools import CATALOG, ToolRegistry, build_toolkit, hydra
from cism.agent.tools.sandbox import BubblewrapRunner, set_default_runner
from cism.depg import EXTRACTORS
from cism.tui.app import CISMApp
```

Add this function directly below `_parse_scope`:

```python
def _enable_live_tools(scope_spec: str) -> tuple[ToolRegistry, GuardrailSeam]:
    """Opts a live run into real tools: BubblewrapRunner as the process
    default Runner, the real CATALOG+hydra toolkit, and a real
    ScopeGuardStage/DangerousFlagGuardStage action chain built from
    scope_spec. Refuses (SystemExit) rather than degrading silently: no
    bwrap means no sandboxing, and an empty scope means ScopeGuardStage
    would block every call anyway — neither check mutates global state
    before both have passed."""
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

- [ ] **Step 4: Run to verify the tests pass**

Run: `.venv/bin/pytest tests/test_run_agent.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `.venv/bin/pytest -q`
Expected: same baseline as before this plan (552 passed, 1 pre-existing unrelated `test_depg_modal` snapshot failure) plus every test added in Tasks 1-3, 0 new failures.

- [ ] **Step 6: Commit**

```bash
git add run_agent.py tests/test_run_agent.py
git commit -m "feat: _enable_live_tools wires BubblewrapRunner, real toolkit, and a real GuardrailSeam action chain"
```

---

### Task 4: Wire into `main()`, correct the stale `GuardrailSeam` docstring, final verification

**Files:**
- Modify: `run_agent.py:53-75` (`main`) and its module docstring (`run_agent.py:1-19`)
- Modify: `cism/agent/guardrails/chain.py:11-12` (stale docstring)

**Interfaces:**
- Consumes: `_enable_live_tools` (Task 3), `parse_args` (Task 1).

- [ ] **Step 1: Implement — modify `main()` in `run_agent.py`**

Replace the whole function (currently `run_agent.py:53-75`):

```python
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    tools, guardrails = _enable_live_tools(args.scope) if args.live_tools else (None, None)

    if args.base_url:
        llm = build_chat_model(args.base_url, args.key_env_var, args.model)
        agent = LangGraphAgent(
            llm=llm,
            tools=tools,
            guardrails=guardrails,
            target=args.target,
            endpoint=args.base_url,
            model_name=args.model,
            key_env_var=args.key_env_var,
        )
    else:
        agent = LangGraphAgent(tools=tools, guardrails=guardrails, target=args.target)

    if agent._endpoint == "local (dummy)":
        print(
            "No real endpoint configured — running against the dummy backend.\n"
            "Pass --base-url/--model, or set CISM_LLM_BASE_URL/CISM_LLM_MODEL.",
            file=sys.stderr,
        )

    CISMApp(agent).run()
    return 0
```

- [ ] **Step 2: Update the module docstring — modify `run_agent.py:1-19`**

Replace the module docstring's example block (after "...without touching the environment::") to add a `--live-tools` example, keeping everything else unchanged:

```python
"""Run the CISM TUI against the real LangGraph-backed agent core.

Unlike ``demo_replay.py`` this does not replay a recorded log — it drives
``cism.agent.LangGraphAgent`` live, through the same ``Agent`` protocol.

With no flags, the agent falls back to whatever ``CISM_LLM_BASE_URL``/
``CISM_LLM_MODEL`` say (or ``DummyChatModel`` if neither is set — see
``cism/agent/core.py``). To point at a real OpenAI-compatible server
(llama.cpp, vLLM, LM Studio, real OpenAI, or Ollama's ``/v1`` endpoint)
without touching the environment::

    .venv/bin/pip install -e ".[dev,agent]"
    python run_agent.py --base-url http://localhost:11434/v1 --model qwen2.5:3b
    python run_agent.py --target 10.0.0.5 --base-url http://localhost:11434/v1 --model qwen2.5:3b

By default, tool calls run against ``dummy_nmap``/``dummy_msfconsole`` — no
real subprocess ever runs. Pass ``--live-tools`` to run the real catalog
(nmap/curl/hydra/...) instead, sandboxed via ``bwrap`` (bubblewrap) and
checked against a real ``ScopeGuardStage``/``DangerousFlagGuardStage``
action chain — this requires ``--scope`` (comma-separated CIDRs/domains
you're authorized against) and a working ``bwrap`` install::

    python run_agent.py --live-tools --scope 10.0.0.0/24,example.internal \\
        --base-url http://localhost:11434/v1 --model qwen2.5:3b

See ``cism/agent/`` for what's behind it and the design specs at
``docs/superpowers/specs/2026-08-29-real-llm-connector-wiring-design.md``
and ``docs/superpowers/specs/2026-09-08-live-tools-and-guardrail-wiring-design.md``.
"""
```

- [ ] **Step 3: Correct the stale docstring — modify `cism/agent/guardrails/chain.py:11-12`**

Before:

```python
Note this says nothing about the separate, still-deferred work of wiring
a ``GuardrailSeam`` into ``LangGraphAgent`` itself — that remains open.
```

After:

```python
``run_agent.py``'s ``--live-tools`` flag builds a real one (ScopeGuardStage
+ DangerousFlagGuardStage on the action chain) and passes it to
``LangGraphAgent`` explicitly; ``LangGraphAgent``'s own default stays
``GuardrailSeam.no_op()`` for every caller — tests included — that doesn't
opt in.
```

- [ ] **Step 4: Run the full suite one more time**

Run: `.venv/bin/pytest -q`
Expected: baseline (552 passed before this plan) plus every test added in Tasks 1-3, 0 new failures, the same single pre-existing `test_depg_modal` snapshot mismatch as before this plan (unrelated).

- [ ] **Step 5: Manual smoke test (not automated — confirms the CLI path for real)**

Run, in an environment with `bwrap` and `nmap` installed:

```bash
python run_agent.py --live-tools --scope 127.0.0.1/32
```

Expected: stderr prints the `LIVE TOOLS ENABLED` banner before the TUI launches. Without `bwrap` installed:

```bash
python run_agent.py --live-tools --scope 127.0.0.1/32
```

Expected: prints the bubblewrap-missing error and exits non-zero, no TUI window opens.

- [ ] **Step 6: Commit**

```bash
git add run_agent.py cism/agent/guardrails/chain.py
git commit -m "feat: wire --live-tools into main(); correct stale GuardrailSeam docstring"
```
