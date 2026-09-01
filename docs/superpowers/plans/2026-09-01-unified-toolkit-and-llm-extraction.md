# Unified Tool/Extractor Registry and LLM-Backed Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the three tool-declaration paths (hand-written `@tool` functions, `CATALOG` rows, dummy stand-ins) into one YAML-backed catalog plus one small Python `EXTRACTORS` dict, add runtime `tool_help` discovery, a dangerous-flag guardrail stage, a swappable sandbox runner seam, and an LLM-backed fallback extractor — so adding tool #51 touches exactly one file, per `docs/superpowers/specs/2026-09-01-unified-toolkit-and-llm-extraction-design.md`.

**Architecture:** `ToolSpec`/`Flag` become Pydantic models loaded from a new `cism/agent/tools/catalog.yaml`; `phases_for(spec)` replaces the hand-authored `PhaseProfile.tool_names` table in `cism/agent/profiles.py`; a new `build_toolkit()` factory in `cism/agent/tools/base.py` assembles catalog tools + hand-written decorated tools (`hydra`) + a generic `tool_help` tool into one `ToolRegistry`; `run_sandboxed` gains a call-time-resolved default `Runner` so a future container-backed runner is one function call, not a rewrite; a new `DangerousFlagGuardStage` joins the existing `action` guardrail chain seam; a new `LLMExtractor` in `cism/depg/extractors.py` becomes the fallback `CauseExtractor` for any tool without a hand-written one, once a real (non-dummy) backend is configured. No existing protocol (`CauseExtractor`, `GuardrailStage`, `ToolRegistry`, `Agent`) changes shape.

**Tech Stack:** Python 3.11+, Pydantic v2 (already a transitive dependency via `langchain-core`, used directly today in `cism/agent/tools/base.py`), PyYAML (new), LangGraph, `langchain-core`, `langchain-openai`, pytest + pytest-asyncio.

## Global Constraints

- **Install and baseline first.** This checkout's `.venv` is missing `langchain_openai` and (until Task 1) `pyyaml`. Run `.venv/bin/pip install -e ".[dev,agent]"` before Task 1, then `.venv/bin/pytest -q` — expect **377 passed** (10 snapshots) with zero failures before touching any file. Re-run the full suite (not just new tests) after every task below that touches a shared file: `cism/agent/tools/catalog.py`, `cism/agent/tools/base.py`, `cism/agent/tools/__init__.py`, `cism/agent/profiles.py`, `cism/agent/guardrails/scope.py`, `cism/agent/nodes.py`, `cism/agent/core.py`.
- **Tests constructing `LangGraphAgent()` must `monkeypatch.setenv("HOME", str(tmp_path))` first** — `get_agent_logger()` writes to `~/.cism/logs/`. This is the existing convention in `tests/test_langgraph_agent.py`; follow it in every new test that constructs the agent.
- **Every built catalog tool's arbitrary-flags argument is named `extra`, and its target argument is named `target`** — these are fixed field names inside `cism/agent/tools/base.py`'s `_args_model`/`render_argv`, not per-tool choices. Migrating `nmap`/`curl` off their hand-written `options`/`url` parameter names onto this generic shape is an intentional, visible signature change (Task 2) — every call site that names a tool call's args (tests, `ScopeGuardStage._TARGET_ARG_BY_TOOL`) must follow.
- **Resolved ambiguity — hydra and `catalog.yaml`:** the design doc's §4 YAML example shows a `hydra:` catalog block, but §5 explicitly says decorated tools like hydra have *no* `CATALOG` row (that's exactly why `_build_help_tool` takes an `extra_binaries` map). This plan follows §5/§10, the operative sections: hydra stays a `@sandboxed_tool`-decorated function, never a `catalog.yaml` row. Its phase availability is preserved via a small `_DECORATED_TOOL_PHASES` mapping added to `cism/agent/profiles.py` (Task 3), not sourced from `CATALOG`.
- **Resolved ambiguity — `tool_help`'s "exempt from phase gating":** implemented at the `think` node's tool-binding step (`make_think_node` unconditionally adds `tool_help` if it's in the registry — Task 4), not by injecting `"tool_help"` into every `PhaseProfile.tool_names`. This keeps `PhaseProfile` a pure declaration of phase-appropriate tools and leaves `tests/test_phase_profiles.py`'s existing "reporting has no tools" assertion meaningful and unmodified.
- **Corrected method name:** the design doc's `DangerousFlagGuardStage` pseudocode (§6) names its method `run`, but the real `GuardrailStage` protocol (`cism/agent/guardrails/chain.py:42-47`) requires `check` — see `ScopeGuardStage.check` for the existing, working convention. Task 5 implements `check`, not `run`.
- **Global mutable state hygiene:** `set_default_runner` (Task 6) mutates a module-level global in `cism/agent/tools/sandbox.py`. Any test that changes the default runner must restore it via `monkeypatch.setattr("cism.agent.tools.sandbox._default_runner", ...)` (which auto-reverts), never by calling `set_default_runner(SubprocessRunner())` manually at the end of a test — a raised assertion before that manual reset would leak the fake runner into every later test in the same process.
- **`ChatOpenAI` (the real connector) does override `bind_tools`; `DummyChatModel` and every hand-rolled test fake in this repo do not.** `BaseChatModel.with_structured_output()` checks `type(self).bind_tools is BaseChatModel.bind_tools` and raises `NotImplementedError` *synchronously, with no network call* when it isn't overridden (verified against the installed `langchain-core` in this repo's `.venv`). This is why `LLMExtractor` (Task 7) safely falls back to `GenericExtractor` for every existing dummy/fake-backed test without any mocking — no test needs to special-case it.
- Reference design doc throughout: `docs/superpowers/specs/2026-09-01-unified-toolkit-and-llm-extraction-design.md`.

---

## File Structure

```
cism/agent/tools/catalog.py         ToolSpec/Flag -> Pydantic, phases_for, YAML loader (Task 1)
cism/agent/tools/catalog.yaml       NEW — the tool catalog as data (Tasks 1, 2)
cism/agent/tools/discovery.py       DELETED — nmap becomes a catalog row (Task 2)
cism/agent/tools/linux.py           DELETED — curl becomes a catalog row (Task 2)
cism/agent/tools/credentials.py     unchanged (hydra stays hand-written)
cism/agent/tools/base.py            + tool_help, build_toolkit, sandboxed_tool binary metadata (Task 4)
cism/agent/tools/__init__.py        exports: CATALOG, build_catalog, build_toolkit, hydra, curl, nmap (Tasks 2, 4)
cism/agent/guardrails/scope.py      curl's target-arg key: "url" -> "target" (Task 2)
cism/agent/guardrails/dangerous_flags.py   NEW — DangerousFlagGuardStage (Task 5)
cism/agent/guardrails/__init__.py   + DangerousFlagGuardStage export (Task 5)
cism/agent/tools/sandbox.py         + set_default_runner, call-time runner resolution (Task 6)
cism/agent/profiles.py              default_profiles() sourced from CATALOG + decorated-tool phases (Task 3)
cism/agent/nodes.py                 make_think_node always binds tool_help (Task 4)
cism/depg/extractors.py             + EXTRACTORS dict, ExtractedFinding/ExtractedFindings, LLMExtractor (Task 7)
cism/depg/__init__.py               + EXTRACTORS, LLMExtractor exports (Task 7)
cism/agent/core.py                  extractor default: GenericExtractor (dummy) vs LLMExtractor (real) (Task 7)
pyproject.toml                      + pyyaml under [agent] extras; package-data for catalog.yaml (Task 1)

tests/test_tool_catalog_data.py     Flag(...) -> keyword form; phases_for tests (Task 1)
tests/test_tool_catalog_build.py    Flag(...) -> keyword form; nmap/curl-via-catalog argv tests (Tasks 1, 2)
tests/test_tool_argv.py             drop nmap/curl (deleted modules), keep hydra only (Task 2)
tests/test_scope_guard.py           curl tests: url= -> target= (Task 2)
tests/test_tool_catalog_integration.py   curl import + args updated to target/extra (Task 2)
tests/test_phase_profiles.py        CATALOG-driven assertions replace the old _TOOLS-shaped ones (Task 3)
tests/test_sandboxed_tool_decorator.py   + binary metadata assertion (Task 4)
tests/test_tool_help.py             NEW (Task 4)
tests/test_build_toolkit.py         NEW (Task 4)
tests/test_nodes.py                 + tool_help-always-bound test (Task 4)
tests/test_dangerous_flags.py       NEW (Task 5)
tests/test_sandbox.py               + set_default_runner tests (Task 6)
tests/test_depg_extractors.py       + EXTRACTORS keys test (Task 7)
tests/test_depg_llm_extractor.py    NEW (Task 7)
tests/test_langgraph_agent.py       + extractor-default-selection tests (Task 7)
tests/test_toolkit_integration.py   NEW — Checkpoint-2 end-to-end proof (Task 8)
```

Task order is load-bearing: 1 before 2 (YAML/Pydantic must exist before rows are added to it); 2 before 3 (profiles.py's CATALOG-derived tool_names needs nmap/curl already migrated, or the "preserve availability" assertions in Task 3 have nothing to check against); 3 and 4 can run in either order relative to each other but both must land before 8; 5 and 6 are independent of everything except Task 8's capstone test, which uses both; 7 must land before 8 (the capstone proves `EXTRACTORS`/`build_toolkit` working together).

---

### Task 1: `ToolSpec`/`Flag` become Pydantic models; `CATALOG` moves to YAML

**Files:**
- Modify: `cism/agent/tools/catalog.py` (whole file rewritten)
- Create: `cism/agent/tools/catalog.yaml`
- Modify: `pyproject.toml:15-19`
- Modify: `tests/test_tool_catalog_data.py` (whole file)
- Modify: `tests/test_tool_catalog_build.py:12-27` (the two `Flag(...)` positional constructions)

**Interfaces:**
- Produces: `ToolSpec` (Pydantic `BaseModel`, fields `binary: str`, `capability: Capability`, `description: str`, `flags: dict[str, Flag] = {}`, `target: str = "positional"`, `allow_raw: bool = False`, `timeout: float = 60.0`, `help_flag: str = "--help"`, `phases: frozenset[Phase] | None = None`); `Flag` (Pydantic `BaseModel`, `cli: str`, `kind: Literal["value","bool"] = "value"`, constructed with keyword args only from here on); `phases_for(spec: ToolSpec) -> frozenset[Phase]`; `CATALOG: dict[str, ToolSpec]` loaded from `catalog.yaml`. Every later task imports `CATALOG`/`ToolSpec`/`Flag`/`phases_for` from `cism.agent.tools.catalog`.

- [ ] **Step 1: Install dependencies and confirm the baseline**

```bash
.venv/bin/pip install -e ".[dev,agent]"
.venv/bin/pytest -q
```

Expected: `377 passed` (plus a snapshot summary), 0 failures. Do not proceed if this baseline doesn't hold — fix the environment first, this plan doesn't touch anything that should make existing tests fail yet.

- [ ] **Step 2: Add `pyyaml` and package-data for the new YAML file**

Modify `pyproject.toml`:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24",
    "pytest-textual-snapshot>=1.0",
    "textual-dev>=1.7",
]
agent = [
    "langgraph>=0.2",
    "langchain-core>=0.3",
    "langchain-openai>=0.2",
    "pyyaml>=6.0",
]
```

And add a package-data entry so a real wheel build carries the YAML file:

```toml
[tool.setuptools.package-data]
"cism.tui" = ["*.tcss"]
"cism.agent.tools" = ["*.yaml"]
```

Run: `.venv/bin/pip install -e ".[dev,agent]"` again to pull in `pyyaml`.

- [ ] **Step 3: Write the failing tests first — replace `tests/test_tool_catalog_data.py`**

```python
"""cism/agent/tools/catalog.py: ToolSpec/Flag are Pydantic models loaded
from catalog.yaml; phases_for() derives a tool's phase availability from
its capability unless the row overrides it explicitly."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cism.agent.state import Phase
from cism.agent.tools.catalog import CATALOG, Flag, ToolSpec, phases_for


def test_every_catalog_row_declares_a_capability() -> None:
    for spec in CATALOG.values():
        assert spec.capability in ("reads", "writes", "executes", "destructive")


def test_nikto_targets_via_a_flag_not_positionally() -> None:
    assert CATALOG["nikto"].target == "-host"


def test_a_bool_flag_defaults_to_value_kind_unless_specified() -> None:
    flag = Flag(cli="-sV")
    assert flag.kind == "value"
    bool_flag = Flag(cli="-sV", kind="bool")
    assert bool_flag.kind == "bool"


def test_tool_spec_flags_default_to_empty() -> None:
    spec = ToolSpec(binary="x", capability="reads", description="d")
    assert spec.flags == {}
    assert spec.target == "positional"
    assert spec.allow_raw is False
    assert spec.help_flag == "--help"
    assert spec.phases is None


def test_an_invalid_capability_literal_raises_a_validation_error() -> None:
    with pytest.raises(ValidationError):
        ToolSpec(binary="x", capability="deletes-everything", description="d")


def test_phases_for_a_reads_tool_with_no_override_defaults_to_early_phases() -> None:
    spec = ToolSpec(binary="x", capability="reads", description="d")
    assert phases_for(spec) == frozenset(
        {Phase.RECON, Phase.ENUMERATION, Phase.VULNERABILITY_DISCOVERY}
    )


def test_phases_for_an_executes_tool_with_no_override_is_unreachable() -> None:
    spec = ToolSpec(binary="x", capability="executes", description="d")
    assert phases_for(spec) == frozenset()


def test_phases_for_respects_an_explicit_override() -> None:
    spec = ToolSpec(
        binary="x", capability="executes", description="d",
        phases=["exploitation", "post-exploitation"],
    )
    assert phases_for(spec) == frozenset({Phase.EXPLOITATION, Phase.POST_EXPLOITATION})


def test_an_unknown_phase_name_in_the_override_raises_at_construction() -> None:
    with pytest.raises((KeyError, ValidationError)):
        ToolSpec(binary="x", capability="reads", description="d", phases=["not-a-real-phase"])
```

- [ ] **Step 4: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_tool_catalog_data.py -v
```

Expected: `Flag(cli="-sV")` fails against the current dataclass-and-positional-constructor `Flag`? No — it currently *works* positionally and as a keyword call too (dataclasses accept keyword args), so most of these will actually error on missing symbols (`phases_for` doesn't exist yet, `ToolSpec(..., phases=[...])` raises `TypeError: unexpected keyword argument 'phases'` since the dataclass has no such field) or fail to raise `ValidationError` (a plain dataclass never validates `capability`). Confirm at least `test_an_invalid_capability_literal_raises_a_validation_error`, `test_phases_for_*`, and `test_an_unknown_phase_name_in_the_override_raises_at_construction` fail with `ImportError`/`TypeError`/`AttributeError`.

- [ ] **Step 5: Update the two positional `Flag(...)` calls in `tests/test_tool_catalog_build.py`**

```python
def test_render_argv_places_a_bool_flag_and_a_value_flag() -> None:
    spec = ToolSpec(
        binary="nmap", capability="reads", description="d",
        flags={"ports": Flag(cli="-p"), "service": Flag(cli="-sV", kind="bool")},
    )
    argv = render_argv(spec, "10.0.0.5", ports="1-1000", service=True)

    assert argv == ["-p", "1-1000", "-sV", "10.0.0.5"]


def test_render_argv_omits_an_unset_bool_flag() -> None:
    spec = ToolSpec(
        binary="nmap", capability="reads", description="d",
        flags={"service": Flag(cli="-sV", kind="bool")},
    )
    argv = render_argv(spec, "10.0.0.5", service=False)

    assert argv == ["10.0.0.5"]
```

(The other two tests in that file, `test_render_argv_places_target_behind_its_flag_when_not_positional` and `test_render_argv_appends_extra_only_when_allow_raw`, don't construct `Flag` — leave them unmodified.)

- [ ] **Step 6: Write `catalog.yaml`**

```yaml
# Every tool used by the agent is declared here: how to run it (binary,
# flags, target, allow_raw), and which phases offer it (phases: — omit to
# use the capability default below).
#
# Capability defaults when `phases:` is omitted:
#   reads                        -> recon, enumeration, vulnerability-discovery
#   writes / executes / destructive -> NONE — registered but unreachable in
#                                      every phase until you add an explicit
#                                      `phases:` key. This is deliberate,
#                                      fail-closed behavior: a destructive
#                                      tool should never become available to
#                                      a phase just because nobody thought
#                                      about it.

nikto:
  binary: nikto
  capability: reads
  description: Web server vulnerability scan.
  target: "-host"

whatweb:
  binary: whatweb
  capability: reads
  description: Fingerprint web technologies in use on a target.

dnsenum:
  binary: dnsenum
  capability: reads
  description: Enumerate DNS records and subdomains for a domain.
```

- [ ] **Step 7: Rewrite `cism/agent/tools/catalog.py`**

```python
"""Data-driven tool declarations: most CLI tools are `binary <flags>
<target>`, so they are rows in cism/agent/tools/catalog.yaml, not
hand-written functions. See cism.agent.tools.base for the factory that
turns a row into a real tool.

ToolSpec is a Pydantic model, not a plain dataclass: a malformed row
(wrong capability literal, an unknown phase name) fails loudly with a real
ValidationError at import time — the same "fails loudly instead of
silently widening what the agent can execute" principle ToolRegistry's own
docstring already states elsewhere in this codebase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, field_validator

from cism.agent.state import Phase

__all__ = ["CATALOG", "Capability", "Flag", "ToolSpec", "phases_for"]

Capability = Literal["reads", "writes", "executes", "destructive"]

_CATALOG_PATH = Path(__file__).parent / "catalog.yaml"


class Flag(BaseModel):
    cli: str
    kind: Literal["value", "bool"] = "value"


class ToolSpec(BaseModel):
    binary: str
    capability: Capability
    description: str
    flags: dict[str, Flag] = {}
    target: str = "positional"
    allow_raw: bool = False
    timeout: float = 60.0
    #: The rare binary needing `-h` (or something else) instead of `--help`
    #: for cism.agent.tools.base._build_help_tool (see the design doc §5).
    help_flag: str = "--help"
    #: None means "use the capability default" (_DEFAULT_PHASES_BY_CAPABILITY
    #: below); an explicit list overrides it entirely, it does not add to it.
    phases: frozenset[Phase] | None = None

    @field_validator("phases", mode="before")
    @classmethod
    def _parse_phases(cls, value: object) -> frozenset[Phase] | None:
        if value is None:
            return None
        return frozenset(Phase[p.upper().replace("-", "_")] for p in value)


_DEFAULT_PHASES_BY_CAPABILITY: dict[Capability, frozenset[Phase]] = {
    "reads": frozenset({Phase.RECON, Phase.ENUMERATION, Phase.VULNERABILITY_DISCOVERY}),
    "writes": frozenset(),
    "executes": frozenset(),
    "destructive": frozenset(),
}


def phases_for(spec: ToolSpec) -> frozenset[Phase]:
    """A tool's real phase availability: its own `phases:` override if it
    has one, otherwise the fail-closed default for its capability."""
    return spec.phases if spec.phases is not None else _DEFAULT_PHASES_BY_CAPABILITY[spec.capability]


def _load_catalog(path: Path = _CATALOG_PATH) -> dict[str, ToolSpec]:
    raw = yaml.safe_load(path.read_text()) or {}
    return {name: ToolSpec(**row) for name, row in raw.items()}


CATALOG: dict[str, ToolSpec] = _load_catalog()
```

- [ ] **Step 8: Run the tests, confirm they pass**

```bash
.venv/bin/pytest tests/test_tool_catalog_data.py tests/test_tool_catalog_build.py -v
```

Expected: all pass.

- [ ] **Step 9: Run the full suite**

```bash
.venv/bin/pytest -q
```

Expected: `377 passed` still (this task is a pure representation change — `CATALOG`'s three rows carry identical values to before, just Pydantic-typed and YAML-sourced).

- [ ] **Step 10: Commit**

```bash
git add cism/agent/tools/catalog.py cism/agent/tools/catalog.yaml pyproject.toml \
        tests/test_tool_catalog_data.py tests/test_tool_catalog_build.py
git commit -m "feat: ToolSpec/Flag become Pydantic models; CATALOG moves to catalog.yaml"
```

---

### Task 2: Migrate `nmap`/`curl` into the catalog; export `nmap`/`curl`/`hydra`; retire `discovery.py`/`linux.py`

**Files:**
- Modify: `cism/agent/tools/catalog.yaml`
- Delete: `cism/agent/tools/discovery.py`
- Delete: `cism/agent/tools/linux.py`
- Modify: `cism/agent/tools/__init__.py` (whole file)
- Modify: `cism/agent/guardrails/scope.py:37-48` (`_TARGET_ARG_BY_TOOL`)
- Modify: `tests/test_tool_argv.py` (whole file — drop nmap/curl, keep hydra)
- Modify: `tests/test_tool_catalog_build.py` (append nmap/curl-via-catalog tests)
- Modify: `tests/test_scope_guard.py:36-48` (curl tests: `url=` -> `target=`)
- Modify: `tests/test_tool_catalog_integration.py:23,32,54` (import + call args)

**Interfaces:**
- Consumes: `CATALOG`, `ToolSpec`, `phases_for` from Task 1.
- Produces: `cism.agent.tools.nmap`, `cism.agent.tools.curl` (both `BaseTool`, built by `build_catalog`, called with `{"target": ..., "extra": "<raw flags>"}` — no more `options`/`url` parameter names anywhere). `cism.agent.tools.hydra` (unchanged tool, now actually exported). Later tasks (3, 4, 7, 8) import all three from `cism.agent.tools`.

- [ ] **Step 1: Add `nmap`/`curl` rows to `catalog.yaml`**

Append to `cism/agent/tools/catalog.yaml`:

```yaml
nmap:
  binary: nmap
  capability: reads
  description: Network/port scan.
  allow_raw: true
  # Explicit override, not the reads-only default above: nmap was already
  # offered in every non-reporting phase before this migration (the old
  # hand-written PhaseProfile._TOOLS table in cism/agent/profiles.py) —
  # this preserves that. See the design doc §10 (Migration).
  phases: [recon, enumeration, vulnerability-discovery, exploitation, post-exploitation]

curl:
  binary: curl
  capability: reads
  description: Fetch a URL and return its response.
  allow_raw: true
  phases: [recon, enumeration, vulnerability-discovery, exploitation, post-exploitation]
```

- [ ] **Step 2: Write the failing tests — append to `tests/test_tool_catalog_build.py`**

```python
def test_nmap_catalog_row_builds_argv_from_target_and_extra() -> None:
    (tool,) = build_catalog({"nmap": CATALOG["nmap"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "10.0.0.5", "extra": "-p 80,443"})

    assert mock_run.call_args.args[0] == ["nmap", "-p", "80,443", "10.0.0.5"]


def test_nmap_catalog_row_with_no_extra_passes_no_flags() -> None:
    """Unlike the old hand-written nmap(), which defaulted to "-sV" when no
    options were given, the catalog's generic `extra` field has no per-tool
    default value — this is an accepted, minor behavior change: the whole
    point of tool_help (Task 4) is letting the model choose its own flags
    rather than relying on one baked in here."""
    (tool,) = build_catalog({"nmap": CATALOG["nmap"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "10.0.0.5"})

    assert mock_run.call_args.args[0] == ["nmap", "10.0.0.5"]


def test_curl_catalog_row_builds_argv_from_target_and_extra() -> None:
    (tool,) = build_catalog({"curl": CATALOG["curl"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "https://example.com", "extra": "-sS -L"})

    assert mock_run.call_args.args[0] == ["curl", "-sS", "-L", "https://example.com"]
```

Add the needed import at the top of the file: `from cism.agent.tools.catalog import CATALOG, Flag, ToolSpec` (add `CATALOG` to the existing import line).

- [ ] **Step 3: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_tool_catalog_build.py -v -k nmap_catalog or curl_catalog
```

Expected: `KeyError: 'nmap'` / `KeyError: 'curl'` (not yet in `CATALOG`).

- [ ] **Step 4: Delete `discovery.py` and `linux.py`**

```bash
git rm cism/agent/tools/discovery.py cism/agent/tools/linux.py
```

- [ ] **Step 5: Rewrite `cism/agent/tools/__init__.py`**

```python
"""Tool registration — see :mod:`cism.agent.tools.registry`.

nmap and curl are built from their catalog.yaml rows (see catalog.py);
this module builds and re-exports one instance of each for convenience —
the same convenience-import shape dummy_nmap/dummy_msfconsole already had.
hydra stays hand-written (cism.agent.tools.credentials) because its
structured credential-list handling doesn't fit build_catalog's flat
flags-and-target shape; it is exported here for the first time, closing
the "not even exported" gap named in the unified-toolkit design doc.
"""

from __future__ import annotations

from .base import build_catalog
from .catalog import CATALOG
from .credentials import hydra
from .dummy import dummy_msfconsole, dummy_nmap
from .registry import ToolRegistry

_CATALOG_TOOLS = {tool.name: tool for tool in build_catalog(CATALOG)}
curl = _CATALOG_TOOLS["curl"]
nmap = _CATALOG_TOOLS["nmap"]

__all__ = [
    "CATALOG",
    "ToolRegistry",
    "build_catalog",
    "curl",
    "dummy_msfconsole",
    "dummy_nmap",
    "hydra",
    "nmap",
]
```

- [ ] **Step 6: Update `ScopeGuardStage._TARGET_ARG_BY_TOOL` in `cism/agent/guardrails/scope.py`**

```python
_TARGET_ARG_BY_TOOL: dict[str, str] = {
    "nmap": "target",
    "masscan": "target",
    "hydra": "target",
    "medusa": "target",
    "curl": "target",
    "wget": "url",
    "gobuster": "url",
    "ffuf": "url",
    "ssh": "host",
    "scp": "host",
}
```

(Only the `"curl"` line changes, from `"url"` to `"target"` — `curl` now goes through `build_catalog`, whose generic positional-target field is always named `target`. `wget`/`gobuster`/`ffuf` are speculative future tool names, not implemented yet — leave them alone.)

- [ ] **Step 7: Update the three curl-related tests in `tests/test_scope_guard.py`**

```python
def test_an_exact_domain_match_is_allowed() -> None:
    result = _stage().check(_call("curl", target="https://example.com/"))
    assert result.allowed is True


def test_a_subdomain_of_an_in_scope_domain_is_allowed() -> None:
    result = _stage().check(_call("curl", target="https://api.example.com/report"))
    assert result.allowed is True


def test_an_out_of_scope_domain_is_blocked() -> None:
    result = _stage().check(_call("curl", target="https://evil.org/"))
    assert result.allowed is False
```

- [ ] **Step 8: Update `tests/test_tool_catalog_integration.py`**

Change the import (line 32):

```python
from cism.agent.tools import curl
```

Change both tool-call arg dicts inside `_CallsCurlOnce._generate` (there are two copies of this class body across the two tests — actually one class, referenced by both tests; update its single `_generate`):

```python
                tool_calls=[
                    {
                        "name": "curl",
                        "args": {"target": "http://127.0.0.1:1/", "extra": "-sS --max-time 2"},
                        "id": f"call_{uuid.uuid4().hex[:8]}",
                        "type": "tool_call",
                    }
                ],
```

- [ ] **Step 9: Rewrite `tests/test_tool_argv.py` to cover only hydra**

```python
"""cism/agent/tools/credentials.py: what argv the hand-written hydra tool
builds from its arguments. nmap and curl became data-driven catalog rows
(see cism/agent/tools/catalog.yaml and tests/test_tool_catalog_build.py);
hydra stays hand-written because its structured credential-list handling
doesn't fit build_catalog's flat flags-and-target shape. run_sandboxed
itself is monkeypatched out so no real subprocess ever runs here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cism.agent.tools import credentials


def test_hydra_materializes_explicit_credential_lists_to_scratch_files(monkeypatch) -> None:
    captured: dict = {}

    def fake(argv, **kwargs):
        # The scratch dir is cleaned up as soon as hydra()'s `with` block
        # exits, right after this call returns — so the credential files
        # must be read here, while they still exist, not after invoke().
        captured["argv"] = argv
        userfile = argv[argv.index("-L") + 1]
        passfile = argv[argv.index("-P") + 1]
        captured["users"] = Path(userfile).read_text().splitlines()
        captured["passwords"] = Path(passfile).read_text().splitlines()
        return "ok"

    monkeypatch.setattr(credentials, "run_sandboxed", fake)

    credentials.hydra.invoke(
        {
            "target": "10.0.0.5",
            "service": "ssh",
            "usernames": ["root", "admin"],
            "passwords": ["toor"],
            "threads": 4,
        }
    )

    argv = captured["argv"]
    assert argv[:3] == ["hydra", "-t", "4"]
    assert argv[-2:] == ["10.0.0.5", "ssh"]
    assert captured["users"] == ["root", "admin"]
    assert captured["passwords"] == ["toor"]


def test_hydra_caps_threads_at_the_documented_maximum(monkeypatch) -> None:
    captured: dict = {}
    monkeypatch.setattr(
        credentials, "run_sandboxed", lambda argv, **kw: captured.setdefault("argv", argv) or "ok"
    )

    credentials.hydra.invoke(
        {
            "target": "10.0.0.5",
            "service": "ssh",
            "usernames": ["root"],
            "passwords": ["toor"],
            "threads": 999,
        }
    )

    assert captured["argv"][:3] == ["hydra", "-t", "16"]


def test_hydra_rejects_giving_both_an_explicit_list_and_a_named_wordlist() -> None:
    with pytest.raises(ValueError):
        credentials.hydra.invoke(
            {
                "target": "10.0.0.5",
                "service": "ssh",
                "usernames": ["root"],
                "userlist": "common-users",
                "passwords": ["toor"],
            }
        )


def test_hydra_rejects_giving_neither_an_explicit_list_nor_a_wordlist() -> None:
    with pytest.raises(ValueError):
        credentials.hydra.invoke({"target": "10.0.0.5", "service": "ssh", "passwords": ["toor"]})
```

- [ ] **Step 10: Run the affected tests**

```bash
.venv/bin/pytest tests/test_tool_argv.py tests/test_tool_catalog_build.py tests/test_scope_guard.py tests/test_tool_catalog_integration.py -v
```

Expected: all pass. (`test_tool_catalog_integration.py`'s two tests are marked `@requires_curl`/skip if `curl` isn't installed on the machine running this — that's pre-existing, not something this task changes.)

- [ ] **Step 11: Run the full suite**

```bash
.venv/bin/pytest -q
```

Expected: `377 passed`.

- [ ] **Step 12: Commit**

```bash
git add cism/agent/tools/catalog.yaml cism/agent/tools/__init__.py cism/agent/guardrails/scope.py \
        tests/test_tool_argv.py tests/test_tool_catalog_build.py tests/test_scope_guard.py \
        tests/test_tool_catalog_integration.py
git rm cism/agent/tools/discovery.py cism/agent/tools/linux.py
git commit -m "feat: migrate nmap/curl into the YAML catalog; export nmap/curl/hydra"
```

---

### Task 3: `default_profiles()` sourced from `CATALOG`, not a hand-authored table

**Files:**
- Modify: `cism/agent/profiles.py` (whole file)
- Modify: `tests/test_phase_profiles.py:35-43`

**Interfaces:**
- Consumes: `CATALOG`, `phases_for` from `cism.agent.tools.catalog` (Task 1/2).
- Produces: `default_profiles(tools: ToolRegistry) -> PhaseProfiles` — same signature as before; `PhaseProfile`/`PhaseProfiles` classes unchanged. `_DECORATED_TOOL_PHASES: dict[str, frozenset[Phase]]` is new, module-private, documents hydra's phase availability outside the catalog.

- [ ] **Step 1: Write the failing tests — replace the two `_TOOLS`-shaped assertions in `tests/test_phase_profiles.py`**

```python
def test_default_profiles_exploitation_includes_hydra_but_not_recon_only_tools() -> None:
    """Adding tools with a real per-tool phase policy means phase tool sets
    are no longer a monotonically growing superset (the old hand-written
    _TOOLS table happened to make RECON <= EXPLOITATION true by omission,
    not by design) — a recon-only scanner like nikto correctly disappears
    from EXPLOITATION's tool set."""
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert "hydra" in profiles.get(Phase.EXPLOITATION).tool_names
    assert "nikto" not in profiles.get(Phase.EXPLOITATION).tool_names


def test_default_profiles_recon_includes_every_reads_capability_catalog_tool() -> None:
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert {"nikto", "whatweb", "dnsenum", "nmap", "curl"} <= profiles.get(Phase.RECON).tool_names
```

Replace the old `test_default_profiles_gives_exploitation_more_tools_than_recon` with these two (delete the old one — it asserted a subset relationship that a real per-tool phase policy no longer guarantees, and shouldn't).

Leave `test_default_profiles_covers_every_phase` and `test_default_profiles_reporting_phase_has_no_tools` exactly as they are — both still hold under the new implementation (REPORTING gets no catalog tool via the `reads` default's phase set, and no decorated tool via `_DECORATED_TOOL_PHASES`).

- [ ] **Step 2: Run to verify the new tests fail**

```bash
.venv/bin/pytest tests/test_phase_profiles.py -v
```

Expected: `test_default_profiles_exploitation_includes_hydra_but_not_recon_only_tools` and `test_default_profiles_recon_includes_every_reads_capability_catalog_tool` fail (current `_TOOLS` table only ever offers `{"nmap", "curl", "hydra"}`, never nikto/whatweb/dnsenum).

- [ ] **Step 3: Rewrite `cism/agent/profiles.py`**

```python
"""Per-phase configuration for think/act: prompt, tool subset, extra action
guardrail stages. One profile per phase; think/act consume this registry and
never branch on phase themselves, so promoting a phase to a real subagent
later is a hand-off at phase_router, not a graph change.

tool_names is derived from cism.agent.tools.catalog.CATALOG via phases_for,
not hand-authored per phase — adding a catalog row with the right
capability (or an explicit `phases:` override) is what makes it reachable
in a phase, not a second edit here. Decorated (non-catalog) tools like
hydra, which have no CATALOG row (see the design doc §5), get their phase
availability from _DECORATED_TOOL_PHASES instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from cism.agent.guardrails import GuardrailStage
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry
from cism.agent.tools.catalog import CATALOG, phases_for

__all__ = ["PhaseProfile", "PhaseProfiles", "default_profiles"]


@dataclass(frozen=True, slots=True)
class PhaseProfile:
    phase: Phase
    system_prompt: str
    tool_names: frozenset[str]
    action_stages: tuple[GuardrailStage, ...] = ()


class PhaseProfiles:
    """A hard allowlist, same convention as ToolRegistry: every phase must
    have a profile, so a missing one raises rather than silently degrading
    the agent to no prompt and no tools."""

    def __init__(self, profiles: dict[Phase, PhaseProfile]) -> None:
        self._profiles = dict(profiles)

    def get(self, phase: Phase) -> PhaseProfile:
        return self._profiles[phase]


_PROMPTS: dict[Phase, str] = {
    Phase.RECON: (
        "You are in the recon phase: map hosts and open services. "
        "Do not attempt exploitation."
    ),
    Phase.ENUMERATION: (
        "You are in enumeration: identify service versions and configuration "
        "on discovered hosts."
    ),
    Phase.VULNERABILITY_DISCOVERY: (
        "You are assessing discovered services for known vulnerabilities."
    ),
    Phase.EXPLOITATION: (
        "You are attempting to exploit a confirmed vulnerability or weak credential."
    ),
    Phase.POST_EXPLOITATION: (
        "You have a foothold; document access and look for further pivots within scope."
    ),
    Phase.REPORTING: "Summarize findings. Do not run further tools.",
}

#: Decorated tools (cism.agent.tools.credentials.hydra) have no CATALOG row
#: — see the design doc §5's extra_binaries reasoning — so their phase
#: availability can't come from phases_for(). This is the one place that
#: gap is filled by hand.
_DECORATED_TOOL_PHASES: dict[str, frozenset[Phase]] = {
    "hydra": frozenset({Phase.EXPLOITATION, Phase.POST_EXPLOITATION}),
}


def default_profiles(tools: ToolRegistry) -> PhaseProfiles:
    """The basic profile set. tool_names lists real tool names; a caller
    whose registry only has the dummy tools simply binds nothing for a
    phase — see make_think_node, which filters tool_names against what the
    registry actually contains."""
    del tools  # not needed to build the basic set; kept for callers' symmetry

    tool_names_by_phase: dict[Phase, set[str]] = {phase: set() for phase in Phase}
    for name, spec in CATALOG.items():
        for phase in phases_for(spec):
            tool_names_by_phase[phase].add(name)
    for name, phases in _DECORATED_TOOL_PHASES.items():
        for phase in phases:
            tool_names_by_phase[phase].add(name)

    return PhaseProfiles(
        {
            phase: PhaseProfile(
                phase=phase,
                system_prompt=_PROMPTS[phase],
                tool_names=frozenset(tool_names_by_phase[phase]),
            )
            for phase in Phase
        }
    )
```

- [ ] **Step 4: Run the tests, confirm they pass**

```bash
.venv/bin/pytest tests/test_phase_profiles.py -v
```

- [ ] **Step 5: Run the full suite**

```bash
.venv/bin/pytest -q
```

Expected: `377 passed` (net test count unchanged — one test removed, two added minus... actually +1 net; that's fine, just confirm 0 failures).

- [ ] **Step 6: Commit**

```bash
git add cism/agent/profiles.py tests/test_phase_profiles.py
git commit -m "feat: default_profiles() derives tool_names from the catalog, not a hand-authored table"
```

---

### Task 4: `tool_help` runtime discovery and `build_toolkit()` assembly

**Files:**
- Modify: `cism/agent/tools/base.py` (append; also touch `sandboxed_tool`'s `metadata=` at `base.py:115`)
- Modify: `cism/agent/tools/__init__.py` (add `build_toolkit` export)
- Modify: `cism/agent/nodes.py:73-96` (`make_think_node`)
- Modify: `tests/test_sandboxed_tool_decorator.py` (append one assertion)
- Create: `tests/test_tool_help.py`
- Create: `tests/test_build_toolkit.py`
- Modify: `tests/test_nodes.py` (append one test)

**Interfaces:**
- Consumes: `CATALOG`, `ToolSpec` (Task 1/2); `hydra` from `cism.agent.tools` (Task 2).
- Produces: `build_toolkit(catalog: dict[str, ToolSpec], decorated_tools: list[BaseTool], extractors: dict[str, CauseExtractor]) -> tuple[ToolRegistry, dict[str, str]]` (the second element is the same `extractors` dict passed in, returned alongside the registry for a caller's convenience — see the design doc §11). `make_think_node` now always includes a `tool_help` tool from the registry, if present, regardless of the active phase's declared `tool_names`.

- [ ] **Step 1: Write the failing test for `sandboxed_tool`'s binary metadata — append to `tests/test_sandboxed_tool_decorator.py`**

```python
def test_a_decorated_tool_carries_its_binary_in_metadata() -> None:
    @sandboxed_tool(binary="hydra-ish", capability="executes")
    def probe(target: str) -> list[str]:
        """Probe a target."""
        return [target]

    assert probe.metadata["binary"] == "hydra-ish"
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_sandboxed_tool_decorator.py -v -k binary_in_metadata
```

Expected: `KeyError: 'binary'`.

- [ ] **Step 3: Add `binary` to `sandboxed_tool`'s metadata — `cism/agent/tools/base.py`**

In `sandboxed_tool`'s `decorator`, change:

```python
        return StructuredTool.from_function(
            func=_run,
            name=func.__name__,
            description=func.__doc__ or "",
            args_schema=_decorated_args_model(func),
            metadata={"capability": capability},
        )
```

to:

```python
        return StructuredTool.from_function(
            func=_run,
            name=func.__name__,
            description=func.__doc__ or "",
            args_schema=_decorated_args_model(func),
            metadata={"capability": capability, "binary": binary},
        )
```

Run: `.venv/bin/pytest tests/test_sandboxed_tool_decorator.py -v` — expect all pass.

- [ ] **Step 4: Write the failing tests for `tool_help` — create `tests/test_tool_help.py`**

```python
"""cism/agent/tools/base.py: tool_help — a generic, always-available tool
that prints a target tool's own --help/-h text, routed through
run_sandboxed like every other tool call (some binaries hang on --help
waiting on stdin, so it still needs the timeout)."""

from __future__ import annotations

from unittest.mock import patch

from cism.agent.tools.base import _build_help_tool
from cism.agent.tools.catalog import ToolSpec


def test_tool_help_uses_the_catalog_row_help_flag() -> None:
    catalog = {"nikto": ToolSpec(binary="nikto", capability="reads", description="d")}
    tool = _build_help_tool(catalog, extra_binaries={})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="usage: nikto ...") as mock_run:
        result = tool.invoke({"tool_name": "nikto"})

    assert result == "usage: nikto ..."
    assert mock_run.call_args.args[0] == ["nikto", "--help"]


def test_tool_help_respects_a_non_default_help_flag() -> None:
    catalog = {"weird": ToolSpec(binary="weird", capability="reads", description="d", help_flag="-h")}
    tool = _build_help_tool(catalog, extra_binaries={})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"tool_name": "weird"})

    assert mock_run.call_args.args[0] == ["weird", "-h"]


def test_tool_help_resolves_a_decorated_tool_via_extra_binaries() -> None:
    tool = _build_help_tool(catalog={}, extra_binaries={"hydra": "hydra"})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="usage: hydra ...") as mock_run:
        result = tool.invoke({"tool_name": "hydra"})

    assert result == "usage: hydra ..."
    assert mock_run.call_args.args[0] == ["hydra", "--help"]


def test_tool_help_reports_an_unknown_tool_name_without_calling_run_sandboxed() -> None:
    tool = _build_help_tool(catalog={}, extra_binaries={})

    with patch("cism.agent.tools.base.run_sandboxed") as mock_run:
        result = tool.invoke({"tool_name": "not-a-real-tool"})

    assert "unknown tool" in result
    mock_run.assert_not_called()
```

- [ ] **Step 5: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_tool_help.py -v
```

Expected: `ImportError: cannot import name '_build_help_tool'`.

- [ ] **Step 6: Implement `_build_help_tool` and `build_toolkit` in `cism/agent/tools/base.py`**

Add these imports to the top of the file (alongside the existing `from cism.agent.tools.catalog import Capability, ToolSpec`):

```python
from cism.depg.extract import CauseExtractor
```

Append to the end of `cism/agent/tools/base.py`:

```python
def _build_help_tool(catalog: dict[str, ToolSpec], extra_binaries: dict[str, str]) -> BaseTool:
    """One generic tool, not one per catalog entry. Still routed through
    run_sandboxed — timeout-protected even for "harmless" --help, since
    some binaries hang on it waiting on stdin. Exempt from phase gating
    (see make_think_node): knowing what a tool can do carries none of the
    risk that using it does."""
    binaries = {name: spec.binary for name, spec in catalog.items()} | extra_binaries

    def _run(tool_name: str) -> str:
        spec = catalog.get(tool_name)
        help_flag = spec.help_flag if spec else "--help"
        binary = binaries.get(tool_name)
        if binary is None:
            return f"unknown tool {tool_name!r}"
        return run_sandboxed([binary, help_flag])

    return StructuredTool.from_function(
        func=_run,
        name="tool_help",
        description="Print a tool's own --help/-h usage text before deciding what flags to pass it.",
        metadata={"capability": "reads"},
    )


def _binaries_of(tools: list[BaseTool]) -> dict[str, str]:
    """A decorated tool's real binary name, read from the metadata
    sandboxed_tool now attaches — not assumed to equal the tool's
    registered name, even though that happens to be true for hydra today."""
    return {tool.name: tool.metadata.get("binary", tool.name) for tool in tools}


def build_toolkit(
    catalog: dict[str, ToolSpec],
    decorated_tools: list[BaseTool],
    extractors: dict[str, CauseExtractor],
) -> tuple[ToolRegistry, dict[str, str]]:
    """Assembles one ToolRegistry from every tool source this codebase has
    (catalog rows, hand-written decorated tools, plus the generic
    tool_help), and hands back the extractors dict unchanged alongside it
    so a caller building both together — as LangGraphAgent does — has one
    call site instead of two independently-ordered ones."""
    catalog_tools = build_catalog(catalog)
    help_tool = _build_help_tool(catalog, extra_binaries=_binaries_of(decorated_tools))
    registry = ToolRegistry([*catalog_tools, *decorated_tools, help_tool])
    return registry, extractors
```

Add `ToolRegistry` import (from `cism.agent.tools.registry`) to `base.py`'s imports, and update `__all__`:

```python
from cism.agent.tools.registry import ToolRegistry

__all__ = ["build_catalog", "build_toolkit", "render_argv", "sandboxed_tool", "write_lines"]
```

- [ ] **Step 7: Run to verify `test_tool_help.py` passes**

```bash
.venv/bin/pytest tests/test_tool_help.py -v
```

- [ ] **Step 8: Write the failing test for `build_toolkit` — create `tests/test_build_toolkit.py`**

```python
"""cism/agent/tools/base.py: build_toolkit assembles catalog rows +
decorated tools + tool_help into one ToolRegistry — the single place
"adding tool #51" has to touch, per the unified-toolkit design doc."""

from __future__ import annotations

from unittest.mock import patch

from cism.agent.tools import CATALOG, hydra
from cism.agent.tools.base import build_toolkit


def test_build_toolkit_registers_every_catalog_row() -> None:
    registry, _ = build_toolkit(CATALOG, decorated_tools=[], extractors={})

    for name in CATALOG:
        assert name in registry


def test_build_toolkit_registers_decorated_tools() -> None:
    registry, _ = build_toolkit(CATALOG, decorated_tools=[hydra], extractors={})

    assert "hydra" in registry
    assert registry.get("hydra") is hydra


def test_build_toolkit_always_registers_tool_help() -> None:
    registry, _ = build_toolkit(CATALOG, decorated_tools=[hydra], extractors={})

    assert "tool_help" in registry


def test_tool_help_from_build_toolkit_resolves_a_decorated_tools_binary() -> None:
    registry, _ = build_toolkit(CATALOG, decorated_tools=[hydra], extractors={})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="usage: hydra ...") as mock_run:
        result = registry.get("tool_help").invoke({"tool_name": "hydra"})

    assert result == "usage: hydra ..."
    assert mock_run.call_args.args[0] == ["hydra", "--help"]


def test_build_toolkit_returns_the_extractors_dict_unchanged() -> None:
    sentinel = {"nmap": object()}
    _, extractors = build_toolkit(CATALOG, decorated_tools=[], extractors=sentinel)

    assert extractors is sentinel
```

- [ ] **Step 9: Run to verify it passes** (implementation already landed in Step 6)

```bash
.venv/bin/pytest tests/test_build_toolkit.py -v
```

- [ ] **Step 10: Write the failing test for `make_think_node`'s `tool_help` exemption — append to `tests/test_nodes.py`**

```python
async def test_think_always_binds_tool_help_even_when_the_profile_declares_no_tools() -> None:
    recorded: list = []

    class _RecordsBoundTools(BaseChatModel):
        @property
        def _llm_type(self) -> str:
            return "records-bound-tools"

        def bind_tools(self, tools, **kwargs):
            recorded.append(tools)
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content="done"))])

    help_tool = StructuredTool.from_function(
        func=lambda tool_name: "help text", name="tool_help", description="d"
    )
    profiles = PhaseProfiles(
        {Phase.REPORTING: PhaseProfile(phase=Phase.REPORTING, system_prompt="p", tool_names=frozenset())}
    )
    think = make_think_node(_RecordsBoundTools(), ToolRegistry([help_tool]), profiles)

    await think({"messages": [HumanMessage(content="go")], "phase": Phase.REPORTING})

    assert [t.name for t in recorded[0]] == ["tool_help"]
```

Add the needed imports at the top of `tests/test_nodes.py` if not already present: `from langchain_core.tools import StructuredTool` and `from langchain_core.messages import HumanMessage` (check the existing import block first — `AIMessage`/`ChatResult`/`ChatGeneration`/`BaseChatModel`/`ToolRegistry`/`PhaseProfile`/`PhaseProfiles`/`Phase`/`make_think_node` are very likely already imported given the file's existing coverage of `make_think_node`; add only what's missing).

- [ ] **Step 11: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_nodes.py -v -k tool_help
```

Expected: `recorded[0]` is empty (REPORTING's profile has zero tool_names, and `tool_help` isn't in it either, so today nothing gets bound).

- [ ] **Step 12: Update `make_think_node` in `cism/agent/nodes.py`**

```python
def make_think_node(
    llm: BaseChatModel, tools: ToolRegistry, profiles: PhaseProfiles
) -> Callable[[AgentState], dict]:
    async def think(state: AgentState) -> dict:
        profile = profiles.get(state["phase"])
        # tool_help is exempt from phase gating (design doc §5): knowing
        # what a tool can do carries none of the risk that using it does,
        # so it's always offered when the registry has one, regardless of
        # what this phase's profile declares. The `if name in tools` filter
        # on profile.tool_names itself is unchanged from before — a profile
        # can still name a tool the current registry doesn't have (e.g. the
        # bare dummy-tools registry).
        names = {name for name in profile.tool_names if name in tools}
        if "tool_help" in tools:
            names.add("tool_help")
        phase_tools = [tools.get(name) for name in names]
        bound = _bind_tools_if_supported(llm, phase_tools)
        # The prompt is prepended for this invocation only — never appended
        # to state, or every loop iteration would stack another copy.
        messages = [SystemMessage(content=profile.system_prompt), *state["messages"]]
        response = None
        async for chunk in bound.astream(messages):
            response = chunk if response is None else response + chunk
        if response is None:
            response = AIMessage(content="")
        return {"messages": [response]}

    return think
```

(Only the `phase_tools`-building lines change — from `[tools.get(name) for name in profile.tool_names if name in tools]` to the `names` set built above.)

- [ ] **Step 13: Run to verify the new test passes, plus the full node suite**

```bash
.venv/bin/pytest tests/test_nodes.py -v
```

- [ ] **Step 14: Add `build_toolkit` to `cism/agent/tools/__init__.py`'s exports**

```python
from .base import build_catalog, build_toolkit
...
__all__ = [
    "CATALOG",
    "ToolRegistry",
    "build_catalog",
    "build_toolkit",
    "curl",
    "dummy_msfconsole",
    "dummy_nmap",
    "hydra",
    "nmap",
]
```

- [ ] **Step 15: Run the full suite**

```bash
.venv/bin/pytest -q
```

Expected: `377 passed` plus the new tests in this task, 0 failures.

- [ ] **Step 16: Commit**

```bash
git add cism/agent/tools/base.py cism/agent/tools/__init__.py cism/agent/nodes.py \
        tests/test_sandboxed_tool_decorator.py tests/test_tool_help.py tests/test_build_toolkit.py \
        tests/test_nodes.py
git commit -m "feat: tool_help runtime discovery and build_toolkit() assembly"
```

---

### Task 5: `DangerousFlagGuardStage` — the dangerous-flag denylist guardrail

**Files:**
- Create: `cism/agent/guardrails/dangerous_flags.py`
- Modify: `cism/agent/guardrails/__init__.py`
- Create: `tests/test_dangerous_flags.py`

**Interfaces:**
- Produces: `DangerousFlagGuardStage` (implements `GuardrailStage[ToolCall]` — `check(self, call: ToolCall) -> GuardrailResult[ToolCall]`, `name = "dangerous-flag-guard"`). Task 8's capstone test constructs one and appends it to an `action` `GuardrailChain` alongside `ScopeGuardStage`.

- [ ] **Step 1: Write the failing tests — create `tests/test_dangerous_flags.py`**

```python
"""cism/agent/guardrails/dangerous_flags.py: DangerousFlagGuardStage blocks
a tool call whose free-form `extra` argument contains a flag that can read
or write outside the sandbox's scratch directory. Token-level match
against shlex.split(extra), not a substring scan — a target/URL value that
happens to contain "-o" as a substring must not false-positive.
"""

from __future__ import annotations

from cism.agent.guardrails.dangerous_flags import DangerousFlagGuardStage


def _call(**args) -> dict:
    return {"id": "call-1", "name": "nmap", "args": args, "type": "tool_call"}


def _stage() -> DangerousFlagGuardStage:
    return DangerousFlagGuardStage()


def test_a_call_with_no_extra_argument_is_allowed() -> None:
    result = _stage().check(_call(target="10.0.0.5"))
    assert result.allowed is True


def test_a_call_with_harmless_extra_flags_is_allowed() -> None:
    result = _stage().check(_call(target="10.0.0.5", extra="-sV -T4"))
    assert result.allowed is True


def test_nmap_script_flag_is_blocked() -> None:
    result = _stage().check(_call(target="10.0.0.5", extra="--script vuln"))
    assert result.allowed is False
    assert "--script" in result.reason


def test_nmap_output_flags_are_blocked() -> None:
    for flag in ("-oN", "-oX", "-oG", "-oA"):
        result = _stage().check(_call(target="10.0.0.5", extra=f"{flag} /tmp/out"))
        assert result.allowed is False, flag


def test_curl_upload_and_config_flags_are_blocked() -> None:
    result = _stage().check(_call(target="https://x", extra="--upload-file /etc/passwd"))
    assert result.allowed is False

    result = _stage().check(_call(target="https://x", extra="-K /etc/curlrc"))
    assert result.allowed is False


def test_a_target_value_containing_a_dangerous_token_as_a_substring_is_not_blocked() -> None:
    """Token match, not substring match: a hostname/path that happens to
    contain "-o" inside another word must not false-positive."""
    result = _stage().check(_call(target="not-outbound-host.example.com", extra="-sV"))
    assert result.allowed is True


def test_a_bare_dash_o_flag_is_blocked() -> None:
    result = _stage().check(_call(target="10.0.0.5", extra="-o /tmp/pwn.txt"))
    assert result.allowed is False
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_dangerous_flags.py -v
```

Expected: `ModuleNotFoundError: No module named 'cism.agent.guardrails.dangerous_flags'`.

- [ ] **Step 3: Implement `cism/agent/guardrails/dangerous_flags.py`**

```python
"""A new stage in the action GuardrailChain, alongside ScopeGuardStage:
blocks a tool call whose free-form `extra` flags string can read or write
outside the sandbox's scratch directory (an arbitrary local path, or
arbitrary code execution via nmap's NSE scripting).

This is a heuristic safety net, not a formal guarantee — same framing as
ScopeGuardStage. Extend _DANGEROUS_FLAG_TOKENS as new catastrophic flags
are found.
"""

from __future__ import annotations

import shlex

from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails.chain import GuardrailResult

__all__ = ["DangerousFlagGuardStage"]

_DANGEROUS_FLAG_TOKENS: frozenset[str] = frozenset(
    {
        "--script",  # nmap: arbitrary NSE Lua execution
        "-oN", "-oX", "-oG", "-oA",  # nmap: write scan report to an attacker-influenced path
        "-o", "-O", "--output", "--remote-name",  # curl/nikto/etc: write response to an arbitrary local path
        "-T", "--upload-file",  # curl: read an arbitrary local file, send its contents
        "-K", "--config",  # curl: treat a local file's contents as more curl flags
    }
)


class DangerousFlagGuardStage:
    name = "dangerous-flag-guard"

    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        extra = str((call.get("args") or {}).get("extra", ""))
        tokens = set(shlex.split(extra)) if extra else set()
        hit = tokens & _DANGEROUS_FLAG_TOKENS
        if hit:
            return GuardrailResult(
                allowed=False,
                value=call,
                reason=f"blocked flag(s) {sorted(hit)}: can read/write outside the sandbox's scratch dir",
            )
        return GuardrailResult(allowed=True, value=call)
```

- [ ] **Step 4: Export it from `cism/agent/guardrails/__init__.py`**

```python
from .chain import (
    GuardrailChain,
    GuardrailResult,
    GuardrailSeam,
    GuardrailStage,
    PassThroughStage,
)
from .dangerous_flags import DangerousFlagGuardStage
from .scope import EngagementScope, ScopeGuardStage

__all__ = [
    "DangerousFlagGuardStage",
    "EngagementScope",
    "GuardrailChain",
    "GuardrailResult",
    "GuardrailSeam",
    "GuardrailStage",
    "PassThroughStage",
    "ScopeGuardStage",
]
```

- [ ] **Step 5: Run the tests, confirm they pass**

```bash
.venv/bin/pytest tests/test_dangerous_flags.py -v
```

- [ ] **Step 6: Run the full suite**

```bash
.venv/bin/pytest -q
```

- [ ] **Step 7: Commit**

```bash
git add cism/agent/guardrails/dangerous_flags.py cism/agent/guardrails/__init__.py tests/test_dangerous_flags.py
git commit -m "feat: DangerousFlagGuardStage — blocks flags that escape the sandbox's scratch dir"
```

---

### Task 6: Sandbox runner portability — `set_default_runner`

**Files:**
- Modify: `cism/agent/tools/sandbox.py:37,129-152`
- Modify: `tests/test_sandbox.py` (append)

**Interfaces:**
- Produces: `set_default_runner(runner: Runner) -> None`. `run_sandboxed(..., runner: Runner | None = None)`'s existing explicit `runner=` parameter is unchanged; it now falls back to the *module-level default* (settable via `set_default_runner`) instead of always constructing a fresh `SubprocessRunner()`.

- [ ] **Step 1: Write the failing tests — append to `tests/test_sandbox.py`**

```python
class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], *, timeout: float, cwd) -> str:
        self.calls.append(argv)
        return "fake-output"


def test_set_default_runner_is_picked_up_by_run_sandboxed(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    fake = _FakeRunner()
    monkeypatch.setattr(sandbox_module, "_default_runner", fake)

    output = run_sandboxed(["definitely-not-a-real-binary-xyz123"])

    assert output == "fake-output"
    assert fake.calls == [["definitely-not-a-real-binary-xyz123"]]


def test_an_explicit_runner_argument_still_overrides_the_default(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    default_fake = _FakeRunner()
    explicit_fake = _FakeRunner()
    monkeypatch.setattr(sandbox_module, "_default_runner", default_fake)

    run_sandboxed(["x"], runner=explicit_fake)

    assert explicit_fake.calls == [["x"]]
    assert default_fake.calls == []


def test_a_build_catalog_tool_picks_up_the_default_runner_without_being_told(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.base import build_catalog
    from cism.agent.tools.catalog import ToolSpec

    fake = _FakeRunner()
    monkeypatch.setattr(sandbox_module, "_default_runner", fake)
    (tool,) = build_catalog({"echo": ToolSpec(binary="echo", capability="reads", description="d")})

    tool.invoke({"target": "hi"})

    assert fake.calls == [["echo", "hi"]]


def test_a_sandboxed_tool_decorated_function_picks_up_the_default_runner_without_being_told(
    monkeypatch,
) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.base import sandboxed_tool

    fake = _FakeRunner()
    monkeypatch.setattr(sandbox_module, "_default_runner", fake)

    @sandboxed_tool(binary="echo-ish", capability="reads")
    def probe(target: str) -> list[str]:
        """Probe."""
        return [target]

    probe.invoke({"target": "hi"})

    assert fake.calls == [["echo-ish", "hi"]]
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_sandbox.py -v -k default_runner
```

Expected: `AttributeError: module 'cism.agent.tools.sandbox' has no attribute '_default_runner'`.

- [ ] **Step 3: Implement the seam in `cism/agent/tools/sandbox.py`**

Add `"set_default_runner"` to `__all__`. Then, just above `run_sandboxed`'s definition, add:

```python
_default_runner: Runner = SubprocessRunner()


def set_default_runner(runner: Runner) -> None:
    """Swaps the runner every tool call uses when it doesn't pass one
    explicitly. Meant to be called once at startup (LangGraphAgent.__init__
    or run_agent.py, once real tools are opted into) — resolved at call
    time inside run_sandboxed, not at tool-construction time, because
    sandboxed_tool is an eager decorator with no later "assembly" moment to
    inject a runner into."""
    global _default_runner
    _default_runner = runner
```

Change `run_sandboxed`'s body:

```python
def run_sandboxed(
    argv: list[str],
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    cwd: Path | None = None,
    max_output: int = _DEFAULT_MAX_OUTPUT,
    runner: Runner | None = None,
) -> str:
    """Runs ``argv`` and returns its captured output, capped to
    ``max_output`` characters. The sole seam every tool function calls into.

    ``cwd`` defaults to a fresh :func:`scratch_dir`; pass one explicitly
    for tools that need to pre-write files (a hydra wordlist, an msfconsole
    resource script) before the process starts. ``runner`` defaults to
    whatever :func:`set_default_runner` last set (a plain
    :class:`SubprocessRunner` until something calls it) — pass one
    explicitly only for a test that wants to inject a fake runner without
    touching global state.
    """
    active_runner = runner or _default_runner

    if cwd is not None:
        output = active_runner.run(argv, timeout=timeout, cwd=cwd)
    else:
        with scratch_dir() as tmp:
            output = active_runner.run(argv, timeout=timeout, cwd=tmp)

    return _cap(output, max_output)
```

- [ ] **Step 4: Run the tests, confirm they pass**

```bash
.venv/bin/pytest tests/test_sandbox.py -v
```

- [ ] **Step 5: Run the full suite**

```bash
.venv/bin/pytest -q
```

Expected: `377 passed` plus this task's new tests, 0 failures — in particular confirm no later test file observes a leaked fake runner (the `monkeypatch.setattr` pattern used above auto-reverts after each test).

- [ ] **Step 6: Commit**

```bash
git add cism/agent/tools/sandbox.py tests/test_sandbox.py
git commit -m "feat: set_default_runner — a swappable sandbox runner, resolved at call time"
```

---

### Task 7: `EXTRACTORS` dict and `LLMExtractor`

**Files:**
- Modify: `cism/depg/extractors.py` (append)
- Modify: `cism/depg/__init__.py`
- Modify: `cism/agent/core.py:34,97` (import + extractor default selection)
- Create: `tests/test_depg_llm_extractor.py`
- Modify: `tests/test_depg_extractors.py` (append)
- Modify: `tests/test_langgraph_agent.py` (append)

**Interfaces:**
- Consumes: `CauseExtractor`, `Extraction`, `GenericExtractor` (`cism.depg.extract`); `Node`, `derive_node_id` (`cism.depg.node`); `Evidence` (`cism.depg.evidence`).
- Produces: `EXTRACTORS: dict[str, CauseExtractor]`; `ExtractedFinding`, `ExtractedFindings` (Pydantic models); `LLMExtractor` (implements `CauseExtractor.extract(call, message, graph, target) -> Extraction`, constructor `LLMExtractor(llm: BaseChatModel)`). `LangGraphAgent.__init__`'s extractor default becomes `GenericExtractor()` when `self._endpoint == "local (dummy)"`, else `LLMExtractor(self._llm)`.

- [ ] **Step 1: Write the failing tests for `EXTRACTORS` — append to `tests/test_depg_extractors.py`**

```python
def test_extractors_dict_keys_are_known_tool_names() -> None:
    """One cheap test catches a typo in EXTRACTORS at CI time instead of it
    silently falling through to the default extractor at runtime — hydra
    is included explicitly since it has no CATALOG row (design doc §5)."""
    from cism.agent.tools.catalog import CATALOG
    from cism.depg.extractors import EXTRACTORS

    assert set(EXTRACTORS) <= set(CATALOG) | {"hydra"}


def test_extractors_maps_nmap_and_hydra_to_their_real_extractors() -> None:
    from cism.depg.extractors import EXTRACTORS

    assert isinstance(EXTRACTORS["nmap"], NmapExtractor)
    assert isinstance(EXTRACTORS["hydra"], HydraExtractor)
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_depg_extractors.py -v -k EXTRACTORS
```

Expected: `ImportError: cannot import name 'EXTRACTORS'`.

- [ ] **Step 3: Write the failing tests for `LLMExtractor` — create `tests/test_depg_llm_extractor.py`**

```python
"""cism/depg/extractors.py: LLMExtractor is the fallback CauseExtractor for
any tool without a hand-written one (NmapExtractor/HydraExtractor), once a
real (non-dummy) backend is configured. Grounding is mechanical — an exact
substring check against the tool's own raw output — not another LLM call:
a finding whose evidence_quote can't be found in the output has its tier
clamped to T3 rather than being dropped."""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import ToolMessage

from cism.agent.llm import DummyChatModel
from cism.depg.extract import GenericExtractor
from cism.depg.extractors import ExtractedFinding, ExtractedFindings, LLMExtractor
from cism.depg.graph import Graph


class _FakeStructuredLLM(BaseChatModel):
    findings: ExtractedFindings

    @property
    def _llm_type(self) -> str:
        return "fake-structured-output"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise AssertionError("this test double is only ever invoked via with_structured_output")

    def with_structured_output(self, schema, **kwargs):
        findings = self.findings

        class _Structured:
            def invoke(self, *_args, **_kwargs):
                return findings

        return _Structured()


def _tool_message(content: str, name: str = "nikto") -> ToolMessage:
    return ToolMessage(content=content, tool_call_id="c1", name=name)


def test_a_grounded_finding_keeps_its_declared_tier() -> None:
    findings = ExtractedFindings(
        findings=[
            ExtractedFinding(
                cause_class="outdated-server-header",
                signal="Apache/2.2.8",
                tier="T2",
                verdict="alive",
                evidence_quote="Server: Apache/2.2.8",
                summary="Outdated Apache version banner.",
            )
        ]
    )
    extractor = LLMExtractor(_FakeStructuredLLM(findings=findings))
    message = _tool_message("Server: Apache/2.2.8 (Ubuntu)\nX-Powered-By: PHP/5.2.4")

    extraction = extractor.extract(None, message, Graph(), "10.0.0.5")

    assert len(extraction.nodes) == 1
    node = extraction.nodes[0]
    assert node.cause_class == "outdated-server-header"
    assert node.target == "10.0.0.5"
    assert node.evidence[0].tier == "T2"
    assert node.evidence[0].verdict == "alive"


def test_an_ungrounded_finding_is_clamped_to_t3() -> None:
    findings = ExtractedFindings(
        findings=[
            ExtractedFinding(
                cause_class="outdated-server-header",
                signal="Apache/2.2.8",
                tier="T1",
                verdict="alive",
                evidence_quote="this text is not actually anywhere in the tool output",
                summary="Outdated Apache version banner.",
            )
        ]
    )
    extractor = LLMExtractor(_FakeStructuredLLM(findings=findings))
    message = _tool_message("Server: Apache/2.2.8 (Ubuntu)")

    extraction = extractor.extract(None, message, Graph(), "10.0.0.5")

    assert extraction.nodes[0].evidence[0].tier == "T3"


def test_an_empty_findings_list_falls_back_to_generic_extractor() -> None:
    extractor = LLMExtractor(_FakeStructuredLLM(findings=ExtractedFindings(findings=[])))
    message = _tool_message("nothing interesting here", name="whatweb")

    extraction = extractor.extract(None, message, Graph(), "10.0.0.5")
    generic = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    assert extraction.nodes[0].cause_class == generic.nodes[0].cause_class
    assert extraction.nodes[0].id == generic.nodes[0].id


def test_a_model_without_structured_output_support_falls_back_to_generic_extractor() -> None:
    """DummyChatModel doesn't override bind_tools, so
    with_structured_output() raises NotImplementedError synchronously (no
    network) — LLMExtractor must catch that and produce exactly what
    GenericExtractor would."""
    extractor = LLMExtractor(DummyChatModel())
    message = _tool_message("raw output", name="nikto")

    extraction = extractor.extract(None, message, Graph(), "10.0.0.5")
    generic = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    assert extraction.nodes[0].cause_class == generic.nodes[0].cause_class
    assert extraction.nodes[0].id == generic.nodes[0].id
```

- [ ] **Step 4: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_depg_llm_extractor.py -v
```

Expected: `ImportError: cannot import name 'ExtractedFinding'`.

- [ ] **Step 5: Implement `LLMExtractor`/`ExtractedFinding`/`ExtractedFindings`/`EXTRACTORS` — append to `cism/depg/extractors.py`**

Update the module docstring and imports at the top of `cism/depg/extractors.py`:

```python
"""Real cause-class extractors: nmap open-port findings and hydra credential
attempts (regex-based, parsing each tool's own default plain-text output),
plus LLMExtractor — the LLM-backed fallback for any tool without a
hand-written parser here, and EXTRACTORS, the small dict of tool-name ->
extractor pairing the two regex-based ones to their tool names.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.messages.tool import ToolCall
from pydantic import BaseModel

from cism.depg.evidence import Evidence
from cism.depg.extract import CauseExtractor, Extraction, GenericExtractor
from cism.depg.graph import Graph
from cism.depg.node import Node, derive_node_id

__all__ = ["EXTRACTORS", "ExtractedFinding", "ExtractedFindings", "HydraExtractor", "LLMExtractor", "NmapExtractor"]
```

Append to the end of the file:

```python
_PROMPT = (
    "You are extracting security findings from a penetration-testing tool's "
    "raw output.\n"
    "For each distinct finding, report: cause_class (a short label, e.g. "
    "'open-port', 'outdated-server-header'), signal (the specific fact, e.g. "
    "'443/tcp'), tier (T1=confirmed exploit/credential, T2=strong structured "
    "evidence like an open port or version string, T3=weak/unstructured "
    "evidence), verdict ('alive' if this finding is still relevant, 'dead' if "
    "the check failed or found nothing), evidence_quote (an exact substring "
    "of the output below that backs this claim), and summary (one short "
    "sentence).\n"
    "If there is nothing worth reporting, return an empty findings list.\n\n"
    "Tool output:\n{output}"
)


class ExtractedFinding(BaseModel):
    cause_class: str
    signal: str
    tier: Literal["T1", "T2", "T3"]
    verdict: Literal["alive", "dead"]
    evidence_quote: str
    summary: str


class ExtractedFindings(BaseModel):
    findings: list[ExtractedFinding]


class LLMExtractor:
    """Fallback CauseExtractor for any tool without a hand-written one.
    Grounding is mechanical (a real substring check), never another LLM
    call: a finding whose evidence_quote can't be found in the tool's own
    output has its tier clamped to T3 rather than dropped. Any exception —
    malformed structured output, the connector not supporting it, a network
    error — falls back to GenericExtractor's exact behavior, the same
    one-weak-T3-node result every tool already gets today.
    """

    def __init__(self, llm: BaseChatModel) -> None:
        self._llm = llm
        self._fallback = GenericExtractor()

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        try:
            structured = self._llm.with_structured_output(ExtractedFindings)
            result = structured.invoke([HumanMessage(content=_PROMPT.format(output=message.content))])
        except Exception:
            return self._fallback.extract(call, message, graph, target)

        content = str(message.content)
        call_id = call["id"] if call else message.tool_call_id
        nodes = []
        for finding in result.findings:
            tier = finding.tier if finding.evidence_quote in content else "T3"
            nodes.append(
                Node(
                    id=derive_node_id(finding.cause_class, target, finding.signal),
                    cause_class=finding.cause_class,
                    target=target,
                    signal=finding.signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(),
                            tool=message.name or "unknown-tool",
                            exit_signal=finding.summary,
                            tier=tier,
                            verdict=finding.verdict,
                            call_id=call_id,
                        )
                    ],
                )
            )
        return Extraction(nodes=nodes) if nodes else self._fallback.extract(call, message, graph, target)


EXTRACTORS: dict[str, CauseExtractor] = {
    "nmap": NmapExtractor(),
    "hydra": HydraExtractor(),
}
```

- [ ] **Step 6: Run to verify the new tests pass**

```bash
.venv/bin/pytest tests/test_depg_llm_extractor.py tests/test_depg_extractors.py -v
```

- [ ] **Step 7: Export from `cism/depg/__init__.py`**

```python
"""The Dependency / Error Propagation Graph domain model.

``Node``/``Edge`` are the working types the agent mutates as a run
progresses; ``Graph`` is the container that merges them as extraction
proposes new ones; ``ExtractorRegistry``/``CauseExtractor`` is the seam that
turns a tool's output into ``Node``/``Edge`` proposals in the first place;
``EXTRACTORS`` pairs the hand-written regex extractors to their tool names,
and ``LLMExtractor`` is the LLM-backed fallback for everything else. The
propagation/gamma math (``propagation.py``) is still later work — none of
this package depends on anything in ``cism.agent`` or ``cism.tui`` except
through ``Node.to_event()``/``Edge.to_event()``/``Graph.to_event()``.
"""

from __future__ import annotations

from .edge import Edge
from .extract import CauseExtractor, Extraction, ExtractorRegistry, GenericExtractor
from .extractors import EXTRACTORS, HydraExtractor, LLMExtractor, NmapExtractor
from .graph import Graph
from .node import Node

__all__ = [
    "CauseExtractor",
    "EXTRACTORS",
    "Edge",
    "Extraction",
    "ExtractorRegistry",
    "GenericExtractor",
    "Graph",
    "HydraExtractor",
    "LLMExtractor",
    "Node",
    "NmapExtractor",
]
```

- [ ] **Step 8: Write the failing tests for `LangGraphAgent`'s extractor default — append to `tests/test_langgraph_agent.py`**

```python
async def test_the_bare_dummy_backed_agent_uses_generic_extractor(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()

    assert isinstance(agent._extractors.get("some-tool-with-no-hand-written-extractor"), GenericExtractor)


async def test_a_configured_real_endpoint_defaults_to_llm_extractor(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(llm=DummyChatModel(), endpoint="http://example.invalid/v1", model_name="m")

    assert isinstance(agent._extractors.get("some-tool-with-no-hand-written-extractor"), LLMExtractor)
```

Add the needed imports at the top of `tests/test_langgraph_agent.py` if not already present: `from cism.depg import GenericExtractor, LLMExtractor` (check the existing import block — this file almost certainly already imports `DummyChatModel` and `LangGraphAgent`; add only what's missing).

- [ ] **Step 9: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_langgraph_agent.py -v -k extractor
```

Expected: the second test fails (`agent._extractors.get(...)` is currently always `GenericExtractor` regardless of endpoint, since `ExtractorRegistry({}, GenericExtractor())` is hard-coded).

- [ ] **Step 10: Update `cism/agent/core.py`**

Change the import line:

```python
from cism.depg import EXTRACTORS, ExtractorRegistry, GenericExtractor, LLMExtractor
```

Change the extractor default in `__init__`:

```python
        self._tools = tools or ToolRegistry([dummy_nmap, dummy_msfconsole])
        self._guardrails = guardrails or GuardrailSeam.no_op()
        default_extractor = (
            GenericExtractor() if self._endpoint == "local (dummy)" else LLMExtractor(self._llm)
        )
        self._extractors = extractors or ExtractorRegistry(EXTRACTORS, default_extractor)
```

- [ ] **Step 11: Run the tests, confirm they pass**

```bash
.venv/bin/pytest tests/test_langgraph_agent.py -v
```

- [ ] **Step 12: Run the full suite**

```bash
.venv/bin/pytest -q
```

Expected: `377 passed` plus this task's new tests, 0 failures. (Every other existing test that constructs `LangGraphAgent(llm=<a hand-rolled fake>)` without an explicit `endpoint=` keeps `self._endpoint == ""`, which is `!= "local (dummy)"` — those now resolve to `LLMExtractor`, but since none of those fakes override `bind_tools`, `LLMExtractor.extract()` hits the exact same synchronous `NotImplementedError` fallback path exercised in Step 3's test, landing on `GenericExtractor`'s behavior exactly as before. This is the global constraint documented at the top of this plan — verify it holds by watching for any *new* failure in `test_tool_catalog_integration.py`, `test_app_with_langgraph_agent.py`, or `test_nodes.py` specifically.)

- [ ] **Step 13: Commit**

```bash
git add cism/depg/extractors.py cism/depg/__init__.py cism/agent/core.py \
        tests/test_depg_llm_extractor.py tests/test_depg_extractors.py tests/test_langgraph_agent.py
git commit -m "feat: EXTRACTORS dict and LLMExtractor, the LLM-backed fallback extractor"
```

---

### Task 8: Checkpoint-2 proof — `build_toolkit()` + guardrails + `LLMExtractor` through a real graph run

**Files:**
- Create: `tests/test_toolkit_integration.py`

**Interfaces:**
- Consumes everything built in Tasks 1-7: `build_toolkit`, `CATALOG`, `hydra`, `EXTRACTORS`, `ScopeGuardStage`, `DangerousFlagGuardStage`, `LangGraphAgent`.

This task adds no new source code — it's the capstone proof that every piece from Tasks 1-7 composes, the way `tests/test_tool_catalog_integration.py` proved the previous sprint's real-tool wiring end to end.

- [ ] **Step 1: Write `tests/test_toolkit_integration.py`**

```python
"""Checkpoint-2 proof: build_toolkit() assembles the real catalog + hydra +
tool_help into one registry, EXTRACTORS supplies real extraction for nmap
without a hand-authored PhaseProfile entry, and the action guardrail chain
(ScopeGuardStage + DangerousFlagGuardStage together) blocks a dangerous
flag before the subprocess ever runs — a real tool call flows through the
actual graph loop end to end, same shape as
tests/test_tool_catalog_integration.py but exercising this sprint's new
assembly path (build_toolkit) instead of a hand-built ToolRegistry.
"""

from __future__ import annotations

import asyncio
import ipaddress
import shutil
import uuid

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from cism.agent import LangGraphAgent
from cism.agent.guardrails import (
    DangerousFlagGuardStage,
    EngagementScope,
    GuardrailChain,
    GuardrailSeam,
    PassThroughStage,
    ScopeGuardStage,
)
from cism.agent.tools import CATALOG, hydra
from cism.agent.tools.base import build_toolkit
from cism.depg import EXTRACTORS, ExtractorRegistry, GenericExtractor
from cism.tui.events import DEPGUpdated, RunFinished, drain

requires_curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")


class _CallsCurlWith(BaseChatModel):
    extra: str

    @property
    def _llm_type(self) -> str:
        return "test-calls-curl-with"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        tool_results = [m for m in messages if isinstance(m, ToolMessage)]
        if not tool_results:
            reply = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "curl",
                        "args": {"target": "http://127.0.0.1:1/", "extra": self.extra},
                        "id": f"call_{uuid.uuid4().hex[:8]}",
                        "type": "tool_call",
                    }
                ],
            )
        else:
            reply = AIMessage(content="done")
        return ChatResult(generations=[ChatGeneration(message=reply)])


def _action_chain(scope: EngagementScope) -> GuardrailChain:
    return GuardrailChain([ScopeGuardStage(scope=scope), DangerousFlagGuardStage()])


async def _drain_until_finished(agent: LangGraphAgent) -> list:
    events: list = []
    while not any(isinstance(e, RunFinished) for e in events):
        events.extend(await asyncio.wait_for(drain(agent.events), timeout=10.0))
    return events


def test_build_toolkit_registers_the_real_catalog_plus_hydra_plus_tool_help() -> None:
    registry, extractors = build_toolkit(CATALOG, decorated_tools=[hydra], extractors=EXTRACTORS)

    for name in ("nikto", "whatweb", "dnsenum", "nmap", "curl", "hydra", "tool_help"):
        assert name in registry
    assert extractors is EXTRACTORS


@requires_curl
async def test_a_real_curl_call_through_build_toolkit_flows_to_a_depg_node(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    scope = EngagementScope(cidrs=(ipaddress.ip_network("127.0.0.1/32"),))
    registry, extractors = build_toolkit(CATALOG, decorated_tools=[hydra], extractors=EXTRACTORS)
    agent = LangGraphAgent(
        llm=_CallsCurlWith(extra="-sS --max-time 2"),
        tools=registry,
        guardrails=GuardrailSeam(
            input=GuardrailChain([PassThroughStage()]),
            action=_action_chain(scope),
            output=GuardrailChain([PassThroughStage()]),
        ),
        extractors=ExtractorRegistry(extractors, GenericExtractor()),
        target="127.0.0.1",
    )

    await agent.submit("probe localhost")
    events = await _drain_until_finished(agent)
    await agent.aclose()

    assert events[-1].ok is True
    depg_updates = [e for e in events if isinstance(e, DEPGUpdated)]
    assert depg_updates
    node = depg_updates[-1].nodes[0]
    assert node.cause_class == "curl"
    assert node.target == "127.0.0.1"
    assert node.evidence


@requires_curl
async def test_a_dangerous_flag_is_blocked_before_the_subprocess_runs(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    scope = EngagementScope(cidrs=(ipaddress.ip_network("127.0.0.1/32"),))
    registry, extractors = build_toolkit(CATALOG, decorated_tools=[hydra], extractors=EXTRACTORS)
    agent = LangGraphAgent(
        llm=_CallsCurlWith(extra="--upload-file /etc/passwd"),
        tools=registry,
        guardrails=GuardrailSeam(
            input=GuardrailChain([PassThroughStage()]),
            action=_action_chain(scope),
            output=GuardrailChain([PassThroughStage()]),
        ),
        extractors=ExtractorRegistry(extractors, GenericExtractor()),
        target="127.0.0.1",
    )

    await agent.submit("probe localhost")
    events = await _drain_until_finished(agent)
    await agent.aclose()

    # A blocked call is evidence of its own: it becomes a dead tombstone
    # node rather than being dropped, so the agent has a record of the
    # attempt instead of silently re-proposing the same dangerous flag.
    depg_updates = [e for e in events if isinstance(e, DEPGUpdated)]
    assert depg_updates
    assert all(n.state == "blocked" for n in depg_updates[-1].nodes)
```

- [ ] **Step 2: Run this file alone**

```bash
.venv/bin/pytest tests/test_toolkit_integration.py -v
```

Expected: all pass (the two `@requires_curl` tests skip cleanly if `curl` isn't installed on the machine running this).

- [ ] **Step 3: Run the complete test suite one final time**

```bash
.venv/bin/pytest -q
```

Expected: `377` (original baseline) `+` every test added across Tasks 1-8, all passing, 0 failures, 10 snapshots passed. This is the final acceptance gate for the whole plan — do not consider the design implemented until this is green.

- [ ] **Step 4: Commit**

```bash
git add tests/test_toolkit_integration.py
git commit -m "test: checkpoint-2 proof — build_toolkit + guardrails + EXTRACTORS through a real run"
```

---

## Deferred, per the design doc's own non-goals (§3) — do not implement in this plan

- `BubblewrapRunner` itself (Task 6 builds only the seam).
- Making real tools `LangGraphAgent()`'s *default* construction, or a `--live-tools`-style flag in `run_agent.py` — every task above keeps opt-in-only wiring (explicit `tools=`/`guardrails=`/`extractors=` construction, as `tests/test_toolkit_integration.py` does).
- A separate, smaller model dedicated to `LLMExtractor` — it reuses `self._llm`.
- Full RWX/graded-propagation guardrail work beyond `DangerousFlagGuardStage`.
