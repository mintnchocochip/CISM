# Unified Tool/Extractor Registry and LLM-Backed Extraction — Design

## 1. Why

Three problems, found by tracing what actually happens between a user's message
and a tool executing, not by inspection alone:

1. **Three tool-declaration paths that never converge.** Hand-written
   `nmap`/`curl`/`hydra` (`cism/agent/tools/discovery.py`/`linux.py`/`credentials.py`,
   raw `@tool` functions calling `run_sandboxed` directly, not even re-exported
   from `tools/__init__.py`), `CATALOG`/`build_catalog` rows (`nikto`/`whatweb`/
   `dnsenum`), and the dummy stand-ins. **None of the real ones are wired into
   `LangGraphAgent`'s default construction.** `run_agent.py` never builds a real
   `ToolRegistry` — every live run today, dummy or real-LLM-backed, only ever
   gets `[dummy_nmap, dummy_msfconsole]`.
2. **Adding one tool today means touching three unrelated files**: a `ToolSpec`
   row (how to run it), an `ExtractorRegistry` entry (how to read its output),
   and a `PhaseProfile.tool_names` string (which phase offers it) — three
   registries that can silently drift out of sync, with no compiler or test
   catching a typo across them.
3. **`ToolSpec.allow_raw` already exists and is unused.** All three current
   `CATALOG` rows have empty `flags={}` and `allow_raw=False` — meaning none of
   them can take a single configurable argument through the catalog path today,
   even once wired in.

This document designs the fix for all three, plus LLM-backed extraction as the
new default parser for any tool without a hand-written one — built now, in the
same sprint, not deferred.

## 2. Goals

- Adding tool #51 requires touching exactly one file, and in the common case,
  writing exactly one line.
- One declaration mechanism per axis (how to run, how to parse, which phases),
  not duplicated per tool-declaration style.
- The agent can use `--help`/`-h` to reason about a tool's flags at runtime,
  the way a human operator would, without reopening the shell-injection surface
  the sandbox was built to close.
- A tool without a hand-written extractor still produces real, tiered evidence
  via an LLM extractor — not a flat, uninterpreted T3 blob.
- The sandbox stays swappable to a real isolation layer (`BubblewrapRunner`)
  later without editing every tool function — build the seam now, not the
  container.

## 3. Non-goals (explicitly deferred, with the reason)

- **`BubblewrapRunner` itself.** This sprint builds the injection seam only;
  `SubprocessRunner` remains the actual runner in use.
- **Real tools becoming `LangGraphAgent()`'s default.** Stays opt-in behind an
  explicit construction call (a `--live-tools`-style flag in `run_agent.py`),
  same as today's "no lab, no weights, no network" bare-default philosophy.
  **Flagged to revisit** once this is tested live — noted here so it isn't
  forgotten, not because the decision is final.
- **A separate, smaller model for `LLMExtractor`.** Reuses `self._llm` (today,
  a locally-hosted 3B Qwen2.5) for this sprint. **Flagged to revisit** once (a)
  live tests show whether extraction quality on a small model is good enough,
  and (b) the per-phase-subagents direction already sketched in
  [2026-08-29-depg-basic-and-memory-design.md §"Per-phase subagents"](2026-08-29-depg-basic-and-memory-design.md)
  gets built — that design explicitly promotes per-phase specialization "when a
  real model shows one shared graph cannot serve all six phases well," which is
  exactly the point at which per-role model choice (including for extraction)
  becomes a real question instead of a guess.
- **Full RWX/graded-propagation guardrail work.** Only the one new guardrail
  stage (§6) is in scope; the rest of that workstream is untouched.

## 4. Unified tool declaration: `CATALOG` (YAML, `phases:` inline) and `EXTRACTORS` (Python)

The original DEPG design spec deferred tool-catalog externalization
explicitly as "the author's call, later" — this is that call, made now,
**for the parts that are pure data.** Not everything qualifies; see the
EXTRACTORS split below before assuming the whole system moved to YAML.

**`CATALOG` moves to a YAML file**, `cism/agent/tools/catalog.yaml`, one block
per tool:

```yaml
nikto:
  binary: nikto
  capability: reads
  description: Web server vulnerability scan.
  target: "-host"

nmap:
  binary: nmap
  capability: reads
  description: Network/port scan.
  allow_raw: true

hydra:
  binary: hydra
  capability: executes
  description: Credential brute-force.
  allow_raw: false
  phases: [exploitation]   # overrides the reads-only default below
```

YAML over TOML: `flags` is a dict of dicts (`{port: {cli: "-p", kind:
value}}`) once a tool needs the declared-allowlist path instead of
`allow_raw` — YAML nests that naturally as one more indent level, TOML turns
it into `[tool.flags.port]` table-array syntax that reads worse the deeper it
nests. For a catalog that's fundamentally "one record per tool, some records
with nested sub-fields," YAML is the closer fit.

**`ToolSpec` becomes a Pydantic model, not a plain dataclass** — this is what
keeps type safety after the move: a malformed row (wrong `capability` literal,
missing `binary`) fails loudly with a real `ValidationError` at load time, the
same "fails loudly instead of silently widening what the agent can execute"
principle `ToolRegistry`'s own docstring already states as a hard requirement
elsewhere in this codebase.

```python
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
    help_flag: str = "--help"          # NEW — see §5
    phases: frozenset[Phase] | None = None   # NEW — None = use the capability default

    @field_validator("phases", mode="before")
    @classmethod
    def _parse_phases(cls, value):
        if value is None:
            return None
        return frozenset(Phase[p.upper().replace("-", "_")] for p in value)
```

`Phase` (`cism/agent/state.py`) is a plain `Enum` with int values, not a
`str` enum — `phases:` entries in YAML use the same lowercase-hyphenated
form the rest of the codebase already uses on the wire
(`Phase.to_wire()`: `"vulnerability-discovery"`, not `"VULNERABILITY_
DISCOVERY"`), and `_parse_phases` is the one place that translates between
them, mirroring `to_wire()`'s own convention rather than inventing a second
one.

**`phases:` folds into each tool's own YAML block** rather than living in a
separate `PHASES` dict — a cleaner fit for YAML specifically than the earlier
three-separate-Python-dicts sketch, since "everything about this one tool" is
now genuinely one block to read, not one entry split across two structures.
Default policy, unchanged from the earlier design, now read off `spec.phases`
instead of a lookup table:

```python
_DEFAULT_PHASES_BY_CAPABILITY: dict[Capability, frozenset[Phase]] = {
    "reads": frozenset({Phase.RECON, Phase.ENUMERATION, Phase.VULNERABILITY_DISCOVERY}),
    "writes": frozenset(),
    "executes": frozenset(),
    "destructive": frozenset(),
}

def phases_for(spec: ToolSpec) -> frozenset[Phase]:
    return spec.phases if spec.phases is not None else _DEFAULT_PHASES_BY_CAPABILITY[spec.capability]
```

`"executes"`/`"destructive"` tools with no `phases:` key still default to
`frozenset()` — **registered but unreachable in every phase** until
explicitly tagged. Still deliberate fail-closed behavior, not a bug, same
reasoning as before: a destructive tool should never become available to a
phase because someone forgot to think about it, and this is the one place in
this design where "it just silently doesn't work" is correct — worth a loud
comment at the top of `catalog.yaml` itself now, since that's where an author
actually looks when adding a tool.

**Loading, with `pyyaml` as a new dependency** (not currently in
`pyproject.toml` — add it under the `agent` extra):

```python
import yaml
from pathlib import Path

_CATALOG_PATH = Path(__file__).parent / "catalog.yaml"

def _load_catalog(path: Path = _CATALOG_PATH) -> dict[str, ToolSpec]:
    raw = yaml.safe_load(path.read_text())
    return {name: ToolSpec(**row) for name, row in raw.items()}

CATALOG: dict[str, ToolSpec] = _load_catalog()
```

**`EXTRACTORS` stays a plain Python dict — this is the part that doesn't move,
and it's a real constraint, not a style preference.** Its values are live
`CauseExtractor` *instances* (`NmapExtractor()`, `HydraExtractor()`,
eventually `LLMExtractor(llm)`), not data. Representing that in YAML means
either inventing a class-path string (`extractor: "cism.depg.extractors.
NmapExtractor"`) resolved via `importlib` at load time, or giving up and
storing config-only data that still needs Python code to interpret — the
first option is exactly the "dynamic lookup by arbitrary name" `ToolRegistry`
was deliberately built to avoid, and the second option doesn't actually
externalize anything, it just adds an indirection layer. `EXTRACTORS` staying
code, populated only for the handful of tools where a hand-written parser
earns its cost (§4 of the prior draft; unchanged), is the correct boundary:
**pure data goes in YAML, code — even a one-line reference to code — stays in
Python.**

**`PhaseProfile.tool_names` stops being hand-authored**, same as before:
`default_profiles()` in `cism/agent/profiles.py` derives each phase's
`tool_names` from `CATALOG` via `phases_for(spec)` — one source of truth,
now sourced from the YAML file instead of a Python literal, with the same
"hand-construct a custom `PhaseProfiles` if you need something non-default"
escape hatch untouched.

## 5. Runtime tool discovery: `tool_help`

One generic, auto-generated tool, not one per catalog entry:

```python
def _build_help_tool(catalog: dict[str, ToolSpec], extra_binaries: dict[str, str]) -> BaseTool:
    binaries = {name: spec.binary for name, spec in catalog.items()} | extra_binaries

    def _run(tool_name: str) -> str:
        spec = catalog.get(tool_name)
        help_flag = spec.help_flag if spec else "--help"
        binary = binaries.get(tool_name)
        if binary is None:
            return f"unknown tool {tool_name!r}"
        return run_sandboxed([binary, help_flag])

    return StructuredTool.from_function(
        func=_run, name="tool_help",
        description="Print a tool's own --help/-h usage text before deciding what flags to pass it.",
        metadata={"capability": "reads"},
    )
```

- Still routed through `run_sandboxed` — timeout-protected even though it's
  "harmless," since some binaries hang on `--help` waiting on stdin.
- **Exempt from `PHASES` gating** — always bound, in every phase, since
  knowing what a tool can do carries none of the risk that using it does.
- `extra_binaries` covers decorator-declared tools (e.g. `hydra`), which don't
  have a `CATALOG` row to read a binary name from.
- `help_flag` on `ToolSpec` (default `"--help"`) is the one escape hatch for
  the rare binary that needs `-h` or something else instead — a field, not
  auto-detection logic.

Reading `--help` never expands what the model is allowed to pass in a *real*
invocation — it only informs what string it chooses to put in `extra`, which
still goes through §6 before touching the sandbox.

## 6. Guardrail: dangerous-flag denylist stage

New stage in the **action** `GuardrailChain`, alongside `ScopeGuardStage`,
running at the same point it already runs — `cism/agent/nodes.py`'s `act`
node calls `action_chain.run(call)` before `tool.invoke(call)`. Appending a
stage is the only change; the chain runner and graph shape don't move.

```python
# cism/agent/guardrails/dangerous_flags.py

_DANGEROUS_FLAG_TOKENS: frozenset[str] = frozenset({
    "--script",                                # nmap: arbitrary NSE Lua execution
    "-oN", "-oX", "-oG", "-oA",                 # nmap: write scan report to an attacker-influenced path
    "-o", "-O", "--output", "--remote-name",     # curl/nikto/etc: write response to an arbitrary local path
    "-T", "--upload-file",                       # curl: read an arbitrary local file, send its contents
    "-K", "--config",                            # curl: treat a local file's contents as more curl flags
})

class DangerousFlagGuardStage:
    name = "dangerous-flag-guard"

    def run(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        extra = str(call.get("args", {}).get("extra", ""))
        tokens = set(shlex.split(extra)) if extra else set()
        hit = tokens & _DANGEROUS_FLAG_TOKENS
        if hit:
            return GuardrailResult(
                allowed=False, value=call,
                reason=f"blocked flag(s) {sorted(hit)}: can read/write outside the sandbox's scratch dir",
            )
        return GuardrailResult(allowed=True, value=call)
```

Token-level match against `shlex.split(extra)`, not a substring scan of the
raw string — a target hostname or argument value that happens to contain `-o`
as a substring must not false-positive. This list is a starting point, the
same "heuristic safety net, not a formal guarantee" framing `ScopeGuardStage`
already carries — extend it as new catastrophic flags are found, same as that
stage.

## 7. Sandbox runner portability

`sandboxed_tool` is an eager decorator, applied at module-import time (e.g.
`hydra` gets built the moment `credentials.py` loads) — so there is no
"assembly time" moment for `build_toolkit()` to inject a runner into it. The
seam has to sit one layer lower, inside `run_sandboxed` itself, resolved at
*call* time:

```python
# cism/agent/tools/sandbox.py — additions

_default_runner: Runner = SubprocessRunner()

def set_default_runner(runner: Runner) -> None:
    global _default_runner
    _default_runner = runner

def run_sandboxed(argv, *, timeout=..., cwd=None, max_output=..., runner: Runner | None = None) -> str:
    active_runner = runner or _default_runner
    ...  # unchanged from here
```

`LangGraphAgent.__init__` (or `run_agent.py`, once real tools are opted into)
calls `set_default_runner(...)` once, before any tool runs. Every tool —
`CATALOG` row or `sandboxed_tool`-decorated function, built at import time or
assembly time — picks up whatever the current default is the next time it
executes. `BubblewrapRunner`, when it's built, is one call at startup, zero
changes to `build_catalog`, `sandboxed_tool`, or any of the ~50 tool
declarations. The explicit `runner=` parameter on `run_sandboxed` stays, for
tests that want to inject a fake runner without touching global state.

## 8. LLM-backed extraction

New class in `cism/depg/` (alongside `GenericExtractor`/`NmapExtractor`/
`HydraExtractor`), implementing the existing `CauseExtractor` protocol
unchanged — no signature, no existing extractor, no existing test touched.

```python
class ExtractedFinding(BaseModel):
    cause_class: str
    signal: str
    tier: Literal["T1", "T2", "T3"]
    verdict: Literal["alive", "dead"]
    evidence_quote: str   # exact substring of the tool's raw output backing this claim
    summary: str

class ExtractedFindings(BaseModel):
    findings: list[ExtractedFinding]

class LLMExtractor:
    def __init__(self, llm: BaseChatModel) -> None:
        self._llm = llm
        self._fallback = GenericExtractor()

    def extract(self, call, message, graph, target) -> Extraction:
        try:
            structured = self._llm.with_structured_output(ExtractedFindings)
            result = structured.invoke([HumanMessage(content=_PROMPT.format(output=message.content))])
        except Exception:
            return self._fallback.extract(call, message, graph, target)

        content = str(message.content)
        nodes = []
        for finding in result.findings:
            tier = finding.tier if finding.evidence_quote in content else "T3"
            nodes.append(Node(
                id=derive_node_id(finding.cause_class, target, finding.signal),
                cause_class=finding.cause_class, target=target, signal=finding.signal,
                evidence=[Evidence(
                    timestamp=_now(), tool=message.name or "unknown-tool",
                    exit_signal=finding.summary, tier=tier, verdict=finding.verdict,
                    call_id=call["id"] if call else message.tool_call_id,
                )],
            ))
        return Extraction(nodes=nodes) if nodes else self._fallback.extract(call, message, graph, target)
```

Key decisions, each with its reason:

- **Grounding is mechanical, not another LLM call.** `finding.evidence_quote
  in content` is a real substring check. Missing → clamp `tier` to `"T3"`
  rather than drop the finding — an unverified claim should stop pretending to
  be confident, not vanish.
- **Failure composes into the existing fallback, doesn't duplicate it.** Any
  exception — malformed structured output, the connector not supporting it,
  a network error — falls back to `GenericExtractor.extract(...)`, the exact
  same one-weak-T3-node behavior every tool already gets today. One failure
  path, reused.
- **The interface doesn't change.** `extract()`'s signature is identical to
  every other `CauseExtractor`. `LLMExtractor.extract()` blocks on
  `llm.invoke(...)` inside a synchronous call, same as `act`'s tool execution
  already blocks on a subprocess — no new async boundary, no changes to
  `depg_update`'s node signature or its tests.
- **Package boundary holds.** Only depends on `langchain_core.BaseChatModel`,
  an external type — not `cism.agent` or `cism.tui` — so `cism/depg` doesn't
  gain an internal coupling it didn't already have.
- **Dummy-backend case is explicit, not exception-driven.**
  `LangGraphAgent.__init__` picks the extractor default directly:

  ```python
  default_extractor = GenericExtractor() if self._endpoint == "local (dummy)" else LLMExtractor(self._llm)
  self._extractors = extractors or ExtractorRegistry(EXTRACTORS, default_extractor)
  ```

  Every existing test (all dummy-backed) keeps hitting `GenericExtractor`
  exactly as before — no new LLM calls, no new mocking infrastructure needed
  just to keep the suite passing. `LLMExtractor` only actually engages once a
  real connector is configured.

## 9. What this design does *not* touch

- `phase_router` / `DEFAULT_NEXT_PHASE` — still the placeholder heuristic it
  already is. `PHASES` (§4) answers a different question ("which tools does
  this phase offer") than phase transition does ("should we move phases at
  all"). There is currently no real phase-lock concept in this codebase
  (nothing gates reaching `EXPLOITATION` on DEPG evidence quality); if that's
  wanted, it's separate, new design, not something this document assumes.
- `MemoryStore.upsert`'s known issue (doesn't update `tier`/`phase_tag`/
  `snippet` on a repeat key) — out of scope here, a pre-existing defect from
  the DEPG/memory-bridge branch, not something this design introduces or
  depends on.
- `CauseExtractor`, `ExtractorRegistry`, `ToolRegistry`, `GuardrailChain`
  interfaces — all reused as-is. Nothing here required changing a shared
  protocol.

## 10. Migration: existing hand-written tools

- **`nmap`, `curl`** (`discovery.py`, `linux.py`) → become `CATALOG` rows.
  Both already use the free-form `options: str` shape that `allow_raw=True`
  exactly matches — no behavior change, just relocation.
- **`hydra`** (`credentials.py`) → becomes a `@sandboxed_tool`-decorated
  function instead of a raw `@tool` calling `run_sandboxed` directly. Its
  structured kwargs (`usernames`/`userlist`/`passwords`/`passwordlist`/
  `threads`) and scratch-dir wordlist materialization stay exactly as
  written — `sandboxed_tool` already supports a `scratch` parameter for
  exactly this shape. Not migrated to `allow_raw` — hydra's structured args
  are the right shape for it, free-form flags aren't needed here.
- Both migrations mean `discovery.py`/`linux.py`/`credentials.py` either
  shrink to nothing (their tools now declared in `catalog.py`) or, for
  `hydra`, keep only the decorated function — `tools/__init__.py` re-exports
  whatever remains, closing the "not even exported" gap named in §1.

## 11. Assembly

```python
# cism/agent/tools/base.py — new top-level factory

def build_toolkit(
    catalog: dict[str, ToolSpec],
    decorated_tools: list[BaseTool],
    extractors: dict[str, CauseExtractor],
) -> tuple[ToolRegistry, dict[str, str]]:
    """Returns the registry and a {name: binary} map for tool_help to use
    against decorator-declared tools, which have no CATALOG row of their own."""
    catalog_tools = build_catalog(catalog)
    help_tool = _build_help_tool(catalog, extra_binaries=_binaries_of(decorated_tools))
    registry = ToolRegistry([*catalog_tools, *decorated_tools, help_tool])
    return registry, extractors
```

`default_profiles()` (unchanged location, `cism/agent/profiles.py`) separately
calls `phases_for(spec)` per `CATALOG` entry to build each phase's
`tool_names` — kept as its own function rather than folded into
`build_toolkit`, since "which tools exist" and "which phase offers which
tool" are genuinely different concerns that don't need to live in one
mega-assembler.

## 12. Testing

- `catalog.yaml` loads into valid `ToolSpec`s for every current tool — a
  malformed row (bad `capability` literal, unknown `phases:` name) fails via
  `ValidationError` at import time, not silently at runtime.
- `EXTRACTORS` keys are a subset of `CATALOG` keys plus known decorator-tool
  names — one cheap test catches a typo at CI time instead of it silently
  falling through to the default extractor at runtime.
- `DangerousFlagGuardStage`: blocks each token in `_DANGEROUS_FLAG_TOKENS`
  individually; does not false-positive on a target/URL value containing `-o`
  as a substring (token match, not substring match).
- `tool_help`: routes through `run_sandboxed` (mockable the same way every
  other tool test already mocks it); falls back sanely for an unknown
  `tool_name`.
- `set_default_runner`/`run_sandboxed`: a fake `Runner` set as default is
  picked up by both a `build_catalog`-built tool and a `sandboxed_tool`-
  decorated one, without either being told about it explicitly.
- `LLMExtractor`: grounded finding keeps its tier; ungrounded finding clamps
  to T3; malformed/exception response falls back to `GenericExtractor`'s exact
  output; dummy-backend `LangGraphAgent` never invokes `LLMExtractor` at all
  (asserted via the same default-extractor selection in §8, not a mock count).
- Migrated `nmap`/`curl`/`hydra`: existing tests for their argv construction
  keep passing unmodified — behavior didn't change, only where they're
  declared.

## 13. Self-review

**Placeholder scan:** no TBD/TODO — every section has real code or a named,
justified deferral (§3).

**Internal consistency:** the phase-availability default policy (§4) matches
its stated rationale in §1 (why three files/registries became one YAML file
plus one small Python dict). `run_sandboxed`'s new default-runner resolution
(§7) is consistent with `LLMExtractor`'s untouched-interface claim (§8) —
neither changes an existing call signature other tests depend on.
`tool_help`'s exemption from phase gating (§5) doesn't contradict the
fail-closed default for `"executes"`/`"destructive"` tools (§4) — different
tools, different risk profile, stated explicitly. `EXTRACTORS` staying Python
while `CATALOG` moves to YAML (§4) doesn't contradict "add a tool in one
place" (§2) — a tool without a custom extractor never needs an `EXTRACTORS`
entry at all, so the common case really is one YAML block.

**Scope check:** one coherent design — tool declaration (now YAML-backed),
discovery, the one guardrail stage, sandbox portability, and LLM extraction
all compose into one `build_toolkit()` + one `ExtractorRegistry` default
decision, not six disconnected features bolted together.

**Ambiguity check:** the two decisions with real ambiguity (live-tools-by-
default, extraction model choice) are named as open and deferred in §3 with a
stated trigger for revisiting, not silently assumed either way.

**Cross-document propagation:** the original DEPG design spec
([2026-08-29-depg-basic-and-memory-design.md](2026-08-29-depg-basic-and-memory-design.md))
deferred two of this document's now-addressed items ("LLM-backed extraction,"
"externalizing the tool catalog to YAML/TOML") and named a third
("per-phase subagents") as the explicit trigger for revisiting §3's deferred
extraction-model-choice — that source document has been annotated to point
here, and this document points back to it (§3), so the decision trail reads
in both directions instead of only forward.
