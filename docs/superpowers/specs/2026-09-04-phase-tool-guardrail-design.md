# Phase-Tool Guardrail: Defense-in-Depth Capability Re-Check — Design

Phase 2 of 2. Phase 1 ([2026-09-04-bubblewrap-sandbox-runner-design.md](2026-09-04-bubblewrap-sandbox-runner-design.md)) builds the OS-level sandbox this design's guardrail backs up.

## 1. Why

`default_profiles()` already restricts which tools are *bound* per phase: `phases_for(spec)` (catalog-driven) plus `_DECORATED_TOOL_PHASES` (hydra) mean the LLM never even sees a destructive- or executes-capability tool as callable outside the phases that declare it. That's a real restriction, but it's a **binding-time** one — it constrains what the LLM is *offered*, not what can actually reach a subprocess.

The action `GuardrailChain` already re-checks calls independently of binding for two other concerns — `ScopeGuardStage` (target-in-scope) and `DangerousFlagGuardStage` (no sandbox-escaping flags) — precisely because binding-time restrictions and prompt correctness aren't a guarantee against a compromised or confused model: a prompt injection, a hallucinated tool name, or a future code path that constructs a `ToolCall` some other way could all bypass what `think`'s tool-binding step intended. Capability-vs-phase has no equivalent independent re-check today. This design adds one.

The original design sketch for this ([2026-08-29-depg-basic-and-memory-design.md §"Read/write/execute guardrails + sandbox"](2026-08-29-depg-basic-and-memory-design.md)) proposed three stages — `ReadGuard`/`WriteGuard`/`ExecGuard` — one per capability. This design deliberately replaces that with a single parameterized stage (§4), because three stages would each implement the identical check ("is this tool's capability allowed here") differing only in which capability they hardcode — and because deriving the allowed set from a second, hand-maintained place risks silently drifting from what `default_profiles()` already computes as ground truth for binding.

## 2. Goals

- A tool call for a tool not offered in the current phase is blocked at the guardrail-chain level, independent of whether it was ever legitimately bound — closing the gap between "the LLM wasn't offered this tool" and "this tool call cannot reach a subprocess."
- The guard's allowed set is derived from, and can never drift from, the exact same source that governs tool binding (`PhaseProfile.tool_names`) — not a hand-maintained parallel mapping.
- Every tool in the registry exposes its capability the same way, closing hydra's status as the one hand-written tool with no `.metadata` at all.
- Proven against the threat model that motivates it: a call for a tool that was never bound in this phase (simulating a hallucinated or injected tool name), not just the happy path of a correctly-bound call.

## 3. Non-goals (explicitly deferred, with the reason)

- **Egress control and input/output guardrail-chain stages.** Both are real, both are currently zero-coverage (`input`/`output` chains are pure `PassThroughStage` everywhere in this codebase today), and both are separate problems with their own shape decisions — named as their own follow-on designs, not folded in here.
- **Wiring a real `GuardrailSeam` into `LangGraphAgent`'s default construction.** This design produces a stage class and where it's built (`default_profiles()`); it does not make `LangGraphAgent()` use it by default. That remains the later live-tools-wiring milestone — and when that milestone is designed, real tools and a real (non-`no_op()`) `GuardrailSeam` must become available together, never one without the other, so it's structurally impossible to opt into live tool execution without also opting into the guardrails that were built to constrain it.
- **A fourth stage/branch for the `destructive` capability.** No catalog tool currently declares `capability: destructive`; the single parameterized stage design already covers it for free the moment one does (it's just another value in the allowed set), so no additional design work is needed now.

## 4. Design

### 4.1 `PhaseToolGuardStage`

```python
# cism/agent/guardrails/phase_tool.py

class PhaseToolGuardStage:
    """Independent re-check that the called tool is actually offered in
    this phase — same role ScopeGuardStage/DangerousFlagGuardStage play
    for their concerns. allowed_tool_names is the exact set this phase's
    PhaseProfile.tool_names computed for binding (plus tool_help, which
    make_think_node binds in every phase regardless of tool_names) — this
    stage re-derives "would this call have been bound here" rather than
    hardcoding a second copy of the answer."""

    name = "phase-tool-guard"

    def __init__(self, phase: Phase, allowed_tool_names: frozenset[str]) -> None:
        self._phase = phase
        self._allowed = allowed_tool_names

    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        if call["name"] not in self._allowed:
            return GuardrailResult(
                allowed=False,
                value=call,
                reason=f"{call['name']!r} is not offered in phase {self._phase.value}",
            )
        return GuardrailResult(allowed=True, value=call)
```

### 4.2 Construction site: `default_profiles()`

`profiles.py` already computes `tool_names` per phase from the catalog plus `_DECORATED_TOOL_PHASES`. `PhaseToolGuardStage` is built right there, from that same value, and attached via the existing (currently unused) `PhaseProfile.action_stages` seam:

```python
for phase in Phase:
    tool_names = ...  # exactly what's already computed for this phase
    profiles[phase] = PhaseProfile(
        tool_names=tool_names,
        action_stages=(PhaseToolGuardStage(phase, tool_names | {"tool_help"}),),
    )
```

No change to `GuardrailChain`, `nodes.py`, or the `action_chain = GuardrailChain(base_action_chain.stages + list(profile.action_stages))` line — that composition already exists and is simply populated for the first time.

### 4.3 `hydra` → `sandboxed_tool`

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

The function now returns only the argv tail — `sandboxed_tool` owns `run_sandboxed`, the scratch dir, and the `binary` prefix. `_materialize`/`_cred_flag`/`_WORDLISTS` are unchanged. `run_sandboxed`/`scratch_dir` imports are dropped from `credentials.py` (no longer called directly). This retires the defensive `(tool.metadata or {})` guard in `_binaries_of` (`base.py`) — every tool now has real metadata, so the fallback becomes unreachable but is left in place rather than removed, since `_binaries_of` still needs to handle a tool with metadata missing a `binary` key in principle.

`_DECORATED_TOOL_PHASES` in `profiles.py` is unaffected — capability and phase-availability are separate axes, and `executes` defaults to zero phases (fail-closed), so hydra still needs its explicit phase override regardless of how its capability is exposed.

## 5. Testing

- **Happy path:** a call to a tool that *is* in the current phase's allowed set passes through unchanged.
- **Adversarial — the actual threat model:** a `ToolCall` naming a tool that exists in the registry but isn't offered in the current phase (e.g. a `hydra` call while `phase=Phase.RECON`) is blocked, simulating a hallucinated or injected call that never went through legitimate binding.
- **Adversarial:** a `ToolCall` naming a tool that doesn't exist in the registry at all is blocked (falls out of the `allowed` set check with no special-casing needed).
- **`tool_help` exemption:** a `tool_help` call passes in every phase, matching its bind-time exemption in `make_think_node`.
- **Integration:** `default_profiles()` produces a `PhaseToolGuardStage` per phase whose `allowed_tool_names` matches that phase's own `tool_names | {"tool_help"}` exactly — proving the guard can't drift from binding by construction, not just by convention.
- `hydra` conversion: existing `test_tool_argv.py` hydra tests updated for the new invocation path (mocking wherever `sandboxed_tool`'s `_run` calls `run_sandboxed`, rather than `credentials.run_sandboxed` directly); a new assertion that `credentials.hydra.metadata == {"capability": "executes", "binary": "hydra"}`.
