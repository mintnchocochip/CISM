# CISM — Known Gaps &amp; Next-Phase Roadmap

Compiled 2026-09-08. Every item below was verified against either the actual
code (file:line) or an explicit "deferred"/"out of scope" note in a design
doc under `docs/superpowers/specs/` — nothing here is a guess. Where a design
doc already tracked something as deferred, that doc is cited rather than
re-litigated; where I found something during the live-test readiness review
that no doc had named yet, it's marked **(new finding)**.

This is a backlog, not a plan — nothing here has been through brainstorming/
design yet. Treat "Suggested priority" as a starting opinion, not a decision.

## How to use this doc

Pick an item, run it through the normal flow (`superpowers:brainstorming` →
design doc → `superpowers:writing-plans` → implementation). When an item
ships, move it to "Resolved" at the bottom with the commit/PR that closed it,
the way `2026-09-06-guardrail-bypass-followup-design.md` and this session's
own TUI-design-doc edit already did — don't delete history, mark it closed.

---

## 1. Security — the highest-leverage gaps now that `--live-tools` is real

Everything in this section became a *live* concern only once real tool
execution was wired in (this session). Before that, these guardrail gaps
existed only on paper.

### 1.1 `GuardrailSeam.input`/`.output` are still pass-through
**Impact: High.** No defense against indirect prompt injection (a scanned
target's HTTP response, banner, or DNS record containing text that
manipulates the next `think` turn) and no input-side guardrail at all.
Named as deferred in three separate docs:
`2026-09-04-phase-tool-guardrail-design.md` §3, `2026-09-06-guardrail-bypass-followup-design.md`
§3, `2026-09-08-live-tools-and-guardrail-wiring-design.md` §3. Confirmed
still true in code: `GuardrailSeam.no_op()` and this session's
`_enable_live_tools()` both only build a real `action` chain
(`cism/agent/guardrails/chain.py:109-122`, `run_agent.py`'s
`_enable_live_tools`).
**Suggested priority: do next.** This is the single biggest gap between
"tools run sandboxed" and "the agent is actually safe to point at a
real target," now that tool output genuinely flows back into context.

### 1.2 DEPG/memory poisoning via injected content
**Impact: High, same root cause as 1.1.** Same injected content that isn't
sanitized on the output leg can also mutate DEPG nodes/memory rows that
persist across the whole run. Named deferred in
`2026-09-04-phase-tool-guardrail-design.md` §3. No design exists yet for
what "sanitizing" would even mean here (content classification, not
argument inspection — a materially different problem than the guardrails
already built).

### 1.3 Network egress control
**Impact: Medium-High.** `BubblewrapRunner` shares the host network fully
(`--share-net`, no netns/nftables, no L7 proxy) — a sandboxed tool can reach
anywhere the host can, regardless of declared `--scope`. Explicitly scoped
out of the sandbox design as its own, larger piece of engineering:
`2026-09-04-bubblewrap-sandbox-runner-design.md` §3 ("network-namespace +
nftables rules... a materially bigger, separate piece of engineering"),
reaffirmed in `2026-09-04-phase-tool-guardrail-design.md` §3 and
`2026-09-08-live-tools-and-guardrail-wiring-design.md` §3.
**Suggested priority: after 1.1** — `ScopeGuardStage` is the only thing
enforcing scope today, and it's a heuristic on argv text, not an OS-level
boundary.

### 1.4 `DangerousFlagGuardStage` is a denylist, not an allowlist grammar
**Impact: Medium.** The security audit's own conclusion
(`2026-09-06-guardrail-bypass-followup-design.md` §3): curl alone has ~250
long options, and a denylist structurally can't cover all of them. 13
concrete bypasses were found and patched in that same document (all fixed —
see Resolved section), but the *class* of bug isn't closed, only every
instance found so far. Deferred pending "a fourteenth variant" surfacing.
**Suggested priority: low urgency, but track** — revisit if any new bypass
is found rather than patching indefinitely.

### 1.5 Resource-limit/DoS guardrails
**Impact: Low-Medium, deliberately unaddressed.** Nothing stops e.g.
`nmap --min-rate 100000 -p-` flooding a target/local network. Named in
`2026-09-04-phase-tool-guardrail-design.md` §3 as "plausibly intentional
given the tool's actual purpose" — worth an explicit decision (rate-limit
by default? require an opt-in flag for aggressive scans?) rather than
leaving it implicit.

### 1.6 Full RWX (read/write/execute) capability guardrail system
**Impact: Low — substantially achieved by a different mechanism than
originally sketched.** The original DEPG design (§"Read/write/execute
guardrails + sandbox") envisioned dedicated `ReadGuard`/`WriteGuard`/
`ExecGuard` stages. What actually shipped is different but covers the same
ground: `catalog.yaml`'s capability defaults
(`cism/agent/tools/catalog.py` — `reads` → recon/enumeration/vuln-discovery;
`writes`/`executes`/`destructive` → no phase unless explicitly listed) gate
which tools even get offered per phase, and `PhaseToolGuardStage`
(`cism/agent/guardrails/phase_tool.py`) re-checks that at call time. Worth
a note in the DEPG design doc that this is resolved-differently, not
worth new implementation work.

---

## 2. Agent correctness

### 2.1 `phase_router` is a placeholder heuristic **(design doc already says so, verified in code)**
**Impact: Medium-High — this is core to whether phase progression means
anything.** `make_phase_router()` (`cism/agent/nodes.py:244-260`) advances to
`DEFAULT_NEXT_PHASE[current]` purely on "did the last tool call not error" —
no DEPG evidence quality, no assessment of whether the phase's actual goal
was met. Confirmed still true; named explicitly in
`2026-09-01-unified-toolkit-and-llm-extraction-design.md` §9: *"There is
currently no real phase-lock concept in this codebase (nothing gates
reaching `EXPLOITATION` on DEPG evidence quality)."*
**Suggested priority: high** for a VAPT agent specifically — advancing to
`EXPLOITATION` just because the last `nmap` call happened to succeed is a
real correctness gap, not a nice-to-have.

### 2.2 `MemoryStore.upsert` doesn't update on a repeat key **(new finding, confirmed against code — this is a real bug, not a deferred feature)**
**Impact: Medium.** `MemoryStore.upsert` (`cism/memory/store.py:40-50`)
increments `hits` on a matching key but never updates `tier`, `phase_tag`,
or `snippet` — so if the same memory key recurs with a different tier or
updated snippet text, the stale original values persist forever, only the
hit count moves. Already named as a known, pre-existing defect in
`2026-09-01-unified-toolkit-and-llm-extraction-design.md` §9 ("out of scope
here... not something this design introduces or depends on") but never
fixed. **This is the one item in this report that's an actual bug, not a
deferred feature** — worth fixing on its own, independent of any bigger
phase of work.

### 2.3 No graph/state persistence
**Impact: Low for a demo/solo tool, High if this ever needs to survive a
restart or run concurrent engagements.** No LangGraph checkpointer, no
resume-across-restart, no per-engagement keying if two runs happened at
once. Explicitly deferred as "a genuinely separate subsystem" in
`2026-08-29-real-llm-connector-wiring-design.md` ("Out of scope"). Confirmed
no checkpointer anywhere (`build_graph()` calls `.compile()` with no
`checkpointer=`).

---

## 3. DEPG accuracy (the graph works, these are precision gaps — see §12 of `2026-08-29-depg-basic-and-memory-design.md`, all still true)

| Gap | Impact | Note |
|---|---|---|
| IP ↔ hostname aliasing | Medium | Same host scanned by IP and by name = two separate DEPG subgraphs, not one. Requires an alias map + graph rewrite when a mapping appears. |
| `inconclusive` observations don't lower confidence | Low-Medium | Currently a no-op; recorded on the evidence log so it's reversible when addressed. |
| γ / graded propagation | Low | `Edge.weight` (`cism/depg/edge.py:22`) is stored but inert — propagation is binary (a precondition is live or dead), not a soft weakening. |
| LLM/embedding node-reconciliation pass | Low | No automatic merge-suggestion for near-duplicate nodes; the identity key stays purely deterministic (by design — keeps the LLM out of it). |
| Generic-fallback false-split | Accepted, not a bug | A tool with no dedicated extractor can produce two DEPG nodes for what's really one cause-class. Accepted as a safe failure; fixed per-tool by adding a real extractor (only `nmap`/`hydra` have one today — see §5 below). |

---

## 4. TUI — command gaps **(found this session, now fully fixed)**

Tracked in full detail in `docs/superpowers/specs/2026-08-02-cism-tui-design.md`,
"Implementation status" note under "Slash commands".

- **`/target`, `/phase`** — ✅ fixed 2026-09-08. Both now intercepted in
  `LangGraphAgent.submit()` (`cism/agent/core.py`), `/phase` going through
  the real `PhaseStateMachine.transition()` with full legality checking,
  not a bypass. 6 new tests in `tests/test_langgraph_agent.py`.
- **`/replay <run_id>`, `/ablate <part>`** — ✅ fixed 2026-09-09. See
  Resolved section below and the design doc's "Implementation status" note.

---

## 5. Tool catalog gaps

### 5.1 `msfconsole` has no live implementation **(new finding)**
**Impact: Medium, if anyone expects it to work.** `dummy_msfconsole`
(`cism/agent/tools/dummy.py`) exists purely for the dummy pipeline —
Metasploit was never added to `catalog.yaml`, and nothing in
`build_toolkit()`'s inputs (`CATALOG` + `[hydra]`) references it. In
`--live-tools` mode, the LLM has no `msfconsole` tool at all; if prompted
to expect one, it'll either hallucinate a call that fails to resolve in
`ToolRegistry`, or just not use it. Needs a decision: add it for real
(bigger lift — Metasploit's RPC/console interface doesn't fit
`build_catalog`'s flat flags-and-target shape any more than `hydra` did),
or remove `dummy_msfconsole` so the dummy pipeline doesn't imply a
capability that was never built.

### 5.2 Extractor coverage: only `nmap`/`hydra` have dedicated extractors
**Impact: Low — has a real, working fallback.** `curl`/`nikto`/`whatweb`/
`dnsenum`/everything else falls back to `LLMExtractor` (real, not a stub)
or `GenericExtractor` in dummy mode. Less precise than a hand-written
regex extractor, more prone to the "generic-fallback false-split" noted in
§3 above. Extend per-tool as usage shows it's needed (per the original
design's own stated approach — graduate a cause-class to a real extractor
when it earns it).

### 5.3 Environment note, not a code gap: `hydra`/`nikto`/`whatweb`/`dnsenum` not installed in this dev environment
Confirmed via `which` during the live-test readiness review. Doesn't block
anything — `BubblewrapRunner` fails closed per-call with
`ToolNotInstalledError` if the LLM tries to invoke a missing binary. Only
matters for what a live test can actually exercise here (`nmap`/`curl`
only, until the others are installed).

---

## 6. Smaller, explicitly-left-open design questions

From `2026-08-29-real-llm-connector-wiring-design.md` "Left open":

- **Real reasoning/"thinking" content extraction** — blocked on an upstream
  `langchain-openai` bug ([langchain-ai/langchain#35516](https://github.com/langchain-ai/langchain/issues/35516)
  et al.), not a local decision. Revisit when that's fixed, or as a
  deliberate decision to add a second, Ollama-native client path just for
  this.
- **Whether a finished streamed answer should auto-collapse past some
  length** — currently always expanded, no decision to revisit this
  without a concrete reason.
- **`CISM_LLM_KEY_ENV_VAR` naming** — kept as indirection for symmetry with
  the CLI/`/api`/`/model` paths; revisit if nobody ever points it anywhere
  but `CISM_API_KEY` in practice.
- **A combined `/connect` command** replacing separate `/api`/`/model`
  — considered, dropped, matches current docs. Not a gap, just recorded so
  it isn't re-proposed without knowing it was already decided against.
- **`/scope <cidr>` as a TUI command** — considered and dropped in
  `2026-08-02-cism-tui-iteration-design.md` ("Out of scope"): engagement
  scope belongs in the agent (now: `run_agent.py --scope`), not the display
  layer. Same reasoning — recorded, not a gap.

---

## 7. Larger architectural directions (not gaps — deliberate future work)

- **Per-phase subagents.** Sketched in `2026-08-29-depg-basic-and-memory-design.md`
  ("Per-phase subagents" section) as the natural next step once "a real
  model shows one shared graph cannot serve all six phases well." Also
  named as the trigger for revisiting `LLMExtractor`'s shared-model choice
  (`2026-09-01-unified-toolkit-and-llm-extraction-design.md` §3). Not
  started; explicitly gated on live-test signal, which is now finally
  possible.
- **A separate, smaller model for `LLMExtractor`** — currently reuses the
  main agent's `self._llm`. Same live-test-signal gate as above.

---

## Suggested phase ordering (my opinion, not a decision)

1. **`MemoryStore.upsert` bug fix** (§2.2) — small, independent, actually a bug.
2. **Live test itself** (already scoped in `2026-09-08-live-tools-and-guardrail-wiring-design.md`, not repeated here) — the highest-value thing that isn't a code gap at all.
3. **Output-leg guardrail** (§1.1) — now the single biggest real security gap.
4. **`phase_router` evidence-driven gating** (§2.1) — core correctness for a VAPT agent.
5. Everything else, prioritized by what the live test actually surfaces — several items above (extraction quality, per-phase subagents, DEPG reconciliation) are explicitly gated on "see what a real run shows" rather than guessable in advance.

---

## Resolved (moved here as items close)

- **Finding 8 — nothing wires a real `GuardrailSeam`/toolkit into
  `LangGraphAgent`.** Fixed 2026-09-08: `run_agent.py --live-tools` wires
  `BubblewrapRunner`, the real toolkit, and a real `ScopeGuardStage`+
  `DangerousFlagGuardStage` action chain. See
  `2026-09-08-live-tools-and-guardrail-wiring-design.md` and
  `docs/superpowers/plans/2026-09-08-live-tools-and-guardrail-wiring.md`.
- **`/target`, `/phase` slash commands not intercepted.** Fixed 2026-09-08.
  See §4 above.
- **Test suite wall-clock time (130s serial).** Fixed 2026-09-08:
  `pytest-xdist` added, `pytest -n auto` → 58s, documented in README.
- **13 guardrail bypass findings (scope-check encoding tricks, curl
  flag-abbreviation/bundling bypasses, nmap scope-escape flags, comma-list
  partial-parse, IPv4-mapped-IPv6, malformed CIDR, exception-aborts-run).**
  All fixed — see `docs/superpowers/plans/2026-09-06-guardrail-bypass-followup.md`
  (all tasks checked complete) and the priority-summary table in
  `2026-09-06-guardrail-bypass-followup-design.md` §7.
- **No auditable run log — `TokenDelta`/`ModelInfo.context` dead code.**
  Fixed 2026-09-09, two parts:
  - `cism/agent/logging.py` already had a TTL'd JSONL logger wired into
    `core.py`, used for exactly one "run started" line. `LangGraphAgent._emit`
    is now the single choke point every `AgentEvent` passes through — each
    one logged (via `cism.tui.events.encode`) alongside being put on the TUI
    queue, so the audit log is always exactly what the TUI saw. Retention
    bumped 1 day → 3.
  - `TokenDelta` was fully defined, with the status bar already reading it,
    but nothing ever constructed one. `build_chat_model` now defaults
    `stream_usage=True` (confirmed live against Ollama), and `core.py` turns
    the resulting `usage_metadata` into a `TokenDelta` per LLM call.
    `ModelInfo.context`/`ctx_max` were hardcoded/guessed; added
    `discover_context_window` (best-effort probe of Ollama's native
    `/api/show`, `None`-safe for any other server) — confirmed live:
    gemma4:e4b's real 131,072, not the old 32,768 guess.
- **`act()` (`cism/agent/nodes.py`) froze the whole TUI during any real tool
  call.** Root cause: `act()` was a plain sync function calling
  `tool.invoke(call)` directly — a real tool call bottoms out in a blocking
  subprocess (`sandbox.py`, up to 60s), and since `act` had no async twin,
  LangGraph ran it in-place on the same event loop Textual's own worker
  runs on, freezing all input/repaint for the call's duration. Explains
  "freezes, especially when I've stepped away" reports exactly: a fast
  localhost scan is imperceptible watching it directly. Fixed 2026-09-09:
  `act()` is now `async def` and awaits `tool.ainvoke(call)`, which
  `BaseTool`'s default async fallback already offloads to a thread — no
  change needed to `sandbox.py` or the tool catalog. Direct regression test
  in `tests/test_nodes.py` runs a slow tool concurrently with a fast
  asyncio ticker and asserts the ticker keeps advancing throughout.
- **`/replay <run_id>`, `/ablate <part>` slash commands unimplemented.**
  Fixed 2026-09-09, once the audit-log work above gave `/replay` somewhere
  real to read from:
  - `read_run_events(run_id)` (`cism/agent/logging.py`) pulls one run's
    exact slice out of the audit log (spanning a midnight rotation if
    needed); `_replay` (`cism/agent/core.py`) decodes it back into real
    `AgentEvent`s (`cism.tui.events.decode`) and replays them into the
    session's queue — pure playback, no tool or model call — bracketed by
    narrations, seq renumbered fresh per event via the shared counter
    (an earlier cut used `rebase()`'s offset+index arithmetic instead,
    which only reserves one counter value and collided with the
    end-of-replay markers — caught live, not by any mocked test), closing
    by re-asserting the real current phase.
  - `/ablate <name>` toggles a tool name or any of the three guardrail
    chains' stage `.name`s into a pending set that `_run` consumes and
    clears at the start of the very next run only, building a one-off
    filtered `ToolRegistry`/`GuardrailSeam`/graph without ever mutating the
    agent's real ones. `think()` already filters bindable tools against the
    registry it's given, so an ablated tool is never offered to the model,
    not merely blocked after the fact.
  - 9 new tests in `tests/test_langgraph_agent.py`, 4 in
    `tests/test_agent_logging.py`. See the design doc's "Implementation
    status" note for the full account, including the live-caught bug.
