# DEPG basic version + memory bridge — design

Date: 2026-08-29
Status: proposed
Supersedes (in part): the DEPG portions of
`2026-08-15-agent-workflow-skeleton-design.md`

## 1. Goal

Turn the DEPG (Dependency / Error-Propagation Graph) from a placeholder that
stamps one generic, unlabeled node per successful tool call into a real graph
that: distinguishes findings by what they are, links them by the precondition
each depended on, tracks failures and lets a dead precondition propagate
forward, and prunes fully-dead branches without losing their provenance. In
parallel, wire a live agent run to populate the memory view — today only the
replay demo does — sourcing memory from more than just DEPG nodes.

The DEPG is the project's stated novelty. Everything else here (nodes, phases,
guardrails) exists to serve it.

## 2. Scope

In scope:

- The Node / Edge / Evidence field schema, with a deterministic identity key.
- State as a derived function (the reducer), recomputed — never latched.
- Dirty-frontier propagation (settle), prune of dead regions, DAG enforcement.
- Normalization rules for the identity key, and where an LLM does / does not
  belong in that pipeline.
- Two real cause-class extractors — `open-port` (nmap) and `credential-found`
  (hydra) — plus the generic fallback.
- The precondition edge-creation rule.
- A `memory_update` graph node bridging step context into memory rows.
- The `contested` node state added to the wire contract.
- A phase-parameterized `think` node via `PhaseProfile` (per-phase prompt +
  tool subset + action stages).
- A `SupportPolicy` seam in the reducer, so graded γ-propagation is a later
  drop-in, not a rewrite.
- A tool-authoring layer (§15): a kwargs-based `ToolSpec` data catalog for the
  common CLI shape, a `sandboxed_tool` decorator escape hatch, and capability
  tags born on each tool.

Out of scope (captured in §12, the deferred log):

- Read/write/execute guardrails and OS-level sandboxing (a separate
  guardrail + sandbox workstream).
- Per-phase subagents (documented as a future direction with a spec sketch).
- γ / graded propagation math (edge `weight` is reserved but inert here).
- LLM-backed extraction for the long-tail tool catalog, and an LLM/embedding
  node-reconciliation pass.
- IP ↔ hostname aliasing.
- `inconclusive` observations lowering confidence.
- Externalizing the tool catalog to YAML/TOML (kept as typed Python rows for
  now; a factory-read change later, the author's call).

## 3. Architecture

One agent (`LangGraphAgent`), one graph, six nodes, one real branch point.
"Multiple agents" is a future restructure (§12), which is why `depg/` and
`memory/` are standalone modules the graph topology can change around.

```
   user text ──▶ core.py ──(input guardrail)──▶ START
                                                  │
                                                  ▼
                                              ┌────────┐   route_after_think:
                                              │ think  │───┬───────────────┬───────────┐
                                              │ (phase)│   │ tool calls    │ none / cap │
                                              └────────┘   │ & under cap   │ hit        │
                                                  ▲        ▼               ▼
                                                  │     ┌──────┐        ┌────────┐
                                                  │     │ act  │◀(action│ respond│◀(output
                                                  │     └──────┘ guard) └────────┘ guard)
                                                  │        │               │
                                                  │        ▼              END
                                                  │  ┌─────────────┐
                                                  │  │ depg_update │ extract → settle → prune
                                                  │  └─────────────┘
                                                  │        │
                                                  │        ▼
                                                  │  ┌──────────────┐
                                                  │  │ phase_router │ legal PTES move only
                                                  │  └──────────────┘
                                                  │        │
                                                  │        ▼
                                                  │  ┌──────────────┐
                                                  └──│ memory_update│ step context → rows
                                                     └──────────────┘
```

Routes: exactly one conditional (`route_after_think`, two branches) plus the
fixed loop `act → depg_update → phase_router → memory_update → think`. Loop
termination is governed by the turn cap (`MAX_AI_TURNS`), not a second branch.

### Module map — who owns what

| Module | Owns | Called by |
|---|---|---|
| `agent/core.py` — `LangGraphAgent` | the graph, the event queue, the TUI `Agent` seam, the input guardrail (pre-graph) | the TUI |
| `agent/graph.py` — `build_graph()` | wiring nodes + routes (pure factory) | core |
| `agent/profiles.py` — `PhaseProfile`/`PhaseProfiles` | per-phase prompt, tool subset, action stages | `think`, `act` |
| `agent/nodes.py` | the six node functions | graph |
| `agent/llm.py` | `DummyChatModel` / real OpenAI-compat model | injected into `think` |
| `agent/tools/` | `ToolRegistry`, `run_sandboxed`, tools | `act` |
| `agent/guardrails/` | input / action / output chains | core, `act`, `respond` |
| `depg/` (the novelty) | Node/Edge/Graph, settle, prune, Evidence, extractors, `normalize_target` | `depg_update` |
| `memory/` (new module) | salience/tiering, `MemoryRow` construction | `memory_update` |

### The nodes

- **`think(phase)`** — phase-parameterized through a `PhaseProfile` (see §3.1):
  the profile for the current phase supplies the system prompt and the tool
  subset. Nodes never branch on phase themselves — they read the profile — so
  the graph stays uniform. `phase_router` remains the seam where a phase's
  profile is later handed to a real subagent instead of the shared `think`.
- **`act`** — runs each tool call through the action guardrail, then executes
  it; produces success or error `ToolMessage`s. Unchanged in shape.
- **`depg_update`** — routes results to extractors → facts → nodes/edges →
  `settle()` → `prune()`. Emits `DEPGUpdated`. This is where all DEPG work
  lives. Unlike today, it does **not** skip error results — a failure becomes
  a node (§5, §7).
- **`phase_router`** — proposes one legal PTES phase move. Unchanged.
- **`memory_update`** (new) — turns the step's context into `MemoryRow`s
  (§10). Emits `MemoryUpdated`. Runs after `phase_router` so it can reuse the
  tiers/verdicts DEPG just computed and tag rows with the resulting phase.
- **`respond`** — final text through the output guardrail → END. Unchanged.

Deliberate split the design leans on: **`depg_update` records findings about
targets; `memory_update` records everything the agent experienced.** A
guardrail block is not a finding — it reaches memory but never the graph.

### 3.1 Phase profiles

One profile per phase, data-driven; `think`/`act` consume a registry and never
branch on phase:

```python
@dataclass(frozen=True)
class PhaseProfile:
    phase: Phase
    system_prompt: str
    tool_names: frozenset[str]                       # subset drawn from the registry
    action_stages: tuple[GuardrailStage, ...] = ()   # phase-specific, appended to the base chain

class PhaseProfiles:
    def get(self, phase: Phase) -> PhaseProfile: ...
```

`make_think_node(llm, profiles)` selects the prompt + tools by current phase and
binds them; `make_act_node(registry, base_chain, profiles)` runs the base action
chain plus the profile's stages. Adding a phase is a profile entry; promoting one
to a subagent later hands that same profile off at `phase_router`.

## 4. Schema

Working copy (`cism/depg/`), richer than the frozen wire format. `to_event()`
projects down, exactly as the existing working-Node / wire-DEPGNode split does.

```python
Verdict = Literal["alive", "dead", "inconclusive"]
#   alive        — this observation confirms the finding holds (port open, login worked)
#   dead         — this observation confirms it's gone/failed (port closed, brute-force exhausted)
#   inconclusive — a direct look that decided nothing (port "filtered"); must NOT flip anything

@dataclass(slots=True)
class Evidence:
    timestamp: str
    tool: str
    exit_signal: str          # summary shown in the DEPG evidence table
    tier: Tier                # T1/T2/T3 — STRENGTH only (see reducer), not survival
    verdict: Verdict          # NEW — what this single observation asserts
    call_id: str              # NEW — provenance; the tool_call_id (was Node.id)

@dataclass(slots=True)
class Node:
    # identity (ground truth, immutable once created)
    id: str                   # derived: f"{cause_class}:{target}:{signal}"
    cause_class: str
    target: str
    signal: str
    phase: str                # PTES phase active when first observed

    # ground truth (append-only)
    evidence: list[Evidence] = field(default_factory=list)
    decision: Decision | None = None

    # DERIVED — written ONLY by Graph.settle(); never by an extractor
    state: NodeState = "untested"    # untested | resolved | blocked | contested
    generality: float = 0.0           # γ — reserved, still a placeholder
    downstream: int = 0               # reachable-downstream count, recomputed

@dataclass(slots=True)
class Edge:
    parent: str
    child: str
    weight: float = 1.0       # RESERVED — inert in the basic reducer (§12).
                              # The seam for graded γ-propagation later.
```

`Node.id` is a **derived key**, not the tool_call_id anymore. The old id
(`tool_call_id`) moves into `Evidence.call_id` so per-call provenance survives
merges. `state` is cached, not stored ground truth: the only writer is
`settle()`. Any mutation must go through `upsert_node` / `add_edge` (which mark
the node dirty) or the cache lies — enforced by keeping those the only public
mutators.

## 5. State reducer

`state` is never assigned by an extractor. It is computed here, the only place
it changes. The one weight-sensitive decision — whether a node is still
supported — is an injected policy, so graded γ-propagation later is a new policy
class, not a reducer rewrite:

```python
class SupportPolicy(Protocol):
    def supported(self, node: Node, parents: list[Node]) -> bool: ...

class BinarySupport:                       # basic: a parent is live or dead, weight ignored
    def supported(self, node, parents):
        return not parents or any(p.state != "blocked" for p in parents)

def reduce_state(node, parents, support: SupportPolicy) -> NodeState:
    D = latest verdict in node.evidence that is "alive" or "dead"   # else: inference ("none")
    ok = support.supported(node, parents)

    if D == "dead":            return "blocked"      # own failure — sticky
    if D == "alive" and ok:    return "resolved"
    if D == "alive":           return "contested"    # own proof, every precondition dead
    if D is None and ok:       return "untested"     # plausible inference
    return "blocked"                                  # inference, no live parent → propagated
```

Two properties make this correct and cheap:

- **Topological order makes the local check global.** When `settle` processes
  a node, its parents are already settled, so `any(p.state != "blocked")` on
  *immediate* parents is exactly transitive reachability-to-a-live-root. No
  separate graph walk.
- **`block_cause` is implied, not stored.** `blocked` with `D == "dead"` is
  *direct* (sticky — only new direct evidence of that node revives it);
  `blocked` with `D is None` is *propagated* (auto-revives when a parent
  revives). This is what makes re-open (a parent comes back) and
  self-inflicted failure (stays dead despite an upstream fix) both fall out of
  one function.

`inconclusive` observations are ignored by the reducer for now (they never set
`D`). Whether they should instead lower confidence is deferred (§12); the
verdict is still recorded on the evidence log so the choice is reversible.

This replaces the old `upsert_node` invariant ("state only ever advances away
from untested"). Evidence still accumulates as it does today; state stops being
latched and becomes derived, in both directions.

## 6. Propagation (settle), prune, DAG

```python
class Graph:
    nodes: dict[str, Node]
    edges: list[Edge]
    _children: dict[str, list[str]]   # adjacency index for the dirty walk
    _dirty: set[str]

    def upsert_node(self, node):   # route by id → append evidence, mark id dirty
    def add_edge(self, edge):      # reject if it creates a cycle (keep DAG); mark child dirty
    def settle(self):             # process _dirty in topological order:
                                  #   recompute each via reduce_state;
                                  #   unchanged → drop; changed → enqueue its _children.
                                  #   cost = O(subgraph that actually moved)
    def prune(self):              # collapse fully-BLOCKED regions into one marker,
                                  #   retaining tombstone provenance
    def to_event(self): ...
```

- **Dirty-frontier only.** `settle` never recomputes the whole graph. An
  observation that confirms existing state touches one node and stops (early
  exit when state is unchanged). A cascade/resurrection touches only the
  affected chain. Worst case (everything flips) is one topological pass,
  `O(N+E)` — the same budget already paid to serialize `DEPGUpdated` each step.
  At pentest scale this is microseconds against seconds-long tool calls.
- **One settle per graph-step.** `depg_update` applies all of a step's
  evidence and edges, then calls `settle()` once — not once per observation.
- **DAG enforced.** `add_edge` rejects any edge that would create a cycle, so
  topological processing is always well-defined and `settle` cannot spin. A
  genuinely cyclic enablement is dropped (accepted limitation, §12).
- **Prune fires only on fully-dead regions.** A subtree every node of which is
  `blocked` collapses to one dead-region marker; a region containing any
  `contested`/`resolved`/`untested` node is left intact. Pruning never deletes
  tombstone provenance ("we tried this, don't retry").

## 7. Normalization and the identity key

Guiding principle: **the identity key holds only the minimal stable, discrete
token; everything descriptive or volatile goes into the evidence log.** If a
token can come back phrased differently on an identical re-observation, it is
evidence, not identity.

### Target (shared `normalize_target()`, all cause-classes)

Cheap lossless transforms only: lowercase; trim; strip scheme
(`ssh://10.0.0.5` → `10.0.0.5`); strip trailing dot; **drop the port** (a host
is one host; ports are findings on it, not host identity). No DNS resolution —
IP ↔ hostname reconciliation is deferred (§12); until then the same host under
two names lives as two subgraphs.

### Signal (per cause-class, inside each extractor)

| cause_class | signal | pushed to evidence instead | reliability |
|---|---|---|---|
| `open-port` | `{port}/{proto}` (e.g. `22/tcp`) | service name, version banner | solid — ports are stable discrete tokens |
| `credential-found` | exact `{user}:{password}`, **no case folding** | the service/port it worked on (a provenance edge, not identity) | solid — exact match; merges the same credential across ports |
| generic (fallback) | short hash of the summary after stripping whitespace + obvious timestamps/durations | full raw output | best-effort — may false-split |

`open-port` keys on `port/proto`, not the banner, or two scans that fingerprint
the service slightly differently would split one port into two nodes.
Credentials get no case folding (passwords are case-sensitive) and no
service/port in the key (so the same credential merges across the ports it
works on). The generic fallback can false-**split** (same finding, differently
worded output → two T3 nodes); this is the *safe* failure — a hash cannot
false-*merge* two different findings, and false-split is low-stakes clutter. A
cause-class graduates from generic to a real extractor the moment it matters.

### Where the LLM belongs

Normalization is two jobs with opposite LLM verdicts:

1. **Unstructured output → structured fact.** Benefits from intelligence. A
   hybrid regex + small-LLM extractor is appropriate for the messy long-tail
   tool catalog — and a small local model is on-brand for an SLM-driven
   project. Basic does **not** need it: nmap (`-oX`) and hydra have structured
   output modes. The `CauseExtractor` protocol already lets an `LLMExtractor`
   drop in later behind the same interface (deferred, §12).
2. **Structured fact → identity key.** Must be a **pure deterministic
   function, never an LLM.** Non-determinism reintroduces the exact false-split
   bug the key exists to kill, breaks record/diff/replay, adds hot-path cost,
   and — worst for an offensive tool — an LLM can hallucinate a finding that
   isn't there, poisoning the graph with fake nodes. The LLM sits *upstream*
   of the key (getting the fact out), never *in* it.

A third, later home for the LLM: semantic node **reconciliation** (aliasing,
fuzzy dedup) as a separate, reversible merge-proposal pass over existing nodes
— keeping non-determinism in an auditable suggestion layer, out of ground-truth
identity (deferred, §12).

## 8. Cause-class extractors

`CauseExtractor` protocol unchanged. Registered for basic:

- **`NmapExtractor`** → `open-port` nodes, one per open port, `verdict="alive"`,
  tier **T2**. `signal = "{port}/{proto}"`. Reads structured output.
- **`HydraExtractor`** → `credential-found` on success (`verdict="alive"`, tier
  **T1**, `signal = "{user}:{password}"`); on failure a node with
  `verdict="dead"`, tier **T3** (the tombstone).
- **`GenericExtractor`** (default) → one node per successful call,
  `verdict="alive"`, tier **T3**, hashed signal.

Tier convention (written down because it didn't exist): generic / uninterpreted
→ T3; real extractor parsing structured output but not confirming exploitability
→ T2; real extractor confirming actual access/exploitation → T1. Tier is
strength only — it ranks which `contested` node to re-verify first and (later)
feeds γ; it does **not** decide survival (the reducer does).

## 9. Edge creation (precondition linking)

When a new node is created, link it to the specific prior node it depended on:
if a prior finding's own detail (e.g. a port number) appears in the new call's
arguments/target, edge from that specific node. Only when nothing in the call's
arguments points at a specific prior finding, fall back to "the last node on
this same target." The fallback is a guess of last resort, not the primary
rule, because a wrong edge is worse than a missing one (a report or a prune
reads it as a real causal claim). Edge creation is a `depg_update` /
graph-level concern, not the extractor's — interpreting output is the
extractor's job; sequencing is the graph's.

## 10. Memory bridge

New module `cism/memory/`, mirroring `cism/depg/`. The `memory_update` node
builds `MemoryRow`s from the step's context. Sources and tiers:

| Source | Tier | Notes |
|---|---|---|
| DEPG node evidence | reuse the node's evidence tier | keyed on the node id — repeat evidence bumps `hits`, not a new row |
| tool failure | T3 | synthesized from the error `ToolMessage` |
| guardrail block | T3 | recorded here though it is *not* a DEPG node |
| narration / reasoning | T3 | non-empty `AIMessage.content` |
| phase transition | T2 | its own row, not buried in a node's decision |

Dedup: a DEPG-derived row reuses the node id as its key. Non-DEPG rows key on
`(source_type, phase, normalized snippet)`, so a recurring block/narration
collapses (`hits += 1`) instead of spamming the table.

`age_s` and initial `salience` seeding must match whatever convention
`cism/tui/replay.py` already uses for the demo log, so live runs and replays
behave identically in the memory view. The implementation plan pins this by
reading `replay.py` rather than inventing a second convention.

## 11. Wire-format change

One change to the deliberately-frozen contract, made once:

- `NodeState` (in `cism/tui/events.py`) gains **`contested`**.
- `cism/tui/widgets/depg_modal.py` gains a colour for it.
- The DEPG SVG snapshots are refreshed.

Working `Evidence` is richer than wire `Evidence`; `to_event()` drops
`verdict` and `call_id` (the TUI evidence table does not show them).
`Edge.weight` projects through unchanged.

## 12. Deferred choices and future directions

Each was a conscious decision to defer, kept here so it is a "revisit," not a
forgotten corner.

- **`inconclusive` lowering confidence.** For now a no-op. Alternative: let a
  filtered/unknown observation nudge confidence down. Recorded on the evidence
  log so the change is reversible.
- **Edge `weight` / graded (γ) propagation.** `weight` is stored but inert;
  basic propagation is binary (a precondition is live or dead). Graded
  propagation — a soft dependency weakening rather than fully killing a child —
  is the γ-math future work.
- **IP ↔ hostname aliasing.** Requires resolution state (an alias map built
  during the run) plus a graph rewrite when a mapping appears. Until then the
  same host under two names is two subgraphs.
- **Generic-fallback false-split.** Accepted (safe failure). Graduating a
  cause-class to a real extractor fixes it per-tool.
- **LLM-backed extraction** for the long-tail tool catalog, behind the existing
  `CauseExtractor` seam; and an **LLM/embedding reconciliation pass** proposing
  reversible node merges. Both keep the LLM out of the deterministic identity
  key.
- **Cyclic enablement.** DAG enforcement drops a genuinely cyclic edge.
  Acceptable for now.

### Read / write / execute guardrails + sandbox (separate workstream)

RWX is a *capability/effect* axis, orthogonal to the *pipeline-stage* axis
(input/action/output). It belongs as additional stages in the action chain
(`ReadGuard` / `WriteGuard` / `ExecGuard`), keyed off per-tool capability
metadata carried on the `ToolRegistry` (`reads` / `writes` / `executes` /
`destructive`) — the guardrail is the soft policy front-end. The **hard**
boundary is OS-level sandboxing (bubblewrap/container: filesystem read/write
confinement, exec restriction, network egress allow-list), which the current
`run_sandboxed()` does not provide (it is a bare `subprocess.Popen`). The
`Runner` protocol is already the seam for that swap. This is high safety
priority but a distinct track from DEPG-basic.

Two concrete seam bindings: phase-specific stages arrive via
`PhaseProfile.action_stages` (exploitation can add `WriteGuard`/`ExecGuard` that
recon does not), and the capability tag is born on the tool declaration (§15),
not retrofitted. For the sandbox, a `BubblewrapRunner` implements `Runner`, and
the engagement scope becomes a constructor argument so egress allow-listing is
OS-enforced — fusing the scope check with the sandbox instead of leaving it a
heuristic on call arguments.

### Per-phase subagents (future direction — spec sketch)

For now: one physical graph, phase-parameterized `think` (per-phase prompt +
tool subset) — giving per-phase tunability/evaluability without orchestration
cost. Promote to real subagents when a real model shows one shared graph cannot
serve all six phases well.

Sketch when that day comes:

- `phase_router` becomes a dispatch point: instead of only moving the phase, it
  hands off to a phase-specialized subagent (e.g. recon-agent, exploit-agent),
  each with its own prompt and tool subset.
- All subagents write into the **one shared** DEPG + memory (already standalone
  modules) — the graph is the shared blackboard, so specialization does not
  fork the novelty.
- The hard parts to design then: the handoff/ownership protocol (who owns the
  phase transition), how a subagent's results merge back, and per-subagent
  evaluation harnesses. Deep Agents' subagent + shared-backend model is a
  candidate substrate.
- Payoff: "which agent needs improvement" becomes a real, measurable question
  — but only once each agent has a real model behind it, which is why it waits.

## 13. Testing

Mirroring existing style (`tests/test_depg_graph.py`, `tests/test_nodes.py`):

- Identity-key merge: same `(cause_class, target, signal)` merges and
  accumulates evidence; a different signal does not.
- Reducer: each of the five branches; `inconclusive` is a no-op; re-open
  (parent revives → contested clears); self-inflicted block stays dead despite
  an upstream fix.
- Dirty-frontier settle: unchanged observation is O(1) / early-exits; a cascade
  touches only the affected chain; DAG enforcement rejects a cycle-creating
  edge.
- Propagation cases: firewall (strong node → contested, stops); multi-parent
  survival (one dead parent, one live → survives); look-alike-no-merge
  (different signals stay distinct); converged prune (fully-dead region → one
  marker, provenance kept); flap (latest verdict wins, log preserved).
- Extractors: `NmapExtractor` / `HydraExtractor` against fixture output
  (success and failure); generic fallback hashing.
- `memory_update`: a row for each source (tool success/failure, narration,
  phase change, guardrail block); dedup / `hits` behaviour; guardrail block
  reaches memory but produces no DEPG node.
- `contested` wire round-trip and one refreshed DEPG snapshot.
- `PhaseProfile` selection drives `think`/`act`: the correct per-phase prompt and
  tool subset are chosen, and a phase's `action_stages` run in addition to the
  base chain.
- The reducer takes a `SupportPolicy`; `BinarySupport` reproduces every §14 case.
- Tool catalog: a `ToolSpec` row renders correct argv (flag rendering, bool vs
  value, target placement, `allow_raw` passthrough); every built tool routes
  through `run_sandboxed` and carries its capability tag.

## 14. Worked examples

Four end-to-end traces through `think → act → depg_update → phase_router →
memory_update`. Scope `10.0.0.5/32` throughout.

### Trace 1 — clean success

```
think  → nmap(10.0.0.5)                        route: act
act    → ALLOW → "22/tcp ssh, 80/tcp http"
depg   → A(open-port 22/tcp, alive T2), B(open-port 80/tcp, alive T2); no edges; settle: RESOLVED
phase  → RECON → ENUMERATION
memory → 2 findings (T2), phase-change (T2)                                   ↺
think  → hydra(ssh://10.0.0.5)                  route: act
act    → ALLOW → "admin:hunter2"
depg   → C(credential-found admin:hunter2, alive T1); edge A─hard─▶C; settle: RESOLVED
phase  → ENUMERATION → EXPLOITATION
memory → credential (T1), phase-change                                        ↺
think  → no tool calls                          route: respond → END
```

Final: `A(22)─▶C(cred)` resolved, `B(80)` resolved.

### Trace 2 — a tool fails (tombstone, no cascade)

```
think  → nmap ... → A, B resolved
think  → hydra(ssh://10.0.0.5) → FAILS "wordlist exhausted" (status=error)
depg   → D(credential-attempt ssh, dead T3); edge A─hard─▶D; settle: BLOCKED (direct); leaf, no cascade
memory → "hydra failed on ssh" (T3)
think  → respond → END
```

The failure becomes a node (today it is dropped); `A` stays resolved.

### Trace 3 — a guardrail block (memory, not the graph)

```
think  → nmap ... → A, B resolved
think  → nmap(10.0.0.99)  ← outside scope
act    → ScopeGuardStage BLOCK → "blocked: out of scope"; tool never runs
depg   → guardrail-block message → NOT a finding → no node
memory → "attempted out-of-scope nmap on 10.0.0.99, blocked" (T3)
think  → stays in scope → respond → END
```

### Trace 4 — failure → cascade → prune → success elsewhere

```
① think → nmap 10.0.0.5 → A(22/tcp, alive T2), B(8080/tcp, alive T2); settle: resolved
② think → curl(8080) → weak banner; agent GUESSES Jetty (inference, D=none)
   depg → G(service jetty, none); edge B─hard─▶G; settle: G = UNTESTED (supported by B)
③ think → hypothesize CVE-2021-28164
   depg → H(cve, none); edge G─soft─▶H; settle: H = UNTESTED
   think → exploit(H) → FAILS (patched)
   depg → append verdict=DEAD to H → H = BLOCKED (direct)   [leaf, no cascade yet]
④ think → re-scan 10.0.0.5 → 8080 CLOSED, 22 open
   depg → append verdict=DEAD to B → B = BLOCKED (direct). CASCADE:
            G: inference, parent B blocked, no other parent → not supported → BLOCKED (propagated)
          region {B, G, H} entirely blocked
   prune → collapse {B, G, H} → one dead-region marker; provenance retained
   memory→ exploit-failed (T3), 8080-closed (T2), "jetty branch pruned"
⑤ think → pivot to port 22 (A resolved); hydra(ssh) → "admin:hunter2"
   depg → C(credential-found, alive T1); edge A─hard─▶C; settle: RESOLVED
   phase→ EXPLOITATION
⑥ think → respond → "8080/Jetty dead-ended (pruned); got SSH as admin:hunter2." → END
```

Final:

```
[A 22/tcp] RESOLVED ──hard──▶ [C cred admin:hunter2] RESOLVED
[dead region: 8080 → jetty → CVE-2021-28164]   (collapsed, provenance retained)
```

Exercises the whole machine: success, an inference chain, a direct failure
(H), a propagated failure (B → G), a prune, and a pivot to success on a
surviving branch — all in the single-agent loop.

## 15. Tool authoring

Adding a tool should be a data entry, not a hand-written function. Three tiers,
escalating only when a tool needs it; all three route through `run_sandboxed`
and carry a capability tag, so none can bypass the sandbox.

**Tier 1 — a kwargs data row (the norm).** Most CLI tools are
`binary <flags> <target>`. Model flags as named kwargs so the model fills typed
params instead of assembling CLI syntax from memory:

```python
@dataclass(frozen=True)
class Flag:
    cli: str                                   # "-p", "-sV"
    kind: Literal["value", "bool"] = "value"

@dataclass(frozen=True)
class ToolSpec:
    binary: str
    capability: Capability                      # reads | writes | executes | destructive
    description: str
    flags: dict[str, Flag] = field(default_factory=dict)   # kwarg -> Flag
    target: str = "positional"                  # "positional" | a flag like "-u" | "" for none
    allow_raw: bool = False                     # expose an `extra` argv passthrough
    timeout: float = 60.0

CATALOG = {
    "nmap": ToolSpec("nmap", "reads", "Port/service scan.",
                     flags={"ports": Flag("-p"), "service": Flag("-sV", "bool")},
                     allow_raw=True),
    "nikto": ToolSpec("nikto", "reads", "Web server vuln scan.", target="-host"),
}
```

A factory turns each row into a sandboxed, capability-tagged `BaseTool` whose LLM
schema is generated from its flags (bool → boolean param, value → string param).
`nmap(target="10.0.0.5", ports="1-1000", service=True)` renders
`["-p", "1-1000", "-sV", "10.0.0.5"]`. `allow_raw` is opt-in, so destructive
tools can deny arbitrary flags.

**Tier 2 — the `extra` passthrough** (`allow_raw=True`) for occasional arbitrary
flags. Still argv-appended via `shlex.split`, so no shell injection.

**Tier 3 — a decorated function** for tools with real prep (file
materialization, subcommands): the function returns the argv tail and receives
the per-call scratch dir when it declares one.

```python
@sandboxed_tool(binary="hydra", capability="executes")
def hydra(target: str, userlist: list[str], passlist: list[str], *, scratch: Path) -> list[str]:
    """Brute-force login credentials against a service."""
    u = write_lines(scratch, "users.txt", userlist)
    p = write_lines(scratch, "pass.txt", passlist)
    return ["-L", u, "-P", p, target]
```

Registration stays an explicit allowlist:
`ToolRegistry(build_catalog(CATALOG) + [hydra, msfconsole])`. The catalog is
typed Python data now; externalizing to YAML/TOML later is a factory-read change
(the author's call, deferred). Lives in `tools/base.py` (factory, decorator,
`write_lines`) and `tools/catalog.py` (the rows) — separable from the DEPG work.

## 16. Extensibility seams and later-rework accounting

What each deferred item costs to add, given the seams above. Everything except
continuous-confidence γ and subagent orchestration is additive against an
existing seam.

| Deferred item | Seam that absorbs it | Later change | Blast radius |
|---|---|---|---|
| γ weight (threshold model) | `SupportPolicy` | new policy class + inject | 1 class, 0 reducer/caller change |
| γ weight (continuous confidence) | none | reducer + `Node`/wire gain a confidence field | moderate rework |
| RWX guardrails | action chain + `PhaseProfile.action_stages` | new stages + capability tags | stages additive; tags born on the tool (§15) |
| Sandbox isolation | `Runner` protocol | new `BubblewrapRunner`, inject | 1 class, 0 tool/node change |
| Network egress = scope | `Runner` constructor arg | runner reads scope | small, contained |
| Per-phase subagents | `phase_router` dispatch + `PhaseProfile` | handoff / shared-state orchestration | largest; profile carries per-phase config |
| Tool catalog → YAML/TOML | catalog is pure data | factory reads a file | small, contained |

The two real reworks — continuous-confidence γ and subagent orchestration — are
both explicitly out of basic.
```
