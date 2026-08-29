# CISM — Cyber Investigation State Memory

An SLM-driven VAPT agent. This repository holds its terminal UI, which is the
only surface: there is no web dashboard.

The TUI reads as a single scrolling conversation — one transcript, one fixed
composer, one status line. The terminal is the frame. Two CISM-specific views,
the dependency/error propagation graph and the memory table, are modal
overlays rather than persistent panes.

```
> scan 10.0.0.5 and tell me what is exposed

Single host on the lab segment, no prior state for this target. I'll open with
a full TCP sweep and version detection before committing to any hypothesis.

⏺ nmap(-sV -p- 10.0.0.5)
  ⎿  1247 lines · 6 open ports · relevance T1 (0.91) · ctrl+o to expand

──────────────────────────  PTES: vulnerability-analysis  ──────────────────────────

⏺ msfconsole(-q -x 'use auxiliary/scanner/mysql/mysql_login')
  ⎿  msfrpcd not reachable — 3 retries, 20s timeout · ctrl+o to expand

  ⠹ Enumerating… (12s · ↑1.2k tokens · esc to interrupt)
╭──────────────────────────────────────────────────────────────────────────────────╮
│ >                                                                                │
╰──────────────────────────────────────────────────────────────────────────────────╯
  qwen2.5-7b-instruct · phase: exploitation · ctx 12.4k/32k (38%) · 47 tok/s ·
  linux·apache·php · depg 11 nodes · mem T1:4 T2:4 T3:2 · ⏵⏵ auto
```

(The status line is one line in the terminal; it is wrapped here to fit the
page. It elides rather than wrapping — see below.)

## Quick start

The whole UI is demoable with no lab, no model weights, and no network — it
replays a recorded event log.

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

```bash
python demo_replay.py
```

```bash
python demo_replay.py --speed 3 --loop
```

`--speed 0` removes every pause, `--wait` holds playback until you send the
first turn, and `--log` points at a different JSONL log.

### Running the real agent instead of a replay

`cism/agent/` is a LangGraph-backed core satisfying the same `Agent` seam
`FakeAgent` does — see "The agent core" below for what it is and, more
importantly, what it still is not. It needs the `agent` extra:

```bash
.venv/bin/pip install -e ".[dev,agent]"
```

```bash
python run_agent.py
python run_agent.py --target 10.0.0.5
```

Also no lab, no weights, no network — the model behind it is a canned
`DummyChatModel` and the two tools it can call are stubs — but it is a real
run through LangGraph's own graph loop, not a scripted log.

## Keys

| Key | |
|---|---|
| `enter` | submit |
| `shift+enter` / `ctrl+j` | newline |
| `esc` | interrupt the running node (or close the slash overlay) |
| `ctrl+c` twice | quit |
| `ctrl+d` | DEPG view |
| `ctrl+m` | memory view |
| `ctrl+o` | expand / collapse the last tool output |
| `up` / `down` | history recall |
| `/` | slash-command overlay (fuzzy, arrow-select) |

## Commands

| Command | |
|---|---|
| `/model <name>` | switch the inference model |
| `/models` | list loadable models, marking the one in use |
| `/target <spec>` | declare the target environment, e.g. `linux nginx php` |
| `/api [url]` | show or switch the inference endpoint |
| `/phase <name>` | force a PTES phase transition |
| `/depg` `/mem` | the two modal views |
| `/replay <run_id>` | counterfactual replay from the output cache |
| `/ablate <part>` | disable a component for the next run |
| `/export` `/clear` `/help` | |

`/depg`, `/mem`, `/models`, `/clear`, `/help`, `/export`, and a bare `/api`
are answered by the TUI from state it already holds. Everything else is
forwarded to the agent as a normal submission — the UI cannot force a phase
transition or load a model on its own, it can only ask.

### Keys are never typed into the composer

`/api` reports the endpoint, the *name* of the environment variable holding
the key, and whether that variable is set. It never shows, stores, or
transmits the value.

If a credential-shaped argument is given to any command, it is masked before
the turn is echoed and the command is refused rather than forwarded:

```
> /api ••••••••

That looks like an API key, so it has not been sent or recorded.
```

This is not decoration. The composer feeds three things that outlive the
keystroke — the transcript, the history recalled with the arrow keys, and the
file written by `/export` — and CISM transcripts get pasted into reports.
Detection is deliberately broad: a false positive costs one retype, a false
negative leaks a key into a deliverable.

## The event contract

The TUI is a **pure consumer**. The agent pushes frozen dataclasses onto an
`asyncio.Queue`; the app drains that queue and mutates widgets. Nothing under
`cism/tui/` calls into LangGraph, llama.cpp, or the cross-encoder scorer, and
no widget ever calls the agent.

```
Composer submit ─▶ Textual message ─▶ CISMApp ─▶ agent.submit()

agent ─▶ asyncio.Queue ─▶ pump worker ─▶ CISMApp._apply(event) ─▶ widgets
```

`_apply` is the only function that mutates transcript state.

### The seam

```python
class Agent(Protocol):
    events: asyncio.Queue[AgentEvent]

    async def start(self) -> None: ...
    async def submit(self, text: str) -> None: ...
    async def interrupt(self) -> None: ...
    async def aclose(self) -> None: ...
```

Four methods and a queue. Two things satisfy it today, and the TUI cannot
tell them apart: `FakeAgent` in [replay.py](cism/tui/replay.py), which
replays a recorded log, and `LangGraphAgent` in
[cism/agent/core.py](cism/agent/core.py), which runs an actual LangGraph
graph — see "The agent core" below. `submit` must not block — it returns
immediately and reports progress by emitting events.

### The events

Every event is a frozen dataclass carrying a monotonically increasing `seq`
and a wall-clock `ts`, so a run can be recorded, diffed, and replayed.

| Event | Payload | Effect |
|---|---|---|
| `RunStarted` | `run_id`, `phase`, `framework` | starts the working indicator |
| `Narration` | `entry_id`, `text`, `done` | streams into one transcript entry |
| `ToolStarted` | `call_id`, `tool`, `args` | appends a `⏺` entry |
| `ToolOutput` | `call_id`, `chunk` | appends to that entry's collapsed body |
| `ToolFinished` | `call_id`, `summary`, `lines`, `tier`, `score` | fills the `⎿` line |
| `ToolFailed` | `call_id`, `reason`, `traceback` | red glyph, traceback stays collapsed |
| `PhaseChanged` | `phase`, `framework` | draws a phase rule, swaps the verb list |
| `DEPGUpdated` | `nodes`, `edges` | replaces the DEPG model |
| `MemoryUpdated` | `rows`, `terms` | replaces the memory model |
| `TokenDelta` | `delta`, `total`, `ctx_used`, `ctx_max` | status bar and token counter |
| `SessionState` | `model`, `models_available`, `endpoint`, `key_env_var`, `key_present`, `target_os`, `target_stack` | model / target segments, `/models`, `/api` |
| `Interrupted` | `reason` | stops the indicator, marks the transcript |
| `RunFinished` | `run_id`, `ok` | stops the indicator |

`AgentEvent` is the union alias over those thirteen types.

**`SessionState` never carries a key.** It carries the *name* of the
environment variable and a boolean saying whether it is set. The TUI has no
field that could hold a secret, so none can reach the transcript.

**Tokens per second is not an event field.** It is derived in the TUI from a
sliding window over `TokenDelta`. Rate is a display concern; the agent should
not have to compute or report it.

### Rules the contract depends on

**Narration is grouped by `entry_id`, not by event.** Chunks sharing an
`entry_id` append to the same widget; a new `entry_id` starts a new paragraph.
Send `done=True` on the last chunk.

**Tool events are correlated by `call_id`.** `ToolOutput`, `ToolFinished`, and
`ToolFailed` for an unknown `call_id` are dropped silently rather than
inventing an entry, so a partial or out-of-order stream degrades instead of
crashing.

**Unknown event types are counted and dropped**, never raised. The consumer is
total; `CISMApp.unknown_events` exposes the count.

**A tool failure is content, not an exception.** Emit `ToolFailed`; do not let
the exception escape into the pump.

**`DEPGUpdated` and `MemoryUpdated` are whole-state replacements**, not deltas.
Send the full node and row set each time. This keeps the modals stateless and
makes a dropped event self-healing on the next update.

**A node's `decision` is the choice that selected it, not its whole history.**
The decision path shown for a node is assembled from the decisions along its
root-to-node path, so each decision is sent exactly once no matter how deep
the branch goes.

### Worker discipline

`exclusive=True` cancels other workers *in the same group*, so a single
exclusive worker for everything would cancel the event pump. Instead:

- the pump is a long-lived worker in `group="pump"`, not exclusive;
- every agent step runs `@work(exclusive=True, thread=False, group="agent-step")`,
  so a new submission cancels the one in flight.

The UI thread never awaits a model, a subprocess, or the scorer.

### The replay log

JSONL, one encoded event per line, `//` comments allowed. `delay` is the pause
*before* that event. A `stream` key on a `Narration` line expands into token
chunks so playback looks like live generation.

```json
{"type":"ToolStarted","call_id":"c-nmap","tool":"nmap","args":"-sV -p- 10.0.0.5","delay":0.5}
{"type":"Narration","entry_id":"n-intro","stream":"Single host on the lab segment.","rate":0.014}
```

Parse errors raise `ReplayLogError` at load time, before the app mounts, so a
broken log never half-starts a demo.

## The agent core

`cism/agent/` is a real LangGraph graph behind `LangGraphAgent`, wired to the
TUI through the same `Agent` seam as `FakeAgent`. It is deliberately still a
skeleton by default — a canned model, dummy tools, guardrails that let
everything through — validated first so later work (real tools, real
guardrail checks, a real model) is additive rather than a rewrite; a first
slice of that later work (real sandboxed tools, a real scope guardrail, live
DEPG population) now exists as opt-in pieces, described below. See the
design spec at
[docs/superpowers/specs/2026-08-15-agent-workflow-skeleton-design.md](docs/superpowers/specs/2026-08-15-agent-workflow-skeleton-design.md)
for the full rationale.

```
think ── llm.astream(), accumulated into one message (DummyChatModel by default, or a real OpenAI-compatible connector — see run_agent.py --base-url/--model)
  │
  tool_calls, under the turn cap?
  │no ──▶ respond ── output guardrail runs on the final text ──▶ end of run
  │yes
act ── for each call: action guardrail runs, then the tool executes if allowed
  │
depg_update ── ExtractorRegistry turns successful tool results into DEPG nodes/edges
  │
phase_router ── proposes a legal phase move via PhaseStateMachine
  │
  └──▶ think (loop)
```

- **Phase** (`cism/agent/state.py`) — the six-phase enum below, with an
  explicit transition table rather than a strict linear sequence, so a
  realistic pivot (post-exploitation on one host kicking off recon on
  another) is legal while an arbitrary jump is not. `PhaseStateMachine`'s
  `transition()` is the single choke point every phase change goes through.

  ```python
  class Phase(Enum):
      RECON = 1
      ENUMERATION = 2
      VULNERABILITY_DISCOVERY = 3
      EXPLOITATION = 4
      POST_EXPLOITATION = 5
      REPORTING = 6
  ```

- **Guardrails** (`cism/agent/guardrails/`) — chain of responsibility, three
  seams (input, action, output). Input and output are still pass-through;
  the action chain has its first real stage, `ScopeGuardStage`
  (`guardrails/scope.py`), which blocks a tool call whose target falls
  outside a declared `EngagementScope` (a CIDR/domain allowlist) — a
  heuristic safety net, since it can only check targets it can actually find
  in a call's arguments, not a formal guarantee. Adding another real check
  is still just appending a stage; neither the chain runner nor the graph
  shape changes.
- **Tools** (`cism/agent/tools/`) — `ToolRegistry` is a hard allowlist: a
  tool is reachable only if it was explicitly constructed into the registry,
  and looking up a name that wasn't raises rather than failing silently.
  `LangGraphAgent()`'s default stays `dummy_nmap`/`dummy_msfconsole` (canned
  output, no subprocess); real, subprocess-backed tools — `nmap`, `curl`,
  `hydra` so far, with the rest of a ~53-tool catalog still to come — are
  opt-in, constructed into the registry explicitly by whoever wants a live
  run. Every real tool goes through one seam, `run_sandboxed()`
  (`tools/sandbox.py`): argv-only execution (never `shell=True`), a per-call
  scratch directory that no longer exists once the call returns, and a hard
  timeout that kills the whole process tree, not just the leaf — behind a
  `Runner` protocol so a container-backed implementation can replace
  `SubprocessRunner` later without any tool function changing.
- **DEPG domain model** (`cism/depg/`) — `Node` and `Edge`, the agent's
  mutable working copy of the dependency/error-propagation graph, distinct
  from the frozen `DEPGNode`/`DEPGEdge` wire format above. `Graph`
  (`depg/graph.py`) is the container that merges nodes/edges as they're
  proposed; `ExtractorRegistry`/`CauseExtractor` (`depg/extract.py`) is the
  seam a tool's result turns into `Node`/`Edge` proposals through — today
  only `GenericExtractor` is registered, stamping one untested node per
  successful tool call with the tool's own name as its cause-class, so a
  live run now shows real (if unlabeled) DEPG nodes instead of the empty
  modal a bare agent run used to leave. `to_event()`/`Graph.to_event()` are
  the only places any of this touches `cism.tui.events`. Cause-class-specific
  extraction, γ/propagation math, and graph traversal are still later work.
- **Logging** (`cism/agent/logging.py`) — separate from both the event
  stream and DEPG evidence: JSONL operational logging for graph steps, tool
  calls, and guardrail decisions, written to `~/.cism/logs/agent.log` with a
  1-day retention TTL enforced by both file rotation and a startup sweep.

What isn't here yet: a real model, the rest of the tool catalog (~50 more
tools beyond `nmap`/`curl`/`hydra`), cause-class-specific DEPG extraction
(today's `GenericExtractor` labels every node with the calling tool's own
name), γ/propagation math, phase locking, and guardrail logic beyond the
action chain's scope check (input and output are still pass-through). Each
was designed with a single, explicit seam to extend into, so none of it
should require reshaping what's already built.

## The status line

One line at any width. Each field carries a short form and a priority; on
overflow the line degrades to short forms worst-priority-first, then drops
whole fields. Model, phase, context and mode are priority 1 and always
survive. Fields with no value — tok/s before any tokens, target before it is
declared — are omitted rather than shown empty.

```
120 cols  qwen2.5-7b · phase: recon · ctx 12.4k/32k (38%) · 47 tok/s · linux·nginx · depg 47 nodes · mem T1:8 T2:31 T3:5 · ⏵⏵ auto
100 cols  qwen2.5-7b · phase: recon · ctx 12.4k/32k (38%) · 47t/s · linux·nginx · depg 47 · mem 44 · ⏵⏵ auto
 70 cols  qwen2.5-7b · recon · ctx 12.4k/32k · 47t/s · linux · mem 44 · ⏵⏵
 44 cols  qwen2.5-7b · recon · ctx 12.4k/32k · ⏵⏵
```

The elision logic is a pure function of segments and an available width, so
it is tested directly at every size rather than through a mounted widget.
Below roughly 40 columns the priority-1 fields alone exceed the line and
Textual clips — that floor is deliberate, since dropping the context gauge
would be worse than truncating it.

## The DEPG decision path

Selecting a node shows how the agent got there. The right half of the modal
stacks the decision trail over the evidence:

```
decision path
 time      chose             over  Δ      cost
 12:06:02  jetty:8080        5     +0.28  120t
 12:06:11  CVE-2021-28164    3     +0.41  340t
 12:07:02  read web.xml      2     +0.19   90t

evidence
 timestamp  tool    exit signal          tier
 12:06:14   nuclei  200 CVE-2021-28164   T1
```

`Δ` is the margin over the runner-up. A small gap means the agent nearly went
somewhere else, which is what you want to see when a branch turns out to be a
dead end.

## Rendering

The transcript is one widget per entry inside a `VerticalScroll`. `RichLog`
was rejected as the primary surface because it is append-only and
non-interactive: it cannot host a clickable `⎿` toggle, so `ctrl+o` and
enter-to-expand would be impossible.

The spec asked for that choice to be measured rather than asserted.
`bench/stream_bench.py` streams tokens into one wrapping paragraph three ways:

```
8000 tokens, 100x30 terminal

strategy                append     per token      render
--------------------------------------------------------
static-buffer            8.9ms        1.1µs       0.8ms
richlog-rewrite        364.2ms       45.5µs       0.4ms
static-naive           793.3ms       99.2µs       0.4ms
```

`static-buffer` — the shipped approach — appends to one Rich `Text` owned by
the widget and refreshes on a coalescing timer. `richlog-rewrite` replays the
whole buffer on each flush, which is what streaming into a paragraph costs
when the widget cannot edit its last line. `static-naive` re-joins the buffer
on every token.

The per-token cost is the point: `static-buffer` stays flat as the entry grows
(1.4 µs at 4k tokens, 1.1 µs at 8k) while `static-naive` climbs from 58 µs to
99 µs — it is quadratic in entry length. Reproduce with
`python bench/stream_bench.py --tokens 8000`.

## Styling

All styling lives in [theme.tcss](cism/tui/theme.tcss); there are no inline
styles in the Python. Text-level colour comes from Textual component classes,
so even a `Text` run's colour is defined in the stylesheet.

One accent — warm orange `#d97757` — is used for the focused composer border,
tool names, the spinner glyph, and phase rules. Everything else is a three-step
grey ramp, with red, green, and yellow used only semantically.

## Tests

```bash
pytest
```

258 tests: the event contract and its serialisation, the replayer, transcript
and composer behaviour, every keybinding, status-line elision at ten widths,
credential masking end to end, both modals, and ten SVG snapshots pinning the
look — plus, for the agent core, the phase state machine's legal and illegal
transitions, the guardrail chain's short-circuit behaviour, the tool
registry's allowlist, DEPG node/edge wire-format round-trips, the `Graph`
container's merge/dedupe rules, `depg_update` turning tool results into DEPG
nodes, the logger's retention sweep, `LangGraphAgent` run end to end
(including a blocked input, a blocked action, and a live run's `DEPGUpdated`
stream), `run_sandboxed`'s timeout/process-tree-kill/output-capping behaviour,
`ScopeGuardStage`'s allow/block heuristics, a real `curl` call proven end to
end through the graph loop, and one test driving `CISMApp` with a real
`LangGraphAgent` instead of `FakeAgent`.

The spinner has its own invariant test — every glyph must be exactly one cell
and not East-Asian-Ambiguous. The first glyph set failed both, which is why
the animation jittered.

```bash
pytest tests/test_snapshots.py --snapshot-update
```

Snapshots are deterministic because `conftest.quiesce()` stops the three
time-driven things that would otherwise leak into a capture: the spinner's
frame clock, the transcript's follow timer, and the composer's cursor blink.
`replay_all()` waits on `Queue.join()` so a capture never races the pump.

## Terminal notes

- **`ctrl+m` is `enter` on terminals without enhanced key reporting.** Where
  the two are indistinguishable, `ctrl+m` will submit instead of opening the
  memory view; use `/mem` there. `shift+enter` has the same caveat, which is
  why `ctrl+j` is bound to newline as well.
- **The DEPG view wants ≥120 columns.** The node label format
  (`[cause-class] target — generality γ=0.72 (3 downstream)`) truncates in the
  tree pane below that. The tree scrolls horizontally.
- **On Windows, set `PYTHONIOENCODING=utf-8`** if you pipe output anywhere;
  the glyph set is not representable in cp1252.

## Layout

```
cism/tui/
  app.py              CISMApp — bindings, event pump, worker orchestration
  events.py           the dataclass union, the Agent protocol, encode/decode
  replay.py           FakeAgent — JSONL log to queue, with timing
  redact.py           keeps credentials out of transcript, history, exports
  theme.tcss          the whole palette and every rule
  widgets/
    transcript.py     Transcript + user/narration/tool/error/phase entries
    composer.py       rounded box, > glyph, history recall
    status.py         the one-line status bar and its elision engine
    spinner.py        the working indicator
    slash.py          the fuzzy slash-command overlay
    depg_modal.py     Tree + decision-path and evidence DataTables
    memory_modal.py   sortable DataTable + live salience equation
cism/agent/            the LangGraph-backed core — see "The agent core"
  core.py               LangGraphAgent — satisfies the Agent protocol
  graph.py              build_graph() — the compiled LangGraph, pure factory
  nodes.py              think / act / depg_update / phase_router / respond
  state.py              Phase, PHASE_TRANSITIONS, PhaseStateMachine, AgentState
  llm.py                DummyChatModel — canned, deterministic
  logging.py            JSONL operational logging, 1-day retention TTL
  tools/                ToolRegistry (hard allowlist) + dummy_nmap/dummy_msfconsole
    sandbox.py            run_sandboxed() — the shared execution seam for real tools
    discovery.py, linux.py, credentials.py   real tools so far: nmap, curl, hydra
  guardrails/           GuardrailChain, GuardrailSeam — input/output still pass-through
    scope.py              ScopeGuardStage — the action chain's first real check
cism/depg/              the dependency/error-propagation graph domain model
  node.py, edge.py      mutable Node/Edge, to_event() into the TUI wire format
  graph.py              Graph — merges nodes/edges as extraction proposes them
  extract.py            ExtractorRegistry/CauseExtractor — GenericExtractor so far
demo_replay.py        the demo entry point (FakeAgent, replays a log)
demo/recon_run.jsonl  the recorded run
run_agent.py          the live entry point (LangGraphAgent; a real OpenAI-compatible
                         connector is opt-in via --base-url/--model or CISM_LLM_BASE_URL/
                         CISM_LLM_MODEL, dummy remains the fallback when unconfigured)
bench/stream_bench.py the streaming benchmark
```
