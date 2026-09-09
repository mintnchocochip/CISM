# CISM Terminal UI — Design

Date: 2026-08-02
Status: approved

## Purpose

CISM (Cyber Investigation State Memory) is a solo-built, SLM-driven VAPT agent.
The terminal UI is its only demo surface — there is no web dashboard. The TUI
must read as a single scrolling conversation, not an operations dashboard.

The visual target is the Claude Code CLI: one transcript, one fixed composer,
one status line. The terminal itself is the frame; there is no header, no
sidebar, no title, and no bordered panel grid.

## Non-goals

- No web dashboard, no persistent side panes.
- No force-directed or 2D graph layout for the DEPG. Tree indentation is the
  layout.
- No blues, no gradients, no emoji outside the defined glyph set.

## Package layout

```
cism/tui/
  app.py              CISMApp — bindings, event pump, worker orchestration
  events.py           frozen dataclass union + Agent Protocol
  replay.py           FakeAgent: JSONL event log -> asyncio.Queue, timed
  widgets/
    transcript.py     Transcript(VerticalScroll) + per-entry widgets
    composer.py       rounded box, `>` glyph, TextArea, history recall
    status.py         one-line status bar
    spinner.py        WorkingIndicator (glyph cycle + phase verb rotation)
    slash.py          fuzzy slash-command overlay
    depg_modal.py     ModalScreen: Tree | DataTable
    memory_modal.py   ModalScreen: DataTable + salience footer
  theme.tcss
demo_replay.py        entry point
demo/recon_run.jsonl  recorded event log
bench/stream_bench.py RichLog vs updating-Static streaming benchmark
tests/
```

## Event contract

All events are frozen dataclasses carrying `seq: int` and `ts: float`.

| Event | Payload | Effect on UI |
|---|---|---|
| `RunStarted` | `run_id`, `phase` | resets working indicator, sets phase |
| `Narration` | `entry_id`, `text`, `done` | streams into a narration entry |
| `ToolStarted` | `call_id`, `tool`, `args` | appends a tool entry, starts spinner |
| `ToolOutput` | `call_id`, `chunk` | appends to that entry's collapsed body |
| `ToolFinished` | `call_id`, `summary`, `lines`, `tier`, `score` | fills the `⎿` line |
| `ToolFailed` | `call_id`, `reason`, `traceback` | red glyph, traceback in body |
| `PhaseChanged` | `framework`, `phase` | draws a phase rule, swaps verb list |
| `DEPGUpdated` | `nodes`, `edges` | replaces DEPG modal model |
| `MemoryUpdated` | `rows`, `terms` | replaces memory modal model |
| `TokenDelta` | `delta`, `total`, `ctx_used`, `ctx_max` | status bar + spinner counter |
| `Interrupted` | `reason` | stops spinner, marks entry interrupted |
| `RunFinished` | `run_id`, `ok` | stops spinner |

`AgentEvent` is the union alias over these types.

The `Agent` Protocol is deliberately small:

```python
class Agent(Protocol):
    events: asyncio.Queue[AgentEvent]
    async def start(self) -> None: ...
    async def submit(self, text: str) -> None: ...
    async def interrupt(self) -> None: ...
    async def aclose(self) -> None: ...
```

`FakeAgent` (replay.py) satisfies it. A real LangGraph adapter satisfies it
later without the TUI changing.

## Data flow

Strictly one-directional. Widgets never call into the agent.

```
Composer submit -> Textual message -> CISMApp -> agent.submit()
agent -> asyncio.Queue -> pump worker -> CISMApp._apply(event) -> widgets
```

`_apply` is the only function that mutates transcript state. Unknown event
types are logged and dropped — the consumer is total.

### Worker discipline

`exclusive=True` cancels other workers *in the same group*. A single exclusive
worker for everything would cancel the event pump, so:

- The pump is a long-lived worker in `group="pump"` (not exclusive).
- Each agent step runs `@work(exclusive=True, thread=False, group="agent-step")`
  so a new submit cancels the in-flight one.

Nothing on the UI thread awaits llama.cpp, subprocess tool execution, or the
cross-encoder scorer.

## Rendering

Widget-per-entry inside a `VerticalScroll`.

RichLog was rejected as the primary transcript surface: it is append-only and
non-interactive, so it cannot host a clickable `⎿` toggle, and `ctrl+o` /
enter-to-expand would be impossible. The streaming benchmark
(`bench/stream_bench.py`) measures RichLog against an updating Static so the
choice is recorded as a measurement, not an assertion.

Entry widgets:

- **UserTurn** — `> ` prefix, bright text.
- **NarrationEntry** — holds a Rich `Text` buffer; `append()` pushes tokens and
  flushes via a ~60ms coalescing timer. Appending never rebuilds the widget.
- **ToolEntry** — a `Vertical` of: header Static (`⏺ ` + bold tool + dim args),
  a focusable clickable meta Static (`  ⎿  …`), and a hidden body
  `VerticalScroll` indented 5 spaces.
- **ErrorEntry** — same shape, red glyph, traceback in the collapsed body.
- **PhaseRule** — re-renders on resize to stay full width.

Autoscroll is a flag, flipped off when the user scrolls up, restored at the
bottom edge or on a new user turn.

## Palette

`theme.tcss` defines everything as CSS variables. One accent — warm orange
`#d97757` — used only for focused border, tool-name bold, spinner glyph, and
phase rules. Everything else is a 3-step grey ramp. Semantic red / green /
yellow used sparingly. Zero inline styles anywhere in the Python.

## Keybinds

`enter` submit · `shift+enter` newline · `esc` interrupt · `ctrl+c` twice quit ·
`ctrl+d` DEPG · `ctrl+m` memory · `ctrl+o` toggle last tool output ·
`up`/`down` history recall · `/` slash-command overlay (fuzzy, arrow-select).

## Slash commands

`/phase <name>` · `/depg` · `/mem` · `/replay <run_id>` · `/ablate <part>` ·
`/export` · `/clear` · `/help`.

### Implementation status (found 2026-09-08, during live-test readiness review)

Not every command listed above — or added to the autocomplete since — is
actually intercepted. `SlashOverlay`'s `COMMANDS` tuple
(`cism/tui/widgets/slash.py:31-44`) lists twelve commands total, including
`/target <os|stack>` and `/model <name>`, neither of which appears in this
design doc's original list above. `App._run_command` (`cism/tui/app.py:383-399`)
only special-cases `api` directly and routes everything else through
`LOCAL_COMMANDS = frozenset({"depg", "mem", "clear", "help", "export",
"models"})` (`cism/tui/app.py:66`); `model` is forwarded as plain text and
picked up one layer down, in `LangGraphAgent.submit()`
(`cism/agent/core.py:139`), which intercepts `api`/`model` before
scheduling a graph run.

That left four commands in the autocomplete with no interception at either
layer — `/target`, `/phase`, `/replay`, `/ablate` — silently sent as literal
chat text to the LLM (`App._run_command`'s fallthrough, `cism/tui/app.py:399`:
`self.send(line)`).

**`/target` and `/phase` fixed same day (2026-09-08).** Both are now
intercepted in `LangGraphAgent.submit()` alongside `api`/`model`
(`cism/agent/core.py:137-153`, `_set_target`/`_set_phase`): `/target <value>`
replaces `self._target`, bare `/target` reports it; `/phase <name>` goes
through the existing `PhaseStateMachine.transition()` — the same choke point
`phase_router` uses — so a manual move is bound by the same
`PHASE_TRANSITIONS` legality rules as an automated one, not a bypass; an
illegal move or an unrecognized name reports a `Narration` and leaves the
phase unchanged; bare `/phase` reports the current phase. No TUI-layer
change was needed — `App._run_command`'s existing fallthrough already routes
through `LangGraphAgent.submit()`, which is what made these two fixes small.
Covered by 6 new tests in `tests/test_langgraph_agent.py`
(`test_target_command_*`, `test_bare_target_command_*`, `test_phase_command_*`,
`test_bare_phase_command_*`).

**`/replay` and `/ablate` fixed 2026-09-09**, once each had somewhere real
to stand on:

- `LangGraphAgent._emit` (`cism/agent/core.py`) now routes every emitted
  event through the JSONL audit log (`cism/agent/logging.py`) via
  `cism.tui.events.encode` — the same round-trip format
  `cism/tui/replay.py` already reads for demo logs. That made the "no
  run-output cache" gap moot: `read_run_events(run_id)` pulls one run's
  slice straight out of the audit log (spanning a midnight rotation if
  needed), and `_replay` (`cism/agent/core.py`) decodes and replays it —
  bracketed by narrations, seq renumbered onto this session's own counter,
  closing by re-asserting the real current phase so the status bar can't
  end up lying about it. Pure playback, no tool or model call happens.
- `_ablate` (`cism/agent/core.py`) toggles a tool name or a guardrail
  stage `.name` (checked across all three chains) into a pending set;
  `_run` consumes and clears it at the start of the very next run,
  building a one-off filtered `ToolRegistry`/`GuardrailSeam`/graph for
  that run only — `self._tools`/`self._guardrails`/`self._graph` are
  never mutated. `think()` already filters `profile.tool_names` against
  the registry it's given, so an ablated tool is never offered to the
  model in the first place, not merely blocked after the fact.

Covered by 9 new tests in `tests/test_langgraph_agent.py` and 4 in
`tests/test_agent_logging.py`. Verified live against the real dummy
backend, including a real bug the live run caught that no mocked test
did: the first cut renumbered replayed events via `rebase()`'s
offset-plus-index arithmetic, which reserves exactly one number from the
shared global seq counter — a later `_emit()` call (the end-of-replay
markers) then drew from that same under-advanced counter and collided
with a seq already handed out during replay. Fixed by minting a fresh
`_next_seq()` per replayed event instead.

## Modals

Both CISM views are `ModalScreen` overlays that dim the transcript behind them.
Escape closes. They are not persistent panes.

**DEPG** — a `Tree` on the left, a `DataTable` of the selected node's evidence
on the right. Node label format:
`[cause-class] target — generality γ=0.72 (3 downstream)`. Node colour encodes
state: blocked red, resolved green, untested dim. Branch text carries the
propagation weight.

**Memory** — a sortable `DataTable`: tier, phase-tag, salience, age,
decay-adjusted score, snippet. Rows colour-graded by tier. The footer renders
the salience equation with current term values substituted, so decay behaviour
is visible live during a demo.

## Error handling

- Tool failures are content, not exceptions — they render as error entries.
- Malformed or unknown events are logged and dropped.
- Replay-log parse errors fail loudly at startup, before the app mounts, so a
  demo never half-starts.

## Testing

- `pytest-textual-snapshot` SVG snapshots pin the look: default transcript,
  composer unfocused/focused, spinner mid-run, expanded tool output, both
  modals.
- Pilot-driven key tests cover every binding and the slash overlay.
- Unit tests cover event round-tripping and the replayer's ordering and timing.

## Build order

Transcript + composer + spinner to pixel-right, then status bar, then slash
overlay, then DEPG modal, then memory modal, then replay log, then benchmark,
then README.
