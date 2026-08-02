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

  ✳ Enumerating… (12s · ↑1.2k tokens · esc to interrupt)
╭──────────────────────────────────────────────────────────────────────────────────╮
│ >                                                                                │
╰──────────────────────────────────────────────────────────────────────────────────╯
  phase: exploitation · ctx 12.4k/32k (38%) · depg 11 nodes · mem T1:4 T2:4 · ⏵⏵ auto
```

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

Commands: `/phase <name>` `/depg` `/mem` `/replay <run_id>` `/ablate <part>`
`/export` `/clear` `/help`.

`/depg`, `/mem`, `/clear`, `/help`, and `/export` are answered by the TUI.
Everything else is forwarded to the agent as a normal submission — the UI
cannot force a phase transition on its own, it can only ask.

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

Four methods and a queue. `FakeAgent` in [replay.py](cism/tui/replay.py)
satisfies it today; a LangGraph-backed core satisfies it later without the TUI
changing. `submit` must not block — it returns immediately and reports
progress by emitting events.

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
| `Interrupted` | `reason` | stops the indicator, marks the transcript |
| `RunFinished` | `run_id`, `ok` | stops the indicator |

`AgentEvent` is the union alias over those twelve types.

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

99 tests: the event contract and its serialisation, the replayer, transcript
and composer behaviour, every keybinding, both modals, and ten SVG snapshots
pinning the look.

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
  theme.tcss          the whole palette and every rule
  widgets/
    transcript.py     Transcript + user/narration/tool/error/phase entries
    composer.py       rounded box, > glyph, history recall
    status.py         the one-line status bar
    spinner.py        the working indicator
    slash.py          the fuzzy slash-command overlay
    depg_modal.py     Tree + evidence DataTable
    memory_modal.py   sortable DataTable + live salience equation
demo_replay.py        the demo entry point
demo/recon_run.jsonl  the recorded run
bench/stream_bench.py the streaming benchmark
```
