# CISM — Cyber Investigation State Memory

**An autonomous VAPT agent driven by a 4-billion-parameter model running on a
6 GB laptop GPU.** No cloud inference, no API bill, no web dashboard — a
LangGraph agent, a sandboxed tool catalog, a dependency/error-propagation
graph, and a terminal.

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests: 936](https://img.shields.io/badge/tests-936-brightgreen)
![Inference: llama.cpp](https://img.shields.io/badge/inference-llama.cpp-orange)

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
  gemma-4-e4b-it · phase: exploitation · ctx 12.4k/96k (13%) · 40 tok/s ·
  linux·apache·php · depg 11 nodes · mem T1:4 T2:4 T3:2 · ⏵⏵ auto
```

(The status line is one line in the terminal; it is wrapped here to fit the
page. It elides rather than wrapping — see "The status line" below.)

## ⚠️ Authorized use only

CISM drives real offensive tooling — nmap, sqlmap, hydra, gobuster, nikto, nc
— against whatever you point it at. **Run it only against systems you own or
have written permission to test.** Unauthorized scanning and exploitation is
a crime in most jurisdictions.

Every live run is gated by an explicit `--scope` allowlist and a
`ScopeGuardStage` that blocks any call falling outside it, but those are
safety nets against the model wandering, not a substitute for authorization.
The scope you declare is the scope you are accountable for.

## What it actually is

Three ideas, in one terminal:

- **A real agent loop, not a prompt chain.** A LangGraph graph —
  `think → act → depg_update → phase_router → memory_update` — with a PTES
  phase state machine that makes a realistic pivot legal and an arbitrary
  jump illegal.
- **A dependency/error-propagation graph (DEPG).** Every tool result becomes
  nodes and edges, each node's state derived from its evidence *and* its
  parent's support, so a dead branch collapses the subtree that depended on
  it instead of leaving the agent chasing a finding that was invalidated
  three steps ago.
- **Tiered memory with real salience.** Findings are retained at T1/T2/T3
  with a decaying salience score, and the context the model sees is compacted
  under pressure — shrink, then stub, then drop — rather than truncated.

The model is small on purpose. The whole point is that the structure around
the model does the work a bigger model would otherwise have to do.

## Quick start — the demo (no lab, no weights, no network)

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

```bash
python demo_replay.py
```

```bash
python demo_replay.py --speed 3 --loop
```

It replays a recorded event log through the real TUI. `--speed 0` removes
every pause, `--wait` holds playback until you send the first turn, and
`--log` points at a different JSONL log.

## Hosting the model with llama.cpp

CISM talks to any OpenAI-compatible server, but the setup it was built and
measured against is **llama.cpp's `llama-server` serving
`gemma-4-E4B-it` at Q4_K_M** — not Ollama. The instructions below are that
setup, end to end.

Why Gemma 4 E4B: it was the only model of the fourteen benchmarked that
scored **90/90 on a tool-calling stress test** (18 case types × 5 repeats,
temperature 0.2) *and* had the smallest VRAM footprint, which is what left
room to push the context window to 96k on a 6 GB card. Every
cybersecurity-specialized fine-tune tested *regressed* on tool calling versus
its own base model. The full shootout, including the models that lost and
why, is in
[presentations/cism-review5/model-shootout.md](presentations/cism-review5/model-shootout.md).

### 1. Build or install llama.cpp

A CUDA-enabled build matters — CPU-only inference is roughly an order of
magnitude slower and the whole design assumes full GPU offload.

Prebuilt binaries (easiest): grab a CUDA release from
[llama.cpp releases](https://github.com/ggml-org/llama.cpp/releases) and put
`llama-server` on your `PATH`.

From source:

```bash
git clone https://github.com/ggml-org/llama.cpp && cd llama.cpp
cmake -B build -DGGML_CUDA=ON
cmake --build build --config Release -j
```

`build/bin/llama-server` is the binary CISM talks to. On macOS swap
`-DGGML_CUDA=ON` for `-DGGML_METAL=ON`.

### 2. Get the weights

Q4_K_M is the quantization that was measured; it is ~4.6 GiB on disk and
~3.9 GB of VRAM at 16k context.

```bash
huggingface-cli download mradermacher/gemma-4-E4B-it-GGUF \
    gemma-4-E4B-it.Q4_K_M.gguf --local-dir ~/models
```

Or let llama.cpp fetch and cache it itself, which is the one-liner version of
the whole section:

```bash
llama-server -hf mradermacher/gemma-4-E4B-it-GGUF:Q4_K_M \
    --alias gemma-4-e4b-it --port 8189 --jinja -ngl 99 -fa on -c 98304 --temp 0.2
```

### 3. Serve it

```bash
./scripts/serve_gemma.sh
```

```powershell
.\scripts\serve_gemma.ps1
```

Both wrap one command:

```bash
llama-server --model ~/models/gemma-4-E4B-it-Q4_K_M.gguf \
    --alias gemma-4-e4b-it \
    --host 0.0.0.0 --port 8189 \
    --jinja -ngl 99 -fa on \
    -c 98304 --temp 0.2
```

What each flag is doing, and why:

| Flag | Why |
|---|---|
| `--jinja` | Applies the model's **own** chat template. Without it tool calls come back in the wrong format and the agent silently stops calling tools. This is the flag people miss. |
| `-ngl 99` | Every layer on the GPU. Partial offload splits the model across the PCIe bus and costs more than the VRAM it saves. |
| `-fa on` | Flash attention. Shrinks the KV cache enough that 96k context fits in 6 GB — without it you are capped around 32k on the same card. |
| `-c 98304` | 96k context. See the VRAM table below for why not 128k. |
| `--temp 0.2` | Tool-call arguments are structured output; sampling noise shows up as malformed JSON. |
| `--alias` | The name the server reports, and therefore what you pass to `--model` on the CISM side. |
| `--host 0.0.0.0` | Only needed so WSL2 or a Docker container can reach a server on the Windows/Linux host. On an untrusted network, use `127.0.0.1`. |

VRAM at full offload, `gemma-4-E4B-it-Q4_K_M` on a 6 GB RTX 3050:

| Context | VRAM |
|---|---|
| 16,384 | 3.90 GB |
| 32,768 | 4.14 GB |
| 65,536 | 4.68 GB |
| **98,304 (96k)** | **5.23 GB** ← chosen, ~900 MB headroom |
| 131,072 (128k) | 5.79 GB — rejected, ~350 MB headroom is too tight |

Measured throughput at that configuration: **~40 tok/s** generation.

Check it is up and reporting the alias you expect:

```bash
curl -s http://127.0.0.1:8189/v1/models | python -m json.tool
```

### 4. Point CISM at it

```bash
export CISM_API_KEY=local
python run_agent.py --base-url http://127.0.0.1:8189/v1 --model gemma-4-e4b-it
```

`--key-env-var` names the environment variable holding the API key (default
`CISM_API_KEY`). `llama-server` does not check the value, but *some*
non-empty value has to be there. The key never enters the TUI — see "Keys are
never typed into the composer" below.

Two CISM-side flags exist specifically for llama.cpp:

- `--backend llamacpp` (on `scripts/benchmark.py`) uses `llama-server`'s raw
  `/completion` endpoint with a **constrained JSON schema** for structured
  extraction, instead of the generic OpenAI function-calling path. Use it
  when DEPG extraction quality matters more than portability.
- Context discovery reads the server's own reported context length rather
  than guessing, so the status-line gauge matches what the server will
  actually accept.

Anything else OpenAI-compatible still works — vLLM, LM Studio, real OpenAI,
or Ollama's `/v1` endpoint — by pointing `--base-url` at it. They just are not
the configuration any of the numbers in this README were measured on.

## Running the real agent

`cism/agent/` is a LangGraph-backed core satisfying the same `Agent` seam the
replay's `FakeAgent` does — see "The agent core" below for what it is and,
more importantly, what it still is not. It needs the `agent` extra:

```bash
.venv/bin/pip install -e ".[dev,agent]"
```

```bash
python run_agent.py
python run_agent.py --target 10.0.0.5
```

With no other flags, no lab, no weights, no network are required — the model
behind it is a canned `DummyChatModel` and the two tools it can call are
stubs (`dummy_nmap`/`dummy_msfconsole`) — but it is a real run through
LangGraph's own graph loop, not a scripted log.

Add `--live-tools --scope <cidr|domain,...>` to run the real tool catalog
(nmap/curl/nikto/whatweb/dnsenum/hydra/sqlmap/gobuster/wafw00f/nc) instead of
the dummy stubs, sandboxed via `bwrap` (bubblewrap) and gated by a real
`ScopeGuardStage`/`DangerousFlagGuardStage` action chain — see "Tool catalog"
below for what's in it and what installing it requires:

```bash
python run_agent.py --live-tools --scope 10.0.0.0/24,example.internal \
    --base-url http://127.0.0.1:8189/v1 --model gemma-4-e4b-it
```

## Live lab: stand up a real target and run a real engagement

This spins up an actual vulnerable web app in Docker and points CISM's real
tool catalog at it — nothing here is a replay or a stub. Needs Docker and the
inference server from the section above already running.

**1. The lab network and target:**

```bash
docker network create --subnet 172.28.0.0/24 cism-lab

docker run -d --name dvwa --network cism-lab vulnerables/web-dvwa
```

DVWA lands on that subnet's second usable address — confirm it and add it to
scope:

```bash
docker inspect dvwa --format '{{(index .NetworkSettings.Networks "cism-lab").IPAddress}}'
```

Then open `http://<that IP>/setup.php` once from a browser on the same
network (or `docker exec -it dvwa bash` and curl it) and click "Create /
Reset Database" — DVWA has no DB until that's done once.

**2. Make sure your shell can actually reach `cism-lab`.** Found the hard
way: a custom Docker bridge network's containers are often *not* reachable
from the Docker host's own shell at all (confirmed on Docker Desktop/WSL2 —
direct `curl`/`ping` from the host to a `cism-lab` IP both got nothing, while
the exact same request from a throwaway container attached to `cism-lab`
worked immediately). If every tool call comes back empty or "filtered"
against a target you know is up, this is almost certainly why:

```bash
docker run --rm --network cism-lab curlimages/curl -s -o /dev/null \
    -w 'HTTP %{http_code}\n' http://<dvwa-ip>/
```

If that returns a real status code but your shell's own `curl` to the same IP
times out, run CISM itself from inside a container on `cism-lab` too —
option 4 below does exactly that.

**3. Run it, with the real tool catalog, against the real target:**

```bash
export CISM_API_KEY=local
python run_agent.py --live-tools --target <dvwa-ip> \
    --scope <dvwa-ip>/32 \
    --base-url http://<your-llama-server>:8189/v1 --model gemma-4-e4b-it
```

Set `--base-url` to wherever `llama-server` actually listens — not
necessarily `localhost`, if it is on another host (e.g. a Windows-hosted
`llama-server` reachable from WSL2 at its LAN IP).

This opens the normal TUI — `ctrl+d` for the DEPG, `ctrl+m` for memory,
`/report` at the end writes both a Markdown and JSON report plus an SVG graph
diagram (needs system `graphviz`'s `dot`; degrades gracefully to DOT-only
without it) to the export directory.

For a headless run (no TUI, just a JSON summary — findings count,
time-to-first-finding, per-phase timing) use the benchmark harness instead:

```bash
python scripts/benchmark.py \
    --target <dvwa-ip> --scope <dvwa-ip>/32 \
    --base-url http://<your-llama-server>:8189/v1 --model gemma-4-e4b-it \
    --backend llamacpp \
    --turn "recon the target with nmap, then enumerate the web service" \
    --out bench_result.json
```

**4. Run it fully containerized instead of from your host**, with the same
hardened sandbox the agent uses in production (non-root, capability-dropped,
seccomp-restricted bwrap) — see [docker/README.md](docker/README.md) for the
full flag-by-flag rationale:

```bash
docker build -t cism-runner -f cism-runner.Dockerfile .

echo -n local > /tmp/cism_api_key && chmod 600 /tmp/cism_api_key

docker run --rm -it \
  --cap-drop=ALL --cap-add=SYS_ADMIN \
  --security-opt seccomp=docker/seccomp-bwrap.json \
  --security-opt no-new-privileges \
  --security-opt systempaths=unconfined \
  --memory=2g --memory-swap=2g --cpus=2 --pids-limit=512 \
  --network cism-lab \
  -v /tmp/cism_api_key:/run/secrets/cism_api_key:ro \
  cism-runner --live-tools --target <dvwa-ip> --scope <dvwa-ip>/32 \
  --base-url http://<your-llama-server>:8189/v1 --model gemma-4-e4b-it \
  --key-file /run/secrets/cism_api_key
```

If your inference server runs on the Docker host itself (not inside
`cism-lab`), the container also needs a route to it — see docker/README.md's
D4 note on why `--add-host=host.docker.internal:host-gateway` is unreliable
on Docker Desktop/WSL2 and what the workaround is.

## Documentation

| | |
|---|---|
| [docs/AUDIT.md](docs/AUDIT.md) | Full engineering/reliability/security audit of the codebase, every finding cited to `file:line` |
| [docs/CODE_REVIEW.md](docs/CODE_REVIEW.md) | Review of the hardening pass, with repros |
| [docs/BACKLOG.md](docs/BACKLOG.md) | Running log of real engagement failures and what each one taught |
| [docs/next-phase-roadmap.md](docs/next-phase-roadmap.md) | What isn't built yet, with the seam each extends into |
| [presentations/cism-review5/model-shootout.md](presentations/cism-review5/model-shootout.md) | The fourteen-model local LLM shootout behind the Gemma 4 E4B pick |
| [docker/README.md](docker/README.md) | Container hardening, flag by flag |
| [cism/pdf/](cism/pdf/) | `mdpdf` — the Rust Markdown→PDF renderer and watcher used for these docs |

### mdpdf — docs to PDF, automatically

Every `.md` in this repo can render itself. `cism/pdf/` is a small Rust
binary: it parses Markdown with `pulldown-cmark` and lays it out with
`printpdf` using only the base-14 PDF fonts, so there are no font files to
install.

```bash
cd cism/pdf && cargo build --release
```

```bash
./target/release/mdpdf ../../README.md        # one file -> README.pdf
./target/release/mdpdf --watch ../..          # every new or changed .md, as it lands
```

The watcher skips `target/`, `.git/`, `.venv/`, `node_modules/`,
`graphify-out/` and `__pycache__/`, debounces editor save storms, and leaves
a PDF alone when it is already newer than its source. Leave it running in a
spare terminal and new Markdown gets a PDF without being asked.

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
| `/scope [add\|remove] <target>` | view or extend the live engagement scope |
| `/depg` `/mem` | the two modal views |
| `/replay <run_id>` | counterfactual replay from the output cache |
| `/ablate <part>` | disable a component for the next run |
| `/report` | write a findings report (Markdown + JSON + SVG graph) from DEPG/memory state |
| `/export` `/clear` `/help` | |

`/depg`, `/mem`, `/models`, `/clear`, `/help`, and `/export` are answered by
the TUI from state it already holds. Everything else — including a bare
`/api`, `/model`, `/target`, `/phase`, and `/scope` — is forwarded to the
agent as a normal submission; the UI cannot force a phase transition, load a
model, or widen scope on its own, it can only ask. `/scope` with no argument
lists the current engagement scope; `/scope add <cidr|domain>` and `/scope
remove <cidr|domain>` extend or shrink it live, on top of whatever
`run_agent.py --scope` set at startup.

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
| `ScopeChanged` | `action`, `target` | reports a `/scope add`/`remove` that actually changed scope |
| `NarrationRedacted` | `entry_id`, `reason` | retroactively withholds a streamed entry |
| `DEPGUpdated` | `nodes`, `edges` | replaces the DEPG model |
| `MemoryUpdated` | `rows`, `terms` | replaces the memory model |
| `TokenDelta` | `delta`, `total`, `ctx_used`, `ctx_max` | status bar and token counter |
| `SessionState` | `model`, `models_available`, `endpoint`, `key_env_var`, `key_present`, `target_os`, `target_stack` | model / target segments, `/models`, `/api` |
| `Interrupted` | `reason` | stops the indicator, marks the transcript |
| `RunFinished` | `run_id`, `ok` | stops the indicator |

`AgentEvent` is the union alias over those fifteen types.

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
memory_update ── this step's findings, failures, narration and phase changes upsert into MemoryStore
  │
  └──▶ think (loop)
```

The turn cap is `MAX_AI_TURNS = 2` (`cism/agent/nodes.py:59`): `route_after_think`
counts AI messages back to the last `HumanMessage` and stops routing into `act`
once that many have accumulated (`nodes.py:901`). It was lowered from 4 because a
reasoning model runs each chained turn out to its full `max_tokens` cap, so a
longer chain could spend ~10 minutes before the step-limit checkpoint handed
control back. `think` also shapes what it sends rather than only what it says:
`_compact_history` drops the oldest messages that don't fit the budget, and under
pressure first shrinks and then stubs out old tool output so fewer have to be
dropped at all. Pressure means either something already didn't fit or estimated
usage is above `_PROACTIVE_COMPACTION_THRESHOLD = 0.75` of the budget
(`nodes.py:274`, `nodes.py:323`) — proactive, not only once a request would
actually fail to fit, since the chars-per-token estimate swings by thousands of
tokens turn to turn on markdown-heavy output. Full history stays in state; only
what is sent to the model is trimmed.

State — messages, DEPG nodes/edges, memory items, phase — persists across
`submit()` calls within one process: `LangGraphAgent.__init__` builds a
`MemorySaver()` checkpointer and every `build_graph()` call in the class is
compiled with it, keyed by a stable per-agent `thread_id`. It does not
survive a process restart.

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
  seams (input, action, output). `LangGraphAgent()`'s own default is
  `GuardrailSeam.no_op()` — pass-through on all three — matching its
  dummy-tools default; `--live-tools` (`_enable_live_tools` in
  `run_agent.py`) wires in real stages on every seam: `InputGuardStage`
  (a length cap) on input, `OutputRedactionStage` (credential/secret
  redaction) on the final answer, `ToolOutputScreenStage` (prompt-injection
  marker detection on tool output fed back to the model) on tool output,
  and on the action chain, `ScopeGuardStage` (`guardrails/scope.py`), which
  blocks a tool call whose target falls outside a declared
  `EngagementScope` (a CIDR/domain allowlist), and `DangerousFlagGuardStage`
  (`guardrails/dangerous_flags.py`), a denylist that blocks a call whose
  free-form flags could read/write outside the sandbox scratch dir or
  trigger code execution (e.g. nmap NSE scripting). `PhaseToolGuardStage`
  (`guardrails/phase_tool.py`) runs on the same action path but isn't in
  that list — it's built per-phase inside `profiles.py`, re-checking a
  call's tool against the current phase's catalog-derived allowlist at call
  time. All of these are heuristic safety nets — they can only check what
  they can actually find in a call's arguments, not a formal guarantee.
  Adding another real check is still just appending a stage; neither the
  chain runner nor the graph shape changes.
- **Tools** (`cism/agent/tools/`) — `ToolRegistry` is a hard allowlist: a
  tool is reachable only if it was explicitly constructed into the registry,
  and looking up a name that wasn't raises rather than failing silently.
  `LangGraphAgent()`'s default stays `dummy_nmap`/`dummy_msfconsole` (canned
  output, no subprocess); real, subprocess-backed tools are opt-in,
  constructed into the registry explicitly by whoever wants a live run — see
  "Tool catalog" below for the current list. Every real tool goes through
  one seam, `run_sandboxed()` (`tools/sandbox.py`): argv-only execution
  (never `shell=True`), a per-call scratch directory that no longer exists
  once the call returns, and a hard timeout that kills the whole process
  tree, not just the leaf — behind a `Runner` protocol so a container-backed
  implementation can replace `SubprocessRunner` later without any tool
  function changing.
- **DEPG domain model** (`cism/depg/`) — `Node` and `Edge`, the agent's
  mutable working copy of the dependency/error-propagation graph, distinct
  from the frozen `DEPGNode`/`DEPGEdge` wire format above. `Graph`
  (`depg/graph.py`) is the container that merges nodes/edges as they're
  proposed, resolves each dirty node's `state` via `reduce_state`
  (`depg/reducer.py`), and prunes fully-dead regions.
  `ExtractorRegistry`/`CauseExtractor` (`depg/extract.py`) is the seam a
  tool's result turns into `Node`/`Edge` proposals through: `NmapExtractor`
  and `HydraExtractor` (`depg/extractors.py`) parse their tool's own
  plain-text output directly; every other tool falls back to `LLMExtractor`
  (same file — structured-output extraction, grounded against the tool's
  own text, T3-clamped if a claimed quote isn't actually present) or, failing
  that, `GenericExtractor` (`depg/extract.py`), which stamps one untested
  node per tool call with the tool's own name as cause-class. `depg/linking.py`
  finds each new node's precondition (the node that led to it);
  `depg/normalize.py` normalizes a target string (scheme/port/case/trailing
  dot stripped) before it becomes part of a node's identity, so
  `10.0.0.5`/`ssh://10.0.0.5:22`/`10.0.0.5.` collapse onto one node family
  instead of fragmenting. `to_event()`/`Graph.to_event()` are the only
  places any of this touches `cism.tui.events`. `generality` (cross-target
  transfer: what share of this run's targets already produced this
  cause_class) and `downstream` (descendant count) are computed by
  `Graph.compute_metrics()` right after `settle()`/`prune()` each step
  (`depg_update` in `nodes.py`) and render as real values — `γ=0.72 (3
  downstream)` — in the DEPG modal. Graded propagation (`Edge.weight`,
  soft-weakening a precondition instead of treating it as live-or-dead) is
  opt-in via `--graded-propagation` and still early; see `GradedSupport`
  in `depg/reducer.py`.
- **Memory** (`cism/memory/`) — `MemoryStore` (`memory/store.py`), the
  working container `memory_update` mutates each step, mirroring `Graph`'s
  role for the DEPG. A DEPG-derived row keys on the node's own id; a
  narration/tool-failure candidate keys on `memory_key(source, phase,
  snippet)` so a recurring one collapses onto one row (`hits` increments)
  instead of spamming the memory view. Each `MemoryItem` carries a tier
  (T1/T2/T3), the phase it was seen in, a snippet, and a salience score
  computed from `DEFAULT_SALIENCE_TERMS` (tier weight, time decay, a small
  per-hit bonus) — the same coefficients the replay demo's recorded log
  uses, so a live run and the demo decay memory identically.
- **Logging** (`cism/agent/logging.py`) — separate from both the event
  stream and DEPG evidence: JSONL operational logging for graph steps, tool
  calls, and guardrail decisions, written to `~/.cism/logs/agent.log` with a
  retention TTL enforced by both file rotation and a startup sweep; also
  `read_run_events(run_id)`, the read path `/replay` uses to pull one run's
  events back out of the log.

  There is no live-log view inside the TUI itself. To watch it while an
  agent is actually running, tail the file from another terminal:

  ```bash
  tail -f ~/.cism/logs/agent.log | jq .
  ```

  Or filter to one run:

  ```bash
  jq 'select(.data.run_id == "YOUR_RUN_ID")' ~/.cism/logs/agent.log
  ```

### Tool catalog

The real catalog is small and deliberately data-driven. Eight tools are
declared in `cism/agent/tools/catalog.yaml` (binary, capability, target flag,
timeout, allowed phases): **nikto**, **whatweb**, **dnsenum**, **nmap**,
**curl**, **sqlmap**, **gobuster**, **wafw00f**. Two more don't fit that flat
shape and are hand-written instead. **hydra** needs a scratch directory
pre-populated with credential files before the process starts
(`cism/agent/tools/credentials.py`). **nc** opens a bare TCP socket to a
non-HTTP service — the gap nmap and curl leave: confirming a backdoor shell
found listening on an unusual port actually answers a command, not just that
something is listening (`cism/agent/tools/network.py:1-11`) — and its
optional `command` argument is written into the per-call scratch directory as
nc's stdin before the process starts (`network.py:40-41`), which no flat
`catalog.yaml` row can express. netcat-openbsd specifically, not ncat or GNU
netcat: OpenBSD's `nc` has no `-e`/exec-on-connect flag at all, so the worst
failure mode for a tool like this is structurally impossible rather than
denylisted (`network.py:7-11`).
`build_toolkit(CATALOG, [hydra, nc], EXTRACTORS)` (`run_agent.py:193`)
assembles all ten plus a synthetic `tool_help` tool into one `ToolRegistry`.
Extending the catalog with another flag-and-target-shaped tool is a
`catalog.yaml` row, not a new Python function; a tool with hydra's or nc's
shape needs its own hand-written function next to
`credentials.py`/`network.py`.

`--live-tools` also hard-requires `bwrap` (bubblewrap), the sandboxing
seam every real tool call runs through. On Debian/Ubuntu/Kali:

```bash
sudo apt update && sudo apt install -y nmap curl nikto whatweb dnsenum hydra \
    sqlmap gobuster wafw00f netcat-openbsd bubblewrap
```

`hydra`'s `userlist`/`passwordlist` arguments only ever select one of two
fixed, named wordlists (`cism/agent/tools/credentials.py`) — never an
arbitrary path, so a compromised model can't turn a credential tool into a
way to read arbitrary files off the host. No package installs these under
these exact names; create them yourself with whatever username/password
lists you're authorized to use:

```bash
sudo install -d /usr/share/wordlists
sudo $EDITOR /usr/share/wordlists/common-users.txt
sudo $EDITOR /usr/share/wordlists/common-passwords.txt
```

What isn't here yet: a real model by default (still `DummyChatModel` unless
`--base-url`/`--model` is passed), a bigger tool catalog beyond the ten
above, graded propagation validated against a real run (`GradedSupport` is
opt-in via `--graded-propagation`; `BinarySupport` stays the default), LLM
reconciliation of near-duplicate DEPG nodes, and IP/hostname alias merging.
Each was designed with a single, explicit seam to extend into, so none of
it should require reshaping what's already built. See
[docs/next-phase-roadmap.md](docs/next-phase-roadmap.md) for the fuller,
file:line-cited list.

## The status line

One line at any width. Each field carries a short form and a priority; on
overflow the line degrades to short forms worst-priority-first, then drops
whole fields. Model, phase, context and mode are priority 1 and always
survive. Fields with no value — tok/s before any tokens, target before it is
declared — are omitted rather than shown empty.

```
120 cols  gemma-4-e4b · phase: recon · ctx 12.4k/32k (38%) · 47 tok/s · linux·nginx · depg 47 nodes · mem T1:8 T2:31 T3:5 · ⏵⏵ auto
100 cols  gemma-4-e4b · phase: recon · ctx 12.4k/32k (38%) · 47t/s · linux·nginx · depg 47 · mem 44 · ⏵⏵ auto
 70 cols  gemma-4-e4b · recon · ctx 12.4k/32k · 47t/s · linux · mem 44 · ⏵⏵
 44 cols  gemma-4-e4b · recon · ctx 12.4k/32k · ⏵⏵
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

For the full suite, `pytest -n auto` (via `pytest-xdist`) parallelizes across
CPU cores — roughly 2x faster, same pass/fail result. Stick to plain `pytest`
when debugging a single test with `-s`/`-vv`, since worker output interleaves.

936 tests: the event contract and its serialisation, the replayer, transcript
and composer behaviour, every keybinding, status-line elision at ten widths,
credential masking end to end, both modals, and ten SVG snapshots pinning the
look — plus, for the agent core, the phase state machine's legal and illegal
transitions, each guardrail stage (`ScopeGuardStage`, `DangerousFlagGuardStage`,
`PhaseToolGuardStage`) and the chain's short-circuit behaviour, the tool
registry's allowlist and `catalog.yaml`/`build_toolkit` assembly, DEPG
node/edge wire-format round-trips, the `Graph` container's merge/dedupe/
settle/prune rules, target normalization, `depg_update` turning tool results
into DEPG nodes (including the real `NmapExtractor`/`HydraExtractor`/
`LLMExtractor`), memory's tiered upsert, the logger's retention sweep and
`/replay`'s read path, `LangGraphAgent` run end to end (including a blocked
input, a blocked action, `/scope`/`/ablate`/`/replay`, and a live run's
`DEPGUpdated` stream, across process restarts via the checkpointer),
`run_sandboxed`'s timeout/process-tree-kill/output-capping behaviour and
`BubblewrapRunner`'s sandbox binds, real `curl`/`nmap` calls proven end to
end through the graph loop via `build_toolkit`, and one test driving
`CISMApp` with a real `LangGraphAgent` instead of `FakeAgent`.

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
  core.py               LangGraphAgent — satisfies the Agent protocol, checkpointer, /scope /replay /ablate
  graph.py              build_graph() — the compiled LangGraph, pure factory
  nodes.py              think / act / depg_update / phase_router / memory_update / respond
  state.py              Phase, PHASE_TRANSITIONS, PhaseStateMachine, AgentState
  profiles.py           PhaseProfiles — per-phase system prompt + tool allowlist
  llm.py                DummyChatModel — canned, deterministic
  logging.py            JSONL operational logging, retention TTL + /replay's read path
  tools/                ToolRegistry (hard allowlist), catalog assembly, dummy_nmap/dummy_msfconsole
    catalog.py             ToolSpec/Flag — the data-driven tool schema
    catalog.yaml           the 8 declared tools: nikto, whatweb, dnsenum, nmap, curl, sqlmap, gobuster, wafw00f
    credentials.py         hydra — hand-written, doesn't fit catalog.yaml's flat shape
    network.py             nc (netcat-openbsd) — hand-written, raw TCP + stdin into the scratch dir
    sandbox.py             run_sandboxed() — the shared execution seam for real tools
    registry.py            ToolRegistry — the hard allowlist
    base.py                build_catalog/build_toolkit — assembles catalog.yaml + hydra/nc + tool_help
  guardrails/            GuardrailChain, GuardrailSeam — input/output still pass-through
    scope.py               ScopeGuardStage — target vs. EngagementScope
    dangerous_flags.py     DangerousFlagGuardStage — denylist on free-form flags
    phase_tool.py          PhaseToolGuardStage — re-checks tool-vs-phase at call time
  memory/                MemoryStore — tiered (T1/T2/T3) retained findings
cism/depg/              the dependency/error-propagation graph domain model
  node.py, edge.py      mutable Node/Edge, to_event() into the TUI wire format
  evidence.py            Evidence — one observation attached to a node
  graph.py               Graph — merges nodes/edges, settle() derives state, prune() collapses dead regions
  reducer.py              reduce_state() — node state from evidence + parent support
  extract.py              ExtractorRegistry/CauseExtractor/GenericExtractor — the fallback seam
  extractors.py            NmapExtractor, HydraExtractor, LLMExtractor — the real ones
  linking.py               find_precondition() — links a new node to what led to it
  normalize.py             normalize_target(), hash_signal() — deterministic identity transforms
demo_replay.py        the demo entry point (FakeAgent, replays a log)
demo/recon_run.jsonl  the recorded run
run_agent.py          the live entry point (LangGraphAgent; a real OpenAI-compatible
                         connector is opt-in via --base-url/--model or CISM_LLM_BASE_URL/
                         CISM_LLM_MODEL, dummy remains the fallback when unconfigured)
cism/report/          /report — Markdown + JSON findings report plus an SVG graph diagram
cism/pdf/             mdpdf — the Rust Markdown→PDF renderer and watcher
scripts/serve_gemma.* llama-server launch for gemma-4-E4B-it — see "Hosting the model"
bench/stream_bench.py the streaming benchmark
```
