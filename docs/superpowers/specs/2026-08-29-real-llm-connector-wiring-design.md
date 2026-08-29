# Real LLM connector wiring — OpenAI/Ollama-compatible backend as the default

Date: 2026-08-29
Status: approved

## Why

`cism/agent/llm.py` already has an OpenAI-compatible `ChatOpenAI` factory
(built in a prior, uncommitted slice — one construction path covers OpenAI,
Ollama's `/v1` endpoint, vLLM, LM Studio, and llama.cpp's `--api` mode,
since they all speak the same wire format), and `LangGraphAgent(llm=...)`
already accepts it. Verified end to end against a local Ollama instance:
direct `invoke()`, and a full graph run where the real model chose a tool
call, populated the DEPG, and narrated a final answer.

Three things are still missing before that's actually usable day to day
instead of a one-off smoke-test script:

1. `run_agent.py` has no flag path to it — every live run is `DummyChatModel`,
   unconditionally.
2. `/api <url>` and `/model <name>`, typed into the TUI, don't do anything
   against the real agent — `LangGraphAgent.submit()` treats them as chat
   text, so today they'd get handed to the model as a literal user message.
3. `LangGraphAgent` never emits `SessionState`, so the status bar's
   model/endpoint fields never reflect what's actually running.

Separately: `LangGraphAgent()`'s bare default has always been
`DummyChatModel()`, unconditionally. That was the right call for the
prior skeleton-validation slice (no lab, no weights, no network, by
design), but now that a real connector exists, staying dummy-by-default
regardless of what's configured is the wrong default going forward — the
kind of thing that quietly stays true past the point it should have
stopped being true. This spec flips it: real-by-default when the
environment says so, dummy only when it explicitly doesn't (or a caller
asks for it directly).

## Out of scope

- **Graph/state persistence** (LangGraph checkpointers, resuming a run
  across restarts, multiple concurrent engagements not colliding). Flagged
  during design as a genuinely separate subsystem — its own tradeoffs
  (checkpointer backend, per-engagement keying, whether DEPG serializes
  independently of LangGraph's own state) deserve a dedicated design pass,
  not a bolt-on here.
- Tool binding correctness beyond what already exists (`_bind_tools_if_supported`
  in `core.py`) — not touched by this spec.
- A combined `/connect` command. `/api` and `/model` stay separate, matching
  what's already documented in the README/slash overlay.
- Any change to `dummy_nmap`/`dummy_msfconsole` or the real sandboxed tools
  (`nmap`/`curl`/`hydra`) — unrelated to which chat model backend is active.
- Validating tool-call support of any specific model beyond what the
  existing `build_chat_model` docstring already caveats (server support for
  the `tools` field is independent of whether the *model itself* was
  trained for function calling).
- **Real reasoning/"thinking" content** (a distinct, collapsible entry
  showing model reasoning separate from the final answer). Blocked on an
  open upstream bug, not a missing decision: `langchain_openai.ChatOpenAI`
  — the client this whole design is built on — currently silently drops
  `reasoning_content` for OpenAI-compatible providers
  ([langchain-ai/langchain#35516](https://github.com/langchain-ai/langchain/issues/35516),
  [#35059](https://github.com/langchain-ai/langchain/issues/35059),
  [#31326](https://github.com/langchain-ai/langchain/issues/31326)).
  Ollama's own `message.thinking` field is clean, but only through its
  native `/api/chat`, not the `/v1` OpenAI-compat layer this spec
  standardizes on — using it would mean a second, Ollama-only client path,
  a materially bigger decision than this spec's scope. The collapsible
  entry mechanism built for the streamed answer (below) is reusable the day
  this becomes unblocked; the extraction itself is not attempted here.

## Design

### 1. Rename the factory

`make_openai_compatible_chat_model` → `build_chat_model` in
`cism/agent/llm.py`. Its `api_key_env_var` parameter is renamed to
`key_env_var` at the same time, to match the name already used everywhere
else this concept appears (`SessionState.key_env_var`, `FakeAgent.key_env_var`,
`CISMApp.key_env_var`) — one name for one concept across the codebase
instead of two.

```python
def build_chat_model(
    base_url: str,
    key_env_var: str,
    model: str,
    **kwargs: Any,
) -> BaseChatModel: ...
```

Behavior unchanged: reads the key from the named env var, raises `ValueError`
if unset, returns a plain unbound `ChatOpenAI`.

### 2. `LangGraphAgent` — env-driven default, session metadata

Three new env vars, read only when `llm` is not explicitly passed in:

| Env var | Purpose | Default |
|---|---|---|
| `CISM_LLM_BASE_URL` | OpenAI-compatible endpoint | unset |
| `CISM_LLM_MODEL` | model name/id on that server | unset |
| `CISM_LLM_KEY_ENV_VAR` | name of the var holding the key | `CISM_API_KEY` |

```python
def _llm_from_env() -> tuple[BaseChatModel, str, str, str]:
    """Real connector if the environment describes one, Dummy otherwise.
    Never raises: an unconfigured environment is a valid, common case
    (every test in this repo runs in one), not an error."""
    base_url = os.environ.get("CISM_LLM_BASE_URL", "")
    model = os.environ.get("CISM_LLM_MODEL", "")
    key_env_var = os.environ.get("CISM_LLM_KEY_ENV_VAR", "CISM_API_KEY")
    if base_url and model:
        return build_chat_model(base_url, key_env_var, model), base_url, model, key_env_var
    return DummyChatModel(), "local (dummy)", "", ""
```

`LangGraphAgent.__init__` gains `endpoint`, `model_name`, `key_env_var`
(all `str = ""`). When `llm` is `None`, all four values come from
`_llm_from_env()` (explicit `endpoint`/`model_name`/`key_env_var` args are
ignored in that branch — there is nothing else they could mean). When
`llm` *is* passed in explicitly (tests, `run_agent.py`, a future caller),
the three metadata strings are taken as given (default `""` — an
externally-injected model with no metadata is unlabeled, not mislabeled as
dummy).

This is deliberately not a hard failure when unconfigured: 8+ existing call
sites (`LangGraphAgent()`, `LangGraphAgent(target=...)` across
`tests/test_langgraph_agent.py`, `test_app_with_langgraph_agent.py`, and
`run_agent.py`'s own current behavior) construct with zero env vars and no
network, and the "no lab, no weights, no network" bar the whole test suite
holds itself to depends on that continuing to work. Falling back to Dummy
keeps that bar intact; the fallback is made *visible* instead of hidden by
point 3 below.

`start()` changes from a no-op to:

```python
async def start(self) -> None:
    await self.events.put(self._session())

def _session(self) -> SessionState:
    return SessionState(
        model=self._model_name or "dummy",
        models_available=(ModelInfo(self._model_name, loaded=True),) if self._model_name else (),
        endpoint=self._endpoint,
        key_env_var=self._key_env_var,
        key_present=bool(os.environ.get(self._key_env_var)) if self._key_env_var else False,
    )
```

`target_os`/`target_stack` are left at their dataclass defaults —
`/target` isn't wired into `LangGraphAgent` today and this spec doesn't
touch that; no regression, matches current behavior.

### 3. `/api <url>` and `/model <name>` in `submit()`

Same shape as `FakeAgent._configure()`, not copied verbatim — every other
input (including other slash commands like `/phase`, `/replay`) is
untouched.

```python
async def submit(self, text: str) -> None:
    if text.startswith("/"):
        name, _, argument = text[1:].partition(" ")
        if name in ("api", "model"):
            await self._configure(name, argument.strip())
            return
    if self._task is not None and not self._task.done():
        self._task.cancel()
    self._task = asyncio.create_task(self._run(text))

async def _configure(self, name: str, argument: str) -> None:
    if argument and not self._key_env_var:
        await self.events.put(Narration(
            entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
            text="No live endpoint is configured for this run (still on the "
                 "dummy backend) — nothing to re-point. Set CISM_LLM_BASE_URL/"
                 "CISM_LLM_MODEL or restart with --base-url/--model.",
            done=True,
        ))
        return

    if argument:
        endpoint = argument if name == "api" else self._endpoint
        model_name = argument if name == "model" else self._model_name
        try:
            llm = build_chat_model(endpoint, self._key_env_var, model_name)
        except ValueError as exc:
            await self.events.put(Narration(
                entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=str(exc), done=True,
            ))
            return
        self._llm = llm
        self._endpoint = endpoint
        self._model_name = model_name
        bound = _bind_tools_if_supported(self._llm, self._tools)
        self._graph = build_graph(bound, self._tools, self._guardrails, self._extractors)

    await self.events.put(self._session())
```

Bare `/model` (no argument — `/api` with no argument never reaches the
agent; the TUI answers it locally) falls through both `if argument` blocks
and just re-emits current session state, matching `FakeAgent`'s own
unconditional-`_session()`-at-the-end shape.

A failed rebuild (bad `key_env_var`) leaves `self._llm`/`self._graph`
untouched — the previous working config keeps running.

### 4. `run_agent.py`

```python
parser.add_argument("--base-url", default="")
parser.add_argument("--model", default="")
parser.add_argument("--key-env-var", default="CISM_API_KEY")
```

`--base-url` without `--model` is a `parser.error` (no half-configured
state). When both are given, `run_agent.py` builds the `llm` itself via
`build_chat_model` and passes `llm`/`endpoint`/`model_name`/`key_env_var`
into `LangGraphAgent` explicitly — CLI flags win over env vars when both
are present, since they're the more specific, more recent instruction.

When no flags are given, construction falls through to `LangGraphAgent`'s
own env-driven default (point 2). Either way, after constructing the
agent, `run_agent.py` checks `agent._endpoint` — if it's `"local (dummy)"`,
it prints one line to stderr before the TUI takes over the terminal:

```
No real endpoint configured — running against the dummy backend.
Pass --base-url/--model, or set CISM_LLM_BASE_URL/CISM_LLM_MODEL.
```

This is the one entry point representing a human trying to do a live run;
everywhere else (tests, library use) the same fallback stays silent by
design.

### 5. Streaming the final answer

`make_think_node` becomes async and calls `llm.astream(...)` instead of
`llm.invoke(...)`:

```python
def make_think_node(llm: BaseChatModel) -> Callable[[AgentState], dict]:
    async def think(state: AgentState) -> dict:
        response = None
        async for chunk in llm.astream(state["messages"]):
            response = chunk if response is None else response + chunk
        return {"messages": [response]}
    return think
```

(`AIMessageChunk.__add__` is how LangChain accumulates a streamed response
into one message — the standard idiom, not something bespoke here.)

LangGraph supports async node functions transparently — `core.py` already
drives everything through `self._graph.astream(...)`. `core.py`'s `_run()`
adds `"messages"` to its stream modes:

```python
async for stream_mode, payload in self._graph.astream(
    initial_state, stream_mode=["updates", "messages"]
):
    if stream_mode == "messages":
        chunk, _metadata = payload
        if chunk.content:
            await self.events.put(
                Narration(entry_id=f"{run_id}-final", text=chunk.content, done=False)
            )
        continue
    for node, update in payload.items():
        ...  # existing per-node translation, unchanged
```

Tool-call-producing turns naturally emit no visible text this way — their
chunks carry empty `content` (the tool call itself streams as a separate
delta shape), so `if chunk.content` already excludes them without needing
to know which kind of turn is in progress.

The `respond` node still runs afterward, still calls the output guardrail
on the complete accumulated text — same as today, just after the chunks
that made up that text have already reached the TUI, not before. Because
`respond`'s input (`content = str(last.message.content)`) is exactly the
concatenation of what was already streamed, the translator can tell
whether the guardrail changed anything by comparing the two:

```python
elif node == "respond":
    for message in update.get("messages", []):
        entry_id = f"{run_id}-final"
        if guard_changed_the_text:  # result.value != the streamed content
            await self.events.put(NarrationRedacted(entry_id=entry_id, reason=result.reason))
        else:
            await self.events.put(Narration(entry_id=entry_id, text="", done=True))
```

Pass-through today means the redaction branch never fires — the entry just
closes with no further text appended, since everything was already shown.

### 6. Collapsible narration entries

`NarrationEntry` (`cism/tui/widgets/transcript.py`) gains the same
`-expanded` CSS class plus `expanded` property and `toggle()` method
`ToolEntry` already has — reusing the mechanism, not inventing a second
one. Default is expanded (you watch it type live, and a finished answer
shouldn't vanish on its own); collapse is manual only.

`Transcript` gains a `last_narration()` alongside its existing `last_tool()`.
`CISMApp.action_toggle_output` (bound to `ctrl+o`, currently
`self.transcript.last_tool().toggle()`) is generalized to toggle whichever
of the two — last tool entry or last narration entry — is more recent, so
the existing binding covers both. No new keybinding, no new keymap surface.

### 7. `NarrationRedacted` — the seam a real output guardrail needs later

One new frozen event in `cism/tui/events.py`'s existing union, alongside
`Narration`:

```python
@dataclass(frozen=True, slots=True)
class NarrationRedacted(_Event):
    entry_id: str = ""
    reason: str = ""
```

`_apply` in `app.py` gets one more branch (`transcript.narration(event.entry_id).redact(event.reason)`),
and `NarrationEntry` gets a `redact(reason)` method that replaces whatever
is currently shown with a withheld-content notice, regardless of what was
already streamed. Nothing emits this event yet — the output guardrail
chain is still pass-through, so the branch built in section 5 that would
fire it is currently dead code, proven only by a test that fakes a
blocking guardrail stage. The point is that the day real output-guardrail
logic exists, it's "emit an event that already has a widget method," not
"design a way to take back something already on screen" from scratch —
matching this codebase's stated discipline of validating seams before the
logic behind them exists.

### Left alone

- `DummyChatModel` itself: unchanged, stays in `cism/agent/llm.py` as the
  explicit fallback/test double it already is. Nothing about its behavior
  changes — only *when* it gets constructed as a default does.
- `dummy_nmap`/`dummy_msfconsole` and the real tools (`nmap`/`curl`/`hydra`):
  untouched, orthogonal to which chat model is active.
- The `Agent` protocol itself (`cism/tui/events.py`): unchanged. Command
  interception stays inside `LangGraphAgent.submit()`, same seam
  `FakeAgent` already uses — no protocol surgery.

## Testing

- `tests/test_llm.py`: existing four tests updated for the rename
  (`build_chat_model`, `key_env_var` param name) — same coverage, same
  "no network, construction and `bind_tools()` are pure local assertions"
  bar.
- `tests/test_langgraph_agent.py`, new cases:
  - no env vars set → `LangGraphAgent()` still builds (Dummy), `start()`
    emits `SessionState(endpoint="local (dummy)", model="dummy", ...)`.
  - `CISM_LLM_BASE_URL`/`CISM_LLM_MODEL`/a monkeypatched key var all set →
    `LangGraphAgent()` builds a real `ChatOpenAI` (construction only, no
    network) with the expected `base_url`/`model`, `start()` reflects it.
  - `/api <url>` and `/model <name>` submitted against an agent constructed
    with real metadata → `self._endpoint`/`self._model_name` updated,
    fresh `SessionState` observed on the event queue, graph still runs.
  - `/api <url>` submitted against an agent still on Dummy (no
    `key_env_var`) → refusal `Narration`, no state change.
  - `/api <url>` with `key_env_var` pointing at an unset var → `Narration`
    carrying the `ValueError` message, prior `_llm`/`_endpoint` untouched.
- New `tests/test_run_agent.py`: `parse_args` — `--base-url` without
  `--model` errors; both given produces the expected values; default
  `--key-env-var` is `CISM_API_KEY`.
- `tests/test_langgraph_agent.py`, streaming cases: a fake `astream`-capable
  `BaseChatModel` (same style as `_RecordingChatModel`/`_CallsCurlOnce`
  already in this suite) proves a final answer arrives as multiple
  non-`done` `Narration` events sharing one `entry_id`, followed by exactly
  one `done=True` with no duplicated text; a tool-call-producing turn
  emits no narration text at all.
- A test-local guardrail stage that actually rewrites/blocks content
  (not real logic — just enough to exercise the branch) proves
  `NarrationRedacted` fires with the right `entry_id`/`reason` instead of a
  plain `done=True` close.
- `tests/test_transcript.py` (or wherever `NarrationEntry`/`ToolEntry` are
  already covered): `NarrationEntry.toggle()`/`expanded`/`redact()`, and
  `action_toggle_output` picking whichever of last-tool/last-narration is
  more recent.

## Left open

- Persistence (see "Out of scope") — next design.
- Real reasoning/"thinking" content extraction (see "Out of scope") —
  blocked on the upstream `langchain-openai` bug; revisit once it's fixed,
  or as a separate deliberate decision to add an Ollama-native second
  client path for it.
- Whether a finished streamed answer should ever auto-collapse (e.g. past
  some length) rather than always defaulting to expanded. Not decided —
  defaulting to expanded (matching "an answer shouldn't vanish on its own")
  until there's a concrete reason to revisit.
- Whether `CISM_LLM_KEY_ENV_VAR` is the right name for the third env var,
  versus reusing `CISM_API_KEY` as both "the var name" and "the var" by
  convention (i.e. dropping the indirection entirely for the env-driven
  path specifically, keeping it only for the CLI/`/api`/`/model` paths
  where a name legitimately needs to travel as a value). Kept as
  indirection here for symmetry with the CLI flag and the TUI's existing
  `key_env_var`/`key_present` contract; revisit if it turns out nobody
  ever actually points it anywhere but `CISM_API_KEY` in practice.
