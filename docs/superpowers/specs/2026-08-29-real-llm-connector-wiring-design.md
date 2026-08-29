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

## Left open

- Persistence (see "Out of scope") — next design.
- Whether `CISM_LLM_KEY_ENV_VAR` is the right name for the third env var,
  versus reusing `CISM_API_KEY` as both "the var name" and "the var" by
  convention (i.e. dropping the indirection entirely for the env-driven
  path specifically, keeping it only for the CLI/`/api`/`/model` paths
  where a name legitimately needs to travel as a value). Kept as
  indirection here for symmetry with the CLI flag and the TUI's existing
  `key_env_var`/`key_present` contract; revisit if it turns out nobody
  ever actually points it anywhere but `CISM_API_KEY` in practice.
