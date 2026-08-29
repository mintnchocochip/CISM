# Real LLM Connector Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the already-built OpenAI-compatible `ChatOpenAI` connector (`cism/agent/llm.py`) the real, default, live-switchable backend for `LangGraphAgent` — reachable from `run_agent.py` flags, env vars, and the TUI's `/api`/`/model` commands — with the final answer streaming token-by-token into the TUI, safely alongside a future (currently pass-through) output guardrail.

**Architecture:** No new subsystems. Every change extends an existing seam: `LangGraphAgent.__init__`'s existing `llm: BaseChatModel | None` parameter, `FakeAgent`'s already-proven `submit()`-text-interception pattern for `/api`/`/model`, `NarrationEntry`'s already-proven append/finish streaming mechanism, and `ToolEntry`'s already-proven collapse/expand mechanism. Nothing here is a rewrite.

**Tech Stack:** Python 3.11+, LangGraph, `langchain-core`, `langchain-openai` (`ChatOpenAI`), Textual (TUI), pytest + pytest-asyncio.

## Global Constraints

- No task may make a real network call in a test. `ChatOpenAI(...)` construction and `bind_tools()` never touch the wire — only `.invoke()`/`.astream()` do — so tests exercise construction and fake streaming models, never a live server. This is the existing "no lab, no weights, no network" bar every test in this repo already holds itself to.
- Every `LangGraphAgent(...)` call site that exists today (8+ across `tests/test_langgraph_agent.py`, `tests/test_app_with_langgraph_agent.py`, `tests/test_tool_catalog_integration.py`, `run_agent.py`) must keep working with zero env vars and no network. Verify this by running the *full* test suite (not just new tests) at the end of every task that touches `cism/agent/core.py`.
- Tests constructing `LangGraphAgent()` must `monkeypatch.setenv("HOME", str(tmp_path))` first — `get_agent_logger()` writes to `~/.cism/logs/agent.log`, and tests must not touch the real home directory. This is already the convention in `tests/test_langgraph_agent.py`; follow it in every new test that constructs the agent.
- Rename `make_openai_compatible_chat_model` → `build_chat_model` and its `api_key_env_var` parameter → `key_env_var` (Task 1) before any other task touches `cism/agent/llm.py` or imports the factory — every later task imports it by the new name.
- Env var names, fixed for this plan: `CISM_LLM_BASE_URL`, `CISM_LLM_MODEL`, `CISM_LLM_KEY_ENV_VAR` (default `CISM_API_KEY`). CLI flags: `--base-url`, `--model`, `--key-env-var` (default `CISM_API_KEY`).
- Run `.venv/bin/pytest -q` (the full suite) after every task's own tests pass, not just the new file — this repo has 263 existing tests and several of the tasks below touch shared files (`cism/agent/core.py`, `cism/tui/events.py`, `cism/tui/widgets/transcript.py`, `cism/tui/app.py`) that other tests already cover.
- Line numbers cited in each task (e.g. `core.py:71-93`) refer to the file's state *before this plan's own edits* — several tasks (2, 3, 8 in `core.py`; 6, 9 in `transcript.py`/`app.py`) touch the same file in sequence, so later tasks' line numbers will have drifted by the time you reach them. Find the target by the function/section name given (e.g. "replace `submit()`"), not by trusting the stale number — the code block in each step is the authority on what the result should look like.

---

## File Structure

```
cism/agent/llm.py                renamed factory (Task 1)
cism/agent/core.py                env-driven default, SessionState, /api //model, streaming translate (Tasks 2, 3, 8)
cism/agent/nodes.py                async streaming think node (Task 7)
cism/agent/graph.py                docstring touch-up only (Task 7)
run_agent.py                       CLI flags (Task 4)
pyproject.toml                     pythonpath fix so tests can `import run_agent` (Task 4)
cism/tui/events.py                 NarrationRedacted event (Task 5)
cism/tui/widgets/transcript.py     collapsible NarrationEntry, Transcript.last_collapsible() (Task 6)
cism/tui/theme.tcss                narration--hint style (Task 6)
cism/tui/app.py                    ctrl+o generalization, NarrationRedacted handling (Task 9)

tests/test_llm.py                  renamed (Task 1)
tests/test_langgraph_agent.py      env default, SessionState, /api //model, streaming, redaction (Tasks 2, 3, 8)
tests/test_run_agent.py            new — CLI flag parsing (Task 4)
tests/test_events.py               NarrationRedacted round-trip (Task 5)
tests/test_widgets.py              collapse/expand, redact (Task 6)
tests/test_nodes.py                async think node (Task 7)
tests/test_app.py                  ctrl+o toggles whichever is more recent (Task 9)
```

Task order matters: 1 before 2/3/4 (rename must land first); 5 before 8/9 (event must exist before anything emits/handles it); 6 before 9 (widget methods must exist before app.py calls them); 7 before 8 (the node must stream before core.py can consume streamed chunks).

---

### Task 1: Rename the factory — `build_chat_model`

**Files:**
- Modify: `cism/agent/llm.py:29-31,100-143`
- Modify: `tests/test_llm.py` (whole file — every call site)

**Interfaces:**
- Produces: `build_chat_model(base_url: str, key_env_var: str, model: str, **kwargs: Any) -> BaseChatModel`, raising `ValueError` if the named env var is unset. Every later task that needs a real connector imports this exact name.

- [ ] **Step 1: Update the test file to the new name first**

Replace the whole contents of `tests/test_llm.py`:

```python
"""cism/agent/llm.py: the real, network-capable model factory.

No network call is exercised anywhere here — ``ChatOpenAI`` doesn't touch
the wire until a request is actually sent, so construction and
``bind_tools()`` are pure local object-graph assertions, the same "no lab,
no weights, no network" bar the rest of this repo holds itself to.
"""

from __future__ import annotations

import pytest
from langchain_openai import ChatOpenAI

from cism.agent.llm import build_chat_model


def test_missing_api_key_env_var_raises_rather_than_silently_using_none(monkeypatch) -> None:
    monkeypatch.delenv("CISM_TEST_MODEL_KEY", raising=False)
    with pytest.raises(ValueError, match="CISM_TEST_MODEL_KEY"):
        build_chat_model(
            base_url="http://localhost:8080/v1",
            key_env_var="CISM_TEST_MODEL_KEY",
            model="some-model",
        )


def test_builds_a_chat_openai_pointed_at_the_given_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("CISM_TEST_MODEL_KEY", "sk-placeholder")

    model = build_chat_model(
        base_url="http://localhost:8080/v1",
        key_env_var="CISM_TEST_MODEL_KEY",
        model="local-llama",
    )

    assert isinstance(model, ChatOpenAI)
    assert model.openai_api_base == "http://localhost:8080/v1"
    assert model.model_name == "local-llama"


def test_ollamas_openai_compatible_endpoint_uses_the_same_construction_path(monkeypatch) -> None:
    """Ollama's /v1 endpoint requires a non-empty api_key but never
    validates it (docs.ollama.com/api/openai-compatibility) — so pointing
    at it takes no special-casing, just a different base_url/model."""
    monkeypatch.setenv("CISM_TEST_OLLAMA_KEY", "ollama")

    model = build_chat_model(
        base_url="http://localhost:11434/v1",
        key_env_var="CISM_TEST_OLLAMA_KEY",
        model="llama3.1",
    )

    assert isinstance(model, ChatOpenAI)
    assert model.openai_api_base == "http://localhost:11434/v1"


def test_extra_kwargs_pass_through_to_chat_openai(monkeypatch) -> None:
    monkeypatch.setenv("CISM_TEST_MODEL_KEY", "sk-placeholder")

    model = build_chat_model(
        base_url="http://localhost:8080/v1",
        key_env_var="CISM_TEST_MODEL_KEY",
        model="local-llama",
        temperature=0.2,
    )

    assert model.temperature == 0.2
```

- [ ] **Step 2: Run the test file to verify it fails**

Run: `.venv/bin/pytest tests/test_llm.py -v`
Expected: FAIL — `ImportError: cannot import name 'build_chat_model' from 'cism.agent.llm'`

- [ ] **Step 3: Rename in `cism/agent/llm.py`**

Change `__all__` (line 31):
```python
__all__ = ["DummyChatModel", "build_chat_model"]
```

Change the function definition and body (replace the whole `make_openai_compatible_chat_model` function, lines 100-143):
```python
def build_chat_model(
    base_url: str,
    key_env_var: str,
    model: str,
    **kwargs: Any,
) -> BaseChatModel:
    """A ``ChatOpenAI`` pointed at any server that speaks the OpenAI chat
    completions wire format — llama.cpp's ``--api`` mode, vLLM, LM Studio,
    real OpenAI, or Ollama's ``/v1`` endpoint. One construction path covers
    all of them because that wire format is the actual shared implementation,
    not a coincidence: Ollama's OpenAI-compatible endpoint requires the
    ``api_key`` field to be present and non-empty but never validates its
    contents (see https://docs.ollama.com/api/openai-compatibility), which is
    exactly why this takes the *name* of an environment variable rather than
    a key value — the same ``key_env_var``/``key_present`` split the TUI's
    ``SessionState`` already uses, so a local no-auth server still gets a
    real (if throwaway) secret name to report instead of a hole in that
    contract.

    Caveat a caller must know before relying on tool calls against a local
    server: whether the *model being served* supports function calling is
    independent of whether the server's endpoint does. Ollama's endpoint
    supports the tools field, but only for models trained for it (e.g.
    Llama 3.1, Mistral Nemo, Firefunction v2, Command-R) — an
    unsupported model will not necessarily error, it may instead emit raw
    tool-call-shaped JSON as ordinary text content, which looks like a
    model failing to call anything rather than a config problem.

    Tool binding is deliberately not done here: this factory only ever
    builds the model, so what it returns is a plain, uncommitted
    ``BaseChatModel`` regardless of which tools (if any) the caller intends
    to bind onto it later, exactly like ``DummyChatModel`` needs no tools to
    exist. Binding is the caller's job (see ``LangGraphAgent``), which is
    also where the tool *registry* — the other half of the pairing — lives.
    """
    api_key = os.environ.get(key_env_var, "")
    if not api_key:
        raise ValueError(
            f"environment variable {key_env_var!r} is not set; "
            "an OpenAI-compatible server still requires a non-empty api_key "
            "even when (as with Ollama) it never checks the value"
        )

    return ChatOpenAI(base_url=base_url, api_key=api_key, model=model, **kwargs)
```

Also update the module docstring reference at the top of the file (lines 12-13), which currently reads:
```python
Swapping this for a real model is the one-line change that docstring
promised: see ``make_openai_compatible_chat_model`` below, ...
```
to:
```python
Swapping this for a real model is the one-line change that docstring
promised: see ``build_chat_model`` below, ...
```

- [ ] **Step 4: Run the test file to verify it passes**

Run: `.venv/bin/pytest tests/test_llm.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Run the full suite to confirm nothing else referenced the old name**

Run: `.venv/bin/pytest -q`
Expected: PASS (no other file imports `make_openai_compatible_chat_model` today — confirmed by `grep -rn "make_openai_compatible_chat_model" cism/ tests/` returning nothing outside `llm.py`/`test_llm.py` before this change)

- [ ] **Step 6: Commit**

```bash
git add cism/agent/llm.py tests/test_llm.py
git commit -m "refactor: rename make_openai_compatible_chat_model to build_chat_model"
```

---

### Task 2: `LangGraphAgent` — env-driven default connector + `SessionState`

**Files:**
- Modify: `cism/agent/core.py`
- Modify: `tests/test_langgraph_agent.py`

**Interfaces:**
- Consumes: `build_chat_model(base_url, key_env_var, model, **kwargs) -> BaseChatModel` (Task 1).
- Produces: `LangGraphAgent.__init__(..., endpoint: str = "", model_name: str = "", key_env_var: str = "")`; `LangGraphAgent._session() -> SessionState`; `LangGraphAgent.start()` now puts one `SessionState` onto `self.events`. Later tasks (3, 8) read/write `self._endpoint`, `self._model_name`, `self._key_env_var`, `self._llm`, `self._graph`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_langgraph_agent.py` (near the top, after existing imports — add `SessionState` to the existing `from cism.tui.events import (...)` block, and add `import asyncio` if not already imported at module level — it already is, per the file's existing `_run_to_completion` helper):

```python
def test_no_env_vars_falls_back_to_dummy(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CISM_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("CISM_LLM_MODEL", raising=False)

    agent = LangGraphAgent()

    session = agent._session()
    assert session.endpoint == "local (dummy)"
    assert session.model == "dummy"
    assert session.key_env_var == ""
    assert session.key_present is False


def test_env_vars_build_a_real_connector(tmp_path, monkeypatch) -> None:
    from langchain_openai import ChatOpenAI

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CISM_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("CISM_LLM_MODEL", "qwen2.5:3b")
    monkeypatch.setenv("CISM_API_KEY", "ollama")

    agent = LangGraphAgent()

    assert isinstance(agent._llm, ChatOpenAI)
    session = agent._session()
    assert session.endpoint == "http://localhost:11434/v1"
    assert session.model == "qwen2.5:3b"
    assert session.key_env_var == "CISM_API_KEY"
    assert session.key_present is True
    assert session.models_available == (ModelInfo("qwen2.5:3b", loaded=True),)


async def test_start_emits_the_initial_session_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CISM_LLM_BASE_URL", raising=False)

    agent = LangGraphAgent()
    await agent.start()

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, SessionState)
    assert event.endpoint == "local (dummy)"


def test_explicit_llm_without_metadata_is_unlabeled_not_dummy(tmp_path, monkeypatch) -> None:
    """An externally-injected model (as tests already do) with no
    endpoint/model_name/key_env_var given is not mislabeled as the dummy
    backend — it's simply unlabeled."""
    monkeypatch.setenv("HOME", str(tmp_path))
    model = _RecordingChatModel()

    agent = LangGraphAgent(llm=model)

    assert agent._endpoint == ""
    assert agent._model_name == ""
```

Add `SessionState` and `ModelInfo` to the existing `from cism.tui.events import (...)` import block in `tests/test_langgraph_agent.py`.

- [ ] **Step 2: Run to verify the tests fail**

Run: `.venv/bin/pytest tests/test_langgraph_agent.py -v -k "env_vars or session_state or unlabeled"`
Expected: FAIL — `AttributeError: 'LangGraphAgent' object has no attribute '_session'` (or similar — the constructor doesn't accept `endpoint`/`model_name`/`key_env_var` yet)

- [ ] **Step 3: Implement in `cism/agent/core.py`**

Add `os` to the imports (top of file, alongside `asyncio`/`uuid`):
```python
import asyncio
import os
import uuid
```

Change the `cism.agent.llm` import:
```python
from cism.agent.llm import DummyChatModel, build_chat_model
```

Add `ModelInfo` and `SessionState` to the `cism.tui.events` import block:
```python
from cism.tui.events import (
    AgentEvent,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Interrupted,
    ModelInfo,
    Narration,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SessionState,
    ToolFailed,
    ToolFinished,
    ToolStarted,
)
```

Add a new module-level function right after `_bind_tools_if_supported` (before `class LangGraphAgent`):
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

Replace `__init__` (currently lines 71-93):
```python
    def __init__(
        self,
        llm: BaseChatModel | None = None,
        tools: ToolRegistry | None = None,
        guardrails: GuardrailSeam | None = None,
        extractors: ExtractorRegistry | None = None,
        target: str = "",
        endpoint: str = "",
        model_name: str = "",
        key_env_var: str = "",
    ) -> None:
        self.events: asyncio.Queue[AgentEvent] = asyncio.Queue()
        if llm is None:
            self._llm, self._endpoint, self._model_name, self._key_env_var = _llm_from_env()
        else:
            self._llm = llm
            self._endpoint = endpoint
            self._model_name = model_name
            self._key_env_var = key_env_var
        self._tools = tools or ToolRegistry([dummy_nmap, dummy_msfconsole])
        self._guardrails = guardrails or GuardrailSeam.no_op()
        self._extractors = extractors or ExtractorRegistry({}, GenericExtractor())
        bound_llm = _bind_tools_if_supported(self._llm, self._tools)
        self._graph = build_graph(bound_llm, self._tools, self._guardrails, self._extractors)
        self._phase = PhaseStateMachine(Phase.RECON)
        self._target = target
        self._task: asyncio.Task[None] | None = None
        self._log = get_agent_logger()
        #: The last DEPGUpdated payload emitted, so depg_update running on
        #: every loop iteration doesn't flood the TUI with identical events
        #: on iterations where nothing about the graph actually changed.
        self._last_depg: tuple[tuple[DEPGNode, ...], tuple[DEPGEdge, ...]] = ((), ())
```

Replace `start()` (currently lines 95-97):
```python
    async def start(self) -> None:
        """Announce the session before any run, so the status bar reflects
        what's actually running (dummy or real) even if nothing is
        submitted yet."""
        await self.events.put(self._session())

    def _session(self) -> SessionState:
        return SessionState(
            model=self._model_name or "dummy",
            models_available=(
                (ModelInfo(self._model_name, loaded=True),) if self._model_name else ()
            ),
            endpoint=self._endpoint,
            key_env_var=self._key_env_var,
            key_present=bool(os.environ.get(self._key_env_var)) if self._key_env_var else False,
        )
```

- [ ] **Step 4: Run to verify the new tests pass**

Run: `.venv/bin/pytest tests/test_langgraph_agent.py -v -k "env_vars or session_state or unlabeled"`
Expected: PASS (4 passed)

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (263 + 4 new = 267 passed) — this confirms every existing zero-arg `LangGraphAgent()`/`LangGraphAgent(target=...)` call site across the suite still works with no env vars set.

- [ ] **Step 6: Commit**

```bash
git add cism/agent/core.py tests/test_langgraph_agent.py
git commit -m "feat: env-driven default connector and SessionState for LangGraphAgent"
```

---

### Task 3: `/api <url>` and `/model <name>` in `submit()`

**Files:**
- Modify: `cism/agent/core.py`
- Modify: `tests/test_langgraph_agent.py`

**Interfaces:**
- Consumes: `self._endpoint`, `self._model_name`, `self._key_env_var`, `self._session()` (Task 2); `build_chat_model` (Task 1); `_bind_tools_if_supported`, `build_graph` (existing).
- Produces: `LangGraphAgent.submit()` now intercepts `/api`/`/model` before scheduling a graph run — no new public interface, but this is the behavior Task 8's streaming work and any future TUI work depend on being correct.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_langgraph_agent.py`:

```python
async def test_api_command_rebuilds_the_connector(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CISM_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("CISM_LLM_MODEL", "qwen2.5:3b")
    monkeypatch.setenv("CISM_API_KEY", "ollama")
    agent = LangGraphAgent()

    await agent.submit("/api http://localhost:9999/v1")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, SessionState)
    assert event.endpoint == "http://localhost:9999/v1"
    assert agent._endpoint == "http://localhost:9999/v1"
    assert agent._model_name == "qwen2.5:3b"  # unchanged


async def test_model_command_rebuilds_the_connector(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CISM_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("CISM_LLM_MODEL", "qwen2.5:3b")
    monkeypatch.setenv("CISM_API_KEY", "ollama")
    agent = LangGraphAgent()

    await agent.submit("/model llama3.1")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, SessionState)
    assert event.model == "llama3.1"
    assert agent._endpoint == "http://localhost:11434/v1"  # unchanged


async def test_bare_model_command_just_reports_session_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CISM_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("CISM_LLM_MODEL", "qwen2.5:3b")
    monkeypatch.setenv("CISM_API_KEY", "ollama")
    agent = LangGraphAgent()

    await agent.submit("/model")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, SessionState)
    assert event.model == "qwen2.5:3b"


async def test_api_command_refuses_when_still_on_dummy(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CISM_LLM_BASE_URL", raising=False)
    agent = LangGraphAgent()

    await agent.submit("/api http://localhost:11434/v1")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, Narration)
    assert "nothing to re-point" in event.text
    assert agent._endpoint == "local (dummy)"


async def test_api_command_with_missing_key_env_var_leaves_prior_config_intact(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CISM_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("CISM_LLM_MODEL", "qwen2.5:3b")
    monkeypatch.setenv("CISM_API_KEY", "ollama")
    agent = LangGraphAgent()
    monkeypatch.delenv("CISM_API_KEY")

    await agent.submit("/api http://localhost:9999/v1")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, Narration)
    assert "CISM_API_KEY" in event.text
    assert agent._endpoint == "http://localhost:11434/v1"  # unchanged
```

- [ ] **Step 2: Run to verify the tests fail**

Run: `.venv/bin/pytest tests/test_langgraph_agent.py -v -k "api_command or model_command"`
Expected: FAIL — `/api ...`/`/model ...` currently get scheduled as a graph run (a `RunStarted` arrives instead of a `SessionState`/`Narration`), so these assertions fail on the wrong event type.

- [ ] **Step 3: Implement in `cism/agent/core.py`**

Replace `submit()` (currently lines 99-106):
```python
    async def submit(self, text: str) -> None:
        """Schedules the run as its own task and returns immediately, per
        the Agent protocol's "must not block" contract. A new submission
        cancels one already in flight — same discipline the TUI's own
        worker groups apply on its side. ``/api``/``/model`` are answered
        directly instead of being scheduled as a graph run."""
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
            await self.events.put(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=(
                        "No live endpoint is configured for this run (still on "
                        "the dummy backend) — nothing to re-point. Set "
                        "CISM_LLM_BASE_URL/CISM_LLM_MODEL or restart with "
                        "--base-url/--model."
                    ),
                    done=True,
                )
            )
            return

        if argument:
            endpoint = argument if name == "api" else self._endpoint
            model_name = argument if name == "model" else self._model_name
            try:
                llm = build_chat_model(endpoint, self._key_env_var, model_name)
            except ValueError as exc:
                await self.events.put(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=str(exc), done=True
                    )
                )
                return
            self._llm = llm
            self._endpoint = endpoint
            self._model_name = model_name
            bound_llm = _bind_tools_if_supported(self._llm, self._tools)
            self._graph = build_graph(
                bound_llm, self._tools, self._guardrails, self._extractors
            )

        await self.events.put(self._session())
```

- [ ] **Step 4: Run to verify the tests pass**

Run: `.venv/bin/pytest tests/test_langgraph_agent.py -v -k "api_command or model_command"`
Expected: PASS (5 passed)

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (267 + 5 = 272 passed)

- [ ] **Step 6: Commit**

```bash
git add cism/agent/core.py tests/test_langgraph_agent.py
git commit -m "feat: handle /api and /model live against the real connector"
```

---

### Task 4: `run_agent.py` CLI flags

**Files:**
- Modify: `run_agent.py`
- Modify: `pyproject.toml` (add `pythonpath = ["."]` so tests can `import run_agent`)
- Create: `tests/test_run_agent.py`

**Interfaces:**
- Consumes: `LangGraphAgent(llm=, target=, endpoint=, model_name=, key_env_var=)` (Task 2), `build_chat_model` (Task 1).
- Produces: `parse_args(argv: list[str] | None = None) -> argparse.Namespace` with `.target`, `.base_url`, `.model`, `.key_env_var` — this exact function is what `tests/test_run_agent.py` imports.

- [ ] **Step 1: Add `pythonpath` to `pyproject.toml` first (a prerequisite, not itself tested)**

`run_agent.py` lives at the repo root, outside the `cism` package, so `import run_agent` from a test under `tests/` fails without this — confirmed empirically (`ModuleNotFoundError: No module named 'run_agent'` before this change).

In `pyproject.toml`, change:
```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
filterwarnings = ["error::DeprecationWarning:cism.*"]
```
to:
```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
pythonpath = ["."]
filterwarnings = ["error::DeprecationWarning:cism.*"]
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_run_agent.py`:
```python
"""run_agent.py: CLI flag parsing. Building the TUI app and actually
running it live is out of scope for an automated test — this covers the
one thing that's pure logic, parse_args."""

from __future__ import annotations

import pytest

from run_agent import parse_args


def test_base_url_without_model_is_an_error(capsys) -> None:
    with pytest.raises(SystemExit):
        parse_args(["--base-url", "http://localhost:11434/v1"])
    assert "--model" in capsys.readouterr().err


def test_base_url_and_model_together_parse_cleanly() -> None:
    args = parse_args(["--base-url", "http://localhost:11434/v1", "--model", "qwen2.5:3b"])
    assert args.base_url == "http://localhost:11434/v1"
    assert args.model == "qwen2.5:3b"
    assert args.key_env_var == "CISM_API_KEY"


def test_no_flags_leaves_base_url_and_model_empty() -> None:
    args = parse_args([])
    assert args.base_url == ""
    assert args.model == ""
    assert args.key_env_var == "CISM_API_KEY"
    assert args.target == ""


def test_key_env_var_can_be_overridden() -> None:
    args = parse_args(
        ["--base-url", "http://localhost:11434/v1", "--model", "m", "--key-env-var", "OTHER_KEY"]
    )
    assert args.key_env_var == "OTHER_KEY"
```

- [ ] **Step 3: Run to verify the tests fail**

Run: `.venv/bin/pytest tests/test_run_agent.py -v`
Expected: FAIL — `parse_args` doesn't accept `--base-url`/`--model`/`--key-env-var` yet (`error: unrecognized arguments`)

- [ ] **Step 4: Implement in `run_agent.py`**

Replace the whole file:
```python
#!/usr/bin/env python
"""Run the CISM TUI against the real LangGraph-backed agent core.

Unlike ``demo_replay.py`` this does not replay a recorded log — it drives
``cism.agent.LangGraphAgent`` live, through the same ``Agent`` protocol.

With no flags, the agent falls back to whatever ``CISM_LLM_BASE_URL``/
``CISM_LLM_MODEL`` say (or ``DummyChatModel`` if neither is set — see
``cism/agent/core.py``). To point at a real OpenAI-compatible server
(llama.cpp, vLLM, LM Studio, real OpenAI, or Ollama's ``/v1`` endpoint)
without touching the environment::

    .venv/bin/pip install -e ".[dev,agent]"
    python run_agent.py --base-url http://localhost:11434/v1 --model qwen2.5:3b
    python run_agent.py --target 10.0.0.5 --base-url http://localhost:11434/v1 --model qwen2.5:3b

See ``cism/agent/`` for what's behind it and the design spec at
``docs/superpowers/specs/2026-08-29-real-llm-connector-wiring-design.md``.
"""

from __future__ import annotations

import argparse
import sys

from cism.agent import LangGraphAgent
from cism.agent.llm import build_chat_model
from cism.tui.app import CISMApp


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target", default="", help="initial target context, e.g. 10.0.0.5"
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="OpenAI-compatible endpoint, e.g. http://localhost:11434/v1",
    )
    parser.add_argument("--model", default="", help="model name/id on that server")
    parser.add_argument(
        "--key-env-var",
        default="CISM_API_KEY",
        help="name of the env var holding the API key (default: CISM_API_KEY)",
    )
    args = parser.parse_args(argv)
    if args.base_url and not args.model:
        parser.error("--base-url requires --model")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.base_url:
        llm = build_chat_model(args.base_url, args.key_env_var, args.model)
        agent = LangGraphAgent(
            llm=llm,
            target=args.target,
            endpoint=args.base_url,
            model_name=args.model,
            key_env_var=args.key_env_var,
        )
    else:
        agent = LangGraphAgent(target=args.target)

    if agent._endpoint == "local (dummy)":
        print(
            "No real endpoint configured — running against the dummy backend.\n"
            "Pass --base-url/--model, or set CISM_LLM_BASE_URL/CISM_LLM_MODEL.",
            file=sys.stderr,
        )

    CISMApp(agent).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run to verify the tests pass**

Run: `.venv/bin/pytest tests/test_run_agent.py -v`
Expected: PASS (4 passed)

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (272 + 4 = 276 passed)

- [ ] **Step 7: Manual smoke test against local Ollama (not automated — confirms the CLI path for real)**

Run: `CISM_API_KEY=ollama .venv/bin/python run_agent.py --base-url http://localhost:11434/v1 --model qwen2.5:3b --target 10.0.0.5`
Expected: TUI launches with no stderr warning (real endpoint configured), status bar shows `qwen2.5:3b`. `ctrl+c` twice to quit.

- [ ] **Step 8: Commit**

```bash
git add run_agent.py pyproject.toml tests/test_run_agent.py
git commit -m "feat: run_agent.py --base-url/--model/--key-env-var flags"
```

---

### Task 5: `NarrationRedacted` event

**Files:**
- Modify: `cism/tui/events.py`
- Modify: `tests/test_events.py`

**Interfaces:**
- Produces: `NarrationRedacted(entry_id: str = "", reason: str = "")`, part of the `AgentEvent` union and `EVENT_TYPES` registry. Task 6 gives `NarrationEntry` a `redact()` method this event's handler will call; Task 8 emits it; Task 9 wires `CISMApp._apply` to call `.redact()` when it arrives.

- [ ] **Step 1: Write the failing test**

In `tests/test_events.py`, add `NarrationRedacted` to the import block:
```python
from cism.tui.events import (
    EVENT_TYPES,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Evidence,
    Interrupted,
    MemoryRow,
    MemoryUpdated,
    Narration,
    NarrationRedacted,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SalienceTerms,
    TokenDelta,
    ToolFailed,
    ToolFinished,
    ToolOutput,
    ToolStarted,
    decode,
    encode,
)
```

Add `NarrationRedacted("e1", "blocked: contains a secret")` to the `SIMPLE_EVENTS` list, and `"NarrationRedacted"` to the `test_every_event_type_is_registered` set:
```python
SIMPLE_EVENTS = [
    RunStarted("run-1", "recon"),
    RunFinished("run-1", True),
    Narration("e1", "hello", False),
    NarrationRedacted("e1", "blocked: contains a secret"),
    ToolStarted("c1", "nmap", "-sV"),
    ToolOutput("c1", "chunk"),
    ToolFinished("c1", "6 open ports", 1247, "T1", 0.91),
    ToolFailed("c1", "timeout", "traceback text"),
    PhaseChanged("exploitation", "PTES"),
    TokenDelta(12, 1200, 4096, 32768),
    Interrupted("user interrupt"),
]
```
```python
def test_every_event_type_is_registered() -> None:
    assert set(EVENT_TYPES) == {
        "RunStarted",
        "RunFinished",
        "Narration",
        "NarrationRedacted",
        "ToolStarted",
        "ToolOutput",
        "ToolFinished",
        "ToolFailed",
        "PhaseChanged",
        "DEPGUpdated",
        "MemoryUpdated",
        "TokenDelta",
        "Interrupted",
        "SessionState",
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pytest tests/test_events.py -v`
Expected: FAIL — `ImportError: cannot import name 'NarrationRedacted'`

- [ ] **Step 3: Implement in `cism/tui/events.py`**

Add `"NarrationRedacted"` to `__all__` (alphabetically, after `"Narration"`).

Add the dataclass right after `Narration` (currently ends at line 231):
```python
@dataclass(frozen=True, slots=True)
class NarrationRedacted(_Event):
    """Replaces whatever has already been shown for ``entry_id`` with a
    withheld-content notice. Used when the output guardrail's verdict on
    the complete text differs from what was already streamed to the
    transcript — the seam a real (currently pass-through) output guardrail
    needs to retroactively take back content that reached the screen
    before the guardrail finished running on it.
    """

    entry_id: str = ""
    reason: str = ""
```

Add `NarrationRedacted` to the `AgentEvent` union (after `Narration`):
```python
AgentEvent: TypeAlias = (
    RunStarted
    | RunFinished
    | Narration
    | NarrationRedacted
    | ToolStarted
    ...
)
```

Add `NarrationRedacted` to the `EVENT_TYPES` dict (after `Narration`):
```python
EVENT_TYPES: dict[str, type] = {
    cls.__name__: cls
    for cls in (
        RunStarted,
        RunFinished,
        Narration,
        NarrationRedacted,
        ToolStarted,
        ...
    )
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/pytest tests/test_events.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (276 + 1 = 277 passed — one new parametrized case added to the existing round-trip test, plus the registry test still counts as one)

- [ ] **Step 6: Commit**

```bash
git add cism/tui/events.py tests/test_events.py
git commit -m "feat: add NarrationRedacted event — the seam a real output guardrail needs later"
```

---

### Task 6: Collapsible `NarrationEntry` + `Transcript.last_collapsible()`

**Files:**
- Modify: `cism/tui/widgets/transcript.py`
- Modify: `cism/tui/theme.tcss`
- Modify: `tests/test_widgets.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `NarrationEntry.expanded: bool`, `NarrationEntry.toggle() -> None`, `NarrationEntry.redact(reason: str) -> None`, `NarrationEntry.redacted: bool`; `Transcript.last_collapsible() -> ToolEntry | NarrationEntry | None`. Task 9 calls `.toggle()` from `action_toggle_output` and `.redact()` from the `NarrationRedacted` handler.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_widgets.py` (near the existing narration tests, after `test_narration_widget_identity_is_stable_across_chunks`):

```python
async def test_narration_entry_is_expanded_by_default(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "hello", done=True))
        await settle(pilot)
        entry = app.transcript.query_one(NarrationEntry)
        assert entry.expanded is True


async def test_toggling_a_finished_narration_entry_collapses_it(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "hello", done=True))
        await settle(pilot)
        entry = app.transcript.query_one(NarrationEntry)
        entry.toggle()
        await settle(pilot, 5)
        assert entry.expanded is False
        entry.toggle()
        await settle(pilot, 5)
        assert entry.expanded is True


async def test_toggling_a_still_streaming_narration_entry_does_nothing(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "hello", done=False))
        await settle(pilot)
        entry = app.transcript.query_one(NarrationEntry)
        entry.toggle()
        await settle(pilot, 5)
        assert entry.expanded is True


async def test_redact_replaces_shown_text_with_a_withheld_notice(quiet_app) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "some streamed text"))
        await settle(pilot)
        entry = app.transcript.narration("e1")
        entry.redact("blocked: contains a secret")
        await settle(pilot, 5)
        assert entry.text == "blocked: contains a secret"
        assert entry.done is True
        assert entry.redacted is True


async def test_last_collapsible_picks_the_more_recent_of_tool_and_narration(
    quiet_app,
) -> None:
    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(ToolStarted("c1", "nmap", "-sV"))
        await settle(pilot)
        agent.events.put_nowait(Narration("e1", "hello", done=True))
        await settle(pilot)
        last = app.transcript.last_collapsible()
        assert isinstance(last, NarrationEntry)

        agent.events.put_nowait(ToolStarted("c2", "curl", ""))
        await settle(pilot)
        last = app.transcript.last_collapsible()
        assert isinstance(last, ToolEntry)
        assert last.call_id == "c2"
```

- [ ] **Step 2: Run to verify the tests fail**

Run: `.venv/bin/pytest tests/test_widgets.py -v -k "narration_entry_is_expanded or toggling_a_finished or toggling_a_still or redact_replaces or last_collapsible"`
Expected: FAIL — `AttributeError: 'NarrationEntry' object has no attribute 'expanded'` (and `Transcript` has no `last_collapsible`)

- [ ] **Step 3: Implement in `cism/tui/widgets/transcript.py`**

Replace `NarrationEntry` (currently lines 48-88):
```python
class NarrationEntry(Static):
    """Streamed model narration.

    Chunks are appended to one Rich ``Text`` held by the widget and flushed on
    a coalescing timer. The widget is never rebuilt and the buffer is never
    re-joined, so append cost does not grow with entry length.

    Expanded by default — you watch it type live, and a finished answer
    shouldn't vanish on its own. ``ctrl+o`` (routed through
    ``Transcript.last_collapsible()``) can collapse it once it's ``done``,
    the same mechanism ``ToolEntry`` already uses for tool output.
    """

    COMPONENT_CLASSES = {"narration--text", "narration--hint"}

    FLUSH_INTERVAL = 0.06

    def __init__(self, entry_id: str) -> None:
        super().__init__()
        self.entry_id = entry_id
        self.done = False
        self.redacted = False
        self._text = Text()
        self._timer = None
        self._collapsed = False

    @property
    def text(self) -> str:
        return self._text.plain

    @property
    def expanded(self) -> bool:
        return not self._collapsed

    def append(self, chunk: str) -> None:
        self._text.append(chunk)
        if self._timer is None:
            self._timer = self.set_timer(self.FLUSH_INTERVAL, self._flush)

    def finish(self) -> None:
        self.done = True
        self._flush()

    def redact(self, reason: str) -> None:
        """Replace whatever has been shown so far with a withheld-content
        notice — used when the output guardrail's verdict differs from
        what was already streamed."""
        self.done = True
        self.redacted = True
        self._collapsed = False
        self._text = Text(reason or "[response withheld by output guardrail]")
        self._flush()

    def toggle(self) -> None:
        if not self.done:
            return
        self._collapsed = not self._collapsed
        self.refresh(layout=True)

    def _flush(self) -> None:
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self.refresh(layout=True)

    def render(self) -> Text:
        style = self.get_component_rich_style("narration--text")
        self._text.style = style
        if self._collapsed and self.done:
            hint_style = self.get_component_rich_style("narration--hint")
            line_count = self._text.plain.count("\n") + 1 if self._text.plain else 0
            out = Text()
            out.append(f"[{line_count} lines collapsed · ctrl+o to expand]", style=hint_style)
            return out
        return self._text
```

In `Transcript.__init__` (currently lines 307-314), add a unified order list:
```python
    def __init__(self) -> None:
        super().__init__()
        self._narrations: dict[str, NarrationEntry] = {}
        self._tools: dict[str, ToolEntry] = {}
        self._tool_order: list[ToolEntry] = []
        self._collapsible_order: list[ToolEntry | NarrationEntry] = []
        self._following = True
        self._expected_y = 0.0
        self._follow_timer = None
```

In `narration()` (currently lines 356-363), append newly-created entries to the order list:
```python
    def narration(self, entry_id: str) -> NarrationEntry:
        """Get the narration entry for ``entry_id``, creating it if needed."""
        entry = self._narrations.get(entry_id)
        if entry is None:
            entry = NarrationEntry(entry_id)
            self._narrations[entry_id] = entry
            self._collapsible_order.append(entry)
            self.mount(entry)
        return entry
```

In `add_tool()` (currently lines 365-370), do the same:
```python
    def add_tool(self, call_id: str, tool: str, args: str) -> ToolEntry:
        entry = ToolEntry(call_id, tool, args)
        self._tools[call_id] = entry
        self._tool_order.append(entry)
        self._collapsible_order.append(entry)
        self.mount(entry)
        return entry
```

Add `last_collapsible()` right after `last_tool()` (currently lines 375-376):
```python
    def last_tool(self) -> ToolEntry | None:
        return self._tool_order[-1] if self._tool_order else None

    def last_collapsible(self) -> ToolEntry | NarrationEntry | None:
        return self._collapsible_order[-1] if self._collapsible_order else None
```

In `clear_entries()` (currently lines 391-397), clear the new list too:
```python
    def clear_entries(self) -> None:
        self._narrations.clear()
        self._tools.clear()
        self._tool_order.clear()
        self._collapsible_order.clear()
        self.remove_children()
        self._following = True
        self._expected_y = 0.0
```

In `cism/tui/theme.tcss`, add one line right after `NarrationEntry > .narration--text { color: $fg; }` (line 74):
```css
NarrationEntry > .narration--text { color: $fg; }
NarrationEntry > .narration--hint { color: $rule; }
```

- [ ] **Step 4: Run to verify the tests pass**

Run: `.venv/bin/pytest tests/test_widgets.py -v -k "narration_entry_is_expanded or toggling_a_finished or toggling_a_still or redact_replaces or last_collapsible"`
Expected: PASS (5 passed)

- [ ] **Step 5: Run the full suite, including snapshots**

Run: `.venv/bin/pytest -q`
Expected: PASS (277 + 5 = 282 passed). The `NarrationEntry` render path only changes output when `_collapsed and done` — a state nothing in the existing snapshot fixtures reaches — so the 10 pinned SVG snapshots should be unaffected. If any snapshot test fails, inspect the diff with `.venv/bin/pytest tests/test_snapshots.py -v` before assuming it's safe to `--snapshot-update`; do not blindly regenerate snapshots without confirming the visual diff is this change and nothing else.

- [ ] **Step 6: Commit**

```bash
git add cism/tui/widgets/transcript.py cism/tui/theme.tcss tests/test_widgets.py
git commit -m "feat: collapsible NarrationEntry, reusing ToolEntry's ctrl+o mechanism"
```

---

### Task 7: Async streaming `think` node

**Files:**
- Modify: `cism/agent/nodes.py:57-61`
- Modify: `cism/agent/graph.py` (docstring only, line 8)
- Modify: `tests/test_nodes.py`

**Interfaces:**
- Produces: `make_think_node(llm)` now returns an `async def think(state) -> dict` (was sync). `graph.py`'s `build_graph` needs no change — LangGraph accepts async node callables transparently, and `core.py` already drives the graph via `astream(...)`.
- Verified empirically before writing this task: `BaseChatModel.astream()` on a model that only implements `_generate` (e.g. `DummyChatModel`, and every existing `BaseChatModel` test double in this repo) falls back to a single-chunk stream — confirmed by running it directly against `DummyChatModel`, which yielded exactly one `AIMessage` chunk carrying the same `tool_calls` `.invoke()` would have produced. So this change requires zero modification to any existing test double.

- [ ] **Step 1: Write the failing tests**

`tests/test_nodes.py` currently imports `from langchain_core.messages import AIMessage, HumanMessage, ToolMessage` and `from cism.agent.nodes import make_depg_update_node`. Change those two lines, and add two new ones, so the top of the file reads:
```python
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult

from cism.agent.llm import DummyChatModel
from cism.agent.nodes import make_depg_update_node, make_think_node
from cism.agent.state import Phase
from cism.depg import ExtractorRegistry, GenericExtractor
```
(the last two lines are already there today — shown only so the ordering is unambiguous; don't duplicate them.)

Add a fake streaming model and two tests, anywhere after the existing helpers:
```python
class _StreamingChatModel(BaseChatModel):
    """A BaseChatModel that genuinely streams multiple chunks, unlike the
    _generate-only fallback every other test double in this repo relies
    on — proves make_think_node's accumulation actually handles more than
    one chunk, not just the single-chunk fallback case."""

    chunks: list = []

    @property
    def _llm_type(self) -> str:
        return "test-streaming-chat-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content="".join(self.chunks)))]
        )

    async def _astream(self, messages, stop=None, run_manager=None, **kwargs):
        for piece in self.chunks:
            yield ChatGenerationChunk(message=AIMessageChunk(content=piece))


async def test_think_node_accumulates_streamed_chunks_into_one_message() -> None:
    llm = _StreamingChatModel(chunks=["Scan ", "of ", "10.0.0.5 ", "complete."])
    think = make_think_node(llm)
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    assert update["messages"][0].content == "Scan of 10.0.0.5 complete."


async def test_think_node_still_works_against_a_non_streaming_model() -> None:
    llm = DummyChatModel()
    think = make_think_node(llm)
    state = _state([HumanMessage(content="scan 10.0.0.5")])

    update = await think(state)

    assert update["messages"][0].tool_calls[0]["name"] == "dummy_nmap"
```

- [ ] **Step 2: Run to verify the tests fail**

Run: `.venv/bin/pytest tests/test_nodes.py -v -k "think_node"`
Expected: FAIL — `TypeError: object dict can't be used in 'await' expression` (today's `think` is sync and returns a plain dict, not a coroutine)

- [ ] **Step 3: Implement in `cism/agent/nodes.py`**

Replace `make_think_node` (currently lines 57-61):
```python
def make_think_node(llm: BaseChatModel) -> Callable[[AgentState], dict]:
    async def think(state: AgentState) -> dict:
        response = None
        async for chunk in llm.astream(state["messages"]):
            response = chunk if response is None else response + chunk
        return {"messages": [response]}

    return think
```

In `cism/agent/graph.py`, update the module docstring's ASCII diagram (line 8) from:
```
    entry -> think ── llm.invoke() (input guardrail already ran in core.py)
```
to:
```
    entry -> think ── llm.astream(), accumulated into one message (input guardrail already ran in core.py)
```

- [ ] **Step 4: Run to verify the tests pass**

Run: `.venv/bin/pytest tests/test_nodes.py -v -k "think_node"`
Expected: PASS (2 passed)

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (282 + 2 = 284 passed). This is the task most likely to reveal a problem in a test that calls `think` synchronously somewhere unexpected — if anything outside `test_nodes.py` fails, it's almost certainly a caller still doing `think(state)` without `await`; find it with `grep -rn "make_think_node\|think(state" cism/ tests/` and fix the call site, don't work around it in `nodes.py`.

- [ ] **Step 6: Commit**

```bash
git add cism/agent/nodes.py cism/agent/graph.py tests/test_nodes.py
git commit -m "feat: stream the think node's model call instead of blocking on invoke()"
```

---

### Task 8: `core.py` — consume the stream, redact on guardrail mismatch

**Files:**
- Modify: `cism/agent/core.py`
- Modify: `tests/test_langgraph_agent.py`

**Interfaces:**
- Consumes: `NarrationRedacted` (Task 5); the now-async, now-streaming `think` node (Task 7, transparent to `core.py` — it only changes how `_run` reads the graph's stream).
- Produces: `_run()`'s graph loop now emits many non-`done` `Narration` events (one per token chunk) followed by exactly one closing event per run — either `Narration(text="", done=True)` or `NarrationRedacted`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_langgraph_agent.py`. This reuses the `_StreamingChatModel` pattern from Task 7 — since it needs `bind_tools` too (route_after_think needs a model that can be asked for tool calls, even if it declines to use them for these tests), give it a no-op `bind_tools`:

```python
class _StreamingChatModel(BaseChatModel):
    """Like tests/test_nodes.py's fake of the same name, plus a no-op
    bind_tools so it survives LangGraphAgent's tool-binding step — the
    tests here exercise a plain answer, never a tool call."""

    chunks: list = []

    @property
    def _llm_type(self) -> str:
        return "test-streaming-chat-model-core"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content="".join(self.chunks)))]
        )

    async def _astream(self, messages, stop=None, run_manager=None, **kwargs):
        for piece in self.chunks:
            yield ChatGenerationChunk(message=AIMessageChunk(content=piece))

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self


async def test_final_answer_streams_as_multiple_events_then_one_close(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    llm = _StreamingChatModel(chunks=["Scan ", "complete."])
    agent = LangGraphAgent(llm=llm)

    events = await _run_to_completion(agent, "scan it")

    narrations = [e for e in events if isinstance(e, Narration)]
    assert len(narrations) >= 2
    assert all(n.entry_id == narrations[0].entry_id for n in narrations)
    assert [n.done for n in narrations] == [False] * (len(narrations) - 1) + [True]
    assert narrations[-1].text == ""
    assert "".join(n.text for n in narrations) == "Scan complete."


async def test_guardrail_rewrite_emits_narration_redacted_instead_of_close(
    tmp_path, monkeypatch
) -> None:
    from cism.agent.guardrails import GuardrailChain, GuardrailResult, GuardrailSeam, PassThroughStage

    class _BlockEverything:
        def run(self, value):
            return GuardrailResult(allowed=False, value=value, reason="test block")

    monkeypatch.setenv("HOME", str(tmp_path))
    llm = _StreamingChatModel(chunks=["Scan ", "complete."])
    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([PassThroughStage()]),
        output=_BlockEverything(),
    )
    agent = LangGraphAgent(llm=llm, guardrails=guardrails)

    events = await _run_to_completion(agent, "scan it")

    redacted = [e for e in events if isinstance(e, NarrationRedacted)]
    assert len(redacted) == 1
    assert "test block" in redacted[0].reason
    assert not any(isinstance(e, Narration) and e.done for e in events)
```

`GuardrailSeam.output` is typed `GuardrailChain[str]`, but that's a type
hint, not a runtime check — `nodes.py`'s `respond` only ever calls
`output_chain.run(content)`, so `_BlockEverything` (which implements
exactly that one method) satisfies it by duck typing without needing to be
a real `GuardrailChain` wrapping a custom `GuardrailStage`. Confirmed
against `cism/agent/guardrails/chain.py`: `GuardrailResult(allowed: bool,
value: T, reason: str = "")` and `GuardrailSeam(input=, action=, output=)`
are exactly the fields the test above uses.

`tests/test_langgraph_agent.py` already imports `BaseChatModel`, `AIMessage`, `ChatGeneration`, `ChatResult` (used by the existing `_RecordingChatModel`) — only two new imports are needed for the code above: add `AIMessageChunk` to the existing `from langchain_core.messages import AIMessage, BaseMessage` line, and `ChatGenerationChunk` to the existing `from langchain_core.outputs import ChatGeneration, ChatResult` line. Also add `NarrationRedacted` to the existing `from cism.tui.events import (...)` block.

- [ ] **Step 2: Run to verify the tests fail**

Run: `.venv/bin/pytest tests/test_langgraph_agent.py -v -k "streams_as_multiple or guardrail_rewrite"`
Expected: FAIL — today's `_run` still uses `stream_mode="updates"` only, so no intermediate `Narration` events exist and `respond` always emits a `done=True` with the full text, never `NarrationRedacted`.

- [ ] **Step 3: Implement in `cism/agent/core.py`**

Add `NarrationRedacted` to the `cism.tui.events` import block (added in Task 2's edit — extend it further):
```python
from cism.tui.events import (
    AgentEvent,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Interrupted,
    ModelInfo,
    Narration,
    NarrationRedacted,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SessionState,
    ToolFailed,
    ToolFinished,
    ToolStarted,
)
```

Replace the body of `_run()` from the `pending_calls`/`ok` setup through the graph loop (currently lines 145-157):
```python
        pending_calls: dict[str, ToolCall] = {}
        streamed: dict[str, str] = {"text": ""}
        ok = True
        try:
            async for stream_mode, payload in self._graph.astream(
                initial_state, stream_mode=["updates", "messages"]
            ):
                if stream_mode == "messages":
                    chunk, _metadata = payload
                    content = getattr(chunk, "content", "")
                    if content:
                        streamed["text"] += content
                        await self.events.put(
                            Narration(entry_id=f"{run_id}-final", text=content, done=False)
                        )
                    continue
                for node, update in payload.items():
                    if not update:
                        continue
                    await self._translate(node, update, run_id, pending_calls, streamed)
        except Exception as exc:  # a graph-loop failure is content, not a crash
            ok = False
            await self.events.put(
                Narration(entry_id=f"{run_id}-error", text=f"run failed: {exc}", done=True)
            )
```

Update `_translate`'s signature to accept `streamed`, and replace its `respond` branch (currently lines 161-210):
```python
    async def _translate(
        self,
        node: str,
        update: dict[str, Any],
        run_id: str,
        pending_calls: dict[str, ToolCall],
        streamed: dict[str, str],
    ) -> None:
        if node == "think":
            for message in update.get("messages", []):
                for call in getattr(message, "tool_calls", None) or []:
                    pending_calls[call["id"]] = call

        elif node == "act":
            for message in update.get("messages", []):
                call_id = message.tool_call_id
                call = pending_calls.pop(call_id, None)
                tool_name = message.name or (call["name"] if call else "unknown")
                args = str(call["args"]) if call else ""
                await self.events.put(ToolStarted(call_id=call_id, tool=tool_name, args=args))
                if getattr(message, "status", "success") == "error":
                    await self.events.put(
                        ToolFailed(call_id=call_id, reason=str(message.content))
                    )
                else:
                    await self.events.put(
                        ToolFinished(call_id=call_id, summary=str(message.content))
                    )

        elif node == "phase_router":
            new_phase = update.get("phase")
            if new_phase is not None and new_phase != self._phase.current:
                self._phase.transition(new_phase)
                await self.events.put(PhaseChanged(phase=new_phase.to_wire()))

        elif node == "depg_update":
            nodes = update.get("depg_nodes") or {}
            edges = update.get("depg_edges") or []
            payload = (
                tuple(n.to_event() for n in nodes.values()),
                tuple(e.to_event() for e in edges),
            )
            if payload != self._last_depg:
                self._last_depg = payload
                await self.events.put(DEPGUpdated(nodes=payload[0], edges=payload[1]))

        elif node == "respond":
            for message in update.get("messages", []):
                entry_id = f"{run_id}-final"
                final_text = str(message.content)
                if final_text != streamed["text"]:
                    await self.events.put(
                        NarrationRedacted(entry_id=entry_id, reason=final_text)
                    )
                else:
                    await self.events.put(Narration(entry_id=entry_id, text="", done=True))
                streamed["text"] = ""
```

- [ ] **Step 4: Run to verify the tests pass**

Run: `.venv/bin/pytest tests/test_langgraph_agent.py -v -k "streams_as_multiple or guardrail_rewrite"`
Expected: PASS (2 passed)

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (284 + 2 = 286 passed). Pay particular attention to any existing test asserting on the *number* or *exact content* of `Narration` events from a full `_run_to_completion` call (e.g. any test built around `DummyChatModel`'s final "Scan of ... complete" answer) — those now receive one streamed chunk (since `DummyChatModel.astream()` falls back to a single chunk, confirmed in Task 7) followed by one empty-text `done=True` close, so `"".join text across all Narration events with this entry_id"` must still equal the full answer, but a test asserting a *single* `Narration` event with the full text in one shot will now see two. Fix any such assertion to match the new two-event shape rather than reverting the streaming behavior.

- [ ] **Step 6: Commit**

```bash
git add cism/agent/core.py tests/test_langgraph_agent.py
git commit -m "feat: stream the final answer into the TUI, redact on guardrail mismatch"
```

---

### Task 9: `app.py` — `ctrl+o` covers narration too, handle `NarrationRedacted`

**Files:**
- Modify: `cism/tui/app.py`
- Modify: `tests/test_app.py`

**Interfaces:**
- Consumes: `Transcript.last_collapsible()` (Task 6), `NarrationEntry.redact()` (Task 6), `NarrationRedacted` (Task 5).
- Produces: nothing new for other tasks to consume — this is the last task, wiring everything built so far into the running app.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_app.py` (near `test_ctrl_o_toggles_the_last_tool_output`):
```python
async def test_ctrl_o_toggles_the_last_narration_when_it_is_more_recent(
    app_and_agent,
) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(100, 30)) as pilot:
        await replay_all(pilot, agent)
        last = app.transcript.last_collapsible()
        from cism.tui.widgets.transcript import NarrationEntry

        assert isinstance(last, NarrationEntry)
        await pilot.press("ctrl+o")
        await settle(pilot, 8)
        assert last.expanded is False
        await pilot.press("ctrl+o")
        await settle(pilot, 8)
        assert last.expanded is True
```

Add to `tests/test_widgets.py` (this exercises the `_apply` wiring, so it belongs with the other event-application tests — check where `Narration`/`ToolFinished` etc. are applied via `agent.events.put_nowait` and add alongside them):
```python
async def test_narration_redacted_replaces_the_shown_text(quiet_app) -> None:
    from cism.tui.events import NarrationRedacted

    app, agent = quiet_app
    async with app.run_test(size=(100, 30)) as pilot:
        agent.events.put_nowait(Narration("e1", "some streamed text"))
        await settle(pilot)
        agent.events.put_nowait(NarrationRedacted("e1", "blocked: contains a secret"))
        await settle(pilot)
        entry = app.transcript.narration("e1")
        assert entry.text == "blocked: contains a secret"
        assert entry.redacted is True
```

- [ ] **Step 2: Run to verify the tests fail**

Run: `.venv/bin/pytest tests/test_app.py tests/test_widgets.py -v -k "ctrl_o_toggles_the_last_narration or narration_redacted_replaces"`
Expected: FAIL — `action_toggle_output` only ever calls `last_tool()` today (the narration test presses ctrl+o but nothing collapses since the demo log's last entry is a `ToolEntry`, so `last.expanded` on a `NarrationEntry` obtained from `last_collapsible()` — which doesn't exist yet — raises `AttributeError`), and `NarrationRedacted` has no `_apply` branch so the transcript is unaffected.

- [ ] **Step 3: Implement in `cism/tui/app.py`**

Add `NarrationRedacted` to the `from .events import (...)` block (alphabetically after `Narration`):
```python
from .events import (
    Agent,
    AgentEvent,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Interrupted,
    MemoryRow,
    MemoryUpdated,
    ModelInfo,
    Narration,
    NarrationRedacted,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SalienceTerms,
    SessionState,
    TokenDelta,
    ToolFailed,
    ToolFinished,
    ToolOutput,
    ToolStarted,
)
```

In `_apply()`, add a branch right after the existing `Narration` branch (currently lines 198-203):
```python
        elif isinstance(event, Narration):
            entry = transcript.narration(event.entry_id)
            if event.text:
                entry.append(event.text)
            if event.done:
                entry.finish()

        elif isinstance(event, NarrationRedacted):
            transcript.narration(event.entry_id).redact(event.reason)

```

Replace `action_toggle_output` (currently lines 489-492):
```python
    def action_toggle_output(self) -> None:
        entry = self.transcript.last_collapsible()
        if entry is not None:
            entry.toggle()
```

- [ ] **Step 4: Run to verify the tests pass**

Run: `.venv/bin/pytest tests/test_app.py tests/test_widgets.py -v -k "ctrl_o_toggles_the_last_narration or narration_redacted_replaces"`
Expected: PASS (2 passed)

- [ ] **Step 5: Run the full suite one final time**

Run: `.venv/bin/pytest -q`
Expected: PASS (286 + 2 = 288 passed). This is the last task — a clean full-suite run here confirms every earlier task's changes still compose correctly together, not just in isolation.

- [ ] **Step 6: Commit**

```bash
git add cism/tui/app.py tests/test_app.py tests/test_widgets.py
git commit -m "feat: wire ctrl+o and NarrationRedacted for the streamed answer"
```

---

## Final Verification (manual, after all 9 tasks)

- [ ] Run the full suite once more from a clean state: `.venv/bin/pytest -q` — expect all ~288 tests passing.
- [ ] Live smoke test against local Ollama, exercising every piece built in this plan in one session:
  ```bash
  CISM_API_KEY=ollama .venv/bin/python run_agent.py --base-url http://localhost:11434/v1 --model qwen2.5:3b --target 10.0.0.5
  ```
  In the TUI: submit a turn, watch the final answer stream in token by token; press `ctrl+o` once it's done to collapse it, again to expand it; run `/api http://localhost:11434/v1` and `/model qwen2.5:3b` (re-pointing at the same server, to confirm both commands work without erroring) and check the status bar updates; quit with `ctrl+c` twice.
- [ ] Confirm `git log --oneline -9` shows exactly the 9 commits from this plan, each independently reviewable.

## Left for later (not this plan — see the design spec's "Out of scope"/"Left open")

- Graph/state persistence (LangGraph checkpointers).
- Real reasoning/"thinking" content extraction (blocked on the upstream `langchain-openai` bug dropping `reasoning_content` for OpenAI-compatible providers).
- Real output-guardrail logic — this plan only builds the seam (`NarrationRedacted`) and proves it with a test-local blocking stage; the chain itself stays pass-through.
