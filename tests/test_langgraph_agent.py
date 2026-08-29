"""cism/agent/core.py: LangGraphAgent against the Agent protocol.

Runs the whole skeleton end to end with every dependency at its default —
DummyChatModel, the dummy tools, no-op guardrails — the same "no lab, no
weights, no network" bar the TUI's own replay demo holds itself to.
"""

from __future__ import annotations

import asyncio

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from cism.agent import LangGraphAgent
from cism.agent.guardrails import GuardrailChain, GuardrailResult, GuardrailSeam, PassThroughStage
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap
from cism.tui.events import (
    Agent,
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
    drain,
)


class _RecordingChatModel(BaseChatModel):
    """A ``BaseChatModel`` that, unlike ``DummyChatModel``, does implement
    ``bind_tools`` — standing in for a real provider integration so the
    binding wired up in ``cism.agent.core`` can be asserted without a
    network-backed model."""

    bound_tools: list = []

    @property
    def _llm_type(self) -> str:
        return "cism-recording-chat-model"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs,
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="done"))])

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        self.bound_tools = list(tools)
        return self


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


def test_a_model_that_supports_bind_tools_is_bound_to_the_registry(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    model = _RecordingChatModel()
    tools = ToolRegistry([dummy_nmap, dummy_msfconsole])

    LangGraphAgent(llm=model, tools=tools)

    assert {t.name for t in model.bound_tools} == {"dummy_nmap", "dummy_msfconsole"}


async def _run_to_completion(agent: LangGraphAgent, text: str, timeout: float = 5.0) -> list:
    await agent.submit(text)
    events: list = []
    while not any(isinstance(e, RunFinished) for e in events):
        events.extend(await asyncio.wait_for(drain(agent.events), timeout=timeout))
    return events


def test_satisfies_the_agent_protocol(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert isinstance(LangGraphAgent(), Agent)


async def test_a_default_run_starts_and_finishes_ok(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="10.0.0.5")
    await agent.start()

    events = await _run_to_completion(agent, "scan 10.0.0.5 and tell me what is exposed")

    assert isinstance(events[0], SessionState)
    assert isinstance(events[1], RunStarted)
    assert isinstance(events[-1], RunFinished)
    assert events[-1].ok is True
    await agent.aclose()


async def test_every_tool_started_has_a_matching_finish_by_call_id(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="10.0.0.5")
    events = await _run_to_completion(agent, "scan 10.0.0.5")

    started = {e.call_id for e in events if isinstance(e, ToolStarted)}
    finished = {e.call_id for e in events if isinstance(e, (ToolFinished, ToolFailed))}
    assert started
    assert started == finished
    await agent.aclose()


async def test_dummy_run_produces_a_final_narration_and_two_phase_changes(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="10.0.0.5")
    events = await _run_to_completion(agent, "scan 10.0.0.5")

    narrations = [e for e in events if isinstance(e, Narration)]
    assert narrations and narrations[-1].done is True

    phase_changes = [e.phase for e in events if isinstance(e, PhaseChanged)]
    assert phase_changes == ["enumeration", "vulnerability-discovery"]
    await agent.aclose()


async def test_a_default_run_populates_the_depg_from_live_tool_calls(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="10.0.0.5")
    events = await _run_to_completion(agent, "scan 10.0.0.5")

    depg_updates = [e for e in events if isinstance(e, DEPGUpdated)]
    assert depg_updates
    assert depg_updates[-1].nodes
    assert all(n.target == "10.0.0.5" for n in depg_updates[-1].nodes)
    await agent.aclose()


async def test_depg_updates_are_never_emitted_back_to_back_unchanged(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="10.0.0.5")
    events = await _run_to_completion(agent, "scan 10.0.0.5")

    depg_updates = [e for e in events if isinstance(e, DEPGUpdated)]
    seen = [(e.nodes, e.edges) for e in depg_updates]
    assert len(seen) == len(set(seen))
    await agent.aclose()


async def test_interrupt_cancels_the_run_and_is_the_last_event(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()
    await agent.submit("scan it")
    await agent.interrupt()

    events = []
    try:
        while True:
            events.extend(await asyncio.wait_for(drain(agent.events), timeout=0.3))
    except asyncio.TimeoutError:
        pass

    assert events
    assert isinstance(events[-1], Interrupted)
    await agent.aclose()


async def test_a_blocked_input_ends_the_run_without_touching_the_model(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    class _RejectEverything:
        name = "reject-all"

        def check(self, value: str) -> GuardrailResult[str]:
            return GuardrailResult(allowed=False, value=value, reason="test rejection")

    guardrails = GuardrailSeam(
        input=GuardrailChain([_RejectEverything()]),
        action=GuardrailChain([PassThroughStage()]),
        output=GuardrailChain([PassThroughStage()]),
    )
    agent = LangGraphAgent(guardrails=guardrails)

    events = await _run_to_completion(agent, "scan 10.0.0.5")

    assert not any(isinstance(e, ToolStarted) for e in events)
    assert events[-1].ok is False
    await agent.aclose()


async def test_a_blocked_action_never_reaches_the_tool(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    class _RejectEverything:
        name = "reject-all"

        def check(self, value) -> GuardrailResult:
            return GuardrailResult(allowed=False, value=value, reason="scope violation")

    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([_RejectEverything()]),
        output=GuardrailChain([PassThroughStage()]),
    )
    agent = LangGraphAgent(guardrails=guardrails)

    events = await _run_to_completion(agent, "scan 10.0.0.5")

    failures = [e for e in events if isinstance(e, ToolFailed)]
    assert failures
    assert all("scope violation" in e.reason for e in failures)
    assert not any(isinstance(e, ToolFinished) for e in events)
    await agent.aclose()


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
