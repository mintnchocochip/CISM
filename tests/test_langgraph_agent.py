"""cism/agent/core.py: LangGraphAgent against the Agent protocol.

Runs the whole skeleton end to end with every dependency at its default —
DummyChatModel, the dummy tools, no-op guardrails — the same "no lab, no
weights, no network" bar the TUI's own replay demo holds itself to.
"""

from __future__ import annotations

import asyncio

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult

from cism.agent import LangGraphAgent
from cism.agent.guardrails import GuardrailChain, GuardrailResult, GuardrailSeam, PassThroughStage
from cism.agent.llm import DummyChatModel
from cism.agent.profiles import PhaseProfile, PhaseProfiles
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap
from cism.depg import GenericExtractor, LLMExtractor
from cism.tui.events import (
    Agent,
    DEPGUpdated,
    Interrupted,
    MemoryUpdated,
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


async def test_a_blocked_action_surfaces_its_rich_reason_via_toolfailed_not_the_llm(
    tmp_path, monkeypatch
) -> None:
    """ToolFailed is what the TUI/operator sees — it should keep getting
    the full detail even though the LLM (via ToolMessage.content) no
    longer does."""
    monkeypatch.setenv("HOME", str(tmp_path))

    class _RichBlock:
        name = "scope-guard"

        def check(self, value) -> GuardrailResult:
            return GuardrailResult(allowed=False, value=value, reason="10.0.0.99 is outside scope")

    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([_RichBlock()]),
        output=GuardrailChain([PassThroughStage()]),
    )
    agent = LangGraphAgent(guardrails=guardrails)

    events = await _run_to_completion(agent, "scan 10.0.0.5")

    failures = [e for e in events if isinstance(e, ToolFailed)]
    assert failures, "expected at least one ToolFailed event"
    assert "10.0.0.99" in failures[0].reason
    assert "scope-guard" in failures[0].reason
    await agent.aclose()


async def test_a_live_run_emits_memory_updated(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="10.0.0.5")
    await agent.start()

    events = await _run_to_completion(agent, "scan 10.0.0.5")

    memory_events = [e for e in events if isinstance(e, MemoryUpdated)]
    assert memory_events
    assert memory_events[-1].rows
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


class _PreambleThenToolCallChatModel(BaseChatModel):
    """A fake model whose first turn streams ordinary preamble text
    alongside a tool call (content and a tool call in the same turn — real
    models sometimes do this), and whose second turn (after the tool
    result comes back) streams only the final answer with no tool calls.
    Exercises the leftover-preamble bug: without the fix, the first turn's
    "Let me check. " content lingers in ``core.py``'s ``streamed["text"]``
    accumulator and corrupts the comparison against the real final answer
    once the run reaches "respond"."""

    call_count: int = 0

    @property
    def _llm_type(self) -> str:
        return "test-preamble-then-tool-call-chat-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        raise NotImplementedError("this test double only supports astream")

    async def _astream(self, messages, stop=None, run_manager=None, **kwargs):
        self.call_count += 1
        if self.call_count == 1:
            yield ChatGenerationChunk(message=AIMessageChunk(content="Let me check. "))
            yield ChatGenerationChunk(
                message=AIMessageChunk(
                    content="",
                    tool_call_chunks=[
                        {
                            "name": "dummy_nmap",
                            "args": '{"target": "10.0.0.5"}',
                            "id": "call_1",
                            "index": 0,
                        }
                    ],
                )
            )
        else:
            yield ChatGenerationChunk(message=AIMessageChunk(content="Scan "))
            yield ChatGenerationChunk(message=AIMessageChunk(content="complete."))

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self


async def test_preamble_before_a_tool_call_does_not_corrupt_the_final_narration(
    tmp_path, monkeypatch
) -> None:
    """Regression test for the false-positive NarrationRedacted bug: a
    think turn that streams non-empty content *and* routes to "act" (via
    a tool call) must not leave its text sitting in the accumulator for
    the next think turn's text to be appended to. If it does, "respond"'s
    real final text won't match the corrupted accumulator and the run
    incorrectly ends in NarrationRedacted instead of a clean close."""
    monkeypatch.setenv("HOME", str(tmp_path))
    llm = _PreambleThenToolCallChatModel()
    agent = LangGraphAgent(llm=llm, target="10.0.0.5")

    events = await _run_to_completion(agent, "scan it")

    redacted = [e for e in events if isinstance(e, NarrationRedacted)]
    assert redacted == []

    narrations = [e for e in events if isinstance(e, Narration)]
    assert narrations and narrations[-1].done is True
    assert narrations[-1].text == ""


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


async def test_tool_binding_happens_per_phase_inside_think_not_at_construction(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    model = _RecordingChatModel()
    # Profiles that name tools this registry actually has, so "did it bind?"
    # is a question about *when*, not about whether the names lined up.
    profiles = PhaseProfiles(
        {
            phase: PhaseProfile(
                phase=phase, system_prompt="p", tool_names=frozenset({"dummy_nmap"})
            )
            for phase in Phase
        }
    )
    agent = LangGraphAgent(
        llm=model,
        tools=ToolRegistry([dummy_nmap, dummy_msfconsole]),
        profiles=profiles,
        target="10.0.0.5",
    )

    assert model.bound_tools == []  # nothing bound yet at construction time

    await agent.start()
    await _run_to_completion(agent, "scan 10.0.0.5")

    assert model.bound_tools  # bound once think actually ran
    await agent.aclose()


async def test_the_bare_dummy_backed_agent_uses_generic_extractor(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()

    assert isinstance(agent._extractors.get("some-tool-with-no-hand-written-extractor"), GenericExtractor)


async def test_a_configured_real_endpoint_defaults_to_llm_extractor(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(llm=DummyChatModel(), endpoint="http://example.invalid/v1", model_name="m")

    assert isinstance(agent._extractors.get("some-tool-with-no-hand-written-extractor"), LLMExtractor)
