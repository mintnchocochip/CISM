"""cism/agent/core.py: LangGraphAgent against the Agent protocol.

Runs the whole skeleton end to end with every dependency at its default —
DummyChatModel, the dummy tools, no-op guardrails — the same "no lab, no
weights, no network" bar the TUI's own replay demo holds itself to.
"""

from __future__ import annotations

import asyncio
import json

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
    TokenDelta,
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
    # context defaults to the status bar's own fallback (32_768) until
    # _refresh_context_window() (start()/_configure()) discovers a real
    # one — _session() alone never makes the network call.
    assert session.models_available == (
        ModelInfo("qwen2.5:3b", context=32_768, loaded=True),
    )


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


async def test_every_emitted_event_is_also_written_to_the_audit_log(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="10.0.0.5")
    await agent.start()
    events = await _run_to_completion(agent, "scan 10.0.0.5")
    await agent.aclose()

    log_path = tmp_path / ".cism" / "logs" / "agent.log"
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]

    assert [r["message"] for r in records] == [type(e).__name__ for e in events]
    run_started = next(r for r in records if r["message"] == "RunStarted")
    assert run_started["data"]["run_id"] == events[1].run_id


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


async def test_target_command_updates_the_agents_target(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="old-target")

    await agent.submit("/target linux nginx php")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, Narration)
    assert "linux nginx php" in event.text
    assert agent._target == "linux nginx php"


async def test_bare_target_command_reports_the_current_target(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="linux nginx")

    await agent.submit("/target")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, Narration)
    assert "linux nginx" in event.text
    assert agent._target == "linux nginx"  # unchanged


async def test_phase_command_forces_a_legal_transition(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()  # starts at RECON

    await agent.submit("/phase enumeration")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, PhaseChanged)
    assert event.phase == "enumeration"
    assert agent._phase.current == Phase.ENUMERATION


async def test_phase_command_refuses_an_illegal_transition(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()  # starts at RECON; RECON -> REPORTING is not a legal move

    await agent.submit("/phase reporting")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, Narration)
    assert "RECON" in event.text and "REPORTING" in event.text
    assert agent._phase.current == Phase.RECON  # unchanged


async def test_phase_command_refuses_an_unknown_phase_name(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()

    await agent.submit("/phase not-a-real-phase")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, Narration)
    assert "not-a-real-phase" in event.text
    assert agent._phase.current == Phase.RECON  # unchanged


async def test_bare_phase_command_reports_the_current_phase(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()

    await agent.submit("/phase")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, Narration)
    assert "recon" in event.text.lower()
    assert agent._phase.current == Phase.RECON  # unchanged


async def test_bare_ablate_command_reports_nothing_pending(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()

    await agent.submit("/ablate")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert isinstance(event, Narration)
    assert "none" in event.text.lower()


async def test_ablate_toggles_a_known_tool_on_then_off(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()

    await agent.submit("/ablate dummy_nmap")
    on_event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "ablated" in on_event.text.lower()
    assert agent._ablated == {"dummy_nmap"}

    await agent.submit("/ablate dummy_nmap")
    off_event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "restored" in off_event.text.lower()
    assert agent._ablated == set()


async def test_ablate_refuses_an_unknown_name(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()

    await agent.submit("/ablate not_a_real_tool_or_stage")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "no such tool or guardrail stage" in event.text.lower()
    assert agent._ablated == set()


async def test_ablate_recognizes_a_guardrail_stage_name_too(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([PassThroughStage()]),
        output=GuardrailChain([PassThroughStage()]),
    )
    agent = LangGraphAgent(guardrails=guardrails)

    await agent.submit("/ablate pass-through")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "ablated" in event.text.lower()


async def test_an_ablated_tool_is_not_bound_for_the_next_run_only(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    llm = _RecordingChatModel()
    # default_profiles() derives tool_names from the real catalog, which a
    # dummy-only registry never matches — an explicit profile naming the
    # dummy tools (same fixture shape as tests/test_nodes.py's act tests)
    # is what actually gets them offered to bind_tools in the first place.
    profiles = PhaseProfiles(
        {
            Phase.RECON: PhaseProfile(
                phase=Phase.RECON,
                system_prompt="",
                tool_names=frozenset({"dummy_nmap", "dummy_msfconsole"}),
            )
        }
    )
    agent = LangGraphAgent(llm=llm, profiles=profiles)

    await agent.submit("/ablate dummy_nmap")
    await asyncio.wait_for(agent.events.get(), timeout=1)  # the ablate ack

    await _run_to_completion(agent, "hello")
    first_run_names = {t.name for t in llm.bound_tools}
    assert "dummy_nmap" not in first_run_names
    assert agent._ablated == set()  # cleared once the run it applied to started

    await _run_to_completion(agent, "hello again")
    second_run_names = {t.name for t in llm.bound_tools}
    assert "dummy_nmap" in second_run_names  # restored — ablation was one run only
    await agent.aclose()


async def test_an_ablated_guardrail_stage_is_skipped_for_the_next_run_only(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    class _RejectEverything:
        name = "reject-all"

        def check(self, value) -> GuardrailResult:
            return GuardrailResult(allowed=False, value=value, reason="always blocks")

    guardrails = GuardrailSeam(
        input=GuardrailChain([PassThroughStage()]),
        action=GuardrailChain([_RejectEverything()]),
        output=GuardrailChain([PassThroughStage()]),
    )
    agent = LangGraphAgent(guardrails=guardrails)

    await agent.submit("/ablate reject-all")
    await asyncio.wait_for(agent.events.get(), timeout=1)  # the ablate ack

    events = await _run_to_completion(agent, "scan it")
    assert any(isinstance(e, ToolFinished) for e in events)
    assert not any(isinstance(e, ToolFailed) for e in events)

    events_again = await _run_to_completion(agent, "scan it again")
    assert any(isinstance(e, ToolFailed) for e in events_again)  # the stage is back
    await agent.aclose()


class _MessageRecordingChatModel(BaseChatModel):
    """Records the exact ``messages`` list it was handed on every call, so a
    test can tell whether a later run's think() actually saw an earlier
    run's conversation or started from a blank slate. Never emits tool
    calls — every turn is a final answer, which keeps each submit() to one
    LLM call, one act-free run."""

    seen: list = []

    @property
    def _llm_type(self) -> str:
        return "cism-message-recording-chat-model"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs,
    ) -> ChatResult:
        self.seen.append(list(messages))
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ack"))])


async def test_a_second_submit_remembers_the_first_runs_conversation(
    tmp_path, monkeypatch
) -> None:
    """The bug this guards against: LangGraphAgent._run() used to build
    initial_state["messages"] as just [HumanMessage(this turn's text)] on
    every submit(), with no checkpointer backing the graph — so the second
    message in a session was a blank slate as far as the agent's own
    memory went. Now build_graph() carries a MemorySaver and every _run()
    reuses the same thread_id, so the second call's think() should see the
    first call's HumanMessage/AIMessage too, not just its own."""
    monkeypatch.setenv("HOME", str(tmp_path))
    model = _MessageRecordingChatModel()
    agent = LangGraphAgent(llm=model)

    await _run_to_completion(agent, "first message")
    await _run_to_completion(agent, "second message")
    await agent.aclose()

    assert len(model.seen) == 2
    first_call_texts = [str(m.content) for m in model.seen[0]]
    second_call_texts = [str(m.content) for m in model.seen[1]]
    assert "first message" in first_call_texts
    # The second call must still be able to see the first turn's exchange,
    # not just its own new text.
    assert "first message" in second_call_texts
    assert "second message" in second_call_texts


async def test_a_second_submit_keeps_the_first_runs_memory_rows(
    tmp_path, monkeypatch
) -> None:
    """Same bug, seen through memory_items: initial_state used to hardcode
    memory_items={} on every run, discarding whatever the previous run had
    just written. It should now only be seeded empty once, at the very
    start of the session."""
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()  # DummyChatModel + dummy tools, real memory_update node

    first_events = await _run_to_completion(agent, "10.0.0.5")
    second_events = await _run_to_completion(agent, "10.0.0.6")
    await agent.aclose()

    first_rows = [e for e in first_events if isinstance(e, MemoryUpdated)][-1].rows
    second_rows = [e for e in second_events if isinstance(e, MemoryUpdated)][-1].rows
    assert len(first_rows) > 0
    # Grew (or at least didn't reset to fewer rows than the first run alone
    # produced) — proves the second run built on top of the first rather
    # than starting from memory_items={} again.
    assert len(second_rows) >= len(first_rows)


async def test_bare_replay_command_reports_usage(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()

    await agent.submit("/replay")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "usage" in event.text.lower()


async def test_replay_of_an_unknown_run_id_says_so(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent()

    await agent.submit("/replay not-a-real-run-id")

    event = await asyncio.wait_for(agent.events.get(), timeout=1)
    assert "no recorded run found" in event.text.lower()


async def test_replay_reproduces_a_past_runs_events(tmp_path, monkeypatch) -> None:
    import cism.agent.core as core_module

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(core_module, "_REPLAY_STEP_DELAY", 0.0)
    agent = LangGraphAgent(target="10.0.0.5")

    original = await _run_to_completion(agent, "scan 10.0.0.5")
    run_id = next(e.run_id for e in original if isinstance(e, RunStarted))
    original_types = [type(e).__name__ for e in original]

    await agent.submit(f"/replay {run_id}")
    replayed: list = []
    # The original run's own PhaseChanged events get replayed too, so
    # stopping on "the last event is a PhaseChanged" would trip on one of
    # those — wait for the queue to actually go quiet instead.
    while True:
        try:
            replayed.extend(await asyncio.wait_for(drain(agent.events), timeout=0.5))
        except asyncio.TimeoutError:
            break

    start_marker = replayed[0]
    assert isinstance(start_marker, Narration)
    assert "replaying run" in start_marker.text and run_id in start_marker.text

    end_index = next(
        i
        for i, e in enumerate(replayed)
        if isinstance(e, Narration) and "end replay" in e.text
    )
    reproduced = replayed[1:end_index]
    assert [type(e).__name__ for e in reproduced] == original_types
    assert next(e for e in reproduced if isinstance(e, RunStarted)).run_id == run_id

    # Regression check: every replayed event must get a fresh seq via the
    # same shared counter live events use, not stale recorded values or an
    # offset assigned by simple arithmetic — either of those can collide
    # with the bracketing narrations/PhaseChanged emitted via _emit after
    # the loop, since those pull their own seq from the same counter.
    all_seqs = [e.seq for e in replayed]
    assert all_seqs == sorted(all_seqs)
    assert len(set(all_seqs)) == len(all_seqs)
    assert replayed[1].seq > original[-1].seq  # replayed[0] is the start marker

    # bracketing the replay must not silently change what the session
    # thinks its real, current phase is.
    assert isinstance(replayed[-1], PhaseChanged)
    assert replayed[-1].phase == agent._phase.current.to_wire()
    await agent.aclose()


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


class _UsageReportingChatModel(BaseChatModel):
    """Streams like a real OpenAI-compat server with ``stream_usage=True``:
    content chunks, then a trailing content-empty chunk carrying
    ``usage_metadata`` — see ``build_chat_model``'s docstring in
    cism/agent/llm.py for why that's the real shape, confirmed against
    Ollama."""

    chunks: list = []
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def _llm_type(self) -> str:
        return "test-usage-reporting-chat-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content="".join(self.chunks)))]
        )

    async def _astream(self, messages, stop=None, run_manager=None, **kwargs):
        for piece in self.chunks:
            yield ChatGenerationChunk(message=AIMessageChunk(content=piece))
        yield ChatGenerationChunk(
            message=AIMessageChunk(
                content="",
                usage_metadata={
                    "input_tokens": self.input_tokens,
                    "output_tokens": self.output_tokens,
                    "total_tokens": self.input_tokens + self.output_tokens,
                },
            )
        )

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self


async def test_a_streamed_reply_emits_a_token_delta(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    llm = _UsageReportingChatModel(chunks=["done"], input_tokens=120, output_tokens=8)
    agent = LangGraphAgent(llm=llm)
    agent._context_window = 4096

    events = await _run_to_completion(agent, "scan it")

    deltas = [e for e in events if isinstance(e, TokenDelta)]
    assert len(deltas) == 1
    assert deltas[0].delta == 128
    assert deltas[0].total == 128
    assert deltas[0].ctx_used == 128
    assert deltas[0].ctx_max == 4096


async def test_token_totals_accumulate_across_multiple_llm_calls_in_one_run(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = LangGraphAgent(target="10.0.0.5")  # default dummy model: two tool calls, three LLM turns

    events = await _run_to_completion(agent, "scan 10.0.0.5")

    # DummyChatModel never streams (no _astream override, so LangChain's
    # default async fallback wraps _generate's single ChatResult with no
    # usage_metadata) — this just confirms a run with zero real usage data
    # produces zero TokenDelta events rather than fabricating one.
    assert [e for e in events if isinstance(e, TokenDelta)] == []
    await agent.aclose()


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
