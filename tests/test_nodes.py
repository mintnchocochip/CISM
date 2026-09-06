"""cism/agent/nodes.py: depg_update tested in isolation against a hand-built
AgentState — no LLM, no compiled graph. Exercises what the node is for:
turning this step's tool results into DEPG graph state, without ever losing
what earlier steps already found.
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from langchain_core.tools import StructuredTool

from cism.agent.guardrails import GuardrailChain, GuardrailResult, GuardrailSeam
from cism.agent.llm import DummyChatModel
from cism.agent.nodes import make_act_node, make_depg_update_node, make_think_node
from cism.agent.profiles import PhaseProfile, PhaseProfiles
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap
from cism.depg import ExtractorRegistry, GenericExtractor

#: The three plain think-node tests below don't care about phase-scoped
#: prompts/tools, just that make_think_node's streaming accumulation works
#: — an empty-tools RECON profile is the minimal fixture for that.
_NO_OP_PROFILES = PhaseProfiles(
    {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset())}
)


class _RecordingChatModelForNodesTest(BaseChatModel):
    """The smallest model think() can drive: answers once, binds anything."""

    @property
    def _llm_type(self) -> str:
        return "test-recording-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="done"))])

    def bind_tools(self, tools, **kwargs):
        return self


def _state(messages, depg_nodes=None, depg_edges=None) -> dict:
    return {
        "messages": messages,
        "phase": Phase.RECON,
        "depg_nodes": depg_nodes or {},
        "depg_edges": depg_edges or [],
        "run_id": "run-1",
        "target": "10.0.0.5",
    }


def _tool_round(call_id: str, name: str, content: str, *, error: bool = False):
    ai = AIMessage(content="", tool_calls=[{"id": call_id, "name": name, "args": {}}])
    kwargs = {"status": "error"} if error else {}
    result = ToolMessage(content=content, tool_call_id=call_id, name=name, **kwargs)
    return ai, result


def _depg_update():
    return make_depg_update_node(ExtractorRegistry({}, GenericExtractor()))


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
    think = make_think_node(llm, ToolRegistry([]), _NO_OP_PROFILES)
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    assert update["messages"][0].content == "Scan of 10.0.0.5 complete."


class _EmptyStreamChatModel(BaseChatModel):
    """A model whose ``astream`` yields zero chunks — standing in for a
    provider that errors mid-handshake or returns an empty completion.
    Overrides the public ``astream`` directly (rather than ``_astream``)
    to force truly zero iterations: ``BaseChatModel``'s own default
    ``astream()`` wrapper raises ``ValueError("No generation chunks were
    returned")`` itself when the underlying ``_astream`` yields nothing,
    so going through ``_astream`` can't exercise the zero-chunk path this
    test targets. Proves make_think_node's accumulation defaults to an
    empty AIMessage instead of returning None, which would otherwise blow
    up downstream in the "respond" node's ``str(last.content)``."""

    @property
    def _llm_type(self) -> str:
        return "test-empty-stream-chat-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=""))])

    async def astream(self, *args, **kwargs):
        return
        yield  # pragma: no cover - makes this an async generator with no items


async def test_think_node_defaults_to_an_empty_message_when_the_stream_yields_nothing() -> None:
    llm = _EmptyStreamChatModel()
    think = make_think_node(llm, ToolRegistry([]), _NO_OP_PROFILES)
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    assert update["messages"][0] is not None
    assert update["messages"][0].content == ""


async def test_think_node_still_works_against_a_non_streaming_model() -> None:
    llm = DummyChatModel()
    think = make_think_node(llm, ToolRegistry([]), _NO_OP_PROFILES)
    state = _state([HumanMessage(content="scan 10.0.0.5")])

    update = await think(state)

    assert update["messages"][0].tool_calls[0]["name"] == "dummy_nmap"


def test_a_successful_tool_call_produces_a_depg_node_for_the_target() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "[dummy] nmap -sV 10.0.0.5 -> 3 open ports")
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = _depg_update()(state)

    assert len(update["depg_nodes"]) == 1
    node = next(iter(update["depg_nodes"].values()))
    assert node.target == "10.0.0.5"
    assert node.evidence


def test_an_errored_tool_call_now_produces_a_node_instead_of_being_dropped() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = _depg_update()(state)

    assert len(update["depg_nodes"]) == 1


def test_multiple_tool_calls_in_one_step_each_produce_their_own_node() -> None:
    ai = AIMessage(
        content="",
        tool_calls=[
            {"id": "call-1", "name": "dummy_nmap", "args": {}},
            {"id": "call-2", "name": "dummy_msfconsole", "args": {}},
        ],
    )
    r1 = ToolMessage(content="ok-1", tool_call_id="call-1", name="dummy_nmap")
    r2 = ToolMessage(content="ok-2", tool_call_id="call-2", name="dummy_msfconsole")
    state = _state([HumanMessage(content="scan it"), ai, r1, r2])

    update = _depg_update()(state)

    assert len(update["depg_nodes"]) == 2


def test_nodes_found_on_an_earlier_step_survive_a_step_with_no_new_evidence() -> None:
    depg_update = _depg_update()
    ai1, result1 = _tool_round("call-1", "dummy_nmap", "ok")
    first = depg_update(_state([HumanMessage(content="scan it"), ai1, result1]))

    ai2, result2 = _tool_round("call-2", "dummy_msfconsole", "boom", error=True)
    second_state = _state(
        [HumanMessage(content="scan it"), ai1, result1, ai2, result2],
        depg_nodes=first["depg_nodes"],
        depg_edges=first["depg_edges"],
    )

    update = depg_update(second_state)

    assert update["depg_nodes"].keys() >= first["depg_nodes"].keys()


def test_a_failed_tool_call_now_produces_a_blocked_tombstone_node() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = _depg_update()(state)

    assert len(update["depg_nodes"]) == 1
    node = next(iter(update["depg_nodes"].values()))
    assert node.state == "blocked"


def test_a_second_call_on_the_same_target_gets_an_edge_from_the_first() -> None:
    depg_update = _depg_update()
    ai1, result1 = _tool_round("call-1", "dummy_nmap", "ok")
    first = depg_update(_state([HumanMessage(content="scan it"), ai1, result1]))

    ai2, result2 = _tool_round("call-2", "dummy_msfconsole", "ok too")
    second_state = _state(
        [HumanMessage(content="scan it"), ai1, result1, ai2, result2],
        depg_nodes=first["depg_nodes"], depg_edges=first["depg_edges"],
    )
    update = depg_update(second_state)

    assert len(update["depg_edges"]) == 1


def test_nodes_produced_in_the_same_step_do_not_link_to_each_other() -> None:
    """Two sibling ports from one nmap-shaped call must not chain A -> B."""
    from cism.depg import ExtractorRegistry
    from cism.depg.extractors import NmapExtractor

    depg_update = make_depg_update_node(
        ExtractorRegistry({"nmap": NmapExtractor()}, GenericExtractor())
    )
    ai = AIMessage(
        content="", tool_calls=[{"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}]
    )
    result = ToolMessage(
        content="22/tcp   open  ssh\n80/tcp   open  http\n",
        tool_call_id="c1", name="nmap",
    )
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = depg_update(state)

    assert len(update["depg_nodes"]) == 2
    assert update["depg_edges"] == []


def test_phase_router_reports_when_it_actually_moved() -> None:
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    state = _state(
        [
            HumanMessage(content="x"),
            ToolMessage(content="ok", tool_call_id="c1", name="dummy_nmap"),
        ]
    )

    update = router(state)

    assert update["phase_changed"] is True


def test_phase_router_reports_no_change_when_it_stays_put() -> None:
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="x"), ai, result])

    update = router(state)

    assert update["phase_changed"] is False


def _memory_state(messages, depg_nodes=None, phase_changed=False) -> dict:
    return {
        "messages": messages, "phase": Phase.RECON, "depg_nodes": depg_nodes or {},
        "depg_edges": [], "run_id": "run-1", "target": "10.0.0.5",
        "memory_items": {}, "phase_changed": phase_changed,
    }


def test_memory_update_records_a_successful_finding_from_this_step() -> None:
    from cism.agent.nodes import make_memory_update_node
    from cism.depg.evidence import Evidence
    from cism.depg.node import Node

    node = Node(
        id="n1", cause_class="open-port", target="10.0.0.5", signal="22/tcp",
        evidence=[
            Evidence(
                timestamp="t", tool="nmap", exit_signal="22/tcp open ssh",
                tier="T2", call_id="c1",
            )
        ],
    )
    ai, result = _tool_round("c1", "nmap", "22/tcp open ssh")
    state = _memory_state([HumanMessage(content="scan"), ai, result], depg_nodes={"n1": node})

    update = make_memory_update_node()(state)

    assert len(update["memory_items"]) == 1


def test_memory_update_ignores_depg_nodes_from_an_earlier_step() -> None:
    from cism.agent.nodes import make_memory_update_node
    from cism.depg.evidence import Evidence
    from cism.depg.node import Node

    old_node = Node(
        id="n1", cause_class="open-port", target="10.0.0.5", signal="22/tcp",
        evidence=[
            Evidence(timestamp="t", tool="nmap", exit_signal="x", tier="T2", call_id="old-call")
        ],
    )
    ai, result = _tool_round("c2", "hydra", "no creds", error=True)
    state = _memory_state([HumanMessage(content="scan"), ai, result], depg_nodes={"n1": old_node})

    update = make_memory_update_node()(state)

    depg_derived = [k for k in update["memory_items"] if k == "n1"]
    assert depg_derived == []


def test_memory_update_records_a_tool_failure() -> None:
    from cism.agent.nodes import make_memory_update_node

    ai, result = _tool_round("c1", "hydra", "wordlist exhausted", error=True)
    state = _memory_state([HumanMessage(content="scan"), ai, result])

    update = make_memory_update_node()(state)

    assert len(update["memory_items"]) == 1


def test_memory_update_records_narration_from_the_most_recent_ai_message() -> None:
    from cism.agent.nodes import make_memory_update_node

    ai = AIMessage(content="I found something interesting.")
    state = _memory_state([HumanMessage(content="scan"), ai])

    update = make_memory_update_node()(state)

    assert len(update["memory_items"]) == 1


def test_memory_update_records_a_phase_change() -> None:
    from cism.agent.nodes import make_memory_update_node

    ai, result = _tool_round("c1", "nmap", "ok")
    state = _memory_state([HumanMessage(content="scan"), ai, result], phase_changed=True)

    update = make_memory_update_node()(state)

    assert any("phase" in item.snippet for item in update["memory_items"].values())


def test_memory_update_dedupes_a_recurring_narration_into_hits() -> None:
    from cism.agent.nodes import make_memory_update_node

    memory_update = make_memory_update_node()
    ai = AIMessage(content="same narration text")
    state = _memory_state([HumanMessage(content="scan"), ai])
    first = memory_update(state)

    second_state = _memory_state([HumanMessage(content="scan"), ai])
    second_state["memory_items"] = first["memory_items"]
    update = memory_update(second_state)

    assert len(update["memory_items"]) == 1
    (item,) = update["memory_items"].values()
    assert item.hits == 2


async def test_think_binds_only_the_current_phases_tools() -> None:
    recorded: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def bind_tools(self, tools, **kwargs):
            recorded.append(list(tools))
            return self

    profiles = PhaseProfiles({
        Phase.RECON: PhaseProfile(
            phase=Phase.RECON, system_prompt="p", tool_names=frozenset({"dummy_nmap"})
        ),
    })
    tools = ToolRegistry([dummy_nmap, dummy_msfconsole])
    think = make_think_node(_Recording(), tools, profiles)
    state = _state([HumanMessage(content="x")])

    await think(state)

    assert [t.name for t in recorded[0]] == ["dummy_nmap"]


async def test_think_prepends_the_phases_system_prompt_without_mutating_state() -> None:
    profiles = PhaseProfiles({
        Phase.RECON: PhaseProfile(
            phase=Phase.RECON, system_prompt="RECON PROMPT", tool_names=frozenset()
        ),
    })
    think = make_think_node(_RecordingChatModelForNodesTest(), ToolRegistry([]), profiles)
    state = _state([HumanMessage(content="x")])

    await think(state)

    assert not any(isinstance(m, SystemMessage) for m in state["messages"])


async def test_think_always_binds_tool_help_even_when_the_profile_declares_no_tools() -> None:
    recorded: list = []

    class _RecordsBoundTools(BaseChatModel):
        @property
        def _llm_type(self) -> str:
            return "records-bound-tools"

        def bind_tools(self, tools, **kwargs):
            recorded.append(tools)
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content="done"))])

    help_tool = StructuredTool.from_function(
        func=lambda tool_name: "help text", name="tool_help", description="d"
    )
    profiles = PhaseProfiles(
        {Phase.REPORTING: PhaseProfile(phase=Phase.REPORTING, system_prompt="p", tool_names=frozenset())}
    )
    think = make_think_node(_RecordsBoundTools(), ToolRegistry([help_tool]), profiles)

    await think({"messages": [HumanMessage(content="go")], "phase": Phase.REPORTING})

    assert [t.name for t in recorded[0]] == ["tool_help"]


class _AlwaysBlockStage:
    name = "always-block"

    def __init__(self, reason: str) -> None:
        self._reason = reason

    def check(self, call):
        return GuardrailResult(allowed=False, value=call, reason=self._reason)


def test_act_reports_a_blocked_call_with_a_generic_message_not_the_rich_reason() -> None:
    """The actual security property: an adversarial or injected model must
    not be able to read back exactly which host/flag/capability tripped
    the guard, or it has a live oracle to map the ruleset and find an
    unlisted equivalent."""
    action_chain = GuardrailChain([_AlwaysBlockStage("10.0.0.99 is outside scope")])
    profiles = PhaseProfiles(
        {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset({"dummy_nmap"}))}
    )
    act = make_act_node(ToolRegistry([dummy_nmap]), action_chain, profiles)
    call = {"id": "c1", "name": "dummy_nmap", "args": {"target": "10.0.0.99"}, "type": "tool_call"}
    state = _state([AIMessage(content="", tool_calls=[call])])

    result = act(state)

    message = result["messages"][0]
    assert message.content == "blocked by action guardrail"
    assert "10.0.0.99" not in message.content
    assert "outside scope" not in message.content


def test_act_preserves_the_rich_guardrail_reason_in_additional_kwargs() -> None:
    action_chain = GuardrailChain([_AlwaysBlockStage("10.0.0.99 is outside scope")])
    profiles = PhaseProfiles(
        {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset({"dummy_nmap"}))}
    )
    act = make_act_node(ToolRegistry([dummy_nmap]), action_chain, profiles)
    call = {"id": "c1", "name": "dummy_nmap", "args": {"target": "10.0.0.99"}, "type": "tool_call"}
    state = _state([AIMessage(content="", tool_calls=[call])])

    result = act(state)

    message = result["messages"][0]
    assert message.additional_kwargs["guardrail_detail"] == "[always-block] 10.0.0.99 is outside scope"
