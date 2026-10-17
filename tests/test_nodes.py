"""cism/agent/nodes.py: depg_update tested in isolation against a hand-built
AgentState — no LLM, no compiled graph. Exercises what the node is for:
turning this step's tool results into DEPG graph state, without ever losing
what earlier steps already found.
"""

from __future__ import annotations

import asyncio
import time

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
from cism.agent.nodes import (
    _compact_history,
    _depg_context,
    _memory_context,
    make_act_node,
    make_depg_update_node,
    make_respond_node,
    make_think_node,
)
from cism.agent.profiles import PhaseProfile, PhaseProfiles
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap
from cism.depg import Extraction, ExtractorRegistry, GenericExtractor, Node
from cism.memory import MemoryItem

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


def _state(messages, depg_nodes=None, depg_edges=None, memory_items=None, target="10.0.0.5") -> dict:
    return {
        "messages": messages,
        "phase": Phase.RECON,
        "depg_nodes": depg_nodes or {},
        "depg_edges": depg_edges or [],
        "memory_items": memory_items or {},
        "run_id": "run-1",
        "target": target,
    }


def _tool_round(call_id: str, name: str, content: str, *, error: bool = False):
    ai = AIMessage(content="", tool_calls=[{"id": call_id, "name": name, "args": {}}])
    kwargs = {"status": "error"} if error else {}
    result = ToolMessage(content=content, tool_call_id=call_id, name=name, **kwargs)
    return ai, result


def _depg_update():
    return make_depg_update_node(ExtractorRegistry({}, GenericExtractor()))


class _BlockingExtractor:
    """extract() blocks synchronously, standing in for a real ~20s LLM
    round-trip — proves depg_update's asyncio.to_thread wrap actually keeps
    the event loop free during that time (B6, AUDIT.md), not just that the
    node is declared async."""

    def extract(self, call, message, graph, target) -> Extraction:
        time.sleep(0.3)
        return Extraction(nodes=[], edges=[])


async def test_depg_update_does_not_block_the_event_loop_during_extraction() -> None:
    depg_update = make_depg_update_node(ExtractorRegistry({}, _BlockingExtractor()))
    ai, result = _tool_round("call-1", "dummy_nmap", "ok")
    state = _state([HumanMessage(content="scan it"), ai, result])

    ticks = 0

    async def _tick_counter() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    counter = asyncio.create_task(_tick_counter())
    await depg_update(state)
    counter.cancel()

    assert ticks > 5  # loop kept running concurrently instead of freezing for 0.3s


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


class _SequencedChatModel(BaseChatModel):
    """Returns the next reply from `replies` on each successive astream() call."""

    replies: list = []
    calls: list = []

    @property
    def _llm_type(self) -> str:
        return "test-sequenced-chat-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        raise NotImplementedError

    def bind_tools(self, tools, **kwargs):
        return self

    async def astream(self, messages, **kwargs):
        self.calls.append(messages)
        reply = self.replies[len(self.calls) - 1]
        yield AIMessageChunk(content=reply.content, tool_calls=reply.tool_calls)


_TOOL_PROFILES = PhaseProfiles(
    {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset({"dummy_nmap"}))}
)


def _toolcall_reply(name: str = "dummy_nmap") -> AIMessage:
    return AIMessage(content="", tool_calls=[{"id": "c1", "name": name, "args": {}}])


def _textonly_reply(text: str = "not calling anything") -> AIMessage:
    return AIMessage(content=text)


def _empty_reply() -> AIMessage:
    return AIMessage(content="")


async def test_think_retries_once_when_the_opening_move_is_truly_empty() -> None:
    llm = _SequencedChatModel(replies=[_empty_reply(), _toolcall_reply()])
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    assert len(llm.calls) == 2
    assert update["messages"][0].tool_calls[0]["name"] == "dummy_nmap"


async def test_think_does_not_retry_a_deliberate_text_answer_on_the_opening_move() -> None:
    """Regression guard: a real answer (e.g. _ACT_ONLY_WHEN_ASKED declining
    to act on a greeting) must stand, not get overridden by a forced retry."""
    llm = _SequencedChatModel(replies=[_textonly_reply("hey, how can I help?")])
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="hi")])

    update = await think(state)

    assert len(llm.calls) == 1
    assert update["messages"][0].content == "hey, how can I help?"


async def test_think_does_not_retry_when_the_opening_move_already_calls_a_tool() -> None:
    llm = _SequencedChatModel(replies=[_toolcall_reply()])
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it")])

    await think(state)

    assert len(llm.calls) == 1


async def test_think_does_not_retry_a_legitimate_final_answer_after_real_tool_use() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "3 open ports")
    llm = _SequencedChatModel(replies=[_textonly_reply("here's what I found")])
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = await think(state)

    assert len(llm.calls) == 1
    assert update["messages"][0].content == "here's what I found"


async def test_think_accepts_the_retrys_text_when_it_also_misses() -> None:
    llm = _SequencedChatModel(replies=[_empty_reply(), _textonly_reply("second miss")])
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    assert len(llm.calls) == 2


async def test_think_retries_when_the_opening_move_asks_for_the_already_known_target() -> None:
    """BACKLOG.md §7, live: the model answered the opening move with a
    clarifying question asking for the target instead of calling a tool,
    even though target_line already gave it the real value. Distinct from
    the truly-empty case above — this response has real text."""
    llm = _SequencedChatModel(
        replies=[_textonly_reply("Please provide the target host or IP address."), _toolcall_reply()]
    )
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it")], target="10.0.0.5")

    update = await think(state)

    assert len(llm.calls) == 2
    assert update["messages"][0].tool_calls[0]["name"] == "dummy_nmap"


async def test_think_does_not_retry_asking_for_target_when_none_is_configured() -> None:
    """The retry is gated on a target actually being set — without one,
    asking for it is the correct answer, not a bug to retry."""
    llm = _SequencedChatModel(replies=[_textonly_reply("Please provide the target host.")])
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it")], target=None)

    update = await think(state)

    assert len(llm.calls) == 1
    assert update["messages"][0].content == "Please provide the target host."


async def test_think_retries_a_later_step_that_announces_an_unexecuted_action() -> None:
    """2026-10-17, live (new reasoning-tuned local model, 3-bit quant): a
    later think() step -- mid tool-chain, after a real tool result already
    landed this turn -- sometimes narrates its next move instead of
    attaching the tool call for it ("Let me run nikto again...") and that
    stub becomes the whole turn's visible answer. Distinct from the
    opening-move retries above, which this reply is not (a real tool result
    already landed before it)."""
    ai, result = _tool_round("call-1", "dummy_nmap", "3 open ports")
    llm = _SequencedChatModel(
        replies=[_textonly_reply("Let me run nikto again to confirm."), _toolcall_reply()]
    )
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = await think(state)

    assert len(llm.calls) == 2
    assert update["messages"][0].tool_calls[0]["name"] == "dummy_nmap"


async def test_think_does_not_retry_a_later_steps_real_answer_that_merely_mentions_a_verb() -> None:
    """Only the trailing sentence is checked -- a real answer that happens
    to open with a future-tense verb must still stand as-is, same
    principle as _is_asking_for_known_target's narrowness."""
    ai, result = _tool_round("call-1", "dummy_nmap", "3 open ports")
    llm = _SequencedChatModel(
        replies=[_textonly_reply(
            "I'll check back once the scan settles. Found 3 open ports on 10.0.0.5."
        )]
    )
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = await think(state)

    assert len(llm.calls) == 1


async def test_think_does_not_retry_a_later_steps_offer_to_help_further() -> None:
    """"let me know" must never match -- "know" isn't one of the gated verbs."""
    ai, result = _tool_round("call-1", "dummy_nmap", "3 open ports")
    llm = _SequencedChatModel(
        replies=[_textonly_reply("Found 3 open ports. Let me know if you want more detail.")]
    )
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = await think(state)

    assert len(llm.calls) == 1


async def test_a_successful_tool_call_produces_a_depg_node_for_the_target() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "[dummy] nmap -sV 10.0.0.5 -> 3 open ports")
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = await _depg_update()(state)

    assert len(update["depg_nodes"]) == 1
    node = next(iter(update["depg_nodes"].values()))
    assert node.target == "10.0.0.5"
    assert node.evidence


async def test_an_errored_tool_call_now_produces_a_node_instead_of_being_dropped() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = await _depg_update()(state)

    assert len(update["depg_nodes"]) == 1


async def test_multiple_tool_calls_in_one_step_each_produce_their_own_node() -> None:
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

    update = await _depg_update()(state)

    assert len(update["depg_nodes"]) == 2


async def test_nodes_found_on_an_earlier_step_survive_a_step_with_no_new_evidence() -> None:
    depg_update = _depg_update()
    ai1, result1 = _tool_round("call-1", "dummy_nmap", "ok")
    first = await depg_update(_state([HumanMessage(content="scan it"), ai1, result1]))

    ai2, result2 = _tool_round("call-2", "dummy_msfconsole", "boom", error=True)
    second_state = _state(
        [HumanMessage(content="scan it"), ai1, result1, ai2, result2],
        depg_nodes=first["depg_nodes"],
        depg_edges=first["depg_edges"],
    )

    update = await depg_update(second_state)

    assert update["depg_nodes"].keys() >= first["depg_nodes"].keys()


async def test_a_failed_tool_call_now_produces_a_blocked_tombstone_node() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = await _depg_update()(state)

    assert len(update["depg_nodes"]) == 1
    node = next(iter(update["depg_nodes"].values()))
    assert node.state == "blocked"


async def test_differently_formatted_targets_normalize_onto_the_same_node() -> None:
    """"ssh://10.0.0.5:22" and "10.0.0.5" must merge onto the same node
    family instead of fragmenting into two — a host is one host regardless
    of scheme/port/case, per cism/depg/normalize.py."""
    ai, result = _tool_round("call-1", "dummy_nmap", "ok")
    state = _state([HumanMessage(content="scan it"), ai, result])
    state["target"] = "ssh://10.0.0.5:22"

    update = await _depg_update()(state)

    node = next(iter(update["depg_nodes"].values()))
    assert node.target == "10.0.0.5"


async def test_a_calls_own_target_argument_wins_over_the_sessions_declared_target() -> None:
    """A multi-host engagement calls the same tool against several hosts in
    one run — state["target"] (set once at startup via --target/--scope)
    must not get stamped onto every node regardless of which host the
    call actually scanned. Confirmed live 2026-10-12: a second nmap call
    against a different host had all its open ports mislabeled with the
    first host's IP because depg_update ignored the call's own args."""
    from cism.depg import ExtractorRegistry
    from cism.depg.extractors import NmapExtractor

    depg_update = make_depg_update_node(
        ExtractorRegistry({"nmap": NmapExtractor()}, GenericExtractor())
    )
    ai = AIMessage(
        content="", tool_calls=[{"id": "c1", "name": "nmap", "args": {"target": "10.0.0.9"}}]
    )
    result = ToolMessage(content="22/tcp   open  ssh\n", tool_call_id="c1", name="nmap")
    state = _state([HumanMessage(content="scan it"), ai, result])
    state["target"] = "10.0.0.5"  # the session's startup target, a different host

    update = await depg_update(state)

    node = next(iter(update["depg_nodes"].values()))
    assert node.target == "10.0.0.9"


async def test_a_call_with_no_target_argument_falls_back_to_the_session_target() -> None:
    """A targetless tool (e.g. tool_help) has no target arg of its own —
    must still fall back to the session's declared target, not blow up."""
    ai, result = _tool_round("call-1", "dummy_nmap", "ok")
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = await _depg_update()(state)

    node = next(iter(update["depg_nodes"].values()))
    assert node.target == "10.0.0.5"


async def test_a_second_call_on_the_same_target_gets_an_edge_from_the_first() -> None:
    depg_update = _depg_update()
    ai1, result1 = _tool_round("call-1", "dummy_nmap", "ok")
    first = await depg_update(_state([HumanMessage(content="scan it"), ai1, result1]))

    ai2, result2 = _tool_round("call-2", "dummy_msfconsole", "ok too")
    second_state = _state(
        [HumanMessage(content="scan it"), ai1, result1, ai2, result2],
        depg_nodes=first["depg_nodes"], depg_edges=first["depg_edges"],
    )
    update = await depg_update(second_state)

    assert len(update["depg_edges"]) == 1


async def test_nodes_produced_in_the_same_step_do_not_link_to_each_other() -> None:
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

    update = await depg_update(state)

    assert len(update["depg_nodes"]) == 2
    assert update["depg_edges"] == []


def _resolved_node(cause_class: str, *, phase: str, target: str = "10.0.0.5", signal: str = "x") -> Node:
    return Node(
        id=f"{cause_class}:{target}:{signal}",
        cause_class=cause_class,
        target=target,
        signal=signal,
        phase=phase,
        state="resolved",
    )


def test_phase_router_advances_when_recon_found_an_open_port() -> None:
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    nodes = {"n1": _resolved_node("open-port", phase="recon")}
    state = _state(
        [HumanMessage(content="x"), ToolMessage(content="ok", tool_call_id="c1", name="nmap")],
        depg_nodes=nodes,
    )

    update = router(state)

    assert update["phase_changed"] is True
    assert update["phase"] == Phase.ENUMERATION


def test_phase_router_does_not_advance_on_a_successful_call_with_no_findings() -> None:
    """The bug this replaces: DEFAULT_NEXT_PHASE advanced on any successful
    tool call, so a scan that found nothing still moved the phase along."""
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    state = _state(
        [HumanMessage(content="x"), ToolMessage(content="ok", tool_call_id="c1", name="nmap")],
        depg_nodes={},
    )

    update = router(state)

    assert update["phase_changed"] is False


def test_phase_router_reports_no_change_when_it_stays_put() -> None:
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="x"), ai, result])

    update = router(state)

    assert update["phase_changed"] is False


def test_phase_router_exploitation_requires_a_found_credential_not_just_an_attempt() -> None:
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    nodes = {"n1": _resolved_node("credential-attempt", phase="exploitation")}
    state = _state(
        [HumanMessage(content="x"), ToolMessage(content="fail", tool_call_id="c1", name="hydra")],
        depg_nodes=nodes,
    )
    state["phase"] = Phase.EXPLOITATION

    update = router(state)

    assert update["phase_changed"] is False


def test_phase_router_advances_exploitation_on_a_found_credential() -> None:
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    nodes = {"n1": _resolved_node("credential-found", phase="exploitation")}
    state = _state(
        [HumanMessage(content="x"), ToolMessage(content="found it", tool_call_id="c1", name="hydra")],
        depg_nodes=nodes,
    )
    state["phase"] = Phase.EXPLOITATION

    update = router(state)

    assert update["phase_changed"] is True
    assert update["phase"] == Phase.POST_EXPLOITATION


def test_phase_router_enumeration_accepts_any_resolved_in_phase_node() -> None:
    """Enumeration/vuln-discovery/post-exploitation have no fixed cause_class
    vocabulary (LLM-extracted free text), so any resolved node tagged with
    the current phase is enough — unlike RECON/EXPLOITATION above."""
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    nodes = {"n1": _resolved_node("whatweb", phase="enumeration")}
    state = _state(
        [HumanMessage(content="x"), ToolMessage(content="Apache/2.2.8", tool_call_id="c1", name="whatweb")],
        depg_nodes=nodes,
    )
    state["phase"] = Phase.ENUMERATION

    update = router(state)

    assert update["phase_changed"] is True
    assert update["phase"] == Phase.VULNERABILITY_DISCOVERY


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
                tier="T2", source="deterministic", call_id="c1",
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
            Evidence(timestamp="t", tool="nmap", exit_signal="x", tier="T2", source="deterministic", call_id="old-call")
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


async def test_fallback_hint_example_uses_the_real_target_not_a_stale_one() -> None:
    """Live, 2026-10-17: replacing the fallback hint's abstract <tool>/
    <target> placeholder with a fixed, concrete example (10.0.0.5) wasn't
    enough — the model parroted *that* literal value into a real nmap
    call instead of the actual configured target. Caught by
    ScopeGuardStage (10.0.0.5 was outside the declared scope), but still
    a real miss. The hint's example target must track target_line."""
    recorded_messages: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
            recorded_messages.extend(messages)
            return super()._generate(messages, stop, run_manager, **kwargs)

    think = make_think_node(_Recording(), ToolRegistry([dummy_nmap]), _TOOL_PROFILES)
    state = _state([HumanMessage(content="scan it")], target="172.28.0.3")

    await think(state)

    system_prompt = recorded_messages[0].content
    assert '"target": "172.28.0.3"' in system_prompt
    assert "10.0.0.5" not in system_prompt


async def test_think_anonymizes_the_target_line_when_a_privacy_gateway_is_given() -> None:
    from cism.agent.guardrails.privacy import PrivacyGateway

    recorded_messages: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
            recorded_messages.extend(messages)
            return super()._generate(messages, stop, run_manager, **kwargs)

    profiles = PhaseProfiles({
        Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="p", tool_names=frozenset())
    })
    gateway = PrivacyGateway()
    think = make_think_node(_Recording(), ToolRegistry([]), profiles, privacy=gateway)
    state = _state([HumanMessage(content="x")])  # target: 10.0.0.5

    await think(state)

    system = next(m for m in recorded_messages if isinstance(m, SystemMessage))
    assert "10.0.0.5" not in str(system.content)
    assert "<ip-1>" in str(system.content)


async def test_think_leaves_the_target_line_real_with_no_privacy_gateway() -> None:
    recorded_messages: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
            recorded_messages.extend(messages)
            return super()._generate(messages, stop, run_manager, **kwargs)

    profiles = PhaseProfiles({
        Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="p", tool_names=frozenset())
    })
    think = make_think_node(_Recording(), ToolRegistry([]), profiles)
    state = _state([HumanMessage(content="x")])

    await think(state)

    system = next(m for m in recorded_messages if isinstance(m, SystemMessage))
    assert "10.0.0.5" in str(system.content)


async def test_think_tells_the_model_never_to_ask_for_the_already_given_target() -> None:
    """2026-10-12 live-test: a real small model asked the user to re-supply
    a target that was already in this line — strengthened after that."""
    recorded_messages: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
            recorded_messages.extend(messages)
            return super()._generate(messages, stop, run_manager, **kwargs)

    profiles = PhaseProfiles({
        Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="p", tool_names=frozenset())
    })
    think = make_think_node(_Recording(), ToolRegistry([]), profiles)
    state = _state([HumanMessage(content="x")])

    await think(state)

    system = next(m for m in recorded_messages if isinstance(m, SystemMessage))
    assert "never ask the user" in str(system.content).lower()


async def test_think_adds_the_one_call_rule_only_when_tools_are_offered() -> None:
    """2026-10-12 live-test: the same model planned a JSON array of several
    future calls in one turn instead of making one real tool call."""
    recorded_messages: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
            recorded_messages.extend(messages)
            return super()._generate(messages, stop, run_manager, **kwargs)

    with_tools = PhaseProfiles({
        Phase.RECON: PhaseProfile(
            phase=Phase.RECON, system_prompt="p", tool_names=frozenset({"dummy_nmap"})
        )
    })
    no_tools = PhaseProfiles({
        Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="p", tool_names=frozenset())
    })

    think_with = make_think_node(_Recording(), ToolRegistry([dummy_nmap]), with_tools)
    await think_with(_state([HumanMessage(content="x")]))
    system_with = next(m for m in recorded_messages if isinstance(m, SystemMessage))
    assert "exactly one tool call per turn" in str(system_with.content)

    recorded_messages.clear()
    think_without = make_think_node(_Recording(), ToolRegistry([]), no_tools)
    await think_without(_state([HumanMessage(content="x")]))
    system_without = next(m for m in recorded_messages if isinstance(m, SystemMessage))
    assert "exactly one tool call per turn" not in str(system_without.content)


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

    await think(_state([HumanMessage(content="go")]) | {"phase": Phase.REPORTING})

    assert [t.name for t in recorded[0]] == ["tool_help"]


class _TextOnlyChatModel(BaseChatModel):
    """No native tool-calling — always answers in prose, like a small local
    model without function-calling support."""

    text: str = ""

    @property
    def _llm_type(self) -> str:
        return "test-text-only-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.text))])


def _recon_profile_with(*tool_names: str) -> PhaseProfiles:
    return PhaseProfiles({
        Phase.RECON: PhaseProfile(
            phase=Phase.RECON, system_prompt="p", tool_names=frozenset(tool_names)
        ),
    })


async def test_think_falls_back_to_a_text_tool_call_when_native_tool_calls_are_empty() -> None:
    llm = _TextOnlyChatModel(
        text='Running a scan.\nTOOL_CALL: {"name": "dummy_nmap", "args": {"target": "10.0.0.5"}}'
    )
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _recon_profile_with("dummy_nmap"))
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    call = update["messages"][0].tool_calls[0]
    assert call["name"] == "dummy_nmap"
    assert call["args"] == {"target": "10.0.0.5"}


async def test_think_text_fallback_accepts_tool_and_arguments_aliases_and_trailing_prose() -> None:
    llm = _TextOnlyChatModel(
        text='TOOL_CALL: {"tool": "dummy_nmap", "arguments": {"target": "10.0.0.5"}} — running it now.'
    )
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _recon_profile_with("dummy_nmap"))
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    call = update["messages"][0].tool_calls[0]
    assert call["name"] == "dummy_nmap"
    assert call["args"] == {"target": "10.0.0.5"}


async def test_think_ignores_a_malformed_text_tool_call() -> None:
    llm = _TextOnlyChatModel(text="TOOL_CALL: not-json-at-all")
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _recon_profile_with("dummy_nmap"))
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    assert update["messages"][0].tool_calls == []


async def test_think_skips_the_text_fallback_when_the_phase_offers_no_tools() -> None:
    profiles = PhaseProfiles(
        {Phase.REPORTING: PhaseProfile(phase=Phase.REPORTING, system_prompt="p", tool_names=frozenset())}
    )
    llm = _TextOnlyChatModel(text='TOOL_CALL: {"name": "dummy_nmap", "args": {}}')
    think = make_think_node(llm, ToolRegistry([]), profiles)
    state = _state([HumanMessage(content="go")]) | {"phase": Phase.REPORTING}

    update = await think(state)

    assert update["messages"][0].tool_calls == []


async def test_think_binds_no_tools_at_all_for_a_plain_acknowledgment() -> None:
    """Live, 2026-10-17 (BACKLOG.md §10): broadening _ACT_ONLY_WHEN_ASKED's
    wording to name "ok, noted" explicitly wasn't enough — mid-engagement,
    with real findings already in the DEPG context block, the model still
    called tools on a plain acknowledgment. Structural fix: no tools are
    bound at all for that turn, so recorded (the actual bind_tools call)
    must be empty — not just "the response has no tool_calls", which a
    wording-only fix could also achieve on a lucky run."""
    recorded: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def bind_tools(self, tools, **kwargs):
            recorded.append(list(tools))
            return self

    think = make_think_node(_Recording(), ToolRegistry([dummy_nmap]), _recon_profile_with("dummy_nmap"))
    state = _state([HumanMessage(content="ok, noted")])

    await think(state)

    # _bind_tools_if_supported never calls bind_tools at all for an empty
    # tool list (it short-circuits to the plain, unbound llm) — that
    # early return is itself the proof no tools were offered this turn.
    assert recorded == []


async def test_think_ignores_a_fallback_text_tool_call_on_a_plain_acknowledgment() -> None:
    """Same bug, the other path: even a non-tool-calling model that writes
    a TOOL_CALL: marker in prose must not have it parsed into a real call
    when the human turn was only an acknowledgment."""
    llm = _TextOnlyChatModel(
        text='Noted. TOOL_CALL: {"name": "dummy_nmap", "args": {"target": "10.0.0.5"}}'
    )
    think = make_think_node(llm, ToolRegistry([dummy_nmap]), _recon_profile_with("dummy_nmap"))
    state = _state([HumanMessage(content="got it")])

    update = await think(state)

    assert update["messages"][0].tool_calls == []


async def test_think_tells_the_model_not_to_write_a_tool_call_on_a_plain_acknowledgment() -> None:
    """Live, round 12 (2026-10-17): binding zero tools stopped the call
    from executing, but the model still wrote one in its own native
    syntax ("<|tool_call_start|>[curl(...)]<|tool_call_end|>"), which then
    became the turn's entire visible narration -- ugly, confusing text
    even though nothing dangerous happened. The note must land, and land
    after the phase's own standing order (recency beats the earlier rule
    on a small model, same lesson as the structural fix itself)."""
    recorded_messages: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
            recorded_messages.extend(messages)
            return super()._generate(messages, stop, run_manager, **kwargs)

    think = make_think_node(_Recording(), ToolRegistry([dummy_nmap]), _recon_profile_with("dummy_nmap"))
    state = _state([HumanMessage(content="ok, noted")])

    await think(state)

    system_prompt = str(next(m for m in recorded_messages if isinstance(m, SystemMessage)).content)
    assert system_prompt.rstrip().endswith(
        "since nothing will execute it and it will only show up as broken text."
    )


async def test_think_adds_no_ack_note_for_a_real_request() -> None:
    recorded_messages: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
            recorded_messages.extend(messages)
            return super()._generate(messages, stop, run_manager, **kwargs)

    think = make_think_node(_Recording(), ToolRegistry([dummy_nmap]), _recon_profile_with("dummy_nmap"))
    state = _state([HumanMessage(content="scan it")])

    await think(state)

    system_prompt = str(next(m for m in recorded_messages if isinstance(m, SystemMessage)).content)
    assert "do not write a tool call in any form" not in system_prompt


async def test_think_still_binds_tools_for_a_message_that_merely_starts_with_an_ack_word() -> None:
    """Exact-match, not substring: "ok, run nikto" must still get tools."""
    recorded: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def bind_tools(self, tools, **kwargs):
            recorded.append(list(tools))
            return self

    think = make_think_node(_Recording(), ToolRegistry([dummy_nmap]), _recon_profile_with("dummy_nmap"))
    state = _state([HumanMessage(content="ok, run nikto")])

    await think(state)

    assert [t.name for t in recorded[0]] == ["dummy_nmap"]


async def test_think_prefers_native_tool_calls_over_the_text_fallback() -> None:
    class _NativeAndTextChatModel(BaseChatModel):
        @property
        def _llm_type(self) -> str:
            return "test-native-and-text-model"

        def bind_tools(self, tools, **kwargs):
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
            message = AIMessage(
                content='TOOL_CALL: {"name": "dummy_msfconsole", "args": {}}',
                tool_calls=[{"id": "call-1", "name": "dummy_nmap", "args": {"target": "10.0.0.5"}}],
            )
            return ChatResult(generations=[ChatGeneration(message=message)])

    think = make_think_node(
        _NativeAndTextChatModel(),
        ToolRegistry([dummy_nmap, dummy_msfconsole]),
        _recon_profile_with("dummy_nmap", "dummy_msfconsole"),
    )
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    assert [c["name"] for c in update["messages"][0].tool_calls] == ["dummy_nmap"]


class _RecordingMessagesChatModel(BaseChatModel):
    """Records the exact message list sent to the model each call, so a
    test can inspect what think() actually put on the wire (B2, AUDIT.md)."""

    seen: list = []

    @property
    def _llm_type(self) -> str:
        return "records-messages"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.seen.append(list(messages))
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="done"))])


async def test_think_leaves_history_untouched_when_it_fits_the_budget() -> None:
    llm = _RecordingMessagesChatModel(seen=[])
    think = make_think_node(llm, ToolRegistry([]), _NO_OP_PROFILES)
    state = _state([HumanMessage(content="short")])
    state["context_window"] = 32_768

    update = await think(state)

    assert update["compacted"] == 0
    assert sum(1 for m in llm.seen[-1] if isinstance(m, HumanMessage)) == 1


async def test_think_drops_the_oldest_turns_when_history_overflows_the_budget() -> None:
    llm = _RecordingMessagesChatModel(seen=[])
    think = make_think_node(llm, ToolRegistry([]), _NO_OP_PROFILES)
    old = HumanMessage(content="x" * 2000)
    recent = HumanMessage(content="the most recent turn")
    state = _state([old, old, old, recent])
    state["context_window"] = 1200

    update = await think(state)

    assert update["compacted"] > 0
    sent = llm.seen[-1]
    assert sent[-1] is recent
    assert any("omitted" in str(m.content) for m in sent if isinstance(m, SystemMessage))


def test_compact_history_counts_fat_tool_calls_not_just_empty_content() -> None:
    """Q2, CODE_REVIEW.md: cost used to be estimated from .content alone, so
    an AIMessage with empty content but a large tool_calls payload (e.g. an
    nmap call with a long `extra` arg) estimated as ~0 tokens and never
    triggered compaction — exactly the multi-tool run B2 exists to bound."""
    fat_call = AIMessage(
        content="",
        tool_calls=[{"id": "c1", "name": "nmap", "args": {"extra": "x" * 4000}, "type": "tool_call"}],
    )
    messages = [fat_call] * 50

    kept, dropped = _compact_history(messages, "sys", 1000)

    assert dropped > 0
    assert len(kept) < len(messages)


def test_compact_history_truncates_old_tool_output_but_keeps_the_current_turns_full() -> None:
    """Live, round 12 follow-up (2026-10-17): an old turn's full nmap/nikto
    dump sat in history at full size even though depg_update had already
    condensed its finding into the DEPG/memory block shown separately —
    paying full token cost twice for the same signal. The current turn's
    own tool results must stay untouched; the model may still need exact
    detail from them to decide its next move."""
    old_tool = ToolMessage(content="A" * 2000, tool_call_id="c1", name="nmap")
    new_tool = ToolMessage(content="B" * 2000, tool_call_id="c2", name="nmap")
    messages = [
        HumanMessage(content="scan it"),
        AIMessage(content="", tool_calls=[{"id": "c1", "name": "nmap", "args": {}}]),
        old_tool,
        HumanMessage(content="scan again"),
        AIMessage(content="", tool_calls=[{"id": "c2", "name": "nmap", "args": {}}]),
        new_tool,
    ]

    kept, dropped = _compact_history(messages, "sys", 32_768)

    assert dropped == 0
    old_kept = kept[2]
    assert len(old_kept.content) < 2000
    assert "truncated" in old_kept.content
    assert kept[-1].content == "B" * 2000


def test_compact_history_leaves_short_old_tool_output_untouched() -> None:
    old_tool = ToolMessage(content="short output", tool_call_id="c1", name="nmap")
    messages = [
        HumanMessage(content="scan it"),
        AIMessage(content="", tool_calls=[{"id": "c1", "name": "nmap", "args": {}}]),
        old_tool,
        HumanMessage(content="what next"),
    ]

    kept, _ = _compact_history(messages, "sys", 32_768)

    assert kept[2].content == "short output"


def test_compact_history_never_truncates_non_tool_messages() -> None:
    old_narration = AIMessage(content="A" * 2000)
    messages = [
        HumanMessage(content="x" * 2000),
        old_narration,
        HumanMessage(content="what next"),
    ]

    kept, _ = _compact_history(messages, "sys", 32_768)

    assert kept[0].content == "x" * 2000
    assert kept[1].content == "A" * 2000


async def test_think_wraps_tool_output_for_the_model_without_touching_state() -> None:
    """C1 (AUDIT.md): a ToolMessage is untrusted data (host-controlled scan
    output) — the model must see it marked as such, but depg_update's regex
    extractors and the audit log need the raw content, so state is untouched."""
    from cism.agent.guardrails import GuardrailChain, ToolOutputScreenStage

    llm = _RecordingMessagesChatModel(seen=[])
    think = make_think_node(
        llm, ToolRegistry([]), _NO_OP_PROFILES, GuardrailChain([ToolOutputScreenStage()])
    )
    tool_msg = ToolMessage(content="22/tcp open ssh", tool_call_id="c1", name="dummy_nmap")
    state = _state([HumanMessage(content="scan it"), tool_msg])

    update = await think(state)

    sent = llm.seen[-1]
    sent_tool_message = next(m for m in sent if isinstance(m, ToolMessage))
    assert "UNTRUSTED TOOL OUTPUT" in str(sent_tool_message.content)
    assert "22/tcp open ssh" in str(sent_tool_message.content)
    assert tool_msg.content == "22/tcp open ssh"  # untouched in state
    assert update["compacted"] == 0


async def test_think_defaults_to_no_screening_when_no_chain_is_given() -> None:
    llm = _RecordingMessagesChatModel(seen=[])
    think = make_think_node(llm, ToolRegistry([]), _NO_OP_PROFILES)
    tool_msg = ToolMessage(content="22/tcp open ssh", tool_call_id="c1", name="dummy_nmap")
    state = _state([HumanMessage(content="scan it"), tool_msg])

    await think(state)

    sent_tool_message = next(m for m in llm.seen[-1] if isinstance(m, ToolMessage))
    assert sent_tool_message.content == "22/tcp open ssh"


class _AlwaysBlockStage:
    name = "always-block"

    def __init__(self, reason: str) -> None:
        self._reason = reason

    def check(self, call):
        return GuardrailResult(allowed=False, value=call, reason=self._reason)


async def test_act_reports_a_blocked_call_with_a_generic_message_not_the_rich_reason() -> None:
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

    result = await act(state)

    message = result["messages"][0]
    assert message.content == "blocked by action guardrail"
    assert "10.0.0.99" not in message.content
    assert "outside scope" not in message.content


async def test_act_surfaces_the_real_reason_when_phase_tool_guard_blocks_a_call() -> None:
    """BACKLOG.md §7, live: a request for sqlmap while still in recon
    silently failed with no indication why — the real reason was already
    computed (PhaseToolGuardStage) but discarded in favor of the generic
    message. Carved out from the test above's security property: which
    tools are offered when isn't secret (the model already sees the
    bound-tools list every turn), unlike a scope/flag rule."""
    from cism.agent.guardrails import PhaseToolGuardStage

    action_chain = GuardrailChain(
        [PhaseToolGuardStage(Phase.RECON, frozenset(), {"dummy_nmap": "executes"})]
    )
    profiles = PhaseProfiles(
        {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset())}
    )
    act = make_act_node(ToolRegistry([dummy_nmap]), action_chain, profiles)
    call = {"id": "c1", "name": "dummy_nmap", "args": {"target": "10.0.0.5"}, "type": "tool_call"}
    state = _state([AIMessage(content="", tool_calls=[call])])

    result = await act(state)

    message = result["messages"][0]
    assert message.content == "'dummy_nmap' [capability=executes] is not offered in phase recon"


async def test_act_preserves_the_rich_guardrail_reason_in_additional_kwargs() -> None:
    action_chain = GuardrailChain([_AlwaysBlockStage("10.0.0.99 is outside scope")])
    profiles = PhaseProfiles(
        {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset({"dummy_nmap"}))}
    )
    act = make_act_node(ToolRegistry([dummy_nmap]), action_chain, profiles)
    call = {"id": "c1", "name": "dummy_nmap", "args": {"target": "10.0.0.99"}, "type": "tool_call"}
    state = _state([AIMessage(content="", tool_calls=[call])])

    result = await act(state)

    message = result["messages"][0]
    assert message.additional_kwargs["guardrail_detail"] == "[always-block] 10.0.0.99 is outside scope"


async def test_act_blocks_a_call_to_a_tool_the_registry_does_not_have_instead_of_raising() -> None:
    """PhaseToolGuardStage's allowed set is catalog-derived, not
    registry-filtered (cism/agent/profiles.py's default_profiles) — a
    registry that is a strict subset of the catalog can let a
    guard-allowed call through to a tool this particular registry never
    bound. A KeyError from ToolRegistry.get() must not be allowed to
    abort the whole run any more than an ordinary guardrail block would."""
    action_chain = GuardrailChain([])
    profiles = PhaseProfiles(
        {
            Phase.RECON: PhaseProfile(
                phase=Phase.RECON, system_prompt="", tool_names=frozenset({"dummy_msfconsole"})
            )
        }
    )
    act = make_act_node(ToolRegistry([dummy_nmap]), action_chain, profiles)
    call = {"id": "c1", "name": "dummy_msfconsole", "args": {}, "type": "tool_call"}
    state = _state([AIMessage(content="", tool_calls=[call])])

    result = await act(state)

    message = result["messages"][0]
    assert message.content == "blocked by action guardrail"
    assert message.status == "error"
    assert "dummy_msfconsole" in message.additional_kwargs["guardrail_detail"]


async def test_act_marks_a_nonzero_exit_as_error_and_keeps_its_output() -> None:
    from cism.agent.tools.sandbox import ToolExecutionError

    def _fails(**kwargs) -> str:
        raise ToolExecutionError(["nmap"], 1, "Couldn't open a raw socket.")

    failing_tool = StructuredTool.from_function(func=_fails, name="dummy_nmap", description="")
    action_chain = GuardrailChain([])
    profiles = PhaseProfiles(
        {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset({"dummy_nmap"}))}
    )
    act = make_act_node(ToolRegistry([failing_tool]), action_chain, profiles)
    call = {"id": "c1", "name": "dummy_nmap", "args": {}, "type": "tool_call"}
    state = _state([AIMessage(content="", tool_calls=[call])])

    result = await act(state)

    message = result["messages"][0]
    assert message.status == "error"
    assert "Couldn't open a raw socket." in message.content


async def test_act_runs_a_slow_sync_tool_without_blocking_the_event_loop() -> None:
    """Regression test for the freeze bug: a real tool call is a blocking
    subprocess (cism/agent/tools/sandbox.py), and act() used to call
    tool.invoke() directly — running it in-place on the same event loop
    Textual's own worker runs on, freezing the whole TUI for the call's
    duration. act() must await tool.ainvoke() instead, which offloads a
    sync-only tool to a thread (BaseTool's default _arun). Proven here by
    running a slow tool concurrently with a fast counter loop and asserting
    the counter keeps advancing while the "tool" is still "running" — on
    the old blocking behaviour this would never advance until the tool
    call returned, and the two totals would be measured sequentially."""
    import asyncio
    import time

    def _slow(**kwargs) -> str:
        time.sleep(0.2)
        return "done"

    slow_tool = StructuredTool.from_function(
        func=_slow, name="dummy_nmap", description="slow stand-in for a real tool call"
    )
    action_chain = GuardrailChain([])
    profiles = PhaseProfiles(
        {Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="", tool_names=frozenset({"dummy_nmap"}))}
    )
    act = make_act_node(ToolRegistry([slow_tool]), action_chain, profiles)
    call = {"id": "c1", "name": "dummy_nmap", "args": {}, "type": "tool_call"}
    state = _state([AIMessage(content="", tool_calls=[call])])

    ticks = 0

    async def _tick_while_running() -> None:
        nonlocal ticks
        for _ in range(50):
            ticks += 1
            await asyncio.sleep(0.01)

    ticker = asyncio.create_task(_tick_while_running())
    result = await act(state)
    ticker.cancel()

    assert result["messages"][0].content == "done"
    assert ticks >= 5  # event loop kept running while the "tool" slept


def _node(id: str, cause_class: str, target: str, signal: str = "", state: str = "resolved") -> Node:
    return Node(id=id, cause_class=cause_class, target=target, signal=signal, state=state)


def test_depg_context_groups_by_target_and_caps_each_target() -> None:
    nodes = {
        f"n{i}": _node(f"n{i}", "open-port", "10.0.0.2", f"{i}/tcp")
        for i in range(10)
    }
    nodes["other"] = _node("other", "open-port", "10.0.0.3", "80/tcp")

    text = _depg_context(nodes)

    assert "10.0.0.2:" in text
    assert "10.0.0.3:" in text
    assert "+2 more" in text  # 10 nodes on .2, capped at 8


def test_depg_context_empty_when_no_nodes() -> None:
    assert _depg_context({}) == ""


def test_depg_context_caps_the_number_of_targets_shown() -> None:
    nodes = {
        f"t{i}": _node(f"t{i}", "open-port", f"10.0.0.{i}", "22/tcp")
        for i in range(15)
    }

    text = _depg_context(nodes)

    shown = sum(1 for i in range(15) if f"10.0.0.{i}:" in text)
    assert shown == 12
    assert "+3 more target(s)" in text


def test_depg_context_keeps_unresolved_findings_over_older_resolved_ones() -> None:
    resolved = [_node(f"r{i}", "open-port", "10.0.0.5", f"{i}/tcp", state="resolved") for i in range(8)]
    critical = _node("c1", "credential-found", "10.0.0.5", "admin:admin", state="untested")
    nodes = {n.id: n for n in [*resolved, critical]}

    text = _depg_context(nodes)

    assert "credential-found:admin:admin" in text  # not buried behind "+1 more"


def test_memory_context_skips_depg_derived_items() -> None:
    items = {
        "a": MemoryItem(id="a", tier="T2", phase_tag="recon", snippet="22/tcp ssh",
                        created_at=0.0, source_type="depg_node"),
        "b": MemoryItem(id="b", tier="T3", phase_tag="recon", snippet="nmap timed out",
                        created_at=0.0, source_type="tool-failure"),
    }

    text = _memory_context(items)

    assert "22/tcp ssh" not in text  # already shown by _depg_context
    assert "nmap timed out" in text


def test_memory_context_screens_tool_failure_snippets_only() -> None:
    """Tool-failure snippets are raw, target-controlled tool output (C1,
    AUDIT.md) -- same injection-screening path as a ToolMessage in
    history. Narration is the model's own prior output, screened already
    by having been generated by it, so it's shown as-is."""
    items = {
        "a": MemoryItem(id="a", tier="T3", phase_tag="recon", snippet="raw failure text",
                        created_at=0.0, source_type="tool-failure"),
        "b": MemoryItem(id="b", tier="T3", phase_tag="recon", snippet="the model's own note",
                        created_at=0.0, source_type="narration"),
    }

    text = _memory_context(items, screen=lambda s: f"SCREENED[{s}]")

    assert "SCREENED[raw failure text]" in text
    assert "the model's own note" in text
    assert "SCREENED[the model's own note]" not in text


def test_memory_context_empty_when_nothing_but_depg_derived_items() -> None:
    items = {
        "a": MemoryItem(id="a", tier="T2", phase_tag="recon", snippet="22/tcp ssh",
                        created_at=0.0, source_type="depg_node"),
    }
    assert _memory_context(items) == ""


async def test_think_puts_depg_and_memory_context_in_the_system_prompt() -> None:
    llm = _RecordingMessagesChatModel(seen=[])
    think = make_think_node(llm, ToolRegistry([]), _NO_OP_PROFILES)
    depg_nodes = {"n1": _node("n1", "open-port", "10.0.0.5", "22/tcp ssh")}
    memory_items = {
        "f1": MemoryItem(id="f1", tier="T3", phase_tag="recon", snippet="nmap timed out",
                         created_at=0.0, source_type="tool-failure"),
    }
    state = _state([HumanMessage(content="what have we found?")], depg_nodes=depg_nodes,
                    memory_items=memory_items)

    await think(state)

    system = next(m for m in llm.seen[-1] if isinstance(m, SystemMessage))
    assert "10.0.0.5" in str(system.content)
    assert "22/tcp ssh" in str(system.content)
    assert "nmap timed out" in str(system.content)


async def test_think_adds_no_context_block_when_nothing_to_summarize() -> None:
    llm = _RecordingMessagesChatModel(seen=[])
    think = make_think_node(llm, ToolRegistry([]), _NO_OP_PROFILES)
    state = _state([HumanMessage(content="hi")])

    await think(state)

    system = next(m for m in llm.seen[-1] if isinstance(m, SystemMessage))
    assert "Findings so far" not in str(system.content)
    assert "Retained memory" not in str(system.content)


async def test_think_screens_a_tool_failure_snippet_in_the_system_prompt() -> None:
    """End to end: a real ToolOutputScreenStage chain, wired through think()
    into _memory_context, must mark a tool-failure snippet the same way it
    marks a ToolMessage in history (C1, AUDIT.md)."""
    from cism.agent.guardrails import GuardrailChain, ToolOutputScreenStage

    llm = _RecordingMessagesChatModel(seen=[])
    think = make_think_node(llm, ToolRegistry([]), _NO_OP_PROFILES, GuardrailChain([ToolOutputScreenStage()]))
    memory_items = {
        "f1": MemoryItem(id="f1", tier="T3", phase_tag="recon", snippet="connection refused",
                         created_at=0.0, source_type="tool-failure"),
    }
    state = _state([HumanMessage(content="what happened?")], memory_items=memory_items)

    await think(state)

    system = next(m for m in llm.seen[-1] if isinstance(m, SystemMessage))
    assert "UNTRUSTED TOOL OUTPUT" in str(system.content)
    assert "connection refused" in str(system.content)


def test_respond_strips_a_leaked_native_tool_call_down_to_a_plain_acknowledgment() -> None:
    """Live, round 12 (2026-10-17): a plain acknowledgment turn with no
    tools bound still got the model's own native tool-call template
    syntax as its entire final answer -- nothing executes it (no tools
    were bound to parse it into), but showing it verbatim reads as
    broken text."""
    respond = make_respond_node(GuardrailChain([]))
    state = {"messages": [AIMessage(
        content="<|tool_call_start|>[curl(target='http://172.28.0.3/login.php')]<|tool_call_end|>"
    )]}

    update = respond(state)

    assert update["messages"][0].content == "Noted."


def test_respond_strips_only_the_leaked_span_and_keeps_real_prose() -> None:
    respond = make_respond_node(GuardrailChain([]))
    state = {"messages": [AIMessage(
        content="Here's what I found.\n<|tool_call_start|>[nmap(target='x')]<|tool_call_end|>\nDone."
    )]}

    update = respond(state)

    assert update["messages"][0].content == "Here's what I found.\n\nDone."


def test_respond_leaves_ordinary_content_untouched() -> None:
    respond = make_respond_node(GuardrailChain([]))
    state = {"messages": [AIMessage(content="The scan found 3 open ports.")]}

    update = respond(state)

    assert update["messages"][0].content == "The scan found 3 open ports."


def test_respond_substitutes_a_question_appropriate_fallback_for_genuine_emptiness() -> None:
    """Live, round 12 (2026-10-17): a status question ("what have we found
    so far?") once got a truly empty final answer -- real reasoning-model
    flakiness surviving the single opening-move retry, not a leaked
    tool-call fragment. "Noted." (the fallback for the leaked-syntax case)
    would be a non-sequitur here -- nothing was said to acknowledge, a
    question just went unanswered."""
    respond = make_respond_node(GuardrailChain([]))
    state = {"messages": [AIMessage(content="")]}

    update = respond(state)

    assert update["messages"][0].content == "I don't have anything further to add right now."


def test_respond_still_uses_noted_when_the_emptiness_came_from_a_leaked_tool_call() -> None:
    respond = make_respond_node(GuardrailChain([]))
    state = {"messages": [AIMessage(
        content="<|tool_call_start|>[curl(target='x')]<|tool_call_end|>"
    )]}

    update = respond(state)

    assert update["messages"][0].content == "Noted."
