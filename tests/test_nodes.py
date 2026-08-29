"""cism/agent/nodes.py: depg_update tested in isolation against a hand-built
AgentState — no LLM, no compiled graph. Exercises what the node is for:
turning this step's tool results into DEPG graph state, without ever losing
what earlier steps already found.
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult

from cism.agent.llm import DummyChatModel
from cism.agent.nodes import make_depg_update_node, make_think_node
from cism.agent.state import Phase
from cism.depg import ExtractorRegistry, GenericExtractor


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
    think = make_think_node(llm)
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
    think = make_think_node(llm)
    state = _state([HumanMessage(content="scan it")])

    update = await think(state)

    assert update["messages"][0] is not None
    assert update["messages"][0].content == ""


async def test_think_node_still_works_against_a_non_streaming_model() -> None:
    llm = DummyChatModel()
    think = make_think_node(llm)
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


def test_an_errored_tool_call_produces_no_node() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = _depg_update()(state)

    assert update["depg_nodes"] == {}


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

    assert update["depg_nodes"].keys() == first["depg_nodes"].keys()
