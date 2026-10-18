"""cism/agent/graph.py: build_graph() is the critical wiring — every other
module is exercised through it indirectly, but nothing asserted its node/edge
topology directly (H1, AUDIT.md)."""

from __future__ import annotations

from langchain_core.messages import HumanMessage

from cism.agent.graph import build_graph
from cism.agent.guardrails import GuardrailSeam
from cism.agent.llm import DummyChatModel
from cism.agent.profiles import default_profiles
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap
from cism.depg import ExtractorRegistry, GenericExtractor


def _build_graph():
    tools = ToolRegistry([dummy_nmap, dummy_msfconsole])
    return build_graph(
        DummyChatModel(),
        tools,
        GuardrailSeam.no_op(),
        ExtractorRegistry({}, GenericExtractor()),
        default_profiles(tools),
    )


def test_every_node_from_the_docstring_diagram_is_wired() -> None:
    nodes = set(_build_graph().get_graph().nodes)
    assert nodes == {
        "__start__", "__end__", "think", "act", "depg_update",
        "phase_router", "memory_update", "respond",
    }


def test_the_loop_edges_match_the_docstring_diagram() -> None:
    edges = {(e.source, e.target) for e in _build_graph().get_graph().edges}
    assert edges == {
        ("__start__", "think"),
        ("think", "act"),
        ("think", "respond"),
        ("act", "depg_update"),
        ("depg_update", "phase_router"),
        ("phase_router", "memory_update"),
        ("memory_update", "think"),
        ("respond", "__end__"),
    }


def test_think_is_the_only_conditional_branch_point() -> None:
    conditional_sources = {e.source for e in _build_graph().get_graph().edges if e.conditional}
    assert conditional_sources == {"think"}


async def test_an_end_to_end_dummy_run_reaches_respond() -> None:
    """DummyChatModel never emits tool_calls, so the loop must take the
    think -> respond branch and terminate, not hang in act/depg_update."""
    graph = _build_graph()
    initial_state = {
        "messages": [HumanMessage(content="scan it")],
        "phase": Phase.RECON,
        "phase_proposal": None,
        "phase_proposal_is_new": False,
        "run_id": "test-run",
        "target": "10.0.0.5",
        "depg_nodes": {},
        "depg_edges": [],
        "memory_items": {},
    }

    result = await graph.ainvoke(initial_state, config={"configurable": {"thread_id": "t1"}})

    assert result["messages"][-1].content
