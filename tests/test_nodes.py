"""cism/agent/nodes.py: depg_update tested in isolation against a hand-built
AgentState — no LLM, no compiled graph. Exercises what the node is for:
turning this step's tool results into DEPG graph state, without ever losing
what earlier steps already found.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from cism.agent.nodes import make_depg_update_node
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
