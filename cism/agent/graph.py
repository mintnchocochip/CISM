"""Builds the LangGraph state graph. A pure factory: every dependency is
injected, nothing is constructed inside it — that's what keeps this file
unchanged whether the model, tools, or guardrails behind it are the dummy
stub versions or real ones later.

::

    entry -> think ── llm.astream(), accumulated into one message (input guardrail already ran in core.py)
               │
       tool_calls in response, under the turn cap?
               │no ──▶ respond ── output_chain runs on final text ──▶ END
               │yes
             act ── for each call: action_chain.run(call), then
                     ToolRegistry.get(call.name).invoke(call) if allowed
               │
         depg_update ── ExtractorRegistry turns successful tool results
                         into DEPG nodes/edges
               │
         phase_router ── PhaseStateMachine proposes a legal transition
               │
               └──▶ think (loop)
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from cism.agent.guardrails import GuardrailSeam
from cism.agent.nodes import (
    make_act_node,
    make_depg_update_node,
    make_phase_router,
    make_respond_node,
    make_think_node,
    route_after_think,
)
from cism.agent.state import AgentState
from cism.agent.tools import ToolRegistry
from cism.depg import ExtractorRegistry

__all__ = ["build_graph"]


def build_graph(
    llm: BaseChatModel,
    tools: ToolRegistry,
    guardrails: GuardrailSeam,
    extractors: ExtractorRegistry,
) -> CompiledStateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("think", make_think_node(llm))
    graph.add_node("act", make_act_node(tools, guardrails.action))
    graph.add_node("depg_update", make_depg_update_node(extractors))
    graph.add_node("phase_router", make_phase_router())
    graph.add_node("respond", make_respond_node(guardrails.output))

    graph.add_edge(START, "think")
    graph.add_conditional_edges("think", route_after_think, {"act": "act", "respond": "respond"})
    graph.add_edge("act", "depg_update")
    graph.add_edge("depg_update", "phase_router")
    graph.add_edge("phase_router", "think")
    graph.add_edge("respond", END)

    return graph.compile()
