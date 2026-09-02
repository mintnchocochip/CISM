"""The graph's node functions: think, act, phase_router, respond.

Each node function is produced by a small factory (``make_*``) that closes
over its injected dependencies (the model, the tool registry, a guardrail
chain) rather than reaching for globals — the same dependency-injection
discipline as :func:`cism.agent.graph.build_graph`, so nodes stay testable
in isolation.

The input guardrail is applied once, in :mod:`cism.agent.core`, to the
user's submitted text before the graph is ever started — not here. Unlike
the action and output chains, there is exactly one input to guard per run,
and it exists before any node does, so there is no seam here for it to sit
in.
"""

from __future__ import annotations

from typing import Callable

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails import GuardrailChain
from cism.agent.profiles import PhaseProfiles
from cism.agent.state import AgentState, IllegalPhaseTransition, Phase, PhaseStateMachine
from cism.agent.tools import ToolRegistry
from cism.depg import Edge, ExtractorRegistry, Graph
from cism.depg.linking import find_precondition
from cism.memory import MemoryStore, memory_key

__all__ = [
    "make_act_node",
    "make_depg_update_node",
    "make_memory_update_node",
    "make_phase_router",
    "make_respond_node",
    "make_think_node",
    "route_after_think",
]

#: Safety valve against a runaway loop (e.g. a model that never stops
#: requesting tools). Counts AI turns, not tool calls.
MAX_AI_TURNS = 6

#: A placeholder progression heuristic: on a successful tool call, propose
#: moving one phase forward. This is not the real phase-decision logic —
#: that is later work — it exists only so the router (and PhaseChanged
#: events) have something observable to validate against dummy data. Every
#: entry here is already a legal move in PHASE_TRANSITIONS.
DEFAULT_NEXT_PHASE: dict[Phase, Phase] = {
    Phase.RECON: Phase.ENUMERATION,
    Phase.ENUMERATION: Phase.VULNERABILITY_DISCOVERY,
    Phase.VULNERABILITY_DISCOVERY: Phase.EXPLOITATION,
    Phase.EXPLOITATION: Phase.POST_EXPLOITATION,
    Phase.POST_EXPLOITATION: Phase.REPORTING,
    Phase.REPORTING: Phase.REPORTING,
}


def _bind_tools_if_supported(llm: BaseChatModel, tools: list) -> BaseChatModel:
    """A phase with no tools, or a model that never implements bind_tools
    (DummyChatModel's inherited default raises NotImplementedError), is used
    unbound rather than crashing the run."""
    if not tools:
        return llm
    try:
        return llm.bind_tools(tools)
    except NotImplementedError:
        return llm


def make_think_node(
    llm: BaseChatModel, tools: ToolRegistry, profiles: PhaseProfiles
) -> Callable[[AgentState], dict]:
    async def think(state: AgentState) -> dict:
        profile = profiles.get(state["phase"])
        # tool_help is exempt from phase gating (design doc §5): knowing
        # what a tool can do carries none of the risk that using it does,
        # so it's always offered when the registry has one, regardless of
        # what this phase's profile declares. The `if name in tools` filter
        # on profile.tool_names itself is unchanged from before — a profile
        # can still name a tool the current registry doesn't have (e.g. the
        # bare dummy-tools registry).
        names = {name for name in profile.tool_names if name in tools}
        if "tool_help" in tools:
            names.add("tool_help")
        phase_tools = [tools.get(name) for name in names]
        bound = _bind_tools_if_supported(llm, phase_tools)
        # The prompt is prepended for this invocation only — never appended
        # to state, or every loop iteration would stack another copy.
        messages = [SystemMessage(content=profile.system_prompt), *state["messages"]]
        response = None
        async for chunk in bound.astream(messages):
            response = chunk if response is None else response + chunk
        if response is None:
            # A provider that errors mid-handshake or returns an empty
            # completion can leave the stream with zero chunks. Without
            # this, ``response`` stays None and "respond" later crashes
            # doing ``str(last.content)`` on it — caught by core.py's
            # broad except as a generic "run failed", but an unhelpful
            # failure mode. An empty final answer is a better default.
            response = AIMessage(content="")
        return {"messages": [response]}

    return think


def route_after_think(state: AgentState) -> str:
    last = state["messages"][-1]
    tool_calls = getattr(last, "tool_calls", None) or []
    ai_turns = sum(1 for m in state["messages"] if isinstance(m, AIMessage))
    if tool_calls and ai_turns < MAX_AI_TURNS:
        return "act"
    return "respond"


def make_act_node(
    tools: ToolRegistry,
    base_action_chain: GuardrailChain,
    profiles: PhaseProfiles,
) -> Callable[[AgentState], dict]:
    def act(state: AgentState) -> dict:
        profile = profiles.get(state["phase"])
        action_chain = GuardrailChain(base_action_chain.stages + list(profile.action_stages))
        last = state["messages"][-1]
        tool_calls = getattr(last, "tool_calls", None) or []
        results: list[ToolMessage] = []

        for call in tool_calls:
            guard = action_chain.run(call)
            if not guard.allowed:
                results.append(
                    ToolMessage(
                        content=f"blocked by action guardrail: {guard.reason or 'no reason given'}",
                        tool_call_id=call["id"],
                        name=call["name"],
                        status="error",
                    )
                )
                continue

            call = guard.value
            # An unregistered tool name is a programming error inside the
            # graph — the model should only ever be offered tools that
            # exist in the registry — so this is allowed to raise and fail
            # the run loudly rather than being treated as guardrail content.
            tool = tools.get(call["name"])

            try:
                message = tool.invoke(call)
            except Exception as exc:  # tool execution failure is content, not an exception
                message = ToolMessage(
                    content=f"{type(exc).__name__}: {exc}",
                    tool_call_id=call["id"],
                    name=call["name"],
                    status="error",
                )
            results.append(message)

        return {"messages": results}

    return act


def _trailing_tool_results(messages: list) -> list[tuple[ToolCall | None, ToolMessage]]:
    """The run of ``ToolMessage``s the most recent ``act`` step appended,
    each paired with its originating ``ToolCall`` (found on the preceding
    ``AIMessage`` — a ``ToolMessage`` alone doesn't carry the call's
    original arguments). Exact, not a heuristic: ``depg_update`` always runs
    immediately after ``act``, and nothing else appends messages between
    them."""
    results: list[ToolMessage] = []
    for message in reversed(messages):
        if isinstance(message, ToolMessage):
            results.append(message)
        else:
            break
    results.reverse()

    calls_by_id: dict[str, ToolCall] = {}
    ai_index = len(messages) - len(results) - 1
    if results and ai_index >= 0:
        for call in getattr(messages[ai_index], "tool_calls", None) or []:
            calls_by_id[call["id"]] = call

    return [(calls_by_id.get(m.tool_call_id), m) for m in results]


def make_depg_update_node(extractors: ExtractorRegistry) -> Callable[[AgentState], dict]:
    def depg_update(state: AgentState) -> dict:
        graph = Graph.from_state(state["depg_nodes"], state["depg_edges"])
        phase_tag = state["phase"].to_wire()

        for call, message in _trailing_tool_results(state["messages"]):
            extraction = extractors.get(message.name or "").extract(
                call, message, graph, state["target"]
            )
            # Every precondition is resolved before any of this message's own
            # nodes land, or two siblings from one call (nmap's two ports)
            # would chain onto each other via the last-touched fallback.
            preconditions = {
                node.id: find_precondition(graph, node.target, call) for node in extraction.nodes
            }
            for node in extraction.nodes:
                node.phase = phase_tag
                stored = graph.upsert_node(node)
                precondition = preconditions[node.id]
                if precondition is not None and precondition.id != stored.id:
                    graph.add_edge(Edge(parent=precondition.id, child=stored.id))
            for edge in extraction.edges:
                graph.add_edge(edge)

        graph.settle()
        graph.prune()
        # depg_nodes/depg_edges have no reducer, so LangGraph's LastValue
        # channel fully replaces state with whatever is returned here — the
        # full merged graph must always come back, never just this step's delta.
        return {"depg_nodes": graph.nodes, "depg_edges": graph.edges}

    return depg_update


def make_phase_router() -> Callable[[AgentState], dict]:
    def phase_router(state: AgentState) -> dict:
        machine = PhaseStateMachine(current=state["phase"])
        last = state["messages"][-1]
        succeeded = isinstance(last, ToolMessage) and last.status != "error"
        before = machine.current

        if succeeded:
            target = DEFAULT_NEXT_PHASE[machine.current]
            try:
                machine.transition(target)
            except IllegalPhaseTransition:
                pass  # stay put; an illegal proposed move is not a run failure

        return {"phase": machine.current, "phase_changed": machine.current != before}

    return phase_router


def make_memory_update_node() -> Callable[[AgentState], dict]:
    def memory_update(state: AgentState) -> dict:
        store = MemoryStore.from_state(state["memory_items"])
        phase_tag = state["phase"].to_wire()
        trailing = _trailing_tool_results(state["messages"])
        this_step_call_ids = {message.tool_call_id for _, message in trailing}

        # Every source below is scoped to this step alone. Widening any of
        # them to the whole run would grow `hits` every iteration whether or
        # not the item actually recurred.
        for node in state["depg_nodes"].values():
            if not node.evidence:
                continue
            latest = node.evidence[-1]
            if latest.call_id in this_step_call_ids:
                store.upsert(node.id, latest.tier, phase_tag, latest.exit_signal)

        for _, message in trailing:
            if getattr(message, "status", "success") != "error":
                continue
            snippet = str(message.content)[:120]
            store.upsert(memory_key("tool-failure", phase_tag, snippet), "T3", phase_tag, snippet)

        last_ai = next((m for m in reversed(state["messages"]) if isinstance(m, AIMessage)), None)
        if last_ai is not None and str(last_ai.content).strip():
            snippet = str(last_ai.content).strip()[:120]
            store.upsert(memory_key("narration", phase_tag, snippet), "T3", phase_tag, snippet)

        if state.get("phase_changed"):
            snippet = f"phase -> {phase_tag}"
            store.upsert(memory_key("phase-change", phase_tag, snippet), "T2", phase_tag, snippet)

        return {"memory_items": store.items}

    return memory_update


def make_respond_node(output_chain: GuardrailChain) -> Callable[[AgentState], dict]:
    def respond(state: AgentState) -> dict:
        """Always returns an explicit message, even when the guardrail
        passes the content through unchanged. That is deliberate: the
        translator in core.py only ever turns a "respond" step into a
        Narration event, never a "think" step, specifically so nothing
        reaches the UI before the output guardrail has had a chance to see
        it. The tradeoff is a second AIMessage in this run's transcript
        (the pre-guard one from "think", plus this one) — harmless today
        since state isn't persisted across submit() calls, but worth
        revisiting once it is.
        """
        last = state["messages"][-1]
        content = str(last.content)
        result = output_chain.run(content)
        text = (
            result.value
            if result.allowed
            else f"[response withheld by output guardrail: {result.reason or 'no reason given'}]"
        )
        return {"messages": [AIMessage(content=text)]}

    return respond
