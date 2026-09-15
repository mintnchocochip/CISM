"""The graph's node functions: think, act, phase_router, respond. Each is
produced by a make_* factory closing over its injected dependencies, so
nodes stay testable in isolation. The input guardrail runs once in
cism.agent.core, before the graph starts — not here."""

from __future__ import annotations

from typing import Awaitable, Callable

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails import GuardrailChain
from cism.agent.profiles import PhaseProfiles
from cism.agent.state import AgentState, IllegalPhaseTransition, Phase, PhaseStateMachine
from cism.agent.tools import ToolRegistry
from cism.depg import Edge, ExtractorRegistry, Graph
from cism.depg.linking import find_precondition
from cism.depg.normalize import normalize_target
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

#: Runaway-loop safety valve. Counts AI turns only since this run's own
#: HumanMessage, not the whole persisted session — otherwise it'd exhaust once, ever.
MAX_AI_TURNS = 6

#: Placeholder progression heuristic — advance one phase on a successful tool
#: call. Not real phase logic; just gives the router something to validate against.
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
        # tool_help is exempt from phase gating — knowing what a tool does carries
        # none of the risk that using it does, so it's always offered when present.
        names = {name for name in profile.tool_names if name in tools}
        if "tool_help" in tools:
            names.add("tool_help")
        phase_tools = [tools.get(name) for name in names]
        bound = _bind_tools_if_supported(llm, phase_tools)
        # Prepended for this invocation only, never appended to state.
        messages = [SystemMessage(content=profile.system_prompt), *state["messages"]]
        response = None
        async for chunk in bound.astream(messages):
            response = chunk if response is None else response + chunk
        if response is None:
            # A provider that errors or returns nothing leaves zero chunks;
            # an empty answer is a better default than a later crash on None.
            response = AIMessage(content="")
        return {"messages": [response]}

    return think


def route_after_think(state: AgentState) -> str:
    messages = state["messages"]
    last = messages[-1]
    tool_calls = getattr(last, "tool_calls", None) or []
    ai_turns = 0
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            break
        if isinstance(message, AIMessage):
            ai_turns += 1
    if tool_calls and ai_turns < MAX_AI_TURNS:
        return "act"
    return "respond"


def make_act_node(
    tools: ToolRegistry,
    base_action_chain: GuardrailChain,
    profiles: PhaseProfiles,
) -> Callable[[AgentState], Awaitable[dict]]:
    async def act(state: AgentState) -> dict:
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
                        content="blocked by action guardrail",
                        tool_call_id=call["id"],
                        name=call["name"],
                        status="error",
                        additional_kwargs={"guardrail_detail": f"[{guard.stage}] {guard.reason}"},
                    )
                )
                continue

            call = guard.value
            # PhaseToolGuardStage's allowed set is catalog-derived, not registry-filtered,
            # so it can pass a call this registry never bound — treated as guardrail
            # content (not raised), same as any other "one bad call" case.
            if call["name"] not in tools:
                results.append(
                    ToolMessage(
                        content="blocked by action guardrail",
                        tool_call_id=call["id"],
                        name=call["name"],
                        status="error",
                        additional_kwargs={
                            "guardrail_detail": f"[act] {call['name']!r} is not a registered tool"
                        },
                    )
                )
                continue
            tool = tools.get(call["name"])

            try:
                # ainvoke, not invoke: a sync call here would block the TUI's event
                # loop for up to 60s. ainvoke's default _arun offloads to a thread.
                message = await tool.ainvoke(call)
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
    """The most recent act step's ToolMessages, each paired with its
    originating ToolCall. Exact, not a heuristic: depg_update always runs
    right after act, nothing else appends messages between them."""
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
        # Normalized once, here — an identity key can't depend on incidental
        # formatting or "10.0.0.5"/"ssh://10.0.0.5:22" fragment into separate nodes.
        target = normalize_target(state["target"])

        for call, message in _trailing_tool_results(state["messages"]):
            extraction = extractors.get(message.name or "").extract(
                call, message, graph, target
            )
            # Resolved before any of this message's own nodes land, or two
            # siblings from one call (nmap's two ports) would chain onto each other.
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
        # No reducer on these keys — must return the full merged graph, never just a delta.
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

        # Scoped to this step alone — widening to the whole run would grow
        # `hits` every iteration regardless of whether the item actually recurred.
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
        passes content through unchanged — so core.py never narrates a
        "think" message before the output guardrail has seen it."""
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
