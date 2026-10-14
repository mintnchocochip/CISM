"""The graph's node functions: think, act, phase_router, respond. Each is
produced by a make_* factory closing over its injected dependencies, so
nodes stay testable in isolation. The input guardrail runs once in
cism.agent.core, before the graph starts — not here."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Awaitable, Callable

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails import GuardrailChain, PrivacyGateway
from cism.agent.profiles import PhaseProfiles
from cism.agent.state import AgentState, IllegalPhaseTransition, Phase, PhaseStateMachine
from cism.agent.tools import ToolRegistry
from cism.depg import Edge, ExtractorRegistry, Graph, GradedSupport, Node
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

#: No local-model tokenizer is available generically, so this is a rough
#: chars-per-token estimate (B2, AUDIT.md) — good enough for a budget, not billing.
_CHARS_PER_TOKEN = 4
_RESPONSE_RESERVE_TOKENS = 512
DEFAULT_CONTEXT_WINDOW = 32_768

#: Flat per-message overhead (role wrapper, message-boundary tokens a chars/4
#: count on content alone can't see) — small, but keeps a long run of
#: near-empty messages from estimating as free.
_PER_MESSAGE_OVERHEAD_TOKENS = 4


def _estimate_tokens(text: str) -> int:
    return len(text) // _CHARS_PER_TOKEN


def _message_cost(message) -> int:
    """Cost of one message as it actually goes on the wire — not just
    ``.content``. An AIMessage's ``tool_calls`` (Q2, CODE_REVIEW.md: a large
    call like ``nmap`` with a long ``extra`` arg) and a ToolMessage's
    ``tool_call_id`` carry real tokens too; counting content alone means
    exactly the multi-tool run B2 exists to bound is under-counted and never
    compacted."""
    content = str(getattr(message, "content", ""))
    tool_calls = getattr(message, "tool_calls", None)
    extra = str(tool_calls) if tool_calls else ""
    tool_call_id = getattr(message, "tool_call_id", None)
    if tool_call_id:
        extra += str(tool_call_id)
    return _estimate_tokens(content) + _estimate_tokens(extra) + _PER_MESSAGE_OVERHEAD_TOKENS


def _compact_history(messages: list, system_prompt: str, context_window: int) -> tuple[list, int]:
    """Keeps the most recent messages that fit the budget; drops older ones
    and, if any were dropped, prepends one summary line in their place.
    Full history stays in state — this only shapes what's sent to the model."""
    budget = context_window - _RESPONSE_RESERVE_TOKENS - _estimate_tokens(system_prompt)
    kept: list = []
    used = 0
    for message in reversed(messages):
        cost = _message_cost(message)
        if kept and used + cost > budget:
            break
        kept.append(message)
        used += cost
    kept.reverse()
    dropped = len(messages) - len(kept)
    if dropped:
        note = SystemMessage(content=f"[{dropped} earlier turn(s) omitted to fit the context window]")
        kept = [note, *kept]
    return kept, dropped

#: The two extractors with a fixed, non-LLM vocabulary — the only
#: cause_class literals _phase_ready can safely match on directly.
_OPEN_PORT_CAUSE = "open-port"
_CREDENTIAL_FOUND_CAUSE = "credential-found"

#: The phase a ready phase moves into next. Every value here is a legal
#: PHASE_TRANSITIONS move, so machine.transition in phase_router never
#: actually raises for a phase drawn from this map.
_FORWARD_PHASE: dict[Phase, Phase] = {
    Phase.RECON: Phase.ENUMERATION,
    Phase.ENUMERATION: Phase.VULNERABILITY_DISCOVERY,
    Phase.VULNERABILITY_DISCOVERY: Phase.EXPLOITATION,
    Phase.EXPLOITATION: Phase.POST_EXPLOITATION,
    Phase.POST_EXPLOITATION: Phase.REPORTING,
    Phase.REPORTING: Phase.REPORTING,
}


def _phase_ready(phase: Phase, nodes: dict[str, Node]) -> bool:
    """Whether this phase's own objective has real DEPG evidence behind it —
    not "some tool call exited zero", which is what the old placeholder
    (advance on any successful call) actually checked. Looks at nodes
    tagged with this phase (Node.phase, set in depg_update from the phase
    active when they were extracted) that reached "resolved" — alive
    verdict *and* supported, per reduce_state. depg_update always runs
    before phase_router in the graph, so this step's own extraction is
    already reflected.

    RECON and EXPLOITATION gate on their phase's one deterministic
    cause_class (nmap's open-port, hydra's credential-found) so a scan
    that finds nothing, or a credential attempt that fails, correctly
    doesn't count as done. The other phases have no fixed cause_class
    vocabulary to match against — LLM-extracted, free text — so they
    accept any resolved node produced while in that phase: still real
    evidence, just not a named-finding requirement.
    """
    phase_tag = phase.to_wire()
    in_phase_resolved = [
        node for node in nodes.values() if node.phase == phase_tag and node.state == "resolved"
    ]
    if phase is Phase.RECON:
        return any(node.cause_class == _OPEN_PORT_CAUSE for node in in_phase_resolved)
    if phase is Phase.EXPLOITATION:
        return any(node.cause_class == _CREDENTIAL_FOUND_CAUSE for node in in_phase_resolved)
    return bool(in_phase_resolved)


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


#: Marker a model without real tool-calling support can emit instead, e.g.
#: 'TOOL_CALL: {"name": "nmap", "args": {"target": "10.0.0.5"}}'.
_TOOL_CALL_MARKER = "TOOL_CALL:"

_FALLBACK_HINT = (
    "\n\nIf you can't make a structured tool call, end your reply with a "
    f'line starting with {_TOOL_CALL_MARKER} followed by a JSON object like '
    '{"name": "<tool>", "args": {...}}.'
)

#: 2026-10-12 live-test against a real small local model (lfm2.5-8b-a1b):
#: given an open-ended instruction, it twice produced zero tool calls —
#: once by writing a JSON *array* of several planned future calls as prose
#: instead of one structured call, once by asking the user to re-confirm
#: the target that was already on the line above. Both are prompt gaps,
#: not model-capability gaps: the same model handled a single, explicit
#: instruction (name the tool, give the target) correctly on the first try.
_ONE_CALL_RULE = (
    "Make exactly one tool call per turn, using the tool-calling mechanism "
    "— never write out a list of several planned calls as text or JSON. "
    "Decide the next single call, see its result, then decide the one "
    "after that."
)

#: 2026-10-12, live: a bare "HI" with no scan request triggered a full,
#: unprompted nmap -> whatweb -> nikto chain against the configured
#: target. Root cause: every phase prompt below is phrased as a standing
#: order ("Start with nmap against the target") with nothing conditioning
#: it on the user's current message actually calling for it — true
#: regardless of phase, so this is prepended once rather than reworded
#: five times. The phase text still answers "what tool, once something
#: needs doing"; this answers "should anything be done on this turn at
#: all", which the phase text was never written to cover.
_ACT_ONLY_WHEN_ASKED = (
    "Only call a tool when the user's current message actually calls for "
    "it — a new scan, a continuation of testing already underway, or an "
    "explicit request. A greeting, small talk, or a question about status "
    "or findings is not a request to act: answer in plain text instead. "
    "Having a target configured and tools available is not, by itself, a "
    "reason to call one."
)


def _extract_balanced_json(text: str, start: int) -> str | None:
    """The first balanced {...} object in text at or after start."""
    open_idx = text.find("{", start)
    if open_idx == -1:
        return None
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx : i + 1]
    return None


def _parse_text_tool_call(content: str) -> ToolCall | None:
    """Recovers a tool call a model without native tool-calling wrote as
    text instead — see _FALLBACK_HINT. None if nothing usable is found."""
    marker_idx = content.find(_TOOL_CALL_MARKER)
    if marker_idx == -1:
        return None
    raw = _extract_balanced_json(content, marker_idx + len(_TOOL_CALL_MARKER))
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    name = payload.get("name") or payload.get("tool")
    args = payload.get("args") or payload.get("arguments") or {}
    if not isinstance(name, str) or not name.strip() or not isinstance(args, dict):
        return None
    return {
        "name": name.strip(),
        "args": args,
        "id": f"call_{uuid.uuid4().hex[:8]}",
        "type": "tool_call",
    }


def make_think_node(
    llm: BaseChatModel,
    tools: ToolRegistry,
    profiles: PhaseProfiles,
    tool_output_chain: GuardrailChain | None = None,
    *,
    privacy: PrivacyGateway | None = None,
) -> Callable[[AgentState], dict]:
    # C1 (AUDIT.md): screened here, at prompt-build time, not when act()
    # appends the ToolMessage to state — depg_update's regex extractors and
    # the audit log both need the raw tool output; only what the model sees
    # needs the untrusted-data wrapper.
    screen = tool_output_chain or GuardrailChain([])

    async def think(state: AgentState) -> dict:
        profile = profiles.get(state["phase"])
        # tool_help is exempt from phase gating — knowing what a tool does carries
        # none of the risk that using it does, so it's always offered when present.
        names = {name for name in profile.tool_names if name in tools}
        if "tool_help" in tools:
            names.add("tool_help")
        phase_tools = [tools.get(name) for name in names]
        bound = _bind_tools_if_supported(llm, phase_tools)
        # Prepended for this invocation only, never appended to state. The
        # target line exists because profile.system_prompt is phase-only and
        # never mentions it — without this, the model has no way to know
        # what "the target" or "our target" refers to. "Already decided...
        # never ask" was added after a live run asked the user to re-supply
        # a target that was sitting right here (see _ONE_CALL_RULE's note).
        target_line = (
            f"Target: {state['target']} — already decided for this run; use it "
            "directly in tool calls. Never ask the user to confirm or supply it."
            if state["target"]
            else "No target configured yet."
        )
        act_rule = f"\n\n{_ACT_ONLY_WHEN_ASKED}" if phase_tools else ""
        rules = f"\n\n{_ONE_CALL_RULE}" if phase_tools else ""
        hint = _FALLBACK_HINT if phase_tools else ""
        system_prompt = f"{target_line}{act_rule}\n\n{profile.system_prompt}{rules}{hint}"
        context_window = state.get("context_window") or DEFAULT_CONTEXT_WINDOW
        history, dropped = _compact_history(state["messages"], system_prompt, context_window)

        def _for_model(text: str) -> str:
            screened = screen.run(text).value
            return privacy.anonymize(screened) if privacy is not None else screened

        history = [
            m.model_copy(update={"content": _for_model(str(m.content))})
            if isinstance(m, ToolMessage) else m
            for m in history
        ]
        if privacy is not None:
            system_prompt = privacy.anonymize(system_prompt)
        messages = [SystemMessage(content=system_prompt), *history]
        response = None
        async for chunk in bound.astream(messages):
            response = chunk if response is None else response + chunk
        if response is None:
            # A provider that errors or returns nothing leaves zero chunks;
            # an empty answer is a better default than a later crash on None.
            response = AIMessage(content="")
        if phase_tools and not response.tool_calls:
            # Weak/non-tool-calling models often describe the call in prose
            # instead of the API's structured field — recover it from text.
            parsed = _parse_text_tool_call(str(response.content))
            if parsed is not None:
                response = response.model_copy(update={"tool_calls": [parsed]})
        return {"messages": [response], "compacted": dropped}

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


def _call_target(call: ToolCall | None, default: str) -> str:
    """The host a tool call's own findings belong to is the target argument
    *that call* was made with, never the session's one declared/startup
    target — a multi-host engagement calls the same tools against several
    hosts, and stamping every node with state["target"] regardless of which
    host was actually scanned silently merges unrelated hosts' findings onto
    one node family. Confirmed live 2026-10-12: a second nmap call against a
    different host had all 19 of its open ports attributed to the first
    host instead. Falls back to the session default only for a call with no
    target argument of its own (e.g. tool_help) or no call at all."""
    if call is not None:
        raw = (call.get("args") or {}).get("target")
        if raw:
            return normalize_target(str(raw))
    return default


def make_depg_update_node(
    extractors: ExtractorRegistry, *, graded_propagation: bool = False
) -> Callable[[AgentState], Awaitable[dict]]:
    async def depg_update(state: AgentState) -> dict:
        graph = Graph.from_state(state["depg_nodes"], state["depg_edges"])
        phase_tag = state["phase"].to_wire()
        # Only a fallback for a call with no target argument of its own
        # (e.g. tool_help) — see _call_target below for why this must not
        # be used for every call in a multi-host engagement.
        default_target = normalize_target(state["target"])

        for call, message in _trailing_tool_results(state["messages"]):
            extractor = extractors.get(message.name or "")
            target = _call_target(call, default_target)
            # to_thread: extraction can be a ~20s blocking LLM call, off the
            # loop thread so it doesn't freeze the TUI. Stays sequential
            # (not gathered) — find_precondition needs each call's nodes
            # upserted before the next call links against them.
            extraction = await asyncio.to_thread(extractor.extract, call, message, graph, target)
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

        graph.settle(support=GradedSupport() if graded_propagation else None)
        graph.prune()
        graph.compute_metrics()
        # No reducer on these keys — must return the full merged graph, never just a delta.
        return {"depg_nodes": graph.nodes, "depg_edges": graph.edges}

    return depg_update


def make_phase_router() -> Callable[[AgentState], dict]:
    def phase_router(state: AgentState) -> dict:
        machine = PhaseStateMachine(current=state["phase"])
        before = machine.current

        if _phase_ready(machine.current, state["depg_nodes"]):
            target = _FORWARD_PHASE[machine.current]
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
                store.upsert(
                    node.id, latest.tier, phase_tag, latest.exit_signal, source_type="depg_node"
                )

        for _, message in trailing:
            if getattr(message, "status", "success") != "error":
                continue
            snippet = str(message.content)[:120]
            store.upsert(
                memory_key("tool-failure", phase_tag, snippet),
                "T3", phase_tag, snippet, source_type="tool-failure",
            )

        last_ai = next((m for m in reversed(state["messages"]) if isinstance(m, AIMessage)), None)
        if last_ai is not None and str(last_ai.content).strip():
            snippet = str(last_ai.content).strip()[:120]
            store.upsert(
                memory_key("narration", phase_tag, snippet),
                "T3", phase_tag, snippet, source_type="narration",
            )

        if state.get("phase_changed"):
            snippet = f"phase -> {phase_tag}"
            store.upsert(
                memory_key("phase-change", phase_tag, snippet),
                "T2", phase_tag, snippet, source_type="phase-change",
            )

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
