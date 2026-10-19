"""The graph's node functions: think, act, phase_router, respond. Each is
produced by a make_* factory closing over its injected dependencies, so
nodes stay testable in isolation. The input guardrail runs once in
cism.agent.core, before the graph starts — not here."""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Awaitable, Callable

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.messages.tool import ToolCall
from langchain_core.utils.function_calling import convert_to_openai_tool

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
#: 2026-10-17, live (lowered from 6): turns bound by real tool execution
#: time (sqlmap/nikto/gobuster/hydra each have their own 60-120s sandbox
#: timeout) aren't helped by this cap either way -- one slow tool call
#: already dominates. But turns using only fast tools (curl/nmap) dropped
#: from ~110-180s to ~45s at this value, with the step-limit cap now
#: hitting it an honest "reached this turn's step limit" message
#: (respond()) instead of silently discarding a pending call. Separately
#: confirmed live with the cap raised to 30 (effectively off): the model
#: converges and stops on its own well before even 4 rounds when left
#: alone -- it isn't runaway-looping, a capped-at-4 turn just occasionally
#: trades a bit of depth for the latency win.
#: 2026-10-18, later same day: lowered again, 4 -> 2. The analysis above
#: was about *tool-execution* latency; a reasoning model (Ornith-1.5-9B,
#: forced <think> lead-in) dominates differently -- several chained turns
#: each running generation out to the full max_tokens cap (~2.2-2.5 min
#: each at this hardware's ~30 tok/s), so a chain of 4 could run ~9-10
#: minutes blind before the step-limit checkpoint ever hands control
#: back. 2 halves that worst case and checkpoints (with DEPG findings
#: carried through regardless) twice as often.
MAX_AI_TURNS = 2

#: No local-model tokenizer is available generically, so this is a rough
#: chars-per-token estimate (B2, AUDIT.md) — good enough for a budget, not
#: billing. 2026-10-17, live (round 12): a real request still overflowed
#: the server's actual context window ("17245 tokens... n_ctx: 16384") by
#: ~1300 tokens despite fitting this budget, because several turns of
#: markdown-heavy model output (bullets, bold, backticks) tokenize less
#: efficiently than the flat chars/4 this was tuned against. Tightened
#: with a safety margin deliberately biased toward compacting one turn
#: too early (cheap — DEPG/memory context already covers what's lost)
#: over a real 400 mid-engagement (a whole turn lost outright).
_CHARS_PER_TOKEN = 3
#: Floor only — think() below reserves the model's own configured
#: max_tokens instead whenever one is set (see _response_reserve).
_RESPONSE_RESERVE_TOKENS = 512
DEFAULT_CONTEXT_WINDOW = 32_768


def _response_reserve(llm: BaseChatModel) -> int:
    """2026-10-18, live: this budget only ever reserved a flat 512 tokens
    for the model's own response, independent of --max-tokens (4096 by
    default, scripts/run_tui*.sh) -- a reasoning model given room to think
    routinely used far more than 512, so a compacted prompt sized right up
    to that 512-token margin left the *actual* generation to run past
    n_ctx mid-stream (confirmed live: llama.cpp truncated a response at
    exactly n_ctx_slot, `truncated: 1`, after prompt + in-progress
    generation together exceeded it). Reserving the real configured cap
    instead means compaction may trigger a little earlier than strictly
    needed on a turn whose response turns out short -- cheap, and the
    established bias here (see _CHARS_PER_TOKEN above) is already toward
    that trade over a lost turn."""
    configured = getattr(llm, "max_tokens", None)
    return max(configured or 0, _RESPONSE_RESERVE_TOKENS)

#: Flat per-message overhead chars/4 can't see on content alone — keeps a
#: long run of near-empty messages from estimating as free.
_PER_MESSAGE_OVERHEAD_TOKENS = 4


def _estimate_tokens(text: str) -> int:
    return len(text) // _CHARS_PER_TOKEN


def _message_cost(message) -> int:
    """Cost of one message as it goes on the wire, not just ``.content`` —
    an AIMessage's ``tool_calls`` and a ToolMessage's ``tool_call_id`` carry
    real tokens too, and skipping them would under-count exactly the
    multi-tool runs B2 exists to bound."""
    content = str(getattr(message, "content", ""))
    tool_calls = getattr(message, "tool_calls", None)
    extra = str(tool_calls) if tool_calls else ""
    tool_call_id = getattr(message, "tool_call_id", None)
    if tool_call_id:
        extra += str(tool_call_id)
    return _estimate_tokens(content) + _estimate_tokens(extra) + _PER_MESSAGE_OVERHEAD_TOKENS


#: 2026-10-17, live (round 12 follow-up): a full nmap/nikto/sqlmap dump
#: from an earlier, already-completed turn sat in history at full size
#: even though depg_update (which always runs right after act(), before
#: the next think()) had already condensed its finding into the
#: DEPG/memory block that's injected into the system prompt separately
#: and regardless of this history. Paying full token cost for the same
#: signal twice made whole-turn dropping (below) kick in sooner than it
#: needed to. Mirrors the one existing precedent for "shrink old content,
#: mark that it happened, never mutate the original" in this codebase —
#: cism/depg/extractors.py's _MAX_PROMPT_CHARS/truncated_note.
_OLD_TOOL_OUTPUT_HEAD_CHARS = 350
_OLD_TOOL_OUTPUT_TAIL_CHARS = 100


#: 2026-10-18, live: a plain char-count cut landed inside the word "valid"
#: in a failed hydra run's own "0 valid password found" line, leaving a
#: tail of "d password found" — read by the model as a positive hit,
#: inverting a negative result. Losing a partial word at either edge
#: costs nothing real; keeping half of one can flip what a finding means.
_WHITESPACE_RE = re.compile(r"\s")


def _snap_head(content: str, limit: int) -> str:
    """``content[:limit]``, pulled back to the nearest preceding
    whitespace so a word is never bisected."""
    if len(content) <= limit:
        return content
    head = content[:limit]
    last_boundary = None
    for last_boundary in _WHITESPACE_RE.finditer(head):
        pass
    return head[: last_boundary.start()] if last_boundary else head


def _snap_tail(content: str, limit: int) -> str:
    """The last ``limit`` chars of content, pushed forward past the
    nearest following whitespace so a word is never bisected."""
    if len(content) <= limit:
        return content
    tail = content[-limit:]
    first_boundary = _WHITESPACE_RE.search(tail)
    return tail[first_boundary.end() :] if first_boundary else tail


def _truncate_old_tool_output(content: str) -> str:
    cap = _OLD_TOOL_OUTPUT_HEAD_CHARS + _OLD_TOOL_OUTPUT_TAIL_CHARS
    if len(content) <= cap:
        return content
    head = _snap_head(content, _OLD_TOOL_OUTPUT_HEAD_CHARS)
    tail = _snap_tail(content, _OLD_TOOL_OUTPUT_TAIL_CHARS)
    omitted = len(content) - len(head) - len(tail)
    return f"{head}\n...[{omitted} chars truncated — already summarized in the findings above]...\n{tail}"


#: 2026-10-19, live (Q&A-driven engagement): a human operator sending one
#: short message per exchange ("try X", "what does Y show") makes *every*
#: exchange its own "turn" under the old since-the-last-HumanMessage
#: boundary -- a tool result from literally one exchange ago (the exact
#: session cookie/CSRF token the model had just extracted) was already
#: "old" and eligible for Tier 2 stubbing the very next turn, under real
#: context pressure on a small model's 16k window. The model then had no
#: way to re-check its own extracted values and wrongly concluded it had
#: fabricated them. DEPG/memory context doesn't cover this gap -- session
#: artifacts (cookies, CSRF tokens) aren't findings, so extraction never
#: carries them forward the way it does a vulnerability. Counting the
#: boundary in tool-call round-trips instead of HumanMessages keeps the
#: last few exchanges' real detail available regardless of how many short
#: human turns land in between, while leaving autonomous/single-shot runs
#: (one HumanMessage, many round-trips in a loop) effectively unchanged --
#: there, the whole loop is usually well within this window already.
_RECENT_TOOL_TURNS_KEPT_FULL = 3


def _old_tool_output_boundary(messages: list) -> int:
    """Index before which a ToolMessage is "old" and eligible for
    shrink/stub. Walks backward counting contiguous ToolMessage groups
    (one tool-call round-trip each) rather than stopping at the most
    recent HumanMessage. Fewer than _RECENT_TOOL_TURNS_KEPT_FULL round
    trips in the whole history (including none at all) means nothing is
    eligible yet: show more, not less, when there's no real pressure to
    justify losing detail."""
    tool_turns_seen = 0
    in_group = False
    for index in range(len(messages) - 1, -1, -1):
        if isinstance(messages[index], ToolMessage):
            if not in_group:
                tool_turns_seen += 1
                in_group = True
        else:
            in_group = False
        if tool_turns_seen > _RECENT_TOOL_TURNS_KEPT_FULL:
            return index + 1
    return 0


def _shrink_old_tool_output(messages: list) -> list:
    """Truncates ToolMessage.content for every round-trip before the most
    recent _RECENT_TOOL_TURNS_KEPT_FULL -- those keep their tool results in
    full, since the model may still need exact detail from them to decide
    its next move."""
    boundary = _old_tool_output_boundary(messages)
    return [
        message.model_copy(update={"content": _truncate_old_tool_output(str(message.content))})
        if index < boundary and isinstance(message, ToolMessage)
        else message
        for index, message in enumerate(messages)
    ]


#: Tier 2 stub, used only once Tier 1 (the 350/100-char shrink above) still
#: can't fit everything in budget — real pressure, not hypothetical. Far
#: cheaper than the shrink, so it can only let *more* old turns survive as
#: bare conversational shape (an AIMessage/ToolMessage pair with none of
#: its original detail) than Tier 1 could, never fewer. Safe to lose that
#: detail entirely once there's real pressure: _depg_context()/
#: _memory_context() already carry the same signal, rebuilt fresh from
#: depg_nodes/memory_items every think() call, not from this chat history.
_OLD_TOOL_OUTPUT_STUB = "[tool output omitted under context pressure — see DEPG findings above]"


def _stub_old_tool_output(messages: list) -> list:
    """Same turn boundary as _shrink_old_tool_output; replaces old
    ToolMessage content with a fixed, near-free stub instead of a
    350/100-char shrink."""
    boundary = _old_tool_output_boundary(messages)
    return [
        message.model_copy(update={"content": _OLD_TOOL_OUTPUT_STUB})
        if index < boundary and isinstance(message, ToolMessage)
        else message
        for index, message in enumerate(messages)
    ]


#: 2026-10-18, live: a request measured as within budget by both the
#: chars/N estimate AND the real /tokenize-verified correction still
#: overflowed llama.cpp's n_ctx (16697 > 16384, a clean 400 — llama.cpp
#: itself handled an oversized request correctly by refusing it; the gap
#: was entirely upstream). Root cause: both budget checks only ever
#: measured system_prompt + message content — neither accounted for the
#: bound tools' own OpenAI tool-call schema JSON, which the server folds
#: into the real prompt and counts against n_ctx the moment any tools are
#: bound. _tool_schema_text below makes that overhead visible to both
#: tiers of the budget check, the same way system_prompt already was.
def _tool_schema_text(tools: list) -> str:
    if not tools:
        return ""
    return json.dumps([convert_to_openai_tool(t) for t in tools])


#: Compact proactively once usage crosses this fraction of budget, not
#: only once something would actually fail to fit — the chars/N estimate
#: (and even the real /tokenize correction) has already been seen to
#: swing several thousand tokens turn to turn on tool-heavy output, so
#: waiting for an exact overflow before reacting is reacting one turn
#: late. Matches the status bar's own WARN_RATIO convention (0.8) in
#: spirit, a bit more conservative given compaction has real headroom to
#: spend and a crashed turn doesn't.
_PROACTIVE_COMPACTION_THRESHOLD = 0.75


def _compact_history(
    messages: list,
    system_prompt: str,
    context_window: int,
    tool_schema_text: str = "",
    response_reserve: int = _RESPONSE_RESERVE_TOKENS,
) -> tuple[list, int]:
    """Keeps the most recent messages that fit the budget; drops older ones
    and, if any were dropped, prepends one summary line in their place.
    Full history stays in state — this only shapes what's sent to the model.

    Three tiers, cheapest-sufficient wins, each engaging once the one
    before it either couldn't fit the budget or left usage above
    _PROACTIVE_COMPACTION_THRESHOLD (real or imminent pressure, not
    engaged unconditionally — 2026-10-18, live: an unconditional Tier 1
    shrank a 777-char hydra result the instant a new chat turn started,
    for no budget reason at all, and the mid-word cut it then made
    inverted the finding — see _snap_head/_snap_tail). Tier 0 is the
    untouched messages. Tier 1 shrinks old ToolMessage content to a
    350/100-char head/tail (_shrink_old_tool_output) — cheap, but still
    carries some of the original tool output's own shape. Tier 2 stubs
    old ToolMessage content out entirely (_stub_old_tool_output), trading
    that remaining detail for letting more old turns survive as bare
    conversational shape instead of being dropped outright. DEPG/memory
    context (_depg_context/_memory_context) is unaffected either way —
    rebuilt fresh from state every think() call, not from this history."""
    budget = (
        context_window
        - response_reserve
        - _estimate_tokens(system_prompt)
        - _estimate_tokens(tool_schema_text)
    )

    def _fit(candidates: list) -> tuple[list, int, int]:
        kept: list = []
        used = 0
        for message in reversed(candidates):
            cost = _message_cost(message)
            if kept and used + cost > budget:
                break
            kept.append(message)
            used += cost
        kept.reverse()
        return kept, len(candidates) - len(kept), used

    def _pressure(dropped: int, used: int) -> bool:
        return dropped > 0 or (budget > 0 and used > budget * _PROACTIVE_COMPACTION_THRESHOLD)

    kept, dropped, used = _fit(messages)
    if _pressure(dropped, used):
        shrunk_kept, shrunk_dropped, shrunk_used = _fit(_shrink_old_tool_output(messages))
        if shrunk_dropped < dropped or shrunk_used < used:
            kept, dropped, used = shrunk_kept, shrunk_dropped, shrunk_used
    if _pressure(dropped, used):
        stubbed_kept, stubbed_dropped, stubbed_used = _fit(_stub_old_tool_output(messages))
        if stubbed_dropped < dropped or stubbed_used < used:
            kept, dropped, used = stubbed_kept, stubbed_dropped, stubbed_used
    # Not a prepended SystemMessage here (as this used to do): that put a
    # second system-role message ahead of the real history, one slot after
    # the real leading SystemMessage think() builds -- the exact shape
    # test_think_retry_keeps_exactly_one_leading_system_message's own fix
    # was written to prevent, just via a different code path. Confirmed
    # live 2026-10-18: this one crashed the chat template the same way
    # ("Jinja Exception: System message must be at the beginning") the
    # moment a real engagement first dropped any history. The caller folds
    # this count into its own single leading SystemMessage instead.
    return kept, dropped


#: 2026-10-18, live: the chars/N estimate above undercounted badly enough
#: on real, markdown-heavy output that actual usage (TokenDelta's
#: ctx_used, the real API-reported count) swung between ~6k and ~14k
#: tokens turn to turn on a 16384-token model -- compaction reacting a
#: full turn late each time, since a turn's own output isn't counted
#: until the NEXT turn's budget check. One real token_counter call (when
#: available) catches an overshoot before this turn's prompt is sent,
#: not after.
#: 2026-10-19, live: a real "Context size has been exceeded" crash from
#: the server, mid-engagement, under heavy concurrent load -- the probe
#: itself (count_tokens_llamacpp's 5s /tokenize call) timed out, returned
#: None, and this function's old contract ("counter failed -> no-op")
#: passed the already-known-unreliable chars/N estimate through with zero
#: safety margin, at exactly the moment concurrent load makes that
#: estimate most likely to have drifted. A shrink this function can't
#: verify is still better than trusting an estimate it just watched fail
#: to confirm.
_PROBE_FAILURE_SAFETY_MARGIN = 0.85


async def _verify_real_token_budget(
    kept: list,
    dropped: int,
    messages: list,
    system_prompt: str,
    context_window: int,
    token_counter: Callable[[str], Awaitable[int | None]] | None,
    tool_schema_text: str = "",
    response_reserve: int = _RESPONSE_RESERVE_TOKENS,
) -> tuple[list, int]:
    if token_counter is None:
        return kept, dropped
    budget = context_window - response_reserve
    full_text = system_prompt + tool_schema_text + "".join(str(m.content) for m in kept)
    real_tokens = await token_counter(full_text)
    if real_tokens is None:
        safe_window = int(context_window * _PROBE_FAILURE_SAFETY_MARGIN)
        return _compact_history(
            messages, system_prompt, safe_window, tool_schema_text, response_reserve
        )
    if real_tokens <= budget:
        return kept, dropped
    # The chars/N estimate was too optimistic for this prompt specifically
    # -- scale the window down by exactly how wrong it was and recompact
    # with the same tiers, rather than guessing at a fixed penalty. One
    # corrective pass, not a retry loop: bounded cost, and a second real
    # call would almost always just confirm the first.
    overshoot_ratio = real_tokens / max(budget, 1)
    corrected_window = max(int(context_window / overshoot_ratio) - 1, 0)
    return _compact_history(
        messages, system_prompt, corrected_window, tool_schema_text, response_reserve
    )


_DEPG_CONTEXT_CAP_PER_TARGET = 8
_DEPG_CONTEXT_MAX_TARGETS = 12
_MEMORY_CONTEXT_CAP = 10


def _display_signal(n: Node) -> str:
    """``n.signal`` for most nodes, but GenericExtractor's blind fallback
    (Evidence.source == "unverified") sets signal to a content hash --
    unique for dedup, but unreadable. Its own evidence.exit_signal is
    already a short text excerpt of the same content (_summarize,
    extract.py) for exactly this case; prefer that one instead, without
    touching the hash that node identity/dedup still relies on."""
    if n.evidence and n.evidence[-1].source == "unverified":
        return n.evidence[-1].exit_signal or n.signal or n.id
    return n.signal or n.id


def _depg_context(depg_nodes: dict) -> str:
    """Per-target findings summary, rebuilt fresh every think() call from
    DEPG state so it survives _compact_history dropping the turns a finding
    came from. Targets and nodes are capped and unresolved-first sorted so
    a big multi-host run can't grow this unboundedly or bury a live finding."""
    if not depg_nodes:
        return ""
    by_target: dict[str, list] = {}
    for node in depg_nodes.values():
        by_target.setdefault(node.target, []).append(node)
    for nodes in by_target.values():
        nodes.sort(key=lambda n: n.state == "resolved")  # unresolved/contested first
    targets = sorted(
        by_target,
        key=lambda t: (
            -sum(1 for n in by_target[t] if n.state != "resolved"),
            -len(by_target[t]),
            t,
        ),
    )
    lines = ["Findings so far, by target (from the dependency graph, not the chat above):"]
    for target in targets[:_DEPG_CONTEXT_MAX_TARGETS]:
        nodes = by_target[target]
        shown = nodes[:_DEPG_CONTEXT_CAP_PER_TARGET]
        parts = [f"{n.cause_class}:{_display_signal(n)} ({n.state})" for n in shown]
        if len(nodes) > len(shown):
            parts.append(f"+{len(nodes) - len(shown)} more")
        lines.append(f"  {target}: {', '.join(parts)}")
    if len(targets) > _DEPG_CONTEXT_MAX_TARGETS:
        lines.append(f"  +{len(targets) - _DEPG_CONTEXT_MAX_TARGETS} more target(s)")
    return "\n".join(lines)


def _memory_context(memory_items: dict, screen=None) -> str:
    """Narrative memory only -- DEPG-derived items (source_type="depg_node")
    are already in _depg_context, so skip them here. `screen`, when given,
    runs over a tool-failure snippet first since that's raw target-controlled
    output needing the same injection screening a ToolMessage gets."""
    items = [m for m in memory_items.values() if m.source_type != "depg_node"]
    if not items:
        return ""
    tier_order = {"T1": 0, "T2": 1, "T3": 2}
    items.sort(key=lambda m: (tier_order.get(m.tier, 3), -m.hits))
    shown = items[:_MEMORY_CONTEXT_CAP]
    lines = ["Retained memory (most important first):"]
    for m in shown:
        snippet = screen(m.snippet) if screen and m.source_type == "tool-failure" else m.snippet
        lines.append(f"  [{m.tier}] {snippet}")
    if len(items) > len(shown):
        lines.append(f"  +{len(items) - len(shown)} more")
    return "\n".join(lines)

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
    """Whether this phase's objective has real DEPG evidence behind it, not
    just "some tool call exited zero". Looks at this phase's own resolved
    nodes (Node.phase, set in depg_update, which always runs first). RECON
    and EXPLOITATION gate on their one deterministic cause_class (open-port,
    credential-found); other phases accept any resolved node, since their
    extraction is free-text LLM output with no fixed vocabulary to match."""
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

#: 2026-10-17, live: replacing this with a concrete IP (10.0.0.5) instead
#: of an abstract <tool>/<target> placeholder wasn't enough — the model
#: parroted *that* literal example value into a real nmap call instead of
#: the actual configured target (caught by ScopeGuardStage, since
#: 10.0.0.5 was outside the declared scope, but still a real miss). The
#: real fix: make the example's target the actual one from target_line
#: above, so parroting it is harmless — it's already the right value.
def _fallback_hint(target: str | None) -> str:
    example_target = target or "10.0.0.5"
    return (
        "\n\nIf you can't make a structured tool call, end your reply with a "
        f'line starting with {_TOOL_CALL_MARKER} followed by a JSON object '
        f'like {{"name": "nmap", "args": {{"target": "{example_target}"}}}}.'
    )

#: Live-test fix: an open-ended instruction made a small local model write
#: several planned calls as prose, or re-ask for a target already given.
_ONE_CALL_RULE = (
    "Make exactly one tool call per turn, using the tool-calling mechanism "
    "— never write out a list of several planned calls as text or JSON. "
    "Decide the next single call, see its result, then decide the one "
    "after that."
)

#: Live-test fix: a bare "HI" triggered an unprompted nmap->whatweb->nikto
#: chain, because every phase prompt is a standing order with nothing
#: conditioning it on the user actually asking. Prepended once for all phases.
_ACT_ONLY_WHEN_ASKED = (
    "Only call a tool when the user's current message actually calls for "
    "it — a new scan, a continuation of testing already underway, or an "
    "explicit request. A greeting, small talk, a plain acknowledgment "
    '(e.g. "ok", "noted", "got it", "thanks"), or a question about status '
    "or findings is not a request to act: answer in plain text instead. "
    "Having a target configured and tools available is not, by itself, a "
    "reason to call one."
)

#: Appended only for the one bounded retry below, never part of the
#: standing system prompt otherwise — a last-resort nudge, not a rule the
#: model should see every turn.
_RETRY_NUDGE = (
    "You did not make a tool call just now, on the opening move of a turn "
    "that calls for one. Make exactly one tool call now, using the "
    "tool-calling mechanism, with the real target value already given "
    "above — do not write text instead."
)

#: 2026-10-12, live (BACKLOG.md §7): the model's opening move sometimes
#: answers with a clarifying question ("please provide the target host")
#: instead of calling a tool, even though target_line above already gave
#: it the real value — non-deterministic, same prompt/model/target.
#: Narrow on purpose: must not match a legitimate text reply (e.g. a
#: greeting under _ACT_ONLY_WHEN_ASKED), which never asks for the target.
_ASKING_FOR_TARGET_RE = re.compile(
    r"\b(provide|supply|confirm|specify|give me|let me know)\b[^.?!]{0,60}"
    r"\b(target|host|ip\s*address|ip)\b",
    re.IGNORECASE,
)


def _is_asking_for_known_target(text: str, target: str | None) -> bool:
    """True if the response is asking for the target when it's already
    been given (target_line above) — the retryable half of the bug this
    exists for. Gated on target being set so this can't fire when there
    genuinely isn't one yet."""
    return bool(target) and bool(_ASKING_FOR_TARGET_RE.search(text))


def _already_has_a_tool_result_this_turn(messages: list) -> bool:
    """True once this turn has produced a real tool result — only the
    opening move is eligible for think()'s empty-response retry below; a
    later step concluding with text is a genuine final answer, never retried."""
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            return False
        if isinstance(message, ToolMessage):
            return True
    return False


def _last_human_text(messages: list) -> str | None:
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            return str(message.content)
    return None


#: Appended only for the one bounded retry below (a later think() step that
#: narrated an action but never attached the tool call for it), never part
#: of the standing system prompt otherwise.
_FOLLOW_THROUGH_NUDGE = (
    "You described your next action in text just now but did not actually "
    "make the tool call for it. Either make that exact tool call now, using "
    "the tool-calling mechanism, or if you are genuinely done, give your "
    "complete final answer instead — do not just describe what you were "
    "about to do."
)

#: 2026-10-17, live (new local model, reasoning-tuned, 3-bit quant): a
#: *later* think() step (already past the opening move, mid tool-chain)
#: sometimes narrates its next move instead of attaching the tool call for
#: it -- "Let me run nikto again..." becomes the entire turn's visible
#: answer once routing sees no tool_calls and ends the turn. Checked only
#: against the trailing sentence, not the whole message: a genuine final
#: answer may legitimately close with an unrelated clause (e.g. "...let me
#: know if you'd like to go further") that must not trip this. "let me
#: know" itself never matches -- "know" isn't one of the gated verbs.
_ANNOUNCED_ACTION_RE = re.compile(
    r"\b(?:let me|let's|i'll|i will)\b[^.!?]{0,40}?"
    r"\b(run|check|try|test|use|attempt|fetch|scan|enumerate|probe|brute[- ]?force)\b",
    re.IGNORECASE,
)


def _is_announcing_an_unexecuted_action(text: str) -> bool:
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    last = sentences[-1] if sentences else ""
    return bool(_ANNOUNCED_ACTION_RE.search(last))


#: 2026-10-14, live (BACKLOG.md §10): a plain acknowledgment ("ok, noted")
#: triggered an unprompted nikto call. 2026-10-17, live: broadening
#: _ACT_ONLY_WHEN_ASKED's wording to explicitly name this phrasing was NOT
#: enough -- re-tested mid-engagement (an active DEPG finding already on
#: the board) and the model still called tools 3/3 times, apparently
#: reading the standing phase order ("start with nmap...") and the fresh
#: findings context below it as permission to continue, despite the rule
#: above both saying not to. A wording-only fix can't out-compete that
#: pull reliably on a small model. Exact-match on purpose, not a substring
#: scan: "ok, run nikto" must never match this, only a message that is
#: *entirely* a closing acknowledgment does.
_PLAIN_ACKNOWLEDGMENTS = frozenset({
    "ok", "okay", "k", "kk", "noted", "ok, noted", "ok noted",
    "got it", "gotcha", "thanks", "thank you", "thanks a lot",
    "sure", "alright", "all right", "sounds good", "no problem",
    "roger", "understood", "cool", "great", "nice", "ack",
})


def _is_plain_acknowledgment(text: str) -> bool:
    normalized = text.strip().lower().rstrip(".!")
    return normalized in _PLAIN_ACKNOWLEDGMENTS


#: 2026-10-17, live (round 12): binding zero tools on a plain-acknowledgment
#: turn correctly stops the call from executing, but the model still tries
#: to *write* one in whatever native tool-call syntax it was trained on
#: (e.g. "<|tool_call_start|>[curl(...)]<|tool_call_end|>") since nothing
#: told it tool-calling itself is off the table this turn -- that raw,
#: broken-looking text then becomes the turn's entire visible narration.
#: Placed at the very end of the system prompt, after the phase's own
#: standing order, not up near _ACT_ONLY_WHEN_ASKED -- the same ordering
#: lesson that motivated the structural fix above: on a small model, later
#: text in the prompt outweighs earlier text.
_ACK_NO_TOOLS_NOTE = (
    "No tools are available to you on this turn. Reply with a brief "
    "plain-text acknowledgment only -- do not write a tool call in any "
    "form (JSON, a TOOL_CALL: line, <|tool_call_start|>, or similar), "
    "since nothing will execute it and it will only show up as broken "
    "text."
)


async def _stream_response(
    bound: BaseChatModel, messages: list, *, retriable: bool = False
) -> AIMessage:
    """One model call, accumulated from its stream. ``retriable`` tags
    this attempt's streamed chunks (via run config metadata) so core.py's
    _run() can retract them from the live transcript/token count if
    think() goes on to discard this attempt and retry — see core.py's
    ``retriable`` tracking in _run()."""
    config = {"metadata": {"cism_retriable": True}} if retriable else None
    response = None
    async for chunk in bound.astream(messages, config=config):
        response = chunk if response is None else response + chunk
    if response is None:
        # A provider that errors or returns nothing leaves zero chunks;
        # an empty answer is a better default than a later crash on None.
        return AIMessage(content="")
    return response


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
    text instead — see _fallback_hint. None if nothing usable is found."""
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
    token_counter: Callable[[str], Awaitable[int | None]] | None = None,
) -> Callable[[AgentState], dict]:
    # C1 (AUDIT.md): screened here, at prompt-build time, not on act()'s
    # ToolMessage — depg_update and the audit log still need the raw output.
    screen = tool_output_chain or GuardrailChain([])

    async def think(state: AgentState) -> dict:
        profile = profiles.get(state["phase"])
        # tool_help is exempt from phase gating — knowing what a tool does carries
        # none of the risk that using it does, so it's always offered when present.
        names = {name for name in profile.tool_names if name in tools}
        if "tool_help" in tools:
            names.add("tool_help")
        phase_tools = [tools.get(name) for name in names]
        # Structural, not prompt-only: a plain acknowledgment gets no tools
        # bound at all, so neither the native tool-calling path nor the
        # _parse_text_tool_call text fallback below can produce a call this
        # turn, regardless of what the standing phase order or fresh DEPG
        # findings context might otherwise pull the model toward.
        is_plain_ack = bool(phase_tools) and _is_plain_acknowledgment(
            _last_human_text(state["messages"]) or ""
        )
        if is_plain_ack:
            phase_tools = []
        bound = _bind_tools_if_supported(llm, phase_tools)
        # Prepended for this invocation only, never appended to state —
        # profile.system_prompt is phase-only and never names the target.
        target_line = (
            f"Target: {state['target']} — already decided for this run; use it "
            "directly in tool calls. Never ask the user to confirm or supply it."
            if state["target"]
            else "No target configured yet."
        )
        act_rule = f"\n\n{_ACT_ONLY_WHEN_ASKED}" if phase_tools else ""

        def _for_model(text: str) -> str:
            screened = screen.run(text).value
            return privacy.anonymize(screened) if privacy is not None else screened

        context_summary = "\n\n".join(
            part for part in (
                _depg_context(state["depg_nodes"]),
                _memory_context(state["memory_items"], screen=_for_model),
            ) if part
        )
        context_block = f"\n\n{context_summary}" if context_summary else ""
        rules = f"\n\n{_ONE_CALL_RULE}" if phase_tools else ""
        hint = _fallback_hint(state["target"]) if phase_tools else ""
        ack_note = f"\n\n{_ACK_NO_TOOLS_NOTE}" if is_plain_ack else ""
        system_prompt = (
            f"{target_line}{act_rule}{context_block}\n\n{profile.system_prompt}"
            f"{rules}{hint}{ack_note}"
        )
        context_window = state.get("context_window") or DEFAULT_CONTEXT_WINDOW
        tool_schema_text = _tool_schema_text(phase_tools)
        response_reserve = _response_reserve(llm)
        history, dropped = _compact_history(
            state["messages"], system_prompt, context_window, tool_schema_text,
            response_reserve,
        )
        history, dropped = await _verify_real_token_budget(
            history, dropped, state["messages"], system_prompt, context_window,
            token_counter, tool_schema_text, response_reserve,
        )
        history = [
            m.model_copy(update={"content": _for_model(str(m.content))})
            if isinstance(m, ToolMessage) else m
            for m in history
        ]
        if privacy is not None:
            system_prompt = privacy.anonymize(system_prompt)
        if dropped:
            system_prompt = (
                f"{system_prompt}\n\n"
                f"[{dropped} earlier turn(s) omitted to fit the context window]"
            )
        messages = [SystemMessage(content=system_prompt), *history]
        # The opening move gets its own retry trigger below
        # (_is_asking_for_known_target / truly empty). A later step gets a
        # narrower one (_is_announcing_an_unexecuted_action) — most later
        # steps legitimately conclude with text (a genuine final answer
        # after real tool use) and must never be retried, only the specific
        # narrated-but-unexecuted-action shape does. Either way, marking the
        # attempt retriable is harmless when no retry ends up happening —
        # core.py's retraction only fires if a second "think" attempt
        # actually streams.
        is_opening_move = bool(phase_tools) and not _already_has_a_tool_result_this_turn(
            state["messages"]
        )
        is_later_tool_step = bool(phase_tools) and not is_opening_move
        response = await _stream_response(bound, messages, retriable=bool(phase_tools))
        if phase_tools and not response.tool_calls:
            # Weak models often describe the call in prose; recover it from text.
            parsed = _parse_text_tool_call(str(response.content))
            if parsed is not None:
                response = response.model_copy(update={"tool_calls": [parsed]})
        # Retried cases: a truly empty attempt (no tool call AND no text),
        # or one that asks for the target when it's already been given
        # (_is_asking_for_known_target) — both are the model declining to
        # act when it should have. A *different* deliberate text answer
        # (e.g. _ACT_ONLY_WHEN_ASKED on a greeting) must stand as-is, never
        # retried. Any live-streamed text/tokens from the discarded attempt
        # are retracted by core.py's _run() (tagged via retriable= above) —
        # an empty attempt streamed nothing, so there's nothing to retract.
        content = str(response.content)
        should_retry_opening_move = is_opening_move and not response.tool_calls and (
            not content.strip() or _is_asking_for_known_target(content, state["target"])
        )
        should_retry_later_step = (
            is_later_tool_step
            and not response.tool_calls
            and _is_announcing_an_unexecuted_action(content)
        )
        if should_retry_opening_move or should_retry_later_step:
            # 2026-10-17, live (new local model): appending a *second*
            # SystemMessage at the end of the list, as this used to do,
            # crashes this model's chat template outright ("Jinja
            # Exception: System message must be at the beginning") --
            # latent since the very first version of this retry, just
            # never triggered until a later-step retry made this path
            # fire often enough to hit it. Folding the nudge into the
            # one leading SystemMessage keeps exactly one, first, always.
            nudge = _RETRY_NUDGE if should_retry_opening_move else _FOLLOW_THROUGH_NUDGE
            leading_system = messages[0].model_copy(
                update={"content": f"{messages[0].content}\n\n{nudge}"}
            )
            retry_messages = [leading_system, *messages[1:]]
            response = await _stream_response(bound, retry_messages)
            if phase_tools and not response.tool_calls:
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
    checkpoint = state.get("phase_proposal_is_new") and state.get("live_tools")
    if tool_calls and ai_turns < MAX_AI_TURNS and not checkpoint:
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
                # Most stages' reasons must stay hidden from the model (see
                # test_act_reports_a_blocked_call_with_a_generic_message_
                # not_the_rich_reason — an adversarial/injected model must
                # not get a live oracle for scope/dangerous-flags rules).
                # phase-tool-guard is categorically different: which tools
                # are offered when isn't secret (the model already sees the
                # bound-tools list every turn), and BACKLOG.md §7 found the
                # model silently giving up instead of telling the operator
                # why a requested tool (e.g. sqlmap pre-enumeration) was
                # unavailable — so this one stage's real reason is safe,
                # and useful, to surface.
                content = (
                    guard.reason
                    if guard.stage == "phase-tool-guard" and guard.reason
                    else "blocked by action guardrail"
                )
                results.append(
                    ToolMessage(
                        content=content,
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
    """A finding belongs to the target *that call* used, never the session
    default — a multi-host engagement would otherwise merge every host's
    findings onto one node family. Falls back to the default only for a
    call with no target argument of its own (e.g. tool_help)."""
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
        # Fallback only — see _call_target for why this must not be used
        # for every call in a multi-host engagement.
        default_target = normalize_target(state["target"])

        for call, message in _trailing_tool_results(state["messages"]):
            extractor = extractors.get(message.name or "")
            target = _call_target(call, default_target)
            # to_thread: extraction can block ~20s on an LLM call. Stays
            # sequential — find_precondition needs each call's nodes
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
        """Detects phase readiness but no longer applies the move itself
        (2026-10-18: operator wants to approve a transition before it
        takes effect, not find out after). Proposes once via
        phase_proposal, then holds — /phase <name> (core.py's _set_phase)
        is the only thing that actually commits it, through the same
        PhaseStateMachine legality check a manual move always used."""
        current = state["phase"]
        if state.get("phase_proposal"):
            # Already proposed and not yet approved — nothing to do until
            # the operator acts; re-detecting readiness here would just
            # notice the same thing again every turn.
            return {"phase": current, "phase_proposal_is_new": False}

        target = _FORWARD_PHASE[current]
        if target != current and _phase_ready(current, state["depg_nodes"]):
            machine = PhaseStateMachine(current=current)
            try:
                machine.transition(target)
            except IllegalPhaseTransition:
                pass  # not actually legal despite _FORWARD_PHASE; stay put
            else:
                return {
                    "phase": current,
                    "phase_proposal": target.to_wire(),
                    "phase_proposal_is_new": True,
                }

        return {"phase": current, "phase_proposal_is_new": False}

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

        if state.get("phase_proposal_is_new"):
            proposal = state.get("phase_proposal") or "?"
            snippet = f"phase proposal -> {proposal} (pending /phase approval)"
            store.upsert(
                memory_key("phase-proposal", phase_tag, snippet),
                "T2", phase_tag, snippet, source_type="phase-proposal",
            )

        return {"memory_items": store.items}

    return memory_update


#: 2026-10-17, live (round 12): the _ACK_NO_TOOLS_NOTE above cuts how
#: often this happens but doesn't eliminate it -- a small model
#: occasionally still writes its own native tool-call template syntax as
#: plain text (e.g. "<|tool_call_start|>[curl(...)]<|tool_call_end|>")
#: when no tools are bound to actually consume it, and that becomes the
#: turn's entire visible answer. Nothing executes it either way (no tools
#: bound means no structured call is ever produced from it), so this is
#: purely a display problem: strip the leaked span rather than show it
#: verbatim. Generic, not ack-mode-specific -- this syntax is never
#: legitimate content regardless of which turn produced it.
_LEAKED_TOOL_CALL_RE = re.compile(r"<\|tool_call_start\|>.*?<\|tool_call_end\|>", re.DOTALL)


#: 2026-10-17, live (round 12, §11): a status question ("what have we
#: found so far?") once got a genuinely empty final answer -- no tool
#: call, no text, not even a leaked tool-call fragment -- documented at
#: the time as accepted "real reasoning-model flakiness" (think()'s
#: single opening-move retry can still come back empty a second time).
#: Reusing _strip_leaked_tool_call_syntax's "stripped to nothing ->
#: substitute something" mechanism for this case too, but "Noted." is
#: the wrong substitute here: it reads as acknowledging a statement, not
#: answering a question that got silently dropped.
_NOTHING_TO_ADD = "I don't have anything further to add right now."


def _strip_leaked_tool_call_syntax(text: str) -> str:
    stripped = _LEAKED_TOOL_CALL_RE.sub("", text).strip()
    if stripped:
        return stripped
    return "Noted." if _LEAKED_TOOL_CALL_RE.search(text) else _NOTHING_TO_ADD


#: 2026-10-17, live (new local model, longer per-step investigations): the
#: only way route_after_think ever sends a message with tool_calls still
#: attached into respond() is the MAX_AI_TURNS cap tripping -- the other
#: route into respond() (no tool_calls at all) never reaches this branch.
#: Before this, that message's lead-in prose ("Let me test the injection
#: directly...") was shown verbatim as if it were a deliberate final
#: answer, with the pending call silently discarded. Named honestly
#: instead of pretending the investigation concluded.
_STEP_LIMIT_NOTE = (
    "(Reached this turn's investigation-step limit before finishing -- the "
    "next planned step ({tools}) did not run. Ask me to continue and I'll "
    "pick up from here.)"
)

#: 2026-10-18, live: route_after_think now also stops on a phase change
#: (not just the MAX_AI_TURNS cap) so a fast-moving engagement checkpoints
#: with the operator instead of racing through several phases unsupervised
#: in one submit() -- confirmed live doing exactly that (recon through
#: exploitation in one turn, then an unbounded reasoning burst). Distinct
#: wording from _STEP_LIMIT_NOTE since the reason is different (forward
#: progress, not a stall).
#: 2026-10-18, later same day: reworded from "just moved" to "ready to
#: move" -- phase_router no longer applies the transition on its own, it
#: only proposes one (phase_proposal); the operator has to run /phase
#: <name> themselves for it to actually take effect.
_PHASE_CHECKPOINT_NOTE = (
    "(Checkpoint: the engagement looks ready to move into the {phase} "
    "phase, so I'm pausing here before continuing -- the next planned "
    "step ({tools}) hasn't run yet. Run /phase {phase} to confirm the "
    "move, or just tell me how you'd like to proceed to stay put.)"
)

#: Cap on how many findings make it into the checkpoint summary below --
#: a long engagement's full depg_nodes could otherwise make every
#: checkpoint message balloon with repeated nikto-finding entries.
_MAX_SUMMARY_FINDINGS = 12


def _format_findings_summary(depg_nodes: dict[str, Node]) -> str:
    """A short, human-readable digest of what's been confirmed so far, for
    the checkpoint messages below. Only "resolved" nodes -- untested/
    disproven ones aren't findings yet."""
    resolved = [n for n in depg_nodes.values() if n.state == "resolved"]
    if not resolved:
        return ""
    resolved.sort(key=lambda n: -n.generality)
    lines = ["Findings so far:"]
    lines.extend(f"- [{n.cause_class}] {n.signal}" for n in resolved[:_MAX_SUMMARY_FINDINGS])
    omitted = len(resolved) - _MAX_SUMMARY_FINDINGS
    if omitted > 0:
        lines.append(f"...({omitted} more finding(s) not shown)")
    return "\n".join(lines)


def make_respond_node(output_chain: GuardrailChain) -> Callable[[AgentState], dict]:
    def respond(state: AgentState) -> dict:
        """Always returns an explicit message, even when the guardrail
        passes content through unchanged — so core.py never narrates a
        "think" message before the output guardrail has seen it."""
        last = state["messages"][-1]
        if last.tool_calls:
            tools_pending = ", ".join(
                sorted({str(call.get("name", "?")) for call in last.tool_calls})
            )
            if state.get("phase_proposal_is_new"):
                note = _PHASE_CHECKPOINT_NOTE.format(
                    phase=state.get("phase_proposal") or "next",
                    tools=tools_pending,
                )
            else:
                note = _STEP_LIMIT_NOTE.format(tools=tools_pending)
            summary = _format_findings_summary(state.get("depg_nodes") or {})
            lead_in = _LEAKED_TOOL_CALL_RE.sub("", str(last.content)).strip()
            parts = [note]
            if summary:
                parts.append(summary)
            if lead_in:
                parts.append(lead_in)
            content = "\n\n".join(parts)
        else:
            content = _strip_leaked_tool_call_syntax(str(last.content))
        result = output_chain.run(content)
        text = (
            result.value
            if result.allowed
            else f"[response withheld by output guardrail: {result.reason or 'no reason given'}]"
        )
        return {"messages": [AIMessage(content=text)]}

    return respond
