"""LangGraphAgent: satisfies cism.tui.events.Agent by translating
LangGraph's step loop into AgentEvent dataclasses pushed onto
self.events. Nothing here touches a widget."""

from __future__ import annotations

import asyncio
import dataclasses
import os
import time
import uuid
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_core.messages.tool import ToolCall
from langgraph.checkpoint.memory import MemorySaver

from cism.agent.graph import build_graph
from cism.agent.guardrails import (
    GuardrailChain,
    GuardrailSeam,
    PrivacyGateway,
    ScopeGuardStage,
    parse_scope,
)
from cism.agent.llm import (
    DummyChatModel,
    build_chat_model,
    discover_context_window,
    discover_context_window_llamacpp,
)
from cism.agent.logging import get_agent_logger, read_run_events
from cism.agent.profiles import PhaseProfiles, default_profiles
from cism.agent.state import IllegalPhaseTransition, Phase, PhaseStateMachine
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap
from cism.depg import (
    EXTRACTORS,
    CauseExtractor,
    ChatModelExtractionBackend,
    ExtractorRegistry,
    GenericExtractor,
    LLMExtractor,
    NmapExtractor,
)
from cism.memory import DEFAULT_SALIENCE_TERMS
from cism.tui.events import (
    AgentEvent,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Interrupted,
    MemoryUpdated,
    ModelInfo,
    Narration,
    NarrationRedacted,
    PhaseChanged,
    RunFinished,
    RunStarted,
    ScopeChanged,
    SessionState,
    TokenDelta,
    ToolFailed,
    ToolFinished,
    ToolStarted,
    decode,
    encode,
)
from cism.tui.events import _next_seq  # same-package access to the shared seq counter

__all__ = ["LangGraphAgent"]

#: Pacing between /replay events — readable, not the original run's real gaps.
_REPLAY_STEP_DELAY = 0.05

#: dummy_nmap's canned output is real nmap open-port-line format (see
#: cism.agent.tools.dummy), so it extracts the same way a live nmap result
#: would — the offline/dummy path exercises genuine "open-port" evidence
#: instead of a GenericExtractor stand-in, which phase_router's RECON gate
#: (cism.agent.nodes._phase_ready) specifically requires.
_DEFAULT_TOOL_EXTRACTORS: dict[str, CauseExtractor] = {**EXTRACTORS, "dummy_nmap": NmapExtractor()}


def _llm_from_env() -> tuple[BaseChatModel, str, str, str]:
    """Real connector if the environment describes one, Dummy otherwise.
    Never raises: an unconfigured environment is a valid, common case
    (every test in this repo runs in one), not an error."""
    base_url = os.environ.get("CISM_LLM_BASE_URL", "")
    model = os.environ.get("CISM_LLM_MODEL", "")
    key_env_var = os.environ.get("CISM_LLM_KEY_ENV_VAR", "CISM_API_KEY")
    if base_url and model:
        return build_chat_model(base_url, key_env_var, model), base_url, model, key_env_var
    return DummyChatModel(), "local (dummy)", "", ""


class LangGraphAgent:
    """Satisfies ``cism.tui.events.Agent``. All dependencies default to the
    dummy/no-op stubs so the loop can be validated with no lab, no weights,
    and no network; pass real ones in once they exist."""

    def __init__(
        self,
        llm: BaseChatModel | None = None,
        tools: ToolRegistry | None = None,
        guardrails: GuardrailSeam | None = None,
        extractors: ExtractorRegistry | None = None,
        profiles: PhaseProfiles | None = None,
        target: str = "",
        endpoint: str = "",
        model_name: str = "",
        key_env_var: str = "",
        backend: str = "openai",
        graded_propagation: bool = False,
        privacy: PrivacyGateway | None = None,
    ) -> None:
        # E5 (AUDIT.md): bounded so a TUI that falls behind applies real
        # backpressure (both put() call sites below are awaited) instead of
        # this queue growing without limit. 512 is generous for normal
        # per-turn event volume — this is a leak guard, not a throttle meant
        # to bind under ordinary load.
        self.events: asyncio.Queue[AgentEvent] = asyncio.Queue(maxsize=512)
        if llm is None:
            self._llm, self._endpoint, self._model_name, self._key_env_var = _llm_from_env()
        else:
            self._llm = llm
            self._endpoint = endpoint
            self._model_name = model_name
            self._key_env_var = key_env_var
        #: "openai" or "llamacpp" — picks the context-window probe below.
        self._backend_kind = backend
        #: B1 follow-up (2.1): opt-in continuous DEPG propagation — see
        #: cism.depg.reducer.GradedSupport. Off by default; one DVWA pass is
        #: the minimum validation bar per AUDIT.md, not the finish line.
        self._graded_propagation = graded_propagation
        #: Privacy Gateway (5.1) — None means no anonymization, the default.
        self._privacy = privacy
        self._tools = tools or ToolRegistry([dummy_nmap, dummy_msfconsole])
        self._guardrails = guardrails or GuardrailSeam.no_op()
        default_extractor = (
            GenericExtractor()
            if self._endpoint == "local (dummy)"
            else LLMExtractor(ChatModelExtractionBackend(self._llm), logger=get_agent_logger())
        )
        self._extractors = extractors or ExtractorRegistry(_DEFAULT_TOOL_EXTRACTORS, default_extractor)
        self._profiles = profiles or default_profiles(self._tools)
        #: In-process session memory only, not restart-survival. A fixed
        #: thread_id so a graph rebuilt mid-session (/ablate) still shares it.
        self._checkpointer = MemorySaver()
        self._thread_id = uuid.uuid4().hex
        #: True once depg_nodes/depg_edges/memory_items have been seeded —
        #: after that, re-supplying `{}` would wipe checkpointed state (see _run).
        self._thread_seeded = False
        self._graph = build_graph(
            self._llm,
            self._tools,
            self._guardrails,
            self._extractors,
            self._profiles,
            checkpointer=self._checkpointer,
            graded_propagation=self._graded_propagation,
            privacy=self._privacy,
        )
        self._phase = PhaseStateMachine(Phase.RECON)
        self._target = target
        self._task: asyncio.Task[None] | None = None
        self._log = get_agent_logger()
        #: Last DEPGUpdated payload sent, so an unchanged graph doesn't re-emit.
        self._last_depg: tuple[tuple[DEPGNode, ...], tuple[DEPGEdge, ...]] = ((), ())
        #: Running session total; never reset (unlike ctx_used, a snapshot).
        self._token_total = 0
        #: H3: lightweight per-run counters, reset in _run() and logged
        #: alongside RunFinished so a run's health is grep-able from the
        #: JSONL log without reconstructing it from every individual event.
        self._metrics = {"tool_calls": 0, "tool_failures": 0, "guardrail_blocks": 0}
        #: Refreshed by _refresh_context_window(); falls back to StatusBar's default.
        self._context_window = 32_768
        #: Tool/guardrail-stage names to skip for the next _run() only (see _ablate).
        self._ablated: set[str] = set()

    async def _refresh_context_window(self) -> None:
        """Best-effort; a stale value from a prior model is harmless."""
        if self._endpoint == "local (dummy)" or not self._model_name:
            return
        if self._backend_kind == "llamacpp":
            discovered = await discover_context_window_llamacpp(self._endpoint)
        else:
            discovered = await discover_context_window(self._endpoint, self._model_name)
        if discovered:
            self._context_window = discovered

    async def _emit(self, event: AgentEvent) -> None:
        """Every AgentEvent's single exit point: logged to the audit log,
        then queued for the TUI, so the log always matches what the TUI
        saw. Uses events.encode so /replay can decode it straight back."""
        self._log.info(type(event).__name__, extra={"data": encode(event)})
        await self.events.put(event)

    async def start(self) -> None:
        """Emits SessionState before any run. Refreshes the context window
        first so it's accurate from the start, not corrected later."""
        await self._refresh_context_window()
        await self._emit(self._session())

    def _session(self) -> SessionState:
        return SessionState(
            model=self._model_name or "dummy",
            models_available=(
                (ModelInfo(self._model_name, context=self._context_window, loaded=True),)
                if self._model_name
                else ()
            ),
            endpoint=self._endpoint,
            key_env_var=self._key_env_var,
            key_present=bool(os.environ.get(self._key_env_var)) if self._key_env_var else False,
        )

    async def submit(self, text: str) -> None:
        """Schedules a task and returns immediately (Agent protocol: must
        not block); a new submission cancels one in flight. Most slash
        commands are answered directly; /replay runs as a real task since
        it plays back over time and should be cancellable the same way."""
        if text.startswith("/"):
            name, _, argument = text[1:].partition(" ")
            if name in ("api", "model"):
                await self._configure(name, argument.strip())
                return
            if name == "target":
                await self._set_target(argument.strip())
                return
            if name == "phase":
                await self._set_phase(argument.strip())
                return
            if name == "scope":
                await self._set_scope(argument.strip())
                return
            if name == "ablate":
                await self._ablate(argument.strip())
                return
            if name == "replay":
                if self._task is not None and not self._task.done():
                    self._task.cancel()
                self._task = asyncio.create_task(self._replay(argument.strip()))
                return
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = asyncio.create_task(self._run(text))

    async def _set_target(self, argument: str) -> None:
        """Bare /target reports the value; /target <value> replaces it —
        takes effect next submit(), not an already-running one."""
        if argument:
            self._target = argument
        await self._emit(
            Narration(
                entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                text=f"target  {self._target or '(none)'}",
                done=True,
            )
        )

    async def _set_phase(self, argument: str) -> None:
        """Bare /phase reports the current phase; /phase <name> goes
        through PhaseStateMachine.transition, same as phase_router, so a
        manual move follows the same legality rules as an automatic one."""
        if not argument:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=f"phase  {self._phase.current.to_wire()}",
                    done=True,
                )
            )
            return
        try:
            requested = Phase[argument.upper().replace("-", "_")]
        except KeyError:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=f"unknown phase {argument!r}",
                    done=True,
                )
            )
            return
        try:
            self._phase.transition(requested)
        except IllegalPhaseTransition as exc:
            await self._emit(
                Narration(entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=str(exc), done=True)
            )
            return
        await self._emit(PhaseChanged(phase=requested.to_wire()))

    def _scope_guard(self) -> ScopeGuardStage | None:
        """The live ScopeGuardStage, if --live-tools wired one; None under
        the default no-op guardrails."""
        for stage in self._guardrails.action.stages:
            if isinstance(stage, ScopeGuardStage):
                return stage
        return None

    async def _set_scope(self, argument: str) -> None:
        """Bare /scope lists current scope; add/remove mutate the live
        ScopeGuardStage in place — the only way to change scope without
        restarting. Each real change emits ScopeChanged; everything else
        (listing, no-ops, errors) is a plain Narration."""
        guard = self._scope_guard()
        if guard is None:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text="/scope requires --live-tools (no ScopeGuardStage is active)",
                    done=True,
                )
            )
            return

        subcommand, _, rest = argument.partition(" ")
        rest = rest.strip()

        if not argument:
            listing = ", ".join(guard.scope.entries()) or (
                "(empty — every live-tool call will be blocked)"
            )
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=f"scope  {listing}", done=True
                )
            )
            return

        if subcommand == "add":
            if not rest:
                await self._emit(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                        text="/scope add requires a target (CIDR or domain)",
                        done=True,
                    )
                )
                return
            addition = parse_scope(rest)
            if not addition.cidrs and not addition.domains:
                await self._emit(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                        text=f"{rest!r} is not a usable CIDR or domain",
                        done=True,
                    )
                )
                return
            already = set(guard.scope.entries())
            guard.expand(addition)
            new_tokens = [token for token in addition.entries() if token not in already]
            if not new_tokens:
                await self._emit(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                        text=f"{rest!r} already in scope — no changes made",
                        done=True,
                    )
                )
                return
            for token in new_tokens:
                await self._emit(ScopeChanged(action="add", target=token))
            return

        if subcommand == "remove":
            if not rest:
                await self._emit(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                        text="/scope remove requires a target",
                        done=True,
                    )
                )
                return
            for token in (t.strip() for t in rest.split(",") if t.strip()):
                if guard.contract(token):
                    await self._emit(ScopeChanged(action="remove", target=token))
                else:
                    await self._emit(
                        Narration(
                            entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                            text=f"{token!r} is not currently in scope",
                            done=True,
                        )
                    )
            return

        await self._emit(
            Narration(
                entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                text=f"unknown /scope subcommand {subcommand!r} — use add, remove, or no argument to list",
                done=True,
            )
        )

    async def _ablate(self, argument: str) -> None:
        """Bare /ablate reports what's pending; /ablate <name> toggles a
        tool or guardrail-stage name for the next run only — toggling
        again clears it, so there's no separate "clear" command."""
        if not argument:
            listing = ", ".join(sorted(self._ablated)) or "(none)"
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=f"ablated  {listing}", done=True
                )
            )
            return

        known_tools = {t.name for t in self._tools.all()}
        known_stages = {
            stage.name
            for chain in (self._guardrails.input, self._guardrails.action, self._guardrails.output)
            for stage in chain.stages
        } | {
            # PhaseToolGuardStage et al. live per-phase in self._profiles, not
            # in guardrails.action — without this they're invisible to /ablate.
            stage.name
            for phase in self._profiles.phases()
            for stage in self._profiles.get(phase).action_stages
        }
        if argument not in known_tools and argument not in known_stages:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=f"no such tool or guardrail stage: {argument!r}",
                    done=True,
                )
            )
            return

        if argument in self._ablated:
            self._ablated.discard(argument)
            verb = "restored"
        else:
            self._ablated.add(argument)
            verb = "ablated — takes effect on the next run only"
        await self._emit(
            Narration(entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=f"{argument}  {verb}", done=True)
        )

    async def _replay(self, run_id: str) -> None:
        """Replays a past run's recorded events from the audit log — no
        tool or model call happens. seq is rebased to this session's
        counter; ts stays historical. Re-asserts the real current phase at
        the end in case the replayed run shows a different one."""
        if not run_id:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text="usage: /replay <run_id>", done=True
                )
            )
            return

        records = read_run_events(run_id)
        if not records:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=f"no recorded run found for {run_id!r}",
                    done=True,
                )
            )
            return

        replay_id = f"replay-{run_id}"
        await self._emit(
            Narration(entry_id=f"{replay_id}-start", text=f"— replaying run {run_id} —", done=True)
        )
        for record in records:
            # Fresh _next_seq() per event, not rebase() — rebase only reserves one value.
            event = dataclasses.replace(decode(record["data"]), seq=_next_seq())
            await self.events.put(event)
            await asyncio.sleep(_REPLAY_STEP_DELAY)
        await self._emit(
            Narration(entry_id=f"{replay_id}-end", text="— end replay —", done=True)
        )
        await self._emit(PhaseChanged(phase=self._phase.current.to_wire()))

    async def _configure(self, name: str, argument: str) -> None:
        if argument and not self._key_env_var:
            await self._emit(
                Narration(
                    entry_id=f"cfg-{uuid.uuid4().hex[:8]}",
                    text=(
                        "No live endpoint is configured for this run (still on "
                        "the dummy backend) — nothing to re-point. Set "
                        "CISM_LLM_BASE_URL/CISM_LLM_MODEL or restart with "
                        "--base-url/--model."
                    ),
                    done=True,
                )
            )
            return

        if argument:
            endpoint = argument if name == "api" else self._endpoint
            model_name = argument if name == "model" else self._model_name
            try:
                llm = build_chat_model(endpoint, self._key_env_var, model_name)
            except ValueError as exc:
                await self._emit(
                    Narration(
                        entry_id=f"cfg-{uuid.uuid4().hex[:8]}", text=str(exc), done=True
                    )
                )
                return
            self._llm = llm
            self._endpoint = endpoint
            self._model_name = model_name
            # Takes effect on the next submit(); an in-flight run already holds the old graph.
            self._graph = build_graph(
                self._llm,
                self._tools,
                self._guardrails,
                self._extractors,
                self._profiles,
                checkpointer=self._checkpointer,
                graded_propagation=self._graded_propagation,
                privacy=self._privacy,
            )
            await self._refresh_context_window()

        await self._emit(self._session())

    async def interrupt(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            await self._emit(Interrupted(reason="user interrupt"))

    async def aclose(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()

    async def _run(self, text: str) -> None:
        run_id = uuid.uuid4().hex

        # Consumed before any await, so a concurrent /ablate can't change "this run".
        ablated, self._ablated = self._ablated, set()
        graph = self._graph
        guardrails = self._guardrails
        profiles = self._profiles
        if ablated:
            tools = ToolRegistry([t for t in self._tools.all() if t.name not in ablated])
            guardrails = GuardrailSeam(
                input=GuardrailChain(
                    [s for s in self._guardrails.input.stages if s.name not in ablated]
                ),
                action=GuardrailChain(
                    [s for s in self._guardrails.action.stages if s.name not in ablated]
                ),
                output=GuardrailChain(
                    [s for s in self._guardrails.output.stages if s.name not in ablated]
                ),
            )
            # Per-phase stages (e.g. PhaseToolGuardStage) live in profiles, not
            # guardrails.action, so they need their own filtering pass here too.
            profiles = PhaseProfiles(
                {
                    phase: dataclasses.replace(
                        self._profiles.get(phase),
                        action_stages=tuple(
                            s for s in self._profiles.get(phase).action_stages if s.name not in ablated
                        ),
                    )
                    for phase in self._profiles.phases()
                }
            )
            graph = build_graph(
                self._llm,
                tools,
                guardrails,
                self._extractors,
                profiles,
                checkpointer=self._checkpointer,
                graded_propagation=self._graded_propagation,
                privacy=self._privacy,
            )

        self._metrics = {"tool_calls": 0, "tool_failures": 0, "guardrail_blocks": 0}
        await self._emit(
            RunStarted(run_id=run_id, phase=self._phase.current.to_wire())
        )
        if ablated:
            await self._emit(
                Narration(
                    entry_id=f"{run_id}-ablate",
                    text=f"ablated for this run only: {', '.join(sorted(ablated))}",
                    done=True,
                )
            )

        guarded = guardrails.input.run(text)
        if not guarded.allowed:
            await self._emit(
                Narration(
                    entry_id=f"{run_id}-input-blocked",
                    text=f"Input rejected: {guarded.reason or 'blocked by input guardrail'}",
                    done=True,
                )
            )
            await self._emit(RunFinished(run_id=run_id, ok=False, **self._run_metrics()))
            return

        initial_state: dict[str, Any] = {
            "messages": [HumanMessage(content=guarded.value)],
            "phase": self._phase.current,
            "phase_changed": False,
            "run_id": run_id,
            "target": self._target,
            "context_window": self._context_window,
        }
        if not self._thread_seeded:
            # Seed once only — no reducer, so resupplying `{}` every run would wipe checkpointed state.
            initial_state["depg_nodes"] = {}
            initial_state["depg_edges"] = []
            initial_state["memory_items"] = {}
            self._thread_seeded = True
        run_config = {"configurable": {"thread_id": self._thread_id}}

        pending_calls: dict[str, ToolCall] = {}
        streamed: dict[str, str] = {"text": ""}
        ok = True
        try:
            async for stream_mode, payload in graph.astream(
                initial_state, run_config, stream_mode=["updates", "messages"]
            ):
                if stream_mode == "messages":
                    chunk, metadata = payload
                    # Only "think"'s token deltas matter here — every other node's
                    # final message duplicates what the "updates" branch already handles.
                    if metadata.get("langgraph_node") != "think":
                        continue
                    content = getattr(chunk, "content", "")
                    if content:
                        streamed["text"] += content
                        await self._emit(
                            Narration(entry_id=f"{run_id}-final", text=content, done=False)
                        )
                    usage = getattr(chunk, "usage_metadata", None)
                    if usage:
                        # Arrives on a trailing empty chunk. ctx_used is a point-in-time
                        # input+output snapshot; delta/total track output_tokens only, so a
                        # resent prompt doesn't spike the live token-rate display.
                        input_tokens = usage.get("input_tokens", 0)
                        output_tokens = usage.get("output_tokens", 0)
                        self._token_total += output_tokens
                        await self._emit(
                            TokenDelta(
                                delta=output_tokens,
                                total=self._token_total,
                                ctx_used=input_tokens + output_tokens,
                                ctx_max=self._context_window,
                            )
                        )
                    continue
                for node, update in payload.items():
                    if not update:
                        continue
                    await self._translate(node, update, run_id, pending_calls, streamed)
        except asyncio.CancelledError:  # submit() cancelled us for a new run — mirror interrupt()
            await self._emit(Interrupted(reason="superseded by new submission"))
            raise
        except Exception as exc:  # a graph-loop failure is content, not a crash
            ok = False
            self._log.exception("run failed", extra={"data": {"run_id": run_id}})
            await self._emit(
                Narration(entry_id=f"{run_id}-error", text=f"run failed: {exc}", done=True)
            )

        await self._emit(RunFinished(run_id=run_id, ok=ok, **self._run_metrics()))

    def _run_metrics(self) -> dict[str, Any]:
        default_extractor = getattr(self._extractors, "_default", None)
        extraction_fallbacks = getattr(default_extractor, "fallback_count", 0)
        return {
            "tokens_total": self._token_total,
            "extraction_fallbacks": extraction_fallbacks,
            **self._metrics,
        }

    async def _translate(
        self,
        node: str,
        update: dict[str, Any],
        run_id: str,
        pending_calls: dict[str, ToolCall],
        streamed: dict[str, str],
    ) -> None:
        if node == "think":
            dropped = update.get("compacted") or 0
            if dropped:
                await self._emit(
                    Narration(
                        entry_id=f"{run_id}-compacted-{uuid.uuid4().hex[:8]}",
                        text=f"context window nearly full — dropped {dropped} earlier turn(s) from the prompt",
                        done=True,
                    )
                )
            for message in update.get("messages", []):
                had_calls = False
                for call in getattr(message, "tool_calls", None) or []:
                    pending_calls[call["id"]] = call
                    had_calls = True
                if had_calls:
                    # Routes to "act", not "respond" — clear preamble text so it doesn't
                    # leak into a later turn's final-answer comparison in "respond" below.
                    streamed["text"] = ""

        elif node == "act":
            for message in update.get("messages", []):
                call_id = message.tool_call_id
                call = pending_calls.pop(call_id, None)
                tool_name = message.name or (call["name"] if call else "unknown")
                args = str(call["args"]) if call else ""
                await self._emit(ToolStarted(call_id=call_id, tool=tool_name, args=args))
                self._metrics["tool_calls"] += 1
                if getattr(message, "status", "success") == "error":
                    guardrail_detail = message.additional_kwargs.get("guardrail_detail")
                    detail = guardrail_detail or str(message.content)
                    if guardrail_detail:
                        self._metrics["guardrail_blocks"] += 1
                    else:
                        self._metrics["tool_failures"] += 1
                    await self._emit(ToolFailed(call_id=call_id, reason=detail))
                else:
                    await self._emit(
                        ToolFinished(call_id=call_id, summary=str(message.content))
                    )

        elif node == "phase_router":
            new_phase = update.get("phase")
            if new_phase is not None and new_phase != self._phase.current:
                # The graph's own phase_router node already validated this
                # move's legality against its own PhaseStateMachine; mirroring
                # it here via .transition() would re-validate against a
                # separate instance that can legitimately be out of step
                # (e.g. right after a replay) and raise on an already-legal
                # move. This mirror only ever needs to record what happened.
                self._phase.current = new_phase
                await self._emit(PhaseChanged(phase=new_phase.to_wire()))

        elif node == "depg_update":
            nodes = update.get("depg_nodes") or {}
            edges = update.get("depg_edges") or []
            payload = (
                tuple(n.to_event() for n in nodes.values()),
                tuple(e.to_event() for e in edges),
            )
            if payload != self._last_depg:
                self._last_depg = payload
                await self._emit(DEPGUpdated(nodes=payload[0], edges=payload[1]))

        elif node == "memory_update":
            items = update.get("memory_items") or {}
            rows = tuple(item.to_event(time.time()) for item in items.values())
            await self._emit(MemoryUpdated(rows=rows, terms=DEFAULT_SALIENCE_TERMS))

        elif node == "respond":
            for message in update.get("messages", []):
                entry_id = f"{run_id}-final"
                final_text = str(message.content)
                if final_text != streamed["text"]:
                    await self._emit(
                        NarrationRedacted(entry_id=entry_id, reason=final_text)
                    )
                else:
                    await self._emit(Narration(entry_id=entry_id, text="", done=True))
                streamed["text"] = ""
