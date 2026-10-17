"""The CISM terminal application.

Layout is flat: one scrolling transcript, a working line, the composer, and
a status line. The app is a pure consumer of agent events — a worker drains
``agent.events`` into :meth:`CISMApp._apply`, the only place transcript
state mutates; user actions go back out via :meth:`Agent.submit` /
:meth:`Agent.interrupt`, each on its own worker so the UI never blocks."""

from __future__ import annotations

import asyncio
import time
import traceback
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import TextArea

from cism.report import PhaseTransition, RunMetrics, build_report, write_graph, write_report

from .events import (
    Agent,
    AgentEvent,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Interrupted,
    MemoryRow,
    MemoryUpdated,
    ModelInfo,
    Narration,
    NarrationRedacted,
    NarrationRetracted,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SalienceTerms,
    ScopeChanged,
    SessionState,
    TokenDelta,
    ToolFailed,
    ToolFinished,
    ToolOutput,
    ToolStarted,
)
from .redact import looks_like_secret, redact_command
from .widgets.composer import Composer, ComposerInput
from .widgets.depg_modal import DEPGModal
from .widgets.memory_modal import MemoryModal
from .widgets.slash import SlashCommand, SlashOverlay
from .widgets.spinner import WorkingIndicator
from .widgets.status import StatusBar
from .widgets.transcript import ToolEntry, Transcript

DOUBLE_TAP_SECONDS = 2.0

#: Window over which tokens-per-second is averaged.
RATE_WINDOW = 4.0

#: Below this span a rate is noise, not a measurement.
MIN_RATE_SPAN = 0.5


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

#: Commands the TUI answers itself. Everything else is forwarded to the agent.
LOCAL_COMMANDS = frozenset({"depg", "mem", "clear", "help", "export", "models", "report"})

HELP_TEXT = """\
/model <name>    switch the inference model
/models          list loadable models
/target <spec>   declare the target environment, e.g. linux nginx php
/api [url]       show or switch the inference endpoint
/phase <name>    force a PTES phase transition
/scope [add|remove] <target>  view or extend the live engagement scope
/depg            dependency / error propagation graph      (ctrl+d)
/mem             memory view                               (ctrl+m)
/replay <run_id> counterfactual replay from the output cache
/ablate <part>   disable a component for the next run
/export          write the transcript to disk
/report          write a findings report (Markdown + JSON) from the DEPG/memory state
/clear           clear the transcript
/help            this list

enter submit · shift+enter newline · esc interrupt · ctrl+c twice to quit
ctrl+o expand or collapse the last tool output · up/down recall history"""

API_KEY_REFUSAL = """\
That looks like an API key, so it has not been sent or recorded.

Keys are read from the environment, never typed into the composer — the
transcript is exported and the composer history is recalled with the arrow
keys, so anything entered here outlives the keystroke.

Set the variable in your shell and point /api at the endpoint only:
  export {var}=...
  /api https://your-endpoint/v1"""

#: E5: three full-snapshot event types — each carries complete current
#: state (every node, every row, the running token total), not a delta —
#: so under a burst, only the last one queued is ever worth rendering.
#: Narration/ToolStarted/ToolFinished/etc. are deliberately excluded:
#: those are genuinely incremental and coalescing them would drop content.
_COALESCIBLE_EVENT_TYPES = (DEPGUpdated, MemoryUpdated, TokenDelta)
#: How many events the pump applies before yielding to the event loop —
#: keeps a burst from starving the UI's own message processing.
_PUMP_YIELD_EVERY = 50


class CISMApp(App[None]):
    """Cyber Investigation State Memory — terminal surface."""

    CSS_PATH = "theme.tcss"
    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("escape", "interrupt", "interrupt", show=False),
        Binding("ctrl+c", "request_quit", "quit", show=False, priority=True),
        Binding("ctrl+d", "show_depg", "DEPG", show=False, priority=True),
        Binding("ctrl+m", "show_memory", "memory", show=False, priority=True),
        Binding("ctrl+o", "toggle_output", "expand output", show=False, priority=True),
    ]

    def __init__(self, agent: Agent, export_dir: Path | None = None) -> None:
        super().__init__()
        self.agent = agent
        self.export_dir = export_dir or Path.cwd()
        self.phase = "recon"
        self.framework = "PTES"
        self.depg_nodes: tuple[DEPGNode, ...] = ()
        self.depg_edges: tuple[DEPGEdge, ...] = ()
        self.memory_rows: tuple[MemoryRow, ...] = ()
        #: For /report — accumulated live from the event stream rather than
        #: re-read from a log, so cism.report never needs a cism.agent import.
        self._last_run_id: str = ""
        self._phase_history: list[PhaseTransition] = []
        self._last_metrics: RunMetrics | None = None
        self.memory_terms: SalienceTerms | None = None
        #: E4: a ref to the currently-mounted modal, so a DEPGUpdated/
        #: MemoryUpdated arriving while it's open can update it in place
        #: instead of the handler pushing a whole new screen (which reset
        #: the tree/table cursor back to the top on every single event).
        #: Cleared by push_screen's dismiss callback, never left dangling
        #: once the modal actually closes.
        self._depg_modal: DEPGModal | None = None
        self._memory_modal: MemoryModal | None = None
        self.token_total = 0
        self.unknown_events = 0
        self.model = ""
        self.models_available: tuple[ModelInfo, ...] = ()
        self.endpoint = "local"
        self.key_env_var = "CISM_API_KEY"
        self.key_present = False
        self.target_os = ""
        self.target_stack: tuple[str, ...] = ()
        self._token_samples: deque[tuple[float, int]] = deque()
        self._last_ctrl_c = 0.0
        self._notice_timer = None

    # -- composition -------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Transcript()
        yield SlashOverlay()
        yield WorkingIndicator()
        yield Composer()
        yield StatusBar()

    def on_mount(self) -> None:
        self.composer.focus_input()
        self.pump()

    async def on_unmount(self) -> None:
        await self.agent.aclose()

    # -- handy accessors ---------------------------------------------------

    @property
    def transcript(self) -> Transcript:
        return self.query_one(Transcript)

    @property
    def composer(self) -> Composer:
        return self.query_one(Composer)

    @property
    def status(self) -> StatusBar:
        return self.query_one(StatusBar)

    @property
    def indicator(self) -> WorkingIndicator:
        return self.query_one(WorkingIndicator)

    @property
    def overlay(self) -> SlashOverlay:
        return self.query_one(SlashOverlay)

    # -- the event pump ----------------------------------------------------

    @work(group="pump", exclusive=False, thread=False)
    async def pump(self) -> None:
        """Drain agent events forever. The only writer of transcript state.

        E5: a queued run of the exact same full-snapshot event type
        (_COALESCIBLE_EVENT_TYPES) collapses to its last member before
        being applied — an older one in the run is already stale by the
        time this loop would get to it. Only ever collapses a contiguous
        run of one type sitting at the front of the queue; a differently
        typed event in between is held and applied next, never skipped
        over, so ordering between distinct event types is unaffected.
        Every event this loop decides to apply still gets task_done()
        only *after* _apply() returns — tests' drain() depends on that to
        mean "the UI reflects this event", not just "it left the queue";
        a superseded event's task_done() fires immediately instead, since
        it will never be applied and there's nothing left to wait for.
        """
        await self.agent.start()
        held: AgentEvent | None = None
        processed = 0
        while True:
            if held is not None:
                event, held = held, None
            else:
                event = await self.agent.events.get()
            if isinstance(event, _COALESCIBLE_EVENT_TYPES):
                event, held = self._coalesce(event)
            try:
                self._apply(event)
            except Exception:
                self.log.error(f"_apply failed for {type(event).__name__}", traceback.format_exc())
                self.unknown_events += 1
            finally:
                self.agent.events.task_done()
            processed += 1
            if processed >= _PUMP_YIELD_EVERY:
                processed = 0
                await asyncio.sleep(0)

    def _coalesce(self, event: AgentEvent) -> tuple[AgentEvent, AgentEvent | None]:
        """Drains any already-queued run of the exact same event type as
        ``event``, keeping only the last. Returns that last event, plus
        the first differently-typed event found (to apply next), or None
        if the queue ran dry first."""
        while not self.agent.events.empty():
            next_event = self.agent.events.get_nowait()
            if isinstance(next_event, type(event)):
                self.agent.events.task_done()
                event = next_event
            else:
                return event, next_event
        return event, None

    def _apply(self, event: AgentEvent) -> None:
        """Apply one event to the UI. Total: unknown events are dropped."""
        transcript = self.transcript

        if isinstance(event, RunStarted):
            self.phase = event.phase
            self.framework = event.framework
            self.status.phase = event.phase
            self.indicator.start(event.phase, token_base=self.token_total)
            self._last_run_id = event.run_id
            if not self._phase_history:
                # Accumulates across the whole session, not reset per turn —
                # a report pulled after several submits should show the
                # engagement's full progression, not just the latest turn's.
                self._phase_history = [PhaseTransition(timestamp=_now_iso(), phase=event.phase)]

        elif isinstance(event, RunFinished):
            self.indicator.stop()
            self._clear_rate()
            self._last_metrics = RunMetrics(
                ok=event.ok,
                tool_calls=event.tool_calls,
                tool_failures=event.tool_failures,
                guardrail_blocks=event.guardrail_blocks,
                extraction_fallbacks=event.extraction_fallbacks,
                tokens_total=event.tokens_total,
            )

        elif isinstance(event, Narration):
            entry = transcript.narration(event.entry_id)
            if event.text:
                entry.append(event.text)
            if event.done:
                entry.finish()

        elif isinstance(event, NarrationRedacted):
            entry = transcript.existing_narration(event.entry_id)
            if entry is not None:
                entry.redact(event.reason)

        elif isinstance(event, NarrationRetracted):
            entry = transcript.existing_narration(event.entry_id)
            if entry is not None:
                entry.retract(event.chars)

        elif isinstance(event, ToolStarted):
            transcript.add_tool(event.call_id, event.tool, event.args)
            if not self.indicator.active:
                self.indicator.start(self.phase, token_base=self.token_total)

        elif isinstance(event, ToolOutput):
            entry = transcript.tool(event.call_id)
            if entry is not None:
                entry.feed(event.chunk)

        elif isinstance(event, ToolFinished):
            entry = transcript.tool(event.call_id)
            if entry is not None:
                entry.finish(event.summary, event.lines, event.tier, event.score)

        elif isinstance(event, ToolFailed):
            entry = transcript.tool(event.call_id)
            if entry is not None:
                entry.fail(event.reason, event.traceback)

        elif isinstance(event, PhaseChanged):
            self.phase = event.phase
            self.framework = event.framework
            self.status.phase = event.phase
            self.indicator.set_phase(event.phase)
            transcript.add_phase_rule(event.framework, event.phase)
            self._phase_history.append(PhaseTransition(timestamp=_now_iso(), phase=event.phase))

        elif isinstance(event, ScopeChanged):
            verb = "added" if event.action == "add" else "removed"
            transcript.add_note(f"scope: {verb} {event.target}")

        elif isinstance(event, DEPGUpdated):
            self.depg_nodes = event.nodes
            self.depg_edges = event.edges
            self.status.depg_nodes = len(event.nodes)
            if self._depg_modal is not None:
                self._depg_modal.refresh_data(event.nodes, event.edges)

        elif isinstance(event, MemoryUpdated):
            self.memory_rows = event.rows
            if event.terms is not None:
                self.memory_terms = event.terms
            self.status.mem_t1 = sum(1 for r in event.rows if r.tier == "T1")
            self.status.mem_t2 = sum(1 for r in event.rows if r.tier == "T2")
            self.status.mem_t3 = sum(1 for r in event.rows if r.tier == "T3")
            if self._memory_modal is not None:
                self._memory_modal.refresh_data(event.rows, self.memory_terms)

        elif isinstance(event, TokenDelta):
            self.token_total = event.total
            self.status.ctx_used = event.ctx_used
            self.status.ctx_max = event.ctx_max
            self.indicator.set_tokens(event.total)
            self._record_rate(event.total)

        elif isinstance(event, SessionState):
            self._apply_session(event)

        elif isinstance(event, Interrupted):
            self.indicator.stop()
            self._clear_rate()
            transcript.add_note(f"⏹ {event.reason}")

        else:
            self.unknown_events += 1
            self.log.warning("dropped unknown event", event=event)

    def _apply_session(self, event: SessionState) -> None:
        if event.model:
            self.model = event.model
            self.status.model = event.model
        if event.models_available:
            self.models_available = event.models_available
        self.endpoint = event.endpoint
        if event.key_env_var:
            self.key_env_var = event.key_env_var
        self.key_present = event.key_present
        self.target_os = event.target_os
        self.target_stack = event.target_stack
        self.status.target_os = event.target_os
        self.status.target_stack = event.target_stack

    # -- token rate --------------------------------------------------------

    def _record_rate(self, total: int) -> None:
        """Average tokens/second over a sliding window, derived here from
        TokenDelta rather than made another field the agent must report."""
        now = time.monotonic()
        samples = self._token_samples
        samples.append((now, total))
        while samples and now - samples[0][0] > RATE_WINDOW:
            samples.popleft()
        span = samples[-1][0] - samples[0][0]
        if len(samples) >= 2 and span >= MIN_RATE_SPAN:
            produced = samples[-1][1] - samples[0][1]
            self.status.tokens_per_second = max(produced / span, 0.0)

    def _clear_rate(self) -> None:
        self._token_samples.clear()
        self.status.tokens_per_second = 0.0

    # -- user input --------------------------------------------------------

    def on_composer_submitted(self, message: Composer.Submitted) -> None:
        message.stop()
        text = message.text
        # Redact before echoing — an exported/recalled transcript shouldn't outlive the keystroke.
        self.transcript.add_user_turn(redact_command(text))
        if text.startswith("/"):
            self._run_command(text)
        else:
            self.send(text)

    @work(group="agent-step", exclusive=True, thread=False)
    async def send(self, text: str) -> None:
        await self.agent.submit(text)

    # E10: a separate group from "agent-step" — interrupt must run
    # *alongside* an in-flight send, not cancel it outright the way
    # Textual's exclusive-group semantics would if they shared one. The
    # agent's own interrupt() is what cooperatively unwinds the run; a
    # worker-level cancel of send() here would race it instead.
    @work(group="agent-interrupt", exclusive=True, thread=False)
    async def interrupt(self) -> None:
        await self.agent.interrupt()

    # -- slash overlay -----------------------------------------------------

    def on_composer_input_slash_opened(self, _: ComposerInput.SlashOpened) -> None:
        self.overlay.show("")
        self.composer.capture = True

    def on_text_area_changed(self, message: TextArea.Changed) -> None:
        text = message.text_area.text
        if not self.overlay.open:
            return
        if not text.startswith("/") or "\n" in text:
            self._close_overlay()
            return
        self.overlay.filter(text)
        self.composer.capture = self.overlay.open

    def on_composer_input_history_move(
        self, message: ComposerInput.HistoryMove
    ) -> None:
        """Only reaches the app while the overlay is capturing arrow keys."""
        message.stop()
        self.overlay.move(message.delta)

    def on_composer_input_submitted(self, message: ComposerInput.Submitted) -> None:
        """Only reaches the app while the overlay is capturing enter."""
        message.stop()
        command = self.overlay.selected()
        self._close_overlay()
        if command is None:
            return
        self._accept_command(command, message.text)

    def on_slash_overlay_picked(self, message: SlashOverlay.Picked) -> None:
        message.stop()
        text = self.composer.text
        self._close_overlay()
        self._accept_command(message.command, text)

    def _accept_command(self, command: SlashCommand, typed: str) -> None:
        """Complete the composer to the picked command, or run it outright."""
        rest = typed.lstrip("/").split(" ", 1)
        argument = rest[1].strip() if len(rest) > 1 else ""
        if command.arg and not argument:
            self.composer.set_text(f"/{command.name} ")
            self.composer.focus_input()
            return
        self.composer.clear()
        line = f"/{command.name} {argument}".strip()
        self.transcript.add_user_turn(line)
        self._run_command(line)

    def _close_overlay(self) -> None:
        self.overlay.hide()
        self.composer.capture = False

    # -- commands ----------------------------------------------------------

    def _run_command(self, line: str) -> None:
        body = line[1:].strip()
        name, _, argument = body.partition(" ")
        name = name.strip()
        argument = argument.strip()

        if name == "api":
            self._api_command(argument)
            return

        if name not in LOCAL_COMMANDS:
            if looks_like_secret(argument):
                self.transcript.add_note(
                    API_KEY_REFUSAL.format(var=self.key_env_var)
                )
                return
            self.send(line)
            return

        if name == "depg":
            self.action_show_depg()
        elif name == "mem":
            self.action_show_memory()
        elif name == "models":
            self.transcript.add_note(self._models_text())
        elif name == "clear":
            self.transcript.clear_entries()
        elif name == "help":
            self.transcript.add_note(HELP_TEXT)
        elif name == "export":
            self._export(argument)
        elif name == "report":
            self._report(argument)

    def _api_command(self, argument: str) -> None:
        """Show the endpoint, or switch it. Never touches the key itself."""
        if looks_like_secret(argument):
            self.transcript.add_note(API_KEY_REFUSAL.format(var=self.key_env_var))
            return
        if not argument:
            state = "set" if self.key_present else "not set"
            self.transcript.add_note(
                f"endpoint  {self.endpoint}\n"
                f"key       ${self.key_env_var} ({state})\n"
                f"model     {self.model or 'unknown'}\n\n"
                f"/api <url> switches the endpoint. The key is read from the "
                f"environment and is never entered here."
            )
            return
        self.send(f"/api {argument}")

    def _models_text(self) -> str:
        if not self.models_available:
            return "no model list received from the agent yet"
        lines = ["models:"]
        for info in self.models_available:
            marker = "●" if info.name == self.model else " "
            context = f"{info.context // 1024}k ctx" if info.context else ""
            lines.append(
                f" {marker} {info.name:<22}{info.params:<7}{context}"
            )
        lines.append("")
        lines.append("/model <name> switches.")
        return "\n".join(lines)

    # E8: a slow/unavailable disk (network mount, full volume) used to
    # block the whole UI loop on this write; now it's a worker, and a
    # write failure is reported in the transcript instead of crashing the
    # app with an unhandled OSError.
    @work(exclusive=False, thread=False)
    async def _export(self, argument: str) -> None:
        target = Path(argument) if argument else self.export_dir / "cism-transcript.txt"
        lines: list[str] = [self._entry_as_text(child) for child in self.transcript.children]
        try:
            await asyncio.to_thread(target.write_text, "\n".join(lines), encoding="utf-8")
        except OSError as exc:
            self.transcript.add_note(f"export to {target} failed: {exc}")
            return
        self.transcript.add_note(f"exported {len(lines)} entries → {target}")

    def _report(self, argument: str) -> None:
        if not self._last_run_id:
            self.transcript.add_note("no run yet — nothing to report on")
            return
        out_dir = Path(argument) if argument else self.export_dir
        # Not self.status.target_stack: that's the detected OS/software
        # fingerprint tags for the status bar (e.g. "linux", "apache"),
        # a tuple — passing it here as the report's network target silently
        # produced a wrong-but-non-crashing header in to_markdown()/to_json()
        # (an f-string coerces a tuple to text without complaint) until
        # build_dot's _escape() made the type mismatch an actual crash.
        # DEPGNode.target is the real host/IP every node in this run shares.
        report = build_report(
            run_id=self._last_run_id,
            target=self.depg_nodes[0].target if self.depg_nodes else "",
            nodes=self.depg_nodes,
            edges=self.depg_edges,
            memory=self.memory_rows,
            phase_history=tuple(self._phase_history),
            metrics=self._last_metrics,
        )
        md_path, json_path = write_report(report, out_dir)
        dot_path = write_graph(report, out_dir)
        svg_path = dot_path.with_suffix(".svg")
        graph_note = f", {svg_path}" if svg_path.exists() else f", {dot_path} (install graphviz for .svg)"
        self.transcript.add_note(
            f"report written — {len(report.findings)} resolved finding(s) → "
            f"{md_path}, {json_path}{graph_note}"
        )

    @staticmethod
    def _entry_as_text(widget) -> str:  # noqa: ANN001 - any transcript entry
        from .widgets.transcript import NarrationEntry, PhaseRule, UserTurn

        if isinstance(widget, UserTurn):
            return f"> {widget.turn_text}"
        if isinstance(widget, NarrationEntry):
            return widget.text
        if isinstance(widget, ToolEntry):
            head = f"⏺ {widget.tool}({widget.args})"
            body = widget.body_text.rstrip()
            return f"{head}\n{body}" if body else head
        if isinstance(widget, PhaseRule):
            return f"--- {widget.framework}: {widget.phase} ---"
        return ""

    # -- actions -----------------------------------------------------------

    def action_interrupt(self) -> None:
        if self.overlay.open:
            self._close_overlay()
            return
        if self.indicator.active:
            self.interrupt()

    def action_request_quit(self) -> None:
        now = time.monotonic()
        if now - self._last_ctrl_c <= DOUBLE_TAP_SECONDS:
            self.exit()
            return
        self._last_ctrl_c = now
        self._notice("press ctrl+c again to quit")

    def action_show_depg(self) -> None:
        if len(self.screen_stack) > 1:
            return
        modal = DEPGModal(self.depg_nodes, self.depg_edges)
        self._depg_modal = modal
        self.push_screen(modal, callback=lambda _: setattr(self, "_depg_modal", None))

    def action_show_memory(self) -> None:
        if len(self.screen_stack) > 1:
            return
        modal = MemoryModal(self.memory_rows, self.memory_terms)
        self._memory_modal = modal
        self.push_screen(modal, callback=lambda _: setattr(self, "_memory_modal", None))

    def action_toggle_output(self) -> None:
        entry = self.transcript.last_collapsible()
        if entry is not None:
            entry.toggle()

    # -- transient status notice -------------------------------------------

    def _notice(self, text: str) -> None:
        self.status.notice = text
        if self._notice_timer is not None:
            self._notice_timer.stop()
        self._notice_timer = self.set_timer(
            DOUBLE_TAP_SECONDS, lambda: setattr(self.status, "notice", "")
        )

    def on_tool_entry_toggled(self, message: ToolEntry.Toggled) -> None:
        message.stop()
