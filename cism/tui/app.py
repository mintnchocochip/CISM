"""The CISM terminal application.

Layout is flat: one scrolling transcript, a working line, the composer, and
a status line. The app is a pure consumer of agent events — a worker drains
``agent.events`` into :meth:`CISMApp._apply`, the only place transcript
state mutates; user actions go back out via :meth:`Agent.submit` /
:meth:`Agent.interrupt`, each on its own worker so the UI never blocks."""

from __future__ import annotations

import time
import traceback
from collections import deque
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import TextArea

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

#: Commands the TUI answers itself. Everything else is forwarded to the agent.
LOCAL_COMMANDS = frozenset({"depg", "mem", "clear", "help", "export", "models"})

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
        self.memory_terms: SalienceTerms | None = None
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
        """Drain agent events forever. The only writer of transcript state."""
        await self.agent.start()
        while True:
            event = await self.agent.events.get()
            try:
                self._apply(event)
            except Exception:
                self.log.error(f"_apply failed for {type(event).__name__}", traceback.format_exc())
                self.unknown_events += 1
            finally:
                self.agent.events.task_done()

    def _apply(self, event: AgentEvent) -> None:
        """Apply one event to the UI. Total: unknown events are dropped."""
        transcript = self.transcript

        if isinstance(event, RunStarted):
            self.phase = event.phase
            self.framework = event.framework
            self.status.phase = event.phase
            self.indicator.start(event.phase, token_base=self.token_total)

        elif isinstance(event, RunFinished):
            self.indicator.stop()
            self._clear_rate()

        elif isinstance(event, Narration):
            entry = transcript.narration(event.entry_id)
            if event.text:
                entry.append(event.text)
            if event.done:
                entry.finish()

        elif isinstance(event, NarrationRedacted):
            transcript.narration(event.entry_id).redact(event.reason)

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

        elif isinstance(event, ScopeChanged):
            verb = "added" if event.action == "add" else "removed"
            transcript.add_note(f"scope: {verb} {event.target}")

        elif isinstance(event, DEPGUpdated):
            self.depg_nodes = event.nodes
            self.depg_edges = event.edges
            self.status.depg_nodes = len(event.nodes)

        elif isinstance(event, MemoryUpdated):
            self.memory_rows = event.rows
            if event.terms is not None:
                self.memory_terms = event.terms
            self.status.mem_t1 = sum(1 for r in event.rows if r.tier == "T1")
            self.status.mem_t2 = sum(1 for r in event.rows if r.tier == "T2")
            self.status.mem_t3 = sum(1 for r in event.rows if r.tier == "T3")

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

    @work(group="agent-step", exclusive=True, thread=False)
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

    def _export(self, argument: str) -> None:
        target = Path(argument) if argument else self.export_dir / "cism-transcript.txt"
        lines: list[str] = []
        for child in self.transcript.children:
            lines.append(self._entry_as_text(child))
        target.write_text("\n".join(lines), encoding="utf-8")
        self.transcript.add_note(f"exported {len(lines)} entries → {target}")

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
        self.push_screen(DEPGModal(self.depg_nodes, self.depg_edges))

    def action_show_memory(self) -> None:
        self.push_screen(MemoryModal(self.memory_rows, self.memory_terms))

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
