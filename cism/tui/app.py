"""The CISM terminal application.

Layout is deliberately flat: one scrolling transcript, an animated working
line, the composer, and a single status line. The terminal is the frame.

The app is a *pure consumer* of agent events. A long-lived worker drains
``agent.events`` and calls :meth:`CISMApp._apply`, which is the only place
transcript state is mutated. Widgets never call into the agent; user actions
travel back out through :meth:`Agent.submit` and :meth:`Agent.interrupt`,
each on its own exclusive worker so the UI thread never awaits llama.cpp,
a subprocess, or the cross-encoder scorer.
"""

from __future__ import annotations

import time
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
    Narration,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SalienceTerms,
    TokenDelta,
    ToolFailed,
    ToolFinished,
    ToolOutput,
    ToolStarted,
)
from .widgets.composer import Composer, ComposerInput
from .widgets.depg_modal import DEPGModal
from .widgets.memory_modal import MemoryModal
from .widgets.slash import SlashCommand, SlashOverlay
from .widgets.spinner import WorkingIndicator
from .widgets.status import StatusBar
from .widgets.transcript import ToolEntry, Transcript

DOUBLE_TAP_SECONDS = 2.0

#: Commands the TUI answers itself. Everything else is forwarded to the agent.
LOCAL_COMMANDS = frozenset({"depg", "mem", "clear", "help", "export"})

HELP_TEXT = """\
/phase <name>    force a PTES phase transition
/depg            dependency / error propagation graph      (ctrl+d)
/mem             memory view                               (ctrl+m)
/replay <run_id> counterfactual replay from the output cache
/ablate <part>   disable a component for the next run
/export          write the transcript to disk
/clear           clear the transcript
/help            this list

enter submit · shift+enter newline · esc interrupt · ctrl+c twice to quit
ctrl+o expand or collapse the last tool output · up/down recall history"""


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

        elif isinstance(event, Narration):
            entry = transcript.narration(event.entry_id)
            if event.text:
                entry.append(event.text)
            if event.done:
                entry.finish()

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

        elif isinstance(event, TokenDelta):
            self.token_total = event.total
            self.status.ctx_used = event.ctx_used
            self.status.ctx_max = event.ctx_max
            self.indicator.set_tokens(event.total)

        elif isinstance(event, Interrupted):
            self.indicator.stop()
            transcript.add_note(f"⏹ {event.reason}")

        else:
            self.unknown_events += 1
            self.log.warning("dropped unknown event", event=event)

    # -- user input --------------------------------------------------------

    def on_composer_submitted(self, message: Composer.Submitted) -> None:
        message.stop()
        text = message.text
        self.transcript.add_user_turn(text)
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

        if name not in LOCAL_COMMANDS:
            self.send(line)
            return

        if name == "depg":
            self.action_show_depg()
        elif name == "mem":
            self.action_show_memory()
        elif name == "clear":
            self.transcript.clear_entries()
        elif name == "help":
            self.transcript.add_note(HELP_TEXT)
        elif name == "export":
            self._export(argument)

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
        entry = self.transcript.last_tool()
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
