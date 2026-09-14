"""The transcript: one scrolling column of left-aligned entries.

There are no boxes and no panels here. Every entry is a plain widget in a
single ``VerticalScroll``, which is anchored to the bottom so new content
follows the cursor until the user scrolls up — at which point Textual releases
the anchor on its own and autoscroll pauses.

Tool output is collapsed by default. The ``⎿`` line is focusable and
clickable; expanding reveals a scrollable, dim block indented five spaces.
"""

from __future__ import annotations

from rich.text import Text
from textual.containers import Vertical, VerticalScroll
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Static

TOOL_GLYPH = "⏺"
BRANCH = "⎿"
#: Wrapped ``⎿`` continuations hang at this indent, aligning under the summary.
INDENT = "     "


class UserTurn(Static):
    """A user turn: ``> `` prefix, bright text, continuations indented."""

    COMPONENT_CLASSES = {"user--glyph", "user--text"}

    def __init__(self, text: str) -> None:
        super().__init__()
        self.turn_text = text

    def render(self) -> Text:
        glyph = self.get_component_rich_style("user--glyph")
        body = self.get_component_rich_style("user--text")
        out = Text()
        lines = self.turn_text.splitlines() or [""]
        out.append("> ", style=glyph)
        out.append(lines[0], style=body)
        for line in lines[1:]:
            out.append("\n  ", style=glyph)
            out.append(line, style=body)
        return out


class NarrationEntry(Static):
    """Streamed model narration.

    Chunks are appended to one Rich ``Text`` held by the widget and flushed on
    a coalescing timer. The widget is never rebuilt and the buffer is never
    re-joined, so append cost does not grow with entry length.

    Expanded by default — you watch it type live, and a finished answer
    shouldn't vanish on its own. ``ctrl+o`` (routed through
    ``Transcript.last_collapsible()``) can collapse it once it's ``done``,
    the same mechanism ``ToolEntry`` already uses for tool output.
    """

    COMPONENT_CLASSES = {"narration--text", "narration--hint"}

    FLUSH_INTERVAL = 0.06

    def __init__(self, entry_id: str) -> None:
        super().__init__()
        self.entry_id = entry_id
        self.done = False
        self.redacted = False
        self._text = Text()
        self._timer = None
        self._collapsed = False

    @property
    def text(self) -> str:
        return self._text.plain

    @property
    def expanded(self) -> bool:
        return not self._collapsed

    def append(self, chunk: str) -> None:
        self._text.append(chunk)
        if self._timer is None:
            self._timer = self.set_timer(self.FLUSH_INTERVAL, self._flush)

    def finish(self) -> None:
        self.done = True
        self._flush()

    def redact(self, reason: str) -> None:
        """Replace whatever has been shown so far with a withheld-content
        notice — used when the output guardrail's verdict differs from
        what was already streamed."""
        self.done = True
        self.redacted = True
        self._collapsed = False
        self._text = Text(reason or "[response withheld by output guardrail]")
        self._flush()

    def toggle(self) -> None:
        if not self.done:
            return
        self._collapsed = not self._collapsed
        self.refresh(layout=True)

    def _flush(self) -> None:
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self.refresh(layout=True)

    def render(self) -> Text:
        style = self.get_component_rich_style("narration--text")
        self._text.style = style
        if self._collapsed and self.done:
            hint_style = self.get_component_rich_style("narration--hint")
            line_count = self._text.plain.count("\n") + 1 if self._text.plain else 0
            out = Text()
            out.append(f"[{line_count} lines collapsed · ctrl+o to expand]", style=hint_style)
            return out
        return self._text


class ToolHeader(Static):
    """``⏺ nmap(-sV -p- 10.0.0.5)`` — glyph, bold name, dim args."""

    COMPONENT_CLASSES = {"tool--glyph", "tool--name", "tool--args"}

    def __init__(self, tool: str, args: str) -> None:
        super().__init__(classes="tool-header")
        self.tool = tool
        self.args = args

    def render(self) -> Text:
        out = Text()
        out.append(f"{TOOL_GLYPH} ", style=self.get_component_rich_style("tool--glyph"))
        out.append(self.tool, style=self.get_component_rich_style("tool--name"))
        if self.args:
            out.append(
                f"({self.args})", style=self.get_component_rich_style("tool--args")
            )
        return out


class ToolMeta(Static):
    """The ``  ⎿  …`` continuation line. Focusable; enter or click toggles."""

    COMPONENT_CLASSES = {"tool--branch", "tool--summary", "tool--tier", "tool--hint"}

    BINDINGS = [("enter", "toggle", "expand/collapse")]

    can_focus = True

    def __init__(self) -> None:
        super().__init__(classes="tool-meta")
        self.summary = "running…"
        self.tier: str | None = None
        self.score: float | None = None
        self.has_body = False
        self.expanded = False

    def render(self) -> Text:
        branch = self.get_component_rich_style("tool--branch")
        summary = self.get_component_rich_style("tool--summary")
        tier_style = self.get_component_rich_style("tool--tier")
        hint = self.get_component_rich_style("tool--hint")

        runs: list[tuple[str, object]] = [(self.summary, summary)]
        if self.tier is not None:
            label = f"· relevance {self.tier}"
            if self.score is not None:
                label += f" ({self.score:.2f})"
            runs.append((label, tier_style))
        if self.has_body:
            runs.append(
                ("· ctrl+o to collapse" if self.expanded else "· ctrl+o to expand", hint)
            )

        out = Text()
        out.append(f"  {BRANCH}  ", style=branch)
        self._append_wrapped(out, runs)
        return out

    def _append_wrapped(self, out: Text, runs: list[tuple[str, object]]) -> None:
        """Fill words into the line, hanging-indenting wraps to column 5.

        Rich has no hanging-indent mode, and letting the widget wrap on its own
        pushes continuations back to column 0 — which breaks the ``⎿`` gutter
        that makes a tool entry readable at a glance.
        """
        width = max((self.size.width or 80) - len(INDENT), 16)
        used = 0
        for text, style in runs:
            for word in text.split():
                extra = len(word) + (1 if used else 0)
                if used and used + extra > width:
                    out.append(f"\n{INDENT}", style=style)
                    out.append(word, style=style)
                    used = len(word)
                else:
                    if used:
                        out.append(" ", style=style)
                    out.append(word, style=style)
                    used += extra

    def on_resize(self) -> None:
        self.refresh(layout=True)

    def action_toggle(self) -> None:
        self.post_message(ToolEntry.Toggled(self))

    def on_click(self) -> None:
        self.focus()
        self.action_toggle()


class ToolEntry(Vertical):
    """A tool call: header line, ``⎿`` summary line, collapsed output body."""

    class Toggled(Message):
        """Posted when a tool entry's output is expanded or collapsed."""

        def __init__(self, meta: ToolMeta) -> None:
            super().__init__()
            self.meta = meta

    def __init__(self, call_id: str, tool: str, args: str) -> None:
        super().__init__()
        self.call_id = call_id
        self.tool = tool
        self.args = args
        self.failed = False
        self._body = Text()
        self._header = ToolHeader(tool, args)
        self._meta = ToolMeta()
        # The Static holds the same Text object the entry mutates, so output
        # that streams in before the widget mounts is never lost.
        self._body_text = Static(self._body, classes="tool-body-text")
        self._body_scroll = VerticalScroll(self._body_text, classes="tool-body")

    def compose(self):
        yield self._header
        yield self._meta
        yield self._body_scroll

    @property
    def expanded(self) -> bool:
        return self.has_class("-expanded")

    @property
    def body_text(self) -> str:
        return self._body.plain

    def feed(self, chunk: str) -> None:
        """Append raw tool output into the collapsed body."""
        self._body.append(chunk)
        self._meta.has_body = True
        self._meta.refresh(layout=True)
        self._body_text.refresh(layout=True)

    def finish(
        self,
        summary: str,
        lines: int = 0,
        tier: str | None = None,
        score: float | None = None,
    ) -> None:
        parts: list[str] = []
        if lines:
            parts.append(f"{lines} lines")
        if summary:
            parts.append(summary)
        self._meta.summary = " · ".join(parts) if parts else "done"
        self._meta.tier = tier
        self._meta.score = score
        self._meta.refresh(layout=True)

    def fail(self, reason: str, traceback: str = "") -> None:
        self.failed = True
        self.add_class("-failed")
        self._meta.summary = reason
        self._meta.tier = None
        self._meta.score = None
        if traceback:
            self.feed(traceback if traceback.endswith("\n") else traceback + "\n")
        self._meta.refresh(layout=True)

    def toggle(self) -> None:
        self.toggle_class("-expanded")
        self._meta.expanded = self.expanded
        self._meta.refresh(layout=True)

    def on_tool_entry_toggled(self, message: ToolEntry.Toggled) -> None:
        if message.meta is self._meta:
            self.toggle()


class PhaseRule(Static):
    """A full-width dim rule with a centred phase label."""

    COMPONENT_CLASSES = {"phase--rule", "phase--label"}

    def __init__(self, framework: str, phase: str) -> None:
        super().__init__()
        self.framework = framework
        self.phase = phase

    def render(self) -> Text:
        rule = self.get_component_rich_style("phase--rule")
        label_style = self.get_component_rich_style("phase--label")
        label = f"  {self.framework}: {self.phase}  "
        width = max(self.size.width, len(label) + 6)
        side = max((width - len(label)) // 2, 3)
        out = Text()
        out.append("─" * side, style=rule)
        out.append(label, style=label_style)
        out.append("─" * (width - side - len(label)), style=rule)
        return out

    def on_resize(self) -> None:
        self.refresh(layout=True)


class Transcript(VerticalScroll):
    """The one scroll region.

    Content is top-aligned until it overflows, then the view follows the
    bottom. Scrolling up pauses that; returning to the bottom resumes it.

    Textual's own :meth:`anchor` is not used here: it pins short content to
    the bottom of the viewport, so an almost-empty transcript would float
    just above the composer instead of starting at the top.
    """

    #: How often the follow check runs, in seconds.
    FOLLOW_INTERVAL = 1 / 15

    def __init__(self) -> None:
        super().__init__()
        self._narrations: dict[str, NarrationEntry] = {}
        self._tools: dict[str, ToolEntry] = {}
        self._tool_order: list[ToolEntry] = []
        self._collapsible_order: list[ToolEntry | NarrationEntry] = []
        self._following = True
        self._expected_y = 0.0
        self._follow_timer = None

    @property
    def following(self) -> bool:
        """True while the view is tracking the bottom of the transcript."""
        return self._following

    def on_mount(self) -> None:
        self._follow_timer = self.set_interval(
            self.FOLLOW_INTERVAL, self._follow_bottom
        )

    def pause_follow(self) -> None:
        """Stop tracking the bottom for good.

        Clearing the flag alone is not enough: the next tick sees the viewport
        sitting at the bottom and turns following back on. Callers that need
        the scroll position to stay put — a scripted capture, say — have to
        stop the timer as well.
        """
        self._following = False
        if self._follow_timer is not None:
            self._follow_timer.stop()
            self._follow_timer = None

    def _follow_bottom(self) -> None:
        bottom = self.max_scroll_y
        if abs(self.scroll_y - self._expected_y) > 0.5:
            # The viewport moved and we did not move it, so the user did.
            self._following = self.scroll_y >= bottom - 0.5
        if self._following and self.scroll_y < bottom:
            self.scroll_end(animate=False, immediate=True)
        self._expected_y = self.scroll_y

    # -- entry construction ------------------------------------------------

    def add_user_turn(self, text: str) -> UserTurn:
        widget = UserTurn(text)
        self.mount(widget)
        self._following = True
        return widget

    def narration(self, entry_id: str) -> NarrationEntry:
        """Get the narration entry for ``entry_id``, creating it if needed."""
        entry = self._narrations.get(entry_id)
        if entry is None:
            entry = NarrationEntry(entry_id)
            self._narrations[entry_id] = entry
            self._collapsible_order.append(entry)
            self.mount(entry)
        return entry

    def add_tool(self, call_id: str, tool: str, args: str) -> ToolEntry:
        entry = ToolEntry(call_id, tool, args)
        self._tools[call_id] = entry
        self._tool_order.append(entry)
        self._collapsible_order.append(entry)
        self.mount(entry)
        return entry

    def tool(self, call_id: str) -> ToolEntry | None:
        return self._tools.get(call_id)

    def last_tool(self) -> ToolEntry | None:
        return self._tool_order[-1] if self._tool_order else None

    def last_collapsible(self) -> ToolEntry | NarrationEntry | None:
        return self._collapsible_order[-1] if self._collapsible_order else None

    def add_phase_rule(self, framework: str, phase: str) -> PhaseRule:
        widget = PhaseRule(framework, phase)
        self.mount(widget)
        return widget

    def add_note(self, text: str) -> NarrationEntry:
        """A one-off line that is not part of a streamed narration entry."""
        entry = NarrationEntry(f"note-{len(self._narrations)}-{id(text)}")
        self.mount(entry)
        entry.append(text)
        entry.finish()
        return entry

    def clear_entries(self) -> None:
        self._narrations.clear()
        self._tools.clear()
        self._tool_order.clear()
        self._collapsible_order.clear()
        self.remove_children()
        self._following = True
        self._expected_y = 0.0
