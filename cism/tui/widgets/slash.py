"""The slash-command overlay.

Opens when ``/`` is typed into an empty composer, filters fuzzily as you keep
typing, and is driven with the arrow keys. It sits directly above the composer
rather than floating, so it pushes the transcript up the way Claude Code's
does.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.text import Text
from textual.containers import Vertical
from textual.fuzzy import Matcher
from textual.message import Message
from textual.widgets import OptionList
from textual.widgets.option_list import Option


@dataclass(frozen=True, slots=True)
class SlashCommand:
    name: str
    arg: str
    help: str


#: Descriptions start at this column so the list reads as two columns.
NAME_COLUMN = 22

COMMANDS: tuple[SlashCommand, ...] = (
    SlashCommand("model", "<name>", "switch the inference model"),
    SlashCommand("models", "", "list loadable models"),
    SlashCommand("target", "<os|stack>", "declare the target environment"),
    SlashCommand("api", "[url]", "show or switch the inference endpoint"),
    SlashCommand("phase", "<name>", "force a PTES phase transition"),
    SlashCommand("depg", "", "open the dependency / error propagation graph"),
    SlashCommand("mem", "", "open the memory view"),
    SlashCommand("replay", "<run_id>", "counterfactual replay from the output cache"),
    SlashCommand("ablate", "<part>", "disable a component for the next run"),
    SlashCommand("export", "", "write the transcript and run state to disk"),
    SlashCommand("clear", "", "clear the transcript"),
    SlashCommand("help", "", "list commands"),
)


class SlashOverlay(Vertical):
    """Fuzzy, arrow-selectable command list."""

    COMPONENT_CLASSES = {"slash--name", "slash--arg", "slash--help", "slash--match"}

    class Picked(Message):
        def __init__(self, command: SlashCommand) -> None:
            super().__init__()
            self.command = command

    class Dismissed(Message):
        pass

    def __init__(self) -> None:
        super().__init__()
        self._matches: list[SlashCommand] = []
        self._list = OptionList()

    def compose(self):
        yield self._list

    @property
    def open(self) -> bool:
        return self.has_class("-active")

    @property
    def matches(self) -> list[SlashCommand]:
        return list(self._matches)

    def show(self, query: str = "") -> None:
        self.add_class("-active")
        self.filter(query)

    def hide(self) -> None:
        self.remove_class("-active")
        self._matches = []
        self._list.clear_options()

    def filter(self, query: str) -> None:
        """Re-rank commands against ``query`` (the text after the slash)."""
        query = query.lstrip("/").split(" ", 1)[0]
        if query:
            matcher = Matcher(query)
            scored = [(matcher.match(c.name), c) for c in COMMANDS]
            self._matches = [c for score, c in sorted(
                (s for s in scored if s[0] > 0), key=lambda s: -s[0]
            )]
        else:
            self._matches = list(COMMANDS)

        self._list.clear_options()
        if not self._matches:
            self.hide()
            return
        self._list.add_options(
            [Option(self._render_row(c), id=c.name) for c in self._matches]
        )
        self._list.highlighted = 0

    def _render_row(self, command: SlashCommand) -> Text:
        name = self.get_component_rich_style("slash--name")
        arg = self.get_component_rich_style("slash--arg")
        help_style = self.get_component_rich_style("slash--help")
        row = Text()
        row.append(f"/{command.name}", style=name)
        written = len(command.name) + 1
        if command.arg:
            row.append(f" {command.arg}", style=arg)
            written += len(command.arg) + 1
        row.append(" " * max(NAME_COLUMN - written, 2), style=help_style)
        row.append(command.help, style=help_style)
        return row

    # -- keyboard driving, delegated from the composer ---------------------

    def move(self, delta: int) -> None:
        if not self._matches:
            return
        current = self._list.highlighted or 0
        self._list.highlighted = (current + delta) % len(self._matches)

    def selected(self) -> SlashCommand | None:
        if not self._matches:
            return None
        index = self._list.highlighted or 0
        return self._matches[index]

    def on_option_list_option_selected(
        self, message: OptionList.OptionSelected
    ) -> None:
        message.stop()
        command = self.selected()
        if command is not None:
            self.post_message(self.Picked(command))
