"""The fixed bottom composer: one rounded box, a ``>`` glyph, and the input.

The border is dim until something inside is focused, then it takes the accent.
Enter submits, shift+enter (or ctrl+j, for terminals that do not distinguish
shift+enter) inserts a newline, and up/down recall history while the buffer is
a single line.
"""

from __future__ import annotations

from textual.containers import Horizontal
from textual.message import Message
from textual.widgets import Static, TextArea


class ComposerInput(TextArea):
    """A TextArea that submits on enter instead of inserting a newline."""

    class Submitted(Message):
        def __init__(self, text: str) -> None:
            super().__init__()
            self.text = text

    class HistoryMove(Message):
        def __init__(self, delta: int) -> None:
            super().__init__()
            self.delta = delta

    class SlashOpened(Message):
        """Posted when ``/`` is typed into an empty buffer."""

    def __init__(self, **kwargs) -> None:
        super().__init__(
            soft_wrap=True,
            tab_behavior="focus",
            show_line_numbers=False,
            theme="css",
            **kwargs,
        )

    async def _on_key(self, event) -> None:  # noqa: ANN001 - Textual event type
        key = event.key
        if key == "enter":
            event.stop()
            event.prevent_default()
            self.post_message(self.Submitted(self.text))
            return
        if key in ("shift+enter", "ctrl+j"):
            event.stop()
            event.prevent_default()
            self.insert("\n")
            return
        if key in ("up", "down") and self.document.line_count == 1:
            event.stop()
            event.prevent_default()
            self.post_message(self.HistoryMove(-1 if key == "up" else 1))
            return
        if event.character == "/" and not self.text:
            self.post_message(self.SlashOpened())
        await super()._on_key(event)


class Composer(Horizontal):
    """The composer box. Owns input history; posts submissions upward."""

    class Submitted(Message):
        def __init__(self, text: str) -> None:
            super().__init__()
            self.text = text

    def __init__(self) -> None:
        super().__init__()
        self._history: list[str] = []
        self._index: int | None = None
        self._draft = ""
        #: While the slash overlay is open it owns enter and the arrow keys,
        #: so the composer lets those messages bubble to the app untouched.
        self.capture = False

    def compose(self):
        yield Static(">", id="composer-glyph")
        yield ComposerInput(id="composer-input")

    @property
    def input(self) -> ComposerInput:
        return self.query_one(ComposerInput)

    @property
    def history(self) -> list[str]:
        return list(self._history)

    @property
    def text(self) -> str:
        return self.input.text

    def focus_input(self) -> None:
        self.input.focus()

    def set_text(self, text: str) -> None:
        self.input.load_text(text)
        self.input.move_cursor(self.input.document.end)

    def clear(self) -> None:
        self.input.load_text("")

    def on_composer_input_submitted(self, message: ComposerInput.Submitted) -> None:
        if self.capture:
            return
        message.stop()
        text = message.text.strip()
        self.clear()
        self._index = None
        self._draft = ""
        if not text:
            return
        if not self._history or self._history[-1] != text:
            self._history.append(text)
        self.post_message(self.Submitted(text))

    def on_composer_input_history_move(
        self, message: ComposerInput.HistoryMove
    ) -> None:
        if self.capture:
            return
        message.stop()
        if not self._history:
            return
        if message.delta < 0:
            if self._index is None:
                self._draft = self.input.text
                self._index = len(self._history) - 1
            else:
                self._index = max(0, self._index - 1)
            self.set_text(self._history[self._index])
        else:
            if self._index is None:
                return
            self._index += 1
            if self._index >= len(self._history):
                self._index = None
                self.set_text(self._draft)
            else:
                self.set_text(self._history[self._index])
