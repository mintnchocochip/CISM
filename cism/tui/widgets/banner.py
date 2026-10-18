"""The startup banner: ASCII wordmark, identity line, and a usage hint.

Lives until the operator's first submission and is then removed for good —
after that the transcript is the surface, and a banner left above it is
just dead rows. It is a sibling of the transcript, not an entry inside it,
so ``/export`` and ``/clear`` never see it.
"""

from __future__ import annotations

from rich.console import RenderableType
from rich.text import Text
from textual.widgets import Static

__all__ = ["Banner"]

_WORDMARK = (
    r" ██████╗██╗███████╗███╗   ███╗",
    r"██╔════╝██║██╔════╝████╗ ████║",
    r"██║     ██║███████╗██╔████╔██║",
    r"██║     ██║╚════██║██║╚██╔╝██║",
    r"╚██████╗██║███████║██║ ╚═╝ ██║",
    r" ╚═════╝╚═╝╚══════╝╚═╝     ╚═╝",
)

#: Narrower than this and the wordmark wraps into noise, so a plain title
#: is used instead. The art is 30 cells wide; the margin covers the gutter.
MIN_WORDMARK_WIDTH = 34

#: Full forms, then the short forms used once the terminal is too narrow
#: to hold them — same degrade-don't-wrap approach the status bar takes.
#: The name has no short form: below the wordmark's width the art itself
#: is already the acronym, so the expansion line is dropped instead.
_NAME = "Cyber Investigation State Memory"
_TAGLINE = "SLM-driven VAPT agent · inference stays on this machine"
_TAGLINE_SHORT = "SLM-driven VAPT agent"
_HINT = "describe a target to begin · /help for commands · ctrl+c twice to quit"
_HINT_SHORT = "/help for commands"


class Banner(Static):
    """Pre-first-prompt splash. Degrades to a single title line when the
    terminal is too narrow to hold the wordmark."""

    COMPONENT_CLASSES = {
        "banner--art",
        "banner--name",
        "banner--tagline",
        "banner--hint",
    }

    def render(self) -> RenderableType:
        art = self.get_component_rich_style("banner--art")
        name = self.get_component_rich_style("banner--name")
        tagline = self.get_component_rich_style("banner--tagline")
        hint = self.get_component_rich_style("banner--hint")

        # size.width is 0 before the first layout pass; treat that as wide
        # enough rather than flashing the narrow form on the way up.
        width = self.size.width or MIN_WORDMARK_WIDTH

        out = Text(no_wrap=True, overflow="ellipsis")
        if width >= MIN_WORDMARK_WIDTH:
            for line in _WORDMARK:
                out.append(line + "\n", art)
            out.append("\n")
            # The wordmark spells the acronym, so the name line expands it.
            _line(out, width, name, _NAME, _NAME)
        else:
            out.append("CISM\n", art)
        _line(out, width, tagline, _TAGLINE, _TAGLINE_SHORT)
        out.append("\n")
        _line(out, width, hint, _HINT, _HINT_SHORT, last=True)
        return out


def _line(out: Text, width: int, style, full: str, short: str, last: bool = False) -> None:
    """Append the longest form that fits, or nothing at all when even the
    short form would not — better a missing subtitle than a ragged wrap."""
    text = full if len(full) <= width else short
    if len(text) > width:
        return
    out.append(text if last else text + "\n", style)
