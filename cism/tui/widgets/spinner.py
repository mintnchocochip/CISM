"""The working indicator that sits directly above the composer.

``✳ Enumerating… (12s · ↑1.2k tokens · esc to interrupt)``

The glyph cycles through an asterisk set, the verb rotates through a themed
word list chosen by the current PTES phase, and the elapsed and token counters
update live off ``TokenDelta`` events.
"""

from __future__ import annotations

import time

from rich.text import Text
from textual.widgets import Static

from ._fmt import elapsed as fmt_elapsed
from ._fmt import tokens as fmt_tokens

GLYPHS = ("·", "✢", "✳", "✶", "✻", "✽", "✻", "✶", "✳", "✢")

VERBS: dict[str, tuple[str, ...]] = {
    "pre-engagement": ("Scoping", "Framing", "Bounding"),
    "recon": ("Probing", "Sweeping", "Fingerprinting", "Enumerating", "Mapping"),
    "intelligence-gathering": (
        "Probing",
        "Sweeping",
        "Fingerprinting",
        "Enumerating",
        "Harvesting",
    ),
    "threat-modeling": ("Modelling", "Ranking", "Triaging", "Weighing"),
    "vulnerability-analysis": (
        "Analysing",
        "Cross-referencing",
        "Verifying",
        "Correlating",
    ),
    "exploitation": ("Exploiting", "Injecting", "Chaining", "Escalating", "Pivoting"),
    "post-exploitation": ("Harvesting", "Tunnelling", "Staging", "Looting"),
    "reporting": ("Summarising", "Drafting", "Scoring", "Consolidating"),
}

FALLBACK_VERBS = ("Working", "Thinking", "Reasoning")

FRAME_INTERVAL = 0.12
VERB_ROTATION = 4.0


class WorkingIndicator(Static):
    """Animated single-line activity indicator."""

    COMPONENT_CLASSES = {"work--glyph", "work--verb", "work--meta"}

    def __init__(self) -> None:
        super().__init__()
        self._frame = 0
        self._verb_index = 0
        self._started = 0.0
        self._last_rotate = 0.0
        self._tokens = 0
        self._token_base = 0
        self._phase = "recon"
        self._timer = None
        self._now = time.monotonic

    @property
    def active(self) -> bool:
        return self.has_class("-active")

    @property
    def verb(self) -> str:
        words = VERBS.get(self._phase) or FALLBACK_VERBS
        return words[self._verb_index % len(words)]

    def set_phase(self, phase: str) -> None:
        self._phase = phase
        self._verb_index = 0
        if self.active:
            self.refresh()

    def set_tokens(self, total: int) -> None:
        """Set the running total; the indicator shows tokens since it started."""
        self._tokens = max(total - self._token_base, 0)
        if self.active:
            self.refresh()

    def start(self, phase: str | None = None, token_base: int = 0) -> None:
        if phase is not None:
            self._phase = phase
        self._token_base = token_base
        self._tokens = 0
        self._started = self._now()
        self._last_rotate = self._started
        self._frame = 0
        self._verb_index = 0
        self.add_class("-active")
        if self._timer is None:
            self._timer = self.set_interval(FRAME_INTERVAL, self._tick)
        self.refresh()

    def stop(self) -> None:
        self.remove_class("-active")
        if self._timer is not None:
            self._timer.stop()
            self._timer = None

    def _tick(self) -> None:
        self._frame += 1
        now = self._now()
        if now - self._last_rotate >= VERB_ROTATION:
            self._last_rotate = now
            self._verb_index += 1
        self.refresh()

    def render(self) -> Text:
        glyph_style = self.get_component_rich_style("work--glyph")
        verb_style = self.get_component_rich_style("work--verb")
        meta_style = self.get_component_rich_style("work--meta")

        seconds = max(self._now() - self._started, 0.0) if self._started else 0.0
        out = Text()
        out.append(f"{GLYPHS[self._frame % len(GLYPHS)]} ", style=glyph_style)
        out.append(f"{self.verb}… ", style=verb_style)
        out.append(
            f"({fmt_elapsed(seconds)} · ↑{fmt_tokens(self._tokens)} tokens"
            f" · esc to interrupt)",
            style=meta_style,
        )
        return out
