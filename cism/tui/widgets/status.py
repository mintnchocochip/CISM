"""The one-line status bar under the composer, e.g. ``qwen2.5-7b · phase:
recon · ctx 12.4k/32k (38%) · 47 tok/s``. Every field has a short form and
a priority; when the line doesn't fit, low-priority fields degrade to
short form then drop out. Priority-1 fields always survive."""

from __future__ import annotations

from dataclasses import dataclass

from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static

from ._fmt import capacity as fmt_capacity
from ._fmt import tokens as fmt_tokens

SEPARATOR = " · "
WARN_RATIO = 0.8

#: Fields at this priority are never dropped.
ESSENTIAL = 1


@dataclass(frozen=True, slots=True)
class Segment:
    """One field of the status line, with a fallback rendering. ``label`` is
    the dim prefix shared by both forms, kept separate only so it can be
    styled down against the value."""

    key: str
    full: str
    short: str
    priority: int = 3
    style: str = "status--value"
    label: str = ""

    def text(self, *, compact: bool) -> str:
        return self.short if compact else self.full


def elide(segments: list[Segment], width: int) -> list[Segment]:
    """Fit ``segments`` into ``width`` columns in two passes: lowest-priority
    segments switch to short form first, then whole segments drop. Pure and
    width-only, so it's testable at any terminal size without a widget."""

    def measure(chosen: list[Segment], compact: set[str]) -> int:
        if not chosen:
            return 0
        parts = [s.text(compact=s.key in compact) for s in chosen]
        return sum(len(p) for p in parts) + len(SEPARATOR) * (len(parts) - 1)

    kept = list(segments)
    compact: set[str] = set()

    if measure(kept, compact) <= width:
        return kept

    # Pass 1 — shorten, worst priority first.
    for segment in sorted(kept, key=lambda s: -s.priority):
        if segment.full != segment.short:
            compact.add(segment.key)
            if measure(kept, compact) <= width:
                return [_reduce(s, compact) for s in kept]

    # Pass 2 — drop, worst priority first, never touching the essentials.
    droppable = [s for s in sorted(kept, key=lambda s: -s.priority)
                 if s.priority > ESSENTIAL]
    for segment in droppable:
        kept = [s for s in kept if s.key != segment.key]
        if measure(kept, compact) <= width:
            break

    return [_reduce(s, compact) for s in kept]


def _reduce(segment: Segment, compact: set[str]) -> Segment:
    if segment.key not in compact:
        return segment
    return Segment(
        segment.key,
        segment.short,
        segment.short,
        segment.priority,
        segment.style,
        segment.label if segment.short.startswith(segment.label) else "",
    )


class StatusBar(Static):
    """Single-line run state summary."""

    COMPONENT_CLASSES = {
        "status--key",
        "status--value",
        "status--sep",
        "status--auto",
        "status--warn",
        "status--model",
        "status--target",
    }

    model: reactive[str] = reactive("")
    phase: reactive[str] = reactive("recon")
    ctx_used: reactive[int] = reactive(0)
    ctx_max: reactive[int] = reactive(32_768)
    tokens_per_second: reactive[float] = reactive(0.0)
    target_os: reactive[str] = reactive("")
    target_stack: reactive[tuple[str, ...]] = reactive(())
    depg_nodes: reactive[int] = reactive(0)
    mem_t1: reactive[int] = reactive(0)
    mem_t2: reactive[int] = reactive(0)
    mem_t3: reactive[int] = reactive(0)
    auto: reactive[bool] = reactive(True)
    notice: reactive[str] = reactive("")

    @property
    def context_ratio(self) -> float:
        return self.ctx_used / self.ctx_max if self.ctx_max else 0.0

    def segments(self) -> list[Segment]:
        """The status line as data, before any width is considered."""
        out: list[Segment] = []

        if self.model:
            out.append(Segment("model", self.model, self.model, 1, "status--model"))

        out.append(
            Segment("phase", f"phase: {self.phase}", self.phase, 1, label="phase: ")
        )

        used = fmt_tokens(self.ctx_used)
        cap = fmt_capacity(self.ctx_max)
        style = "status--warn" if self.context_ratio >= WARN_RATIO else "status--value"
        out.append(
            Segment(
                "ctx",
                f"ctx {used}/{cap} ({self.context_ratio * 100:.0f}%)",
                f"ctx {used}/{cap}",
                1,
                style,
                label="ctx ",
            )
        )

        if self.tokens_per_second > 0:
            rate = f"{self.tokens_per_second:.0f}"
            out.append(Segment("rate", f"{rate} tok/s", f"{rate}t/s", 2))

        if self.target_os or self.target_stack:
            parts = [self.target_os, *self.target_stack]
            full = "·".join(p for p in parts if p)
            out.append(
                Segment("target", full, self.target_os or full, 2, "status--target")
            )

        out.append(
            Segment(
                "depg",
                f"depg {self.depg_nodes} nodes",
                f"depg {self.depg_nodes}",
                label="depg ",
            )
        )

        total = self.mem_t1 + self.mem_t2 + self.mem_t3
        out.append(
            Segment(
                "mem",
                f"mem T1:{self.mem_t1} T2:{self.mem_t2} T3:{self.mem_t3}",
                f"mem {total}",
                label="mem ",
            )
        )

        mode = "⏵⏵ auto" if self.auto else "⏸ manual"
        out.append(Segment("mode", mode, mode.split(" ")[0], 1, "status--auto"))

        if self.notice:
            out.append(Segment("notice", self.notice, self.notice, 1, "status--warn"))

        return out

    def render(self) -> Text:
        width = self.content_size.width or 80
        out = Text()
        separator = self.get_component_rich_style("status--sep")
        key_style = self.get_component_rich_style("status--key")
        for index, segment in enumerate(elide(self.segments(), width)):
            if index:
                out.append(SEPARATOR, style=separator)
            body = segment.full
            if segment.label and body.startswith(segment.label):
                out.append(segment.label, style=key_style)
                body = body[len(segment.label) :]
            out.append(body, style=self.get_component_rich_style(segment.style))
        return out

    def on_resize(self) -> None:
        self.refresh(layout=True)
