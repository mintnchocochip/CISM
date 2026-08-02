"""The one-line status bar that sits under the composer.

``phase: recon · ctx 12.4k/32k (38%) · depg 47 nodes · mem T1:8 T2:31 · ⏵⏵ auto``

No border, dim text. Every field is a reactive, so the pump can set them
individually and the line repaints itself.
"""

from __future__ import annotations

from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static

from ._fmt import capacity as fmt_capacity
from ._fmt import tokens as fmt_tokens

SEPARATOR = " · "
WARN_RATIO = 0.8


class StatusBar(Static):
    """Single-line run state summary."""

    COMPONENT_CLASSES = {
        "status--key",
        "status--value",
        "status--sep",
        "status--auto",
        "status--warn",
    }

    phase: reactive[str] = reactive("recon")
    ctx_used: reactive[int] = reactive(0)
    ctx_max: reactive[int] = reactive(32_768)
    depg_nodes: reactive[int] = reactive(0)
    mem_t1: reactive[int] = reactive(0)
    mem_t2: reactive[int] = reactive(0)
    auto: reactive[bool] = reactive(True)
    notice: reactive[str] = reactive("")

    def render(self) -> Text:
        key = self.get_component_rich_style("status--key")
        value = self.get_component_rich_style("status--value")
        sep = self.get_component_rich_style("status--sep")
        auto_style = self.get_component_rich_style("status--auto")
        warn = self.get_component_rich_style("status--warn")

        ratio = self.ctx_used / self.ctx_max if self.ctx_max else 0.0
        ctx_style = warn if ratio >= WARN_RATIO else value

        out = Text()
        out.append("phase: ", style=key)
        out.append(self.phase, style=value)

        out.append(SEPARATOR, style=sep)
        out.append("ctx ", style=key)
        out.append(
            f"{fmt_tokens(self.ctx_used)}/{fmt_capacity(self.ctx_max)}"
            f" ({ratio * 100:.0f}%)",
            style=ctx_style,
        )

        out.append(SEPARATOR, style=sep)
        out.append("depg ", style=key)
        out.append(f"{self.depg_nodes} nodes", style=value)

        out.append(SEPARATOR, style=sep)
        out.append("mem ", style=key)
        out.append(f"T1:{self.mem_t1} T2:{self.mem_t2}", style=value)

        out.append(SEPARATOR, style=sep)
        out.append("⏵⏵ auto" if self.auto else "⏸ manual", style=auto_style)

        if self.notice:
            out.append(SEPARATOR, style=sep)
            out.append(self.notice, style=warn)
        return out
