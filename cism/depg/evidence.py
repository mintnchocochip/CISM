"""The working Evidence type — richer than the frozen wire format, carrying
fields (verdict, call_id) the TUI table never shows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from cism.tui.events import Evidence as WireEvidence
from cism.tui.events import Tier

__all__ = ["Evidence", "Source", "Verdict"]

Verdict = Literal["alive", "dead", "inconclusive"]

#: How the tier was assigned: "deterministic" (regex parser), "llm" (model
#: judgment call, even if grounded), "unverified" (GenericExtractor's blind
#: fallback). No default — every extractor must declare it.
Source = Literal["deterministic", "llm", "unverified"]


@dataclass(slots=True)
class Evidence:
    timestamp: str
    tool: str
    exit_signal: str
    tier: Tier
    source: Source
    verdict: Verdict = "alive"
    call_id: str = ""

    def to_event(self) -> WireEvidence:
        return WireEvidence(
            timestamp=self.timestamp,
            tool=self.tool,
            exit_signal=self.exit_signal,
            tier=self.tier,
        )
