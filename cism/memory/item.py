"""The working memory item — richer than the frozen MemoryRow wire format.

Mirrors the Node/DEPGNode split in cism.depg: age_s is computed at emission
time from a stored wall-clock creation time, which MemoryRow (frozen, part
of the wire contract) has no field for.
"""

from __future__ import annotations

from dataclasses import dataclass

from cism.tui.events import MemoryRow, Tier

__all__ = ["MemoryItem"]

_BASE_SALIENCE = 1.0


@dataclass(slots=True)
class MemoryItem:
    id: str
    tier: Tier
    phase_tag: str
    snippet: str
    created_at: float
    hits: int = 1

    def to_event(self, now: float) -> MemoryRow:
        return MemoryRow(
            id=self.id,
            tier=self.tier,
            phase_tag=self.phase_tag,
            salience=_BASE_SALIENCE,
            age_s=max(0.0, now - self.created_at),
            snippet=self.snippet,
            hits=self.hits,
        )
