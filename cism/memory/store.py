"""MemoryStore: the working container memory_update mutates each step,
mirroring cism.depg.graph.Graph's role for the DEPG.
"""

from __future__ import annotations

import time

from cism.memory.item import MemoryItem
from cism.tui.events import MemoryRow, SalienceTerms, Tier

__all__ = ["DEFAULT_SALIENCE_TERMS", "MemoryStore", "memory_key"]

#: Matches the coefficients already hand-authored in demo/recon_run.jsonl,
#: so a live run and the replay demo decay memory identically.
DEFAULT_SALIENCE_TERMS = SalienceTerms(
    tier_weight={"T1": 1.4, "T2": 1.0, "T3": 0.6},
    decay_lambda=0.0012,
    hit_bonus=0.05,
)


def memory_key(source_type: str, phase_tag: str, snippet: str) -> str:
    """Dedup key for a non-DEPG memory candidate, so a recurring block or
    narration collapses onto one row instead of spamming the table."""
    normalized = " ".join(snippet.split()).lower()
    return f"{source_type}:{phase_tag}:{normalized}"


class MemoryStore:
    def __init__(self, items: dict[str, MemoryItem] | None = None) -> None:
        self.items: dict[str, MemoryItem] = dict(items) if items else {}

    @classmethod
    def from_state(cls, items: dict[str, MemoryItem]) -> MemoryStore:
        return cls(dict(items))

    def upsert(self, key: str, tier: Tier, phase_tag: str, snippet: str) -> MemoryItem:
        """A matching key bumps hits and keeps the original creation time,
        so age reflects how long this has been true. A new key inserts fresh."""
        existing = self.items.get(key)
        if existing is None:
            item = MemoryItem(
                id=key, tier=tier, phase_tag=phase_tag, snippet=snippet,
                created_at=time.time(), hits=1,
            )
            self.items[key] = item
            return item
        existing.hits += 1
        return existing

    def snapshot(self, now: float | None = None) -> tuple[MemoryRow, ...]:
        now = time.time() if now is None else now
        return tuple(item.to_event(now) for item in self.items.values())
