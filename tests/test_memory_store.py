"""cism/memory/store.py: dedup by key, hits increment, age computed at
snapshot time from a stored creation timestamp."""

from __future__ import annotations

from cism.memory.store import MemoryStore, memory_key


def test_a_new_key_creates_a_fresh_item_with_hits_one() -> None:
    store = MemoryStore()
    item = store.upsert("k1", "T2", "recon", "found something")

    assert item.hits == 1
    assert item.tier == "T2"


def test_upserting_the_same_key_again_increments_hits_not_a_new_row() -> None:
    store = MemoryStore()
    store.upsert("k1", "T2", "recon", "found something")
    store.upsert("k1", "T2", "recon", "found something")

    assert len(store.items) == 1
    assert store.items["k1"].hits == 2


def test_a_different_key_is_a_separate_row() -> None:
    store = MemoryStore()
    store.upsert("k1", "T2", "recon", "a")
    store.upsert("k2", "T2", "recon", "b")

    assert len(store.items) == 2


def test_repeated_upsert_keeps_the_original_created_at() -> None:
    store = MemoryStore()
    first = store.upsert("k1", "T2", "recon", "a")
    original_created_at = first.created_at
    store.upsert("k1", "T2", "recon", "a")

    assert store.items["k1"].created_at == original_created_at


def test_snapshot_computes_age_from_created_at() -> None:
    store = MemoryStore()
    item = store.upsert("k1", "T2", "recon", "a")

    rows = store.snapshot(now=item.created_at + 30.0)

    assert rows[0].age_s == 30.0
    assert rows[0].salience == 1.0


def test_from_state_copies_rather_than_aliases() -> None:
    store = MemoryStore()
    store.upsert("k1", "T2", "recon", "a")

    rebuilt = MemoryStore.from_state(store.items)
    rebuilt.upsert("k2", "T2", "recon", "b")

    assert "k2" not in store.items


def test_memory_key_normalizes_whitespace_and_case() -> None:
    a = memory_key("narration", "recon", "  Some Text  ")
    b = memory_key("narration", "recon", "some text")
    assert a == b


def test_salience_is_derived_from_source_type_not_a_constant() -> None:
    store = MemoryStore()
    depg_item = store.upsert("k1", "T2", "recon", "a", source_type="depg_node")
    store.upsert("k2", "T2", "recon", "b", source_type="narration")

    rows = store.snapshot(now=depg_item.created_at)
    by_id = {row.id: row for row in rows}

    assert by_id["k1"].salience != by_id["k2"].salience
    assert by_id["k1"].salience == 1.2
    assert by_id["k2"].salience == 0.8


def test_unknown_source_type_falls_back_to_the_default_salience() -> None:
    store = MemoryStore()
    item = store.upsert("k1", "T2", "recon", "a", source_type="some-future-source")

    row = store.snapshot(now=item.created_at)[0]

    assert row.salience == 1.0
