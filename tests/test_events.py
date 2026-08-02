"""The event contract: serialisation, value objects, and the salience model."""

from __future__ import annotations

import math

import pytest

from cism.tui.events import (
    EVENT_TYPES,
    DEPGEdge,
    DEPGNode,
    DEPGUpdated,
    Evidence,
    Interrupted,
    MemoryRow,
    MemoryUpdated,
    Narration,
    PhaseChanged,
    RunFinished,
    RunStarted,
    SalienceTerms,
    TokenDelta,
    ToolFailed,
    ToolFinished,
    ToolOutput,
    ToolStarted,
    decode,
    encode,
)

SIMPLE_EVENTS = [
    RunStarted("run-1", "recon"),
    RunFinished("run-1", True),
    Narration("e1", "hello", False),
    ToolStarted("c1", "nmap", "-sV"),
    ToolOutput("c1", "chunk"),
    ToolFinished("c1", "6 open ports", 1247, "T1", 0.91),
    ToolFailed("c1", "timeout", "traceback text"),
    PhaseChanged("exploitation", "PTES"),
    TokenDelta(12, 1200, 4096, 32768),
    Interrupted("user interrupt"),
]


@pytest.mark.parametrize("event", SIMPLE_EVENTS, ids=lambda e: type(e).__name__)
def test_simple_events_round_trip(event) -> None:
    assert decode(encode(event)) == event


def test_every_event_type_is_registered() -> None:
    assert set(EVENT_TYPES) == {
        "RunStarted",
        "RunFinished",
        "Narration",
        "ToolStarted",
        "ToolOutput",
        "ToolFinished",
        "ToolFailed",
        "PhaseChanged",
        "DEPGUpdated",
        "MemoryUpdated",
        "TokenDelta",
        "Interrupted",
        "SessionState",
    }


def test_depg_round_trip_preserves_nested_value_objects() -> None:
    event = DEPGUpdated(
        nodes=(
            DEPGNode(
                "n1",
                "auth-bypass",
                "10.0.0.5:80/admin",
                0.72,
                "blocked",
                3,
                (Evidence("12:04:11", "nuclei", "403", "T1"),),
            ),
        ),
        edges=(DEPGEdge("n1", "n2", 0.44),),
    )
    restored = decode(encode(event))
    assert restored == event
    assert isinstance(restored.nodes, tuple)
    assert isinstance(restored.nodes[0].evidence[0], Evidence)
    assert isinstance(restored.edges[0], DEPGEdge)


def test_memory_round_trip_preserves_terms() -> None:
    event = MemoryUpdated(
        rows=(MemoryRow("m1", "T1", "recon", 0.83, 214.0, "ssh banner", 3),),
        terms=SalienceTerms({"T1": 1.4, "T2": 1.0, "T3": 0.6}, 0.0012, 0.05),
    )
    restored = decode(encode(event))
    assert restored == event
    assert isinstance(restored.terms, SalienceTerms)


def test_decode_rejects_unknown_event_type() -> None:
    with pytest.raises(KeyError):
        decode({"type": "NotAnEvent"})


def test_sequence_numbers_increase() -> None:
    first = Narration("e1", "a")
    second = Narration("e1", "b")
    assert second.seq > first.seq


def test_node_label_matches_the_specified_format() -> None:
    node = DEPGNode("n1", "auth-bypass", "10.0.0.5:80/admin", 0.72, "blocked", 3)
    assert node.label() == (
        "[auth-bypass] 10.0.0.5:80/admin — generality γ=0.72 (3 downstream)"
    )


def test_salience_score_follows_the_documented_equation() -> None:
    terms = SalienceTerms({"T1": 1.4, "T2": 1.0, "T3": 0.6}, 0.0012, 0.05)
    row = MemoryRow("m1", "T1", "recon", 0.90, 200.0, "snippet", 2)
    expected = 1.4 * 0.90 * math.exp(-0.0012 * 200.0) + 0.05 * 2
    assert terms.score(row) == pytest.approx(expected)


def test_salience_decays_with_age() -> None:
    terms = SalienceTerms({"T1": 1.4}, 0.0012, 0.0)
    young = MemoryRow("a", "T1", "recon", 0.9, 10.0, "x")
    old = MemoryRow("b", "T1", "recon", 0.9, 5000.0, "x")
    assert terms.score(young) > terms.score(old)


def test_equation_substitutes_live_term_values() -> None:
    terms = SalienceTerms({"T1": 1.4}, 0.0012, 0.05)
    row = MemoryRow("m1", "T1", "recon", 0.83, 214.0, "snippet", 3)
    rendered = terms.equation(row)
    assert "1.4" in rendered and "0.83" in rendered and "214" in rendered
    assert rendered.endswith(f"{terms.score(row):.3f}")
