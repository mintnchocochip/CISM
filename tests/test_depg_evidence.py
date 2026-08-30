"""cism/depg/evidence.py: the working Evidence carries verdict/call_id that
the wire format doesn't; to_event() must drop them."""

from __future__ import annotations

from cism.depg.evidence import Evidence


def test_to_event_drops_verdict_and_call_id() -> None:
    evidence = Evidence(
        timestamp="12:00:00", tool="nmap", exit_signal="22/tcp open ssh",
        tier="T2", verdict="alive", call_id="call-1",
    )
    wire = evidence.to_event()

    assert wire.timestamp == "12:00:00"
    assert wire.tool == "nmap"
    assert wire.exit_signal == "22/tcp open ssh"
    assert wire.tier == "T2"
    assert not hasattr(wire, "verdict")
    assert not hasattr(wire, "call_id")


def test_verdict_and_call_id_default_for_call_sites_that_do_not_care() -> None:
    evidence = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T3")
    assert evidence.verdict == "alive"
    assert evidence.call_id == ""
