"""cism/depg/node.py: the derived identity key and the widened schema."""

from __future__ import annotations

from cism.depg.evidence import Evidence
from cism.depg.node import Node, derive_node_id


def test_derive_node_id_combines_cause_class_target_and_signal() -> None:
    assert derive_node_id("open-port", "10.0.0.5", "22/tcp") == "open-port:10.0.0.5:22/tcp"


def test_different_signal_on_same_target_and_class_is_a_different_id() -> None:
    a = derive_node_id("open-port", "10.0.0.5", "22/tcp")
    b = derive_node_id("open-port", "10.0.0.5", "80/tcp")
    assert a != b


def test_node_to_event_maps_working_evidence_to_wire_evidence() -> None:
    node = Node(
        id="open-port:10.0.0.5:22/tcp", cause_class="open-port", target="10.0.0.5",
        signal="22/tcp",
        evidence=[Evidence(timestamp="t", tool="nmap", exit_signal="22/tcp open ssh", tier="T2")],
    )
    wire = node.to_event()

    assert wire.id == "open-port:10.0.0.5:22/tcp"
    assert wire.evidence[0].exit_signal == "22/tcp open ssh"


def test_node_state_defaults_untested_and_accepts_contested() -> None:
    node = Node(id="n1", cause_class="c", target="t", signal="s", state="contested")
    assert node.state == "contested"
