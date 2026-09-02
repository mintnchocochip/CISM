"""cism/depg/extractors.py: real parsing for nmap open ports and hydra
credential attempts."""

from __future__ import annotations

from langchain_core.messages import ToolMessage

from cism.depg.extractors import HydraExtractor, NmapExtractor
from cism.depg.graph import Graph

_NMAP_OUTPUT = """
Starting Nmap 7.94
Nmap scan report for 10.0.0.5
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  closed https
Nmap done: 1 IP address (1 host up) scanned in 1.2 seconds
"""

_HYDRA_SUCCESS = "[22][ssh] host: 10.0.0.5   login: admin   password: hunter2"
_HYDRA_FAILURE = "1 of 1 target completed, 0 valid passwords found"


def test_nmap_extractor_produces_one_node_per_open_port() -> None:
    message = ToolMessage(content=_NMAP_OUTPUT, tool_call_id="c1", name="nmap")
    call = {"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}

    extraction = NmapExtractor().extract(call, message, Graph(), "10.0.0.5")

    signals = {n.signal for n in extraction.nodes}
    assert signals == {"22/tcp", "80/tcp"}
    assert all(n.cause_class == "open-port" for n in extraction.nodes)
    assert all(n.evidence[0].tier == "T2" for n in extraction.nodes)
    assert all(n.evidence[0].verdict == "alive" for n in extraction.nodes)


def test_nmap_extractor_ignores_closed_ports() -> None:
    message = ToolMessage(content=_NMAP_OUTPUT, tool_call_id="c1", name="nmap")
    call = {"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}

    extraction = NmapExtractor().extract(call, message, Graph(), "10.0.0.5")

    assert "443/tcp" not in {n.signal for n in extraction.nodes}


def test_hydra_extractor_success_is_a_t1_credential_node() -> None:
    message = ToolMessage(content=_HYDRA_SUCCESS, tool_call_id="c1", name="hydra")
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    extraction = HydraExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "credential-found"
    assert node.signal == "admin:hunter2"
    assert node.evidence[0].tier == "T1"
    assert node.evidence[0].verdict == "alive"


def test_hydra_extractor_failure_is_a_t3_tombstone() -> None:
    message = ToolMessage(content=_HYDRA_FAILURE, tool_call_id="c1", name="hydra")
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    extraction = HydraExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "credential-attempt"
    assert node.evidence[0].tier == "T3"
    assert node.evidence[0].verdict == "dead"


def test_hydra_extractor_treats_an_error_status_as_a_failed_attempt() -> None:
    message = ToolMessage(
        content="ToolTimeoutError: hydra: timed out after 120s",
        tool_call_id="c1", name="hydra", status="error",
    )
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    extraction = HydraExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "credential-attempt"
    assert node.evidence[0].verdict == "dead"


def test_extractors_dict_keys_are_known_tool_names() -> None:
    """One cheap test catches a typo in EXTRACTORS at CI time instead of it
    silently falling through to the default extractor at runtime — hydra
    is included explicitly since it has no CATALOG row (design doc §5)."""
    from cism.agent.tools.catalog import CATALOG
    from cism.depg.extractors import EXTRACTORS

    assert set(EXTRACTORS) <= set(CATALOG) | {"hydra"}


def test_extractors_maps_nmap_and_hydra_to_their_real_extractors() -> None:
    from cism.depg.extractors import EXTRACTORS

    assert isinstance(EXTRACTORS["nmap"], NmapExtractor)
    assert isinstance(EXTRACTORS["hydra"], HydraExtractor)
