"""cism/depg/linking.py: which prior node a new call actually depended on."""

from __future__ import annotations

from cism.depg.evidence import Evidence
from cism.depg.graph import Graph
from cism.depg.linking import find_precondition
from cism.depg.node import Node


def _node(id: str, target: str, signal: str, exit_signal: str = "") -> Node:
    evidence = (
        [Evidence(timestamp="t", tool="nmap", exit_signal=exit_signal, tier="T2")]
        if exit_signal
        else []
    )
    return Node(id=id, cause_class="open-port", target=target, signal=signal, evidence=evidence)


def test_matches_a_call_argument_against_a_prior_nodes_evidence() -> None:
    graph = Graph()
    graph.upsert_node(_node("port22", "10.0.0.5", "22/tcp", "22/tcp open ssh"))
    graph.upsert_node(_node("port80", "10.0.0.5", "80/tcp", "80/tcp open http"))
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    match = find_precondition(graph, "10.0.0.5", call)

    assert match is not None
    assert match.id == "port22"


def test_falls_back_to_the_last_touched_node_on_the_target_when_nothing_matches() -> None:
    graph = Graph()
    graph.upsert_node(_node("port22", "10.0.0.5", "22/tcp", "22/tcp open ssh"))
    graph.upsert_node(_node("port80", "10.0.0.5", "80/tcp", "80/tcp open http"))
    call = {"id": "c1", "name": "some-tool", "args": {"target": "10.0.0.5"}}

    match = find_precondition(graph, "10.0.0.5", call)

    assert match is not None
    assert match.id == "port80"


def test_returns_none_on_an_empty_target() -> None:
    graph = Graph()
    call = {"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}

    assert find_precondition(graph, "10.0.0.5", call) is None


def test_returns_none_when_call_is_none() -> None:
    graph = Graph()
    graph.upsert_node(_node("port22", "10.0.0.5", "22/tcp", "22/tcp open ssh"))

    assert find_precondition(graph, "10.0.0.5", None) is not None  # still falls back to last-touched


def test_prefers_an_exact_word_match_over_a_substring_collision() -> None:
    """nmap names one service "ccproxy-ftp" — a real, different service that
    happens to contain "ftp" as a substring. hydra's service="ftp" must
    still land on the genuine ftp node, not this one, in a live run against
    metasploitable2 (which exposes both port 21/ftp and port 2121/ccproxy-ftp)."""
    graph = Graph()
    graph.upsert_node(_node("port21", "10.0.0.5", "21/tcp", "21/tcp ftp"))
    graph.upsert_node(_node("port2121", "10.0.0.5", "2121/tcp", "2121/tcp ccproxy-ftp"))
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ftp"}}

    match = find_precondition(graph, "10.0.0.5", call)

    assert match is not None
    assert match.id == "port21"


def test_matches_a_url_shaped_argument_by_its_scheme_word() -> None:
    """A tool called with a full URL (nikto's target="http://10.0.0.5") must
    still match the http node by its embedded "http" word, not miss every
    candidate and fall back to whatever port was upserted last — that
    fallback is exactly what mis-linked nikto's web findings under an
    unrelated port node (e.g. irc) in a live run."""
    graph = Graph()
    graph.upsert_node(_node("port22", "10.0.0.5", "22/tcp", "22/tcp open ssh"))
    graph.upsert_node(_node("port80", "10.0.0.5", "80/tcp", "80/tcp open http"))
    graph.upsert_node(_node("port6667", "10.0.0.5", "6667/tcp", "6667/tcp open irc"))
    call = {"id": "c1", "name": "nikto", "args": {"target": "http://10.0.0.5"}}

    match = find_precondition(graph, "10.0.0.5", call)

    assert match is not None
    assert match.id == "port80"
