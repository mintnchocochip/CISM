"""cism/depg/extract.py: GenericExtractor now handles failures too, instead
of never being called for them."""

from __future__ import annotations

from langchain_core.messages import ToolMessage

from cism.depg.extract import GenericExtractor
from cism.depg.graph import Graph


def test_generic_extractor_marks_a_successful_call_alive() -> None:
    message = ToolMessage(content="some output", tool_call_id="c1", name="whatweb")

    extraction = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "whatweb"
    assert node.evidence[0].tier == "T3"
    assert node.evidence[0].verdict == "alive"


def test_generic_extractor_marks_a_failed_call_dead() -> None:
    message = ToolMessage(content="boom", tool_call_id="c1", name="whatweb", status="error")

    extraction = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.evidence[0].verdict == "dead"


def test_generic_extractor_same_output_dedupes_to_the_same_id() -> None:
    message = ToolMessage(content="identical output", tool_call_id="c1", name="whatweb")

    a = GenericExtractor().extract(None, message, Graph(), "10.0.0.5").nodes[0]
    b = GenericExtractor().extract(None, message, Graph(), "10.0.0.5").nodes[0]

    assert a.id == b.id


def test_generic_extractor_finds_a_php_config_credential_instead_of_a_hash() -> None:
    """2026-10-18, live: curl has no dedicated extractor and its LLM
    fallback failed 3/3 times in one real engagement -- a leaked DVWA DB
    password landed here every time and became an opaque content-hash
    node, permanently unreadable. This is the exact shape that leaked."""
    content = (
        "<?php\n"
        "define('DB_SERVER', 'localhost');\n"
        "define('DB_DATABASE', 'dvwa');\n"
        "define('DB_USERNAME', 'app');\n"
        "define('DB_PASSWORD', 'vulnerables');\n"
        "?>\n"
    )
    message = ToolMessage(content=content, tool_call_id="c1", name="curl")

    extraction = GenericExtractor().extract(None, message, Graph(), "172.28.0.3")

    signals = {n.signal for n in extraction.nodes}
    assert "DB_PASSWORD=vulnerables" in signals
    assert all(n.cause_class == "credential-found" for n in extraction.nodes)
    assert all(n.evidence[0].tier == "T2" for n in extraction.nodes)
    assert all(n.evidence[0].source == "deterministic" for n in extraction.nodes)


def test_generic_extractor_finds_a_plain_key_value_credential() -> None:
    message = ToolMessage(
        content="some banner text\napi_key: sk-abc123\nmore text", tool_call_id="c1", name="dnsenum"
    )

    extraction = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    assert any(n.signal == "api_key=sk-abc123" for n in extraction.nodes)


def test_generic_extractor_falls_back_to_a_hash_node_when_nothing_credential_shaped() -> None:
    message = ToolMessage(content="just plain banner output, nothing secret here", tool_call_id="c1", name="curl")

    extraction = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "curl"
    assert node.evidence[0].source == "unverified"


def test_generic_extractor_does_not_scan_a_failed_call_for_credentials() -> None:
    """A failed call's content is an error message, not real tool output --
    scanning it risks a false "credential found" from error text that
    happens to contain the word "password"."""
    message = ToolMessage(
        content="define('DB_PASSWORD', 'vulnerables')",
        tool_call_id="c1",
        name="curl",
        status="error",
    )

    extraction = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "curl"
    assert node.evidence[0].verdict == "dead"
