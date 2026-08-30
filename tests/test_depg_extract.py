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
