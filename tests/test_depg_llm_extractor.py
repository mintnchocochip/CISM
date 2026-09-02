"""cism/depg/extractors.py: LLMExtractor is the fallback CauseExtractor for
any tool without a hand-written one (NmapExtractor/HydraExtractor), once a
real (non-dummy) backend is configured. Grounding is mechanical — an exact
substring check against the tool's own raw output — not another LLM call:
a finding whose evidence_quote can't be found in the output has its tier
clamped to T3 rather than being dropped."""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import ToolMessage

from cism.agent.llm import DummyChatModel
from cism.depg.extract import GenericExtractor
from cism.depg.extractors import ExtractedFinding, ExtractedFindings, LLMExtractor
from cism.depg.graph import Graph


class _FakeStructuredLLM(BaseChatModel):
    findings: ExtractedFindings

    @property
    def _llm_type(self) -> str:
        return "fake-structured-output"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise AssertionError("this test double is only ever invoked via with_structured_output")

    def with_structured_output(self, schema, **kwargs):
        findings = self.findings

        class _Structured:
            def invoke(self, *_args, **_kwargs):
                return findings

        return _Structured()


def _tool_message(content: str, name: str = "nikto") -> ToolMessage:
    return ToolMessage(content=content, tool_call_id="c1", name=name)


def test_a_grounded_finding_keeps_its_declared_tier() -> None:
    findings = ExtractedFindings(
        findings=[
            ExtractedFinding(
                cause_class="outdated-server-header",
                signal="Apache/2.2.8",
                tier="T2",
                verdict="alive",
                evidence_quote="Server: Apache/2.2.8",
                summary="Outdated Apache version banner.",
            )
        ]
    )
    extractor = LLMExtractor(_FakeStructuredLLM(findings=findings))
    message = _tool_message("Server: Apache/2.2.8 (Ubuntu)\nX-Powered-By: PHP/5.2.4")

    extraction = extractor.extract(None, message, Graph(), "10.0.0.5")

    assert len(extraction.nodes) == 1
    node = extraction.nodes[0]
    assert node.cause_class == "outdated-server-header"
    assert node.target == "10.0.0.5"
    assert node.evidence[0].tier == "T2"
    assert node.evidence[0].verdict == "alive"


def test_an_ungrounded_finding_is_clamped_to_t3() -> None:
    findings = ExtractedFindings(
        findings=[
            ExtractedFinding(
                cause_class="outdated-server-header",
                signal="Apache/2.2.8",
                tier="T1",
                verdict="alive",
                evidence_quote="this text is not actually anywhere in the tool output",
                summary="Outdated Apache version banner.",
            )
        ]
    )
    extractor = LLMExtractor(_FakeStructuredLLM(findings=findings))
    message = _tool_message("Server: Apache/2.2.8 (Ubuntu)")

    extraction = extractor.extract(None, message, Graph(), "10.0.0.5")

    assert extraction.nodes[0].evidence[0].tier == "T3"


def test_an_empty_findings_list_falls_back_to_generic_extractor() -> None:
    extractor = LLMExtractor(_FakeStructuredLLM(findings=ExtractedFindings(findings=[])))
    message = _tool_message("nothing interesting here", name="whatweb")

    extraction = extractor.extract(None, message, Graph(), "10.0.0.5")
    generic = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    assert extraction.nodes[0].cause_class == generic.nodes[0].cause_class
    assert extraction.nodes[0].id == generic.nodes[0].id


def test_a_model_without_structured_output_support_falls_back_to_generic_extractor() -> None:
    """DummyChatModel doesn't override bind_tools, so
    with_structured_output() raises NotImplementedError synchronously (no
    network) — LLMExtractor must catch that and produce exactly what
    GenericExtractor would."""
    extractor = LLMExtractor(DummyChatModel())
    message = _tool_message("raw output", name="nikto")

    extraction = extractor.extract(None, message, Graph(), "10.0.0.5")
    generic = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    assert extraction.nodes[0].cause_class == generic.nodes[0].cause_class
    assert extraction.nodes[0].id == generic.nodes[0].id
