"""cism/depg/extractors.py: LlamaCppExtractionBackend posts straight to a
llama.cpp server's /completion with a json_schema constraint, instead of
relying on with_structured_output/function-calling — the "alternative
compatible inference server" path (AUDIT.md G1). Mocked at the httpx layer;
no real llama.cpp server was reachable while writing this."""

from __future__ import annotations

import httpx
import pytest

from cism.depg.extractors import ExtractedFindings, LlamaCppExtractionBackend


class _FakeResponse:
    def __init__(self, *, status_code: int = 200, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=self)  # type: ignore[arg-type]

    def json(self) -> dict:
        return self._payload


def test_parses_a_successful_completion_into_extracted_findings(monkeypatch) -> None:
    findings_json = (
        '{"findings": [{"cause_class": "open-port", "signal": "80/tcp", '
        '"tier": "T2", "verdict": "alive", "evidence_quote": "80/tcp open http", '
        '"summary": "HTTP open."}]}'
    )
    captured: dict = {}

    def fake_post(url, *, json, timeout):
        captured["url"] = url
        captured["json"] = json
        return _FakeResponse(payload={"content": findings_json})

    monkeypatch.setattr(httpx, "post", fake_post)
    backend = LlamaCppExtractionBackend("http://localhost:8080")

    result = backend.extract("extract findings from: 80/tcp open http")

    assert isinstance(result, ExtractedFindings)
    assert result.findings[0].cause_class == "open-port"
    assert captured["url"] == "http://localhost:8080/completion"
    assert captured["json"]["json_schema"] == ExtractedFindings.model_json_schema()


def test_strips_a_trailing_slash_from_base_url(monkeypatch) -> None:
    captured: dict = {}

    def fake_post(url, *, json, timeout):
        captured["url"] = url
        return _FakeResponse(payload={"content": '{"findings": []}'})

    monkeypatch.setattr(httpx, "post", fake_post)
    backend = LlamaCppExtractionBackend("http://localhost:8080/")

    backend.extract("prompt")

    assert captured["url"] == "http://localhost:8080/completion"


def test_an_http_error_returns_none_not_an_exception(monkeypatch) -> None:
    def fake_post(url, *, json, timeout):
        return _FakeResponse(status_code=500)

    monkeypatch.setattr(httpx, "post", fake_post)
    backend = LlamaCppExtractionBackend("http://localhost:8080")

    assert backend.extract("prompt") is None


def test_a_connection_failure_returns_none_not_an_exception(monkeypatch) -> None:
    def fake_post(url, *, json, timeout):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", fake_post)
    backend = LlamaCppExtractionBackend("http://localhost:8080")

    assert backend.extract("prompt") is None


def test_malformed_json_content_returns_none_not_an_exception(monkeypatch) -> None:
    def fake_post(url, *, json, timeout):
        return _FakeResponse(payload={"content": "not valid json"})

    monkeypatch.setattr(httpx, "post", fake_post)
    backend = LlamaCppExtractionBackend("http://localhost:8080")

    assert backend.extract("prompt") is None
