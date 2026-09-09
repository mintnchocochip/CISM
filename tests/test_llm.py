"""cism/agent/llm.py: the real, network-capable model factory.

No network call is exercised anywhere here — ``ChatOpenAI`` doesn't touch
the wire until a request is actually sent, so construction and
``bind_tools()`` are pure local object-graph assertions, the same "no lab,
no weights, no network" bar the rest of this repo holds itself to.
"""

from __future__ import annotations

import pytest
from langchain_openai import ChatOpenAI

import cism.agent.llm as llm_module
from cism.agent.llm import build_chat_model, discover_context_window


def test_missing_api_key_env_var_raises_rather_than_silently_using_none(monkeypatch) -> None:
    monkeypatch.delenv("CISM_TEST_MODEL_KEY", raising=False)
    with pytest.raises(ValueError, match="CISM_TEST_MODEL_KEY"):
        build_chat_model(
            base_url="http://localhost:8080/v1",
            key_env_var="CISM_TEST_MODEL_KEY",
            model="some-model",
        )


def test_builds_a_chat_openai_pointed_at_the_given_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("CISM_TEST_MODEL_KEY", "sk-placeholder")

    model = build_chat_model(
        base_url="http://localhost:8080/v1",
        key_env_var="CISM_TEST_MODEL_KEY",
        model="local-llama",
    )

    assert isinstance(model, ChatOpenAI)
    assert model.openai_api_base == "http://localhost:8080/v1"
    assert model.model_name == "local-llama"


def test_ollamas_openai_compatible_endpoint_uses_the_same_construction_path(monkeypatch) -> None:
    """Ollama's /v1 endpoint requires a non-empty api_key but never
    validates it (docs.ollama.com/api/openai-compatibility) — so pointing
    at it takes no special-casing, just a different base_url/model."""
    monkeypatch.setenv("CISM_TEST_OLLAMA_KEY", "ollama")

    model = build_chat_model(
        base_url="http://localhost:11434/v1",
        key_env_var="CISM_TEST_OLLAMA_KEY",
        model="llama3.1",
    )

    assert isinstance(model, ChatOpenAI)
    assert model.openai_api_base == "http://localhost:11434/v1"


def test_extra_kwargs_pass_through_to_chat_openai(monkeypatch) -> None:
    monkeypatch.setenv("CISM_TEST_MODEL_KEY", "sk-placeholder")

    model = build_chat_model(
        base_url="http://localhost:8080/v1",
        key_env_var="CISM_TEST_MODEL_KEY",
        model="local-llama",
        temperature=0.2,
    )

    assert model.temperature == 0.2


def test_stream_usage_defaults_on_so_token_tracking_has_something_to_read(monkeypatch) -> None:
    monkeypatch.setenv("CISM_TEST_MODEL_KEY", "sk-placeholder")

    model = build_chat_model(
        base_url="http://localhost:8080/v1",
        key_env_var="CISM_TEST_MODEL_KEY",
        model="local-llama",
    )

    assert model.stream_usage is True


def test_stream_usage_can_still_be_overridden(monkeypatch) -> None:
    monkeypatch.setenv("CISM_TEST_MODEL_KEY", "sk-placeholder")

    model = build_chat_model(
        base_url="http://localhost:8080/v1",
        key_env_var="CISM_TEST_MODEL_KEY",
        model="local-llama",
        stream_usage=False,
    )

    assert model.stream_usage is False


class _FakeResponse:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError("bad status", request=None, response=self)

    def json(self) -> dict:
        return self._payload


class _FakeAsyncClient:
    """Stands in for httpx.AsyncClient — records the request it was asked
    to make and returns a canned response, so discover_context_window can
    be tested without a real server (this repo's "no network" test bar)."""

    last_url: str | None = None
    last_json: dict | None = None
    response: _FakeResponse | Exception = _FakeResponse({})

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    async def __aenter__(self) -> "_FakeAsyncClient":
        return self

    async def __aexit__(self, *exc_info) -> None:
        return None

    async def post(self, url: str, json: dict) -> _FakeResponse:
        type(self).last_url = url
        type(self).last_json = json
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


async def test_discover_context_window_returns_none_for_a_non_v1_base_url() -> None:
    assert await discover_context_window("http://localhost:8080", "some-model") is None


async def test_discover_context_window_parses_ollamas_show_response(monkeypatch) -> None:
    _FakeAsyncClient.response = _FakeResponse(
        {"model_info": {"gemma3.context_length": 8192, "general.architecture": "gemma3"}}
    )
    monkeypatch.setattr(llm_module.httpx, "AsyncClient", _FakeAsyncClient)

    result = await discover_context_window("http://localhost:11434/v1", "gemma3:4b")

    assert result == 8192
    assert _FakeAsyncClient.last_url == "http://localhost:11434/api/show"
    assert _FakeAsyncClient.last_json == {"model": "gemma3:4b"}


async def test_discover_context_window_returns_none_when_the_field_is_missing(monkeypatch) -> None:
    _FakeAsyncClient.response = _FakeResponse({"model_info": {"general.architecture": "gemma3"}})
    monkeypatch.setattr(llm_module.httpx, "AsyncClient", _FakeAsyncClient)

    assert await discover_context_window("http://localhost:11434/v1", "gemma3:4b") is None


async def test_discover_context_window_returns_none_on_request_failure(monkeypatch) -> None:
    import httpx

    _FakeAsyncClient.response = httpx.ConnectError("refused")
    monkeypatch.setattr(llm_module.httpx, "AsyncClient", _FakeAsyncClient)

    assert await discover_context_window("http://localhost:11434/v1", "gemma3:4b") is None
