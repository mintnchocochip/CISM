"""cism/agent/llm.py: the real, network-capable model factory.

No network call is exercised anywhere here — ``ChatOpenAI`` doesn't touch
the wire until a request is actually sent, so construction and
``bind_tools()`` are pure local object-graph assertions, the same "no lab,
no weights, no network" bar the rest of this repo holds itself to.
"""

from __future__ import annotations

import pytest
from langchain_openai import ChatOpenAI

from cism.agent.llm import make_openai_compatible_chat_model


def test_missing_api_key_env_var_raises_rather_than_silently_using_none(monkeypatch) -> None:
    monkeypatch.delenv("CISM_TEST_MODEL_KEY", raising=False)
    with pytest.raises(ValueError, match="CISM_TEST_MODEL_KEY"):
        make_openai_compatible_chat_model(
            base_url="http://localhost:8080/v1",
            api_key_env_var="CISM_TEST_MODEL_KEY",
            model="some-model",
        )


def test_builds_a_chat_openai_pointed_at_the_given_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("CISM_TEST_MODEL_KEY", "sk-placeholder")

    model = make_openai_compatible_chat_model(
        base_url="http://localhost:8080/v1",
        api_key_env_var="CISM_TEST_MODEL_KEY",
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

    model = make_openai_compatible_chat_model(
        base_url="http://localhost:11434/v1",
        api_key_env_var="CISM_TEST_OLLAMA_KEY",
        model="llama3.1",
    )

    assert isinstance(model, ChatOpenAI)
    assert model.openai_api_base == "http://localhost:11434/v1"


def test_extra_kwargs_pass_through_to_chat_openai(monkeypatch) -> None:
    monkeypatch.setenv("CISM_TEST_MODEL_KEY", "sk-placeholder")

    model = make_openai_compatible_chat_model(
        base_url="http://localhost:8080/v1",
        api_key_env_var="CISM_TEST_MODEL_KEY",
        model="local-llama",
        temperature=0.2,
    )

    assert model.temperature == 0.2
