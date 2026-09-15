"""A canned, deterministic chat model for validating the loop with no lab,
weights, or network — the agent-side equivalent of ``cism/tui/replay.py``.
Behaviour is driven purely by how many tool results are already in the
conversation: none -> call ``dummy_nmap``, one -> call ``dummy_msfconsole``,
two+ -> a final answer. ``build_chat_model`` below builds the real,
network-capable ``BaseChatModel`` counterpart."""

from __future__ import annotations

import os
import re
import uuid
from typing import Any

import httpx
from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_openai import ChatOpenAI

__all__ = ["DummyChatModel", "build_chat_model", "discover_context_window"]

_SHOW_TIMEOUT = 3.0

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DEFAULT_TARGET = "0.0.0.0"


def _target_from(messages: list[BaseMessage]) -> str:
    """Scans only the current turn (back to the most recent ``HumanMessage``),
    not the whole session — else an earlier turn's IP could be picked up instead."""
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            match = _IPV4.search(str(message.content))
            return match.group(0) if match else _DEFAULT_TARGET
    return _DEFAULT_TARGET


class DummyChatModel(BaseChatModel):
    @property
    def _llm_type(self) -> str:
        return "cism-dummy-chat-model"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        # Scoped to the current turn only, same reasoning as _target_from above.
        tool_results: list[ToolMessage] = []
        for message in reversed(messages):
            if isinstance(message, HumanMessage):
                break
            if isinstance(message, ToolMessage):
                tool_results.append(message)
        target = _target_from(messages)

        if len(tool_results) == 0:
            reply = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "dummy_nmap",
                        "args": {"target": target},
                        "id": f"call_{uuid.uuid4().hex[:8]}",
                        "type": "tool_call",
                    }
                ],
            )
        elif len(tool_results) == 1:
            reply = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "dummy_msfconsole",
                        "args": {
                            "module": "auxiliary/scanner/http/http_version",
                            "target": target,
                        },
                        "id": f"call_{uuid.uuid4().hex[:8]}",
                        "type": "tool_call",
                    }
                ],
            )
        else:
            reply = AIMessage(
                content=(
                    f"Scan of {target} complete: nmap found open ports, "
                    "msfconsole found no immediately exploitable service. "
                    "Stub run finished."
                ),
            )

        return ChatResult(generations=[ChatGeneration(message=reply)])


def build_chat_model(
    base_url: str,
    key_env_var: str,
    model: str,
    **kwargs: Any,
) -> BaseChatModel:
    """A ``ChatOpenAI`` pointed at any server speaking the OpenAI chat
    completions wire format — llama.cpp, vLLM, LM Studio, real OpenAI, or
    Ollama's ``/v1`` endpoint. Takes the *name* of an env var rather than a
    key value because Ollama requires ``api_key`` non-empty but never
    validates it, so a no-auth server still gets a real secret name to
    report via ``key_env_var``/``key_present``.

    Whether the *model being served* supports function calling is
    independent of whether the endpoint does — an unsupported model may
    emit raw tool-call JSON as plain text instead of erroring.

    Tool binding isn't done here; this only builds a plain, uncommitted
    ``BaseChatModel`` — binding is the caller's job (``LangGraphAgent``).

    ``stream_usage`` defaults on so a streaming response's final chunk
    carries real ``usage_metadata`` (``LangGraphAgent`` reads it for
    ``TokenDelta``); pass ``stream_usage=False`` for a server that chokes on it.
    """
    api_key = os.environ.get(key_env_var, "")
    if not api_key:
        raise ValueError(
            f"environment variable {key_env_var!r} is not set; "
            "an OpenAI-compatible server still requires a non-empty api_key "
            "even when (as with Ollama) it never checks the value"
        )

    kwargs.setdefault("stream_usage", True)
    return ChatOpenAI(base_url=base_url, api_key=api_key, model=model, **kwargs)


async def discover_context_window(base_url: str, model: str) -> int | None:
    """Best-effort context-window size for ``model``, in tokens. The OpenAI
    wire format has no field for this, so Ollama's sibling endpoint
    (``POST {base}/api/show``) is queried instead. Returns ``None`` — never
    raises — for any non-Ollama server or request failure; the caller
    already has a sane fallback."""
    trimmed = base_url.rstrip("/")
    if not trimmed.endswith("/v1"):
        return None
    show_url = trimmed[: -len("/v1")] + "/api/show"

    try:
        async with httpx.AsyncClient(timeout=_SHOW_TIMEOUT) as client:
            response = await client.post(show_url, json={"model": model})
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        return None

    model_info = payload.get("model_info")
    if not isinstance(model_info, dict):
        return None
    for key, value in model_info.items():
        if key.endswith(".context_length") and isinstance(value, int):
            return value
    return None
