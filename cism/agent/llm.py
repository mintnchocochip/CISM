"""A canned, deterministic chat model for validating the loop with no lab,
no weights, and no network — the agent-side equivalent of what
``cism/tui/replay.py`` does for the TUI.

Behaviour is driven purely by how many tool results are already in the
conversation, so a run is reproducible call for call:

- no tool result yet          -> call ``dummy_nmap`` on the target
- one tool result (nmap)      -> call ``dummy_msfconsole`` on the target
- two or more tool results    -> a final answer, no further tool calls

Swapping this for a real model is the one-line change that docstring
promised: see ``build_chat_model`` below, which builds a
network-capable ``BaseChatModel`` for whoever opts into one, since both are
just ``BaseChatModel`` instances.
"""

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
    """Scans only the *current* turn's ask — the most recent
    ``HumanMessage`` — not the whole conversation. ``messages`` now spans
    every turn in the session (a real checkpointer backs the graph), so
    scanning forward from the start would find whatever IP an earlier,
    possibly unrelated turn happened to mention instead of what was just
    asked."""
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
        # Scoped to the current turn (back to the most recent HumanMessage),
        # same reasoning as _target_from above: messages now spans the
        # whole session, and counting every ToolMessage ever produced would
        # make this stub treat turn 2 onward as already mid-scan (or
        # already finished) regardless of what was actually just asked.
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
    """A ``ChatOpenAI`` pointed at any server that speaks the OpenAI chat
    completions wire format — llama.cpp's ``--api`` mode, vLLM, LM Studio,
    real OpenAI, or Ollama's ``/v1`` endpoint. One construction path covers
    all of them because that wire format is the actual shared implementation,
    not a coincidence: Ollama's OpenAI-compatible endpoint requires the
    ``api_key`` field to be present and non-empty but never validates its
    contents (see https://docs.ollama.com/api/openai-compatibility), which is
    exactly why this takes the *name* of an environment variable rather than
    a key value — the same ``key_env_var``/``key_present`` split the TUI's
    ``SessionState`` already uses, so a local no-auth server still gets a
    real (if throwaway) secret name to report instead of a hole in that
    contract.

    Caveat a caller must know before relying on tool calls against a local
    server: whether the *model being served* supports function calling is
    independent of whether the server's endpoint does. Ollama's endpoint
    supports the tools field, but only for models trained for it (e.g.
    Llama 3.1, Mistral Nemo, Firefunction v2, Command-R) — an
    unsupported model will not necessarily error, it may instead emit raw
    tool-call-shaped JSON as ordinary text content, which looks like a
    model failing to call anything rather than a config problem.

    Tool binding is deliberately not done here: this factory only ever
    builds the model, so what it returns is a plain, uncommitted
    ``BaseChatModel`` regardless of which tools (if any) the caller intends
    to bind onto it later, exactly like ``DummyChatModel`` needs no tools to
    exist. Binding is the caller's job (see ``LangGraphAgent``), which is
    also where the tool *registry* — the other half of the pairing — lives.

    ``stream_usage`` defaults on: it sets the standard OpenAI wire-format
    ``stream_options: {include_usage: true}`` request field, which makes a
    streaming response's final chunk carry a real ``usage_metadata``
    (input/output/total token counts) instead of leaving every chunk's
    ``usage_metadata`` at ``None`` — confirmed against Ollama's own
    OpenAI-compat endpoint, which honours it. ``LangGraphAgent`` reads that
    field to drive the status bar's token/context tracking (see
    ``TokenDelta`` in ``cism/tui/events.py``). Pass ``stream_usage=False``
    explicitly for a server that chokes on the field.
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
    """Best-effort context-window size for ``model``, in tokens.

    The OpenAI chat-completions wire format ``build_chat_model`` otherwise
    speaks has no standard field for this, so there is nothing to ask a
    generic server. Ollama does know (and serves plenty of local dev setups
    this project targets), via a *sibling* endpoint outside that wire
    format: ``POST {base}/api/show`` returns a ``model_info`` object with an
    architecture-prefixed ``"<arch>.context_length"`` key.

    Returns ``None`` — never raises — for a non-``/v1`` base URL, a server
    that isn't Ollama, or any request failure (timeout, 404, bad JSON): the
    caller already has a sane fallback (the status bar's own default), and
    "couldn't determine this" is an expected, common outcome here, not an
    error.
    """
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
