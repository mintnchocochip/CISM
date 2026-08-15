"""A canned, deterministic chat model for validating the loop with no lab,
no weights, and no network — the agent-side equivalent of what
``cism/tui/replay.py`` does for the TUI.

Behaviour is driven purely by how many tool results are already in the
conversation, so a run is reproducible call for call:

- no tool result yet          -> call ``dummy_nmap`` on the target
- one tool result (nmap)      -> call ``dummy_msfconsole`` on the target
- two or more tool results    -> a final answer, no further tool calls

Swapping this for a real model later is a one-line change in whatever
constructs the graph, since both are just ``BaseChatModel`` instances.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

__all__ = ["DummyChatModel"]

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DEFAULT_TARGET = "0.0.0.0"


def _target_from(messages: list[BaseMessage]) -> str:
    for message in messages:
        if isinstance(message, HumanMessage):
            match = _IPV4.search(str(message.content))
            if match:
                return match.group(0)
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
        tool_results = [m for m in messages if isinstance(m, ToolMessage)]
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
