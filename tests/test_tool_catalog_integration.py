"""Checkpoint-1 proof: a real tool call flows through the actual graph
loop end to end — LLM tool-call -> ScopeGuardStage -> run_sandboxed ->
real subprocess -> ToolMessage -> depg_update's GenericExtractor fallback
-> phase router -> DEPGUpdated.

Uses a tiny test-local fake model (not DummyChatModel, which is hardcoded
to call dummy_nmap/dummy_msfconsole by name) so the graph exercises one of
the real, subprocess-backed tools from cism/agent/tools/ instead.
"""

from __future__ import annotations

import asyncio
import ipaddress
import shutil
import uuid

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from cism.agent import LangGraphAgent
from cism.agent.guardrails import (
    EngagementScope,
    GuardrailChain,
    GuardrailSeam,
    PassThroughStage,
    ScopeGuardStage,
)
from cism.agent.tools import ToolRegistry
from cism.agent.tools.linux import curl
from cism.tui.events import DEPGUpdated, RunFinished, drain

requires_curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")


class _CallsCurlOnce(BaseChatModel):
    """Calls the real ``curl`` tool once, then gives a final answer — the
    minimum needed to drive one real trip through act -> depg_update."""

    @property
    def _llm_type(self) -> str:
        return "test-calls-curl-once"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        tool_results = [m for m in messages if isinstance(m, ToolMessage)]
        if not tool_results:
            reply = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "curl",
                        "args": {"url": "http://127.0.0.1:1/", "options": "-sS --max-time 2"},
                        "id": f"call_{uuid.uuid4().hex[:8]}",
                        "type": "tool_call",
                    }
                ],
            )
        else:
            reply = AIMessage(content="done")
        return ChatResult(generations=[ChatGeneration(message=reply)])


@requires_curl
async def test_a_real_tool_call_flows_through_the_graph_to_a_depg_node(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    scope = EngagementScope(cidrs=(ipaddress.ip_network("127.0.0.1/32"),))
    agent = LangGraphAgent(
        llm=_CallsCurlOnce(),
        tools=ToolRegistry([curl]),
        guardrails=GuardrailSeam(
            input=GuardrailChain([PassThroughStage()]),
            action=GuardrailChain([ScopeGuardStage(scope=scope)]),
            output=GuardrailChain([PassThroughStage()]),
        ),
        target="127.0.0.1",
    )

    await agent.submit("probe localhost")
    events: list = []
    while not any(isinstance(e, RunFinished) for e in events):
        events.extend(await asyncio.wait_for(drain(agent.events), timeout=10.0))
    await agent.aclose()

    assert events[-1].ok is True

    depg_updates = [e for e in events if isinstance(e, DEPGUpdated)]
    assert depg_updates
    assert depg_updates[-1].nodes
    node = depg_updates[-1].nodes[0]
    assert node.cause_class == "curl"
    assert node.target == "127.0.0.1"
    assert node.evidence


@requires_curl
async def test_an_out_of_scope_target_is_blocked_before_the_subprocess_runs(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    # Scope deliberately excludes 127.0.0.1 — the call should be blocked by
    # ScopeGuardStage and never reach run_sandboxed at all.
    scope = EngagementScope(cidrs=(ipaddress.ip_network("10.0.0.0/24"),))
    agent = LangGraphAgent(
        llm=_CallsCurlOnce(),
        tools=ToolRegistry([curl]),
        guardrails=GuardrailSeam(
            input=GuardrailChain([PassThroughStage()]),
            action=GuardrailChain([ScopeGuardStage(scope=scope)]),
            output=GuardrailChain([PassThroughStage()]),
        ),
        target="127.0.0.1",
    )

    await agent.submit("probe localhost")
    events: list = []
    while not any(isinstance(e, RunFinished) for e in events):
        events.extend(await asyncio.wait_for(drain(agent.events), timeout=10.0))
    await agent.aclose()

    # A blocked call is evidence of its own: it becomes a dead tombstone
    # node rather than being dropped, so the agent has a record of the
    # attempt instead of silently re-proposing it.
    depg_updates = [e for e in events if isinstance(e, DEPGUpdated)]
    assert depg_updates
    assert all(n.state == "blocked" for n in depg_updates[-1].nodes)
