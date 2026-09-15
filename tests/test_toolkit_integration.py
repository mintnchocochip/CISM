"""Checkpoint-2 proof: build_toolkit() assembles the real catalog + hydra +
tool_help into one registry, EXTRACTORS supplies real extraction for nmap
without a hand-authored PhaseProfile entry, and the action guardrail chain
(ScopeGuardStage + DangerousFlagGuardStage together) blocks a dangerous
flag before the subprocess ever runs — a real tool call flows through the
actual graph loop end to end, same shape as
tests/test_tool_catalog_integration.py but exercising this sprint's new
assembly path (build_toolkit) instead of a hand-built ToolRegistry.
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
    DangerousFlagGuardStage,
    EngagementScope,
    GuardrailChain,
    GuardrailSeam,
    PassThroughStage,
    ScopeGuardStage,
)
from cism.agent.tools import CATALOG, hydra
from cism.agent.tools.base import build_toolkit
from cism.depg import EXTRACTORS, ExtractorRegistry, GenericExtractor
from cism.tui.events import DEPGUpdated, RunFinished, drain

requires_curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")


class _CallsCurlWith(BaseChatModel):
    extra: str

    @property
    def _llm_type(self) -> str:
        return "test-calls-curl-with"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        tool_results = [m for m in messages if isinstance(m, ToolMessage)]
        if not tool_results:
            reply = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "curl",
                        "args": {"target": "http://127.0.0.1:1/", "extra": self.extra},
                        "id": f"call_{uuid.uuid4().hex[:8]}",
                        "type": "tool_call",
                    }
                ],
            )
        else:
            reply = AIMessage(content="done")
        return ChatResult(generations=[ChatGeneration(message=reply)])


def _action_chain(scope: EngagementScope) -> GuardrailChain:
    return GuardrailChain([ScopeGuardStage(scope=scope), DangerousFlagGuardStage()])


async def _drain_until_finished(agent: LangGraphAgent) -> list:
    events: list = []
    while not any(isinstance(e, RunFinished) for e in events):
        events.extend(await asyncio.wait_for(drain(agent.events), timeout=10.0))
    return events


def test_build_toolkit_registers_the_real_catalog_plus_hydra_plus_tool_help() -> None:
    registry, extractors = build_toolkit(CATALOG, decorated_tools=[hydra], extractors=EXTRACTORS)

    for name in ("nikto", "whatweb", "dnsenum", "nmap", "curl", "hydra", "tool_help"):
        assert name in registry
    assert extractors is EXTRACTORS


@requires_curl
async def test_a_real_curl_call_through_build_toolkit_flows_to_a_depg_node(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    scope = EngagementScope(cidrs=(ipaddress.ip_network("127.0.0.1/32"),))
    registry, extractors = build_toolkit(CATALOG, decorated_tools=[hydra], extractors=EXTRACTORS)
    agent = LangGraphAgent(
        llm=_CallsCurlWith(extra="-sS --max-time 2"),
        tools=registry,
        guardrails=GuardrailSeam(
            input=GuardrailChain([PassThroughStage()]),
            action=_action_chain(scope),
            output=GuardrailChain([PassThroughStage()]),
        ),
        extractors=ExtractorRegistry(extractors, GenericExtractor()),
        target="127.0.0.1",
    )

    await agent.submit("probe localhost")
    events = await _drain_until_finished(agent)
    await agent.aclose()

    assert events[-1].ok is True
    depg_updates = [e for e in events if isinstance(e, DEPGUpdated)]
    assert depg_updates
    node = depg_updates[-1].nodes[0]
    # curl against 127.0.0.1:1 (nothing ever listens there) genuinely fails —
    # now correctly marked dead and pruned into a dead-region marker, rather
    # than silently reported as a live "curl" node.
    assert node.cause_class == "dead-region"
    assert node.target == "127.0.0.1"
    assert node.evidence


@requires_curl
async def test_a_dangerous_flag_is_blocked_before_the_subprocess_runs(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    scope = EngagementScope(cidrs=(ipaddress.ip_network("127.0.0.1/32"),))
    registry, extractors = build_toolkit(CATALOG, decorated_tools=[hydra], extractors=EXTRACTORS)
    agent = LangGraphAgent(
        llm=_CallsCurlWith(extra="--upload-file /etc/passwd"),
        tools=registry,
        guardrails=GuardrailSeam(
            input=GuardrailChain([PassThroughStage()]),
            action=_action_chain(scope),
            output=GuardrailChain([PassThroughStage()]),
        ),
        extractors=ExtractorRegistry(extractors, GenericExtractor()),
        target="127.0.0.1",
    )

    await agent.submit("probe localhost")
    events = await _drain_until_finished(agent)
    await agent.aclose()

    # A blocked call is evidence of its own: it becomes a dead tombstone
    # node rather than being dropped, so the agent has a record of the
    # attempt instead of silently re-proposing the same dangerous flag.
    depg_updates = [e for e in events if isinstance(e, DEPGUpdated)]
    assert depg_updates
    assert all(n.state == "blocked" for n in depg_updates[-1].nodes)
