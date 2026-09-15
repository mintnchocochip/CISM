"""A stage in the action GuardrailChain: independently re-checks that a
called tool is actually offered in the current phase. Binding-time
restriction (default_profiles) isn't a guarantee against a compromised or
confused model — a prompt injection or hallucinated name could construct a
ToolCall another way. allowed_tool_names is the exact same value
default_profiles() computed for binding, not a second derivation."""

from __future__ import annotations

from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails.chain import GuardrailResult
from cism.agent.state import Phase

__all__ = ["PhaseToolGuardStage"]

#: Matches make_think_node's own tool_help exemption — knowing what a tool
#: does carries none of the risk of using it.
_EXEMPT_TOOL_NAMES: frozenset[str] = frozenset({"tool_help"})


class PhaseToolGuardStage:
    name = "phase-tool-guard"

    def __init__(
        self,
        phase: Phase,
        allowed_tool_names: frozenset[str],
        tool_capabilities: dict[str, str],
    ) -> None:
        self._phase = phase
        self._allowed = allowed_tool_names
        self._capabilities = tool_capabilities

    def check(self, call: ToolCall) -> GuardrailResult[ToolCall]:
        name = call["name"]
        if name in _EXEMPT_TOOL_NAMES or name in self._allowed:
            return GuardrailResult(allowed=True, value=call)
        capability = self._capabilities.get(name, "unknown")
        return GuardrailResult(
            allowed=False,
            value=call,
            reason=f"{name!r} [capability={capability}] is not offered in phase {self._phase.to_wire()}",
        )
