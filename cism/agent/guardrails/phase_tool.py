"""A stage in the action GuardrailChain, alongside ScopeGuardStage and
DangerousFlagGuardStage: independently re-checks that a called tool is
actually offered in the current phase.

default_profiles() (cism/agent/profiles.py) already restricts which
tools are bound at the think step — a destructive-capability tool is
never even offered to the model outside the phases that declare it. This
stage exists because binding-time restriction is not a guarantee against
a compromised or confused model: a prompt injection (from a scanned
target's own banner text, a DNS TXT record — anything the agent reads
back as tool output) or a hallucinated tool name could construct a
ToolCall some other way. allowed_tool_names is deliberately the exact
same value default_profiles() already computed for binding, not a
second, parallel derivation that could drift from it.
"""

from __future__ import annotations

from langchain_core.messages.tool import ToolCall

from cism.agent.guardrails.chain import GuardrailResult
from cism.agent.state import Phase

__all__ = ["PhaseToolGuardStage"]

#: Matches make_think_node's own bind-time exemption for tool_help
#: (cism/agent/nodes.py): knowing what a tool can do carries none of the
#: risk using it does, so it's exempt from phase gating here too,
#: independent of whatever allowed_tool_names the caller passed in.
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
