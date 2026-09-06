"""cism/agent/guardrails/phase_tool.py: PhaseToolGuardStage independently
re-checks that a called tool is actually offered in the current phase —
the same defense-in-depth role ScopeGuardStage/DangerousFlagGuardStage
play for their own concerns, closing the gap between "the LLM wasn't
bound this tool" and "this tool call cannot reach a subprocess" for a
hallucinated or prompt-injected call that never went through legitimate
binding.
"""

from __future__ import annotations

from cism.agent.guardrails.phase_tool import PhaseToolGuardStage
from cism.agent.state import Phase


def _call(name: str) -> dict:
    return {"id": "call-1", "name": name, "args": {}, "type": "tool_call"}


def test_a_bound_tool_is_allowed() -> None:
    stage = PhaseToolGuardStage(Phase.RECON, frozenset({"nmap", "curl"}), {"nmap": "reads"})
    result = stage.check(_call("nmap"))
    assert result.allowed is True


def test_a_tool_not_offered_in_this_phase_is_blocked() -> None:
    """The actual threat model: hydra exists in the registry and has a
    real capability, but was never bound in RECON — a hallucinated or
    injected call naming it anyway must still be blocked here,
    independent of whatever bound it (or didn't) at the think step."""
    stage = PhaseToolGuardStage(Phase.RECON, frozenset({"nmap", "curl"}), {"hydra": "executes"})
    result = stage.check(_call("hydra"))
    assert result.allowed is False
    assert "hydra" in result.reason
    assert "executes" in result.reason
    assert "recon" in result.reason.lower()


def test_a_completely_unregistered_tool_name_is_blocked() -> None:
    stage = PhaseToolGuardStage(Phase.RECON, frozenset({"nmap"}), {})
    result = stage.check(_call("totally-made-up-tool"))
    assert result.allowed is False


def test_tool_help_is_exempted_in_every_phase() -> None:
    """Matches make_think_node's own bind-time exemption for tool_help —
    knowing what a tool can do carries none of the risk using it does."""
    stage = PhaseToolGuardStage(Phase.REPORTING, frozenset(), {})  # REPORTING offers zero tools
    result = stage.check(_call("tool_help"))
    assert result.allowed is True


def test_the_stage_name_is_phase_tool_guard() -> None:
    stage = PhaseToolGuardStage(Phase.RECON, frozenset(), {})
    assert stage.name == "phase-tool-guard"
