"""Per-phase configuration for think/act: prompt, tool subset, extra action
guardrail stages. One profile per phase; think/act consume this registry and
never branch on phase themselves, so promoting a phase to a real subagent
later is a hand-off at phase_router, not a graph change.
"""

from __future__ import annotations

from dataclasses import dataclass

from cism.agent.guardrails import GuardrailStage
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry

__all__ = ["PhaseProfile", "PhaseProfiles", "default_profiles"]


@dataclass(frozen=True, slots=True)
class PhaseProfile:
    phase: Phase
    system_prompt: str
    tool_names: frozenset[str]
    action_stages: tuple[GuardrailStage, ...] = ()


class PhaseProfiles:
    """A hard allowlist, same convention as ToolRegistry: every phase must
    have a profile, so a missing one raises rather than silently degrading
    the agent to no prompt and no tools."""

    def __init__(self, profiles: dict[Phase, PhaseProfile]) -> None:
        self._profiles = dict(profiles)

    def get(self, phase: Phase) -> PhaseProfile:
        return self._profiles[phase]


_PROMPTS: dict[Phase, str] = {
    Phase.RECON: (
        "You are in the recon phase: map hosts and open services. "
        "Do not attempt exploitation."
    ),
    Phase.ENUMERATION: (
        "You are in enumeration: identify service versions and configuration "
        "on discovered hosts."
    ),
    Phase.VULNERABILITY_DISCOVERY: (
        "You are assessing discovered services for known vulnerabilities."
    ),
    Phase.EXPLOITATION: (
        "You are attempting to exploit a confirmed vulnerability or weak credential."
    ),
    Phase.POST_EXPLOITATION: (
        "You have a foothold; document access and look for further pivots within scope."
    ),
    Phase.REPORTING: "Summarize findings. Do not run further tools.",
}

_TOOLS: dict[Phase, frozenset[str]] = {
    Phase.RECON: frozenset({"nmap", "curl"}),
    Phase.ENUMERATION: frozenset({"nmap", "curl"}),
    Phase.VULNERABILITY_DISCOVERY: frozenset({"nmap", "curl"}),
    Phase.EXPLOITATION: frozenset({"nmap", "curl", "hydra"}),
    Phase.POST_EXPLOITATION: frozenset({"nmap", "curl", "hydra"}),
    Phase.REPORTING: frozenset(),
}


def default_profiles(tools: ToolRegistry) -> PhaseProfiles:
    """The basic profile set. tool_names lists real tool names (nmap/curl/
    hydra); a caller whose registry only has the dummy tools simply binds
    nothing for a phase — see make_think_node, which filters tool_names
    against what the registry actually contains."""
    del tools  # not needed to build the basic set; kept for callers' symmetry
    return PhaseProfiles(
        {
            phase: PhaseProfile(
                phase=phase, system_prompt=_PROMPTS[phase], tool_names=_TOOLS[phase]
            )
            for phase in Phase
        }
    )
