"""Per-phase configuration for think/act: prompt, tool subset, extra action
guardrail stages. One profile per phase; think/act never branch on phase
themselves. tool_names is derived from CATALOG via phases_for, not
hand-authored — decorated (non-catalog) tools like hydra get their phase
availability from _DECORATED_TOOL_PHASES instead."""

from __future__ import annotations

from dataclasses import dataclass

from cism.agent.guardrails import GuardrailStage, PhaseToolGuardStage
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry
from cism.agent.tools.catalog import CATALOG, phases_for

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

    def phases(self) -> list[Phase]:
        """Registered phases only — a caller iterating all of them (e.g.
        collecting every action_stage) must not assume every Phase is
        present, since a test/partial PhaseProfiles isn't required to."""
        return list(self._profiles)


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

#: Decorated tools (e.g. hydra) have no CATALOG row, so phases_for() can't
#: cover them — filled in by hand here instead.
_DECORATED_TOOL_PHASES: dict[str, frozenset[Phase]] = {
    "hydra": frozenset({Phase.EXPLOITATION, Phase.POST_EXPLOITATION}),
    "dummy_nmap": frozenset({Phase.RECON}),
    "dummy_msfconsole": frozenset({Phase.ENUMERATION}),
}

#: Same gap as _DECORATED_TOOL_PHASES, for capability instead of phase.
_DECORATED_TOOL_CAPABILITIES: dict[str, str] = {
    "hydra": "executes",
    "dummy_nmap": "reads",
    "dummy_msfconsole": "executes",
}


def default_profiles(tools: ToolRegistry) -> PhaseProfiles:
    """The basic profile set. make_think_node filters tool_names against
    what the registry actually contains, so a dummy-only registry just
    binds nothing. Each phase's PhaseToolGuardStage is built from that
    same tool_names value so the re-check can't drift from binding."""
    del tools  # not needed to build the basic set; kept for callers' symmetry

    tool_names_by_phase: dict[Phase, set[str]] = {phase: set() for phase in Phase}
    for name, spec in CATALOG.items():
        for phase in phases_for(spec):
            tool_names_by_phase[phase].add(name)
    for name, phases in _DECORATED_TOOL_PHASES.items():
        for phase in phases:
            tool_names_by_phase[phase].add(name)

    tool_capabilities: dict[str, str] = {name: spec.capability for name, spec in CATALOG.items()}
    tool_capabilities.update(_DECORATED_TOOL_CAPABILITIES)

    return PhaseProfiles(
        {
            phase: PhaseProfile(
                phase=phase,
                system_prompt=_PROMPTS[phase],
                tool_names=frozenset(tool_names_by_phase[phase]),
                action_stages=(
                    PhaseToolGuardStage(
                        phase,
                        frozenset(tool_names_by_phase[phase]) | {"tool_help"},
                        tool_capabilities,
                    ),
                ),
            )
            for phase in Phase
        }
    )
