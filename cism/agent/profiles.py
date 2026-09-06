"""Per-phase configuration for think/act: prompt, tool subset, extra action
guardrail stages. One profile per phase; think/act consume this registry and
never branch on phase themselves, so promoting a phase to a real subagent
later is a hand-off at phase_router, not a graph change.

tool_names is derived from cism.agent.tools.catalog.CATALOG via phases_for,
not hand-authored per phase — adding a catalog row with the right
capability (or an explicit `phases:` override) is what makes it reachable
in a phase, not a second edit here. Decorated (non-catalog) tools like
hydra, which have no CATALOG row (see the design doc §5), get their phase
availability from _DECORATED_TOOL_PHASES instead.
"""

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

#: Decorated tools (cism.agent.tools.credentials.hydra) have no CATALOG row
#: — see the design doc §5's extra_binaries reasoning — so their phase
#: availability can't come from phases_for(). This is the one place that
#: gap is filled by hand.
_DECORATED_TOOL_PHASES: dict[str, frozenset[Phase]] = {
    "hydra": frozenset({Phase.EXPLOITATION, Phase.POST_EXPLOITATION}),
    "dummy_nmap": frozenset({Phase.RECON}),
    "dummy_msfconsole": frozenset({Phase.ENUMERATION}),
}

#: Same gap as _DECORATED_TOOL_PHASES, for the capability axis instead of
#: the phase axis: decorated tools have no CATALOG row to read a
#: `capability:` value from. hydra's is now real (Task 4's conversion to
#: sandboxed_tool), read here rather than hand-duplicated a third time.
_DECORATED_TOOL_CAPABILITIES: dict[str, str] = {
    "hydra": "executes",
    "dummy_nmap": "reads",
    "dummy_msfconsole": "executes",
}


def default_profiles(tools: ToolRegistry) -> PhaseProfiles:
    """The basic profile set. tool_names lists real tool names; a caller
    whose registry only has the dummy tools simply binds nothing for a
    phase — see make_think_node, which filters tool_names
    against what the registry actually contains. Every phase also gets a
    PhaseToolGuardStage built from that exact same tool_names value, so
    the action-chain re-check can never drift from what binding decided."""
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
