"""cism/agent/profiles.py: per-phase prompt/tool-subset/action-stage config,
a hard allowlist like ToolRegistry."""

from __future__ import annotations

import pytest

from cism.agent.profiles import PhaseProfile, PhaseProfiles, default_profiles
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap


def test_get_returns_the_profile_for_a_phase() -> None:
    profile = PhaseProfile(phase=Phase.RECON, system_prompt="p", tool_names=frozenset({"nmap"}))
    profiles = PhaseProfiles({Phase.RECON: profile})

    assert profiles.get(Phase.RECON) is profile


def test_phases_lists_only_registered_phases() -> None:
    profile = PhaseProfile(phase=Phase.RECON, system_prompt="p", tool_names=frozenset())
    profiles = PhaseProfiles({Phase.RECON: profile})

    assert profiles.phases() == [Phase.RECON]


def test_get_raises_on_an_unregistered_phase() -> None:
    profiles = PhaseProfiles({})
    with pytest.raises(KeyError):
        profiles.get(Phase.RECON)


def test_default_profiles_covers_every_phase() -> None:
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    for phase in Phase:
        profile = profiles.get(phase)
        assert profile.phase == phase
        assert profile.system_prompt


def test_default_profiles_exploitation_includes_hydra_but_not_recon_only_tools() -> None:
    """Adding tools with a real per-tool phase policy means phase tool sets
    are no longer a monotonically growing superset (the old hand-written
    _TOOLS table happened to make RECON <= EXPLOITATION true by omission,
    not by design) — a recon-only scanner like nikto correctly disappears
    from EXPLOITATION's tool set."""
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert "hydra" in profiles.get(Phase.EXPLOITATION).tool_names
    assert "nikto" not in profiles.get(Phase.EXPLOITATION).tool_names


def test_default_profiles_recon_includes_every_reads_capability_catalog_tool() -> None:
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert {"nikto", "whatweb", "dnsenum", "nmap", "curl"} <= profiles.get(Phase.RECON).tool_names


def test_default_profiles_name_a_concrete_tool_and_a_done_criterion() -> None:
    """2026-10-12: the original one-sentence-per-phase prompts gave a real
    small model no stopping criterion and no tool-selection hint — a live
    run against them produced zero tool calls on an open-ended instruction.
    Each actionable phase now names at least one real tool and a concrete
    "done" signal, not just the phase's abstract goal."""
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert "nmap" in profiles.get(Phase.RECON).system_prompt
    assert "whatweb" in profiles.get(Phase.ENUMERATION).system_prompt
    assert "nikto" in profiles.get(Phase.VULNERABILITY_DISCOVERY).system_prompt
    assert "hydra" in profiles.get(Phase.EXPLOITATION).system_prompt


def test_default_profiles_reporting_phase_has_no_tools() -> None:
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert profiles.get(Phase.REPORTING).tool_names == frozenset()


def test_default_profiles_attaches_a_phase_tool_guard_matching_its_own_tool_names() -> None:
    """The guard's allowed set must be exactly this phase's own tool_names
    plus tool_help — proving it can't drift from binding by construction,
    not just by convention."""
    from cism.agent.guardrails import PhaseToolGuardStage

    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    for phase in Phase:
        profile = profiles.get(phase)
        assert len(profile.action_stages) == 1
        stage = profile.action_stages[0]
        assert isinstance(stage, PhaseToolGuardStage)
        assert stage._allowed == profile.tool_names | {"tool_help"}


def test_default_profiles_phase_tool_guard_knows_hydras_real_capability() -> None:
    from cism.agent.guardrails import PhaseToolGuardStage

    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    stage = profiles.get(Phase.RECON).action_stages[0]
    assert isinstance(stage, PhaseToolGuardStage)
    assert stage._capabilities.get("hydra") == "executes"


def test_default_profiles_phase_tool_guard_blocks_hydra_outside_its_phases() -> None:
    from cism.agent.guardrails import PhaseToolGuardStage

    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    stage = profiles.get(Phase.RECON).action_stages[0]
    result = stage.check({"id": "c1", "name": "hydra", "args": {}, "type": "tool_call"})
    assert result.allowed is False
