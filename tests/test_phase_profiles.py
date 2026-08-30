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


def test_default_profiles_gives_exploitation_more_tools_than_recon() -> None:
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert profiles.get(Phase.RECON).tool_names <= profiles.get(Phase.EXPLOITATION).tool_names


def test_default_profiles_reporting_phase_has_no_tools() -> None:
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert profiles.get(Phase.REPORTING).tool_names == frozenset()
