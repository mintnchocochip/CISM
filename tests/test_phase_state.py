"""cism/agent/state.py: the phase enum, its transition table, and the
single choke point every phase change must go through."""

from __future__ import annotations

import pytest

from cism.agent.state import PHASE_TRANSITIONS, IllegalPhaseTransition, Phase, PhaseStateMachine


def test_every_phase_can_stay_put() -> None:
    for phase in Phase:
        assert phase in PHASE_TRANSITIONS[phase]


@pytest.mark.parametrize(
    "start,to",
    [
        (Phase.RECON, Phase.ENUMERATION),
        (Phase.ENUMERATION, Phase.VULNERABILITY_DISCOVERY),
        (Phase.ENUMERATION, Phase.RECON),
        (Phase.VULNERABILITY_DISCOVERY, Phase.EXPLOITATION),
        (Phase.EXPLOITATION, Phase.POST_EXPLOITATION),
        (Phase.EXPLOITATION, Phase.VULNERABILITY_DISCOVERY),
        (Phase.POST_EXPLOITATION, Phase.RECON),
        (Phase.POST_EXPLOITATION, Phase.REPORTING),
    ],
)
def test_legal_transitions_succeed(start: Phase, to: Phase) -> None:
    machine = PhaseStateMachine(start)
    assert machine.can_transition(to)
    assert machine.transition(to) is to
    assert machine.current is to


@pytest.mark.parametrize(
    "start,to",
    [
        (Phase.RECON, Phase.EXPLOITATION),
        (Phase.RECON, Phase.REPORTING),
        (Phase.REPORTING, Phase.RECON),
        (Phase.EXPLOITATION, Phase.RECON),
    ],
)
def test_illegal_transitions_raise_and_leave_current_unchanged(start: Phase, to: Phase) -> None:
    machine = PhaseStateMachine(start)
    assert not machine.can_transition(to)
    with pytest.raises(IllegalPhaseTransition):
        machine.transition(to)
    assert machine.current is start


def test_reporting_is_terminal() -> None:
    assert PHASE_TRANSITIONS[Phase.REPORTING] == frozenset({Phase.REPORTING})


def test_wire_format_matches_phase_changed_event_convention() -> None:
    assert Phase.RECON.to_wire() == "recon"
    assert Phase.VULNERABILITY_DISCOVERY.to_wire() == "vulnerability-discovery"
    assert Phase.POST_EXPLOITATION.to_wire() == "post-exploitation"
