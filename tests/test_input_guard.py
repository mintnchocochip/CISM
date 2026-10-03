"""cism/agent/guardrails/input_guard.py: a length cap on submitted input,
defense against blowing the context window before B2's compaction has a
turn to run (C1, AUDIT.md)."""

from __future__ import annotations

from cism.agent.guardrails.input_guard import MAX_INPUT_CHARS, InputGuardStage


def test_ordinary_input_is_allowed_unchanged() -> None:
    stage = InputGuardStage()
    result = stage.check("scan 10.0.0.5")

    assert result.allowed is True
    assert result.value == "scan 10.0.0.5"


def test_input_over_the_cap_is_blocked() -> None:
    stage = InputGuardStage()
    result = stage.check("x" * (MAX_INPUT_CHARS + 1))

    assert result.allowed is False
    assert "exceeds" in result.reason


def test_input_exactly_at_the_cap_is_allowed() -> None:
    stage = InputGuardStage()
    result = stage.check("x" * MAX_INPUT_CHARS)

    assert result.allowed is True
