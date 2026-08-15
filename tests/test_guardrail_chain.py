"""cism/agent/guardrails/: chain of responsibility, no real checks yet.

Proves the mechanism — ordering, short-circuiting, pass-through-by-default
— before any real guardrail logic exists to test.
"""

from __future__ import annotations

from cism.agent.guardrails import GuardrailChain, GuardrailResult, GuardrailSeam, PassThroughStage


class _UpperCaseStage:
    name = "uppercase"

    def check(self, value: str) -> GuardrailResult[str]:
        return GuardrailResult(allowed=True, value=value.upper())


class _BlockingStage:
    name = "blocker"

    def __init__(self, reason: str = "blocked for test") -> None:
        self.reason = reason
        self.calls = 0

    def check(self, value: str) -> GuardrailResult[str]:
        self.calls += 1
        return GuardrailResult(allowed=False, value=value, reason=self.reason)


class _NeverCalledStage:
    name = "should-not-run"

    def __init__(self) -> None:
        self.calls = 0

    def check(self, value: str) -> GuardrailResult[str]:
        self.calls += 1
        return GuardrailResult(allowed=True, value=value)


def test_pass_through_chain_leaves_value_unchanged() -> None:
    chain = GuardrailChain([PassThroughStage()])
    result = chain.run("hello")
    assert result.allowed
    assert result.value == "hello"


def test_stages_run_in_order_and_can_transform() -> None:
    chain = GuardrailChain([PassThroughStage(), _UpperCaseStage()])
    result = chain.run("hello")
    assert result.allowed
    assert result.value == "HELLO"


def test_a_blocking_stage_short_circuits_later_stages() -> None:
    blocker = _BlockingStage(reason="nope")
    never_called = _NeverCalledStage()
    chain = GuardrailChain([blocker, never_called])

    result = chain.run("hello")

    assert not result.allowed
    assert result.reason == "nope"
    assert blocker.calls == 1
    assert never_called.calls == 0


def test_guardrail_seam_no_op_passes_everything_through() -> None:
    seam = GuardrailSeam.no_op()
    assert seam.input.run("text").allowed
    assert seam.output.run("text").allowed
    call = {"name": "dummy_nmap", "args": {"target": "10.0.0.5"}, "id": "c1", "type": "tool_call"}
    assert seam.action.run(call).allowed
