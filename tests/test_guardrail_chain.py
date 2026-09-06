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


def test_stages_exposes_the_chains_stage_list() -> None:
    stage = PassThroughStage()
    chain = GuardrailChain([stage])

    assert chain.stages == [stage]


def test_a_blocking_stage_result_is_stamped_with_the_stage_that_blocked_it() -> None:
    blocker = _BlockingStage(reason="nope")
    chain = GuardrailChain([blocker])

    result = chain.run("hello")

    assert result.stage == "blocker"


def test_a_passing_result_has_no_stage_stamped() -> None:
    chain = GuardrailChain([PassThroughStage()])

    result = chain.run("hello")

    assert result.stage == ""


class _RaisingStage:
    name = "raising-stage"

    def check(self, value):
        raise ValueError("could not parse this call")


def test_a_stage_that_raises_produces_a_blocked_result_instead_of_propagating() -> None:
    """A malformed/adversarial call can make a stage's internal parsing
    logic raise (e.g. scope.py's _extract_host on a malformed bracketed
    URL, or a non-dict `args` from a malformed ToolCall langchain_core can
    actually produce). Before this fix that exception escapes run(),
    propagates out of act(), and is caught by core.py's broad top-level
    except — ending the ENTIRE agent run rather than blocking the ONE
    call. A single hallucinated or malformed tool call must not have the
    power to kill the run."""
    chain = GuardrailChain([_RaisingStage()])

    result = chain.run("hello")

    assert result.allowed is False
    assert result.stage == "raising-stage"
    assert "could not parse this call" in result.reason


def test_a_stage_that_raises_short_circuits_later_stages_the_same_way_a_block_does() -> None:
    never_called = _NeverCalledStage()
    chain = GuardrailChain([_RaisingStage(), never_called])

    result = chain.run("hello")

    assert result.allowed is False
    assert never_called.calls == 0
