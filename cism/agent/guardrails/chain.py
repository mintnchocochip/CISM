"""The guardrail seam: chain of responsibility, no real checks yet.

Three chains are threaded through the graph — input, action, output — each a
``GuardrailChain`` over its own payload type. All three default to a single
:class:`PassThroughStage`, so today nothing is actually checked. Adding a
real guardrail later means appending a stage to the relevant chain; the
runner and the graph shape it is wired into never change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

from langchain_core.messages.tool import ToolCall

__all__ = [
    "GuardrailChain",
    "GuardrailResult",
    "GuardrailSeam",
    "GuardrailStage",
    "PassThroughStage",
]

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class GuardrailResult(Generic[T]):
    """The outcome of running a value through a chain.

    ``value`` carries the (possibly transformed) payload forward when
    ``allowed`` is true, or is the original payload unchanged when it is
    false — ``reason`` explains the block in that case.
    """

    allowed: bool
    value: T
    reason: str = ""


class GuardrailStage(Protocol[T]):
    """One link in a guardrail chain."""

    name: str

    def check(self, value: T) -> GuardrailResult[T]: ...


class GuardrailChain(Generic[T]):
    """Runs stages in order. The first stage to block wins and short-circuits
    the rest; a passing stage may transform the value before the next stage
    sees it."""

    def __init__(self, stages: list[GuardrailStage[T]]) -> None:
        self._stages = list(stages)

    def run(self, value: T) -> GuardrailResult[T]:
        current = value
        for stage in self._stages:
            result = stage.check(current)
            if not result.allowed:
                return result
            current = result.value
        return GuardrailResult(allowed=True, value=current)


class PassThroughStage(Generic[T]):
    """Lets every value through unchanged. The only stage wired in today."""

    name = "pass-through"

    def check(self, value: T) -> GuardrailResult[T]:
        return GuardrailResult(allowed=True, value=value)


@dataclass(frozen=True, slots=True)
class GuardrailSeam:
    """The three chains bundled into one dependency for the graph and agent."""

    input: GuardrailChain[str]
    action: GuardrailChain[ToolCall]
    output: GuardrailChain[str]

    @classmethod
    def no_op(cls) -> GuardrailSeam:
        return cls(
            input=GuardrailChain([PassThroughStage()]),
            action=GuardrailChain([PassThroughStage()]),
            output=GuardrailChain([PassThroughStage()]),
        )
