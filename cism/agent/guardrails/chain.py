"""The guardrail seam: chain of responsibility.

Four chains run through the graph — input, action, output, tool_output —
each a ``GuardrailChain`` over its own payload type. Adding a guardrail
means appending a stage to the relevant chain; the runner and graph shape
never change. ``LangGraphAgent``'s default is ``GuardrailSeam.no_op()``;
``run_agent.py --live-tools`` builds a real one and passes it in explicitly."""

from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

from langchain_core.messages.tool import ToolCall

_log = logging.getLogger(__name__)

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
    """The outcome of running a value through a chain. ``value`` carries the
    (possibly transformed) payload when ``allowed``, else the original
    payload with ``reason`` explaining the block."""

    allowed: bool
    value: T
    reason: str = ""
    stage: str = ""


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

    @property
    def stages(self) -> list[GuardrailStage[T]]:
        return list(self._stages)

    def run(self, value: T) -> GuardrailResult[T]:
        current = value
        for stage in self._stages:
            try:
                result = stage.check(current)
            except Exception as exc:
                # A stage raising on a malformed call must not crash the graph node.
                stage_name = getattr(stage, "name", "unknown")  # stage itself may be malformed
                _log.warning(
                    "guardrail stage raised", extra={"data": {"stage": stage_name, "error": str(exc)}}
                )
                return GuardrailResult(
                    allowed=False,
                    value=current,
                    reason=f"{type(exc).__name__}: {exc}",
                    stage=stage_name,
                )
            if not result.allowed:
                _log.info(
                    "guardrail blocked", extra={"data": {"stage": stage.name, "reason": result.reason}}
                )
                return dataclasses.replace(result, stage=stage.name)
            current = result.value
        return GuardrailResult(allowed=True, value=current)


class PassThroughStage(Generic[T]):
    """Lets every value through unchanged. The only stage wired in today."""

    name = "pass-through"

    def check(self, value: T) -> GuardrailResult[T]:
        return GuardrailResult(allowed=True, value=value)


@dataclass(frozen=True, slots=True)
class GuardrailSeam:
    """The four chains bundled into one dependency for the graph and agent.
    ``tool_output`` defaults to pass-through so existing callers that only
    name input/action/output keep working unchanged."""

    input: GuardrailChain[str]
    action: GuardrailChain[ToolCall]
    output: GuardrailChain[str]
    tool_output: GuardrailChain[str] = dataclasses.field(
        default_factory=lambda: GuardrailChain([PassThroughStage()])
    )

    @classmethod
    def no_op(cls) -> GuardrailSeam:
        return cls(
            input=GuardrailChain([PassThroughStage()]),
            action=GuardrailChain([PassThroughStage()]),
            output=GuardrailChain([PassThroughStage()]),
            tool_output=GuardrailChain([PassThroughStage()]),
        )
