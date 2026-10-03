"""InputGuardStage: a hard length cap on submitted input — cheap defense
against a huge accidental paste blowing the context window before B2's
compaction gets a turn to run. Deliberately doesn't pattern-match for
override-attempt phrasing: this is the operator's own instruction to their
own agent, not untrusted data crossing a trust boundary (that's
ToolOutputScreenStage's job) — blocking a trusted principal's own wording on
a heuristic would only add false-positive friction, not stop anything they
couldn't already do directly."""

from __future__ import annotations

from cism.agent.guardrails.chain import GuardrailResult

__all__ = ["MAX_INPUT_CHARS", "InputGuardStage"]

MAX_INPUT_CHARS = 8_000


class InputGuardStage:
    name = "input-guard"

    def check(self, value: str) -> GuardrailResult[str]:
        if len(value) > MAX_INPUT_CHARS:
            return GuardrailResult(
                allowed=False, value=value, reason=f"input exceeds {MAX_INPUT_CHARS} characters"
            )
        return GuardrailResult(allowed=True, value=value)
