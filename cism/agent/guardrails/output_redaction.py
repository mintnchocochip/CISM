"""OutputRedactionStage: the same credential-shaped-word detection
cism.tui.redact uses to mask what's shown on screen, enforced in the
pipeline itself — the TUI's redaction is display-only, so a final answer
that echoes back a key isn't actually caught unless the guardrail catches it too."""

from __future__ import annotations

from cism.agent.guardrails.chain import GuardrailResult
from cism.tui.redact import redact_text

__all__ = ["OutputRedactionStage"]


class OutputRedactionStage:
    name = "output-redaction"

    def check(self, value: str) -> GuardrailResult[str]:
        return GuardrailResult(allowed=True, value=redact_text(value))
