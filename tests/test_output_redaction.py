"""cism/agent/guardrails/output_redaction.py: enforces cism.tui.redact's
credential detection in the pipeline itself, not just the display layer (C1, AUDIT.md).

Q1, CODE_REVIEW.md: the stage used to reuse redact_command's space-only
tokenizer, so a secret delimited by anything else (newline, tab, a JSON
quote/colon) sailed through unmasked even though this stage is the only
thing enforcing "no secret in the final answer". Parametrized below over
every delimiter shape the finding called out."""

from __future__ import annotations

import pytest

from cism.agent.guardrails.output_redaction import OutputRedactionStage

_SECRET = "sk-ant-abcdefghijklmnopqrstuvwx"


def test_a_credential_shaped_word_is_masked_and_never_blocked() -> None:
    stage = OutputRedactionStage()
    result = stage.check("your api key is sk-ant-abcdefghijklmnopqrstuvwx")

    assert result.allowed is True
    assert "sk-ant-abcdefghijklmnopqrstuvwx" not in result.value
    assert "••••••••" in result.value


def test_ordinary_text_passes_through_unchanged() -> None:
    stage = OutputRedactionStage()
    result = stage.check("scan complete: 2 open ports found")

    assert result.value == "scan complete: 2 open ports found"


@pytest.mark.parametrize(
    "text",
    [
        f"Authorization:\n{_SECRET}",
        f"token\t{_SECRET}",
        f"token\r\n{_SECRET}",
        f'"token":"{_SECRET}"',
        f"{{'token': '{_SECRET}'}}",
    ],
    ids=["newline", "tab", "crlf", "json-value", "python-dict-value"],
)
def test_a_secret_is_masked_regardless_of_what_delimits_it(text: str) -> None:
    stage = OutputRedactionStage()
    result = stage.check(text)

    assert _SECRET not in result.value
    assert "••••••••" in result.value
