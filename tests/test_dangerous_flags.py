"""cism/agent/guardrails/dangerous_flags.py: DangerousFlagGuardStage blocks
a tool call whose free-form `extra` argument contains a flag that can read
or write outside the sandbox's scratch directory. Token-level match
against shlex.split(extra), not a substring scan — a target/URL value that
happens to contain "-o" as a substring must not false-positive.
"""

from __future__ import annotations

from cism.agent.guardrails.dangerous_flags import DangerousFlagGuardStage


def _call(**args) -> dict:
    return {"id": "call-1", "name": "nmap", "args": args, "type": "tool_call"}


def _stage() -> DangerousFlagGuardStage:
    return DangerousFlagGuardStage()


def test_a_call_with_no_extra_argument_is_allowed() -> None:
    result = _stage().check(_call(target="10.0.0.5"))
    assert result.allowed is True


def test_a_call_with_harmless_extra_flags_is_allowed() -> None:
    result = _stage().check(_call(target="10.0.0.5", extra="-sV -T4"))
    assert result.allowed is True


def test_nmap_script_flag_is_blocked() -> None:
    result = _stage().check(_call(target="10.0.0.5", extra="--script vuln"))
    assert result.allowed is False
    assert "--script" in result.reason


def test_nmap_output_flags_are_blocked() -> None:
    for flag in ("-oN", "-oX", "-oG", "-oA"):
        result = _stage().check(_call(target="10.0.0.5", extra=f"{flag} /tmp/out"))
        assert result.allowed is False, flag


def test_curl_upload_and_config_flags_are_blocked() -> None:
    result = _stage().check(_call(target="https://x", extra="--upload-file /etc/passwd"))
    assert result.allowed is False

    result = _stage().check(_call(target="https://x", extra="-K /etc/curlrc"))
    assert result.allowed is False


def test_a_target_value_containing_a_dangerous_token_as_a_substring_is_not_blocked() -> None:
    """Token match, not substring match: a hostname/path that happens to
    contain "-o" inside another word must not false-positive."""
    result = _stage().check(_call(target="not-outbound-host.example.com", extra="-sV"))
    assert result.allowed is True


def test_a_bare_dash_o_flag_is_blocked() -> None:
    result = _stage().check(_call(target="10.0.0.5", extra="-o /tmp/pwn.txt"))
    assert result.allowed is False
