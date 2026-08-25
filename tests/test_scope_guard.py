"""cism/agent/guardrails/scope.py: ScopeGuardStage blocks a tool call whose
target falls outside the declared engagement scope, and allows a call
through when no target-shaped argument can be found at all.
"""

from __future__ import annotations

import ipaddress

from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage


def _call(name: str, **args) -> dict:
    return {"id": "call-1", "name": name, "args": args, "type": "tool_call"}


def _stage() -> ScopeGuardStage:
    scope = EngagementScope(
        cidrs=(ipaddress.ip_network("10.0.0.0/24"),),
        domains=("example.com",),
    )
    return ScopeGuardStage(scope)


def test_an_in_scope_ip_target_is_allowed() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", options="-sV"))
    assert result.allowed is True


def test_an_out_of_scope_ip_target_is_blocked() -> None:
    result = _stage().check(_call("nmap", target="192.168.1.5", options="-sV"))
    assert result.allowed is False
    assert "192.168.1.5" in result.reason


def test_an_exact_domain_match_is_allowed() -> None:
    result = _stage().check(_call("curl", url="https://example.com/"))
    assert result.allowed is True


def test_a_subdomain_of_an_in_scope_domain_is_allowed() -> None:
    result = _stage().check(_call("curl", url="https://api.example.com/report"))
    assert result.allowed is True


def test_an_out_of_scope_domain_is_blocked() -> None:
    result = _stage().check(_call("curl", url="https://evil.org/"))
    assert result.allowed is False


def test_a_composite_user_at_host_argument_is_checked_against_scope() -> None:
    result = _stage().check(_call("ssh", host="root@192.168.1.5"))
    assert result.allowed is False
    assert "192.168.1.5" in result.reason


def test_a_call_with_no_target_shaped_argument_is_allowed_through() -> None:
    result = _stage().check(_call("ss", options="-tulpn"))
    assert result.allowed is True


def test_an_unregistered_tool_falls_back_to_scanning_every_string_arg() -> None:
    result = _stage().check(_call("some-new-tool", host="evil.org", note="fine"))
    assert result.allowed is False


def test_an_unregistered_tool_with_no_host_shaped_values_is_allowed() -> None:
    result = _stage().check(_call("john", mode="wordlist", format="raw-md5"))
    assert result.allowed is True
