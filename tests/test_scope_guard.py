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
    result = _stage().check(_call("curl", target="https://example.com/"))
    assert result.allowed is True


def test_a_subdomain_of_an_in_scope_domain_is_allowed() -> None:
    result = _stage().check(_call("curl", target="https://api.example.com/report"))
    assert result.allowed is True


def test_an_out_of_scope_domain_is_blocked() -> None:
    result = _stage().check(_call("curl", target="https://evil.org/"))
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


def test_a_second_target_smuggled_into_extra_as_a_bare_positional_is_blocked() -> None:
    """render_argv (base.py) places extra's tokens BEFORE target in argv
    — for curl this means a bare URL in extra becomes a second URL curl
    will actually fetch, completely unvetted by the scope check that only
    ever looked at "target". This is a real, currently-exploitable bypass
    in shipped code, not a hypothetical."""
    result = _stage().check(
        _call("curl", target="https://example.com", extra="https://evil-target.com")
    )
    assert result.allowed is False


def test_a_second_target_smuggled_into_extra_via_nmap_is_blocked() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="192.168.1.99"))
    assert result.allowed is False


def test_an_in_scope_target_with_only_flags_in_extra_is_still_allowed() -> None:
    """The fix must not make every allow_raw call fail just because extra
    is non-empty — only an actual out-of-scope host inside extra should
    block."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="-p 80,443 -sV"))
    assert result.allowed is True


def test_a_comma_separated_multi_target_token_with_one_out_of_scope_host_is_blocked() -> None:
    """nmap accepts 'host1,host2' as one token. Before this fix,
    _extract_host doesn't recognize this shape at all and silently drops
    it — not incorrectly allowed by a broken check, just never checked."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="10.0.0.5,192.168.1.5"))
    assert result.allowed is False


def test_a_comma_separated_multi_target_token_with_all_in_scope_hosts_is_allowed() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="10.0.0.5,10.0.0.6"))
    assert result.allowed is True


def test_a_comma_containing_value_that_is_not_actually_a_host_list_is_unaffected() -> None:
    """A guard against over-fixing: something that merely contains a comma
    but isn't a clean multi-host list (e.g. a port list) must not be
    misclassified as a host token and must not break existing behavior."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="-p 80,443"))
    assert result.allowed is True


def test_a_valid_out_of_scope_host_smuggled_via_a_trailing_comma_is_still_blocked() -> None:
    """A comma-joined token where only SOME parts are host-shaped must not
    let the whole token slip past detection — otherwise appending a trailing
    comma is a trivial bypass for the comma-list check itself."""
    result = _stage().check(
        _call("nmap", target="10.0.0.5", extra="192.168.1.99,")
    )
    assert result.allowed is False


def test_a_valid_out_of_scope_host_smuggled_via_garbage_suffix_is_still_blocked() -> None:
    """A comma-joined token where only SOME parts are host-shaped must not
    let the whole token slip past detection — otherwise appending garbage
    after a comma is a trivial bypass for the comma-list check itself."""
    result = _stage().check(
        _call("nmap", target="10.0.0.5", extra="192.168.1.99,notahost")
    )
    assert result.allowed is False
