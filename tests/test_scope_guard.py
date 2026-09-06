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


def test_the_cloud_metadata_endpoint_is_blocked_even_inside_a_wide_declared_cidr() -> None:
    """169.254.169.254 (AWS/GCP/Azure instance metadata) must never be
    reachable through this agent, regardless of what the operator declared
    in scope — a classic SSRF pivot to steal instance credentials. Unlike
    RFC1918 ranges generally (legitimate targets for internal pentests),
    the metadata endpoint is never a legitimate target."""
    from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage

    wide_scope = EngagementScope(
        cidrs=(ipaddress.ip_network("169.254.0.0/16"),),
    )
    stage = ScopeGuardStage(wide_scope)

    result = stage.check(_call("curl", target="http://169.254.169.254/latest/meta-data/"))

    assert result.allowed is False


def test_gcp_metadata_hostname_is_blocked() -> None:
    from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage

    scope = EngagementScope(domains=("google.internal",))  # deliberately would match via subdomain rule
    stage = ScopeGuardStage(scope)

    result = stage.check(_call("curl", target="http://metadata.google.internal/computeMetadata/v1/"))

    assert result.allowed is False


def test_a_normal_in_scope_host_is_unaffected_by_the_metadata_denylist() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5"))
    assert result.allowed is True


def test_a_cidr_target_fully_within_the_declared_scope_is_allowed() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.0/28"))
    assert result.allowed is True


def test_a_cidr_smuggled_into_extra_fully_within_scope_is_allowed() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="10.0.0.0/28 -sV"))
    assert result.allowed is True


def test_a_cidr_target_entirely_outside_the_declared_scope_is_blocked() -> None:
    """Before the fix, _extract_host returned None for CIDR-shaped values
    and _candidate_hosts silently dropped them — an out-of-scope /24 target
    was never checked at all, not merely mismatched."""
    result = _stage().check(_call("nmap", target="192.168.1.0/24"))
    assert result.allowed is False


def test_a_cidr_smuggled_into_extra_entirely_outside_scope_is_blocked() -> None:
    """Task 1's exact threat model: render_argv places extra's tokens
    before the positional target, so `nmap 10.0.0.5` with
    extra="192.168.1.0/24" actually runs `nmap 192.168.1.0/24 10.0.0.5` —
    a whole out-of-scope network scan smuggled through extra."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="192.168.1.0/24"))
    assert result.allowed is False


def test_a_cidr_that_only_partially_overlaps_the_declared_scope_is_blocked() -> None:
    """Fail closed on partial overlap: a /23 straddling the declared
    10.0.0.0/24 scope only half-overlaps it and must not be allowed to
    scan the out-of-scope half."""
    result = _stage().check(_call("nmap", target="10.0.0.0/23"))
    assert result.allowed is False


def test_metadata_endpoint_expressed_as_a_slash_32_cidr_is_still_hard_denied() -> None:
    """169.254.169.254/32 is just another way to spell the bare address —
    Task 6's hard-deny must not be bypassable by adding a /32 suffix."""
    wide_scope = EngagementScope(cidrs=(ipaddress.ip_network("169.254.0.0/16"),))
    stage = ScopeGuardStage(wide_scope)

    result = stage.check(_call("nmap", target="169.254.169.254/32"))
    assert result.allowed is False


def test_metadata_endpoint_cidr_smuggled_into_extra_is_still_hard_denied() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="169.254.169.254/32"))
    assert result.allowed is False


def test_a_wide_cidr_that_merely_contains_the_metadata_address_is_not_hard_denied() -> None:
    """The hard-deny only fires for a CIDR that reduces to exactly one
    address matching the denylist, not any wider network that happens to
    contain it. A /16 covering (among billions of other addresses)
    169.254.169.254, when it IS the declared scope itself, is judged by
    the normal in-scope network check — not incorrectly hard-denied just
    because the metadata address falls somewhere inside it. Contrast with
    the /32 case above, which stays hard-denied even in this same scope."""
    wide_scope = EngagementScope(cidrs=(ipaddress.ip_network("169.254.0.0/16"),))
    stage = ScopeGuardStage(wide_scope)

    result = stage.check(_call("nmap", target="169.254.0.0/16"))
    assert result.allowed is True


def test_trailing_dot_fqdn_for_the_metadata_hostname_is_still_hard_denied() -> None:
    """A trailing "." makes an absolute DNS name — semantically identical
    to the name without it. Task 6's hard-deny on
    "metadata.google.internal" must not be defeated by this one-character
    difference."""
    result = _stage().check(_call("curl", target="http://metadata.google.internal./x"))
    assert result.allowed is False


def test_trailing_dot_fqdn_smuggled_into_extra_is_still_hard_denied() -> None:
    result = _stage().check(
        _call("nmap", target="10.0.0.5", extra="metadata.google.internal.")
    )
    assert result.allowed is False


def test_a_trailing_dot_in_scope_domain_is_still_allowed() -> None:
    """The trailing-dot normalization must work both ways: it should not
    turn an otherwise in-scope absolute domain name into a false block."""
    result = _stage().check(_call("curl", target="https://example.com./report"))
    assert result.allowed is True


def test_a_normal_host_with_no_trailing_dot_and_no_cidr_is_unaffected() -> None:
    """Regression guard: ordinary in-scope host targets, the overwhelming
    common case, must behave exactly as before these fixes."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="-sV -T4"))
    assert result.allowed is True


def test_the_ipv6_metadata_endpoint_is_blocked_regardless_of_case_or_compression() -> None:
    """_ALWAYS_DENIED_HOSTS stores the canonical lowercase-compressed form —
    the check itself must canonicalize before comparing, or an attacker
    can trivially bypass the hard-deny just by writing the same address
    differently."""
    from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage

    stage = ScopeGuardStage(EngagementScope())

    # Test uppercase variant
    result = stage.check(_call("curl", target="http://[FD00:EC2::254]/"))
    assert result.allowed is False, "IPv6 metadata endpoint in uppercase should be blocked"

    # Test fully-expanded variant (all zeros written out)
    result = stage.check(_call("curl", target="http://[fd00:ec2:0:0:0:0:0:254]/"))
    assert result.allowed is False, "IPv6 metadata endpoint in expanded form should be blocked"


def test_a_decimal_encoded_metadata_ip_is_blocked() -> None:
    """curl/getaddrinfo resolve a bare decimal integer as an IPv4 address
    (2852039166 == 169.254.169.254) — ipaddress.ip_address rejects this
    spelling outright, which is exactly the gap that let it slip past the
    scope guard unchecked before this fix."""
    result = _stage().check(_call("curl", target="http://2852039166/"))
    assert result.allowed is False


def test_a_hex_encoded_metadata_ip_is_blocked() -> None:
    result = _stage().check(_call("curl", target="http://0xA9FEA9FE/"))
    assert result.allowed is False


def test_a_decimal_encoded_out_of_scope_host_smuggled_into_extra_is_blocked() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="2130706433"))  # 127.0.0.1
    assert result.allowed is False


def test_a_small_decimal_flag_value_is_not_misread_as_an_encoded_ip() -> None:
    """The numeric-IPv4 recognition must not swallow ordinary small
    integers this agent's own tools actually take as arguments (a port,
    a thread count, an nmap timing level) — only a value large enough
    that it could plausibly BE an encoded address is treated as one."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="-T 4"))
    assert result.allowed is True

    result = _stage().check(_call("curl", target="https://example.com", extra="80"))
    assert result.allowed is True


def test_the_bare_metadata_short_hostname_is_blocked() -> None:
    """GCP's instance metadata service is also reachable via the bare
    single-label hostname "metadata" (resolved through the VM's default
    DNS search domain) — no dot at all, so _BARE_DOMAIN_RE never
    recognized it as host-shaped before this fix."""
    result = _stage().check(_call("curl", target="http://metadata/computeMetadata/v1/"))
    assert result.allowed is False

    result = _stage().check(_call("nmap", target="10.0.0.5", extra="metadata"))
    assert result.allowed is False


def test_an_unrelated_bare_word_is_still_allowed_through() -> None:
    """Regression guard: the bare-word hard-deny check is narrow — it only
    recognizes strings already in _ALWAYS_DENIED_HOSTS, so an ordinary
    service name or module path must still pass through unaffected."""
    result = _stage().check(_call("ss", options="-tulpn"))
    assert result.allowed is True

    result = _stage().check(_call("some-new-tool", note="responder"))
    assert result.allowed is True


def test_url_wrapped_decimal_encoded_metadata_ip_is_blocked_via_hard_deny() -> None:
    """Fix-round regression for Finding 1: the URL branch of _extract_host
    must recurse back through _extract_host so a numeric-encoded hostname
    embedded in a URL's authority gets canonicalized, not returned as the
    raw undecoded digit string. Proven here with a scope wide enough
    (0.0.0.0/0) that the raw string "2852039166" would ALSO be considered
    "in scope" if _is_always_denied's canonicalization never ran — so this
    test only passes if the hard-deny mechanism itself actually fired on
    the canonicalized "169.254.169.254", not incidentally via a narrow
    declared-scope mismatch."""
    wide_scope = EngagementScope(cidrs=(ipaddress.ip_network("0.0.0.0/0"),))
    stage = ScopeGuardStage(wide_scope)

    result = stage.check(_call("curl", target="http://2852039166/"))
    assert result.allowed is False


def test_url_wrapped_ordinary_domain_is_unaffected_by_the_recursion_fix() -> None:
    """The recursive _extract_host call in the URL branch must not change
    behavior for a plain domain that was already handled correctly."""
    result = _stage().check(_call("curl", target="http://example.com/"))
    assert result.allowed is True


def test_url_wrapped_bare_ip_authority_is_unaffected_by_the_recursion_fix() -> None:
    wide_scope = EngagementScope(cidrs=(ipaddress.ip_network("169.254.0.0/16"),))
    stage = ScopeGuardStage(wide_scope)

    result = stage.check(_call("curl", target="http://169.254.169.254/"))
    assert result.allowed is False  # still hard-denied, same as before the fix


def test_url_wrapped_nondenied_bare_word_is_unaffected_by_the_recursion_fix() -> None:
    """A single-label hostname that isn't in _ALWAYS_DENIED_HOSTS (so the
    recursive _extract_host call returns None) must fall back to the raw
    hostname via the ``or hostname`` clause, exactly as the un-recursed
    branch returned it before this fix."""
    scope = EngagementScope(domains=("localhost",))
    stage = ScopeGuardStage(scope)

    result = stage.check(_call("curl", target="http://localhost/"))
    assert result.allowed is True


def test_nmap_min_rate_value_is_not_misread_as_an_encoded_ip() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="--min-rate 100000"))
    assert result.allowed is True


def test_nmap_max_rate_value_is_not_misread_as_an_encoded_ip() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="--max-rate 500000"))
    assert result.allowed is True


def test_nmap_host_timeout_value_is_not_misread_as_an_encoded_ip() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="--host-timeout 900000"))
    assert result.allowed is True


def test_a_bare_smuggled_encoded_ip_not_following_a_numeric_arg_flag_is_still_blocked() -> None:
    """Regression guard for the _NUMERIC_ARG_FLAGS skip-list: it must only
    skip the token immediately after one of those specific flags, not
    weaken detection of an encoded IP smuggled anywhere else in extra."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="--min-rate 100000 2130706433"))
    assert result.allowed is False  # 2130706433 == 127.0.0.1, a bare (non-skipped) token

    result = _stage().check(_call("nmap", target="10.0.0.5", extra="2130706433"))
    assert result.allowed is False


def test_a_comma_glued_target_immediately_after_a_numeric_arg_flag_is_still_checked() -> None:
    """The skip for _NUMERIC_ARG_FLAGS must not apply to a token that
    isn't actually shaped like one of these flags' real numeric argument
    — a real --min-rate value is always a bare number, never a
    comma-list, so a comma-glued value placed right after the flag name
    must still be checked normally rather than skipped outright."""
    result = _stage().check(
        _call("nmap", target="10.0.0.5", extra="--min-rate 2852039166,10.0.0.1")
    )
    assert result.allowed is False


def test_a_genuinely_legitimate_rate_value_is_still_skipped_and_unaffected() -> None:
    """Regression guard: the digit-shape addition must not break the
    original fix — a real, bare numeric --min-rate value must still be
    skipped (not misread as an encoded IP) exactly as before this
    round."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="--min-rate 500000"))
    assert result.allowed is True


def test_a_file_url_target_with_no_host_at_all_is_blocked() -> None:
    """file:///etc/shadow has an empty authority — urlparse's .hostname is
    "" (falsy), so before this fix _extract_host returned None and
    _candidate_hosts treated it as "nothing to check" rather than "block
    this". curl supports file:// natively and returns the file's own
    contents as tool output — this is an arbitrary local file read, not a
    hypothetical."""
    result = _stage().check(_call("curl", target="file:///etc/shadow"))
    assert result.allowed is False


def test_a_file_url_smuggled_into_extra_is_blocked() -> None:
    result = _stage().check(
        _call("curl", target="https://example.com", extra="file:///etc/shadow")
    )
    assert result.allowed is False


def test_a_normal_url_with_a_real_hostname_is_unaffected() -> None:
    """Regression guard: the fix only changes behavior for a URL that
    parses to no host at all — an ordinary URL must still resolve its
    real hostname and be checked against scope exactly as before."""
    result = _stage().check(_call("curl", target="https://example.com/report"))
    assert result.allowed is True


def test_a_tool_mapped_to_a_target_arg_name_the_catalog_never_emits_still_gets_scope_checked() -> None:
    """_TARGET_ARG_BY_TOOL maps wget/gobuster/ffuf to "url" and ssh/scp to
    "host" — but build_catalog (base.py) always names the target field
    "target", never these. Before this fix, a tool call under one of
    these five names took the registered-tool branch, looked up a key
    that's never present, found nothing, and checked NOTHING — not the
    fallback scan, silence. This test simulates exactly that shape
    (a real ToolCall args dict for a hypothetical catalog-built "wget")
    to prove the fallback now kicks in."""
    result = _stage().check(_call("wget", target="http://169.254.169.254/"))
    assert result.allowed is False


def test_the_existing_registered_tools_are_unaffected_by_the_fallback_change() -> None:
    """Regression guard: every currently-real registered tool (nmap,
    curl, hydra, medusa, masscan) really is mapped to "target", which
    build_catalog really does emit — the fallback path must never trigger
    for these, so behavior must be identical to before this task."""
    result = _stage().check(_call("nmap", target="10.0.0.5"))
    assert result.allowed is True

    result = _stage().check(_call("curl", target="192.168.1.5"))
    assert result.allowed is False


def test_a_comma_list_with_one_real_host_and_one_permanently_unparseable_part_is_blocked() -> None:
    """A comma-joined token where SOME parts are host-shaped and others
    genuinely aren't recognized by this parser (not "clearly a port
    list" — nothing would parse; not "clearly a clean multi-host list" —
    everything parses) must be blocked outright rather than silently
    keeping just the parts this parser happened to recognize. An
    unrecognized comma-part might be host-shaped in an encoding this
    parser doesn't know about yet — defense in depth for the next
    encoding, on top of Task 1's specific fixes."""
    result = _stage().check(
        _call("nmap", target="10.0.0.5", extra="10.0.0.5,this-has-a-space in it")
    )
    assert result.allowed is False


def test_a_comma_list_where_every_part_parses_is_still_checked_normally() -> None:
    """Regression guard: the "all parts recognized" case must be
    unaffected — still checked host-by-host, not treated as a blanket
    block just because it's a comma list."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="10.0.0.5,10.0.0.6"))
    assert result.allowed is True


def test_a_comma_list_where_no_part_parses_is_still_allowed_through() -> None:
    """Regression guard: "nothing here looks like a target list at all"
    (e.g. a port range) must remain allowed, unchanged from before this
    task."""
    result = _stage().check(_call("nmap", target="10.0.0.5", extra="-p 80,443"))
    assert result.allowed is True


def test_ipv4_mapped_ipv6_form_of_the_metadata_ip_is_hard_denied() -> None:
    """9300eab canonicalized case/compression for a bare IPv6 address, but
    Python renders "::ffff:169.254.169.254" as "::ffff:a9fe:a9fe" — a
    string that isn't in _ALWAYS_DENIED_HOSTS on its own, so the embedded
    IPv4 address was never being extracted for comparison. A v6-capable
    declared scope is required for this to reach EngagementScope at all
    (a v4-only scope already fails closed on a v6-family mismatch), so
    this uses an empty scope — the hard-deny must fire regardless."""
    from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage

    stage = ScopeGuardStage(EngagementScope())

    result = stage.check(_call("curl", target="http://[::ffff:169.254.169.254]/"))
    assert result.allowed is False

    result = stage.check(_call("curl", target="http://[::ffff:a9fe:a9fe]/"))
    assert result.allowed is False


def test_a_normal_ipv6_address_unrelated_to_the_denylist_is_unaffected() -> None:
    """Regression guard: the ipv4_mapped check must only fire for an
    actual IPv4-mapped address; an ordinary, unrelated IPv6 host must
    still pass through the normal scope check unaffected."""
    from cism.agent.guardrails.scope import EngagementScope, ScopeGuardStage

    scope = EngagementScope(cidrs=(ipaddress.ip_network("2001:db8::/32"),))
    stage = ScopeGuardStage(scope)

    result = stage.check(_call("curl", target="http://[2001:db8::1]/"))
    assert result.allowed is True


def test_nmap_hostname_slash_prefixlen_syntax_is_blocked() -> None:
    """nmap's own documented target syntax ("hostname/prefixlen") resolves
    the hostname and scans the surrounding network — before this fix,
    _extract_host's CIDR branch only recognized numeric CIDR literals and
    silently fell through to unrecognized (unchecked, not blocked) for
    anything else containing a "/". Verified live: this reaches argv
    unblocked, with the metadata hostname as the host half."""
    result = _stage().check(_call("nmap", target="metadata.google.internal/24"))
    assert result.allowed is False


def test_a_malformed_leading_zero_cidr_is_blocked() -> None:
    """A leading-zero octet is rejected by ipaddress.ip_network (Python
    treats it as ambiguous/potentially-octal) but wasn't rejected by real
    network tools historically — before this fix the ValueError caused a
    silent fall-through to "unrecognized", not a block."""
    result = _stage().check(_call("nmap", target="192.168.001.0/24"))
    assert result.allowed is False


def test_an_out_of_range_prefix_length_is_blocked() -> None:
    result = _stage().check(_call("nmap", target="10.0.0.0/33"))
    assert result.allowed is False


def test_a_url_with_a_numeric_last_path_segment_is_not_misread_as_a_cidr() -> None:
    """Regression guard: an ordinary URL whose last path segment happens
    to be numeric (a REST resource id) must not be misread as
    "hostname/prefixlen" and blocked as an unparseable network — real
    CIDR/hostname-prefix target syntax is always a bare string, never
    embedded in a URL, so anything containing "://" is excluded from the
    CIDR-detection branch entirely."""
    result = _stage().check(_call("curl", target="https://example.com/v1/users/24"))
    assert result.allowed is True


def test_existing_numeric_cidr_behavior_is_unaffected() -> None:
    """Regression guard: the already-working numeric-CIDR happy paths
    (in-scope, out-of-scope, partial-overlap, metadata /32 hard-deny)
    must all still hold exactly as before this task."""
    result = _stage().check(_call("nmap", target="10.0.0.0/28"))
    assert result.allowed is True

    result = _stage().check(_call("nmap", target="192.168.1.0/24"))
    assert result.allowed is False


def test_a_malformed_bracketed_url_is_blocked_not_raised() -> None:
    """_extract_host's urlparse(value).hostname access can raise
    ValueError on a malformed bracketed URL (a plausible model
    hallucination, e.g. an unterminated IPv6 bracket) — this must now
    produce a blocked GuardrailResult via GuardrailChain.run's exception
    handling, not propagate out of ScopeGuardStage.check() directly (the
    stage itself doesn't catch it; the chain does, per Task 9)."""
    from cism.agent.guardrails.chain import GuardrailChain

    chain = GuardrailChain([_stage()])
    result = chain.run(_call("curl", target="http://[::1"))
    assert result.allowed is False
