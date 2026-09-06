"""cism/agent/guardrails/dangerous_flags.py: DangerousFlagGuardStage blocks
a tool call whose free-form `extra` argument contains a flag that can read
or write outside the sandbox's scratch directory. Matching runs against
shlex.split(extra) tokens, not a substring scan of the whole `extra`
string — a target/URL value that happens to contain "-o" as a substring
must not false-positive. Within a token, a short (-x) denylisted flag
matches by prefix (curl/nmap accept an attached value with no separating
space, e.g. "-o/tmp/pwn"); a long (--xxx) denylisted flag matches only by
exact `=`-split head, never by prefix, so one long flag is never mistaken
for another that merely shares its start.
"""

from __future__ import annotations

from cism.agent.guardrails.dangerous_flags import DangerousFlagGuardStage


def _call(name: str = "nmap", **args) -> dict:
    return {"id": "call-1", "name": name, "args": args, "type": "tool_call"}


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
    result = _stage().check(_call(name="curl", target="https://x", extra="--upload-file /etc/passwd"))
    assert result.allowed is False

    result = _stage().check(_call(target="https://x", extra="-K /etc/curlrc"))  # -K is shared, name doesn't matter
    assert result.allowed is False


def test_a_target_value_containing_a_dangerous_token_as_a_substring_is_not_blocked() -> None:
    """Token match, not substring match: a hostname/path that happens to
    contain "-o" inside another word must not false-positive."""
    result = _stage().check(_call(target="not-outbound-host.example.com", extra="-sV"))
    assert result.allowed is True


def test_a_bare_dash_o_flag_is_blocked() -> None:
    result = _stage().check(_call(name="curl", target="https://x", extra="-o /tmp/pwn.txt"))
    assert result.allowed is False


def test_an_unparseable_extra_argument_is_blocked_not_raised() -> None:
    """An unbalanced quote makes shlex.split raise ValueError. The guard
    must fail closed (block the call) rather than let the exception escape
    — this stage runs before act()'s try/except in nodes.py, so a raised
    ValueError here would crash the whole graph run instead of producing a
    normal blocked-call outcome."""
    result = _stage().check(_call(target="10.0.0.5", extra='-H "unbalanced'))
    assert result.allowed is False


def test_curl_form_flag_is_blocked() -> None:
    """curl -F/--form supports @path to read and upload an arbitrary local
    file — same class of risk as the already-covered -T/--upload-file,
    just a different flag, and it wasn't covered before this fix."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-F file=@/etc/passwd"))
    assert result.allowed is False


def test_curl_data_flags_are_blocked() -> None:
    for flag in ("-d", "--data", "--data-binary", "--data-urlencode", "--data-raw"):
        result = _stage().check(_call(name="curl", target="https://x", extra=f"{flag} @/etc/passwd"))
        assert result.allowed is False, flag


def test_curl_dump_header_and_cookie_jar_flags_are_blocked() -> None:
    result = _stage().check(_call(name="curl", target="https://x", extra="-D /tmp/headers.txt"))
    assert result.allowed is False

    result = _stage().check(_call(name="curl", target="https://x", extra="-c /tmp/cookies.txt"))
    assert result.allowed is False


def test_nmap_timing_template_written_with_a_space_is_not_a_false_positive() -> None:
    """-T is curl-specific (--upload-file); nmap's own -T<0-5> timing
    template is a different flag that happens to share the letter. Before
    the fix, a space-separated "-T 4" (unusual but not invalid input from
    a model) produced a bare "-T" token that incorrectly triggered curl's
    rule for an nmap call."""
    result = _stage().check(_call(name="nmap", target="10.0.0.5", extra="-T 4"))
    assert result.allowed is True


def test_curl_still_blocks_its_own_dash_t_upload_flag() -> None:
    """Regression check: fixing the nmap false positive must not weaken
    curl's own -T coverage."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-T /etc/passwd"))
    assert result.allowed is False


def test_nmap_reading_a_target_list_from_a_local_file_is_blocked() -> None:
    result = _stage().check(_call(name="nmap", target="10.0.0.5", extra="-iL /etc/passwd"))
    assert result.allowed is False


def test_curl_output_flag_with_no_space_before_the_value_is_blocked() -> None:
    """curl accepts an attached value with no separating space at all
    (-o/tmp/pwn is equivalent to -o /tmp/pwn). Exact token-membership
    against shlex.split(extra) missed this shape entirely — the token is
    "-o/tmp/pwn", not "-o", so `tokens & denylist` never matched."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-o/tmp/pwn"))
    assert result.allowed is False


def test_curl_data_flag_with_attached_at_syntax_is_blocked() -> None:
    result = _stage().check(_call(name="curl", target="https://x", extra="-d@/etc/passwd"))
    assert result.allowed is False


def test_curl_upload_file_flag_with_no_space_is_blocked() -> None:
    result = _stage().check(_call(name="curl", target="https://x", extra="-T/etc/passwd"))
    assert result.allowed is False


def test_curl_config_flag_with_no_space_is_blocked() -> None:
    """-K/--config is in the shared denylist, not just curl's own — this
    confirms the prefix match applies there too."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-K/etc/curlrc"))
    assert result.allowed is False


def test_curl_cookie_jar_flag_with_no_space_is_blocked() -> None:
    result = _stage().check(_call(name="curl", target="https://x", extra="-c/tmp/jar"))
    assert result.allowed is False


def test_a_long_flag_that_merely_shares_a_prefix_with_a_denylisted_long_flag_is_not_blocked() -> None:
    """Long (--xxx) flags must only match by exact `=`-split head, never by
    startswith — otherwise a distinct, safe long option that happens to
    begin with a denylisted long flag's name would be falsely blocked.
    "--output" is denylisted for curl; "--output-dir" is a different,
    fictitious-but-plausible flag name that must NOT be caught by it."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--output-dir=/tmp"))
    assert result.allowed is True


def test_a_safe_short_flag_that_does_not_appear_in_the_denylist_is_not_blocked() -> None:
    """Regression guard for the new prefix-matching path: an ordinary,
    harmless curl flag must still be allowed through untouched."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-s -A MyAgent/1.0"))
    assert result.allowed is True


def test_nmap_os_detection_flag_is_not_confused_with_curls_denylisted_dash_o() -> None:
    """-O is denylisted for curl (--remote-name) but is a completely
    different, safe, and extremely common nmap flag (OS detection). The
    per-tool denylist scoping must still hold with the new prefix logic —
    nmap's denylist doesn't contain -O at all, so it must never trigger
    here regardless of curl's rules."""
    result = _stage().check(_call(name="nmap", target="10.0.0.5", extra="-O"))
    assert result.allowed is True


def test_an_unknown_tool_only_gets_the_shared_denylist() -> None:
    """A tool with no per-tool entry (not yet added to the catalog, or a
    typo) must fail closed to the shared baseline, not to an empty set —
    -K/--config stays blocked for everyone; a tool-specific flag like
    curl's -F does not apply to a tool that isn't curl."""
    result = _stage().check(_call(name="some-future-tool", target="x", extra="-K /etc/passwd"))
    assert result.allowed is False

    result = _stage().check(_call(name="some-future-tool", target="x", extra="-F file=@x"))
    assert result.allowed is True
