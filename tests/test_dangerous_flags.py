"""cism/agent/guardrails/dangerous_flags.py: DangerousFlagGuardStage blocks
a tool call whose free-form `extra` argument contains a flag that can read
or write outside the sandbox's scratch directory. Matching runs against
shlex.split(extra) tokens, not a substring scan of the whole `extra`
string — a target/URL value that happens to contain "-o" as a substring
must not false-positive. Within a token, a short (-x) denylisted flag
matches by prefix and by cluster membership (curl/nmap accept an attached
value with no separating space, e.g. "-o/tmp/pwn", and bundle short flags
into one token, e.g. "-sSo/tmp/pwn"); a long (--xxx) denylisted flag
matches its `=`-split head exactly OR as an abbreviation of it (curl and
nmap both resolve any unambiguous prefix of a long option, so "--conf"
invokes "--config"), but never the reverse, so a longer unrelated flag is
never mistaken for a denylisted one that merely shares its start. For a
tool whose parser uses getopt_long_only (nmap), a single-dash long option
("-script") is normalized to its "--" form before those long-flag rules
run.
"""

from __future__ import annotations

from cism.agent.guardrails.dangerous_flags import (
    _PER_TOOL_DANGEROUS_TOKENS,
    DangerousFlagGuardStage,
)
from cism.agent.tools.catalog import CATALOG


def _call(name: str = "nmap", **args) -> dict:
    return {"id": "call-1", "name": name, "args": args, "type": "tool_call"}


def _stage() -> DangerousFlagGuardStage:
    return DangerousFlagGuardStage()


def test_every_allow_raw_catalog_tool_has_a_dangerous_token_denylist_entry() -> None:
    """C2: allow_raw lets a tool's `extra` through almost unfiltered, so the
    per-tool denylist is the only thing standing between that and real
    sandbox escape. Nothing currently enforces the two stay coupled — this
    is that enforcement. A future allow_raw tool added to catalog.yaml with
    no matching _PER_TOOL_DANGEROUS_TOKENS entry fails this test instead of
    silently shipping unguarded."""
    raw_tools = {name for name, spec in CATALOG.items() if spec.allow_raw}
    missing = raw_tools - _PER_TOOL_DANGEROUS_TOKENS.keys()
    assert not missing, f"allow_raw tool(s) with no dangerous-token denylist: {missing}"


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


def test_curl_data_flags_with_a_literal_value_are_allowed() -> None:
    """The real risk in -d/--data* is @filename (read a local file and send
    it) -- a plain literal value, like verifying credentials the agent
    already found, carries none of that risk and must not be blocked
    identically to the file-read case."""
    for flag in ("-d", "--data", "--data-binary", "--data-urlencode", "--data-raw"):
        result = _stage().check(
            _call(name="curl", target="https://x", extra=f'{flag} "username=app&password=vulnerables"')
        )
        assert result.allowed is True, flag


def test_curl_data_flag_attached_literal_value_is_allowed() -> None:
    """Same carve-out, attached-value form (-dliteral, no space)."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-dusername=app"))
    assert result.allowed is True


def test_curl_data_flag_equals_literal_value_is_allowed() -> None:
    result = _stage().check(_call(name="curl", target="https://x", extra="--data=username=app"))
    assert result.allowed is True


def test_curl_data_flag_with_no_value_at_all_is_blocked() -> None:
    """A bare, trailing -d with nothing after it (attached or as a next
    token) has no literal value to verify as safe -- fail closed."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-d"))
    assert result.allowed is False


def test_curl_data_flag_abbreviations_are_value_aware_too() -> None:
    """The value-aware carve-out applies through curl's own long-flag
    abbreviation resolution (--data-r for --data-raw), not just the fully
    spelled-out form."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--data-r literal=1"))
    assert result.allowed is True


def test_curl_form_flag_with_a_plain_field_value_is_allowed() -> None:
    """-F's own syntax is name=value; only name=@file (upload) or
    name=<file (read) is the file-touching primitive -- a plain field
    value is exactly what a normal form submission looks like."""
    result = _stage().check(_call(name="curl", target="https://x", extra='-F "username=app"'))
    assert result.allowed is True


def test_curl_form_flag_read_syntax_is_still_blocked() -> None:
    """-F's name=<file reads a local file as the field's value -- same
    risk class as name=@file, just the read-not-upload spelling."""
    result = _stage().check(_call(name="curl", target="https://x", extra='-F "file=</etc/passwd"'))
    assert result.allowed is False


def test_curl_data_urlencode_bare_name_at_file_form_is_blocked() -> None:
    """curl's --data-urlencode has a file-read shape plain -d/--data don't:
    a bare `name@file` (no `=` anywhere) reads a local file and
    URL-encodes it, even though the value doesn't start with '@'. A naive
    value.startswith("@") check (correct for every other data flag) misses
    this — this was a real bypass in the first version of this carve-out."""
    for value in ("x@/etc/passwd", "@/etc/passwd"):
        result = _stage().check(_call(name="curl", target="https://x", extra=f'--data-urlencode "{value}"'))
        assert result.allowed is False, value


def test_curl_data_urlencode_literal_forms_are_allowed() -> None:
    """A leading '=' forces curl to treat the rest as literal content even
    if it contains '@' (the documented way to pass e.g. an email address);
    an '=' appearing before any '@' means name=content, also literal —
    curl's own parser resolves the ambiguity by whichever character comes
    first."""
    for value in ("=user@example.com", "name=user@example.com", "plain literal", "name=value"):
        result = _stage().check(_call(name="curl", target="https://x", extra=f'--data-urlencode "{value}"'))
        assert result.allowed is True, value


def test_curl_data_urlencode_abbreviation_is_also_value_aware_for_the_bypass_case() -> None:
    result = _stage().check(_call(name="curl", target="https://x", extra='--data-u "x@/etc/passwd"'))
    assert result.allowed is False


def test_curl_data_flag_bundled_in_a_short_flag_cluster_still_blocks_outright() -> None:
    """Deliberately not value-aware: -d bundled with other short flags
    (e.g. -sSd@file) falls through to the generic, always-block path
    rather than trying to parse a value out of a cluster."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-sSdliteral"))
    assert result.allowed is False


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


def test_output_dir_is_now_denylisted_in_its_own_right() -> None:
    """--output-dir turned out not to be fictitious — it's a real curl
    flag (Finding 5) that redirects where -o/-O/-J write, and is now
    denylisted directly rather than merely "not accidentally caught by
    --output's prefix". This test's old name/premise (that it must NOT be
    blocked) no longer holds; --outputXYZfictitious above is the new
    regression guard for the "shares a prefix but isn't --output-dir
    either" case."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--output-dir=/tmp"))
    assert result.allowed is False


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


def test_curl_long_flag_abbreviation_is_blocked() -> None:
    """curl's own parser accepts any unambiguous prefix of a long option
    (--conf for --config). Verified against real curl: a curlrc reached
    via --conf gives unrestricted file write, identical to the
    already-blocked -K/--config. --data-r/-u/-b abbreviate value-aware data
    flags (see test_curl_data_flag_abbreviations_are_value_aware below), so
    they're exercised here with an @-prefixed value to keep this test about
    abbreviation resolution, not value-awareness."""
    for abbrev, value in (
        ("--conf", "/tmp/x"),
        ("--dump-h", "/tmp/x"),
        ("--cookie-j", "/tmp/x"),
        ("--data-r", "@/tmp/x"),
        ("--data-u", "@/tmp/x"),
        ("--data-b", "@/tmp/x"),
        ("--upload-f", "/tmp/x"),
    ):
        result = _stage().check(_call(name="curl", target="https://x", extra=f"{abbrev} {value}"))
        assert result.allowed is False, abbrev


def test_curl_short_flag_bundling_is_blocked() -> None:
    """curl accepts single-dash short options bundled into one cluster,
    with a value-taking flag consuming the remainder as its value
    (-sSo/tmp/pwn == -s -S -o /tmp/pwn). Verified against real curl: this
    writes the file exactly like the already-blocked -o /tmp/pwn."""
    for bundled in ("-sSo/tmp/pwn", "-sO", "-fsSLo/tmp/pwn", "-sST/etc/passwd"):
        result = _stage().check(_call(name="curl", target="https://x", extra=bundled))
        assert result.allowed is False, bundled


def test_a_safe_boolean_short_flag_cluster_is_not_blocked() -> None:
    """Regression guard: bundling detection must not turn every bundled
    cluster into a block — only one that actually contains a denylisted
    flag's letter."""
    result = _stage().check(_call(name="curl", target="https://x", extra="-sSL"))
    assert result.allowed is True


def test_curl_connection_redirection_flags_are_blocked() -> None:
    """--resolve/--connect-to redirect the connection to an arbitrary
    address while the *visible* URL (the only thing ScopeGuardStage sees)
    stays in-scope — verified live via a real listener that the
    connection really goes where --resolve points, not where the
    hostname would otherwise resolve."""
    for flag_and_value in (
        "--resolve a.example.com:80:169.254.169.254",
        "--connect-to a.example.com:80:169.254.169.254:80",
        "-x http://169.254.169.254:80",
        "--proxy http://169.254.169.254:80",
        "--unix-socket /var/run/docker.sock",
        "--abstract-unix-socket x",
    ):
        result = _stage().check(_call(name="curl", target="https://a.example.com/", extra=flag_and_value))
        assert result.allowed is False, flag_and_value


def test_curl_file_touching_flags_are_blocked() -> None:
    """-w/@file and -b/<file> are arbitrary-file-read-and-exfiltrate
    primitives; --trace*/--stderr/--output-dir/--netrc-file/--etag-save
    are arbitrary-file-write primitives — verified live against real
    curl for each class."""
    for flag_and_value in (
        "-w @/etc/passwd",
        "--write-out @/etc/passwd",
        "-b /etc/passwd",
        "--cookie /etc/passwd",
        "--trace /tmp/t",
        "--trace-ascii /tmp/t",
        "--stderr /tmp/t",
        "--output-dir /etc",
        "--netrc-file /etc/passwd",
        "--etag-save /tmp/e",
        "--etag-compare /etc/passwd",
        "-J",
        "--remote-header-name",
        "--remote-name-all",
        "--cert /etc/passwd",
        "--key /etc/passwd",
        "--cacert /etc/passwd",
    ):
        result = _stage().check(_call(name="curl", target="https://x", extra=flag_and_value))
        assert result.allowed is False, flag_and_value


def test_a_long_flag_abbreviation_still_requires_a_real_prefix_match() -> None:
    """Regression guard: an abbreviation must actually be a prefix of a
    real denylisted flag — a long flag that merely starts with the same
    letter as a denylisted one, but isn't a prefix relationship, must not
    be caught."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--http1.1"))
    assert result.allowed is True


def test_the_existing_long_flag_prefix_regression_guard_still_holds() -> None:
    """--output-dir is now itself denylisted (Finding 5), so this
    existing regression test's premise changed — --output-dir must be
    blocked now, but confirm --output itself (the shorter, already
    denylisted flag) still isn't confused with a DIFFERENT, unrelated
    long flag that happens to share a prefix."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--outputXYZfictitious=1"))
    assert result.allowed is True


def test_nmap_random_internet_targets_flag_is_blocked() -> None:
    """-iR <n> tells nmap to generate and scan random Internet hosts,
    ignoring the target argument entirely — a complete engagement-scope
    escape that ScopeGuardStage cannot see, since the only host-shaped
    argument on the call is the legitimate in-scope target."""
    result = _stage().check(_call(name="nmap", target="10.0.0.5", extra="-iR 1000"))
    assert result.allowed is False


def test_nmap_datadir_and_related_flags_are_blocked() -> None:
    for flag_and_value in (
        "--datadir /tmp/evil",
        "--script-args-file /etc/passwd",
        "--resume /tmp/x",
        "--stylesheet /etc/passwd",
        "-oS /tmp/x",
        "--proxies http://169.254.169.254:80",
        "--servicedb /etc/passwd",
        "--versiondb /etc/passwd",
        "--webxml",
        "--script-help",
        "--append-output",
    ):
        result = _stage().check(_call(name="nmap", target="10.0.0.5", extra=flag_and_value))
        assert result.allowed is False, flag_and_value


def test_a_safe_nmap_flag_is_still_unaffected_by_the_new_entries() -> None:
    """Regression guard: the new nmap entries must not catch anything
    beyond what they explicitly name."""
    result = _stage().check(_call(name="nmap", target="10.0.0.5", extra="-sV -A -T4"))
    assert result.allowed is True


def test_curl_interface_flag_is_blocked() -> None:
    """--interface binds the outgoing connection to a chosen interface or
    source address, redirecting where the request actually leaves from
    while the visible URL stays in-scope — same class as --resolve. It
    shipped in the denylist with no assertion covering it."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--interface eth0"))
    assert result.allowed is False
    assert "--interface" in result.reason


def test_curl_create_dirs_flag_is_blocked() -> None:
    """--create-dirs lets -o/--output-dir materialize an arbitrary
    directory tree outside the scratch dir instead of failing. It shipped
    in the denylist with no assertion covering it."""
    result = _stage().check(_call(name="curl", target="https://x", extra="--create-dirs -o out/x"))
    assert result.allowed is False
    assert "--create-dirs" in result.reason


def test_nmap_single_dash_long_options_are_blocked() -> None:
    """nmap parses its command line with getopt_long_only(), so a long
    option written with ONE dash is the same option to the real binary.
    Live-verified against nmap 7.94SVN: `-script=nonexistent-script-xyz`
    really starts the NSE engine (arbitrary Lua execution) and
    `-excludefile /tmp/no-such-file` really opens the file. Before this
    fix every one of these bypassed the entire nmap denylist, since
    matching only ever normalized `--`-prefixed heads."""
    for extra in (
        "-script /tmp/evil.nse",
        "-script=http-vuln",
        "-datadir /tmp/evil",
        "-excludefile /etc/passwd",
        "-resume /tmp/x",
        "-stylesheet /etc/passwd",
        "-proxies http://169.254.169.254:80",
        "-append-output",
    ):
        result = _stage().check(_call(name="nmap", target="10.0.0.5", extra=extra))
        assert result.allowed is False, extra


def test_a_single_dash_long_option_abbreviation_is_also_blocked() -> None:
    """getopt_long_only resolves abbreviations for the single-dash
    spelling too — live-verified: `nmap -excludef /tmp/no-such-file`
    behaves exactly like `--excludefile`. So blocking only the fully
    spelled-out single-dash form would leave a one-character bypass."""
    for extra in ("-scri /tmp/x", "-excludef /etc/passwd", "-datad /tmp/evil"):
        result = _stage().check(_call(name="nmap", target="10.0.0.5", extra=extra))
        assert result.allowed is False, extra


def test_short_single_dash_long_option_abbreviations_are_blocked() -> None:
    """getopt_long_only resolves an abbreviation as soon as it is
    unambiguous, which for several denylisted options is only TWO
    characters after the dash — so the normalization floor must sit at 2,
    not higher. Live-verified against nmap 7.94SVN: `nmap -sty
    /etc/nonexistent-xyz -oX - -sL 127.0.0.1` really emits an
    `<?xml-stylesheet href="/etc/nonexistent-xyz" ...?>` header (i.e.
    `--stylesheet` genuinely engages), and `-ser <path>` really resolves
    to `--servicedb`, observable through its documented implicit `-F`."""
    for extra in (
        "-sty /etc/passwd",
        "-sty=/etc/passwd",
        "-ser /etc/passwd",
        "-we",
        "-web",
        "-ap",
        "-app",
    ):
        result = _stage().check(_call(name="nmap", target="10.0.0.5", extra=extra))
        assert result.allowed is False, extra


def test_legitimate_short_nmap_flags_are_not_caught_by_the_single_dash_normalization() -> None:
    """False-positive regression guard for the single-dash normalization:
    nmap's real short flags — including the extremely common `-p`, which
    would collide with `--proxies` if normalization had no length floor —
    must all still be allowed."""
    for extra in (
        "-sV",
        "-sC",
        "-Pn",
        "-sS",
        "-A",
        "-T4",
        "-p 80,443",
        "-p-",
        "-p1-65535",
        "-PS22",
        "-sV -sC -Pn -T4 -p 1-1000",
        "-open",
        "-v",
        "-n",
        "-d3",
    ):
        result = _stage().check(_call(name="nmap", target="10.0.0.5", extra=extra))
        assert result.allowed is True, extra


def test_curl_short_flags_are_unaffected_by_the_single_dash_normalization() -> None:
    """curl does NOT accept single-dash long options, so the
    normalization must not apply to it at all: `-s` (silent) must not be
    read as an abbreviation of curl's denylisted `--stderr`, and the
    genuinely denylisted curl short flags must keep blocking exactly as
    before."""
    for extra in ("-s -A MyAgent/1.0", "-sSL", "-L", "-k", "-i"):
        result = _stage().check(_call(name="curl", target="https://x", extra=extra))
        assert result.allowed is True, extra

    for extra in ("-o /tmp/x", "-O", "-J", "-c /tmp/jar", "-K /etc/curlrc"):
        result = _stage().check(_call(name="curl", target="https://x", extra=extra))
        assert result.allowed is False, extra
