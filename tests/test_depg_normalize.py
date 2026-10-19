"""cism/depg/normalize.py: deterministic transforms for the identity key."""

from __future__ import annotations

from cism.depg.normalize import hash_signal, normalize_target


def test_lowercases_and_trims() -> None:
    assert normalize_target("  Host.Local  ") == "host.local"


def test_strips_a_url_scheme() -> None:
    assert normalize_target("ssh://10.0.0.5") == "10.0.0.5"


def test_strips_trailing_fqdn_dot() -> None:
    assert normalize_target("host.local.") == "host.local"


def test_drops_a_port() -> None:
    assert normalize_target("10.0.0.5:8080") == "10.0.0.5"


def test_leaves_a_bare_hostname_with_no_port_unchanged() -> None:
    assert normalize_target("host.local") == "host.local"


def test_leaves_an_unbracketed_ipv6_literal_unchanged() -> None:
    assert normalize_target("::1") == "::1"


def test_leaves_a_longer_unbracketed_ipv6_literal_unchanged() -> None:
    assert normalize_target("fe80::1") == "fe80::1"


def test_strips_brackets_and_port_from_a_bracketed_ipv6_literal() -> None:
    assert normalize_target("[::1]:80") == "::1"


def test_strips_brackets_from_a_bracketed_ipv6_literal_with_no_port() -> None:
    assert normalize_target("[::1]") == "::1"


def test_hash_signal_is_deterministic() -> None:
    assert hash_signal("some tool output") == hash_signal("some tool output")


def test_hash_signal_differs_for_different_text() -> None:
    assert hash_signal("output one") != hash_signal("output two")


def test_hash_signal_ignores_incidental_whitespace() -> None:
    assert hash_signal("a  b") == hash_signal("a b")


_CURL_PREAMBLE = (
    "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
    "                                 Dload  Upload   Total   Spent    Left  Speed\n"
    "  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0"
    "100  1523  100  1523    0     0   157k      0 --:--:-- --:--:-- --:--:--  165k\n\n"
)


def test_hash_signal_ignores_curls_own_progress_meter() -> None:
    body = "<html>same page</html>"
    assert hash_signal(_CURL_PREAMBLE + body) == hash_signal(body)


def test_hash_signal_ignores_a_fresh_csrf_token_in_a_value_attribute() -> None:
    page = "<input type='hidden' name='user_token' value='{token}' />"
    first = page.format(token="85af13483345c7a4ed09f68666019111")
    second = page.format(token="bcd3bfe9a0bfd47a9ee8953dcc391091")
    assert hash_signal(first) == hash_signal(second)


def test_hash_signal_still_distinguishes_a_real_dumped_hash_in_plain_text() -> None:
    # Not wrapped in value='...' -- a UNION-dumped password hash, unlike a
    # CSRF token, must not be masked away or two different dumps collapse
    # onto the same node.
    dump_one = "admin 5f4dcc3b5aa765d61d8327deb882cf99"
    dump_two = "admin e99a18c428cb38d5f260853678922e03"
    assert hash_signal(dump_one) != hash_signal(dump_two)


def test_hash_signal_dedupes_two_curl_probes_that_only_differ_by_token_and_timing() -> None:
    # The exact real-world case this fix targets: two separately-fetched
    # copies of the same login page, each with curl's own timing-jittered
    # progress meter and DVWA's own freshly-rotated CSRF token.
    page_one = _CURL_PREAMBLE + (
        "<form><input type='hidden' name='user_token' "
        "value='85af13483345c7a4ed09f68666019111' /></form>"
    )
    page_two = (
        "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
        "                                 Dload  Upload   Total   Spent    Left  Speed\n"
        "  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0"
        "100  1599  100  1523  100    76   194k   9959 --:--:-- --:--:-- --:--:--  223k\n\n"
        "<form><input type='hidden' name='user_token' "
        "value='bcd3bfe9a0bfd47a9ee8953dcc391091' /></form>"
    )
    assert hash_signal(page_one) == hash_signal(page_two)
