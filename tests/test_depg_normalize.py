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


def test_hash_signal_is_deterministic() -> None:
    assert hash_signal("some tool output") == hash_signal("some tool output")


def test_hash_signal_differs_for_different_text() -> None:
    assert hash_signal("output one") != hash_signal("output two")


def test_hash_signal_ignores_incidental_whitespace() -> None:
    assert hash_signal("a  b") == hash_signal("a b")
