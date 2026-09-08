"""run_agent.py: CLI flag parsing. Building the TUI app and actually
running it live is out of scope for an automated test — this covers the
one thing that's pure logic, parse_args."""

from __future__ import annotations

import ipaddress

import pytest

from run_agent import _parse_scope, parse_args


def test_base_url_without_model_is_an_error(capsys) -> None:
    with pytest.raises(SystemExit):
        parse_args(["--base-url", "http://localhost:11434/v1"])
    assert "--model" in capsys.readouterr().err


def test_base_url_and_model_together_parse_cleanly() -> None:
    args = parse_args(["--base-url", "http://localhost:11434/v1", "--model", "qwen2.5:3b"])
    assert args.base_url == "http://localhost:11434/v1"
    assert args.model == "qwen2.5:3b"
    assert args.key_env_var == "CISM_API_KEY"


def test_no_flags_leaves_base_url_and_model_empty() -> None:
    args = parse_args([])
    assert args.base_url == ""
    assert args.model == ""
    assert args.key_env_var == "CISM_API_KEY"
    assert args.target == ""


def test_key_env_var_can_be_overridden() -> None:
    args = parse_args(
        ["--base-url", "http://localhost:11434/v1", "--model", "m", "--key-env-var", "OTHER_KEY"]
    )
    assert args.key_env_var == "OTHER_KEY"


def test_live_tools_without_scope_is_an_error(capsys) -> None:
    with pytest.raises(SystemExit):
        parse_args(["--live-tools"])
    assert "--scope" in capsys.readouterr().err


def test_live_tools_and_scope_together_parse_cleanly() -> None:
    args = parse_args(["--live-tools", "--scope", "10.0.0.0/24"])
    assert args.live_tools is True
    assert args.scope == "10.0.0.0/24"


def test_scope_without_live_tools_is_not_an_error() -> None:
    args = parse_args(["--scope", "10.0.0.0/24"])
    assert args.live_tools is False
    assert args.scope == "10.0.0.0/24"


def test_no_flags_leaves_live_tools_false_and_scope_empty() -> None:
    args = parse_args([])
    assert args.live_tools is False
    assert args.scope == ""


def test_parse_scope_single_cidr() -> None:
    scope = _parse_scope("10.0.0.0/24")
    assert scope.cidrs == (ipaddress.ip_network("10.0.0.0/24"),)
    assert scope.domains == ()


def test_parse_scope_bare_ip_widens_to_slash_32() -> None:
    scope = _parse_scope("10.0.0.5")
    assert scope.cidrs == (ipaddress.ip_network("10.0.0.5/32"),)
    assert scope.domains == ()


def test_parse_scope_domain() -> None:
    scope = _parse_scope("example.internal")
    assert scope.domains == ("example.internal",)
    assert scope.cidrs == ()


def test_parse_scope_mixed_comma_list_preserves_order_per_kind() -> None:
    scope = _parse_scope("10.0.0.0/24, example.internal , 10.0.0.9")
    assert scope.cidrs == (
        ipaddress.ip_network("10.0.0.0/24"),
        ipaddress.ip_network("10.0.0.9/32"),
    )
    assert scope.domains == ("example.internal",)


def test_parse_scope_all_blank_tokens_returns_empty_scope() -> None:
    scope = _parse_scope(" , , ")
    assert scope.cidrs == ()
    assert scope.domains == ()
