"""run_agent.py: CLI flag parsing. Building the TUI app and actually
running it live is out of scope for an automated test — this covers the
one thing that's pure logic, parse_args."""

from __future__ import annotations

import pytest

from run_agent import parse_args


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
