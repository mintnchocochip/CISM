"""run_agent.py: CLI flag parsing. Building the TUI app and actually
running it live is out of scope for an automated test — this covers the
one thing that's pure logic, parse_args."""

from __future__ import annotations

import ipaddress

import pytest

from cism.agent.guardrails import parse_scope
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
    scope = parse_scope("10.0.0.0/24")
    assert scope.cidrs == (ipaddress.ip_network("10.0.0.0/24"),)
    assert scope.domains == ()


def test_parse_scope_bare_ip_widens_to_slash_32() -> None:
    scope = parse_scope("10.0.0.5")
    assert scope.cidrs == (ipaddress.ip_network("10.0.0.5/32"),)
    assert scope.domains == ()


def test_parse_scope_domain() -> None:
    scope = parse_scope("example.internal")
    assert scope.domains == ("example.internal",)
    assert scope.cidrs == ()


def test_parse_scope_mixed_comma_list_preserves_order_per_kind() -> None:
    scope = parse_scope("10.0.0.0/24, example.internal , 10.0.0.9")
    assert scope.cidrs == (
        ipaddress.ip_network("10.0.0.0/24"),
        ipaddress.ip_network("10.0.0.9/32"),
    )
    assert scope.domains == ("example.internal",)


def test_parse_scope_all_blank_tokens_returns_empty_scope() -> None:
    scope = parse_scope(" , , ")
    assert scope.cidrs == ()
    assert scope.domains == ()


from cism.agent.guardrails import DangerousFlagGuardStage, ScopeGuardStage
from cism.agent.tools import ToolRegistry
from cism.agent.tools.sandbox import BubblewrapRunner

import run_agent


def test_enable_live_tools_without_bwrap_refuses(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module, "_default_runner", sandbox_module._default_runner)
    monkeypatch.setattr("shutil.which", lambda name: None)
    called: list[object] = []
    monkeypatch.setattr(run_agent, "set_default_runner", lambda runner: called.append(runner))

    with pytest.raises(SystemExit) as exc_info:
        run_agent._enable_live_tools("10.0.0.0/24")

    assert "bwrap" in str(exc_info.value)
    assert called == []


def test_enable_live_tools_with_empty_scope_refuses(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module, "_default_runner", sandbox_module._default_runner)
    monkeypatch.setattr(
        "shutil.which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None
    )
    called: list[object] = []
    monkeypatch.setattr(run_agent, "set_default_runner", lambda runner: called.append(runner))

    with pytest.raises(SystemExit) as exc_info:
        run_agent._enable_live_tools(" , ")

    assert "scope" in str(exc_info.value).lower()
    assert called == []


def test_enable_live_tools_wires_real_tools_and_a_real_guardrail_seam(
    monkeypatch, capsys
) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module, "_default_runner", sandbox_module._default_runner)
    monkeypatch.setattr(
        "shutil.which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None
    )

    tools, guardrails = run_agent._enable_live_tools("10.0.0.0/24,example.internal")

    assert isinstance(tools, ToolRegistry)
    assert "nmap" in tools
    assert "curl" in tools
    assert "hydra" in tools
    assert "tool_help" in tools
    assert isinstance(sandbox_module._default_runner, BubblewrapRunner)
    stage_types = {type(stage) for stage in guardrails.action.stages}
    assert stage_types == {ScopeGuardStage, DangerousFlagGuardStage}
    assert guardrails.input.stages and guardrails.output.stages  # still pass-through, but present
    assert "LIVE TOOLS ENABLED" in capsys.readouterr().err
