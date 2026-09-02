"""cism/agent/tools/base.py: tool_help — a generic, always-available tool
that prints a target tool's own --help/-h text, routed through
run_sandboxed like every other tool call (some binaries hang on --help
waiting on stdin, so it still needs the timeout)."""

from __future__ import annotations

from unittest.mock import patch

from cism.agent.tools.base import _build_help_tool
from cism.agent.tools.catalog import ToolSpec


def test_tool_help_uses_the_catalog_row_help_flag() -> None:
    catalog = {"nikto": ToolSpec(binary="nikto", capability="reads", description="d")}
    tool = _build_help_tool(catalog, extra_binaries={})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="usage: nikto ...") as mock_run:
        result = tool.invoke({"tool_name": "nikto"})

    assert result == "usage: nikto ..."
    assert mock_run.call_args.args[0] == ["nikto", "--help"]


def test_tool_help_respects_a_non_default_help_flag() -> None:
    catalog = {"weird": ToolSpec(binary="weird", capability="reads", description="d", help_flag="-h")}
    tool = _build_help_tool(catalog, extra_binaries={})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"tool_name": "weird"})

    assert mock_run.call_args.args[0] == ["weird", "-h"]


def test_tool_help_resolves_a_decorated_tool_via_extra_binaries() -> None:
    tool = _build_help_tool(catalog={}, extra_binaries={"hydra": "hydra"})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="usage: hydra ...") as mock_run:
        result = tool.invoke({"tool_name": "hydra"})

    assert result == "usage: hydra ..."
    assert mock_run.call_args.args[0] == ["hydra", "--help"]


def test_tool_help_reports_an_unknown_tool_name_without_calling_run_sandboxed() -> None:
    tool = _build_help_tool(catalog={}, extra_binaries={})

    with patch("cism.agent.tools.base.run_sandboxed") as mock_run:
        result = tool.invoke({"tool_name": "not-a-real-tool"})

    assert "unknown tool" in result
    mock_run.assert_not_called()
