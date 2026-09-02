"""cism/agent/tools/base.py: build_toolkit assembles catalog rows +
decorated tools + tool_help into one ToolRegistry — the single place
"adding tool #51" has to touch, per the unified-toolkit design doc."""

from __future__ import annotations

from unittest.mock import patch

from cism.agent.tools import CATALOG, hydra
from cism.agent.tools.base import build_toolkit


def test_build_toolkit_registers_every_catalog_row() -> None:
    registry, _ = build_toolkit(CATALOG, decorated_tools=[], extractors={})

    for name in CATALOG:
        assert name in registry


def test_build_toolkit_registers_decorated_tools() -> None:
    registry, _ = build_toolkit(CATALOG, decorated_tools=[hydra], extractors={})

    assert "hydra" in registry
    assert registry.get("hydra") is hydra


def test_build_toolkit_always_registers_tool_help() -> None:
    registry, _ = build_toolkit(CATALOG, decorated_tools=[hydra], extractors={})

    assert "tool_help" in registry


def test_tool_help_from_build_toolkit_resolves_a_decorated_tools_binary() -> None:
    registry, _ = build_toolkit(CATALOG, decorated_tools=[hydra], extractors={})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="usage: hydra ...") as mock_run:
        result = registry.get("tool_help").invoke({"tool_name": "hydra"})

    assert result == "usage: hydra ..."
    assert mock_run.call_args.args[0] == ["hydra", "--help"]


def test_build_toolkit_returns_the_extractors_dict_unchanged() -> None:
    sentinel = {"nmap": object()}
    _, extractors = build_toolkit(CATALOG, decorated_tools=[], extractors=sentinel)

    assert extractors is sentinel
