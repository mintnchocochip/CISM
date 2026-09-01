"""cism/agent/tools/base.py: render_argv is pure; build_catalog wires each
row through run_sandboxed and carries its capability tag."""

from __future__ import annotations

from unittest.mock import patch

from cism.agent.tools.base import build_catalog, render_argv
from cism.agent.tools.catalog import CATALOG, Flag, ToolSpec


def test_render_argv_places_a_bool_flag_and_a_value_flag() -> None:
    spec = ToolSpec(
        binary="nmap", capability="reads", description="d",
        flags={"ports": Flag(cli="-p"), "service": Flag(cli="-sV", kind="bool")},
    )
    argv = render_argv(spec, "10.0.0.5", ports="1-1000", service=True)

    assert argv == ["-p", "1-1000", "-sV", "10.0.0.5"]


def test_render_argv_omits_an_unset_bool_flag() -> None:
    spec = ToolSpec(
        binary="nmap", capability="reads", description="d",
        flags={"service": Flag(cli="-sV", kind="bool")},
    )
    argv = render_argv(spec, "10.0.0.5", service=False)

    assert argv == ["10.0.0.5"]


def test_render_argv_places_target_behind_its_flag_when_not_positional() -> None:
    spec = ToolSpec(binary="nikto", capability="reads", description="d", target="-host")
    argv = render_argv(spec, "10.0.0.5")

    assert argv == ["-host", "10.0.0.5"]


def test_render_argv_appends_extra_only_when_allow_raw() -> None:
    spec = ToolSpec(binary="nmap", capability="reads", description="d", allow_raw=True)
    argv = render_argv(spec, "10.0.0.5", extra="--top-ports 20")

    assert argv == ["--top-ports", "20", "10.0.0.5"]


def test_build_catalog_produces_one_tool_per_row_with_its_capability() -> None:
    catalog = {
        "nikto": ToolSpec(binary="nikto", capability="reads", description="d", target="-host")
    }
    (tool,) = build_catalog(catalog)

    assert tool.name == "nikto"
    assert tool.metadata["capability"] == "reads"


def test_a_built_tool_routes_through_run_sandboxed() -> None:
    catalog = {
        "nikto": ToolSpec(binary="nikto", capability="reads", description="d", target="-host")
    }
    (tool,) = build_catalog(catalog)

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        result = tool.invoke({"target": "10.0.0.5"})

    assert result == "ok"
    mock_run.assert_called_once()
    assert mock_run.call_args.args[0] == ["nikto", "-host", "10.0.0.5"]


def test_nmap_catalog_row_builds_argv_from_target_and_extra() -> None:
    (tool,) = build_catalog({"nmap": CATALOG["nmap"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "10.0.0.5", "extra": "-p 80,443"})

    assert mock_run.call_args.args[0] == ["nmap", "-p", "80,443", "10.0.0.5"]


def test_nmap_catalog_row_with_no_extra_passes_no_flags() -> None:
    """Unlike the old hand-written nmap(), which defaulted to "-sV" when no
    options were given, the catalog's generic `extra` field has no per-tool
    default value — this is an accepted, minor behavior change: the whole
    point of tool_help (Task 4) is letting the model choose its own flags
    rather than relying on one baked in here."""
    (tool,) = build_catalog({"nmap": CATALOG["nmap"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "10.0.0.5"})

    assert mock_run.call_args.args[0] == ["nmap", "10.0.0.5"]


def test_curl_catalog_row_builds_argv_from_target_and_extra() -> None:
    (tool,) = build_catalog({"curl": CATALOG["curl"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "https://example.com", "extra": "-sS -L"})

    assert mock_run.call_args.args[0] == ["curl", "-sS", "-L", "https://example.com"]
