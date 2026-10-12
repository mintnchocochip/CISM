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


def test_render_argv_always_appends_forced_flags() -> None:
    spec = ToolSpec(binary="nmap", capability="reads", description="d", forced_flags=["-sT", "-Pn"])
    argv = render_argv(spec, "10.0.0.5")

    assert argv == ["-sT", "-Pn", "10.0.0.5"]


def test_render_argv_forced_flags_come_before_extra() -> None:
    spec = ToolSpec(
        binary="nmap", capability="reads", description="d", allow_raw=True, forced_flags=["-sT", "-Pn"]
    )
    argv = render_argv(spec, "10.0.0.5", extra="-p 80,443")

    assert argv == ["-sT", "-Pn", "-p", "80,443", "10.0.0.5"]


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

    assert mock_run.call_args.args[0] == ["nmap", "-sT", "-Pn", "-p", "80,443", "10.0.0.5"]


def test_nmap_catalog_row_with_no_extra_still_forces_the_no_raw_socket_flags() -> None:
    """-sT -Pn is forced_flags, not extra: the sandbox has no raw-socket
    privilege regardless of what the model does or doesn't type, so this one
    combination is baked in rather than left to the model to retype
    correctly every call (see the nmap row in catalog.yaml)."""
    (tool,) = build_catalog({"nmap": CATALOG["nmap"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "10.0.0.5"})

    assert mock_run.call_args.args[0] == ["nmap", "-sT", "-Pn", "10.0.0.5"]


def test_curl_catalog_row_builds_argv_from_target_and_extra() -> None:
    (tool,) = build_catalog({"curl": CATALOG["curl"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "https://example.com", "extra": "-sS -L"})

    assert mock_run.call_args.args[0] == [
        "curl", "--proto", "-all,+http,+https", "-sS", "-L", "https://example.com",
    ]


def test_wafw00f_catalog_row_puts_target_positionally_after_forced_flags() -> None:
    """wafw00f's own CLI takes the target positionally (no -u/--url flag at
    all) — unlike every other web-facing row in this catalog, which is why
    this is tested explicitly rather than assumed from the others."""
    (tool,) = build_catalog({"wafw00f": CATALOG["wafw00f"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "http://10.0.0.5/"})

    assert mock_run.call_args.args[0] == [
        "wafw00f", "-f", "json", "-o", "-", "http://10.0.0.5/",
    ]


def test_wafw00f_defaults_a_schemeless_target_to_http() -> None:
    """wafw00f itself defaults to https and fails outright (connection
    refused) against an http-only target when given a bare host —
    confirmed live against DVWA 2026-10-12."""
    (tool,) = build_catalog({"wafw00f": CATALOG["wafw00f"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "172.28.0.3"})

    assert mock_run.call_args.args[0] == [
        "wafw00f", "-f", "json", "-o", "-", "http://172.28.0.3",
    ]


def test_wafw00f_does_not_override_a_scheme_the_model_already_gave() -> None:
    (tool,) = build_catalog({"wafw00f": CATALOG["wafw00f"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "https://172.28.0.3"})

    assert mock_run.call_args.args[0] == [
        "wafw00f", "-f", "json", "-o", "-", "https://172.28.0.3",
    ]


def test_sqlmap_catalog_row_forces_forms_and_crawl() -> None:
    """Without --forms/--crawl, sqlmap finds nothing to test on a bare URL
    that hosts a POST login form and exits "no parameter(s) found for
    testing" while the call still reports success — confirmed live against
    DVWA's login.php 2026-10-12."""
    (tool,) = build_catalog({"sqlmap": CATALOG["sqlmap"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "http://10.0.0.5/login.php"})

    assert mock_run.call_args.args[0] == [
        "sqlmap", "--batch", "--forms", "--crawl=2", "-u", "http://10.0.0.5/login.php",
    ]


def test_gobuster_catalog_row_suppresses_the_live_progress_indicator() -> None:
    """-z (--no-progress): gobuster's progress indicator rewrites the
    current line with a raw \\r + ANSI clear-line before every hit, which
    desynced GobusterExtractor's regex from real content — confirmed live
    against DVWA 2026-10-12. The extractor strips that noise regardless,
    but suppressing it at the source means there's nothing to strip."""
    (tool,) = build_catalog({"gobuster": CATALOG["gobuster"]})

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        tool.invoke({"target": "http://10.0.0.5/"})

    assert mock_run.call_args.args[0] == [
        "gobuster", "dir", "-w", "/usr/share/wordlists/common-dirs.txt", "-z",
        "-u", "http://10.0.0.5/",
    ]
