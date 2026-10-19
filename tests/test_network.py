"""cism/agent/tools/network.py: nc's argv shape and stdin-file convention
for a one-shot command sent to a raw TCP service."""

from __future__ import annotations

from unittest.mock import patch

from cism.agent.tools.network import NETWORK_TOOLS, nc


def test_nc_is_registered_in_network_tools() -> None:
    assert nc in NETWORK_TOOLS


def _invoke(**kwargs):
    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        result = nc.invoke(kwargs)
    return result, mock_run


def test_connecting_with_no_command_has_no_stdin_file() -> None:
    _, mock_run = _invoke(target="10.0.0.5", port=1524)

    argv = mock_run.call_args.args[0]
    assert argv == ["nc", "-w", "10", "10.0.0.5", "1524"]
    assert mock_run.call_args.kwargs["stdin"] is None


def test_a_command_is_written_to_a_scratch_stdin_file_and_passed_through() -> None:
    # Read the file's content inside run_sandboxed's own mocked call,
    # before the scratch_dir context manager that owns it tears it down.
    seen: dict[str, object] = {}

    def _capture(argv, **kwargs):
        stdin_path = kwargs["stdin"]
        seen["name"] = stdin_path.name if stdin_path else None
        seen["content"] = stdin_path.read_text() if stdin_path else None
        return "ok"

    with patch("cism.agent.tools.base.run_sandboxed", side_effect=_capture):
        nc.invoke({"target": "172.28.0.2", "port": 1524, "command": "id"})

    assert seen["name"] == "stdin"
    assert seen["content"] == "id\n"


def test_argv_uses_a_bare_host_and_structured_port_not_a_combined_string() -> None:
    """target stays a plain single-token field, going through ScopeGuardStage
    completely unchanged from how every other tool's target already does —
    no "host port" smuggled into one string."""
    _, mock_run = _invoke(target="172.28.0.2", port=1524)

    argv = mock_run.call_args.args[0]
    assert "172.28.0.2" in argv
    assert "1524" in argv
    assert "172.28.0.2 1524" not in argv
    assert "172.28.0.2:1524" not in argv
