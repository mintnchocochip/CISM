"""cism/agent/tools/base.py: the escape hatch for tools needing real prep."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from cism.agent.tools.base import sandboxed_tool, write_lines


def test_write_lines_writes_and_returns_the_path(tmp_path: Path) -> None:
    result = write_lines(tmp_path, "users.txt", ["admin", "root"])

    assert Path(result).read_text() == "admin\nroot\n"


def test_decorated_tool_without_scratch_routes_through_run_sandboxed() -> None:
    @sandboxed_tool(binary="whoami-ish", capability="reads")
    def probe(target: str) -> list[str]:
        """Probe a target."""
        return ["-v", target]

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        result = probe.invoke({"target": "10.0.0.5"})

    assert result == "ok"
    assert mock_run.call_args.args[0] == ["whoami-ish", "-v", "10.0.0.5"]


def test_decorated_tool_with_scratch_gets_a_real_directory() -> None:
    seen: list[Path] = []

    @sandboxed_tool(binary="hydra-ish", capability="executes")
    def probe(target: str, *, scratch: Path) -> list[str]:
        """Probe with prep."""
        seen.append(scratch)
        return ["-L", write_lines(scratch, "u.txt", ["admin"]), target]

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        probe.invoke({"target": "10.0.0.5"})

    assert seen[0].exists() is False  # scratch_dir cleans up on exit
    assert mock_run.call_args.kwargs["cwd"] == seen[0]


def test_a_decorated_tool_carries_its_binary_in_metadata() -> None:
    @sandboxed_tool(binary="hydra-ish", capability="executes")
    def probe(target: str) -> list[str]:
        """Probe a target."""
        return [target]

    assert probe.metadata["binary"] == "hydra-ish"
