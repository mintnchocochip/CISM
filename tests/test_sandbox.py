"""cism/agent/tools/sandbox.py: what run_sandboxed actually guarantees —
no shell interpretation, a runaway process (and its children) actually
gets killed on timeout, a tool can't leave files outside its own scratch
directory, and huge output doesn't lose the tool's final summary line.

Exercised entirely against sys.executable stand-ins — no real security
tools involved.
"""

from __future__ import annotations

import sys
import time

import pytest

from cism.agent.tools.sandbox import (
    ToolNotInstalledError,
    ToolTimeoutError,
    run_sandboxed,
    scratch_dir,
)


def test_a_normal_command_returns_its_output() -> None:
    output = run_sandboxed([sys.executable, "-c", "print('hello')"])
    assert "hello" in output


def test_shell_metacharacters_in_an_argument_are_never_interpreted() -> None:
    malicious = "; echo INJECTED"
    output = run_sandboxed(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", malicious]
    )
    assert output.strip() == malicious


def test_a_missing_binary_raises_a_clean_error_not_a_stack_trace() -> None:
    with pytest.raises(ToolNotInstalledError):
        run_sandboxed(["definitely-not-a-real-binary-xyz123"])


def test_a_timeout_raises_promptly_instead_of_waiting_for_the_process() -> None:
    start = time.monotonic()
    with pytest.raises(ToolTimeoutError):
        run_sandboxed([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2)
    assert time.monotonic() - start < 3


def test_a_timeout_kills_the_whole_process_tree_not_just_the_leaf(tmp_path) -> None:
    marker = tmp_path / "marker"
    child = tmp_path / "child.py"
    parent = tmp_path / "parent.py"
    child.write_text(f"import time\ntime.sleep(0.5)\nopen({str(marker)!r}, 'w').close()\n")
    parent.write_text(f"import subprocess, sys, time\nsubprocess.Popen([sys.executable, {str(child)!r}])\ntime.sleep(5)\n")

    with pytest.raises(ToolTimeoutError):
        run_sandboxed([sys.executable, str(parent)], timeout=0.2)

    time.sleep(1)  # longer than the child's own 0.5s delay
    assert not marker.exists()


def test_large_output_is_capped_but_keeps_the_final_summary_line() -> None:
    script = "print('START'); print('x' * 50_000); print('END')"
    output = run_sandboxed([sys.executable, "-c", script], max_output=1000)

    assert len(output) < 1200
    assert "START" in output
    assert "END" in output


def test_a_tool_writing_a_file_does_not_pollute_the_caller_working_directory(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    run_sandboxed([sys.executable, "-c", "open('marker', 'w').close()"])
    assert not (tmp_path / "marker").exists()


def test_scratch_dir_is_removed_after_normal_use() -> None:
    with scratch_dir() as tmp:
        assert tmp.exists()
    assert not tmp.exists()


def test_scratch_dir_is_removed_even_if_the_block_raises() -> None:
    holder: list = []
    with pytest.raises(ValueError):
        with scratch_dir() as tmp:
            holder.append(tmp)
            raise ValueError("boom")
    assert not holder[0].exists()


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], *, timeout: float, cwd) -> str:
        self.calls.append(argv)
        return "fake-output"


def test_set_default_runner_is_picked_up_by_run_sandboxed(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    fake = _FakeRunner()
    monkeypatch.setattr(sandbox_module, "_default_runner", fake)

    output = run_sandboxed(["definitely-not-a-real-binary-xyz123"])

    assert output == "fake-output"
    assert fake.calls == [["definitely-not-a-real-binary-xyz123"]]


def test_an_explicit_runner_argument_still_overrides_the_default(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module

    default_fake = _FakeRunner()
    explicit_fake = _FakeRunner()
    monkeypatch.setattr(sandbox_module, "_default_runner", default_fake)

    run_sandboxed(["x"], runner=explicit_fake)

    assert explicit_fake.calls == [["x"]]
    assert default_fake.calls == []


def test_a_build_catalog_tool_picks_up_the_default_runner_without_being_told(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.base import build_catalog
    from cism.agent.tools.catalog import ToolSpec

    fake = _FakeRunner()
    monkeypatch.setattr(sandbox_module, "_default_runner", fake)
    (tool,) = build_catalog({"echo": ToolSpec(binary="echo", capability="reads", description="d")})

    tool.invoke({"target": "hi"})

    assert fake.calls == [["echo", "hi"]]


def test_a_sandboxed_tool_decorated_function_picks_up_the_default_runner_without_being_told(
    monkeypatch,
) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.base import sandboxed_tool

    fake = _FakeRunner()
    monkeypatch.setattr(sandbox_module, "_default_runner", fake)

    @sandboxed_tool(binary="echo-ish", capability="reads")
    def probe(target: str) -> list[str]:
        """Probe."""
        return [target]

    probe.invoke({"target": "hi"})

    assert fake.calls == [["echo-ish", "hi"]]
