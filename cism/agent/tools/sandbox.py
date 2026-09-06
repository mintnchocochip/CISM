"""The one place any real tool subprocess actually runs.

Every tool function in this package calls :func:`run_sandboxed` instead of
touching ``subprocess`` itself. That keeps three guarantees in one place
instead of re-litigated per tool: argv is always a list (never a shell
string — the anti-injection guarantee), every call gets a fresh scratch
working directory that disappears afterward, and every call is bounded by a
hard timeout that kills the whole process tree, not just the leaf.

:class:`Runner` is the seam a future container-backed implementation swaps
into — :func:`run_sandboxed` only ever calls ``runner.run(...)``, so nothing
about the ~53 tool functions, ``cism/agent/nodes.py``, or ``cism/agent/
graph.py`` needs to change when a stronger isolation layer replaces
:class:`SubprocessRunner`.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Protocol

__all__ = [
    "Runner",
    "SubprocessRunner",
    "ToolNotInstalledError",
    "ToolTimeoutError",
    "run_sandboxed",
    "scratch_dir",
    "set_default_runner",
]

_DEFAULT_TIMEOUT = 60.0
_DEFAULT_MAX_OUTPUT = 20_000


class ToolTimeoutError(Exception):
    """Raised instead of letting ``subprocess.TimeoutExpired`` escape, so
    callers only ever handle one timeout type regardless of which Runner
    ran the call. Not caught here — ``act`` (cism/agent/nodes.py) already
    turns any exception into an error ToolMessage, so this propagates."""

    def __init__(self, argv: list[str], timeout: float) -> None:
        super().__init__(f"{argv[0]}: timed out after {timeout:g}s")
        self.argv = argv
        self.timeout = timeout


class ToolNotInstalledError(Exception):
    """Raised in place of a raw FileNotFoundError, which reads like an
    OS-level stack trace rather than a normal, expected "not installed"
    outcome for a catalog covering ~53 different binaries."""

    def __init__(self, binary: str) -> None:
        super().__init__(f"{binary}: command not found")
        self.binary = binary


class Runner(Protocol):
    def run(self, argv: list[str], *, timeout: float, cwd: Path) -> str: ...


class SubprocessRunner:
    """Runs a tool as a real OS subprocess. ``shell=False`` always: argv is
    handed to the target binary's own argument parser as a list, so shell
    metacharacters an LLM puts inside an argument value are inert."""

    def run(self, argv: list[str], *, timeout: float, cwd: Path) -> str:
        if shutil.which(argv[0]) is None:
            raise ToolNotInstalledError(argv[0])

        popen_kwargs: dict[str, object] = {}
        if os.name == "posix":
            # Own process group, so a timeout can kill every descendant
            # (rustscan shells to nmap, msfconsole/routersploit/testssl.sh
            # fork children) rather than just the immediate leaf.
            popen_kwargs["start_new_session"] = True
        elif os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            **popen_kwargs,
        )
        try:
            stdout, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            proc.communicate()  # reap, discard
            raise ToolTimeoutError(argv, timeout) from None

        return stdout.decode("utf-8", errors="replace")


def _kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass  # already gone
    else:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
        proc.kill()


@contextmanager
def scratch_dir() -> Iterator[Path]:
    """A directory that exists only for the duration of one tool call.
    Smallest possible blast radius: one call's temp files can never
    collide with, or leak into, a later, unrelated call. Cleaned up on
    every exit path — normal return, exception, or timeout — since it's a
    context manager around ``tempfile.TemporaryDirectory``."""
    with tempfile.TemporaryDirectory(prefix="cism-tool-") as tmp:
        yield Path(tmp)


_default_runner: Runner = SubprocessRunner()


def set_default_runner(runner: Runner) -> None:
    """Swaps the runner every tool call uses when it doesn't pass one
    explicitly. Meant to be called once at startup (LangGraphAgent.__init__
    or run_agent.py, once real tools are opted into) — resolved at call
    time inside run_sandboxed, not at tool-construction time, because
    sandboxed_tool is an eager decorator with no later "assembly" moment to
    inject a runner into."""
    global _default_runner
    _default_runner = runner


def run_sandboxed(
    argv: list[str],
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    cwd: Path | None = None,
    max_output: int = _DEFAULT_MAX_OUTPUT,
    runner: Runner | None = None,
) -> str:
    """Runs ``argv`` and returns its captured output, capped to
    ``max_output`` characters. The sole seam every tool function calls into.

    ``cwd`` defaults to a fresh :func:`scratch_dir`; pass one explicitly
    for tools that need to pre-write files (a hydra wordlist, an msfconsole
    resource script) before the process starts. ``runner`` defaults to
    whatever :func:`set_default_runner` last set (a plain
    :class:`SubprocessRunner` until something calls it) — pass one
    explicitly only for a test that wants to inject a fake runner without
    touching global state.
    """
    active_runner = runner or _default_runner

    if cwd is not None:
        output = active_runner.run(argv, timeout=timeout, cwd=cwd)
    else:
        with scratch_dir() as tmp:
            output = active_runner.run(argv, timeout=timeout, cwd=tmp)

    return _cap(output, max_output)


def _cap(text: str, limit: int) -> str:
    """Head+tail truncation, not a plain tail cut — a tool's final summary
    line (e.g. nmap's "Nmap done: ... scanned in Y seconds") would
    otherwise be the first thing lost."""
    if len(text) <= limit:
        return text
    half = limit // 2
    omitted = len(text) - limit
    return f"{text[:half]}\n... [{omitted} chars omitted] ...\n{text[-half:]}"


def _etc_symlink_hops(path: Path) -> set[Path]:
    """Every /etc-rooted directory in path's full symlink chain, not just
    its final target — pathlib's own .resolve() would skip straight past
    an intermediate hop like /etc/alternatives/foo, which is exactly the
    case that broke nmap under BubblewrapRunner (see the design doc §4.2):
    /usr/lib/.../libblas.so.3 -> /etc/alternatives/... -> the real file.
    Binding /usr wholesale doesn't help if the *middle* of the chain lives
    somewhere else entirely."""
    hops: set[Path] = set()
    current = path
    seen: set[Path] = set()
    while current not in seen and current.is_symlink():
        seen.add(current)
        target = current.readlink()
        if not target.is_absolute():
            target = (current.parent / target).resolve()
        if target.is_relative_to("/etc"):
            hops.add(target.parent)  # bind the containing dir, not one file
        current = target
    return hops
