"""The one place any real tool subprocess actually runs.

Every tool function calls :func:`run_sandboxed` instead of touching
``subprocess`` directly: argv is always a list (never a shell string),
each call gets a fresh scratch dir, and a hard timeout kills the whole
process tree. :class:`Runner` is the seam a stronger isolation layer
(container-backed) can swap into later without touching callers.
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
    "BubblewrapRunner",
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
    callers only ever handle one timeout type regardless of Runner."""

    def __init__(self, argv: list[str], timeout: float) -> None:
        super().__init__(f"{argv[0]}: timed out after {timeout:g}s")
        self.argv = argv
        self.timeout = timeout


class ToolNotInstalledError(Exception):
    """Raised instead of a raw FileNotFoundError, which reads like a crash
    rather than an expected "not installed" outcome."""

    def __init__(self, binary: str) -> None:
        super().__init__(f"{binary}: command not found")
        self.binary = binary


class Runner(Protocol):
    def run(self, argv: list[str], *, timeout: float, cwd: Path) -> str: ...


class SubprocessRunner:
    """Runs a tool as a real OS subprocess; ``shell=False`` always, so shell
    metacharacters in an argument value are inert."""

    def run(self, argv: list[str], *, timeout: float, cwd: Path) -> str:
        if shutil.which(argv[0]) is None:
            raise ToolNotInstalledError(argv[0])

        popen_kwargs: dict[str, object] = {}
        if os.name == "posix":
            # Own process group so a timeout kills every descendant, not just the leaf.
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
    """A directory scoped to one tool call, cleaned up on every exit path
    (return, exception, or timeout) via ``tempfile.TemporaryDirectory``."""
    with tempfile.TemporaryDirectory(prefix="cism-tool-") as tmp:
        yield Path(tmp)


_default_runner: Runner = SubprocessRunner()


def set_default_runner(runner: Runner) -> None:
    """Swaps the default Runner. Called once at startup — resolved at call
    time inside run_sandboxed since sandboxed_tool has no later "assembly"
    moment to inject a runner into."""
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
    """Runs ``argv``, returns its output capped to ``max_output`` chars.
    ``cwd`` defaults to a fresh :func:`scratch_dir`; pass one explicitly
    for tools that pre-write files before running. ``runner`` defaults to
    whatever :func:`set_default_runner` last set; pass one explicitly to
    inject a fake runner in tests without touching global state."""
    active_runner = runner or _default_runner

    if cwd is not None:
        output = active_runner.run(argv, timeout=timeout, cwd=cwd)
    else:
        with scratch_dir() as tmp:
            output = active_runner.run(argv, timeout=timeout, cwd=tmp)

    return _cap(output, max_output)


def _cap(text: str, limit: int) -> str:
    """Head+tail truncation, not a plain tail cut, so a tool's final
    summary line (e.g. nmap's "Nmap done...") isn't lost."""
    if len(text) <= limit:
        return text
    half = limit // 2
    omitted = len(text) - limit
    return f"{text[:half]}\n... [{omitted} chars omitted] ...\n{text[-half:]}"


def _etc_symlink_hops(path: Path) -> set[Path]:
    """Every directory with an ``etc`` path component anywhere in path's
    symlink chain — not just the final target, since .resolve() would skip
    past an intermediate hop like /etc/alternatives/foo (the case that
    broke nmap under BubblewrapRunner)."""
    hops: set[Path] = set()
    current = path
    seen: set[Path] = set()
    while current not in seen and current.is_symlink():
        seen.add(current)
        target = current.readlink()
        if not target.is_absolute():
            target = (current.parent / target).resolve()
        if "etc" in target.parts:
            hops.add(target.parent)  # bind the dir, not one file
        current = target
    return hops


def _dynamic_etc_binds(binary: str) -> frozenset[str]:
    """Every `etc`-containing directory in binary's shared-library
    dependency closure, found by running `ldd` on the host and walking
    each resolved library's symlink chain. `binary` always comes from the
    fixed tool catalog, never from LLM input."""
    resolved = shutil.which(binary)
    if resolved is None:
        return frozenset()

    try:
        result = subprocess.run(["ldd", resolved], capture_output=True, text=True, timeout=5)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return frozenset()  # static binary or no ldd — _RO_BIND_ETC baseline still applies

    hops: set[Path] = set()
    for line in result.stdout.splitlines():
        parts = line.split("=>")
        raw = parts[1] if len(parts) > 1 else parts[0]
        candidate = raw.split(" (")[0].strip()
        if candidate and Path(candidate).is_absolute() and Path(candidate).exists():
            hops |= _etc_symlink_hops(Path(candidate))

    return frozenset(str(p) for p in hops)


class BubblewrapRunner:
    """Runs a tool inside bwrap: read-only system libs + a small justified
    slice of /etc, one writable scratch bind, cleared env, network shared.
    The hard boundary behind the soft guardrail heuristics — what stops a
    call if ScopeGuardStage/DangerousFlagGuardStage have a gap."""

    #: --ro-bind-try skips paths missing on this distro instead of erroring.
    _RO_BIND_DIRS: tuple[str, ...] = ("/usr", "/bin", "/lib", "/lib64", "/sbin")

    #: Explicitly justified, never a wholesale /etc bind (which would expose
    #: /etc/shadow, SSH host keys, etc.): resolv.conf/nsswitch.conf/hosts for
    #: DNS, ssl for the CA store, ld.so.cache for the linker, alternatives
    #: because Debian/Ubuntu route shared libs through /etc/alternatives/...
    #: (see _etc_symlink_hops/_dynamic_etc_binds).
    _RO_BIND_ETC: tuple[str, ...] = (
        "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/hosts",
        "/etc/ssl", "/etc/ld.so.cache", "/etc/alternatives",
    )

    def __init__(self) -> None:
        self._etc_binds_cache: dict[str, frozenset[str]] = {}

    def run(self, argv: list[str], *, timeout: float, cwd: Path) -> str:
        if shutil.which(argv[0]) is None:
            raise ToolNotInstalledError(argv[0])
        if shutil.which("bwrap") is None:
            raise ToolNotInstalledError("bwrap")

        binary = argv[0]
        if binary not in self._etc_binds_cache:
            self._etc_binds_cache[binary] = _dynamic_etc_binds(binary)
        # sorted(): frozenset order isn't stable, so an unsorted tuple() would
        # make bwrap argv vary run-to-run and flake tests that assert on it.
        etc_binds = self._RO_BIND_ETC + tuple(sorted(self._etc_binds_cache[binary]))

        bwrap_argv = ["bwrap"]
        for path in self._RO_BIND_DIRS + etc_binds:
            bwrap_argv += ["--ro-bind-try", path, path]
        bwrap_argv += [
            "--bind", str(cwd), "/work",
            "--chdir", "/work",
            "--proc", "/proc",
            "--dev", "/dev",
            "--unshare-all", "--unshare-user", "--share-net",
            "--die-with-parent",
            "--new-session",
            "--disable-userns",
            "--clearenv",
            "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "HOME", "/work",
            "--setenv", "LANG", "C.UTF-8",
            *argv,
        ]

        popen_kwargs: dict[str, object] = {}
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        elif os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        proc = subprocess.Popen(
            bwrap_argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            **popen_kwargs,
        )
        try:
            stdout, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            proc.communicate()
            raise ToolTimeoutError(argv, timeout) from None

        return stdout.decode("utf-8", errors="replace")
