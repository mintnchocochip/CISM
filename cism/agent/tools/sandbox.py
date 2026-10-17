"""The one place any real tool subprocess actually runs.

Every tool function calls :func:`run_sandboxed` instead of touching
``subprocess`` directly: argv is always a list (never a shell string),
each call gets a fresh scratch dir, and a hard timeout kills the whole
process tree. :class:`Runner` is the seam a stronger isolation layer
(container-backed) can swap into later without touching callers.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Protocol

#: Propagates into get_agent_logger()'s handler once an agent has started
#: (that logger's name is a parent of this one) — no DI needed here.
_log = logging.getLogger(__name__)

__all__ = [
    "BubblewrapRunner",
    "Runner",
    "SubprocessRunner",
    "ToolExecutionError",
    "ToolNotInstalledError",
    "ToolOutputReadError",
    "ToolTimeoutError",
    "run_sandboxed",
    "scratch_dir",
    "set_default_runner",
]

_DEFAULT_TIMEOUT = 60.0
_DEFAULT_MAX_OUTPUT = 20_000

#: D3 (AUDIT.md): a tool writing far past max_output is aborted early rather
#: than read to EOF. The multiplier alone isn't enough for a small max_output
#: (an ordinary, finite, somewhat-larger-than-the-cap output would trip it) —
#: the real point is bounding memory against a genuinely pathological/
#: unbounded writer, so an absolute floor sets the real threshold in practice.
_OVERFLOW_MULTIPLIER = 4
_OVERFLOW_FLOOR = 10_000_000
_POLL_INTERVAL = 0.1


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


class ToolExecutionError(Exception):
    """Raised when a tool ran but exited non-zero. Keeps the real output
    (unlike ToolNotInstalledError/ToolTimeoutError) instead of a terse label."""

    def __init__(self, argv: list[str], returncode: int, output: str) -> None:
        super().__init__(f"{argv[0]} exited {returncode}\n{output}")
        self.argv = argv
        self.returncode = returncode
        self.output = output


class ToolOutputReadError(Exception):
    """Raised instead of silently returning a partial buffer (Q3,
    CODE_REVIEW.md) when the background stdout reader either crashed
    mid-read or never finished within its join timeout — in both cases
    ``result()`` would otherwise hand back less than the tool actually
    wrote, indistinguishable from a complete, successful read."""

    def __init__(self, argv: list[str], reason: str) -> None:
        super().__init__(f"{argv[0]}: output reader {reason}")
        self.argv = argv
        self.reason = reason


class Runner(Protocol):
    def run(self, argv: list[str], *, timeout: float, cwd: Path, max_output: int) -> str: ...


class SubprocessRunner:
    """Runs a tool as a real OS subprocess; ``shell=False`` always, so shell
    metacharacters in an argument value are inert."""

    def run(
        self, argv: list[str], *, timeout: float, cwd: Path, max_output: int = _DEFAULT_MAX_OUTPUT
    ) -> str:
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
        return _run_capped(proc, argv, timeout, max_output)


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


class _CappedReader:
    """Reads a subprocess's stdout in a background thread, keeping only a
    head+tail window in memory instead of buffering everything (what
    ``communicate()`` used to do) — a hostile/runaway tool writing
    gigabytes must not OOM the parent before the char cap ever applies
    (D3, AUDIT.md). Sets ``.overflowed`` once far more than ``max_output``
    has been seen, so the caller can kill the tool early instead of reading
    to EOF."""

    def __init__(self, stream, max_output: int) -> None:
        self._half = max_output // 2
        self._max_output = max_output
        self._overflow_at = max(max_output * _OVERFLOW_MULTIPLIER, _OVERFLOW_FLOOR)
        self._buf = bytearray()  # the head, while still under max_output
        self._tail = bytearray()  # only grows once over budget
        self._over_budget = False
        self.total = 0
        self.overflowed = False
        #: Set from the reader thread if ``stream.read1()`` itself raises
        #: (e.g. the fd closes under it) — distinct from a clean EOF (`None`
        #: chunk), which is the normal, successful end of the stream.
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._read, args=(stream,), daemon=True)
        self._thread.start()

    def _read(self, stream) -> None:
        try:
            while True:
                chunk = stream.read1(65536)
                if not chunk:
                    return
                self.total += len(chunk)
                if not self._over_budget:
                    self._buf += chunk
                    if len(self._buf) > self._max_output:
                        self._over_budget = True
                        self._tail = bytearray(self._buf[self._half:])
                        del self._buf[self._half:]  # now exactly the frozen head
                else:
                    self._tail += chunk
                    if len(self._tail) > self._half * 2:
                        del self._tail[: len(self._tail) - self._half]
                if self.total > self._overflow_at:
                    self.overflowed = True
                    return
        except Exception as exc:  # noqa: BLE001 — recorded, not swallowed; see .error
            self.error = exc

    @property
    def failed(self) -> bool:
        """True if the read ended abnormally: the thread crashed, or it's
        still running after the caller's join timeout — either way,
        ``result()`` reflects less than the tool actually wrote."""
        return self.error is not None or self._thread.is_alive()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def result(self) -> str:
        """Only meaningful after the reader has stopped (join'd)."""
        if not self._over_budget:
            return bytes(self._buf).decode("utf-8", errors="replace")
        tail = self._tail[-self._half:] if len(self._tail) > self._half else self._tail
        omitted = self.total - len(self._buf) - len(tail)
        head_text = bytes(self._buf).decode("utf-8", errors="replace")
        tail_text = bytes(tail).decode("utf-8", errors="replace")
        return f"{head_text}\n... [{omitted} chars omitted] ...\n{tail_text}"


def _run_capped(proc: subprocess.Popen, argv: list[str], timeout: float, max_output: int) -> str:
    """Waits on ``proc`` while ``_CappedReader`` streams-and-caps its stdout
    in the background, instead of ``communicate(timeout=timeout)`` (which
    buffers the whole output before any cap applies). Replaces both
    Runners' identical communicate()-based block."""
    reader = _CappedReader(proc.stdout, max_output)
    deadline = time.monotonic() + timeout
    timed_out = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or reader.overflowed:
            timed_out = True
            break
        try:
            proc.wait(timeout=min(_POLL_INTERVAL, remaining))
            break
        except subprocess.TimeoutExpired:
            continue

    if timed_out:
        _kill_tree(proc)
        proc.wait()
        reader.join(timeout=5.0)
        raise ToolTimeoutError(argv, timeout)

    reader.join(timeout=5.0)
    if reader.failed:
        reason = f"crashed: {reader.error}" if reader.error else "did not finish draining in time"
        raise ToolOutputReadError(argv, reason)
    output = reader.result()
    if proc.returncode != 0:
        raise ToolExecutionError(argv, proc.returncode, output)
    return output


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
    inject a fake runner in tests without touching global state. The cap
    is enforced by the Runner itself while streaming (D3, AUDIT.md), not
    applied after the fact here — a hostile/runaway tool's full output is
    never buffered in this process."""
    active_runner = runner or _default_runner

    if cwd is not None:
        return active_runner.run(argv, timeout=timeout, cwd=cwd, max_output=max_output)
    with scratch_dir() as tmp:
        return active_runner.run(argv, timeout=timeout, cwd=tmp, max_output=max_output)


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
    #: /opt because not every tool comes from apt — e.g. nikto (a git clone
    #: to /opt/nikto with a symlink into /usr/local/bin) needs its actual
    #: install tree readable, not just the symlink.
    #: /opt bound wholesale would expose every other /opt-installed package
    #: on the host, not just nikto's — narrow to the one subtree a catalog
    #: tool actually needs (D7).
    _RO_BIND_DIRS: tuple[str, ...] = (
        "/usr", "/bin", "/lib", "/lib64", "/sbin", "/opt/nikto",
    )

    #: Explicitly justified, never a wholesale /etc bind (which would expose
    #: /etc/shadow, SSH host keys, etc.): resolv.conf/nsswitch.conf/hosts for
    #: DNS, ssl for the CA store, ld.so.cache for the linker, alternatives
    #: because Debian/Ubuntu route shared libs through /etc/alternatives/...
    #: (see _etc_symlink_hops/_dynamic_etc_binds).
    #: ssh_config here, built into the image (cism-runner.Dockerfile), adds
    #: legacy algorithms hydra's ssh module needs to even negotiate a
    #: connection to an intentionally-ancient target like Metasploitable2
    #: (confirmed live: "kex error: no match for method server host key
    #: algo" against ssh-rsa/ssh-dss-only servers) — additive (`+`), so a
    #: modern target still gets modern algorithms first. --ro-bind-try
    #: makes this a no-op if the image never wrote the file.
    _RO_BIND_ETC: tuple[str, ...] = (
        "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/hosts",
        "/etc/ssl", "/etc/ld.so.cache", "/etc/alternatives", "/etc/ssh/ssh_config",
    )

    def __init__(self) -> None:
        self._etc_binds_cache: dict[str, frozenset[str]] = {}

    def run(
        self, argv: list[str], *, timeout: float, cwd: Path, max_output: int = _DEFAULT_MAX_OUTPUT
    ) -> str:
        resolved_binary = shutil.which(argv[0])
        if resolved_binary is None:
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
            # Absolute path, not argv[0] literal: PATH inside the sandbox is
            # deliberately narrow (/usr/bin:/bin), so a binary installed
            # elsewhere (e.g. nikto's symlink lives in /usr/local/bin) would
            # otherwise fail a plain execvp PATH search even though its
            # directory is bind-mounted and readable.
            resolved_binary,
            *argv[1:],
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
            return _run_capped(proc, argv, timeout, max_output)
        except ToolTimeoutError:
            _log.warning("tool timed out", extra={"data": {"argv": argv, "timeout": timeout}})
            raise
        except ToolExecutionError as exc:
            _log.warning(
                "tool exited non-zero", extra={"data": {"argv": argv, "returncode": exc.returncode}}
            )
            raise
