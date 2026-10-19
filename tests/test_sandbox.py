"""cism/agent/tools/sandbox.py: what run_sandboxed actually guarantees —
no shell interpretation, a runaway process (and its children) actually
gets killed on timeout, a tool can't leave files outside its own scratch
directory, and huge output doesn't lose the tool's final summary line.

Exercised entirely against sys.executable stand-ins — no real security
tools involved.
"""

from __future__ import annotations

import io
import shutil
import socket
import sys
import time
from pathlib import Path

import pytest

from cism.agent.tools.sandbox import (
    ToolExecutionError,
    ToolNotInstalledError,
    ToolOutputReadError,
    ToolTimeoutError,
    run_sandboxed,
    scratch_dir,
)


def test_a_normal_command_returns_its_output() -> None:
    output = run_sandboxed([sys.executable, "-c", "print('hello')"])
    assert "hello" in output


def test_a_nonzero_exit_raises_instead_of_being_reported_as_success() -> None:
    script = "print('partial output before failure'); import sys; sys.exit(1)"

    with pytest.raises(ToolExecutionError) as exc_info:
        run_sandboxed([sys.executable, "-c", script])

    assert exc_info.value.returncode == 1
    assert "partial output before failure" in exc_info.value.output
    assert "partial output before failure" in str(exc_info.value)


def test_shell_metacharacters_in_an_argument_are_never_interpreted() -> None:
    malicious = "; echo INJECTED"
    output = run_sandboxed(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", malicious]
    )
    assert output.strip() == malicious


def test_stdin_file_content_reaches_the_subprocesss_real_stdin(tmp_path) -> None:
    stdin_file = tmp_path / "stdin"
    stdin_file.write_text("hello from stdin\n")

    output = run_sandboxed(
        [sys.executable, "-c", "import sys; print(sys.stdin.read().strip())"],
        stdin=stdin_file,
    )

    assert output.strip() == "hello from stdin"


def test_omitting_stdin_behaves_exactly_as_before_the_parameter_existed() -> None:
    """A call with no stdin= at all must produce byte-for-byte the same
    output as the existing, unparameterized call shape — pure addition,
    no behavior change for any of the callers that predate this parameter."""
    assert run_sandboxed([sys.executable, "-c", "print('hello')"]) == "hello\n"


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


def test_a_runaway_writer_is_killed_well_before_the_wall_clock_timeout() -> None:
    """D3 (AUDIT.md): a tool that never stops writing must be aborted once
    it's produced pathologically more output than max_output, not read to
    EOF first — the old communicate()-based path buffered everything
    before any cap applied, so a hostile/looping tool could OOM the parent."""
    script = "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n"
    start = time.monotonic()

    with pytest.raises(ToolTimeoutError):
        run_sandboxed([sys.executable, "-c", script], timeout=30.0, max_output=1000)

    assert time.monotonic() - start < 15


class _CrashingStream:
    """A stdout stand-in whose read1() returns a couple of real chunks then
    raises, like a pipe fd closing out from under the reader thread."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def read1(self, size: int = -1) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        raise OSError("fd closed under the reader")


class _FakePopenWithCrashingStdout:
    """Enough of Popen's interface for _run_capped: a stream that crashes
    mid-read, and a process that otherwise exits cleanly and promptly —
    isolating the reader-thread failure from any timeout/kill-tree path."""

    def __init__(self, argv, **kwargs) -> None:
        self.stdout = _CrashingStream([b"partial output before the pipe dies"])
        self.returncode = 0

    def wait(self, timeout=None) -> int:
        return self.returncode

    def poll(self) -> int:
        return self.returncode


def test_a_reader_thread_crash_raises_instead_of_returning_the_partial_buffer(
    monkeypatch,
) -> None:
    """Q3, CODE_REVIEW.md: the background reader thread used to have no
    try/except — if stream.read1() itself raised, the thread just died and
    result() silently handed back whatever had been buffered so far,
    indistinguishable from a complete, successful read."""
    from cism.agent.tools import sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakePopenWithCrashingStdout)
    monkeypatch.setattr(sandbox_module, "_kill_tree", lambda proc: None)

    with pytest.raises(ToolOutputReadError):
        run_sandboxed([sys.executable, "-c", "pass"])


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
        self.stdins: list[Path | None] = []

    def run(
        self,
        argv: list[str],
        *,
        timeout: float,
        cwd,
        max_output: int = 20_000,
        stdin: Path | None = None,
    ) -> str:
        self.calls.append(argv)
        self.stdins.append(stdin)
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


def test_etc_symlink_hops_finds_an_intermediate_etc_hop(tmp_path) -> None:
    from cism.agent.tools.sandbox import _etc_symlink_hops

    # real_lib <- /etc/alternatives/thing <- /lib/thing, mirroring the
    # actual libblas.so.3 -> /etc/alternatives/... -> real file chain.
    etc_dir = tmp_path / "etc" / "alternatives"
    etc_dir.mkdir(parents=True)
    real_lib = tmp_path / "usr" / "lib" / "real.so"
    real_lib.parent.mkdir(parents=True)
    real_lib.write_text("not a real library")

    etc_link = etc_dir / "thing"
    etc_link.symlink_to(real_lib)
    lib_link = tmp_path / "lib" / "thing"
    lib_link.parent.mkdir(parents=True)
    lib_link.symlink_to(etc_link)

    hops = _etc_symlink_hops(lib_link)

    assert hops == {etc_dir}


def test_etc_symlink_hops_returns_empty_for_a_non_symlink(tmp_path) -> None:
    from cism.agent.tools.sandbox import _etc_symlink_hops

    real_file = tmp_path / "real.so"
    real_file.write_text("not a real library")

    assert _etc_symlink_hops(real_file) == set()


def test_etc_symlink_hops_returns_empty_when_the_chain_never_touches_etc(tmp_path) -> None:
    from cism.agent.tools.sandbox import _etc_symlink_hops

    real_file = tmp_path / "real.so"
    real_file.write_text("not a real library")
    link = tmp_path / "link.so"
    link.symlink_to(real_file)

    assert _etc_symlink_hops(link) == set()


def test_etc_symlink_hops_does_not_loop_forever_on_a_circular_symlink(tmp_path) -> None:
    from cism.agent.tools.sandbox import _etc_symlink_hops

    a = tmp_path / "a"
    b = tmp_path / "b"
    a.symlink_to(b)
    b.symlink_to(a)

    # Must return (not hang) even though this chain never resolves to a
    # real file — the `seen` set breaks the cycle.
    assert _etc_symlink_hops(a) == set()


def test_dynamic_etc_binds_parses_ldd_output_and_finds_etc_hops(tmp_path, monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import _dynamic_etc_binds

    # Build a tiny fake dependency chain: one lib resolves cleanly, one
    # routes through /etc — same shape as the real libblas.so.3 case.
    etc_dir = tmp_path / "etc" / "alternatives"
    etc_dir.mkdir(parents=True)
    real_lib = tmp_path / "usr" / "lib" / "real.so"
    real_lib.parent.mkdir(parents=True)
    real_lib.write_text("x")
    etc_link = etc_dir / "picked"
    etc_link.symlink_to(real_lib)
    routed_lib = tmp_path / "lib" / "routed.so"
    routed_lib.parent.mkdir(parents=True)
    routed_lib.symlink_to(etc_link)

    plain_lib = tmp_path / "lib" / "plain.so"
    plain_lib.write_text("y")

    fake_ldd_output = (
        f"\tlinux-vdso.so.1 (0x00007fff00000000)\n"
        f"\tplain.so => {plain_lib} (0x00007f0000000000)\n"
        f"\trouted.so => {routed_lib} (0x00007f0000000000)\n"
        f"\t/lib64/ld-linux-x86-64.so.2 (0x00007f0000000000)\n"
    )

    class _FakeCompletedProcess:
        stdout = fake_ldd_output

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: "/usr/bin/fake-binary")
    monkeypatch.setattr(
        sandbox_module.subprocess, "run", lambda *a, **kw: _FakeCompletedProcess()
    )

    result = _dynamic_etc_binds("fake-binary")

    assert result == frozenset({str(etc_dir)})


def test_dynamic_etc_binds_returns_empty_set_when_ldd_fails(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import _dynamic_etc_binds

    def raise_not_found(*a, **kw):
        raise FileNotFoundError("no ldd")

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: "/usr/bin/fake-binary")
    monkeypatch.setattr(sandbox_module.subprocess, "run", raise_not_found)

    assert _dynamic_etc_binds("fake-binary") == frozenset()


def test_dynamic_etc_binds_against_a_real_installed_binary_with_no_etc_dependencies() -> None:
    """Real, non-mocked check: /bin/true has essentially no library
    dependencies, so this must return an empty set without erroring —
    proving the function survives a real ldd invocation, not just the
    mocked-output path above."""
    import shutil

    from cism.agent.tools.sandbox import _dynamic_etc_binds

    if shutil.which("true") is None:
        import pytest

        pytest.skip("`true` not installed")

    result = _dynamic_etc_binds("true")

    assert isinstance(result, frozenset)


class _FakeCompletedPopen:
    """Enough of subprocess.Popen's interface for BubblewrapRunner's argv-
    construction tests: captures what argv it was launched with, returns
    canned output, never actually runs anything."""

    captured_argv: list[str] | None = None
    last_kwargs: dict[str, object] = {}
    returncode = 0

    def __init__(self, argv, **kwargs) -> None:
        type(self).captured_argv = argv
        type(self).last_kwargs = kwargs
        self._kwargs = kwargs
        self.stdout = io.BytesIO(b"fake bwrap output")

    def wait(self, timeout=None) -> int:
        return self.returncode

    def poll(self) -> int:
        return self.returncode


def test_bubblewrap_runner_binds_every_ro_bind_dir_and_etc_path(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox_module, "_dynamic_etc_binds", lambda binary: frozenset())
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    BubblewrapRunner().run(["nmap", "10.0.0.5"], timeout=5.0, cwd=Path("/tmp/scratch"))

    argv = _FakeCompletedPopen.captured_argv
    assert argv[0] == "bwrap"
    for path in BubblewrapRunner._RO_BIND_DIRS + BubblewrapRunner._RO_BIND_ETC:
        idx = argv.index(path)
        assert argv[idx - 1] == "--ro-bind-try"
        assert argv[idx + 1] == path  # SRC and DEST are the same path


def test_bubblewrap_runner_includes_dynamically_discovered_etc_binds(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        sandbox_module, "_dynamic_etc_binds", lambda binary: frozenset({"/etc/alternatives"})
    )
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    BubblewrapRunner().run(["nmap", "10.0.0.5"], timeout=5.0, cwd=Path("/tmp/scratch"))

    argv = _FakeCompletedPopen.captured_argv
    idx = argv.index("/etc/alternatives")
    assert argv[idx - 1] == "--ro-bind-try"


def test_bubblewrap_runner_memoizes_dynamic_etc_binds_per_binary(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    calls: list[str] = []

    def fake_dynamic(binary: str) -> frozenset[str]:
        calls.append(binary)
        return frozenset()

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox_module, "_dynamic_etc_binds", fake_dynamic)
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    runner = BubblewrapRunner()
    runner.run(["nmap", "10.0.0.5"], timeout=5.0, cwd=Path("/tmp/scratch"))
    runner.run(["nmap", "10.0.0.6"], timeout=5.0, cwd=Path("/tmp/scratch2"))

    assert calls == ["nmap"]  # second call for the same binary hits the cache


def test_bubblewrap_runner_clears_and_reallowlists_the_environment(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox_module, "_dynamic_etc_binds", lambda binary: frozenset())
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    BubblewrapRunner().run(["curl", "https://x"], timeout=5.0, cwd=Path("/tmp/scratch"))

    argv = _FakeCompletedPopen.captured_argv
    assert "--clearenv" in argv
    assert argv[argv.index("--setenv") : argv.index("--setenv") + 3] == ["--setenv", "PATH", "/usr/bin:/bin"]
    assert "HOME" in argv and "/work" in argv
    assert "LANG" in argv and "C.UTF-8" in argv


def test_bubblewrap_runner_sets_security_hardening_flags(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox_module, "_dynamic_etc_binds", lambda binary: frozenset())
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    BubblewrapRunner().run(["curl", "https://x"], timeout=5.0, cwd=Path("/tmp/scratch"))

    argv = _FakeCompletedPopen.captured_argv
    for flag in ("--new-session", "--disable-userns", "--die-with-parent", "--unshare-all", "--unshare-user", "--share-net"):
        assert flag in argv


def test_bubblewrap_runner_binds_cwd_as_work_and_chdirs_into_it(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox_module, "_dynamic_etc_binds", lambda binary: frozenset())
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    BubblewrapRunner().run(["curl", "https://x"], timeout=5.0, cwd=Path("/tmp/my-scratch"))

    argv = _FakeCompletedPopen.captured_argv
    bind_idx = argv.index("--bind")
    assert argv[bind_idx + 1 : bind_idx + 3] == ["/tmp/my-scratch", "/work"]
    assert argv[argv.index("--chdir") + 1] == "/work"


def test_bubblewrap_runner_passes_a_stdin_file_as_the_real_subprocess_stdin(
    monkeypatch, tmp_path
) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox_module, "_dynamic_etc_binds", lambda binary: frozenset())
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    stdin_file = tmp_path / "stdin"
    stdin_file.write_text("id\n")

    BubblewrapRunner().run(
        ["nc", "10.0.0.2", "1524"], timeout=5.0, cwd=tmp_path, stdin=stdin_file
    )

    passed_stdin = _FakeCompletedPopen.last_kwargs["stdin"]
    assert passed_stdin.name == str(stdin_file)
    passed_stdin.close()


def test_bubblewrap_runner_passes_no_stdin_kwarg_when_omitted(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox_module, "_dynamic_etc_binds", lambda binary: frozenset())
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    BubblewrapRunner().run(["nmap", "10.0.0.5"], timeout=5.0, cwd=Path("/tmp/scratch"))

    assert "stdin" not in _FakeCompletedPopen.last_kwargs


def test_bubblewrap_runner_appends_the_real_argv_last(monkeypatch) -> None:
    """argv[0] is resolved to its absolute path (via the same shutil.which
    lookup already used for the ToolNotInstalledError check) rather than
    passed through as the bare name: PATH inside the sandbox is narrowed to
    /usr/bin:/bin, so a binary living elsewhere (e.g. nikto's symlink in
    /usr/local/bin) would fail execvp's PATH search even with its directory
    bind-mounted. The rest of argv (flags/target) is untouched."""
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox_module, "_dynamic_etc_binds", lambda binary: frozenset())
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    BubblewrapRunner().run(["curl", "-sS", "https://x"], timeout=5.0, cwd=Path("/tmp/scratch"))

    assert _FakeCompletedPopen.captured_argv[-3:] == ["/usr/bin/curl", "-sS", "https://x"]


def test_bubblewrap_runner_raises_tool_not_installed_for_a_missing_binary(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner, ToolNotInstalledError

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: None)

    with pytest.raises(ToolNotInstalledError):
        BubblewrapRunner().run(["not-a-real-binary"], timeout=5.0, cwd=Path("/tmp/scratch"))


def test_bubblewrap_runner_raises_tool_not_installed_when_bwrap_itself_is_missing(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner, ToolNotInstalledError

    def fake_which(name):
        return None if name == "bwrap" else f"/usr/bin/{name}"

    monkeypatch.setattr(sandbox_module.shutil, "which", fake_which)

    with pytest.raises(ToolNotInstalledError) as exc_info:
        BubblewrapRunner().run(["curl", "https://x"], timeout=5.0, cwd=Path("/tmp/scratch"))
    assert "bwrap" in str(exc_info.value)


requires_bwrap = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap not installed")
requires_nmap = pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed")
requires_curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")


def _has_network_egress() -> bool:
    """A real, fast outbound-connectivity probe, not a binary-presence
    check — bwrap/curl being installed says nothing about whether this
    environment (a CI runner without egress, for instance) can actually
    reach the internet, which the DNS/HTTPS test below genuinely needs."""
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=2).close()
        return True
    except OSError:
        return False


requires_network = pytest.mark.skipif(
    not _has_network_egress(), reason="no outbound network access"
)


@requires_bwrap
def test_bubblewrap_runner_blocks_writes_outside_the_scratch_bind(tmp_path) -> None:
    from cism.agent.tools.sandbox import BubblewrapRunner

    outside = tmp_path / "outside-scratch"
    outside.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    # Attempt to write to a path that exists on the host but is never
    # bound into the sandbox — must fail because the path doesn't exist
    # from the sandboxed process's point of view, not because of
    # permissions (nothing outside declared binds is even visible).
    output = BubblewrapRunner().run(
        ["sh", "-c", f"touch {outside}/should-not-exist 2>&1; echo exit=$?"],
        timeout=5.0,
        cwd=scratch,
    )

    assert "exit=0" not in output
    assert not (outside / "should-not-exist").exists()


@requires_bwrap
def test_bubblewrap_runner_allows_writes_inside_the_scratch_bind(tmp_path) -> None:
    from cism.agent.tools.sandbox import BubblewrapRunner

    scratch = tmp_path / "scratch"
    scratch.mkdir()

    BubblewrapRunner().run(["sh", "-c", "touch /work/marker"], timeout=5.0, cwd=scratch)

    assert (scratch / "marker").exists()


@requires_bwrap
@requires_curl
@requires_network
def test_bubblewrap_runner_resolves_dns_and_completes_a_real_https_call(tmp_path) -> None:
    """Proves /etc/resolv.conf and the CA trust store binds are both
    actually working, not just present in argv — a raw-IP request
    wouldn't exercise DNS at all."""
    from cism.agent.tools.sandbox import BubblewrapRunner

    scratch = tmp_path / "scratch"
    scratch.mkdir()

    output = BubblewrapRunner().run(
        ["curl", "-s", "-m", "10", "-o", "/dev/null", "-w", "http_code=%{http_code}", "https://example.com"],
        timeout=15.0,
        cwd=scratch,
    )

    assert "http_code=200" in output


@requires_bwrap
@requires_nmap
def test_bubblewrap_runner_runs_a_real_nmap_scan(tmp_path) -> None:
    """This is the exact case that broke during design (libblas.so.3
    routing through /etc/alternatives) — a real nmap invocation is the
    regression test for that fix, not a mock."""
    from cism.agent.tools.sandbox import BubblewrapRunner

    scratch = tmp_path / "scratch"
    scratch.mkdir()

    output = BubblewrapRunner().run(
        ["nmap", "-sn", "--host-timeout", "5s", "127.0.0.1"],
        timeout=15.0,
        cwd=scratch,
    )

    assert "error while loading shared libraries" not in output
    assert "Nmap done" in output


@requires_bwrap
def test_dynamic_etc_binds_finds_alternatives_for_nmap_specifically() -> None:
    """Pinned regression test for the exact bug found during design:
    nmap's libblas.so.3 dependency routes through /etc/alternatives.
    Skipped (not failed) if nmap isn't installed or this distro doesn't
    happen to route it through alternatives — the point is proving the
    discovery mechanism works generically, and this is its one confirmed
    real-world case."""
    if shutil.which("nmap") is None:
        pytest.skip("nmap not installed")

    from cism.agent.tools.sandbox import _dynamic_etc_binds

    result = _dynamic_etc_binds("nmap")

    if not result:
        pytest.skip("this nmap build doesn't route any dependency through /etc (fine — distro-specific)")
    assert "/etc/alternatives" in result


@requires_bwrap
def test_bubblewrap_runner_does_not_leak_secret_environment_variables(tmp_path, monkeypatch) -> None:
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setenv("CISM_API_KEY", "super-secret-test-value")
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    output = BubblewrapRunner().run(["env"], timeout=5.0, cwd=scratch)

    assert "super-secret-test-value" not in output
    assert "CISM_API_KEY" not in output


@requires_bwrap
def test_bubblewrap_runner_raises_tool_execution_error_on_nonzero_exit(tmp_path) -> None:
    """H2 (AUDIT.md): a sandboxed tool's non-zero exit was invisible in the audit log."""
    import json
    import logging

    from cism.agent.logging import get_agent_logger
    from cism.agent.tools.sandbox import BubblewrapRunner, ToolExecutionError

    get_agent_logger(log_dir=tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    with pytest.raises(ToolExecutionError) as exc_info:
        BubblewrapRunner().run(
            ["sh", "-c", "echo real-output; exit 3"], timeout=5.0, cwd=scratch
        )

    assert exc_info.value.returncode == 3
    assert "real-output" in exc_info.value.output

    for handler in logging.getLogger("cism.agent").handlers:
        handler.flush()
    records = [json.loads(line) for line in (tmp_path / "agent.log").read_text(encoding="utf-8").splitlines()]
    logged = next(r for r in records if r["message"] == "tool exited non-zero")
    assert logged["data"]["returncode"] == 3


@requires_bwrap
def test_bubblewrap_runner_kill_on_timeout_also_kills_a_detached_child(tmp_path) -> None:
    """Proves the PID-namespace-teardown claim (design doc §4.4): a
    process that forks a child specifically to survive its parent's death
    still dies, because the whole PID namespace tears down when bwrap's
    own init-equivalent process is killed — not just because os.killpg
    happened to catch it."""
    import json
    import logging

    from cism.agent.logging import get_agent_logger
    from cism.agent.tools.sandbox import BubblewrapRunner, ToolTimeoutError

    get_agent_logger(log_dir=tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    marker = scratch / "child-still-alive"

    script = "(sleep 0.5 && touch /work/child-still-alive) & sleep 5"

    with pytest.raises(ToolTimeoutError):
        BubblewrapRunner().run(["sh", "-c", script], timeout=0.2, cwd=scratch)

    for handler in logging.getLogger("cism.agent").handlers:
        handler.flush()
    records = [json.loads(line) for line in (tmp_path / "agent.log").read_text(encoding="utf-8").splitlines()]
    assert any(r["message"] == "tool timed out" for r in records)

    time.sleep(1)  # longer than the detached child's own 0.5s delay
    assert not marker.exists()
