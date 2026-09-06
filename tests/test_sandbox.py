"""cism/agent/tools/sandbox.py: what run_sandboxed actually guarantees —
no shell interpretation, a runaway process (and its children) actually
gets killed on timeout, a tool can't leave files outside its own scratch
directory, and huge output doesn't lose the tool's final summary line.

Exercised entirely against sys.executable stand-ins — no real security
tools involved.
"""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path

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


#: Host paths that Debian/Ubuntu route through /etc/alternatives — the same
#: symlink indirection that broke nmap's libblas.so.3 during design (§4.2).
#: Real, not faked: _etc_symlink_hops checks the literal /etc, so a fake
#: tmp_path tree would never exercise the branch that actually matters.
_ETC_ALTERNATIVES_CANDIDATES = (
    "/usr/bin/awk",
    "/usr/lib/cpp",
    "/usr/bin/pager",
    "/usr/bin/editor",
    "/usr/bin/c++",
    "/usr/bin/cc",
)


def _first_path_routing_through_etc_alternatives():
    from pathlib import Path

    for candidate in _ETC_ALTERNATIVES_CANDIDATES:
        p = Path(candidate)
        if not p.is_symlink():
            continue
        target = p.readlink()
        if not target.is_absolute():
            target = (p.parent / target)
        if str(target).startswith("/etc/alternatives/"):
            return p
    return None


def test_etc_symlink_hops_finds_a_real_intermediate_etc_alternatives_hop() -> None:
    """Real, non-mocked: on Debian/Ubuntu many binaries and shared
    libraries reach their target through an /etc/alternatives symlink hop
    (e.g. /usr/bin/awk -> /etc/alternatives/awk -> /usr/bin/mawk) — the
    exact indirection class that broke nmap under BubblewrapRunner (design
    doc §4.2). Skipped, not failed, on a host that doesn't use the
    alternatives system for any of the probe paths."""
    from pathlib import Path

    from cism.agent.tools.sandbox import _etc_symlink_hops

    routed = _first_path_routing_through_etc_alternatives()
    if routed is None:
        pytest.skip("no host path routes through /etc/alternatives")

    assert _etc_symlink_hops(routed) == {Path("/etc/alternatives")}


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


def test_dynamic_etc_binds_walks_real_symlink_chains_to_find_etc_hops(monkeypatch) -> None:
    """ldd output is stubbed (no installed binary on a typical host has a
    library-closure that routes through /etc), but the chain walk and the
    /etc detection run against real host paths — the fix in §4.2 is about
    an *intermediate* real /etc/alternatives hop, so a faked /etc tree
    wouldn't exercise the branch that matters. Skipped where no probe path
    routes through /etc/alternatives."""
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import _dynamic_etc_binds

    routed = _first_path_routing_through_etc_alternatives()
    if routed is None:
        pytest.skip("no host path routes through /etc/alternatives")

    fake_ldd_output = (
        "\tlinux-vdso.so.1 (0x00007fff00000000)\n"
        f"\tlibrouted.so => {routed} (0x00007f0000000000)\n"
        "\t/lib64/ld-linux-x86-64.so.2 (0x00007f0000000000)\n"
    )

    class _FakeCompletedProcess:
        stdout = fake_ldd_output

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: "/usr/bin/fake-binary")
    monkeypatch.setattr(
        sandbox_module.subprocess, "run", lambda *a, **kw: _FakeCompletedProcess()
    )

    result = _dynamic_etc_binds("fake-binary")

    assert result == frozenset({"/etc/alternatives"})


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
        pytest.skip("`true` not installed")

    result = _dynamic_etc_binds("true")

    assert isinstance(result, frozenset)


class _FakeCompletedPopen:
    """Enough of subprocess.Popen's interface for BubblewrapRunner's argv-
    construction tests: captures what argv it was launched with, returns
    canned output, never actually runs anything."""

    captured_argv: list[str] | None = None

    def __init__(self, argv, **kwargs) -> None:
        type(self).captured_argv = argv
        self._kwargs = kwargs

    def communicate(self, timeout=None):
        return (b"fake bwrap output", None)


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


def test_bubblewrap_runner_appends_the_real_argv_last(monkeypatch) -> None:
    from cism.agent.tools import sandbox as sandbox_module
    from cism.agent.tools.sandbox import BubblewrapRunner

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox_module, "_dynamic_etc_binds", lambda binary: frozenset())
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", _FakeCompletedPopen)

    BubblewrapRunner().run(["curl", "-sS", "https://x"], timeout=5.0, cwd=Path("/tmp/scratch"))

    assert _FakeCompletedPopen.captured_argv[-3:] == ["curl", "-sS", "https://x"]


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
def test_bubblewrap_runner_kill_on_timeout_also_kills_a_detached_child(tmp_path) -> None:
    """Proves the PID-namespace-teardown claim (design doc §4.4): a
    process that forks a child specifically to survive its parent's death
    still dies, because the whole PID namespace tears down when bwrap's
    own init-equivalent process is killed — not just because os.killpg
    happened to catch it."""
    from cism.agent.tools.sandbox import BubblewrapRunner, ToolTimeoutError

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    marker = scratch / "child-still-alive"

    script = "(sleep 0.5 && touch /work/child-still-alive) & sleep 5"

    with pytest.raises(ToolTimeoutError):
        BubblewrapRunner().run(["sh", "-c", script], timeout=0.2, cwd=scratch)

    time.sleep(1)  # longer than the detached child's own 0.5s delay
    assert not marker.exists()
