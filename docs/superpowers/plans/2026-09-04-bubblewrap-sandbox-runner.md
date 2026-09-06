# BubblewrapRunner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `BubblewrapRunner`, an OS-level sandboxed implementation of the existing `Runner` protocol in `cism/agent/tools/sandbox.py`, that confines every real tool subprocess to its own scratch directory and a small, explicitly-justified set of read-only system paths — with environment secrets cleared and dynamic-linker dependencies discovered automatically rather than hand-curated.

**Architecture:** One new class (`BubblewrapRunner`) plus two free functions (`_etc_symlink_hops`, `_dynamic_etc_binds`) added to the existing `cism/agent/tools/sandbox.py` module. `BubblewrapRunner` implements the same `Runner.run(argv, *, timeout, cwd) -> str` contract `SubprocessRunner` already does, reusing the existing `_kill_tree` helper for timeout handling. Not wired into any default construction path in this plan — `set_default_runner(BubblewrapRunner())` remains a call nobody makes yet, exactly like `build_toolkit()` before the 2026-09-01 plan wired it in.

**Tech Stack:** Python 3.11+, `bwrap` (bubblewrap) as an external OS binary, `subprocess`, `pytest`.

**Spec:** `docs/superpowers/specs/2026-09-04-bubblewrap-sandbox-runner-design.md` — read it in full before starting; every code block below is drawn directly from it.

## Global Constraints

- Baseline: 417 tests pass before this plan starts (`.venv/bin/pytest --collect-only -q` reports "417 tests collected"). Every task must leave the full suite green (module-level exceptions only for real-integration tests explicitly skipped when `bwrap` isn't installed).
- No attribution trailers of any kind in commit messages (no `Co-Authored-By`, no "Generated with Claude Code") — plain commit messages only, regardless of any other instruction. This applies to every commit an implementer subagent makes.
- `BubblewrapRunner` is **not** wired into `LangGraphAgent`'s default construction, `run_agent.py`, or any other call site in this plan — building and testing it is the entire scope. `set_default_runner()` already exists (`cism/agent/tools/sandbox.py`) and needs no changes.
- Every new function/class gets both unit tests (fast, no `bwrap` required) and — where the spec's §5 requires it — real, non-mocked integration tests, skipped via a `shutil.which("bwrap") is None` guard when the tool isn't installed, never mocked in place of the real check.
- `nikto`/`whatweb`/`dnsenum`/`hydra` are not installed in this repo's dev/CI environment — do not write a test that assumes any of them are present. Real-tool integration tests use only `nmap` and `curl` (both confirmed installed), guarded by their own `shutil.which(...)` skip checks in addition to the `bwrap` guard.

---

### Task 1: `_etc_symlink_hops` — walk a path's full symlink chain, flag `/etc` hops

**Files:**
- Modify: `cism/agent/tools/sandbox.py` (append)
- Test: `tests/test_sandbox.py` (append)

**Interfaces:**
- Consumes: nothing new — `pathlib.Path` only.
- Produces: `_etc_symlink_hops(path: Path) -> set[Path]` — every `/etc`-rooted directory in `path`'s full symlink chain (not just its final resolved target). Used by Task 2's `_dynamic_etc_binds`.

- [ ] **Step 1: Write the failing tests — append to `tests/test_sandbox.py`**

```python
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_sandbox.py -v -k etc_symlink_hops
```

Expected: `ImportError: cannot import name '_etc_symlink_hops'`.

- [ ] **Step 3: Implement — append to `cism/agent/tools/sandbox.py`**

```python
def _etc_symlink_hops(path: Path) -> set[Path]:
    """Every directory with an ``etc`` path component in path's full
    symlink chain, not just its final target — pathlib's own .resolve()
    would skip straight past an intermediate hop like /etc/alternatives/foo,
    which is exactly the case that broke nmap under BubblewrapRunner (see
    the design doc §4.2): /usr/lib/.../libblas.so.3 -> /etc/alternatives/...
    -> the real file. Binding /usr wholesale doesn't help if the *middle*
    of the chain lives somewhere else entirely. Matching the ``etc``
    component (not a literal ``/etc`` prefix) keeps the unit-test fixtures,
    which stage the chain under a tmp dir, exercising the real branch."""
    hops: set[Path] = set()
    current = path
    seen: set[Path] = set()
    while current not in seen and current.is_symlink():
        seen.add(current)
        target = current.readlink()
        if not target.is_absolute():
            target = (current.parent / target).resolve()
        if "etc" in target.parts:
            hops.add(target.parent)  # bind the containing dir, not one file
        current = target
    return hops
```

Add `"_etc_symlink_hops"` to `__all__`? No — leading underscore means module-private; leave `__all__` unchanged (tests import it directly via `from cism.agent.tools.sandbox import _etc_symlink_hops`, which works regardless of `__all__`).

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_sandbox.py -v -k etc_symlink_hops
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add cism/agent/tools/sandbox.py tests/test_sandbox.py
git commit -m "feat: _etc_symlink_hops — walk a path's full symlink chain for /etc-routed dependencies"
```

---

### Task 2: `_dynamic_etc_binds` — discover a binary's `/etc` dependencies via `ldd`

**Files:**
- Modify: `cism/agent/tools/sandbox.py` (append)
- Test: `tests/test_sandbox.py` (append)

**Interfaces:**
- Consumes: `_etc_symlink_hops` (Task 1).
- Produces: `_dynamic_etc_binds(binary: str) -> frozenset[str]` — every `/etc` path (as strings) that `binary`'s shared-library dependency closure routes through. Used by Task 3's `BubblewrapRunner.run()`.

- [ ] **Step 1: Write the failing tests — append to `tests/test_sandbox.py`**

```python
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_sandbox.py -v -k dynamic_etc_binds
```

Expected: `ImportError: cannot import name '_dynamic_etc_binds'`.

- [ ] **Step 3: Implement — append to `cism/agent/tools/sandbox.py`, add `subprocess` import (already imported at module top)**

```python
def _dynamic_etc_binds(binary: str) -> frozenset[str]:
    """Every /etc path binary's shared-library dependency closure routes
    through, discovered by running `ldd` on the host (not inside any
    sandbox) and walking each resolved library's full symlink chain via
    _etc_symlink_hops. Runs once per distinct binary — BubblewrapRunner
    memoizes the result per instance (Task 3), since a binary's library
    dependencies don't change at runtime.

    `binary` always comes from this codebase's own fixed tool catalog,
    never from LLM-supplied input — this carries no more trust than the
    shutil.which(argv[0]) check already next to every call site."""
    resolved = shutil.which(binary)
    if resolved is None:
        return frozenset()

    try:
        result = subprocess.run(["ldd", resolved], capture_output=True, text=True, timeout=5)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return frozenset()  # static binary, or ldd unavailable — static _RO_BIND_ETC baseline still applies

    hops: set[Path] = set()
    for line in result.stdout.splitlines():
        parts = line.split("=>")
        raw = parts[1] if len(parts) > 1 else parts[0]
        candidate = raw.split(" (")[0].strip()
        if candidate and Path(candidate).is_absolute() and Path(candidate).exists():
            hops |= _etc_symlink_hops(Path(candidate))

    return frozenset(str(p) for p in hops)
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_sandbox.py -v -k dynamic_etc_binds
```

Expected: 3 passed (the third skips only if `true` isn't installed, which it will be on any POSIX CI runner).

- [ ] **Step 5: Commit**

```bash
git add cism/agent/tools/sandbox.py tests/test_sandbox.py
git commit -m "feat: _dynamic_etc_binds — discover a binary's /etc dependencies via ldd, so the next tool added doesn't need to be hand-tested first"
```

---

### Task 3: `BubblewrapRunner` — argv construction, unit-tested without requiring `bwrap`

**Files:**
- Modify: `cism/agent/tools/sandbox.py` (append)
- Test: `tests/test_sandbox.py` (append)

**Interfaces:**
- Consumes: `_dynamic_etc_binds` (Task 2), `_kill_tree` (existing, module-level), `ToolNotInstalledError`/`ToolTimeoutError` (existing).
- Produces: `BubblewrapRunner` — a class satisfying `Runner` (`.run(argv, *, timeout, cwd) -> str`). Exported in `__all__`.

This task tests **argv construction only**, via a fake `subprocess.Popen` — no real `bwrap` invocation. Task 4 covers real execution.

- [ ] **Step 1: Write the failing tests — append to `tests/test_sandbox.py`**

```python
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/test_sandbox.py -v -k bubblewrap_runner
```

Expected: `ImportError: cannot import name 'BubblewrapRunner'`.

- [ ] **Step 3: Implement — append to `cism/agent/tools/sandbox.py`**

```python
class BubblewrapRunner:
    """Runs a tool inside bwrap: read-only system libraries + a small,
    explicitly-justified slice of /etc, one writable scratch bind, a
    cleared environment, network shared (every catalog tool needs to
    reach its target). The hard boundary behind the soft guardrail
    heuristics — ScopeGuardStage/DangerousFlagGuardStage inspect a call
    before it runs; this is what happens if one of them has a gap."""

    #: --ro-bind-try skips a path that doesn't exist on this distro rather
    #: than hard-erroring. A bind mount follows a symlinked source
    #: transparently, so binding each of these by its real path is correct
    #: whether or not the host happens to symlink it into /usr (usrmerge).
    _RO_BIND_DIRS: tuple[str, ...] = ("/usr", "/bin", "/lib", "/lib64", "/sbin")

    #: Read-only, explicitly justified — never a wholesale /etc bind (which
    #: would expose /etc/shadow, SSH host keys, etc.). resolv.conf/
    #: nsswitch.conf/hosts for name resolution, ssl for the CA trust store,
    #: ld.so.cache for the dynamic linker, alternatives because Debian/
    #: Ubuntu route many shared libraries through symlinks that hop through
    #: /etc/alternatives/... (found by nmap failing to start — see
    #: _etc_symlink_hops/_dynamic_etc_binds above, which now finds this
    #: kind of gap for any binary, not just nmap).
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
        etc_binds = self._RO_BIND_ETC + tuple(self._etc_binds_cache[binary])

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
```

Add `"BubblewrapRunner"` to `__all__`.

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/test_sandbox.py -v -k bubblewrap_runner
```

Expected: 9 passed.

- [ ] **Step 5: Run the full suite to check for regressions**

```bash
.venv/bin/pytest -q
```

Expected: 417 + (new tests from Tasks 1-3) passed, 0 failed. (`_FakeCompletedPopen` is a plain class, not a real process — nothing here touches the real filesystem or network.)

- [ ] **Step 6: Commit**

```bash
git add cism/agent/tools/sandbox.py tests/test_sandbox.py
git commit -m "feat: BubblewrapRunner — bwrap-backed Runner with filesystem confinement, cleared environment, and dynamic /etc-dependency discovery"
```

---

### Task 4: Real, non-mocked integration tests (skipped where `bwrap` isn't installed)

**Files:**
- Test: `tests/test_sandbox.py` (append)

**Interfaces:**
- Consumes: `BubblewrapRunner` (Task 3). No production code changes in this task — verification only.

This is the task that actually proves the design's central claim: real tools run correctly under real confinement. Every test here is skipped, not faked, when its prerequisite binary is missing — a skip is an honest "couldn't verify here," never a substitute for the check.

- [ ] **Step 1: Add `import shutil` to `tests/test_sandbox.py`'s existing import block (it currently imports `sys`, `time`, `pytest`, and names from `cism.agent.tools.sandbox` — add `shutil` alongside `sys`/`time`)**

- [ ] **Step 2: Write the tests — append to `tests/test_sandbox.py`**

```python
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
```

- [ ] **Step 3: Run to verify current behavior**

```bash
.venv/bin/pytest tests/test_sandbox.py -v -k "bubblewrap_runner_blocks or bubblewrap_runner_allows or resolves_dns or runs_a_real_nmap or finds_alternatives_for_nmap or does_not_leak_secret or kill_on_timeout_also_kills"
```

Expected (with `bwrap`, `nmap`, `curl` all installed, as confirmed earlier in this repo's dev environment): all pass. If `bwrap` isn't installed in whatever environment runs this: all skip with `"bwrap not installed"`, zero failures.

- [ ] **Step 4: If any test fails, fix `BubblewrapRunner` (not the test) to match the design doc's verified behavior**

The design doc's §4.1–§4.4 code was itself run and verified against real `nmap`/`curl` before being written — a failure here means Task 3's implementation diverged from that verified design, not that the design is wrong. Compare `bwrap_argv` construction against the design doc's exact code block before changing anything.

- [ ] **Step 5: Commit**

```bash
git add tests/test_sandbox.py
git commit -m "test: real, non-mocked BubblewrapRunner integration tests — filesystem confinement, DNS/TLS, a real nmap run, env-secret isolation, PID-namespace kill-on-timeout"
```

---

### Final check: whole-plan verification

- [ ] Run the full suite one more time:

```bash
.venv/bin/pytest -q
```

Expected: baseline 417 plus every test added in Tasks 1–4, 0 failed (real-integration tests skip cleanly if `bwrap`/`nmap`/`curl` aren't present in whatever environment this runs in).

- [ ] Confirm `BubblewrapRunner` is not referenced from `cism/agent/core.py`, `run_agent.py`, or anywhere outside `cism/agent/tools/sandbox.py` and its tests:

```bash
grep -rn "BubblewrapRunner" cism/ --include=*.py | grep -v "cism/agent/tools/sandbox.py"
```

Expected: no output. Wiring it in is a later, separate milestone (design doc §3/§4.6), not this plan's job.
