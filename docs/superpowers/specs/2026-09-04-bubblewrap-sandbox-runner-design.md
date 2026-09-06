# BubblewrapRunner: OS-Level Sandbox Runner — Design

Phase 1 of 2. Phase 2 ([2026-09-04-phase-tool-guardrail-design.md](2026-09-04-phase-tool-guardrail-design.md)) covers the guardrail-chain work that follows this one.

## 1. Why

Every real tool call today runs through `SubprocessRunner` (`cism/agent/tools/sandbox.py`) — a bare `subprocess.Popen`. The only things stopping a tool call from reading or writing anywhere on the host are heuristics that inspect the call *before* it runs: `ScopeGuardStage` (is the target in scope), `DangerousFlagGuardStage` (does `extra` contain a known-dangerous flag). Both are pattern-matches on LLM-supplied text. If either heuristic has a gap nobody has found yet — an unrecognized argument shape, a flag not yet in the denylist — the actual subprocess still has unrestricted filesystem access.

The `Runner` protocol (`Runner.run(argv, *, timeout, cwd) -> str`) already exists as the seam for exactly this: "a future container-backed implementation swaps into `run_sandboxed`... nothing about the ~53 tool functions, `nodes.py`, or `graph.py` needs to change" (`sandbox.py` docstring). This document builds that implementation: `BubblewrapRunner`, using `bwrap` (bubblewrap) — the same sandboxing primitive Flatpak trusts as its minimal, no-daemon, unprivileged building block.

This was scoped down from an earlier, broader idea (network egress allow-listing tied to engagement scope) after direct testing in this repo's dev environment showed the two halves have very different costs: filesystem confinement is small and works today; network egress control needs either an L7 proxy (covers only HTTP(S) tools) or per-run network-namespace + nftables rules (covers the raw-protocol tools), and is a materially bigger, separate piece of engineering. Egress control is named explicitly in §3 as deferred, not attempted here.

**CISM installs on each user's own system — this is not a fleet CISM's authors control.** That deployment shape was weighed explicitly against Docker (§3) and is why `bwrap`, not a container runtime, is the right primitive here.

**Everything in this document that isn't marked "asserted" was verified by actually running it** (WSL2, 2026-09-04, `bubblewrap 0.9.0`) against the tools this environment has installed (`nmap`, `curl`). Two real bugs and one real security gap were found this way and are folded into the design below rather than left as a first draft.

## 2. Goals

- A tool call's subprocess cannot read or write any path on the host except its own per-call scratch directory and the small, explicitly-justified set of read-only system paths it needs to run.
- It cannot see secrets from the calling process's own environment (`CISM_API_KEY`, LLM endpoint config) — verified, not assumed.
- Zero changes to any of the ~53 tool functions, `run_sandboxed`'s call sites, `nodes.py`, or `graph.py`. The swap happens entirely behind `Runner`.
- Real tools actually run under it — proven against `nmap` and `curl`, not just a synthetic `echo`, so DNS resolution, TLS, and dynamic-linker correctness are all exercised, not assumed. Dynamic-linker gaps for tools not yet installed anywhere they've been tested (`nikto`/`whatweb`/`dnsenum`/`hydra`) are discovered automatically (§4.2b) rather than depending on someone happening to test each one by hand first.
- Existing timeout and process-tree-kill guarantees (`ToolTimeoutError`, `_kill_tree`) preserved — and, where bwrap's own process-namespace behavior gives a *stronger* guarantee than today's, that's used and stated explicitly (§4.4).

## 3. Non-goals (explicitly deferred, with the reason)

- **Network egress allow-listing.** Every catalog tool needs to reach its target over the network, so this design shares the network namespace with the host (no `--unshare-net`). A real hard boundary here needs two different mechanisms for two different tool shapes (an L7 proxy for HTTP(S) tools; network-namespace + nftables for raw-protocol tools) and deserves its own design once there's real signal on what scope shapes engagements actually use.
- **Per-tool minimal rootfs / exec confinement.** This design binds `/usr`, `/bin`, `/lib`, `/lib64`, `/sbin` read-only wholesale (needed for shared libraries across ~53 different binaries) rather than a minimal per-tool bind set. A sandboxed process can technically still exec any other installed system binary. Filesystem *write* confinement (the actual goal) is unaffected by this.
- **Wiring into `LangGraphAgent`'s default construction or `run_agent.py`.** `set_default_runner()` already exists and is what this design calls into; nothing calls it in production yet — a separate, later milestone, alongside Phase 2's guardrail work.
- **Docker/container runtime instead of bwrap.** Considered directly, not just in passing, because CISM's deployment model (each user installs it on their own machine) is exactly the case where this matters most. Docker's real advantage — a pinned image eliminates the distro-path variability found in §4.2 entirely — is real, but it costs two things this project consistently avoids: a running daemon, and (for the non-rootless setup) `docker`-group membership, which is effectively root-equivalent access to the host. Asking a user to grant that as a prerequisite for a *security* tool works against the tool's own purpose. Rootless Docker avoids the privilege issue but is known to be fragile across varied host setups — including WSL2, the environment this was verified in. Revisit Docker specifically when egress control (above) is designed — container networking is a much better foundation for that than hand-rolled netns+nftables around bwrap — but not for filesystem confinement now.
- **Replacing bwrap with nsjail.** nsjail (Google's) has native network-namespace + seccomp support and is a legitimate alternative, but switching now would discard the bwrap primitive already verified working in this exact environment, for capabilities (seccomp, scale) not currently needed.

## 4. Design

### 4.1 `BubblewrapRunner`

```python
class BubblewrapRunner:
    """Runs a tool inside bwrap: read-only system libraries + a small,
    explicitly-justified slice of /etc (§4.2), one writable scratch bind,
    a cleared environment (§4.3), network shared (every catalog tool needs
    to reach its target). The hard boundary behind the soft guardrail
    heuristics — ScopeGuardStage/DangerousFlagGuardStage inspect a call
    before it runs; this is what happens if one of them has a gap."""

    #: --ro-bind-try skips a path that doesn't exist on this distro rather
    #: than hard-erroring (bwrap's plain --ro-bind does the latter) — more
    #: portable than the read/write pair once used here (--symlink usr/bin
    #: /bin), which assumed every deployment target uses usrmerge symlinks.
    #: A bind mount follows a symlinked source transparently either way, so
    #: binding each of these directly by its real path is correct whether
    #: or not the host happens to symlink it into /usr.
    _RO_BIND_DIRS = ("/usr", "/bin", "/lib", "/lib64", "/sbin")

    #: Read-only, explicitly justified — never a wholesale /etc bind (which
    #: would expose /etc/shadow, SSH host keys, etc.). Each entry earns its
    #: place: resolv.conf/nsswitch.conf/hosts for name resolution, ssl for
    #: the CA trust store, ld.so.cache for the dynamic linker, alternatives
    #: because Debian/Ubuntu route many shared libraries through symlinks
    #: that hop through /etc/alternatives/... — found by nmap actually
    #: failing to start (§4.2) until this was added.
    _RO_BIND_ETC = (
        "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/hosts",
        "/etc/ssl", "/etc/ld.so.cache", "/etc/alternatives",
    )

    def __init__(self) -> None:
        self._etc_binds_cache: dict[str, frozenset[str]] = {}  # binary -> dynamic /etc binds, §4.2b

    def run(self, argv: list[str], *, timeout: float, cwd: Path) -> str:
        if shutil.which(argv[0]) is None:
            raise ToolNotInstalledError(argv[0])
        if shutil.which("bwrap") is None:
            raise ToolNotInstalledError("bwrap")

        binary = argv[0]
        if binary not in self._etc_binds_cache:
            self._etc_binds_cache[binary] = _dynamic_etc_binds(binary)  # §4.2b — computed once per binary, memoized
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
            "--new-session",       # blocks TIOCSTI terminal-injection into a process outside the sandbox
            "--disable-userns",    # sandboxed process can't create its own nested user namespaces
            "--clearenv",          # §4.3 — do not inherit CISM_API_KEY / LLM endpoint config
            "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "HOME", "/work",
            "--setenv", "LANG", "C.UTF-8",
            *argv,
        ]
        # subprocess.Popen(bwrap_argv, ...) — same start_new_session /
        # communicate(timeout=) / _kill_tree() shape as SubprocessRunner,
        # reusing that module's existing helpers rather than duplicating them.
```

`--disable-userns` requires `--unshare-user` to be present explicitly on the command line — bwrap's own arg validation rejects it otherwise even though `--unshare-all` already implies unsharing the user namespace. Verified: omitting `--unshare-user` here fails with `bwrap: --disable-userns requires --unshare-user` before the sandboxed process even starts. (Verified against `bubblewrap 0.9.0`; if a future bwrap version changes this validation, the unit test in §5 asserting `--unshare-user` is present in argv will catch a regression either way, independent of *why* it's required.)

`_dynamic_etc_binds` (the function `__init__`'s cache and `run()` call above depend on) is defined in §4.2b — forward-referenced here because the memoization lives on the instance, but the discovery logic itself is a free function with no `BubblewrapRunner` state.

### 4.2 Two real bugs found by actually running this against installed tools

Neither of these was caught by reasoning about the design — both only surfaced by testing `curl`/`nmap` for real inside the sandbox, which is exactly why §5 requires that rather than mocked-only tests.

1. **DNS/TLS were missing entirely from the first draft of this design**, despite this exact repo's own earlier hand-verification (same conversation, before this design was written) having proven `/etc/resolv.conf` and a CA trust store are both required for any network call to succeed. Omitting them would have broken every network-touching tool on first real use. Fixed: both are in `_RO_BIND_ETC` above.
2. **`nmap` failed to start**: `error while loading shared libraries: libblas.so.3: cannot open shared object file`. Traced to Debian's `update-alternatives`: `/usr/lib/x86_64-linux-gnu/libblas.so.3` is a symlink to `/etc/alternatives/libblas.so.3-x86_64-linux-gnu`, which symlinks again to the real file under `/usr/lib/.../blas/`. Binding `/usr` alone leaves the middle hop — inside `/etc`, deliberately not bound wholesale — dangling. Fixed: `/etc/alternatives` is in `_RO_BIND_ETC`, read-only, nothing else under `/etc` exposed. Verified after the fix: `nmap -sn scanme.nmap.org` completes successfully inside the sandbox.

This class of bug (a library resolves through an indirection this design doesn't bind) is a real, open-ended risk as the catalog grows past `nmap`/`curl` to tools not installed in this dev environment (`nikto`, `whatweb`, `dnsenum`, `hydra`) — a hand-curated `_RO_BIND_ETC` found by testing one tool at a time is exactly the kind of thing that silently stops covering the next one. §4.2b replaces the hand-curated part of this with something that can't go stale that way.

### 4.2b Discovering `/etc` dependencies automatically, not by hand

Verified generically, not just for `libblas.so.3`: running `ldd <binary>` lists every shared library a binary needs; walking each result's *full* symlink chain (not just its final resolved target — `pathlib`'s own `.resolve()` would skip straight past the interesting hop) and checking whether any hop has an `etc` path component finds exactly the one dependency that does, out of nmap's ~25:

```python
def _etc_symlink_hops(path: Path) -> set[Path]:
    """Every hop with an `etc` path component in path's full symlink chain,
    not just its final target — the bug in §4.2 was an *intermediate* hop
    (/etc/alternatives/...), which .resolve() alone would skip past.
    Matching the `etc` component rather than a literal `/etc` prefix lets
    the unit tests stage the chain under a tmp dir and still exercise it."""
    hops: set[Path] = set()
    current, seen = path, set()
    while current not in seen and current.is_symlink():
        seen.add(current)
        target = current.readlink()
        if not target.is_absolute():
            target = (current.parent / target).resolve()
        if "etc" in target.parts:
            hops.add(target.parent)  # bind the containing dir, not one file
        current = target
    return hops


def _dynamic_etc_binds(binary: str) -> frozenset[str]:
    """Runs once per distinct binary (memoized — a binary's library
    dependencies don't change at runtime), on the host, before that
    binary's first sandboxed invocation. `binary` always comes from this
    codebase's own fixed catalog (never LLM-supplied), so this carries no
    more trust than the shutil.which(argv[0]) check already next to it."""
    try:
        ldd_output = subprocess.run(
            ["ldd", shutil.which(binary)], capture_output=True, text=True, timeout=5
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return frozenset()  # static binary, or ldd unavailable — fall back to the static baseline only

    hops: set[Path] = set()
    for line in ldd_output.splitlines():
        parts = line.split("=>")
        candidate = parts[1].split(" (")[0].strip() if len(parts) > 1 else parts[0].split(" (")[0].strip()
        if candidate and Path(candidate).exists():
            hops |= _etc_symlink_hops(Path(candidate))
    return frozenset(str(p) for p in hops)
```

`BubblewrapRunner.run()` calls `_dynamic_etc_binds(argv[0])` (memoized in an instance dict keyed by binary name) and adds the result to `_RO_BIND_ETC` for that call. The static list (`resolv.conf`, `nsswitch.conf`, `hosts`, `ssl`, `ld.so.cache`) stays — those are needed for name resolution/TLS generally, independent of any one binary's library dependencies, and aren't discoverable via `ldd` at all. The dynamic part specifically closes the "next tool hits the same surprise and nobody notices" gap: it runs automatically for `nikto`/`whatweb`/`dnsenum`/`hydra` the first time each is actually invoked, with no one needing to have manually tested them first.

### 4.3 Environment hardening (a gap this design introduced awareness of, not one that existed before)

`bwrap`, like any subprocess, inherits its parent's full environment unless told otherwise. The calling Python process's environment includes `CISM_API_KEY`, `CISM_LLM_BASE_URL`, `CISM_LLM_MODEL` (`cism/agent/core.py`'s `_llm_from_env`). Without `--clearenv`, every sandboxed tool call — including one whose argv came from an untrusted or injected instruction — would see all of it.

**Verified directly**: running `bwrap ... --clearenv --setenv PATH ... /usr/bin/env` with `CISM_API_KEY=super-secret-value` set in the calling shell produces output containing only `PATH` and `PWD` (the latter set by bwrap itself) — the secret is not visible. `--setenv` adds exactly `PATH`, `HOME=/work`, `LANG=C.UTF-8` — the minimum a CLI tool needs to run predictably; nothing else passes through.

### 4.4 Timeout/kill: a stronger guarantee than `SubprocessRunner`, not just a preserved one

`--unshare-all` puts the sandboxed process in its own PID namespace, with the process bwrap spawns effectively acting as that namespace's init. Linux tears down every process in a PID namespace when its init process dies. That means `_kill_tree`'s existing `os.killpg` call — signaling the outer `bwrap` process's group on timeout — cascades through kernel PID-namespace semantics to kill everything inside, including a tool that double-forks or daemonizes specifically to escape a process group (a real gap in `SubprocessRunner`'s current tree-kill, which only catches processes that stayed inside the group). `--die-with-parent` is a separate, additional safety net (`prctl(PR_SET_PDEATHSIG)`) for the case where the calling Python process itself dies unexpectedly — not a replacement for the explicit timeout/kill path.

### 4.5 Error mapping

`bwrap`'s own failure when the target binary can't be found inside the sandbox view (`execvp <binary>: No such file or directory`) must map to the existing `ToolNotInstalledError`, not leak a bwrap-specific message. Detected the same way `SubprocessRunner` does it: `shutil.which(argv[0])` checked *before* invoking bwrap — if the binary doesn't exist on the host's PATH, raise before bwrap ever runs, rather than parsing bwrap's stderr. A missing `bwrap` binary itself is a distinct, environment-level failure, raised as `ToolNotInstalledError("bwrap")`.

### 4.6 Rollout

`BubblewrapRunner` is built and fully tested in this phase but is **not** wired into any default construction path — same status `build_toolkit()` had before this conversation started. `set_default_runner(BubblewrapRunner())` becomes a real call site only in the later live-tools-wiring milestone, alongside the guardrail work from Phase 2.

## 5. Testing

- Unit tests with a controllable fake `subprocess.Popen` (mirroring how `SubprocessRunner` itself is tested) for: argv construction (including the full `_RO_BIND_DIRS`/`_RO_BIND_ETC`/`--clearenv`/`--setenv` set), timeout → `ToolTimeoutError`, missing-binary → `ToolNotInstalledError`, missing-bwrap → `ToolNotInstalledError("bwrap")`.
- **Real, non-mocked integration tests**, skipped where `bwrap` isn't available (`shutil.which("bwrap")` fixture guard):
  - filesystem: a write outside the scratch bind fails; a write inside it succeeds and is visible after the call returns.
  - network: a real DNS-resolved HTTPS call (not just a raw socket to an IP) succeeds — proves `/etc/resolv.conf` + the CA bind are both actually working, not just present in argv.
  - **run at least `nmap` and `curl` for real** (both installed in CI/dev), not a synthetic binary — this is what caught the `libblas.so.3` bug; a synthetic `echo`-only test would not have.
  - `_dynamic_etc_binds`: assert it correctly returns `/etc/alternatives` for `nmap` (the known case, pinned as a regression test) and returns an empty set for a statically-linked or trivial binary (e.g. `/bin/true`) — proving the memoized discovery mechanism works generically, not just re-asserting the one bug already found by hand.
  - environment: set a fake secret env var on the test process, assert it is *not* visible inside the sandbox (e.g. via a small helper tool that prints its own environment) — the same check performed by hand in §4.3, made permanent.
  - timeout/kill: a sandboxed process that forks a detached child, killed via the same path `_kill_tree` uses — assert the child is also gone (proves §4.4's PID-namespace claim, doesn't just assert it).
- Existing `Runner`-protocol tests (`test_sandbox.py`) extended to instantiate `BubblewrapRunner` wherever they currently parametrize over `SubprocessRunner`, so the protocol contract is proven identical between the two.
