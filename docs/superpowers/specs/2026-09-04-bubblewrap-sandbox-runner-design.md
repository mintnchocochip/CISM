# BubblewrapRunner: OS-Level Sandbox Runner — Design

Phase 1 of 2. Phase 2 ([2026-09-04-phase-tool-guardrail-design.md](2026-09-04-phase-tool-guardrail-design.md)) covers the guardrail-chain work that follows this one.

## 1. Why

Every real tool call today runs through `SubprocessRunner` (`cism/agent/tools/sandbox.py`) — a bare `subprocess.Popen`. The only things stopping a tool call from reading or writing anywhere on the host are heuristics that inspect the call *before* it runs: `ScopeGuardStage` (is the target in scope), `DangerousFlagGuardStage` (does `extra` contain a known-dangerous flag). Both are pattern-matches on LLM-supplied text. If either heuristic has a gap nobody has found yet — an unrecognized argument shape, a flag not yet in the denylist — the actual subprocess still has unrestricted filesystem access.

The `Runner` protocol (`Runner.run(argv, *, timeout, cwd) -> str`) already exists as the seam for exactly this: "a future container-backed implementation swaps into `run_sandboxed`... nothing about the ~53 tool functions, `nodes.py`, or `graph.py` needs to change" (`sandbox.py` docstring). This document builds that implementation: `BubblewrapRunner`, using `bwrap` (bubblewrap) — the same sandboxing primitive Flatpak trusts as its minimal, no-daemon, unprivileged building block.

This was scoped down from an earlier, broader idea (network egress allow-listing tied to engagement scope) after direct testing in this repo's dev environment showed the two halves have very different costs: filesystem confinement is small and works today; network egress control needs either an L7 proxy (covers only HTTP(S) tools — 3 of ~7 in the catalog) or per-run network-namespace + nftables rules (covers the raw-protocol tools — nmap, hydra, dnsenum — but is a materially bigger, separate piece of engineering with its own failure modes: hostname-vs-IP resolution timing, multi-host/CIDR scope, IPv6). Egress control is named explicitly in §3 as deferred, not attempted here.

## 2. Goals

- A tool call's subprocess cannot read or write any path on the host except its own per-call scratch directory and the read-only system libraries it needs to run.
- Zero changes to any of the ~53 tool functions, `run_sandboxed`'s call sites, `nodes.py`, or `graph.py`. The swap happens entirely behind `Runner`.
- Real, verified behavior — not mocked-only. This repo's dev environment (WSL2) has been confirmed to support unprivileged bwrap sandboxing (verified 2026-09-04: read-only root + single writable scratch bind blocks writes elsewhere; `--share-net`/`--unshare-net` correctly gate network reachability).
- Existing timeout and process-tree-kill guarantees (`ToolTimeoutError`, `_kill_tree`) preserved exactly.

## 3. Non-goals (explicitly deferred, with the reason)

- **Network egress allow-listing.** Every catalog tool needs to reach its target over the network, so this design shares the network namespace with the host (no `--unshare-net`). A real hard boundary here — restricting egress to the engagement's declared scope — needs two different mechanisms for two different tool shapes (an L7 proxy for HTTP(S) tools; network-namespace + nftables for raw-protocol tools like nmap/hydra/dnsenum) and deserves its own design once there's real signal on what scope shapes engagements actually use. Flagged to revisit, not forgotten.
- **Per-tool minimal rootfs / exec confinement.** This design binds `/usr`, `/lib`, `/lib64` read-only wholesale (needed for shared libraries across ~53 different binaries) rather than a minimal per-tool bind set. This means a sandboxed process can technically still exec any other installed system binary — bwrap alone doesn't provide exec confinement without a much more invasive minimal-rootfs-per-tool scheme, which isn't attempted here. Filesystem *write* confinement (the actual goal) is unaffected by this.
- **Wiring into `LangGraphAgent`'s default construction or `run_agent.py`.** `set_default_runner()` already exists and is what this design calls into; nothing calls it in production yet. That remains a separate, later milestone — real tools and real guardrails become opt-in together, not before the guardrail-chain work (Phase 2) exists.
- **Replacing bwrap with nsjail.** nsjail (Google's) has native network-namespace + seccomp support and is a legitimate alternative, but switching now would discard the bwrap primitive already verified working in this exact environment, for capabilities (seccomp, scale) not currently needed.

## 4. Design

### 4.1 `BubblewrapRunner`

```python
class BubblewrapRunner:
    """Runs a tool inside bwrap: read-only system libraries, one writable
    scratch bind, network shared (every catalog tool needs to reach its
    target). The hard boundary behind the soft guardrail heuristics —
    ScopeGuardStage/DangerousFlagGuardStage inspect a call before it runs;
    this is what happens if one of them has a gap."""

    def run(self, argv: list[str], *, timeout: float, cwd: Path) -> str:
        if shutil.which(argv[0]) is None:
            raise ToolNotInstalledError(argv[0])
        if shutil.which("bwrap") is None:
            raise ToolNotInstalledError("bwrap")

        bwrap_argv = [
            "bwrap",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--symlink", "usr/bin", "/bin",
            "--bind", str(cwd), "/work",
            "--chdir", "/work",
            "--proc", "/proc",
            "--dev", "/dev",
            "--unshare-all", "--share-net",
            "--die-with-parent",
            *argv,
        ]
        # subprocess.Popen(bwrap_argv, ...) — same start_new_session /
        # communicate(timeout=) / _kill_tree() shape as SubprocessRunner,
        # reusing that module's existing helpers rather than duplicating them.
```

`/lib64` is conditionally included only if it exists (some distros don't have it — binding a nonexistent path is a bwrap hard error, not a soft skip).

### 4.2 Error mapping

`bwrap`'s own failure when the target binary can't be found inside the sandbox view (`execvp <binary>: No such file or directory`) must map to the existing `ToolNotInstalledError`, not leak a bwrap-specific message — callers already only handle that one exception type regardless of which `Runner` produced it. Detected the same way `SubprocessRunner` does it: `shutil.which(argv[0])` checked *before* invoking bwrap (against the host's view, which matches the sandbox's view since `/usr` is bound in wholesale) — if the binary doesn't exist there, raise before bwrap ever runs, rather than parsing bwrap's stderr.

A missing `bwrap` binary itself (not installed) is a distinct, environment-level failure — also raised as `ToolNotInstalledError("bwrap")`, checked once at the top of `run()`.

### 4.3 Rollout

`BubblewrapRunner` is built and fully tested in this phase but is **not** wired into any default construction path — same status `build_toolkit()` had before this conversation started. `set_default_runner(BubblewrapRunner())` becomes a real call site only in the later live-tools-wiring milestone, alongside the guardrail work from Phase 2.

## 5. Testing

- Unit tests with a controllable fake `subprocess.Popen` (mirroring how `SubprocessRunner` itself is tested) for: argv construction, timeout → `ToolTimeoutError`, process-tree kill on timeout, missing-binary → `ToolNotInstalledError`, missing-bwrap → `ToolNotInstalledError("bwrap")`.
- **At least one real, non-mocked integration test**, run only where `bwrap` is actually available (skipped otherwise via a fixture that checks `shutil.which("bwrap")`), proving the exact behavior already hand-verified in this environment:
  - a write attempt to a path outside the scratch bind fails (no such path exists in the sandbox's view),
  - a write inside the scratch dir succeeds and is visible to the caller after the call returns,
  - a real network call (e.g. to a loopback test server) succeeds, proving `--share-net` didn't accidentally isolate networking.
- Existing `Runner`-protocol tests (`test_sandbox.py`) extended to instantiate `BubblewrapRunner` wherever they currently parametrize over `SubprocessRunner`, so the protocol contract is proven identical between the two.
