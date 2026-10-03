# Container hardening for cism-runner (AUDIT.md D1)

## What changed
- `cism-runner.Dockerfile`: runs as a non-root user (`cism`, uid 1000) at
  runtime. Everything that needs root (apt installs, the nikto clone,
  `pip install`) still happens as root during the build; only the final
  `ENTRYPOINT` runs unprivileged.
- `docker/seccomp-bwrap.json`: Docker's own default seccomp profile
  (fetched from `github.com/moby/profiles`, unmodified) plus exactly one
  addition — `pivot_root` is allowed under the same `CAP_SYS_ADMIN` gate
  Docker's default already uses for `unshare`/`mount`/`umount2`/`setns`/
  `clone`/`clone3`. Diff from stock `default.json`: +1 syscall name,
  nothing removed, nothing else loosened.

## Why not `seccomp=unconfined`
Docker's default profile (verified by fetching and inspecting the actual
file, 2026-09-22) already allow-lists `unshare`, `mount`, `umount2`,
`umount`, `setns`, `sethostname`, `setdomainname`, `clone`, `clone3` — but
only for a process that holds `CAP_SYS_ADMIN` in the container. Since we
keep `--cap-add=SYS_ADMIN` (see below), bwrap's own `--unshare-user`/
`--unshare-all` namespace setup and its bind-mount calls are already
covered by the *default* profile with that one capability added — no
blanket seccomp bypass is needed for any of that.

The one syscall the default profile blocks unconditionally (it isn't even
capability-gated — it's simply absent from the profile, so it falls to
`defaultAction: SCMP_ACT_ERRNO`) is `pivot_root`, which bubblewrap uses to
switch to its new sandboxed root. That's the one addition in
`docker/seccomp-bwrap.json`.

This was **not** live-tested against a real `docker run` in this session —
no docker daemon was reachable (`docker info` fails, `dockerd` isn't
installed here). It's derived directly from Docker's currently-published
default profile plus bubblewrap's documented use of `pivot_root(2)`, not a
guess. Smoke-test one `nmap` call through `--live-tools` after deploying
this before trusting it (checklist below). If bwrap still fails, `docker
logs` / `dmesg` will show which syscall was denied (an `audit:
... syscall=... exe="bwrap"` line, or bwrap exiting immediately with no
useful stderr, is the seccomp-denial signature) — add that syscall's name
to the same `CAP_SYS_ADMIN`-gated rule in `seccomp-bwrap.json` and re-test.

## Why `SYS_ADMIN` stays
AUDIT.md's original ladder (step 3) suggested trying to drop
`--cap-add=SYS_ADMIN` entirely, reasoning that bwrap's `--unshare-user`
path is the *unprivileged* user-namespace mechanism and might not need it.
Having now inspected Docker's default seccomp profile directly: it doesn't
matter whether the unprivileged-userns kernel mechanism would otherwise
allow it — Docker's default profile seccomp-blocks `unshare` (along with
`mount`/`setns`/`clone3`) for *any* container that lacks `CAP_SYS_ADMIN`,
before the kernel's own namespace-permission logic is ever reached. So
bwrap can't even attempt the unprivileged path inside this container
without the capability. Ladder step 3 (test-drop `SYS_ADMIN`) is dropped
from the plan on this evidence — it isn't a "try it and see," it's a
"Docker's own profile forbids it." Re-open it only if a future
bwrap/container-runtime change removes bwrap's dependence on these
syscalls.

## Hardened `docker run`
Replaces the old `--cap-add=SYS_ADMIN --security-opt seccomp=unconfined
--security-opt systempaths=unconfined`. Run from the repo root (the
`docker/seccomp-bwrap.json` path below is relative to it):

```bash
docker build -t cism-runner -f cism-runner.Dockerfile .

docker run --rm -it \
  --cap-drop=ALL \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=docker/seccomp-bwrap.json \
  --security-opt no-new-privileges \
  --network cism-lab \
  --network cism-egress \
  -e CISM_API_KEY=dummy \
  cism-runner --live-tools --target <target>
```

Notes:
- `--cap-drop=ALL` removes every capability Docker grants by default
  (`NET_RAW`, `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, …) before
  re-adding only `SYS_ADMIN`. None of the dropped ones are needed: nmap
  already runs `-sT -Pn` (TCP connect scan, no raw sockets — see
  `catalog.yaml`'s comment on why), and nothing in this image binds a
  privileged port, changes file ownership, or drops privileges at runtime.
- `systempaths=unconfined` **is still required** — this was wrong in the
  first draft of this doc, corrected after live-testing (below). It's not
  coupled to `seccomp=unconfined`; it's independently needed because
  `cism.agent.tools.sandbox.BubblewrapRunner` invokes bwrap with
  `--disable-userns`, and bwrap's own source
  (bubblewrap.c, `opt_disable_userns` branch, v0.12.0) enforces that by
  opening `/proc/sys/user/max_user_namespaces` `O_WRONLY` and writing `1`
  to it, from inside the user namespace bwrap already unshared into — this
  stops the *sandboxed tool itself* from creating a further nested user
  namespace to try to climb out, it does not touch the host's real value
  (confirmed: host stayed at its original 55875 after the run below).
  Docker's default profile bind-mounts all of `/proc/sys` read-only
  (`readonlyPaths`), which turns that write into `EROFS` and bwrap dies
  before running anything — confirmed live, see the log below.
  `systempaths=unconfined` is the only Docker knob that lifts this; Docker
  has no path-scoped equivalent. The residual exposure from lifting it
  (`/proc/kcore`, `/proc/sysrq-trigger`, etc. becoming reachable again) is
  materially smaller than in the pre-hardening setup, since this container
  is now non-root with every capability dropped except `SYS_ADMIN` —
  `/proc/sysrq-trigger` is root-owned mode 0200 on the host, so uid 1000
  without `DAC_OVERRIDE` still can't write it even with the mount unmasked.
- `--security-opt no-new-privileges` is new and unconditional — nothing in
  this image calls a setuid binary or otherwise needs to gain privileges
  mid-run, so this is free hardening.

## Verification checklist — done, 2026-09-22
Run against a live `metasploitable2` container on `cism-lab` (172.28.0.2),
docker daemon reachable this session:

1. ✅ `docker build -t cism-runner -f cism-runner.Dockerfile .` — succeeds.
2. ✅ `docker run --rm --entrypoint id cism-runner` →
   `uid=1000(cism) gid=1000(cism) groups=1000(cism)`.
3. ✅ `docker image inspect cism-runner --format '{{.Config.User}}'` → `cism`.
4. ✅ `nmap -sT -Pn 172.28.0.2` through a real `BubblewrapRunner` (bypassing
   the LLM loop, calling `run_sandboxed` directly — same code path
   `--live-tools` uses) inside the hardened container: all 17 real open
   ports returned in 0.24s.
5. ✅ `nikto -host http://172.28.0.2 -maxtime 45s` in the same container:
   full finding set in 42s (outdated Apache/PHP, phpinfo leak, directory
   indexing, TRACE/XST, missing security headers, phpMyAdmin exposure).
6. First attempt (without `systempaths=unconfined`) failed exactly as
   predicted for an unrelated-looking reason — `bwrap: cannot open
   /proc/sys/user/max_user_namespaces: Read-only file system` — which is
   what sent us to bwrap's source and produced the corrected note above.
   Confirms the checklist's own troubleshooting step (read `docker logs`/
   the tool's stderr for the exact syscall/path denied, don't guess).

Final hardened command (build + run), copy-paste ready:

```bash
docker build -t cism-runner -f cism-runner.Dockerfile .

docker run --rm -it \
  --cap-drop=ALL \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=docker/seccomp-bwrap.json \
  --security-opt no-new-privileges \
  --security-opt systempaths=unconfined \
  --memory=2g --memory-swap=2g --cpus=2 --pids-limit=512 \
  --network cism-lab \
  --network cism-egress \
  -e CISM_API_KEY=dummy \
  cism-runner --live-tools --target <target>
```

Net change from the original (pre-audit) command: **root → non-root**,
**`seccomp=unconfined` → a 1-syscall diff from Docker's own default
profile**, **added `--memory`/`--cpus`/`--pids-limit`** (D2). `SYS_ADMIN`
and `systempaths=unconfined` stay, both now with a verified, specific
reason instead of "it didn't work without them."

## D2 — resource limits (2026-09-23, live-verified)
`--memory=2g --memory-swap=2g --cpus=2 --pids-limit=512` added to the run
command above. `--ulimit nofile=1024:1024` was considered and left out —
bwrap's own fd usage plus a scanning tool's open connections made a hard
1024 feel likely to nick a legitimate large scan; the other three limits
are what actually bound fork-bomb/OOM risk within the timeout window.
Verified against the live `cism-lab` target (172.28.0.2): a real
`nmap -sT -Pn` (full 17-port result) and a real
`nikto -host ... -maxtime 30s` (full finding set, 26s) both completed
normally through `BubblewrapRunner` with these limits plus every D1 flag
active — nothing starves bwrap's own process/namespace setup.

## D4 — network egress (2026-09-23, investigated, not closed)
Tried AUDIT.md's suggested fix — drop `cism-egress`, keep only `cism-lab`
(`internal:true`), and reach host-Ollama via
`--add-host=host.docker.internal:host-gateway`. **It doesn't work on this
Docker Desktop/WSL2 setup**, confirmed live:
- `host.docker.internal` resolves to an IPv6 address on `cism-lab` that
  doesn't route anywhere.
- The plain bridge gateway IP (`172.28.0.1`) gets `Connection refused` —
  Ollama on the host binds `127.0.0.1:11434` only (`ss -tlnp` confirmed),
  not `0.0.0.0`, so nothing outside the host's own loopback can reach it
  by IP at all.
- On `cism-egress` (non-internal), `host.docker.internal` resolves to
  `192.168.65.254` — Docker Desktop's own WSL2 host-access proxy, which
  only exists on networks with a default route out. `internal:true`
  networks don't get it. There is no plain-bridge-gateway path to a
  loopback-bound host service.

So today's setup only reaches Ollama *because* `cism-egress` grants full
internet egress as a side effect — the guard is the string-based
`ScopeGuardStage` (C3), not the network. Two real fixes were considered:
1. A host-level `DOCKER-USER` iptables rule restricting `cism-egress` to
   the lab subnet + Ollama's host:port. Needs root on the Docker host, not
   available in this session (no passwordless sudo).
2. Run Ollama itself in a container on `cism-lab`, removing the need for
   `cism-egress` entirely. **Ruled out by the user (2026-09-23): don't
   containerize Ollama.**

So (1) is the only path left, and it needs a person with Docker-host root
to add the `DOCKER-USER` rule. Until then, `cism-egress` stays attached and
`ScopeGuardStage` is the only thing keeping tool calls in-scope — that's
the accepted risk, not an oversight.

Left open pending that decision.

## D5 — supply chain (2026-09-23, live-verified)
`cism-runner.Dockerfile`: nikto pinned to the `2.6.1` tag with a build-time
assertion against its dereferenced commit SHA
(`d201dac320fc5187eac75e723dd07a716196ec5a`); every apt package pinned to
its exact `python:3.12-slim` candidate version as of this date. `docker
build` succeeding proves the SHA assertion passed; `dpkg -s` inside the
built image confirms every package landed at its pinned version, and
`nikto -Version` reports `2.6.1`. Pip hash-pinning left undone (P2 — needs
new lockfile tooling).
