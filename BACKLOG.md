# CISM backlog

Split from the 2026-10-11 review of AUDIT.md + the Dark-Moon comparison.
Each item is a standalone task, broken into the concrete sub-steps needed
to actually finish it. Status markers: `[ ]` not started, `[~]` partially
built (see note), `[x]` done.

## Working policy (2026-10-11)

**Do not test after every small change.** Write/implement a full module
end-to-end first, then run its test pass once at the end — not a
test-edit-test-edit loop per function. This applies to every task below:
each one lists its implementation steps first and a single verification
step last. Only exception: a change made specifically *because* a test
caught a regression (fix-verify is one step, not a new loop).

---

## 1. Demo readiness (do first)

### 1.1 Stand up DVWA on `cism-lab`
Chosen over Metasploitable2/Juice Shop: maps directly to OWASP Top 10
categories (item 1's framing) and is the one target the current 6-tool
catalog (nmap/curl/nikto/whatweb/dnsenum/hydra) can produce real findings
against — a classic PHP/MySQL stack, not a modern SPA that needs
sqlmap/browser automation to say anything interesting.

- [ ] Pull the image: `docker pull vulnerables/web-dvwa`.
- [ ] Attach it to the existing `cism-lab` network (same pattern the
  Metasploitable2 container already uses — `docker network inspect
  cism-lab` first to confirm the subnet/gateway, then `docker run -d
  --name dvwa --network cism-lab vulnerables/web-dvwa`).
- [ ] Confirm it has a stable IP on `cism-lab` (`docker inspect dvwa
  --format '{{.NetworkSettings.Networks.cism-lab.IPAddress}}'`) — note it
  down, this is `<target>` in every command below.
- [ ] One-time DVWA setup: browse to `http://<target>/setup.php` and click
  "Create / Reset Database" (DVWA ships with no DB until this runs once).
- [ ] Set DVWA's security level to "low" for the first demo pass
  (`DVWA Security` tab in its own UI, or seed `security = low` directly in
  its config/session) — low is what makes nikto/hydra findings land
  cleanly; raise it later once the demo path is proven.
- [ ] Smoke-test manually, outside the agent, before running CISM against
  it: `curl -I http://<target>/`, `nmap -sT -Pn <target>`, `nikto -host
  http://<target> -maxtime 45s` from the host or an existing
  `cism-runner` shell. Confirm each returns real output (open port 80,
  DVWA's banner, nikto's finding list) before trusting the agent run.
- [ ] Add `<target>` to the engagement scope: `--scope <target-ip>/32` (or
  via `/scope add` in the TUI) so `ScopeGuardStage` doesn't block it.
- [ ] Run one full CISM engagement against it end-to-end
  (`run_agent.py --live-tools --scope <target-ip>/32 --target <target>`)
  and confirm the full phase progression actually happens: RECON (nmap
  finds port 80) → ENUMERATION (whatweb/dnsenum) → VULN (nikto findings
  resolve a node) → EXPLOITATION (hydra against DVWA's login form) →
  REPORTING. This is the first real end-to-end test of the DEPG-driven
  phase router (B1) against a target it wasn't validated on before.
- [ ] Capture the DEPG modal + transcript from that run as the demo's
  visual — this is what gets shown live, don't rely on improvising the
  TUI during the demo itself.
- [ ] **Verify once, at the end:** re-run the full engagement from a clean
  container (`docker restart dvwa` to reset state) and confirm it
  reproduces the same finding set — a demo that only worked once isn't a
  demo you can run live.

### 1.2 (Stretch) Juice Shop as a secondary target
- [ ] Only pick this up after §4.1 (tool catalog expansion) adds something
  that can actually test a JS-driven SPA (sqlmap at minimum). Not worth
  standing up before that — today's toolset returns near-empty results
  against it, confirmed by reasoning about what nikto/whatweb actually
  check for (server-side misconfig, not client-side app logic).

---

## 2. Activate dormant features (code exists, nothing turns it on)

### 2.1 Wire in graded weighted propagation
- [ ] In `cism/agent/nodes.py:387`, change `graph.settle()` to
  `graph.settle(support=GradedSupport())`.
- [ ] Import `GradedSupport` from `cism.depg` at the top of `nodes.py`.
- [ ] Re-run the DVWA engagement from §1.1 with this change in and confirm
  the DEPG modal's node states/reachability scores look sane (no node
  stuck at a nonsensical score, no state flapping between calls).
- [ ] Decide whether to keep this as the new default or gate it behind a
  flag (`--graded-propagation`) until you're confident in a few more runs
  — AUDIT.md's own condition was "validated against a real run," so one
  DVWA pass is the minimum bar, not the finish line.
- [ ] **Verify once, at the end:** run the existing
  `tests/test_depg_graded_support.py` + `tests/test_depg_graph.py` suites
  to confirm nothing about the wiring change broke the already-passing
  unit tests (the logic itself is already tested — this just confirms
  the new call site didn't typo the wiring).

### 2.2 Live-test the llama.cpp backend
- [ ] Stand up a llama.cpp server with `--api` enabled, serving any model
  CISM can reach from the container network.
- [ ] Run `run_agent.py --backend llamacpp --base-url <llama.cpp endpoint>
  --live-tools --scope <target>` against the DVWA target.
- [ ] Confirm structured extraction actually works: check that DEPG nodes
  get populated with real `cause_class`/evidence from the LLM-extracted
  tools (nikto/whatweb/dnsenum), not falling back to `GenericExtractor`
  silently (G1's fix made this fallback log instead of swallow — check
  the JSONL log for that fallback warning; its absence is the pass
  condition).
- [ ] Confirm `discover_context_window_llamacpp` actually returns a real
  `n_ctx` from `/props` instead of falling back to the 32,768 default.
- [ ] **Verify once, at the end:** one full engagement transcript showing
  real tool calls, real extraction, real phase progression through this
  backend — that transcript is the proof this item is done, not a unit
  test.

---

## 3. Open bugs / gaps (confirmed still present, 2026-10-11)

### 3.1 D4 — network egress not scoped
- [ ] Get Docker-host root access (this is the actual blocker — nothing
  else here can proceed without it).
- [ ] Add a `DOCKER-USER` iptables rule scoping `cism-egress`'s egress to
  the `cism-lab` subnet + Ollama's host:port only, dropping everything
  else.
- [ ] **Verify once, at the end:** from inside a `cism-runner` container,
  confirm `curl https://1.1.1.1` fails, `curl <ollama host>:11434`
  succeeds, and a live engagement against the DVWA target still completes
  normally.

### 3.2 E7 — modal double-stacking
- [x] In `cism/tui/app.py`, add `if len(self.screen_stack) > 1: return` as
  the first line of both `action_show_depg` and `action_show_memory`.
- [x] **Verify once, at the end:** automated instead of manual — added
  `test_ctrl_d_twice_in_a_row_pushes_only_one_modal`/`..._ctrl_m...` to
  `tests/test_app.py`; full `test_app.py` run (41 tests) passes.

### 3.3 A5 — IPv6 normalize bug
- [x] In `cism/depg/normalize.py`, guard the `rpartition(":")` branch:
  only strip a trailing port if `value.count(":") == 1` (a single colon
  means `host:port`, not an IPv6 literal); add a bracketed-IPv6 case
  (`[::1]:80` → strip the bracket + port, keep `::1`).
- [x] **Verify once, at the end:** ran the existing normalize tests plus
  new cases for `::1`, `[::1]:80`, `fe80::1`, `[::1]` (no port) — all pass.

### 3.4 A4 — memory salience is a constant
- [x] In `cism/memory/item.py`/`cism/memory/store.py`, map `source_type` →
  a base salience value at `upsert` time instead of hardcoding
  `_BASE_SALIENCE`. Vocabulary: `depg_node` (1.2), `tool-failure`/
  `phase-change` (1.0), `narration` (0.8), unknown falls back to 1.0.
- [x] Store that derived value on `MemoryItem`; have `to_event` emit it.
- [x] **Verify once, at the end:** ran `tests/test_memory_store.py` +
  `tests/test_nodes.py` — pass.

### 3.5 B4 — dual `PhaseStateMachine` desync risk
- [x] In `core.py`'s `_translate`, replace the `self._phase.transition(...)`
  mirror call with a direct `self._phase.current = new_phase` assignment
  (the graph node already validated legality).
- [x] Keep `transition()` only for the user-driven `/phase` command path.
- [ ] **Verify once, at the end:** run `tests/test_langgraph_agent.py` and
  `tests/test_agent_graph.py`. (pending batch test pass)

### 3.6 C2 — `allow_raw` fail-open denylist coupling
- [x] Add a test asserting every catalog tool with `allow_raw: true` has a
  matching `_PER_TOOL_DANGEROUS_TOKENS` entry in `dangerous_flags.py`.
- [ ] **Verify once, at the end:** passes today (both existing allow_raw
  tools — nmap, curl — already have denylist entries); real value is as a
  regression guard for the *next* allow_raw tool. (pending batch test pass)

### 3.7 D6 — API key visible via `docker inspect`
- [x] Added `run_agent.py --key-file <path>` (reads the key from a mounted
  file into the env var at startup) instead of `--env-file` — confirmed
  `--env-file` would *not* actually fix this (Docker puts `--env-file`
  values into `Config.Env` exactly like `-e`, so `docker inspect` would
  still show them); a bind-mounted secret file is the only thing that
  keeps the real value out of `Config.Env`.
- [x] Updated `docker/README.md`'s run commands to `-v
  /tmp/cism_api_key:/run/secrets/cism_api_key:ro` + `--key-file
  /run/secrets/cism_api_key`, with a note explaining why.
- [ ] **Verify once, at the end:** `docker inspect` on a running container
  no longer shows the real key value. (pending live docker run tonight)

### 3.8 D7 — `/opt` bound wholesale + curl `file://`
- [x] In `cism/agent/tools/sandbox.py`'s `_RO_BIND_DIRS`, replace `/opt`
  with `/opt/nikto` specifically.
- [x] Add `--proto -all,+http,+https` to curl's `forced_flags` in
  `catalog.yaml` to block `file://`.
- [ ] **Verify once, at the end:** a live nikto run still works (bind
  narrowing didn't break its own install path); `curl file:///etc/passwd`
  through the tool now fails. (pending live DVWA run tonight)

### 3.9 E4/E5/E6/E8/E9/E10 — TUI polish batch
Group these — same file (`app.py`/modal widgets), do them in one pass:
- [ ] E4: hold a ref to the mounted modal; on `DEPGUpdated`/`MemoryUpdated`,
  diff-update it in place instead of rebuild, preserving cursor position.
- [ ] E5: give the agent-side queue a `maxsize`; `await asyncio.sleep(0)`
  every N events in the pump; coalesce repeated event types.
- [ ] E6: show per-incoming-edge weight (`w=`) in the node label, not just
  the surviving parent's.
- [ ] E8: move `/export`'s `write_text` to `asyncio.to_thread`, wrap in
  `try/except OSError`.
- [ ] E9: add an `existing_narration()` lookup; no-op the redaction if the
  `entry_id` isn't found.
- [ ] E10: move `interrupt` off the `send` worker's exclusive group.
- [ ] **Verify once, at the end:** one full TUI session exercising all six
  paths (open/close modals repeatedly during a run, trigger `/export`,
  double-submit, redact after entry removal) — single pass, not six.

### 3.10 H3 — no metrics surface
- [x] Added `tool_calls`/`tool_failures`/`guardrail_blocks`/
  `extraction_fallbacks`/`tokens_total` counters, logged as one
  `"RunMetrics"` JSONL line per run (`cism/agent/core.py`). Also fixed a
  real bug found along the way: `run_agent.py`'s `--backend llamacpp` path
  built `LLMExtractor` with no `logger=`, so the G1 fallback-warning fix
  was silently inert for that backend specifically — the one backend
  §2.2 exists to test. Fixed (`logger=get_agent_logger()`).
- [ ] **Verify once, at the end:** grep a run's log for the new counter
  fields. (pending live run tonight)

### 3.11 D5 remainder — pip hash-pinning
- [ ] Generate a hash-pinned `requirements.txt` via `pip-compile` or `uv`.
- [ ] Switch the Dockerfile's `pip install` to `pip install --require-hashes`.
- [ ] **Verify once, at the end:** `docker build` succeeds with the pinned
  lockfile.

### 3.12 Zero-coverage modules
- [ ] Write `tests/test_registry.py` (`ToolRegistry.get` raising on unknown).
- [ ] Write tests for `depg/edge.py` (`to_event`) and `memory/item.py`
  (`to_event`).
- [ ] Write tests for `tools/dummy.py`.
- [ ] **Verify once, at the end:** run the full suite once, not per file.

---

## 4. Not started (original 5-item list, genuine gaps)

### 4.1 Tool catalog expansion
- [ ] Decide the next 3-5 tools by target-type gap, not arbitrarily — given
  DVWA is the near-term demo target, `sqlmap` (SQLi module coverage) and
  `gobuster`/`ffuf` (directory/endpoint discovery, which nikto only
  partially covers) are the highest-value adds.
- [ ] For each: add a `catalog.yaml` entry (binary name, args model, forced
  flags, `allow_raw` decision) following the existing nmap/curl pattern.
- [ ] Add it to `cism-runner.Dockerfile`'s apt/build step, version-pinned
  per D5's existing pattern (exact version, not HEAD/latest).
- [ ] Add a `CauseExtractor` for its output format (regex-based if the
  output has a stable grammar, like nmap/hydra; LLM-extracted fallback
  otherwise) in `cism/depg/extractors.py`.
- [ ] Add it to the relevant `PhaseProfile`(s) in `profiles.py` so phase
  legality covers it.
- [ ] **Verify once, at the end:** one full engagement against DVWA with
  all new tools in the catalog, confirming each gets called and produces
  a DEPG node — single end-to-end pass per batch of tools added, not one
  test cycle per tool.

### 4.2 Report generation
- [ ] Scope the format first (Markdown export vs. structured JSON vs.
  both) — this is a design decision, not an implementation detail; decide
  before writing code.
- [ ] Define what a report pulls from: DEPG nodes (resolved findings +
  evidence), memory store (narrative context), phase history.
- [ ] Build a `cism/report/` module: one function that walks the final
  DEPG + memory state and emits the chosen format.
- [ ] Wire a `/report` slash command or a `REPORTING`-phase action that
  triggers it.
- [ ] **Verify once, at the end:** generate a report from the DVWA demo
  run and confirm every resolved DEPG finding appears with its evidence
  — one full report against one full run, not a test per section.

### 4.3 End-to-end inference-swap verification
- [ ] Pick a second real backend beyond llama.cpp (e.g. a different
  OpenAI-wire provider, or Ollama directly via `OpenAIBackend`).
- [ ] Run one full engagement through it.
- [ ] **Verify once, at the end:** confirm tool-calling, structured
  extraction, and context-window discovery all work on this second
  backend too — this is the actual "swappable backend" claim being
  proven, not assumed from the one llama.cpp pass in §2.2.

---

## 5. Privacy Gateway (new, from Dark-Moon comparison)

### 5.1 Build an inbound/outbound anonymization layer
- [ ] Design the mapping: what gets placeholdered (IPs, hostnames, creds)
  and the identifier scheme (`<ip-1>`, `<host-1>`, etc.), scoped per-run
  so mappings don't leak across engagements.
- [ ] Build the swap-in stage: before tool output/prompt reaches the
  model, replace real values with placeholders. Likely slots into the
  existing `tool_output` guardrail chain seam (C1) as a new stage, or a
  stage ahead of it.
- [ ] Build the swap-out stage: before a tool call's arguments are
  actually executed, restore placeholders back to real values. This is
  the symmetric half — without it the agent can reason about targets but
  can never actually call a tool against them.
- [ ] Decide what happens to already-displayed TUI content (does the
  operator see placeholders or real values? likely real — this gateway
  protects what the *model* sees, not the operator).
- [ ] **Verify once, at the end:** one full DVWA engagement showing the
  model's prompt/transcript only ever containing placeholders for the
  target's real IP, while tool calls against the real DVWA IP still
  succeed — single end-to-end run proves both halves work together.

---

## 6. Dark-Moon-inspired improvements (lower priority / exploratory)

### 6.1 Specialist tool-profile grouping
- [ ] Do this *as part of* §4.1's catalog growth, not as a separate pass —
  group new tools by domain (web/network/credential) reusing the
  existing `PhaseProfile` seam, rather than retrofitting the current 6
  tools into groups first.

### 6.2 Promote `/scope` flags to CLI flags
- [ ] Add `--focus`/`--exclude`/`--noise` flags to `run_agent.py` that map
  onto the existing `parse_scope`/`EngagementScope` machinery already
  backing `/scope`.
- [ ] **Verify once, at the end:** one run using each new flag, confirming
  it produces the same `EngagementScope` state as the equivalent
  `/scope add` command would.

### 6.3 Standard benchmark harness
- [ ] Pick a fixed scoring method (findings count, time-to-first-finding,
  phase-completion time) against the DVWA target from §1.1.
- [ ] Build a small script that runs a full engagement and reports those
  numbers from the resulting DEPG/log.
- [ ] **Verify once, at the end:** run it twice against an unchanged
  codebase and confirm the numbers are stable enough to be meaningful
  before using it to judge any future change.

### 6.4 AI/LLM-endpoint-specific checks
- [ ] Research-only for now: review what Dark-Moon's methodology docs
  actually check for against AI/LLM endpoints, and note which of those
  apply to CISM's own LLM-out bridge (D4). No implementation until the
  research step produces a concrete list.
