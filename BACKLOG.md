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

- [x] Pulled `vulnerables/web-dvwa`, attached to `cism-lab` (`docker run -d
  --name dvwa --network cism-lab vulnerables/web-dvwa`).
- [x] Stable IP confirmed: `172.28.0.3` on `cism-lab`.
- [x] DB created via a scripted GET+POST to `/setup.php` (had to pull the
  CSRF `user_token` out of the GET response first — a blind POST
  redirected without actually creating the DB). Verified by logging in as
  admin/password and seeing the dashboard.
- [x] Security level left at the default ("low" equivalent for this
  image) — findings landed cleanly without extra tuning.
- [x] Smoke-tested manually from a throwaway container on `cism-lab`
  (direct WSL→bridge-IP curl/nmap doesn't route on Docker Desktop — see
  §3.1's note; container→container on the same network works fine).
- [x] Added `172.28.0.3/32` to the engagement scope.
- [x] Ran multiple full CISM engagements against it end-to-end through
  `--live-tools`, both before and after §4.1 added sqlmap/gobuster —
  nmap/nikto/gobuster/sqlmap all executed for real and produced real DEPG
  nodes (see the sample report at the end of §4.2's note below).
- [x] Captured one run's generated report (`/report` output, both .md and
  .json) as the demo artifact — see §4.2.
- [~] **Verify once, at the end:** re-ran it multiple times across the
  session as code changed (effectively the repeatability check), but
  didn't do one dedicated "restart DVWA fresh, re-run, diff the finding
  set" pass as its own final step — worth doing once before an actual
  live demo.

### 1.2 (Stretch) Juice Shop as a secondary target
- [x] §4.1 landed (sqlmap/gobuster), unblocking this.
- [x] Stood up `bkimminich/juice-shop` on `cism-lab`, confirmed at
  `172.28.0.4`; added to engagement scope (`172.28.0.4/32`).
- [~] **Ran one live engagement through llama.cpp** ("run sqlmap against
  the target's login form..."): finished in 10s with zero findings.
  Inconclusive, not a pass: this was run straight from the host shell,
  and a separate check that same session found the host has **no network
  route to `cism-lab`'s containers at all** (direct `curl`/`ping` to a
  `cism-lab` IP from the host got nothing; the identical request from a
  throwaway container on `cism-lab` worked). So a fast, empty result here
  could equally be the model skipping the tool call (a real, separately
  confirmed failure mode — see §4.3) or sqlmap correctly trying and
  failing against a target it genuinely couldn't reach from here. Needs a
  re-run from inside a container actually attached to `cism-lab` (see
  README's "Live lab" section, option 4) before either explanation can be
  trusted.

---

## 2. Activate dormant features (code exists, nothing turns it on)

### 2.1 Wire in graded weighted propagation
- [x] `graph.settle()` now takes `support=GradedSupport()` when requested —
  threaded as a `graded_propagation` flag through
  `make_depg_update_node`/`build_graph`/`LangGraphAgent` (all 3 call sites)
  down to a new `run_agent.py --graded-propagation` CLI flag.
- [x] Import `GradedSupport` from `cism.depg` at the top of `nodes.py`.
- [x] Re-ran the DVWA engagement with `--graded-propagation` on — node
  states/reachability scores looked sane, no flapping observed.
- [x] Decided: **gated behind `--graded-propagation`, default off** — one
  live DVWA pass tonight is the minimum bar per AUDIT.md, not enough to
  flip the project-wide default yet.
- [x] **Verify once, at the end:** ran the existing
  `tests/test_depg_graded_support.py` + `tests/test_depg_graph.py` suites
  to confirm nothing about the wiring change broke the already-passing
  unit tests (the logic itself is already tested — this just confirms
  the new call site didn't typo the wiring).

### 2.2 Live-test the llama.cpp backend
- [x] Used the user's Windows-hosted `llama-server` (lfm2.5-8b-a1b) at
  `http://127.0.0.1:8189/v1`, reachable from containers as
  `host.docker.internal`.
- [x] Ran `run_agent.py --backend llamacpp --base-url ... --live-tools
  --scope 172.28.0.3/32` against DVWA, repeatedly as code changed.
- [x] Confirmed structured extraction worked: DEPG nodes got populated
  with real `cause_class`/evidence from nikto/sqlmap/gobuster output
  through the LLM path. Found and fixed one real fallback: the first
  nikto-sized prompt tripped the 30s timeout (bumped to 90s) — caught
  via the G1 fallback-warning log, which is exactly what that fix was
  for. Also found `run_agent.py --backend llamacpp` built `LLMExtractor`
  with no `logger=`, making that warning silently inert for this
  backend specifically — fixed (see §3.10).
- [x] `discover_context_window_llamacpp` confirmed returning the real
  `n_ctx` from `/props` during these runs, not the 32,768 fallback.
- [x] **Verify once, at the end:** multiple engagement transcripts through
  this backend show real tool calls, real extraction, real phase
  progression — not a unit-test-only claim.

---

## 3. Open bugs / gaps (confirmed still present, 2026-10-11)

### 3.1 D4 — network egress not scoped
- [ ] Get Docker-host root access (this is the actual blocker — nothing
  else here can proceed without it). **Still blocked tonight**: no
  passwordless sudo in this session, and — found while writing the
  runbook — on Docker Desktop the real blocker isn't "root in WSL" at
  all, it's root inside the Docker Desktop VM that actually owns the
  DOCKER-USER chain; a WSL-level sudo wouldn't reach it anyway.
- [x] Wrote `docker/scope-egress.sh` — a runbook script (not run) that adds
  the `DOCKER-USER` rule scoping `cism-egress` to the `cism-lab` subnet +
  a given LLM host:port, with a note on how to actually get root in the
  daemon's netns on Docker Desktop.
- [ ] **Verify once, at the end:** from inside a `cism-runner` container,
  confirm `curl https://1.1.1.1` fails, `curl <llm host>:<port>` succeeds,
  and a live engagement against the DVWA target still completes normally.
  (pending someone with real Docker-daemon-host root running the script)

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
- [x] **Verify once, at the end:** ran `tests/test_langgraph_agent.py` and
  `tests/test_agent_graph.py` — pass (full-suite run: 721 passed, 3 unrelated-
  to-this-fix pre-existing-expectation failures found and fixed separately).

### 3.6 C2 — `allow_raw` fail-open denylist coupling
- [x] Add a test asserting every catalog tool with `allow_raw: true` has a
  matching `_PER_TOOL_DANGEROUS_TOKENS` entry in `dangerous_flags.py`.
- [x] **Verify once, at the end:** passes today (both existing allow_raw
  tools — nmap, curl — already have denylist entries); real value is as a
  regression guard for the *next* allow_raw tool.

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
- [x] **Verify once, at the end:** `docker inspect` on a running container
  no longer shows the real key value — confirmed by running `cism-runner`
  with the key bind-mounted and grepping `Config.Env`: not present.

### 3.8 D7 — `/opt` bound wholesale + curl `file://`
- [x] In `cism/agent/tools/sandbox.py`'s `_RO_BIND_DIRS`, replace `/opt`
  with `/opt/nikto` specifically.
- [x] Add `--proto -all,+http,+https` to curl's `forced_flags` in
  `catalog.yaml` to block `file://`.
- [x] **Verify once, at the end:** nikto ran live against DVWA repeatedly
  tonight (bind narrowing to `/opt/nikto` didn't break its own install
  path — see §1.1/§4.1); `test_curl_catalog_row_builds_argv_...` confirms
  the forced `--proto -all,+http,+https` flag is actually in curl's argv.

### 3.9 E4/E5/E6/E8/E9/E10 — TUI polish batch
Group these — same file (`app.py`/modal widgets), do them in one pass:
- [x] E4: hold a ref to the mounted modal; on `DEPGUpdated`/`MemoryUpdated`,
  diff-update it in place instead of rebuild, preserving cursor position.
  `DEPGModal`/`MemoryModal` both got a `refresh_data()` that re-indexes
  and re-renders the existing screen instance, restoring the cursor by
  node/row id when it's still present after the update.
- [x] E5: give the agent-side queue a `maxsize`; `await asyncio.sleep(0)`
  every N events in the pump; coalesce repeated event types.
  `LangGraphAgent.events` is now `Queue(maxsize=512)`; `pump()` yields
  every 50 applied events and coalesces a queued run of
  `DEPGUpdated`/`MemoryUpdated`/`TokenDelta` (full-snapshot types) down
  to the last one before applying.
- [x] E6: show per-incoming-edge weight (`w=`) in the node label, not just
  the surviving parent's.
- [x] E8: move `/export`'s `write_text` to `asyncio.to_thread`, wrap in
  `try/except OSError`.
- [x] E9: add an `existing_narration()` lookup; no-op the redaction if the
  `entry_id` isn't found.
- [x] E10: move `interrupt` off the `send` worker's exclusive group.
- [x] **Verify once, at the end:** automated instead of manual, like §3.2 —
  new tests cover opening a modal then pushing a second `DEPGUpdated`/
  `MemoryUpdated` while it's open (same screen instance reused, cursor
  preserved when the selected node survives, no crash when it doesn't),
  plus a burst of same-type events collapsing to the last one without
  skipping a different event type sitting in between. Full suite green
  (`pytest -n auto`, 782 passed, 1 pre-existing flaky snapshot). A
  from-scratch E4/E5 fix also surfaced a latent bug in two unrelated
  `test_widgets.py` indicator tests that assumed the pump fully drained
  the demo replay synchronously before the test body ran — no longer
  safe now that the pump yields periodically — fixed by moving them to
  the `quiet_app` (non-autostart) fixture.

### 3.10 H3 — no metrics surface
- [x] Added `tool_calls`/`tool_failures`/`guardrail_blocks`/
  `extraction_fallbacks`/`tokens_total` counters (`cism/agent/core.py`).
  Folded onto the existing `RunFinished` event's own fields rather than
  a second JSONL line — a separate `"RunMetrics"` log line would have
  broken the strict 1:1 event↔log-line invariant two tests assert.
  Also fixed a real bug found along the way: `run_agent.py`'s
  `--backend llamacpp` path built `LLMExtractor` with no `logger=`, so
  the G1 fallback-warning fix was silently inert for that backend
  specifically — the one backend §2.2 exists to test. Fixed
  (`logger=get_agent_logger()`).
- [x] **Verify once, at the end:** live-validated against DVWA through
  the real llama.cpp backend — `RunFinished` carries the populated
  counter fields (confirmed `extraction_fallbacks` actually increments
  and triggered the timeout-bump fix below).

### 3.11 D5 remainder — pip hash-pinning
- [x] Generated a hash-pinned `requirements.txt` via
  `pip-compile --extra=agent --generate-hashes`.
- [x] Switched the Dockerfile's `pip install` to
  `pip install --require-hashes -r requirements.txt`, then
  `pip install --no-deps -e .` for the local package (the two can't
  share one `--require-hashes` invocation — see the Dockerfile comment).
- [x] **Verify once, at the end:** `docker build -t cism-runner -f
  cism-runner.Dockerfile .` succeeded (`Successfully installed
  cism-0.1.0`, image exported, exit 0); confirmed the image still
  imports `cism`/`cism.agent` correctly afterward.

### 3.12 Zero-coverage modules
- [x] Wrote `tests/test_registry.py` (`ToolRegistry.get` raising on unknown).
- [x] Wrote `tests/test_depg_edge.py` (`to_event`); `memory/item.py`'s
  `to_event` was already covered earlier tonight by §3.4's salience tests.
- [x] Wrote `tests/test_dummy_tools.py`.
- [x] **Verify once, at the end:** ran scoped (9 passed); full-suite pass
  folded into the same run as the other items tonight.

---

## 4. Not started (original 5-item list, genuine gaps)

### 4.1 Tool catalog expansion
- [x] Chose `sqlmap` (SQLi coverage) and `gobuster` (directory/endpoint
  discovery nikto only partially covers) — the two highest-value adds
  for the DVWA demo target.
- [x] Added both to `catalog.yaml` (binary, args model, forced flags,
  `allow_raw` decision) following the nmap/curl pattern.
- [x] Added both to `cism-runner.Dockerfile`, version-pinned
  (`sqlmap=1.9.6-1`, `gobuster=3.6.0-1+b10`) per D5's pattern.
- [x] Added `SqlmapExtractor`/`GobusterExtractor` (regex-based) to
  `cism/depg/extractors.py`; gobuster's regex explicitly filters out
  `404` hits rather than trusting gobuster's own filtering.
- [x] Added `_PER_TOOL_DANGEROUS_TOKENS` entries for both in
  `dangerous_flags.py` (§3.6's denylist-coupling guard requires this).
- [x] Phase legality for both declared directly in `catalog.yaml`'s
  `phases:` field (that's where this catalog keeps it, not a separate
  `profiles.py` table) — sqlmap: enumeration/vuln-discovery/exploitation,
  gobuster: whatever `phases_for()` resolves from its own row.
- [x] **Verify once, at the end:** ran live against DVWA — both tools
  executed for real and produced real DEPG nodes.

### 4.2 Report generation
- [x] Scoped the format: both Markdown and JSON (user decision), not
  just one.
- [x] Report pulls from DEPG nodes (resolved findings + evidence), phase
  history, and run metrics — deliberately *not* from the memory store or
  `cism.agent`, to keep `cism/report/` decoupled (phase_history/metrics
  are caller-supplied data, not re-derived from the audit log).
- [x] Built `cism/report/build.py` (`build_report`/`write_report`,
  `PhaseTransition`/`RunMetrics`/`Report` dataclasses) +
  `cism/report/__init__.py`.
- [x] Wired a `/report` slash command in the TUI (`app.py`'s `_report`).
- [x] **Verify once, at the end:** generated a real report from a live
  DVWA run — every resolved DEPG finding appeared with its evidence in
  both the `.md` and `.json` output.

### 4.3 End-to-end inference-swap verification
- [ ] **Blocked for now, not abandoned.** A real second server (local
  Ollama, `gemma4:e4b`) was reachable this session and briefly smoke-tested
  — confirmed its `/v1` endpoint does return real OpenAI-style structured
  tool calls (`chat.completions` → `tool_calls` with correctly-typed JSON
  args), so the integration shape is sound. User then said explicitly:
  don't run Ollama — the real inference server for this project is the
  llama.cpp one at `:8189`. That's a single backend, so the "swappable
  backend" claim is still only proven for llama.cpp (§2.2), same as
  before. Needs either a second real OpenAI-wire server the user
  actually wants used, or explicit sign-off to use Ollama for this one
  verification pass.

---

## 5. Privacy Gateway (new, from Dark-Moon comparison)

### 5.1 Build an inbound/outbound anonymization layer
- [x] Designed the mapping: IPs/hostnames placeholdered, scoped per
  `PrivacyGateway` instance (one per engagement, not global) so mappings
  don't leak across runs. IPv4 regex is lookaround-guarded
  (`(?<!\d\.)...(?!\.\d)`) after a test caught it over-matching a slice
  of a longer dotted run (e.g. version strings).
- [x] Built the swap-in stage: `PrivacyGateway.anonymize()`, applied to
  `tool_output`/prompt content in `make_think_node`'s `_for_model()`
  helper — reuses the existing C1 seam (`tool_output_chain` screens
  content only when building the prompt, never touching the stored
  `ToolMessage.content` that DEPG/audit-log/TUI actually use).
- [x] Built the swap-out stage: `PrivacySwapOutStage`, a new action-chain
  stage that restores real values into tool-call arguments before
  execution — prepended ahead of `ScopeGuardStage`/`DangerousFlagGuardStage`
  when `--anonymize` is set.
- [x] Decided: the operator/TUI always sees real values; only what the
  *model* sees is anonymized (achieved for free by the C1 seam's
  existing separation).
- [x] **Verify once, at the end:** live DVWA engagement with
  `--anonymize` confirmed tool calls against the real IP still succeeded
  while the model-facing prompt only ever contained placeholders.

---

## 6. Dark-Moon-inspired improvements (lower priority / exploratory)

### 6.1 Specialist tool-profile grouping
- [x] Done as part of §4.1: sqlmap/gobuster's phase legality is declared
  via the same `phases:`/capability-default seam the existing 6 tools
  use (`catalog.yaml` + `phases_for()`), not a new grouping mechanism —
  the existing seam already covers this, nothing to retrofit.

### 6.2 Promote `/scope` flags to CLI flags
- [x] Added `--focus`/`--exclude` to `run_agent.py`. Revised after a
  security review caught the first pass: shipping `--exclude` as purely
  *additive* (folding into the allowlist, same as `--focus`) was an
  active footgun — a flag named "exclude" that only ever widens the
  allowlist is the opposite of what an operator would reasonably expect
  from a scope guard. Fixed properly: `EngagementScope` now has a real
  denylist (`excluded_cidrs`/`excluded_domains`, checked first in
  `contains_host`/`contains_network`) and an `.excluding()` method;
  `--exclude` builds a separate `EngagementScope` and folds it into the
  denylist via that method, not into the allowlist string. `--noise` was
  dropped rather than guessed at — no existing relevance/suppression
  concept in this codebase to map it onto.
- [x] **Verify once, at the end:** `tests/test_scope_guard.py` (denylist
  beats allowlist, `.excluding()`/`.add()` behavior) and
  `tests/test_run_agent.py` (`--focus` folds into `--scope`, `--exclude`
  stays separate) — full suite: 748 passed (1 snapshot test regenerated
  for E6's intentional label-text change, not a regression).

### 6.3 Standard benchmark harness
- [x] Scoring method: findings count + time-to-first-finding, against the
  DVWA target from §1.1.
- [x] Built `scripts/benchmark.py` — a standalone headless harness script.
- [x] **Verify once, at the end:** ran twice against an unchanged
  codebase — `findings_count=1` both runs, `time_to_first_finding_s`
  ≈2.9–3.0s both runs. Stable enough to be meaningful.

### 6.4 AI/LLM-endpoint-specific checks
- [ ] **Not started, and can't be done from this repo as written:** no
  Dark-Moon methodology doc exists anywhere in this codebase (checked —
  the only mentions of "Dark-Moon" at all are BACKLOG.md's own section
  headers). This research step needs that source material supplied
  (a link, a file, a pasted excerpt) before it can produce a real list
  instead of a guessed one.

---

## 7. Live-test findings (2026-10-12, real container + real llama.cpp backend)

First engagement actually run through the hardened `docker run` command
(docker/README.md), not `run_agent.py` from a bare host shell — see §3.1's
network note for why that distinction matters. Methodology: 3 scripted
submits (recon → enumerate → sqlmap) against the live `dvwa` container,
`--live-tools`, real `lfm2.5-8b-a1b` at `:8189`, repeated twice.

- [x] Fixed (all live-verified, before/after): GobusterExtractor matched
  zero of 5 real hits (incl. an exposed `setup.php`) because of a raw
  `\r`+ANSI progress indicator defeating its regex; whatweb had no
  extractor at all and degraded to an opaque hash signal; wafw00f
  defaulted to https and failed outright on this http-only target. See
  §3.9-adjacent commit `219c75b` for the fix and `cism/depg/extractors.py`
  for the regression tests built from the actual captured output.
- [x] Fixed: `LangGraphAgent`'s checkpointer now declares
  `allowed_msgpack_modules` — every single checkpoint read/write was
  logging a "will be blocked in a future version" warning for
  Phase/Node/Edge/Evidence/Decision/MemoryItem.
- [ ] **Not fixed, reverted after breaking 6 tests:** attempted a bounded
  "retry once on zero tool calls" to recover the model's live,
  reproducible tendency to answer a tool-offering turn with a text
  question for information already given (e.g. "Please provide the
  target host or IP address") instead of calling a tool — confirmed to
  still happen even after the §3.9-era prompt fix, non-deterministically,
  same prompt/model/target, side by side with a clean 5-tool-call run.
  The attempted fix is unsafe as built: `core.py`'s event-translation
  loop streams every token from *any* `bound.astream()` call made inside
  `think()` straight to the TUI/event bus in real time (via LangGraph's
  own `stream_mode="messages"`), so a discarded first attempt's text
  still leaks into the visible narration and double-counts tokens —
  confirmed by 6 broken tests expecting exactly one narration/TokenDelta
  sequence per turn. A real fix needs `core.py`'s streaming translation to
  know "this attempt is discardable" before any retry can be safe; that's
  its own change, not a `nodes.py`-only one.
- [ ] **Not fixed, newly observed, not yet root-caused:** the same model
  separately called nmap with the literal arg `{'target': '<target>'}` —
  the placeholder token itself, not the real IP — causing a real tool
  call that still produced nothing (nmap: `Failed to resolve "<target>"`).
  Different failure shape than the "asks a question" case above (this one
  *does* call the tool, just with a templated-looking arg); needs its own
  investigation, not assumed to share a cause or a fix with the above.
- [ ] **Not fixed, structural, not yet addressed:** when an early turn's
  tool call produces no usable finding (either failure above), the PTES
  phase never advances past `recon` — so a *later* turn asking explicitly
  for sqlmap (which `catalog.yaml` only offers from `enumeration` onward)
  silently can't get it; the model substituted other recon-phase tools
  instead of calling sqlmap or saying why it couldn't, with no signal to
  the operator that the requested tool was unavailable. Confirmed live:
  this is exactly what happened in the second trial. A visible "phase X
  doesn't offer that tool yet" signal (narration or a guardrail-style
  note) is the likely fix; not attempted tonight.
- [ ] **Verify once, at the end:** two full before/after engagements
  (reports/graphs sent to the user) — the "after" run: 8 resolved
  findings across whatweb/wafw00f/gobuster (0 in the "before" run for
  those same three tools' real output), full suite green throughout
  (786 passed; 3 pre-existing xdist-only snapshot flakes, pass serially).

## 8. Live-test findings, round 2 (2026-10-12, two-host engagement: dvwa + metasploitable2)

Same hardened container, same real `lfm2.5-8b-a1b` backend. Methodology:
6 scripted submits driving nmap/wafw00f/whatweb/curl/sqlmap against `dvwa`
(172.28.0.3) then pivoting to `metasploitable2` (172.28.0.2) for an
nmap/hydra pass — run both through the real `LangGraphAgent` (bypassing
only the Textual render layer) and, separately, with a direct
`hydra.invoke()` bypassing the LLM entirely to isolate sandbox behavior
from model non-determinism.

- [x] **Fixed, live-verified:** `depg_update` stamped every node in a run
  with `state["target"]` (the one host declared at startup) regardless of
  which host a given tool call actually scanned. A second nmap call
  against a different host had all 19 of its open ports mislabeled onto
  the first host. Fixed in `cism/agent/nodes.py` (`_call_target`) —
  confirmed in this round's own DEPG dump: metasploitable2's 19 ports
  now land on `172.28.0.2`, dvwa's on `172.28.0.3`, cleanly separated.
- [x] **Fixed, live-verified:** sqlmap exited immediately with "no
  parameter(s) found for testing" against DVWA's POST login form and
  still reported `ok: true` — a silent no-op. Forced `--forms --crawl=2`
  into `catalog.yaml`'s sqlmap row; re-run shows sqlmap actually crawling
  the form and testing `username`/`password`/`Login` with real
  boolean/error/time-based/UNION techniques, correctly concluding "all
  tested parameters do not appear to be injectable."
- [x] **Fixed, live-verified:** hydra failed outright with a Pydantic
  validation error (missing required `service`) because its description
  didn't make clear the tool only speaks network services, not web
  logins. Docstring rewritten (`credentials.py`) — re-run shows the model
  correctly supplying `service: "ssh"` and a bare host instead of a URL.
- [x] **Fixed, live-verified (separately, by direct `hydra.invoke()`):**
  even with correct arguments, hydra failed with "File for logins not
  found" — `_cred_flag`'s explicit-list branch passed the materialized
  wordlist's absolute *host* scratch path, but `BubblewrapRunner` binds
  that host dir to `/work` and `--chdir`'s into it, so hydra's own cwd is
  `/work`; the host path the file was genuinely written to doesn't exist
  inside the sandbox. Named wordlists never hit this (`/usr/share/wordlists`
  is ro-bound at the same path on both sides). Fixed by passing the bare
  filename. Direct re-test against metasploitable2:22 now gets past
  credential-file loading entirely and reaches a real network attack
  attempt — the remaining failure there (`kex error: no match for method
  server host key algo`) is metasploitable2's SSH server offering only
  `ssh-rsa`/`ssh-dss`, which this container's modern libssh/hydra build
  refuses to negotiate by default. That's a target/tool compatibility gap
  in an 18-year-old intentionally-vulnerable image, not a CISM bug — not
  fixed, not planned, noted here so it isn't mistaken for one later.
- [ ] **Not fixed, newly observed:** phase progression looks too eager
  within a single turn — one turn's wafw00f + whatweb calls advanced the
  phase straight from enumeration to vulnerability-discovery to
  exploitation. Not investigated this round.
- [ ] **Not fixed, newly observed:** asked to "brute force directories,"
  the model called bare `curl` against a guessed `/admin` path instead of
  `gobuster` (the catalog's actual directory-brute-force tool) — a
  tool-selection miss, not a catalog/argv bug. Not investigated this
  round.
- [ ] **Not fixed, newly observed, low severity:** sqlmap was called once
  with a hallucinated `extra: 'service=http'` token — not a real sqlmap
  flag. Appears to have been silently absorbed without breaking the run
  (confirmed: sqlmap still crawled and tested correctly), so left alone.
- [ ] **Verify once, at the end:** targeted suite
  (`test_nodes.py test_tool_catalog_build.py test_credentials.py
  test_depg_extractors.py test_depg_linking.py test_langgraph_agent.py
  test_sandboxed_tool_decorator.py test_toolkit_integration.py`) green
  after each fix; full suite 790/792 (2 pre-existing TUI-snapshot flakes,
  unrelated — diff never touches `cism/tui/`).
