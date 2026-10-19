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
- [x] **Fixed (2026-10-17):** the retry now streams live exactly as
  before (no buffering, no "eat every normal reply's streaming" repeat
  of the earlier mistake) and retracts after the fact if discarded.
  `nodes.py`'s `think()` tags only the opening move's first attempt
  retriable; `core.py`'s `_run()` tracks it, and if a retry starts
  streaming for `think()` while a retriable attempt was still open, it
  truncates the leaked narration and emits a corrective negative
  `TokenDelta` — new `NarrationRetracted` event, same precedent as the
  existing `NarrationRedacted`. The retry trigger itself widened: beyond
  the already-landed truly-empty case, it now also fires when the
  response asks for the target when it's already been given
  (`_is_asking_for_known_target`, a narrow regex gated on the target
  being set — doesn't fire on a legitimate text reply like a greeting).
  All existing streaming/token tests pass unmodified (confirms the happy
  path truly didn't change); new tests cover the retried case.
- [x] **Fixed (2026-10-17):** two parts. `_FALLBACK_HINT`'s abstract
  `<tool>` placeholder template was replaced with a concrete example —
  but a live re-test immediately surfaced that this wasn't the real fix:
  the model started parroting *that* literal example value (`10.0.0.5`)
  into real nmap/sqlmap/whatweb calls instead of the actual configured
  target, caught only by ScopeGuardStage (it was outside the declared
  scope). Real fix: `_fallback_hint(target)` now interpolates the actual
  configured target into its own example, so parroting it is harmless.
  Confirmed live, 3 clean re-runs (15 turns total) against DVWA: every
  tool call used the real target, zero scope-guard rejections. Second,
  independent part: the args model now rejects a placeholder-shaped
  target (`<`/`>`/`{`/`}`) outright via a pydantic validator, and
  `ScopeGuardStage`'s `_candidate_hosts` fails closed instead of open on
  an unparseable value on a tool with a known target-arg mapping (it
  already had this pattern for a sibling CIDR case, just not applied
  here) — defense in depth beyond the specific placeholder string.
- [x] **Fixed (2026-10-17):** `act()` now surfaces `PhaseToolGuardStage`'s
  real reason (e.g. `"'sqlmap' [capability=executes] is not offered in
  phase recon"`) as the blocked call's actual message content, instead of
  the generic "blocked by action guardrail" every other guardrail stage
  still gets — carved out specifically for this one stage since which
  tools are offered when isn't secret the way a scope/flag rule is (the
  existing security test guarding the generic message for other stages
  is untouched and still passes). Not independently live-forced this
  round — the model declined directly in text both times it was asked,
  without ever attempting the blocked call — so this is verified via a
  dedicated unit test (`test_act_surfaces_the_real_reason_when_phase_
  tool_guard_blocks_a_call`) rather than a live trigger.
- [x] **Verify once, at the end:** targeted suite green after each fix
  (`test_langgraph_agent.py test_nodes.py test_scope_guard.py
  test_tool_catalog_build.py test_sandboxed_tool_decorator.py`), full
  suite 816 passed. Live: 3 full fresh engagements (15 turns) against
  DVWA through the real llama.cpp backend inside the hardened container —
  nmap/sqlmap/whatweb all executed for real against the correct target
  every time, zero crashes, zero `NarrationRetracted` events (the
  retry/retraction path didn't need to fire this round — non-
  deterministic, consistent with how it was originally found).
  Original two-run before/after comparison from this round's first pass
  (prior to the DEPG-context work in §10): 8 resolved findings across
  whatweb/wafw00f/gobuster (0 before), full suite green throughout (786
  passed; 3 pre-existing xdist-only snapshot flakes, pass serially).

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
  in an 18-year-old intentionally-vulnerable image, not a CISM bug.
- [x] **Fixed (2026-10-17), on request:** the kex-algo gap just above
  recurred verbatim in a fresh live re-test, user asked for it to be
  addressed properly. `cism-runner.Dockerfile` now writes a global
  `/etc/ssh/ssh_config` with `HostKeyAlgorithms`/`KexAlgorithms`/`MACs`/
  `Ciphers` all `+`-appended (never replacing libssh's own defaults, so a
  modern target still negotiates modern algorithms first) — confirmed by
  iterating live against metasploitable2:22 directly (bare `docker run`,
  not yet sandboxed) that host-key-algo alone wasn't enough: fixing it
  just exposed the *next* mismatch, a legacy MAC algo, which needed its
  own addition. `cism/agent/tools/sandbox.py`'s `BubblewrapRunner.
  _RO_BIND_ETC` now ro-binds this file in too — without it the image has
  the file but bwrap's sandboxed hydra process never sees it (confirmed:
  the fix verified bare-`docker run` first, then separately through the
  real `BubblewrapRunner` + `hydra.invoke()` path, non-root, inside the
  hardened container — negotiation succeeds both ways, 0 valid password
  found against the wrong username used in that test, not a negotiation
  failure).
- [x] **Investigated (2026-10-12, `e916f9a`) and deliberately left alone —
  revisited and reconfirmed (2026-10-17), still correct, not re-fixed:**
  phase progression looks too eager within a single turn — one turn's
  wafw00f + whatweb calls advanced the phase straight from enumeration to
  vulnerability-discovery to exploitation. A cap of one phase-advance per
  user submission was built and tested in `e916f9a`'s branch, then
  reverted in that same commit after `tests/test_langgraph_agent.py`
  showed the dummy demo flow itself relies on exactly two phase changes in
  one submit — not a bug, a deliberate product decision made the night
  before a demo. 2026-10-17: re-implemented this exact cap from scratch
  without having read this note first, re-discovered the same test
  failure, reverted again. **If this keeps surfacing, the test itself
  (not the cap) is probably what needs revisiting — but that's a product
  call, not one to make unilaterally again.**
- [x] **Fixed (`e916f9a`):** asked to "brute force directories," the model
  called bare `curl` against a guessed `/admin` path instead of `gobuster`
  (the catalog's actual directory-brute-force tool) — a tool-selection
  miss, not a catalog/argv bug. curl's description now explicitly says
  it's for one known URL, not directory discovery, and points to gobuster
  for that.
- [x] **Fixed (`e916f9a`):** sqlmap was called once with a hallucinated
  `extra: 'service=http'` token — not a real sqlmap flag. The `extra`
  field every `allow_raw` tool exposes had no description at all; added a
  concrete description with real examples so the model stops guessing.
- [ ] **Verify once, at the end:** targeted suite
  (`test_nodes.py test_tool_catalog_build.py test_credentials.py
  test_depg_extractors.py test_depg_linking.py test_langgraph_agent.py
  test_sandboxed_tool_decorator.py test_toolkit_integration.py`) green
  after each fix; full suite 790/792 (2 pre-existing TUI-snapshot flakes,
  unrelated — diff never touches `cism/tui/`).

## 9. `wip-overeager-tool-calls` branch — all three fixes landed (2026-10-14)

- [x] **Fixed, live-verified:** `--max-tokens` below 512 silently truncated
  a reasoning model's hidden thinking tokens before any tool call or
  content was emitted — looked identical to "model chose not to act" from
  the outside. Hard floor added in `run_agent.py`/`scripts/benchmark.py`.
- [x] **Fixed, live-verified (5/5 trials):** every phase prompt in
  `profiles.py` is an unconditional standing order ("map hosts...", etc.)
  with nothing conditioning it on the user's message, so a bare "HI"
  triggered a full scan. Fixed with `_ACT_ONLY_WHEN_ASKED`, prepended to
  every phase's system prompt — greetings/status questions now get a
  plain-text reply, real requests still trigger tools.
- [x] **Fixed, live-verified:** separately from the max-tokens case, the
  model sometimes still produces a genuinely empty opening move (no tool
  call, no text) even with a healthy token budget — real reasoning-model
  flakiness, not truncation. `think()` now retries once, but only when
  the attempt is truly empty (no tool call AND no text after stripping);
  a deliberate text answer (e.g. the greeting case above) is never
  second-guessed. An earlier version of this fix tagged the first
  attempt's stream as "discardable" and suppressed its live narration in
  `core.py` — dropped after it silently ate every normal reply's live
  streaming; proved unnecessary anyway, since an attempt that triggers
  the retry produced zero content chunks in the first place (message-
  chunk content only ever concatenates, never erases), so there was
  nothing to suppress. `state.py`/`core.py` are back to exactly their
  pre-branch content; the whole fix now lives in `nodes.py` alone.

## 10. Extensive live testing round (2026-10-14, containerized, real model + real lab)

Driven through the real `CISMApp` + `LangGraphAgent` via Textual's pilot —
same code path the interactive TUI uses, not a scripted shortcut — against
Metasploitable2 (172.28.0.2) and DVWA (172.28.0.3), live tools, real bwrap
sandbox, real model.

- [x] **Fixed, live-verified (the main one):** `think()` never read
  `depg_nodes`/`memory_items` — the model's only memory was raw chat
  history, which `_compact_history` drops wholesale (just a bare "[N
  turns omitted]" note) once the context window fills. Added a per-target
  DEPG findings block and a narrative-memory block to the system prompt
  every turn, rebuilt fresh from state, independent of history
  compaction. Live-verified: forced `context_window` to 1200, scanned a
  real host, sent filler turns until 10 earlier turns were dropped from
  raw history, then asked "what ports did we find again" — answered
  correctly, visibly quoting the DEPG block's own "+N more" cap notation.
- [x] **Fixed, live-verified:** gobuster's model-facing description
  didn't mention a wordlist is already forced — live run added a
  gratuitous, wrong `extra: '-e <path>'` (a boolean flag in gobuster's
  dir mode, not a wordlist flag) pointing at a file that doesn't exist,
  causing a real `exited 1`. Same hallucinated-`extra` pattern as the
  earlier sqlmap fix. Fixed by naming the forced wordlist in the
  description and telling the model not to add its own.
- [x] **Confirmed working, not a bug:** manual `/phase` override. Legal
  transition (`/phase enumeration` from RECON) succeeds; illegal
  (`/phase exploitation` from RECON) is correctly refused. If this reads
  as "can't control the phase," it's a discoverability/UX gap, not a
  functional one.
- [x] **Confirmed working, not a bug:** per-call target attribution.
  Mid-engagement question about a different host than the configured
  target correctly ran `sqlmap` against that host, not the default.
- [x] **Fixed (2026-10-17), live-verified (0/3 tool calls after the fix,
  vs. multiple real tool calls per turn before it):** a plain
  acknowledgment ("ok, noted" — not a request) triggered an unprompted
  `nikto` call — an `_ACT_ONLY_WHEN_ASKED` miss distinct from the
  plain-greeting case that rule already handled correctly. First attempt
  (broadening `_ACT_ONLY_WHEN_ASKED`'s wording to explicitly name "ok",
  "noted", "got it", "thanks" as examples) was **not enough** —
  live-tested mid-engagement (a real finding already on the board) and
  the model still called tools on all 3/3 repeated "ok, noted" turns
  (`nmap`/`hydra`/`curl`, once caught by `dangerous-flag-guard`). Reading
  `nodes.py`'s system-prompt assembly order explains why: `_ACT_ONLY_
  WHEN_ASKED` is prepended *before* the DEPG findings block and the
  phase's own standing order ("start with nmap against the target..."),
  so on a small model the later, more concrete text apparently wins over
  the earlier rule — a wording-only fix can't reliably out-compete that.
  **Real fix is structural, not prompt-only:** `think()` now detects an
  exact-match plain acknowledgment (`_is_plain_acknowledgment` —
  "ok"/"noted"/"got it"/etc., the *whole* message, never a substring, so
  "ok, run nikto" is unaffected) and binds **zero tools** for that turn,
  which also disables the `TOOL_CALL:` text-fallback parser
  (`_parse_text_tool_call`, gated on `phase_tools` being non-empty) — so
  neither path the model has for producing a tool call is available,
  regardless of what the prompt text says. Live-verified against the real
  `lfm2.5-8b-a1b` backend mid-engagement on `dvwa`: the model still
  visibly *tried* to call a tool (once via its own non-standard
  `<|tool_call_start|>...<|tool_call_end|>` text format), but with no
  tools bound it just streamed as inert narration — 0 real tool calls
  across all 3 repeated turns.
- Test-harness lesson (not a product bug): driving the real agent via
  `agent.events.join()` to detect "turn finished" is wrong for a slow
  real model — the queue can drain momentarily mid-run and the next
  submit() cancels the one in flight ("superseded by new submission").
  Poll `agent._task.done()` instead when scripting a multi-turn session
  against a real backend.
- Sandbox lesson (not a product bug): a quick test container without the
  README's documented `--cap-add=SYS_ADMIN`/seccomp/no-new-privileges
  flags makes every real tool call fail identically with "bwrap: No
  permissions to create a new namespace" — looks like a tool/product bug
  until you check the container's own flags against `docker/README.md`.
- Docs fixed (`ac468a6`): README claimed guardrails' input/output seams
  are "still pass-through" (false once `--live-tools` is used) and that
  `generality`/`downstream` are "not yet computed" (false —
  `Graph.compute_metrics()` already fills both, DEPG modal renders real
  values). Test count and tool-catalog count were stale too.

## 11. Live testing round 12 (2026-10-17, full re-run after §10's fixes)

A fresh 13-turn engagement through the real `LangGraphAgent` + real
`lfm2.5-8b-a1b` backend + real sandboxed tools, driving dvwa then
pivoting to metasploitable2, deliberately re-exercising every fix landed
in §7-§10 plus a few scenarios no prior round's script covered (a
phase-gated tool requested before it's offered, a status question
mid-engagement, acknowledgments at three different points in one
engagement). Regression check first, new findings second.

**Regression check — all still holding:**
- #1 (retry+retraction), #2 (placeholder-target rejection), the
  Metasploitable2 SSH/hydra kex fix, and the structural "ok, noted" fix
  (zero tools bound) all confirmed working live, unchanged from §10.
  Every "ok, noted"/"thanks"/"got it" turn produced **0 real tool calls**
  across both this round and the follow-up round below.
- #3 (phase-gate reason surfacing): asking for `sqlmap` while still in
  `recon` (it isn't offered in that phase yet) got a clear "I don't have
  the ability to run sqlmap... would you like an nmap scan instead?" —
  not a generic blocked-call message.

**New findings, fixed and live-verified this round:**
- [x] **Context-overflow 400, mid-engagement:** two consecutive turns
  near the end of the 13-turn run failed outright —
  `request (17245 tokens) exceeds the available context size (16384
  tokens)` — despite `_compact_history`'s own budget estimate saying it
  fit. Root cause: `_CHARS_PER_TOKEN = 4` is a flat heuristic tuned
  against average English prose; several turns of markdown-heavy model
  output (bullets, bold, backticks) tokenize less efficiently than that,
  so the estimate quietly ran ~8-9% low. Tightened to `3`, deliberately
  biased toward compacting one turn earlier than strictly necessary
  (cheap — the DEPG/memory context block already covers what's lost)
  over a real mid-engagement 400 (a whole turn lost outright). Re-ran the
  same engagement shape afterward: no overflow, including at the exact
  turn that failed before.
- [x] **hydra `service="web"` — real exit-255 instead of actionable
  feedback:** asked to "brute force SSH credentials" earlier in the
  engagement, then later asked to attack the web login, the model reused
  `hydra` with `service: "web"` — satisfies the required-field check
  (unlike the earlier, already-fixed "no service at all" bug) but isn't
  a real hydra module name, so hydra itself exited 255 with a raw usage
  error. The tool's own docstring already says "never a web page... use
  sqlmap or curl instead" — nothing enforced it. Added an explicit
  allow-list of real hydra service names (`credentials.py`); an unknown
  one now raises `ValueError` with the same guidance the docstring
  already gives, before a real subprocess ever runs. Verified by direct
  `hydra.invoke()` (bypassing the LLM) with `service="web"`.
- [x] **Plain-acknowledgment turns showing raw model-internal syntax as
  the final answer:** the structural "zero tools bound" fix (§10)
  correctly stops the *call*, but the model still sometimes *writes* one
  in its own native template tokens (e.g.
  `<|tool_call_start|>[curl(...)]<|tool_call_end|>`), and with nothing to
  parse/consume it, that raw text became the turn's entire visible
  narration — confusing, looks broken, could read as if a real call
  happened when nothing executed. Tried a prompt-only nudge first
  (`_ACK_NO_TOOLS_NOTE`, telling the model not to write any tool-call
  syntax this turn) — live-tested, cut the rate down but didn't
  eliminate it (1/3 leaked in one re-run). Real fix: `respond()` now
  strips any `<|tool_call_start|>...<|tool_call_end|>` span from the
  final content before it's shown (`_strip_leaked_tool_call_syntax`,
  falls back to `"Noted."` if that's all there was) — generic, not
  ack-mode-specific, since this syntax is never legitimate content
  regardless of which turn produced it. **Live-verification lesson:**
  the first attempt to verify this live wrongly reported the fix as
  *not* working — the test script only inspected `Narration` events and
  missed that `core.py`'s existing `NarrationRedacted` mechanism (built
  for the output-guardrail-withheld case) already fires whenever
  `respond()`'s final text differs from what streamed live, fully
  *replacing* the displayed text with the clean version. Re-checked with
  `NarrationRedacted.reason` included: 0/4 raw leaks in the actual final
  displayed text across a repeated trial, even though the model still
  wrote the raw syntax live in the stream itself every time.

**New finding, understood but not fixed — a product decision, not a bug
fix:**
- [ ] Directory brute-forcing was requested mid-engagement
  ("brute force directories on it") and got no `gobuster` call at all —
  the model tried an `nmap --script=dirb` workaround (blocked by
  `dangerous-flag-guard`) and then claimed "none of the available tools
  support this," which is **false against the full catalog** but was
  very likely **true against what was actually bound that turn**:
  `gobuster`'s (and `nikto`/`whatweb`/`wafw00f`/`dnsenum`'s) default
  `reads`-capability phases are `recon, enumeration,
  vulnerability-discovery` only (`catalog.yaml`) — if the engagement had
  already raced past `vulnerability-discovery` into `exploitation` by
  this turn (very plausible: §8's already-known "eager phase
  progression" means several resolved findings across a handful of
  turns can walk the phase forward more than once per turn), those tools
  would have genuinely disappeared from the bound set, and `nmap`/`curl`/
  `sqlmap` (all explicitly offered through `exploitation`) would be all
  that's left — exactly what the model still had access to. This
  reframes §8's "eager phase progression" item: it isn't just a
  cosmetic/logging concern, advancing early can silently take away
  still-useful passive recon/enum tools with no signal to the user about
  why. The `e916f9a`/2026-10-17 decision to leave phase-advance capping
  alone (the demo flow needs it) still stands — but extending the
  default `reads` phase set further into `exploitation`/`post-
  exploitation`, or giving `gobuster` its own explicit phase list like
  `nmap`/`curl` already have, is a real option worth a deliberate
  product call, not something to change unilaterally here.
- [ ] A status question ("what have we found so far?") once got a
  genuinely empty final answer (no tool call, no text) — the documented,
  accepted "real reasoning-model flakiness" category from §9 (`think()`
  retries once on a truly-empty opening move; a second empty attempt in
  a row is left as-is rather than retried again). Not re-opened.
- Test-harness lesson (not a product bug, learned the hard way this
  round): any live-test script checking the model's final narration must
  also check `NarrationRedacted` events, not just `Narration` — the
  latter can be stale once the former fires. Missing this produced a
  false "fix doesn't work" result above before it was caught and
  corrected.
- Verification: targeted suite green after each fix; full suite
  825/825 (no flakes this run). Live-verified via two full engagement
  passes (13-turn original + a focused 9-turn re-run) plus two isolated
  checks (direct `hydra.invoke()`, a 4-trial repeated-acknowledgment
  spot-check) against the real `lfm2.5-8b-a1b` backend and real
  dvwa/metasploitable2 targets.

## 12. Cumulative phase-tool gating + compaction truncation (2026-10-17)

Two follow-ups from §11's "directory brute-forcing got no gobuster call"
finding and a direct question about whether history compaction was
actually managing tokens efficiently.

- [x] **Fixed, live-verified:** `cism/agent/tools/catalog.py`'s
  `_DEFAULT_PHASES_BY_CAPABILITY["reads"]` was a *fixed window*
  (`recon, enumeration, vulnerability-discovery`) — any reads-capability
  tool with no explicit `phases:` override (nikto, whatweb, dnsenum,
  gobuster, wafw00f) permanently disappeared once the engagement moved
  into exploitation, even though it's still legitimately useful there
  (re-running gobuster after a shell reveals a new path, say). Extended
  the default through `post-exploitation`, matching `nmap`/`curl`'s own
  explicit lists — `reporting` stays tool-free everywhere, unchanged.
  `tests/test_phase_profiles.py`'s
  `test_default_profiles_exploitation_includes_hydra_but_not_recon_only_tools`
  explicitly pinned the *old* window design (its own docstring said so);
  renamed and flipped, plus a new test pinning the monotonic contract.
  Live-verified: drove a real engagement into `Phase.EXPLOITATION`
  (confirmed by reading the actual graph state), then asked to "brute
  force directories on it" — `gobuster` was called this time, where
  round 12 got a false "no tool supports this."
  - Also newly observed, not fixed: that same live gobuster call failed
    on its own — the model passed `extra: '-p 1-1000'` (a port-range
    flag, meaningless in gobuster's dir-brute-force mode), so gobuster
    errored with a clear "pattern file '1-1000' does not exist" message.
    Benign (clear error, nothing dangerous) and the same flavor as the
    earlier sqlmap/hydra hallucinated-flag bugs. Not investigated this
    round.
- [x] **Fixed, live-verified:** `_compact_history` (`cism/agent/nodes.py`)
  only ever dropped whole old messages by recency — an old turn's full
  `ToolMessage` content (a real nmap/nikto/sqlmap dump, sometimes several
  KB) stayed in the kept history at full size even though `depg_update`
  (which always runs right after `act()`, before the next `think()`) had
  already condensed its finding into the DEPG/memory block injected
  separately into the system prompt. Added `_shrink_old_tool_output`, a
  pre-pass before the existing budget loop: any `ToolMessage` before the
  most recent `HumanMessage` gets truncated to a 350/100-char head/tail
  with a marker pointing back at the findings block; the turn in progress
  keeps its own tool results in full. Mirrors the one existing precedent
  for this in the codebase — `cism/depg/extractors.py`'s
  `_MAX_PROMPT_CHARS`/`truncated_note` slice-and-mark pattern. Runs
  unconditionally (not just when the budget would otherwise be
  exceeded), so it also lets more whole turns fit before anything needs
  dropping outright. Live-verified by reading the real accumulated graph
  state mid-engagement: 4 of 7 real `ToolMessage`s (sizes up to 7770
  chars, including a full nikto dump) shrank to ~522 chars each with the
  marker; the short and current-turn ones were untouched.
- Verification: `pytest -n auto` 829/829 after both fixes; targeted suite
  re-run after each. Live-verified together in one engagement (driving
  into `exploitation`, inspecting real graph state via
  `agent._graph.aget_state()`, then re-triggering the exact round-12
  failure).
- [x] **Fixed:** §11's previously-accepted "status question gets a
  genuinely empty final answer" flakiness now gets a substitute instead
  of true silence. Reused `respond()`'s existing leaked-tool-call filter
  (`_strip_leaked_tool_call_syntax`) rather than add new plumbing — it
  already substitutes something when stripped content is empty; the fix
  is distinguishing *why* it's empty. A leaked `<|tool_call_start|>...`
  fragment still falls back to `"Noted."` (something non-substantive was
  attempted); genuine emptiness with no leaked fragment at all now falls
  back to `"I don't have anything further to add right now."` —
  `"Noted."` would be a non-sequitur for an unanswered question. Covered
  directly by unit tests (crafted empty-content and leaked-syntax
  inputs); a 6-trial live re-run of the exact status-question trigger
  didn't happen to reproduce genuine emptiness this time (expected —
  it's rare), confirming no regression on the normal path.

---

## 13. Local model swap: Ornith-1.5-9B-MTP (IQ3_M) replacing lfm2.5-8b-a1b (2026-10-17)

The user swapped the local llama.cpp backend to a different model — a
9B-parameter reasoning model (separate `reasoning_content` field) at a
lossy 3-bit quant (IQ3_M), 16K context. Re-ran the live-test harness
against it (dvwa + metasploitable2, real tools) to compare against the
old model and fix what broke.

**Initial read, confirmed better on several axes**, live: zero timeouts/
hangs across an 8-turn engagement (the old model's logs were full of
them), no leaked `<|tool_call_start|>...` raw template syntax, real
credential extraction from a backup config file, clean ack-turn handling,
never truly silent across repeated status questions.

**But a new failure mode surfaced** — "transitional narration": a turn
ending with the model describing its next move ("Let me run nikto
again...") instead of either a tool call or a real answer, shown to the
user as if it were the final answer. Recounted properly (not from a
rough first read): roughly 2/3 of tool-heavy turns across two test
batches ended this way — the dominant failure mode for this model, not
an edge case.

- [x] **Fixed, live-verified:** a narrower sibling of the opening-move
  retry (`cism/agent/nodes.py`'s `think()`) for the genuine "no tool_calls
  attached at all" case on a *later* step — `_is_announcing_an_unexecuted_
  action`, gated on the trailing sentence only (so a real answer that
  merely opens with a future-tense verb, e.g. "I'll check back once the
  scan settles. Found 3 open ports.", is untouched). Reuses the exact
  same retriable-narration-retraction plumbing in `core.py`, which turned
  out to never actually be tied to "opening move" specifically, just to
  the `think` node's own streaming attempts.
- [x] **Fixed, live-verified — this was the dominant cause, not the
  above:** direct inspection of the raw `AIMessage` (not just streamed
  text) showed most "transitional narration" turns actually had a real
  `tool_calls` entry attached — `route_after_think`'s `MAX_AI_TURNS` cap
  had tripped while the model still wanted to act, and `respond()` was
  silently discarding the pending call, showing only its lead-in prose as
  if it were a deliberate conclusion. `respond()` now names the dropped
  call honestly instead: `"(Reached this turn's investigation-step limit
  before finishing -- the next planned step ({tool}) did not run. Ask me
  to continue and I'll pick up from here.)"`. `last.tool_calls` being
  non-empty is unambiguous proof this is why respond() was reached at all
  — the other route into respond() always has an empty list.
- [x] **Fixed, live-verified — a real crash, not just the above two:**
  both fixes above made retries fire far more often than before (only the
  opening move could ever retry previously), which surfaced a latent bug
  in the retry mechanism itself: appending a second `SystemMessage` at
  the *end* of the message list (`[*messages, SystemMessage(nudge)]`)
  crashes this model's chat template outright — `Jinja Exception: System
  message must be at the beginning`. The old model's template tolerated
  it; this one doesn't. Present since the very first version of this
  retry, never triggered until a later-step retry made the path fire
  often enough to hit it. Fixed by folding the nudge into the one leading
  `SystemMessage` instead of appending a second one — keeps exactly one,
  first, always, which is also just a more broadly correct shape
  regardless of model.
- **Latency investigation** (not a bug, a real cost): raw generation
  speed measured directly against the server (bypassing the agent and
  Docker) is ~30ms/token — not the bottleneck. The actual driver is
  `sqlmap`/`nikto`/`gobuster`/`hydra`'s own sandbox timeouts (90s/75s/
  60s/120s respectively, `catalog.yaml`/`credentials.py`, deliberately
  generous so these tools return real findings) compounding across
  rounds — identical cost under any model. `MAX_AI_TURNS` lowered 6→4:
  real ~2.5-3x win on turns bound by round count using only fast tools
  (curl/nmap: ~110-180s → ~45s), no effect on turns already bound by one
  slow tool's own timeout. Separately confirmed live with the cap raised
  to 30 (effectively off): the model converges and stops on its own after
  just 3 rounds when left alone ("I have a confirmed exploit and
  credentials... this is complete") — not a runaway loop, the 384s it
  took was genuine tool execution + reasoning time, visible live in the
  TUI the whole time, not a hang.
- **Verdict:** keep the new model. Its one real gap (transitional
  narration) is now fixed at the root (two distinct causes, both fixed);
  its latency is dominated by real tool execution time any model would
  incur identically; the old model's problems (hangs, leaked template
  syntax, crashes) were harder failures that could prevent a turn from
  completing at all, not just make it slower.
- Verification: `pytest -n auto` 839/839 after all four fixes (narration
  retry, honest step-limit message, SystemMessage shape, `MAX_AI_TURNS`
  lowered), targeted suite re-run after each. Every fix live-verified
  against the real stack before committing; the SystemMessage crash fix
  specifically confirmed by reproducing the exact Jinja error pre-fix and
  its absence post-fix across repeated runs.

## 14. `--live-tools` launch scripts, a phase-change checkpoint, and a `--max-tokens` default (2026-10-18)

Added `scripts/start_lab.sh` (the `cism-lab` network + dvwa + metasploitable2),
`scripts/run_tui.sh` (plain host-shell TUI), and `scripts/run_tui_container.sh`
(the hardened `cism-runner` container from `docker/README.md`, both `cism-lab`
and `cism-egress` attached — `host.docker.internal` only resolves on the
latter, D4). Live-tested the container variant and found two real problems
with the engagement itself, not the scripts:

- **No supervision point.** The TUI's `⏸ manual`/`⏵⏵ auto` status-bar toggle
  (`cism/tui/widgets/status.py:113,175`) looks like a pause control but is
  dead — nothing in the codebase ever sets it. A live run raced through
  recon → enumeration → vulnerability-discovery → exploitation inside one
  `submit()` with no checkpoint at all.
- **Unbounded reasoning.** Neither script passed `--max-tokens`, so a turn
  ran away to 11,000+ decoded tokens (confirmed live via llama.cpp's
  `/slots` endpoint: `max_tokens: -1`), nearly exhausting the model's 16K
  context on one single turn.

Fixes:
- `scripts/run_tui.sh`/`run_tui_container.sh` now default `--max-tokens 4096`
  (`CISM_MAX_TOKENS` to override) — above both `run_agent.py`'s hard floor
  (512) and its documented safe default (2048+).
- `route_after_think` (`cism/agent/nodes.py`) now also stops the loop on a
  phase change, not just the `MAX_AI_TURNS` cap — "whichever comes first",
  per the user's explicit choice. Gated on a new `AgentState.live_tools`
  flag (`cism/agent/state.py`, set from `LangGraphAgent.__init__`'s
  `tools is not None`, `cism/agent/core.py`): the scripted dummy-tool demo
  path deliberately races through two phase changes per `submit()`
  (confirmed by `test_dummy_run_produces_a_final_narration_and_two_phase_
  changes` breaking when the gate wasn't scoped to live engagements only)
  and must keep doing so — nothing to checkpoint there, no real model
  decision to pause and redirect.
- `respond()` now distinguishes *why* it stopped — the existing
  `_STEP_LIMIT_NOTE` for the turn cap, a new `_PHASE_CHECKPOINT_NOTE` for a
  phase change — and appends a real findings digest (`_format_findings_summary`,
  capped at 12 resolved DEPG nodes by generality) instead of leaving the
  operator to guess what was found before deciding how to proceed.
- Verification: `pytest -n auto` 845/845. Live-verified via a headless
  harness driving `LangGraphAgent` directly inside the real hardened
  container against dvwa (same approach as §13): one `nmap` call, phase
  advanced to `enumeration`, and the run stopped with
  `"Findings so far:\n- [open-port] 80/tcp"` plus the pending tool name
  (`whatweb`) instead of continuing unsupervised.

## 15. `--backend llamacpp` default, value-aware curl data guardrail, per-turn narration entry_id, threshold-triggered DEPG-only compaction (2026-10-18)

Live-testing §14's checkpoint feature surfaced three more real problems,
all root-caused directly against the running container's `agent.log`:

- **Context window silently wrong.** Neither launch script passed
  `--backend llamacpp` (`run_agent.py`'s own default is `"openai"`), so
  `_refresh_context_window()` (`cism/agent/core.py`) probed Ollama's
  `/api/show` against a llama.cpp server, 404'd, and silently fell back to
  the hardcoded 32768 default — double the model's real `n_ctx` (16384),
  confirmed via `SessionState.context` in the log. `_compact_history`
  (`cism/agent/nodes.py`) sizes its keep/drop budget off that value, so it
  was computing room for roughly double what the server would actually
  accept. `scripts/run_tui.sh`/`run_tui_container.sh` now default
  `--backend llamacpp` (`CISM_BACKEND` to override) — also switches DEPG
  extraction onto the json_schema-constrained `/completion` path
  `run_agent.py --backend` was built for, instead of OpenAI function-calling.
- **Curl's `-d`/`--data*`/`-F`/`--form` guardrail was value-blind.**
  `DangerousFlagGuardStage` (`cism/agent/guardrails/dangerous_flags.py`)
  matched these flags by name only, blocking a literal POST (e.g.
  verifying credentials the agent just found: `curl -d
  "username=app&password=vulnerables"`) exactly as hard as the real risk,
  `curl -d @/etc/passwd` (local-file-read-and-exfil). Added
  `_curl_value_aware_flag`/`_dangerous_data_value`: only an `@`- (or, for
  `-F`/`--form`'s `name=<file` syntax, `<`-) prefixed value still blocks;
  a short flag bundled into a cluster (`-sSd...`) deliberately isn't
  recognized here and keeps failing closed through the existing generic
  path. Scoped to curl's data/form flags only — every other entry in the
  denylist (nmap's `-oN`/etc., sqlmap's `--file-read`/etc.) is inherently
  about a *path*, not an optionally-literal value, so there's no safe
  literal case to carve out there.
- **Narration `entry_id` was scoped to the whole run, not per AI turn.**
  `_run()` (`cism/agent/core.py`) streams token deltas from every `think()`
  call in a run, not just the final answer, but emitted all of them under
  one constant `f"{run_id}-final"`. `Transcript.narration()`
  (`cism/tui/widgets/transcript.py`) mounts a new widget the first time an
  id is seen and reuses the existing one — wherever it already sits in the
  DOM — every time after, so a later turn's text got appended into an
  earlier turn's already-mounted widget, positioned above whatever tool
  call ran in between. Fixed by bumping a turn counter at the same
  boundary already used to detect "a new think() attempt started"
  (`is_retriable and retriable is None`) and keying every narration event
  in the live-streaming path — including the final `done=True`/
  `NarrationRedacted` marker emitted from `respond()` — off
  `f"{run_id}-final-{turn}"` instead.
- **History compaction now has a second, threshold-triggered tier.**
  Measured against a real live engagement log: raw tool output ≈4,401
  tokens; today's 350/100-char shrink (`_shrink_old_tool_output`) already
  gets that to ≈808 untouched; a DEPG-only equivalent of the same findings
  ≈220. Shrinking already captures most of the win over raw, so
  `_compact_history` (`cism/agent/nodes.py`) only pays the rest of that
  cost when there's real pressure: a new Tier 2 (`_stub_old_tool_output`)
  engages *only* when Tier 1's shrink-only pass still has to drop a whole
  old turn to fit the budget (`dropped > 0`) — stubbing old `ToolMessage`
  content to a fixed, near-free placeholder instead, which can only let
  *more* old turns survive as bare conversational shape than Tier 1 could,
  never fewer. `_depg_context()`/`_memory_context()` already carry the
  same signal either way, rebuilt fresh from `depg_nodes`/`memory_items`
  every `think()` call, not from this chat history.
- Verification: `pytest -n auto` 855/855 (49 in `test_dangerous_flags.py`
  covering the new value-aware cases, a new per-turn `entry_id` regression
  test in `test_langgraph_agent.py`, a new Tier 2 compaction test in
  `test_nodes.py` showing a budget that drops 11/15 messages under
  shrink-only compaction but only 3/15 once stubbing engages).
  `graphify update .` run after.

**Follow-up same day:** an automated post-commit security review on §15's
guardrail change caught a real bypass before this ever ran live:
`--data-urlencode` has a file-read shape `-d`/`--data` don't — a bare
`name@file` (no `=` anywhere) reads a local file and URL-encodes it, even
though the value doesn't start with `@`. The original
`value.startswith("@")` check (correct for every other data flag) missed
it, so `--data-urlencode "x@/etc/passwd"` would have slipped through as if
it were a harmless literal. Fixed in `_dangerous_data_value` with a
dedicated `--data-urlencode` branch: a leading `=` or an `=` appearing
before any `@` means `name=content` (always literal, curl's own
disambiguation rule — covers the legitimate `=user@example.com` case
too); otherwise an `@` with no earlier `=` is the file-read form.
Verification: `pytest -n auto` 857/857 (one pre-existing flaky snapshot
test, confirmed unrelated — it replays a static fixture log, not live
code — and passes in isolation). `graphify update .` run after.

## 16. Interrupting an in-flight run and resubmitting could crash the next run with `KeyError: 'depg_nodes'` (2026-10-18)

Every `~/.cism/logs/agent.log*` file on the host had the same `ERROR run
failed` traceback (37 occurrences across today's and yesterday's logs, one
per log): `think()` (`cism/agent/nodes.py`) crashing on
`state["depg_nodes"]` — a plain `KeyError`, not a guardrail/tool failure,
swallowed by `_run()`'s own `except Exception` into a silent
`RunFinished(ok=False)`. Traced every occurrence to the same trigger: a
new `submit()` arriving while a previous run was still in flight
("superseded by new submission") — confirmed the existing
`test_a_new_submit_emits_interrupted_for_the_run_it_superseded`
(`tests/test_langgraph_agent.py`) already exercises exactly this sequence
and has been silently hitting this crash on every test run; it only ever
asserted on the `Interrupted` event, never on whether the superseding run
actually succeeded.

Root cause: `depg_nodes`/`depg_edges`/`memory_items` have no reducer, so
`_run()` (`cism/agent/core.py`) used to seed them into `initial_state`
with `{}` only on the thread's first-ever run (a `self._thread_seeded`
flag, flipped unconditionally before `graph.astream()` was even called),
relying on every later run omitting the keys to keep the checkpoint's
accumulated value. That flag desynced from reality the moment a run was
cancelled before completing its own turn: the flag was already `True`,
but nothing had actually been committed for this thread yet — so every
run after that omitted the keys from `initial_state` while the checkpoint
still had nothing to fall back on, and `think()` crashed outright.
Checking `graph.aget_state(run_config)` instead of the flag turned out not
to be enough on its own either — it can report a channel as present in the
checkpoint even when a `graph.astream()` call immediately after, on an
`initial_state` that omits that channel, still doesn't carry it forward
into the first node's `state` (reproduced directly: `aget_state()` showed
`depg_nodes` in the checkpoint's `values`, yet `think()`'s own `state`
dict, logged the same run, didn't have the key at all). Fixed by not
relying on omission-means-keep-existing at all: read the checkpoint via
`aget_state()` and **always** write `depg_nodes`/`depg_edges`/
`memory_items` into `initial_state` explicitly (falling back to
`{}`/`[]`/`{}` when the checkpoint doesn't have them yet), every run.

Also hardened the actual race `submit()` has (cancelling the old task and
scheduling the new one in the same breath, no await between, so two
`graph.astream()` calls on the same checkpointer+thread_id could overlap):
`submit()` now passes the cancelled task to the new one, which awaits it
(swallowing `CancelledError`) before touching the checkpointer at all, so
two runs on one thread are never concurrent. This wasn't the actual root
cause of the crash above — a scan of the delay between the two
submissions, and direct instrumentation of the checkpoint read vs. what
`think()` received, showed the corruption already baked into a single
cancelled run's incomplete checkpoint, not a timing race between two — but
there's no reason to leave two readers/writers of the same in-memory
checkpoint able to overlap regardless, so it stays as defense in depth.

Verification: strengthened the existing test to assert every `RunFinished`
in the sequence has `ok=True`, confirmed it reproduces the crash
deterministically against the pre-fix code (not flaky — 8/8 failures),
then confirmed 8/8 passes after the fix. `pytest -n auto tests/` 877/878
(the same pre-existing flaky snapshot test as §15, confirmed unrelated —
passes standalone). `graphify update .` run after.

## 17. Lower `MAX_AI_TURNS` to 2, proactive 75%-threshold compaction, tool-schema token accounting (2026-10-18)

Live, against `Ornith-1.5-9B-MTP-IQ3_M` (`--backend llamacpp`): two real,
distinct failures in the same session, neither a CISM crash.

**Looked hung, wasn't.** A `--live-tools` run sat on "Chaining…" for
minutes with `↑0 tokens`. The container and the llama.cpp server were both
fine (`/health` instant, `/slots` responsive); the server's own log showed
continuous generation the whole time — several consecutive AI turns each
ran all the way to the 4096-token `max_tokens` cap before stopping
(confirmed: tasks hit exactly 4096 `n_gen`, ~2.2-2.5 min each at this
hardware's ~30 tok/s). Root cause: this model forces a `<think>` lead-in
(`reasoning_format: deepseek` in its own `/props`) and often doesn't
finish reasoning within budget. Chained across `MAX_AI_TURNS` turns before
the existing step-limit checkpoint (§14) ever hands control back, that's
several uninterrupted minutes of apparent silence. Fix: `MAX_AI_TURNS`
4 → 2 (`cism/agent/nodes.py`) — halves the worst case; the step-limit/
phase-checkpoint narration (DEPG findings included either way) now fires
twice as often instead of once every ~9-10 minutes.

**Actually crashed.** Separately, a real `run failed` traceback:
llama.cpp's own 400 — `request (16697 tokens) exceeds the available
context size (16384 tokens)`. llama.cpp handled this correctly (a clean
refusal, not silent truncation or corruption); the gap was entirely
upstream. Root cause: `_compact_history`'s budget (both the chars/N
estimate and `_verify_real_token_budget`'s real `/tokenize`-verified
correction) only ever measured `system_prompt` + message content — neither
accounted for the bound tools' own OpenAI tool-call schema JSON, which the
server folds into the real prompt and counts against `n_ctx` the instant
any tools are bound. For a tool-heavy phase that invisible overhead is
easily a few hundred tokens — enough to explain the exact 313-token
overshoot on its own. Fixed with `_tool_schema_text()`
(`cism/agent/nodes.py`, via `langchain_core.utils.function_calling.
convert_to_openai_tool`), threaded into both budget tiers the same way
`system_prompt` already was.

Also added proactive compaction: `_compact_history` used to be purely
reactive (only engage Tier 1/2 once Tier 0 literally couldn't fit).
`_PROACTIVE_COMPACTION_THRESHOLD = 0.75` now engages the cheaper tiers
once usage crosses that fraction of budget even when nothing would yet be
dropped — insurance against the chars/N estimate's own documented swings
(§15: ~6k-14k turn to turn on one real prompt), reacting before an
overshoot rather than one turn after.

Verification: `pytest -n auto tests/` 879/880 (same pre-existing flaky
snapshot test as §15/§16, confirmed unrelated — passes standalone).
`graphify update .` run after.

## 18. PTES phase transitions now require operator approval instead of applying automatically (2026-10-18)

`phase_router` used to apply a detected phase transition the instant
`_phase_ready()` returned true, with the only existing safeguard
(`route_after_think`'s phase-change checkpoint, §14) pausing the *tool
loop* for one turn — narration like "the engagement just moved into the
enumeration phase" — after the move had already happened. The operator
had no way to decline or delay it; text framed as a checkpoint, applied as
a fait accompli.

`phase_router` (`cism/agent/nodes.py`) now only *proposes*: on readiness it
sets `AgentState.phase_proposal` (wire-format name of the target phase)
and `phase_proposal_is_new` (true for exactly the one step it was just
set, driving the one-shot checkpoint/narration/memory side effects —
`phase_proposal` itself stays truthy for as many turns as it's outstanding
and must not re-trigger them each time). While a proposal is outstanding,
`phase_router` holds rather than re-detecting readiness. The existing
`/phase <name>` command (`core.py`'s `_set_phase`) is the only thing that
actually commits a move — unchanged itself, but now also clears any
pending `phase_proposal` on a successful manual transition (confirming the
one proposed, or overtaking it with a different move, either way resolves
it). `route_after_think`'s checkpoint and `respond()`'s wording
(`_PHASE_CHECKPOINT_NOTE`, reworded from "just moved" to "looks ready to
move... run /phase {phase} to confirm") now key off `phase_proposal_is_new`
instead of an already-applied `phase_changed`. `memory_update` logs a
"phase proposal -> X (pending /phase approval)" item instead of an applied
change.

`core.py` tracks `self._phase_proposal` the same way it already tracks
`self._phase` — written explicitly into every run's `initial_state`, never
relied on via checkpoint carry-forward (the exact omission-semantics
fragility §16 fixed for `depg_nodes`, applied here too rather than risking
it again for a second field). A new `PhaseProposed` event
(`cism/tui/events.py`) and status-bar segment (`cism/tui/widgets/
status.py`: `phase: recon -> enumeration? (/phase enumeration)`, warn-styled)
give the operator a persistent, visible signal distinct from the one-line
narration, cleared on the next `PhaseChanged`.

Exposed a real, previously-latent TUI bug along the way: `respond()`'s
checkpoint-note content (built fresh, never streamed from the model) used
to always route through `NarrationRedacted`, which only updates an
*already-mounted* narration widget (`transcript.py`'s `existing_narration`
is deliberately create-nothing, so a redaction for an entry `clear_entries()`
removed doesn't mount a phantom). A pure tool-call turn with empty
streamed content — the common case for a checkpoint note, since nothing
was ever live-streamed into that `entry_id` — had no widget to update, so
the note silently never appeared in the TUI at all. Only surfaced because
lowering `MAX_AI_TURNS` (§17) made the scripted dummy-tool demo hit this
path for the first time. Fixed in `core.py`'s respond-handling: when
nothing was streamed, emit a fresh `Narration(done=True)` with the final
text instead of a `NarrationRedacted` with nothing to attach to.

Also fixes the dummy-tool demo's own old behavior: it used to race through
multiple phase changes unsupervised in one `submit()` (the whole reason
`route_after_think`'s checkpoint was gated on `live_tools` in the first
place) — now it just holds at one pending proposal like every other path,
since nothing auto-applies regardless of `live_tools` anymore.

Verification: renamed/rewrote the `phase_router`/`route_after_think`/
`memory_update`/`respond` unit tests in `tests/test_nodes.py` for the new
propose-not-apply semantics, updated `tests/test_langgraph_agent.py`'s
dummy-run test (now asserts one `PhaseProposed`, zero `PhaseChanged`, and
the checkpoint note's text) and `tests/test_app_with_langgraph_agent.py`'s
TUI integration test (1 tool entry, not 2 — `dummy_msfconsole` is
ENUMERATION-only and the lowered turn cap now stops the run before `act()`
ever reaches it; `app.phase` stays `"recon"`), added `PhaseProposed`'s
round-trip/registration coverage to `tests/test_events.py`. `pytest -n
auto tests/` 879/880 (same pre-existing flaky snapshot test, confirmed
unrelated — passes standalone). `graphify update .` run after.

## 19. Phase-approval modal, depg/mem status-bar regression, response-reserve vs. real `max_tokens`, and a curl cookie guardrail gap confirmed against a live DVWA crack (2026-10-18)

Four fixes from one live session, found in the course of actually running
the operator's own workflow rather than synthetic testing.

**`/phase` command silently reverting.** `_translate()`'s `phase_router`
branch (`core.py`) used to compare the stale, run-frozen
`update["phase"]` (just `state["phase"]` echoed back, frozen at that
run's `_run()`-start) against the live `self._phase.current` and
"correct" it back whenever an in-flight run's later node update arrived
after a manual `/phase` command had already changed the live value —
silently undoing the operator's own override the moment §18's proposal
machinery emitted its next update. Fixed by deleting the auto-apply/revert
block entirely; only `_set_phase` may touch `self._phase.current` now,
and this branch just surfaces `phase_proposal`/`phase_proposal_is_new` as
before.

**No modal for a pending phase proposal.** §18 gave the status bar a
`phase_proposal` segment, but an operator looking at the transcript
instead of the status bar had no prompt at all. Added
`PhaseApprovalModal` (`cism/tui/widgets/phase_modal.py`,
`ModalScreen[bool]`, approve/dismiss buttons, Enter/Escape bound) pushed
from `app.py`'s `PhaseProposed` handler (guarded by
`len(self.screen_stack) <= 1` so it never double-stacks), resolved via
`_resolve_phase_modal()` which runs the existing `/phase <name>` command
on approval. A `PhaseChanged` event (manual override via the status bar
or a typed command while the modal is still open) auto-dismisses it.

**`depg`/`mem` status-bar segments vanishing at ordinary terminal
widths.** Root cause: §18's new `phase_proposal` segment widened the
"phase" field enough to crowd `depg`/`mem` (then an unlabeled default
priority, the lowest tier) out of `elide()`'s width-fitting pass at
everyday widths (~80 columns) — confirmed by a scratch width-simulation
comparing segment survival with/without a pending proposal, not by
guesswork. Fixed two ways: shortened the proposal segment's text (dropped
the trailing `(/phase {name})`, redundant with the modal now prompting
the same action) and gave `depg`/`mem` their own explicit priority 2, one
tier above the rate/target segments they used to share a tier with — the
engagement's own finding counts should survive tight width before
cosmetic nice-to-haves do.

**Compaction's response reserve was a flat 512 tokens, not the model's
actual configured cap.** §17 added proactive compaction and tool-schema
accounting but still reserved a flat `_RESPONSE_RESERVE_TOKENS` (512) for
the model's own answer — confirmed via a live llama.cpp server log
(`12537 + 3847 = 16384`, `truncated: 1`) that a reasoning model given room
to think routinely generates well past 512 tokens, so a "correctly"
compacted prompt could still leave the model free to overflow `n_ctx`
mid-generation. Added `_response_reserve(llm)` (`cism/agent/nodes.py`),
reading the bound `ChatOpenAI`'s own `max_tokens` attribute and using
whichever is larger than the 512 floor; `_compact_history()` and
`_verify_real_token_budget()` both now take it as a parameter instead of
closing over the module constant directly. `_RESPONSE_RESERVE_TOKENS` is
now a floor, not the reserve.

**`curl -b`/`--cookie` was flat-denylisted with no value-aware carve-out**
(unlike `-d`/`--data*`/`-F`/`--form`, which already have one from §9/§10)
— blocking the agent from ever carrying a session cookie across two curl
calls, which is exactly what logging into a target application and then
acting as that session requires. Confirmed live and manually (`docker
exec` into the running `cism-runner` container, bypassing the agent
entirely, per the operator's own request to verify ground truth before
trusting the agent): DVWA's default `admin`/`password` login via curl
with CSRF/`PHPSESSID` handling, a UNION-based SQLi
(`id=1' UNION SELECT user,password FROM users-- -`) dumping all 5 users'
MD5 hashes through curl alone, and the same flow automated end-to-end via
`sqlmap --cookie --batch --dump` — proving the existing tool catalog is
already sufficient to fully crack DVWA, no new tool needed for this
target. `sqlmap --cookie` was never blocked; only curl's `-b`/`--cookie`
was. Added `-b`, `--cookie` to `_CURL_VALUE_AWARE_FLAGS` and a new
`_CURL_COOKIE_FLAGS` branch in `_dangerous_data_value()`
(`cism/agent/guardrails/dangerous_flags.py`) with curl's own, *different*
file-read rule for this flag: any value containing no `=` at all (no `@`
marker needed, unlike `-d`/`-F`) is read as a filename to load cookies
from, so a literal `name=value` cookie string is always safe and a bare
path (`-b /etc/passwd`, `-b cookiejar.txt`) stays blocked. `-c`/
`--cookie-jar` (write cookies to an arbitrary file) is a different flag
and stays flat-blocked, unaffected.

Verification: 10 new cases in `tests/test_dangerous_flags.py` for the
cookie carve-out (literal string, `=`-joined, abbreviation, no-value,
file-read block, cookie-jar regression), 5 new cases in
`tests/test_status.py`/`tests/test_app.py` for the modal and segment-
priority fixes, 4 new cases in `tests/test_nodes.py` for
`_response_reserve`. `pytest -n auto tests/` 914/914. `graphify update .`
run after.

## 20. Overnight unattended run against dvwa + metasploitable2: nmap timeout and a second dual-SystemMessage chat-template crash (2026-10-18)

An unattended overnight engagement (operator driving the TUI through tmux,
no human watching) against both lab targets surfaced two more live bugs
beyond §19's batch, both confirmed with hard evidence before fixing.

**`nmap` timed out on every `-sV` attempt against a busy host.** The
60s `ToolSpec` default (`cism/agent/tools/catalog.py`) was never
overridden for `nmap` in `catalog.yaml`, unlike every other
timeout-sensitive tool (`sqlmap` 90s, `nikto` 75s, `wafw00f` 45s). Timed a
real `nmap -sT -Pn -sV` by hand against Metasploitable2 (14 open ports):
**152.82s** — so the agent could never version-scan a multi-service host
at all; every attempt was killed at 60s before it could finish. Fixed with
an explicit `timeout: 240.0` on `nmap`'s catalog entry, with margin above
the measured number.

**A second, different shape of the §17/§18-era "Jinja Exception: System
message must be at the beginning" crash.** §17's original fix covers the
retry path (`think()` folding a nudge into the one leading SystemMessage
instead of appending a second one at the end). `_compact_history`
(`cism/agent/nodes.py`) had its own, independent instance of the same
defect: whenever it actually dropped any turns, it prepended its own
`"[N earlier turn(s) omitted]"` SystemMessage onto the kept history —
which `think()` then placed at index 1, immediately after the real
leading SystemMessage it builds at index 0. Two system-role messages, the
second not at position 0, crashed the chat template exactly the same way,
latent since §12 introduced compaction and only triggered live once an
unattended engagement ran long enough for compaction to actually drop a
turn for the first time (confirmed via the server's own error text,
byte-for-byte identical to §17's). Once triggered, every subsequent think()
call hit the same crash — a tight, continuous `RunFinished(ok=false)`
loop, never hanging but never making progress either, since `dropped > 0`
stays true turn after turn. Fixed by having `_compact_history` return the
drop count only (no message of its own) and `think()` fold the same note
text into its one real leading SystemMessage, mirroring §17's fix exactly.
Verification: `test_think_keeps_exactly_one_leading_system_message_when_
turns_are_dropped` added alongside the existing
`test_think_retry_keeps_exactly_one_leading_system_message`, same
assertion shape (`len(system_messages) == 1`). `pytest -n auto tests/`
915/915. `graphify update .` run after.

Two more observations from the same run, noted but not code changes:
`gobuster` repeatedly failed on invalid flags the model added itself
(`-ir`, a custom `-w` to a seclists path that doesn't exist in this
image) despite the catalog description already saying not to — resolved
with a plain-language chat correction rather than a code fix, since the
description already covers this and the model just wasn't following it.
Separately, the model fell into a degenerate repetition loop constructing
a raw SQLi payload by hand (hundreds of repeated `%20` tokens, burning the
full `max_tokens` cap in one generation) and produced an unparseable,
unbalanced-quote `extra` string — `dangerous-flag-guard`'s existing
fail-closed handling for this exact case (tested:
`test_an_unparseable_extra_argument_is_blocked_not_raised`) caught it and
blocked cleanly rather than crashing or passing it through. Both are model
-reliability observations about this specific small/quantized model, not
CISM defects.

## 21. Same overnight run, continued: scope-guard/URL comma conflation, llamacpp `/v1` extraction endpoint, dead-region re-wrap (2026-10-18/19)

Three more live bugs found continuing §20's same unattended run, after the
model successfully logged into DVWA and moved on to the SQL injection page.

**`ScopeGuardStage._extract_host`'s comma-split ran before its URL check.**
The comma-split exists for `--target`/`--scope`'s own `"10.0.0.1,10.0.0.2"`
list syntax, but it ran on the raw value before checking whether the value
was a URL at all. A real UNION-based SQLi payload in a curl call's query
string (`...SELECT user,password FROM users-- -`) has its own comma, split
into `"user"` and `"password..."` — neither host-shaped — and the call was
blocked as `<unparseable-multi-target>`, live, against an otherwise
in-scope target. Fixed by moving the URL-scheme check to the top of
`_extract_host`, before the comma-split logic. Commit `20e404c`.

**`LlamaCppExtractionBackend` posted to `{base_url}/completion` with
`base_url` taken as-is from `--base-url`**, which is the OpenAI-compatible
chat endpoint (`.../v1`, `scripts/run_tui*.sh`'s own default for
`--backend llamacpp`) — not llama.cpp's native `/completion`, which lives
at the server root. Every single call all engagement long went to
`.../v1/completion`, 404'd, and silently fell back to `GenericExtractor`'s
opaque hash node instead of a real structured finding. Confirmed directly
against the live server (`.../v1/completion` → 404, `.../completion` →
200) and confirmed fixed live immediately after rebuild: the first curl
call post-fix produced a real `outdated-server-header` finding instead of
a generic hash node. Fixed by stripping a trailing `/v1` path segment in
`LlamaCppExtractionBackend.__init__`. Commit `e05f5e1`.

**`Graph.prune()` wasn't idempotent on an already-settled dead-region
marker.** `make_depg_update_node()` calls `prune()` roughly once per
engagement tick. A dead-region marker's `_collapse()`-assigned state
(`"blocked"`) never changes, so once a lone marker had nothing new
attached to it, every subsequent `prune()` call still found it as a
fresh single-node all-blocked component and re-wrapped it in yet another
marker — nesting it 8 levels deep across one run, confirmed live via
`agent.log`'s `DEPGUpdated` events, each one's id longer than the last
(`pruned:...:pruned:...:pruned:...:sql-injection:...`). Found while
auditing why a confirmed DVWA SQL-injection finding — a real UNION-based
dump of the `users` table, 6 credentials, verified directly against the
agent's own raw curl output — never appeared in the final `/report`
output as a resolved finding: it was swept into one of these markers.
Fixed by skipping re-collapse when a component is exactly one node that
is already a `dead-region` marker; a new dead node attached to an
existing marker is still absorbed normally. Commit `acff6d3`.

Separately, root-caused rather than left speculative: the SQLi node's
own first-ever verdict was `"dead"`. Initial theory was a one-off model
misread, but replaying the *exact* same confirmed-SQLi curl output
against the real running model 5 times with unchanged code proved it's
sampling variance, not a one-off: **3 of 5 missed the sql-injection
finding entirely**, 1 got it half right, only 1 fully correct —
`LlamaCppExtractionBackend.extract()` set no `temperature` on its
`/completion` call, so the server's own default sampling applied to
what is a classification task, not creative generation. The same prompt
at `temperature=0.0` was 6/6 identical and correct across repeated
calls, and sanity-checked against a clean port-scan and a
nothing-to-report case to confirm it doesn't suppress real findings.
Fixed by pinning `temperature: 0.0` on the request. Commit `7c69808`.

`pytest -n auto tests/` 923/923. `graphify update .` run after.

## 22. Live verification of #21's fixes, a token-budget probe-failure gap, and a 3-hour unassisted loose-prompt test (2026-10-19)

Rebuilt `cism-runner` with #21's two fixes baked in and re-ran the exact
same DVWA login + UNION SQLi dump by hand against the fixed image: the
`sql-injection` finding now appears correctly as `[resolved] ... [T1]` in
the real `/report` output (`engagement-reports/run5-verify-d7a3f96e.md`)
— confirming both fixes work end-to-end, not just in unit tests.

**A second, deeper determinism gap, found live while re-replaying the same
extraction prompt during a concurrent engagement run.** Temperature=0
alone gave 6/6 identical results in isolation, but under real concurrent
server load (`total_slots: 4`, long streaming generations in flight,
plus this model's IQ3_S quantization — 3.66 bits/weight, razor-thin
numeric margins) the *same* prompt still produced a stable-but-wrong
result repeatedly. This is model/infra-level residual variance (floating
-point non-associativity under concurrent batched compute on an
extremely quantized model), not something fixable from `cism`'s request
parameters — noted here, not fixed further, since temperature=0 is still
a strict improvement over the pre-#21 baseline (which failed outright
3/5 times with no determinism at all).

**A real, separate robustness gap found chasing that investigation:** a
genuine `openai.APIError: Context size has been exceeded` crash hit
mid-engagement during the loose-prompt test (below), ~90 minutes in,
under the same heavy concurrent load. Root-caused to
`_verify_real_token_budget` (`cism/agent/nodes.py`): its real-tokenizer
probe (`count_tokens_llamacpp`, a 5s-timeout `/tokenize` call) timed out
under load, and the old contract treated "probe failed" exactly like "no
counter configured at all" — a no-op, passing the already-known-
unreliable chars/N estimate through with zero safety margin, at exactly
the moment concurrent load makes that estimate least trustworthy. Not a
crash loop (the auto-pilot's existing continue-nudge recovered the run
immediately), but confirmed it would recur under the same load pattern.
Fixed by applying a defensive 85%-of-window recompaction when the probe
itself fails, instead of trusting the raw estimate unchanged. Commit
`761440d`.

**The loose-prompt experiment itself** (the user's standing question:
can a terse prompt like *"Find vulnerabilities - go with option 1"*,
with no detailed instructions, still drive a complete engagement):
a single such prompt, with no further operator input, ran for 3 hours
against DVWA, PTES phase-advancing on its own (126 agent runs, 110
resolved findings — nikto issues, exposed paths, missing headers,
insecure PHP config, full port/service enumeration;
`engagement-reports/run6-loose-prompt-b9949a48.md`). Breadth of generic
recon/enumeration held up fine fully unassisted. The deeper multi-step
exploit chain did not: the model got stuck guessing a wrong URL prefix
(`/dvwa/vulnerabilities/sqli/...` — this DVWA install's real path has no
`/dvwa/` segment) for most of the run and never self-corrected back to
the *correct* path it had already found during its own earlier recon in
the same session. Every SQLi attempt against the wrong path was
correctly classified `sql-injection-attempt`/`no-injection-found` — DEPG
extraction held up correctly throughout; the gap is in the agent's own
path-correction behavior, not DEPG quality. Earlier tonight, one explicit
chat message naming the exact correct URL unstuck the identical mistake
immediately (§20/§21). **Conclusion: a bleak/terse prompt is sufficient
for broad recon but not reliable for the deeper exploit chain with this
small/quantized model — it can get stuck in a persistent wrong-path rut
for hours without external correction.**

`pytest -n auto tests/` 924/924. `graphify update .` run after.

## 23. A sandboxed raw-TCP tool (`nc`, netcat-openbsd) so a found backdoor can be tested, not just identified (2026-10-19)

Tonight's `nmap -sV` run against Metasploitable2 (172.28.0.2) got back a
literal `root@...:/# ` shell prompt from the ingreslock backdoor on 1524
— nmap's own service-detection probe incidentally catching the backdoor's
banner. Strong circumstantial evidence it's live, but the toolkit had no
way to go further: nmap/curl/nikto/whatweb/dnsenum/sqlmap/gobuster/hydra
are all either HTTP-shaped or credential-brute-force shaped — none can
open a raw TCP socket and exchange bytes with a non-HTTP service.
Confirmed live inside the running container at the time: no `nc`,
`ncat`, `netcat`, or `socat` binary existed at all.

This is the gap `catalog.yaml`'s own `wafw00f` comment already named but
didn't solve — a full Metasploit Framework integration was considered and
rejected there as "too heavy to wire into one sandboxed CLI call." Sound
for `msfconsole` (interactive, stateful), but a one-shot `nc host port`
call fits the existing "one argv list, one timeout, one captured output"
shape just as well as every other tool already does.

**Scope: Tier B** — not just "connect and read the banner" but "connect,
send one command, read the response," the minimum needed to prove command
execution rather than just presence.

**netcat-openbsd, not `ncat`/GNU netcat**: OpenBSD's `nc` has no
`-e`/exec-on-connect flag at all (removed upstream specifically because
binding a shell to a socket is a backdoor primitive) — the single most
catastrophic failure mode for a tool like this is structurally
impossible here, not just denylisted. Pinned to `1.229-1`, the version
`apt-cache policy` resolves to on this image's base (`cism-runner.Dockerfile`).

**Design**: `cism/agent/tools/network.py`, a hand-written `@sandboxed_tool`
(same reason as `hydra`: needs to write a scratch file — `command`'s text
— before the process runs). `target`/`port` are a plain host string and a
structured int, never combined into one string: `target` flows through
`ScopeGuardStage` exactly like every other tool's target (added to
`_TARGET_ARG_BY_TOOL` in `scope.py`), deliberately avoiding a repeat of
#21's comma-in-a-URL scope-guard bug in a new shape. Forced `-w 10` (nc's
own connect/idle timeout) as a second, independent timeout alongside
`run_sandboxed`'s own.

**Sandbox core change** (the one piece touching every tool, so it got the
most scrutiny): `run_sandboxed`/`Runner`/`SubprocessRunner`/
`BubblewrapRunner` (`cism/agent/tools/sandbox.py`) gained an optional
`stdin: Path | None = None` parameter, defaulting to `None` everywhere —
verified a pure addition, not a behavior change, by running the full
suite before and after. When set, it's opened and passed as the real
subprocess's own `stdin=` kwarg via `Popen` — a plain fd redirect, not a
shell feature, so it doesn't touch `bwrap`'s argv construction at all.
`sandboxed_tool`'s decorator (`base.py`) wires this in by convention: if
the decorated function wrote `scratch / "stdin"`, that file is passed
through automatically; a tool that doesn't (hydra, and every decorated
tool before this one) is unaffected.

**Guardrails**: `_PER_TOOL_DANGEROUS_TOKENS["nc"] = frozenset({"-l",
"-k"})` blocks listen mode, the only way this tool could become a
reverse-shell catcher or relay. Verified this is currently a defense-in-
depth / future-proofing entry, not an active one: `nc`'s real schema
exposes only `target`/`port`/`command`, no raw-flags field at all, so a
real call can never reach a `-l`/`-k` flag in the first place — the entry
only matters if the model hallucinates an `extra` kwarg the schema
doesn't define, which the guard still catches cleanly instead of letting
it fall through to a confusing `TypeError`. No exec-flag entry needed:
OpenBSD `nc` has nothing to name. `_DECORATED_TOOL_PHASES`/
`_DECORATED_TOOL_CAPABILITIES` (`profiles.py`) bind `nc` to
EXPLOITATION/POST_EXPLOITATION only, same window as hydra.

**Tests**: `tests/test_network.py` (argv shape, bare host/structured
port, stdin-file materialization), `tests/test_sandbox.py` (stdin reaches
the real subprocess through both `SubprocessRunner` and
`BubblewrapRunner`; omitting it is byte-for-byte unchanged),
`tests/test_dangerous_flags.py` (`-l`/`-k` blocked, a plain connect
allowed), `tests/test_phase_profiles.py` (phase-window pin, same shape as
hydra's). `pytest -n auto tests/` 935/935 (924 prior + 11 new); one
`test_depg_modal` snapshot failure seen under `-n auto` reproduced as
flaky — passed both before and after this change when run in isolation,
not caused by it, not chased further (lightweight-testing policy).
`graphify update .` run after.

Checkpointed before starting (`git tag pre-nc-tool`, already present at
this point). Container rebuild deliberately deferred — a second agent was
using the running `cism-runner` container concurrently; per the user's
instruction, the actual rebuild + in-sandbox verification (driving the
agent's own shipped `nc` tool through bubblewrap) happens once that
concurrent work is done, backing up the existing container first.

**Mechanism pre-validated live, outside `cism-runner` entirely, same
night**: the host shell itself isn't attached to the `cism-lab` docker
network (`ping 172.28.0.2` from the host: 100% loss — confirmed via
`docker network inspect cism-lab`, `Attachable: false`/`Internal: true`,
host not in its container list). Rather than wait, spun up a disposable
`docker run --rm --network cism-lab alpine:3.20` (netcat-openbsd
installed fresh inside it, discarded on exit) to test the exact
mechanism the new tool uses — `nc -w <timeout> host port` with a command
piped into stdin — without touching the running `cism-runner` container
at all. Result: unauthenticated root shell confirmed on the ingreslock
backdoor, port 1524:

```
root@1240f8386034:/# id
uid=0(root) gid=0(root) groups=0(root)
root@1240f8386034:/# whoami
root
root@1240f8386034:/# hostname
1240f8386034
```

`1240f8386034` matches the real `metasploitable2` container's own ID in
`docker ps` — not an echo or decoy, a genuine shell inside the target.
Direct answer to "can Metasploitable2 be cracked": yes, trivially, no
credential guessing or injection chain needed — one connection, one line
of input, full root.

One design note surfaced by this: the backdoor is a persistent
interactive shell, not a one-shot responder — it happily accepted several
newline-separated commands in the same connection before idling out. The
shipped tool deliberately sends exactly one `command` and reads the
response (sufficient to *prove* exploitation, the Tier B goal stated
above); chaining multiple commands in one session would be a Tier C
extension, not something this design covers. Not acted on tonight —
noted for if/when that's wanted.

This validates the mechanism and the real target, not yet the shipped
code path itself — that still only runs inside `cism-runner` under
bubblewrap, pending the deferred rebuild.

**Follow-up same night: does this target need any more tools than
`nc`+`hydra`+the existing web-vector set?** Live port/banner probe of
172.28.0.2 (same disposable-container method) found the classic
Metasploitable2 service set — vsFTPd 2.3.4 (21), OpenSSH 4.7p1 (22),
Postfix (25), Samba (139/445), rlogin/rsh (512-514), Java RMI (1099),
ingreslock (1524, proven), MySQL 5.0.51a (3306), distccd (3632),
PostgreSQL (5432), UnrealIRCd (6667), and an unexpected Ruby DRb service
on 8787 — notably NOT port 80/8180/5900/6000/2049, which the classic VM
normally has; this particular image (`tleemcjr/metasploitable2`) is
narrower than the full VM.

Tried extending the proven `nc`-backdoor pattern to the two other
classic plaintext backdoors on this box — both failed, informatively:
- **vsftpd 2.3.4 smiley backdoor** (`USER x:)` -> root shell on 6200):
  sent three ways (plain, held-open connection, with/without CRLF);
  port 6200 never opened.
- **UnrealIRCd `AB;cmd;` backdoor**: got back a normal IRC protocol
  error (`451 AB; :You have not registered`) — the server tokenized
  `AB;` as an ordinary unknown command rather than intercepting it
  pre-parse, the signature of the backdoor hook not being compiled in.

Conclusion: this image reproduces the classic services' *version
banners* but apparently not the two trojaned binaries themselves — only
the deliberately-added `ingreslock` listener (a plain `/etc/inetd.conf`
shell, not tied to any CVE'd binary) is a confirmed-working
unauthenticated root path on this particular box. RMI (1099), Samba
`usermap_script` (139/445), and the DRb service (8787) would each need a
dedicated binary-protocol exploit (Java serialization / SMB framing /
Ruby `Marshal`) to even test, not something `nc`'s plain-text one-shot
shape can reach — not attempted, since even if real they'd be redundant
with the already-proven root access, and building three bespoke
protocol exploits for marginal, duplicate findings isn't worth it right
now. Revisit only if the goal becomes "catalog every distinct RCE here,"
not "can it be cracked" (already yes, via ingreslock).

## 24. Fixed a GenericExtractor node-identity bug causing DEPG bloat; scoped (not yet built) an edge-aware replacement for `_depg_context`'s flat cap (2026-10-19)

A live unassisted run against DVWA's login flow surfaced two related but
distinct problems in how findings reach the model's context.

**Fixed: `hash_signal` wasn't actually stable against the two most common
sources of run-to-run noise.** Neither curl nor `nc` has a dedicated
`CauseExtractor` (same gap §15's own comment on this file already
flagged for curl), so every call falls through to `GenericExtractor`,
whose node identity is `hash_signal(raw tool output)`. Confirmed live:
a dozen+ separately-fetched copies of DVWA's login page — functionally
identical ("still logged out") — each became a *permanent, separate*
DEPG node, because `hash_signal` didn't strip two things that vary on
every call despite the content being the same finding: curl's own
progress-meter preamble (byte counts and transfer speed jitter purely
from timing) and DVWA's freshly-rotated CSRF `user_token` embedded in
the page body. Since `_depg_context`/`_memory_context` (`nodes.py`) fold
straight into every `think()` call's system prompt, this wasn't just
noisy findings — it was actively consuming the compaction budget that
should have gone to the hint/fix the operator had just given the model,
making it look like context was being dropped too aggressively when the
real problem was upstream junk inflating what had to fit in the first
place.

Fixed in `cism/depg/normalize.py`'s `hash_signal` (not a new per-tool
extractor — this is the one shared choke point every content-hash-keyed
fallback node already goes through): strip curl's progress-meter block
via a pattern matching its two fixed header lines plus the numeric/`:`/
`%`/unit-suffix stats that follow, and mask any hex string specifically
inside an HTML `value='...'`/`value="..."` attribute (the generic shape
of a hidden CSRF/nonce field) to a fixed placeholder before hashing.
Deliberately *not* masking bare hex substrings anywhere in the text: a
UNION-dumped password hash is real, distinguishing content displayed as
plain page content, not a form's hidden-input value, and two different
dumps must not collapse onto the same node just because both happen to
be 32 hex characters. Verified both directions with real captured
samples: two genuinely-different login-page fetches (different token,
different curl timing) now hash identically; two genuinely-different
plain-text password hashes still hash differently.

**Scoped, not built: `_depg_context` needs to select an actual subgraph,
not just cap a flat list.** Today it groups nodes by target, sorts
targets by unresolved-count then size, and takes the top
`_DEPG_CONTEXT_CAP_PER_TARGET` nodes per target — no edges considered at
all. Confirmed by reading `Graph.prune()` (the only place in the
codebase that *does* walk edges for a similar purpose): it only
collapses weakly-connected all-`blocked` components, which never
applies to GenericExtractor's orphan nodes (no edges to anything,
`linking.py`'s `find_precondition` doesn't relate two generic
hash-keyed nodes to each other) — so today's cap genuinely has no
graph-structural awareness, it's a flat count-and-sort.

Proposed design for the actual fix, next time this is picked up:
- `AgentState` already carries `depg_nodes`/`depg_edges` as flat
  collections, and `Graph.from_state(nodes, edges)` already exists to
  seed a working `Graph` (with `_children`/`_parents`/`last_for_target`
  built) from exactly that shape — reuse it inside `_depg_context`
  rather than building new adjacency-tracking from scratch.
- Per target, in priority order until the existing per-target cap is
  filled: (1) every T1-tier node unconditionally (credential-found,
  confirmed sql-injection — ground-truth capability unlocked, must
  never be crowded out by recency or position), (2) a depth-bounded
  BFS (same traversal shape as `_weakly_connected`, just not
  state-restricted) outward from `last_for_target[target]` over
  `_children`/`_parents` — recovers the causal neighborhood of wherever
  the engagement's attention currently is, not just "whatever's newest
  in insertion order", (3) only then, highest-signal *orphan* nodes
  (no edges at all) as the lowest-priority fallback — same
  unresolved-first tie-break as today, now correctly deprioritized
  below anything the graph actually knows is connected to live
  investigation.
- Same asymptotic cost as today: one bounded BFS per target, capped at
  the existing per-target node budget — no new indexing work, since
  `Graph` already maintains the adjacency dicts this reads from.
- Open question for whoever implements this: whether to also render
  light structure (e.g. indent a child under its parent in the text
  block) or keep the flat one-line-per-node format and let ordering
  alone carry the "this is connected to that" signal — the latter is
  the smaller change and should ship first; structure can follow if the
  flat-but-ordered version still isn't legible enough live.

Verification (today's fix only — #2 above is design, not code):
`pytest -n auto tests/` 939/940 (the one failure, `test_failed_tool_entry`,
is `test_snapshots.py`'s pre-existing order-dependent flakiness under
`-n auto` — confirmed by re-running it alone, where it passes).
5 new cases in `tests/test_depg_normalize.py` covering the curl-meter
strip, the CSRF-token mask, that a real dumped hash is *not* masked, and
the combined real-world repro (two login-page fetches differing only by
timing + token, now hashing identically). `graphify update .` run after.

## 25. Noted, not yet fixed: a text submission sent while a `PhaseProposed` is pending can silently auto-confirm it instead of being treated as a new operator message (2026-10-19)

Live, driving a TUI session via `tmux send-keys`: with a phase-approval
modal/proposal pending, submitting a plain text redirect (not `/phase
...`, not the approve keybinding) twice landed as the pending proposal
getting silently confirmed — the engagement jumped straight from
`post-exploitation` to the terminal `reporting` phase mid-investigation,
before the model had actually used a credential it had only just found
(not yet attempted the login). Phase transitions in this state machine
are one-directional (confirmed live: `/phase post-exploitation` from
`reporting` returns `"cannot transition from REPORTING to
POST_EXPLOITATION"`), so this isn't just a wasted turn — it permanently
ends that engagement's ability to complete the step the operator
actually asked for, with no recovery but starting over.

Not root-caused yet — candidates worth checking first, not yet
narrowed down: whether a pending `PhaseProposed` modal is still
intercepting plain `Enter`/text submission as "approve" even after new
text has been typed into the input box; a race between the TUI's event
loop and `tmux send-keys`' near-simultaneous keystrokes-then-Enter
(plausible but unconfirmed, since this reproduced even with the text
visibly present in the input box before Enter was sent the second time);
or something specific to this model/build's modal-dismissal path, since
it didn't happen with the other models driven the same way earlier
tonight. Revisit with a controlled, slowed-down repro (type, wait,
screenshot/capture-pane, then Enter as a separate step) before touching
any code — right now there's a reproduced symptom but no confirmed root
cause, and this file's own working policy is root-cause-first.

Interim mitigation until fixed: don't submit a new instruction while a
phase proposal is visibly pending in the TUI — dismiss or explicitly
approve/reject it first, then send the next message as its own,
separate step.

## 26. A model declared a login "successful" from an empty response body alone — the same empty body is DVWA's actual response on both success and rejection (2026-10-19)

Live, Gemma 4 E4B against DVWA: it POSTed `admin`/`password` to
`login.php` with no session cookie attached and a stale CSRF token
reused from several turns earlier, got back a 0-byte response, and
narrated "the login attempt ... was successful ... we have successfully
gained access" — then planned its next step (an LFI attempt) on that
premise, without ever checking the one thing that would have confirmed
or refuted it.

Verified directly against the live target (bypassing the agent, same
ground-truth-check pattern as earlier live sessions) that this
conclusion cannot be drawn from an empty body alone on this target:

- A **well-formed** login (matching `PHPSESSID` cookie + a token fetched
  from that same session) returns `302 Found`, `Content-Length: 0`,
  `Location: index.php` — real success.
- The model's **actual** request shape (no cookie at all, stale token)
  also returns `302 Found`, `Content-Length: 0` — but `Location:
  login.php` — rejected, bounced straight back to the login page.

Both cases are byte-for-byte identical in everything the model's own
`curl` call captured, because it never requested `-i`/`-D-` to see
status code or headers — only the `Location` value distinguishes them,
and that was never visible to it. So this wasn't just a wrong
conclusion, it was an *unfalsifiable* one from the evidence the model
chose to look at: a 0-byte body genuinely doesn't tell you which case
you're in without headers, on this specific target's login behavior.

Options worth weighing next time this is picked up, not yet decided
between:
- Force `-i` (or a header-revealing flag) onto curl's own forced flags
  in the catalog, so the agent always has status/redirect-target
  visibility and physically cannot reach this blind spot — the
  strongest fix, but changes curl's default output shape for every
  call, including ones where it's irrelevant noise.
- A narrower nudge via the tool's own description (similar to the
  existing curl catalog entry's live-correction comments) telling the
  model specifically that an empty body on a POST to a login endpoint
  is not evidence of success and `-i` is required to confirm a
  redirect's target — cheaper, but relies on the model reading and
  acting on prose rather than a structural guarantee.
- Leave as an operator-nudge case (what happened live tonight): catch
  it when the narration claims an unverified success and redirect the
  model to actually check, same as any other wrong-conclusion. Doesn't
  scale to an unattended run, but needs no code change.

Not fixed tonight — flagged live to the operator, who redirected the
model directly rather than waiting for it to self-correct (it hadn't,
across one full turn of acting on the false premise already).

## 27. Overnight build: CurlExtractor, the edge-aware DEPG subgraph (#24), and a graded-propagation integration test (2026-10-19/20)

Three of this file's own open items, picked up together per the
operator's standing overnight instruction ("build all changed").

**Built: `CurlExtractor` (closes #26's gap).** curl's catalog entry now
forces `-i` (`cism/agent/tools/catalog.yaml`) so the status line and
headers are always present, and a new `CurlExtractor`
(`cism/depg/extractors.py`) parses them deterministically: the final
`HTTP/x.y <status>` line (last match, in case curl itself followed a
redirect) and the `Location` header produce a `http-redirect`
(`"302 -> index.php"`) or `http-response` (`"200"`) node at T2 — never
infers success/failure itself, only surfaces the fact for the model to
reason from. Also runs the same `_scan_for_credentials` sweep
`GenericExtractor` already does, so a leaked credential in a curl'd body
(e.g. `config.inc.php`) still surfaces alongside the status node. Falls
back to `GenericExtractor` only when no status line is present at all
(a connection failure). This was verified the same night it was
designed: the live Gemma 4 E4B DVWA engagement (below) independently hit
the exact failure mode #26 described — "CSRF token is incorrect" and a
stale `Security Level: impossible` were both only resolvable by reading
`Location`/body text the model's own `curl` calls already had but
GenericExtractor's opaque hash was throwing away.

**Built: the edge-aware `_depg_context` subgraph scoped in #24.**
`_select_subgraph` (`cism/agent/nodes.py`) replaces the flat
per-target slice with the three-tier priority #24 specified: every T1
node unconditionally (never crowded out by recency/state), then a
budget-bounded BFS outward from `graph.last_for_target[target]` over
both `_children` and `_parents` (same traversal shape as
`Graph._weakly_connected`, just not state-restricted), then whatever's
left in the existing unresolved-first order as filler. Shipped as the
flat-but-ordered text format #24 flagged as the smaller first step, not
the indented/structured variant. `_depg_context` now takes
`depg_edges` too (threaded from the one call site in `think()`) and
builds a `Graph.from_state` once per call to get `last_for_target`/
`_children`/`_parents` — no new indexing, reuses what `Graph` already
maintains. Two new tests confirm the behavior the flat cap couldn't
guarantee: a T1 node sorted *last* (resolved, inserted last) still
survives an 8-cap alongside 8 higher-sorting nodes, and two nodes
connected to `last_for_target` win their slots over edge-less orphans
that would otherwise rank first by the resolved/untested sort alone.
All 6 pre-existing `_depg_context` tests pass unchanged against the new
selection logic (verified concretely, not assumed, since several depend
on exactly which nodes get cut by the cap).

**Validated, not rebuilt: `--graded-propagation`.** The reducer math
(`GradedSupport`, `cism/depg/reducer.py`) already had 12 passing unit
tests covering monotonicity/boundary/clamp/idempotence/tier-discount —
but grepping `graded_propagation` across `tests/` before tonight found
zero hits outside the pure-reducer test file, and that file's own
`test_binary_support_stays_the_default...` docstring says outright:
"GradedSupport is opt-in only until validated against a real run." No
real run (or even a `make_depg_update_node`-level integration test) had
ever actually exercised the flag. Added one: a T1 hydra credential
followed by a second same-target call (confirmed elsewhere to get
linked as its child) comes out with a non-default `.reachability` under
`graded_propagation=True`, and stays at the untested-prior `0.3` with
the flag off (default) — the same shape, same two calls, flag is the
only variable. This is the first test that would fail if the
`run_agent.py` → `core.py` → `graph.py` → `nodes.py` wiring chain were
ever silently broken, which nothing before tonight would have caught.
Did not attempt a live GPU A/B run tonight: doing so would have meant a
second concurrent llama.cpp-backed session competing with the live
Gemma 4 E4B DVWA engagement already running on the same box for the
operator to review in the morning, which seemed like the wrong
trade-off to make unilaterally overnight. Recommended next step: a
real `--graded-propagation` run against tonight's actual DVWA findings
shape once the operator can watch for resource contention.

**Live-session note, same engagement this was built next to:** the
operator-driven Gemma 4 E4B DVWA run referenced above reached a genuine,
ground-truth-confirmed UNION-capable SQL injection at `vulnerabilities/
sqli/` (dumped all 5 DVWA users via `id=1' OR '1'='1 -- -`) after two
real, substantive blockers that both needed an operator nudge rather
than self-correcting: (1) it never noticed `Security Level: impossible`
made the module unexploitable by design until told, and (2) after
fixing that, it carried only the `PHPSESSID` cookie forward, not the
`security=low` cookie `security.php` had just set, and separately sent
the GET-only `sqli` form's parameters as a POST `-d` body instead of a
query string — needing a second, more detailed nudge naming both issues
and giving an exact corrected call before it worked. Once corrected, it
read the dumped user list and chose the right next technique
(`ORDER BY` column-count probing ahead of a `UNION SELECT`) entirely on
its own, and separately self-diagnosed a stale-CSRF-token failure
without prompting. Net picture: reliable *within* a technique once
correctly set up, but did not independently notice two real
environment-state facts (`security` cookie semantics, GET-vs-POST on a
specific form) that a `CurlExtractor`-grounded status/redirect view
might make more visible going forward — worth re-testing once this
engagement's own container has the extractor in it, since tonight's
run started before this backlog entry's code existed.

Verification: `pytest -n auto tests/` 948/948 (939 prior baseline + 9
new: 5 `CurlExtractor` cases, 2 `_select_subgraph` cases, 1
`graded_propagation` integration case, 1 catalog-argv update for the
forced `-i`). `graphify update .` run after.

## 28. A second, more severe false-success claim: fabricated content, not just an over-read ambiguous body (2026-10-19/20)

Same live Gemma 4 E4B DVWA engagement, after #27's UNION-column-count
work. It sent `id=1 UNION SELECT 1, version(),3--` with no leading
quote (the *exact* mistake it had just been corrected on for `ORDER
BY`, recurring one technique later) and 3 columns against a table
already confirmed to have 2. The actual response body was
byte-for-byte the normal, unmodified `id=1` result: `First name: admin
<br />Surname: admin` — no version string, no error, nothing
injection-shaped at all, because the unescaped payload was coerced to
the integer `1` by MySQL's loose string/int comparison and never
reached the SQL parser as code.

The model's narration read: *"The `UNION SELECT 1, version(), 3`
attack was successful, and the output confirmed the database version.
This confirms the SQL injection vulnerability and the correct number
of columns (3)"* — then planned its next step (`UNION SELECT 1,
database(), 3`) on that premise. This is categorically worse than
#26's empty-body case: #26 was a wrong conclusion from genuinely
ambiguous evidence (an empty body that really was identical in both
outcomes); this is a specific, checkable claim ("confirmed the
database version") that is flatly false against evidence the model's
own call already had in front of it, in plain readable text, no
`-i`/headers needed. Reading the response at all would have shown the
unchanged admin/admin row.

Caught and corrected live before the model acted further on it
(it had not yet made the follow-up `database()` call). Once given the
corrected payload with the leading quote and the right column count
(`id=1%27%20UNION%20SELECT%201,version()--%20-`), the real result came
back as a genuine second row — `First name: 1<br />Surname:
10.1.26-MariaDB-0+deb9u1` — a real, confirmed UNION-based data
exfiltration.

Not fixed tonight, same as #26 — this is further live evidence for
that entry's open question ("how do we force verification before
acting") rather than a new, separate problem with a different fix.
Worth noting for whoever revisits #26's three candidate options: a
`CurlExtractor`-style deterministic check would not have caught this
one either, since the *response itself* was syntactically fine (a
normal 200, a normal page) — the only thing wrong was the narration's
claim about its content not matching its content. That is a harder
problem than status/header grounding; closer to needing the model (or
a cheap deterministic check) to diff the UNION probe's response
against the baseline single-row response and only call it a hit when
something actually changed, rather than trusting the narration's own
account of what it saw.
