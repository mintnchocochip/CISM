# CISM code-quality review — hardening-pass changes

**Date:** 2026-09-23
**Scope:** the code added/changed in the recent hardening passes (AUDIT.md items
A1–A3, B2, B3, B5, C1, D2, D3, D5, E1, E2, E3, H1, H2, B6). The pre-existing
codebase is covered by `AUDIT.md`; this report only covers the *new* code, which
had not been independently reviewed.
**Method:** manual read of each changed hunk + live reproduction of every
correctness/security finding below (repro commands included).
**For:** junior agents to pick up and fix. Each finding is self-contained:
what's wrong → repro → why the tests didn't catch it → the fix → the test to add.

Severity key: **S1** the fix silently fails to do its job on realistic input ·
**S2** wrong/misleading behavior or observability · **S3** robustness/style.

The recurring theme: **several fixes pass their tests but don't work on realistic
input, because the tests only exercised the happy path.** Fixing the code without
also adding the missing test just re-opens the hole later. Every S1 item below
ships with the test that should have existed.

---

## S1 — fixes that silently don't work on realistic input

### Q1. `OutputRedactionStage` only redacts space-delimited secrets (C1)
- **Where:** `cism/agent/guardrails/output_redaction.py` → reuses
  `cism/tui/redact.py::redact_command`.
- **Problem:** `redact_command` was written for a single composer *command line*;
  it does `text.split(" ")` and masks per space-delimited word. Reused verbatim
  for the output guardrail, it never sees a credential that is newline- or
  tab-delimited — which is how real tool output and LLM answers are structured
  (HTTP headers, key/value dumps, JSON, env listings).
- **Repro (confirmed):**
  ```
  from cism.agent.guardrails.output_redaction import OutputRedactionStage
  s = OutputRedactionStage()
  s.check('key is sk-ant-abcdefghijklmnopqrstuvwxyz').value      # → masked ✓
  s.check('Authorization:\nsk-ant-abcdefghijklmnopqrstuvwxyz').value  # → NOT masked ✗
  s.check('token\tsk-ant-abcdefghijklmnopqrstuvwxyz').value      # → NOT masked ✗
  ```
- **Why it matters:** this stage is the *only* thing enforcing "no secret in the
  final answer" in the pipeline (the TUI redactor is display-only, per C1's own
  rationale). A key on its own line sails through. The stage gives false
  assurance.
- **Why the tests missed it:** `tests/test_output_redaction.py` only tested a
  space-delimited secret (`'your api key is sk-ant-...'`).
- **Fix:** don't reuse the command-line tokenizer for free text. Tokenize on any
  whitespace (`re.split(r'(\s+)', text)` keeping separators so the text can be
  rejoined losslessly), run `looks_like_secret` on each non-whitespace token, and
  mask. Keep `redact_command` as-is for the composer; add a separate
  `redact_text` for multi-line output, or have the stage call a whitespace-aware
  helper.
- **Test to add:** parametrized over space/newline/tab/CRLF-delimited secrets and
  a secret as a bare JSON value (`"token":"sk-..."`), asserting each is masked.

### Q2. Prompt compaction ignores tool-call payloads → never triggers for tool-heavy runs (B2)
- **Where:** `cism/agent/nodes.py::_compact_history` / `_estimate_tokens`.
- **Problem:** cost per message is `_estimate_tokens(str(message.content))`. An
  `AIMessage` that carries a large `tool_calls=[...]` but empty `content`
  estimates as **0 tokens**. `ToolMessage` metadata and per-message role overhead
  are likewise uncounted. So exactly the conversation B2 exists to bound — a
  multi-tool run — is under-counted and never compacted.
- **Repro (confirmed):**
  ```
  ai = AIMessage(content='', tool_calls=[{'id':'c1','name':'nmap',
        'args':{'extra':'x'*4000}}])
  _estimate_tokens(str(ai.content))            # → 0
  _compact_history([ai]*50, 'sys', 1000)       # → dropped=0  (should drop most)
  ```
- **Why it matters:** AUDIT.md B2's own problem statement is "a multi-tool run
  overflows a small local context within a few steps." The fix doesn't measure
  the tool calls that make up that run, so the overflow it was written to prevent
  still happens.
- **Why the tests missed it:** both B2 tests in `tests/test_nodes.py` used plain
  `HumanMessage(content=...)` with real string content; none used a tool-call
  message.
- **Fix:** estimate cost from the whole serialized message, not just `.content`.
  Cheapest correct-enough version: include `str(getattr(m, "tool_calls", ""))`
  and any `ToolMessage` fields in the char count; add a small fixed per-message
  overhead. Better: reuse whatever serialization actually goes on the wire.
- **Test to add:** a conversation of empty-content, fat-`tool_calls` AIMessages
  against a small `context_window`, asserting `dropped > 0`.

### Q3. `_CappedReader` swallows reader-thread failures and returns partial output as complete (D3)
- **Where:** `cism/agent/tools/sandbox.py::_CappedReader._read` /
  `_run_capped`.
- **Problem:** `_read` runs in a daemon thread with **no try/except**. If
  `stream.read1()` raises (e.g. the fd is closed under it — possible when a
  grandchild keeps the pipe open past the kill and the stream is later closed),
  the thread dies with a stderr traceback and `result()` returns whatever was
  buffered so far. Separately, in the success path `reader.join(timeout=5.0)` can
  *time out* (a detached child holding the write end); the code then calls
  `reader.result()` unconditionally and returns **partial output as if it were
  the complete, successful tool result** — no error, no marker, and for a
  non-zero exit it feeds that truncated text into `ToolExecutionError`.
- **Why it matters:** silent truncation of tool output presented as complete
  corrupts everything downstream — DEPG extraction, the audit log, the model's
  own reasoning — with no signal that anything was lost.
- **Why the tests missed it:** no test exercises a reader-thread exception or a
  join-timeout; the timeout tests all hit the clean-EOF-after-kill path.
- **Fix:** wrap `_read`'s loop body in `try/except Exception` and record the
  failure on a `self.error` field; in `_run_capped`, if `join` times out or
  `reader.error` is set, treat it as a failed/incomplete read (raise, or append
  an explicit `[output truncated: reader did not drain]` marker) rather than
  silently returning `result()`.
- **Test to add:** a fake stream whose `read1` raises after N chunks → assert the
  runner surfaces an error rather than returning the partial buffer.

---

## S2 — wrong or misleading behavior / observability

### Q4. Overflow-kill reports itself as a wall-clock timeout (D3)
- **Where:** `sandbox.py::_run_capped` — on `reader.overflowed` it raises
  `ToolTimeoutError(argv, timeout)`.
- **Problem:** a tool that floods `_OVERFLOW_FLOOR` (10 MB) in two seconds is
  killed for *volume*, but the raised error message is
  `"<tool>: timed out after 30s"`. The audit log will say "timed out" for what
  was actually an output flood — a junior debugging it chases the wrong cause.
- **Fix:** distinguish the two. Either a new `ToolOutputOverflowError` (preferred
  — it's a distinct failure class) or at minimum pass a reason so the message
  reads "aborted: produced >10MB" instead of a false timeout. Keep both handled
  uniformly by callers if that's the concern.
- **Test to add:** the runaway-writer test already exists; extend it to assert the
  error *type/message* reflects overflow, not timeout.

### Q5. `result()` labels byte counts as "chars" and can mangle a char at the split (D3)
- **Where:** `sandbox.py::_CappedReader.result`.
- **Problem:** `omitted = self.total - len(self._buf) - len(tail)` is a **byte**
  count rendered as `[{omitted} chars omitted]`. The old `_cap` operated on the
  decoded `str`, so its count was true characters. Also `bytes(self._buf)` is
  sliced at an arbitrary byte offset (`self._half`), so a multibyte UTF-8
  sequence straddling the head/tail boundary decodes to a replacement char.
- **Why it matters:** low-stakes (tool output is mostly ASCII, `errors="replace"`
  prevents a crash), but the message is inaccurate and the head/tail boundary is
  silently lossy — the kind of imprecision the "sloppy" comment is about.
- **Fix:** either say "bytes omitted" (honest), or decode first and cap on the
  decoded string for a true char count. If keeping byte buffers, snap the split
  to a UTF-8 boundary.

---

## S3 — robustness / style

### Q6. Tool-output wrap is one-sided — no closing fence (C1)
- **Where:** `cism/agent/guardrails/tool_output.py::ToolOutputScreenStage.check`
  returns `f"{prefix}\n{value}"`.
- **Problem:** the untrusted content is appended after an *opening* marker with no
  closing delimiter or nonce, so injected output can write its own
  `"[END UNTRUSTED]\nSYSTEM: ..."` and forge a trusted region. Confirmed: the
  wrap adds a prefix only.
- **Why it's S3 not S1:** this is defense-in-depth on top of the scope/action
  guards, and the injection markers still fire; but a one-sided fence is weak.
- **Fix:** wrap with a start *and* end fence built around an unguessable per-call
  nonce, and state in the prefix that everything up to `<nonce>` is data. Strip
  any occurrence of the nonce from `value` first.

### Q7. Unsynchronized cross-thread flag read (D3)
- **Where:** `_run_capped` reads `reader.overflowed` while the reader thread
  writes it; `reader.total` similarly.
- **Problem:** GIL-atomic in CPython today, so it works, but it relies on that and
  isn't documented. If the read loop is ever refactored to compute on `total`
  mid-flight, `+=` (load-add-store) is not atomic.
- **Fix:** a `threading.Event` for `overflowed` is the clean expression of
  intent; or document the GIL reliance explicitly. Low priority.

### Q8. `_extra_parents` label is ambiguous when parents share a cause-class (E2)
- **Where:** `cism/tui/widgets/depg_modal.py::node_label` renders
  `f"{p.cause_class}@{w:.2f}"` per extra parent.
- **Problem:** two upstream parents with the same `cause_class` render as e.g.
  `(+2 more: open-port@0.40, open-port@0.30)` — indistinguishable. The tree body
  disambiguates sibling nodes with `(signal)` for exactly this reason; the extra-
  parents line dropped it.
- **Fix:** include the parent's `signal` (or a short id) in the extra-parent
  label, matching how `node_label` already disambiguates siblings.

### Q9. Compaction: minor budget/format nits (B2)
- The prepended `"[N earlier turn(s) omitted...]"` `SystemMessage` consumes tokens
  but isn't subtracted from the budget — the prompt can exceed the budget by that
  note's size. Negligible, but note it.
- `cism/agent/nodes.py`: only one blank line separates `_compact_history` (ends
  L69) from the following `#:` block (L71); PEP 8 wants two between top-level
  defs. Cosmetic, but it's the kind of thing a linter would catch — see Q10.

### Q10. No linter/formatter/type-checker is wired up
- **Where:** `pyproject.toml` has no `ruff`/`black`/`mypy` config, and none are
  installed in the venv.
- **Why it matters:** every style/consistency nit in this review (and Q9's blank
  line, unused-import risk after refactors, the `Runner` protocol's `max_output`
  default drift) is exactly what a linter catches for free. For a security-
  adjacent codebase, a type-checker would also have flagged the `proc.stdout`
  (`IO | None`) access in `_run_capped`.
- **Fix:** add `ruff` (lint + format) and `mypy` to the `[dev]` extras and a
  minimal config; wire into the test command. Do this first — it will surface a
  batch of the smaller items mechanically.

---

## Test-rigor summary (cross-cutting)

The three S1 findings share one root cause: **tests asserted the happy path and
stopped.** When fixing Q1–Q3, the acceptance bar is *the added test fails against
the current code and passes after the fix* — not just "the suite is green."

| Fix | Test that exists | Test that was missing |
|-----|------------------|-----------------------|
| C1 output redaction | space-delimited secret masked | newline/tab/JSON-value secret (Q1) |
| B2 compaction | plain-content turns dropped | fat-`tool_calls` turns dropped (Q2) |
| D3 capped reader | clean EOF + runaway kill | reader-thread failure / join-timeout (Q3) |

Suggested order for a junior: **Q10 first** (wire the linter, mechanical cleanup),
then **Q1, Q2, Q3** (real holes, each with its repro above), then Q4–Q9.
