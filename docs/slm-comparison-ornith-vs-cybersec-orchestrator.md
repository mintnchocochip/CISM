# SLM comparison: Ornith-1.5-9B-MTP-IQ3_M vs NVIDIA-Orchestrator-Cybersecurity-8B-Merged-Q4_K_M

Two local SLMs, same scoped target (DVWA at 172.28.0.2/172.28.0.3, login.php),
same fully-unassisted operating rules: the operator only approves phase
transitions and sends "continue" at the model's own step-limit checkpoints,
never supplies syntax, flags, or injection strings. Both sessions are
otherwise un-coached.

Source data: Ornith's run is the saved engagement report
[`engagement-reports/run6-loose-prompt-b9949a48.md`](../engagement-reports/run6-loose-prompt-b9949a48.md)
(its container no longer exists, so this write-up relies on that report, not
a live re-check). The cybersec-tuned model's run was observed live this
session via `agent.log` and tmux; no corresponding report has been generated
yet.

## Headline result

**Neither model found or exploited an actual SQL injection in DVWA's
login.php in its observed window.** Ornith ran for ~3 real-world hours
without landing a working payload; the cybersec model's test was stopped
after ~20 minutes once it settled into an unproductive loop. Different
failure shapes, same outcome: no confirmed exploit.

## Ornith-1.5-9B-MTP-IQ3_M

- **Duration:** ~3 hours wall clock (01:29 → 04:25 UTC), all four PTES phases
  entered within the first 2 minutes, then the entire remaining ~3 hours
  spent inside `exploitation` grinding on `login.php`.
- **Approach:** broad and varied — dozens of distinct curl payload variants
  against `login.php` (`union select`, `' or '1'='1`, URL-encoded quotes,
  comment-based bypasses), plus nikto/whatweb/gobuster/wafw00f runs earlier.
  It kept generating new attempts rather than repeating the same one, which
  is the opposite failure shape from the cybersec model.
- **Failure mode:** almost entirely mechanical/syntax-level, not reasoning-level.
  Confirmed, reproducible curl malformation (raw unescaped characters in
  `-G -d` values), a persistent habit of writing `&amp;` instead of `&` in
  query strings, and no instance of actually sending the DVWA session +
  security cookies together — each of these alone is enough to make a
  correctly-targeted SQLi payload fail at the transport layer before the
  vulnerable code is ever reached.
- **Extraction/report quality:** poor. The saved report is full of garbled,
  hallucinated finding summaries from the DEPG extraction layer — e.g. "Port
  4 JSON is open", "the-line-bested", "HTTP  curl" — and duplicate/contested
  entries. This is a known weakness of the extraction step independent of
  the base model, but it did make this report noisier and harder to trust
  than the cybersec model's cleaner (if sparser) output.
- **Token cost:** the report's own `tokens_total` metric reads 124,030 —
  but that metric is captured at the final `RunFinished` of the session, and
  it's unclear from the report alone whether it's cumulative over the whole
  3-hour engagement or just the last run. Treat this number as directional,
  not as a clean per-turn comparison point against the cybersec model below.

## NVIDIA-Orchestrator-Cybersecurity-8B-Merged (Q4_K_M)

- **Duration:** ~20 minutes observed, stopped deliberately by the operator
  after it failed to escape a stuck pattern even after two explicit
  corrective redirects.
- **Approach:** narrower and more "textbook" at the start — its first move
  against `login.php` was `sqlmap --batch --forms --crawl=2 --risk=3`, a
  genuinely well-chosen, appropriately aggressive command for finding an
  injection point, and more decisive than Ornith's manual curl-permutation
  grind.
- **Failure mode:** reasoning-level, not syntax-level. It attached
  `--tamper=space2comment` to that sqlmap call, which the sandbox's
  dangerous-flag-guard blocks (any `--tamper` script can read/write outside
  the sandbox's scratch dir). It then repeated the identical blocked call
  three times. After a strategic redirect ("stop retrying `--tamper`, try a
  different approach"), it swapped in `--tamper=htmlentitize` — reading the
  redirect as "try a different value for the flag I was told to stop using"
  rather than "stop using that flag family." It then fell into a two-state
  oscillation: an identical, already-failed `curl --data 'username=admin'`
  call (no password, no CSRF-token reuse, no session cookie — strictly
  no new information each time) alternating with the same blocked sqlmap
  call. A second, more explicit redirect naming both stuck behaviors
  directly did not break the pattern either — its very next move was the
  same blocked `--tamper=htmlentitize` flag with an unrelated `--dbms=mysql`
  appended, cosmetically different but functionally identical.
- **Extraction/report quality:** clean in what little it extracted — no
  garbled summaries observed, DEPG findings matched the actual tool output.
  Too short a run to call this a strong signal either way.
- **Token/latency cost:** ~11,400–13,800 tokens and ~45–90 seconds *per single
  tool-call turn* (confirmed directly from `RunFinished.tokens_total` on
  four consecutive single-tool-call runs). For a model meant to run on
  consumer hardware, that's a lot of compute spent per unit of forward
  progress, especially once it stopped making forward progress at all.

## What this actually tells us

1. **Domain fine-tuning bought better tool selection, not better self-correction.**
   The cybersec model's opening sqlmap call was better-judged than anything
   Ornith tried in 3 hours. But the moment it hit a guardrail, it couldn't
   generalize "this flag is blocked" into "stop trying variants of this
   flag" — even when told so explicitly, twice. That's a more concerning gap
   for an *autonomous* agent than Ornith's syntax clumsiness, because syntax
   errors are visible and typically self-correct with retries across
   different approaches, whereas this was a genuine inability to update
   behavior from direct feedback.
2. **Ornith's failures are the kind more tooling can fix; the cybersec
   model's are not.** Ornith's blockers (HTML-entity escaping, missing dual
   cookies, raw-space URL malformation) are exactly the class of thing
   structured tool schemas and curl-builds-the-query-string patterns already
   mitigate elsewhere in this project (see `BACKLOG.md`). The cybersec
   model's blocker — ignoring explicit correction and re-trying a cosmetically
   modified version of a blocked action — isn't a tooling gap; it's a
   planning/memory gap. No schema change fixes "doesn't track what it just
   tried and failed."
3. **Neither result supports switching to the cybersec-tuned model as-is.**
   It isn't faster (first real finding of comparable value hasn't happened
   in either run within the observed windows) and it isn't more reliable
   once it needs to recover from a blocked action, which is a routine event
   in a sandboxed pentest agent, not an edge case.
4. **Open question, not yet tested:** whether the stuck-loop behavior is a
   quantization artifact (Q4_K_M) rather than a property of the fine-tune
   itself. A less-aggressive quant of the same cybersec model would be the
   cheapest next experiment to isolate that variable, same as the earlier
   quantization-vs-parameter-count discussion concluded.

## Caveats

- Sample size is one run each, not a statistically meaningful benchmark.
- The two runs differ a lot in length (3 hours vs ~20 minutes) by
  circumstance, not by design — Ornith's run wasn't cut short, the cybersec
  model's was, specifically because it had stopped making any progress.
- Token-cost figures aren't on a clean common basis between the two models
  (see note above); don't quote a precise ratio from this document.
