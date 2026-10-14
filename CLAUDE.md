## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- Use graphify for every codebase read or search: before any raw `Read`/`grep` on this repo's source, run `graphify query "<question>"` (or `graphify path "<A>" "<B>"` for relationships, `graphify explain "<concept>"` for a focused concept) when graphify-out/graph.json exists. This applies to ANY search or lookup across this repo — not just reads before edits. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep/Read output. Only fall back to a direct Read/grep once graphify has oriented you, or when editing/debugging a specific line it can't resolve (e.g. a local variable).
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

## Comments

Keep comments minimal. Don't add explanatory comments to every function — only comment where the WHY is genuinely non-obvious (a hidden constraint, a workaround, a subtle invariant). Prefer 1-2 lines max when a comment is warranted.

## Tests

Run pytest in parallel, not sequentially: use `pytest -n auto` (pytest-xdist is installed). Only drop to sequential (no `-n`) when debugging a single failing test in isolation.

Don't write or run tests for every change by default. A prompt/wording change, a comment, a trivial one-line fix, or anything that can't realistically break does not need a new test or a test run. Only test when the change adds real logic (branching, a new code path, a retry/state mechanism) or when you suspect an actual flaw — then scope the run to the affected file(s), not the full suite.
