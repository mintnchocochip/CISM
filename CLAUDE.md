## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- Use graphify for every codebase read: before any raw `Read`/`grep` on this repo's source, run `graphify query "<question>"` (or `graphify path "<A>" "<B>"` for relationships, `graphify explain "<concept>"` for a focused concept) when graphify-out/graph.json exists. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep/Read output. Only fall back to a direct Read/grep once graphify has oriented you, or when editing/debugging a specific line it can't resolve (e.g. a local variable).
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
