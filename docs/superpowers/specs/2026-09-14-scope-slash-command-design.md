# `/scope` slash command — design

## Motivation

Engagement scope (`--scope`, comma-separated CIDRs/domains) is currently
parsed once by `run_agent.py` and baked into a `ScopeGuardStage` at process
start (`cism/agent/tools/... → _enable_live_tools`). There is no way to
extend it — or even see what it currently is — without restarting the whole
TUI session. That's a real gap for a multi-target engagement whose scope
grows mid-session (a client adds a host, a second domain comes into scope),
and it's also just confusing on its own: `/target` looks like it might set
the authorized target but is actually an unrelated free-text DEPG label
(`cism/agent/guardrails/scope.py`'s own module docstring already calls this
out), so there is currently no in-TUI way to reason about what's actually
authorized.

This adds `/scope`, `/scope add <target[,target...]>`, and
`/scope remove <target[,target...]>` as a live, audited way to manage the
engagement scope for the rest of the session — without ever letting the
agent touch a host that wasn't explicitly named.

**Out of scope:** persistence across a process restart (scope is still
process-lifetime only, same as today); any UI beyond a transcript line
(no status-bar field); undo/history beyond what the audit log already
records.

## Data model (`cism/agent/guardrails/scope.py`)

- `EngagementScope` gains two pure methods, staying frozen/immutable:
  - `.add(other: EngagementScope) -> EngagementScope` — union of
    `cidrs`/`domains`, de-duplicated, order-preserving.
  - `.without(token: str) -> tuple[EngagementScope, bool]` — removes one
    exact CIDR or domain (parsed the same way `parse_scope` parses a single
    token); the `bool` says whether anything was actually removed, so the
    caller can tell "removed" from "wasn't there."
  - `.entries() -> tuple[str, ...]` — `cidrs` as strings, followed by
    `domains`, for listing.
- `parse_scope(value: str) -> EngagementScope` is extracted from
  `run_agent.py`'s private `_parse_scope` (same CIDR-vs-domain-per-token
  logic, comma-separated) and made public here — this is guardrail domain
  logic, not CLI logic. `run_agent.py` imports and calls it instead of
  defining its own copy. The 5 existing tests in `tests/test_run_agent.py`
  that import `_parse_scope` from `run_agent` are repointed to import
  `parse_scope` from `cism.agent.guardrails` — a straight rename, not a
  compatibility shim.
- `ScopeGuardStage` gains `.expand(addition: EngagementScope) -> None`,
  `.contract(token: str) -> bool`, and a `.scope` read property — the
  single place scope actually mutates at runtime (it already holds
  `self._scope` as a private, non-frozen attribute).

## Command handling (`cism/agent/core.py`)

`LangGraphAgent.submit()` gains `/scope`, dispatched to a new `_set_scope`
handler, same shape as the existing `_set_target`/`_set_phase`.

`_set_scope` looks for a `ScopeGuardStage` inside
`self._guardrails.action.stages`. Behavior:

- **No such stage** (no `--live-tools`): a plain `Narration` — `/scope`
  requires `--live-tools`, since there is no real guard to change. No
  silent no-op.
- **Bare `/scope`**: `Narration` listing `guard.scope.entries()`, or
  `"(empty — every live-tool call will be blocked)"`.
- **`/scope add <target[,target...]>`**: parses via `parse_scope`, calls
  `guard.expand(...)`. If the parse produced nothing usable, a `Narration`
  error. Otherwise, one `ScopeChanged(action="add", target=...)` event per
  token actually added — granular, so the audit log shows exactly which
  targets were authorized and when, not just "scope changed."
- **`/scope remove <target[,target...]>`**: for each comma-separated
  token, calls `guard.contract(token)`; a real removal emits
  `ScopeChanged(action="remove", target=token)`, a miss emits a
  `Narration` saying that token wasn't in scope (not an error — just
  informational, same tone as `/phase`'s unknown-phase message).
- **Anything else** (unrecognized subcommand): a `Narration` error naming
  `add`/`remove`/bare-list as the valid forms.

## New event + rendering

`cism/tui/events.py` gains `ScopeChanged(action: str, target: str)` —
wired into `AgentEvent`, `EVENT_TYPES`, `__all__`, same boilerplate every
existing event already has, so it's automatically audited (via
`LangGraphAgent._emit`) and replayable.

`cism/tui/app.py`'s `_apply` renders it as one transcript line via the
existing `transcript.add_note()` (no new widget):
`"scope: added <target>"` / `"scope: removed <target>"`.

## Slash-command discovery

`cism/tui/widgets/slash.py`'s `COMMANDS` gains
`SlashCommand("scope", "[add|remove] <target>", "view or extend the live engagement scope")`.

## Testing

- `tests/test_scope_guard.py`: `EngagementScope.add`/`.without`/`.entries`,
  `ScopeGuardStage.expand`/`.contract`/`.scope`.
- `tests/test_run_agent.py`: repoint the 5 `_parse_scope` tests to the
  shared `parse_scope`.
- `tests/test_langgraph_agent.py`: `_set_scope` — bare list (empty and
  non-empty), add (single and comma-list), remove (hit and miss), unknown
  subcommand, and the no-`--live-tools` refusal; assert `ScopeChanged`
  actually reaches `self.events` (and therefore the audit log).
- `tests/test_app.py`: a `ScopeChanged` event renders as a transcript
  note with the right text for both `add` and `remove`.
