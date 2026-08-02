# CISM TUI — iteration 2

Date: 2026-08-02
Status: approved
Supersedes nothing; extends `2026-08-02-cism-tui-design.md`.

## Why

Feedback after the first demo run:

1. The spinner animation reads badly.
2. The status line should carry model, context window, token speed, and
   memory stats.
3. Slash commands should be able to switch models, configure the inference
   endpoint, and declare target environment context.
4. Selecting a DEPG node should show the decision points that led to it, not
   only the evidence for it.

## 1. Spinner

The existing set is `· ✢ ✳ ✶ ✻ ✽`. Two defects, both measured:

- `·` (U+00B7) and `✽` (U+273D) are East Asian Width **Ambiguous**, so a
  terminal may render them double-width. The line shifts horizontally as the
  animation cycles.
- The glyphs are four unrelated shapes with very different visual mass, so the
  result reads as an erratic flicker rather than rotation.

Replaced with the braille orbit `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` at 80 ms. Every glyph is
Neutral width and identical mass; it is one shape rotating.

A test asserts each glyph is cell-width 1 and not EAW-Ambiguous, so this class
of regression cannot return. The `⏺` tool glyph and the accent colour are
unchanged.

## 2. Status bar

Segments gain a short form and a priority. Rendering tries every segment at
full width; on overflow it degrades to short forms worst-priority-first, then
drops whole segments. Priority-1 segments are never dropped. The line never
wraps and never truncates mid-token.

| Segment | Full | Short | Priority |
|---|---|---|---|
| model | `qwen2.5-7b` | `qwen2.5-7b` | 1 |
| phase | `phase: recon` | `recon` | 1 |
| context | `ctx 12.4k/32k (38%)` | `ctx 12.4k/32k` | 1 |
| mode | `⏵⏵ auto` | `⏵⏵` | 1 |
| tok/s | `47 tok/s` | `47t/s` | 2 |
| target | `linux·nginx` | `linux` | 2 |
| depg | `depg 47 nodes` | `depg 47` | 3 |
| memory | `mem T1:8 T2:31 T3:5` | `mem 44` | 3 |

Segments with no value are omitted entirely: tok/s only while a run is
producing tokens, target only once declared.

The elision logic is a pure function over `(full, short, priority)` tuples and
an available width, so it is unit-testable without mounting a widget.

**Token speed requires no contract change.** It is computed in the TUI from a
sliding window over `TokenDelta` events. Rate is a display concern; the agent
should not have to report it.

## 3. Session state

`/model`, `/target` and `/api` change agent state, so they are forwarded. The
TUI needs to display the result, which requires one new event.

```python
@dataclass(frozen=True, slots=True)
class ModelInfo:
    name: str
    params: str = ""        # "7B"
    context: int = 0        # tokens
    loaded: bool = False

@dataclass(frozen=True, slots=True)
class SessionState(_Event):
    model: str = ""
    models_available: tuple[ModelInfo, ...] = ()
    endpoint: str = "local"
    key_env_var: str = ""
    key_present: bool = False
    target_os: str = ""
    target_stack: tuple[str, ...] = ()
```

`/models` and a bare `/api` render locally from the last `SessionState` — no
round trip. `/model <name>`, `/target <spec>` and `/api <url>` forward.

### Credential handling

The TUI never accepts, stores, or displays an API key.

`/api` shows the endpoint URL, the *name* of the environment variable that
holds the key, and whether that variable is set — never its value. If the
argument to `/api` looks like a credential, the command refuses and points at
the environment variable instead.

This matters more than usual here: the transcript is exported with `/export`
and pasted into reports, and command history is recalled with the arrow keys.
A key typed into the composer would end up in both.

Detection is deliberately broad — known prefixes (`sk-`, `ghp_`, `xox`,
`bearer`, …) or any bare 24+ character token of URL-unsafe-free characters. A
false positive costs the user one retype; a false negative leaks a key into a
report.

## 4. DEPG decision path

New value object, attached to the **node**. The trail to any node is then the
decisions along its root-to-node path, with nothing duplicated per edge.

```python
@dataclass(frozen=True, slots=True)
class Decision:
    timestamp: str
    chose: str
    alternatives: int    # how many were rejected
    score_gap: float     # delta to the runner-up
    tokens: int          # what the decision cost
    rationale: str = ""
```

`DEPGNode` gains `decision: Decision | None = None`.

The modal rebalances from 62/38 to 50/50. The right half splits vertically:
decision path on top, evidence below. Moving the tree cursor recomputes both.

The tree itself, the node label format, the colour-by-state rule, and the
"no force-directed layout" constraint are unchanged.

## Contract compatibility

Every change is additive. No existing event changes shape, no field is
removed or renamed, and both new fields default. A producer written against
iteration 1 still drives this UI correctly; it simply never populates the
decision pane or the model segment.

## Out of scope

`/scope <cidr>` was considered and dropped. Engagement-scope enforcement
belongs in the agent, not the display layer, and a status-bar badge implying
enforcement the TUI does not perform would be worse than nothing.

## Testing

- Spinner glyph width and EAW invariants.
- `elide()` at several widths, asserting priority-1 survival and that output
  never exceeds the budget.
- Decision-path derivation for a root node, a leaf, and a detached node.
- `/models` and bare `/api` render without touching the agent; `/model`,
  `/target` and `/api <url>` forward.
- `/api` with a credential-shaped argument is refused, nothing is echoed, and
  the argument does not appear in the exported transcript.
- Snapshots regenerated for the new status bar, spinner, and DEPG pane.
