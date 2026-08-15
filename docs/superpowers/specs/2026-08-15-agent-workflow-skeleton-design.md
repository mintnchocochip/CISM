# Agent workflow skeleton — LangGraph core, DEPG domain model, tool & guardrail seams

Date: 2026-08-15
Status: approved

## Why

`cism/tui/events.py` already defines the seam a real agent must satisfy —
the `Agent` protocol (an `asyncio.Queue[AgentEvent]` plus
`start`/`submit`/`interrupt`/`aclose`) — and `FakeAgent` proves the seam
works by replaying a recorded log through it. Nothing that actually thinks
exists yet.

The goal here is a runnable skeleton for that missing half: a
LangGraph-backed core wired to the existing `Agent` protocol, driven by a
canned/dummy model and dummy tools so the loop itself can be validated with
no lab, no weights, and no network — matching the philosophy
`demo_replay.py` already established for the TUI side. Guardrails
(input/output/action) and real tools come later, once the loop shape is
proven; this skeleton exists so that later work is additive rather than a
rewrite.

Separately, a minimal DEPG domain model (`Node`/`Edge`) is scaffolded so the
dependency/error-propagation graph has a place to live that's independent of
both the agent loop and the TUI's frozen wire-format dataclasses.

## Out of scope

- Real guardrail logic (scope checks, prompt-injection detection, output
  filtering). Only the seam — chains wired at three points, each a
  pass-through — is built now.
- Real tools (actual nmap/msfconsole invocation). Only dummy, canned-output
  tools.
- A real inference backend. The model is a canned/deterministic LangChain
  chat model; wiring a real llama.cpp/OpenAI-compatible endpoint is later
  work, deliberately decoupled by depending only on LangChain's chat-model
  interface.
- DEPG propagation math (generality/γ computation), graph traversal, or a
  graph container class. Only `Node` and `Edge` as data.
- Phase locking implementation. Only ensuring `PhaseStateMachine` has a
  single choke point that locking can hook into later.
- Wiring `LangGraphAgent` into `demo_replay.py` or the live TUI app. This
  spec produces a component that satisfies the `Agent` protocol and is
  tested in isolation; swapping it in for `FakeAgent` is a separate,
  later step.

## Architecture

Two new top-level packages. Both depend on `cism/tui/events.py` for the
wire-format dataclasses; `cism/tui/` depends on neither of them, preserving
the existing rule that nothing under `cism/tui/` calls into LangGraph.

```
cism/depg/                  domain model — mutable, agent-side source of truth
  __init__.py                 exports Node, Edge (only — see "Left open")
  node.py                     Node dataclass + to_event()
  edge.py                     Edge dataclass + to_event()

cism/agent/                 orchestration — implements the Agent protocol
  __init__.py                 exports LangGraphAgent
  core.py                     LangGraphAgent: owns the queue, runs the graph,
                               translates graph steps -> AgentEvent
  state.py                    Phase(Enum), PHASE_TRANSITIONS, PhaseStateMachine,
                               IllegalPhaseTransition, AgentState (TypedDict)
  graph.py                    build_graph(llm, tools, guardrails) -> compiled graph
  nodes.py                    think / act / phase_router node functions
  llm.py                      DummyChatModel (LangChain BaseChatModel)
  logging.py                  DailyRotatingLogger, get_agent_logger()
  tools/
    __init__.py
    registry.py                ToolRegistry (hard allowlist)
    dummy.py                    dummy_nmap, dummy_msfconsole (@tool)
  guardrails/
    __init__.py
    chain.py                    GuardrailStage, GuardrailChain, GuardrailResult,
                                 PassThroughStage
```

`cism/agent/` depends on `langgraph` and `langchain-core`. These are added
as a new `agent` extras group in `pyproject.toml`, not a base dependency —
a TUI-only install stays lightweight, mirroring the existing "no lab, no
weights, no network" promise for the replay demo. `cism/depg/` has no such
dependency at all; it is plain dataclasses plus a projection method.

## Components

### Phase & state machine (`cism/agent/state.py`)

```python
class Phase(Enum):
    RECON = 1
    ENUMERATION = 2
    VULNERABILITY_DISCOVERY = 3
    EXPLOITATION = 4
    POST_EXPLOITATION = 5
    REPORTING = 6
```

Transitions are an explicit table, not a free-for-all — realistic engagement
pivots (post-exploitation on host A kicking off recon on host B; a failed
exploit sending you back to vulnerability discovery) are legal, but nothing
outside the table is:

```python
PHASE_TRANSITIONS: dict[Phase, frozenset[Phase]] = {
    Phase.RECON: frozenset({Phase.RECON, Phase.ENUMERATION}),
    Phase.ENUMERATION: frozenset({Phase.ENUMERATION, Phase.VULNERABILITY_DISCOVERY, Phase.RECON}),
    Phase.VULNERABILITY_DISCOVERY: frozenset({Phase.VULNERABILITY_DISCOVERY, Phase.EXPLOITATION, Phase.ENUMERATION}),
    Phase.EXPLOITATION: frozenset({Phase.EXPLOITATION, Phase.POST_EXPLOITATION, Phase.VULNERABILITY_DISCOVERY}),
    Phase.POST_EXPLOITATION: frozenset({Phase.POST_EXPLOITATION, Phase.REPORTING, Phase.RECON}),
    Phase.REPORTING: frozenset({Phase.REPORTING}),  # terminal
}
```

`PhaseStateMachine` wraps a current `Phase` and this table:

```python
class IllegalPhaseTransition(ValueError): ...

class PhaseStateMachine:
    def __init__(self, start: Phase = Phase.RECON): ...
    @property
    def current(self) -> Phase: ...
    def can_transition(self, to: Phase) -> bool: ...
    def transition(self, to: Phase) -> Phase:
        """The single choke point for every phase change. Raises
        IllegalPhaseTransition rather than allowing an out-of-table move.
        Future phase-locking is a check added at the top of this method
        alone — every call site already routes through it."""
```

`state.py` also owns `AgentState`, the LangGraph state schema:

```python
class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    phase: Phase
    depg_nodes: dict[str, Node]
    depg_edges: list[Edge]
    run_id: str
    target: str
```

Note on wire compatibility: `PhaseChanged.phase` (in `cism/tui/events.py`)
is a plain string. The conversion is `phase.name.lower().replace("_", "-")`,
so `VULNERABILITY_DISCOVERY` becomes `"vulnerability-discovery"` — not the
README's illustrative `"vulnerability-analysis"`. That README line was prose
example, not a contract; flagging the divergence as a conscious choice.

### DEPG domain model (`cism/depg/`)

```python
# node.py
@dataclass(slots=True)
class Node:
    id: str
    cause_class: str
    target: str
    generality: float = 0.0
    state: NodeState = "untested"          # reuses tui.events.NodeState
    downstream: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    decision: Decision | None = None

    def to_event(self) -> events.DEPGNode: ...

# edge.py
@dataclass(slots=True)
class Edge:
    parent: str
    child: str
    weight: float = 1.0

    def to_event(self) -> events.DEPGEdge: ...
```

Deliberately not frozen (unlike the TUI's wire-format dataclasses) — this is
the mutable working copy the agent updates as a run progresses.
`to_event()` is the *only* place either class touches `cism.tui.events`;
`LangGraphAgent` calls it to build `DEPGUpdated` (whole-state replacement,
per the existing contract) whenever DEPG state changes.

**Left open on purpose.** `cism/depg/__init__.py` exports only `Node` and
`Edge`. The package has zero import from `cism/agent/`, so the graph
container, traversal, and propagation/γ math that come later are new files
in this same package (`graph.py`, `propagation.py`) — DEPG stays
independently testable and evolvable without touching the agent loop. Since
`to_event()` is the sole conversion point, the domain model can grow fields
with no wire-format equivalent (they're simply not included in `to_event()`)
without ever breaking `DEPGUpdated`'s shape.

### Guardrail seam (`cism/agent/guardrails/chain.py`)

Chain of responsibility, generic over payload type so one runner serves all
three seams:

```python
T = TypeVar("T")

@dataclass(frozen=True, slots=True)
class GuardrailResult(Generic[T]):
    allowed: bool
    value: T
    reason: str = ""

class GuardrailStage(Protocol[T]):
    name: str
    def check(self, value: T) -> GuardrailResult[T]: ...

class GuardrailChain(Generic[T]):
    def __init__(self, stages: list[GuardrailStage[T]]): ...
    def run(self, value: T) -> GuardrailResult[T]:
        """Runs stages in order. The first stage to block wins and short-
        circuits the rest; a passing stage may transform the value before
        the next stage sees it."""

class PassThroughStage(Generic[T]):
    name = "pass-through"
    def check(self, value: T) -> GuardrailResult[T]:
        return GuardrailResult(allowed=True, value=value)
```

Three chains are constructed and injected into `build_graph()`:

- **input** — runs on the user's submitted text before it reaches the model.
- **action** — runs on each tool call the model requests, before
  `ToolRegistry` executes it. This is the one guardrail seam that has to
  actually matter for a pentest agent: it sits between the model's decision
  and real execution, which is why the design does not use
  `langgraph.prebuilt.ToolNode` (it executes immediately with no
  interception point) — see "Tools" below.
- **output** — runs on model narration before it becomes a `Narration`
  event.

All three default to `GuardrailChain([PassThroughStage()])`. Adding a real
check later is appending a stage; the chain runner and the graph shape never
change (open/closed).

The three are bundled into one value object so `build_graph()` and
`LangGraphAgent` take a single dependency rather than three positional
chains:

```python
@dataclass(frozen=True, slots=True)
class GuardrailSeam:
    input: GuardrailChain[str]
    action: GuardrailChain[ToolCall]
    output: GuardrailChain[str]

    @classmethod
    def no_op(cls) -> "GuardrailSeam":
        return cls(
            input=GuardrailChain([PassThroughStage()]),
            action=GuardrailChain([PassThroughStage()]),
            output=GuardrailChain([PassThroughStage()]),
        )
```

### Tools (`cism/agent/tools/`)

LangChain's `@tool`/`BaseTool`, as requested — this stub leans on LangChain
for tool-calling rather than a bespoke protocol.

```python
# dummy.py
@tool
def nmap_scan(target: str, args: str = "-sV") -> str:
    """Dummy nmap scan; returns canned output for skeleton validation."""
    return f"[dummy] nmap {args} {target} -> 3 open ports (22,80,443)"

@tool
def msfconsole_exploit(module: str, target: str) -> str:
    """Dummy msfconsole run; returns a canned attempt result."""
    return f"[dummy] msfconsole use {module} against {target} -> session not opened (stub)"
```

```python
# registry.py
class ToolRegistry:
    """The only way a tool is reachable from the graph. Not a convenience
    wrapper — an allowlist. get() on an unregistered name raises rather
    than returning None, so a bug can't silently widen what the agent can
    execute."""
    def __init__(self, tools: list[BaseTool]): ...
    def all(self) -> list[BaseTool]: ...
    def get(self, name: str) -> BaseTool: ...  # raises KeyError if absent
```

This is designed to carry real weight later, not just dummy tools: whether
a future tool is a hand-written wrapper around an actual binary (real nmap,
real msfconsole) or an existing LangChain/community tool the agent is
allowed to reuse as-is, it becomes reachable the same way — constructed into
a `ToolRegistry`. Nothing about `graph.py` or `nodes.py` changes when the
dummy tools are swapped for real ones; only the registry's construction
site does. The action guardrail chain is where a scope/allowlist check
(e.g. "target must be inside the declared engagement CIDR") plugs in later,
and it applies uniformly regardless of which tools are registered.

### Logging (`cism/agent/logging.py`)

Separate from the `AgentEvent` stream (UI-facing protocol) and from DEPG
evidence (domain state): operational/debug logging for graph steps, tool
calls, and guardrail decisions, written to disk.

```python
def get_agent_logger(name: str = "cism.agent") -> logging.Logger:
    """A logger writing JSONL lines to ~/.cism/logs/agent-YYYY-MM-DD.log via
    TimedRotatingFileHandler(when="midnight", backupCount=1), so at most
    today's and yesterday's files exist at once. On construction, also
    sweeps the log directory and deletes any file dated more than 1 day
    old — covers the case where the process wasn't running at midnight to
    trigger a natural rollover, so a long-idle gap can't leave stale logs
    sitting around indefinitely."""
```

### The graph (`cism/agent/graph.py`, `nodes.py`)

Skeleton shape, not a real planner:

```
entry -> think ── input_chain runs on the human message, then llm.invoke()
           │
    tool_calls in response?
           │no ──▶ output_chain runs on final text ──▶ END
           │yes
         act ── for each call: action_chain.run(call), then
                 ToolRegistry.get(call.name).invoke(call.args) if allowed
           │
      phase_router ── PhaseStateMachine decides: stay, or a legal transition
           │
           └──▶ think (loop) or END
```

`build_graph(llm: BaseChatModel, tools: ToolRegistry, guardrails: GuardrailSeam) -> CompiledStateGraph`
is a pure factory — every dependency is injected, nothing is constructed
inside it. This is what makes the graph testable with fakes and, later,
swappable to a real model/real tools without touching this file.

### `LangGraphAgent` (`cism/agent/core.py`)

Implements `cism.tui.events.Agent` exactly as `FakeAgent` does — same four
methods, same `events: asyncio.Queue[AgentEvent]` — so it is a drop-in
replacement wherever an `Agent` is expected, though wiring it into
`demo_replay.py`/the live app is out of scope here.

```python
class LangGraphAgent:
    def __init__(
        self,
        llm: BaseChatModel | None = None,          # defaults to DummyChatModel
        tools: ToolRegistry | None = None,          # defaults to the dummy tools
        guardrails: GuardrailSeam | None = None,    # defaults to no-op chains
    ) -> None:
        self.events: asyncio.Queue[AgentEvent] = asyncio.Queue()
        ...

    async def start(self) -> None: ...
    async def submit(self, text: str) -> None:
        """Schedules the internal run as its own task; does not block."""
    async def interrupt(self) -> None:
        """Cancels the in-flight run task; emits Interrupted."""
    async def aclose(self) -> None: ...
```

Internally, `_run(text)` streams the compiled graph (`astream`) and
translates each step into `RunStarted` / `Narration` / `ToolStarted` /
`ToolFinished` / `PhaseChanged` / `RunFinished` on `self.events`. This is
the first real implementer of the translation layer the existing README
already names as "the seam" — no change to the event contract itself.

## Data flow

```
LangGraphAgent.submit(text) ─▶ asyncio.create_task(_run(text))
                                      │
                         graph.astream(AgentState) ── LangGraph's own
                                      │                 internal step loop
                    each step ─▶ translated ─▶ AgentEvent ─▶ self.events

(elsewhere, not built here) a pump worker awaits self.events and calls
CISMApp._apply(event) — the only function that mutates transcript state.
```

Two independent loops — the graph's step loop inside the agent, and
whatever drains `self.events` on the consumer side — connected by nothing
but the queue. This lets the agent's loop take as long as a model call or a
scan needs without ever blocking a consumer, and lets `FakeAgent` and
`LangGraphAgent` be interchangeable since neither the queue nor the protocol
cares which one is filling it.

## Error handling

- A blocked guardrail stage (`GuardrailResult(allowed=False, reason=...)`)
  is translated to content — a `ToolFailed` for a blocked action, a
  narration event explaining a blocked input/output — never an exception
  escaping into `_run`. Matches the existing contract's "a tool failure is
  content, not an exception."
- `IllegalPhaseTransition` is caught at the same boundary in
  `phase_router`, turned into a narration event explaining the graph
  declined to change phase, and `PhaseStateMachine.current` is left
  unchanged.
- `ToolRegistry.get()` raising `KeyError` on an unregistered name is a
  programming error inside the graph (the model should only ever be offered
  tools that exist in the registry), not a runtime guardrail case — it is
  allowed to propagate and fail the run loudly, matching
  `ReplayLogError`'s "fail loudly rather than half-start" philosophy
  elsewhere in this codebase.
- Nothing in `cism/agent/` should let an unhandled exception reach
  `self.events` unencoded; `_run` wraps the graph stream in a
  try/except that emits `RunFinished(ok=False)` on failure.

## Testing

Unit:
- `PhaseStateMachine` — every legal transition in the table succeeds; a
  sample of illegal ones raise `IllegalPhaseTransition` and leave `current`
  unchanged.
- `GuardrailChain` — a pass-through chain lets a value through unchanged; a
  chain with a stub blocking stage short-circuits and later stages don't
  run (proves the mechanism before any real check exists).
- `ToolRegistry` — `get()` on a registered name returns it; on an
  unregistered name raises `KeyError`.
- `Node.to_event()` / `Edge.to_event()` — round-trip field values into the
  `cism.tui.events` dataclasses correctly, including `evidence` as a tuple
  and `decision` passed through as-is.
- `DailyRotatingLogger` — writes today's file; a pre-seeded file dated 2+
  days old is swept away on construction; a file dated yesterday survives.

Integration:
- Construct `LangGraphAgent()` with all defaults (`DummyChatModel`, dummy
  tools, no-op guardrails). `submit("scan 10.0.0.5")`, drain `self.events`,
  and assert: the sequence starts with `RunStarted` and ends with
  `RunFinished(ok=True)`; every `ToolStarted` has a matching
  `ToolFinished`/`ToolFailed` by `call_id`; `isinstance(agent, Agent)` is
  `True` (mirrors `test_fake_agent_satisfies_the_agent_protocol`).
- `interrupt()` mid-run cancels the task and an `Interrupted` event is the
  last thing on the queue.

## Dependencies

New `agent` extras group in `pyproject.toml`:

```toml
[project.optional-dependencies]
agent = ["langgraph>=0.2", "langchain-core>=0.3"]
```

Not added to base `dependencies` — a plain `pip install -e .` (TUI only)
stays exactly as lightweight as it is today.
