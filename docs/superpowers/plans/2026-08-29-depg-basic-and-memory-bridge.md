# DEPG Basic Version + Memory Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the DEPG from a placeholder that stamps one generic node per successful tool call into a real dependency/error-propagation graph (deterministic identity, derived state, dirty-frontier propagation, prune), wire a live agent run to populate the memory view, make `think`/`act` phase-parameterized, and make adding a new tool a data row instead of a hand-written function.

**Architecture:** One `LangGraphAgent`, one graph, six nodes (`think → act → depg_update → phase_router → memory_update → think`, with `respond` off the one conditional branch). `cism/depg/` and `cism/memory/` are standalone modules the graph calls into; `cism/agent/profiles.py` is a data-driven registry `think`/`act` consume without branching on phase themselves; `cism/agent/tools/catalog.py` + `base.py` turn most new tools into a data row instead of a function.

**Tech Stack:** Python 3.11+, LangGraph, LangChain Core, pytest.

**Spec:** [docs/superpowers/specs/2026-08-29-depg-basic-and-memory-design.md](../specs/2026-08-29-depg-basic-and-memory-design.md)

## Global Constraints

- `Node.id` is always the derived key `f"{cause_class}:{target}:{signal}"` (spec §4) — never a tool_call_id again.
- `state` is written **only** by `Graph.settle()`, never by an extractor or `upsert_node` (spec §4, §5).
- The reducer takes an injected `SupportPolicy`; basic uses `BinarySupport` (spec §5, §16).
- `add_edge` rejects any edge that would create a cycle — the graph is always a DAG (spec §6).
- `settle()` runs once per graph-step, not once per observation (spec §6).
- Tier convention: generic/uninterpreted → T3; real extractor, structured but unconfirmed → T2; real extractor, confirmed access/exploit → T1 (spec §8).
- `NodeState` (wire, `cism/tui/events.py`) gains exactly one new value, `"contested"` — no other wire dataclass changes (spec §11).
- `PhaseProfile` fields are exactly: `phase`, `system_prompt`, `tool_names: frozenset[str]`, `action_stages: tuple[GuardrailStage, ...] = ()` (spec §3.1).
- Tool catalog rows use `ToolSpec`/`Flag`/`Capability` exactly as spec §15; kept as typed Python data, not YAML (explicit project decision).
- No comments explaining WHAT code does — only WHY, and only when genuinely non-obvious, matching this repo's existing style.
- **Coordination point:** `cism/agent/core.py`, `cism/agent/llm.py`, `pyproject.toml`, and `tests/test_langgraph_agent.py` are concurrently being modified by a parallel agent (uncommitted, real-OpenAI/Ollama-endpoint wiring — it added `_bind_tools_if_supported` and eager tool-binding in `LangGraphAgent.__init__`). **Task 14 directly relocates that binding logic.** Before starting Task 12 or Task 14, re-read the current content of `core.py` and `tests/test_langgraph_agent.py` — they may have changed further since this plan was written — and reconcile rather than blindly applying the diffs shown, which are written against the content read at plan-writing time (reproduced in each task).
- Existing tools (`cism/agent/tools/discovery.py` nmap, `linux.py` curl, `credentials.py` hydra) are **not** migrated to the new catalog layer in this plan — left exactly as they are. The catalog/decorator layer (Part IV) is additive, demonstrated with three new tools.

---

## Part I — DEPG core

The dependency root. Parts II–IV build on this but do not require each other.

### Task 1: Working `Evidence` + `Verdict`, and the new `Node` schema

**Files:**
- Create: `cism/depg/evidence.py`
- Modify: `cism/depg/node.py`
- Modify: `cism/tui/events.py:66` (the `NodeState` type alias)
- Modify: `tests/test_depg_graph.py` (existing `Evidence` import/construction)
- Test: `tests/test_depg_evidence.py`, `tests/test_depg_node.py` (new)

**Interfaces:**
- Consumes: `cism.tui.events.Evidence` (wire), `cism.tui.events.Tier`, `cism.tui.events.Decision`, `cism.tui.events.DEPGNode`, `cism.tui.events.NodeState`.
- Produces: `cism.depg.evidence.Evidence(timestamp, tool, exit_signal, tier, verdict="alive", call_id="")`, `cism.depg.evidence.Verdict` (`Literal["alive", "dead", "inconclusive"]`), `cism.depg.node.derive_node_id(cause_class, target, signal) -> str`, `cism.depg.node.Node` with fields `id, cause_class, target, signal, evidence, decision, state, generality, downstream, phase`.

- [ ] **Step 1: Write the failing tests**

`tests/test_depg_evidence.py`:

```python
"""cism/depg/evidence.py: the working Evidence carries verdict/call_id that
the wire format doesn't; to_event() must drop them."""

from __future__ import annotations

from cism.depg.evidence import Evidence


def test_to_event_drops_verdict_and_call_id() -> None:
    evidence = Evidence(
        timestamp="12:00:00", tool="nmap", exit_signal="22/tcp open ssh",
        tier="T2", verdict="alive", call_id="call-1",
    )
    wire = evidence.to_event()

    assert wire.timestamp == "12:00:00"
    assert wire.tool == "nmap"
    assert wire.exit_signal == "22/tcp open ssh"
    assert wire.tier == "T2"
    assert not hasattr(wire, "verdict")
    assert not hasattr(wire, "call_id")


def test_verdict_and_call_id_default_for_call_sites_that_do_not_care() -> None:
    evidence = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T3")
    assert evidence.verdict == "alive"
    assert evidence.call_id == ""
```

`tests/test_depg_node.py`:

```python
"""cism/depg/node.py: the derived identity key and the widened schema."""

from __future__ import annotations

from cism.depg.evidence import Evidence
from cism.depg.node import Node, derive_node_id


def test_derive_node_id_combines_cause_class_target_and_signal() -> None:
    assert derive_node_id("open-port", "10.0.0.5", "22/tcp") == "open-port:10.0.0.5:22/tcp"


def test_different_signal_on_same_target_and_class_is_a_different_id() -> None:
    a = derive_node_id("open-port", "10.0.0.5", "22/tcp")
    b = derive_node_id("open-port", "10.0.0.5", "80/tcp")
    assert a != b


def test_node_to_event_maps_working_evidence_to_wire_evidence() -> None:
    node = Node(
        id="open-port:10.0.0.5:22/tcp", cause_class="open-port", target="10.0.0.5",
        signal="22/tcp",
        evidence=[Evidence(timestamp="t", tool="nmap", exit_signal="22/tcp open ssh", tier="T2")],
    )
    wire = node.to_event()

    assert wire.id == "open-port:10.0.0.5:22/tcp"
    assert wire.evidence[0].exit_signal == "22/tcp open ssh"


def test_node_state_defaults_untested_and_accepts_contested() -> None:
    node = Node(id="n1", cause_class="c", target="t", signal="s", state="contested")
    assert node.state == "contested"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_depg_evidence.py tests/test_depg_node.py -v`
Expected: FAIL — `cism.depg.evidence` doesn't exist yet, and `Node` doesn't take `signal`.

- [ ] **Step 3: Widen `NodeState` on the wire contract**

Modify `cism/tui/events.py:66`:

```python
NodeState: TypeAlias = Literal["blocked", "resolved", "untested", "contested"]
```

- [ ] **Step 4: Create the working `Evidence` type**

Create `cism/depg/evidence.py`:

```python
"""The working Evidence type — richer than the frozen wire format.

Separate from cism.tui.events.Evidence for the same reason Node is separate
from DEPGNode: this carries fields (verdict, call_id) the TUI table never
shows. to_event() is the only place this touches cism.tui.events.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from cism.tui.events import Evidence as WireEvidence
from cism.tui.events import Tier

__all__ = ["Evidence", "Verdict"]

Verdict = Literal["alive", "dead", "inconclusive"]


@dataclass(slots=True)
class Evidence:
    timestamp: str
    tool: str
    exit_signal: str
    tier: Tier
    verdict: Verdict = "alive"
    call_id: str = ""

    def to_event(self) -> WireEvidence:
        return WireEvidence(
            timestamp=self.timestamp,
            tool=self.tool,
            exit_signal=self.exit_signal,
            tier=self.tier,
        )
```

- [ ] **Step 5: Rewrite `Node`**

Modify `cism/depg/node.py` (full file):

```python
"""The agent-side working node of the Dependency / Error Propagation Graph.

This is the mutable copy the agent updates as a run progresses. It is a
different object from :class:`cism.tui.events.DEPGNode`, which is the
frozen, whole-state-replacement wire format the TUI consumes. ``to_event()``
is the only place this module touches ``cism.tui.events``.

``id`` is a derived identity key, not a tool_call_id — see
:func:`derive_node_id`. ``state`` is never set here or by an extractor; only
:meth:`cism.depg.graph.Graph.settle` writes it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cism.depg.evidence import Evidence
from cism.tui.events import Decision, DEPGNode, NodeState

__all__ = ["Node", "derive_node_id"]


def derive_node_id(cause_class: str, target: str, signal: str) -> str:
    """Two observations merge only when all three match — this is what stops
    "port 22" and "port 80" on the same host colliding into one node just
    because they share a cause_class and target."""
    return f"{cause_class}:{target}:{signal}"


@dataclass(slots=True)
class Node:
    """A cause/target pair the agent is tracking, plus what it knows so far."""

    id: str
    cause_class: str
    target: str
    signal: str
    evidence: list[Evidence] = field(default_factory=list)
    decision: Decision | None = None
    state: NodeState = "untested"
    generality: float = 0.0
    downstream: int = 0
    phase: str = ""

    def to_event(self) -> DEPGNode:
        return DEPGNode(
            id=self.id,
            cause_class=self.cause_class,
            target=self.target,
            generality=self.generality,
            state=self.state,
            downstream=self.downstream,
            evidence=tuple(e.to_event() for e in self.evidence),
            decision=self.decision,
        )
```

- [ ] **Step 6: Fix the existing test that constructed evidence via the wire type**

Modify `tests/test_depg_graph.py`: change the import and the two `Evidence(...)` construction lines.

```python
# before: from cism.tui.events import Evidence
# after:
from cism.depg.evidence import Evidence
```

The two calls (`Evidence(timestamp="12:00:00", tool="nmap", exit_signal="a", tier="T3")` etc.) are unchanged otherwise — `verdict`/`call_id` default.

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_depg_evidence.py tests/test_depg_node.py tests/test_depg_graph.py -v`
Expected: PASS for the two new files. `tests/test_depg_graph.py` will still show 2 failures (`test_upserting_an_existing_id_can_advance_state_away_from_untested`, `test_upserting_an_existing_id_never_regresses_an_already_advanced_state`) — expected at this point, since `Graph` hasn't changed yet. Task 4 replaces those two tests; do not attempt to fix them here.

- [ ] **Step 8: Commit**

```bash
git add cism/depg/evidence.py cism/depg/node.py cism/tui/events.py tests/test_depg_evidence.py tests/test_depg_node.py tests/test_depg_graph.py
git commit -m "feat: working Evidence/Verdict, derived Node identity key, contested NodeState"
```

### Task 2: `normalize_target` and the generic-fallback signal hash

**Files:**
- Create: `cism/depg/normalize.py`
- Test: `tests/test_depg_normalize.py`

**Interfaces:**
- Produces: `cism.depg.normalize.normalize_target(raw: str) -> str`, `cism.depg.normalize.hash_signal(text: str) -> str`.

- [ ] **Step 1: Write the failing tests**

```python
"""cism/depg/normalize.py: deterministic transforms for the identity key."""

from __future__ import annotations

from cism.depg.normalize import hash_signal, normalize_target


def test_lowercases_and_trims() -> None:
    assert normalize_target("  Host.Local  ") == "host.local"


def test_strips_a_url_scheme() -> None:
    assert normalize_target("ssh://10.0.0.5") == "10.0.0.5"


def test_strips_trailing_fqdn_dot() -> None:
    assert normalize_target("host.local.") == "host.local"


def test_drops_a_port() -> None:
    assert normalize_target("10.0.0.5:8080") == "10.0.0.5"


def test_leaves_a_bare_hostname_with_no_port_unchanged() -> None:
    assert normalize_target("host.local") == "host.local"


def test_hash_signal_is_deterministic() -> None:
    assert hash_signal("some tool output") == hash_signal("some tool output")


def test_hash_signal_differs_for_different_text() -> None:
    assert hash_signal("output one") != hash_signal("output two")


def test_hash_signal_ignores_incidental_whitespace() -> None:
    assert hash_signal("a  b") == hash_signal("a b")
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_depg_normalize.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement**

```python
"""Deterministic normalization for the DEPG identity key.

The identity key must never depend on anything an LLM decided (design spec
§7) — everything here is a pure string transform.
"""

from __future__ import annotations

import hashlib
import re

__all__ = ["hash_signal", "normalize_target"]

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
_DURATION_RE = re.compile(r"\b\d+(\.\d+)?s\b")


def normalize_target(raw: str) -> str:
    """Lowercase, trim, strip a URL scheme, strip a trailing FQDN dot, and
    drop any port — a host is one host; ports are findings ON it, not host
    identity."""
    value = raw.strip().lower()
    value = _SCHEME_RE.sub("", value)
    value = value.rstrip("/")
    if value.endswith("."):
        value = value[:-1]
    host, _, port = value.rpartition(":")
    if host and port.isdigit():
        value = host
    return value


def hash_signal(text: str) -> str:
    """A short deterministic signal for the generic fallback extractor. Not
    semantically meaningful — just stable enough that a literal repeat of
    the same tool output dedupes onto the same node."""
    normalized = re.sub(r"\s+", " ", text.strip())
    normalized = _DURATION_RE.sub("", normalized)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_depg_normalize.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cism/depg/normalize.py tests/test_depg_normalize.py
git commit -m "feat: deterministic target/signal normalization for the DEPG identity key"
```

### Task 3: `SupportPolicy` and `reduce_state`

**Files:**
- Create: `cism/depg/reducer.py`
- Test: `tests/test_depg_reducer.py`

**Interfaces:**
- Consumes: `cism.depg.node.Node`, `cism.depg.evidence.Evidence`, `cism.tui.events.NodeState`.
- Produces: `cism.depg.reducer.SupportPolicy` (Protocol), `cism.depg.reducer.BinarySupport`, `cism.depg.reducer.reduce_state(node, parents, support) -> NodeState`.

- [ ] **Step 1: Write the failing tests**

```python
"""cism/depg/reducer.py: state is derived, never latched — the five branches,
plus resurrection and sticky self-failure."""

from __future__ import annotations

from cism.depg.evidence import Evidence
from cism.depg.node import Node
from cism.depg.reducer import BinarySupport, reduce_state


def _node(**kwargs) -> Node:
    defaults = dict(id="n", cause_class="c", target="t", signal="s")
    defaults.update(kwargs)
    return Node(**defaults)


def _ev(verdict: str) -> Evidence:
    return Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict=verdict)


def test_own_dead_evidence_blocks_regardless_of_parents() -> None:
    node = _node(evidence=[_ev("dead")])
    assert reduce_state(node, [], BinarySupport()) == "blocked"


def test_alive_with_support_resolves() -> None:
    node = _node(evidence=[_ev("alive")])
    parent = _node(id="p", state="resolved")
    assert reduce_state(node, [parent], BinarySupport()) == "resolved"


def test_alive_with_no_live_parent_is_contested_not_blocked() -> None:
    node = _node(evidence=[_ev("alive")])
    parent = _node(id="p", state="blocked")
    assert reduce_state(node, [parent], BinarySupport()) == "contested"


def test_pure_inference_with_support_is_untested() -> None:
    node = _node()
    parent = _node(id="p", state="resolved")
    assert reduce_state(node, [parent], BinarySupport()) == "untested"


def test_pure_inference_with_no_live_parent_is_blocked() -> None:
    node = _node()
    parent = _node(id="p", state="blocked")
    assert reduce_state(node, [parent], BinarySupport()) == "blocked"


def test_inconclusive_evidence_is_a_no_op() -> None:
    node = _node(evidence=[_ev("alive"), _ev("inconclusive")])
    assert reduce_state(node, [], BinarySupport()) == "resolved"


def test_a_revived_parent_lets_a_pure_inference_recover() -> None:
    node = _node()
    revived_parent = _node(id="p", state="resolved")
    assert reduce_state(node, [revived_parent], BinarySupport()) == "untested"


def test_own_direct_failure_stays_blocked_even_with_a_live_parent() -> None:
    node = _node(evidence=[_ev("dead")])
    parent = _node(id="p", state="resolved")
    assert reduce_state(node, [parent], BinarySupport()) == "blocked"


def test_no_parents_at_all_counts_as_supported() -> None:
    node = _node(evidence=[_ev("alive")])
    assert reduce_state(node, [], BinarySupport()) == "resolved"
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_depg_reducer.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement**

```python
"""The state reducer: state is derived, never latched. See design spec §5."""

from __future__ import annotations

from typing import Protocol

from cism.depg.node import Node
from cism.tui.events import NodeState

__all__ = ["BinarySupport", "SupportPolicy", "reduce_state"]


class SupportPolicy(Protocol):
    def supported(self, node: Node, parents: list[Node]) -> bool: ...


class BinarySupport:
    """Basic policy: a parent is live or dead, edge weight ignored. The seam
    a graded gamma-propagation policy replaces later without touching
    reduce_state or its callers."""

    def supported(self, node: Node, parents: list[Node]) -> bool:
        return not parents or any(p.state != "blocked" for p in parents)


def _latest_direct_verdict(node: Node) -> str | None:
    for evidence in reversed(node.evidence):
        if evidence.verdict in ("alive", "dead"):
            return evidence.verdict
    return None


def reduce_state(node: Node, parents: list[Node], support: SupportPolicy) -> NodeState:
    verdict = _latest_direct_verdict(node)
    ok = support.supported(node, parents)

    if verdict == "dead":
        return "blocked"
    if verdict == "alive" and ok:
        return "resolved"
    if verdict == "alive":
        return "contested"
    if verdict is None and ok:
        return "untested"
    return "blocked"
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_depg_reducer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cism/depg/reducer.py tests/test_depg_reducer.py
git commit -m "feat: SupportPolicy-backed state reducer for the DEPG"
```

### Task 4: `Graph` — dirty-frontier `settle()` and DAG-enforcing `add_edge`

This replaces the old "state only advances away from untested" invariant. Two existing tests in `tests/test_depg_graph.py` encode that invariant directly and must be replaced, not patched — see Step 6.

**Files:**
- Modify: `cism/depg/graph.py` (full rewrite)
- Modify: `tests/test_depg_graph.py`

**Interfaces:**
- Consumes: `cism.depg.reducer.{SupportPolicy, BinarySupport, reduce_state}`, `cism.depg.node.Node`, `cism.depg.edge.Edge` (unchanged: `parent, child, weight=1.0`).
- Produces: `Graph.last_for_target: dict[str, str]`, `Graph.settle(support: SupportPolicy | None = None) -> None`, `Graph.add_edge` now silently rejects a cycle-creating edge. `Graph.upsert_node`, `Graph.roots()`, `Graph.to_event()`, `Graph.from_state()` keep their existing signatures.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_depg_graph.py` (append; do not remove the tests already there yet — Step 6 handles that):

```python
def test_settle_resolves_a_root_with_alive_evidence() -> None:
    graph = Graph()
    ev = Evidence(timestamp="t", tool="nmap", exit_signal="x", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="s", evidence=[ev]))

    graph.settle()

    assert graph.nodes["a"].state == "resolved"


def test_settle_blocks_a_root_with_dead_evidence() -> None:
    graph = Graph()
    ev = Evidence(timestamp="t", tool="nmap", exit_signal="x", tier="T3", verdict="dead")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="s", evidence=[ev]))

    graph.settle()

    assert graph.nodes["a"].state == "blocked"


def test_a_strong_child_survives_a_dead_parent_as_contested() -> None:
    graph = Graph()
    parent_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="dead")
    child_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T1", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[parent_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b", evidence=[child_ev]))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.settle()

    assert graph.nodes["a"].state == "blocked"
    assert graph.nodes["b"].state == "contested"


def test_a_pure_inference_child_is_blocked_when_its_only_parent_dies() -> None:
    graph = Graph()
    parent_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="dead")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[parent_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.settle()

    assert graph.nodes["b"].state == "blocked"


def test_a_child_with_one_dead_and_one_live_parent_survives() -> None:
    graph = Graph()
    dead_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="dead")
    live_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[dead_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b", evidence=[live_ev]))
    graph.upsert_node(Node(id="x", cause_class="c", target="t", signal="x"))
    graph.add_edge(Edge(parent="a", child="x"))
    graph.add_edge(Edge(parent="b", child="x"))

    graph.settle()

    assert graph.nodes["x"].state == "untested"


def test_a_revived_parent_lets_a_blocked_inference_child_recover() -> None:
    graph = Graph()
    dead_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="dead")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[dead_ev]))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b"))
    graph.settle()
    assert graph.nodes["b"].state == "blocked"

    alive_ev = Evidence(timestamp="t2", tool="x", exit_signal="y", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[alive_ev]))
    graph.settle()

    assert graph.nodes["a"].state == "resolved"
    assert graph.nodes["b"].state == "untested"


def test_a_self_inflicted_block_survives_an_upstream_fix() -> None:
    graph = Graph()
    alive_ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a", evidence=[alive_ev]))
    own_failure = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T3", verdict="dead")
    graph.upsert_node(Node(id="d", cause_class="c", target="t", signal="d", evidence=[own_failure]))
    graph.add_edge(Edge(parent="a", child="d"))

    graph.settle()

    assert graph.nodes["d"].state == "blocked"


def test_settle_only_walks_the_dirty_frontier() -> None:
    """An unrelated node's state is untouched by settling a different one."""
    graph = Graph()
    graph.upsert_node(Node(id="untouched", cause_class="c", target="t1", signal="s"))
    graph.settle()
    assert graph.nodes["untouched"].state == "untested"

    ev = Evidence(timestamp="t", tool="x", exit_signal="y", tier="T2", verdict="alive")
    graph.upsert_node(Node(id="other", cause_class="c", target="t2", signal="o", evidence=[ev]))
    graph.settle()

    assert graph.nodes["untouched"].state == "untested"
    assert graph.nodes["other"].state == "resolved"


def test_add_edge_rejects_a_cycle() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="t", signal="a"))
    graph.upsert_node(Node(id="b", cause_class="c", target="t", signal="b"))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.add_edge(Edge(parent="b", child="a"))

    assert Edge(parent="b", child="a") not in graph.edges


def test_last_for_target_tracks_the_most_recently_touched_node() -> None:
    graph = Graph()
    graph.upsert_node(Node(id="a", cause_class="c", target="10.0.0.5", signal="a"))
    graph.upsert_node(Node(id="b", cause_class="c", target="10.0.0.5", signal="b"))

    assert graph.last_for_target["10.0.0.5"] == "b"
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_depg_graph.py -v`
Expected: FAIL — `Graph` has no `settle`, no `last_for_target`; `add_edge` doesn't reject cycles yet.

- [ ] **Step 3: Rewrite `Graph`**

Replace `cism/depg/graph.py` in full:

```python
"""cism/depg/graph.py — the agent's mutable working copy of the DEPG: node
identity/merge, edges with cycle rejection, and the dirty-frontier state
settle. Pruning of fully-dead regions is Task 5, in this same file.
"""

from __future__ import annotations

from collections import deque

from cism.depg.edge import Edge
from cism.depg.node import Node
from cism.depg.reducer import BinarySupport, SupportPolicy, reduce_state
from cism.tui.events import DEPGEdge, DEPGNode

__all__ = ["Graph"]


class Graph:
    def __init__(
        self,
        nodes: dict[str, Node] | None = None,
        edges: list[Edge] | None = None,
    ) -> None:
        self.nodes: dict[str, Node] = dict(nodes) if nodes else {}
        self.edges: list[Edge] = list(edges) if edges else []
        self.last_for_target: dict[str, str] = {}
        self._children: dict[str, list[str]] = {}
        self._parents: dict[str, list[str]] = {}
        self._dirty: set[str] = set()
        for edge in self.edges:
            self._index_edge(edge)

    @classmethod
    def from_state(cls, nodes: dict[str, Node], edges: list[Edge]) -> "Graph":
        """Seeds a working copy by copying rather than aliasing, so mutating
        it never touches the state snapshot a caller may still be holding."""
        return cls(dict(nodes), list(edges))

    def upsert_node(self, node: Node) -> Node:
        """Routes by identity key: a matching id accumulates evidence; a new
        id is inserted as-is. Either way the node is marked dirty for the
        next settle() and becomes the target's most recently touched node."""
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            existing = node
        else:
            existing.evidence.extend(node.evidence)
            if node.decision is not None:
                existing.decision = node.decision
        self.last_for_target[node.target] = node.id
        self._dirty.add(node.id)
        return existing

    def add_edge(self, edge: Edge) -> None:
        """De-dupes on (parent, child), replacing the weight in place. A new
        edge that would create a cycle is silently dropped — a DAG is what
        makes settle() a single well-defined topological pass."""
        for i, existing in enumerate(self.edges):
            if existing.parent == edge.parent and existing.child == edge.child:
                self.edges[i] = edge
                self._dirty.add(edge.child)
                return
        if self._reaches(edge.child, edge.parent):
            return
        self.edges.append(edge)
        self._index_edge(edge)
        self._dirty.add(edge.child)

    def _index_edge(self, edge: Edge) -> None:
        self._children.setdefault(edge.parent, []).append(edge.child)
        self._parents.setdefault(edge.child, []).append(edge.parent)

    def _reaches(self, start: str, goal: str) -> bool:
        seen = {start}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            if current == goal:
                return True
            for child in self._children.get(current, []):
                if child not in seen:
                    seen.add(child)
                    queue.append(child)
        return False

    def settle(self, support: SupportPolicy | None = None) -> None:
        """Recomputes state only for nodes the dirty set can reach, stopping
        a branch the instant a node's state doesn't change — cost is O(the
        subgraph that actually moved), not O(the whole graph)."""
        support = support or BinarySupport()
        frontier = deque(self._dirty)
        queued = set(frontier)
        self._dirty.clear()
        while frontier:
            node_id = frontier.popleft()
            queued.discard(node_id)
            node = self.nodes.get(node_id)
            if node is None:
                continue
            parents = [self.nodes[p] for p in self._parents.get(node_id, []) if p in self.nodes]
            new_state = reduce_state(node, parents, support)
            if new_state == node.state:
                continue
            node.state = new_state
            for child in self._children.get(node_id, []):
                if child not in queued:
                    queued.add(child)
                    frontier.append(child)

    def roots(self) -> list[Node]:
        children = {e.child for e in self.edges}
        return [n for node_id, n in self.nodes.items() if node_id not in children]

    def to_event(self) -> tuple[tuple[DEPGNode, ...], tuple[DEPGEdge, ...]]:
        return (
            tuple(n.to_event() for n in self.nodes.values()),
            tuple(e.to_event() for e in self.edges),
        )
```

- [ ] **Step 4: Run to verify most tests pass**

Run: `pytest tests/test_depg_graph.py -v`
Expected: all new tests PASS. `test_upserting_an_existing_id_can_advance_state_away_from_untested` and `test_upserting_an_existing_id_never_regresses_an_already_advanced_state` FAIL — expected, handled next.

- [ ] **Step 5: Replace the two obsolete invariant tests**

In `tests/test_depg_graph.py`, delete these two functions:

```python
def test_upserting_an_existing_id_can_advance_state_away_from_untested() -> None: ...
def test_upserting_an_existing_id_never_regresses_an_already_advanced_state() -> None: ...
```

They asserted the old "state only advances, set directly by upsert_node" behavior, which the design spec (§5) explicitly replaces with a derived reducer. The new tests added in Step 1 (`test_settle_resolves_a_root_with_alive_evidence` etc.) cover the replacement behavior.

- [ ] **Step 6: Run the full DEPG test file**

Run: `pytest tests/test_depg_graph.py -v`
Expected: PASS, all tests.

- [ ] **Step 7: Commit**

```bash
git add cism/depg/graph.py tests/test_depg_graph.py
git commit -m "feat: dirty-frontier settle() and DAG-enforcing add_edge on Graph"
```

### Task 5: `Graph.prune()`

**Files:**
- Modify: `cism/depg/graph.py`
- Modify: `tests/test_depg_graph.py`

**Interfaces:**
- Consumes: everything from Task 4, plus `cism.depg.evidence.Evidence`.
- Produces: `Graph.prune() -> None`.

A candidate region is a maximal weakly-connected set of `blocked` nodes. It is only collapsed if **no edge leaves the region to a non-blocked node** — an outgoing live dependency means something still needs that history, so the region is left alone. Collapsing rewires boundary edges (exactly one endpoint in the region) onto the single marker node instead of dropping them, so provenance from outside the region is preserved; edges fully inside the region are absorbed into the marker.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_depg_graph.py`:

```python
def _blocked(id: str, target: str = "t") -> Node:
    node = Node(id=id, cause_class="c", target=target, signal=id, state="blocked")
    return node


def test_prune_collapses_a_fully_blocked_chain_into_one_marker() -> None:
    graph = Graph()
    graph.nodes = {"a": _blocked("a"), "b": _blocked("b"), "c": _blocked("c")}
    graph.add_edge(Edge(parent="a", child="b"))
    graph.add_edge(Edge(parent="b", child="c"))

    graph.prune()

    assert set(graph.nodes) - {"a", "b", "c"}
    assert not ({"a", "b", "c"} & set(graph.nodes))
    (marker,) = graph.nodes.values()
    assert marker.cause_class == "dead-region"
    assert marker.state == "blocked"
    assert "a" in marker.evidence[-1].exit_signal
    assert "b" in marker.evidence[-1].exit_signal
    assert "c" in marker.evidence[-1].exit_signal


def test_prune_leaves_a_region_alone_if_it_still_feeds_a_live_node() -> None:
    graph = Graph()
    graph.nodes = {
        "a": _blocked("a"),
        "b": _blocked("b"),
        "live": Node(id="live", cause_class="c", target="t", signal="live", state="resolved"),
    }
    graph.add_edge(Edge(parent="a", child="b"))
    graph.add_edge(Edge(parent="b", child="live"))

    graph.prune()

    assert {"a", "b", "live"} == set(graph.nodes)


def test_prune_rewires_a_live_ancestor_edge_onto_the_marker() -> None:
    graph = Graph()
    graph.nodes = {
        "live": Node(id="live", cause_class="c", target="t", signal="live", state="resolved"),
        "a": _blocked("a"),
        "b": _blocked("b"),
    }
    graph.add_edge(Edge(parent="live", child="a"))
    graph.add_edge(Edge(parent="a", child="b"))

    graph.prune()

    remaining_ids = set(graph.nodes) - {"live"}
    (marker_id,) = remaining_ids
    assert Edge(parent="live", child=marker_id) in [
        Edge(parent=e.parent, child=e.child) for e in graph.edges
    ]
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_depg_graph.py -v -k prune`
Expected: FAIL — `prune` doesn't exist.

- [ ] **Step 3: Implement `prune()`**

Add to `cism/depg/graph.py` (import `Evidence` at the top: `from cism.depg.evidence import Evidence`), methods added to `Graph`:

```python
    def prune(self) -> None:
        """Collapses a maximal weakly-connected all-BLOCKED region into one
        dead-region marker, as long as nothing outside still depends on it.
        Provenance is never deleted, only summarized."""
        blocked = {nid for nid, n in self.nodes.items() if n.state == "blocked"}
        visited: set[str] = set()
        for start in list(blocked):
            if start in visited:
                continue
            component = self._weakly_connected(start, blocked)
            visited |= component
            if self._has_edge_to_outside_non_blocked(component):
                continue
            self._collapse(component)

    def _weakly_connected(self, start: str, universe: set[str]) -> set[str]:
        seen = {start}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            neighbors = self._children.get(current, []) + self._parents.get(current, [])
            for neighbor in neighbors:
                if neighbor in universe and neighbor not in seen:
                    seen.add(neighbor)
                    queue.append(neighbor)
        return seen

    def _has_edge_to_outside_non_blocked(self, component: set[str]) -> bool:
        for node_id in component:
            for child in self._children.get(node_id, []):
                if child not in component and self.nodes[child].state != "blocked":
                    return True
        return False

    def _collapse(self, component: set[str]) -> None:
        members = sorted(component)
        first = self.nodes[members[0]]
        marker_id = f"pruned:{first.target}:{'+'.join(members)}"
        marker = Node(
            id=marker_id,
            cause_class="dead-region",
            target=first.target,
            signal="+".join(members),
            state="blocked",
            evidence=[
                Evidence(
                    timestamp=first.evidence[-1].timestamp if first.evidence else "",
                    tool="prune",
                    exit_signal=f"collapsed {len(members)} dead nodes: {', '.join(members)}",
                    tier="T3",
                    verdict="dead",
                )
            ],
        )

        kept_edges: list[Edge] = []
        for e in self.edges:
            parent_in, child_in = e.parent in component, e.child in component
            if parent_in and child_in:
                continue
            if parent_in:
                kept_edges.append(Edge(parent=marker_id, child=e.child, weight=e.weight))
            elif child_in:
                kept_edges.append(Edge(parent=e.parent, child=marker_id, weight=e.weight))
            else:
                kept_edges.append(e)
        self.edges = kept_edges

        for node_id in members:
            del self.nodes[node_id]
        self.nodes[marker_id] = marker

        self._children = {}
        self._parents = {}
        for e in self.edges:
            self._index_edge(e)
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_depg_graph.py -v`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add cism/depg/graph.py tests/test_depg_graph.py
git commit -m "feat: Graph.prune() collapses fully-dead regions, keeping provenance"
```

### Task 6: Precondition-linking (`find_precondition`)

**Files:**
- Create: `cism/depg/linking.py`
- Test: `tests/test_depg_linking.py`

**Interfaces:**
- Consumes: `cism.depg.graph.Graph`, `cism.depg.node.Node`, `langchain_core.messages.tool.ToolCall`.
- Produces: `cism.depg.linking.find_precondition(graph, target, call) -> Node | None`.

- [ ] **Step 1: Write the failing tests**

```python
"""cism/depg/linking.py: which prior node a new call actually depended on."""

from __future__ import annotations

from cism.depg.evidence import Evidence
from cism.depg.graph import Graph
from cism.depg.linking import find_precondition
from cism.depg.node import Node


def _node(id: str, target: str, signal: str, exit_signal: str = "") -> Node:
    evidence = [Evidence(timestamp="t", tool="nmap", exit_signal=exit_signal, tier="T2")] if exit_signal else []
    return Node(id=id, cause_class="open-port", target=target, signal=signal, evidence=evidence)


def test_matches_a_call_argument_against_a_prior_nodes_evidence() -> None:
    graph = Graph()
    graph.upsert_node(_node("port22", "10.0.0.5", "22/tcp", "22/tcp open ssh"))
    graph.upsert_node(_node("port80", "10.0.0.5", "80/tcp", "80/tcp open http"))
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    match = find_precondition(graph, "10.0.0.5", call)

    assert match is not None
    assert match.id == "port22"


def test_falls_back_to_the_last_touched_node_on_the_target_when_nothing_matches() -> None:
    graph = Graph()
    graph.upsert_node(_node("port22", "10.0.0.5", "22/tcp", "22/tcp open ssh"))
    graph.upsert_node(_node("port80", "10.0.0.5", "80/tcp", "80/tcp open http"))
    call = {"id": "c1", "name": "some-tool", "args": {"target": "10.0.0.5"}}

    match = find_precondition(graph, "10.0.0.5", call)

    assert match is not None
    assert match.id == "port80"


def test_returns_none_on_an_empty_target() -> None:
    graph = Graph()
    call = {"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}

    assert find_precondition(graph, "10.0.0.5", call) is None


def test_returns_none_when_call_is_none() -> None:
    graph = Graph()
    graph.upsert_node(_node("port22", "10.0.0.5", "22/tcp", "22/tcp open ssh"))

    assert find_precondition(graph, "10.0.0.5", None) is not None  # still falls back to last-touched
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_depg_linking.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement**

```python
"""Precondition-linking: which prior node a new tool call actually depended
on. See the design spec's edge-creation section for why the fallback is a
last resort, not the primary rule.
"""

from __future__ import annotations

from langchain_core.messages.tool import ToolCall

from cism.depg.graph import Graph
from cism.depg.node import Node

__all__ = ["find_precondition"]


def find_precondition(graph: Graph, target: str, call: ToolCall | None) -> Node | None:
    """Looks for a same-target node whose own signal or latest evidence
    mentions something this call's own arguments reference (e.g. hydra's
    service="ssh" matching nmap's "22/tcp open ssh" evidence). Falls back to
    the most recently touched node on this target when nothing matches — a
    guess of last resort, since a wrong edge is worse than a missing one.
    """
    tokens = _reference_tokens(call)
    candidates = [n for n in graph.nodes.values() if n.target == target]

    for node in reversed(candidates):
        haystack = node.signal
        if node.evidence:
            haystack += " " + node.evidence[-1].exit_signal
        if any(token and token in haystack for token in tokens):
            return node

    fallback_id = graph.last_for_target.get(target)
    if fallback_id and fallback_id in graph.nodes:
        return graph.nodes[fallback_id]
    return None


def _reference_tokens(call: ToolCall | None) -> list[str]:
    if call is None:
        return []
    args = call.get("args") or {}
    return [str(v) for v in args.values() if isinstance(v, str)]
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_depg_linking.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cism/depg/linking.py tests/test_depg_linking.py
git commit -m "feat: precondition-linking with a last-touched-on-target fallback"
```

### Task 7: `NmapExtractor`, `HydraExtractor`, and the updated `GenericExtractor`

**Files:**
- Create: `cism/depg/extractors.py`
- Modify: `cism/depg/extract.py`
- Modify: `cism/depg/__init__.py`
- Test: `tests/test_depg_extractors.py`, `tests/test_depg_extract.py` (extend existing generic-extractor coverage if present, else new)

**Interfaces:**
- Consumes: `cism.depg.evidence.Evidence`, `cism.depg.node.{Node, derive_node_id}`, `cism.depg.normalize.hash_signal`, `cism.depg.extract.Extraction`, `langchain_core.messages.ToolMessage`.
- Produces: `cism.depg.extractors.NmapExtractor`, `cism.depg.extractors.HydraExtractor` (both satisfy `CauseExtractor`, unchanged protocol). `GenericExtractor.extract` now also handles `status="error"` messages (verdict="dead") instead of never being called for them.

Tier convention applied here (Global Constraints): `NmapExtractor` → T2 (structured, not yet exploited). `HydraExtractor` success → T1 (confirmed access). `HydraExtractor` failure and `GenericExtractor` → T3.

- [ ] **Step 1: Write the failing tests**

```python
"""cism/depg/extractors.py: real parsing for nmap open ports and hydra
credential attempts."""

from __future__ import annotations

from langchain_core.messages import ToolMessage

from cism.depg.extractors import HydraExtractor, NmapExtractor
from cism.depg.graph import Graph

_NMAP_OUTPUT = """
Starting Nmap 7.94
Nmap scan report for 10.0.0.5
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  closed https
Nmap done: 1 IP address (1 host up) scanned in 1.2 seconds
"""

_HYDRA_SUCCESS = "[22][ssh] host: 10.0.0.5   login: admin   password: hunter2"
_HYDRA_FAILURE = "1 of 1 target completed, 0 valid passwords found"


def test_nmap_extractor_produces_one_node_per_open_port() -> None:
    message = ToolMessage(content=_NMAP_OUTPUT, tool_call_id="c1", name="nmap")
    call = {"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}

    extraction = NmapExtractor().extract(call, message, Graph(), "10.0.0.5")

    signals = {n.signal for n in extraction.nodes}
    assert signals == {"22/tcp", "80/tcp"}
    assert all(n.cause_class == "open-port" for n in extraction.nodes)
    assert all(n.evidence[0].tier == "T2" for n in extraction.nodes)
    assert all(n.evidence[0].verdict == "alive" for n in extraction.nodes)


def test_nmap_extractor_ignores_closed_ports() -> None:
    message = ToolMessage(content=_NMAP_OUTPUT, tool_call_id="c1", name="nmap")
    call = {"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}

    extraction = NmapExtractor().extract(call, message, Graph(), "10.0.0.5")

    assert "443/tcp" not in {n.signal for n in extraction.nodes}


def test_hydra_extractor_success_is_a_t1_credential_node() -> None:
    message = ToolMessage(content=_HYDRA_SUCCESS, tool_call_id="c1", name="hydra")
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    extraction = HydraExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "credential-found"
    assert node.signal == "admin:hunter2"
    assert node.evidence[0].tier == "T1"
    assert node.evidence[0].verdict == "alive"


def test_hydra_extractor_failure_is_a_t3_tombstone() -> None:
    message = ToolMessage(content=_HYDRA_FAILURE, tool_call_id="c1", name="hydra")
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    extraction = HydraExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "credential-attempt"
    assert node.evidence[0].tier == "T3"
    assert node.evidence[0].verdict == "dead"


def test_hydra_extractor_treats_an_error_status_as_a_failed_attempt() -> None:
    message = ToolMessage(
        content="ToolTimeoutError: hydra: timed out after 120s",
        tool_call_id="c1", name="hydra", status="error",
    )
    call = {"id": "c1", "name": "hydra", "args": {"target": "10.0.0.5", "service": "ssh"}}

    extraction = HydraExtractor().extract(call, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "credential-attempt"
    assert node.evidence[0].verdict == "dead"
```

`tests/test_depg_extract.py` (extend or create — check whether a `GenericExtractor` test file already exists under a different name first; if `tests/test_depg.py` already covers it, add there instead of creating a duplicate):

```python
"""cism/depg/extract.py: GenericExtractor now handles failures too, instead
of never being called for them."""

from __future__ import annotations

from langchain_core.messages import ToolMessage

from cism.depg.extract import GenericExtractor
from cism.depg.graph import Graph


def test_generic_extractor_marks_a_successful_call_alive() -> None:
    message = ToolMessage(content="some output", tool_call_id="c1", name="whatweb")

    extraction = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.cause_class == "whatweb"
    assert node.evidence[0].tier == "T3"
    assert node.evidence[0].verdict == "alive"


def test_generic_extractor_marks_a_failed_call_dead() -> None:
    message = ToolMessage(content="boom", tool_call_id="c1", name="whatweb", status="error")

    extraction = GenericExtractor().extract(None, message, Graph(), "10.0.0.5")

    (node,) = extraction.nodes
    assert node.evidence[0].verdict == "dead"


def test_generic_extractor_same_output_dedupes_to_the_same_id() -> None:
    message = ToolMessage(content="identical output", tool_call_id="c1", name="whatweb")

    a = GenericExtractor().extract(None, message, Graph(), "10.0.0.5").nodes[0]
    b = GenericExtractor().extract(None, message, Graph(), "10.0.0.5").nodes[0]

    assert a.id == b.id
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_depg_extractors.py tests/test_depg_extract.py -v`
Expected: FAIL — `cism.depg.extractors` doesn't exist; `GenericExtractor` still uses the old id/signal scheme.

- [ ] **Step 3: Implement `extractors.py`**

```python
"""Real cause-class extractors: nmap open-port findings and hydra credential
attempts. Both parse a tool's own default plain-text output — nmap's tabular
port lines and hydra's "login:/password:" success line are regular enough
that a regex beats requiring -oX/machine-readable flags the tool wrapper
doesn't currently request.
"""

from __future__ import annotations

import re
from datetime import datetime

from langchain_core.messages import ToolMessage
from langchain_core.messages.tool import ToolCall

from cism.depg.evidence import Evidence
from cism.depg.extract import Extraction
from cism.depg.graph import Graph
from cism.depg.node import Node, derive_node_id

__all__ = ["HydraExtractor", "NmapExtractor"]

_OPEN_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", re.MULTILINE)
_HYDRA_SUCCESS_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)")


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _call_id(call: ToolCall | None, message: ToolMessage) -> str:
    return call["id"] if call else message.tool_call_id


class NmapExtractor:
    """One node per open port — a single scan can and should produce several
    nodes, not one node per call."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        content = str(message.content)
        call_id = _call_id(call, message)
        nodes = []
        for port, proto, service in _OPEN_PORT_RE.findall(content):
            signal = f"{port}/{proto}"
            nodes.append(
                Node(
                    id=derive_node_id("open-port", target, signal),
                    cause_class="open-port",
                    target=target,
                    signal=signal,
                    evidence=[
                        Evidence(
                            timestamp=_now(), tool="nmap",
                            exit_signal=f"{signal} {service}",
                            tier="T2", verdict="alive", call_id=call_id,
                        )
                    ],
                )
            )
        return Extraction(nodes=nodes)


class HydraExtractor:
    """Success becomes a confirmed credential (T1); failure or an error
    status becomes a tombstone (T3) so the agent doesn't retry the identical
    attempt."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        call_id = _call_id(call, message)
        content = str(message.content)
        failed = getattr(message, "status", "success") == "error"
        service = (call["args"].get("service") if call else None) or "unknown"
        match = None if failed else _HYDRA_SUCCESS_RE.search(content)

        if match:
            user, password = match.groups()
            signal = f"{user}:{password}"
            node = Node(
                id=derive_node_id("credential-found", target, signal),
                cause_class="credential-found",
                target=target,
                signal=signal,
                evidence=[
                    Evidence(
                        timestamp=_now(), tool="hydra", exit_signal=content[:80],
                        tier="T1", verdict="alive", call_id=call_id,
                    )
                ],
            )
        else:
            signal = f"{service}:no-match"
            node = Node(
                id=derive_node_id("credential-attempt", target, signal),
                cause_class="credential-attempt",
                target=target,
                signal=signal,
                evidence=[
                    Evidence(
                        timestamp=_now(), tool="hydra", exit_signal=content[:80],
                        tier="T3", verdict="dead", call_id=call_id,
                    )
                ],
            )
        return Extraction(nodes=[node])
```

- [ ] **Step 4: Update `GenericExtractor` in `extract.py`**

Modify `cism/depg/extract.py`: replace the imports and the `GenericExtractor` class.

```python
# replace:
#   from cism.depg.edge import Edge
#   from cism.depg.graph import Graph
#   from cism.depg.node import Node
#   from cism.tui.events import Evidence
# with:
from cism.depg.edge import Edge
from cism.depg.evidence import Evidence
from cism.depg.graph import Graph
from cism.depg.node import Node, derive_node_id
from cism.depg.normalize import hash_signal
```

```python
class GenericExtractor:
    """The fallback: every tool call becomes exactly one node, cause_class
    taken from the tool's own name. No real interpretation of the output
    happens here, so the evidence tier stays at the weakest (T3) rather than
    implying a confidence that hasn't been earned yet. Failures are now
    captured too (verdict="dead"), not silently skipped."""

    def extract(
        self, call: ToolCall | None, message: ToolMessage, graph: Graph, target: str
    ) -> Extraction:
        tool_name = message.name or "unknown-tool"
        failed = getattr(message, "status", "success") == "error"
        content = str(message.content)
        signal = hash_signal(content)
        call_id = call["id"] if call else message.tool_call_id
        node = Node(
            id=derive_node_id(tool_name, target, signal),
            cause_class=tool_name,
            target=target,
            signal=signal,
            evidence=[
                Evidence(
                    timestamp=_now_str(),
                    tool=tool_name,
                    exit_signal=_summarize(content),
                    tier="T3",
                    verdict="dead" if failed else "alive",
                    call_id=call_id,
                )
            ],
        )
        return Extraction(nodes=[node])
```

Add a small `_now_str()` helper near `_summarize` in `extract.py` — the file
already imports `datetime` at module level, so no new import is needed:

```python
def _now_str() -> str:
    return datetime.now().strftime("%H:%M:%S")
```

- [ ] **Step 5: Export the new extractors**

Modify `cism/depg/__init__.py`:

```python
from .edge import Edge
from .extract import CauseExtractor, Extraction, ExtractorRegistry, GenericExtractor
from .extractors import HydraExtractor, NmapExtractor
from .graph import Graph
from .node import Node

__all__ = [
    "CauseExtractor",
    "Edge",
    "Extraction",
    "ExtractorRegistry",
    "GenericExtractor",
    "Graph",
    "HydraExtractor",
    "Node",
    "NmapExtractor",
]
```

- [ ] **Step 6: Run to verify pass**

Run: `pytest tests/test_depg_extractors.py tests/test_depg_extract.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add cism/depg/extractors.py cism/depg/extract.py cism/depg/__init__.py tests/test_depg_extractors.py tests/test_depg_extract.py
git commit -m "feat: real NmapExtractor/HydraExtractor; GenericExtractor now handles failures"
```

### Task 8: Rewire `depg_update` — no more skip-on-error, wire in linking/settle/prune

**Files:**
- Modify: `cism/agent/nodes.py` (`make_depg_update_node`, lines 143-163 as currently written)
- Modify: `tests/test_nodes.py`

**Interfaces:**
- Consumes: `cism.depg.linking.find_precondition`, `cism.depg.edge.Edge`, everything `depg_update` already consumed (`cism.depg.graph.Graph`, `cism.depg.extract.ExtractorRegistry`).
- Produces: `make_depg_update_node` keeps its exact signature (`extractors: ExtractorRegistry`) and return shape (`{"depg_nodes": ..., "depg_edges": ...}`) — callers (`graph.py`) are unaffected.

A precondition is looked up for **all of a message's newly-extracted nodes before any of them are upserted** — otherwise two sibling nodes from the same call (e.g. nmap's two ports) would wrongly link to each other via the last-touched fallback once the first one is inserted.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_nodes.py`:

```python
def test_a_failed_tool_call_now_produces_a_blocked_tombstone_node() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = _depg_update()(state)

    assert len(update["depg_nodes"]) == 1
    node = next(iter(update["depg_nodes"].values()))
    assert node.state == "blocked"


def test_a_second_call_on_the_same_target_gets_an_edge_from_the_first() -> None:
    depg_update = _depg_update()
    ai1, result1 = _tool_round("call-1", "dummy_nmap", "ok")
    first = depg_update(_state([HumanMessage(content="scan it"), ai1, result1]))

    ai2, result2 = _tool_round("call-2", "dummy_msfconsole", "ok too")
    second_state = _state(
        [HumanMessage(content="scan it"), ai1, result1, ai2, result2],
        depg_nodes=first["depg_nodes"], depg_edges=first["depg_edges"],
    )
    update = depg_update(second_state)

    assert len(update["depg_edges"]) == 1


def test_nodes_produced_in_the_same_step_do_not_link_to_each_other() -> None:
    """Two sibling ports from one nmap-shaped call must not chain A -> B."""
    from cism.depg import ExtractorRegistry
    from cism.depg.extractors import NmapExtractor

    depg_update = make_depg_update_node(ExtractorRegistry({"nmap": NmapExtractor()}, GenericExtractor()))
    ai = AIMessage(content="", tool_calls=[{"id": "c1", "name": "nmap", "args": {"target": "10.0.0.5"}}])
    result = ToolMessage(
        content="22/tcp   open  ssh\n80/tcp   open  http\n",
        tool_call_id="c1", name="nmap",
    )
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = depg_update(state)

    assert len(update["depg_nodes"]) == 2
    assert update["depg_edges"] == []
```

Add the `NmapExtractor`/`AIMessage`/`ToolMessage` imports the new test needs at the top of `tests/test_nodes.py` if not already present (`AIMessage`/`ToolMessage` already are).

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_nodes.py -v -k "tombstone or edge_from_the_first or do_not_link"`
Expected: FAIL — `test_an_errored_tool_call_produces_no_node` (existing) currently passes and will now start FAILING once Step 3 lands, since that's exactly the behavior being replaced; the three new tests fail for lack of the new behavior.

- [ ] **Step 3: Rewrite `make_depg_update_node`**

Replace lines 143-163 of `cism/agent/nodes.py` (the current `make_depg_update_node` function) with:

```python
def make_depg_update_node(extractors: ExtractorRegistry) -> Callable[[AgentState], dict]:
    def depg_update(state: AgentState) -> dict:
        graph = Graph.from_state(state["depg_nodes"], state["depg_edges"])
        phase_tag = state["phase"].to_wire()

        for call, message in _trailing_tool_results(state["messages"]):
            extraction = extractors.get(message.name or "").extract(
                call, message, graph, state["target"]
            )
            preconditions = {
                node.id: find_precondition(graph, node.target, call) for node in extraction.nodes
            }
            for node in extraction.nodes:
                node.phase = phase_tag
                stored = graph.upsert_node(node)
                precondition = preconditions[node.id]
                if precondition is not None and precondition.id != stored.id:
                    graph.add_edge(Edge(parent=precondition.id, child=stored.id))
            for edge in extraction.edges:
                graph.add_edge(edge)

        graph.settle()
        graph.prune()
        return {"depg_nodes": graph.nodes, "depg_edges": graph.edges}

    return depg_update
```

Add the two new imports at the top of `cism/agent/nodes.py` alongside the existing `from cism.depg import ExtractorRegistry, Graph` line:

```python
from cism.depg import Edge, ExtractorRegistry, Graph
from cism.depg.linking import find_precondition
```

(`Edge` was not previously imported in this file — check it isn't already imported under a different alias before adding.)

- [ ] **Step 4: Fix the now-obsolete "errored call produces no node" test**

In `tests/test_nodes.py`, `test_an_errored_tool_call_produces_no_node` asserted the old skip-on-error behavior. Replace it:

```python
def test_an_errored_tool_call_now_produces_a_node_instead_of_being_dropped() -> None:
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="scan it"), ai, result])

    update = _depg_update()(state)

    assert len(update["depg_nodes"]) == 1
```

(This duplicates the intent of `test_a_failed_tool_call_now_produces_a_blocked_tombstone_node` added in Step 1 — keep both; one checks node creation, the other checks the resulting state.)

- [ ] **Step 5: Run to verify pass**

Run: `pytest tests/test_nodes.py -v`
Expected: PASS, all tests.

- [ ] **Step 6: Run the full DEPG-related suite to catch regressions**

Run: `pytest tests/test_depg_graph.py tests/test_depg_extractors.py tests/test_depg_extract.py tests/test_depg_linking.py tests/test_nodes.py -v`
Expected: PASS, all tests.

- [ ] **Step 7: Commit**

```bash
git add cism/agent/nodes.py tests/test_nodes.py
git commit -m "feat: depg_update tracks failures, links preconditions, settles and prunes"
```

### Task 9: `contested` color in the DEPG modal + snapshot refresh

**Files:**
- Modify: `cism/tui/widgets/depg_modal.py` (the `state`-to-CSS-class mapping, and the counts line if it enumerates states)
- Modify: `cism/tui/theme.tcss` (add the `node--contested` rule if the existing states are styled there)
- Test: `tests/test_depg_modal.py` if it exists, else a new minimal one; snapshot regeneration

**Interfaces:**
- Consumes: `cism.tui.events.NodeState` (now includes `"contested"`).
- Produces: no new public interface — a rendering completeness fix.

- [ ] **Step 1: Locate the current state→style mapping**

Run: `grep -n "blocked\|resolved\|untested" cism/tui/widgets/depg_modal.py cism/tui/theme.tcss`

Find the dict/CSS rules keyed by `NodeState` values (this repo's existing pattern colors `"blocked"`/`"resolved"`/`"untested"` — verify the exact variable name and file before editing, since it wasn't re-read in this planning pass; do not guess the surrounding code, read the actual lines the grep returns first).

- [ ] **Step 2: Write the failing test**

```python
"""cism/tui/widgets/depg_modal.py: a contested node must not crash rendering
and must resolve to a distinct style, not silently fall back to another
state's color."""

from __future__ import annotations

from cism.tui.events import DEPGNode
from cism.tui.widgets.depg_modal import STATE_CLASS  # adjust name to match Step 1's finding


def test_contested_has_its_own_style_class() -> None:
    assert "contested" in STATE_CLASS
    assert STATE_CLASS["contested"] not in (
        STATE_CLASS["blocked"], STATE_CLASS["resolved"], STATE_CLASS["untested"],
    )
```

(If Step 1 finds the mapping under a different name than `STATE_CLASS`, adjust the import and dict name in this test to match — the constant name shown here mirrors this repo's existing `TIER_CLASS` naming convention in `memory_modal.py`, but confirm against the actual file rather than assuming.)

- [ ] **Step 3: Run to verify failure**

Run: `pytest tests/test_depg_modal.py -v -k contested`
Expected: FAIL — `"contested"` missing from the mapping.

- [ ] **Step 4: Add the mapping entry and a CSS rule**

Add a `"contested"` key to the state→class dict found in Step 1, following the exact pattern of the three existing entries (same dict literal shape). Add a corresponding `node--contested` CSS rule in `cism/tui/theme.tcss` near the existing `node--blocked`/`node--resolved`/`node--untested` rules, using the same declaration shape (color only, matching this repo's "one accent, three-step grey ramp, semantic red/green/yellow" palette rule from the README — pick yellow/amber, since contested means "needs re-verification," the same semantic category the README already reserves for non-error attention states).

- [ ] **Step 5: Run to verify pass**

Run: `pytest tests/test_depg_modal.py -v`
Expected: PASS

- [ ] **Step 6: Refresh snapshots**

Run: `pytest tests/test_snapshots.py --snapshot-update`

Review the diff on the regenerated SVG(s) before committing — it should show only the new color available, not an unrelated layout change. If a snapshot fixture doesn't already exercise a `contested` node, this step will show no visual diff at all, which is fine — the mapping is still exercised by Step 2's unit test.

- [ ] **Step 7: Commit**

```bash
git add cism/tui/widgets/depg_modal.py cism/tui/theme.tcss tests/test_depg_modal.py tests/test_snapshots.py
git commit -m "feat: contested DEPG node state gets its own color"
```

**Part I is now complete and independently shippable.** A live agent run tracks failures, links preconditions, propagates and prunes — with no dependency on Parts II–IV.

---

## Part II — Memory bridge

Depends on Part I only for `Evidence.tier`/`call_id` (Task 1) and `Node` (read-only). Nothing here touches `cism/depg/`.

### Task 10: `cism/memory/` — `MemoryItem` and `MemoryStore`

**Files:**
- Create: `cism/memory/__init__.py`
- Create: `cism/memory/item.py`
- Create: `cism/memory/store.py`
- Test: `tests/test_memory_store.py`

**Interfaces:**
- Consumes: `cism.tui.events.{MemoryRow, SalienceTerms, Tier}`.
- Produces: `cism.memory.item.MemoryItem(id, tier, phase_tag, snippet, created_at, hits=1)` with `.to_event(now) -> MemoryRow`; `cism.memory.store.DEFAULT_SALIENCE_TERMS: SalienceTerms`; `cism.memory.store.memory_key(source_type, phase_tag, snippet) -> str`; `cism.memory.store.MemoryStore` with `.from_state(items)`, `.upsert(key, tier, phase_tag, snippet) -> MemoryItem`, `.items: dict[str, MemoryItem]`, `.snapshot(now=None) -> tuple[MemoryRow, ...]`.

Salience seeding decision (the design spec flagged this as needing a concrete answer, deferring to whatever `replay.py` does): **`replay.py` has no seeding convention — `demo/recon_run.jsonl` hand-authors every `MemoryRow` field directly, including salience, as fixture data, not as computed output.** So this task establishes the live-run convention fresh: base `salience` is always `1.0` (tier differentiation happens entirely through `SalienceTerms.tier_weight` at display/decay time, already in `cism.tui.events.SalienceTerms.score()`); `age_s` is computed at snapshot time from a stored `created_at` wall-clock float, mirroring how `Evidence.timestamp` already records when an observation happened. `DEFAULT_SALIENCE_TERMS` reuses the exact coefficients already hand-authored in `demo/recon_run.jsonl` (`tier_weight={"T1": 1.4, "T2": 1.0, "T3": 0.6}`, `decay_lambda=0.0012`, `hit_bonus=0.05`) so a live run and the replay demo decay identically.

- [ ] **Step 1: Write the failing tests**

```python
"""cism/memory/store.py: dedup by key, hits increment, age computed at
snapshot time from a stored creation timestamp."""

from __future__ import annotations

from cism.memory.store import MemoryStore, memory_key


def test_a_new_key_creates_a_fresh_item_with_hits_one() -> None:
    store = MemoryStore()
    item = store.upsert("k1", "T2", "recon", "found something")

    assert item.hits == 1
    assert item.tier == "T2"


def test_upserting_the_same_key_again_increments_hits_not_a_new_row() -> None:
    store = MemoryStore()
    store.upsert("k1", "T2", "recon", "found something")
    store.upsert("k1", "T2", "recon", "found something")

    assert len(store.items) == 1
    assert store.items["k1"].hits == 2


def test_a_different_key_is_a_separate_row() -> None:
    store = MemoryStore()
    store.upsert("k1", "T2", "recon", "a")
    store.upsert("k2", "T2", "recon", "b")

    assert len(store.items) == 2


def test_repeated_upsert_keeps_the_original_created_at() -> None:
    store = MemoryStore()
    first = store.upsert("k1", "T2", "recon", "a")
    original_created_at = first.created_at
    store.upsert("k1", "T2", "recon", "a")

    assert store.items["k1"].created_at == original_created_at


def test_snapshot_computes_age_from_created_at() -> None:
    store = MemoryStore()
    item = store.upsert("k1", "T2", "recon", "a")

    rows = store.snapshot(now=item.created_at + 30.0)

    assert rows[0].age_s == 30.0
    assert rows[0].salience == 1.0


def test_from_state_copies_rather_than_aliases() -> None:
    store = MemoryStore()
    store.upsert("k1", "T2", "recon", "a")

    rebuilt = MemoryStore.from_state(store.items)
    rebuilt.upsert("k2", "T2", "recon", "b")

    assert "k2" not in store.items


def test_memory_key_normalizes_whitespace_and_case() -> None:
    a = memory_key("narration", "recon", "  Some Text  ")
    b = memory_key("narration", "recon", "some text")
    assert a == b
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_memory_store.py -v`
Expected: FAIL — `cism.memory` doesn't exist.

- [ ] **Step 3: Implement `item.py`**

```python
"""The working memory item — richer than the frozen MemoryRow wire format.

Mirrors the Node/DEPGNode split in cism.depg: age_s is computed at emission
time from a stored wall-clock creation time, which MemoryRow (frozen, part
of the wire contract) has no field for.
"""

from __future__ import annotations

from dataclasses import dataclass

from cism.tui.events import MemoryRow, Tier

__all__ = ["MemoryItem"]

_BASE_SALIENCE = 1.0


@dataclass(slots=True)
class MemoryItem:
    id: str
    tier: Tier
    phase_tag: str
    snippet: str
    created_at: float
    hits: int = 1

    def to_event(self, now: float) -> MemoryRow:
        return MemoryRow(
            id=self.id,
            tier=self.tier,
            phase_tag=self.phase_tag,
            salience=_BASE_SALIENCE,
            age_s=max(0.0, now - self.created_at),
            snippet=self.snippet,
            hits=self.hits,
        )
```

- [ ] **Step 4: Implement `store.py`**

```python
"""MemoryStore: the working container memory_update mutates each step,
mirroring cism.depg.graph.Graph's role for the DEPG.
"""

from __future__ import annotations

import time

from cism.memory.item import MemoryItem
from cism.tui.events import MemoryRow, SalienceTerms, Tier

__all__ = ["DEFAULT_SALIENCE_TERMS", "MemoryStore", "memory_key"]

#: Matches the coefficients already hand-authored in demo/recon_run.jsonl,
#: so a live run and the replay demo decay memory identically.
DEFAULT_SALIENCE_TERMS = SalienceTerms(
    tier_weight={"T1": 1.4, "T2": 1.0, "T3": 0.6},
    decay_lambda=0.0012,
    hit_bonus=0.05,
)


def memory_key(source_type: str, phase_tag: str, snippet: str) -> str:
    """Dedup key for a non-DEPG memory candidate: a recurring block or
    narration collapses onto one row (hits increments) instead of spamming
    the table. A DEPG-derived row uses the node's own id as its key instead
    of this function."""
    normalized = " ".join(snippet.split()).lower()
    return f"{source_type}:{phase_tag}:{normalized}"


class MemoryStore:
    def __init__(self, items: dict[str, MemoryItem] | None = None) -> None:
        self.items: dict[str, MemoryItem] = dict(items) if items else {}

    @classmethod
    def from_state(cls, items: dict[str, MemoryItem]) -> "MemoryStore":
        return cls(dict(items))

    def upsert(self, key: str, tier: Tier, phase_tag: str, snippet: str) -> MemoryItem:
        """A matching key bumps hits and keeps the original creation time (so
        age reflects how long this item has been true, not when it last
        recurred). A new key is inserted fresh."""
        existing = self.items.get(key)
        if existing is None:
            item = MemoryItem(
                id=key, tier=tier, phase_tag=phase_tag, snippet=snippet,
                created_at=time.time(), hits=1,
            )
            self.items[key] = item
            return item
        existing.hits += 1
        return existing

    def snapshot(self, now: float | None = None) -> tuple[MemoryRow, ...]:
        now = time.time() if now is None else now
        return tuple(item.to_event(now) for item in self.items.values())
```

- [ ] **Step 5: Create the package `__init__.py`**

```python
"""cism/memory: the working memory model — a MemoryStore that memory_update
mutates each step, and MemoryItem, its per-row working type."""

from __future__ import annotations

from .item import MemoryItem
from .store import DEFAULT_SALIENCE_TERMS, MemoryStore, memory_key

__all__ = ["DEFAULT_SALIENCE_TERMS", "MemoryItem", "MemoryStore", "memory_key"]
```

- [ ] **Step 6: Run to verify pass**

Run: `pytest tests/test_memory_store.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add cism/memory/ tests/test_memory_store.py
git commit -m "feat: MemoryItem/MemoryStore, the working memory model"
```

### Task 11: `make_memory_update_node` and `phase_changed` on `phase_router`

Only `state["phase"]` (the new phase) is available in `AgentState`, with no record of whether it actually changed this step. `phase_router` needs to say so, and `memory_update` needs to read it — this is the one small addition to an existing node.

**Files:**
- Modify: `cism/agent/nodes.py` (`make_phase_router`, and a new `make_memory_update_node`)
- Modify: `cism/agent/state.py` (`AgentState` gains `phase_changed: bool` and `memory_items: dict[str, MemoryItem]`)
- Test: `tests/test_nodes.py`

**Interfaces:**
- Consumes: `cism.memory.{MemoryStore, MemoryItem, memory_key}`, everything `_trailing_tool_results` already exposes.
- Produces: `make_phase_router()` return dict gains `"phase_changed": bool`. `make_memory_update_node() -> Callable[[AgentState], dict]` returning `{"memory_items": dict[str, MemoryItem]}`.

Each of the five sources is scoped to **this step only** (not the whole run's history), or `hits` would grow every step regardless of real recurrence:
- DEPG evidence: only nodes whose *latest* evidence's `call_id` is one of this step's tool-call ids (added in Task 1/7).
- Tool failure / guardrail block: `_trailing_tool_results` already scopes to this step; both arrive as an error-status `ToolMessage` and share one code path (the design spec lists them as separate sources conceptually, but the mechanism producing a T3 row is identical for both).
- Narration: only the single most recent `AIMessage`, not the whole message history.
- Phase transition: only when `state["phase_changed"]` is true this step.

- [ ] **Step 1: Write the failing tests**

Add to `cism/agent/state.py`'s test file (`tests/test_phase_state.py`) if `phase_router` tests live there, otherwise add directly to `tests/test_nodes.py` alongside the other `make_phase_router`/`make_depg_update_node` tests:

```python
def test_phase_router_reports_when_it_actually_moved() -> None:
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    state = _state([HumanMessage(content="x"), ToolMessage(content="ok", tool_call_id="c1", name="dummy_nmap")])

    update = router(state)

    assert update["phase_changed"] is True


def test_phase_router_reports_no_change_when_it_stays_put() -> None:
    from cism.agent.nodes import make_phase_router

    router = make_phase_router()
    ai, result = _tool_round("call-1", "dummy_nmap", "boom", error=True)
    state = _state([HumanMessage(content="x"), ai, result])

    update = router(state)

    assert update["phase_changed"] is False


def _memory_state(messages, depg_nodes=None, phase_changed=False) -> dict:
    return {
        "messages": messages, "phase": Phase.RECON, "depg_nodes": depg_nodes or {},
        "depg_edges": [], "run_id": "run-1", "target": "10.0.0.5",
        "memory_items": {}, "phase_changed": phase_changed,
    }


def test_memory_update_records_a_successful_finding_from_this_step() -> None:
    from cism.agent.nodes import make_memory_update_node
    from cism.depg.evidence import Evidence
    from cism.depg.node import Node

    node = Node(
        id="n1", cause_class="open-port", target="10.0.0.5", signal="22/tcp",
        evidence=[Evidence(timestamp="t", tool="nmap", exit_signal="22/tcp open ssh", tier="T2", call_id="c1")],
    )
    ai, result = _tool_round("c1", "nmap", "22/tcp open ssh")
    state = _memory_state([HumanMessage(content="scan"), ai, result], depg_nodes={"n1": node})

    update = make_memory_update_node()(state)

    assert len(update["memory_items"]) == 1


def test_memory_update_ignores_depg_nodes_from_an_earlier_step() -> None:
    from cism.agent.nodes import make_memory_update_node
    from cism.depg.evidence import Evidence
    from cism.depg.node import Node

    old_node = Node(
        id="n1", cause_class="open-port", target="10.0.0.5", signal="22/tcp",
        evidence=[Evidence(timestamp="t", tool="nmap", exit_signal="x", tier="T2", call_id="old-call")],
    )
    ai, result = _tool_round("c2", "hydra", "no creds", error=True)
    state = _memory_state([HumanMessage(content="scan"), ai, result], depg_nodes={"n1": old_node})

    update = make_memory_update_node()(state)

    depg_derived = [k for k in update["memory_items"] if k == "n1"]
    assert depg_derived == []


def test_memory_update_records_a_tool_failure() -> None:
    from cism.agent.nodes import make_memory_update_node

    ai, result = _tool_round("c1", "hydra", "wordlist exhausted", error=True)
    state = _memory_state([HumanMessage(content="scan"), ai, result])

    update = make_memory_update_node()(state)

    assert len(update["memory_items"]) == 1


def test_memory_update_records_narration_from_the_most_recent_ai_message() -> None:
    from cism.agent.nodes import make_memory_update_node

    ai = AIMessage(content="I found something interesting.")
    state = _memory_state([HumanMessage(content="scan"), ai])

    update = make_memory_update_node()(state)

    assert len(update["memory_items"]) == 1


def test_memory_update_records_a_phase_change() -> None:
    from cism.agent.nodes import make_memory_update_node

    ai, result = _tool_round("c1", "nmap", "ok")
    state = _memory_state([HumanMessage(content="scan"), ai, result], phase_changed=True)

    update = make_memory_update_node()(state)

    assert any("phase" in item.snippet for item in update["memory_items"].values())


def test_memory_update_dedupes_a_recurring_narration_into_hits() -> None:
    from cism.agent.nodes import make_memory_update_node

    memory_update = make_memory_update_node()
    ai = AIMessage(content="same narration text")
    state = _memory_state([HumanMessage(content="scan"), ai])
    first = memory_update(state)

    second_state = _memory_state([HumanMessage(content="scan"), ai], )
    second_state["memory_items"] = first["memory_items"]
    update = memory_update(second_state)

    assert len(update["memory_items"]) == 1
    (item,) = update["memory_items"].values()
    assert item.hits == 2
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_nodes.py -v -k "phase_router or memory_update"`
Expected: FAIL — `phase_changed` not returned; `make_memory_update_node` doesn't exist.

- [ ] **Step 3: Add `phase_changed` to `phase_router`**

Replace the existing `make_phase_router` function body in `cism/agent/nodes.py`:

```python
def make_phase_router() -> Callable[[AgentState], dict]:
    def phase_router(state: AgentState) -> dict:
        machine = PhaseStateMachine(current=state["phase"])
        last = state["messages"][-1]
        succeeded = isinstance(last, ToolMessage) and last.status != "error"
        before = machine.current

        if succeeded:
            target = DEFAULT_NEXT_PHASE[machine.current]
            try:
                machine.transition(target)
            except IllegalPhaseTransition:
                pass  # stay put; an illegal proposed move is not a run failure

        return {"phase": machine.current, "phase_changed": machine.current != before}

    return phase_router
```

- [ ] **Step 4: Implement `make_memory_update_node`**

Add to `cism/agent/nodes.py` (after `make_phase_router`), plus the new imports:

```python
from cism.memory import MemoryStore, memory_key
```

```python
def make_memory_update_node() -> Callable[[AgentState], dict]:
    def memory_update(state: AgentState) -> dict:
        store = MemoryStore.from_state(state["memory_items"])
        phase_tag = state["phase"].to_wire()
        trailing = _trailing_tool_results(state["messages"])
        this_step_call_ids = {message.tool_call_id for _, message in trailing}

        for node in state["depg_nodes"].values():
            if not node.evidence:
                continue
            latest = node.evidence[-1]
            if latest.call_id in this_step_call_ids:
                store.upsert(node.id, latest.tier, phase_tag, latest.exit_signal)

        for _, message in trailing:
            if getattr(message, "status", "success") != "error":
                continue
            snippet = str(message.content)[:120]
            store.upsert(memory_key("tool-failure", phase_tag, snippet), "T3", phase_tag, snippet)

        last_ai = next((m for m in reversed(state["messages"]) if isinstance(m, AIMessage)), None)
        if last_ai is not None and str(last_ai.content).strip():
            snippet = str(last_ai.content).strip()[:120]
            store.upsert(memory_key("narration", phase_tag, snippet), "T3", phase_tag, snippet)

        if state.get("phase_changed"):
            snippet = f"phase -> {phase_tag}"
            store.upsert(memory_key("phase-change", phase_tag, snippet), "T2", phase_tag, snippet)

        return {"memory_items": store.items}

    return memory_update
```

Add `make_memory_update_node` to `nodes.py`'s `__all__` list.

- [ ] **Step 5: Add the two new `AgentState` fields**

Modify `cism/agent/state.py`'s `AgentState` TypedDict:

```python
class AgentState(TypedDict):
    """The LangGraph state schema threaded through every node."""

    messages: Annotated[list[Any], add_messages]
    phase: Phase
    phase_changed: bool
    depg_nodes: dict[str, Node]
    depg_edges: list[Edge]
    memory_items: dict[str, "MemoryItem"]
    run_id: str
    target: str
```

Add the import at the top of `state.py` (guard against a circular import — `cism.memory` does not import from `cism.agent`, so this is safe):

```python
from cism.memory import MemoryItem
```

- [ ] **Step 6: Run to verify pass**

Run: `pytest tests/test_nodes.py -v`
Expected: PASS, all tests. Note existing tests calling `_state(...)` (the `depg_update`-only helper, not `_memory_state`) do not set `memory_items`/`phase_changed` — that's fine, since `make_depg_update_node` and `make_phase_router`/`make_memory_update_node` are tested with their own respective state-builder helpers (`_state` vs `_memory_state`) and neither reads a field the other doesn't provide.

- [ ] **Step 7: Commit**

```bash
git add cism/agent/nodes.py cism/agent/state.py tests/test_nodes.py
git commit -m "feat: memory_update node sourcing memory beyond DEPG evidence"
```

### Task 12: Wire `memory_update` into `build_graph` and `core.py`

**⚠ Coordination point.** `cism/agent/core.py` is concurrently being modified by a parallel agent (uncommitted at plan-writing time, real-OpenAI/Ollama-endpoint wiring). **Before editing, re-read the current file** — the diff below is written against the version quoted here; if it has changed further, reconcile by hand rather than pasting blindly. The parallel agent's `_bind_tools_if_supported` helper and its call site in `__init__` are untouched by this task (Task 14 is the one that relocates that logic) — this task only adds `memory_items`/`phase_changed` to the initial state dict and a new branch in `_translate`.

**Files:**
- Modify: `cism/agent/graph.py` (add the `memory_update` node and re-route the loop edge)
- Modify: `cism/agent/core.py` (`__init__`'s `initial_state`, and `_translate`)
- Modify: `tests/test_langgraph_agent.py`

**Interfaces:**
- Consumes: `cism.agent.nodes.make_memory_update_node`, `cism.memory.DEFAULT_SALIENCE_TERMS`, `cism.tui.events.MemoryUpdated`.
- Produces: no signature changes to `build_graph()` or `LangGraphAgent.__init__` — both keep their current parameter lists.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_langgraph_agent.py`:

```python
async def test_a_live_run_emits_memory_updated() -> None:
    agent = LangGraphAgent()
    await agent.start()
    await agent.submit("scan 10.0.0.5")

    events = []
    while True:
        batch = await drain(agent.events)
        events.extend(batch)
        if any(isinstance(e, RunFinished) for e in batch):
            break

    memory_events = [e for e in events if type(e).__name__ == "MemoryUpdated"]
    assert memory_events
    assert memory_events[-1].rows
```

Add `MemoryUpdated` to the `from cism.tui.events import (...)` block at the top of the file if not already present.

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_langgraph_agent.py -v -k memory_updated`
Expected: FAIL — no `memory_update` node exists in the compiled graph yet, so no `MemoryUpdated` event is ever emitted.

- [ ] **Step 3: Add the node and edge to `build_graph`**

Modify `cism/agent/graph.py`:

```python
from cism.agent.nodes import (
    make_act_node,
    make_depg_update_node,
    make_memory_update_node,
    make_phase_router,
    make_respond_node,
    make_think_node,
    route_after_think,
)
```

```python
def build_graph(
    llm: BaseChatModel,
    tools: ToolRegistry,
    guardrails: GuardrailSeam,
    extractors: ExtractorRegistry,
) -> CompiledStateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("think", make_think_node(llm))
    graph.add_node("act", make_act_node(tools, guardrails.action))
    graph.add_node("depg_update", make_depg_update_node(extractors))
    graph.add_node("phase_router", make_phase_router())
    graph.add_node("memory_update", make_memory_update_node())
    graph.add_node("respond", make_respond_node(guardrails.output))

    graph.add_edge(START, "think")
    graph.add_conditional_edges("think", route_after_think, {"act": "act", "respond": "respond"})
    graph.add_edge("act", "depg_update")
    graph.add_edge("depg_update", "phase_router")
    graph.add_edge("phase_router", "memory_update")
    graph.add_edge("memory_update", "think")
    graph.add_edge("respond", END)

    return graph.compile()
```

Also update the module docstring's ASCII diagram (near the top of the file) to add `memory_update` after `phase_router`, matching the design spec's diagram in §3.

- [ ] **Step 4: Wire `core.py`**

In `LangGraphAgent._run`'s `initial_state` dict (re-read the current file first per the coordination note above — the two new keys go alongside the existing `"depg_nodes"`/`"depg_edges"` entries):

```python
initial_state: dict[str, Any] = {
    "messages": [HumanMessage(content=guarded.value)],
    "phase": self._phase.current,
    "phase_changed": False,
    "depg_nodes": {},
    "depg_edges": [],
    "memory_items": {},
    "run_id": run_id,
    "target": self._target,
}
```

Add a new branch to `_translate` (after the existing `elif node == "depg_update":` block):

```python
elif node == "memory_update":
    items = update.get("memory_items") or {}
    rows = tuple(item.to_event(time.time()) for item in items.values())
    await self.events.put(MemoryUpdated(rows=rows, terms=DEFAULT_SALIENCE_TERMS))
```

Add the three new imports `core.py` now needs:

```python
import time

from cism.memory import DEFAULT_SALIENCE_TERMS
from cism.tui.events import (
    # ...existing names...
    MemoryUpdated,
)
```

- [ ] **Step 5: Run to verify pass**

Run: `pytest tests/test_langgraph_agent.py -v`
Expected: PASS, all tests, including the parallel agent's own `bind_tools`-related tests (unaffected by this task).

- [ ] **Step 6: Run the full suite**

Run: `pytest -v`
Expected: PASS. This is the first point where Parts I and II are exercised together through a real compiled graph — worth doing before moving to Part III.

- [ ] **Step 7: Commit**

```bash
git add cism/agent/graph.py cism/agent/core.py tests/test_langgraph_agent.py
git commit -m "feat: wire memory_update into the compiled graph and the event translator"
```

**Part II is now complete.** A live run populates both the DEPG and memory views.

---

## Part III — Phase profiles

Depends on Part I/II only for shared types already in place (`Phase`, `AgentState`). Task 14 has the plan's second and last coordination point with the parallel agent's `core.py` changes.

### Task 13: `PhaseProfile` and `PhaseProfiles`

**Files:**
- Create: `cism/agent/profiles.py`
- Modify: `cism/agent/guardrails/chain.py` (`GuardrailChain` gains a `.stages` property, needed by Task 14 to compose base + phase-specific chains)
- Test: `tests/test_phase_profiles.py`, `tests/test_guardrail_chain.py` (extend)

**Interfaces:**
- Consumes: `cism.agent.state.Phase`, `cism.agent.guardrails.GuardrailStage`, `cism.agent.tools.ToolRegistry`.
- Produces: `cism.agent.profiles.PhaseProfile(phase, system_prompt, tool_names: frozenset[str], action_stages: tuple[GuardrailStage, ...] = ())`, `cism.agent.profiles.PhaseProfiles.get(phase) -> PhaseProfile` (raises `KeyError` on an unregistered phase, same hard-allowlist convention as `ToolRegistry`), `cism.agent.profiles.default_profiles(tools: ToolRegistry) -> PhaseProfiles`. `GuardrailChain.stages -> list[GuardrailStage[T]]`.

- [ ] **Step 1: Write the failing tests**

```python
"""cism/agent/profiles.py: per-phase prompt/tool-subset/action-stage config,
a hard allowlist like ToolRegistry."""

from __future__ import annotations

import pytest

from cism.agent.profiles import PhaseProfile, PhaseProfiles, default_profiles
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap


def test_get_returns_the_profile_for_a_phase() -> None:
    profile = PhaseProfile(phase=Phase.RECON, system_prompt="p", tool_names=frozenset({"nmap"}))
    profiles = PhaseProfiles({Phase.RECON: profile})

    assert profiles.get(Phase.RECON) is profile


def test_get_raises_on_an_unregistered_phase() -> None:
    profiles = PhaseProfiles({})
    with pytest.raises(KeyError):
        profiles.get(Phase.RECON)


def test_default_profiles_covers_every_phase() -> None:
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    for phase in Phase:
        profile = profiles.get(phase)
        assert profile.phase == phase
        assert profile.system_prompt


def test_default_profiles_gives_exploitation_more_tools_than_recon() -> None:
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert profiles.get(Phase.RECON).tool_names <= profiles.get(Phase.EXPLOITATION).tool_names


def test_default_profiles_reporting_phase_has_no_tools() -> None:
    profiles = default_profiles(ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert profiles.get(Phase.REPORTING).tool_names == frozenset()
```

Add to `tests/test_guardrail_chain.py`:

```python
def test_stages_exposes_the_chains_stage_list() -> None:
    stage = PassThroughStage()
    chain = GuardrailChain([stage])

    assert chain.stages == [stage]
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_phase_profiles.py tests/test_guardrail_chain.py -v`
Expected: FAIL — `cism.agent.profiles` doesn't exist; `GuardrailChain` has no `.stages`.

- [ ] **Step 3: Add `GuardrailChain.stages`**

Modify `cism/agent/guardrails/chain.py`, add to `GuardrailChain`:

```python
    @property
    def stages(self) -> list["GuardrailStage[T]"]:
        return list(self._stages)
```

- [ ] **Step 4: Implement `profiles.py`**

```python
"""Per-phase configuration for think/act: prompt, tool subset, extra action
guardrail stages. One profile per phase; think/act consume this registry and
never branch on phase themselves, so promoting a phase to a real subagent
later is a hand-off at phase_router, not a graph change.
"""

from __future__ import annotations

from dataclasses import dataclass

from cism.agent.guardrails import GuardrailStage
from cism.agent.state import Phase
from cism.agent.tools import ToolRegistry

__all__ = ["PhaseProfile", "PhaseProfiles", "default_profiles"]


@dataclass(frozen=True, slots=True)
class PhaseProfile:
    phase: Phase
    system_prompt: str
    tool_names: frozenset[str]
    action_stages: tuple[GuardrailStage, ...] = ()


class PhaseProfiles:
    """A hard allowlist, same convention as ToolRegistry: every phase must
    have a profile, so a missing one raises rather than silently degrading
    the agent to no prompt and no tools."""

    def __init__(self, profiles: dict[Phase, PhaseProfile]) -> None:
        self._profiles = dict(profiles)

    def get(self, phase: Phase) -> PhaseProfile:
        return self._profiles[phase]


_PROMPTS: dict[Phase, str] = {
    Phase.RECON: "You are in the recon phase: map hosts and open services. Do not attempt exploitation.",
    Phase.ENUMERATION: "You are in enumeration: identify service versions and configuration on discovered hosts.",
    Phase.VULNERABILITY_DISCOVERY: "You are assessing discovered services for known vulnerabilities.",
    Phase.EXPLOITATION: "You are attempting to exploit a confirmed vulnerability or weak credential.",
    Phase.POST_EXPLOITATION: "You have a foothold; document access and look for further pivots within scope.",
    Phase.REPORTING: "Summarize findings. Do not run further tools.",
}

_TOOLS: dict[Phase, frozenset[str]] = {
    Phase.RECON: frozenset({"nmap", "curl"}),
    Phase.ENUMERATION: frozenset({"nmap", "curl"}),
    Phase.VULNERABILITY_DISCOVERY: frozenset({"nmap", "curl"}),
    Phase.EXPLOITATION: frozenset({"nmap", "curl", "hydra"}),
    Phase.POST_EXPLOITATION: frozenset({"nmap", "curl", "hydra"}),
    Phase.REPORTING: frozenset(),
}


def default_profiles(tools: ToolRegistry) -> PhaseProfiles:
    """The basic profile set. tool_names lists real tool names (nmap/curl/
    hydra); a caller whose registry only has the dummy tools simply binds
    nothing for a phase — see make_think_node, which filters tool_names
    against what the registry actually contains."""
    del tools  # not needed to build the basic set; kept for callers' symmetry
    return PhaseProfiles(
        {
            phase: PhaseProfile(phase=phase, system_prompt=_PROMPTS[phase], tool_names=_TOOLS[phase])
            for phase in Phase
        }
    )
```

- [ ] **Step 5: Run to verify pass**

Run: `pytest tests/test_phase_profiles.py tests/test_guardrail_chain.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add cism/agent/profiles.py cism/agent/guardrails/chain.py tests/test_phase_profiles.py tests/test_guardrail_chain.py
git commit -m "feat: PhaseProfile/PhaseProfiles, per-phase prompt/tool/guardrail config"
```

### Task 14: `think`/`act` consume `PhaseProfile`

**⚠ Coordination point — read this before touching any code.** The parallel agent added `_bind_tools_if_supported(llm, tools: ToolRegistry) -> BaseChatModel` to `cism/agent/core.py`, called **once, eagerly, in `LangGraphAgent.__init__`** against the *whole* registry, before `build_graph` is called. `PhaseProfile.tool_names` needs a *different* subset bound *per phase*, which a one-time eager bind against the whole registry cannot do — a phase's `think` call needs to bind only its own `tool_names` each invocation. The reconciliation is: **delete the eager bind from `__init__`; move the bind-with-fallback helper into `nodes.py`; call it inside `think`, once per invocation, against that phase's tool subset.** `core.py` passes the raw, unbound `self._llm` into `build_graph` from now on.

This also means the parallel agent's own test asserting eager binding in `__init__` (using `_RecordingChatModel` in `tests/test_langgraph_agent.py`) is testing behavior this task removes. **Re-read `tests/test_langgraph_agent.py` now, find that test, and rewrite it to assert binding happens per-invocation inside `think` instead** (Step 5 below shows the replacement) — do not leave a test asserting removed behavior, and do not silently delete it without a replacement that still exercises binding.

**Files:**
- Modify: `cism/agent/nodes.py` (`make_think_node`, `make_act_node`)
- Modify: `cism/agent/graph.py` (`build_graph` gains a `profiles: PhaseProfiles` parameter)
- Modify: `cism/agent/core.py` (`__init__`: remove eager bind, construct/accept `PhaseProfiles`, pass raw `llm`)
- Modify: `tests/test_langgraph_agent.py`, `tests/test_nodes.py`

**Interfaces:**
- Consumes: `cism.agent.profiles.{PhaseProfile, PhaseProfiles, default_profiles}`.
- Produces: `make_think_node(llm: BaseChatModel, tools: ToolRegistry, profiles: PhaseProfiles)`. `make_act_node(tools: ToolRegistry, base_action_chain: GuardrailChain, profiles: PhaseProfiles)`. `build_graph(llm, tools, guardrails, extractors, profiles: PhaseProfiles)`. `LangGraphAgent.__init__` gains an optional `profiles: PhaseProfiles | None = None` parameter, defaulting to `default_profiles(self._tools)`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_nodes.py`:

```python
def test_think_binds_only_the_current_phases_tools() -> None:
    from cism.agent.nodes import make_think_node
    from cism.agent.profiles import PhaseProfile, PhaseProfiles

    recorded: list = []

    class _Recording(_RecordingChatModelForNodesTest):
        def bind_tools(self, tools, **kwargs):
            recorded.append(list(tools))
            return self

    profiles = PhaseProfiles({
        Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="p", tool_names=frozenset({"dummy_nmap"})),
    })
    tools = ToolRegistry([dummy_nmap, dummy_msfconsole])
    think = make_think_node(_Recording(), tools, profiles)
    state = _state([HumanMessage(content="x")])

    think(state)

    assert [t.name for t in recorded[0]] == ["dummy_nmap"]


def test_think_prepends_the_phases_system_prompt_without_mutating_state() -> None:
    from cism.agent.nodes import make_think_node
    from cism.agent.profiles import PhaseProfile, PhaseProfiles

    profiles = PhaseProfiles({
        Phase.RECON: PhaseProfile(phase=Phase.RECON, system_prompt="RECON PROMPT", tool_names=frozenset()),
    })
    think = make_think_node(_RecordingChatModelForNodesTest(), ToolRegistry([]), profiles)
    state = _state([HumanMessage(content="x")])

    think(state)

    assert not any(isinstance(m, SystemMessage) for m in state["messages"])
```

These two tests need a minimal recording `BaseChatModel` local to `tests/test_nodes.py` — add near the top of the file (mirroring `_RecordingChatModel` already defined in `tests/test_langgraph_agent.py`, but this file has no such fixture yet):

```python
class _RecordingChatModelForNodesTest(BaseChatModel):
    last_messages: list = []

    @property
    def _llm_type(self) -> str:
        return "test-recording-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        type(self).last_messages = list(messages)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="done"))])

    def bind_tools(self, tools, **kwargs):
        return self
```

Add the needed imports at the top of `tests/test_nodes.py`: `from langchain_core.callbacks import CallbackManagerForLLMRun`, `from langchain_core.language_models.chat_models import BaseChatModel`, `from langchain_core.messages import SystemMessage`, `from langchain_core.outputs import ChatGeneration, ChatResult`, `from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap`.

Add to `tests/test_langgraph_agent.py`, **replacing** whatever existing test currently asserts eager binding in `__init__` against `_RecordingChatModel` (locate it first — it references `_RecordingChatModel` and `LangGraphAgent(llm=...)`):

```python
async def test_tool_binding_happens_per_phase_inside_think_not_at_construction() -> None:
    model = _RecordingChatModel()
    agent = LangGraphAgent(llm=model, tools=ToolRegistry([dummy_nmap, dummy_msfconsole]))

    assert model.bound_tools == []  # nothing bound yet at construction time

    await agent.start()
    await agent.submit("scan 10.0.0.5")
    await drain(agent.events)

    assert model.bound_tools  # bound once think actually ran
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_nodes.py tests/test_langgraph_agent.py -v -k "think or tool_binding"`
Expected: FAIL — `make_think_node`/`make_act_node` don't take `tools`/`profiles` yet; `core.py` still binds eagerly.

- [ ] **Step 3: Rewrite `make_think_node` and `make_act_node`**

Replace in `cism/agent/nodes.py`:

```python
def _bind_tools_if_supported(llm: BaseChatModel, tools: list) -> BaseChatModel:
    """A phase with no tools, or a model that never implements bind_tools
    (DummyChatModel's inherited default raises NotImplementedError), is used
    unbound rather than crashing the run — relocated here from core.py so
    binding happens per phase invocation, not once against the whole
    registry at construction time."""
    if not tools:
        return llm
    try:
        return llm.bind_tools(tools)
    except NotImplementedError:
        return llm


def make_think_node(
    llm: BaseChatModel, tools: ToolRegistry, profiles: PhaseProfiles
) -> Callable[[AgentState], dict]:
    def think(state: AgentState) -> dict:
        profile = profiles.get(state["phase"])
        phase_tools = [tools.get(name) for name in profile.tool_names if name in tools]
        bound = _bind_tools_if_supported(llm, phase_tools)
        messages = [SystemMessage(content=profile.system_prompt), *state["messages"]]
        response = bound.invoke(messages)
        return {"messages": [response]}

    return think
```

```python
def make_act_node(
    tools: ToolRegistry, base_action_chain: GuardrailChain, profiles: PhaseProfiles
) -> Callable[[AgentState], dict]:
    def act(state: AgentState) -> dict:
        profile = profiles.get(state["phase"])
        action_chain = GuardrailChain(base_action_chain.stages + list(profile.action_stages))
        last = state["messages"][-1]
        tool_calls = getattr(last, "tool_calls", None) or []
        results: list[ToolMessage] = []

        for call in tool_calls:
            guard = action_chain.run(call)
            if not guard.allowed:
                results.append(
                    ToolMessage(
                        content=f"blocked by action guardrail: {guard.reason or 'no reason given'}",
                        tool_call_id=call["id"], name=call["name"], status="error",
                    )
                )
                continue
            call = guard.value
            tool = tools.get(call["name"])
            try:
                message = tool.invoke(call)
            except Exception as exc:
                message = ToolMessage(
                    content=f"{type(exc).__name__}: {exc}",
                    tool_call_id=call["id"], name=call["name"], status="error",
                )
            results.append(message)

        return {"messages": results}

    return act
```

Add the new imports `nodes.py` needs: `from langchain_core.messages import SystemMessage` (alongside the existing `AIMessage, ToolMessage` import), `from cism.agent.profiles import PhaseProfiles`.

- [ ] **Step 4: Thread `profiles` through `build_graph`**

Modify `cism/agent/graph.py`:

```python
from cism.agent.profiles import PhaseProfiles
```

```python
def build_graph(
    llm: BaseChatModel,
    tools: ToolRegistry,
    guardrails: GuardrailSeam,
    extractors: ExtractorRegistry,
    profiles: PhaseProfiles,
) -> CompiledStateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("think", make_think_node(llm, tools, profiles))
    graph.add_node("act", make_act_node(tools, guardrails.action, profiles))
    graph.add_node("depg_update", make_depg_update_node(extractors))
    graph.add_node("phase_router", make_phase_router())
    graph.add_node("memory_update", make_memory_update_node())
    graph.add_node("respond", make_respond_node(guardrails.output))

    graph.add_edge(START, "think")
    graph.add_conditional_edges("think", route_after_think, {"act": "act", "respond": "respond"})
    graph.add_edge("act", "depg_update")
    graph.add_edge("depg_update", "phase_router")
    graph.add_edge("phase_router", "memory_update")
    graph.add_edge("memory_update", "think")
    graph.add_edge("respond", END)

    return graph.compile()
```

- [ ] **Step 5: Update `core.py` — remove eager bind, construct/accept `profiles`**

Re-read the current file first (coordination note above). Remove the `_bind_tools_if_supported` function and its docstring from `core.py` entirely (relocated to `nodes.py` in Step 3). In `LangGraphAgent.__init__`:

```python
def __init__(
    self,
    llm: BaseChatModel | None = None,
    tools: ToolRegistry | None = None,
    guardrails: GuardrailSeam | None = None,
    extractors: ExtractorRegistry | None = None,
    profiles: PhaseProfiles | None = None,
    target: str = "",
) -> None:
    self.events: asyncio.Queue[AgentEvent] = asyncio.Queue()
    self._llm = llm or DummyChatModel()
    self._tools = tools or ToolRegistry([dummy_nmap, dummy_msfconsole])
    self._guardrails = guardrails or GuardrailSeam.no_op()
    self._extractors = extractors or ExtractorRegistry({}, GenericExtractor())
    self._profiles = profiles or default_profiles(self._tools)
    self._graph = build_graph(self._llm, self._tools, self._guardrails, self._extractors, self._profiles)
    self._phase = PhaseStateMachine(Phase.RECON)
    self._target = target
    self._task: asyncio.Task[None] | None = None
    self._log = get_agent_logger()
    self._last_depg: tuple[tuple[DEPGNode, ...], tuple[DEPGEdge, ...]] = ((), ())
```

Add the import: `from cism.agent.profiles import PhaseProfiles, default_profiles`.

`default_profiles`'s `tool_names` reference real tool names (`nmap`/`curl`/`hydra`); the default registry (`dummy_nmap`/`dummy_msfconsole`) won't match any of them for a fresh `LangGraphAgent()` with no args — `think`'s `[tools.get(name) for name in profile.tool_names if name in tools]` filter already handles this by binding nothing for a phase whose tool names aren't in the registry, which is the same graceful-degrade behavior `_bind_tools_if_supported` already provides for a model that can't bind. This is expected and correct for the bare-default construction path, not a bug to fix here.

- [ ] **Step 6: Run to verify pass**

Run: `pytest tests/test_nodes.py tests/test_langgraph_agent.py -v`
Expected: PASS, all tests.

- [ ] **Step 7: Run the full suite**

Run: `pytest -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add cism/agent/nodes.py cism/agent/graph.py cism/agent/core.py tests/test_nodes.py tests/test_langgraph_agent.py
git commit -m "feat: think/act consume PhaseProfile; relocate tool-binding to per-phase in think"
```

**Part III is now complete.** Each phase has its own prompt, tool subset, and can carry its own extra action-guardrail stages.

---

## Part IV — Tool authoring layer

Fully independent of Parts I–III — touches only `cism/agent/tools/`. Adds three new read-only recon tools (`nikto`, `whatweb`, `dnsenum`) as proof; does not migrate the existing `nmap`/`curl`/`hydra` (Global Constraints).

### Task 15: `cism/agent/tools/catalog.py` — `Capability`, `Flag`, `ToolSpec`

**Files:**
- Create: `cism/agent/tools/catalog.py`
- Test: `tests/test_tool_catalog_data.py`

**Interfaces:**
- Produces: `Capability = Literal["reads", "writes", "executes", "destructive"]`, `Flag(cli, kind="value")`, `ToolSpec(binary, capability, description, flags={}, target="positional", allow_raw=False, timeout=60.0)`, `CATALOG: dict[str, ToolSpec]`.

- [ ] **Step 1: Write the failing tests**

```python
"""cism/agent/tools/catalog.py: the tool catalog is pure data."""

from __future__ import annotations

from cism.agent.tools.catalog import CATALOG, Flag, ToolSpec


def test_every_catalog_row_declares_a_capability() -> None:
    for spec in CATALOG.values():
        assert spec.capability in ("reads", "writes", "executes", "destructive")


def test_nikto_targets_via_a_flag_not_positionally() -> None:
    assert CATALOG["nikto"].target == "-host"


def test_a_bool_flag_defaults_to_value_kind_unless_specified() -> None:
    flag = Flag("-sV")
    assert flag.kind == "value"
    bool_flag = Flag("-sV", "bool")
    assert bool_flag.kind == "bool"


def test_tool_spec_flags_default_to_empty() -> None:
    spec = ToolSpec(binary="x", capability="reads", description="d")
    assert spec.flags == {}
    assert spec.target == "positional"
    assert spec.allow_raw is False
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_tool_catalog_data.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement**

```python
"""Data-driven tool declarations: most CLI tools are `binary <flags>
<target>`, so they are rows here, not hand-written functions. See
cism.agent.tools.base for the factory that turns a row into a real tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

__all__ = ["CATALOG", "Capability", "Flag", "ToolSpec"]

Capability = Literal["reads", "writes", "executes", "destructive"]


@dataclass(frozen=True, slots=True)
class Flag:
    cli: str
    kind: Literal["value", "bool"] = "value"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    binary: str
    capability: Capability
    description: str
    flags: dict[str, Flag] = field(default_factory=dict)
    target: str = "positional"
    allow_raw: bool = False
    timeout: float = 60.0


CATALOG: dict[str, ToolSpec] = {
    "nikto": ToolSpec(
        binary="nikto", capability="reads",
        description="Web server vulnerability scan.",
        target="-host",
    ),
    "whatweb": ToolSpec(
        binary="whatweb", capability="reads",
        description="Fingerprint web technologies in use on a target.",
    ),
    "dnsenum": ToolSpec(
        binary="dnsenum", capability="reads",
        description="Enumerate DNS records and subdomains for a domain.",
    ),
}
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_tool_catalog_data.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cism/agent/tools/catalog.py tests/test_tool_catalog_data.py
git commit -m "feat: kwargs-based ToolSpec catalog for common-shape CLI tools"
```

### Task 16: `cism/agent/tools/base.py` — `build_catalog`, `sandboxed_tool`, `write_lines`

**Files:**
- Create: `cism/agent/tools/base.py`
- Modify: `cism/agent/tools/__init__.py`
- Test: `tests/test_tool_catalog_build.py`, `tests/test_sandboxed_tool_decorator.py`

**Interfaces:**
- Consumes: `cism.agent.tools.catalog.{Capability, Flag, ToolSpec, CATALOG}`, `cism.agent.tools.sandbox.{run_sandboxed, scratch_dir}`.
- Produces: `render_argv(spec, target, **kwargs) -> list[str]`, `build_catalog(catalog: dict[str, ToolSpec]) -> list[BaseTool]`, `write_lines(scratch: Path, filename: str, values: list[str]) -> str`, `sandboxed_tool(binary, capability, timeout=60.0)` decorator producing a `BaseTool`.

Every path here routes through `run_sandboxed` — a data row can no more bypass the sandbox than a hand-written `@tool` function can (Global Constraints, spec §15).

- [ ] **Step 1: Write the failing tests**

`tests/test_tool_catalog_build.py`:

```python
"""cism/agent/tools/base.py: render_argv is pure; build_catalog wires each
row through run_sandboxed and carries its capability tag."""

from __future__ import annotations

from unittest.mock import patch

from cism.agent.tools.base import build_catalog, render_argv
from cism.agent.tools.catalog import Flag, ToolSpec


def test_render_argv_places_a_bool_flag_and_a_value_flag() -> None:
    spec = ToolSpec(
        binary="nmap", capability="reads", description="d",
        flags={"ports": Flag("-p"), "service": Flag("-sV", "bool")},
    )
    argv = render_argv(spec, "10.0.0.5", ports="1-1000", service=True)

    assert argv == ["-p", "1-1000", "-sV", "10.0.0.5"]


def test_render_argv_omits_an_unset_bool_flag() -> None:
    spec = ToolSpec(binary="nmap", capability="reads", description="d", flags={"service": Flag("-sV", "bool")})
    argv = render_argv(spec, "10.0.0.5", service=False)

    assert argv == ["10.0.0.5"]


def test_render_argv_places_target_behind_its_flag_when_not_positional() -> None:
    spec = ToolSpec(binary="nikto", capability="reads", description="d", target="-host")
    argv = render_argv(spec, "10.0.0.5")

    assert argv == ["-host", "10.0.0.5"]


def test_render_argv_appends_extra_only_when_allow_raw() -> None:
    spec = ToolSpec(binary="nmap", capability="reads", description="d", allow_raw=True)
    argv = render_argv(spec, "10.0.0.5", extra="--top-ports 20")

    assert argv == ["--top-ports", "20", "10.0.0.5"]


def test_build_catalog_produces_one_tool_per_row_with_its_capability() -> None:
    catalog = {"nikto": ToolSpec(binary="nikto", capability="reads", description="d", target="-host")}
    (tool,) = build_catalog(catalog)

    assert tool.name == "nikto"
    assert tool.metadata["capability"] == "reads"


def test_a_built_tool_routes_through_run_sandboxed() -> None:
    catalog = {"nikto": ToolSpec(binary="nikto", capability="reads", description="d", target="-host")}
    (tool,) = build_catalog(catalog)

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        result = tool.invoke({"target": "10.0.0.5"})

    assert result == "ok"
    mock_run.assert_called_once()
    assert mock_run.call_args.args[0] == ["nikto", "-host", "10.0.0.5"]
```

`tests/test_sandboxed_tool_decorator.py`:

```python
"""cism/agent/tools/base.py: the escape hatch for tools needing real prep."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from cism.agent.tools.base import sandboxed_tool, write_lines


def test_write_lines_writes_and_returns_the_path(tmp_path: Path) -> None:
    result = write_lines(tmp_path, "users.txt", ["admin", "root"])

    assert Path(result).read_text() == "admin\nroot\n"


def test_decorated_tool_without_scratch_routes_through_run_sandboxed() -> None:
    @sandboxed_tool(binary="whoami-ish", capability="reads")
    def probe(target: str) -> list[str]:
        """Probe a target."""
        return ["-v", target]

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        result = probe.invoke({"target": "10.0.0.5"})

    assert result == "ok"
    assert mock_run.call_args.args[0] == ["whoami-ish", "-v", "10.0.0.5"]


def test_decorated_tool_with_scratch_gets_a_real_directory() -> None:
    seen: list[Path] = []

    @sandboxed_tool(binary="hydra-ish", capability="executes")
    def probe(target: str, *, scratch: Path) -> list[str]:
        """Probe with prep."""
        seen.append(scratch)
        return ["-L", write_lines(scratch, "u.txt", ["admin"]), target]

    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        probe.invoke({"target": "10.0.0.5"})

    assert seen[0].exists() is False  # scratch_dir cleans up on exit
    assert mock_run.call_args.kwargs["cwd"] == seen[0]
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_tool_catalog_build.py tests/test_sandboxed_tool_decorator.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement**

```python
"""The factory and escape hatch behind the tool catalog: every built tool
routes through run_sandboxed, so a data row can no more bypass the sandbox
than a hand-written @tool function can.
"""

from __future__ import annotations

import functools
import shlex
from pathlib import Path
from typing import Any, Callable

from langchain_core.tools import BaseTool, StructuredTool
from pydantic import create_model

from cism.agent.tools.catalog import Capability, ToolSpec
from cism.agent.tools.sandbox import run_sandboxed, scratch_dir

__all__ = ["build_catalog", "render_argv", "sandboxed_tool", "write_lines"]


def render_argv(spec: ToolSpec, target: str, **kwargs: Any) -> list[str]:
    argv: list[str] = []
    for name, flag in spec.flags.items():
        if name not in kwargs or kwargs[name] in (None, False):
            continue
        if flag.kind == "bool":
            argv.append(flag.cli)
        else:
            argv += [flag.cli, str(kwargs[name])]
    if spec.allow_raw and kwargs.get("extra"):
        argv += shlex.split(str(kwargs["extra"]))
    if spec.target == "positional":
        argv.append(target)
    elif spec.target:
        argv += [spec.target, target]
    return argv


def _args_model(name: str, spec: ToolSpec):
    fields: dict[str, Any] = {"target": (str, ...)}
    for flag_name, flag in spec.flags.items():
        fields[flag_name] = (bool, False) if flag.kind == "bool" else (str | None, None)
    if spec.allow_raw:
        fields["extra"] = (str | None, None)
    return create_model(f"{name.title()}Args", **fields)


def _build_one(name: str, spec: ToolSpec) -> BaseTool:
    def _run(**kwargs: Any) -> str:
        target = kwargs.pop("target")
        argv = [spec.binary, *render_argv(spec, target, **kwargs)]
        return run_sandboxed(argv, timeout=spec.timeout)

    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=spec.description,
        args_schema=_args_model(name, spec),
        metadata={"capability": spec.capability},
    )


def build_catalog(catalog: dict[str, ToolSpec]) -> list[BaseTool]:
    """One sandboxed, capability-tagged BaseTool per catalog row."""
    return [_build_one(name, spec) for name, spec in catalog.items()]


def write_lines(scratch: Path, filename: str, values: list[str]) -> str:
    path = scratch / filename
    path.write_text("\n".join(values) + "\n")
    return str(path)


def sandboxed_tool(
    binary: str, capability: Capability, timeout: float = 60.0
) -> Callable[[Callable[..., list[str]]], BaseTool]:
    """Escape hatch for a tool needing real prep (file materialization,
    subcommands) rather than the flat flags-and-target shape build_catalog
    covers. The wrapped function returns only the argv tail; this decorator
    still owns the sandbox call, exactly like build_catalog's rows do."""

    def decorator(func: Callable[..., list[str]]) -> BaseTool:
        needs_scratch = "scratch" in func.__code__.co_varnames

        @functools.wraps(func)
        def _run(**kwargs: Any) -> str:
            if needs_scratch:
                with scratch_dir() as tmp:
                    argv_tail = func(scratch=tmp, **kwargs)
                    return run_sandboxed([binary, *argv_tail], cwd=tmp, timeout=timeout)
            argv_tail = func(**kwargs)
            return run_sandboxed([binary, *argv_tail], timeout=timeout)

        return StructuredTool.from_function(
            func=_run, name=func.__name__, description=func.__doc__ or "",
            metadata={"capability": capability},
        )

    return decorator
```

- [ ] **Step 4: Export the new catalog tools**

Modify `cism/agent/tools/__init__.py`:

```python
"""Tool registration — see :mod:`cism.agent.tools.registry`."""

from __future__ import annotations

from .base import build_catalog
from .catalog import CATALOG
from .dummy import dummy_msfconsole, dummy_nmap
from .registry import ToolRegistry

__all__ = ["CATALOG", "ToolRegistry", "build_catalog", "dummy_msfconsole", "dummy_nmap"]
```

- [ ] **Step 5: Run to verify pass**

Run: `pytest tests/test_tool_catalog_build.py tests/test_sandboxed_tool_decorator.py -v`
Expected: PASS

- [ ] **Step 6: Run the full suite**

Run: `pytest -v`
Expected: PASS — this is the full plan exercised together.

- [ ] **Step 7: Commit**

```bash
git add cism/agent/tools/base.py cism/agent/tools/__init__.py tests/test_tool_catalog_build.py tests/test_sandboxed_tool_decorator.py
git commit -m "feat: build_catalog factory and sandboxed_tool decorator for new tools"
```

**Part IV is now complete.** Adding a new common-shape tool is a `CATALOG` row; a tool needing real prep is a `@sandboxed_tool`-decorated function. Both are sandboxed and capability-tagged from birth.

---

## Self-Review

**Spec coverage** — every in-scope item from the design spec (§2) maps to a task:
- Node/Edge/Evidence schema, derived identity key → Task 1
- Normalization → Task 2
- SupportPolicy/reducer → Task 3
- Dirty-frontier settle, DAG enforcement → Task 4
- Prune → Task 5
- Precondition edge-creation rule → Task 6
- Two real extractors + updated generic → Task 7
- depg_update wiring (failures tracked, linking, settle, prune) → Task 8
- `contested` wire-format addition → Task 9
- `memory_update` node, memory bridge → Tasks 10–12
- Phase-parameterized `think`/`act` via `PhaseProfile` → Tasks 13–14
- Tool-authoring layer (`ToolSpec`, `sandboxed_tool`, capability tags) → Tasks 15–16

Deliberately out of scope per the spec (§2/§12) and *not* tasked here: RWX guardrail stages, `BubblewrapRunner`/sandbox isolation, γ/graded propagation, IP↔hostname aliasing, LLM-backed extraction, per-phase subagents, YAML catalog externalization, migrating the existing nmap/curl/hydra onto the new catalog layer.

**Update, 2026-09-01:** four of these are no longer deferred — see [2026-09-01-unified-toolkit-and-llm-extraction-design.md](../specs/2026-09-01-unified-toolkit-and-llm-extraction-design.md), which designs LLM-backed extraction (§8), YAML catalog externalization for `CATALOG` specifically (§4 — `EXTRACTORS` deliberately stays Python), migrating nmap/curl/hydra onto the catalog layer (§10), and a dangerous-flag guardrail stage plus a portable sandbox-runner seam that partially covers the RWX/sandbox-isolation item (§6–§7, not the full workstream). `BubblewrapRunner` itself, γ/graded propagation, IP↔hostname aliasing, and per-phase subagents remain fully deferred.

**Placeholder scan** — no TBD/TODO markers; every step carries real code or an exact command. The two spots that ask an implementer to "re-read the current file first" (Tasks 12 and 14) are not placeholders — they are explicit coordination instructions for files under concurrent modification by a parallel agent, with the exact diff still fully specified against the version quoted in this plan.

**Type/signature consistency** — traced across tasks: `Node.id`/`derive_node_id` (Tasks 1, 6, 7, 8) match; `Evidence.verdict/call_id` (Task 1) match their use in Tasks 3, 4, 7, 11; `Graph.settle`/`prune`/`last_for_target` (Tasks 4, 5) match their call sites in Task 8; `MemoryStore.upsert`/`snapshot` signature (Task 10) matches Task 11's calls; `make_think_node`/`make_act_node`/`build_graph` signatures are updated consistently across Tasks 8 (unaffected — depg_update's own signature never changes), 12 (adds `memory_update` node/edge only), and 14 (adds `tools`/`profiles` params) — Task 12's `build_graph` call in `core.py` is superseded by Task 14's version of the same call site; Task 14 quotes the full replacement so there is no partial/contradictory intermediate state once both are applied in order.

**Scope check** — four subsystems (DEPG core, memory bridge, phase profiles, tool authoring), each ending in a "Part N is now complete" checkpoint with working, testable software; Parts II–IV depend only on Part I's foundational types, not on each other, so they can be executed and reviewed in any order after Part I if that's ever useful, though the plan is written in the dependency-safe order (I → II → III → IV).
