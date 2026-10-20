"""Offline ablation of the compaction tiers, on real recorded engagement data.

Rebuilds the message sequence from a recorded run, then calls the shipped
``_compact_history`` (cism.agent.nodes) over it with each tier disabled, and
sweeps the context window to find where each tier starts paying for itself.

No lab, no model weights, no network: this is the shipped function on real
content, so the numbers are measured rather than modelled. The reconstruction
is a lower bound on the real prompt, because the recording stores a tool
result's summary and line count rather than its full body, so what is
reported here is the *shape* of the tradeoff, not the exact token totals of
that engagement.

    python scripts/ablate_compaction.py [recording.jsonl]
"""

from __future__ import annotations

import json
import sys

from langchain_core.messages import AIMessage, ToolMessage

import cism.agent.nodes as nodes

DEFAULT_RECORDING = "demo-recording/gemma-dvwa-run.jsonl"
#: ctx_max the server reported during the recorded run.
OBSERVED_WINDOW = 98_304
SWEEP = (8_192, 16_384, 32_768, 49_152, 65_536, 98_304)
#: A recorded ToolFinished keeps the summary and a line count, not the body.
#: Rebuild a body of about the right size so message costs stay realistic.
CHARS_PER_OUTPUT_LINE = 60


def load_messages(path: str) -> list:
    messages: list = []
    streaming: dict[str, list[str]] = {}
    for line in open(path, encoding="utf8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = event.get("type")
        if kind == "Narration":
            streaming.setdefault(event["entry_id"], []).append(event.get("text", ""))
            if event.get("done"):
                messages.append(AIMessage(content="".join(streaming.pop(event["entry_id"], []))))
        elif kind == "ToolStarted":
            messages.append(
                AIMessage(
                    content="",
                    tool_calls=[{
                        "name": event.get("tool", "tool"),
                        "args": {"raw": event.get("args", "")},
                        "id": event["call_id"],
                    }],
                )
            )
        elif kind == "ToolFinished":
            body = (event.get("summary") or "") + "\n"
            body += ("x" * CHARS_PER_OUTPUT_LINE + "\n") * int(event.get("lines") or 0)
            messages.append(ToolMessage(content=body, tool_call_id=event["call_id"]))
        elif kind == "ToolFailed":
            messages.append(ToolMessage(content=event.get("reason", "failed"), tool_call_id=event["call_id"]))
    return messages


def compact_with(messages: list, system: str, window: int, tiers: set[str]) -> tuple[int, int, int]:
    """Run the shipped _compact_history with only ``tiers`` enabled."""
    shrink, stub = nodes._shrink_old_tool_output, nodes._stub_old_tool_output
    try:
        if "shrink" not in tiers:
            nodes._shrink_old_tool_output = lambda m: m
        if "stub" not in tiers:
            nodes._stub_old_tool_output = lambda m: m
        kept, dropped = nodes._compact_history(messages, system, window)
        sent = sum(nodes._message_cost(m) for m in kept) + nodes._estimate_tokens(system)
        return len(kept), dropped, sent
    finally:
        nodes._shrink_old_tool_output, nodes._stub_old_tool_output = shrink, stub


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RECORDING
    messages = load_messages(path)
    system = "You are CISM, an autonomous VAPT agent. " * 40
    raw = sum(nodes._message_cost(m) for m in messages) + nodes._estimate_tokens(system)

    print(f"recording            : {path}")
    print(f"reconstructed turns  : {len(messages)}")
    print(f"uncompacted prompt   : {raw} tokens")
    print(f"observed window      : {OBSERVED_WINDOW}")
    print()
    print("turns lost, by context window and by which tiers are enabled")
    print(f'{"window":>9}{"uncompacted":>16}{"drop only":>12}{"+ shrink":>11}{"+ stub":>9}')
    for window in SWEEP:
        row = [compact_with(messages, system, window, t)[1]
               for t in (set(), {"shrink"}, {"shrink", "stub"})]
        state = f"over by {raw - window}" if raw > window else "fits"
        print(f"{window:>9}{state:>16}{row[0]:>12}{row[1]:>11}{row[2]:>9}")


if __name__ == "__main__":
    main()
