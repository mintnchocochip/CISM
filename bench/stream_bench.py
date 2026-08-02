"""Streaming benchmark: RichLog versus an updating Static.

The design question is narrow. Narration arrives as tokens that belong to one
wrapping paragraph, so the widget holding it is rewritten thousands of times
per run. Three strategies are measured over the same token stream:

``static-buffer``
    One Rich ``Text`` owned by the widget. Tokens are appended to it and the
    widget is refreshed on a coalescing timer. This is what the TUI ships.

``richlog-rewrite``
    A ``RichLog`` cleared and rewritten on every flush. RichLog is append-only
    with no way to edit the last line, so streaming into a paragraph means
    replaying the whole buffer.

``static-naive``
    ``Static.update("".join(buffer))`` on every single token — the obvious
    implementation, included to show what the coalescing timer is worth.

Run::

    python bench/stream_bench.py --tokens 4000
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import RichLog, Static

#: Tokens are flushed to the screen at this cadence, matching NarrationEntry.
FLUSH_INTERVAL = 0.06

SAMPLE = (
    "The traversal is confirmed and its generality is high so it is worth "
    "spending the budget here pulling web.xml first if it carries datasource "
    "credentials the mysql branch resolves without touching the login form "
    ).split()


def token_stream(count: int) -> list[str]:
    return [SAMPLE[i % len(SAMPLE)] + " " for i in range(count)]


class BenchApp(App[None]):
    """Hosts all three widgets so each is measured in a real layout."""

    CSS = "Screen { layout: vertical; } RichLog, Static { height: 1fr; }"

    def compose(self) -> ComposeResult:
        yield Static(id="static-buffer")
        yield Static(id="static-naive")
        yield RichLog(id="richlog", wrap=True, markup=False)


async def measure(tokens: list[str], width: int, height: int) -> dict[str, dict]:
    results: dict[str, dict] = {}
    app = BenchApp()
    async with app.run_test(size=(width, height)) as pilot:
        buffer_widget = app.query_one("#static-buffer", Static)
        naive_widget = app.query_one("#static-naive", Static)
        rich_log = app.query_one("#richlog", RichLog)

        flush_every = max(int(len(tokens) * FLUSH_INTERVAL / 2), 1)

        # -- static-buffer: mutate one Text, refresh on a cadence ----------
        text = Text()
        buffer_widget.update(text)
        start = time.perf_counter()
        for index, token in enumerate(tokens):
            text.append(token)
            if index % flush_every == 0:
                buffer_widget.refresh(layout=True)
        buffer_widget.refresh(layout=True)
        append = time.perf_counter() - start
        await pilot.pause()
        start = time.perf_counter()
        app.screen._compositor.render_strips()
        results["static-buffer"] = {
            "append_s": append,
            "render_s": time.perf_counter() - start,
        }

        # -- richlog-rewrite: clear and replay the buffer on each flush ----
        parts: list[str] = []
        start = time.perf_counter()
        for index, token in enumerate(tokens):
            parts.append(token)
            if index % flush_every == 0:
                rich_log.clear()
                rich_log.write(Text("".join(parts)))
        rich_log.clear()
        rich_log.write(Text("".join(parts)))
        append = time.perf_counter() - start
        await pilot.pause()
        start = time.perf_counter()
        app.screen._compositor.render_strips()
        results["richlog-rewrite"] = {
            "append_s": append,
            "render_s": time.perf_counter() - start,
        }

        # -- static-naive: join and update on every token ------------------
        parts = []
        start = time.perf_counter()
        for token in tokens:
            parts.append(token)
            naive_widget.update("".join(parts))
        append = time.perf_counter() - start
        await pilot.pause()
        start = time.perf_counter()
        app.screen._compositor.render_strips()
        results["static-naive"] = {
            "append_s": append,
            "render_s": time.perf_counter() - start,
        }

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Narration streaming benchmark")
    parser.add_argument("--tokens", type=int, default=4000)
    parser.add_argument("--width", type=int, default=100)
    parser.add_argument("--height", type=int, default=30)
    args = parser.parse_args(argv)

    tokens = token_stream(args.tokens)
    results = asyncio.run(measure(tokens, args.width, args.height))

    print(f"\n{args.tokens} tokens, {args.width}x{args.height} terminal\n")
    print(f"{'strategy':<18}{'append':>12}{'per token':>14}{'render':>12}")
    print("-" * 56)
    for name, data in results.items():
        per_token = data["append_s"] / args.tokens * 1e6
        print(
            f"{name:<18}{data['append_s'] * 1000:>10.1f}ms"
            f"{per_token:>11.1f}µs{data['render_s'] * 1000:>10.1f}ms"
        )
    print()
    baseline = results["static-buffer"]["append_s"]
    for name, data in results.items():
        if name != "static-buffer":
            print(f"  {name} is {data['append_s'] / baseline:.1f}x static-buffer")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
