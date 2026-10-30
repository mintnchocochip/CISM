"""Renders a Report's Markdown into a print-ready PDF — the same
``to_markdown()`` text the ``.md`` deliverable carries, so the two never
drift. Markdown stays the single source of truth; this module only changes
the container.

Deliberately dependency-free, the same way ``cism/report/graph_viz.py``
leans on the system ``dot`` binary rather than the ``graphviz`` package:
a small pure-Python Markdown→HTML pass (covering exactly the constructs
``build.py`` emits — headings, bullet lists, pipe tables, fenced code,
inline code/bold/italic) feeds a best-effort headless-browser print. The
browser is the one PDF engine that is already present wherever a demo is
shown (and one apt line in the Dockerfile otherwise), so a missing
renderer loses only the ``.pdf`` — the ``.html`` always lands, exactly as
``write_graph`` always lands the ``.dot``.
"""

from __future__ import annotations

import contextlib
import html
import os
import re
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

from cism.report.build import Report

__all__ = ["markdown_to_html", "write_pdf"]

_RENDER_TIMEOUT_S = 60.0

#: Browser binaries we know how to drive with ``--print-to-pdf``. Order is
#: preference; an explicit ``CISM_PDF_BROWSER`` wins over all of them.
_BROWSER_NAMES = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
)

#: Clean, print-first styling. Not the deck's Terminal Noir — a report is
#: read on paper/PDF, where dark backgrounds waste toner and light-on-dark
#: body text is harder to read. Monospaced only where the Markdown marked
#: something as code, matching the source register.
_CSS = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body {
  font: 11pt/1.5 "Helvetica Neue", Arial, sans-serif;
  color: #1a1a1a; max-width: 100%; margin: 0;
}
h1 { font-size: 20pt; margin: 0 0 4pt; }
h2 { font-size: 14pt; margin: 18pt 0 6pt; border-bottom: 1px solid #ddd; padding-bottom: 3pt; }
h3 { font-size: 11.5pt; margin: 12pt 0 4pt; }
h4 { font-size: 11pt; margin: 10pt 0 4pt; color: #444; }
p, li { margin: 3pt 0; }
ul { margin: 4pt 0; padding-left: 18pt; }
li > ul { margin: 2pt 0; }
code { font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9.5pt; background: #f4f4f4; padding: 0.5pt 3pt; border-radius: 3px; }
pre { background: #f4f4f4; padding: 8pt 10pt; border-radius: 4px; overflow-x: auto;
  white-space: pre-wrap; word-break: break-word; }
pre code { background: none; padding: 0; font-size: 9pt; }
table { border-collapse: collapse; margin: 6pt 0; width: 100%; font-size: 9.5pt; }
th, td { border: 1px solid #ccc; padding: 3pt 6pt; text-align: left; vertical-align: top;
  word-break: break-word; }
th { background: #f0f0f0; }
blockquote { margin: 6pt 0; padding-left: 10pt; border-left: 3px solid #ccc; color: #555; }
"""

_INLINE_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<![A-Za-z0-9])[*_]([^*_\n]+)[*_](?![A-Za-z0-9])")


def _inline(text: str) -> str:
    """Escapes HTML, then re-applies the inline Markdown spans. Code spans
    are extracted first so their contents are never touched by the bold or
    italic passes (a ```**x**`` must stay literal)."""
    codes: list[str] = []

    def _stash(m: re.Match[str]) -> str:
        codes.append(html.escape(m.group(1)))
        return f"\x00{len(codes) - 1}\x00"

    text = _INLINE_CODE.sub(_stash, text)
    text = html.escape(text)
    text = _BOLD.sub(r"<strong>\1</strong>", text)
    text = _ITALIC.sub(r"<em>\1</em>", text)
    return re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{codes[int(m.group(1))]}</code>", text)


def _is_table_sep(line: str) -> bool:
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    return bool(cells) and all(re.fullmatch(r":?-+:?", c) for c in cells)


def _split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def markdown_to_html(md: str, *, title: str) -> str:
    """Renders the report Markdown dialect — the constructs ``build.py``
    emits plus the pipe tables, fenced code and blockquotes that augmented
    reports carry — into a standalone, print-styled HTML document."""
    lines = md.splitlines()
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]

        if line.startswith("```"):
            buf: list[str] = []
            i += 1
            while i < n and not lines[i].startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1  # closing fence (or EOF)
            out.append(f"<pre><code>{html.escape(chr(10).join(buf))}</code></pre>")
            continue

        if not line.strip():
            i += 1
            continue

        m = re.match(r"(#{1,6})\s+(.*)", line)
        if m:
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(m.group(2).strip())}</h{level}>")
            i += 1
            continue

        # Pipe table: a header row immediately followed by a separator row.
        if line.lstrip().startswith("|") and i + 1 < n and _is_table_sep(lines[i + 1]):
            header = _split_row(line)
            i += 2
            rows: list[list[str]] = []
            while i < n and lines[i].lstrip().startswith("|"):
                rows.append(_split_row(lines[i]))
                i += 1
            head = "".join(f"<th>{_inline(c)}</th>" for c in header)
            body = "".join(
                "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>" for r in rows
            )
            out.append(f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
            continue

        if re.match(r"\s*[-*]\s+", line):
            out.append("<ul>")
            depth = 1
            while i < n and re.match(r"\s*[-*]\s+", lines[i]):
                indent = len(lines[i]) - len(lines[i].lstrip())
                want = 2 if indent >= 2 else 1
                while depth < want:
                    out.append("<ul>")
                    depth += 1
                while depth > want:
                    out.append("</ul>")
                    depth -= 1
                content = re.sub(r"\s*[-*]\s+", "", lines[i], count=1)
                out.append(f"<li>{_inline(content)}</li>")
                i += 1
            while depth > 0:
                out.append("</ul>")
                depth -= 1
            continue

        if line.startswith(">"):
            buf = []
            while i < n and lines[i].startswith(">"):
                buf.append(lines[i].lstrip(">").strip())
                i += 1
            out.append(f"<blockquote>{_inline(' '.join(buf))}</blockquote>")
            continue

        # Paragraph: consume the current line, then gather following plain
        # lines. Consuming the current line unconditionally guarantees
        # progress — a line that starts no known block (e.g. a stray `|`
        # from ASCII art, which is not a real table without a separator
        # row) becomes paragraph text rather than spinning the loop.
        buf = [line.strip()]
        i += 1
        while i < n and lines[i].strip() and not re.match(r"(#{1,6}\s|\s*[-*]\s|>|```)", lines[i]):
            nxt = lines[i]
            if nxt.lstrip().startswith("|") and i + 1 < n and _is_table_sep(lines[i + 1]):
                break
            buf.append(nxt.strip())
            i += 1
        out.append(f"<p>{_inline(' '.join(buf))}</p>")

    body = "\n".join(out)
    return (
        "<!doctype html>\n<html><head><meta charset=\"utf-8\">\n"
        f"<title>{html.escape(title)}</title>\n<style>{_CSS}</style>\n"
        f"</head>\n<body>\n{body}\n</body></html>\n"
    )


def _find_browser() -> str | None:
    override = os.environ.get("CISM_PDF_BROWSER")
    if override:
        return override if (shutil.which(override) or Path(override).is_file()) else None
    for name in _BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    # Playwright's managed install is a common offline fallback (and is how
    # the shipped container gets a browser); match any pinned version.
    pw_root = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers"))
    if pw_root.is_dir():
        for chrome in sorted(pw_root.glob("chromium-*/chrome-linux/chrome"), reverse=True):
            if chrome.is_file():
                return str(chrome)
    return None


def _render_pdf(browser: str, html_path: Path, pdf_path: Path) -> bool:
    # Headless Chromium spawns a zygote and a crashpad handler that outlive
    # the launcher and inherit its stdio. Capturing output would make a
    # timeout hang on the pipe those children hold, so stdio goes to
    # DEVNULL and the whole process group is killed on timeout — the same
    # "kill the tree, not the leaf" rule the sandbox runner follows.
    argv = [
        browser,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_path}",
        html_path.resolve().as_uri(),
    ]
    with tempfile.TemporaryDirectory(prefix="cism-pdf-") as profile:
        argv.insert(-1, f"--user-data-dir={profile}")
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            return False
        try:
            rc = proc.wait(timeout=_RENDER_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            return False
        if rc != 0:
            return False
    return pdf_path.is_file() and pdf_path.stat().st_size > 0


def write_pdf(report: Report, out_dir: Path) -> Path:
    """Writes ``<run_id>.html`` always, and ``<run_id>.pdf`` alongside it
    when a headless browser is available and the print succeeds. Like
    ``write_graph``, the PDF is best-effort: a caller that needs to know
    whether it landed checks the returned path's ``.with_suffix(".pdf")``
    rather than this raising over a missing renderer."""
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / f"{report.run_id}.html"
    html_path.write_text(
        markdown_to_html(report.to_markdown(), title=f"CISM report — {report.target}"),
        encoding="utf-8",
    )
    browser = _find_browser()
    if browser is not None:
        _render_pdf(browser, html_path, html_path.with_suffix(".pdf"))
    return html_path
