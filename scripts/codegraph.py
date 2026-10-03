#!/usr/bin/env python
"""Regenerates the module-dependency Mermaid diagram in
.claude/skills/cism-map/SKILL.md. Stdlib-only (ast + pathlib), so there's
nothing extra to install or keep in sync. Run after any change that adds,
removes, or rewires an import between cism/ subpackages:

    .venv/bin/python scripts/codegraph.py
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "cism"
SKILL_FILE = ROOT / ".claude" / "skills" / "cism-map" / "SKILL.md"
START_MARKER = "<!-- codegraph:start -->"
END_MARKER = "<!-- codegraph:end -->"


def _subpackage(module: str) -> str | None:
    """'cism.agent.tools.sandbox' -> 'agent.tools'; 'cism.agent.core' -> 'agent'."""
    parts = module.split(".")
    if len(parts) < 2 or parts[0] != "cism":
        return None
    return parts[1] if len(parts) == 2 else f"{parts[1]}.{parts[2]}" if parts[1] == "tui" and parts[2] == "widgets" else parts[1]


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def build_edges() -> set[tuple[str, str]]:
    edges: set[tuple[str, str]] = set()
    for path in PACKAGE.rglob("*.py"):
        rel = path.relative_to(PACKAGE).with_suffix("")
        own_parts = rel.parts
        own = own_parts[0] if len(own_parts) == 1 else (
            f"{own_parts[0]}.{own_parts[1]}" if own_parts[0] == "tui" and own_parts[1] == "widgets" else own_parts[0]
        )
        for module in _imports(path):
            target = _subpackage(module)
            if target and target != own:
                edges.add((own, target))
    return edges


def to_mermaid(edges: set[tuple[str, str]]) -> str:
    lines = ["```mermaid", "graph LR"]
    for src, dst in sorted(edges):
        lines.append(f"    {src} --> {dst}")
    lines.append("```")
    return "\n".join(lines)


def main() -> None:
    diagram = to_mermaid(build_edges())
    text = SKILL_FILE.read_text()
    start = text.index(START_MARKER) + len(START_MARKER)
    end = text.index(END_MARKER)
    SKILL_FILE.write_text(f"{text[:start]}\n{diagram}\n{text[end:]}")
    print(diagram)


if __name__ == "__main__":
    main()
