"""cism/agent/tools/registry.py: a hard allowlist — get() raises on an
unregistered name rather than falling back."""

from __future__ import annotations

import pytest
from langchain_core.tools import tool

from cism.agent.tools.registry import ToolRegistry


@tool
def _stub(target: str) -> str:
    """A stub tool."""
    return target


def test_get_returns_a_registered_tool() -> None:
    registry = ToolRegistry([_stub])

    assert registry.get("_stub") is _stub


def test_get_raises_on_an_unknown_tool_name() -> None:
    registry = ToolRegistry([_stub])

    with pytest.raises(KeyError):
        registry.get("not-registered")


def test_contains_reflects_registration() -> None:
    registry = ToolRegistry([_stub])

    assert "_stub" in registry
    assert "not-registered" not in registry


def test_all_returns_every_registered_tool() -> None:
    registry = ToolRegistry([_stub])

    assert registry.all() == [_stub]
