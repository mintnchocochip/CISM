"""cism/agent/tools/registry.py: a hard allowlist, not a lookup convenience."""

from __future__ import annotations

import pytest

from cism.agent.tools import ToolRegistry, dummy_msfconsole, dummy_nmap


def test_registered_tools_are_reachable_by_name() -> None:
    registry = ToolRegistry([dummy_nmap, dummy_msfconsole])
    assert registry.get("dummy_nmap") is dummy_nmap
    assert registry.get("dummy_msfconsole") is dummy_msfconsole
    assert set(t.name for t in registry.all()) == {"dummy_nmap", "dummy_msfconsole"}


def test_unregistered_name_raises_rather_than_returning_none() -> None:
    registry = ToolRegistry([dummy_nmap])
    with pytest.raises(KeyError):
        registry.get("dummy_msfconsole")


def test_contains_reflects_the_allowlist() -> None:
    registry = ToolRegistry([dummy_nmap])
    assert "dummy_nmap" in registry
    assert "anything_else" not in registry


def test_a_tool_not_constructed_into_the_registry_is_never_reachable() -> None:
    """The registry is the only way in — omission is exclusion."""
    registry = ToolRegistry([])
    assert registry.all() == []
    with pytest.raises(KeyError):
        registry.get("dummy_nmap")
