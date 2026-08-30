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
