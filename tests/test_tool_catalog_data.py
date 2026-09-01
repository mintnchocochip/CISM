"""cism/agent/tools/catalog.py: ToolSpec/Flag are Pydantic models loaded
from catalog.yaml; phases_for() derives a tool's phase availability from
its capability unless the row overrides it explicitly."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cism.agent.state import Phase
from cism.agent.tools.catalog import CATALOG, Flag, ToolSpec, phases_for


def test_every_catalog_row_declares_a_capability() -> None:
    for spec in CATALOG.values():
        assert spec.capability in ("reads", "writes", "executes", "destructive")


def test_nikto_targets_via_a_flag_not_positionally() -> None:
    assert CATALOG["nikto"].target == "-host"


def test_a_bool_flag_defaults_to_value_kind_unless_specified() -> None:
    flag = Flag(cli="-sV")
    assert flag.kind == "value"
    bool_flag = Flag(cli="-sV", kind="bool")
    assert bool_flag.kind == "bool"


def test_tool_spec_flags_default_to_empty() -> None:
    spec = ToolSpec(binary="x", capability="reads", description="d")
    assert spec.flags == {}
    assert spec.target == "positional"
    assert spec.allow_raw is False
    assert spec.help_flag == "--help"
    assert spec.phases is None


def test_an_invalid_capability_literal_raises_a_validation_error() -> None:
    with pytest.raises(ValidationError):
        ToolSpec(binary="x", capability="deletes-everything", description="d")


def test_phases_for_a_reads_tool_with_no_override_defaults_to_early_phases() -> None:
    spec = ToolSpec(binary="x", capability="reads", description="d")
    assert phases_for(spec) == frozenset(
        {Phase.RECON, Phase.ENUMERATION, Phase.VULNERABILITY_DISCOVERY}
    )


def test_phases_for_an_executes_tool_with_no_override_is_unreachable() -> None:
    spec = ToolSpec(binary="x", capability="executes", description="d")
    assert phases_for(spec) == frozenset()


def test_phases_for_respects_an_explicit_override() -> None:
    spec = ToolSpec(
        binary="x", capability="executes", description="d",
        phases=["exploitation", "post-exploitation"],
    )
    assert phases_for(spec) == frozenset({Phase.EXPLOITATION, Phase.POST_EXPLOITATION})


def test_an_unknown_phase_name_in_the_override_raises_at_construction() -> None:
    with pytest.raises((KeyError, ValidationError)):
        ToolSpec(binary="x", capability="reads", description="d", phases=["not-a-real-phase"])
