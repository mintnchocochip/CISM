"""cism/tui/widgets/depg_modal.py: a contested node must not crash rendering
and must resolve to a distinct style, not silently fall back to another
state's color."""

from __future__ import annotations

from cism.tui.widgets.depg_modal import STATE_CLASS


def test_contested_has_its_own_style_class() -> None:
    assert "contested" in STATE_CLASS
    assert STATE_CLASS["contested"] not in (
        STATE_CLASS["blocked"], STATE_CLASS["resolved"], STATE_CLASS["untested"],
    )
