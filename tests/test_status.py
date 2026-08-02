"""Status-line elision, the spinner glyph invariants, and credential masking."""

from __future__ import annotations

import unicodedata

import pytest
from conftest import replay_all, settle
from rich.cells import cell_len

from cism.tui.redact import MASK, looks_like_secret, redact_command
from cism.tui.widgets.spinner import GLYPHS
from cism.tui.widgets.status import SEPARATOR, Segment, StatusBar, elide


# -- spinner ---------------------------------------------------------------


@pytest.mark.parametrize("glyph", GLYPHS, ids=[f"U+{ord(g):04X}" for g in GLYPHS])
def test_spinner_glyphs_are_exactly_one_cell(glyph: str) -> None:
    """A double-width frame would shift the whole line as the spinner cycles."""
    assert cell_len(glyph) == 1


@pytest.mark.parametrize("glyph", GLYPHS, ids=[f"U+{ord(g):04X}" for g in GLYPHS])
def test_spinner_glyphs_are_not_ambiguous_width(glyph: str) -> None:
    """East-Asian-Ambiguous glyphs render double-width in some terminals."""
    assert unicodedata.east_asian_width(glyph) == "N"


def test_spinner_has_more_than_one_frame() -> None:
    assert len(set(GLYPHS)) > 1


# -- elision ---------------------------------------------------------------


def demo_segments() -> list[Segment]:
    bar = StatusBar()
    bar.model = "qwen2.5-7b"
    bar.phase = "recon"
    bar.ctx_used = 12420
    bar.ctx_max = 32768
    bar.tokens_per_second = 47
    bar.target_os = "linux"
    bar.target_stack = ("nginx",)
    bar.depg_nodes = 47
    bar.mem_t1, bar.mem_t2, bar.mem_t3 = 8, 31, 5
    return bar.segments()


def render(segments: list[Segment]) -> str:
    return SEPARATOR.join(s.full for s in segments)


def test_everything_fits_at_full_width() -> None:
    line = render(elide(demo_segments(), 200))
    assert "qwen2.5-7b" in line
    assert "phase: recon" in line
    assert "ctx 12.4k/32k (38%)" in line
    assert "47 tok/s" in line
    assert "linux·nginx" in line
    assert "depg 47 nodes" in line
    assert "mem T1:8 T2:31 T3:5" in line
    assert "⏵⏵ auto" in line


@pytest.mark.parametrize("width", [200, 140, 120, 110, 100, 88, 76, 64, 56, 44])
def test_elision_never_exceeds_the_budget(width: int) -> None:
    assert len(render(elide(demo_segments(), width))) <= width


@pytest.mark.parametrize("width", [200, 120, 100, 88, 76, 64, 56, 44, 30, 10])
def test_essentials_always_survive(width: int) -> None:
    keys = {s.key for s in elide(demo_segments(), width)}
    assert {"model", "phase", "ctx", "mode"} <= keys


def test_detail_is_lost_before_fields_are() -> None:
    """At 100 columns the line should shorten, not start dropping fields."""
    kept = elide(demo_segments(), 100)
    assert {s.key for s in kept} == {s.key for s in demo_segments()}
    assert "depg 47" in render(kept)
    assert "depg 47 nodes" not in render(kept)


def test_low_priority_fields_go_first() -> None:
    kept = {s.key for s in elide(demo_segments(), 64)}
    assert "depg" not in kept  # priority 3
    assert "ctx" in kept  # priority 1


def test_absent_values_are_omitted_entirely() -> None:
    bar = StatusBar()
    keys = {s.key for s in bar.segments()}
    assert "rate" not in keys  # no tokens produced yet
    assert "target" not in keys  # no environment declared
    assert "model" not in keys  # no session state received


def test_context_warning_style_engages_near_the_limit() -> None:
    bar = StatusBar()
    bar.ctx_used, bar.ctx_max = 30000, 32768
    ctx = next(s for s in bar.segments() if s.key == "ctx")
    assert ctx.style == "status--warn"


# -- credential masking ----------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "sk-proj-AbCd1234EfGh5678IjKl9012",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "xoxb-1234567890-abcdefghijkl",
        "AKIAIOSFODNN7EXAMPLE1234",
        "bearer_abcdefghijklmnop",
        "aVeryLongOpaqueTokenWithNoSpaces123456",
    ],
)
def test_credential_shapes_are_detected(value: str) -> None:
    assert looks_like_secret(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "linux",
        "exploitation",
        "phi-3.5-mini",
        "https://infer.example/v1",
        "http://localhost:8080/v1",
        "local",
        "vulnerability-analysis",
    ],
)
def test_ordinary_arguments_are_not_flagged(value: str) -> None:
    assert looks_like_secret(value) is False


def test_redaction_masks_only_the_credential() -> None:
    line = redact_command("/api sk-proj-AbCd1234EfGh5678IjKl9012")
    assert line == f"/api {MASK}"


def test_redaction_leaves_normal_commands_untouched() -> None:
    assert redact_command("/target windows iis") == "/target windows iis"
    assert redact_command("scan 10.0.0.5") == "scan 10.0.0.5"


# -- live wiring -----------------------------------------------------------


async def test_status_bar_reports_the_session_model(app_and_agent) -> None:
    app, agent = app_and_agent
    async with app.run_test(size=(140, 32)) as pilot:
        await replay_all(pilot, agent)
        assert app.status.model == "qwen2.5-7b-instruct"
        assert app.status.target_os == "linux"
        assert app.status.target_stack == ("apache", "php")
        assert "qwen2.5-7b-instruct" in app.status.render().plain


async def test_token_rate_needs_a_real_span(quiet_app) -> None:
    """Events replayed with no delay must not report an infinite rate."""
    from cism.tui.events import TokenDelta

    app, agent = quiet_app
    async with app.run_test(size=(140, 32)) as pilot:
        for total in (100, 200, 300):
            agent.events.put_nowait(TokenDelta(100, total, total * 2, 32768))
        await settle(pilot)
        assert app.status.tokens_per_second == 0.0


async def test_token_rate_clears_when_the_run_ends(quiet_app) -> None:
    from cism.tui.events import RunFinished

    app, agent = quiet_app
    async with app.run_test(size=(140, 32)) as pilot:
        app.status.tokens_per_second = 42.0
        agent.events.put_nowait(RunFinished("r1", True))
        await settle(pilot)
        assert app.status.tokens_per_second == 0.0
