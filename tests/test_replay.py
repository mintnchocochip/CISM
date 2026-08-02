"""The replayer: log parsing, stream expansion, ordering, and interrupts."""

from __future__ import annotations

import asyncio

import pytest

from cism.tui.events import (
    Agent,
    Interrupted,
    Narration,
    RunStarted,
    SessionState,
    ToolStarted,
)
from cism.tui.replay import FakeAgent, ReplayLogError, load_log

from conftest import DEMO_LOG


def write_log(tmp_path, *lines: str):
    path = tmp_path / "log.jsonl"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def test_demo_log_parses() -> None:
    steps = load_log(DEMO_LOG)
    assert len(steps) > 20


def test_fake_agent_satisfies_the_agent_protocol() -> None:
    agent = FakeAgent(load_log(DEMO_LOG))
    assert isinstance(agent, Agent)


def test_missing_log_raises(tmp_path) -> None:
    with pytest.raises(ReplayLogError, match="not found"):
        load_log(tmp_path / "nope.jsonl")


def test_empty_log_raises(tmp_path) -> None:
    with pytest.raises(ReplayLogError, match="empty"):
        load_log(write_log(tmp_path, "// only a comment"))


def test_malformed_json_raises_with_the_line_number(tmp_path) -> None:
    with pytest.raises(ReplayLogError, match="line 2"):
        load_log(write_log(tmp_path, '{"type":"Interrupted"}', "{not json"))


def test_unknown_event_type_raises_at_load_time(tmp_path) -> None:
    with pytest.raises(ReplayLogError, match="unknown event type"):
        load_log(write_log(tmp_path, '{"type":"Nope"}'))


def test_bad_field_raises_at_load_time(tmp_path) -> None:
    with pytest.raises(ReplayLogError, match="line 1"):
        load_log(write_log(tmp_path, '{"type":"ToolStarted","nonsense":1}'))


def test_stream_without_entry_id_raises(tmp_path) -> None:
    with pytest.raises(ReplayLogError, match="requires an 'entry_id'"):
        load_log(write_log(tmp_path, '{"type":"Narration","stream":"hello there"}'))


def test_stream_expands_into_chunks_ending_with_done(tmp_path) -> None:
    steps = load_log(
        write_log(
            tmp_path,
            '{"type":"Narration","entry_id":"e1","stream":"one two three"}',
        )
    )
    events = [event for _, event in steps[0].events()]
    assert all(isinstance(e, Narration) for e in events)
    assert "".join(e.text for e in events) == "one two three"
    assert events[-1].done is True
    assert [e.done for e in events[:-1]] == [False] * (len(events) - 1)


async def test_playback_preserves_order() -> None:
    agent = FakeAgent(load_log(DEMO_LOG), speed=0)
    await agent.start()
    await agent.wait()
    events = []
    while not agent.events.empty():
        events.append(agent.events.get_nowait())
    # start() announces the session before any playback.
    assert isinstance(events[0], SessionState)
    assert isinstance(events[1], RunStarted)
    assert [e.seq for e in events] == sorted(e.seq for e in events)
    assert any(isinstance(e, ToolStarted) and e.tool == "nmap" for e in events)


async def test_submit_is_recorded_and_restarts_playback(tmp_path) -> None:
    steps = load_log(write_log(tmp_path, '{"type":"Interrupted","reason":"x"}'))
    agent = FakeAgent(steps, speed=0, autostart=False)
    await agent.start()
    # start() announces the session and nothing else until a turn arrives.
    assert isinstance(agent.events.get_nowait(), SessionState)
    assert agent.events.empty()

    await agent.submit("scan 10.0.0.5")
    await agent.wait()
    assert agent.submissions == ["scan 10.0.0.5"]
    assert not agent.events.empty()


async def test_config_commands_answer_without_replaying(tmp_path) -> None:
    steps = load_log(write_log(tmp_path, '{"type":"Interrupted","reason":"x"}'))
    agent = FakeAgent(steps, speed=0, autostart=False)
    await agent.start()
    agent.events.get_nowait()  # the opening SessionState

    await agent.submit("/model phi-3.5-mini")
    state = agent.events.get_nowait()
    assert isinstance(state, SessionState)
    assert state.model == "phi-3.5-mini"
    assert agent.events.empty()  # the log was not replayed

    await agent.submit("/target windows iis")
    state = agent.events.get_nowait()
    assert state.target_os == "windows"
    assert state.target_stack == ("iis",)


async def test_unknown_model_is_reported_not_applied(tmp_path) -> None:
    steps = load_log(write_log(tmp_path, '{"type":"Interrupted","reason":"x"}'))
    agent = FakeAgent(steps, speed=0, autostart=False)
    await agent.start()
    original = agent.model
    agent.events.get_nowait()

    await agent.submit("/model not-a-model")
    reply = agent.events.get_nowait()
    assert isinstance(reply, Narration)
    assert "no such model" in reply.text
    assert agent.model == original


async def test_interrupt_emits_an_interrupted_event() -> None:
    agent = FakeAgent(load_log(DEMO_LOG), speed=1.0)
    await agent.start()
    await asyncio.sleep(0.05)
    await agent.interrupt()
    events = []
    while not agent.events.empty():
        events.append(agent.events.get_nowait())
    assert isinstance(events[-1], Interrupted)


async def test_aclose_stops_playback() -> None:
    agent = FakeAgent(load_log(DEMO_LOG), speed=1.0)
    await agent.start()
    await asyncio.sleep(0.05)
    await agent.aclose()
    assert agent._task is not None and agent._task.done()
