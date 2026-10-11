"""cism/agent/tools/dummy.py: canned output, no subprocess — validates the
graph's tool-calling loop with no lab and no real tooling installed."""

from __future__ import annotations

from cism.agent.tools.dummy import dummy_msfconsole, dummy_nmap


def test_dummy_nmap_returns_grep_able_open_port_lines() -> None:
    result = dummy_nmap.invoke({"target": "10.0.0.5"})

    assert "10.0.0.5" in result
    assert "22/tcp   open  ssh" in result
    assert "80/tcp   open  http" in result


def test_dummy_nmap_echoes_the_options_argument() -> None:
    result = dummy_nmap.invoke({"target": "10.0.0.5", "options": "-p 1-100"})

    assert "-p 1-100" in result


def test_dummy_msfconsole_echoes_module_and_target() -> None:
    result = dummy_msfconsole.invoke({"module": "exploit/foo", "target": "10.0.0.5"})

    assert "exploit/foo" in result
    assert "10.0.0.5" in result
    assert "session not opened" in result
