"""cism/agent/tools/{discovery,linux,credentials}.py: what argv each real
tool function builds from its arguments — the actual, model-facing
behavior of a tool call, independent of run_sandboxed's own execution
mechanics (covered separately in test_sandbox.py). run_sandboxed itself is
monkeypatched out so no real subprocess ever runs here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cism.agent.tools import credentials, discovery, linux


def test_nmap_builds_argv_from_target_and_options(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(discovery, "run_sandboxed", lambda argv, **kw: calls.append(argv) or "ok")

    discovery.nmap.invoke({"target": "10.0.0.5", "options": "-p 80,443"})

    assert calls == [["nmap", "-p", "80,443", "10.0.0.5"]]


def test_nmap_defaults_options_to_a_service_version_scan(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(discovery, "run_sandboxed", lambda argv, **kw: calls.append(argv) or "ok")

    discovery.nmap.invoke({"target": "10.0.0.5"})

    assert calls == [["nmap", "-sV", "10.0.0.5"]]


def test_curl_builds_argv_from_url_and_options(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(linux, "run_sandboxed", lambda argv, **kw: calls.append(argv) or "ok")

    linux.curl.invoke({"url": "https://example.com", "options": "-sS -L"})

    assert calls == [["curl", "-sS", "-L", "https://example.com"]]


def test_hydra_materializes_explicit_credential_lists_to_scratch_files(monkeypatch) -> None:
    captured: dict = {}

    def fake(argv, **kwargs):
        # The scratch dir is cleaned up as soon as hydra()'s `with` block
        # exits, right after this call returns — so the credential files
        # must be read here, while they still exist, not after invoke().
        captured["argv"] = argv
        userfile = argv[argv.index("-L") + 1]
        passfile = argv[argv.index("-P") + 1]
        captured["users"] = Path(userfile).read_text().splitlines()
        captured["passwords"] = Path(passfile).read_text().splitlines()
        return "ok"

    monkeypatch.setattr(credentials, "run_sandboxed", fake)

    credentials.hydra.invoke(
        {
            "target": "10.0.0.5",
            "service": "ssh",
            "usernames": ["root", "admin"],
            "passwords": ["toor"],
            "threads": 4,
        }
    )

    argv = captured["argv"]
    assert argv[:3] == ["hydra", "-t", "4"]
    assert argv[-2:] == ["10.0.0.5", "ssh"]
    assert captured["users"] == ["root", "admin"]
    assert captured["passwords"] == ["toor"]


def test_hydra_caps_threads_at_the_documented_maximum(monkeypatch) -> None:
    captured: dict = {}
    monkeypatch.setattr(
        credentials, "run_sandboxed", lambda argv, **kw: captured.setdefault("argv", argv) or "ok"
    )

    credentials.hydra.invoke(
        {
            "target": "10.0.0.5",
            "service": "ssh",
            "usernames": ["root"],
            "passwords": ["toor"],
            "threads": 999,
        }
    )

    assert captured["argv"][:3] == ["hydra", "-t", "16"]


def test_hydra_rejects_giving_both_an_explicit_list_and_a_named_wordlist() -> None:
    with pytest.raises(ValueError):
        credentials.hydra.invoke(
            {
                "target": "10.0.0.5",
                "service": "ssh",
                "usernames": ["root"],
                "userlist": "common-users",
                "passwords": ["toor"],
            }
        )


def test_hydra_rejects_giving_neither_an_explicit_list_nor_a_wordlist() -> None:
    with pytest.raises(ValueError):
        credentials.hydra.invoke({"target": "10.0.0.5", "service": "ssh", "passwords": ["toor"]})
