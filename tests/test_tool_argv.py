"""cism/agent/tools/credentials.py: what argv the hand-written hydra tool
builds from its arguments. nmap and curl became data-driven catalog rows
(see cism/agent/tools/catalog.yaml and tests/test_tool_catalog_build.py);
hydra stays hand-written because its structured credential-list handling
doesn't fit build_catalog's flat flags-and-target shape. run_sandboxed
itself is monkeypatched out so no real subprocess ever runs here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cism.agent.tools import base as base_module, credentials


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

    monkeypatch.setattr(base_module, "run_sandboxed", fake)

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
        base_module, "run_sandboxed", lambda argv, **kw: captured.setdefault("argv", argv) or "ok"
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


def test_hydra_carries_capability_and_binary_metadata() -> None:
    """This is what closes the gap _binaries_of's defensive `(tool.metadata
    or {})` guard existed for — hydra now has real metadata like every
    other tool in the registry."""
    assert credentials.hydra.metadata == {"capability": "executes", "binary": "hydra"}
