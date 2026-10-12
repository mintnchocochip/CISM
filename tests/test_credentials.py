"""cism/agent/tools/credentials.py: hydra's wordlist materialization and its
"exactly one of list/named" validation (H1, AUDIT.md)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from cism.agent.tools.credentials import CREDENTIAL_TOOLS, hydra


def test_hydra_is_registered_in_credential_tools() -> None:
    assert hydra in CREDENTIAL_TOOLS


def _invoke(**kwargs):
    with patch("cism.agent.tools.base.run_sandboxed", return_value="ok") as mock_run:
        result = hydra.invoke(kwargs)
    return result, mock_run


def test_explicit_lists_are_materialized_into_scratch_files() -> None:
    result, mock_run = _invoke(
        target="10.0.0.5", service="ssh", usernames=["admin"], passwords=["hunter2"],
    )

    assert result == "ok"
    argv = mock_run.call_args.args[0]
    assert argv[0] == "hydra"
    # Bare filenames, not the scratch dir's host-absolute path: bwrap binds
    # that host dir to /work and --chdir's into it (sandbox.py), so hydra's
    # own cwd is /work — the host path these files were just written to
    # does not exist inside the sandbox. Confirmed live 2026-10-12: passing
    # the absolute host path made hydra fail with "File for logins not
    # found" against a real target.
    assert argv[argv.index("-L") + 1] == "users.txt"
    assert argv[argv.index("-P") + 1] == "pass.txt"
    assert argv[-2:] == ["10.0.0.5", "ssh"]


def test_a_named_wordlist_is_passed_by_path_not_materialized() -> None:
    _, mock_run = _invoke(
        target="10.0.0.5",
        service="ssh",
        userlist="common-users",
        passwordlist="common-passwords",
    )

    argv = mock_run.call_args.args[0]
    assert "/usr/share/wordlists/common-users.txt" in argv
    assert "/usr/share/wordlists/common-passwords.txt" in argv


def test_giving_both_an_explicit_list_and_a_named_wordlist_raises() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        hydra.invoke(
            {
                "target": "10.0.0.5",
                "service": "ssh",
                "usernames": ["admin"],
                "userlist": "common-users",
                "passwords": ["hunter2"],
            }
        )


def test_giving_neither_an_explicit_list_nor_a_named_wordlist_raises() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        hydra.invoke({"target": "10.0.0.5", "service": "ssh", "passwords": ["hunter2"]})


def test_an_unknown_named_wordlist_raises() -> None:
    with pytest.raises(ValueError, match="unknown wordlist"):
        hydra.invoke(
            {
                "target": "10.0.0.5",
                "service": "ssh",
                "userlist": "not-a-real-list",
                "passwords": ["hunter2"],
            }
        )


def test_threads_are_capped_at_sixteen() -> None:
    _, mock_run = _invoke(
        target="10.0.0.5",
        service="ssh",
        usernames=["admin"],
        passwords=["hunter2"],
        threads=999,
    )

    argv = mock_run.call_args.args[0]
    assert argv[argv.index("-t") + 1] == "16"
