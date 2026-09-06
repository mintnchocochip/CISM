"""Password/credential attack tools. ``hydra`` is the structurally most
demanding of the three Checkpoint-1 proof tools: it needs a scratch
directory pre-populated with credential files before the process starts,
not just an argv list.
"""

from __future__ import annotations

from pathlib import Path

from cism.agent.tools.base import sandboxed_tool

__all__ = ["CREDENTIAL_TOOLS", "hydra"]

_MAX_THREADS = 16

#: userlist/passwordlist select from a small known-safe set of names, never
#: an arbitrary host path — same reasoning as a wordlist-by-name pattern
#: elsewhere in this catalog: letting the model supply any filesystem path
#: would turn a credential tool into a way to read arbitrary files off the
#: host running the agent.
_WORDLISTS: dict[str, Path] = {
    "common-users": Path("/usr/share/wordlists/common-users.txt"),
    "common-passwords": Path("/usr/share/wordlists/common-passwords.txt"),
}


def _materialize(values: list[str], path: Path) -> None:
    path.write_text("\n".join(values) + "\n")


def _cred_flag(flag: str, values: list[str] | None, listname: str | None, path: Path) -> list[str]:
    if (values is None) == (listname is None):
        raise ValueError("exactly one of an explicit list or a named wordlist must be given")
    if values is not None:
        _materialize(values, path)
        return [flag, str(path)]
    wordlist = _WORDLISTS.get(listname)
    if wordlist is None:
        raise ValueError(f"unknown wordlist {listname!r}; choose one of {sorted(_WORDLISTS)}")
    return [flag, str(wordlist)]


@sandboxed_tool(binary="hydra", capability="executes", timeout=120.0)
def hydra(
    scratch: Path,
    target: str,
    service: str,
    usernames: list[str] | None = None,
    userlist: str | None = None,
    passwords: list[str] | None = None,
    passwordlist: str | None = None,
    threads: int = 4,
) -> list[str]:
    """Run hydra against one target/service with explicit credential lists
    or a named wordlist. Exactly one of usernames/userlist and one of
    passwords/passwordlist must be given; threads is capped at 16 —
    real safety here is the scope guardrail and the run timeout, not
    argv tricks."""
    argv = ["-t", str(min(threads, _MAX_THREADS))]
    argv += _cred_flag("-L", usernames, userlist, scratch / "users.txt")
    argv += _cred_flag("-P", passwords, passwordlist, scratch / "pass.txt")
    argv += [target, service]
    return argv


CREDENTIAL_TOOLS = [hydra]
