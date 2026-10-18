"""Password/credential attack tools. ``hydra`` needs a scratch directory
pre-populated with credential files before the process starts, not just an argv list."""

from __future__ import annotations

from pathlib import Path

from cism.agent.tools.base import sandboxed_tool

__all__ = ["CREDENTIAL_TOOLS", "hydra"]

_MAX_THREADS = 16

#: userlist/passwordlist select from a known-safe set of names, never an
#: arbitrary host path — else the model could read arbitrary files off the host.
_WORDLISTS: dict[str, Path] = {
    "common-users": Path("/usr/share/wordlists/common-users.txt"),
    "common-passwords": Path("/usr/share/wordlists/common-passwords.txt"),
}


#: Real hydra module names this tool supports -- deliberately excludes
#: http-get/http-post-form and anything else web-shaped. The docstring
#: below already says "never a web page", but nothing enforced it until a
#: live run (2026-10-17) passed service="web" against DVWA anyway and got
#: a raw hydra exit-255 usage error ("[ERROR] Unknown service", not caught
#: by this tool's own validation) instead of an actionable message.
_SERVICES = frozenset({
    "ssh", "ftp", "ftps", "telnet", "smtp", "smtps", "pop3", "pop3s",
    "imap", "imaps", "mysql", "postgres", "mssql", "oracle", "rdp", "vnc",
    "smb", "snmp",
})


def _materialize(values: list[str], path: Path) -> None:
    path.write_text("\n".join(values) + "\n")


def _cred_flag(flag: str, values: list[str] | None, listname: str | None, path: Path) -> list[str]:
    if (values is None) == (listname is None):
        raise ValueError("exactly one of an explicit list or a named wordlist must be given")
    if values is not None:
        _materialize(values, path)
        # path.name, not str(path): BubblewrapRunner binds the host scratch
        # dir to /work and --chdir's into it (sandbox.py), so hydra's own
        # cwd is /work, not the host's scratch path — the absolute host
        # path this process just wrote to does not exist inside the
        # sandbox at all. Confirmed live 2026-10-12: an explicit
        # usernames/passwords list made hydra fail with "File for logins
        # not found", pointing at the correctly-written but
        # sandbox-unreachable host path. A named wordlist never hit this
        # because /usr/share/wordlists is itself ro-bound at the same path
        # inside the sandbox.
        return [flag, path.name]
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
    """Brute-force a login on a network SERVICE — ssh, ftp, telnet, mysql,
    postgres, and similar — never a web page. target is a bare host or IP
    (e.g. "10.0.0.5"), not a URL, and service is required with no default:
    pass the exact protocol name hydra expects (e.g. "ssh", "ftp",
    "telnet"). This tool does NOT support HTTP form logins (hydra's
    http-post-form module needs a form-path/field/failure-string argument
    this tool doesn't expose) — for a web login form, use sqlmap's --data
    for injection testing, or curl's -d/--data with a literal (not
    @filename) value to verify credentials already found elsewhere — a
    literal value is allowed by DangerousFlagGuardStage, only an
    @filename-prefixed one (arbitrary local file read) is blocked.
    Confirmed live 2026-10-18: following the old wording here ("curl to
    test credentials") sent the model into a dead-end retry loop against
    that guardrail back when curl's -d was blocked outright, regardless of
    value; fixed at the guardrail (now value-aware) rather than here.
    Confirmed live 2026-10-12: a call aimed at a web login URL with no
    service argument failed outright with a validation error.

    Exactly one of usernames/userlist and one of passwords/passwordlist
    must be given; threads is capped at 16 — real safety here is the scope
    guardrail and the run timeout, not argv tricks."""
    if service not in _SERVICES:
        raise ValueError(
            f"{service!r} is not a network service this tool supports (choose "
            f"one of {sorted(_SERVICES)}); there is no web-form module here — "
            "use sqlmap's --data for injection testing, or curl's -d with a "
            "literal (non-@filename) value to verify credentials against a "
            "login page."
        )
    argv = ["-t", str(min(threads, _MAX_THREADS))]
    argv += _cred_flag("-L", usernames, userlist, scratch / "users.txt")
    argv += _cred_flag("-P", passwords, passwordlist, scratch / "pass.txt")
    argv += [target, service]
    return argv


CREDENTIAL_TOOLS = [hydra]
