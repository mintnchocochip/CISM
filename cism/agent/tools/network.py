"""Raw-TCP reachability/exploitation tool. Fills a gap nmap/curl/sqlmap/
hydra all leave: none of them can open a bare socket and exchange bytes
with a non-HTTP service (e.g. a backdoor shell found listening on an
unusual port) -- confirming it actually responds to a command, not just
that something is listening there.

netcat-openbsd, not ncat or GNU netcat: OpenBSD's ``nc`` has no
``-e``/exec-on-connect flag at all (removed upstream because binding a
shell to a socket is a backdoor primitive itself) -- the single most
catastrophic failure mode for a tool like this is structurally
impossible here, not just denylisted."""

from __future__ import annotations

from pathlib import Path

from cism.agent.tools.base import sandboxed_tool

__all__ = ["NETWORK_TOOLS", "nc"]

#: nc's own -w (connect/idle timeout), kept below this tool's overall
#: sandboxed_tool timeout so nc itself gives up first, with run_sandboxed's
#: own timeout as a second, independent backstop if it doesn't.
_NC_TIMEOUT_SECONDS = 10


@sandboxed_tool(binary="nc", capability="executes", timeout=15.0)
def nc(scratch: Path, target: str, port: int, command: str | None = None) -> list[str]:
    """Open a raw TCP connection to TARGET:PORT -- for a non-HTTP service
    (e.g. a suspected backdoor shell on an unusual port) that nmap can
    only identify, never interact with. target is a bare host or IP, not
    a URL. With no command, this just connects and reads whatever the
    service sends on its own (its banner) until it closes or times out --
    use this to confirm a service is actually live and see what it says.
    With command, that exact text is sent (newline-terminated) right
    after connecting, and the response is read back -- use this to prove
    a backdoor actually executes something, not merely that something is
    listening. This is a one-shot, non-interactive connection: no further
    back-and-forth after the single command is sent."""
    if command is not None:
        (scratch / "stdin").write_text(command + "\n")
    return ["-w", str(_NC_TIMEOUT_SECONDS), target, str(port)]


NETWORK_TOOLS = [nc]
