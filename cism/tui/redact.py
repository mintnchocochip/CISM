"""Keep credentials out of the transcript.

The composer feeds three places that outlive the keystroke: the transcript,
the input history recalled with the arrow keys, and the file written by
``/export``. A key pasted into any slash command would reach all three, and
CISM transcripts get pasted into reports.

So a credential-shaped argument is redacted before the turn is ever echoed,
and the command that received it is refused rather than forwarded.

Detection is deliberately broad. A false positive costs one retype; a false
negative leaks a key into a report.
"""

from __future__ import annotations

import re

__all__ = ["MASK", "looks_like_secret", "redact_command"]

MASK = "••••••••"

#: Well-known credential prefixes.
_PREFIXES = re.compile(
    r"(?i)^(sk|pk|rk|api|apikey|key|token|bearer|ghp|gho|ghs|github_pat|xox[abprs]"
    r"|aws|akia|asia|glpat|hf|nvapi|sk-ant|sk-proj)[-_]"
)

#: A bare opaque token: long, unbroken, and made only of key-ish characters.
#: URLs are excluded by construction — they carry ``:`` and ``/``.
_OPAQUE = re.compile(r"^[A-Za-z0-9_\-]{24,}$")

#: Arguments that are obviously not secrets, however long.
_SAFE = re.compile(r"(?i)^(https?://|ws://|wss://|local$|default$|none$|off$)")


def looks_like_secret(value: str) -> bool:
    """True if ``value`` might be a credential."""
    candidate = value.strip()
    if not candidate or _SAFE.match(candidate):
        return False
    if _PREFIXES.match(candidate):
        return True
    return bool(_OPAQUE.match(candidate))


def redact_command(text: str) -> str:
    """Mask any credential-shaped word in a composer line.

    Applies to every command, not just ``/api`` — the point is that no path
    from the composer to the transcript can carry a key, including a command
    added later that forgot about this.
    """
    if not text.strip():
        return text
    words = text.split(" ")
    return " ".join(MASK if looks_like_secret(w) else w for w in words)
