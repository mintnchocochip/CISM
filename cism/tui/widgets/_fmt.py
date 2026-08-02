"""Small formatting helpers shared by the status bar and the spinner."""

from __future__ import annotations


def tokens(count: int) -> str:
    """Render a token count the way the status line does: 1200 -> ``1.2k``."""
    if count < 1000:
        return str(count)
    if count < 1_000_000:
        value = count / 1000
        return f"{value:.1f}k" if value < 100 else f"{value:.0f}k"
    return f"{count / 1_000_000:.1f}M"


def capacity(count: int) -> str:
    """Render a context window size. A round 32768 reads as ``32k``, not ``32.8k``."""
    if count >= 1024 and count % 1024 == 0:
        return f"{count // 1024}k"
    return tokens(count)


def elapsed(seconds: float) -> str:
    """Render an elapsed duration compactly: ``12s``, ``3m04s``."""
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    return f"{total // 60}m{total % 60:02d}s"
