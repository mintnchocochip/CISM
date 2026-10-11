"""Deterministic normalization for the DEPG identity key.

The identity key must never depend on anything an LLM decided (design spec
§7) — everything here is a pure string transform.
"""

from __future__ import annotations

import hashlib
import re

__all__ = ["hash_signal", "normalize_target"]

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
_DURATION_RE = re.compile(r"\b\d+(\.\d+)?s\b")


def normalize_target(raw: str) -> str:
    """Lowercase, trim, strip a URL scheme, strip a trailing FQDN dot, and
    drop any port — a host is one host; ports are findings ON it, not host
    identity."""
    value = raw.strip().lower()
    value = _SCHEME_RE.sub("", value)
    value = value.rstrip("/")
    if value.endswith("."):
        value = value[:-1]
    if value.startswith("[") and "]" in value:
        # Bracketed IPv6, e.g. "[::1]" or "[::1]:80" — unwrap the brackets
        # and drop a trailing :port, but never touch what's inside them.
        closing = value.index("]")
        host = value[1:closing]
        rest = value[closing + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host
        return host + rest
    if value.count(":") == 1:
        # A single colon means host:port. Two or more means an unbracketed
        # IPv6 literal (e.g. "fe80::1") — never strip anything from those.
        host, _, port = value.rpartition(":")
        if host and port.isdigit():
            value = host
    return value


def hash_signal(text: str) -> str:
    """A short deterministic signal for the generic fallback extractor. Not
    semantically meaningful — just stable enough that a literal repeat of
    the same tool output dedupes onto the same node."""
    normalized = re.sub(r"\s+", " ", text.strip())
    normalized = _DURATION_RE.sub("", normalized)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
