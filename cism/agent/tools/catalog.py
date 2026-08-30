"""Data-driven tool declarations: most CLI tools are `binary <flags>
<target>`, so they are rows here, not hand-written functions. See
cism.agent.tools.base for the factory that turns a row into a real tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

__all__ = ["CATALOG", "Capability", "Flag", "ToolSpec"]

Capability = Literal["reads", "writes", "executes", "destructive"]


@dataclass(frozen=True, slots=True)
class Flag:
    cli: str
    kind: Literal["value", "bool"] = "value"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    binary: str
    capability: Capability
    description: str
    flags: dict[str, Flag] = field(default_factory=dict)
    target: str = "positional"
    allow_raw: bool = False
    timeout: float = 60.0


CATALOG: dict[str, ToolSpec] = {
    "nikto": ToolSpec(
        binary="nikto", capability="reads",
        description="Web server vulnerability scan.",
        target="-host",
    ),
    "whatweb": ToolSpec(
        binary="whatweb", capability="reads",
        description="Fingerprint web technologies in use on a target.",
    ),
    "dnsenum": ToolSpec(
        binary="dnsenum", capability="reads",
        description="Enumerate DNS records and subdomains for a domain.",
    ),
}
