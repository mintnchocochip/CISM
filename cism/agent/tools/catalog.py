"""Data-driven tool declarations: most CLI tools are `binary <flags>
<target>`, so they're rows in catalog.yaml, not hand-written functions —
see cism.agent.tools.base for the factory that builds a row into a real
tool. ToolSpec is a Pydantic model so a malformed row fails loudly with a
real ValidationError at import time."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, field_validator

from cism.agent.state import Phase

__all__ = ["CATALOG", "Capability", "Flag", "ToolSpec", "phases_for"]

Capability = Literal["reads", "writes", "executes", "destructive"]

_CATALOG_PATH = Path(__file__).parent / "catalog.yaml"


class Flag(BaseModel):
    cli: str
    kind: Literal["value", "bool"] = "value"


class ToolSpec(BaseModel):
    binary: str
    capability: Capability
    description: str
    flags: dict[str, Flag] = {}
    target: str = "positional"
    #: Some tools (wafw00f) take a URL, not a bare host, and silently
    #: assume their own default scheme when given one — wafw00f tries
    #: https first and fails outright (connection refused) against an
    #: http-only target, confirmed live against DVWA 2026-10-12. Applied
    #: in render_argv only when the model's target doesn't already
    #: contain "://", so a model that already knows the right scheme
    #: (e.g. after nmap found 443 open) is never overridden.
    default_scheme: str | None = None
    #: Always appended, regardless of what the model puts in `extra` — for a
    #: sandbox-wide constraint the model can't be trusted to retype
    #: correctly every call (e.g. nmap's no-raw-socket workaround), not a
    #: general default. extra can still add anything on top.
    forced_flags: list[str] = []
    allow_raw: bool = False
    timeout: float = 60.0
    #: The rare binary needing `-h` (or something else) instead of `--help`
    #: for cism.agent.tools.base._build_help_tool (see the design doc §5).
    help_flag: str = "--help"
    #: None means "use the capability default" (_DEFAULT_PHASES_BY_CAPABILITY
    #: below); an explicit list overrides it entirely, it does not add to it.
    phases: frozenset[Phase] | None = None

    @field_validator("phases", mode="before")
    @classmethod
    def _parse_phases(cls, value: object) -> frozenset[Phase] | None:
        if value is None:
            return None
        return frozenset(Phase[p.upper().replace("-", "_")] for p in value)


_DEFAULT_PHASES_BY_CAPABILITY: dict[Capability, frozenset[Phase]] = {
    "reads": frozenset({Phase.RECON, Phase.ENUMERATION, Phase.VULNERABILITY_DISCOVERY}),
    "writes": frozenset(),
    "executes": frozenset(),
    "destructive": frozenset(),
}


def phases_for(spec: ToolSpec) -> frozenset[Phase]:
    """A tool's real phase availability: its own `phases:` override if it
    has one, otherwise the fail-closed default for its capability."""
    return spec.phases if spec.phases is not None else _DEFAULT_PHASES_BY_CAPABILITY[spec.capability]


def _load_catalog(path: Path = _CATALOG_PATH) -> dict[str, ToolSpec]:
    raw = yaml.safe_load(path.read_text()) or {}
    return {name: ToolSpec(**row) for name, row in raw.items()}


CATALOG: dict[str, ToolSpec] = _load_catalog()
