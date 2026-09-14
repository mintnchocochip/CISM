"""The guardrail seam — see :mod:`cism.agent.guardrails.chain`."""

from __future__ import annotations

from .chain import (
    GuardrailChain,
    GuardrailResult,
    GuardrailSeam,
    GuardrailStage,
    PassThroughStage,
)
from .dangerous_flags import DangerousFlagGuardStage
from .phase_tool import PhaseToolGuardStage
from .scope import EngagementScope, ScopeGuardStage, parse_scope

__all__ = [
    "DangerousFlagGuardStage",
    "EngagementScope",
    "GuardrailChain",
    "GuardrailResult",
    "GuardrailSeam",
    "GuardrailStage",
    "PassThroughStage",
    "PhaseToolGuardStage",
    "parse_scope",
    "ScopeGuardStage",
]
