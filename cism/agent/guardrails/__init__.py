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
from .input_guard import InputGuardStage, MAX_INPUT_CHARS
from .output_redaction import OutputRedactionStage
from .phase_tool import PhaseToolGuardStage
from .scope import EngagementScope, ScopeGuardStage, parse_scope
from .tool_output import ToolOutputScreenStage

__all__ = [
    "DangerousFlagGuardStage",
    "EngagementScope",
    "GuardrailChain",
    "GuardrailResult",
    "GuardrailSeam",
    "GuardrailStage",
    "InputGuardStage",
    "MAX_INPUT_CHARS",
    "OutputRedactionStage",
    "PassThroughStage",
    "PhaseToolGuardStage",
    "ToolOutputScreenStage",
    "parse_scope",
    "ScopeGuardStage",
]
