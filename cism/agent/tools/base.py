"""The factory and escape hatch behind the tool catalog: every built tool
routes through run_sandboxed, so a data row can no more bypass the sandbox
than a hand-written @tool function can.
"""

from __future__ import annotations

import inspect
import shlex
from pathlib import Path
from typing import Any, Callable

from langchain_core.tools import BaseTool, StructuredTool
from pydantic import create_model

from cism.agent.tools.catalog import Capability, ToolSpec
from cism.agent.tools.sandbox import run_sandboxed, scratch_dir

__all__ = ["build_catalog", "render_argv", "sandboxed_tool", "write_lines"]

_SCRATCH_PARAM = "scratch"


def render_argv(spec: ToolSpec, target: str, **kwargs: Any) -> list[str]:
    argv: list[str] = []
    for name, flag in spec.flags.items():
        if name not in kwargs or kwargs[name] in (None, False):
            continue
        if flag.kind == "bool":
            argv.append(flag.cli)
        else:
            argv += [flag.cli, str(kwargs[name])]
    if spec.allow_raw and kwargs.get("extra"):
        argv += shlex.split(str(kwargs["extra"]))
    if spec.target == "positional":
        argv.append(target)
    elif spec.target:
        argv += [spec.target, target]
    return argv


def _args_model(name: str, spec: ToolSpec):
    fields: dict[str, Any] = {"target": (str, ...)}
    for flag_name, flag in spec.flags.items():
        fields[flag_name] = (bool, False) if flag.kind == "bool" else (str | None, None)
    if spec.allow_raw:
        fields["extra"] = (str | None, None)
    return create_model(f"{name.title()}Args", **fields)


def _build_one(name: str, spec: ToolSpec) -> BaseTool:
    def _run(**kwargs: Any) -> str:
        target = kwargs.pop("target")
        argv = [spec.binary, *render_argv(spec, target, **kwargs)]
        return run_sandboxed(argv, timeout=spec.timeout)

    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=spec.description,
        args_schema=_args_model(name, spec),
        metadata={"capability": spec.capability},
    )


def build_catalog(catalog: dict[str, ToolSpec]) -> list[BaseTool]:
    """One sandboxed, capability-tagged BaseTool per catalog row."""
    return [_build_one(name, spec) for name, spec in catalog.items()]


def write_lines(scratch: Path, filename: str, values: list[str]) -> str:
    path = scratch / filename
    path.write_text("\n".join(values) + "\n")
    return str(path)


def _decorated_args_model(func: Callable[..., list[str]]):
    """The model-facing schema is the decorated function's own signature
    minus ``scratch`` — that parameter is supplied by this module, not by
    the model, so exposing it would let a caller name its own directory."""
    fields: dict[str, Any] = {}
    for name, parameter in inspect.signature(func).parameters.items():
        if name == _SCRATCH_PARAM:
            continue
        annotation = str if parameter.annotation is inspect.Parameter.empty else parameter.annotation
        default = ... if parameter.default is inspect.Parameter.empty else parameter.default
        fields[name] = (annotation, default)
    return create_model(f"{func.__name__.title()}Args", **fields)


def sandboxed_tool(
    binary: str, capability: Capability, timeout: float = 60.0
) -> Callable[[Callable[..., list[str]]], BaseTool]:
    """Escape hatch for a tool needing real prep (file materialization,
    subcommands) rather than the flat flags-and-target shape build_catalog
    covers. The wrapped function returns only the argv tail; this decorator
    still owns the sandbox call, exactly like build_catalog's rows do."""

    def decorator(func: Callable[..., list[str]]) -> BaseTool:
        needs_scratch = _SCRATCH_PARAM in inspect.signature(func).parameters

        def _run(**kwargs: Any) -> str:
            if needs_scratch:
                with scratch_dir() as tmp:
                    argv_tail = func(scratch=tmp, **kwargs)
                    return run_sandboxed([binary, *argv_tail], cwd=tmp, timeout=timeout)
            argv_tail = func(**kwargs)
            return run_sandboxed([binary, *argv_tail], timeout=timeout)

        return StructuredTool.from_function(
            func=_run,
            name=func.__name__,
            description=func.__doc__ or "",
            args_schema=_decorated_args_model(func),
            metadata={"capability": capability},
        )

    return decorator
