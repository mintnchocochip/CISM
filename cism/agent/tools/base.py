"""The factory and escape hatch behind the tool catalog: every built tool
routes through run_sandboxed, so a data row can no more bypass the sandbox
than a hand-written @tool function can."""

from __future__ import annotations

import inspect
import shlex
from pathlib import Path
from typing import Any, Callable

from langchain_core.tools import BaseTool, StructuredTool
from pydantic import Field, create_model

from cism.agent.tools.catalog import Capability, ToolSpec
from cism.agent.tools.registry import ToolRegistry
from cism.agent.tools.sandbox import run_sandboxed, scratch_dir
from cism.depg.extract import CauseExtractor

__all__ = ["build_catalog", "build_toolkit", "render_argv", "sandboxed_tool", "write_lines"]

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
    argv += spec.forced_flags
    if spec.allow_raw and kwargs.get("extra"):
        argv += shlex.split(str(kwargs["extra"]))
    if spec.default_scheme and "://" not in target:
        target = f"{spec.default_scheme}://{target}"
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
        # Explicit about what belongs here: without this, "extra" is a bare
        # unlabeled field and the model guesses — confirmed live
        # 2026-10-12, sqlmap once got extra="service=http", a free-form
        # token no CLI flag here resembles.
        fields["extra"] = (
            str | None,
            Field(
                default=None,
                description=(
                    "Extra raw CLI flags only, space-separated exactly as "
                    "they'd appear on the command line, e.g. '-p 1-1000' or "
                    "'--level 3'. Never a bare key=value token — if it's "
                    "not a real flag this tool's own CLI takes, leave this "
                    "unset."
                ),
            ),
        )
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
    """The decorated function's signature minus ``scratch``, which this
    module supplies rather than the model — else a caller could name its own directory."""
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
    subcommands) beyond build_catalog's flat flags-and-target shape. The
    wrapped function returns only the argv tail; this decorator still owns the sandbox call."""

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
            metadata={"capability": capability, "binary": binary},
        )

    return decorator


def _build_help_tool(catalog: dict[str, ToolSpec], extra_binaries: dict[str, str]) -> BaseTool:
    """One generic tool, not one per catalog entry. Still routed through
    run_sandboxed — timeout-protected even for "harmless" --help, since
    some binaries hang waiting on stdin. Exempt from phase gating."""
    binaries = {name: spec.binary for name, spec in catalog.items()} | extra_binaries

    def _run(tool_name: str) -> str:
        spec = catalog.get(tool_name)
        help_flag = spec.help_flag if spec else "--help"
        binary = binaries.get(tool_name)
        if binary is None:
            return f"unknown tool {tool_name!r}"
        return run_sandboxed([binary, help_flag])

    return StructuredTool.from_function(
        func=_run,
        name="tool_help",
        description="Print a tool's own --help/-h usage text before deciding what flags to pass it.",
        metadata={"capability": "reads"},
    )


def _binaries_of(tools: list[BaseTool]) -> dict[str, str]:
    """A decorated tool's real binary name, from sandboxed_tool's metadata —
    not assumed equal to the registered name. `or {}` covers a tool with no
    metadata at all the same way as metadata missing a "binary" key."""
    return {tool.name: (tool.metadata or {}).get("binary", tool.name) for tool in tools}


def build_toolkit(
    catalog: dict[str, ToolSpec],
    decorated_tools: list[BaseTool],
    extractors: dict[str, CauseExtractor],
) -> tuple[ToolRegistry, dict[str, str]]:
    """Assembles one ToolRegistry from every tool source (catalog rows,
    decorated tools, generic tool_help) and hands back extractors
    unchanged alongside it, so callers building both have one call site."""
    catalog_tools = build_catalog(catalog)
    help_tool = _build_help_tool(catalog, extra_binaries=_binaries_of(decorated_tools))
    registry = ToolRegistry([*catalog_tools, *decorated_tools, help_tool])
    return registry, extractors
