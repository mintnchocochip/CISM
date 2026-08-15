"""Tool registration — see :mod:`cism.agent.tools.registry`."""

from __future__ import annotations

from .dummy import dummy_msfconsole, dummy_nmap
from .registry import ToolRegistry

__all__ = ["ToolRegistry", "dummy_msfconsole", "dummy_nmap"]
