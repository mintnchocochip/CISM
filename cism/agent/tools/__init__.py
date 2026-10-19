"""Tool registration — see :mod:`cism.agent.tools.registry`.

nmap and curl are built from their catalog.yaml rows (see catalog.py);
this module builds and re-exports one instance of each for convenience —
the same convenience-import shape dummy_nmap/dummy_msfconsole already had.
hydra stays hand-written (cism.agent.tools.credentials) because its
structured credential-list handling doesn't fit build_catalog's flat
flags-and-target shape; it is exported here for the first time, closing
the "not even exported" gap named in the unified-toolkit design doc. nc
(cism.agent.tools.network) is hand-written for the same reason: it needs
to write a scratch stdin file before the process runs.
"""

from __future__ import annotations

from .base import build_catalog, build_toolkit
from .catalog import CATALOG
from .credentials import hydra
from .dummy import dummy_msfconsole, dummy_nmap
from .network import nc
from .registry import ToolRegistry

_CATALOG_TOOLS = {tool.name: tool for tool in build_catalog(CATALOG)}
curl = _CATALOG_TOOLS["curl"]
nmap = _CATALOG_TOOLS["nmap"]

__all__ = [
    "CATALOG",
    "ToolRegistry",
    "build_catalog",
    "build_toolkit",
    "curl",
    "dummy_msfconsole",
    "dummy_nmap",
    "hydra",
    "nc",
    "nmap",
]
