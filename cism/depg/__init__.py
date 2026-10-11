"""The Dependency / Error Propagation Graph domain model.

``Node``/``Edge`` are the working types the agent mutates as a run
progresses; ``Graph`` is the container that merges them as extraction
proposes new ones; ``ExtractorRegistry``/``CauseExtractor`` is the seam that
turns a tool's output into ``Node``/``Edge`` proposals in the first place;
``EXTRACTORS`` pairs the hand-written regex extractors to their tool names,
and ``LLMExtractor`` is the LLM-backed fallback for everything else.
``BinarySupport``/``GradedSupport`` (``reducer.py``) are the two state-
derivation policies ``Graph.settle()`` can run. None of this package depends
on anything in ``cism.agent`` or ``cism.tui`` except through
``Node.to_event()``/``Edge.to_event()``/``Graph.to_event()``.
"""

from __future__ import annotations

from .edge import Edge
from .extract import CauseExtractor, Extraction, ExtractorRegistry, GenericExtractor
from .extractors import (
    EXTRACTORS,
    ChatModelExtractionBackend,
    ExtractionBackend,
    GobusterExtractor,
    HydraExtractor,
    LlamaCppExtractionBackend,
    LLMExtractor,
    NmapExtractor,
    SqlmapExtractor,
)
from .graph import Graph
from .node import Node
from .reducer import BinarySupport, GradedSupport, SupportPolicy, reduce_state

__all__ = [
    "CauseExtractor",
    "EXTRACTORS",
    "BinarySupport",
    "ChatModelExtractionBackend",
    "Edge",
    "Extraction",
    "ExtractionBackend",
    "ExtractorRegistry",
    "GenericExtractor",
    "GobusterExtractor",
    "GradedSupport",
    "Graph",
    "HydraExtractor",
    "LLMExtractor",
    "LlamaCppExtractionBackend",
    "Node",
    "NmapExtractor",
    "SqlmapExtractor",
    "SupportPolicy",
    "reduce_state",
]
