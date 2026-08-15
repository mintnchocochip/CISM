"""The Dependency / Error Propagation Graph domain model.

Deliberately minimal today: just the two working types the agent mutates as
a run progresses. Graph traversal, containment, and the propagation/gamma
math are not implemented yet — they arrive later as new modules in this same
package (e.g. ``graph.py``, ``propagation.py``), which is why ``Node`` and
``Edge`` have no dependency on anything in ``cism.agent``.
"""

from __future__ import annotations

from .edge import Edge
from .node import Node

__all__ = ["Edge", "Node"]
