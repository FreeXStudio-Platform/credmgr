"""State diagrams, system maps, and dependency/call graphs (VISUAL_LIBRARY.md catalog).

All three reuse ``VisualSpec``'s node+edge shape and the flowchart family's proven
rendering/collision pipeline (``tools.docgen.visual``) — the same geometry, glyphs, and
overlap rules apply. What makes each its own visual CONVENTION (per the catalog, not a
new data shape) is a constructor-time invariant this module enforces:

- **State diagram** — "what states exist and what transitions between them." Every node
  must be ``NodeType.STATE`` (a rounded-stadium shape distinct from process/decision/gate);
  edges are labeled transitions. Static — a state diagram shows what's POSSIBLE, not one
  run, so motion is always forced off.
- **System map** — "what are the parts and how do they connect." No edge may be flagged
  ``main`` (there is no privileged flow direction); static.
- **Dependency / call graph** — "what depends on / calls what." Directed edges describe
  structure (dashed = a weak/optional dependency), not a runtime sequence; static.

Reusing ``visual.render``/``visual.check_collisions`` directly means these three inherit
the same collision math and hash-gate determinism with zero duplicated SVG code.

Stdlib only; mypy --strict clean.
"""

from __future__ import annotations

from dataclasses import replace

from tools.docgen.models import Finding, NodeType, VisualSpec
from tools.docgen.visual import CollisionError, check_collisions
from tools.docgen.visual import render as _render_visual


class DiagramConventionError(ValueError):
    """Raised when a spec violates the constructor-time invariant for its diagram kind."""


def _as_static(spec: VisualSpec) -> VisualSpec:
    """Force ``motion=False`` — these three views are structural, not a single run."""
    return spec if not spec.motion else replace(spec, motion=False)


def _require_all_nodes(spec: VisualSpec, expected: NodeType, kind_name: str) -> None:
    offenders = [n.id for n in spec.nodes if n.type is not expected]
    if offenders:
        raise DiagramConventionError(
            f"{kind_name} requires every node to be NodeType.{expected.name}; "
            f"offending node id(s): {offenders}"
        )


def _require_no_main_edges(spec: VisualSpec, kind_name: str) -> None:
    offenders = [f"{e.src}->{e.dst}" for e in spec.edges if e.main]
    if offenders:
        raise DiagramConventionError(
            f"{kind_name} edges may not be flagged main=True (no privileged flow direction); "
            f"offending edge(s): {offenders}"
        )


def check_state_diagram(spec: VisualSpec) -> list[Finding]:
    """Collision findings for a state diagram (identical geometry to the flowchart family)."""
    return check_collisions(spec)


def render_state_diagram(spec: VisualSpec, *, theme: str = "dark") -> str:
    """Render a state diagram. Every node must be ``NodeType.STATE``; raises
    ``DiagramConventionError`` otherwise, ``CollisionError`` on any overlap.
    """
    _require_all_nodes(spec, NodeType.STATE, "a state diagram")
    return _render_visual(_as_static(spec), theme=theme)


def check_system_map(spec: VisualSpec) -> list[Finding]:
    """Collision findings for a system map (identical geometry to the flowchart family)."""
    return check_collisions(spec)


def render_system_map(spec: VisualSpec, *, theme: str = "dark") -> str:
    """Render an undirected system/component map. No edge may be ``main=True``; raises
    ``DiagramConventionError`` otherwise, ``CollisionError`` on any overlap.
    """
    _require_no_main_edges(spec, "a system map")
    return _render_visual(_as_static(spec), theme=theme)


def check_dependency_graph(spec: VisualSpec) -> list[Finding]:
    """Collision findings for a dependency/call graph (identical geometry to the flowchart family)."""
    return check_collisions(spec)


def render_dependency_graph(spec: VisualSpec, *, theme: str = "dark") -> str:
    """Render a directed dependency/call graph. Static (no flow-dot) — describes structure,
    not a runtime sequence. Raises ``CollisionError`` on any overlap.
    """
    return _render_visual(_as_static(spec), theme=theme)


__all__ = [
    "CollisionError",
    "DiagramConventionError",
    "check_dependency_graph",
    "check_state_diagram",
    "check_system_map",
    "render_dependency_graph",
    "render_state_diagram",
    "render_system_map",
]
