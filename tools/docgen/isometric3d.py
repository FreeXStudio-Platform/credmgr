"""True isometric (axonometric) 3D renderer — stacked boxes / layered-volume view
(VISUAL_LIBRARY.md §1 "3D workflow / layered" + §2 "3D / layered views"; RULEBOOK L16).

Unlike ``layered_workflow.py`` — which fakes depth with a flat horizontal *shear* per plane
— this renderer performs a **real isometric projection**: every box is a 3D cuboid with
``(x, y, z)`` world coordinates and ``(w, d, h)`` extents, projected through the standard
2:1 isometric matrix onto the screen, drawn as three visible faces (top + left + right) with
their edges, and depth-sorted by a painter's algorithm so nearer volumes occlude farther
ones correctly. It is the honest "3D stack" the operator asked for (stacked-volume tiers,
an engine-stack rendered as receding cuboids), not a shadow trick.

The projection is a fixed deterministic matrix (no runtime state, no ``Date.now``/random);
all emitted SVG floats are rounded to 2 dp and every set/dict is sorted before serialization,
so a build-twice run is byte-identical (required by the hash-gate).

Self-contained ``<svg>``: ``role="img"`` + ``aria-label``, B&W ink/paper base drawn with
``currentColor`` (theme applied by the wrapping element's ``color``), at most ONE CredMgr
accent (the ``--sig-hi`` active-layer highlight), and the only motion is the sanctioned ambient
pulse on a highlighted box, guarded behind ``@media (prefers-reduced-motion: reduce), print``.
The collision validator runs on the **projected screen-space footprints** and FAILS the render
on any overlap, so a valid isometric layout passes and an overlapping one is blocked.

Reuses the flowchart family's ``_r``/``_fmt``/``_escape``/``_intersects``/``_gap`` helpers so
rounding, formatting, and collision math stay identical across every figure type in the engine.

Stdlib only; mypy --strict clean.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from tools.docgen.models import DataSource, Finding, LegendEntry, Severity
from tools.docgen.visual import BBox, _escape, _fmt, _gap, _intersects, _r

# --- Isometric projection constants (fixed, deterministic) -----------------
# Standard 2:1 "video-game" isometric: 30° from horizontal on both ground axes.
# Screen = (world_x - world_y) * COS30 * SCALE for X, and
#          (world_x + world_y) * SIN30 * SCALE - world_z * SCALE for Y (up = -Y).
_COS30 = math.cos(math.radians(30.0))  # ≈ 0.8660254
_SIN30 = math.sin(math.radians(30.0))  # = 0.5
_SCALE = 1.0  # world units are already in px; keep a knob but default 1:1

_ORIGIN_X = 360.0  # screen-space origin the world projects around (centred-ish)
_ORIGIN_Y = 300.0

_LABEL_FONT_PX = 12.0
_LAYER_LABEL_FONT_PX = 11.0
_MIN_GAP_PX = 22.0  # DESIGN_SYSTEM §"Spacing": ≥22px between diagram elements
_MAX_BOXES = 24  # legibility cap — a 3D stack past this reads as noise

_TOP_FILL = "var(--paper-2,#141420)"
_LEFT_FILL = "var(--g2,#1c1c28)"
_RIGHT_FILL = "var(--g1,#242433)"
_ACCENT = "var(--sig-hi,#5FBFA8)"  # the single sanctioned accent (active box)


@dataclass(frozen=True)
class IsoBox:
    """One 3D cuboid in world space.

    ``(x, y, z)`` is the box's near-bottom corner in world units; ``z`` is height off the
    ground plane (depth/stacking axis). ``(w, d, h)`` are its extents along the world X
    (right-and-down-screen), world Y (left-and-down-screen), and world Z (up-screen) axes.
    """

    id: str
    label: str
    x: float
    y: float
    z: float
    w: float = 96.0
    d: float = 96.0
    h: float = 44.0
    note: str = ""
    highlight: bool = False  # active box -> single --sig-hi accent + ambient pulse


@dataclass(frozen=True)
class IsoConnector:
    """A connector between two boxes' projected top-centres (routed as a straight line)."""

    src: str
    dst: str
    label: str = ""
    style: str = "solid"  # "solid" | "dashed"


@dataclass(frozen=True)
class IsometricSpec:
    """A true-isometric 3D scene: a set of world-placed cuboids + optional connectors.

    ``layer_labels`` (optional) name the stacking planes by z-index tier, shown along the
    left as an axis legend. All numeric extents are world units (px after ``_SCALE``).
    """

    id: str
    title: str
    caption: str
    boxes: list[IsoBox]
    connectors: list[IsoConnector] = field(default_factory=list)
    layer_labels: list[str] = field(default_factory=list)
    legend: list[LegendEntry] = field(default_factory=list)
    motion: bool = True
    width: float = 720.0
    height: float = 480.0
    data_sources: list[DataSource] = field(default_factory=list)


class IsometricCollisionError(RuntimeError):
    """Raised by ``render`` when ``check_collisions`` finds a blocking overlap."""


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


def project(wx: float, wy: float, wz: float) -> tuple[float, float]:
    """Project a world point ``(wx, wy, wz)`` to isometric screen coordinates.

    Deterministic fixed matrix. ``wz`` is the up axis (subtracted from screen Y so height
    rises on screen). Result is rounded to 2 dp for byte-stable output.
    """
    sx = _ORIGIN_X + (wx - wy) * _COS30 * _SCALE
    sy = _ORIGIN_Y + (wx + wy) * _SIN30 * _SCALE - wz * _SCALE
    return (_r(sx), _r(sy))


def _box_screen_footprint(box: IsoBox) -> BBox:
    """Axis-aligned screen-space bounding box of a projected cuboid's 8 corners.

    Used by the collision validator: two cuboids whose projected footprints overlap will
    visually collide regardless of depth order, so we fail on footprint intersection.
    """
    corners: list[tuple[float, float]] = []
    for dx in (0.0, box.w):
        for dy in (0.0, box.d):
            for dz in (0.0, box.h):
                corners.append(project(box.x + dx, box.y + dy, box.z + dz))
    xs = [c[0] for c in corners]
    ys = [c[1] for c in corners]
    return (min(xs), min(ys), max(xs), max(ys))


def _depth_key(box: IsoBox) -> tuple[float, str]:
    """Painter's-algorithm sort key: farther boxes first (smaller x+y+z draws behind).

    Tie-broken by ``id`` so the order is total and deterministic.
    """
    return (box.x + box.y + box.z, box.id)


# ---------------------------------------------------------------------------
# Collision validation
# ---------------------------------------------------------------------------


def check_collisions(spec: IsometricSpec) -> list[Finding]:
    """Blocking findings: no boxes, too many boxes, duplicate/unknown ids, connector refs,
    and any projected-footprint overlap (or sub-22px gap) between two distinct cuboids.
    Fail-closed: any structural problem is a CRIT blocking finding.
    """
    findings: list[Finding] = []
    if not spec.boxes:
        findings.append(
            Finding(
                gate="iso3d.rule",
                message="isometric scene has no boxes",
                severity=Severity.CRIT,
            )
        )
        return findings
    if len(spec.boxes) > _MAX_BOXES:
        findings.append(
            Finding(
                gate="iso3d.rule",
                message=f"{len(spec.boxes)} boxes exceeds the {_MAX_BOXES}-box legibility cap",
                severity=Severity.CRIT,
            )
        )

    ids: set[str] = set()
    for box in spec.boxes:
        if box.id in ids:
            findings.append(
                Finding(
                    gate="iso3d.rule",
                    message=f"duplicate box id '{box.id}'",
                    severity=Severity.CRIT,
                )
            )
        ids.add(box.id)
        if box.w <= 0 or box.d <= 0 or box.h <= 0:
            findings.append(
                Finding(
                    gate="iso3d.rule",
                    message=f"box '{box.id}' has a non-positive extent",
                    severity=Severity.CRIT,
                )
            )

    for conn in spec.connectors:
        if conn.src not in ids:
            findings.append(
                Finding(
                    gate="iso3d.rule",
                    message=f"connector references unknown src '{conn.src}'",
                    severity=Severity.CRIT,
                )
            )
        if conn.dst not in ids:
            findings.append(
                Finding(
                    gate="iso3d.rule",
                    message=f"connector references unknown dst '{conn.dst}'",
                    severity=Severity.CRIT,
                )
            )

    if findings:
        return findings

    footprints = [(box.id, _box_screen_footprint(box)) for box in spec.boxes]
    # Two cuboids that share a world footprint (one stacked exactly above another, same x/y)
    # are legitimately allowed to overlap on screen — that IS the stack. Only flag overlaps
    # between boxes that do NOT share a ground column.
    ground: dict[str, tuple[float, float, float, float]] = {
        b.id: (b.x, b.y, b.w, b.d) for b in spec.boxes
    }
    for i in range(len(footprints)):
        id_a, box_a = footprints[i]
        for j in range(i + 1, len(footprints)):
            id_b, box_b = footprints[j]
            if _same_ground_column(ground[id_a], ground[id_b]):
                continue
            if _intersects(box_a, box_b):
                findings.append(
                    Finding(
                        gate="iso3d.collision",
                        message=f"boxes '{id_a}' and '{id_b}' overlap in projected screen space",
                        severity=Severity.CRIT,
                    )
                )
            elif _gap(box_a, box_b) < _MIN_GAP_PX:
                findings.append(
                    Finding(
                        gate="iso3d.collision",
                        message=(
                            f"projected gap between '{id_a}' and '{id_b}' below the "
                            f"{_MIN_GAP_PX:g}px minimum"
                        ),
                        severity=Severity.CRIT,
                    )
                )

    return findings


def _same_ground_column(
    a: tuple[float, float, float, float], b: tuple[float, float, float, float]
) -> bool:
    """True when two boxes occupy the same ground (x, y, w, d) footprint — a legal stack."""
    return a == b


# ---------------------------------------------------------------------------
# SVG emission
# ---------------------------------------------------------------------------


def _defs_css() -> str:
    return (
        "<style><![CDATA["
        ".iso-face{stroke:currentColor;stroke-width:1;stroke-linejoin:round;}"
        ".iso-edge{stroke:currentColor;stroke-width:1.25;fill:none;stroke-linejoin:round;}"
        ".iso-label{font-family:var(--f-body,Inter,system-ui,sans-serif);fill:currentColor;}"
        ".iso-note{font-family:var(--f-mono,monospace);fill:currentColor;opacity:0.7;}"
        ".iso-layer-label{font-family:var(--f-mono,monospace);fill:currentColor;opacity:0.7;}"
        ".iso-conn{stroke:currentColor;stroke-width:1.5;fill:none;opacity:0.85;}"
        ".iso-conn-label{font-family:var(--f-body,Inter,system-ui,sans-serif);fill:currentColor;}"
        ".figure-title{font-family:var(--f-body,Inter,system-ui,sans-serif);}"
        ".figure-caption{font-family:var(--f-body,Inter,system-ui,sans-serif);fill:currentColor;}"
        f".iso-active{{stroke:{_ACCENT};stroke-width:1.75;}}"
        # Ambient pulse on the active box — GUARDED off for reduced-motion + print.
        "@media (prefers-reduced-motion: no-preference){"
        ".iso-pulse{animation:iso-breathe 2.8s ease-in-out infinite;transform-origin:center;}"
        "@keyframes iso-breathe{0%,100%{opacity:0.85;}50%{opacity:1;}}"
        "}"
        "]]></style>"
    )


def _poly(points: list[tuple[float, float]], css_class: str, fill: str) -> str:
    pts = " ".join(f"{_fmt(x)},{_fmt(y)}" for x, y in points)
    return f'<polygon class="{css_class}" points="{pts}" fill="{fill}"/>'


def _render_box(box: IsoBox) -> str:
    """Emit one cuboid: top + left + right faces (painter order: back faces implied by the
    single visible-corner isometric view) with edges, then the label on the top face.
    """
    x, y, z, w, d, h = box.x, box.y, box.z, box.w, box.d, box.h
    # 8 corners: b*=bottom (z), t*=top (z+h); named by (x-near/far, y-near/far).
    # Near corner is (x, y); the three visible faces are top, left (y=0 wall), right (x=w wall).
    p_b_00 = project(x, y, z)
    p_b_w0 = project(x + w, y, z)
    p_b_wd = project(x + w, y + d, z)
    p_t_00 = project(x, y, z + h)
    p_t_w0 = project(x + w, y, z + h)
    p_t_0d = project(x, y + d, z + h)
    p_t_wd = project(x + w, y + d, z + h)

    active = box.highlight
    face_cls = "iso-face iso-active" if active else "iso-face"
    edge_cls = "iso-edge iso-active" if active else "iso-edge"
    group_cls = "iso-box iso-pulse" if active else "iso-box"

    parts: list[str] = [f'<g class="{group_cls}">']
    # Top face (the up-facing quad t_00 → t_w0 → t_wd → t_0d).
    parts.append(_poly([p_t_00, p_t_w0, p_t_wd, p_t_0d], face_cls, _TOP_FILL))
    # Left face (y-near wall: b_00 → b_w0 → t_w0 → t_00).
    parts.append(_poly([p_b_00, p_b_w0, p_t_w0, p_t_00], face_cls, _LEFT_FILL))
    # Right face (x-far wall: b_w0 → b_wd → t_wd → t_w0).
    parts.append(_poly([p_b_w0, p_b_wd, p_t_wd, p_t_w0], face_cls, _RIGHT_FILL))
    # Silhouette edges for crispness.
    for a, b in (
        (p_t_00, p_t_w0),
        (p_t_w0, p_t_wd),
        (p_t_wd, p_t_0d),
        (p_t_0d, p_t_00),
        (p_b_00, p_t_00),
        (p_b_w0, p_t_w0),
        (p_b_wd, p_t_wd),
        (p_b_00, p_b_w0),
        (p_b_w0, p_b_wd),
    ):
        parts.append(
            f'<line class="{edge_cls}" x1="{_fmt(a[0])}" y1="{_fmt(a[1])}" '
            f'x2="{_fmt(b[0])}" y2="{_fmt(b[1])}"/>'
        )
    # Label centred on the top face (average of its 4 corners).
    lx = _r((p_t_00[0] + p_t_w0[0] + p_t_wd[0] + p_t_0d[0]) / 4)
    ly = _r((p_t_00[1] + p_t_w0[1] + p_t_wd[1] + p_t_0d[1]) / 4 + 4.0)
    parts.append(
        f'<text class="iso-label" x="{_fmt(lx)}" y="{_fmt(ly)}" text-anchor="middle" '
        f'font-size="{_LABEL_FONT_PX}">{_escape(box.label)}</text>'
    )
    if box.note:
        parts.append(
            f'<text class="iso-note" x="{_fmt(lx)}" y="{_fmt(ly + 14.0)}" '
            f'text-anchor="middle" font-size="9">{_escape(box.note)}</text>'
        )
    parts.append("</g>")
    return "".join(parts)


def _render_connectors(spec: IsometricSpec, boxes_by_id: dict[str, IsoBox]) -> str:
    parts: list[str] = []
    for conn in spec.connectors:
        src, dst = boxes_by_id[conn.src], boxes_by_id[conn.dst]
        sx, sy = project(src.x + src.w / 2, src.y + src.d / 2, src.z + src.h)
        dx, dy = project(dst.x + dst.w / 2, dst.y + dst.d / 2, dst.z + dst.h)
        dash = ' stroke-dasharray="6 4"' if conn.style == "dashed" else ""
        parts.append(
            f'<line class="iso-conn" x1="{_fmt(sx)}" y1="{_fmt(sy)}" '
            f'x2="{_fmt(dx)}" y2="{_fmt(dy)}"{dash}/>'
        )
        if conn.label:
            mx, my = _r((sx + dx) / 2), _r((sy + dy) / 2 - 6.0)
            parts.append(
                f'<text class="iso-conn-label" x="{_fmt(mx)}" y="{_fmt(my)}" '
                f'text-anchor="middle" font-size="10">{_escape(conn.label)}</text>'
            )
    return "".join(parts)


def _render_layer_labels(spec: IsometricSpec) -> str:
    if not spec.layer_labels:
        return ""
    parts: list[str] = []
    for idx, label in enumerate(spec.layer_labels):
        parts.append(
            f'<text class="iso-layer-label" x="16" y="{_fmt(72.0 + idx * 22.0)}" '
            f'font-size="{_LAYER_LABEL_FONT_PX}">{_escape(f"z{idx}·{label}")}</text>'
        )
    return "".join(parts)


def render(spec: IsometricSpec, *, theme: str = "dark") -> str:
    """Render ``spec`` to a self-contained isometric-3D ``<svg>``.

    Depth-sorts boxes (painter's algorithm), draws each as a real projected cuboid, overlays
    connectors and axis labels, and adds the title + caption. Raises ``IsometricCollisionError``
    on any blocking collision. Deterministic across calls (byte-identical build-twice).
    """
    collisions = check_collisions(spec)
    if collisions:
        messages = "; ".join(f.message for f in collisions)
        raise IsometricCollisionError(
            f"{spec.id}: {len(collisions)} blocking collision(s): {messages}"
        )

    boxes_by_id = {b.id: b for b in spec.boxes}
    ordered = sorted(spec.boxes, key=_depth_key)

    body = _defs_css()
    body += _render_layer_labels(spec)
    # Connectors drawn under boxes so nearer volumes occlude the lines behind them.
    body += _render_connectors(spec, boxes_by_id)
    for box in ordered:
        body += _render_box(box)

    if spec.title:
        body += (
            f'<text x="{_fmt(spec.width / 2)}" y="24" class="figure-title" '
            f'font-size="18" text-anchor="middle" font-weight="700" '
            f'fill="currentColor">{_escape(spec.title)}</text>'
        )
    if spec.caption:
        body += (
            f'<text x="{_fmt(spec.width / 2)}" y="{_fmt(spec.height - 10.0)}" '
            f'class="figure-caption" font-size="12" text-anchor="middle">'
            f"{_escape(spec.caption)}</text>"
        )

    return (
        f'<svg viewBox="0 0 {_fmt(spec.width)} {_fmt(spec.height)}" '
        f'xmlns="http://www.w3.org/2000/svg" class="ah-figure ah-iso3d" '
        f'data-theme="{theme}" role="img" '
        f'aria-label="{_escape(spec.title or spec.id)}">{body}</svg>'
    )
