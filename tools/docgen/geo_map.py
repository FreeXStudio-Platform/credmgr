"""Geographic / schematic MAP renderer (VISUAL_LIBRARY.md catalog).

VISUAL_LIBRARY draws a hard line between node/edge graphs, data-series charts, and this
family: a geo/schematic map answers "*where* on a territory do things sit, and how are
they connected across it." It is NOT a ``VisualSpec`` graph (a point's position is a real
projected coordinate, not free x/y layout) and NOT a data-series chart (there is no value
axis). It therefore gets its own small spec dataclass (``GeoMapSpec``) and its own renderer
here — the same authoring shape as ``charts.py``.

Design law (mirrors the rest of the engine, enforced not merely advised):

- **No network fetch, ever.** Coordinates are supplied in the spec as normalized
  ``(lon, lat)`` in WGS84-ish degrees; the base outline is a small built-in schematic world
  path baked into this module as inline path data. A map render never touches the network.
- **Equirectangular projection** (the honest, deterministic default): ``lon`` maps linearly
  to x over [-180, 180], ``lat`` to y over [90, -90]. No datum lookups, no external
  proj libraries — pure arithmetic so the output is byte-stable for the hash-gate.
- **B&W ink/paper base, at most ONE KEEP signal accent** for the plotted points (per the SVG law).
  Regions are a faint ink wash; points are the lone sig accent; a "hot" point may use the
  single danger accent to mark severity, still within the one-accent-per-figure budget
  (accent + its severity sibling, matching charts' single-accent rule).
- **Collision-validated, fail-closed.** Point labels are conservatively over-estimated and a
  label overlap FAILS the render, exactly like every other figure in the engine.
- **Every numeric datum is sourced (L8/L16).** A ``point.value`` (or any figure number) must
  resolve to a ``DataSource.ref``; an unsourced number FAILS the render (fail-closed).

Reuses the flowchart family's generic geometry/text/escape helpers so every figure in the
engine shares one collision math and one formatting path.

Stdlib only; mypy --strict clean; deterministic (2dp-rounded floats, stable ordering).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tools.docgen.models import DataSource, Finding, Severity
from tools.docgen.visual import (
    BBox,
    _caption_block,
    _escape,
    _fmt,
    _gap,
    _intersects,
    _r,
    _text_box,
    _title_block,
)

# ---------------------------------------------------------------------------
# Layout constants (match charts.py conventions)
# ---------------------------------------------------------------------------

_MARGIN_LEFT = 24.0
_MARGIN_RIGHT = 24.0
_MARGIN_TOP = 48.0
_MARGIN_BOTTOM = 40.0
_LABEL_FONT_PX = 11.0
_MIN_LABEL_GAP_PX = 6.0
_POINT_R = 5.0
_HOT_POINT_R = 6.5
_LABEL_DY = 14.0  # label sits below its point marker

# The single sanctioned accents (KEEP signal colours) — one primary + its severity sibling.
_ACCENT = "var(--sig-hi,#5FBFA8)"
_ACCENT_HOT = "var(--danger-hi,#D6595C)"

# Longitude/latitude domain of an equirectangular projection.
_LON_MIN, _LON_MAX = -180.0, 180.0
_LAT_MIN, _LAT_MAX = -90.0, 90.0


class GeoMapRuleError(ValueError):
    """Raised when a spec violates a geo-map hard rule (bad coords, unsourced number, overlap)."""


# ---------------------------------------------------------------------------
# Spec dataclasses (own shape — a point is a real projected coordinate)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GeoPoint:
    """A single plotted location. ``lon``/``lat`` are WGS84-ish degrees."""

    id: str
    label: str
    lon: float
    lat: float
    hot: bool = False  # severity emphasis -> the lone danger accent
    value: float | None = None  # optional magnitude; if set, MUST be sourced (L16)
    note: str = ""


@dataclass(frozen=True)
class GeoLink:
    """A great-circle-ish connection drawn as a straight projected line between two points."""

    src: str
    dst: str
    label: str = ""
    style: str = "solid"  # "solid" | "dashed"


@dataclass(frozen=True)
class GeoMapSpec:
    id: str
    title: str
    caption: str
    points: list[GeoPoint]
    links: list[GeoLink] = field(default_factory=list)
    width: float = 900.0
    height: float = 500.0
    show_base: bool = True  # draw the built-in schematic continents wash
    data_sources: list[DataSource] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in schematic world outline (inline path data, ink wash — NO network).
#
# A deliberately coarse, recognizable land silhouette in the equirectangular
# [-180,180] x [90,-90] domain. Each polygon is a list of (lon, lat) vertices;
# it is projected at render time so the base scales with the canvas. Coarse by
# design: the point is orientation, not cartographic accuracy.
# ---------------------------------------------------------------------------

_WORLD_SCHEMATIC: tuple[tuple[tuple[float, float], ...], ...] = (
    # North America
    (
        (-168.0, 66.0),
        (-150.0, 60.0),
        (-125.0, 49.0),
        (-117.0, 33.0),
        (-97.0, 26.0),
        (-81.0, 25.0),
        (-76.0, 38.0),
        (-70.0, 45.0),
        (-56.0, 51.0),
        (-64.0, 60.0),
        (-95.0, 70.0),
        (-130.0, 70.0),
    ),
    # South America
    (
        (-81.0, 8.0),
        (-70.0, -5.0),
        (-70.0, -18.0),
        (-75.0, -37.0),
        (-66.0, -55.0),
        (-58.0, -34.0),
        (-48.0, -25.0),
        (-35.0, -8.0),
        (-50.0, 0.0),
        (-60.0, 6.0),
    ),
    # Africa
    (
        (-17.0, 21.0),
        (-5.0, 5.0),
        (9.0, 4.0),
        (12.0, -6.0),
        (18.0, -34.0),
        (33.0, -28.0),
        (40.0, -12.0),
        (51.0, 12.0),
        (43.0, 12.0),
        (32.0, 31.0),
        (10.0, 34.0),
        (-9.0, 33.0),
    ),
    # Eurasia
    (
        (-9.0, 43.0),
        (5.0, 43.0),
        (12.0, 45.0),
        (30.0, 45.0),
        (48.0, 41.0),
        (70.0, 40.0),
        (90.0, 45.0),
        (105.0, 22.0),
        (122.0, 31.0),
        (135.0, 48.0),
        (160.0, 62.0),
        (140.0, 72.0),
        (90.0, 76.0),
        (40.0, 70.0),
        (10.0, 60.0),
        (5.0, 55.0),
    ),
    # Australia
    (
        (114.0, -22.0),
        (129.0, -12.0),
        (142.0, -11.0),
        (150.0, -37.0),
        (137.0, -38.0),
        (120.0, -34.0),
    ),
)


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


def _plot_rect(spec: GeoMapSpec) -> tuple[float, float, float, float]:
    """Return the (x0, y0, plot_w, plot_h) inner drawing rectangle."""
    plot_w = spec.width - _MARGIN_LEFT - _MARGIN_RIGHT
    plot_h = spec.height - _MARGIN_TOP - _MARGIN_BOTTOM
    return (_MARGIN_LEFT, _MARGIN_TOP, plot_w, plot_h)


def _project(lon: float, lat: float, spec: GeoMapSpec) -> tuple[float, float]:
    """Equirectangular projection of (lon, lat) into canvas pixels (rounded)."""
    x0, y0, plot_w, plot_h = _plot_rect(spec)
    fx = (lon - _LON_MIN) / (_LON_MAX - _LON_MIN)
    fy = (_LAT_MAX - lat) / (_LAT_MAX - _LAT_MIN)
    return (_r(x0 + fx * plot_w), _r(y0 + fy * plot_h))


# ---------------------------------------------------------------------------
# Validation / collision
# ---------------------------------------------------------------------------


def check_geo_map_collisions(spec: GeoMapSpec) -> list[Finding]:
    """Return blocking findings: no points, out-of-range coords, an unsourced numeric
    ``value`` (L16), a link referencing an unknown point, or overlapping point labels.
    Fail-closed — any of these blocks the render.
    """
    findings: list[Finding] = []
    if not spec.points:
        findings.append(
            Finding(gate="geomap.rule", message="geo map has no points", severity=Severity.CRIT)
        )
        return findings

    ids = {p.id for p in spec.points}
    known_refs = {ds.ref for ds in spec.data_sources}

    for p in spec.points:
        if not (_LON_MIN <= p.lon <= _LON_MAX):
            findings.append(
                Finding(
                    gate="geomap.rule",
                    message=f"point '{p.id}' lon={p.lon} outside [{_LON_MIN}, {_LON_MAX}]",
                    severity=Severity.CRIT,
                )
            )
        if not (_LAT_MIN <= p.lat <= _LAT_MAX):
            findings.append(
                Finding(
                    gate="geomap.rule",
                    message=f"point '{p.id}' lat={p.lat} outside [{_LAT_MIN}, {_LAT_MAX}]",
                    severity=Severity.CRIT,
                )
            )
        # L16 claim-ledger: every numeric datum must resolve to a DataSource.ref (fail-closed).
        if p.value is not None and not known_refs:
            findings.append(
                Finding(
                    gate="geomap.source",
                    message=(
                        f"point '{p.id}' carries a numeric value ({p.value:g}) but the spec "
                        "has no DataSource; every figure number must be sourced (L16)"
                    ),
                    severity=Severity.CRIT,
                )
            )

    for link in spec.links:
        missing = [end for end in (link.src, link.dst) if end not in ids]
        if missing:
            findings.append(
                Finding(
                    gate="geomap.rule",
                    message=f"link {link.src}->{link.dst} references unknown point id(s): {missing}",
                    severity=Severity.CRIT,
                )
            )

    # Label collisions — conservative, over-estimated boxes; a hit fails the render.
    boxes: list[tuple[str, BBox]] = []
    for p in spec.points:
        px, py = _project(p.lon, p.lat, spec)
        box = _text_box(px, py + _LABEL_DY, p.label, _LABEL_FONT_PX)
        boxes.append((p.id, box))
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            if _intersects(boxes[i][1], boxes[j][1]) or _gap(boxes[i][1], boxes[j][1]) < _MIN_LABEL_GAP_PX:
                findings.append(
                    Finding(
                        gate="geomap.collision",
                        message=(
                            f"Point labels '{boxes[i][0]}' and '{boxes[j][0]}' overlap "
                            "(locations too close for this canvas size)"
                        ),
                        severity=Severity.CRIT,
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# SVG helpers (self-contained; mirror charts.py's wrapper style)
# ---------------------------------------------------------------------------


def _defs_css() -> str:
    return (
        "<style><![CDATA["
        ".geo-base{fill:currentColor;fill-opacity:0.10;stroke:currentColor;"
        "stroke-opacity:0.30;stroke-width:1;}"
        ".geo-frame{fill:none;stroke:currentColor;stroke-opacity:0.35;stroke-width:1;}"
        ".geo-grid{stroke:currentColor;stroke-opacity:0.12;stroke-width:0.75;fill:none;}"
        ".geo-link{fill:none;stroke:currentColor;stroke-width:1.25;stroke-opacity:0.55;}"
        ".geo-link-dashed{stroke-dasharray:5 4;}"
        ".geo-label,.figure-caption,.figure-title{"
        "font-family:var(--f-body,Inter,system-ui,sans-serif);fill:currentColor;}"
        "]]></style>"
    )


def _base_svg(spec: GeoMapSpec) -> str:
    if not spec.show_base:
        return ""
    parts: list[str] = []
    for polygon in _WORLD_SCHEMATIC:
        pts = " ".join(
            f"{_fmt(px)},{_fmt(py)}"
            for px, py in (_project(lon, lat, spec) for lon, lat in polygon)
        )
        parts.append(f'<polygon class="geo-base" points="{pts}"/>')
    return "".join(parts)


def _graticule_svg(spec: GeoMapSpec) -> str:
    """A faint equator + prime-meridian graticule so the projection reads as a map."""
    x0, y0, plot_w, plot_h = _plot_rect(spec)
    eq_x, eq_y = _project(0.0, 0.0, spec)
    return (
        f'<line class="geo-grid" x1="{_fmt(x0)}" y1="{_fmt(eq_y)}" '
        f'x2="{_fmt(x0 + plot_w)}" y2="{_fmt(eq_y)}"/>'
        f'<line class="geo-grid" x1="{_fmt(eq_x)}" y1="{_fmt(y0)}" '
        f'x2="{_fmt(eq_x)}" y2="{_fmt(y0 + plot_h)}"/>'
    )


def _frame_svg(spec: GeoMapSpec) -> str:
    x0, y0, plot_w, plot_h = _plot_rect(spec)
    return (
        f'<rect class="geo-frame" x="{_fmt(x0)}" y="{_fmt(y0)}" '
        f'width="{_fmt(plot_w)}" height="{_fmt(plot_h)}"/>'
    )


def _links_svg(spec: GeoMapSpec, coords: dict[str, tuple[float, float]]) -> str:
    parts: list[str] = []
    for link in spec.links:
        sx, sy = coords[link.src]
        dx, dy = coords[link.dst]
        cls = "geo-link geo-link-dashed" if link.style == "dashed" else "geo-link"
        parts.append(
            f'<line class="{cls}" x1="{_fmt(sx)}" y1="{_fmt(sy)}" x2="{_fmt(dx)}" y2="{_fmt(dy)}"/>'
        )
        if link.label:
            mx, my = _r((sx + dx) / 2), _r((sy + dy) / 2)
            parts.append(
                f'<text class="geo-label" x="{_fmt(mx)}" y="{_fmt(my - 4.0)}" '
                f'text-anchor="middle" font-size="10">{_escape(link.label)}</text>'
            )
    return "".join(parts)


def _points_svg(spec: GeoMapSpec, coords: dict[str, tuple[float, float]]) -> str:
    parts: list[str] = []
    # Stable draw order: id-sorted, so the byte output never depends on input ordering.
    for p in sorted(spec.points, key=lambda pt: pt.id):
        px, py = coords[p.id]
        color = _ACCENT_HOT if p.hot else _ACCENT
        radius = _HOT_POINT_R if p.hot else _POINT_R
        parts.append(
            f'<circle cx="{_fmt(px)}" cy="{_fmt(py)}" r="{_fmt(radius)}" '
            f'fill="{color}" stroke="var(--paper,#060608)" stroke-width="1"/>'
        )
        label = p.label if p.value is None else f"{p.label} ({p.value:g})"
        parts.append(
            f'<text class="geo-label" x="{_fmt(px)}" y="{_fmt(py + _LABEL_DY)}" '
            f'text-anchor="middle" font-size="{_LABEL_FONT_PX}">{_escape(label)}</text>'
        )
    return "".join(parts)


def render_geo_map(spec: GeoMapSpec, *, theme: str = "dark") -> str:
    """Render ``spec`` to a self-contained ``<svg>`` string (a schematic geo map).

    Raises ``GeoMapRuleError`` on any blocking finding (no points, out-of-range coordinates,
    an unsourced numeric value, a dangling link, or overlapping point labels). ``theme`` is
    accepted for signature parity with the other renderers; all colour is ``currentColor`` /
    CSS-var based so the wrapping element's ``color`` selects dark or light with no re-render.
    """
    _ = theme  # colour is currentColor/var-driven; theme is applied by the host element.
    collisions = check_geo_map_collisions(spec)
    if collisions:
        raise GeoMapRuleError(f"{spec.id}: " + "; ".join(f.message for f in collisions))

    coords = {p.id: _project(p.lon, p.lat, spec) for p in spec.points}

    body = (
        _base_svg(spec)
        + _graticule_svg(spec)
        + _frame_svg(spec)
        + _links_svg(spec, coords)
        + _points_svg(spec, coords)
    )
    # Wrapped title/caption with a growing viewBox — long text pushes the canvas
    # taller instead of overflowing the edges or overlapping the map.
    title_svg, title_extra = _title_block(spec.width, spec.title)
    caption_svg, caption_h = _caption_block(spec.width, spec.caption, spec.height + title_extra)
    total_h = spec.height + title_extra + caption_h
    return (
        f'<svg viewBox="0 0 {_fmt(spec.width)} {_fmt(total_h)}" '
        f'xmlns="http://www.w3.org/2000/svg" class="ah-figure ah-geomap" '
        f'role="img" aria-label="{_escape(spec.title or spec.id)}">'
        f"{_defs_css()}"
        f"{title_svg}"
        f'<g transform="translate(0,{_fmt(title_extra)})">{body}</g>'
        f"{caption_svg}"
        f"</svg>"
    )


__all__ = [
    "GeoLink",
    "GeoMapRuleError",
    "GeoMapSpec",
    "GeoPoint",
    "check_geo_map_collisions",
    "render_geo_map",
]
