"""Data-series chart renderers: bar, radar, pie/donut, timeline, heatmap.

VISUAL_LIBRARY.md draws a hard line: these five are NOT node/edge graphs ("bar/heatmap/
radar/pie/timeline are data-series charts... need their own small spec dataclass(es)").
Each has its own ``*Spec`` dataclass (``models.py``) and its own renderer here, but all
five share the catalog's selection rules as hard, enforced constraints rather than
style advice:

- bar: always a zero baseline, non-negative values.
- radar: axes must be labeled; at least 3 axes (a "profile", not a 2-point comparison);
  every series must supply exactly one value per axis.
- pie/donut: never more than 6 slices; a non-empty positive total.
- timeline: events must be temporally ordered and far enough apart to read.
- heatmap: never without a scale legend; the matrix shape must match its labels.

A categorical palette (6 colors max, matching the pie-slice cap) is drawn from the
KEEP achromatic law (v2/design/tokens/keep.tokens.json) — no new colors invented.

Reuses the flowchart family's generic geometry/text/escape helpers so every figure in
the engine shares the same collision math and formatting.

Stdlib only; mypy --strict clean; deterministic (2dp-rounded floats, stable ordering).
"""

from __future__ import annotations

import math

from tools.docgen.models import (
    BarSpec,
    Finding,
    HeatmapSpec,
    PieSpec,
    RadarSpec,
    Severity,
    TimelineSpec,
)
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

_MARGIN_LEFT = 56.0
_MARGIN_RIGHT = 24.0
_MARGIN_TOP = 48.0
_MARGIN_BOTTOM = 56.0
_LABEL_FONT_PX = 12.0
_MIN_GAP_PX = 22.0
_PIE_MAX_SLICES = 6
_RADAR_MIN_AXES = 3

# Categorical palette: an achromatic lightness ramp (bone -> ash -> mute -> steel-3 ->
# steel-2 -> faint), NOT a multi-hue palette — KEEP reserves colour for exactly three
# states (sig/warn/danger) and treats anything else as decorative (v2/design/tokens/
# keep.tokens.json, identity.principles). `--sig-hi` is the lone accent for a
# single-series chart (matching the "one accent per figure" budget); the achromatic
# tones only appear once >1 category exists, ordered for perceptual separation.
_CATEGORICAL_PALETTE = (
    "var(--sig-hi,#5FBFA8)",
    "var(--bone,#E9ECF1)",
    "var(--ash,#98A0AE)",
    "var(--mute,#767E8C)",
    "var(--steel-3,#1B1B22)",
    "var(--faint,#2A2E38)",
)

# Literal hex (not CSS vars) — heatmap cell fills are computed per-value interpolations,
# which requires real RGB math, not an opaque `var()` reference.
_HEAT_LOW = (19, 19, 24)  # --steel-2
_HEAT_MID = (23, 59, 51)  # --sig-dim
_HEAT_HIGH = (95, 191, 168)  # --sig-hi


class ChartRuleError(ValueError):
    """Raised when a spec violates one of VISUAL_LIBRARY's hard chart-selection rules."""


def _color_for(index: int) -> str:
    return _CATEGORICAL_PALETTE[index % len(_CATEGORICAL_PALETTE)]


def _defs_css() -> str:
    return (
        "<style><![CDATA["
        ".axis{stroke:currentColor;stroke-width:1;opacity:0.5;}"
        ".axis-grid{stroke:currentColor;stroke-width:0.75;opacity:0.25;fill:none;}"
        ".chart-label,.chart-value,.figure-caption,.legend-label{"
        "font-family:var(--f-body,Inter,system-ui,sans-serif);fill:currentColor;}"
        ".chart-value{font-variant-numeric:tabular-nums;}"
        "]]></style>"
    )


def _wrap_svg(
    width: float,
    height: float,
    css_class: str,
    title: str,
    body: str,
    caption: str,
    footer: str = "",
    footer_h: float = 0.0,
) -> str:
    """Assemble the final ``<svg>``. The title wraps (extra lines push the body
    down), an optional footer block (legend rows) sits below the body, and the
    caption wraps below that — the viewBox grows so long text can never overlap
    the plot or clip at the canvas edge.
    """
    title_svg, title_extra = _title_block(width, title)
    footer_svg = (
        f'<g transform="translate(0,{_fmt(height + title_extra)})">{footer}</g>' if footer else ""
    )
    caption_svg, caption_h = _caption_block(width, caption, height + title_extra + footer_h)
    total_h = height + title_extra + footer_h + caption_h
    return (
        f'<svg viewBox="0 0 {_fmt(width)} {_fmt(total_h)}" xmlns="http://www.w3.org/2000/svg" '
        f'class="ah-figure {css_class}" role="img" aria-label="{_escape(title)}">'
        f"{_defs_css()}{title_svg}"
        f'<g transform="translate(0,{_fmt(title_extra)})">{body}</g>'
        f"{footer_svg}{caption_svg}</svg>"
    )


# ---------------------------------------------------------------------------
# Bar chart
# ---------------------------------------------------------------------------


def check_bar_collisions(spec: BarSpec) -> list[Finding]:
    findings: list[Finding] = []
    if not spec.items:
        findings.append(
            Finding(gate="chart.rule", message="bar chart has no items", severity=Severity.CRIT)
        )
        return findings
    if any(item.value < 0 for item in spec.items):
        findings.append(
            Finding(
                gate="chart.rule",
                message="bar chart values must be >= 0 (zero baseline, VISUAL_LIBRARY selection rule)",
                severity=Severity.CRIT,
            )
        )

    plot_w = spec.width - _MARGIN_LEFT - _MARGIN_RIGHT
    slot_w = plot_w / len(spec.items)
    boxes: list[BBox] = []
    for i, item in enumerate(spec.items):
        cx = _r(_MARGIN_LEFT + slot_w * (i + 0.5))
        box = _text_box(cx, spec.height - _MARGIN_BOTTOM + 16.0, item.label, _LABEL_FONT_PX)
        boxes.append(box)
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            if _intersects(boxes[i], boxes[j]):
                findings.append(
                    Finding(
                        gate="chart.collision",
                        message=f"Category labels {i} and {j} overlap (chart too narrow for {len(spec.items)} items)",
                        severity=Severity.CRIT,
                    )
                )
    return findings


def _bar_value_label(value: float, unit: str) -> str:
    """Human-readable value label: '$'-units get currency formatting; the full unit
    string is rendered ONCE as an axis note, never repeated on every bar."""
    if unit.strip().startswith("$"):
        return f"${value:,.0f}" if abs(value) >= 100 else f"${value:g}"
    return f"{value:g}"


def render_bar(spec: BarSpec) -> str:
    """Render ``spec`` to a self-contained ``<svg>``. Raises ``ChartRuleError`` on any
    blocking finding (empty chart, negative value, or overlapping category labels).
    """
    collisions = check_bar_collisions(spec)
    if collisions:
        raise ChartRuleError(f"{spec.id}: " + "; ".join(f.message for f in collisions))

    plot_w = spec.width - _MARGIN_LEFT - _MARGIN_RIGHT
    plot_h = spec.height - _MARGIN_TOP - _MARGIN_BOTTOM
    baseline_y = _MARGIN_TOP + plot_h
    max_value = max((item.value for item in spec.items), default=0.0) or 1.0
    slot_w = plot_w / len(spec.items)
    bar_w = slot_w * 0.6

    # Log mode keeps wide-dynamic-range comparisons readable (a $0.5 bar next to a
    # $70k bar is invisible on a linear axis); zero/negative values stay at zero.
    positives = [item.value for item in spec.items if item.value > 0]
    log_mode = spec.log_scale and bool(positives)
    log_lo = math.log10(min(positives)) if log_mode else 0.0
    log_span = (math.log10(max(positives)) - log_lo) or 1.0 if log_mode else 1.0

    def _frac_of(value: float) -> float:
        if log_mode:
            if value <= 0:
                return 0.0
            return 0.06 + 0.94 * ((math.log10(value) - log_lo) / log_span)
        return value / max_value if max_value > 0 else 0.0

    parts: list[str] = [
        f'<line class="axis" x1="{_fmt(_MARGIN_LEFT)}" y1="{_fmt(baseline_y)}" '
        f'x2="{_fmt(spec.width - _MARGIN_RIGHT)}" y2="{_fmt(baseline_y)}"/>'
    ]
    if spec.unit:
        unit_note = f"{spec.unit} — log scale" if log_mode else spec.unit
        parts.append(
            f'<text class="chart-value" x="{_fmt(_MARGIN_LEFT)}" y="{_fmt(_MARGIN_TOP - 10.0)}" '
            f'text-anchor="start" font-size="11" opacity="0.75">{_escape(unit_note)}</text>'
        )
    for i, item in enumerate(spec.items):
        bar_h = _r(_frac_of(item.value) * plot_h)
        x = _r(_MARGIN_LEFT + slot_w * i + (slot_w - bar_w) / 2)
        y = _r(baseline_y - bar_h)
        color = _color_for(0)  # single-series bar: one accent, per VISUAL_LIBRARY
        parts.append(
            f'<rect x="{_fmt(x)}" y="{_fmt(y)}" width="{_fmt(bar_w)}" height="{_fmt(bar_h)}" fill="{color}"/>'
        )
        parts.append(
            f'<text class="chart-value" x="{_fmt(x + bar_w / 2)}" y="{_fmt(y - 6.0)}" '
            f'text-anchor="middle" font-size="{_LABEL_FONT_PX}">'
            f"{_escape(_bar_value_label(item.value, spec.unit))}</text>"
        )
        parts.append(
            f'<text class="chart-label" x="{_fmt(x + bar_w / 2)}" y="{_fmt(baseline_y + 16.0)}" '
            f'text-anchor="middle" font-size="{_LABEL_FONT_PX}">{_escape(item.label)}</text>'
        )
        if item.note:
            parts.append(
                f'<text class="chart-label" x="{_fmt(x + bar_w / 2)}" y="{_fmt(baseline_y + 30.0)}" '
                f'text-anchor="middle" font-size="10" opacity="0.7">{_escape(item.note)}</text>'
            )

    return _wrap_svg(spec.width, spec.height, "ah-bar", spec.title, "".join(parts), spec.caption)


# ---------------------------------------------------------------------------
# Radar / spider chart
# ---------------------------------------------------------------------------


def check_radar_collisions(spec: RadarSpec) -> list[Finding]:
    findings: list[Finding] = []
    if len(spec.axes) < _RADAR_MIN_AXES:
        findings.append(
            Finding(
                gate="chart.rule",
                message=f"radar needs at least {_RADAR_MIN_AXES} labeled axes (has {len(spec.axes)})",
                severity=Severity.CRIT,
            )
        )
    for s in spec.series:
        if len(s.values) != len(spec.axes):
            findings.append(
                Finding(
                    gate="chart.rule",
                    message=f"series '{s.label}' has {len(s.values)} values for {len(spec.axes)} axes",
                    severity=Severity.CRIT,
                )
            )
    if spec.max_value <= 0:
        findings.append(
            Finding(
                gate="chart.rule", message="radar max_value must be > 0", severity=Severity.CRIT
            )
        )
    if findings:
        return findings

    cx, cy = spec.width / 2, spec.height / 2 + 8.0
    radius = min(spec.width, spec.height) / 2 - 64.0
    n = len(spec.axes)
    boxes: list[BBox] = []
    for i, label in enumerate(spec.axes):
        angle = -math.pi / 2 + i * (2 * math.pi / n)
        lx = _r(cx + math.cos(angle) * (radius + 22.0))
        ly = _r(cy + math.sin(angle) * (radius + 22.0))
        boxes.append(_text_box(lx, ly, label, _LABEL_FONT_PX))
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            if _intersects(boxes[i], boxes[j]) or _gap(boxes[i], boxes[j]) < _MIN_GAP_PX:
                findings.append(
                    Finding(
                        gate="chart.collision",
                        message=f"Axis labels '{spec.axes[i]}' and '{spec.axes[j]}' collide (too many axes for this size)",
                        severity=Severity.CRIT,
                    )
                )
    return findings


def render_radar(spec: RadarSpec) -> str:
    """Render ``spec`` to a self-contained ``<svg>``. Raises ``ChartRuleError`` on any
    blocking finding (too few axes, a series/axis-count mismatch, or label collisions).
    """
    collisions = check_radar_collisions(spec)
    if collisions:
        raise ChartRuleError(f"{spec.id}: " + "; ".join(f.message for f in collisions))

    cx, cy = spec.width / 2, spec.height / 2 + 8.0
    radius = min(spec.width, spec.height) / 2 - 64.0
    n = len(spec.axes)
    angles = [-math.pi / 2 + i * (2 * math.pi / n) for i in range(n)]

    parts: list[str] = []
    for ring_frac in (1 / 3, 2 / 3, 1.0):
        pts = " ".join(
            f"{_fmt(cx + math.cos(a) * radius * ring_frac)},{_fmt(cy + math.sin(a) * radius * ring_frac)}"
            for a in angles
        )
        parts.append(f'<polygon class="axis-grid" points="{pts}"/>')
    for i, label in enumerate(spec.axes):
        a = angles[i]
        parts.append(
            f'<line class="axis" x1="{_fmt(cx)}" y1="{_fmt(cy)}" '
            f'x2="{_fmt(cx + math.cos(a) * radius)}" y2="{_fmt(cy + math.sin(a) * radius)}"/>'
        )
        lx = _r(cx + math.cos(a) * (radius + 22.0))
        ly = _r(cy + math.sin(a) * (radius + 22.0))
        parts.append(
            f'<text class="chart-label" x="{_fmt(lx)}" y="{_fmt(ly)}" '
            f'text-anchor="middle" font-size="{_LABEL_FONT_PX}">{_escape(label)}</text>'
        )

    for s_idx, s in enumerate(spec.series):
        color = _color_for(s_idx)
        poly_pts: list[str] = []
        for i, value in enumerate(s.values):
            frac = max(0.0, min(1.0, value / spec.max_value))
            a = angles[i]
            poly_pts.append(
                f"{_fmt(cx + math.cos(a) * radius * frac)},{_fmt(cy + math.sin(a) * radius * frac)}"
            )
        parts.append(
            f'<polygon points="{" ".join(poly_pts)}" fill="{color}" fill-opacity="0.18" '
            f'stroke="{color}" stroke-width="1.5"/>'
        )

    if spec.legend:
        entries = [(entry.label, entry.key) for entry in spec.legend]
    else:
        entries = [(s.label, _color_for(i)) for i, s in enumerate(spec.series)]
    footer, footer_h = _swatch_legend_rows(spec.width, entries)

    return _wrap_svg(
        spec.width,
        spec.height,
        "ah-radar",
        spec.title,
        "".join(parts),
        spec.caption,
        footer=footer,
        footer_h=footer_h,
    )


# ---------------------------------------------------------------------------
# Pie / donut
# ---------------------------------------------------------------------------


def check_pie_collisions(spec: PieSpec) -> list[Finding]:
    findings: list[Finding] = []
    if not spec.slices:
        findings.append(
            Finding(gate="chart.rule", message="pie chart has no slices", severity=Severity.CRIT)
        )
        return findings
    if len(spec.slices) > _PIE_MAX_SLICES:
        findings.append(
            Finding(
                gate="chart.rule",
                message=f"pie has {len(spec.slices)} slices, exceeds the {_PIE_MAX_SLICES}-slice VISUAL_LIBRARY cap",
                severity=Severity.CRIT,
            )
        )
    if any(s.value < 0 for s in spec.slices):
        findings.append(
            Finding(
                gate="chart.rule", message="pie slice values must be >= 0", severity=Severity.CRIT
            )
        )
    total = sum(s.value for s in spec.slices)
    if total <= 0:
        findings.append(
            Finding(
                gate="chart.rule", message="pie total value must be > 0", severity=Severity.CRIT
            )
        )
    return findings


def _arc_point(cx: float, cy: float, r: float, angle: float) -> tuple[float, float]:
    return (cx + math.cos(angle) * r, cy + math.sin(angle) * r)


def render_pie(spec: PieSpec) -> str:
    """Render ``spec`` to a self-contained ``<svg>``. Raises ``ChartRuleError`` on any
    blocking finding (empty/oversized slice count, or a non-positive total).
    """
    collisions = check_pie_collisions(spec)
    if collisions:
        raise ChartRuleError(f"{spec.id}: " + "; ".join(f.message for f in collisions))

    cx, cy = spec.width / 2, spec.height / 2 + 4.0
    r_outer = min(spec.width, spec.height) / 2 - 56.0
    r_inner = r_outer * 0.55 if spec.donut else 0.0
    total = sum(s.value for s in spec.slices)

    parts: list[str] = []
    angle = -math.pi / 2
    for i, slc in enumerate(spec.slices):
        sweep = (slc.value / total) * 2 * math.pi
        end_angle = angle + sweep
        large_arc = 1 if sweep > math.pi else 0
        color = _color_for(i)
        o0 = _arc_point(cx, cy, r_outer, angle)
        o1 = _arc_point(cx, cy, r_outer, end_angle)
        if r_inner > 0:
            i0 = _arc_point(cx, cy, r_inner, end_angle)
            i1 = _arc_point(cx, cy, r_inner, angle)
            d = (
                f"M {_fmt(o0[0])} {_fmt(o0[1])} "
                f"A {_fmt(r_outer)} {_fmt(r_outer)} 0 {large_arc} 1 {_fmt(o1[0])} {_fmt(o1[1])} "
                f"L {_fmt(i0[0])} {_fmt(i0[1])} "
                f"A {_fmt(r_inner)} {_fmt(r_inner)} 0 {large_arc} 0 {_fmt(i1[0])} {_fmt(i1[1])} Z"
            )
        else:
            d = (
                f"M {_fmt(cx)} {_fmt(cy)} L {_fmt(o0[0])} {_fmt(o0[1])} "
                f"A {_fmt(r_outer)} {_fmt(r_outer)} 0 {large_arc} 1 {_fmt(o1[0])} {_fmt(o1[1])} Z"
            )
        parts.append(f'<path d="{d}" fill="{color}"/>')
        angle = end_angle

    entries = [
        (f"{s.label} ({s.value / total * 100:.0f}%)", _color_for(i))
        for i, s in enumerate(spec.slices)
    ]
    footer, footer_h = _swatch_legend_rows(spec.width, entries)

    return _wrap_svg(
        spec.width,
        spec.height,
        "ah-pie",
        spec.title,
        "".join(parts),
        spec.caption,
        footer=footer,
        footer_h=footer_h,
    )


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

_TIMELINE_MIN_EVENT_GAP_PX = 60.0


def check_timeline_collisions(spec: TimelineSpec) -> list[Finding]:
    findings: list[Finding] = []
    if not spec.events:
        findings.append(
            Finding(gate="chart.rule", message="timeline has no events", severity=Severity.CRIT)
        )
        return findings
    for e in spec.events:
        if not (0.0 <= e.t <= 1.0):
            findings.append(
                Finding(
                    gate="chart.rule",
                    message=f"event '{e.label}' has t={e.t} outside [0,1]",
                    severity=Severity.CRIT,
                )
            )
    plot_w = spec.width - _MARGIN_LEFT - _MARGIN_RIGHT
    ordered = sorted(spec.events, key=lambda e: e.t)
    for a, b in zip(ordered, ordered[1:], strict=False):
        gap = (b.t - a.t) * plot_w
        if gap < _TIMELINE_MIN_EVENT_GAP_PX:
            findings.append(
                Finding(
                    gate="chart.collision",
                    message=f"Events '{a.label}' and '{b.label}' are {gap:.1f}px apart, below the {_TIMELINE_MIN_EVENT_GAP_PX}px minimum",
                    severity=Severity.CRIT,
                )
            )
    return findings


def render_timeline(spec: TimelineSpec) -> str:
    """Render ``spec`` to a self-contained ``<svg>``. Raises ``ChartRuleError`` on any
    blocking finding (an out-of-range position, or events packed too closely to read).
    """
    collisions = check_timeline_collisions(spec)
    if collisions:
        raise ChartRuleError(f"{spec.id}: " + "; ".join(f.message for f in collisions))

    plot_w = spec.width - _MARGIN_LEFT - _MARGIN_RIGHT
    axis_y = spec.height / 2
    parts: list[str] = [
        f'<line class="axis" x1="{_fmt(_MARGIN_LEFT)}" y1="{_fmt(axis_y)}" '
        f'x2="{_fmt(spec.width - _MARGIN_RIGHT)}" y2="{_fmt(axis_y)}"/>'
    ]
    ordered = sorted(spec.events, key=lambda e: e.t)
    for idx, e in enumerate(ordered):
        x = _r(_MARGIN_LEFT + e.t * plot_w)
        above = idx % 2 == 0
        label_y = axis_y - 28.0 if above else axis_y + 40.0
        date_y = axis_y - 12.0 if above else axis_y + 24.0
        # Clamp text centers so edge-event labels stay inside the viewBox instead
        # of clipping off the left/right edge (marker stays at the true position).
        half_l = len(e.label) * _LABEL_FONT_PX * _CHAR_ADVANCE_FACTOR / 2
        label_x = _r(min(max(x, half_l + 4.0), spec.width - half_l - 4.0))
        half_d = len(e.date_label) * 10.0 * _CHAR_ADVANCE_FACTOR / 2
        date_x = _r(min(max(x, half_d + 4.0), spec.width - half_d - 4.0))
        parts.append(
            f'<line class="axis" x1="{_fmt(x)}" y1="{_fmt(axis_y - 6.0)}" x2="{_fmt(x)}" y2="{_fmt(axis_y + 6.0)}"/>'
        )
        parts.append(f'<circle cx="{_fmt(x)}" cy="{_fmt(axis_y)}" r="4" fill="{_color_for(0)}"/>')
        parts.append(
            f'<text class="chart-label" x="{_fmt(label_x)}" y="{_fmt(label_y)}" text-anchor="middle" '
            f'font-size="{_LABEL_FONT_PX}">{_escape(e.label)}</text>'
        )
        parts.append(
            f'<text class="chart-value" x="{_fmt(date_x)}" y="{_fmt(date_y)}" text-anchor="middle" '
            f'font-size="10">{_escape(e.date_label)}</text>'
        )

    return _wrap_svg(
        spec.width, spec.height, "ah-timeline", spec.title, "".join(parts), spec.caption
    )


# ---------------------------------------------------------------------------
# Heatmap
# ---------------------------------------------------------------------------


def _lerp_color(t: float) -> str:
    t = max(0.0, min(1.0, t))
    if t <= 0.5:
        lo, hi, local_t = _HEAT_LOW, _HEAT_MID, t / 0.5
    else:
        lo, hi, local_t = _HEAT_MID, _HEAT_HIGH, (t - 0.5) / 0.5
    rgb = tuple(round(lo[i] + (hi[i] - lo[i]) * local_t) for i in range(3))
    return f"rgb({rgb[0]},{rgb[1]},{rgb[2]})"


def _heatmap_left_margin(spec: HeatmapSpec) -> float:
    """Left margin wide enough for the longest row label — a fixed 56px margin
    clipped long labels clean off the viewBox edge."""
    widest = max((len(label) for label in spec.row_labels), default=0)
    return max(_MARGIN_LEFT, widest * _LABEL_FONT_PX * _CHAR_ADVANCE_FACTOR + 16.0)


def check_heatmap_collisions(spec: HeatmapSpec) -> list[Finding]:
    findings: list[Finding] = []
    n_rows, n_cols = len(spec.row_labels), len(spec.col_labels)
    if n_rows == 0 or n_cols == 0:
        findings.append(
            Finding(
                gate="chart.rule",
                message="heatmap needs at least one row and one column",
                severity=Severity.CRIT,
            )
        )
        return findings
    if len(spec.matrix) != n_rows or any(len(row) != n_cols for row in spec.matrix):
        findings.append(
            Finding(
                gate="chart.rule",
                message=f"matrix shape must be {n_rows}x{n_cols} to match row/col labels",
                severity=Severity.CRIT,
            )
        )
        return findings
    if spec.min_value > spec.max_value:
        findings.append(
            Finding(
                gate="chart.rule", message="min_value must be <= max_value", severity=Severity.CRIT
            )
        )

    plot_w = spec.width - _heatmap_left_margin(spec) - _MARGIN_RIGHT
    plot_h = spec.height - _MARGIN_TOP - _MARGIN_BOTTOM
    cell_w, cell_h = plot_w / n_cols, plot_h / n_rows
    # A cell must be big enough to hold its (conservatively over-estimated) value label.
    max_label_len = max((len(f"{v:g}") for row in spec.matrix for v in row), default=1)
    min_cell_w_needed = max_label_len * _LABEL_FONT_PX * 0.62 + 6.0
    if cell_w < min_cell_w_needed or cell_h < _LABEL_FONT_PX * 1.35 + 6.0:
        findings.append(
            Finding(
                gate="chart.collision",
                message=(
                    f"cell size {cell_w:.1f}x{cell_h:.1f}px is too small for its value labels "
                    f"({n_rows}x{n_cols} grid in {spec.width}x{spec.height})"
                ),
                severity=Severity.CRIT,
            )
        )
    return findings


def render_heatmap(spec: HeatmapSpec) -> str:
    """Render ``spec`` to a self-contained ``<svg>`` with a scale legend (VISUAL_LIBRARY:
    "never a heatmap without a scale legend"). Raises ``ChartRuleError`` on any blocking
    finding (a shape mismatch, an inverted range, or cells too small for their labels).
    """
    collisions = check_heatmap_collisions(spec)
    if collisions:
        raise ChartRuleError(f"{spec.id}: " + "; ".join(f.message for f in collisions))

    n_rows, n_cols = len(spec.row_labels), len(spec.col_labels)
    left = _heatmap_left_margin(spec)
    plot_w = spec.width - left - _MARGIN_RIGHT
    plot_h = spec.height - _MARGIN_TOP - _MARGIN_BOTTOM
    cell_w, cell_h = plot_w / n_cols, plot_h / n_rows
    value_range = spec.max_value - spec.min_value or 1.0

    # Column labels shrink to fit their cell (floor 8px) instead of overlapping
    # their neighbours when many columns share a narrow plot.
    widest_col = max((len(label) for label in spec.col_labels), default=1)
    col_font = min(
        _LABEL_FONT_PX, max(8.0, _r((cell_w - 6.0) / (widest_col * _CHAR_ADVANCE_FACTOR)))
    )

    parts: list[str] = []
    for r, row_label in enumerate(spec.row_labels):
        ly = _r(_MARGIN_TOP + cell_h * (r + 0.5) + 4.0)
        parts.append(
            f'<text class="chart-label" x="{_fmt(left - 8.0)}" y="{_fmt(ly)}" '
            f'text-anchor="end" font-size="{_LABEL_FONT_PX}">{_escape(row_label)}</text>'
        )
    for c, col_label in enumerate(spec.col_labels):
        lx = _r(left + cell_w * (c + 0.5))
        parts.append(
            f'<text class="chart-label" x="{_fmt(lx)}" y="{_fmt(_MARGIN_TOP - 8.0)}" '
            f'text-anchor="middle" font-size="{_fmt(col_font)}">{_escape(col_label)}</text>'
        )
    for r in range(n_rows):
        for c in range(n_cols):
            value = spec.matrix[r][c]
            t = (value - spec.min_value) / value_range
            x = _r(left + cell_w * c)
            y = _r(_MARGIN_TOP + cell_h * r)
            parts.append(
                f'<rect x="{_fmt(x)}" y="{_fmt(y)}" width="{_fmt(cell_w)}" height="{_fmt(cell_h)}" '
                f'fill="{_lerp_color(t)}" stroke="var(--paper,#060608)" stroke-width="1"/>'
                f'<text class="chart-value" x="{_fmt(x + cell_w / 2)}" y="{_fmt(y + cell_h / 2 + 4.0)}" '
                f'text-anchor="middle" font-size="{_LABEL_FONT_PX}" fill="white">{_escape(f"{value:g}")}</text>'
            )

    scale_y = spec.height - 28.0
    scale_x0, scale_x1 = left, spec.width - _MARGIN_RIGHT
    stops = "".join(
        f'<stop offset="{frac}" stop-color="{_lerp_color(frac)}"/>' for frac in (0.0, 0.5, 1.0)
    )
    parts.append(
        f'<defs><linearGradient id="heat-scale-{spec.id}" x1="0" y1="0" x2="1" y2="0">{stops}</linearGradient></defs>'
        f'<rect x="{_fmt(scale_x0)}" y="{_fmt(scale_y)}" width="{_fmt(scale_x1 - scale_x0)}" height="10" '
        f'fill="url(#heat-scale-{spec.id})"/>'
        f'<text class="chart-value" x="{_fmt(scale_x0)}" y="{_fmt(scale_y - 4.0)}" font-size="10">{_escape(f"{spec.min_value:g}")}</text>'
        f'<text class="chart-value" x="{_fmt(scale_x1)}" y="{_fmt(scale_y - 4.0)}" text-anchor="end" font-size="10">{_escape(f"{spec.max_value:g}")}</text>'
    )

    return _wrap_svg(
        spec.width, spec.height, "ah-heatmap", spec.title, "".join(parts), spec.caption
    )


# ---------------------------------------------------------------------------
# Shared legend helper (row-wrapping layout — entries that would overflow the
# right edge wrap onto a new row, so a legend can never clip or collide with
# the caption; callers place the returned block below the plot via _wrap_svg)
# ---------------------------------------------------------------------------

_CHAR_ADVANCE_FACTOR = 0.62
_LEGEND_FONT_PX = 11.0
_LEGEND_ROW_H = 20.0


def _swatch_legend_rows(width: float, entries: list[tuple[str, str]]) -> tuple[str, float]:
    """Render swatch legend entries, wrapping into rows within ``width``.

    Returns (svg fragment positioned at y=0, total block height) for use as a
    ``_wrap_svg`` footer.
    """
    if not entries:
        return ("", 0.0)
    parts = ['<g class="legend">']
    x, row = 12.0, 0
    for label, color in entries:
        entry_w = 20.0 + len(label) * _LEGEND_FONT_PX * _CHAR_ADVANCE_FACTOR + 24.0
        if x + entry_w > width - 12.0 and x > 12.0:
            row += 1
            x = 12.0
        y = row * _LEGEND_ROW_H
        parts.append(
            f'<rect x="{_fmt(x)}" y="{_fmt(y)}" width="14" height="14" rx="3" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{_fmt(x + 20)}" y="{_fmt(y + 11.0)}" class="legend-label" '
            f'font-size="{_LEGEND_FONT_PX}">{_escape(label)}</text>'
        )
        x += entry_w
    parts.append("</g>")
    return ("".join(parts), (row + 1) * _LEGEND_ROW_H + 4.0)
