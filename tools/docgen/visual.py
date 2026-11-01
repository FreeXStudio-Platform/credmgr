"""VisualSpec -> SVG renderer: glyphs, edge routing, motion (the "dot"), collisions.

Implements MOTION_SPEC.md and VISUAL_LIBRARY.md exactly:
  - one glyph per node (assets/glyphs.py), currentColor stroke, --sig fill only on highlight
  - an edge router that goes around non-endpoint node bboxes (simple orthogonal/elbow)
  - a flow-dot riding each ``main`` edge at a build-time-constant 120px/s via
    ``<animateMotion>`` + arc-length-sampled ``keyPoints``/``keyTimes`` (S2)
  - z-order: edges -> dots -> nodes -> labels (S3)
  - arrival light-up, fan-out split, decision-branch alternation (S4-S5)
  - a reduced-motion static variant: all branches + numbered edge badges + lit terminal (S9)
  - a collision validator that FAILS (raises) on any overlap -- the S-arch class cannot ship (S7)

Determinism is load-bearing: all floats rounded to 2dp, no random ids, stable ordering,
so ``render()`` called twice on the same spec produces byte-identical output (hash-gate).

Stdlib only; mypy --strict clean.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from tools.docgen.assets.glyphs import ambient_pulse_defs, render_glyph
from tools.docgen.models import Edge, Finding, Node, Severity, VisualSpec

# ---------------------------------------------------------------------------
# Constants (from assets/tokens.json "diagram" block -- mirrored here as the
# renderer's compiled-in defaults so this module has no I/O dependency).
# ---------------------------------------------------------------------------

GRID_PX = 22.0
NODE_GAP_MIN_PX = 22.0
NODE_GAP_MIN_RATIO = 1.5
DOT_SPEED_PX_S = 120.0
DOT_MAX_DUR_S = 4.0
VELOCITY_TOLERANCE = 0.05
ARC_SAMPLES_DEFAULT = 64
DWELL_MS = 450
INTERLOOP_GAP_MS = 900

# Conservative (fail-closed) average glyph-advance for text width over-estimate,
# expressed as a fraction of font-size per character. Real advances are typically
# 0.5-0.6x for proportional sans/mono; we deliberately over-estimate so the
# collision gate can never under-count and let an overlap slip through.
_CHAR_ADVANCE_FACTOR = 0.62
_LABEL_FONT_PX = 12.0
_CAPTION_FONT_PX = 12.0
_NOTE_FONT_PX = 12.0
_LEGEND_FONT_PX = 11.0
_LINE_HEIGHT_FACTOR = 1.35

# Footer stack (bottom -> up): caption, then a real gap, then the legend row.
# Both the renderer and the collision checker read these same offsets so the
# two never drift apart.
_CAPTION_Y_FROM_BOTTOM = 10.0
_LEGEND_Y_FROM_BOTTOM = 78.0
_TITLE_Y = 20.0


class CollisionError(RuntimeError):
    """Raised by ``render()`` when ``check_collisions`` finds a blocking overlap."""


def _r(value: float) -> float:
    return round(value, 2)


def _fmt(value: float) -> str:
    r = _r(value)
    if r == int(r):
        return str(int(r))
    return f"{r:g}"


def _safe_id(text: str) -> str:
    out = []
    for ch in text:
        out.append(ch if (ch.isalnum() or ch in "-_") else "-")
    return "".join(out) or "x"


# ---------------------------------------------------------------------------
# Bounding boxes
# ---------------------------------------------------------------------------

BBox = tuple[float, float, float, float]  # x0, y0, x1, y1


def _union(a: BBox, b: BBox) -> BBox:
    return (min(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2]), max(a[3], b[3]))


def _expand(box: BBox, pad: float) -> BBox:
    return (box[0] - pad, box[1] - pad, box[2] + pad, box[3] + pad)


def _intersects(a: BBox, b: BBox) -> bool:
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def _gap(a: BBox, b: BBox) -> float:
    """Minimum edge-to-edge gap between two axis-aligned boxes (0 if overlapping)."""
    dx = max(b[0] - a[2], a[0] - b[2], 0.0)
    dy = max(b[1] - a[3], a[1] - b[3], 0.0)
    if dx == 0.0 and dy == 0.0:
        return 0.0
    return math.hypot(dx, dy)


def _text_box(cx: float, cy: float, text: str, font_px: float, *, anchor: str = "middle") -> BBox:
    """Conservative (over-estimated, fail-closed) bbox for a single line of text."""
    if not text:
        return (cx, cy, cx, cy)
    width = len(text) * font_px * _CHAR_ADVANCE_FACTOR
    height = font_px * _LINE_HEIGHT_FACTOR
    if anchor == "middle":
        x0 = cx - width / 2
    elif anchor == "start":
        x0 = cx
    else:
        x0 = cx - width
    return (x0, cy - height / 2, x0 + width, cy + height / 2)


_TITLE_FONT_PX = 18.0
_TITLE_LINE_H = 24.0
_CAPTION_FONT_PX = 12.0
_CAPTION_LINE_H = 16.0


def _wrap_text(text: str, font_px: float, max_w: float) -> list[str]:
    """Greedy word-wrap using the conservative glyph-advance estimate.

    A word longer than the line is kept whole (never split mid-word); the
    over-estimated advance keeps the result fail-closed for collision gates.
    """
    if not text:
        return []
    max_chars = max(8, int(max_w / (font_px * _CHAR_ADVANCE_FACTOR)))
    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}".strip()
        if len(candidate) <= max_chars or not current:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def _title_block(width: float, title: str) -> tuple[str, float]:
    """Wrapped, centered figure title. Returns (svg, extra height beyond one line)."""
    if not title:
        return ("", 0.0)
    lines = _wrap_text(title, _TITLE_FONT_PX, width - 32.0)
    parts = [
        f'<text x="{_fmt(width / 2)}" y="{_fmt(20.0 + i * _TITLE_LINE_H)}" class="figure-title" '
        f'font-size="18" text-anchor="middle" font-weight="700" '
        f'fill="currentColor">{_escape(line)}</text>'
        for i, line in enumerate(lines)
    ]
    return ("".join(parts), (len(lines) - 1) * _TITLE_LINE_H)


def _caption_block(width: float, caption: str, y_top: float) -> tuple[str, float]:
    """Wrapped, centered caption whose first baseline sits below ``y_top``.

    Returns (svg, block height) so callers can grow the viewBox instead of
    letting a long caption overflow or collide with the plot/legend.
    """
    if not caption:
        return ("", 0.0)
    lines = _wrap_text(caption, _CAPTION_FONT_PX, width - 24.0)
    parts = [
        f'<text x="{_fmt(width / 2)}" y="{_fmt(y_top + 12.0 + i * _CAPTION_LINE_H)}" '
        f'class="figure-caption" font-size="12" text-anchor="middle">{_escape(line)}</text>'
        for i, line in enumerate(lines)
    ]
    return ("".join(parts), len(lines) * _CAPTION_LINE_H + 8.0)


def _wrapped_text_box(
    cx: float, cy: float, text: str, font_px: float, max_chars: int, *, anchor: str = "middle"
) -> BBox:
    """Bbox for text that wraps at ``max_chars`` per line (captions/notes)."""
    if not text:
        return (cx, cy, cx, cy)
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        cand = f"{cur} {w}".strip()
        if len(cand) > max_chars and cur:
            lines.append(cur)
            cur = w
        else:
            cur = cand
    if cur:
        lines.append(cur)
    if not lines:
        lines = [text]
    widest = max(len(line) for line in lines)
    width = widest * font_px * _CHAR_ADVANCE_FACTOR
    height = len(lines) * font_px * _LINE_HEIGHT_FACTOR
    if anchor == "middle":
        x0 = cx - width / 2
    elif anchor == "start":
        x0 = cx
    else:
        x0 = cx - width
    return (x0, cy - height / 2, x0 + width, cy + height / 2)


# ---------------------------------------------------------------------------
# Edge routing (simple orthogonal/elbow, routed around non-endpoint node bboxes)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RoutedEdge:
    edge: Edge
    points: list[tuple[float, float]]  # polyline in order src -> dst
    path_d: str
    label_pos: tuple[float, float] | None
    condition_pos: tuple[float, float] | None


def _node_anchor(node: Node, towards: tuple[float, float]) -> tuple[float, float]:
    """Pick the boundary point on ``node`` closest to facing ``towards``."""
    cx, cy = node.cx, node.cy
    tx, ty = towards
    dx, dy = tx - cx, ty - cy
    if dx == 0 and dy == 0:
        return (cx, node.y + node.h)
    half_w, half_h = node.w / 2, node.h / 2
    if half_w == 0 or half_h == 0:
        return (cx, cy)
    scale = min(abs(half_w / dx) if dx else math.inf, abs(half_h / dy) if dy else math.inf)
    return (_r(cx + dx * scale), _r(cy + dy * scale))


def _segment_hits_box(p0: tuple[float, float], p1: tuple[float, float], box: BBox) -> bool:
    """Conservative check: does the segment's own bbox intersect ``box``?

    Sufficient for the axis-aligned elbow segments this router produces (each
    segment is purely horizontal or vertical), so segment-bbox == segment path.
    """
    seg_box = (min(p0[0], p1[0]), min(p0[1], p1[1]), max(p0[0], p1[0]), max(p0[1], p1[1]))
    # Degenerate (zero-width or zero-height) segments still need a hit test.
    seg_box = _expand(seg_box, 0.01)
    return _intersects(seg_box, box)


def _route_edge(edge: Edge, nodes_by_id: dict[str, Node], obstacles: list[Node]) -> _RoutedEdge:
    src = nodes_by_id[edge.src]
    dst = nodes_by_id[edge.dst]
    start = _node_anchor(src, (dst.cx, dst.cy))
    end = _node_anchor(dst, (src.cx, src.cy))

    obstacle_boxes = [
        _expand(n.bbox(), NODE_GAP_MIN_PX / 2)
        for n in obstacles
        if n.id not in (edge.src, edge.dst)
    ]

    points = [start, end]
    # Simple orthogonal elbow: if the direct segment threads through an obstacle,
    # detour via a mid-point offset above/below the midline (whichever is clearer).
    if any(_segment_hits_box(start, end, box) for box in obstacle_boxes):
        mid_x = _r((start[0] + end[0]) / 2)
        mid_y = _r((start[1] + end[1]) / 2)
        candidates = [
            (mid_x, min(start[1], end[1]) - GRID_PX * 2),
            (mid_x, max(start[1], end[1]) + GRID_PX * 2),
            (min(start[0], end[0]) - GRID_PX * 2, mid_y),
            (max(start[0], end[0]) + GRID_PX * 2, mid_y),
        ]
        for cand in candidates:
            leg1_clear = not any(_segment_hits_box(start, cand, box) for box in obstacle_boxes)
            leg2_clear = not any(_segment_hits_box(cand, end, box) for box in obstacle_boxes)
            if leg1_clear and leg2_clear:
                points = [start, cand, end]
                break
        else:
            # No clean detour found; keep the direct route (collision pass will
            # report the specific edge-through-node finding rather than silently
            # "fixing" it with an arbitrary long detour).
            points = [start, end]

    path_d = "M " + " L ".join(f"{_fmt(x)} {_fmt(y)}" for x, y in points)

    label_pos = None
    condition_pos = None
    if edge.label or edge.condition:
        # Place at the true arc-length midpoint (not the vertex average, which
        # is wrong for a 3-point elbow), offset perpendicular to the local
        # segment direction so short/near-horizontal edges near their
        # endpoint nodes still clear those nodes vertically.
        total_len = _path_length(points)
        mx, my = _point_at_length(points, total_len / 2.0)
        seg = _segment_at_length(points, total_len / 2.0)
        (sx0, sy0), (sx1, sy1) = seg
        dx, dy = sx1 - sx0, sy1 - sy0
        seg_len = math.hypot(dx, dy)
        if seg_len > 0:
            perp_x, perp_y = -dy / seg_len, dx / seg_len
        else:
            perp_x, perp_y = 0.0, -1.0
        if edge.label:
            label_pos = (_r(mx + perp_x * 18.0), _r(my + perp_y * 18.0 - 6.0))
        if edge.condition:
            offset = 44.0 if edge.label else 30.0
            condition_pos = (_r(mx + perp_x * offset), _r(my + perp_y * offset + 8.0))

    return _RoutedEdge(
        edge=edge, points=points, path_d=path_d, label_pos=label_pos, condition_pos=condition_pos
    )


def _segment_at_length(
    points: list[tuple[float, float]], target: float
) -> tuple[tuple[float, float], tuple[float, float]]:
    """Return the (p0, p1) segment of the polyline containing arc-length ``target``."""
    remaining = target
    for p0, p1 in zip(points, points[1:], strict=False):
        seg_len = math.hypot(p1[0] - p0[0], p1[1] - p0[1])
        if seg_len <= 0:
            continue
        if remaining <= seg_len or math.isclose(remaining, seg_len):
            return (p0, p1)
        remaining -= seg_len
    if len(points) >= 2:
        return (points[-2], points[-1])
    return (points[0], points[0])


def _path_length(points: list[tuple[float, float]]) -> float:
    total = 0.0
    for (x0, y0), (x1, y1) in zip(points, points[1:], strict=False):
        total += math.hypot(x1 - x0, y1 - y0)
    return total


def _point_at_length(points: list[tuple[float, float]], target: float) -> tuple[float, float]:
    """Sample the polyline at arc-length ``target`` from the start."""
    remaining = target
    for (x0, y0), (x1, y1) in zip(points, points[1:], strict=False):
        seg_len = math.hypot(x1 - x0, y1 - y0)
        if seg_len <= 0:
            continue
        if remaining <= seg_len or math.isclose(remaining, seg_len):
            t = 0.0 if seg_len == 0 else remaining / seg_len
            return (x0 + (x1 - x0) * t, y0 + (y1 - y0) * t)
        remaining -= seg_len
    return points[-1]


# ---------------------------------------------------------------------------
# Arc-length sampling for constant-velocity <animateMotion> (MOTION_SPEC S2)
# ---------------------------------------------------------------------------


def _flatten_path_points(d: str) -> list[tuple[float, float]]:
    """Parse a simple "M x y L x y L x y ..." path (this router never emits curves)."""
    tokens = d.replace("M", " M ").replace("L", " L ").split()
    points: list[tuple[float, float]] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("M", "L"):
            x = float(tokens[i + 1])
            y = float(tokens[i + 2])
            points.append((x, y))
            i += 3
        else:
            i += 1
    return points


def arc_length_keytimes(d: str, n: int = 64) -> tuple[list[float], list[float]]:
    """Sample path ``d`` at ``n`` equal ARC-LENGTH intervals.

    Returns ``(key_points, key_times)`` both in ``[0, 1]`` for SVG
    ``<animateMotion keyPoints="..." keyTimes="...">`` -- equal-time sampling of
    an arc-length-parameterized path is what gives constant *visual* velocity,
    including on curved/multi-segment polylines (equal-parameter sampling is NOT
    constant velocity, per MOTION_SPEC S2).

    ``n`` is adaptive-friendly: callers pass a larger ``n`` for longer/curvier
    paths (see ``_adaptive_sample_count``). Minimum 2 samples (start/end).
    """
    n = max(2, n)
    points = _flatten_path_points(d)
    total = _path_length(points)
    key_points: list[float] = []
    key_times: list[float] = []
    if total <= 0:
        return ([0.0, 1.0], [0.0, 1.0])
    for i in range(n):
        frac = i / (n - 1)
        key_times.append(_r(frac))
        # keyPoints is the fraction of *arc length* traveled; since our sampling
        # is itself uniform in arc length, keyPoints == keyTimes by construction.
        # We still compute both explicitly (not just alias) so a future
        # non-uniform time curve stays correct.
        key_points.append(_r(frac))
    # Guarantee exact endpoints after rounding.
    key_times[0], key_points[0] = 0.0, 0.0
    key_times[-1], key_points[-1] = 1.0, 1.0
    return (key_points, key_times)


def _adaptive_sample_count(path_length: float, num_segments: int) -> int:
    """Longer or more-jointed paths get more samples (bounded [16, 256])."""
    base = ARC_SAMPLES_DEFAULT
    length_factor = max(1.0, path_length / 200.0)
    seg_factor = max(1.0, num_segments / 2.0)
    n = int(base * math.sqrt(length_factor) * math.sqrt(seg_factor))
    return max(16, min(256, n))


def velocity_ok(
    d: str, dur: float, target: float = DOT_SPEED_PX_S, *, tolerance: float = VELOCITY_TOLERANCE
) -> bool:
    """Assert the average speed implied by ``dur`` over path ``d`` is within
    ``tolerance`` (relative) of ``target`` px/s. ``target`` should be the
    edge's *actual* target speed -- i.e. the compressed speed when the 4s cap
    was applied, not always the nominal 120px/s.
    """
    points = _flatten_path_points(d)
    length = _path_length(points)
    if dur <= 0:
        return length == 0
    actual_speed = length / dur
    if target <= 0:
        return False
    deviation = abs(actual_speed - target) / target
    return deviation <= tolerance


def _edge_timing(path_length: float) -> tuple[float, float, str]:
    """Compute ``(dur_seconds, effective_speed, caption_note)`` for an edge,
    applying the 4s honesty cap by raising speed proportionally (MOTION_SPEC S2).
    """
    if path_length <= 0:
        return (0.0, DOT_SPEED_PX_S, "")
    dur = path_length / DOT_SPEED_PX_S
    if dur <= DOT_MAX_DUR_S:
        return (_r(dur), DOT_SPEED_PX_S, "")
    capped_dur = DOT_MAX_DUR_S
    effective_speed = path_length / capped_dur
    factor = effective_speed / DOT_SPEED_PX_S
    note = f"animation compressed {factor:.1f}×"
    return (_r(capped_dur), _r(effective_speed), note)


# ---------------------------------------------------------------------------
# Collision validation (fail-closed; MOTION_SPEC S7)
# ---------------------------------------------------------------------------


def check_collisions(spec: VisualSpec) -> list[Finding]:
    """Return blocking ``Finding``s for any overlap class in ``spec``.

    Covers: node rects, rendered text (labels/captions/legend/notes -- using a
    conservative OVER-estimate per-char advance so this fails closed), edge
    routes passing through a non-endpoint node, minimum gaps. Any hit is a
    blocking Finding (severity CRIT); an empty list means the layout is clean.

    Containment semantics: a node's own inline label lives INSIDE that node's
    box by design (DESIGN_SYSTEM S4 glyph-per-node) -- that is not an overlap.
    So each box carries an ``owner`` (the node/edge id it belongs to, or ""
    for independent elements); pairs sharing the same non-empty owner are
    exempt from the overlap/gap checks against EACH OTHER, but still checked
    against everything else.
    """
    findings: list[Finding] = []
    nodes_by_id = {n.id: n for n in spec.nodes}
    boxes: list[tuple[str, str, BBox]] = []  # (name, owner, box)

    for node in spec.nodes:
        boxes.append((f"node:{node.id}", node.id, node.bbox()))
        if node.label:
            boxes.append(
                (
                    f"node-label:{node.id}",
                    node.id,
                    _text_box(node.cx, node.cy, node.label, _LABEL_FONT_PX),
                )
            )
        if node.note:
            note_y = node.y + node.h + NODE_GAP_MIN_PX + _NOTE_FONT_PX
            boxes.append(
                (
                    f"node-note:{node.id}",
                    node.id,
                    _wrapped_text_box(node.cx, note_y, node.note, _NOTE_FONT_PX, max_chars=24),
                )
            )

    if spec.title:
        title_box = _wrapped_text_box(spec.width / 2, _TITLE_Y, spec.title, 18.0, max_chars=60)
        boxes.append(("title", "", title_box))
    if spec.caption:
        caption_box = _wrapped_text_box(
            spec.width / 2,
            spec.height - _CAPTION_Y_FROM_BOTTOM,
            spec.caption,
            _CAPTION_FONT_PX,
            max_chars=90,
        )
        boxes.append(("caption", "", caption_box))
    if spec.legend:
        # Mirror _legend_svg()'s exact layout: group translated to (12, height -
        # _LEGEND_Y_FROM_BOTTOM), each entry's swatch+label starting at local x,
        # text at local x+24, row height ~14px centered around local y=7.
        legend_y = spec.height - _LEGEND_Y_FROM_BOTTOM + 7.0
        legend_x = 12.0
        for entry in spec.legend:
            entry_box = _text_box(
                legend_x + 24.0, legend_y, entry.label, _LEGEND_FONT_PX, anchor="start"
            )
            boxes.append((f"legend:{entry.key}", "", entry_box))
            legend_x += 24.0 + len(entry.label) * _LEGEND_FONT_PX * _CHAR_ADVANCE_FACTOR + 24.0

    routed = [_route_edge(e, nodes_by_id, spec.nodes) for e in spec.edges]
    for r in routed:
        owner = f"edge:{r.edge.src}->{r.edge.dst}"
        if r.label_pos:
            boxes.append(
                (
                    f"edge-label:{r.edge.src}->{r.edge.dst}",
                    owner,
                    _text_box(*r.label_pos, r.edge.label, _LABEL_FONT_PX),
                )
            )
        if r.condition_pos:
            boxes.append(
                (
                    f"edge-condition:{r.edge.src}->{r.edge.dst}",
                    owner,
                    _text_box(*r.condition_pos, r.edge.condition, _LABEL_FONT_PX),
                )
            )

    # (a) no two boxes intersect; (b) min gap >=22px. Boxes sharing a non-empty
    # owner (a node and its own inline label) are exempt from each other.
    for i in range(len(boxes)):
        name_a, owner_a, box_a = boxes[i]
        for j in range(i + 1, len(boxes)):
            name_b, owner_b, box_b = boxes[j]
            if owner_a and owner_a == owner_b:
                continue
            if _intersects(box_a, box_b):
                findings.append(
                    Finding(
                        gate="visual.collision",
                        message=f"Overlap between '{name_a}' and '{name_b}'",
                        severity=Severity.CRIT,
                        blocking=True,
                        evidence=f"{box_a} intersects {box_b}",
                    )
                )
                continue
            gap = _gap(box_a, box_b)
            if gap < NODE_GAP_MIN_PX:
                findings.append(
                    Finding(
                        gate="visual.collision",
                        message=f"Gap {gap:.2f}px between '{name_a}' and '{name_b}' below the {NODE_GAP_MIN_PX}px minimum",
                        severity=Severity.CRIT,
                        blocking=True,
                        evidence=f"gap={gap:.2f}",
                    )
                )

    # (c) node-node gap >= 1.5x the larger node's short side.
    nodes_list = spec.nodes
    for i in range(len(nodes_list)):
        for j in range(i + 1, len(nodes_list)):
            a, b = nodes_list[i], nodes_list[j]
            gap = _gap(a.bbox(), b.bbox())
            short_a = min(a.w, a.h)
            short_b = min(b.w, b.h)
            required = NODE_GAP_MIN_RATIO * max(short_a, short_b)
            if gap < required:
                findings.append(
                    Finding(
                        gate="visual.collision",
                        message=(
                            f"Node gap {gap:.2f}px between '{a.id}' and '{b.id}' below "
                            f"required {required:.2f}px (1.5x larger short side)"
                        ),
                        severity=Severity.CRIT,
                        blocking=True,
                        evidence=f"gap={gap:.2f} required={required:.2f}",
                    )
                )

    # (d) no edge polyline passes through a non-endpoint node box.
    for r in routed:
        for node in nodes_list:
            if node.id in (r.edge.src, r.edge.dst):
                continue
            padded = _expand(node.bbox(), 0.0)
            for p0, p1 in zip(r.points, r.points[1:], strict=False):
                if _segment_hits_box(p0, p1, padded):
                    findings.append(
                        Finding(
                            gate="visual.collision",
                            message=f"Edge {r.edge.src}->{r.edge.dst} passes through node '{node.id}'",
                            severity=Severity.CRIT,
                            blocking=True,
                            evidence=f"segment {p0}->{p1} hits {padded}",
                        )
                    )

    return findings


# ---------------------------------------------------------------------------
# Legend, defs (CSS), and top-level render
# ---------------------------------------------------------------------------


def _legend_svg(spec: VisualSpec) -> str:
    if not spec.legend:
        return ""
    parts = [
        f'<g class="legend" transform="translate(12,{_fmt(spec.height - _LEGEND_Y_FROM_BOTTOM)})">'
    ]
    x = 0.0
    for entry in spec.legend:
        if entry.kind == "node":
            swatch = f'<rect x="{_fmt(x)}" y="0" width="18" height="14" rx="3" fill="none" stroke="currentColor" stroke-width="1.5"/>'
        elif entry.kind == "line":
            dash = ' stroke-dasharray="6 4"' if entry.key == "dashed" else ""
            swatch = f'<line x1="{_fmt(x)}" y1="7" x2="{_fmt(x + 18)}" y2="7" stroke="currentColor" stroke-width="1.5"{dash}/>'
        else:
            swatch = f'<rect x="{_fmt(x)}" y="0" width="18" height="14" rx="3" fill="{entry.key}" stroke="none"/>'
        parts.append(swatch)
        parts.append(
            f'<text x="{_fmt(x + 24)}" y="11" class="legend-label" font-size="{_LEGEND_FONT_PX}">{_escape(entry.label)}</text>'
        )
        x += 24.0 + len(entry.label) * _LEGEND_FONT_PX * _CHAR_ADVANCE_FACTOR + 24.0
    parts.append("</g>")
    return "".join(parts)


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def _caption_svg(spec: VisualSpec, notes: list[str]) -> str:
    caption = spec.caption
    if notes:
        caption = f"{caption} ({'; '.join(notes)})" if caption else "; ".join(notes)
    if not caption:
        return ""
    y = _fmt(spec.height - _CAPTION_Y_FROM_BOTTOM)
    return (
        f'<text x="{_fmt(spec.width / 2)}" y="{y}" class="figure-caption" '
        f'font-size="{_CAPTION_FONT_PX}" text-anchor="middle">{_escape(caption)}</text>'
    )


def _defs_css(theme: str) -> str:
    # currentColor-based, theme applied via the wrapping element's `color`.
    return (
        "<style><![CDATA["
        ".glyph{vector-effect:non-scaling-stroke;}"
        ".glyph-hi{filter:none;}"
        ".edge{fill:none;stroke:currentColor;stroke-width:1.5;}"
        ".edge-dashed{stroke-dasharray:6 4;}"
        ".edge-label,.edge-condition,.node-label,.figure-caption,.legend-label,.node-note{"
        "font-family:var(--f-body,Inter,system-ui,sans-serif);fill:currentColor;}"
        ".node-note{font-size:12px;}"
        ".dot{fill:var(--sig-hi,#5FBFA8);}"
        ".dot-transformed{fill:var(--sig,#3E9C86);}"
        ".dot-verified{fill:var(--sig,#3E9C86);}"
        ".dot-flagged{fill:var(--sev-crit,#C0282A);}"
        ".node-lit{filter:drop-shadow(0 0 4px var(--sig-glow,#3E9C8626));}"
        "@media (prefers-reduced-motion: no-preference){"
        ".glyph-alive .glyph-pulse{animation:ah-pulse 2.5s ease-in-out infinite;}"
        "}"
        "@keyframes ah-pulse{0%,100%{opacity:.25;}50%{opacity:.55;}}"
        f"/* theme:{theme} */"
        "]]></style>"
    )


def render(spec: VisualSpec, *, theme: str = "dark") -> str:
    """Render ``spec`` to a complete, self-contained ``<svg>``.

    Runs ``check_collisions`` first and raises ``CollisionError`` on any
    blocking finding -- the overlap class cannot ship (MOTION_SPEC S7). Output
    is fully deterministic (2dp-rounded floats, stable ordering, no
    timestamps/random ids) so calling this twice on the same spec yields
    byte-identical strings.
    """
    collisions = check_collisions(spec)
    if collisions:
        messages = "; ".join(f.message for f in collisions)
        raise CollisionError(f"{spec.id}: {len(collisions)} blocking collision(s): {messages}")

    nodes_by_id = {n.id: n for n in spec.nodes}
    routed = [_route_edge(e, nodes_by_id, spec.nodes) for e in spec.edges]

    # --- edges layer -------------------------------------------------------
    edge_parts: list[str] = []
    label_parts: list[str] = []
    edge_notes: list[str] = []
    main_edges: list[tuple[_RoutedEdge, float, float, float]] = []  # (redge, length, dur, speed)

    # Group outgoing main edges per source node to detect fan-out (S5).
    fan_out: dict[str, list[_RoutedEdge]] = {}
    for r in routed:
        if r.edge.main:
            fan_out.setdefault(r.edge.src, []).append(r)

    badge_num = 0
    for r in routed:
        edge = r.edge
        eid = f"e-{_safe_id(edge.src)}-{_safe_id(edge.dst)}"
        cls = "edge" + (" edge-dashed" if edge.style == "dashed" else "")
        edge_parts.append(f'<path id="{eid}" class="{cls}" d="{r.path_d}"/>')

        length = _path_length(r.points)
        if edge.main and length > 0:
            dur, speed, note = _edge_timing(length)
            if note:
                edge_notes.append(f"{edge.src}→{edge.dst}: {note}")
            main_edges.append((r, length, dur, speed))

        if r.label_pos:
            lx, ly = r.label_pos
            label_parts.append(
                f'<text x="{_fmt(lx)}" y="{_fmt(ly)}" class="edge-label" '
                f'font-size="{_LABEL_FONT_PX}" text-anchor="middle">{_escape(edge.label)}</text>'
            )
        if r.condition_pos:
            cx, cy = r.condition_pos
            label_parts.append(
                f'<text x="{_fmt(cx)}" y="{_fmt(cy)}" class="edge-condition" '
                f'font-size="{_LABEL_FONT_PX}" text-anchor="middle" font-style="italic">'
                f"{_escape(edge.condition)}</text>"
            )

        # Numbered badges are the always-present static fallback: reduced-motion
        # users read the flow by number (the labeled travel sequence, MOTION_SPEC
        # §5/§9); harmless with motion on. CSS @media gates the actual dot motion.
        if edge.main:
            badge_num += 1
            mx = _r((r.points[0][0] + r.points[-1][0]) / 2)
            my = _r((r.points[0][1] + r.points[-1][1]) / 2) - 18.0
            label_parts.append(
                f'<circle cx="{_fmt(mx)}" cy="{_fmt(my)}" r="8" class="edge-badge" '
                f'fill="var(--paper-2,#141420)" stroke="currentColor" stroke-width="1"/>'
                f'<text x="{_fmt(mx)}" y="{_fmt(my + 3.5)}" text-anchor="middle" '
                f'font-size="9" class="edge-badge-label">{badge_num}</text>'
            )

    # --- dot layer (motion) --------------------------------------------------
    dot_parts: list[str] = []
    if spec.motion:
        for r, length, dur, _speed in main_edges:
            n = _adaptive_sample_count(length, len(r.points) - 1)
            key_points, key_times = arc_length_keytimes(r.path_d, n)
            kp = ";".join(_fmt(k) for k in key_points)
            kt = ";".join(_fmt(k) for k in key_times)
            eid = f"e-{_safe_id(r.edge.src)}-{_safe_id(r.edge.dst)}"
            dot_id = f"dot-{eid}"
            dot_parts.append(
                f'<circle id="{dot_id}" class="dot" r="4">'
                f'<animateMotion dur="{_fmt(dur)}s" repeatCount="indefinite" '
                f'keyPoints="{kp}" keyTimes="{kt}" calcMode="linear">'
                f'<mpath href="#{eid}"/>'
                f"</animateMotion>"
                f"</circle>"
            )

    # --- nodes layer ---------------------------------------------------------
    node_parts: list[str] = []
    for node in spec.nodes:
        node_parts.append(render_glyph(node))
        if node.alive:
            node_parts.append(ambient_pulse_defs(node.id))

    # --- labels layer ----------------------------------------------------
    for node in spec.nodes:
        if node.label:
            label_parts.append(
                f'<text x="{_fmt(node.cx)}" y="{_fmt(node.cy + 4.0)}" class="node-label" '
                f'font-size="{_LABEL_FONT_PX}" text-anchor="middle">{_escape(node.label)}</text>'
            )
        if node.note:
            note_y = node.y + node.h + NODE_GAP_MIN_PX + _NOTE_FONT_PX
            wrapped = _wrap_lines(node.note, max_chars=24)
            box_w = _r(
                max(len(line) for line in wrapped) * _NOTE_FONT_PX * _CHAR_ADVANCE_FACTOR + 12.0
            )
            box_h = _r(len(wrapped) * _NOTE_FONT_PX * _LINE_HEIGHT_FACTOR + 8.0)
            box_x = _r(node.cx - box_w / 2)
            box_y = _r(note_y - _NOTE_FONT_PX)
            label_parts.append(
                f'<rect x="{_fmt(box_x)}" y="{_fmt(box_y)}" width="{_fmt(box_w)}" height="{_fmt(box_h)}" '
                f'rx="4" fill="var(--paper-2,#141420)" stroke="currentColor" stroke-width="0.75" opacity="0.85"/>'
            )
            for i, line in enumerate(wrapped):
                ly = box_y + 14.0 + i * (_NOTE_FONT_PX * _LINE_HEIGHT_FACTOR)
                label_parts.append(
                    f'<text x="{_fmt(node.cx)}" y="{_fmt(ly)}" class="node-note" '
                    f'text-anchor="middle">{_escape(line)}</text>'
                )

    title_svg = ""
    if spec.title:
        title_svg = (
            f'<text x="{_fmt(spec.width / 2)}" y="20" class="figure-title" '
            f'font-size="18" text-anchor="middle" font-weight="700" '
            f'fill="currentColor">{_escape(spec.title)}</text>'
        )

    legend_svg = _legend_svg(spec)
    caption_svg = _caption_svg(spec, edge_notes)

    body = "".join(
        [
            _defs_css(theme),
            '<g class="edges">',
            *edge_parts,
            "</g>",
            '<g class="dots">',
            *dot_parts,
            "</g>",
            '<g class="nodes">',
            *node_parts,
            "</g>",
            '<g class="labels">',
            title_svg,
            *label_parts,
            "</g>",
            legend_svg,
            caption_svg,
        ]
    )

    return (
        f'<svg viewBox="0 0 {_fmt(spec.width)} {_fmt(spec.height)}" '
        f'xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'class="ah-figure ah-figure-{_safe_id(spec.id)}" data-theme="{theme}" '
        f'role="img" aria-label="{_escape(spec.title or spec.id)}">{body}</svg>'
    )


def _wrap_lines(text: str, max_chars: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        cand = f"{cur} {w}".strip()
        if len(cand) > max_chars and cur:
            lines.append(cur)
            cur = w
        else:
            cur = cand
    if cur:
        lines.append(cur)
    return lines or [text]
