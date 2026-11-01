"""Sankey / flow-volume renderer (VISUAL_LIBRARY.md — "how a quantity splits and
merges as it moves from sources to sinks").

A Sankey is a genuinely different shape from the node/edge flowchart (``VisualSpec``)
and from the data-series charts (``charts.py``): the visual variable is the *width* of
each flow band, proportional to its value. Nodes sit in columns (left = upstream,
right = downstream); each flow leaves its source and arrives at its target as a band
whose thickness encodes the flow's value; a node's height is the max of what flows in
vs. what flows out. So this gets its own small ``SankeySpec`` dataclass here (not in
``models.py``, matching how each ``charts.py`` chart owns its selection rules) rather
than being forced into ``nodes+edges`` or a bar series.

Hard selection rules (enforced, fail-closed — a violation *raises*, never renders a
lie):

- every flow value must be strictly positive (a zero/negative "flow" is meaningless
  and would render a zero-width or inverted band);
- flow endpoints must reference declared nodes (no dangling source/target);
- the graph must be acyclic *by column* — a flow may only go to a strictly-later
  column, so the layout has an unambiguous left-to-right reading and cannot self-cross
  back on itself;
- at least one node and one flow.

The palette is B&W ink/paper by construction: bands and nodes are paper-toned
(``--paper-2``) with a translucent ink stroke, and **at most one** CredMgr accent
(``--sig-hi``) is spent — on the single flow the caller marks ``emphasis=True`` (if
any). This honors the DESIGN_SYSTEM visual law: ink/paper base, one accent per figure.

Reuses the flowchart family's geometry/text/escape helpers (``visual.py``) so this
figure shares the same collision math, float rounding, and XML escaping as every other
renderer in the engine.

Determinism is load-bearing (hash-gate): all SVG floats are rounded to 2dp via
``_fmt``, node columns are laid out in stable input order, and there is no
``Date.now``/random anywhere — ``render()`` twice on one spec is byte-identical.

Stdlib only; mypy --strict clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tools.docgen.models import DataSource, Finding, Severity
from tools.docgen.visual import (
    BBox,
    _escape,
    _fmt,
    _intersects,
    _r,
    _text_box,
)

# ---------------------------------------------------------------------------
# Layout constants (mirror charts.py's margins so the whole engine reads alike)
# ---------------------------------------------------------------------------

_MARGIN_LEFT = 24.0
_MARGIN_RIGHT = 24.0
_MARGIN_TOP = 48.0
_MARGIN_BOTTOM = 56.0
_NODE_WIDTH = 16.0  # the thin vertical node bar
_NODE_GAP_MIN_PX = 8.0  # minimum vertical gap between two nodes in a column
_LABEL_FONT_PX = 12.0
_VALUE_FONT_PX = 10.0
_MIN_BAND_PX = 1.0  # a band is never thinner than this (still readable when tiny)

# Ink/paper base (no accent) + the single sanctioned CredMgr accent for the one
# emphasized flow. These match tokens.json / DESIGN_SYSTEM §1.
_NODE_FILL = "var(--paper-2,#141420)"
_NODE_STROKE = "currentColor"
_BAND_FILL = "currentColor"
_BAND_OPACITY = 0.16
_ACCENT_FILL = "var(--sig-hi,#5FBFA8)"
_ACCENT_OPACITY = 0.34


class SankeyRuleError(ValueError):
    """Raised when a spec violates one of the Sankey hard selection rules.

    Fail-closed: a non-positive flow, a dangling endpoint, a non-forward (cyclic-by-
    column) flow, an empty graph, or a node-label collision all *raise* rather than
    render a misleading diagram.
    """


@dataclass(frozen=True)
class SankeyNode:
    """One node (a source, a waypoint, or a sink) placed in a numbered column."""

    id: str
    label: str
    col: int  # 0 = leftmost/source column; flows only go to strictly-later columns


@dataclass(frozen=True)
class SankeyFlow:
    """A single flow band from ``src`` to ``dst``, ``value`` sets its width."""

    src: str
    dst: str
    value: float
    label: str = ""
    emphasis: bool = False  # the one flow that may spend the CredMgr accent


@dataclass(frozen=True)
class SankeySpec:
    id: str
    title: str
    caption: str
    nodes: list[SankeyNode]
    flows: list[SankeyFlow]
    unit: str = ""
    width: float = 720.0
    height: float = 420.0
    data_sources: list[DataSource] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Validation / collision check
# ---------------------------------------------------------------------------


def check_sankey_collisions(spec: SankeySpec) -> list[Finding]:
    """Return blocking findings for a spec (empty graph, bad flows, or label overlaps).

    Fail-closed: any structural violation is a CRIT finding; an empty return means the
    spec is safe to render. This mirrors ``charts.py``'s ``check_*_collisions`` contract.
    """
    findings: list[Finding] = []

    if not spec.nodes:
        findings.append(
            Finding(gate="sankey.rule", message="sankey has no nodes", severity=Severity.CRIT)
        )
        return findings
    if not spec.flows:
        findings.append(
            Finding(gate="sankey.rule", message="sankey has no flows", severity=Severity.CRIT)
        )
        return findings

    ids = [n.id for n in spec.nodes]
    if len(set(ids)) != len(ids):
        findings.append(
            Finding(
                gate="sankey.rule",
                message="sankey node ids must be unique",
                severity=Severity.CRIT,
            )
        )
        return findings

    col_by_id = {n.id: n.col for n in spec.nodes}
    for f in spec.flows:
        if f.value <= 0:
            findings.append(
                Finding(
                    gate="sankey.rule",
                    message=f"flow {f.src}->{f.dst} value must be > 0 (got {f.value:g})",
                    severity=Severity.CRIT,
                )
            )
        if f.src not in col_by_id:
            findings.append(
                Finding(
                    gate="sankey.rule",
                    message=f"flow references unknown source node '{f.src}'",
                    severity=Severity.CRIT,
                )
            )
        if f.dst not in col_by_id:
            findings.append(
                Finding(
                    gate="sankey.rule",
                    message=f"flow references unknown target node '{f.dst}'",
                    severity=Severity.CRIT,
                )
            )
        if f.src in col_by_id and f.dst in col_by_id and col_by_id[f.dst] <= col_by_id[f.src]:
            findings.append(
                Finding(
                    gate="sankey.rule",
                    message=(
                        f"flow {f.src}(col {col_by_id[f.src]})->{f.dst}(col {col_by_id[f.dst]}) "
                        "must go to a strictly-later column (sankeys read left-to-right, no back-flow)"
                    ),
                    severity=Severity.CRIT,
                )
            )
    if len([f for f in spec.flows if f.emphasis]) > 1:
        findings.append(
            Finding(
                gate="sankey.rule",
                message="at most one flow may set emphasis=True (only one CredMgr accent per figure)",
                severity=Severity.CRIT,
            )
        )
    if findings:
        return findings

    # Geometry-derived label collision: two node labels in the same column must not
    # overlap. We over-estimate label width (fail-closed) via visual._text_box.
    layout = _layout_nodes(spec)
    by_col: dict[int, list[str]] = {}
    for n in spec.nodes:
        by_col.setdefault(n.col, []).append(n.id)
    for col, node_ids in sorted(by_col.items()):
        boxes: list[tuple[str, BBox]] = []
        for nid in node_ids:
            geo = layout[nid]
            label_cx = geo.x + _NODE_WIDTH / 2
            label_cy = geo.y - 6.0
            boxes.append((nid, _text_box(label_cx, label_cy, _node_label(spec, nid), _LABEL_FONT_PX)))
        for i in range(len(boxes)):
            for j in range(i + 1, len(boxes)):
                if _intersects(boxes[i][1], boxes[j][1]):
                    findings.append(
                        Finding(
                            gate="sankey.collision",
                            message=(
                                f"Node labels '{boxes[i][0]}' and '{boxes[j][0]}' overlap in column {col} "
                                f"(too many nodes for a {spec.height:g}px-tall figure)"
                            ),
                            severity=Severity.CRIT,
                        )
                    )
    return findings


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _NodeGeo:
    x: float
    y: float
    h: float


def _node_label(spec: SankeySpec, node_id: str) -> str:
    for n in spec.nodes:
        if n.id == node_id:
            return n.label
    return node_id


def _node_value(spec: SankeySpec, node_id: str) -> float:
    """A node's magnitude = max(total in, total out) — its band-stack height driver."""
    total_in = sum(f.value for f in spec.flows if f.dst == node_id)
    total_out = sum(f.value for f in spec.flows if f.src == node_id)
    return max(total_in, total_out)


def _layout_nodes(spec: SankeySpec) -> dict[str, _NodeGeo]:
    """Place every node into its column and stack columns vertically, scaling value→px.

    Deterministic: columns are sorted numerically, nodes within a column keep input
    order, and a single global value→px scale is derived from the busiest column so band
    widths are comparable across the whole figure.
    """
    plot_x0 = _MARGIN_LEFT
    plot_x1 = spec.width - _MARGIN_RIGHT
    plot_y0 = _MARGIN_TOP
    plot_y1 = spec.height - _MARGIN_BOTTOM
    plot_h = plot_y1 - plot_y0

    cols = sorted({n.col for n in spec.nodes})
    n_cols = len(cols)

    # Per-column total magnitude → pick a scale so the busiest column fits the plot
    # height (minus inter-node gaps). Fail-safe: never divide by zero.
    col_nodes: dict[int, list[SankeyNode]] = {}
    for n in spec.nodes:
        col_nodes.setdefault(n.col, []).append(n)
    max_col_total = 0.0
    for col in cols:
        nodes = col_nodes[col]
        total = sum(_node_value(spec, n.id) for n in nodes)
        gaps = max(0, len(nodes) - 1) * _NODE_GAP_MIN_PX
        # value that must fit into (plot_h - gaps)
        usable = max(plot_h - gaps, 1.0)
        if total > 0:
            max_col_total = max(max_col_total, total / usable)
    scale = max_col_total if max_col_total > 0 else 1.0  # px-per-unit denominator

    layout: dict[str, _NodeGeo] = {}
    for c_idx, col in enumerate(cols):
        if n_cols > 1:
            x = plot_x0 + (plot_x1 - plot_x0 - _NODE_WIDTH) * (c_idx / (n_cols - 1))
        else:
            x = (plot_x0 + plot_x1 - _NODE_WIDTH) / 2
        nodes = col_nodes[col]
        heights = [max(_node_value(spec, n.id) / scale, _MIN_BAND_PX) for n in nodes]
        gaps = max(0, len(nodes) - 1) * _NODE_GAP_MIN_PX
        stack_h = sum(heights) + gaps
        y = plot_y0 + (plot_h - stack_h) / 2  # vertically centered column
        for n, h in zip(nodes, heights, strict=True):
            layout[n.id] = _NodeGeo(x=_r(x), y=_r(y), h=_r(h))
            y += h + _NODE_GAP_MIN_PX
    return layout


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _defs_css() -> str:
    return (
        "<style><![CDATA["
        ".sankey-label,.sankey-value,.figure-caption,.figure-title{"
        "font-family:var(--f-body,Inter,system-ui,sans-serif);fill:currentColor;}"
        ".sankey-value{font-variant-numeric:tabular-nums;opacity:0.75;}"
        "]]></style>"
    )


def _title_svg(width: float, title: str) -> str:
    if not title:
        return ""
    return (
        f'<text x="{_fmt(width / 2)}" y="20" class="figure-title" font-size="18" '
        f'text-anchor="middle" font-weight="700">{_escape(title)}</text>'
    )


def _caption_svg(width: float, height: float, caption: str) -> str:
    if not caption:
        return ""
    return (
        f'<text x="{_fmt(width / 2)}" y="{_fmt(height - 10.0)}" class="figure-caption" '
        f'font-size="12" text-anchor="middle">{_escape(caption)}</text>'
    )


def _band_path(x0: float, y0a: float, y0b: float, x1: float, y1a: float, y1b: float) -> str:
    """A left-to-right flow band as a filled cubic-Bezier ribbon (top edge out, bottom back)."""
    mid = _r((x0 + x1) / 2)
    return (
        f"M {_fmt(x0)} {_fmt(y0a)} "
        f"C {_fmt(mid)} {_fmt(y0a)} {_fmt(mid)} {_fmt(y1a)} {_fmt(x1)} {_fmt(y1a)} "
        f"L {_fmt(x1)} {_fmt(y1b)} "
        f"C {_fmt(mid)} {_fmt(y1b)} {_fmt(mid)} {_fmt(y0b)} {_fmt(x0)} {_fmt(y0b)} Z"
    )


def render_sankey(spec: SankeySpec) -> str:
    """Render ``spec`` to a self-contained ``<svg>``.

    Raises ``SankeyRuleError`` on any blocking finding (empty graph, a non-positive flow
    value, a dangling/back-flow endpoint, more than one emphasized flow, or overlapping
    node labels). The returned SVG is B&W ink/paper with at most one CredMgr accent
    (on the single ``emphasis`` flow), ``role="img"`` + ``aria-label`` for a11y, and
    deterministic (2dp floats, stable ordering) for the hash-gate.
    """
    collisions = check_sankey_collisions(spec)
    if collisions:
        raise SankeyRuleError(f"{spec.id}: " + "; ".join(f.message for f in collisions))

    layout = _layout_nodes(spec)

    # Track how much vertical band-space is already consumed at each node's left/right
    # face, so stacked flows do not overlap. Order flows deterministically (by source
    # column, then source id, then target id) so cursors advance identically every run.
    col_by_id = {n.id: n.col for n in spec.nodes}
    ordered_flows = sorted(
        spec.flows, key=lambda f: (col_by_id[f.src], f.src, col_by_id[f.dst], f.dst)
    )
    scale = _band_scale(spec, layout)
    out_cursor: dict[str, float] = {nid: geo.y for nid, geo in layout.items()}
    in_cursor: dict[str, float] = {nid: geo.y for nid, geo in layout.items()}

    band_parts: list[str] = []
    for f in ordered_flows:
        src_geo = layout[f.src]
        dst_geo = layout[f.dst]
        band_h = max(f.value * scale, _MIN_BAND_PX)
        x0 = _r(src_geo.x + _NODE_WIDTH)
        x1 = _r(dst_geo.x)
        y0a = out_cursor[f.src]
        y0b = _r(y0a + band_h)
        y1a = in_cursor[f.dst]
        y1b = _r(y1a + band_h)
        out_cursor[f.src] = y0b
        in_cursor[f.dst] = y1b
        fill = _ACCENT_FILL if f.emphasis else _BAND_FILL
        opacity = _ACCENT_OPACITY if f.emphasis else _BAND_OPACITY
        title = _escape(f.label or f"{f.src} → {f.dst}: {f.value:g}{spec.unit}")
        band_parts.append(
            f'<path class="sankey-band" d="{_band_path(x0, y0a, y0b, x1, y1a, y1b)}" '
            f'fill="{fill}" fill-opacity="{opacity:g}"><title>{title}</title></path>'
        )

    node_parts: list[str] = []
    for n in spec.nodes:
        geo = layout[n.id]
        node_parts.append(
            f'<rect class="sankey-node" x="{_fmt(geo.x)}" y="{_fmt(geo.y)}" '
            f'width="{_fmt(_NODE_WIDTH)}" height="{_fmt(geo.h)}" rx="2" '
            f'fill="{_NODE_FILL}" stroke="{_NODE_STROKE}" stroke-width="1"/>'
        )
        # Right-most column labels sit to the LEFT of the bar; all others to the right,
        # so a label never runs off the figure edge.
        is_last_col = col_by_id[n.id] == max(col_by_id.values())
        if is_last_col:
            lx = _r(geo.x - 6.0)
            anchor = "end"
        else:
            lx = _r(geo.x + _NODE_WIDTH + 6.0)
            anchor = "start"
        ly = _r(geo.y + geo.h / 2 + 4.0)
        val = _node_value(spec, n.id)
        node_parts.append(
            f'<text class="sankey-label" x="{_fmt(lx)}" y="{_fmt(ly)}" '
            f'text-anchor="{anchor}" font-size="{_LABEL_FONT_PX}">{_escape(n.label)}</text>'
        )
        node_parts.append(
            f'<text class="sankey-value" x="{_fmt(lx)}" y="{_fmt(ly + 13.0)}" '
            f'text-anchor="{anchor}" font-size="{_VALUE_FONT_PX}">{_escape(f"{val:g}{spec.unit}")}</text>'
        )

    body = "".join(band_parts) + "".join(node_parts)
    return (
        f'<svg viewBox="0 0 {_fmt(spec.width)} {_fmt(spec.height)}" '
        f'xmlns="http://www.w3.org/2000/svg" class="ah-figure ah-sankey" role="img" '
        f'aria-label="{_escape(spec.title or spec.id)}">'
        f"{_defs_css()}{_title_svg(spec.width, spec.title)}{body}"
        f"{_caption_svg(spec.width, spec.height, spec.caption)}</svg>"
    )


def _band_scale(spec: SankeySpec, layout: dict[str, _NodeGeo]) -> float:
    """px-per-unit for band widths — identical to the node-height scale so a node's
    face is exactly filled by the flows through it (bands never over/under-fill a node).
    """
    # Recover the scale from any node with positive value: geo.h == value / scale_denom.
    for n in spec.nodes:
        val = _node_value(spec, n.id)
        if val > 0:
            return layout[n.id].h / val
    return 1.0
