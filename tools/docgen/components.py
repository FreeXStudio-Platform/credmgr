"""HTML partials for the doc-system (DESIGN_SYSTEM.md §4-6, RULEBOOK L21).

Every function returns a plain ``str`` of HTML. All interpolated text is escaped via
``html.escape`` — callers may pass pre-built (already-escaped/safe) HTML fragments as
``body``/``svg`` parameters where documented. Stdlib only; mypy --strict clean.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from html import escape
from pathlib import Path
from typing import Final

from tools.docgen.models import DocHeader, Tier

_ASSETS_DIR: Final[Path] = Path(__file__).resolve().parent / "assets"
# Placeholder — the real CredMgr mark is still an open design task
# (CredMgr-V2-Design/04_CLAUDE_DESIGN_PROMPT_STRICT.md); replace this file in place
# once it lands, no code change needed here.
_MARK_PATH: Final[Path] = _ASSETS_DIR / "keep-mark-placeholder.svg"

_TIER_BADGE_CLASS: Final[dict[Tier, str]] = {
    Tier.PUBLIC: "badge-public",
    Tier.CONFIDENTIAL: "badge-confidential",
    Tier.SECRET: "badge-secret",
}

_TIER_LABEL: Final[dict[Tier, str]] = {
    Tier.PUBLIC: "PUBLIC",
    Tier.CONFIDENTIAL: "CONFIDENTIAL",
    Tier.SECRET: "SECRET",
}

_TIER_GLYPH: Final[dict[Tier, str]] = {
    # Achromatic shield glyph for PUBLIC (KEEP's neutral state), warn-coloured diamond
    # for CONFIDENTIAL, danger hazard-stripe swatch for SECRET — the same sig/warn/danger
    # mapping tokens.py's badge-* CSS classes use (KEEP has no fourth "neutral brand" hue).
    Tier.PUBLIC: '<span aria-hidden="true">&#128737;</span>',
    Tier.CONFIDENTIAL: '<span aria-hidden="true">&#9670;</span>',
    Tier.SECRET: '<span aria-hidden="true">&#9888;</span>',
}


def classification_badge(tier: Tier) -> str:
    """Render the classification badge: PUBLIC=achromatic, CONFIDENTIAL=warn, SECRET=danger-striped."""
    css_class = _TIER_BADGE_CLASS[tier]
    label = _TIER_LABEL[tier]
    glyph = _TIER_GLYPH[tier]
    return f'<span class="badge {css_class}">{glyph}<span>{escape(label)}</span></span>'


def logo_svg() -> str:
    """Inline the CredMgr eye mark (single source: assets/ah-mark.svg — never redraw it)."""
    svg = _MARK_PATH.read_text(encoding="utf-8").strip()
    # Tag with a class hook for sizing via CSS (masthead vs. verified-stamp contexts differ).
    return svg.replace("<svg ", '<svg class="mark-svg" ', 1)


def theme_toggle() -> str:
    """A small inline-JS theme toggle: persists to localStorage, honors prefers-color-scheme.

    Self-contained (no external script). Safe to inline multiple times per page (uses
    ``closest`` lookups and idempotent listeners scoped to the clicked button).
    """
    return """\
<button type="button" class="theme-toggle" data-docgen-theme-toggle aria-label="Toggle light/dark theme">
  <span data-docgen-theme-label>theme</span>
</button>
<script>
(function () {
  var KEY = "docgen-theme";
  function apply(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    document.querySelectorAll("[data-docgen-theme-label]").forEach(function (el) {
      el.textContent = theme;
    });
  }
  function initial() {
    try {
      var saved = window.localStorage.getItem(KEY);
      if (saved === "dark" || saved === "light") return saved;
    } catch (e) { /* localStorage unavailable — fall through */ }
    var prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
    return prefersLight ? "light" : "dark";
  }
  var current = initial();
  apply(current);
  document.querySelectorAll("[data-docgen-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      current = current === "dark" ? "light" : "dark";
      apply(current);
      try { window.localStorage.setItem(KEY, current); } catch (e) { /* ignore */ }
    });
  });
})();
</script>"""


def masthead(header: DocHeader) -> str:
    """Render the document masthead: logo + title + mono meta line + classification badge + theme toggle."""
    title = escape(header.title)
    meta_bits = [
        escape(header.id),
        escape(header.owner),
        escape(header.status),
        escape(header.last_reviewed),
    ]
    meta_line = " &middot; ".join(meta_bits)
    badge = classification_badge(header.classification)
    logo = logo_svg()
    toggle = theme_toggle()
    return f"""\
<header class="masthead">
  <div class="masthead-brand">
    <div class="masthead-logo" aria-hidden="true">{logo}</div>
    <div class="masthead-titles">
      <h1 class="t-h2">{title}</h1>
      <div class="t-mono-label masthead-meta">{meta_line}</div>
    </div>
  </div>
  <div class="masthead-meta">
    {badge}
    {toggle}
  </div>
</header>"""


def section(eyebrow: str, body: str) -> str:
    """Render a numbered section frame: mono eyebrow (real id) + hairline + body."""
    return f"""\
<section class="doc-section">
  <span class="t-eyebrow">{escape(eyebrow)}</span>
  <div class="t-body">{body}</div>
</section>"""


def data_table(
    headers: list[str],
    rows: list[list[str]],
    *,
    render_cell: Callable[[str], str] | None = None,
) -> str:
    """Render a data table: dark header row, tabular-nums, wrapped in an overflow-x container.

    ``headers`` and each row cell are HTML-escaped (plain text only, no embedded markup).

    ``render_cell`` optionally replaces that escaping with a caller-supplied renderer — the
    generator passes ``markdown_blocks.render_inline`` so a cell whose text is wrapped in
    backticks renders as inline code rather than as literal backtick characters. It is keyword-only and defaults to ``None``
    (escape-only) so every existing caller, and every previously-built document, is byte-identical.
    A renderer supplied here is responsible for its own escaping; the two in this repo escape first
    and only then add markup.
    """
    cell = render_cell if render_cell is not None else escape
    head_cells = "".join(f"<th>{cell(h)}</th>" for h in headers)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{cell(str(c))}</td>" for c in row)
        body_rows.append(f"<tr>{cells}</tr>")
    body_html = "".join(body_rows)
    return f"""\
<div class="doc-table-wrap">
  <table class="doc-table">
    <thead><tr>{head_cells}</tr></thead>
    <tbody>{body_html}</tbody>
  </table>
</div>"""


def figure(svg: str, caption: str, legend_html: str = "") -> str:
    """Render a figure block: ``.svgwrap`` blueprint canvas + numbered caption + optional legend.

    ``svg`` is trusted pre-rendered SVG markup (from ``visual.render``); ``caption`` is escaped.
    ``legend_html`` is trusted pre-built HTML (e.g. from a legend-building helper) and passed
    through unescaped by design — callers are responsible for escaping any dynamic text within.
    """
    legend_block = f'<div class="figure-legend">{legend_html}</div>' if legend_html else ""
    return f"""\
<figure class="doc-figure">
  <div class="svgwrap">{svg}</div>
  <figcaption class="figcap">{escape(caption)}</figcaption>
  {legend_block}
</figure>"""


_CALLOUT_CLASS: Final[dict[str, str]] = {
    "info": "callout-info",
    "warn": "callout-warn",
    "crit": "callout-crit",
}


def callout(kind: str, body: str) -> str:
    """Render a callout block with an accent/severity left rule.

    ``kind`` is one of ``info``/``warn``/``crit`` (unknown kinds fall back to the neutral
    accent rule rather than raising, since callouts are presentational, not gating).
    """
    css_class = _CALLOUT_CLASS.get(kind, "")
    return f'<div class="callout {css_class}">{body}</div>'


def verified_stamp(audit_ref: str) -> str:
    """Render the 'Verified by CredMgr' trust footer stamp (DESIGN_SYSTEM §6).

    Static by default (reduced-motion compliant — no animation is emitted here; a future
    motion layer may progressively enhance this markup, but the base render must be legible
    and complete without any script/animation running).
    """
    logo = logo_svg()
    ref = escape(audit_ref)
    return f"""\
<div class="verified-stamp">
  <div class="verified-stamp-mark" aria-hidden="true">{logo}</div>
  <div class="verified-stamp-text">
    <span class="t-mono-label">Verified by CredMgr</span>
    <span class="t-body-sm">{ref}</span>
  </div>
</div>"""


# ---- WCAG AA contrast helpers -------------------------------------------------------------


def _hex_to_rgb(color: str) -> tuple[float, float, float]:
    """Parse a ``#rrggbb`` or ``#rgb`` hex color into 0-255 float channels. Raises on bad input."""
    c = color.strip().lstrip("#")
    if len(c) == 3:
        c = "".join(ch * 2 for ch in c)
    if len(c) != 6:
        raise ValueError(f"not a hex color: {color!r}")
    r = int(c[0:2], 16)
    g = int(c[2:4], 16)
    b = int(c[4:6], 16)
    return float(r), float(g), float(b)


def _srgb_channel_to_linear(c: float) -> float:
    cs = c / 255.0
    if cs <= 0.04045:
        return cs / 12.92
    return math.pow((cs + 0.055) / 1.055, 2.4)


def _relative_luminance(color: str) -> float:
    r, g, b = _hex_to_rgb(color)
    rl = _srgb_channel_to_linear(r)
    gl = _srgb_channel_to_linear(g)
    bl = _srgb_channel_to_linear(b)
    return 0.2126 * rl + 0.7152 * gl + 0.0722 * bl


def contrast_ratio(fg: str, bg: str) -> float:
    """Return the WCAG contrast ratio between two ``#rrggbb`` hex colors (1.0 .. 21.0)."""
    l1 = _relative_luminance(fg)
    l2 = _relative_luminance(bg)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def wcag_aa_ok(fg: str, bg: str, large: bool = False) -> bool:
    """True if ``fg`` on ``bg`` meets WCAG AA: >=4.5:1 normal text, >=3:1 large text (>=18pt/14pt-bold)."""
    ratio = contrast_ratio(fg, bg)
    threshold = 3.0 if large else 4.5
    return ratio >= threshold
