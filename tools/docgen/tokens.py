"""KEEP design tokens -> CSS.

Loads ``assets/tokens.json`` (mirrors ``v2/design/tokens/keep.tokens.json`` — never fork
values here, re-copy from KEEP's own file instead, see ``tools/PROVENANCE.md``) and emits a
single self-contained stylesheet: vendored ``@font-face`` faces
(``fonts.build_font_face_css()``), dark (native) + light (report/print) themes, the three-
state signal palette (``sig``/``warn``/``danger`` — KEEP's own achromatic-by-default,
colour-is-a-state-never-a-decoration law), the KEEP ``.t-*`` type-role classes, spacing/
radii, the blueprint diagram canvas (``.svgwrap``), and the doc-system component CSS
(masthead, classification badge, data table, figure, callout, verified stamp, theme toggle).

Stdlib only; mypy --strict clean; no network references (no ``@import``, no CDN links) —
fonts are embedded as base64 data-URIs, not fetched.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from tools.docgen.fonts import build_font_face_css

_ASSETS_DIR: Final[Path] = Path(__file__).resolve().parent / "assets"
_TOKENS_PATH: Final[Path] = _ASSETS_DIR / "tokens.json"


def _load_tokens(path: Path = _TOKENS_PATH) -> dict[str, object]:
    """Load the vendored KEEP token JSON. Raises if the file is missing/malformed (fail-closed)."""
    with path.open("r", encoding="utf-8") as f:
        data: dict[str, object] = json.load(f)
    return data


TOKENS: Final[dict[str, object]] = _load_tokens()


def _css_vars(prefix_map: dict[str, str]) -> str:
    """Render a flat name->value mapping as ``--name:value;`` lines (2-space indented)."""
    lines = [f"  --{name}:{value};" for name, value in prefix_map.items()]
    return "\n".join(lines)


def _sub(name: str) -> dict[str, str]:
    """Fetch a nested string-keyed, string-valued sub-object from ``TOKENS`` (e.g. ``"brand"``)."""
    value = TOKENS[name]
    if not isinstance(value, dict):
        raise TypeError(f"tokens.json[{name!r}] is not an object: {type(value).__name__}")
    return {str(k): str(v) for k, v in value.items()}


def build_css() -> str:  # noqa: PLR0915 - single cohesive stylesheet emitter, sectioned by comments
    """Emit the full self-contained doc-system stylesheet from ``TOKENS``.

    Includes the vendored ``@font-face`` rules (real Inter/JetBrains Mono faces, embedded as
    base64 data-URIs — see ``fonts.py``), both ``:root``/``[data-theme=dark]`` and
    ``[data-theme=light]`` grounds/inks, the three-state signal palette, the KEEP ``.t-*``
    type-role classes (system-stack fallbacks after the real face, never a serif), spacing/
    radii, the ``.svgwrap`` blueprint grid, table/badge/callout/masthead component rules, a
    ``prefers-reduced-motion`` guard, and a visible ``:focus-visible`` ring. No ``@import``,
    no CDN reference — every font byte is embedded, so a self-contained render always shows
    the real KEEP faces rather than silently substituting a system font.

    KEEP is achromatic by default (``identity.principles`` in the token source): colour is
    reserved for exactly three states (healthy/verified = ``sig``, attention = ``warn``,
    danger = ``danger``) and is never decorative. Every component below that used to carry a
    brand hue (badges, the verified stamp, the focus ring, the callout accent) is remapped
    onto that three-state law rather than onto an invented colour — see each rule's own
    comment for which KEEP state it encodes and why.
    """
    grounds_dark = _sub("grounds_dark")
    inks_dark = _sub("inks_dark")
    grounds_light = _sub("grounds_light")
    inks_light = _sub("inks_light")
    signal = _sub("signal")
    fonts = _sub("fonts")
    weights = _sub("weights")
    font_size = _sub("font_size")
    line_height = _sub("line_height")
    spacing = _sub("spacing")
    radii = _sub("radii")
    layout = _sub("layout")
    diagram = _sub("diagram")

    dark_vars = _css_vars(
        {
            "void": grounds_dark["void"],
            "night": grounds_dark["night"],
            "steel": grounds_dark["steel"],
            "steel-2": grounds_dark["steel-2"],
            "steel-3": grounds_dark["steel-3"],
            "bone": inks_dark["bone"],
            "ash": inks_dark["ash"],
            "mute": inks_dark["mute"],
            "faint": inks_dark["faint"],
            "bg": "var(--night)",
            "paper": "var(--night)",
            "paper-2": "var(--steel)",
            "fg": "var(--bone)",
        }
    )
    light_vars = _css_vars(
        {
            "void": grounds_light["void"],
            "night": grounds_light["night"],
            "steel": grounds_light["steel"],
            "steel-2": grounds_light["steel-2"],
            "steel-3": grounds_light["steel-3"],
            "bone": inks_light["bone"],
            "ash": inks_light["ash"],
            "mute": inks_light["mute"],
            "faint": inks_light["faint"],
            "bg": grounds_light["night"],
            "paper": grounds_light["night"],
            "paper-2": grounds_light["steel"],
            "fg": inks_light["bone"],
        }
    )
    brand_vars = _css_vars(
        {
            "sig": signal["sig"],
            "sig-hi": signal["sig-hi"],
            "sig-dim": signal["sig-dim"],
            "warn": signal["warn"],
            "warn-hi": signal["warn-hi"],
            "warn-dim": signal["warn-dim"],
            "danger": signal["danger"],
            "danger-hi": signal["danger-hi"],
            "danger-dim": signal["danger-dim"],
            "accent": "var(--sig-hi)",
            "f-display": fonts["display"],
            "f-body": fonts["body"],
            "f-mono": fonts["mono"],
            "fw-label": str(weights["label"]),
            "fw-eyebrow": str(weights["label"]),
            "fw-body": str(weights["body"]),
            "fw-emphasis": str(weights["body-em"]),
            "fw-button": str(weights["label"]),
            "fw-display": str(weights["display"]),
            "maxw": layout["maxw"],
            "pad": layout["pad"],
            "r-xs": radii["xs"],
            "r-sm": radii["sm"],
            "r-md": radii["md"],
            "r-lg": radii["md"],
            "r-pill": radii["pill"],
            "diagram-grid": diagram["grid"],
        }
    )
    fs_vars = _css_vars({f"fs-{k}": v for k, v in font_size.items()})
    lh_vars = _css_vars({f"lh-{k}": v for k, v in line_height.items()})
    sp_vars = _css_vars({f"g{k}": v for k, v in spacing.items()})
    font_faces = build_font_face_css()

    return f"""\
/* CredMgr doc-system stylesheet — generated by tools/docgen/tokens.py from assets/tokens.json.
   Self-contained: no @import, no CDN — fonts embedded as base64 data-URIs below. Do not
   hand-edit; edit the token source and rebuild (RULEBOOK L7). */

{font_faces}

:root, [data-theme="dark"] {{
{dark_vars}
}}

[data-theme="light"] {{
{light_vars}
}}

:root {{
{brand_vars}
{fs_vars}
{lh_vars}
{sp_vars}
}}

* {{ box-sizing: border-box; }}

html {{ color-scheme: dark light; }}

body {{
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: var(--f-body);
  font-weight: var(--fw-body);
  font-size: var(--fs-base);
  line-height: var(--lh-base);
  -webkit-font-smoothing: antialiased;
}}

.doc-root {{
  max-width: var(--maxw);
  margin: 0 auto;
  padding: var(--pad);
}}

/* ---- KEEP type-role classes (v2/design/tokens/keep.tokens.json) ---- */
.t-h1, .t-h2, .t-h3, .t-h4 {{
  font-family: var(--f-display);
  font-weight: var(--fw-display);
  line-height: var(--lh-tight);
  letter-spacing: -0.01em;
  text-wrap: balance;
  margin: 0;
}}
.t-h1 {{ font-size: var(--fs-4xl); }}
.t-h2 {{ font-size: var(--fs-3xl); }}
.t-h3 {{ font-size: var(--fs-2xl); }}
.t-h4 {{ font-size: var(--fs-xl); }}

.t-lede {{
  font-family: var(--f-body);
  font-weight: var(--fw-body);
  font-size: var(--fs-lg);
  line-height: var(--lh-loose);
  max-width: 68ch;
}}
.t-body {{
  font-family: var(--f-body);
  font-weight: var(--fw-body);
  font-size: var(--fs-base);
  line-height: var(--lh-base);
  max-width: 68ch;
}}
.t-body-sm {{
  font-family: var(--f-body);
  font-weight: var(--fw-body);
  font-size: var(--fs-sm);
  line-height: var(--lh-base);
}}
.t-mono-label {{
  font-family: var(--f-mono);
  font-weight: var(--fw-label);
  font-size: var(--fs-xs);
  letter-spacing: 0.18em;
  text-transform: uppercase;
}}
.t-mono-data {{
  font-family: var(--f-mono);
  font-weight: var(--fw-body);
  font-variant-numeric: tabular-nums;
  font-size: var(--fs-sm);
}}
.t-caption, .t-eyebrow {{
  font-family: var(--f-mono);
  font-weight: var(--fw-eyebrow);
  font-size: var(--fs-xs);
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--ash);
}}

/* ---- Masthead ---- */
.masthead {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--g4);
  padding-bottom: var(--g5);
  border-bottom: 1px solid var(--faint);
  margin-bottom: var(--g6);
}}
.masthead-brand {{ display: flex; align-items: center; gap: var(--g3); }}
.masthead-logo {{ width: 28px; height: 28px; color: var(--fg); flex: none; }}
.masthead-titles {{ display: flex; flex-direction: column; gap: var(--g1); }}
.masthead-meta {{ display: flex; align-items: center; gap: var(--g3); flex-wrap: wrap; }}

/* ---- Classification badge ---- */
.badge {{
  display: inline-flex;
  align-items: center;
  gap: var(--g1);
  padding: 3px var(--g3);
  border-radius: var(--r-pill);
  font-family: var(--f-mono);
  font-weight: var(--fw-label);
  font-size: var(--fs-2xs);
  letter-spacing: 0.14em;
  text-transform: uppercase;
  white-space: nowrap;
}}
/* KEEP has no neutral "brand" hue for public — achromatic is the neutral state (identity.principles). */
.badge-public {{ background: var(--steel-2); color: var(--ash); border: 1px solid var(--faint); }}
.badge-confidential {{ background: var(--warn-dim); color: var(--warn-hi); border: 1px solid var(--warn); }}
.badge-secret {{
  color: var(--bone);
  border: 1px solid var(--danger);
  background: repeating-linear-gradient(45deg, var(--danger-dim), var(--danger-dim) 6px, var(--night) 6px, var(--night) 12px);
}}

/* ---- Section frame ---- */
.doc-section {{ margin: var(--g8) 0; }}
.doc-section > .t-eyebrow {{ display: block; margin-bottom: var(--g2); padding-bottom: var(--g1); border-bottom: 1px solid var(--faint); }}

/* ---- Tables ---- */
.doc-table-wrap {{ overflow-x: auto; margin: var(--g5) 0; }}
table.doc-table {{ width: 100%; border-collapse: collapse; font-size: var(--fs-sm); }}
table.doc-table thead th {{
  background: var(--paper-2);
  color: var(--fg);
  text-align: left;
  font-family: var(--f-mono);
  font-weight: var(--fw-label);
  font-size: var(--fs-2xs);
  letter-spacing: 0.1em;
  text-transform: uppercase;
  padding: var(--g2) var(--g3);
  border-bottom: 1px solid var(--faint);
  white-space: nowrap;
}}
table.doc-table td {{
  padding: var(--g2) var(--g3);
  border-bottom: 1px solid var(--faint);
  font-variant-numeric: tabular-nums;
  vertical-align: top;
}}
table.doc-table tbody tr:nth-child(even) {{ background: color-mix(in srgb, var(--paper-2) 40%, transparent); }}

/* ---- Figure / blueprint canvas ---- */
figure.doc-figure {{ margin: var(--g6) 0; }}
.svgwrap {{
  background-image:
    linear-gradient(var(--faint) 1px, transparent 1px),
    linear-gradient(90deg, var(--faint) 1px, transparent 1px);
  background-size: var(--diagram-grid) var(--diagram-grid);
  background-color: var(--paper);
  border: 1px solid var(--faint);
  border-radius: var(--r-md);
  padding: var(--g4);
  overflow-x: auto;
}}
.svgwrap svg {{ display: block; max-width: 100%; height: auto; }}
figcaption.figcap {{ margin-top: var(--g3); font-size: var(--fs-sm); color: var(--ash); }}
.figure-legend {{ display: flex; flex-wrap: wrap; gap: var(--g3); margin-top: var(--g2); }}
.figure-legend-item {{ display: flex; align-items: center; gap: var(--g1); font-size: var(--fs-xs); color: var(--ash); }}

/* ---- Callouts ---- */
/* ---- Long-form document body (markdown_blocks, added 2026-08-18) ---- */
.doc-list {{
  font-family: var(--f-body);
  font-weight: var(--fw-body);
  line-height: var(--lh-loose);
  margin: var(--g3) 0;
  padding-left: var(--g5);
}}
.doc-list li {{ margin: var(--g2) 0; }}
.doc-list .doc-list {{ margin: var(--g2) 0; }}
.doc-code {{
  font-family: var(--f-mono);
  font-size: var(--fs-sm);
  line-height: var(--lh-base);
  background: var(--paper-2);
  border: 1px solid var(--faint);
  border-radius: var(--r-sm);
  padding: var(--g4);
  margin: var(--g4) 0;
  overflow-x: auto;
  white-space: pre;
}}
.t-code-inline {{
  font-family: var(--f-mono);
  font-size: 0.92em;
  background: var(--paper-2);
  border-radius: var(--r-xs);
  padding: 0.1em 0.35em;
}}
.doc-quote {{
  border-left: 3px solid var(--faint);
  padding-left: var(--g4);
  margin: var(--g4) 0;
  color: var(--ash);
}}
.doc-rule {{
  border: 0;
  border-top: 1px solid var(--faint);
  margin: var(--g6) 0;
}}
.doc-link {{ color: var(--sig); text-decoration: underline; }}
.doc-section h3, .doc-section h4, .doc-section h5, .doc-section h6 {{
  margin: var(--g5) 0 var(--g3);
}}

.callout {{
  border-left: 3px solid var(--accent);
  background: var(--paper-2);
  border-radius: 0 var(--r-sm) var(--r-sm) 0;
  padding: var(--g4);
  margin: var(--g5) 0;
}}
.callout-info {{ border-left-color: var(--sig); }}
.callout-warn {{ border-left-color: var(--warn); }}
.callout-crit {{ border-left-color: var(--danger); }}

/* ---- Verified stamp (trust footer) ---- */
.verified-stamp {{
  display: flex;
  align-items: center;
  gap: var(--g3);
  padding: var(--g5);
  margin-top: var(--g8);
  border-top: 1px solid var(--faint);
}}
/* "verified" is explicitly in KEEP's own sig state list (state_semantics.sig). */
.verified-stamp-mark {{ width: 32px; height: 32px; color: var(--sig); flex: none; }}
.verified-stamp-text {{ display: flex; flex-direction: column; gap: 2px; }}

/* ---- Theme toggle ---- */
.theme-toggle {{
  appearance: none;
  border: 1px solid var(--faint);
  background: var(--paper-2);
  color: var(--fg);
  border-radius: var(--r-pill);
  padding: 4px var(--g3);
  font-family: var(--f-mono);
  font-size: var(--fs-2xs);
  cursor: pointer;
}}

/* ---- Focus + motion guards ---- */
:focus-visible {{
  outline: 2px solid var(--sig-hi);
  outline-offset: 2px;
}}

@media (prefers-reduced-motion: reduce) {{
  *, *::before, *::after {{
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
    scroll-behavior: auto !important;
  }}
}}

@media (max-width: 768px) {{
  .masthead {{ flex-direction: column; align-items: flex-start; }}
}}
"""
