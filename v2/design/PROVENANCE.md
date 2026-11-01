# KEEP — provenance and derivation record

`verified: 2026-08-04`

KEEP is the design system for **CredMgr V2 (Vault Next)**. It was derived, on operator
instruction, from the **the upstream design system** project's document design system and its graph engine.
This file records exactly what was taken, what was deliberately *not* taken, and how to
re-derive if the upstream changes.

## Read this first — what "derived" means here

Two different things were copied, and they carry different obligations:

| Kind | What | Obligation |
|---|---|---|
| **Verbatim vendored code** | `graph-engine/force-graph.min.js` | Third-party MIT library. Checksum-pinned below. Never edited in place. |
| **Extracted structure** | token architecture, layout rules, component vocabulary, B/W discipline | Re-authored for CredMgr. No upstream value survives unchanged except where noted. |
| **Reference-only copies** | every file prefixed `_reference-` | Kept for comparison while building V2. **Not shipped.** Delete before v2.0.0 tags. |

## Source files read (the upstream design system — read-only, nothing written back)

| Upstream path | Used for |
|---|---|
| `design/atlas/tokens/brand.css` | The four-layer token architecture; the "grounds / inks / accent" naming split; the near-black ground discipline |
| `design/atlas/tokens/scale.css` | 8px spacing rhythm; the "never a raw px in component CSS" rule; type-scale-by-optical-role naming |
| `design/atlas/tokens/easing.css` | The closed easing table + "custom easings are forbidden outside this file" rule |
| `design/atlas/tokens/depth.css` | *Studied, not used.* Its scroll-driven depth arc is narrative-site machinery with no place in a utility app. |
| `design/atlas/print.css` | Print/theme parity approach |
| `tools/docgen/template.html` | **The B/W document template** — the operator's "black-and-white template system". Layout grid, sticky TOC, section numbering, stat grid, `.svgwrap` blueprint canvas, note/callout, badge, steps, containment rules |
| `tools/docgen/assets/tokens.json` | The token-JSON-as-source-of-truth pattern that `keep.tokens.json` follows |
| `tools/docgen/tokens.py` | The self-contained-stylesheet emitter pattern (fonts inlined, no `@import`, no CDN) |
| `tools/docgen/charts.py`, `visual.py`, `diagram_graphs.py` | **The chart/diagram engine.** Studied for its geometry contract: collision checking before render, minimum node gaps, deterministic output, `currentColor` strokes so a diagram reads in both themes. KEEP adopts the *contract*; it does not port the Python. |
| `docs/design/doc-system/DESIGN_SYSTEM.md` | The dual-theme + no-overlap + containment rulebook |
| `tools/graphify/graph-view.html` | **The graph viewer pattern** — vendored engine, data-file loader, degree-scaled node size, zoom-gated labels, click-to-focus, search-to-focus, fit-to-view |
| `tools/graphify/vendor/force-graph.min.js` | Vendored verbatim (see below) |

## Vendored third-party code

| File | Upstream | Bytes | sha384 | Verified |
|---|---|---|---|---|
| `graph-engine/force-graph.min.js` | `https://unpkg.com/force-graph@1/dist/force-graph.min.js` | 177599 | `1e6e86a50713348e55a868064bb94bc531ad105731bbf90e555d01ee8cc8651bbd6e5595be282fe61b6d250676a99998` | 2026-08-04, matched against the upstream project's own PROVENANCE record |

`force-graph` is MIT-licensed (Vasco Asturiano). It is vendored — **never loaded from a CDN** —
because CredMgr must render identically offline, inside the WKWebView shell, and with a
content-security-policy that forbids remote script. To update: re-download the pinned URL,
diff size + sha384, review the diff, bump this table.

> **The 3D mode is not adopted.** The upstream reference viewer lazy-loads `3d-force-graph`
> from unpkg at runtime. That is a live CDN dependency inside a credential manager and is
> forbidden here. V2 is 2D-only. If 3D is ever wanted it must be vendored the same way.

## What was deliberately NOT taken

The upstream project's **brand** belongs to that project. None of the following appears anywhere in KEEP, and
no future session may reintroduce them:

- The **eye mark** (`ah-mark.svg`), the wordmark, or any lockup.
- The colours `--shield` `#1E3A6E`, `--bronze` `#6B4A18`, `--gold` `#B08848`, `--ember`,
  and the five-step severity lattice built from them.
- `Space Grotesk` as the display face (it reads as the upstream design system).
- The Act/depth narrative system, the "Verified by the upstream design system" stamp, the classification
  badge taxonomy (PUBLIC/CONFIDENTIAL/SECRET), the motif SVGs.
- Any the upstream design system document text, naming, or `docs/` structure.

KEEP's own identity is stated in `tokens/keep.tokens.json → identity`:
achromatic base, three state colours, sealed-is-colourless, mono as the vault's voice.

## Re-derivation

If an internal design system changes and KEEP should follow, the only legitimate inheritance is
**structural**: a new token layer, a new containment rule, a new component archetype.
Copying a value is drift. Record any re-derivation as a row here with a date.

## Cross-project note

Reading the upstream design system is always permitted (portfolio rule: read anywhere). **Nothing was
written into the upstream design system during this extraction** — verified: only `cp` out, never in.
KEEP lives entirely inside `Projects/CredMgr/V2/`.
