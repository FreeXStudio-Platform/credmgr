<!-- classification: INTERNAL -->

# Reskinning and theme policy

### appearance may change, semantics may not · 2026-08-08 · v1.0.0

**Authority chain:** KEEP `v2/design/tokens/keep.tokens.json` →
`tools/docgen/assets/tokens.json` (mirrored copy, see `tools/PROVENANCE.md`) →
`adapters/echarts/theme-adapter.mjs` → `themes/*.json`
(GENERATED — never hand-edit; `npm run build:themes` after editing KEEP's own file).

- Four approved themes: `project-theme` (dark, native), `project-theme-dark`,
  `project-theme-light`, `print-theme`. Agents never invent colors, fonts, or
  new themes.
- **Categorical palette is achromatic** — a six-step lightness ramp (bone,
  ash, mute, steel-3, steel-2, faint), `--sig-hi` as the lone single-series
  accent. Not a multi-hue palette: KEEP reserves colour for exactly three
  states and treats anything else as decorative (`identity.principles` in
  the token source). Max 6 series — same cap as the pie law.
- **Signal palette is semantic, not decorative**: sig `#3E9C86` (healthy/
  verified) · warn `#B0812E` (attention) · danger `#B3373A`. Used only where
  one of those three states is the actual meaning (preset
  `semantics.severity_items` maps `severity: "critical"` to danger and
  nothing else — KEEP's own `state_semantics` table, verbatim).
- Heat ramp: steel-2 → sig-dim → sig-hi — derived from the same token file,
  identical to docgen charts.py.
- Fonts: Inter (body + display), JetBrains Mono (numerals/labels) — exactly
  KEEP's own `--f-display`/`--f-body`/`--f-mono` stack, no third display face.

**The reskin law (spec §15.6):** a theme/reskin may alter color, typography,
stroke, spacing, background, legend, framing, emphasis. It may NOT alter data,
grouping, series membership, axis scale, units, sort meaning, thresholds,
severity mapping, category identity, edge direction, missing-data meaning, or
uncertainty. Enforced by the semantic checksum: `option_sha256` is computed on
the option AFTER theme application only via ECharts' theme registry (themes
never touch `series[].data`), and the reskin regression test renders the same
job under all four themes and asserts identical decoded data series.
