# tools/visual-engine + tools/docgen — provenance and derivation record

`verified: 2026-08-17`

`tools/visual-engine` (Apache ECharts 6.1.0, SSR data-chart renderer) and `tools/docgen`
(Python, document/structural-diagram renderer) were derived, on operator instruction, from
an upstream project's own visualization engine and document-build system — the same
upstream project `v2/design/PROVENANCE.md` already records as KEEP's own origin. This file
is that document's sibling for the *tooling*, not the design tokens; read both together.

## Read this first — what "derived" means here

| Kind | What | Obligation |
|---|---|---|
| **Full source copy** | Every file under `tools/visual-engine/` and `tools/docgen/` except `node_modules/`, `__pycache__/`, and build output (`renders/`, `evidence/`, `_out/`, `demo/*.html`) | Copied whole, then rebranded and reworked in place — not a reference-only snapshot. This *is* the shipped tool. |
| **Rebranded, not merely renamed** | Every string, filename, preset, and code path naming the source project or its own domain concepts (its product's vulnerability-detector taxonomy, its subscription tiers, its logo) | Removed or replaced with a CredMgr-appropriate equivalent — see "What was rewritten," below. A `grep -ri` for the source project's name across both trees (excluding `node_modules`) returns nothing. |
| **Excluded outright** | The source project's own logo (`ah-mark.svg`), its attack-pattern animation library (`assets/animations/*` — reentrancy/sandwich/bridge-drain/etc.), its `Space Grotesk` display font (KEEP already rejects this face — `v2/design/PROVENANCE.md`), its own domain-specific linter (`bank_doc_lint.py`) | Never copied into the working tree at all, or deleted immediately after the initial copy — not disguised, not kept "just in case." |

## Source read (the upstream project — read-only, nothing written back)

| Upstream path | Used for |
|---|---|
| `tools/visual-engine/` (the whole tree) | The ECharts SSR adapter, its validated job schema, its gate system (G-STRUCT/G-SEC/G-SIZE/G-CHART/G-CONF/G-ROUTE), its preset library shape, and its MCP facade. |
| `tools/docgen/` (the whole tree) | The Markdown -> self-contained-HTML document build, its 9-gate leak sanitizer, its structural-diagram renderers (bar/heatmap/radar/pie/timeline/sankey/geo-map/isometric/sequence/flowchart), its `DOC_MANIFEST.md`/header-drift validation, and its WCAG-AA contrast gate. |

## What was rewritten, and why

- **Every brand/domain string.** `Upstream`/`upstream` -> `CredMgr`/`credmgr` throughout;
  the vulnerability-`detector` vocabulary -> generic `op`/`finding` vocabulary in preset ids,
  fixture data, and the acceptance-simulation script; `gatekeeper` -> `ci-gate`. The package
  identity (`@upstream/visual-engine` -> `@credmgr/visual-engine`), the MCP tool names, and
  every doc title were renamed to match.
- **The design-token bridge.** `tools/docgen/assets/tokens.json` used to mirror the upstream
  project's own "Atlas" brand tokens (`shield`/`bronze`/`gold`/`ember`/`verify`, a six-level
  severity lattice). It now mirrors **KEEP** (`v2/design/tokens/keep.tokens.json`) — same file
  shape (`grounds_dark`/`inks_dark`/`fonts`/`weights`/...), one addition (`diagram.grid`, a
  docgen-only canvas-grid pitch KEEP's own token file has no reason to carry). Both
  `theme-adapter.mjs` (ECharts) and `tokens.py` (docgen's CSS emitter) were rewritten against
  the new shape, not merely re-pointed at a renamed file.
- **The categorical/heat palettes.** KEEP is achromatic by default — colour is reserved for
  exactly three states (`sig`/`warn`/`danger`, `identity.principles` in the token source) and
  is never decorative (`v2/design/tokens/keep.tokens.json`). The old six-hue categorical
  palette (`shield-hi`/`bronze-hi`/`gold-hi`/`verify`/`ember-hi`/`shield-dim`) is now an
  achromatic lightness ramp (`bone`/`ash`/`mute`/`steel-3`/`steel-2`/`faint`); the heat ramp
  is `steel-2 -> sig-dim -> sig-hi`. This is a *design decision*, not a mechanical
  substitution — see `RESKINNING_AND_THEME_POLICY.md` for the full reasoning.
- **The severity-color mapping.** The old six-level lattice (`crit`/`high`/`med`/`med-hi`/
  `low`/`info`) collapses to KEEP's own `state_semantics.danger` rule, verbatim:
  `severity: "critical"` maps to `danger`; every other severity level renders achromatic,
  because KEEP's own token source explicitly lists "sensitivity low/medium/high" under
  `none` — this was not invented for the port, it was already decided.
- **The classification-badge/verified-stamp/callout/focus-ring colors** (docgen's
  `tokens.py`) — remapped onto the same three-state law: PUBLIC achromatic, CONFIDENTIAL
  warn, SECRET danger; the verified-stamp mark uses `sig` because "verified" is explicitly in
  KEEP's own `sig` state list.
- **The WCAG-AA contrast baseline** (`export_sanitizer.py`'s `_DEFAULT_CONTRAST_PAIRS`) —
  recomputed against KEEP's real hex values (not assumed): every pairing re-verified via the
  WCAG relative-luminance formula, all >= 4.5:1. Ratios recorded inline as comments.
- **The fonts.** Space Grotesk removed outright (KEEP already rejects it as the display face
  — `v2/design/PROVENANCE.md`). Inter and JetBrains Mono kept unchanged: they are the exact
  two families KEEP's own `--f-display`/`--f-body`/`--f-mono` already specify, OFL-licensed,
  not the source project's brand asset.
- **The logo.** `assets/ah-mark.svg` deleted, not rebranded — CredMgr's own mark is still an
  open design task (`CredMgr-V2-Design/04_CLAUDE_DESIGN_PROMPT_STRICT.md`), so inventing a
  permanent one here would prejudge that work. `docgen`'s masthead now points at
  `assets/keep-mark-placeholder.svg`, explicitly labeled as provisional in its own file and
  in the code that loads it (`components.py`) — replace in place, no code change needed,
  once the real mark exists.
- **The acceptance-simulation content** (`tools/visual-engine/tests/run_simulations.mjs`,
  22 required simulations). Every simulation that exercised real domain data now uses real
  CredMgr facts, cited to their source, not placeholder text: crate test-tier counts
  (`cargo test --workspace`, 2026-08-17), the session/login funnel (ADR-056), the V2
  build-phase DAG (`docs/12_BUILD_PLAN.md`), the Phase 8 incident timeline (`BUILD_LOG.md`
  Session 16 / ADR-053), the Lite/Pro entitlement matrix (ADR-031), and the real crate
  dependency graph (verified against the workspace's own `Cargo.toml` files). Simulations
  that exist purely to exercise renderer mechanics (dense-scatter performance, malformed-
  input rejection, export-format checks) keep illustrative placeholder data, because no real
  CredMgr number would mean anything there — each says so in its own comment.

## What was deliberately not ported

- **The upstream project's own domain content**: its logo, its attack-pattern animation
  library, its "bank" document linter, its detector/gatekeeper/tier-entitlement preset
  *data* (the preset *shapes* — a status matrix, a severity/confidence scatter, a stage-
  reconciliation funnel — are generic and were kept, renamed, and re-described).
- **Its own test fixtures and golden renders.** `fixtures/normal/detector-coverage-heatmap.json`
  and every file under `renders/golden/`, `renders/current/`, and `evidence/` were deleted,
  not rebranded — they are outputs of *their* data, not CredMgr's. Fresh CredMgr goldens were
  generated by `npm run simulate` against the rewritten simulation script.
- **Its own doc-system test suite.** The source project's `tests/docgen/*.py` live outside
  `tools/docgen/` at its own repo root, so nothing came across with the copied tree and that
  upstream suite was never ported. `tools/visual-engine/tests/` *is* fully ported (it lives
  inside the copied tree) and is green (30/30 unit tests, 22/22 acceptance simulations). The
  follow-up work this section originally named — porting the Python suite too — was instead
  closed by **writing a CredMgr-original one**: `tools/docgen/tests/` (`test_doc_outline.py`,
  `test_generator_build.py`, `test_markdown_blocks.py`; added 2026-08-18 in `280a6fe` and
  `7ffaf40`), stdlib `unittest` only, so it needs no dependency this repo does not already
  have. Run it from the repo root with
  `python3 -m unittest discover -s tools/docgen/tests -t .` — **52 tests, `OK`, exit 0**
  (`verified: 2026-09-13`). `tools/docgen`'s correctness is also demonstrated directly: a real
  document (`docs/blueprints/session-login-mechanism.md`) built clean through the full 9-gate
  pipeline, `ok: true`, zero findings — still true, and still not sufficient on its own, which
  is exactly why those tests assert the artifact rather than the gate (see the `2026-08-17`
  (second) correction below).

## Correction, `2026-08-17` (second) — "built clean through the full 9-gate pipeline" was true but misleading

The "What was deliberately not ported" section below says `docgen`'s correctness is
"demonstrated directly: a real document … built clean through the full 9-gate pipeline,
`ok: true`, zero findings." **The gate result was real; the document was not correct.** Its one
figure had been authored as a raw `<figure class="svgwrap">` HTML block, which `docgen`'s
generator escapes rather than passes through (`generator.py:203-205`, deliberate fail-closed
behaviour) — so the figure shipped as visible escaped SVG source, and every gate still passed,
because no gate asserts that a figure rendered.

Found by an adversarial documentation sweep the same day, then fixed at the source: the document
now uses `docgen`'s real mechanism (a `<!-- figure:ID -->` directive plus a
`session-login-mechanism_spec.json` sibling with `"kind": "echarts"`), and the rebuilt HTML
carries 1 real `<figure>`, 3 `<svg>` elements, and 0 escaped ones, still `ok: true` with zero
findings. `tools/ENGINE_ROUTING_POLICY.md` — which had prescribed the wrong workflow in its own
router table — was corrected too, and now carries the verification commands.

**The transferable lesson, recorded because it will recur:** a green gate is evidence that the
gates passed, never that the artifact is right. The gates here check leakage, drift, and
contrast — none of them check "did the picture appear." Grep the *output*.

## Correction, `2026-08-17` (first) — the font sweep was incomplete on first pass

The "What was rewritten" section above claims Space Grotesk was "removed outright." That was
true for `tools/docgen`'s Python side (`fonts.py`) but **not fully true for
`tools/visual-engine`**: `adapters/echarts/html-template.mjs` — the standalone-HTML export
wrapper, a code path the original port's proof document never exercised (it only produced an
SVG embedded in a docgen-built page, not a standalone `visual-engine` HTML render) — still
hardcoded `font-family: "Space Grotesk"` on its own `h1` rule, independent of `theme-adapter.mjs`
(which was correctly fixed). Found when generating the first real standalone-HTML blueprint
(`renders/golden/BP-graph-node-radius.{job.json,svg,html}`) and grepping its output for
residue — the earlier "grep -rli returns nothing" claim was accurate against the *source tree*
but this bug only manifests in *rendered output*, which the original sweep didn't include.
Fixed in place (now `"Inter"`, matching the rest of the theme); full `npm test` re-run clean
(30/30) after the fix. Recorded here rather than silently corrected, per this project's own
fact-verification discipline — a provenance claim that turns out incomplete gets fixed and
noted, not quietly patched over.

## Cross-project note

Reading the upstream project is always permitted (portfolio rule: read anywhere). **Nothing
was written into it during this port** — verified before and after via `git status` in that
project's own repository, both times clean. Everything above lives entirely inside
`Projects/CredMgr/`.
