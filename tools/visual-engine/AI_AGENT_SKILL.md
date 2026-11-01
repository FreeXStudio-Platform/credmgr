<!-- classification: INTERNAL -->

# AI agent skill — CredMgr visualization engine

### how any agent renders a correct, project-styled visual · 2026-08-08 · v1.0.0

> You are an **orchestrator, not a chart renderer**. You select the visual and
> submit a compact structured job; the approved engine renders it in the
> project's design system. You do not hand-write ECharts options, HTML
> boilerplate, themes, or accessibility wrappers for routine charts — that
> code lives here once, validated (token-efficiency rule, spec §32).

## The mandatory loop

```text
UNDERSTAND QUESTION            what must the reader be able to answer?
→ LOAD PROJECT CHART KNOWLEDGE knowledge/CHART_USE_CASE_CATALOG.json (+ decision tree)
→ INSPECT DATA SHAPE           table | items | matrix | flow | graph | tree | events
→ SELECT OR REJECT VISUAL      NO_CHART is a first-class outcome (§18)
→ BUILD NORMALIZED VISUAL JOB  schemas/visual-job.schema.json
→ ROUTE TO APPROVED ENGINE     ENGINE_ROUTING_POLICY.json (docgen? echarts? refuse?)
→ RENDER                       MCP visual_render OR adapters/echarts/cli.mjs
→ PROJECT THEME APPLIED        automatic — never restyle by hand
→ VALIDATE SEMANTICS           values reconcile, unknowns visible, no anti-pattern
→ VALIDATE A11Y/EXPORT         text_summary present, static equivalent exists
→ STORE SPEC + EVIDENCE        evidence/validation/<visual_id>.json (Gate G9)
```

## Which engine — the 10-second router

| The visual is… | Engine | How |
|---|---|---|
| Architecture, workflow, state, sequence, dependency, 2.5D/3D, geo, motion — **document-grade diagram** | **tools/docgen** (authoritative) | `VisualSpec` → `python -m tools.docgen.cli render` |
| Quantitative **data chart** (compare, trend, distribute, relate, compose, flow, matrix, hierarchy, status) | **this engine** (echarts 6.1.0, pinned) | MCP `visual_render` or `node tools/visual-engine/adapters/echarts/cli.mjs render job.json --formats svg,png,html --evidence` |
| Product app UI | frontend Recharts | not this engine's scope |
| Exact values, 1–2 numbers, procedural logic | **NO_CHART** | `selected_visual: "none"` + `no_chart_reason` |

Unsure? Call MCP `visual_explain_selection` with your draft job.

## Minimal job packet (full schema: `schemas/visual-job.schema.json`)

```json
{
  "visual_id": "VIS-DET-001",
  "reader_question": "Which crates lean most on unit tests, with the least real-broker coverage?",
  "classification": "internal",
  "selected_visual": "heatmap",
  "preset": "crate-test-coverage-heatmap",
  "title": "Detector coverage by family",
  "units": ["percent"], "scale_min": 0, "scale_max": 100,
  "text_summary": "Access-control coverage sits at 45%; flashloan regression is untested at 20%.",
  "data": { "rows": ["reentrancy", "…"], "cols": ["unit", "…"], "matrix": [[92, 88], [45, 40]] }
}
```

Prefer a **preset** (`presets/` — 22 project presets, `visual_list_presets`)
over a bare visual: presets carry the reviewed defaults and semantics.

## Laws that will fail your job (fail-closed, with gate ids)

- `G-CONF` — `classification: "restricted"` never renders via MCP; direct adapter needs explicit human-approved `allowRestricted`.
- `G-SEC` — no scripts, functions, event handlers, or external URLs anywhere in data/title/units.
- `G-SIZE` — ≤50k cells, ≤1.5k nodes, ≤4000px. Aggregate first; a denser chart answers no question.
- `G-CHART` — pie ≤6 slices; bar zero-baseline; radar ≥3 axes; sankey flows positive+conserved; heatmap always gets its scale legend.
- Anti-patterns (`knowledge/CHART_ANTI_PATTERNS.json`): no 3D decoration, no dual axes, no force layouts, no aggregate health percentages (T-R3).

## Non-negotiables carried from project law

- **Reskin may change appearance, never semantics** (RESKINNING_AND_THEME_POLICY.md). Themes are the four approved ones; you never invent colors.
- **SVG is canonical**; PNG is convenience; interactive HTML is self-contained with a static reduced-motion/print fallback (EXPORT_POLICY.md).
- **Evidence per render** — pass `--evidence` (CLI) or use MCP (automatic). A visual without evidence does not enter a source-of-truth document (Gate G9, T-R2).
- **`text_summary` is required** before a visual ships in a document (Gate G7).
- Data for public/commercial surfaces comes from **sanitized sources only** (§31).

## When to research instead of render

Consult `knowledge/CHART_USE_CASE_CATALOG.json` first. Browse the internet only
when the case is missing, stale (past `review_due`), unusual, or high-stakes —
then add what you learned to the catalog with a source + date
(`knowledge/SOURCE_REGISTRY.json`). Do not re-derive chart-selection theory
per chart.

## Worked examples

1. **Standard chart** — fixtures/normal/crate-test-coverage-heatmap.json → heatmap preset, svg+png.
2. **Workflow diagram** — REJECT here; route to docgen (`explain_selection` says so).
3. **Current-vs-destination** — `current-target-conformance` preset; never blend current and target in one cell.
4. **Interactive** — same job, `formats: ["svg","html"]`; HTML is self-contained with static fallback.
5. **Print** — same job, `theme: "print-theme"`, embed the SVG.
6. **Rejected** — "make a 3D pie of two numbers" → `selected_visual: "none"`, `no_chart_reason: "two exact values; metric card"`.
