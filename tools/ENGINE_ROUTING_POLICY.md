# Engine routing policy — which system draws which picture

`verified: 2026-08-17` · applies portfolio-wide to `<local checkout>`
(`v1/`, `v2/`, and this `tools/` tree)

Four systems can produce a visual in this project. Each has a real, different job; none of
them can safely substitute for another. Picking the wrong one for a given request is the
most likely way this pipeline degrades into duplicate or contradictory output.

## The four-second router

| The visual is… | Engine | How |
|---|---|---|
| A **document-grade structural diagram** — architecture, workflow, dependency, sequence, state, a system/blueprint map | **`tools/docgen`** (authoritative) | Put a `<!-- figure:ID -->` directive in the `.md` and the spec in its sibling `<stem>_spec.json` (see "How a figure actually gets into a document," below) |
| A **quantitative data chart** — compare, trend, distribute, relate, compose, flow, matrix, hierarchy, status | **`tools/visual-engine`** (ECharts 6.1.0, pinned) | Standalone: `node tools/visual-engine/adapters/echarts/cli.mjs render job.json --formats svg,png,html`. **Inside a document**: the same job packet under `"kind": "echarts"` in the sibling spec — docgen calls the engine for you |
| The **product's own in-app node graph** — the live, draggable, zoomable vault-topology screen an end user sees inside the CredMgr V2 app itself | **`force-graph`** (vendored, checksum-pinned) | Already decided, already shipped in the design brief — `v2/design/graph-engine/`, `ADR-022`, `v2/design/PROVENANCE.md`. Not reopened by this policy. |
| A **one-off, ephemeral, in-conversation visual** — something to look at right now, never saved as a project document | The assistant's own `visualize`/Artifact tooling | Fine for a quick answer; never the source for a document under `docs/` — those go through one of the three engines above so they are extractable, regenerable, and linked, not throwaway. |

Unsure which of the first two applies? `tools/visual-engine/AI_AGENT_SKILL.md §"Which
engine"` has the same table with worked examples; call MCP `visual_explain_selection` with a
draft job if a specific case is ambiguous.

## How a figure actually gets into a document — the one mechanism that works

**Corrected `2026-08-17`.** This section previously told you to render an SVG and paste it into
the Markdown inside a `<figure class="svgwrap">` block. **That silently does not work**:
docgen's generator escapes unrecognised raw HTML rather than passing it through
(`generator.py:203-205`, deliberate — "never emit raw unescaped user Markdown as HTML"), so the
figure ships as visible escaped source code and the build still reports `ok: true`. It was
wrong in this file, and the project's first real document shipped broken because of it, gate-green
the whole time. **Failing loudly would have been better; assume nothing until you grep the output.**

The real mechanism is a directive plus a sibling spec file:

1. In the `.md`, at the point the figure belongs:
   ```markdown
   <!-- figure:login-funnel -->
   ```
2. Beside it, `<stem>_spec.json` — one object, or an array for several figures. Each object's
   `kind` selects the renderer: `flowchart` (default), `sequence`, `sankey`, `geo_map`,
   `isometric`, or **`echarts`** for a quantitative chart, whose `job` field takes a
   visual-engine job packet verbatim and is rendered through the engine by `echarts_bridge`.
   ```jsonc
   { "kind": "echarts", "id": "login-funnel", "caption": "…",
     "job": { "visual_id": "…", "selected_visual": "funnel", "data": { "items": [...] } } }
   ```
3. Build normally. docgen calls the engine, wraps the returned SVG in its own `figure`
   component, and attaches the caption and any legend.

**Verify, do not assume** — the build reporting `ok: true` does not mean the figure rendered:

```bash
grep -c '<figure'  docs/blueprints/YOUR_DOC.html   # must be >= 1
grep -c '&lt;svg'  docs/blueprints/YOUR_DOC.html   # must be 0
```

Worked example: `docs/blueprints/session-login-mechanism.{md,_spec.json,html}`.

## Why three separate systems, not one

No single library does all four rows well. `docgen`'s own hard rule (`AI_AGENT_SKILL.md`) is
explicit: **it does not render quantitative charts**, and `visual-engine`'s own rule is the
mirror image — **it does not render document-grade diagrams** (`ENGINE_MANIFEST.json`,
`ENGINE_ROUTING_POLICY.json`). `force-graph` is a different thing again: an *interactive UI
feature* a real user drags and zooms, not a static document illustration — it is judged on
"does it feel alive in the running app," not "is it byte-identical across regenerations,"
which is `docgen`/`visual-engine`'s own defining requirement (`README.md`: "same job + same
pins => byte-identical SVG… no force layouts"). Forcing one engine to cover another's job
would mean either giving up determinism (document tooling) or giving up interactivity (the
product feature) — neither is acceptable, so the boundary stays where it already was in the
system this was ported from.

## "Locked to reality" — what that means operationally

A chart or diagram under `docs/` is not hand-drawn. It is:

1. A structured job/spec file (`visual-job.schema.json` for `visual-engine`, `VisualSpec` for
   `docgen`) whose `data`/`text_summary` cites a real source — a command's real output, a
   file, a test run, an ADR. Not an LLM's free-hand guess at plausible numbers.
2. Rendered deterministically by one of the two engines above. Re-running the same job
   against the same tool version produces byte-identical output (`visual-engine`'s own
   regression gate enforces this; `docgen`'s "build-twice determinism" test does the same).
3. Saved as its own file (`.job.json`/`VisualSpec` JSON *and* the rendered `.svg`/`.html`),
   separate from but linked to the document that embeds it — so the picture can be
   regenerated, diffed, or reused without re-deriving it from a conversation.
4. Zero LLM tokens to reproduce. Once the job/spec file exists, `npm run render` /
   `python3 -m tools.docgen.cli render` regenerates the exact same output for free, forever
   — the expensive step (deciding what the chart should say) happens once, not on every view.

## Documents + blueprints: one pair per subject, explicitly linked

Convention for anything built under `docs/` going forward: a document (`.md` -> `.html` via
`docgen build --formats html,json`) names, in its own text, the job/spec file(s) behind each
figure it embeds (see `docs/blueprints/session-login-mechanism.md §6`, "Source," for the
pattern). The job file lives beside the rendered output under the producing engine's own
`renders/golden/` (regression-pinned) or a project-specific `docs/blueprints/` companion
directory — never only inline in the document's own HTML, so the underlying data survives a
re-theme or a re-render independent of the prose around it.

## What is not decided here

- **Where blueprint JSON/SVG pairs live long-term** (a per-document sibling folder vs. a
  central `docs/blueprints/_jobs/` registry) — `docs/blueprints/session-login-mechanism.md`
  is this policy's first real instance; the convention above is provisional until a second
  and third document prove it out.
- **A `docgen`-rendered (not `visual-engine`-rendered) figure has not yet been produced for
  this project** — `tools/docgen`'s structural renderers are ported and unit-verified only
  indirectly (via the full document build's own gates), not yet exercised end to end for a
  CredMgr-specific `VisualSpec`. Named as the natural next proof, not silently claimed done.
