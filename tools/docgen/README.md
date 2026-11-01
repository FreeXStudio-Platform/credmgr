<!-- classification: public -->
# tools/docgen — the document build

`verified: 2026-08-17`

> Authors write Markdown; this build supplies the design, the gates, and a machine-readable
> sibling. One command turns a compliant `.md` into a self-contained offline HTML document
> styled from **KEEP** (`v2/design/tokens/keep.tokens.json`) plus a `.json` twin for agents —
> achromatic base, monospace as the system voice, colour reserved for exactly three states,
> no network reference of any kind in the output.

Where this engine came from, what was rebranded, and what was deliberately excluded:
`tools/PROVENANCE.md`. Which engine draws which picture (this one vs. `tools/visual-engine`
vs. the product's own `force-graph`): `tools/ENGINE_ROUTING_POLICY.md` — **read that first**
if you are about to make a figure.

## Usage — `cli.py` is the entry point

```bash
# Build a document: Markdown -> self-contained HTML + JSON sibling, through all 9 gates
python3 -m tools.docgen.cli build docs/blueprints/SOME_DOC.md --formats html,json

# Gate-check without emitting anything
python3 -m tools.docgen.cli check docs/blueprints/SOME_DOC.md

# Render a structural diagram (VisualSpec JSON -> SVG) to embed in a document
python3 -m tools.docgen.cli render spec.json -o figure.svg

# Print the DOC_MANIFEST registry rows
python3 -m tools.docgen.cli manifest
```

Dependency: `python3 -m pip install markdown`. No pins fetched at build time, no network.

## The rules a document must satisfy

1. **A `DOC_MANIFEST.md` row must exist** for the document's id *prefix*
   (`docs/design/doc-system/DOC_MANIFEST.md`). The `id` column holds the **prefix**
   (`BP-V2`), not a literal document id (`BP-V2-001`) — `classification.py`'s
   `_extract_prefix()` splits on the last hyphen. Gate 5 (`manifest_drift`) fails closed on a
   missing or disagreeing row; this is the single most common first-time build failure.
2. **A classification comment on line 1**: `<!-- classification: public|confidential|secret -->`.
3. **One `# Title`**, then a `### kicker · date · version` line, then one `>` lead paragraph.
4. **`## Sections`** become numbered sections with TOC entries.
5. **Figures are raw-HTML wrappers around inline SVG**:
   `<figure class="svgwrap"><svg role="img" aria-label="…">…</svg><figcaption class="figcap">Fig. N — …</figcaption></figure>`.
   The SVG is produced by one of the two engines, never hand-drawn, and the document's own
   text should name the job/spec file behind it (see `session-login-mechanism.md §6`).

## The design contract

- **Output is self-contained** — CSS inlined, fonts embedded, no CDN, no script fetch. A
  document opens correctly from a thumb drive on a machine with no network.
- **Colour is a state, never decoration.** Everything is ink/paper/grey by default; KEEP's
  three semantic states (`sig` / `warn` / `danger`) are the only hues, and each means something
  specific. **There is no "CredMgr blue" and no brand accent hue** — if you find a document or
  a token asserting one, it is wrong and predates this file (see the note below).
- Tables and wide figures scroll inside their own container; the page never scrolls sideways.
- Motion and scroll-reveal are guarded by `prefers-reduced-motion`.
- WCAG-AA contrast is gated, not assumed — `export_sanitizer.py` carries real computed ratios.

## Note — the legacy v1.0 path was removed 2026-08-17

An earlier `build.py` + `template.html` pair (plus `AUTHORING_PROMPT.md` and `gallery.md`,
its component showcase) shipped in the original copy of this engine and was **deleted**: it
was dead code — nothing in the live pipeline referenced it — and `template.html` still carried
the upstream project's own brand-blue tokens (`--ah`, `#1E3A6E`/`#4A7FC1`). Worse, the port's
first rebranding sweep had mechanically renamed that palette's *description* from the upstream's
name to "CredMgr blue", inventing a brand fact this project does not have and KEEP explicitly
forbids. Deleting the path was the correct fix rather than recolouring a file nothing loads.
Resurrection, if ever needed, is `git log`.
