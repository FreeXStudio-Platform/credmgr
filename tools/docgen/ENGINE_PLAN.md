<!-- classification: public -->
<!-- Defensive security documentation: protects the CredMgr platform and its customers. -->
<!-- HISTORICAL — this is the plan the original build session followed, kept as build
     history, not current fact. It predates the port into this repo: "the Atlas" and
     "eye-mark" below refer to the *source* project's own tokens/logo, since replaced
     by KEEP and a placeholder mark respectively — see tools/PROVENANCE.md for what
     changed and why. Do not treat this file's asset/token references as current. -->
# doc-system ENGINE — build plan (the machine that obeys the rulebook)

> Builds everything the rulebook/calibration requires **except the docs themselves**: the token-driven multiformat
> generator, the 9-gate leak sanitizer, the visual-spec renderer (glyphs + motion + collision), the schemas, the
> DOC_MANIFEST reader, the guarded fact-fetcher, the hash-gate, the CLI, and the tests. Python 3.11, ruff, mypy-strict,
> pytest. Home: `tools/docgen/`. Design authority: the Atlas (`DESIGN_SYSTEM.md §1–2`). Rules: `../../docs/design/doc-system/`.

## 0. The 10/10 bar (definition of done — every item must be TRUE + demonstrated)
1. `docgen build sample.md` emits a **self-contained** HTML (inline CSS from Atlas tokens, inline eye-mark, embedded rendered SVG), dark+light toggle, no external refs.
2. The **leak-gate** actually BLOCKS: a planted secret value, a planted implementation-internal/threshold, a non-public tier on an export path, and a variant-overlap span (Gate 9). Proven by tests.
3. The **visual renderer** turns a `visual_spec.json` into valid SVG: glyph-per-node, edges routed around nodes, legend+caption, the dot rides the path at constant 120px/s (build-time arc-length keyPoints/keyTimes, ±5% asserted), dot under nodes, node light-up, fan-out split, branch alternation, reduced-motion static fallback, **collision validator fails the render** on overlap.
4. **Schemas** (header, visual_spec, export_manifest, doc_manifest) validate real instances; bad instances rejected.
5. `docgen check` runs the **hash-gate** (locked-rule edit without a VERSION bump → non-zero exit) + manifest consistency.
6. `pytest tests/docgen/` green; `ruff` + `mypy --strict` clean on `tools/docgen/`.
7. Honest: anything stubbed (e.g. PDF if weasyprint absent) degrades gracefully + is logged, never silently faked.

## 1. Module map + CONTRACTS (fixed here; builders implement to these — no interface drift)
All shared types live in `models.py` (I author it first). Every module imports from it.

| Module | Responsibility | Key public API (exact) |
|---|---|---|
| `models.py` | shared dataclasses + enums | `DocHeader`, `Tier`, `Surface`, `VisualSpec`, `Node`, `Edge`, `Legend`, `GateResult`, `Finding`, `ManifestRow`, `BuildResult`, `Fact` |
| `tokens.py` | Atlas tokens → CSS | `TOKENS: dict`, `build_css() -> str` (dark+light+brand+`.t-*` roles) |
| `classification.py` | header parse+validate (L2/L3/L5/L14) | `parse_header(md: str) -> DocHeader`, `validate_header(h: DocHeader) -> list[Finding]` |
| `leak_gate.py` | the 9 gates (L4/L6 + Gate 9) | `run_gates(md: str, header: DocHeader, *, siblings: list[str]|None=None) -> GateResult`; `SECRET_PATTERNS`, `DETECTOR_INTERNAL_PATTERNS`, `shingle_overlap(a,b,n=8) -> list[str]` |
| `visual.py` | visual_spec → SVG (+ motion) | `render(spec: VisualSpec, *, theme:str="dark") -> str`; `check_collisions(spec) -> list[Finding]`; `arc_length_keytimes(d: str, n:int=64) -> tuple[list[float],list[float]]` |
| `components.py` | HTML partials | `masthead(header)`, `classification_badge(tier)`, `section(eyebrow, body)`, `data_table(...)`, `figure(svg, caption, legend)`, `callout(...)`, `theme_toggle()`, `logo_svg()`, `verified_stamp(audit_ref)` |
| `generator.py` | MD → HTML/JSON(/PDF) | `build(md_path: Path, *, formats=("html",)) -> BuildResult` (runs gate first; blocks on fail for public) |
| `doc_manifest.py` | DOC_MANIFEST.md reader | `read_manifest(path: Path) -> list[ManifestRow]` |
| `fetch_public_fact.py` | SSRF-guarded fetch (KB-005) | `fetch(url:str, *, allowlist:set[str]) -> Fact` (blocks private IPs/redirects/non-allowlisted hosts) |
| `hash_gate.py` | VERSION.json rule hash-gate | `check(rules_dir: Path, version_json: Path) -> GateResult`; `compute_hash(files) -> str` |
| `cli.py` | argparse entry | subcommands `build|gate|render|check|manifest`; exit non-zero on gate fail |

Assets: `assets/tokens.json` (from Atlas brand.css+scale.css), `assets/ah-mark.svg` (the real eye mark), `assets/glyphs.py` (the node-shape SVG library), `assets/animations/` (6 reusable exploit-flow specs: bridge-drain, brute-force, sandwich, manipulation, double-spend, reentrancy). Schemas in `schemas/`. Tests in `../../tests/docgen/`. `README.md`.

## 2. Build waves (Opus orchestrates, Sonnet builds against the contracts above)
- **Wave 0 (me, Opus):** `models.py` + `assets/ah-mark.svg` + `assets/tokens.json` (from Atlas) + this plan. The integration backbone.
- **Wave 1 (parallel Sonnet builders — leaf modules, no cross-deps):**
  - **B1:** `schemas/*.json` (4) + `classification.py` + `doc_manifest.py` + their tests.
  - **B2:** `leak_gate.py` (9 gates incl. Gate 9 shingle-overlap; credential/token pattern dialect originally from a since-retired internal rule set, + implementation-internal net) + tests that PROVE blocking.
  - **B3:** `visual.py` + `assets/glyphs.py` + arc-length motion + collision validator + reduced-motion + 2 example specs + tests.
  - **B4:** `tokens.py` (build_css from assets/tokens.json) + `components.py` (incl. eye `logo_svg` + `verified_stamp` + `theme_toggle`) + `fetch_public_fact.py` + `hash_gate.py` + tests.
- **Wave 2 (me, Opus — integration):** `generator.py` + `cli.py` composing Wave-1; wire the gate-before-emit; a real `sample.md` + `sample_spec.json`; then RUN everything, fix integration, get pytest+ruff+mypy green.

## 3. Deep-verification / gaps to hunt (fold the verifier's findings before Wave 1)
Open questions the plan must not leave empty (the adversarial pass fills these):
- Fonts: Atlas fonts may not be redistributable as data-URIs → decide inline-if-present-else-documented-fallback (never a serif).
- PDF: weasyprint optional → graceful skip + log; HTML is canonical.
- Motion in PDF: static SVG only (no SMIL in print) → renderer emits a `static` variant.
- Gate 9 needs the SIBLING texts → generator passes them from DOC_MANIFEST `variants:`; standalone gate takes explicit siblings.
- SSRF: block RFC-1918/loopback/link-local/metadata IPs, non-http(s), redirects to non-allowlisted hosts, DNS-rebinding (resolve+check).
- Hash-gate: which files are "locked" (RULEBOOK, CLASSIFICATION, DESIGN_SYSTEM, calibration/*, DOC_MANIFEST) → list in VERSION.json.
- Detector-internal net: patterns for thresholds/weights/confidence-cutoffs/feature-names that must never appear in a public doc.
- Idempotence + determinism (no Date.now/random in output; stable ordering) so the hash-gate + diffs are stable.

## 4. Verify (Wave 2, demonstrated in the report)
`python -m tools.docgen.cli build tools/docgen/sample.md` → open the HTML (self-contained ✓). Run the gate on a planted-secret doc → BLOCK. Render `sample_spec.json` → SVG with motion + reduced-motion + collision-clean. `docgen check` → hash-gate + manifest OK. `pytest tests/docgen -q` green. ruff+mypy clean.

## 4b. PASS-2 FOLD — hardening addenda (BINDING; from the adversarial gap-check 2026-07-05)
**Reconciliation already applied by the architect:** `VERSION.json` `rulebook_files` now lists the full locked set
(spine + all `calibration/*` + `DOC_MANIFEST`), fail-closed on any missing file; `L23` amended to **in-repo** artifacts.
**Builders CREATE these missing governance files** (all `classification: public`): `TAXONOMY.md` (doc-type id-prefixes —
DET/ENG/WF/SYS/ATK/SOC-S/SOC-E/API/SDK/BENCH/TM/EDU/VER, matching `DOC_MANIFEST`), `CONTRADICTION.md` (L11 tie-breaker
table incl. security>commercial, pulse-vs-sober), `update_impact_map.json` (L10 change-type→dependent-docs+sanitization),
and a vendored in-repo `BRAND_MANIFEST.md` (© + ™ + eye-mark + Atlas pointer, for L20/L23).

**Module names — match the locked specs (avoid KB-021 name drift):** the leak-gate library is `export_sanitizer.py`
(CLASSIFICATION §leak-gate); the gate CLI + hash-gate is `validate_doc_system.py` (VERSION.json `gate`); `cli.py` does
build/render/manifest. (Rename the plan's `leak_gate.py`→`export_sanitizer.py`, `hash_gate.py` logic lives in
`validate_doc_system.py`.)

**Leak-gate hardening (MUST — the moat):**
1. **Normalize before every scan:** unicode NFKC + strip zero-width/ctrl chars + also try base64/hex-decoded views (a secret encoded in a data-URI must still be caught).
2. **Scan the FINAL RENDERED bytes of every output channel** (after SVG/font/asset inlining), not only source markdown — the export artifact is the thing that leaks. `generator.py` re-runs the gate on the rendered HTML/JSON.
3. **Add L4 nets** beyond secrets: PII (emails, private IPs), private paths (`/Users/…`, `/opt/…`), internal hostnames, stack-trace/log dumps. Each a labeled gate.
4. **Detector-internal net is ADVISORY** (paraphrase-fragile) — it FLAGS for human review, not a silent sole-moat block; say so honestly. The hard blocks are: tier (Gate 1), secret-value (Gate 3), PII/path (Gate 3b), variant-overlap (Gate 9).
5. **Gate 9 (variant non-overlap) — normalize (lowercase/collapse-ws/strip-stopwords/light-stem) + shingle at n=8 AND n=4 + a similarity ratio threshold**, not just exact-span. **FAIL-CLOSED when a declared sibling file is absent** (git-ignored siblings are often missing on a checkout/CI) — block the public export, never skip.
6. **Header↔manifest drift (L5):** cross-check the doc's header tier against its `DOC_MANIFEST` row; mismatch blocks.
7. **Fail-closed per gate** — a missing input (TAXONOMY, sibling, mark, LICENSE) BLOCKS, never skips. State it in each gate's docstring.
8. **Precedence spine (L1)** — a `PRECEDENCE` tuple adjudicates conflicting findings (security first).
9. **`data_source` / claim-ledger linter (L8/L16):** every numeric datum in a `VisualSpec`/figure must resolve to a `DataSource.ref`; unsourced numbers BLOCK.
10. **L7 generated-file guard:** the generator stamps each output with `<!-- generated-by docgen · content-sha256:… -->`; the gate re-computes and FAILS if the file was hand-edited after generation.

**Renderer/motion (MUST/SHOULD):**
- **Edge router** (simple orthogonal/elbow that routes around node bboxes) so the collision validator can PASS valid diagrams, not only fail them.
- **Adaptive arc sampling** (N grows with path length/curvature); the **±5% velocity assertion is checked against the edge's ACTUAL target speed** (incl. the compressed-cap speed when `dur` hit the 4s cap), and the caption injects "animation compressed N×" when capped.
- **Collision validator** covers node rects + **rendered text bounding boxes** (labels/captions/legend/notes) + decorative marks + edge-through-non-endpoint-node; **over-estimate text width** (fail-closed) using a conservative per-char advance; a hit FAILS the render.
- **Determinism (critical for the hash-gate):** round all SVG floats to fixed precision (e.g. 2 dp), sort any set/dict before serialization, **exclude `created_at`/timestamps from the content hash**, byte-stable asset embedding. Prove with a build-twice-identical test.
- Reduced-motion + PDF path emit the **static variant** (all branches + numbered edge badges + lit terminal state; SMIL stripped for weasyprint); PDF absent → `BuildResult` records `pdf: skipped(weasyprint absent)`, honest exit code.

**Fetcher (`fetch_public_fact.py`) hardening (KB-005):** resolve host → **connect to the pinned IP** (no re-resolve TOCTOU); block RFC-1918/loopback/link-local/metadata (169.254.169.254); follow redirects **manually, re-validating host+IP per hop against the allow-list**; cap body size + time + content-type; sanitize the cache filename (no path traversal).

**Isolation/inputs (L12):** canonicalize `md_path` + every `variants:` path and assert it stays inside the repo (block `../`/symlink escape). `--strict` mode (used by a pre-push hook, CLASSIFICATION Gate 7) turns advisory flags into failures and returns non-zero.

**Tests (demand these adversarial cases):** base64-encoded secret; secret inside an inlined SVG/data-URI; reordered/synonym Gate-9 overlap; homoglyph analyzer name; **missing-sibling → fail-closed**; missing-TAXONOMY/mark/LICENSE → fail-closed; capped-edge velocity assertion; over-long label collision; **build-twice → identical bytes**; weasyprint-absent path; header↔manifest drift.

**Deferred to POOL (implement existence-readers now; active adjudication later):** live CONTRADICTION/update-impact adjudication beyond existence-validation, surface↔channel git router, git-staged-content scanner, WCAG-AA auto-contrast (ship a helper now), incremental cache/watch, i18n, CI-cost-control wiring. Record in `docs/pm/POOL.md`.

## 5. Out of scope (explicitly deferred — the docs themselves)
No detector dossiers, no engine/workflow/system docs, no attacks-catalog content. Those are authored LATER using this engine. This session builds ONLY the engine + its tests + a sample proving it works.
