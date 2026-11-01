<!-- classification: INTERNAL -->

# Visual-engine security policy

### chart rendering is executable infrastructure, not cosmetics · 2026-08-08 · v1.0.0

> Threat model: a visual job is **untrusted input** — it may originate from
> agent-processed contract data, scraped content, or user text. The engine is
> therefore fail-closed at every gate (T-R9: silent success is a defect class).

## Controls (implemented in `adapters/echarts/validate.mjs` + `mcp/server.mjs`)

| Threat | Control | Gate |
|---|---|---|
| Executable option content (formatter functions, renderItem, protos) | forbidden keys + function-literal patterns rejected; options are **data-only JSON**; the only formatters are engine-owned template strings | G-SEC |
| Script/HTML injection into SVG/HTML output | `<script`, `javascript:`, `data:text/html`, inline `on*=` handlers rejected in every string; HTML template escapes all job text | G-SEC |
| Exfiltration via chart assets | external URLs rejected in option-bound fields; SSR performs no network I/O; interactive HTML inlines everything (no CDN) | G-SEC |
| Confidential data through cloud chart tools | engine is local-only by construction; apache/echarts-mcp **rejected** for default Baidu-cloud storage (mcp/approved-server.json); `restricted` classification never renders via MCP | G-CONF |
| Resource exhaustion (CPU/memory/canvas bombs) | 50k-cell / 1.5k-node / 5k-edge / 4000px / 500-char caps; SSR is synchronous per job with no unbounded loops; batch capped at 20 | G-SIZE |
| Pathological regex | no user-supplied regex is ever evaluated | — |
| Arbitrary filesystem writes | MCP writes only under `renders/current/` + `evidence/validation/`; `visual_id` is basename-sanitized; CLI callers choose outdir explicitly | — |
| Secrets in charts | jobs carry data snapshots, never credentials; the docgen leak-gate (export_sanitizer) still runs on any document embedding these SVGs | — |
| Supply chain | 4 deps, exact-pinned (VERSION_LOCK.json), lockfile committed, `npm install` audit clean 2026-08-08; CI dep-audit covers this tree once registered | — |

## MCP permission model (least privilege, spec §8)

The facade receives: normalized jobs, approved theme ids, format list. It
exposes: seven `visual_*` tools, nothing else. It has **no** shell, **no**
network listener (stdio only), **no** caller-chosen paths, **no** restricted
render path at all.

## What this policy does NOT cover

Rendering of **restricted** data via the direct adapter is possible only with
`allowRestricted` — that flag is a human sign-off marker, and outputs must stay
inside the engine tree. Embedding rendered SVGs into published documents is
governed by docgen's export sanitizer (9-gate leak-gate), which remains the
final gate for anything leaving the repo.
