# MCP fallback plan

The MCP facade is an adapter, never the authority (spec §7). If the MCP
process is down, unreachable, or de-registered, **nothing is lost**:

1. **Direct CLI** — `node tools/visual-engine/adapters/echarts/cli.mjs render <job.json> -o <outdir> --formats svg,png,html --evidence`
2. **Direct import** — `import { renderSVG, renderPNG } from "tools/visual-engine/adapters/echarts/render.mjs"` (what CI and the test suite use; the MCP itself is a thin wrapper over these functions).
3. **Batch** — `renderBatch(jobs)` or repeated CLI calls.

The MCP-down path is exercised by `tests/run_simulations.mjs` (simulation 21):
the same job rendered via MCP and via the direct adapter must produce the same
svg_sha256. Recovery: `npm run mcp` restarts the facade; registration is
`.mcp.json` at the repo root.
