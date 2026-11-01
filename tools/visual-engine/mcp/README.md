# credmgr-visuals MCP facade

Constrained MCP wrapper over the direct ECharts adapter. See
`approved-server.json` (selection decision + rejected candidates),
`tool-schema-snapshot.json` (frozen tool contracts),
`capability-test-results.json` (live handshake/render/refusal evidence) and
`fallback-plan.md` (the mandatory non-MCP path).

Run: `npm run mcp` (stdio). Registered project-wide via repo-root `.mcp.json`.
Restricted-classification jobs are always refused here; the tool surface is
the eight-tool `visual.*` set from the implementation directive §7.3 — nothing
else is exposed.
