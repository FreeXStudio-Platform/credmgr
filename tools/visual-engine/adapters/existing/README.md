# Preserved engines — pointers, not copies

No engine was removed or modified by the visual-engine installation. One fact,
one home — full records in `knowledge/ENGINE_FEATURE_MAP.json` and the routing
in `../../ENGINE_ROUTING_POLICY.json`.

| Engine | Home | Authority |
|---|---|---|
| docgen (documents/diagrams, AUTHORITATIVE) | `tools/docgen/` — README, RULEBOOK at `docs/design/doc-system/` | design authority for every document visual |
| Recharts dashboard | `frontend/src/components/dashboard/` + `chart-colors.ts` | app UI |
| mermaid fences | 62 files under `docs/` | markdown drafting stage |
| graphify | `tools/graphify/` (vendored force-graph@1) | local code-graph navigation |
| product PDF reports | `src/reports/pdf_exporter.py` | Jinja2+WeasyPrint, chartless today |
