<!-- classification: INTERNAL -->

# Chart-selection policy

### question first, engine last · 2026-08-08 · v1.0.0

1. **Define the reader question** (change / compare / rank / distribute /
   relate / compose / flow / locate / sequence / hierarchy / topology / status /
   uncertainty / current-vs-target / evidence completeness).
2. **Classify the data** (categorical, ordinal, quantitative, temporal,
   relational, hierarchical, matrix, event, state) and record rows, series
   count, density, missing rate.
3. **Retrieve candidates** from `knowledge/CHART_USE_CASE_CATALOG.json` and
   walk `knowledge/CHART_SELECTION_DECISION_TREE.json`.
4. **Reject anti-patterns** (`knowledge/CHART_ANTI_PATTERNS.json`).
5. **Pick the simplest visual that answers the question** — a table or
   NO_CHART beats a clever chart (§18).
6. **Route** via `ENGINE_ROUTING_POLICY.json` (document diagrams → docgen).
7. Non-trivial selections record `selection_reason` + rejected alternatives in
   the job packet (Gate G2).

`ENGINE_CAN_RENDER_THIS ≠ THIS_IS_THE_CORRECT_VISUALIZATION` (§30).
Capability never equals suitability.

Knowledge maintenance: entries carry `last_verified` + `review_due`. Research
again only when missing, stale, unusual, disagreeing, or high-stakes — then
write the conclusion back with a source (`SOURCE_REGISTRY.json`).
