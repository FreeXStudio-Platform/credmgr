<!-- classification: public -->
# DOC_MANIFEST — CredMgr doc-system registry

Every document built through `tools/docgen` must have exactly one row here, and its header
(`id`/`title`/`classification`/`surface`) must agree with this table — the `manifest_drift`
gate (Gate 5) fails closed on any mismatch, including a missing row. See
`tools/PROVENANCE.md` for where this doc-system engine itself came from.

## Rows

| id | title | type | variants | content_role | surface | status |
|---|---|---|---|---|---|---|
| `BP-V2` | V2 blueprint documents (`BP-V2-NNN`) | blueprint | public | project-doc | repo | verified-current |
| `V2` | V2 design corpus (`V2-NNN`, one per `v2/docs/NN_*.md`) | design-corpus | public | project-doc | repo | in-rewrite |

## Rule

A row's `variants` must be a superset of every tier the doc is ever built at (`public` /
`confidential` / `secret`, pipe-separated when more than one). `surface` must match the doc's
own frontmatter `surface` field. Adding a document without adding its row here is a build
failure, by design (RULEBOOK L10/L18) — the manifest is the registry a header can drift
against, not a formality.

*Change history*

| date | change |
|---|---|
| 2026-08-17 | Manifest created — first row, `BP-V2-001`, the pipeline's own proof-of-work document. |
| 2026-08-18 | Second row, `V2` — the 24-document design corpus (`v2/docs/`), as it begins building through this pipeline. Only `id`, `variants` and `surface` are machine-checked (`classification.check_manifest_drift`); the other columns are documentation. |
