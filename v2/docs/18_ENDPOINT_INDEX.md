---
id: V2-018
classification: public
title: Endpoint index
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-10-31
---

<!-- artifact-hardened: Approved With Known Risks @ 3d8545f on 2026-10-31 via three-pass-v1. Evidence: every gate green on the code at 34542f8 (workspace 910 tests in 59 binaries, desktop bridge 202, endpoint matrix 55/55 operations and 243 rows, clippy, fmt, cargo deny, cargo audit, desktop unit, e2e and real-daemon suites, strict public export PASS); final adversarial audit v2/docs/release-verification/AUDIT_2026-10-31.md (the P0 and both P1 fixed, re-verified twice); known risks K-1 to K-19 in v2/docs/PHASE8_AUDIT_REPORT.md sections 4 and 7, each with bound, owner and resolution. Known risks that bear on this document: K-12 GitHub CI has not run on this release (billing); K-14 the idle lock and a real sleep or screen lock were not exercised by hand on this build; K-19 a seed in an unrecognised shape is not protected until its owner types it. Not a claim about anything after 3d8545f. -->
# Endpoint index — every surface, indexed and mapped V1 → V2

`CredMgr V2` · the mapping from V1's surface to V2's, and what of V2's surface exists today · `2026-10-31`

> **Status.** The mapping itself is complete and `verified-current`. **What changed in this
> rewrite is that it now distinguishes what is built from what is designed.** Every row carries
> **`built`**, **`planned`** or **`removed`** (a row may also be **`partial`**; none is, as of
> 2026-10-03, when `entry.create_batch` became fully built): 34 built, 23 planned and 6 removed across the mapping tables
> (§1.1–§1.7; a row counts under the marker its Notes cell opens with; re-counted 2026-10-31), plus the operations in §1.8
> that have no V1 ancestor and were previously indexed nowhere at all (ten at this rewrite, thirteen
> since 2026-10-26). Before this pass the document
> named a V2 operation surface far larger than the one that exists — including
> `vault.set_passphrase`, which is dispatched nowhere in the codebase — and marked none of it as
> unbuilt.

Extracted from the V1 source, not from memory, and re-counted against `v1/` (1.9.1) on 2026-10-31:
**57 HTTP routes** (`v1/lib/server.js`, the `*` catch-all included) · **10 MCP tools** (`v1/mcp/server.js`) ·
**37 CLI commands** (`v1/bin/credmgr` dispatches 36 distinct commands, 45 case labels with aliases; `migrate`,
§2, is the 37th and exists only in the raw package). An earlier revision said 48 CLI commands; that figure does
not reproduce from either count and its own columns summed to 36.

The purpose of this document is to make it impossible to lose a capability by accident. Every
V1 endpoint appears below with an explicit V2 disposition — **carried · renamed · merged ·
removed (with a reason) · new**. Silence is not a disposition.

**Legend** — ✅ carried · ✏️ renamed/reshaped · 🔀 merged into another · ❌ removed (reason
given) · ⭐ new in V2 · 🔒 gate change. Each row's Notes cell additionally leads with its build
status: **`built`** (the named op is dispatched by `crates/brokerd/src/ops.rs` today),
**`planned`** (designed here, dispatched nowhere yet), **`removed`** (no V2 op, reason given).

> **This document is hand-maintained, and now mechanically guarded.** For months it asserted that
> a test `I-26` parsed it and made drift from the broker impossible. No such test has ever
> existed; the isolation suite runs I-1…I-25 and stops. That claim was removed on 2026-08-17, and
> the guard it described was actually written on 2026-08-18 as
> `tools/corpus_check.py endpoints` — which proves, in both directions, that every op named here
> exists and every op the broker dispatches is named here. It is green as of this rewrite. It is
> not a Rust test because the artifact being checked is a document; the guarantee is identical.

---

## 1. HTTP API (V1) → Broker operations (V2)

V2 has **no HTTP surface at all** (ADR-019, F-12). Every route becomes a broker operation over
the UDS/named pipe. The `/api/` prefix disappears; the shape is `noun.verb`.

### 1.1 Vault lifecycle

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/health` | `vault.status` | 🔀 | **built** — merged with `/api/status` |
| `GET /api/status` | `vault.status` | ✅ | **built** — drives the trust pill; answers `{locked, initialized, pendingApprovals}`. `initialized` (`ADR-077`) is false only before `vault.init_confirm`, so a client can offer "create a vault"; `pendingApprovals` (`ADR-090`) is a bare count of the approval requests still waiting (unexpired, undecided) and names no node, entry or requester. No capability needed |
| `GET /api/lock-status` | `vault.status` | 🔀 | **built** — one status object, not three |
| `POST /api/unlock` | `vault.unlock` | 🔒 | **built** — now also requires gate 2FA before node keys load (`07 §3`) |
| `POST /api/lock` | `vault.lock` | ✅ | **built** — drops the resident root key and zeroises every hot node key, ends every login session and second-factor elevation, and voids any value staged for an approved request (the lock epoch moves; no manifest `generation` does) |
| `POST /api/pin` | `vault.set_passphrase` | ✏️ | **planned** — V1's 4-digit dashboard PIN will become a real passphrase + platform keystore |
| — | `vault.node_lock` / `node_unlock` | ⭐ | **built** — per-node lock (F-7) |
| — | `vault.pending_list` / `pending_accept` / `pending_discard` | ⭐ | **built** — the locked-write review tray (F-1) |
| — | `vault.init_begin` | ⭐ | **built** — vault bootstrap, phase 1 (ADR-061): generates the root key, wraps it, returns the recovery code exactly once. No V1 HTTP route — V1's `init` was CLI-only (`§2`) |
| — | `vault.init_confirm` | ⭐ | **built** — vault bootstrap, phase 2 (ADR-061): takes the retyped recovery code and writes the vault. Refuses if a vault already exists |

### 1.2 Credentials → entries

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/credentials` | `entry.list` | 🔒 | **built** — scope-filtered by the access graph; plus `entries` manifest metadata (type, sensitivity, field count, dates, `hasTotp` — ADR-080) for **human sessions only** (`ADR-077`), same gate and filter as `ids` — an agent never receives it. A node with `privateNames` answers `ids`, `names` and `entries` empty with `nameHidden: true` and a `count` (hidden below three entries) to everyone but the owner's login (`ADR-083`); a node whose `requireTwoFactor` is `always` answers `two_factor_required` to a caller with no live second factor (`ADR-085`). CLI: `credmgr list` |
| `GET /api/search` | `entry.search` | 🔒 | **planned** — scope-filtered; never searches values (F-18) |
| `GET /api/credentials/:name` | `entry.get` | ✅ | **built** — metadata: the entry's type, sensitivity, `fieldCount`, `hasTotp`, dates, generation, and for each field its id, label, type and masking (and whether the type / masking is a user override) — **never a value** (`ADR-078`). `read`; needs the node unlocked, because the labels are encrypted with the values (`vault_locked` for a locked vault, `node_locked` for a locked node, no approval path); a held (tray) entry is `not_found`. `two_factor_required` on an `always` node (`ADR-085`); on a `privateNames` node the entry `name` and every field `label` come back `null` for anyone but the owner's login (`ADR-083`). CLI: `credmgr field ls`; MCP: `credmgr_get_metadata` |
| `GET /api/credentials/:name/value` | `entry.reveal` | 🔒 | **built** — when the vault has a confirmed gate and the node asks for a second factor (`reveal`, the default, or `always`), a caller with no live one gets `two_factor_required` (`ADR-085`; the owner's login is exempt); `approval_pending` when the vault or node is locked and the entry exists (an unknown entry is `not_found`, so invented ids cannot grow the request table). Takes `fieldIds` (a non-empty subset; every id must exist, else `not_found` with no partial answer) and answers `fields: [{id, label, value, type, masked}]` in stored order, plus `value` **only when exactly one field is returned** (`ADR-078`); an approval covers the entry and `fieldIds` narrows the approved answer (`ADR-079`: the value is staged when the decision is made; since `ADR-088` a wholly locked vault records the request and answers `approval_pending` as well, so it can be decided with the unlock factors) |
| `GET /api/ref/:ref` | `entry.get_by_ref` | ✅ | **planned** — refs stay vault-global |
| `POST /api/credentials` | `entry.create` | 🔒 | **built** — works while locked → pending tray (F-1). Exactly one of `value` (with an optional `label`) or `fields: [{label, value, type?, masked?}]`, plus optional `entryType` / `sensitivity` (`"auto"` clears an override); the answer carries `fieldCount` and `fieldIds` (`ADR-078`). A name over 200 characters is `malformed_request` (`ADR-093`); names are compared in canonical form, so a look-alike twin is `entry_exists` and a name mixing Latin with Greek or Cyrillic is accepted with `warnings: ["mixed_script_name"]` (`ADR-084`). CLI: `credmgr set` (`--bulk`, `--field`) |
| `PATCH /api/credentials/:name` | `entry.update` | 🔒 | **built** — **requires unlock** (F-1). Takes `value` (with `field` naming the field on a multi-field entry, and an optional `label` rename) **or** `fields` (replace the whole list; an `id` keeps a field's identity), and/or `entryType` / `sensitivity`; keeps no history (`ADR-078`) |
| `DELETE /api/credentials/:name` | `entry.remove` | ✅ | **built** — soft, 7-day recovery |
| `POST /api/credentials/:name/rotate` | `entry.rotate` | ✅ | **built** — the same body as `entry.update`; keeps the previous envelope (undoable) and stamps `rotatedAt` (`ADR-078`). CLI: `credmgr rotate` (`--field`) |
| `GET /api/credentials/:name/history` | `entry.history` | ✅ | **planned** |
| `POST /api/credentials/batch` | `entry.create_batch` | ✅ | **built** — `{node, entries: [{name, value?, label?, fields?, entryType?, sensitivity?}]}`, 1–500 entries; every item is validated and encoded before the first write (each document ≤ 16 MiB, the batch ≤ 64 MiB), a locked vault holds the whole batch in the pending tray, a part-way failure answers `complete: false`; each item's name follows the `entry.create` rules, the 200-character cap included (the refusal names the item's index and never the text, `ADR-093`), and a twin of an earlier item is `malformed_request` (`ADR-073`, multi-field since `ADR-078`; the split-by-`///` toggle is one item per segment). CLI: `credmgr import <file\|-> --node <id>` (an all-or-nothing `.env` import) |
| — | `field.add` / `update` / `remove` / `reorder` | ⭐ | **built** — fields are first-class in V2 (`ADR-078`): `update` capability, unlocked, generation-checked; `add` appends (or inserts at `position`), `update` takes a `patch` (`label`, `value`, `type`, `masked`; `"auto"` clears a pin), `remove` refuses the last field, `reorder` takes an exact permutation of the ids; each keeps the previous envelope and is undoable through `entry.undo`. CLI: `credmgr field add\|set\|rm\|mv`; MCP: `credmgr_field_add` / `_update` / `_remove` (`reorder` has no tool) |
| — | `notes.read` / `notes.write` | ⭐ | **built** — the privacy-vault half (`ADR-072`): one markdown note per node, sealed under the node key, gated on the separate `notes` capability (never implied by `read`) and bound to the manifest's `notesSha256`. `notes.read` also returns the manifest `generation` a write must be based on (`ADR-077`), and answers `markdown: null` to anyone but the owner's login on a `privateNames` node (`ADR-083`). CLI: `credmgr notes show` / `notes set` / `notes clear`; no MCP tool reaches it yet (§3) |

### 1.3 Projects → nodes

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/projects` | `node.list` | 🔒 | **built** — returns only reachable nodes (F-6) |
| `PATCH /api/projects/:id` | `node.update` | ✅ | **built** — rename (`label`) only (`ADR-071`): trimmed, 1–120 characters, no control characters, and a label mixing Latin with Greek or Cyrillic is accepted with `warnings` (`ADR-084`); the id never changes, so grants, workdirs and scopes are untouched. Global and Orphan refuse. Human-only; on the MCP forbidden list. CLI: `credmgr node rename` |
| `DELETE /api/projects/:id` | `node.seal` | ✏️ | **built** — **seal, never delete** (ADR-007). Durable since `ADR-079`: the seal record lives in the signed registry, the orphan node and its cold key are made by `credmgr init` (or lazily by the first seal in an older vault), and a crash at any step leaves a vault that unlocks. Refuses a node with live sub-nodes and an id that is already sealed. `archiveMovePending: true` in the answer means the file moves after the commit will finish at the next unlock |
| `POST /api/projects/:id/reassign` | `entry.move` | ✏️ | **planned** — moving an entry between nodes re-encrypts it |
| — | `node.create` · `node.reparent` · `node.restore` | ⭐ | **built** — `reparent` is scope-widening → grant gate (F-8). `node.create` enforces the node-id grammar `[a-z0-9][a-z0-9_-]{0,63}` and reserves `global`, `orphan`, `removed-entries`, `entry-history`, refuses the id of a node whose archive still exists (`ADR-079`), validates `label` like `node.update` (1–120 characters, no control characters; `ADR-093` — before that creation took any label), and waits for a seal or restore in flight (`ADR-089`). `node.restore` (inside the 7-day window, across restarts) refuses a sealed parent and reports `workdirsDropped` for a workdir another node now owns |
| — | `node.policy` | ⭐ | **built** — a partial patch of the six policy fields with a mandatory `reason`, recorded in the audit record (`ADR-071`). Tightening applies at once; a widening (`descendantRead` on, `siblingVisibility: shared`) answers `presence_required` and applies nothing until a presence transport exists. All six fields are enforced: `privateNames` since `ADR-083`, `requireTwoFactor` since `ADR-085` (a policy change ends every second-factor elevation); `notEnforced` stays in the response as an empty list. `reason` is 1–500 characters. Human-only; on the MCP forbidden list. CLI: `credmgr node policy` |
| — | `grant.list` / `create` / `revoke` | ⭐ | **built** — `admin` capability, so no agent holds it. `list` and `revoke` answer a human session; `create` validates everything and is then refused with `presence_required` on every call until a presence transport exists (issue #18, `2.0.0-rc.1`) |

> **Correction, `2026-08-23`.** This row previously marked `node.create`/`node.reparent`/
> `node.restore` **planned** as one bundled cell with `node.policy`. Re-verified against
> `crates/brokerd/src/ops.rs` while building `§9`'s figure (`grep -n '"node\.'` shows dispatch
> arms at lines 2079/2326/2426): the three are already dispatched — only `node.policy` remains
> undispatched. `tools/corpus_check.py endpoints` does not catch this class of drift (it flags an
> op claimed built-but-missing, or shipped-but-undocumented; it does not flag an op **marked**
> `planned` that is actually already built), so this was live and gate-green until this pass.
> (`node.policy` itself has been dispatched since `2026-09-24`, `ADR-071`.)

### 1.4 Maintenance

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/verify` | `maintenance.verify` | ✅ | **built** — now also checks manifest HMACs + generation (F-2/F-3), and each envelope's bytes against its manifest digest with no key (ADR-067) |
| `POST /api/doctor` | `maintenance.doctor` | ✅ | **built** — gains `--rebuild-registry` (F-10; refused with `presence_required` after its other checks). Never destroys anything on a plain run: `purgeExpiredSeals` defaults to **false** and must be sent as `true` to remove the retained originals of a seal whose seven days are over (`ADR-089`; `admin` on `global`, vault unlocked; with `apply: false` it only lists `would-purge-expired-seal`, and `malformed_request` if it is not a boolean). CLI: `credmgr doctor [--dry-run] [--purge-expired-seals] [--rebuild-registry]`. The desktop's plain Doctor sends no purge (`ADR-092`) |
| `POST /api/backup` | `maintenance.backup` | 🔒 | **built** — operator-invoked only: `admin` on `global`, takes a non-empty `passphrase` and `retain` (default 14), writes an encrypted file and prunes older ones. F-16's automatic daily and pre-destructive firing is **not built** — the broker has no scheduler (`ADR-039`); no GitHub issue tracks it |
| — | `maintenance.rotate_root` | ⭐ | **built** — replace the root key: a new root key, every node key re-wrapped, both root wraps rewritten, every root-signed file re-signed, a **new recovery code** issued once (`ADR-076`). Crash-safe: stage, one atomic commit record, idempotent roll-forward; recovery is key-free, runs at start-up and at every unlock, and is serialised against a rotation by a per-vault lock. Takes `{passphrase}`. Human only, `admin` on `global`, a fresh vault second factor (`two_factor_required`), then **presence**: the wire answers `presence_required` until a transport can attest it (`ADR-047`), and the logic is tested directly (§4.2 of `10`). On the MCP forbidden list (absent, not gated); on the per-uid auth backoff. No V1 ancestor; no CLI command yet |
| `GET /api/generate` | `util.generate` | ✅ | **built** (ADR-087, 2026-10-24) — the broker makes the password (`length` 8–128, `symbols`, `pronounceable`) and answers `{value, length, symbols, pronounceable, entropyBits}`; needs `create` or `update`; not an MCP tool. CLI: `credmgr generate` |
| `GET /api/expiring` | `entry.expiring` | ✅ | **planned** |
| `GET /api/audit` | `audit.report` | ✅ | **planned** — + stale-grant sweep |
| `GET /api/access-log` | `audit.tail` | 🔀 | **built** — one hash-chained log replaces changelog + access-log |
| `GET /api/export/:project` | `node.export` | 🔒 | **planned** — 2FA + presence + explicit `--out`; scope defined in `04 §7` |
| `GET/POST /api/export-password` | — | ❌ | **removed** — V1 protected exports with a separate password. V2 gates on the real factors instead; a second password was a third auth system nobody kept in sync. |
| `GET /api/stats` | — | ❌ | **removed** — no stats op. V1 answered cross-project totals by project, category and sensitivity. Per-node `counts` (`entries`, `totp`) ride on `graph.snapshot` and need no unlock; a total over every node would be an aggregate over nodes the caller may not reach (F-6). The row was missing from this index until 2026-10-31; the CLI's `stats` (§2) is likewise not built |

### 1.5 Merge / suggestions engine

The auto-merge engine **survives**, with its decision memory intact — the user's explicit
requirement. It matters less in V2 (node scoping removes most duplicate causes) so it moves to
**Pro → Maintenance**, but nothing is lost.

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/suggestions` | `merge.suggestions` | 🔒 | **planned** — will apply **within one node**; will never propose across a boundary |
| `POST /api/suggestions/dismiss` | `merge.dismiss` | ✅ | **planned** — **the decision memory** — a dismissed suggestion will never return |
| `POST /api/suggestions/undismiss` | `merge.undismiss` | ✅ | **planned** |
| `GET /api/suggestions/dismissed` | `merge.dismissed_list` | ✅ | **planned** |
| `POST /api/suggestions/restore-all` | `merge.restore_all` | ✅ | **planned** |
| `POST /api/merge` | `merge.apply` | ✅ | **planned** — aliases preserved (V1 4.1) |
| `POST /api/merge/auto` | `merge.auto` | ✅ | **planned** |
| `POST /api/merge/auto-all` | `merge.auto_all` | ✅ | **planned** — dry-run first, always |
| `GET /api/schemas` | — | ❌ | **removed** — `TYPE_SCHEMAS` deleted (ADR-011). Field *types* replace field-name schemas; the column-suggestion UI goes with it. |

### 1.6 Changelog / undo — the 7-day isolation

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/changelog` | `audit.tail` | 🔀 | **built** — always redacted for agents |
| `GET /api/changelog/:id` | `audit.get` | 🔒 | **built** — full record needs presence |
| `POST /api/changelog/:id/undo` | `entry.undo` | ✅ | **built** — `replace` / `keep-both` collision modes retained. Answers `ok: true` and `restored: {action, entry, …}`; a `field.*` edit can be undone for seven days from when it was made, then `not_undoable` (`ADR-086`; no `field.undo` op exists) |
| `POST /api/changelog/purge` | `audit.purge` | 🔒 | **planned** — **human only** — no agent path, ever |
| `DELETE /api/changelog/:id` | — | ❌ | **removed** — deleting one record from a hash-chained log breaks the chain. The 7-day window is not user-shortenable (`10 §3.2`). |

### 1.7 Agents & integrations

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/daemon-token` | `agent.token_status` | ✅ | **planned** — `{hasToken, last4}` only |
| `POST /api/daemon-token/rotate` | `agent.token_rotate` | ✅ | **planned** — rotate-to-reveal |
| `POST /api/daemon-token/revoke` | `agent.token_revoke` | ✅ | **planned** |
| — | `agent.token_issue` | ⭐ | **planned** — **node-scoped** tokens |
| `GET/POST/DELETE /api/integrations…` | `integration.*` | ❌ | **removed** — four V1 routes (list, add, toggle, delete); no `integration.*` op exists. The auto-MCP wiring they did is the `planned` `llm.*` family below |
| — | `llm.detect` / `llm.connect` / `llm.disconnect` / `llm.prompt` | ⭐ | **planned** — the auto-MCP wiring (`17 §4`) |
| `GET /api/machine-lock` + enable/disable | `keystore.status` / `bind` / `unbind` | ✏️ | **planned** — generalised to the platform keystore (`16 §3`) |
| `GET *` (SPA catch-all) | — | ❌ | **removed** — no HTTP server exists; the UI is served by the shell (F-12) |

**Scheduling of the `planned` rows (re-checked 2026-10-31 against the open GitHub issues).** `planned` means
designed here and dispatched nowhere; only some rows have a milestone. Issue #32 (`2.0.0`) lists `audit.report`
and the `--age` export (read here as `node.export`, the broker op behind `export`); #31 (`2.0.0`) is the owner's
build-or-formally-drop decision for `llm.*` and machine lock; #29 (`2.0.0`) is the Windows and Linux keystores,
the nearest issue to `keystore.*`. Presence (#18, `2.0.0-rc.1`) is what lets `grant.create`, `node.reparent`,
`totp.seed`, `audit.get`, `maintenance.rotate_root`, a registry rebuild and a widening `node.policy` stop answering
`presence_required`. **No issue or milestone names `merge.*`, `agent.*`, `entry.search`, `entry.get_by_ref`,
`entry.history`, `entry.move`, `entry.expiring`, `audit.purge` or `vault.set_passphrase`: they are unscheduled.**
`audit.purge` and `node.export` stay off the MCP tool list when built.

---

### 1.8 Operations with no V1 ancestor — `built`, and previously indexed nowhere

Thirteen of the broker's 55 operations are indexed here because V2 needed them and V1 had no route that
became them (ten when this section was written; `vault.gate_recover` and `node.set_workdirs`,
ADR-064 and ADR-066, 2026-09-24, and `vault.approval_get`, ADR-090, 2026-10-26, are the last three rows). They were absent from every table above, which meant the coverage assertion in §6
could be true in the V1→V2 direction and still leave a third of the shipped surface undocumented.
`tools/corpus_check.py endpoints` now fails closed on exactly that omission, in both directions.
(`vault.init_begin`/`vault.init_confirm`, added by ADR-061 after this section was written, have no
V1 route either; they are indexed as ⭐ rows in `§1.1`, so they are not counted here — nor are
`node.policy` and `notes.read`/`notes.write`, ADR-071/072, ⭐ rows in `§1.3` and `§1.2`, nor
`maintenance.rotate_root`, ADR-076, the ⭐ row in `§1.4`, nor `field.add`/`update`/`remove`/`reorder`,
ADR-078, the ⭐ row in `§1.2`.)

| V2 op | Status | Why it exists |
|---|---|---|
| `whoami` | **built** — | resolves the calling process to a node via peer credentials and cwd. V1 had no node boundary, so it had nothing to answer. `06 §4` |
| `search` | **built** — | a top-level op rather than `entry.search`: it spans every node the caller may reach, and the result set is a function of the access graph, not of one node's contents |
| `entry.restore` | **built** — | the counterpart to `entry.remove` within the 7-day window (`ADR-055`). V1's undo was a changelog operation; V2's is an entry operation, because the entry is what carries the ciphertext |
| `graph.snapshot` | **built** — | serves the vault-topology screen. V1 had a flat project list and needed no graph. `meta.sealed` (`[{id, label, sealedAt, expiresAt}]`) is added for non-agent callers holding Admin only (`ADR-080`); absent otherwise |
| `vault.gate_enroll_begin` | **built** — | enrolment step 1: issues the TOTP secret only, unconfirmed and gating nothing yet. The ten recovery codes are generated once, only by `vault.gate_enroll_confirm` (`07_TWO_FACTOR.md §4`) |
| `vault.gate_enroll_confirm` | **built** — | enrolment step 2: proves the operator stored the secret before the gate becomes mandatory |
| `vault.gate_verify` | **built** — | the gate itself, and — since `ADR-056` — one of the two places a real session token is minted. Called by an already-logged-in owner session it is a **step-up** instead (`ADR-085`): the same code check and backoff, a 300-second elevation for every caller, no token minted, answer `{locked: false, elevated: true, expiresIn}`. With **no gate enrolled** the step-up answers `malformed_request` ("nothing to verify"), not `gate_verification_failed`, and does not feed the unlock backoff; a tokenless caller with no gate pending still gets `gate_verification_failed` |
| `totp.seed` | **built** — | stores a TOTP seed as an entry field. Distinct from the gate: this is a credential the vault holds *for* the operator, not the factor that guards the vault. Takes `field` on a multi-field entry (`ADR-078`) |
| `totp.code` | **built** — | derives a current code from a stored seed, so the seed itself never has to be revealed to be used. Takes `field`; without it, the only field, else the one TOTP-seed field, else `malformed_request` (`ADR-078`) |
| `vault.approval_decide` | **built** — | resolves an approval-on-demand request (`ADR-042`): an agent asked to reveal from a locked node, and the owner session approves or denies it once. Not the locked-write tray (`vault.pending_*`, `F-1`). The decision stages the value (`ADR-079`). With `passphrase` (and `code` when a gate is confirmed) it is decided by the unlock factors **while the vault stays locked** (`ADR-088`): no capability or session, wrong passphrase `wrong_passphrase`, missing code `two_factor_required`, wrong code `gate_verification_failed`, a recovery code refused, an interrupted root-key rotation finished first (`ADR-093`); unlocked, a passphrase is `malformed_request`. Without a passphrase, a wholly locked live vault answers `vault_locked`. CLI `credmgr approve <request> [--deny] [--code <n>]` |
| `vault.approval_get` | **built** — | what a waiting approval request asks for (`ADR-090`): node and entry (by name when the broker holds the names and the node's name is not private), the command, seconds left; with no `request`, the list of everything waiting. Read-only, answered on a locked vault, decrypts nothing; on an unlocked vault the owner's login only. `vault.status` carries the bare count as `pendingApprovals`. CLI `credmgr approvals`. Not an MCP tool |
| `vault.gate_recover` | **built** — | the last door (`ADR-064`, `07_TWO_FACTOR.md §4`): the vault passphrase **and** the printed root recovery code together reset a lost gate. Resets, never unlocks; which factor failed is never said; shares `vault.unlock`'s auth backoff. Not an MCP tool |
| `node.set_workdirs` | **built** — | binds the directories that scope an agent to a node (`ADR-066`, `03_DATA_MODEL.md §1`) — absolute, existing, stored canonical, one directory to one node. Human-only. V1 had no node boundary to bind to |

## 2. CLI — 37 V1 commands

All 37 V1 commands are accounted for (36 in the public `v1/bin/credmgr` 1.9.1, plus `migrate`, which the raw V1 package
had and the public one does not — the raw package is not in this repository, so that one is carried from earlier
revisions of this document, not re-counted).

> **Status of this section — added 2026-09-21.** The three lists below map V1's surface onto V2's
> *intended* CLI. They are **not** a statement of what exists. Exactly **27 top-level subcommands
> are `built`** today (the match in `crates/cli/src/main.rs::run`, plus `help` and `--version`); 50
> counting every nested `node`/`grant`/`gate`/`pending`/`notes`/`field` arm as well, by
> `10_API_AND_MCP.md §2.1`'s method (`gate enroll`, `gate recover` and `node workdir` landed
> 2026-09-24 — ADR-064, ADR-066 — and `pending` the same day, ADR-069; `import`, `notes` and `node
> rename`/`node policy` on 2026-10-02 — ADR-071…073; `field` and the `--field` / `--field-id` / `--all` /
> `--json` / `--bulk` selectors on `get`, `set` and `rotate` on 2026-10-03 — ADR-078; `generate` and `approve` on
> 2026-10-24 — ADR-087, ADR-088; `approvals` on 2026-10-26 — ADR-090):
>
> `init` · `status` · `unlock` · `lock` · `gate` · `whoami` · `list` · `get` · `field` · `search` · `set` ·
> `rotate` · `rm` · `undo` · `audit` · `verify` · `pending` · `doctor` · `generate` · `approve` · `approvals` ·
> `backup` · `node` · `grant` · `import` · `notes` · `mcp`
>
> **Every command named below that is not in that list is `planned`** — roughly half the section,
> including `export`, `batch`, `history`, `dashboard`, `daemon`,
> `token`, `edit`, `projects`, `expiring`, `access-log`, `ssh-agent-add`, `keystore`, `totp`,
> `prompt`, `llm` and `scan` (`pending` is `built` since ADR-069; `import` and `notes` since
> 2026-10-02; `field` since 2026-10-03; `generate` since 2026-10-24). `stats` is neither: its HTTP route is `removed`
> (§1.4) and no stats op will back it. Read every unmarked row below as `planned` until
> it carries its own marker. (`ADR-059` requires the three-word vocabulary; this section predates
> the convention and is annotated here rather than rewritten row by row, because a *wrong* marker
> on a row is worse than an accurate banner over the section.)

**Carried unchanged (30):** `init get rm list search show env rotate generate
import batch history changelog undo verify doctor backup restore stats dashboard daemon token
mcp edit projects expiring audit access-log which/where/home help` (`stats` is in V1's list and is `removed`
in V2, §1.4; `which`, `where` and `home` are one V1 command)

**Reshaped (6) and removed (1):**

| V1 | V2 | Why |
|---|---|---|
| `set NAME "value"` | `set NAME` (stdin / `$EDITOR`) | argv leaks to shell history and `ps` (`10 §2`) |
| `export <project>` → stdout | `export --node <n> --out <file>` | piping a vault into a terminal is how it reaches scrollback |
| `ssh-key` → temp plaintext file | `ssh-agent-add` | never writes a key to disk |
| `machine-lock` | `keystore` | cross-platform (`16 §3`) |
| `purge-changelog` | `audit purge` | one log |
| `deploy` | `export --node … + scp`, documented | V1's deploy embedded one user's server layout; a vault should not own a deploy pipeline |
| `migrate` | — | ❌ removed in the V1 raw package too: it imported one specific user's legacy plaintext files and had no value to anyone else |

**New (15):** `whoami · node (ls/add/rm/restore/policy/reparent) · grant (ls/add/revoke) ·
totp · notes · prompt · llm (detect/connect) · scan · unlock · lock · pending · gate · field · approve · approvals`
(`gate`, `field`, `approve` and `approvals` are `built`; `approvals [<request>] [--json]` prints
`vault.approval_get`, and `credmgr status` prints `approvals waiting: N` when N is above zero, `ADR-090`)

---

## 3. MCP tools

| V1 tool | V2 | | Notes |
|---|---|---|---|
| `credmgr_get` | `credmgr_get` | 🔒 | **built** — scope-checked; may return `approval_pending`; takes `fieldIds`, answers `fields` (and `value` when one field is returned) (`ADR-078`) |
| `credmgr_list` | `credmgr_list` | 🔒 | **built** — scope-filtered |
| `credmgr_search` | `credmgr_search` | 🔒 | **built** — scope-filtered |
| `credmgr_get_metadata` | `credmgr_get_metadata` | ✅ | **built** — `entry.get`: field labels, types and masking, never a value (`ADR-078`; `10_API_AND_MCP.md §3.1`) |
| `credmgr_set` | `credmgr_create` + `credmgr_update` | ✏️ | **built** — split — credential substitution (F-1); both take `fields` (`ADR-078`) |
| `credmgr_rotate` | `credmgr_rotate` | ✅ | **built** |
| `credmgr_remove` | `credmgr_remove` | ✅ | **built** — soft |
| `credmgr_undo` | `credmgr_undo` | ✅ | **built** — keep-both retained |
| `credmgr_recent_changes` | `credmgr_recent_changes` | ✅ | **built** — redacted |
| `credmgr_list_projects` | `credmgr_whoami` | ✏️ | **built** — ⚠️ **V1 listed every project to every agent.** V2 returns only reachable nodes (F-6) |
| — | `credmgr_totp_code` | ⭐ | **built** — code only, never the seed; takes `field` (`ADR-078`) |
| — | `credmgr_field_add` / `_update` / `_remove` | ⭐ | **built** — `field.add` / `update` / `remove`, no wider than `credmgr_update` / `credmgr_remove` (`ADR-078` D11); `field.reorder` has no tool |
| — | `credmgr_notes_read` / `_write` | ⭐ | **planned** — separate capability, not among the 15 registered tools |

**Tools that must never exist** (enumerated and test-enforced by I-13): grant create/modify ·
orphan read · TOTP seed · node policy change · node reparent · audit purge · cross-node read ·
raw key or file access · topology listing beyond scope.

---

## 4. Tauri IPC commands (V2, new surface)

The desktop shell reaches `credmgrd` the same way every other client does — as a socket peer
over the newline-delimited JSON protocol of §1 — and holds no node key of its own. There is no
second API here: each command is a thin pass-through to one broker op, and the bridge adds no
authorization decision, no reshaping, and no vocabulary of its own.

**Built — all 55 of the broker's ops** (`apps/desktop/src-tauri/src/commands.rs`, `HAND_WRITTEN` 8 + the `bridge_ops!` table 47, counted 2026-10-31): eight
hand-written by ADR-057, because they carry token custody or return `AuthState`, and forty-seven
generated from one `bridge_ops!` table by ADR-062 (2026-09-24; thirty-four at that ADR, five more
the same day with ADR-071…073, `maintenance.rotate_root` with ADR-076, five with ADR-078, `util.generate` with ADR-087, and `vault.approval_get` with ADR-090). Until then this section read *8 of 40*, with the rest deliberately
left unwired. The hand-written eight:

| `invoke()` command | broker op | capability |
|---|---|---|
| `vault_status` | `vault.status` | none |
| `vault_unlock` | `vault.unlock` | none (mints the session token) |
| `vault_gate_verify` | `vault.gate_verify` | none (completes the login) |
| `vault_lock` | `vault.lock` | none |
| `whoami` | `whoami` | none |
| `graph_snapshot` | `graph.snapshot` | `list` |
| `entry_list` | `entry.list` | `list` |
| `entry_reveal` | `entry.reveal` | `reveal` |

**The generated forty-seven** — named `<op with dots as underscores>` — are every other op: `entry.get`, the
entry mutations (`entry.create`/`create_batch`/`update`/`rotate`/`remove`/`restore`/`undo`), the four
`field.*` operations, the
`node.*` family including `node.set_workdirs`, `node.update` and `node.policy`, `notes.*`,
`grant.*`, `totp.*`, `vault.pending_*`,
`vault.approval_decide`, `vault.approval_get`, `vault.node_*`, `vault.init_*`, `vault.gate_enroll_*`,
`vault.gate_recover`, `maintenance.*`, `audit.*`, `util.generate` and `search`. Each is a pass-through that makes no
UX decision: `generation`, presence and approval semantics stay broker-side and reach the UI as the
broker's own error codes. The one thing the bridge adds is additive: the envelope's `audit` id is copied into the
answer of the 24 changing ops in `AUDIT_PASSTHROUGH` (never over a member the broker put there, `ADR-091`), so the
page can ask `entry.undo` for the right record. Four (`totp.seed`, `node.reparent`, `grant.create`, `audit.get`) are
refused with `presence_required` on every call until a presence transport exists, and
`maintenance.rotate_root` is refused the same way once its human, `admin` and second-factor checks
pass (`ADR-076`); `node.policy` refuses a widening patch the same way (`ADR-071`). `vault_status`
returns `AuthState {locked, authenticated, initialized}`, `entry_list` returns `entries` (to a human
session, which every bridge session is) and `notes_read` returns `generation` (`ADR-077`). A typed
TypeScript client for the whole surface is `apps/desktop/src/lib/bridge.ts`, owned by this side
of the contract (`19_FRONTEND_DELIVERY_SCOPE.md §3.3`).

**Four shell commands are not broker ops** (`SHELL_COMMANDS`): `entry_copy` (reveal one field with
`entry.reveal` and put it on the pasteboard concealed, so the value never enters the webview),
`copy_text` (a plain, non-secret string — the donation address), `app_icon_set` (the Dock or window icon, one
of six marks; no vault data, no session) and `fields_preview` (`ADR-078` D5: the
bulk-paste preview, computed in the shell with `credmgr-core`'s parser and inference — no socket, no
audit record, never logged). `entry_reveal` gained `fieldIds`; `entry_create`, `entry_update` and
`entry_rotate` gained `fields`, `entryType` and `sensitivity` (and `field` on the last two);
`totp_code` and `totp_seed` gained `field`.

**The invariants this section asserts, and the tests that hold them.**

1. *No session token crosses into the webview.* ADR-057's rule. Enforced by
   `tests/bridge_wire.rs::no_command_result_ever_serialises_a_token_shaped_string`,
   `the_session_token_is_captured_attached_and_never_returned`, and — across every bridged command —
   `tests/bridge_ops.rs::no_result_across_every_command_carries_a_token_shaped_string`
   (it asserts it swept exactly the bridged surface, all 55 commands).
2. *Every op the broker dispatches has a command, and every command names a real op.* Enforced by
   `tests/drift_guards.rs::the_bridge_covers_every_op_the_broker_dispatches_and_nothing_else`,
   which parses `crates/brokerd/src/ops.rs` rather than trusting this table, in both directions.
   Sibling guards hold every wire key against the op's own arm, every command's registration in
   `generate_handler!`, and all 25 error discriminants against `protocol.rs`; `tests/ts_client.rs`
   holds `bridge.ts` to the same table.

This is the enforcement `§1`'s mapping historically claimed for itself via a test `I-26` that
did not exist (`PROJECT_MAP.md §5.11`). For the IPC surface specifically, the guard is real
and was falsified before being trusted.

## 5. UI routes

> **Status of this section — added 2026-09-21, re-measured 2026-10-03.** The table below is the original
> 22-route plan, kept as the map of what each screen needs from the broker. The hosted design
> (`ADR-075`) implements these as the screens, dialogs and overlays of one page, not as 22 routes.
> Every screen is wired to the broker (`apps/desktop/README.md`): first run, the Lock screen with the
> second factor, the graph, tree and inspector, the entry detail with its fields, Add entry, the review
> tray, nodes with their policy, seal and restore, grants, the audit trail, Verify, Doctor, Back up, root-key
> rotation, settings and About — each control and the bridge command and broker op behind it is listed in
> `RELEASE_VERIFICATION.md`. Five operations are sent for real and refused with `presence_required`
> (grant creation, the full audit record, a TOTP field's "show seed", root-key rotation, a registry
> rebuild); the app says so and changes nothing.

| Route | View | Modes |
|---|---|---|
| `/` | graph (or tree, remembered) + inspector | both |
| `/node/:id` | node selected | both |
| `/node/:id/entry/:eid` | entry detail | both |
| `/orphan` | sealed panel | both |
| `/settings/{security,appearance,backup,mode}` | | both |
| `/settings/{nodes,grants,agents,llm,maintenance,audit,advanced}` | | **Pro** |
| `/settings/{about,donate,privacy,licenses}` | | both |
| `/operations` | the Operations panel | **Pro** |
| `/locked` | lock screen | both |
| `/onboarding/:step` | first run | both |

---

## 6. Coverage assertion

| Surface | V1 | Carried | Reshaped | Merged | Removed | New | **Accounted** |
|---|---|---|---|---|---|---|---|
| HTTP → broker | 57 | 37 | 6 | 4 | 10 | 39 | **57/57 ✅** |
| CLI | 37 | 30 | 6 | — | 1 | 15 | **37/37 ✅** |
| MCP | 10 | 8 | 2 | — | 0 | 6 | **10/10 ✅** |

Re-counted 2026-10-31 route by route against `v1/lib/server.js` (carried = ✅ and 🔒 rows; the four integration
routes count as four removals, the two export-password routes as two; `GET /api/stats` was the one route with no row
and is now a removal) and against `v1/mcp/server.js`; the earlier row summed to 50 and the CLI row to 36 while
claiming 57 and 48. "New" is the ops in this index with no V1 route: 39 for the broker (34 built, 5 planned), and for the
MCP 4 built tools (`credmgr_totp_code`, `credmgr_field_add`/`_update`/`_remove`) plus the 2 planned notes tools.

Every removal has a stated reason above.

> **⚠ Correction, `2026-08-17`: this section previously claimed a test `I-26` "added in Pass 3"
> parses this document and asserts the index cannot silently drift from the broker. That test
> does not exist and never did** — the isolation suite runs `I-1`…`I-25` and stops
> (`grep -rn "I-26" crates/` returns nothing). The claim was written in Pass 3 as a design
> intention and then read by later sessions, and by `19_FRONTEND_DELIVERY_SCOPE.md`, as an
> existing guarantee. **This index is maintained by hand and can drift silently.** Re-verify it
> against `crates/brokerd/src/ops.rs`, `crates/mcp/src/tools.rs` and `crates/cli/src/main.rs`
> before trusting it. Writing the real `I-26` is named as open work in `PROJECT_MAP.md §5`.

## 7. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `10_API_AND_MCP.md §1` | the wire shape every V2 op in this index conforms to |
| depends on | `06_ACCESS_GRAPH.md §3` | the capability each op is authorised against |
| feeds | `19_FRONTEND_DELIVERY_SCOPE.md §2` | which operations a delivered screen can actually call today |
| feeds | `13_TEST_PLAN.md §4.1` | the op inventory the isolation suite is measured against |
| depends on | `14_DECISIONS.md` | `ADR-019` (no HTTP surface), `ADR-055` (`entry.undo`/`restore`), `ADR-056` (session login), `ADR-059` (the status vocabulary this rewrite applies), `ADR-071`…`ADR-073` (`node.update`/`node.policy`, `notes.*`, `entry.create_batch`), `ADR-076` (`maintenance.rotate_root`), `ADR-077` (`vault.status` `initialized`, `entry.list` `entries`, `notes.read` `generation`), `ADR-078` (`entry.get`, `field.*`, the field-addressed params), `ADR-079` (durable `node.seal` / `node.restore`, the staged approval), `ADR-083`…`ADR-089` (`privateNames`, canonical names, `requireTwoFactor`, `entry.undo`'s answer, `util.generate`, the locked decision, the seal purge), `ADR-090` / `ADR-091` (`vault.approval_get`, `pendingApprovals`, `warnings`, the audit pass-through), `ADR-092` (Doctor's purge is its own row), `ADR-093` (name caps, the vault-wide second factor) |

## 8. Source

**Design.** `ADR-019` removed the HTTP surface; `ADR-059` defines the `built`/`partial`/`planned`
vocabulary each row now carries, beside `removed`; `ADR-061` added the two-phase vault bootstrap in `§1.1`;
`ADR-062` bridged every op (`§4`); `ADR-064` and `ADR-066` added the last two `§1.8` rows;
`ADR-071`, `ADR-072` and `ADR-073` built `node.update`/`node.policy`, `notes.read`/`notes.write`
and the single-value `entry.create_batch` (`§1.2`, `§1.3`); `ADR-076` built `maintenance.rotate_root`
(`§1.4`), `ADR-077` added the response fields noted in `§1.1`–`§1.2`, `ADR-078` built `entry.get` and the
four `field.*` operations (`§1.2`), `ADR-079` made `node.seal` / `node.restore` durable (`§1.3`), `ADR-083`…`ADR-086`
enforced `privateNames` and `requireTwoFactor`, made names canonical and gave `entry.undo` its answer (`§1.2`, `§1.3`, `§1.8`),
`ADR-087` built `util.generate` (`§1.4`), `ADR-088` and `ADR-089` added the locked decision and the seal purge (`§1.4`, `§1.8`),
`ADR-090` built `vault.approval_get` (`§1.8`) and `ADR-093` capped names (`§1.2`, `§1.3`).

**Code.** `crates/brokerd/src/ops.rs` — 55 dispatched ops (count with
`tools.corpus_check.broker_ops()`, never a grep; 55 on 2026-10-31), the authority for every **`built`** marking in
this document. `crates/mcp/src/tools.rs` — 15 registered tools. `crates/cli/src/main.rs` — 27
top-level subcommands. `apps/desktop/src-tauri/src/commands.rs` — 55 bridge commands for broker ops
and 4 shell commands. `crates/brokerd/src/protocol.rs` — 25 error codes.

**Verification.** `python3 -m tools.corpus_check endpoints` — proves both directions. Green as of
2026-10-31 (`python3 -m tools.corpus_check`: clean; every row's marker was also compared with `ops.rs` by hand that day, and no `planned` row names a dispatched op). (It went red on `2026-08-31`, when ADR-061 shipped `vault.init_begin`/`vault.init_confirm`
without indexing them here — exactly the shipped-but-undocumented direction it exists to catch — and
was red until the `§1.1` rows were added on `2026-09-13`.)
The per-row statuses were computed from `ops.rs` rather than typed by hand, so a row
cannot disagree with the broker without the check failing — except for the one drift class that
check cannot see (a row marked `planned` for an op the broker already dispatches), corrected in
`§1.3` on `2026-08-23` and folded into the figure below.

## 9. Operation surface: built vs. documented, by namespace

<!-- figure:op-surface-built-vs-planned -->

Every operation named anywhere in `§1`, grouped by its `noun.` namespace and split into what
`crates/brokerd/src/ops.rs` actually dispatches today versus what this index documents but does
not yet dispatch. 55 built against 83 documented (recomputed 2026-10-31: `ADR-087` built `util.generate`, already
documented, and `ADR-090` added `vault.approval_get`, the one new row; 53 against 82 on 2026-10-03, after `ADR-078` built `entry.get` and
the four `field.*` operations — all five already documented, so the documented total did not move;
48 against 82 on 2026-10-02, after `ADR-076` added `maintenance.rotate_root`; 47 against 81 on
2026-09-24 a second time, after ADR-071…073 built `node.update`, `node.policy`, `notes.read`/`notes.write`
and `entry.create_batch`, all five already documented; 42 against 81 earlier that day, after `§1.8` gained
`vault.gate_recover` and `node.set_workdirs`; 40 against 79 on `2026-09-13`) — the built surface (`§8`'s 55
dispatched ops) is about two thirds of the documented one — and the gap sits almost entirely in four
namespaces that are **currently zero built**: `merge.*` (8), `agent.*` (4), `llm.*` (4), `keystore.*` (3)
(`notes.*` left this list with ADR-072, `field.*` with ADR-078 and `util.*` with ADR-087). That is 19 of the 28 planned operations —
over two-thirds of all undispatched work — sitting behind namespaces that have not been started at all, not
thinly spread across otherwise-built ones. The other nine are `entry.*` (5 of 15 documented not built:
`search`, `get_by_ref`, `history`, `move`, `expiring`), `audit.*` (`report`, `purge`), `vault.set_passphrase` and `node.export`. `entry.*` (10 of 15 built) and `vault.*` (16 of 17) carry the
largest raw counts and are mostly or almost entirely built; `node.*` is 8 of 9 and `merge.*` is the one mid-size namespace with nothing built.

**Source.** Derived, not hand-entered: `tools/visual-engine/renders/golden/VIS-ENDPOINT-001.job.json`
re-runs the same extraction `tools/corpus_check.py::check_endpoints` uses over
`18_ENDPOINT_INDEX.md §1`'s tables (expanding each mapping cell's bundled op names), corrected
against `crates/brokerd/src/ops.rs` for the one row `§1.3`'s correction note names. Spec:
`v2/docs/18_ENDPOINT_INDEX_spec.json`. **The rendered figure is pre-ADR-061** — it was derived
before `vault.init_begin`/`vault.init_confirm` existed, so it still shows 38 built against 77
documented and its `vault.` bar is two short of the `2026-09-13` counts — three short of the
current ones, and its `node.` bar one short, since ADR-064 and ADR-066; since ADR-071…073 its
`node.` bar is three short, its `entry.` bar one short, and its `notes.` bar shows none of the two
built; since ADR-076 its `maintenance.` bar is one short; since ADR-078 its `entry.` bar is one further
short (`get`) and its `field.` bar shows none of the four built; since ADR-087 its `util.` bar shows 0 of 1 built, and
since ADR-090 its `vault.` bar lacks `approval_get`. The live counts are 55 built against 83 documented; the job was not re-run on 2026-10-31.
Re-running the job restores agreement.
