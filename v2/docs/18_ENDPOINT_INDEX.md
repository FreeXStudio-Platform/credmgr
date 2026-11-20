---
id: V2-018
classification: public
title: Endpoint index
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-11-07
---

<!-- artifact-hardened: NEEDS RE-HARDENING — the merge.* rows (§1.5), the entry.tag_set row (§1.8) and the counts (ADR-167, ADR-168, feat/rc2-v1-gaps, 2026-11-20) and the credmgr edit line (feat/rc2-editor, 2026-11-20) was added after the last pass; that pass was: Approved With Known Risks @ 3ba7435 on 2026-11-14 via three-pass-v1. Evidence: this pass against 3ba7435 (PR #69 merges of feat/doctor-scan (ADR-158 entry.move, ADR-161 vault.doctor_scan) and feat/qr-import-diag-log (ADR-159 diagnostic log, ADR-160 QR import), merge commits 77b9243 and 6a54ee1: 93 ops checked against crates/brokerd/src/ops.rs arms (corpus_check.broker_ops 93, src-tauri drift_guards 93 bridged + 17 shell, diag_log::KNOWN_OPS test now lists entry.move and vault.doctor_scan), crates/mcp/src/tools.rs (21 tools; entry.move and vault.doctor_scan in FORBIDDEN_OPS), core error.rs unchanged (27 error codes), cli main.rs dispatch (+move, 46 commands; doctor --scan and status --log are flags); ADR-158 to ADR-161 kept in number order in 14_DECISIONS; rust workspace 1231 tests green, clippy --all-targets -D warnings and fmt clean; endpoint matrix 93/93 ops, 347 rows; e2e-journey all passed; airlock-check PASS; desktop shell 226 tests green incl. drift_guards 9 and real_broker 4, clippy -D warnings and fmt clean; desktop vitest 854 green with the 7 known Node 22 failures in adr090-091.test.ts that main has too, binding count 860 (825 + 14 move + 14 doctor + 7 QR); npm run check clean; gen_help --check (182 topics), release_verification_check (351 rows in 30 templates) and corpus_check clean apart from these stamps; secret and personal-data guards clean after two fake home paths in the ADR-159 tests were renamed (19a8c2b); semgrep, cargo deny and cargo audit not run here (not installed); the new controls not pressed in a built app (K-F)); earlier: this pass against d37fe9f (ADR-156 quick wins: ops and counts checked against crates/brokerd/src/ops.rs arms (91, corpus_check.broker_ops), crates/mcp/src/tools.rs (21 tools, unchanged), cli main.rs and quick_cmds.rs usage (45 commands), desktop drift guards (91 bridged + 17 shell); K-1, K-9, K-10 (a, e), K-23 (a, b, d), K-24 entries checked against the named tests; rust workspace 1187 tests green, clippy -D warnings and fmt clean; endpoint matrix 91/91 ops, 340 rows; e2e-journey all passed; airlock-check PASS; desktop shell 216, drift guard 44/44; corpus_check, gen_help --check, release_verification_check clean; secret and personal-data guards clean); earlier: this pass against 4f0f212 (ADR-155 switchboard: settings.* rows and counts checked against crates/brokerd/src/ops.rs arms (84, corpus_check.broker_ops), crates/mcp/src/tools.rs (21 tools, I-13), cli settings_cmd.rs; rust workspace 1158, shell 219, vitest 772, e2e 814 green; corpus_check, gen_help --check, release_verification_check clean; secret scan clean); earlier: prior verifier passes (3abb4fe, 320a8f2) and this pass 3 against the code at 9bc33d7 (corpus_check broker_ops 76; 27 error codes; highest ADR 152; --security-level strict alias of stored sealed in cli main.rs; "Strict (stored as sealed)" in core agentcfg.rs and brokerd ops.rs; search entries, hide seed, re-masks in, Settings › Security groups in apps/desktop); independent ADR-150 review P0/P1 fixed with refusal tests (19ccf39); CI green on PRs #56–#60 (17 checks each); full gates.sh green at dbef0c7 incl. legacy alpha.6; VoiceOver pass 2026-11-08, two defects fixed (ACCESSIBILITY.md, #22 closed); Touch ID, idle and screen lock, ADR-150 confirm checked by hand (RELEASE_VERIFICATION §14, §15 and addenda); corpus_check, gen_help --check, release_verification_check clean; secret scan clean. Known risks: K-A not signed or notarised (bound: Gatekeeper quarantine, SHA256SUMS only provenance, Apple Silicon only; owner: operator; resolution: scripts/sign-notarise.sh with a Developer ID before publishing rc.1); K-B per-control re-press of all rows and the built-app look of the 2026-11-08 design merge (§16) not done by hand (bound: §15 spot re-walk of every screen plus e2e/design audit; owner: operator; resolution: record in RELEASE_VERIFICATION before publishing); K-D Touch ID dialog residual, PHASE8 K-21 (bound: refused to identified agents, dialog names the requester, back-off after five; owner: backend and the user at the dialog; resolution: stated in SECURITY.md, none planned for 2.0.0). K-F the ADR-156 app screens (change passphrase, start at login, Touch ID row, anomaly bar), the ADR-157 screens (expiry chip and dialog, History tab), the ADR-158 Move to project control and dialog, the ADR-161 Tidy up screen and its Settings and Operations entries, the ADR-160 2FA QR drop area and file picker (with dragDropEnabled false), the bundled credmgrd and the macOS launchctl path not pressed in a built app (bound: unit, fixture-broker, bridge and drift tests, release self-test case; RELEASE_VERIFICATION rows marked not pressed; owner: operator; resolution: press the nine ADR-156 rows, the fourteen ADR-157 rows, the six ADR-158 rows, the seven ADR-161 rows and the two ADR-160 rows before publishing). Not a claim about anything after 3ba7435. -->
# Endpoint index — every surface, indexed and mapped V1 → V2

`CredMgr V2` · the mapping from V1's surface to V2's, and what of V2's surface exists today · `2026-10-31`

> **Status.** The mapping itself is complete and `verified-current`. **What changed in this
> rewrite is that it now distinguishes what is built from what is designed.** Every row carries
> **`built`**, **`planned`** or **`removed`** (a row may also be **`partial`**; none is, as of
> 2026-10-03, when `entry.create_batch` became fully built): 63 built, 1 planned, 6 removed and 1 dropped row across the mapping tables
> (§1.1–§1.7; a row counts under the marker its Notes cell opens with; re-counted 2026-11-20 when the rc.2 line merged `ADR-163`'s ⭐ `vault.recover` row, `ADR-164`'s four built `agent.token_*` rows and `ADR-165`'s built `keystore.*` row with `ADR-168`'s eight built `merge.*` rows; 49/14 on 2026-11-14 after `ADR-158` built the planned `entry.move` row; 48/15 on 2026-11-09 after `ADR-156` built five planned rows; 43/20 on 2026-11-07, 34/23/6 on 2026-10-31), plus the 35 operations in §1.8
> that have no V1 ancestor and were previously indexed nowhere at all (ten at this rewrite, twenty-one
> since 2026-11-06, thirty-two since 2026-11-09, thirty-three since 2026-11-14, thirty-five since 2026-11-20). In operations rather than rows: **111 built and 1 planned** (§9). Before this pass the document
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
| `POST /api/unlock` | `vault.unlock` | 🔒 | **built** — now also requires gate 2FA before node keys load (`07 §3`); `method: "device"` (Touch ID) is refused before any prompt to an agent token or a call from inside a registered project folder, the dialog names the requester, and a dismissal or timeout counts in the back-off (ADR-148) |
| `POST /api/lock` | `vault.lock` | ✅ | **built** — drops the resident root key and zeroises every hot node key, ends every login session and second-factor elevation, and voids any value staged for an approved request (the lock epoch moves; no manifest `generation` does) |
| `POST /api/pin` | `vault.set_passphrase` | ✏️ | **built** — `{passphrase, newPassphrase}` → a new recovery code, shown once (`ADR-156`). The same gates and crash-safe rotation as `maintenance.rotate_root`: a human login, `admin` on Global, a fresh vault second factor when one is enrolled, a presence proof when a presence key is enrolled (with none, the current passphrase proven inside the rotation is the proof a person is here). The same passphrase twice is `malformed_request`. Every live node also gets a new keypair in the same commit (`nodesRekeyed`, `filesResealed`; ADR-165 N5). CLI `credmgr passphrase` (both values on stdin or prompted, never argv); the app's Settings row. Not an MCP tool |
| — | `vault.recover` | ⭐ | **built** — the passphrase is forgotten: `{recoveryCode, newPassphrase, code?}` opens a **locked** vault with the printed recovery code alone and, in the same crash-safe root rotation `vault.set_passphrase` uses, sets the new passphrase and answers a **new** recovery code once (the used code and the old passphrase stop opening anything) plus a login token (`ADR-163`); every live node gets a new keypair in the same commit (`nodesRekeyed`, `filesResealed`; ADR-165 N5). No login needed; refused to an agent token or a call from inside a registered project folder (before any code is read; on a broker that has not loaded the vault yet, once the code has loaded it and before anything changes); an enrolled second factor is still required (`code`: a TOTP code or a gate backup code; without it `two_factor_required`), Touch ID is not; a wrong code is `recovery_code_mismatch` and counts in the shared unlock back-off with a wrong second factor (`gate_verification_failed`); an open vault is `malformed_request`; a vault with no `root.wrap.recovery` is `not_found` (`vault.status` answers `recoveryUnlock: false`). Every attempt is audited, one refused while locked at the next unlock. CLI `credmgr recover` (stdin only); the app's Lock screen "Forgot passphrase?". Not an MCP tool |
| — | `vault.node_lock` / `node_unlock` | ⭐ | **built** — per-node lock (F-7) |
| — | `vault.pending_list` / `pending_accept` / `pending_discard` | ⭐ | **built** — the locked-write review tray (F-1); accepting or discarding is refused to any agent-origin caller (`capability_not_held`, ADR-148 P1-4) |
| — | `vault.init_begin` | ⭐ | **built** — vault bootstrap, phase 1 (ADR-061): generates the root key, wraps it, returns the recovery code exactly once. No V1 HTTP route — V1's `init` was CLI-only (`§2`) |
| — | `vault.init_confirm` | ⭐ | **built** — vault bootstrap, phase 2 (ADR-061): takes the retyped recovery code and writes the vault. Refuses if a vault already exists |

### 1.2 Credentials → entries

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/credentials` | `entry.list` | 🔒 | **built** — scope-filtered by the access graph; plus `entries` manifest metadata (type, sensitivity, field count, dates, `hasTotp` — ADR-080) for **human sessions only** (`ADR-077`), same gate and filter as `ids` — an agent never receives it. A node with `privateNames` answers `ids`, `names` and `entries` empty with `nameHidden: true` and a `count` (hidden below three entries) to everyone but the owner's login (`ADR-083`); a node whose `requireTwoFactor` is `always` answers `two_factor_required` to a caller with no live second factor (`ADR-085`). CLI: `credmgr list` |
| `GET /api/search` | `entry.search` | 🔒 | **built** — `{node, term}`: names and aliases on one node containing `term`, case-insensitive; never values (F-18). The same gate as `entry.list`; a name-blind reader of a private node gets nothing (`ADR-156`). The cross-node form is the top-level `search` (§1.8). Not an MCP tool |
| `GET /api/credentials/:name` | `entry.get` | ✅ | **built** — metadata: the entry's type, sensitivity, `fieldCount`, `hasTotp`, dates, generation, and for each field its id, label, type and masking (and whether the type / masking is a user override) — **never a value** (`ADR-078`). `read`; needs the node unlocked, because the labels are encrypted with the values (`vault_locked` for a locked vault, `node_locked` for a locked node, no approval path); a held (tray) entry is `not_found`. `two_factor_required` on an `always` node (`ADR-085`); on a `privateNames` node the entry `name` and every field `label` come back `null` for anyone but the owner's login (`ADR-083`). CLI: `credmgr field ls`; MCP: `credmgr_get_metadata` |
| `GET /api/credentials/:name/value` | `entry.reveal` | 🔒 | **built** — when the vault has a confirmed gate and the node asks for a second factor (`reveal`, the default, or `always`), a caller with no live one gets `two_factor_required` (`ADR-085`; the owner's login is exempt); `approval_pending` when the vault or node is locked and the entry exists (an unknown entry is `not_found`, so invented ids cannot grow the request table). Takes `fieldIds` (a non-empty subset; every id must exist, else `not_found` with no partial answer) and answers `fields: [{id, label, value, type, masked}]` in stored order, plus `value` **only when exactly one field is returned** (`ADR-078`); an approval covers the entry and `fieldIds` narrows the approved answer (`ADR-079`: the value is staged when the decision is made; since `ADR-088` a wholly locked vault records the request and answers `approval_pending` as well, so it can be decided with the unlock factors). With the vault's "confirm before showing secrets" policy on (`ADR-150`), a non-agent caller with no confirmation that meets the policy for the entry's sensitivity gets `confirmation_required` (`operation`, `mode`, `windowSeconds`, `remedy`), checked after every access, approval and second-factor check and after the answer is built (so a bad `fieldIds` never spends a confirmation); a value an approval staged (`ADR-079`) is gated the same way before the approval is consumed; an entry with no manifest row is gated as critical; the shell's `entry_copy` reveals through this op and is gated the same way; agents are not asked |
| `GET /api/ref/:ref` | `entry.get_by_ref` | ✅ | **built** — `{reference}` → `{node, entry, name, ref}`; refs stay vault-global. Only entries the caller could already list are candidates, so a ref in an unreachable node is the same `not_found` as no such ref (I-3, `ADR-156`). CLI `credmgr ref <n>`. Not an MCP tool |
| `POST /api/credentials` | `entry.create` | 🔒 | **built** — works while locked → pending tray (F-1). Exactly one of `value` (with an optional `label`) or `fields: [{label, value, type?, masked?}]`, plus optional `entryType` / `sensitivity` (`"auto"` clears an override); the answer carries `fieldCount` and `fieldIds` (`ADR-078`). A name over 200 characters is `malformed_request` (`ADR-093`); names are compared in canonical form, so a look-alike twin is `entry_exists` and a name mixing Latin with Greek or Cyrillic is accepted with `warnings: ["mixed_script_name"]` (`ADR-084`). CLI: `credmgr set` (`--bulk`, `--field`) |
| `PATCH /api/credentials/:name` | `entry.update` | 🔒 | **built** — **requires unlock** (F-1). Takes `value` (with `field` naming the field on a multi-field entry, and an optional `label` rename) **or** `fields` (replace the whole list; an `id` keeps a field's identity), and/or `entryType` / `sensitivity`; keeps no history (`ADR-078`) An agent change that lowers an entry's effective sensitivity on a Guarded or Sealed node is refused (`node_access_denied`, rule `L1`, ADR-148). |
| `DELETE /api/credentials/:name` | `entry.remove` | ✅ | **built** — soft, 7-day recovery |
| `POST /api/credentials/:name/rotate` | `entry.rotate` | ✅ | **built** — the same body as `entry.update`; keeps the previous envelope (undoable) and stamps `rotatedAt` (`ADR-078`). CLI: `credmgr rotate` (`--field`) |
| `GET /api/credentials/:name/history` | `entry.history` | ✅ | **built** — `{node, entry, limit?}`: every audit record naming the entry, oldest first (the newest `limit` kept), plus the rotation and edit times the manifest holds; actions, times, decisions and the redacted actor, never a value. Gated on `list` for the entry; human sessions only (`ADR-156`). CLI `credmgr history`. Not an MCP tool |
| `POST /api/credentials/batch` | `entry.create_batch` | ✅ | **built** — `{node, entries: [{name, value?, label?, fields?, entryType?, sensitivity?}]}`, 1–500 entries; every item is validated and encoded before the first write (each document ≤ 16 MiB, the batch ≤ 64 MiB), a locked vault holds the whole batch in the pending tray, a part-way failure answers `complete: false`; each item's name follows the `entry.create` rules, the 200-character cap included (the refusal names the item's index and never the text, `ADR-093`), and a twin of an earlier item is `malformed_request` (`ADR-073`, multi-field since `ADR-078`; the split-by-`///` toggle is one item per segment). CLI: `credmgr import <file\|-> --node <id>` (an all-or-nothing `.env` import) |
| — | `field.add` / `update` / `remove` / `reorder` | ⭐ | **built** — fields are first-class in V2 (`ADR-078`): `update` capability, unlocked, generation-checked; `add` appends (or inserts at `position`), `update` takes a `patch` (`label`, `value`, `type`, `masked`; `"auto"` clears a pin), `remove` refuses the last field, `reorder` takes an exact permutation of the ids; each keeps the previous envelope and is undoable through `entry.undo`. CLI: `credmgr field add\|set\|rm\|mv`; MCP: `credmgr_field_add` / `_update` / `_remove` (`reorder` has no tool) |
| — | `notes.read` / `notes.write` | ⭐ | **built** — the privacy-vault half (`ADR-072`): one markdown note per node, sealed under the node key, gated on the separate `notes` capability (never implied by `read`) and bound to the manifest's `notesSha256`. `notes.read` also returns the manifest `generation` a write must be based on (`ADR-077`), and answers `markdown: null` to anyone but the owner's login on a `privateNames` node (`ADR-083`). CLI: `credmgr notes show` / `notes set` / `notes clear`; no MCP tool reaches it yet (§3) |

### 1.3 Projects → nodes

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/projects` | `node.list` | 🔒 | **built** — returns only reachable nodes (F-6) |
| `PATCH /api/projects/:id` | `node.update` | ✅ | **built** — rename (`label`) only (`ADR-071`): trimmed, 1–120 characters, no control characters, and a label mixing Latin with Greek or Cyrillic is accepted with `warnings` (`ADR-084`); the id never changes, so grants, workdirs and scopes are untouched. Global and Orphan refuse. Human-only; on the MCP forbidden list. CLI: `credmgr node rename` |
| `DELETE /api/projects/:id` | `node.seal` | ✏️ | **built** — **seal, never delete** (ADR-007). Durable since `ADR-079`: the seal record lives in the signed registry, the orphan node and its cold key are made by `credmgr init` (or lazily by the first seal in an older vault), and a crash at any step leaves a vault that unlocks. Refuses a node with live sub-nodes and an id that is already sealed. `archiveMovePending: true` in the answer means the file moves after the commit will finish at the next unlock |
| `POST /api/projects/:id/reassign` | `entry.move` | ✏️ | **built** (`ADR-158`) — moves one entry to another node, re-sealed to that node's key in one crash-safe step: copies of both manifests and a sealed plan are staged, the registry write binding both new manifests is the commit, and the next load settles a leftover stage forward or back, so the entry is never readable in both nodes and never lost. Keeps the id, reference, name, aliases and expiry; revokes grants on the entry; drops its rotation history (`historyDropped`). Takes the source's `generation` (`conflict` when stale) and answers the destination's as `toGeneration`. A name or alias the destination uses is `entry_exists`. The owner's login only, `Admin` on both nodes, a fresh second factor and a presence proof on every call; on the MCP forbidden list. Audit: the request's record names the source, an `entry.move` record names the destination (`moved from <source>`), and `entry.history` follows the move. CLI: `credmgr move`; desktop: Move to project… in the entry inspector |
| — | `node.create` · `node.reparent` · `node.restore` | ⭐ | **built** — `reparent` is scope-widening → grant gate (F-8). `node.create` enforces the node-id grammar `[a-z0-9][a-z0-9_-]{0,63}` and reserves `global`, `orphan`, `removed-entries`, `entry-history`, refuses the id of a node whose archive still exists (`ADR-079`), validates `label` like `node.update` (1–120 characters, no control characters; `ADR-093` — before that creation took any label), and waits for a seal or restore in flight (`ADR-089`). `node.restore` (inside the 7-day window, across restarts) refuses a sealed parent and reports `workdirsDropped` for a workdir another node now owns |
| — | `node.policy` | ⭐ | **built** — a partial patch of the policy fields (the six of `ADR-071`, plus `securityLevel`, `ADR-140`, and `revealConfirm`, `ADR-150`, which is accepted on `global` only and is otherwise `malformed_request`) with a mandatory `reason`, recorded in the audit record (`ADR-071`). Tightening applies at once; a widening (`descendantRead` on, `siblingVisibility: shared`) and lowering a security level need a presence proof (`ADR-098`, `ADR-140`), else `presence_required` and nothing applies. A `revealConfirm` change is the owner's login only; one that makes it ask less (off, a longer window, back from every time, all → high) needs a confirmation from the last 60 s, which it uses up, else `confirmation_required` with `operation: "node.policy"`; asking more needs nothing. The original six fields are enforced: `privateNames` since `ADR-083`, `requireTwoFactor` since `ADR-085` (a policy change ends every second-factor elevation); `notEnforced` stays in the response as an empty list. `reason` is 1–500 characters. Human-only; on the MCP forbidden list. CLI: `credmgr node policy` |
| — | `grant.list` / `create` / `revoke` | ⭐ | **built** — `admin` capability, so no agent holds it. `list` and `revoke` answer a human session; `create` validates everything and is then refused with `presence_required` on every call until a presence transport exists (issue #18, `2.0.0-rc.1`) An entry-level grant (`to: {kind: "entry", nodeId, entryId}`, `ADR-172`) is `read` and/or `reveal` of that one entry, one-way, and lists that entry only (an implied `list` in `resolve()`); `create` refuses `notes`, `list`, `mutual` and an entry the node does not hold for an entry target, and `entry.reveal` / `entry.get` / `totp.code` honour it for exactly the entry it names (PHASE8 K-10 (b), closed). |

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
| `POST /api/doctor` | `maintenance.doctor` | ✅ | **built** — gains `--rebuild-registry` (F-10; refused with `presence_required` after its other checks). Never destroys anything on a plain run: `purgeExpiredSeals` defaults to **false** and must be sent as `true` to remove the retained originals of a seal whose seven days are over (`ADR-089`; `admin` on `global`, vault unlocked; with `apply: false` it only lists `would-purge-expired-seal`, and `malformed_request` if it is not a boolean). CLI: `credmgr doctor [--dry-run] [--purge-expired-seals] [--rebuild-registry]`. The desktop's plain Doctor sends no purge (`ADR-092`). The owner's tidy-up scan of entries is a separate op, `vault.doctor_scan` (`ADR-161`, §1.8); this one is unchanged |
| `POST /api/backup` | `maintenance.backup` | 🔒 | **built** — operator-invoked only: `admin` on `global`, takes a non-empty `passphrase` and `retain` (default 14), writes an encrypted file and prunes older ones. F-16's automatic daily and pre-destructive firing is **not built** — the broker has no scheduler (`ADR-039`); no GitHub issue tracks it |
| — | `maintenance.rotate_root` | ⭐ | **built** — replace the root key: a new root key, every node key re-wrapped, both root wraps rewritten, every root-signed file re-signed, a **new recovery code** issued once (`ADR-076`). Crash-safe: stage, one atomic commit record, idempotent roll-forward; recovery is key-free, runs at start-up and at every unlock, and is serialised against a rotation by a per-vault lock. Takes `{passphrase}`. Human only, `admin` on `global`, a fresh vault second factor (`two_factor_required`), then **presence**: the wire answers `presence_required` until a transport can attest it (`ADR-047`), and the logic is tested directly (§4.2 of `10`). On the MCP forbidden list (absent, not gated); on the per-uid auth backoff. No V1 ancestor; no CLI command yet |
| `GET /api/generate` | `util.generate` | ✅ | **built** (ADR-087, 2026-10-24) — the broker makes the password (`length` 8–128, `symbols`, `pronounceable`, `hex`; `hex` excludes the other two) and answers `{value, length, symbols, pronounceable, hex, entropyBits}`; needs `create` or `update`; not an MCP tool. CLI: `credmgr generate` |
| `PUT /api/entries/:id/aliases` | `entry.alias` | ✅ | **built** (ADR-121) — sets the whole list of other names an entry answers to (at most 8, generation-checked); a name or alias another entry has is `entry_exists`; human sessions with `update`; not an MCP tool. CLI: `credmgr alias` |
| `GET /api/entries/similar` | `entry.similar` | ✅ | **built** (ADR-121) — which names of a node resemble a candidate and whether it is taken; `list` capability; not an MCP tool. CLI: `credmgr similar` |
| `POST /api/entries/import-env` | `entry.import_env` | ✅ | **built** (ADR-122) — parsed `.env` pairs into one node; `dryRun` previews, otherwise each pair is its own entry with its own audit record; no answer carries a value; `create` capability; not an MCP tool. CLI: `credmgr import-env` |
| `GET /api/expiring` | `entry.expiring` | ✅ | **built** — `{days?, node?}`: entries expiring within `days` (default 30, at most ten years; already expired included), across every node the caller may list or one node, soonest first; names, ids, refs, `expiresAt`, `rotatedAt`, never a value. Human sessions only (`ADR-156`). CLI `credmgr expiring`. Not an MCP tool |
| `GET /api/audit` | `audit.report` | ✅ | **built** (ADR-134, 2026-11-06) — a summary of the audit log for `[from, to)` (≤ 366 days): records, decisions, counts by action / actor / node, denials by action and error tag with the 25 newest, presence uses and refusals, and whether the month's hash chain verifies now. Owner login with `admin`; no value, no entry name, none of the free text a person wrote; not an MCP tool. CLI: `credmgr audit report (--days N \| --from … --to …) [--node id] [--json]`. The stale-grant sweep is **not** part of it |
| `GET /api/access-log` | `audit.tail` | 🔀 | **built** — one hash-chained log replaces changelog + access-log |
| `GET /api/export/:project` | `node.export` | 🔒 | **built** (ADR-133, 2026-11-06) — owner, `reveal` on the node, a fresh second factor (the vault's and the node's own, when it has one) and a presence proof. Built **inside the broker** and answered as age ciphertext (`archive`, base64) for one passphrase (12+ characters) or `age1…` recipients; stored 2FA seeds are left out and counted (`omittedSeeds`); notes are not included. CLI: `credmgr export --node X --out FILE --age [--age-recipient age1…]… [--force]`, written mode `0600` to a file only, never stdout. Off the MCP tool list |
| — | `node.rekey` | 🔒 | **built** (ADR-130, 2026-11-06) — a new keypair for a node and every file sealed to the old one re-sealed (entries, note, retained history, removed entries; digests and the signed records that carry them), as a crash-safe commit protocol with recovery on every load. Owner, `admin`, a fresh second factor, a presence proof; runs under the exclusive request barrier; refuses `orphan`, a sealed node and a node with locked-write tray entries. CLI: `credmgr node rekey <id>` |
| — | `orphan.destroy` | 🔒 | **built** (ADR-131, 2026-11-06) — permanently delete sealed entries and the archives behind them: owner, `admin`, `confirm: "destroy-sealed-entries"`, `count` equal to what the call would destroy, a fresh second factor, a presence proof; journalled so a crash after the commit still finishes the deletion. Never undoable. CLI: `credmgr orphan ls`, `credmgr orphan destroy (--all \| ids) --count N --confirm destroy-sealed-entries` |
| — | `search.content` | ✅ | **built** (ADR-132, 2026-11-06) — find entries by what their field **values** contain; answers `{results: [{node, id, name}], truncated}` and nothing else. `reveal` capability; term 3–200 characters; 12 calls per minute per caller; a private node is never searched for a reader who may not see its names; a stored 2FA seed is never matched. Not an MCP tool. CLI: `credmgr search <term> --deep [--node id]` An agent's search skips every entry on a Sealed node and every entry a Guarded node would hold for approval (ADR-148 P2-1). |
| — | `node.gate_enroll_begin` · `node.gate_enroll_confirm` · `node.gate_verify` · `node.gate_remove` | 🔒 | **built** (ADR-135, 2026-11-06) — a project's **own** second factor (ADR-093's known risk, issue #16): its own secret, ten recovery codes, replay ledger and 300-second window. A node that has one is asked for it **even of the owner**; its code opens that node only and the vault's code never opens it. `remove` takes its fresh code and a presence proof, or the passphrase and root recovery code together. `node.rekey`, `node.export` and `node.gate_remove` on such a node also cost its code; it is neither sealed nor released by a locked-vault approval. Not for `global` (`vault.gate_*`). CLI: `credmgr gate enroll\|verify <code>\|remove [--last-door] --node <id>` A node's own gate asks for its code before every reveal whatever `requireTwoFactor` says, and `node.gate_verify` is persisted (ADR-148 P1-2, P2-2). |
| `GET/POST /api/export-password` | — | ❌ | **removed** — V1 protected exports with a separate password. V2 gates on the real factors instead; a second password was a third auth system nobody kept in sync. |
| `GET /api/stats` | — | ❌ | **removed** — no stats op. V1 answered cross-project totals by project, category and sensitivity. Per-node `counts` (`entries`, `totp`) ride on `graph.snapshot` and need no unlock; a total over every node would be an aggregate over nodes the caller may not reach (F-6). The row was missing from this index until 2026-10-31; the CLI's `stats` (§2) is likewise not built |

### 1.5 Merge / suggestions engine

The auto-merge engine **survives**, with its decision memory intact — the user's explicit
requirement. It matters less in V2 (node scoping removes most duplicate causes) so it moves to
**Pro → Maintenance**, but nothing is lost.

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/suggestions` | `merge.suggestions` | 🔒 | **built** (`ADR-168`) — **within one node**, never across a boundary: groups `identical` (every value equal), `shared_value` and `similar_names` (`entry.similar`'s rule), each `{key, kind, reasons, keep, identical, entries:[{entry, ref, name}]}`; values compared inside the broker under an HMAC key drawn per call and dropped (no value, digest or fragment leaves); a node whose own second factor is not open is compared by name only (`valuesCompared: false`); dismissed keys left out unless `includeDismissed`. The owner's login with `admin` on the node; not an MCP tool. CLI `credmgr merge suggest` |
| `POST /api/suggestions/dismiss` | `merge.dismiss` | ✅ | **built** (`ADR-168`) — **the decision memory** — a dismissed key never returns until undismissed or restored; kept per node, sealed to the node's key in `nodes/<id>/merge.env` with its digest in the signed manifest (`mergeSha256`), re-sealed by `node.rekey`; moves the node's generation. CLI `credmgr merge dismiss --group <key>` |
| `POST /api/suggestions/undismiss` | `merge.undismiss` | ✅ | **built** (`ADR-168`) — `{restored}`; CLI `credmgr merge undismiss` |
| `GET /api/suggestions/dismissed` | `merge.dismissed_list` | ✅ | **built** (`ADR-168`) — newest first, each key with its entries' names (`null` for one no longer in the node); CLI `credmgr merge dismissed` |
| `POST /api/suggestions/restore-all` | `merge.restore_all` | ✅ | **built** (`ADR-168`) — forgets every dismissal on the node, answers the count; CLI `credmgr merge restore-all` |
| `POST /api/merge` | `merge.apply` | ✅ | **built** (`ADR-168`) — aliases preserved (V1 4.1): `{node, keep, drop[], generation}` keeps one entry, gives it every dropped name and alias as aliases and the union of the tags, and removes the dropped entries through the `entry.remove` path (7-day archive; `entry.undo` of the answer's `undo` id restores one and takes the merge's aliases off the kept entry). A stale generation `conflict`, an id not in the node `not_found`, more than 8 aliases or 16 tags or a dropped entry with its own grant `malformed_request`, all before a fresh second factor; the generation and plan are checked again under the node's write lock. Audit: one `entry.remove` item event per dropped entry and one `merge.apply` on the kept one. CLI `credmgr merge apply --keep <name> --drop <name>…` |
| `POST /api/merge/auto` | `merge.auto` | ✅ | **built** (`ADR-168`) — one open suggestion, **only when `identical`**, keeping its proposed `keep`; a fresh second factor. CLI `credmgr merge auto --group <key>` |
| `POST /api/merge/auto-all` | `merge.auto_all` | ✅ | **built** (`ADR-168`) — dry-run first, always: without `apply: true` it answers the plan of every open `identical` group and writes nothing; with it (and `generation`, a fresh second factor) it merges them under one hold of the node's lock; a group with a grant on a dropped entry is `skipped`. CLI `credmgr merge auto-all [--apply]` |
| `GET /api/schemas` | — | ❌ | **removed** — `TYPE_SCHEMAS` deleted (ADR-011). Field *types* replace field-name schemas; the column-suggestion UI goes with it. |

### 1.6 Changelog / undo — the 7-day isolation

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/changelog` | `audit.tail` | 🔀 | **built** — always redacted for agents |
| `GET /api/changelog/:id` | `audit.get` | 🔒 | **built** — full record needs presence |
| `POST /api/changelog/:id/undo` | `entry.undo` | ✅ | **built** — `replace` / `keep-both` collision modes retained. Answers `ok: true` and `restored: {action, entry, …}`; a `field.*` edit can be undone for seven days from when it was made, then `not_undoable` (`ADR-086`; no `field.undo` op exists) An agent's undo that would lower sensitivity on a Guarded or Sealed node is refused before anything moves (`L1`, ADR-148). |
| `POST /api/changelog/purge` | `audit.purge` | 🔒 | **planned** — **human only** — no agent path, ever |
| `DELETE /api/changelog/:id` | — | ❌ | **removed** — deleting one record from a hash-chained log breaks the chain. The 7-day window is not user-shortenable (`10 §3.2`). |

### 1.7 Agents & integrations

| V1 route | V2 op | | Notes |
|---|---|---|---|
| `GET /api/daemon-token` | `agent.token_status` | ✅ | **built** (ADR-164) — the live agent tokens as metadata only (id, label, node, capabilities, effective capabilities, created/expires/last-used/rotated times); no part of a secret, so the planned `{hasToken, last4}` became a list. Owner login only. CLI `credmgr agent token ls`. Not an MCP tool |
| `POST /api/daemon-token/rotate` | `agent.token_rotate` | ✅ | **built** (ADR-164) — a new secret for an existing token, shown once, with a new expiry; the old one is refused on its next request. Owner login, a fresh second factor where enrolled and a Touch ID proof. CLI `credmgr agent token rotate <id>`. Not an MCP tool |
| `POST /api/daemon-token/revoke` | `agent.token_revoke` | ✅ | **built** (ADR-164) — the next request with the token is refused (`session_expired`) and audited under its id. Owner login; no proof (it only removes access). CLI `credmgr agent token revoke <id>`. Not an MCP tool |
| — | `agent.token_issue` | ⭐ | **built** (ADR-164) — **node-scoped** tokens: exactly one node (no global, ancestors, descendants or grants), capabilities a subset of `list, read, reveal, create, update` and of the node's `agentAccess`, a label, a mandatory expiry (1 day default, 7 at most); the `cma_` secret is shown once and stored as a hash. Owner login, a fresh second factor where enrolled and a Touch ID proof; never an agent. CLI `credmgr agent token issue <node>`. Not an MCP tool; the MCP server presents it from `CREDMGR_AGENT_TOKEN` |
| `GET/POST/DELETE /api/integrations…` | `integration.*` | ❌ | **removed** — four V1 routes (list, add, toggle, delete); no `integration.*` op exists. The auto-MCP wiring they did is built in the CLI and the app, not the broker (`ADR-143`, `ADR-146`) |
| — | — | ❌ | **dropped (`ADR-146`)** — the four `llm.*` operations the first design planned (`detect`, `connect`, `disconnect`, `prompt`). The wiring is `credmgr mcp --print-config`, `credmgr agent …` and `credmgr prompt` (CLI) and Settings → Agents (app), none a broker operation, because the broker must not write other applications' files |
| `GET /api/machine-lock` + enable/disable | `keystore.status` / `bind` / `unbind` | ✏️ | **built** (`ADR-165`, the smallest safe version `ADR-144` defined; macOS file tier only) — `bind` seals `keys/root.wrap.pass` under a device key at `<state>/machine/lock.key` (0600, outside the vault folder), and is a root rotation that re-keys every project (review P0-1: a new recovery code; an older plain wrap put back opens nothing written after it), so a copy of the vault folder made after the bind does not open elsewhere with the passphrase alone; a missing or different key is `machine_lock_refused` and the recovery code (`vault.recover`, which never needs the key) is the way in, sealing to the new Mac. Owner only, refused to an agent before anything is read, all three on `FORBIDDEN_OPS`; `bind` is two phases (second addendum, N1): `prepare` needs the vault open, `passphrase` and the current `recoveryCode` (both counted in the back-off), every project unlocked and nothing in the tray or the sealed entries, changes nothing durable and answers the new code; `commit` takes that code typed back and only then rotates and re-keys; `unbind` a fresh second factor and Touch ID where enrolled, and `passphrase` where neither is. `status` reports the honest tier (a key file, never the Secure Enclave). Rotation and passphrase change re-seal; `status` names a plain file under a vault this Mac bound (`plainWhileBound`) and projects still on a pre-bind key (`preBindNodes`). Not a protection for a stolen or unlocked Mac, Time Machine, whole-disk images or Migration Assistant (they carry the device key), what a pre-bind copy held, or CredMgr backups (the wrap is unsealed inside their own encryption; while bound they are written to `<state>/backups/<vault id>/`, outside the vault folder, second addendum N2). The bind record is keyed by `<vault>/vault.id`, not the path (N4). CLI `credmgr keystore status|bind|unbind`; the app's Settings > Security > Machine lock. The V1 duress code has no V2 row: dropped, `ADR-145` |
| `GET *` (SPA catch-all) | — | ❌ | **removed** — no HTTP server exists; the UI is served by the shell (F-12) |

**Scheduling of the `planned` rows (re-checked 2026-10-31 against the open GitHub issues).** `planned` means
designed here and dispatched nowhere; only some rows have a milestone. **Updated 2026-11-06:** issue #32's broker
set (`node.rekey`, `search.content`, the `--age` export as `node.export`, `orphan.destroy`, `audit.report`) and issue
#16 (`node.gate_*`) are built — the rows above; security levels, the last of #32, are built as a node policy field (`ADR-140`, no new operation).
#31 (`2.0.0`) was the owner's
build-or-formally-drop decision for `llm.*` and machine lock, answered by `ADR-146` (`llm.*` dropped, so no row here), `ADR-144` (machine lock defined, built by `ADR-165` on 2026-11-14) and `ADR-145` (duress dropped); #29 is the Windows and Linux keystores,
the nearest issue to `keystore.*`; **since 2026-11-07 the Windows and Linux keystores, the named pipe and the machine lock (the three `keystore.*` rows) are `2.1` work, not `2.0.0` (`ADR-147`); the macOS file tier of the machine lock is built (`ADR-165`).** Presence (#18, `2.0.0-rc.1`) is what lets `grant.create`, `node.reparent`,
`totp.seed`, `audit.get`, `maintenance.rotate_root`, a registry rebuild and a widening `node.policy` stop answering
`presence_required`. **No issue or milestone names `agent.*` or `audit.purge`: they are unscheduled; `merge.*` was built by `ADR-168` (rc.2 §3 item 2).** (`entry.search`, `entry.get_by_ref`, `entry.history`, `entry.expiring` and `vault.set_passphrase` were built by the post-launch quick-wins batch, `ADR-156`; `entry.move` by `ADR-158`.)
`audit.purge` stays off the MCP tool list when built; `node.export`, `node.rekey`, `orphan.destroy`, `search.content`, `audit.report`
and `node.gate_*` are built and are **not** MCP tools (the forbidden list in `10 §3.2` and test I-13 are unchanged).

---

### 1.8 Operations with no V1 ancestor — `built`, and previously indexed nowhere

Thirty-five of the broker's 111 operations are indexed here because V2 needed them and V1 had no route that
became them (ten when this section was written; `vault.gate_recover` and `node.set_workdirs`,
ADR-064 and ADR-066, 2026-09-24, `vault.approval_get`, ADR-090, 2026-10-26, and the eight presence, device and orphan
operations of ADR-098, 2026-11-06, bring it to twenty-one, `session.confirm`, ADR-150, 2026-11-08, to twenty-two, the eight `settings.*` operations of ADR-155, 2026-11-09, to thirty, `entry.set_expiry` and `vault.anomalies_ack`, ADR-156, 2026-11-09, to thirty-two, `vault.doctor_scan`, ADR-161, 2026-11-14, to thirty-three, `entry.tag_set`, ADR-167, 2026-11-20, to thirty-four, and `vault.doctor_apply`, ADR-169, 2026-11-20, to thirty-five; the other 76 are mapped from V1 routes or are ⭐ rows in §1.1–§1.7, `vault.recover`, ADR-163, 2026-11-14, among them in §1.1). They were absent from every table above, which meant the coverage assertion in §6
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
| `graph.snapshot` | **built** — | serves the vault-topology screen. V1 had a flat project list and needed no graph. `meta.sealed` (`[{id, label, sealedAt, expiresAt}]`) is added for non-agent callers holding Admin only (`ADR-080`); absent otherwise. `revealConfirm` (the vault's `ADR-150` policy) is added for the owner's own login only |
| `vault.gate_enroll_begin` | **built** — | enrolment step 1: issues the TOTP secret only, unconfirmed and gating nothing yet. The ten recovery codes are generated once, only by `vault.gate_enroll_confirm` (`07_TWO_FACTOR.md §4`) |
| `vault.gate_enroll_confirm` | **built** — | enrolment step 2: proves the operator stored the secret before the gate becomes mandatory |
| `vault.gate_verify` | **built** — | the gate itself, and — since `ADR-056` — one of the two places a real session token is minted. Called by an already-logged-in owner session it is a **step-up** instead (`ADR-085`): the same code check and backoff, a 300-second elevation for every caller, no token minted, answer `{locked: false, elevated: true, expiresIn}`. With **no gate enrolled** the step-up answers `malformed_request` ("nothing to verify"), not `gate_verification_failed`, and does not feed the unlock backoff; a tokenless caller with no gate pending still gets `gate_verification_failed` |
| `totp.seed` | **built** — | reveals a TOTP seed stored as an entry field, to the owner only and with a presence proof (`ADR-098`); the app's "show seed" displays it, re-masks it and never copies it (`d9e6c7c`). Distinct from the gate: this is a credential the vault holds *for* the operator, not the factor that guards the vault. Takes `field` on a multi-field entry (`ADR-078`). Not an MCP tool |
| `totp.code` | **built** — | derives a current code from a stored seed, so the seed itself never has to be revealed to be used; answers `{node, entry, code, validForSeconds}` (1–30). Takes `field`; without it, the only field, else the one TOTP-seed field, else `malformed_request` (`ADR-078`). Gated like `entry.reveal` by the vault's "confirm before showing secrets" policy: `confirmation_required` until the owner's login confirms (`ADR-150`); agents are not asked |
| `vault.approval_decide` | **built** — | resolves an approval-on-demand request (`ADR-042`): an agent asked to reveal from a locked node, and the owner session approves or denies it once. Not the locked-write tray (`vault.pending_*`, `F-1`). The decision stages the value (`ADR-079`). With `passphrase` (and `code` when a gate is confirmed) it is decided by the unlock factors **while the vault stays locked** (`ADR-088`): no capability or session, wrong passphrase `wrong_passphrase`, missing code `two_factor_required`, wrong code `gate_verification_failed`, a recovery code refused, an interrupted root-key rotation finished first (`ADR-093`); unlocked, a passphrase is `malformed_request`. Without a passphrase, a wholly locked live vault answers `vault_locked`. From a login (no `passphrase`), approving needs a presence proof when a presence key is enrolled (`ADR-173`; the shell attaches it, deny is never gated). CLI `credmgr approve <request> [--deny] [--code-on-argv <n>]` (the code is normally the second stdin line or a prompt, ADR-113). With the vault's "confirm before showing secrets" policy on (`ADR-150`, review amendment), approving in the session form needs the deciding login to hold a confirmation meeting the policy for the entry's sensitivity (checked after the value is staged, before the decision is stored), else `confirmation_required`; denying is never gated and the locked-vault form is authorised by the unlock factors. In "every time" mode an owner's own lock → approve → collect costs two confirmations |
| `vault.approval_get` | **built** — | what a waiting approval request asks for (`ADR-090`): node and entry (by name when the broker holds the names and the node's name is not private), the command, seconds left; with no `request`, the list of everything waiting. Read-only, answered on a locked vault, decrypts nothing; on an unlocked vault the owner's login only. `vault.status` carries the bare count as `pendingApprovals`. CLI `credmgr approvals`. Not an MCP tool |
| `presence.status` | **built** — | what this Mac can do for Touch ID (Secure Enclave, biometry, device password), the enrolled presence keys (id, label, date; never the key) and whether Touch ID unlock is on (`ADR-098`). The owner's login only. CLI `credmgr presence status`. Not an MCP tool |
| `session.confirm` | **built** — | ADR-150: `{passphrase}` or a presence proof → `{confirmed, method, expiresIn}`. Confirms the owner's login for the vault's "confirm before showing secrets" policy (`global.policy.revealConfirm`, set with `node.policy`); until then `entry.reveal`, `totp.code` and an approving `vault.approval_decide` answer `confirmation_required`. Owner only; a wrong passphrase, or a presence proof that does not verify, counts in the per-uid unlock backoff, and a successful confirm never resets it (review P1). CLI `credmgr confirm`. Not an MCP tool |
| `settings.list` | **built** — | ADR-155: `{node?}` → every setting (`credmgr_core::settings::SETTINGS`) with value, default, values, purpose, where it is stored, risk and the caller's rule (`you`); project settings only with `node`, and an agent only for a project it reaches. MCP `credmgr_settings_list`; CLI `credmgr settings list` |
| `settings.get` | **built** — | ADR-155: `{id, node?}` → one setting plus its last 10 recorded changes. MCP `credmgr_settings_get`; CLI `credmgr settings get` |
| `settings.set` | **built** — | ADR-155: `{id, value, reason, node?}`. Owner: the rules `node.policy` had (`admin` on the node; presence to widen reach; a fresh confirmation to loosen `revealConfirm`). Agent: cosmetic or stricter applies at once; weaker → `{state: "pending", request}`. Every applied change recorded in `global.policy.settingsHistory`. MCP `credmgr_settings_set`; CLI `credmgr settings set` / `toggle` |
| `settings.revert` | **built** — | ADR-155: `{change, reason?}` → sets the value a recorded change replaced, under `settings.set`'s rules. MCP `credmgr_settings_revert`; CLI `credmgr settings revert` |
| `settings.request_get` | **built** — | ADR-155: `{request}` → a waiting or decided agent request; only its requester or the owner reads it. MCP `credmgr_settings_request` |
| `settings.request_list` | **built** — | ADR-155: owner only → every agent request (with the requester's folder). CLI `credmgr settings requests`. Not an MCP tool (`FORBIDDEN_OPS`) |
| `settings.request_decide` | **built** — | ADR-155: `{request, approve}`, owner only; approving a weakening change needs a fresh confirmation (`session.confirm`) or presence where it widens reach. CLI `credmgr settings approve` / `deny`. Not an MCP tool (`FORBIDDEN_OPS`) |
| `settings.kb` | **built** — | ADR-155: → `{markdown}`, the LLM knowledge base generated from the settings table (`docs/LLM_KB.md`). MCP `credmgr_kb`; CLI `credmgr kb` |
| `presence.challenge` | **built** — | `{op, params}` → a single-use 32-byte nonce, the digest to sign and a sentence for the Touch ID dialog (`ADR-098`). Only for the presence-gated ops; 60 seconds; bound to the op, the exact params and the login session. Owner only. The CLI and the shell call it themselves. Not an MCP tool |
| `presence.enrol` | **built** — | `{publicKey (base64 P-256 point), label?}` — enrol this Mac's Secure Enclave presence key. The first needs `admin`, a human and a fresh second factor; any later one needs a presence proof from an existing key (`ADR-098`). CLI `credmgr presence enrol`. Not an MCP tool Since ADR-148 enrolling also needs proof of possession (`params.possession`, signed over a `presence.challenge {possession: true}` nonce), and the enrolled keys live in the signed registry (`presenceKeys`). |
| `presence.unenrol` | **built** — | `{id}` — remove an enrolled presence key; needs a presence proof (`ADR-098`). CLI `credmgr presence unenrol`. Not an MCP tool |
| `device.enrol` | **built** — | turn on unlocking with Touch ID: seals the resident root key to a Secure Enclave key into `keys/root.wrap.se` (`ADR-098`). The vault open, `admin`, a fresh second factor and — once a presence key exists — a proof. CLI `credmgr touch-id enable`. Not an MCP tool Since ADR-148 the wrap carries an HMAC tag under the root key and the signed registry names it (`deviceWraps`); a rotation re-seals only to a tagged, named wrap. |
| `device.remove` | **built** — | turn Touch ID unlock off (deletes `keys/root.wrap.se`); same gate as `device.enrol`. CLI `credmgr touch-id disable`. Not an MCP tool Since ADR-148 it writes a registry naming no wrap before deleting the file, so a wrap put back later is never prompted for. |
| `orphan.list` | **built** — | the sealed ("orphaned") entries: id, name, ref, type, modified — no value. The owner's login only (`ADR-098`). Not an MCP tool, no CLI command |
| `orphan.reveal` | **built** — | `{entry, fieldIds?}` — read one sealed entry: the owner, a fresh second factor **and** a presence proof every time; the second-factor window is dropped afterwards (`ADR-098`, `04 §5.2`). The desktop app only: no CLI command, absent from the MCP tool list. Rule R0 admits exactly this caller |
| `vault.gate_recover` | **built** — | the last door (`ADR-064`, `07_TWO_FACTOR.md §4`): the vault passphrase **and** the printed root recovery code together reset a lost gate. Resets, never unlocks; which factor failed is never said; shares `vault.unlock`'s auth backoff. Not an MCP tool |
| `entry.set_expiry` | **built** — | `{node, entry, generation, expiresAt}` sets an entry's expiry (unix seconds, at most year 9999) and `{…, clear: true}` removes it; exactly one of the two (`ADR-156`). Expiry is plaintext manifest metadata, so the sealed envelope is not touched; the gate is `entry.update`'s (`update`, R1's locked refusal, F-9's generation check). V1 kept expiry inside the credential record and had no separate route. CLI `credmgr expire`. Not an MCP tool. CLI `credmgr edit <name> --node <id>` also drives it (with `entry.alias`, `entry.update`, `field.update`) from one `$EDITOR` document; metadata only. |
| `vault.anomalies_ack` | **built** — | the owner has seen the anomaly alarm (`ADR-156`): clears `vault.status`'s `anomaliesUnseen` count, which the app's notice bar and `credmgr status` show. Owner only. V1 had no alarm to acknowledge. CLI `credmgr status --ack`. Not an MCP tool |
| `entry.tag_set` | **built** — | entry tags (`ADR-167`): `{node, entry, generation, tags}` replaces the entry's whole tag set (`[]` clears), normalised by `credmgr_core::tags` (trimmed, lower-cased, inner spaces to one `-`; letters, digits and `- _ . : /`; 1–32 characters; at most 16) and answers `{node, entry, generation, tags}`. Names-level metadata on the signed manifest row: `entry.get` and `entry.list`'s rows carry `tags`; `entry.list` and `entry.search` take a `tag` filter that narrows the one node named; a node that hides its names hides its tags and refuses a filtered list. The owner's sessions only (`Origin::Agent` refused, as `entry.alias`); `update` on the node; metadata only. V1 kept tags on the credential. CLI `credmgr tag`, `credmgr list --tag`; desktop tag chips. Not an MCP tool |
| `vault.doctor_scan` | **built** — | the doctor's tidy-up scan, phase 1 (`ADR-161`): `{staleDays?, expiringDays?}` → a report and a preview plan of shared values (found by HMAC under a key drawn for the scan; no value, digest or fragment leaves the broker), near-identical names, entries misfiled in Global, weak passwords, mistyped values, expired, expiring and stale entries, each naming its entries and nodes and, for a move, the exact `entry.move` parameters with the generation. Writes nothing; each move is applied by the owner through `entry.move`. The owner's login and `admin` on `global` (the gate of `audit.report`); reads only what `entry.list` would show and values only where the owner could reveal them without being asked for more; one scan at a time (`rate_limited`), capped at 10,000 entries, 10 s and 500 findings per kind. V1 had no scan. CLI `credmgr doctor --scan`; desktop Tidy up. Not an MCP tool (`FORBIDDEN_OPS`) |
| `vault.doctor_apply` | **built** — | every move of one tidy-up plan in one request (`ADR-169`): `{moves: [{node, entry, to, generation}], reason?}`, 1 to 500 moves, each exactly a `vault.doctor_scan` proposal's `move`. Every step is re-checked against the vault as it is, in order (a stale generation `conflict`, a missing entry `not_found`, a name the destination already uses or an earlier step brings in `entry_exists`, a locked node `node_locked`, the same entry twice `malformed_request`) before any factor is asked for; then `entry.move`'s gates once for the plan (the owner's login, `admin` on every node named, a fresh second factor for the vault and each named node with its own, one presence proof over the whole request) and each move through `entry.move`'s crash-safe commit. Stops at the first move that fails: before anything moved that is the error; after, `{complete: false, applied, stopped, notApplied}`. Each applied move is moved back with `entry.move`. V1 had no scan. CLI `credmgr doctor --scan --apply`; desktop Tidy up › Apply all moves. Not an MCP tool (`FORBIDDEN_OPS`) |
| `node.set_workdirs` | **built** — | binds the directories that scope an agent to a node (`ADR-066`, `03_DATA_MODEL.md §1`) — absolute, existing, stored canonical, one directory to one node. Human-only. V1 had no node boundary to bind to |

## 2. CLI — 37 V1 commands

All 37 V1 commands are accounted for (36 in the public `v1/bin/credmgr` 1.9.1, plus `migrate`, which the raw V1 package
had and the public one does not — the raw package is not in this repository, so that one is carried from earlier
revisions of this document, not re-counted).

> **Status of this section — added 2026-09-21.** The three lists below map V1's surface onto V2's
> *intended* CLI. They are **not** a statement of what exists. Exactly **37 top-level subcommands
> are `built`** today (the match in `crates/cli/src/main.rs::run`, counted 2026-11-07, plus `help` and `--version`); 50
> on 2026-10-26, not recounted since, counting every nested `node`/`grant`/`gate`/`pending`/`notes`/`field` arm as well, by
> `10_API_AND_MCP.md §2.1`'s method (`gate enroll`, `gate recover` and `node workdir` landed
> 2026-09-24 — ADR-064, ADR-066 — and `pending` the same day, ADR-069; `import`, `notes` and `node
> rename`/`node policy` on 2026-10-02 — ADR-071…073; `field` and the `--field` / `--field-id` / `--all` /
> `--json` / `--bulk` selectors on `get`, `set` and `rotate` on 2026-10-03 — ADR-078; `generate` and `approve` on
> 2026-10-24 — ADR-087, ADR-088; `approvals` on 2026-10-26 — ADR-090):
>
> `init` · `status` · `unlock` · `presence` · `touch-id` · `lock` · `gate` · `whoami` · `list` · `get` · `field` · `search` ·
> `set` · `rotate` · `rm` · `undo` · `audit` · `verify` · `pending` · `doctor` · `generate` · `approve` · `approvals` ·
> `backup` · `restore` · `node` · `grant` · `import` · `import-env` · `alias` · `similar` · `notes` · `orphan` · `export` ·
> `mcp` · `agent` · `prompt`
>
> **Every command named below that is not in that list is `planned`** — roughly half the section,
> including `batch`, `history`, `dashboard`, `daemon`,
> `token` (built as `credmgr agent token …` since ADR-164, not as a top-level command), `edit`, `projects`, `expiring`, `access-log`, `ssh-agent-add`, `keystore`, `totp`,
> `llm` (dropped, `ADR-146`) and `scan` (`pending` is `built` since ADR-069; `import` and `notes` since
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
page can ask `entry.undo` for the right record. Four (`totp.seed`, `node.reparent`, `grant.create`, `audit.get`) answer
`presence_required` without a presence proof (with Touch ID set up the shell attaches one, ADR-098), and
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
   `generate_handler!`, and every error discriminant against `protocol.rs` (27 on 2026-11-08); `tests/ts_client.rs`
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
> rebuild) and, since ADR-098, answer after a Touch ID check; the app's "show seed" then displays the seed (a fresh second factor too, if the vault has one), re-masks it after the reveal window, never copies it and clears it on lock (2026-11-08, `d9e6c7c`).

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

**Code.** `crates/brokerd/src/ops.rs` — 111 dispatched ops (count with
`tools.corpus_check.broker_ops()`, never a grep; 111 on 2026-11-20 when the rc.2 line (103, after ADR-167, ADR-168 and ADR-169) merged ADR-163, ADR-164 and ADR-165 (eight more), 93 on 2026-11-14 after ADR-161, 92 after ADR-158, 91 on 2026-11-09 after ADR-156, 84 after ADR-155, 76 on 2026-11-08, 75 on 2026-11-07, 55 on 2026-10-31), the authority for every **`built`** marking in
this document. `crates/mcp/src/tools.rs` — 21 registered tools (ADR-156, ADR-158, ADR-161, ADR-163, ADR-164, ADR-165, ADR-167, ADR-168 and ADR-169 added none). `crates/cli/src/main.rs` — 52
top-level subcommands (counted in the match in `run`, 2026-11-20 — ADR-167 and ADR-168 added `tag` and `merge`, ADR-165 `keystore`, ADR-163 `recover`, ADR-164 none (`agent token …` extends `agent`), ADR-169 none (`doctor --scan --apply` extends `doctor`), rc.2 §3 `edit` and §1 `totp`; ADR-161 none (`doctor --scan` extends `doctor`); ADR-158 `move`; ADR-156 `passphrase`, `expire`, `expiring`, `history` and `ref`; `help` and `--version` aside). `apps/desktop/src-tauri/src/commands.rs` — 111 bridge commands for broker ops
(`HAND_WRITTEN` 11 + `TABLE` 100 — ADR-165's three `keystore_*`, ADR-164's `agent_token_status`/`agent_token_revoke`, ADR-167's `entry_tag_set`, ADR-168's eight `merge_*` and ADR-169's `vault_doctor_apply` are generated; ADR-163's `vault_recover` is hand-written, because it captures the login token like `vault_unlock`, and so are ADR-164's `agent_token_issue`/`agent_token_rotate`, which hand the bearer to the concealed clipboard) and 18 shell commands (`SHELL_COMMANDS`). `crates/brokerd/src/protocol.rs` — 28 error codes (`presence_failed` added by ADR-098, `confirmation_required` by ADR-150, `machine_lock_refused` by ADR-165).

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
not yet dispatch. **2026-11-20 recount (rc.2 merge of ADR-163, ADR-164, ADR-165, ADR-167, ADR-168 and ADR-169):** `tools/corpus_check.py::broker_ops()` reports **111** dispatched ops against **112** documented (every op named in a §1 table or in §1.8), so **1 is planned**: `audit.purge`. The history of the figure: 103 built against 111 documented after ADR-169 added `vault.doctor_apply` (§1.8); 102 built against 110 documented after ADR-168 built the eight planned `merge.*` ops and ADR-167 added `entry.tag_set` (§1.8); on a parallel line, 101 against 110 after ADR-163 added and built `vault.recover`, ADR-164 built the four `agent.*` ops and ADR-165 the three `keystore.*` ops; 93 built against 109 documented after ADR-161; 92 built against 108 documented after ADR-158, and ADR-161 added `vault.doctor_scan` (§1.8); 91 built against 108 documented after ADR-156, and ADR-158 built the planned `entry.move`; 84 built against 106 documented after ADR-155's eight `settings.*` ops, and ADR-156 built five planned ops (`entry.search`, `entry.get_by_ref`, `entry.history`, `entry.expiring`, `vault.set_passphrase`) and added two (`entry.set_expiry`, `vault.anomalies_ack`); 75 against 97 on 2026-11-07; 55 built against 83 documented on 2026-10-31; the 2.0.0 broker batch added nine ops (`node.rekey`, `orphan.destroy`, `search.content`, `node.export`, `audit.report`, the four `node.gate_*`), ADR-098 eight (the presence, device and orphan ops), ADR-121 and ADR-122 three (`entry.alias`, `entry.similar`, `entry.import_env`), all of them either documented already or new rows. No namespace is zero built any more (`merge.*`, `agent.*` and `keystore.*` were, until ADR-168, ADR-164 and ADR-165). `keystore.*` is the macOS file tier only; the Windows and Linux keystores stay `2.1` work (ADR-147).

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
since ADR-090 its `vault.` bar lacks `approval_get`. The live counts are 111 built against 112 documented (2026-11-20); the job was not re-run since 2026-10-31.
Re-running the job restores agreement.
