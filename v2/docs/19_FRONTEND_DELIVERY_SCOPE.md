---
id: V2-019
classification: public
title: Frontend delivery scope
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21), corrected the same day against the Session 21 verification backlog,
     then corrected again on 2026-08-19 against that backlog's round 2. The stamp this replaces
     named NO commit at all ("not yet hardened"), so nothing was ever attested and
     `tools/corpus_check.py stamps` had nothing to compare; the body it sat on has since been
     overtaken twice — by the Tauri bridge landing (ADR-057, `b23a5ae`) and by the
     re-verification of the out-of-repo endpoint snapshot this document used to treat as drifted.
     The round-1 pass fixed six defects an independent skeptic found surviving the rewrite: a
     present-tense claim that the desktop UI "is built" (§1) contradicting the Status block four
     lines above it; a status word ("mixed") outside the corpus vocabulary (§2); three section
     numbers cited but not opened (`16_CROSS_PLATFORM.md §3` for the Windows named pipe, which is
     §5.3; `06_ACCESS_GRAPH.md §5` for the grant edge, twice, which is §10.6; `13_TEST_PLAN.md §3`
     for the bridge tests and drift guards, which is §6); and a false claim that the "Pro settings
     = 10 sections" figure is not derivable from either source document, when it is — from
     `09_UI_UX_SPEC.md §5` alone. That pass claimed to have closed every wrong-section citation but
     missed a fourth of the identical kind: `07_TWO_FACTOR.md §3` for the gate-enrolment ops
     (§3.3), which is actually §4 — fixed in round 2, alongside a false "the design package went
     out / was sent out 2026-08-18" premise this document still carried in three places (the
     Status table, §3.1's `greet`-retention rationale, and §8's hand-over-hazard paragraph) after
     the operator corrected that premise the same day it was written (`HANDOVER_STATE.md` §1,
     commit `ee59696`: no external front-end team or Claude Design project has ever held the
     package), and a presupposing "the front-end team" surviving in five places where the rest of
     the document correctly says "front-end track". Every claim below was re-checked against live
     source in both passes. The corpus-wide hardening status is the operator's to assign after
     their own review, not this session's to self-award. Updated 2026-09-24 for ADR-062…066
     (the bridge now reaches all 42 ops, a real CSP, the live unlock). Updated 2026-09-24 for
     ADR-071…073 (47 ops, thirty-nine generated; §3.3 gains the notes family; the bridge's error
     list recounted at its actual 24). Updated 2026-10-03 for the wired app (ADR-078 and ADR-079: 53 ops, the shell's 186 tests, the
     status block, the ledger rows and §5's status). -->
# Frontend delivery scope — what the desktop delivery must contain, and how completeness is judged

`CredMgr V2` · the hand-over contract for the desktop UI: what must be delivered, what it may call today, and what proves it done · `2026-08-18`

> **Status.** **The desktop application is hosted and wired.** `v2/apps/desktop/` serves the finished app design,
> precompiled and under the strict CSP (`ADR-075`). Every screen reads from the broker and every change goes to it
> (`apps/desktop/src/vault/`, `apps/desktop/README.md`): first run, the lock screen with the second factor and the
> recovery codes, the graph and tree, an entry's fields (add, edit, remove, reorder), a paste as one entry or split into
> several, the held-entry tray, nodes with their policy, seal and restore, grants, the audit trail, Verify, Doctor, Back up,
> root-key rotation and the settings. A control with no operation behind it was removed rather than left mocked, and a
> release build carries no demo data. Five operations are sent for real and refused by the broker with
> `presence_required` (grant creation, the full audit record, a TOTP seed, root-key rotation once its other checks pass,
> and a registry rebuild); the app says so and changes nothing. (`apps/desktop/README.md` counts four: it omits the TOTP seed.) What is **not** done is the evidence: the
> 212-row human checklist in `RELEASE_VERIFICATION.md` has an empty result column, the real-broker suite's drift guard
> fails on the merged tree (`13_TEST_PLAN.md §11`), and the app has no control to delete an entry, to approve an agent's
> request or to edit a node's note. Beneath the screens is the seam: a Tauri↔broker command bridge reaching **all 53 of
> the broker's operations** (`apps/desktop/src-tauri/src/commands.rs`, ADR-057 for the first eight, ADR-062 for the next
> thirty-four, five more for ADR-071…073, `maintenance.rotate_root` for ADR-076 and five for ADR-078) plus three shell
> commands (`entry_copy`, `copy_text`, `fields_preview`), a typed TypeScript client for it
> (`apps/desktop/src/lib/bridge.ts`), a real Content Security Policy on the window, and the shell's own concealed clipboard
> and lock-on-sleep — with the shell's 186 tests (listed 2026-10-03), run in CI. Everything in §5 and later that speaks in
> the future tense is the specification the delivery was checked against, not a claim that it is unbuilt.

---

## 1. What this document is, and why it is scope rather than design

The desktop UI is designed and delivered on a track **outside this repository's build chain**.
The design is now hosted in `apps/desktop/` and only partly wired to the broker (the Status block
above, §2); the arrangement below is about where the remaining work happens, not about what it has
produced. Phase 6 was pulled
out of the autonomous build sequence deliberately (`12_BUILD_PLAN.md §4`): the backend phases
close on exit gates a test can assert, and a visual delivery does not. The design work therefore
runs externally, against a package handed over by the operator, and lands back here as an
artifact.

That arrangement needs a contract, and this is it. It answers four questions and nothing else:

1. **What may a screen call today**, and under what rules (§3, §4).
2. **What must the finished delivery contain** — every route, in both modes (§5, §6).
3. **How is a delivery checked off** as complete rather than merely polished (§7).
4. **Who wires it to the broker afterwards**, and where the output goes (§8).

**It is not the design.** How a screen looks and behaves is `09_UI_UX_SPEC.md`; colour and mode
are `20_THEMING.md`; the graph's own rendering contract is `design/graph-engine/VAULT_GRAPH_SPEC.md`.
Those documents specify *quality*. This one specifies *extent* — and the two are separable in
exactly the way that matters here, because the failure mode a hand-over actually produces is not
an ugly screen. It is a beautiful primary view with twenty-one routes missing.

## 2. Status of the delivery surface

Every row below carries one of the three corpus words (`ADR-059`): **`built`** exists and a
passing test covers it, **`partial`** exists but does not yet do everything this document
specifies, **`planned`** does not exist in any form.

| Piece of the delivery | Status | Evidence |
|---|---|---|
| Desktop screens — all 22 routes | `built`, verification pending | The design is hosted (`apps/desktop/src/design/`, `src/dc/`; ADR-075; the scaffold's `routes/` and `app.html` are gone), renders every screen, and every read and change goes through the broker (`apps/desktop/src/vault/`) — see the Status block above. Whether each control does what its row in `RELEASE_VERIFICATION.md` says is a human pass that has not been done |
| Tauri↔broker command bridge | `built` | 53 of 53 ops in `apps/desktop/src-tauri/src/commands.rs` (ADR-062, ADR-078), plus three shell commands; 186 tests listed (156 passing on 2026-10-02), in CI as `security.yml` → `v2-desktop-bridge` (§3, §12) |
| Typed TypeScript client for the bridge | `built` | `apps/desktop/src/lib/bridge.ts`, held to the Rust table by `tests/ts_client.rs` (§3.3) |
| Content Security Policy on the window | `built` | `apps/desktop/src-tauri/tauri.conf.json` `security.csp` (production) and `devCsp`; held by `tests/shell_config.rs` (ADR-062) |
| Broker operations the screens call | `built` | 53 dispatched in `crates/brokerd/src/ops.rs`; which of them a given screen needs is `18_ENDPOINT_INDEX.md §1`. Five are refused with `presence_required` until a presence transport exists — `totp.seed`, `node.reparent`, `grant.create` and `audit.get` on every call, `maintenance.rotate_root` once its human, `admin` and second-factor checks pass (ADR-076; `10_API_AND_MCP.md §4.2`) — and `node.policy` refuses a widening patch the same way (§3.3) |
| Design tokens (KEEP) | `built` | `design/tokens/keep.tokens.json`, `keep.css`, `keep-components.css` |
| Graph engine, vendored and pinned | `built` | `design/graph-engine/force-graph.min.js` + `VAULT_GRAPH_SPEC.md` |
| Theming rules | `built` as a specification, `built` in the settings that apply it | `20_THEMING.md`; the Appearance settings are remembered and applied (`apps/desktop/tests/e2e/wp-d-prefs.spec.ts`) |
| Delivered design artifacts, returned | `planned` | `v2/design/handoff/` does not exist; the design package is staged locally and has never been sent to anyone, so nothing has come back either (`HANDOVER_STATE.md` §1) |
| Screens that drive the §3.3 commands | `built` | the commands exist (§3.3) and the screens call them: a source search on 2026-10-03 (each bridge function other than the three shell commands, looked up on non-comment lines of `apps/desktop/src/` outside `lib/bridge.ts`) finds a caller in app code for 42 of the 53 broker-op commands. The eleven with none are `entry.remove`, `entry.restore`, `entry.rotate`, `entry.undo`, `entry.update`, `node.list`, `node.reparent`, `node.set_workdirs`, `notes.write`, `vault.approval_decide` and `whoami` — so the app cannot delete an entry, edit a node's note or approve an agent's request. Eight of the eleven have a command-line route (`entry.remove`, `entry.rotate`, `entry.undo`, `entry.update`, `notes.write`, `node.set_workdirs`, `node.list`, `whoami`; `RELEASE_VERIFICATION.md §6`); `entry.restore`, `node.reparent` and `vault.approval_decide` have none (`apps/desktop/src/vault/`; the specs under `tests/e2e/` assert the commands sent) |

**One number is worth stating plainly because it sets the shape of the whole hand-over:** of the
53 operations the broker dispatches, **all 53** are reachable from the desktop shell (ADR-062, ADR-078), and the
screens call 42 of them. Mocks shaped like §4 remain the way to build and test without a running broker (the fixture
broker the Playwright specs use). Until 2026-09-24 this read *8 of 40*, with the other 32 to be wired only once screens
existed to drive them (ADR-057); ADR-062 reversed that sequencing.

## 3. The Tauri bridge — **`built`**

### 3.1 The eight hand-written commands — **`built`**

Fifty-six commands are registered in `apps/desktop/src-tauri/src/lib.rs`'s `generate_handler!`: fifty-three
thin pass-throughs, one per broker op, and the shell's own three (`entry_copy` and `copy_text`, the
concealed clipboard, and `fields_preview`, the local bulk-paste preview, `02_ARCHITECTURE.md §6.2`). Of the fifty-three, eight are hand-written, because
they carry token custody or return `AuthState` — the four authentication commands and four reads —
and are listed here; the other forty-five are generated (§3.3). The bridge makes no
authorization decision, holds no node key, and reshapes nothing (`02_ARCHITECTURE.md §6.1`: "It
does not reshape responses"; ADR-001 makes the broker the single enforcement point).

| `invoke()` command | Broker op | Arguments | Returns |
|---|---|---|---|
| `vault_status` | `vault.status` | — | `{locked, authenticated, initialized}` (`initialized` is false only before `vault.init_confirm`; an older daemon omits it, which reads as true — ADR-077) |
| `vault_unlock` | `vault.unlock` | `passphrase` | `{locked, authenticated}` |
| `vault_gate_verify` | `vault.gate_verify` | `code` | `{locked, authenticated}` |
| `vault_lock` | `vault.lock` | — | `{locked, authenticated}` |
| `whoami` | `whoami` | — | the broker's body, unreshaped |
| `graph_snapshot` | `graph.snapshot` | — | the broker's body, unreshaped |
| `entry_list` | `entry.list` | `node` | the broker's body, unreshaped |
| `entry_reveal` | `entry.reveal` | `node`, `entry` | the broker's body, unreshaped |

The scaffold's `greet` command and the `opener` plugin were removed together with the scaffold page
when the design was hosted (ADR-075, 2026-10-02); `src-tauri/tests/shell_config.rs` fails if either
returns. No external front-end team ever held this package (commit `ee59696`; `HANDOVER_STATE.md` §1),
so there was never an in-flight build to protect.

<!-- figure:desktop-login-sequence -->

*The session token never crosses into the webview: `vault_gate_verify` mints it, the bridge
strips it from the response, and only the bridge attaches it to a later call like
`entry_reveal` — the webview only ever learns that it is authenticated.*

### 3.2 Six rules every screen inherits from the bridge — **`built`**

These are properties of the seam, not suggestions. A delivery that assumes otherwise will
compile and then be wrong at runtime.

1. **No session token, and nothing derived from one, crosses into the webview.** ADR-057
   decision 1. The three authentication commands return `{locked, authenticated}` and nothing
   else. A screen must therefore model login as *state held by the bridge*, never as a credential it
   carries, stores, or passes back down. Held by
   `tests/bridge_wire.rs::no_command_result_ever_serialises_a_token_shaped_string`.
2. **`two_factor_required` arrives as an error, not a success state.** That is what it is on the
   wire (`crates/brokerd/src/protocol.rs` makes it an `OpError`), and translating it here would
   put the bridge and the audit log into two vocabularies for one event. The UI will branch on
   `err.code === "two_factor_required"` and call `vault_gate_verify`.
3. **Broker error codes pass through verbatim.** The closed set is 25 discriminants —
   `node_access_denied`, `two_factor_required`, `approval_pending`, `conflict`, `vault_locked`, `node_locked`,
   `wrong_passphrase`, `malformed_request`, `capability_not_held`, `not_found`, `entry_exists`,
   `internal`, `presence_required`, `archive_expired`, `approval_denied`, `rate_limited`,
   `gate_verification_failed`, `gate_not_enrolling`, `entry_removal_expired`, `not_undoable`,
   and ADR-061's four bootstrap codes `vault_already_initialized`,
   `vault_inside_git_working_tree`, `vault_init_not_pending`, `recovery_code_mismatch`,
   ADR-068's `session_expired`, and ADR-077's `node_locked` — the vault is unlocked but this one node
   is locked individually (the body names the node).
   A denial rendered on screen is the same word `audit.tail` records for it. The list is pinned
   against `protocol.rs` on disk by
   `tests/drift_guards.rs::the_bridges_error_vocabulary_matches_the_brokers_exactly`, and
   `bridge.ts`'s `BrokerErrorCode` union is pinned to the same list by `tests/ts_client.rs`.
4. **A *vault* reporting `locked: true` ends the session bridge-side, silently.** The idle
   auto-lock (ADR-043) fires on a wall-clock tick and pushes nothing to any client, so the bridge
   treats three signals as proof its token is dead: a top-level `locked` field **on the four
   vault-state ops only** (`session::VAULT_STATE_OPS` — `vault.status`, `vault.unlock`,
   `vault.gate_verify`, `vault.lock`), `meta.vaultLocked` on any op that carries it (today
   `graph.snapshot`), and a `vault_locked` or `session_expired` denial. `vault.node_lock`'s `{"node", "locked": true}`
   is about one node and does **not** end the login, and neither does a `node_locked` denial
   (ADR-077: it is deliberately absent from `SESSION_ENDED_CODES`) — reading it as the vault's would have logged
   the user out the moment they locked a single project (ADR-062;
   `session::tests::locking_one_node_is_not_mistaken_for_the_vault_locking`,
   `tests/bridge_ops.rs::locking_one_node_over_the_wire_keeps_the_login`). **A screen that caches
   "authenticated" locally will therefore disagree with the bridge after an idle lock.** The lock
   screen must be driven by what a command returns, not by a UI-side flag. **One case produces no
   lock signal:** since ADR-065 a login unused for the vault idle timeout is revoked on its own
   clock even while agent traffic keeps the vault unlocked. Until ADR-068 the broker then resolved
   the bridge's next call from the app's own cwd as `Origin::Agent` — a silent demotion. It now
   answers `session_expired` (`server.rs::handle_request_at`), which is in `SESSION_ENDED_CODES`
   (`src/error.rs`), so the bridge drops the token on that call and the screen should return to
   unlock (`tests/bridge_wire.rs::an_idled_out_login_is_refused_and_the_session_dropped`).
5. **`entry_list` returns the manifest `generation`, and it is not decorative.** Every mutating
   op must echo the caller's last-seen value; the broker answers `conflict` if it has moved on
   (F-9's optimistic concurrency). A screen that discards it cannot perform a *first* update at
   all. Since ADR-077 it also returns `entries` — `{id, name, type, sensitivity, fieldCount,
   modified, rotatedAt, expiresAt}` per entry the caller may list — to a human session, which every
   bridge session is (an agent or MCP caller never receives that key); `notes_read` returns the same
   `generation`, so the notes screen can write without calling `entry_list`.
6. **Unix only, today.** `credmgrd` binds a Unix domain socket; non-Unix builds compile and
   return `platform_unsupported` rather than failing to build. The Windows named pipe is designed
   in `16_CROSS_PLATFORM.md §5.3` and is `planned`.

### 3.3 The other forty-five operations — **`built`**

Until 2026-09-24 these were not reachable from `invoke()`: ADR-057 declined to wire them ahead of
the screens that drive them, because every mutating op carries the `generation` of rule 5 above
and several sit behind presence or approval gates whose interaction design *is* the delivery this
document scopes. **ADR-062 wired them anyway, deciding nothing a screen has to undo**: the bridge
makes no UX decision for any of them — `generation`, presence and approval semantics stay
broker-side and reach the UI as the broker's own error codes (rule 3), and `dispatch_at` attaches
the session token and reconciles lock state (rule 4) for every op alike.

All forty-five are generated from one `bridge_ops!` table in
`apps/desktop/src-tauri/src/commands.rs`: each row is the single place its op name, its Rust
argument names and its wire keys exist. The thirteen families below account for all forty-five —
7 + 5 + 8 + 2 + 3 + 4 + 2 + 3 + 2 + 2 + 1 + 4 + 2 — so the table can be checked against
`crates/brokerd/src/ops.rs` minus the eight of §3.1 rather than taken on trust. The commands are
**`built`**, and so are the screens that drive them (§5), apart from the eleven operations that have
no control in the app (§2, last row); whether each control does what the checklist says is the open
human pass (`RELEASE_VERIFICATION.md`):

| Family | Ops | Driven by |
|---|---|---|
| Entry mutation | `entry.create`, `create_batch`, `update`, `rotate`, `remove`, `restore`, `undo` | the inspector and entry detail (`09_UI_UX_SPEC.md §7`, `§8`); each `create_batch` item takes the same body as `entry.create`, a single value or a field list (ADR-073, ADR-078); the app edits an entry through the field operations below, so `update`, `rotate`, `remove`, `restore` and `undo` have no control (§2) |
| Entry fields (ADR-078) | `entry.get`, `field.add`, `update`, `remove`, `reorder` | entry detail: labels, types and masking from `entry.get`, never a value; adding, editing, removing and reordering one field at a time; `08_FIELD_MODEL.md` |
| Node lifecycle | `node.create` (optional `workdirs`), `list`, `set_workdirs`, `update`, `policy`, `reparent`, `restore`, `seal` | `/settings/nodes` and the graph's add/remove flows (`09_UI_UX_SPEC.md §9`); directory binding is ADR-066; rename and the policy patch are ADR-071 |
| Notes | `notes.read`, `notes.write` | the inspector's notes (`09_UI_UX_SPEC.md §2`); ADR-072 |
| Grants | `grant.list`, `create`, `revoke` | `/settings/grants` (`09_UI_UX_SPEC.md §10`) |
| Locked-write tray | `vault.pending_list`, `pending_accept`, `pending_discard`, `approval_decide` | the pending-review tray (F-1) |
| Per-node lock | `vault.node_lock`, `node_unlock` | the node inspector's lock control |
| Gate enrolment and recovery | `vault.gate_enroll_begin`, `gate_enroll_confirm`, `gate_recover` | onboarding and `/settings/security` (`07_TWO_FACTOR.md §4`); `gate_recover` is the last door (ADR-064) |
| Vault bootstrap | `vault.init_begin`, `init_confirm` | the first-run screen (ADR-061); the CLI's `credmgr init` drives them today |
| Stored TOTP | `totp.seed`, `totp.code` | entry detail's TOTP field (`07_TWO_FACTOR.md §6`) |
| Search | `search` | the search surface (`09_UI_UX_SPEC.md §6`) |
| Maintenance | `maintenance.verify`, `doctor`, `backup`, `rotate_root` | `/settings/backup` and `/settings/maintenance`; Advanced → Rotate root key (`rotate_root` is ADR-076; its wire answer is `presence_required` until presence can be attested) |
| Audit | `audit.tail`, `audit.get` | recent activity and `/settings/audit` (§6.4) |

**Four of them are wired and refused on every call.** `totp.seed`, `node.reparent`,
`grant.create` and `audit.get` answer `presence_required` broker-side until a transport can attest
presence (ADR-047, F-8), as does `maintenance.doctor` with `rebuildRegistry`, `maintenance.rotate_root`
(after its human, `admin` and fresh-second-factor checks, ADR-076), and `node.policy`
for a patch that turns `descendantRead` on or `siblingVisibility` to `shared` (ADR-071). A screen
for any of them is designed against that refusal, not against a success body.

**The typed client.** `apps/desktop/src/lib/bridge.ts` wraps every command with the argument names
and response shapes the broker uses, and exports the `BrokerErrorCode` union. It is part of the
bridge contract and owned by this repository, not a UI component (ADR-062). It carries `nodeUpdate`, `nodePolicy`,
`notesRead`, `notesWrite` and `entryCreateBatch` for ADR-071…073.

The invariants that keep this surface honest hold for every command, and each reads the other
side's source off disk: the token custody rule of §3.2.1 is enforced by the bridge's own dispatch
path rather than per-command;
`tests/drift_guards.rs::the_bridge_covers_every_op_the_broker_dispatches_and_nothing_else` parses
`crates/brokerd/src/ops.rs` in both directions, so a command naming an op the broker does not have,
or an op with no command, fails the build rather than shipping;
`::every_param_the_bridge_sends_is_one_the_broker_reads_and_every_required_one_is_sent` holds the
wire keys; `::every_bridged_command_is_registered_with_tauri` holds `generate_handler!`; and
`tests/ts_client.rs` holds `bridge.ts` to the Rust table and the error vocabulary.

## 4. The response shapes a screen renders against — **`built`**

Read from `crates/brokerd/src/ops.rs` in this pass. A screen must render these shapes, not
invented ones — the single most expensive class of rework in a hand-over is a component built
around a field the backend never sends.

| Op | Response |
|---|---|
| `vault.status` | `{ "locked": bool }` |
| `whoami` | `{ "node", "capabilities": [...], "reachable": [node ids] }` — reachable nodes only, never the whole registry (F-6). For the desktop's own login (a token `vault.unlock`/`vault.gate_verify` minted) `reachable` is every node but Orphaned (ADR-065); for an agent it is only its own reach |
| `node.list` | `{ "nodes": [node ids] }` — bare ids, filtered the same way as `whoami`'s `reachable`; labels, kinds and parents come from `graph.snapshot` |
| `entry.list` | `{ "node", "ids": [...], "names": [...], "generation": int }` |
| `entry.reveal` | `{ "node", "entry", "value" }` — the plaintext itself |
| `audit.tail` | `{ "records": [...] }`; `limit` defaults to 50 and is clamped to 1…500 |
| `graph.snapshot` | `{ "nodes": [...], "links": [...], "meta": { "generatedAt", "vaultLocked" } }` |

`graph.snapshot`'s node object is the one the primary view is built on, so it is worth stating
field by field: `id`, `label`, `kind`, `depth`, `parentId`, `counts: { entries, totp }`,
`gate: { locked, twofa }`, `health`. Four consequences follow directly, and each is a design
constraint rather than a detail:

- **`counts` carries exactly two numbers**, which is why `09_UI_UX_SPEC.md §4`'s hover card shows
  exactly two. There is no third number to show.
- **`health` is `null` in every response today.** No integrity or expiry computation exists
  behind it. The health affordance must render a sane default for `null` rather than treating it
  as an error or an empty state — this is the common case, not a bug to route around.
- **`gate.twofa` is one of `none`, `enrolled`, `required`**, derived from the node's own
  `requireTwoFactor` policy and whether the vault gate is confirmed. It is not a boolean.
- **`links` are structural parent→child edges only.** Grant edges — the dashed ones
  `06_ACCESS_GRAPH.md §10.6` and the graph spec both describe — are **`planned`**: `graph.snapshot`
  emits no grant link today, so the dashed-edge treatment will be designed and then rendered
  against `grant.list`, which §3.3 now wires.

Two behaviours matter as much as the shapes. **The graph is designed to render while the vault
is locked** — `graph.snapshot` reads the in-memory registry and needs no root key — so `/locked`
is a state layered over a live topology, not a blank wall. One exception is real since the daemon
began loading its vault from disk (ADR-063): **after a broker restart, the graph is empty until the
first unlock**, because the registry cannot be verified without the root key and an unverified
registry is never shown. The `/locked` screen must render that empty-before-first-unlock case as
well as the populated-but-locked one. And **filtering is broker-side**: a node absent from the
response was never sent, not hidden by the UI, so there is nothing for a screen to filter and
nothing it may reveal by trying.

## 5. Delivery scope: every route, in both modes — **`built`**, verification pending

*Status 2026-10-03: the list below is the scope the delivery was checked against; all twenty-two routes are rendered and wired to the broker (the Status block above). The future tense is the specification's. The route-by-route human pass is `RELEASE_VERIFICATION.md`.*

`18_ENDPOINT_INDEX.md §5` is the route table and `09_UI_UX_SPEC.md §5` is the mode matrix.
Reproduced here as one list because the delivery is checked against it, and cross-referencing
two documents during a build is how a route goes missing.

**Fourteen routes will ship in both modes:**

`/` (graph or tree, remembered, plus inspector) · `/node/:id` · `/node/:id/entry/:eid` ·
`/orphan` · `/settings/security` · `/settings/appearance` · `/settings/backup` ·
`/settings/mode` · `/settings/about` · `/settings/donate` · `/settings/privacy` ·
`/settings/licenses` · `/locked` · `/onboarding/:step`

**Eight routes are Pro-only, and will ship in the Pro bundle in addition to all fourteen
above:**

`/settings/nodes` · `/settings/grants` · `/settings/agents` · `/settings/llm` ·
`/settings/maintenance` · `/settings/audit` · `/settings/advanced` · `/operations`

**Twenty-two routes, and the delivery is both bundles in full.** A delivery covering `/` and two
settings pages is incomplete regardless of visual quality; that is the explicit instruction to
the front-end track and the reason this document exists as scope rather than design.

Mode is not a visual variant. `09_UI_UX_SPEC.md §5` fixes the principle — *Lite hides levers,
never safety* — and the consequences are behavioural: grant **creation** will be Pro-only, grant
**revocation** will be in both; sealed-node **restore** will be in both; automatic backup and
integrity checking will run in both and surface only on failure in Lite. A Lite vault will be
byte-identical to a Pro one, and switching modes will be instant and non-destructive. A design that removes a control which would make
a bad situation harder to fix has mis-read the rule.

<!-- figure:route-coverage-by-mode -->

*Twenty-two routes, not one screen: fourteen ship in both bundles and eight are Pro-only, so
mode gating is a property of eight routes rather than of the application — "we built the main
view" is roughly 1/22 of the hand-over. `/settings/llm` is shown disputed, not resolved (§10).*

## 6. Behaviour every screen must implement — **`planned`**

### 6.1 Four states per view, designed rather than improvised

`09_UI_UX_SPEC.md §13` is normative: every view specifies **empty, loading, error, denied**, and
a missing empty state is a bug, not a polish item. Two of the four are easy to skip and are
called out because they carry security meaning:

- **Denied is not one treatment.** In search, results the caller cannot see will be **omitted
  silently** — the human sees their own vault, and machine denials are the API's concern
  (`06_ACCESS_GRAPH.md §5`). In entry detail, a 2FA prompt will be inline, never a modal. In the
  orphan panel, the whole panel *is* a denial state by design, so it has no separate one.
- **`approval_pending` is a fifth outcome the reveal path can return** and is not a failure. A
  locked vault whose target would otherwise be readable opens a one-tap approval path instead of
  denying (ADR-042). It will need its own designed state.

### 6.2 Theming — both modes, every screen

`20_THEMING.md` is the specification: dark ⇄ light is a real inversion (elevation flips to
shadow), and colour is a single user-chosen hue derived in OKLCH so lightness is never set by the
hue. Contrast must hold at ≥ 4.5:1 for text and ≥ 3:1 for meaningful strokes **in both themes**,
and the greyscale test is normative — printed in black and white, no state may become ambiguous.
The delivery will apply this across all twenty-two routes in both modes, not to the primary
view only. `20_THEMING.md §5` lists the six renders the design track owes back.

### 6.3 Accessibility — a delivery gate, not a review comment

`09_UI_UX_SPEC.md §14` is non-negotiable and three of its clauses are the ones a graph-centred
design tends to violate: **every graph action will have a tree or menu equivalent** (a
canvas-only feature is a bug, including grant creation); a hidden `<ul role="tree">` will mirror
the graph and stay in sync; and `prefers-reduced-motion` will disable the force simulation's
animation, all reveals, and all countdown animations — a countdown becomes a number. Responsive behaviour is
fixed in `09_UI_UX_SPEC.md §15`: below 820 px the tree view will become the default and the
graph opt-in.

### 6.4 Recent activity refreshes on mutation, not on a timer

Whatever surface renders recent activity will be fed by `audit.tail`. It **will** update immediately
after any action that changes it — using an entry, creating one, rotating, removing, restoring —
and not on a timer, and not only on next navigation. The concrete complaint driving this is
stale activity: an operator acts and the list does not reflect it without a manual refresh.

**The target mechanism is a client-side refetch-on-mutation, and deliberately not a push.** The
protocol is request/response over a socket with no persistent streaming session
(`10_API_AND_MCP.md §1`), so after any mutating command resolves successfully the UI re-issues
the `audit.tail` call feeding the view — invalidate and refetch. This needs no new broker op and
no protocol change. The bridge's part is small and already true in shape: each command's success
path is a resolved promise a refetch can key off. If multi-window synchronisation later makes a
real push mechanism worth its cost, that is an architectural decision that will get its own ADR
rather than being assumed here.

### 6.5 The donation screen

`/settings/donate` will ship in **both** modes and will render `v2/DONATE.md`'s five chains so
each is identifiable at a glance rather than as a bare address table:

- **The EVM row is one address across five networks** — Ethereum, BNB Chain, Arbitrum, Optimism,
  Base. It will show a small icon **per network**, side by side, so the reader can see at a glance
  which chains that single address is valid on. The row must not imply five different addresses.
- **Bitcoin, Solana, Tron and TON** will each get one chain icon beside the chain name, in the
  same visual treatment as the EVM row's per-network icons.
- **The safety copy is part of the screen, not decoration.** `DONATE.md`'s verification lines
  will travel with it: check the first and last six characters after pasting (clipboard hijackers
  target exactly this), send a test amount first, the EVM address is valid only on the listed
  chains, and a donation is non-refundable and buys nothing.
- **The no-nag rule is absolute.** One static entry under Settings → Donate. Never a banner,
  never a countdown, never a gated feature.

Icon selection — which set, which sizes, which files — is front-end scope (§8). If
`design/tokens/keep-components.css` already defines a suitable icon component or token, it will be
used; if not, choosing one is a design decision for that track to make, not a gap to escalate. **Nothing in
`crates/brokerd/src/ops.rs` changes for this**: the chain list is static content in `DONATE.md`,
not data queried from the broker, and no chain-metadata op is needed or planned.

## 7. Acceptance — how a delivery is checked off

Run against a delivery before accepting it. Each line is checkable by someone who did not build
it, which is the only property that makes a checklist worth having.

- [ ] **Both bundles present.** Lite = the fourteen shared routes. Pro = those fourteen plus the
      eight Pro-only routes. Count them against §5; twenty-two is the number.
- [ ] **Every screen's four states designed** — empty, loading, error, denied (§6.1) — plus
      `approval_pending` wherever a reveal can occur.
- [ ] **Every data-bound screen renders a real response shape from §4** and calls its op through
      `apps/desktop/src/lib/bridge.ts`, and any screen bound to one of the presence-gated ops of
      §3.3 is designed against its `presence_required` refusal, not a success body.
- [ ] **The graph renders `counts` as exactly two numbers, `health: null` as a sane default, and
      `gate.twofa` as three-valued** — and renders while the vault is locked.
- [ ] **No screen holds, stores, or expects a session token** (§3.2.1), and the lock screen is
      driven by command results rather than a UI-side flag (§3.2.4).
- [ ] **`two_factor_required` is handled as an error code**, not as a success state (§3.2.2).
- [ ] **Dark and light applied to all twenty-two routes in both modes**, with the contrast and
      greyscale checks of §6.2 evidenced, not asserted.
- [ ] **Every graph action has a tree or menu equivalent**, and `prefers-reduced-motion` is
      honoured throughout (§6.3).
- [ ] **Recent activity refetches after every successful mutation** (§6.4).
- [ ] **`/settings/donate` renders five chains with per-network EVM icons and carries the
      verification copy and the no-nag rule** (§6.5).
- [ ] **No hard-coded token value, address, or vault path** anywhere in the delivered source —
      `v2/scripts/guard-no-personal-data.mjs` and `v1/scripts/guard-no-secrets.mjs` run over it
      before it is committed here.

## 8. Division of labour, and the integration path — **`partial`**

| Owner | Scope |
|---|---|
| Front-end track | The visual and interaction layer only: component structure, layout, styling, graph rendering, all four states per view, copy, both bundles, all twenty-two routes. Built and verified against mocks shaped exactly like §4's real responses. **`built`, verification pending** (ADR-075: the design is hosted and every route is wired to the broker; the control-by-control human pass is `RELEASE_VERIFICATION.md`, results column empty) |
| This repository | The `#[tauri::command]` glue (§3.3) — a command per op, with its tests — plus the typed client `apps/desktop/src/lib/bridge.ts` and the drift guards that keep both honest. Small and mechanical; it is not a design decision. **`built`** (ADR-062, ADR-078): all 53 commands, the client, and the guards, in CI. |

The two tracks do not gate each other. This repository's half landed first, so the front-end
delivery can call real commands through `bridge.ts` from its first screen — and still builds
against mocks shaped like §4 wherever no broker is running, which is the point of specifying §4's
response shapes precisely enough to mock.

**When a delivery lands**, that is Phase 9 (`12_BUILD_PLAN.md §5.1`), and two things will happen
here in order: the artifacts will go into `v2/design/handoff/`, which does not exist yet and will
be created then; and the delivery will be recorded in `09_UI_UX_SPEC.md`. There are no commands
left to wire at that point — §3.3 already reaches every op. (The scaffold's `greet` command is
already gone, ADR-075.) The two bridge-side checks Phase 9's exit gate names are
already met: every broker op is reachable
(`tests/drift_guards.rs::the_bridge_covers_every_op_the_broker_dispatches_and_nothing_else`), and
no result across every command serialises a token-shaped string
(`tests/bridge_ops.rs::no_result_across_every_command_carries_a_token_shaped_string` — the
sweep asserts it covers exactly the bridged surface).

One hand-over hazard is worth carrying in this document rather than only in a session log,
because it has already cost a real leak: **a copied document set drifts silently and
re-introduces defects that were already fixed here.** A 40-agent adversarial review of the
still-local staged bundle (Session 20, 2026-08-18) found it carrying a pre-fix copy of a
reference file — an address literal that this repository had already sanitised to an RFC 5737
documentation address (`203.0.113.x`). The bundle was never sent to anyone (`HANDOVER_STATE.md`
§1; commit `ee59696`) — the drift happened, and was caught, entirely within the still-local copy,
before anyone determined the hand-over itself had never occurred. Diff any outgoing bundle
against `v2/docs/` before every hand-over, and treat a bundle copy as a stale fork by default.

## 9. Where endpoint truth lives — and one source that is not in this repository

Two documents answer two different questions, and they are not interchangeable.

| Question | Answer lives in | Guarded? |
|---|---|---|
| "What is the full V1→V2 surface, and which parts of it exist?" | `18_ENDPOINT_INDEX.md §1` — the complete mapping, every row marked `built` / `planned` / `removed` | Yes — `python3 -m tools.corpus_check endpoints` proves, in both directions, that every op named there exists and every op the broker dispatches is named there |
| "What is implemented and tested right now, as a dated snapshot?" | ~~`03_ENDPOINTS_CURRENT.md`~~ — **deleted 2026-09-07; no replacement.** Use `18_ENDPOINT_INDEX.md §1` plus a fresh grep | **No** |

**`03_ENDPOINTS_CURRENT.md` was never part of this corpus, was never in this repository, and no
longer exists anywhere.** It lived
in the operator's design-handoff staging area, a separate local git repository never published
from here; the operator deleted that whole folder on 2026-09-07 (re-checked absent 2026-09-21).
Whether to recreate it in-repo or retire the idea is an open operator decision. Until then there
is **no dated as-built snapshot** — the question in the table above has no answer except to
re-derive it from source. Earlier revisions of this document cited it side by side with corpus
documents, in the same notation, which made it read as a sibling of `18_ENDPOINT_INDEX.md`; it is
not one. Three consequences follow, and they are the reason this section exists:

1. **Nothing in this repository can check it.** `tools/corpus_check.py` walks `v2/docs/` only, so
   the guard that keeps `18_ENDPOINT_INDEX.md` honest does not reach it.
2. **Cross-references to it do not resolve.** Its absence was the single blocking finding of
   `python3 -m tools.corpus_check crossrefs` before this rewrite. This document no longer cites
   it by section, because a section reference to a document the corpus cannot see is a citation
   that can never be verified.
3. **It is a snapshot of a moving codebase and goes stale by construction** — that is a property,
   not a defect. It was re-verified and re-stamped on 2026-08-17, so the drift narrative earlier
   revisions of this document carried (`node.create` mis-listed as unbuilt, an op count of 31) is
   closed and has been removed rather than corrected in place.

**The rule when they disagree: live source wins, and neither document is source-of-truth for a
safety- or data-integrity-critical decision.** Re-run the greps — `crates/brokerd/src/ops.rs`,
`crates/mcp/src/tools.rs`, `crates/cli/src/main.rs` — and believe those. If the front-end track
needs a fresher snapshot, re-running that document's own verification method in full and
re-stamping it under the three-pass rule is real engineering work and its own task, not a side
effect of a documentation pass.

## 10. What this document deliberately does not resolve

Four items, named and bounded rather than smoothed over. None blocks the delivery; each would
produce a wrong artifact if guessed at. The first three are open; the fourth was resolved on
2026-09-24 and stays here for the caveat that survives it.

1. **`/settings/llm`'s mode status.** `18_ENDPOINT_INDEX.md §5` routes seven Pro-only settings
   paths including `llm`; `09_UI_UX_SPEC.md §5` names six Pro-only control sections and does not
   mention it. The delivery covers the **union** — seven Pro-only settings routes — and this
   document does not pick a winner. **Note also, corrected:** the figure "Pro settings = 10
   sections" that circulated in earlier revisions *is* derivable, from `09_UI_UX_SPEC.md §5`
   alone — Lite's four sections (Security · Appearance · Backup · Mode) plus Pro's six
   additional (Nodes · Grants · Agents · Maintenance · Audit · Advanced) is ten. That count is of
   UI settings **sections** a Pro user sees in total, a different measure from the seven-vs-six
   Pro-**only** route disagreement above, and `llm` is one of the seven-vs-six routes, not one of
   the ten sections — so the ten-section total does not settle it either way.
2. **Grant edges have no data source.** `graph.snapshot` emits structural links only, so the
   dashed grant edge that `06_ACCESS_GRAPH.md §10.6` and the graph spec both describe cannot be
   rendered from a real response today. It is designed against `grant.list`, and is `planned`.
3. **`health` has nothing behind it.** The field is `null` in every response and no integrity or
   expiry computation exists. Designing a rich health affordance now risks designing for data
   that will never arrive in that shape.
4. **The passphrase argument to `vault_unlock` is honoured — resolved by ADR-063.** Until
   2026-09-24 it was inert: the broker unwrapped with the keystore `credmgrd` built at process
   start. `vault.unlock {passphrase}` now builds the Software keystore from the passphrase per
   request, proves it against `keys/root.wrap.pass`, and loads and verifies the vault from disk
   (`crates/brokerd/src/state/durable.rs`). The call site did not change. **The caveat that
   survives:** a passphrase arriving as a JS string was already copied by the IPC layer before the
   bridge sees it, and Rust gives no guarantee that heap allocation is zeroised — a real
   limitation, named here rather than papered over, and one the unlock screen's copy should not
   overstate. The same holds for `vault_gate_recover`'s and `maintenance_backup`'s passphrase.

## 11. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `18_ENDPOINT_INDEX.md §4` | the fifty-three built broker-op commands — eight hand-written, forty-five generated (ADR-062, ADR-078) — plus the shell's own three |
| depends on | `18_ENDPOINT_INDEX.md §5` | the route table §5 reproduces and checks the delivery against |
| depends on | `09_UI_UX_SPEC.md §5` | the Lite/Pro matrix that decides which routes are gated, and the "hides levers, never safety" rule |
| depends on | `09_UI_UX_SPEC.md §13` | the four-states-per-view requirement §6.1 makes an acceptance gate |
| depends on | `20_THEMING.md §5` | the six theme renders the design track owes back |
| depends on | `10_API_AND_MCP.md §1` | the request/response wire model that makes §6.4 a refetch rather than a push |
| depends on | `06_ACCESS_GRAPH.md §1` | rule R1's `approval_pending` branch — a locked-vault reveal that would otherwise be allowed returns `approval_pending` rather than a flat denial |
| depends on | `06_ACCESS_GRAPH.md §5` | the silent search omission §6.1's denied-state design follows |
| depends on | `06_ACCESS_GRAPH.md §10.6` | the unrendered grant edge — `graph.snapshot` emits structural links only |
| depends on | `16_CROSS_PLATFORM.md §5.3` | the Windows named pipe the bridge's `platform_unsupported` path is waiting on |
| feeds | `12_BUILD_PLAN.md §4` | Phase 6's status as an external track with no autonomous exit gate, and its exit-gate checklist |
| feeds | `12_BUILD_PLAN.md §5.1` | Phase 9's integration scope — the delivered screens, driving the commands §3.3 already wires |
| feeds | `13_TEST_PLAN.md §6` | the bridge tests and drift guards that sit outside the workspace suite |

## 12. Source

**Design.** `ADR-035` (the desktop crate is excluded from the v2 workspace, which is why its
tests are not in the workspace count), `ADR-042` (the locked-but-reachable approval path),
`ADR-043` (the idle auto-lock nothing pushes), `ADR-056` (the session token
`vault.unlock`/`vault.gate_verify` mint), `ADR-057` (the bridge: token custody, verbatim error
codes, drift guards, and the eight-of-thirty-eight scope it started with), `ADR-059` (the status
vocabulary each heading carries), `ADR-062` (every op bridged, the typed client, the
`VAULT_STATE_OPS` fix, the CSP), `ADR-063` (the live unlock that makes the passphrase argument
real), `ADR-065` (the login's whole-vault reach `whoami` reports), `ADR-071`…`ADR-073` (the five
ops added to the generated table).

**Code.** `apps/desktop/src-tauri/src/commands.rs` (the eight hand-written commands and the
`bridge_ops!` table that generates the other forty-five, with their argument shapes),
`src/lib.rs` (`generate_handler!`; the scaffold's `greet` and the `opener` plugin are gone, ADR-075), `src/session.rs` (token capture,
the three lock signals, `VAULT_STATE_OPS`), `src/error.rs` (`BROKER_ERROR_CODES`, 25
discriminants). `apps/desktop/src/lib/bridge.ts` (the typed client). `tauri.conf.json`
(`security.csp`, `security.devCsp`). `crates/brokerd/src/ops.rs` for every response shape in §4 —
`graph.snapshot`'s node object, `entry.list`'s `generation`, `whoami`'s reachable-only list,
`node.list`'s bare ids, `audit.tail`'s 1…500 clamp — and for the 53-op dispatcher.
`apps/desktop/src/vault/` and `apps/desktop/README.md` for which screens are wired to the broker and which are not. `design/tokens/` and
`design/graph-engine/` for the built design assets.

**Tests.** `cargo test` in `v2/apps/desktop/src-tauri`: **186 tests listed in 12 test executables on 2026-10-03**; **156
passing, 0 failing, exit 0** across ten test executables, **re-measured 2026-10-02** — adding the concealed clipboard and lock-on-sleep
(`tests/shell_ipc.rs`, `tests/macos_pasteboard.rs`), the dependency policy
(`tests/dependency_policy.rs`) and the shell's unit tests to the bridge's. Before that, **40 passing,
0 failing**, verified 2026-08-18 — 23 unit, 13 in `tests/bridge_wire.rs` against a real Unix socket,
4 in `tests/drift_guards.rs` — and **64 on 2026-09-24 (ADR-062); 65 after ADR-068's
`session_expired` case**, adding
`tests/bridge_ops.rs` (every generated command's frame, token attachment, optional-omission, and
the whole-surface no-token sweep), `tests/ts_client.rs` and `tests/shell_config.rs`, and widening
`tests/drift_guards.rs`. **These are not part of the `cargo test --workspace` count** (see
`BUILD_LOG.md`'s latest entry for that), because ADR-035 excludes this crate from the workspace; a
session that runs only the workspace suite has not exercised the bridge at all. Since 2026-09-24
the suite runs in CI as its own job (`.github/workflows/security.yml` → `v2-desktop-bridge`) — it
had sat red for three weeks while nothing ran it. The named guards are
`bridge_wire.rs::the_session_token_is_captured_attached_and_never_returned`,
`::no_command_result_ever_serialises_a_token_shaped_string`,
`::two_factor_required_reaches_the_ui_as_the_brokers_own_code_and_mints_nothing`,
`bridge_ops.rs::no_result_across_every_command_carries_a_token_shaped_string`,
`drift_guards.rs::the_bridge_covers_every_op_the_broker_dispatches_and_nothing_else`,
`ts_client.rs::the_client_calls_every_bridged_command_once_with_exactly_its_wire_keys`, and
`shell_config.rs::the_production_csp_exists_and_admits_no_remote_origin`.

**Figures.** `19_FRONTEND_DELIVERY_SCOPE_spec.json` (sibling of this document), an array of two:
`desktop-login-sequence` (`kind: "sequence"`, rendered by `tools/docgen/sequence_diagram.py`
from `apps/desktop/src-tauri/src/commands.rs`, `src/session.rs`, and the two named
`bridge_wire.rs` tests above) and `route-coverage-by-mode` (`kind: "flowchart"`, rendered by
`tools/docgen/visual.py` from `18_ENDPOINT_INDEX.md §5` and `09_UI_UX_SPEC.md §5`, rendering
the §10 item 1 disagreement over `/settings/llm` as a disputed node rather than resolving it).

**Verification.** `python3 -m tools.corpus_check crossrefs` and `... endpoints`.
`python3 -m tools.docgen.cli build v2/docs/19_FRONTEND_DELIVERY_SCOPE.md --formats html,json`.
