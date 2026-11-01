---
id: V2-001
classification: public
title: Concept
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21). The previous stamp (Approved With Known Risks @ 6ee1e5f on
     2026-08-10, ADR-052) attested a body with two defects a full re-derivation against
     `v2/crates/` found. First, §3 described notes as encrypted, node-scoped storage in the
     present tense ("Notes are encrypted under the node key and are scoped exactly like
     credentials") — no operation reads or writes a note anywhere in this workspace;
     `notes.read`/`notes.write` are `planned` rows in `18_ENDPOINT_INDEX.md §1.2`, dispatched
     nowhere in `crates/brokerd/src/ops.rs`, and `crates/store/src/backup.rs`'s `notes.env` write
     is a test fixture, not a built feature. Second, §2 described the orphan carve-out as
     something "only a human at the keyboard, with the master factor and 2FA, can open." That is
     false today: `presence_attested` is hardcoded `false` at three call sites in `ops.rs`
     (lines 91, 124, 314) on every transport that exists — including the new Tauri bridge
     (`ADR-057`, commit `b23a5ae`), which constructs no `Origin::Native` and sets no presence
     attestation anywhere (`session.rs` derives `Origin::Agent` from cwd, nothing else). R0's
     native-plus-presence exception is therefore unreachable by anyone, and a sealed node is, at
     this moment, unreadable by every caller including the operator
     (`04_CRYPTO_AND_KEYS.md §5.2` says so in the same words). Both are now marked `planned`
     with their complete target design kept, per `ADR-059`. A verify pass beyond the two named
     defects found a third, same-shaped gap and fixed it in §2's fourth promise: `grant.create`
     itself refuses unconditionally with `PresenceRequired` on every transport that exists today
     (`ops.rs:2513-2570`), after validating everything else including a caller that already holds
     `Admin` — grants can be listed and revoked, but not newly created, by anyone, yet. The
     capability list in §5/§6 is corrected to the real seven-variant enum
     (`crates/core/src/registry.rs:145-153`) — `list, read, reveal, create, update, notes, admin`,
     never `write` — and `## Connections` / `## Source` sections are added; this document had
     neither, though `00_README_START_HERE.md §4.2` makes both mandatory. Updated 2026-09-24
     for ADR-062…066 (42 broker ops; the bridge at 42/42). Updated 2026-09-24 for ADR-071…073
     (notes built in the broker, §3 now `partial`; 47 broker ops; `node.policy`'s conditional
     presence refusal, §2.2). Updated 2026-10-03 for ADR-078/079 (53 broker ops; §2.1 sealing works in a
     vault `credmgr init` made and across restarts; §2.2 the orphan cold key exists, still unread by any
     operation; notes reached by the CLI and the inspector). -->
# Vault Next — the concept

`CredMgr V2` · Pass 1 · `2026-08-04`

---

> **Status.** The node-as-boundary model in §1–§2 is **`built`**: per-node asymmetric keys,
> upward-only inheritance, depth-2 sibling sharing, and sealing-on-removal all exist and are
> tested (`crates/core/`, `crates/brokerd/tests/isolation.rs`). Two things this document
> previously described as already working were not, and are corrected below rather than
> softened. **The notes half of "privacy vault" (§3) is `partial`** — since 2026-09-24
> (`ADR-072`) the broker stores, seals and serves one note per node behind the separate `notes`
> capability; since 2026-10-02 the CLI (`credmgr notes show|set|clear`) and the inspector (which shows a node's
note) reach it, and no MCP tool does. **The native-presence door §2 describes is
> unreachable by anyone today, human included** (§2.2) — the field it depends on,
> `presence_attested`, is hardcoded `false` on every transport, so a sealed node is currently
> unreadable by every caller, not opened by "a human at the keyboard." Both are designed here in
> full and claimed nowhere as shipped, per the vocabulary `ADR-059` fixes for this whole corpus.

## 1. The one-sentence change

**In V1 a project is a label. In V2 a node is a boundary.**

Everything else in this design follows from that sentence. V1 stores 185 credentials in one
`vault.age` file, encrypted to one key, tagged with a `project` string that is used for
*filtering* and nothing else. Any process that can read `.credmgr/master.key` reads all 185.
An agent working on Northwind can `credmgr get ACME_VPS_PASSWORD` and it just works.

V2 makes the project tag load-bearing: a **node** owns its own key, its own encrypted
material, its own notes and its own agent scope (the second factor is one gate for the whole vault in 2.0.0-beta.1; a per-node secret is planned, ADR-093). Reading across nodes is
not a filter you forgot to apply — it is a decision someone made, once, on the record.

---

## 2. The model — **`built`**, with two exceptions marked below

```
                         ┌───────────┐
                         │  GLOBAL   │   depth 0 · exactly one · readable by every node
                         └─────┬─────┘
          ┌──────────┬─────────┼─────────┬──────────┐
      ┌───┴──┐   ┌───┴──┐  ┌───┴──┐  ┌───┴──┐   ┌───┴────┐
      │  A   │   │  B   │  │  C   │  │  D   │   │ Linux  │   depth 1 · projects
      └───┬──┘   └──────┘  └──────┘  └──────┘   └───┬────┘
      ┌───┴───┐                             ┌───────┼───────┐
   ┌──┴─┐  ┌──┴─┐                        ┌──┴─┐ ┌──┴─┐ ┌───┴┐  depth 2 · sub-nodes
   │ X  │  │ Y  │                        │ n1 │ │ n2 │ │ n3 │
   └────┘  └────┘                        └────┘ └────┘ └────┘

   ┌ ─ ─ ─ ─ ─ ┐
     ORPHANED     off-tree · sealed · names visible, values unreadable by everyone (§2.2)
   └ ─ ─ ─ ─ ─ ┘
```

**Four structural promises.**

1. **Containment.** A node's entries live in that node. Project A's credentials are not in
   the same encrypted blob as Project B's — they are under different X25519 keypairs, one per
   node. **`built`** — `crates/core/` mints and stores a keypair per node;
   `04_CRYPTO_AND_KEYS.md §3` is the mechanism.
2. **Inheritance flows up only.** A node can read its ancestors, ending at Global. A child
   reads its parent; the parent does **not** read the child. (This is the one place the
   operator's brief was silent and I chose the privacy-maximal reading — see §5, `ADR-005`.)
   **`built`** — rule R4, `06_ACCESS_GRAPH.md §1`, and `is_strict_ancestor` walks the chain
   correctly (`crates/core/src/registry.rs`).
3. **Siblings never see siblings, across the tree, by default** — with one exception the
   brief states explicitly: **sub-nodes under the same parent share** (X and Y are
   interconnected). Depth-1 projects never share. See `06_ACCESS_GRAPH.md §1` (rule R6) for
   the exact matrix and how to flip either default. **`built`**, `ADR-006`.
4. **Anything else requires a grant.** A grant is a dashed line drawn by a human, through a
   dialog, behind 2FA, with an optional expiry, recorded in the audit log, revocable in one
   click. **`partial`.** Grant *resolution* is fully built and tested — rule R7 and its
   `mutual` variant (`06_ACCESS_GRAPH.md §1c`) — and an existing grant can be listed
   (`grant.list`) or revoked (`grant.revoke`) today. **Minting a new grant cannot be done by
   anyone yet.** `grant.create` validates the reason string, the scope, and
   `Capability::Admin` against the target node — then unconditionally returns
   `PresenceRequired`, for every caller including one that already holds `Admin`
   (`crates/brokerd/src/ops.rs:2513-2570`). It is the same architectural gap as §2.2's orphan
   door: both need a presence attestation nothing on any transport can supply today. "Through
   a dialog, behind 2FA" is the target design, designed in full at §2.2; it is not yet a
   callable path.

### 2.1 Removal — **`built`**: seals for seven days before it stops being reversible

Removing a node does not delete it. **`node.seal`** re-encrypts every entry to the **orphan
node's public key**, moves the original ciphertexts and the node's own private key into a
seven-day archive, and drops the node from the live registry. Names, refs and types stay in
the plaintext manifest, so a human can find what used to be there even while its value is
gone. This is `ADR-007`'s decision, and the mechanism is real:
`crates/brokerd/tests/isolation.rs::i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone`
proves both halves — a day-6 restore is byte-identical, a day-8 restore returns
`archive_expired`.

**Restore, within the window, is a move, not an unseal.** It uses the *retained* original key
material, not the orphan cold key — because a one-click "Restore node" and a per-item
presence-gated unseal are incompatible promises, and Pass 1 originally claimed both
(`04_CRYPTO_AND_KEYS.md §5.1`). `node.restore` resolves against the sealed node itself, the
same way `node.seal` does, so an admin token scoped to an unrelated node cannot restore what
it could not have sealed (`ADR-053`, closing a real hole `i21b_…` was written to catch, and
did).

### 2.2 Unsealing after day seven — **`planned`**: today, sealed data answers to no one, not only to no agent (the cold key exists; nothing opens it)

**What is true right now, stated plainly because the promise above was not stating it.** Past
the seven-day window, the orphan node's *private* key exists but is not for use (`ADR-079`, 2026-10-03):
`keys/cold/orphan.key` holds it sealed under a key derived from the vault's root key, `credmgr init` writes
it, the loader never puts it in the hot key set, and the only code that opens it is `node.seal`'s pre-flight
(to prove the key is recoverable before data is committed to it) — while the 53
broker ops contain no orphan-reveal operation of any kind. The access resolver's own rule, R0,
denies `orphan` as a target to every subject **except** one whose `origin` is `native` *and*
which carries a live `presence_attested: true` — and no transport built through Phase 5 can
construct that subject. Not the CLI. Not the MCP server. Not the new Tauri bridge: its session
layer derives every scope as `Origin::Agent` from the caller's cwd
(`apps/desktop/src-tauri/src/session.rs`) and constructs no `Origin::Native` anywhere. **The
door in the diagram above is real in the sense that the rule exists and is tested — R0 has
exactly the shape described — and unreal in the sense that nothing today can walk through it.
A sealed node past day seven is unreadable by every caller including the operator, at the
keyboard, with the master factor and 2FA, because none of those factors is the one R0 checks.**
This is not softened anywhere else in the corpus either:
`04_CRYPTO_AND_KEYS.md §5.2` states it in the same words, and
`success_criterion_2_seal_leaves_the_value_recoverable_listable_and_unreadable`
(`crates/cli/tests/success_criteria.rs`) proves it by refusing even an orphan-scoped
`Capability::List` token, not merely an ordinary agent.

**The target design, in full, unbuilt.** A fourth branch will be added to how a caller's scope
is established: a request arriving over the desktop shell's own channel, carrying a presence
proof the platform's biometric API produced immediately before the call, will resolve to
`origin: 'native'` with `presence_attested: true`. The broker will verify the proof itself
rather than trust the client's word for it — the same custody rule `ADR-057` already applies
to the session token, which is held in Rust and never crosses into the webview. Everything
downstream of that one new branch already exists and needs no further change: R0's exception is
already written, and five operations — `audit.get`, `totp.seed`, `node.reparent`,
`grant.create`, and `maintenance.doctor --rebuild-registry` — already check
`presence_attested` and are already refusing correctly for want of it, rather than granting
something they should not. Landing presence turns five silent refusals into five working
gates without touching their logic. (A sixth, conditional refusal is the exception:
`node.policy` answers `presence_required` for a patch that widens reach, `ADR-071`, without
consulting `presence_attested` — that arm will need the check in place of its refusal.) The exact key-wrap mechanism the orphan path will use — an
HKDF over an ECDH between the platform keystore key and the orphan node's wrap key, salted by
a fresh single-use gate proof, never cached, never batched, no `--yes` — is specified in full in
`04_CRYPTO_AND_KEYS.md §5.2`; the resolver branch itself is specified in
`06_ACCESS_GRAPH.md §10.3`. This document states the consequence rather than repeating the
mechanism, so the mechanism has exactly one place it can drift from.

**Removal never deletes — that half is true today.** What "recoverable" means for the first
seven days, and what "sealed" means after, are two different mechanisms with two different
current states, and conflating them is the mistake this section exists to correct.

---

## 3. It is a privacy vault, not only a credential vault — **`partial`**

Each node is meant to carry **notes**: free markdown the operator or an agent writes about
*why* things are the way they are — "this key rotates every 90 days and the rotation script
lives at X", "the second wallet is the cold one, do not deploy from it", "customer asked us not
to log this." This is the feature that makes the boundary worth having beyond credential
storage alone. Credentials leak *access*; notes leak *context*, and context is often the more
dangerous of the two. An agent in Project B must not be able to read Project A's operational
reasoning any more than its passwords.

**The storage and the two operations are built** (`ADR-072`, 2026-09-24). `notes.read` and
`notes.write` in `crates/brokerd/src/ops.rs` read and write one markdown note per node, sealed
under the node's own key into `nodes/<id>/notes.env` — the same envelope format an entry uses,
with the node id in the AAD and the reserved envelope id `notes`, so a note envelope cannot be
moved into another node and cannot be swapped with an entry. The manifest's `notesSha256` holds
the digest of the note's *ciphertext*, never its plaintext — the mistake `04_CRYPTO_AND_KEYS.md §8`
records for entries — so `maintenance.verify` detects a truncated, swapped or unrecorded note file
without the key, and `notes.read` refuses to serve a file that does not match it
(`03_DATA_MODEL.md §4`). Evidence:
`crates/brokerd/tests/durable_vault.rs::a_note_is_sealed_capability_gated_digest_bound_and_survives_a_restart`.

**What is not built is the agent surface and a screen that writes a note.** The CLI
reaches `notes.*` since 2026-10-02 (`credmgr notes show` / `set` / `clear`, `10_API_AND_MCP.md §2.1`);
no MCP tool does (`§3.1`). The desktop app reads a node's note through `notes_read` and shows it read-only,
but no control calls `notes_write` (`RELEASE_VERIFICATION.md §6`); so a note is written by the CLI, by a client
speaking the broker socket, or through the desktop bridge's `notes_write` command. An agent recording *why* it did
something — the use case above — waits on the `credmgr_notes_*` tools, which are `planned`. That
is why this section is `partial`.

**The capability is separate, and it is enforced.** `Capability::Notes` is a variant of the
seven-member capability enum (`crates/core/src/registry.rs` — `List, Read, Reveal, Create,
Update, Notes, Admin`; there has never been a `write` capability, `ADR-023`), `grant.create`
validates it as one of exactly three grantable scopes (`read`, `reveal`, `notes` —
`03_DATA_MODEL.md §6`), and both note ops require it, resolved against the node like any entry
op. A note is scoped exactly like an entry: an agent that cannot read node A's entries cannot
read node A's note, and inheritance and grants apply the same way. **`notes` deliberately does
not ride along with `read`.** Context is separately sensitive, so it is separately requested — a
caller holding `read` on a node learns nothing about that node's notes, by design, not by
omission (this is the exact distinction `06_ACCESS_GRAPH.md §3` cites this section for). A note
is never in a `.env` backup (`store::backup::select_files` leaves `notes.env` out); when exports
and note-bearing MCP tools exist, they will include one only if the caller explicitly holds
`notes` scope and the node's own policy permits it.

```ts
type Note = { nodeId: string; markdown: string; modified: number; };
```

---

## 4. What "isolation" honestly means here

The current live vault's own `CLAUDE.md` says something admirable and true:

> Neither protects against local shell + `master.key`. That is the CLI trust domain; a local
> vault cannot defend against its own user account.

V2 must not quietly abandon that honesty while adding a graph that *looks* like a security
boundary. So, stated plainly and derived precisely in `05_THREAT_MODEL.md §5`:

**What node isolation genuinely stops:**

- An agent scoped to Project B **cannot read Project A's values through the API** — the
  broker resolves scope and refuses. There is no flag, no argument, no tool that returns
  them. This converts the common accident (a confused agent reaching for the wrong node) into
  a structural impossibility rather than a policy that could be forgotten.
- Reaching another node the honest way requires either a token bound to a different directory
  — logged as an anomaly — or physically changing into a workdir that is not yours, which has
  its own trail. There is no silent success, only a legible one.
- **At rest**, A and B are under different keys. A backup, a stolen disk image, a synced
  folder, or a partially-unlocked vault exposes only the nodes whose keys are open.
- **Orphaned and locked nodes stay sealed even while the vault is unlocked**, because their
  keys are never in the broker's hot set — and, as of today, orphaned nodes stay sealed for
  everyone, full stop (§2.2).
- **Blast radius of any single mistake shrinks** from "the whole vault" to "one node," and a
  `list` that would have returned 185 names now returns only what one node can see, which
  removes single-call reconnaissance as a free win.

**What it does not stop, and no local vault can:**

- A process running as your user account, with your Touch ID prompt answered, that talks to
  the broker with a legitimate token can use that token's scope. Scope is enforced; identity
  is asserted. Local malware running as the owner does not need to steal a token file — there
  are none — it can simply `cd` into a registered workdir and connect; what it gets there is
  bounded by that node's policy, which can include `reveal`.
- Anyone who can attach a debugger to the unlocked broker reads its memory.
- The operator, at the keyboard, can — by design — open anything a real login session's token
  reaches, which is everything except orphan (§2.2 explains why even the operator cannot reach
  orphan today, and why that is a gap being closed rather than a permanent limitation).

The design's job is to make the *common* failure impossible and the *exotic* failure loud.
Claiming more than that would be theatre, and this document refuses to.

---

## 5. Decisions I made where the brief was silent

Flagged here so they are visible, not buried. Full rationale in `14_DECISIONS.md`.

| # | Question the brief did not settle | Decision | Why |
|---|---|---|---|
| D-01 | Can a parent read its children? | **No.** Upward-read only. | "Linux" holding dev/staging/**prod** should not hand prod secrets to whoever is working on the parent. Opt-in per node via `descendantRead` (`ADR-005`). |
| D-02 | Do siblings share? | **Depth-2 siblings under one parent: yes** (the brief says X and Y are interconnected). **Depth-1 projects: never.** Per-parent toggle `siblingVisibility`. | Follows the brief exactly, but makes the surprising half configurable (`ADR-006`). |
| D-03 | How deep can the tree go? | **Hard cap at depth 2.** | The brief describes exactly two layers. Unbounded depth makes the access matrix unreasonable to audit and the graph unreadable. A cap is a feature (`ADR-004`); enforced today by `node.create`'s depth check, not only documented. |
| D-04 | Are grants directional? | **Yes**, with an explicit `mutual` option. | "X may read B" and "B may read X" are different risks and must be separately revocable. The *resolution* of a mutual grant is built and tested (`06_ACCESS_GRAPH.md §1c`); *minting* either kind is presence-gated today (§2, promise 4) — `03_DATA_MODEL.md §6` types `direction`. |
| D-05 | Can a grant be narrower than a whole node? | **Yes** — entry-level grants. | "B needs *one* API key from A" is the common case; granting the whole node for it is the thing that erodes boundaries. The narrowing logic is built and tested (`06_ACCESS_GRAPH.md §1b`), with one honest seam: it needs `list` in the grant's scope, and `grant.create`'s type only ever accepts `read`/`reveal`/`notes` — so the exact shape the test proves the narrowing against is injected directly into the registry, not minted through the built operation. |
| D-06 | What does the hover's "2FA number" count? | **Stored TOTP items owned by the node.** The node's own gate status is a glyph on the ring, not a number. | Keeps the card to exactly two numbers as instructed, and separates the two meanings of "2FA" that would otherwise collide (see `07_TWO_FACTOR.md`). **Partly built** — the hosted design (`ADR-075`) draws the card from `graph.snapshot`'s per-node `counts.entries` and `counts.totp`; that those counts mean this row's decision is the broker's, not something the screen asserts. Its complete spec is `09_UI_UX_SPEC.md §4`. |
| D-07 | Where does the vault-wide "Global" credential live? | Global is a **real node** (`depth 0`), not a virtual bucket. | It has keys, notes, a gate, and an entry count like any node — otherwise every rule needs a special case. **`built`** — `kind: 'global'` is one of four real `NodeKind` values (`03_DATA_MODEL.md §1`), not a synthesized case. |

---

## 6. What is being simplified away

The brief is as much about removal as addition. V2 deletes:

| V1 thing | Fate in V2 |
|---|---|
| `TYPE_SCHEMAS` — predefined field names (`derivationPath`, `xpub`, `apiSecret`, …) | **Deleted**, `ADR-011`. One "+ Add field" button. The label is free text the user types. Types are *inferred* and overridable, never prescribed (`ADR-012`) — the inference engine itself is `built` (`08_FIELD_MODEL.md`). |
| 16-command search palette | **`planned`** — no wired screen exists yet to remove it from. Deleted in Lite (search shows only "Add new"); kept in Pro as an explicit **Operations** panel, not a surprise list under the search bar. Full target design: `09_UI_UX_SPEC.md §6`; the `/operations` route is already reserved (`18_ENDPOINT_INDEX.md §5`). |
| Flat credential list as the home screen | **`planned`** — replaced by the node graph + worktree tree once a screen exists. Spec: `design/graph-engine/VAULT_GRAPH_SPEC.md`; the data it will render, `graph.snapshot`, is itself already `built` and correct while the vault is locked (`ADR-047`). |
| `merge` / `autoMerge` / `findMergeSuggestions` / near-duplicate detection | **`planned`**, demoted to Pro → Maintenance. It exists because V1's flat namespace produced duplicates; node scoping removes most of the cause, so it is designed but not yet a priority build target (`18_ENDPOINT_INDEX.md §1.5`). |
| `classify.js` auto-project detection from the credential name | **Deleted outright.** Node placement is explicit. Guessing which boundary a secret belongs in, from its name, is exactly the wrong instinct for a system built on boundaries. There is no classify subsystem and no regex engine in any V2 process (`17_AIRLOCK_AND_LLM.md §1`, invariant A-4) — the rule about where V1's classify rules run does not describe V2 at all. |
| `deployedTo`, `relatedIds`, `format`, `tags` metadata sprawl | **Collapsed** into `type` plus free-text notes. The `type` half is `built` (`08_FIELD_MODEL.md`); the notes half this collapse leans on is `partial` (§3) — stored and served by the broker since `ADR-072`, reachable by no CLI command, MCP tool or screen yet. |

---

## 7. Success criteria

> **Corrected `2026-08-08`.** Criterion 6 as originally written ("all 185 V1 credentials are
> in V2") directly contradicted the no-migration decision made in `11_MIGRATION.md`
> (2026-08-05): "V2 ships empty. It does not import from V1." That correction updated four
> documents and a build phase but missed this one — found during a second deep-verification
> pass. Fixed below, not silently — the old wording is struck through so nobody re-derives it.
>
> **Backend-vs-UI split, stated explicitly because it was previously implicit and caused real
> confusion about phase sequencing:** criteria 1, 2 and 6 are demonstrable by the backend
> alone (CLI/MCP/broker) — these are what `12_BUILD_PLAN.md §3.1` (Phase 7's exit gate) actually
> means by "every success criterion in `01 §7` demonstrated." Criteria 3, 4, 5 and 7 are
> UI-observable behavior and are independently restated, word for word, in Phase 6's own exit
> gate (`12_BUILD_PLAN.md §4`) — they are proven there, not re-proven in Phase 7. **Phase 7 does
> not require the UI to exist, and as of this rewrite Phase 6 had not started (`v2/apps/desktop/`
> had no screens — the Tauri↔broker bridge behind where those screens sit was `partial`,
> 8 of 40 ops, `ADR-057`, and was `built` on 2026-09-24: all 42 ops, `ADR-062` — 47 since
`ADR-071`…`ADR-073` the same day, 48 since `ADR-076`, 53 since `ADR-078`; the design has since been hosted,
`ADR-075`, and wired to the broker end to end).**

V2 is finished when all of these are true and demonstrated:

1. **`built`, demonstrated.** An MCP agent launched in `~/projects/northwind/` can list and
   read Northwind + Global entries, and receives a structured refusal — not an empty list — for
   anything in `acme`. Proven end-to-end against the real compiled binary and a real socket:
   `success_criterion_1_mcp_agent_reads_its_own_scope_and_is_structurally_refused_elsewhere`
   (`crates/cli/tests/success_criteria.rs`). The refusal carries a remedy rather than a bare
   denial (`ADR-021`, `06_ACCESS_GRAPH.md §5`).
2. **`built`, demonstrated — and stronger than originally stated.** `credmgr node seal linux`
   leaves every value recoverable (within seven days, §2.1), listable by name, and unreadable
   by any agent. Proven by
   `success_criterion_2_seal_leaves_the_value_recoverable_listable_and_unreadable`, which goes
   further than the criterion asks: it also shows an orphan-scoped `Admin`/`List` token is
   refused, not only an ordinary agent — because, as §2.2 states plainly, sealed data is
   unreadable by *everyone* today, a strictly stronger guarantee than "any agent" describes.
3. *(UI-observable — proven in Phase 6's exit gate, `12_BUILD_PLAN.md §4`)* Adding a credential
   takes one label box and one value box, with no dropdown of field names anywhere in the flow.
4. *(UI-observable — proven in Phase 6's exit gate)* Lite mode's search bar offers exactly one
   action.
5. *(UI-observable — proven in Phase 6's exit gate)* Hovering any node shows exactly two
   numbers (`09_UI_UX_SPEC.md §4`, D-06 above).
6. ~~All 185 V1 credentials are in V2, each in a node, with V1 still intact and reversible.~~
   **Corrected, `built`, demonstrated:** A fresh V2 vault, created and populated only through
   its own CLI/MCP/broker (never imported), places every credential in exactly one node, and
   nothing is reachable from a node that did not create or receive a grant for it. V1's 185
   credentials stay in V1, untouched, exactly as `11_MIGRATION.md` specifies — there is no
   migration to demonstrate. Proven by
   `success_criterion_6_fresh_credentials_land_in_exactly_one_node_and_nothing_leaks_by_default`.
7. *(UI-observable — proven in Phase 6's exit gate)* The graph renders, with correct counts,
   while the vault is locked. The backend half — `graph.snapshot` returning correct counts
   while locked — is `built` and tested (`ADR-047`); this criterion's UI half is what Phase 6
   adds.

---

## 8. Connections

| Direction | Document | What flows across |
|---|---|---|
| feeds | `00_README_START_HERE.md §7` | the node-as-boundary model this document states in one sentence, that index's own summary of it |
| feeds | `02_ARCHITECTURE.md §1` | the node-as-boundary model whose single enforcement point (the broker) that document makes real |
| depends on | `06_ACCESS_GRAPH.md §1` | the R0–R8 resolution rules that make §2's inheritance, sibling-sharing and grant promises enforced, not advisory |
| depends on | `06_ACCESS_GRAPH.md §9` | the seal/restore mechanism §2.1 describes as `built`, and the day-7 destruction gap it names |
| depends on | `06_ACCESS_GRAPH.md §10.3` | the native-presence resolver branch §2.2 designs at the concept level and cites for the exact mechanism |
| depends on | `04_CRYPTO_AND_KEYS.md §5.1` | why restore is a move from a retained key, not an unseal, the fact §2.1 states |
| depends on | `04_CRYPTO_AND_KEYS.md §5.2` | the orphan cold-key wrap formula §2.2's target design cites rather than repeats |
| depends on | `03_DATA_MODEL.md §4` | the `Note` type and storage shape §3's target design is built from |
| depends on | `03_DATA_MODEL.md §6` | the `Grant` type's `direction` and grantable-scope fields D-04/D-05 and §2's fourth promise depend on |
| depends on | `05_THREAT_MODEL.md §5` | the precise claim about what scope resolution stops and where it stops, that §4 restates |
| depends on | `18_ENDPOINT_INDEX.md §1.2` | the `notes.read`/`notes.write` op names §3 designs against, and their `built` status (`ADR-072`) |
| feeds | `12_BUILD_PLAN.md §9` | the success-criteria split — 1/2/6 to Phase 7, 3/4/5/7 to Phase 6 — that document's own Connections table names as depending on this one |
| depends on | `14_DECISIONS.md` | `ADR-004` (depth cap), `ADR-005` (upward read), `ADR-006` (sibling sharing), `ADR-007` (seal not delete), `ADR-011`/`ADR-012` (field schemas deleted, inference), `ADR-023` (no `write` capability), `ADR-053` (restore resolves against the sealed node), `ADR-057` (Tauri bridge presence custody), `ADR-058`/`ADR-059`/`ADR-060` (this document's own header, vocabulary and figure-artifact contract) |

## 9. Source

**Design.** `ADR-004`, `ADR-005`, `ADR-006`, `ADR-007`, `ADR-011`, `ADR-012`, `ADR-023`,
`ADR-053`, `ADR-057`, `ADR-072` for the decisions this document states; `ADR-058`/`ADR-059`/`ADR-060` for
the header, status-vocabulary and figure-artifact contract this rewrite applies.

**Code.** `crates/core/src/registry.rs` — the `Capability` enum (seven variants, no `write`,
lines 145–153), `Node`/`NodeKind`, and the depth-cap check. `crates/core/src/access.rs` — rule
`resolve`, R0's native-plus-presence exception. `crates/brokerd/src/ops.rs` — `presence_attested`
hardcoded `false` at lines 91, 124, 314; `grant.create`'s unconditional `PresenceRequired` at
lines 2513–2570; the five presence-gated ops (`audit.get`, `totp.seed`, `node.reparent`,
`grant.create`, `maintenance.doctor --rebuild-registry`), and the `notes.read`/`notes.write` arms
(`ADR-072`). `crates/store/src/paths.rs` and `manifest.rs` — the `notes.env` path and
`notesSha256` slot, reserved until `ADR-072` and used since.
`apps/desktop/src-tauri/src/session.rs` — the Tauri bridge deriving `Origin::Agent` from cwd,
never `Origin::Native`.

**Tests.** `cargo test --workspace -- --list` lists 813 tests in 50 test binaries (2026-10-03); the last full run recorded is 571 passing, 0 failing, 41 test binaries, exit 0 (2026-10-02; earlier: 448 passing, 37 test binaries on 2026-09-24, re-measured 2026-10-01; 406 passing as of 2026-09-13, run 34743281942; 397 passing,
verified 2026-08-18).
`crates/brokerd/tests/isolation.rs::i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone`
and `::i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node`.
`crates/cli/tests/success_criteria.rs` — criteria 1, 2 and 6, against the real compiled binary.
`crates/store/src/backup.rs::never_includes_the_se_wrap_the_socket_the_audit_log_or_notes`.

**Verification.** `python3 -m tools.corpus_check` (`endpoints`, `crossrefs`, `stamps`);
`tools/docgen/tests/` (52 tests as of 2026-09-24).
