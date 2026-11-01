---
id: V2-003
classification: public
title: Data model
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21). The previous stamp (Approved With Known Risks @ d15a5c7,
     2026-08-04) attests a body this rewrite replaces, and had already drifted before it.
     Every type, field, file path and default below was re-read from v2/crates/** this pass.
     Eight claims that live source contradicts were corrected — listed in the Status note
     below — and two of them are exposure-relevant (the per-entry digest in §8, the
     unimplemented retention in §9). Those two are named as open items rather than quietly
     fixed in prose, because the operator, not this session, decides whether they are
     acceptable. Re-hardening is theirs to stamp after that review.

     Updated 2026-08-18, same day: a verification pass over this rewrite found four more
     source-contradicted claims and two ADR-059 present-tense violations that survived the
     rewrite above, all re-derived from live source and fixed in place — the §8 concurrency
     claim narrowed to the five ops that actually carry `params.generation`; §2's I-19/I-20
     citation corrected (I-19 tests the manifest, not the registry); two `05_THREAT_MODEL.md`
     citations corrected from §6 (out of scope) to §7 (accepted risks, AR-1); the freshness
     counter's `16_CROSS_PLATFORM.md` citation corrected from §4.3 (Windows) to §4.4 (Linux,
     the actual no-TPM file fallback); §5's entry/field-type consumers and §1's
     `lockAfterSeconds: ... 300` comment reworded out of the present tense, since none of
     those consumers or that default exist yet. Still NEEDS RE-HARDENING — this pass corrects
     the document, it does not re-approve it.

     Round-2 verification pass, 2026-08-19: three findings from
     `VERIFICATION_BACKLOG_S21_ROUND2.md` fixed after re-deriving each from live source.
     (1) §8's concurrency paragraph grouped `node.create` and `grant.revoke` with `entry.create`
     and `node.seal` as all protected by the per-node `state.rs::node_write_lock` — false for the
     first two. Neither `node.create` (`ops.rs`'s `"node.create"` arm) nor `grant.revoke`
     (`state.rs::revoke_grant`) ever calls `node_write_lock` or touches a manifest at all; each is
     a registry-only mutation serialised by the separate `state.rs::registry: RwLock<Registry>`,
     taken as `state.registry.write()`. Only `entry.create` (`ops.rs:1211`) and `node.seal`
     (`ops.rs:2225-2226`, for both the target node and `orphan`) actually take `node_write_lock`.
     The paragraph now splits the four ops by which lock actually serialises them. (2) The same
     paragraph said I-25 "drives two concurrent writers" — the live test
     (`isolation.rs::i25_concurrent_writers_same_starting_generation_exactly_one_wins`) declares
     `const WRITERS: usize = 16` and asserts one success against `WRITERS - 1` conflicts: sixteen
     writers, not two. (3) §7's pending-tray sentence cited this document's own §8 (Manifest — HMAC,
     cross-binding, concurrency token; no mention of the word "pending" anywhere in it) and
     `06_ACCESS_GRAPH.md §1` (the rule-precedence table; no pending-tray content either). The
     pending-tray behaviour actually lives in this document's own §3 ("`entry.create` enforces it
     against both the accepted manifest and the pending tray") and in `06_ACCESS_GRAPH.md §3`
     ("Capabilities" table: "`create` ... gates `entry.create`, which works while locked and
     lands in the pending tray") — both citations corrected from §8/§1 to §3/§3. All three fixes
     replace the wrong claim with the ultimate-destination-correct one; none required touching
     any other section. Still NEEDS RE-HARDENING — this pass corrects the document, it does not
     re-approve it. Updated 2026-09-24 for ADR-062…066 (settable workdirs, the persisted
     `gate.twofa`, the previous signed registry pair, refs continuing across a restart).
     Updated 2026-09-24 for ADR-071…073 (notes built, §4; policy writable by `node.policy` and
     nodes renameable by `node.update`, §1; `entry.create_batch`, §3). Updated 2026-10-03 for ADR-078/079:
     §3 rewritten — an entry is a field document sealed as envelope version 2, legacy values are read in
     place; §5 the overrides and the `note` type; §7 the version table; §8 `hasTotp`, the single recount and the
     ten generation-guarded ops; §2 and §4 for the seal records now living in the signed registry. -->
# Data model

`CredMgr V2` · the five things a vault contains, what each is encrypted under, and what is deliberately left in the clear · `2026-08-18`

> **Status.** The storage layer is **built and covered by tests**: the node registry, the
> per-node manifest, the `CMV2` envelope (versions 1 and 2), the hash-chained audit log and the entry
> lifecycle all exist in `v2/crates/store/` and `v2/crates/core/`, and the broker writes them
> (`cargo test --workspace -- --list` lists 813 tests in 50 test binaries on 2026-10-03; the last full run
> recorded is 571 passing, 0 failing, 41 binaries, 2026-10-02; earlier 448 passing as of 2026-09-24, 406 as of
> 2026-09-13 and 397 on 2026-08-18). **Multi-field entries are built** (§3, ADR-078): an entry's plaintext
> is a canonical-JSON field document sealed as envelope version 2, and entries written by `2.0.0-alpha.6`
> (version 1, one raw value) are read in place, with no migration. One part is **not** built and is written
> below as target design only: **audit retention** (§9) is specified at 12 months with nothing implementing
> it. (**Notes**, §4, were a third until 2026-09-24 — a reserved file path and an always-`null` manifest
> slot; they are built, ADR-072.) Two
> further gaps are corrections this pass found rather than design: the per-entry `sha256` in
> the manifest was a digest of the **plaintext value** and is compared by nothing (§8 — the
> digest half closed 2026-09-24, ADR-067: it now digests the sealed envelope), and
> the freshness counter lives in a signed file, not in a hardware keystore (§2).

Five entity types. Nothing else exists in the vault.

```
Node ──owns──► Entry ──contains──► Field
  │                                  ▲
  ├──owns──► Note                    │ (a TOTP item is an Entry
  └──owns──► TotpItem ───────────────┘  whose primary field type is totp-seed)

Grant ──connects──► (Node|Entry) → Node
```

`TotpItem` is not a sixth type and never was: a stored TOTP seed is an `Entry` whose primary
field is typed `totp-seed`, which is exactly how `totp.code` reads one today — it decrypts an
ordinary entry envelope and derives a code from the plaintext (`crates/brokerd/src/ops.rs`,
`totp.code`). A dedicated `totp/<nodeId>/<itemId>.env` path is reserved in
`crates/store/src/paths.rs` and is written by nothing; it exists so a future per-item store
does not have to renegotiate the layout.

**What exists today, by section:**

| § | Entity | Status | Evidence |
|---|---|---|---|
| 1 | Node | `partial` | type + invariants in `crates/core/src/registry.rs`; policy writable by `node.policy` and the label by `node.update` (ADR-071), a widening patch refused for want of presence; `privateNames` is stored and read by nothing; per-node 2FA policy is display-only |
| 2 | Node registry | `built` | `crates/store/src/registry_file.rs`; rollback refused by I-20 |
| 3 | Entry | `built` | `entry.create/create_batch/get/update/reveal/rotate/remove/restore/undo` and `field.add/update/remove/reorder` dispatch; a field document sealed as envelope version 2, legacy version-1 values read in place (ADR-078); `crates/core/src/fields.rs`, `field_doc.rs` (P-13…P-18), `field_model.rs` |
| 4 | Note | `built` | `notes.read`/`notes.write` (ADR-072): sealed at `nodes/<id>/notes.env`, bound to `notesSha256`, gated on `notes`; `durable_vault.rs::a_note_is_sealed_capability_gated_digest_bound_and_survives_a_restart` |
| 5 | Types | `built` | `crates/core/src/inference.rs`; P-11 proves inference never mutates a value; the user's overrides are stored in the document (ADR-078) |
| 6 | Grant | `partial` | type, validation, `grant.list`/`grant.revoke` built; `grant.create` refuses for want of presence |
| 7 | On-disk envelope | `built` | `crates/core/src/envelope.rs`; P-1…P-5, P-16 (versions 1 and 2) |
| 8 | Manifest | `built` | HMAC + cross-binding (I-19), the per-entry envelope digest (ADR-067) and `hasTotp` (ADR-078); `alpha6_golden.rs` pins the byte shape |
| 9 | Audit log | `partial` | hash chain + tip sidecar + redaction built; retention and purge unbuilt |

**The eight corrections this rewrite made against source**, recorded rather than silently
applied, because each was believed for months: on-disk timestamps are Unix epoch seconds and
not ISO strings (§1, ADR-040); the node invariants are unit-tested, not property-tested (§1);
the freshness counter is a signed file outside the vault, not a Keychain item (§2); there is
no `deletedRefs` ledger (§3); the migration section reference this document carried pointed
at a section that does not exist in a document that numbers no sections, and asserted a
migration that was cancelled (§3); a grant's `expiresAt` is epoch seconds (§6); the manifest's
per-entry `sha256` digested the plaintext value and nothing ever checks it (§8; the digest is of
the sealed envelope since ADR-067); and the
12-month retention is specified but unimplemented (§9).

---

## 1. Node

**`partial`.** The type, its invariants and the invariant checker are built in
`crates/core/src/registry.rs`; `node.create` enforces the depth cap for real
(`crates/brokerd/src/ops.rs`). Four of the six policy fields are fully enforced, one is
display-only, and one is inert — the table at the end of this section says which is which.
Since 2026-09-24 all six are writable by `node.policy`, a partial patch with a mandatory reason
(ADR-071, `06_ACCESS_GRAPH.md §10.1`), except that a patch widening `siblingVisibility` or
`descendantRead` answers `presence_required` and applies nothing; `node.update` renames a node
(its `label`) and never touches its id.

A node is the **boundary**. Everything else in this corpus follows from that: keys are
per-node (`04_CRYPTO_AND_KEYS.md §2`), access resolution is a question about nodes
(`06_ACCESS_GRAPH.md §1`), and an envelope is bound to the node it belongs to (§7).

```ts
type Node = {
  id: string;              // "global" | "orphan" | "n_" + 8 hex. Immutable forever.
  label: string;           // display name. Renameable (node.update). Never an identifier.
  kind: 'global' | 'project' | 'sub' | 'orphan';
  depth: 0 | 1 | 2;
  parentId: string | null; // null for global and orphan only
  created: number;         // Unix epoch seconds (ADR-040) — NOT an ISO string
  workdirs: string[];      // absolute paths that auto-scope an agent to this node
  publicKey: string;       // hex X25519 public half (04 §2) — the private half never lands here
  policy: {
    siblingVisibility: 'shared' | 'isolated';  // applies to this node's CHILDREN
    descendantRead: boolean;                   // may this node read its own children?
    requireTwoFactor: 'never' | 'reveal' | 'always';
    lockAfterSeconds: number | null;           // NODE-level idle lock (ADR-030).
                                               // null = never (today's default); vault lock
                                               // still applies regardless. ADR-033's auto-
                                               // hardening proposal (planned, below) will
                                               // SUGGEST 300 on a node holding a `critical`
                                               // entry — nothing sets it automatically today.
    privateNames: boolean;                     // ADR-029. true ⇒ this node's manifest stores
                                               // counts + opaque ids only; entry names are
                                               // encrypted, absent from locked search, and
                                               // render as •••• until unlock.
    agentAccess: 'read-write' | 'read-only' | 'none';
  };
  gate: { twofa: TwoFactorEnrolment | null };
  pinned: { x: number; y: number } | null;     // graph position
};
```

**The type is deliberately split across two crates, and both halves are one definition.**
`credmgr_core::registry::Node` carries exactly the fields `access::resolve` and the invariant
checker consume — id, label, kind, depth, parentId, workdirs, policy. `crates/store`'s
`NodeDoc` `#[serde(flatten)]`s that type in and adds the persistence-only fields — `created`,
`gate`, `pinned`, `publicKey`. There is no mirrored DTO: the type `resolve()` reasons about is
the type that round-trips through the registry file, which is why a field cannot drift between
"what the rules see" and "what is stored".

**`gate.twofa` is populated — `built` since 2026-09-24 (ADR-064).** It was an empty slot no code
wrote until the vault became durable; it now persists a **confirmed** 2FA gate on the scope's own
node — `global` for the vault gate, the only scope that exists (per-node gates are `planned`,
`07_TWO_FACTOR.md §3`). Its shape is `{ v: 1, confirmed, secret, recoveryHashes, lastCounter }`:
`secret` is the TOTP seed sealed with ChaCha20-Poly1305 under
`HKDF(RK, "credmgr/v2/gate-secret/<scope>")`, so reading the registry does not reveal it;
`recoveryHashes` are the SHA-256 hashes of the ten gate recovery codes, each `null` once burned;
`lastCounter` is the last accepted TOTP step, re-entered at load as a replay floor. The registry's
HMAC is what stops anyone without RK from stripping or altering a gate, and an unreadable gate
document fails the whole load rather than reading as "no gate".

**Invariants**, checked by `validate_registry` in `crates/core/src/registry.rs` and covered by
that module's own unit tests (`valid_registry_has_no_violations`,
`sub_node_under_another_sub_node_is_rejected`, `duplicate_workdir_is_rejected`,
`ancestor_walk_is_strict_and_transitive`):

- `depth === 0` ⟺ `id === 'global'`. Exactly one, cannot be deleted or renamed away.
  (`orphan` is excluded from that count: it is off-tree, and its depth is not meaningful.)
- `kind === 'sub'` ⟹ `depth === 2` ∧ parent's `depth === 1`.
- No node has `depth > 2`. Creating a child of a sub-node is rejected by `node.create` before
  anything is written, with the depth cap named in the error.
- `orphan` is off-tree: no parent, no children, cannot be a grant endpoint, cannot be deleted,
  cannot be renamed. `global` cannot be renamed either (ADR-071); every other node can, by
  `node.update`, and its id never changes.
- `workdirs` entries are absolute, canonicalised, and **globally unique** — one directory maps
  to at most one node, else auto-scoping is ambiguous and the broker must refuse.

**Workdirs are settable — `built` since 2026-09-24 (ADR-066).** Until then `node.create`
hard-coded `workdirs: []` and no op edited a node's list, so in a vault `credmgr init` made no agent
could ever be scoped to a project. Now `node.create` takes an optional `workdirs`, and
`node.set_workdirs {node, workdirs}` replaces a node's list (`[]` clears it). Each path must be
absolute and an existing directory; the broker stores it **canonical** (`/tmp/x` →
`/private/tmp/x` on macOS), because it is matched against the kernel's own resolved cwd of the
calling process and an uncanonical path would never match; `/`, the home directory and every
ancestor of it are refused (review L4 — binding one would scope every agent the user runs);
uniqueness across nodes
is the `validate_registry` invariant above. Setting workdirs is human-only — it needs
`Capability::Admin` on the node, which no agent scope holds, and refuses `Origin::Agent` outright —
because re-pointing a directory re-points every agent launched in it. The change is written through
to disk (ADR-063). CLI: `credmgr node create … --workdir <dir>` and
`credmgr node workdir <id> [<dir>…]`, a relative argument resolved against the caller's own cwd.
Test: `crates/brokerd/tests/durable_vault.rs::a_bound_workdir_scopes_an_agent_to_its_project_and_survives_a_restart`.

The last three are split by design between shape and behaviour. `validate_registry` proves the
shape; the runtime half — that `orphan` cannot be sealed, that a grant cannot name it — is
enforced where those operations live (`node.seal` and `grant.create` both reject the reserved
ids explicitly). A rule that is only a data-shape check cannot stop an operation, and a rule
that is only an operation check cannot stop a hand-edited registry file; both exist because
both failure modes are real.

**Defaults on create** (`NodePolicy::default()`): `siblingVisibility: 'shared'`,
`descendantRead: false`, `requireTwoFactor: 'reveal'`, `lockAfterSeconds: null`,
`privateNames: false`, `agentAccess: 'read-write'`. Global overrides one of them —
`siblingVisibility: 'isolated'`, because the top-level partition *is* the product
(`06_ACCESS_GRAPH.md §1`). The vault-wide idle timer runs at 900 seconds (ADR-030), held
separately from any node's own timer.

**Where each policy field actually bites:**

| Field | Status | Enforced by |
|---|---|---|
| `siblingVisibility` | `built` | `Registry::are_shared_depth2_siblings`, consumed by resolution rule R6 |
| `descendantRead` | `built` | `crates/core/src/access.rs` — the opt-in that lets a parent read its children |
| `agentAccess` | `built` | `crates/brokerd/src/scope.rs::capabilities_for_agent_access` — the capability set an agent gets from a cwd-derived scope |
| `lockAfterSeconds` | `built` | `crates/brokerd/src/state.rs`'s per-node idle sweep; covered by `a_nodes_own_lock_after_seconds_locks_only_that_node_not_the_vault` |
| `requireTwoFactor` | `partial` | read in `graph.snapshot` only, to label a node `none`/`enrolled`/`required`. The vault-wide gate is real (`07_TWO_FACTOR.md §2`); **per-node gates are unwired** — recorded in `crates/brokerd/tests/phase5_gate.rs`'s own scope note |
| `privateNames` | `planned` | stored, defaulted, settable by `node.policy` (ADR-071), and read by nothing. Names are plaintext in every manifest today (§2) |

**`privateNames`, in full, as the finished thing.** When a node sets it, that node's manifest
will store entry ids and counts only; each entry's name will be sealed into the entry envelope
alongside its fields rather than written to the manifest, and the manifest will carry an
opaque per-entry blind index in place of the name. Locked search will skip such a node
entirely rather than return partial results — a search that silently omits a node is worse
than one that says it cannot see it — and the graph will render the node's children as `••••`
with the count still visible, because the count is what makes the locked graph worth drawing.
Turning it on will be a re-write of that node's manifest, not a re-encryption of its entries:
the names move, the ciphertext does not. Turning it off will be refused while the vault is
locked, since the plaintext names cannot be recovered without the node key.

**Automatic hardening proposal (ADR-033) — `planned`.** When an entry containing a
`seed-phrase` or `private-key` field lands in a node, the app will **propose** — never
silently apply — `requireTwoFactor: 'always'`, `lockAfterSeconds: 300`, `privateNames: true`,
`agentAccess: 'read-only'`, as a one-click banner naming each consequence. Nothing implements
this today. Of the two things it needs, the `node.policy` operation exists since 2026-09-24
(ADR-071) — all four values it proposes tighten, so they need only the admin gate, though
`requireTwoFactor` and `privateNames` are both enforced since 2026-10-24 (ADR-085, ADR-083) — and the screen that shows
the banner (`09_UI_UX_SPEC.md`) does not. The
reasoning it encodes stands regardless: a vault that changes its own security policy without
telling you is a vault you stop trusting; a node you set up once and never revisit is the one
that most needs hardening. The proposal resolves both.

**Node ids are caller-supplied today, under a grammar (ADR-079).** `node.create` takes `params.id` and
enforces `[a-z0-9][a-z0-9_-]{0,63}` — an id is joined into file paths (`keys/nodes/<id>.key`, `nodes/<id>/`,
`archive/<id>/`), and before this rule `../x` left the vault and `removed-entries` aliased a node's seal archive
onto the entry archives. `global`, `orphan`, `removed-entries` and `entry-history` are reserved; a collision is
rejected; so is the id of a node whose seal archive still exists. An id that already exists is never refused at
load. This is not the `"n_" + 8 hex` shape this section specifies. The finished operation will mint the id itself
and ignore any caller-supplied one, for the same reason entry ids are already minted broker-side: an id the
caller chooses is an id the caller can collide with, or use as a channel.

---

## 2. The node registry — and the metadata it deliberately leaks

**`built`.** `crates/store/src/registry_file.rs` writes and verifies it; a rolled-back
registry is refused at broker open, proven by isolation test I-20. A tampered registry is
refused too, but not by I-19 — this section previously miscited that test. I-19 hand-edits the
per-node *manifest*, not the registry — see §8,
`i19_tampered_manifest_is_refused_at_broker_open_naming_the_node`. The registry-tamper case is
a store unit test this document did not previously cite: `registry_file.rs`'s own
`tampered_registry_sig_is_refused`. Since 2026-09-24 the live daemon applies both checks at
unlock (ADR-063), keeps the **previous** signed pair beside the current one
(`registry.json.prev`/`registry.sig.prev`) so a write interrupted before the registry landed is
recovered rather than lost, and every successful change is written through to disk.

`<vault>/registry.json` is **unencrypted**, `0600`, HMAC-signed with a key derived from the
root key, with the tag in a sibling `registry.sig`. It holds every node record, every grant,
the vault generation, the per-node manifest bindings §8 describes, and — since ADR-079 — a `format` number
(this build writes 2 and refuses a registry of a higher one with a named error) and `sealed`: one record per
node sealed inside its 7-day window, `{v, the node's own record, sealedAt, manifest binding, nodeKeySha256,
orphanEntryIds}`. The records are in the registry, not in a sidecar beside the archive, because a file with
its own HMAC proves authorship and not freshness: an older record of the same id would verify and reinstate an
older policy, and in the registry it rides the registry's HMAC and the external generation counter. The
archive's files are bound by the record (`04_CRYPTO_AND_KEYS.md §5.1`). An alpha build ignores `sealed` on read and drops it on
its next write, so a vault must not go back below `2.0.0-beta.1`.

**Why unencrypted:** the graph must draw, with correct topology and correct counts, while the
vault is locked — that is a stated product requirement, and it is also the behaviour that
makes locking cheap enough that people actually lock. Encrypting the registry would mean
unlocking to see the shape of your own vault. The same reasoning is why `search` runs against
manifest names (§8) and works locked: it never touches a value.

**What that leaks to anyone who can read the file:** node names, tree shape, grant edges,
entry counts, entry *names* (in per-node manifests), timestamps, and — an addition this pass
found, see §8 — a SHA-256 digest of each entry's plaintext value.
**What it does not leak:** any field label, any value, any note, any TOTP seed.

This is a deliberate, bounded trade. It is defensible because the same attacker already has
the vault directory. It is recorded as an accepted risk in `05_THREAT_MODEL.md §7` rather than
hidden. `registry.sig` means the attacker can *read* the shape but cannot *rewrite* it —
tampering, for instance re-parenting a node to widen access, is detected at broker start and
fails closed with the file named.

**Freshness, not just authorship.** An HMAC proves who wrote a file, never *when*. Restoring a
valid older `registry.json` would silently reinstate a revoked grant or undo a tightened
policy. The registry therefore carries a monotonic `vaultGeneration`, whose current value
lives **outside the vault directory**, so that restoring a copy of the vault does not restore
the counter with it.

**Where that counter actually lives — corrected 2026-08-18.** This section previously said the
value sits "in the macOS Keychain as an owner-only item, mirrored into the SE-wrapped root
blob". It does not, and no code has ever put it there. `crates/store/src/generation.rs`
defines a `GenerationCounter` trait with one shipped implementation,
`FileGenerationCounter`: a `0600` JSON file in a per-user **state** directory —
`CREDMGR_STATE_DIR` if set, else the platform's own state location, always a sibling of the
vault and never inside it — holding the value plus an HMAC over its big-endian bytes under a
`generation-counter/<name>` label. That is `16_CROSS_PLATFORM.md §4.4`'s documented no-TPM
fallback (§4.3 is Windows Hello/DPAPI, not this), generalised to every platform by ADR-039.
A hardware-backed counter is still the target: `crates/keystore` already declares
`read_counter`/`write_counter` on the
`PlatformKeystore` trait so a Secure Enclave or TPM implementation can satisfy it without a
format change — but `crates/keystore/src/` contains exactly one backend today
(`software.rs`, Argon2id), so the hardware tier is **`planned`**, not degraded.
A registry whose generation is below the last seen value is refused at broker start with a
named remedy (`04_CRYPTO_AND_KEYS.md §6`, `02_ARCHITECTURE.md §7`).

**On entry names.** Entry names remain in the plaintext manifest. Encrypting them would break
the locked graph and locked search — two features that exist specifically to make locking
cheap enough that it actually happens. The exposure is recorded as `AR-1`; **ADR-029**
resolves it — plaintext by default, with the per-node `privateNames` opt-out for wallet-class
nodes that §1 specifies and nothing yet implements.

<!-- figure:plaintext-boundary -->

*Every path is enumerated in `crates/store/src/paths.rs`. Plaintext, HMAC-signed files
(registry, per-node manifest, audit log + tip, the external generation counter) sit on the
left; everything sealed inside a `CMV2` envelope under a node key (§7) sits on the right —
`notes.env` is written by `notes.write` since ADR-072 (§4); the per-item TOTP path is reserved
but written by nothing.*

---

## 3. Entry

**`built`** (ADR-078). An entry's identity, lifecycle, ciphertext and field list are built —
`entry.create`, `entry.get`, `entry.update`, `entry.reveal`, `entry.rotate`, `entry.remove`,
`entry.restore`, `entry.undo` and the four `field.*` operations are all dispatched by
`crates/brokerd/src/ops.rs` and exercised by `entry_lifecycle.rs`, `entry_undo.rs`, `field_model.rs` and
isolation tests I-18, I-25 and I-27…I-29. What is **not** stored on an entry today is `aliases` (below).

An entry is one credential — one wallet, one server login, one API integration. It is the unit
of grant, rotation, and archive.

```ts
type Entry = {
  id: string;             // "e_" + 12 hex, minted broker-side from the OS RNG
  nodeId: string;
  name: string;           // free text, unique within its node (NOT globally)
  ref: number;            // stable ref, unique vault-wide, never reused
  type: EntryType;        // see §5
  sensitivity: 'low' | 'medium' | 'high' | 'critical';
  fields: Field[];        // ordered; the user's order is preserved verbatim
  created: number; modified: number; rotatedAt: number | null;   // epoch seconds (ADR-040)
  expiresAt: number | null;
  aliases: string[];      // names this entry has answered to before
  sealed: boolean;        // true only while in the orphan node
};

type Field = {
  id: string;             // "f_" + 8 hex
  label: string;          // FREE TEXT. No enum. No schema. Whatever the user typed.
  value: string;          // encrypted at rest as part of the entry envelope
  type: FieldType;        // inferred, user-overridable (§5)
  masked: boolean;        // default derived from type; user-overridable
};
```

**What is built of that shape.** `id`, `nodeId`, `name`, `ref`, `type`, `sensitivity`,
`modified`, `expiresAt` and `rotatedAt` live in the manifest entry
(`crates/store/src/manifest.rs::ManifestEntry`, with `fieldCount` and `hasTotp`, §8) and the broker maintains
them. The **fields** live in the ciphertext, as one document. `aliases` and `sealed` are not stored
anywhere — sealing is a whole-node state held in the signed registry and the archive (ADR-079), not a
per-entry flag.

**The field document (`crates/core/src/fields.rs`).** An entry's plaintext is a canonical JSON document
sealed as a single envelope of **version 2** (§7), not one envelope per field:

```json
{"v":1,"entryType":"server","fields":[
  {"id":"f_1a2b3c4d","label":"host","value":"db.example.com"},
  {"id":"f_5e6f7a8b","label":"password","value":"…","masked":false}]}
```

- `v` is the document schema (always 1; any other value is refused), independent of the envelope version.
- `fields` is ordered, the user's order verbatim, and holds at least one field. An `id` is `f_` plus eight
  lowercase hex digits, minted by the broker and unique within the entry; **`f_00000000` is reserved** for
  a legacy field and never minted. A `label` is free text — empty is allowed, at most 200 characters, no C0
  or DEL control character, any script; there is **no field-count cap, no label vocabulary and no reserved
  label** (ADR-011; `crates/core/tests/no_field_schema.rs` greps `crates/` and `apps/desktop/src*` for the old
  schema names and fails on any). A `value` is verbatim — no trimming (ADR-038).
- `type` and `masked` (per field) and `entryType` and `sensitivity` (per entry) are present **only when the
  user chose one**; absent means "infer now" (ADR-012, §5). No answer inference gave is ever cached in the
  ciphertext, so an edit re-infers everything that is not pinned.
- The encoded document is at most 16 MiB (`ENTRY_DOC_MAX_BYTES`, `08 §3.5`'s "envelope limit", now enforced).
- `decode` is strict: an unknown key, `v` other than 1, no fields, a bad or duplicate id, or a label rule
  violation is refused, and the message names an index or a field id — never a label or a value.

One envelope per entry is what makes the entry the unit of rotation and of the AAD binding in §7;
splitting fields into separate envelopes would make a partial write produce a half-rotated credential,
and would let an attacker who can delete files remove one field from an entry without breaking anything
that checks. **The manifest is the document's plaintext projection** (`fields::project`): entry type,
sensitivity, `fieldCount` and `hasTotp` (§8) — `fieldCount` stays a plaintext count because the count is
graph metadata and the labels are not: a reader who knows an entry has four fields learns nothing, and a
reader who knows one of them is labelled `recovery phrase` learns a great deal. Labels, field types and
values never reach the manifest, the pending-tray sidecar or the audit log. The bulk grammar that produces
the fields (`crates/core/src/parser.rs`, P-7, P-8, P-18) is parsed by the **client**; the broker receives
structure (`08_FIELD_MODEL.md §3`).

**Legacy entries are read in place.** An entry written by `2.0.0-alpha.6` is a version-1 envelope holding
one raw value. It is read as a one-field document — id `f_00000000`, label `""` (the label was never
stored), the value verbatim — with an override pinned **only where inference without the lost label would
disagree with what the manifest already shows**: masking when the stored sensitivity is `high` or above, and
the entry's sensitivity and type. Its projection therefore equals its manifest entry exactly (property
P-15), reading rewrites nothing, and the first write — `entry.update`, `entry.rotate`, any `field.*` —
re-seals the entry as version 2. The kind comes from the authenticated version byte, never from sniffing:
a raw value that happens to read `{"v":1,"fields":[…]}` is one raw field holding that text.

**Name uniqueness is per-node, not global.** Two nodes may both hold `DB_PASSWORD`. This is
the point: names stop being a global namespace, so they stop needing per-project prefixes.
`entry.create` enforces it against both the accepted manifest and the pending tray, so two
creates against a locked vault cannot both succeed and collide later at accept time.

**Refs stay vault-global** so a numeric reference keeps working across the whole vault.
**There is no `deletedRefs` ledger, and there will not be one** — this section previously said
one "continues to guarantee no reuse", carried over from V1, where refs *were* reclaimed and a
ledger was needed to stop collisions. V2's `next_ref()` is a monotonic, vault-global,
non-reclaiming counter, so a reused ref is not a state that can occur and not a state
`maintenance.doctor` can ever find (ADR-048, ADR-054). The counter is **`partial`** in one
respect that matters: it is an in-process atomic seeded at 1000 on broker start, and its
high-water mark is not persisted. Since 2026-09-24 (ADR-063) a vault load continues it past the
highest ref present in any manifest (`crates/brokerd/src/state/durable.rs`), so refs no longer
restart at 1000 across a restart — but a ref whose entry is in no manifest at load can still be
issued again. The finished counter will also persist its high-water mark alongside the registry
and take the maximum of that and the observed maximum, so a lost state file costs monotonicity
from the observed maximum rather than from zero.

**There is no migration, and this document no longer claims one.** The previous text said
"Migration keeps the V1 names as-is and records the short name as an alias
(`11_MIGRATION.md §4`)". That reference was broken twice over: `11_MIGRATION.md` numbers no
sections at all, so `§4` resolves to nothing, and the migration it described was cancelled —
that document's whole content is now the decision that V2 ships empty and imports nothing from
V1. `aliases` survives as a field for a different reason: renaming an entry should not break
the name a script already uses, so a rename will push the old name onto `aliases` and lookup
will fall back to it. ADR-032 ("keep long names, show short") still applies as a *display*
rule for names any user chooses.

---

## 4. Note

**`built`** since 2026-09-24 (ADR-072). `notes.read` and `notes.write` read and write one note
per node, sealed at `nodes/<id>/notes.env` and bound to the manifest's `notesSha256`. Evidence:
`crates/brokerd/tests/durable_vault.rs::a_note_is_sealed_capability_gated_digest_bound_and_survives_a_restart`
and `crates/store/src/verify.rs::tests::a_note_is_checked_against_its_manifest_digest_without_a_key`.
Neither a CLI command nor an MCP tool reaches it yet (`10_API_AND_MCP.md §2`, `§3`) — the ops are
reachable from the broker socket and the desktop bridge.

```ts
type Note = { nodeId: string; markdown: string; modified: number; };
```

One note document per node, encrypted under the node key into `nodes/<id>/notes.env` — the same
envelope format as an entry (§7), with the node id in the AAD and the reserved envelope id
`notes`, never an entry id, so a note envelope cannot be moved into another node and cannot be
swapped with an entry. The sealed payload is `{markdown, modified}` as JSON, `modified` in Unix
epoch seconds. This is the "privacy vault" half of the product: the *why*, not the *what*.

It is scoped identically to entries — an agent that cannot read node A's entries cannot read
node A's note, and inheritance and grants apply the same way, because both ops resolve against
the node through the one access function. The capability is separate rather than implied:
`Capability::Notes` in `crates/core/src/registry.rs` is one of the three scopes `grant.create`
accepts, and both ops require it. A note is therefore reachable only by a caller that holds
`notes` on the node, never as a side-effect of holding `read`.

`notes.read` needs the node's key loaded (a locked vault answers `vault_locked`) and returns
`{markdown: "", modified: null}` when the node has no note. `notes.write` takes the manifest
`generation` for optimistic concurrency (F-9, §8), needs the node unlocked — a note is not a
locked-write tray item — and is capped at 64 KiB; an empty `markdown` removes the note. Each
write bumps the manifest generation and is written through (ADR-063). Sealing a node moves its
note into the archive with the rest of the node folder.

Notes are **never** included in `.env` backups — `store::backup::select_files` leaves
`notes.env` out, and its test says so — and there is no export and no MCP tool to carry one;
when those exist, they will include a note only if the caller explicitly requests `notes` scope
and the node's policy permits it. `notesSha256` holds the digest of the note **ciphertext** —
not of its plaintext, which is the mistake §8 records for entries (ADR-067's rule) — so
`maintenance.verify` detects a truncated, swapped or unrecorded note file without a key
(`credmgr_store::verify::find_note_mismatch`), and `notes.read` refuses a file that does not
match it: an older note restored over the current one is not served.

---

## 5. Types — the categorisation layer

**`built`.** `crates/core/src/inference.rs` implements both axes and is proven never to mutate
the value it classifies (property P-11, `crates/core/tests/properties.rs`). **The user-override half is
built too** (ADR-078): a field's `type` and `masked` and the entry's `entryType` and `sensitivity` are stored
in the field document when — and only when — the user chose one (`field.update` with `"auto"` clears a
pin), and the desktop's type pickers send exactly that.

The brief asks that credentials and data be separated and categorised by type. Two independent
axes do that work.

**Entry type** — what the credential *is*. The broker computes it from the document
(`fields::project` → `infer_entry_type_labelled`) unless the user pinned one, and stores it in the manifest;
it drives the inspector's type badge and the entry count by type. There is no export operation
(`crates/cli/src/main.rs`'s only `export` prints a shell `export CREDMGR_TOKEN=...` login hint, not a data
export).

`server` · `database` · `api` · `wallet` · `login` · `ssh` · `certificate` · `token` ·
`totp` · `env-bundle` · `note` · `other`

`note` is the entry whose single field is free text (ADR-078). It was spelled `note-only` until 2026-10-03 —
a variant no code path ever constructed, so no stored value holds it; `note-only` is still accepted on input.
**Inference rules, first match wins:** *R0* exactly one field, labelled `note` or `notes` → `note`; *R1* a
TOTP-seed field and at most two fields → `totp` (a server that merely carries a 2FA seed stays a `server`,
and the manifest's `hasTotp` flag — not its type — is what puts it in `counts.totp`); *R2* a seed phrase or a
private key → `wallet`; *R3* a certificate → `certificate`; *R4* host, username and a password or API key →
`server`; otherwise `other`. R0 is the one place a label is read at all, and it is a suggestion for the type,
never a rule on the label. The design's richer tree (`login`, `api`, `ssh`) is not adopted; the types stay in
the vocabulary because a user may pin one.

**Field type** — what a single field *contains*. `default_masked` computes the boolean
(`crates/core/src/inference.rs`) and `fields::effective` applies a pin over it; the broker returns
each field's effective `type` and `masked` from `entry.get` and `entry.reveal`, and the desktop masks
accordingly (a field with `masked` shows dots until revealed, one field at a time).

| type | inferred from | masked | notes |
|---|---|---|---|
| `password` | label matches `pass`/`pwd`/`secret` | ✅ | |
| `api-key` | known vendor prefixes, or a `key`/`token`/`api` label | ✅ | partially carries V1's secret-scan prefixes forward and adds new ones (`AKIA`, `AIza`, the `xox` family) — three of V2's six prefixes have no V1 counterpart, and V1's `sk_`/`AGE-SECRET-KEY-`/`ssh-` are not carried over |
| `private-key` | a PEM `PRIVATE KEY` header | ✅ | multi-line preserved byte-exact |
| `seed-phrase` | 12/15/18/21/24 all-lowercase words | ✅ | forces `sensitivity: critical` |
| `totp-seed` | an `otpauth://` URI, or base32 of length 16/26/32 | ✅ | generates codes; counted in the node's TOTP number |
| `username` | an email-shaped value, or a `user` label | ✕ | |
| `host` | hostname or dotted-quad shape | ✕ | |
| `port` | integer 1–65535 | ✕ | |
| `url` | an `http`/`https` scheme | ✕ | |
| `certificate` | a PEM `CERTIFICATE` header | ✕ | |
| `text` | fallback | ✕ | |

**Value first, label second.** `infer_field_type` tests the value's shape before it looks at
the label, so a URL pasted into a field labelled `password` is typed `url`, not `password` —
there is a test named for exactly that case. `default_masked()` derives the masked column
above; `default_sensitivity()` derives an entry's sensitivity from its strongest field type
(`seed-phrase`/`private-key` → `critical`; `password`/`api-key`/`totp-seed`/`certificate` →
`high`; `username`/`host`/`port`/`url` → `medium`; `text` → `low`). Entry type is then
inferred from the set of field types present.

**One inference is deliberately weaker than an earlier draft of the spec, and says so in the
code.** The original design derived `wallet` from a seed-phrase or private-key field **plus an
address-shaped field** — but no `address` field type exists in the table above, so there was
nothing to test that qualifier against. The implementation infers `wallet` from the key or
phrase alone and records the simplification in its own module doc rather than inventing an
address heuristic; `08_FIELD_MODEL.md §6.2` records the same correction. Under-inferring costs
one click; inventing a heuristic costs a wrong type nobody can predict.

**Inference is a suggestion, never a decision** (ADR-012). Every detection surfaces in the
add-entry preview — computed by the shell's own copy of this code, `fields_preview` — with the inferred
type visible and a picker to change it; nothing is silently retyped, nothing is rejected for failing to match
a type, and a type the user did not pick is **not stored** (it is re-inferred on every read). This is the exact opposite of V1's
`TYPE_SCHEMAS`, which told the user what fields a wallet is *allowed* to have, and which
ADR-011 deleted outright.

---

## 6. Grant

**`partial`.** The type, every validation rule below, `grant.list` and `grant.revoke` are
built and covered by `crates/brokerd/tests/grant_ops.rs` and isolation tests I-5, I-6 and I-7.
**`grant.create` validates in full and then refuses**, because creating a grant requires a
presence attestation and no transport in this build can produce one — the same honest gap
`node.reparent` and `audit.get` carry.

```ts
type Grant = {
  id: string;                     // "g_" + 8 hex
  from: string;                   // nodeId that RECEIVES access
  to:   { kind: 'node'; nodeId: string }
      | { kind: 'entry'; nodeId: string; entryId: string };
  direction: 'one-way' | 'mutual';
  scope: ('read' | 'reveal' | 'notes')[];   // read = list+metadata, reveal = values
  createdAt: number; createdBy: 'human';    // epoch seconds; 'human' is the only legal value
  expiresAt: number | null;                 // epoch seconds (ADR-040), NOT an ISO string
  reason: string;                 // required, min 8 chars — a grant without a reason is a leak waiting to be forgotten
  lastUsedAt: number | null;      // drives the stale-grant sweep
};
```

- `createdBy` is typed as the literal `'human'` because **no code path may create a grant**.
  Not the CLI with a flag, not an MCP tool, not an import. `crates/store`'s `CreatedByHuman`
  is a one-inhabitant enum for exactly that reason: an agent-created grant is a type error,
  not merely a runtime check.
- `scope` is narrowed at the operation, not only in the type. `crates/core`'s `Capability`
  enum has seven members — `list`, `read`, `reveal`, `create`, `update`, `notes`, `admin` —
  because resolution needs all seven; `grant.create` rejects any requested scope containing
  anything but `read`, `reveal` or `notes`, and rejects an empty scope. `create`, `update` and
  `admin` are therefore not grantable across a boundary by construction.
- `reason` is mandatory and validated at 8 characters minimum. Six months from now the only
  question that matters about a dashed line is *why*, and nobody remembers.
- A grant to `orphan` is rejected. A grant *from* `orphan` is rejected. Both are checked
  before any capability check, so the refusal does not depend on who is asking.
- `direction: 'mutual'` is enforced in `access::resolve` as if a mirror one-way grant existed
  with the endpoints swapped — the reading consistent with grants being human-drawn, symmetric
  edges on the graph (`06_ACCESS_GRAPH.md §1c`).

**What `grant.create` will do when presence exists.** Every check above already runs, in
order, against the live registry; the operation then returns `presence_required` rather than
writing. When the native shell can attest presence (`16_CROSS_PLATFORM.md §3`), the same arm
will mint the id, stamp `createdAt`, set `createdBy: 'human'`, append the grant to the
registry and write it under the same signature as everything else — no new validation, no new
gate. `lastUsedAt` will be stamped by `resolve()` on each allow that a grant was the deciding
rule for, which is what makes the stale-grant sweep in `06_ACCESS_GRAPH.md §6` possible;
nothing writes it today.

---

## 7. On-disk envelope

**`built`.** `crates/core/src/envelope.rs`, with five property tests behind it: P-1 (seal/open
round-trips), P-2 (a different node's key never opens it), P-3 (a wrong asserted node id
fails), P-4 (a wrong asserted entry id fails), P-5 (sealing is non-deterministic).

Every encrypted file (`*.env`) is one envelope. The format is versioned from byte zero so a
future algorithm change is a migration, not a guess.

```
magic      "CMV2"                        4 bytes
version    uint8                         1 byte   (1 = the plaintext is one raw value;
                                                   2 = the plaintext is a field document, §3)
suite      uint8                         1 byte   (1 = X25519-HKDF-SHA512-ChaCha20Poly1305)
nodeId     16 bytes                      the owning node, zero-padded UTF-8, in cleartext
epk        32 bytes                      ephemeral X25519 public key
nonce      12 bytes
ciphertext var
tag        16 bytes
```

The AAD covers `magic ‖ version ‖ suite ‖ nodeId ‖ entryId`. Binding the envelope to its node
and entry id means a stolen envelope cannot be moved into another node's directory to be read
under that node's key, and cannot be swapped with a sibling entry.

**The version byte is the payload discriminator (ADR-078).** Version 1 and version 2 share the suite, the
key derivation, the header layout, the nonce and the tag; they differ in that one byte. Because the
byte is inside the AAD, **the payload kind is authenticated**: flipping a version-2 envelope's byte to 1 (or
the reverse) fails the tag, so a field document can never be served as a raw value, nor a raw value parsed as
a document (P-16, I-29). Nothing sniffs the plaintext and nothing in the manifest says which kind an entry
is. `envelope::open` accepts version 1 only and refuses a version-2 envelope with `UnsupportedVersion(2)` (an
alpha build does exactly that); `open_any` reports which kind it opened. A node's note (`notes.env`,
§4) stays version 1.

**Which `nodeId` the AAD uses, resolved.** The line above does not by itself say whether that
`nodeId` is the header field as written or the caller's asserted context. The implementation
uses the **caller's asserted** node and entry ids — the values the storage layer derives from
*where the file lives* — for the header field at seal time and for the AAD at both seal and
open time. That is the only reading under which relocating an envelope is guaranteed to fail:
the ECDH already uses a different node key, and the AAD the receiver reconstructs from its own
path-derived context now disagrees with the AAD that authenticated the ciphertext. The header
field is then a redundant, unauthenticated hint — "which key do I need, without decrypting".
A stored value that disagrees with the caller's asserted id is rejected before
the AEAD call for a clearer error, but the tag is what enforces it.

The entry key is `HKDF-SHA512(ikm = ECDH shared, salt = ephemeral.pub ‖ node.pub,
info = "credmgr/v2/entry", len = 32)`, per `04_CRYPTO_AND_KEYS.md §3`. Sealing needs only the
node's **public** key, which is why `entry.create` works while the vault is locked and lands
in the pending tray (§3, and `06_ACCESS_GRAPH.md §3`).

---

## 8. Manifest

**`partial`.** The manifest, its HMAC, and the registry cross-binding are built
(`crates/store/src/manifest.rs`); a tampered manifest is refused at broker open with the node
named (isolation test I-19), and the optimistic-concurrency token is real (I-25). Two fields
are not what this document previously claimed: `notesSha256` was always `null` because notes did
not exist (§4; since ADR-072 it holds the note ciphertext's digest whenever a node has a note),
and the per-entry `sha256` is not what it appears to be (below — since ADR-067 a
digest of the sealed envelope, which `maintenance.verify` checks without a key).

`nodes/<id>/manifest.json` — unencrypted, `0600`:

```json
{
  "nodeId": "n_1a2b3c4d",
  "entries": [
    { "id": "e_...", "name": "vps-root", "ref": 3060, "type": "server",
      "sensitivity": "critical", "fieldCount": 4, "hasTotp": true, "sha256": "...",
      "modified": 1785000000, "expiresAt": null, "rotatedAt": null }
  ],
  "counts": { "entries": 12, "totp": 3 },
  "notesSha256": null,
  "generation": 41,
  "hmac": "..."
}
```

Every `hmac`/tag field in this document — the manifest's, the registry's, the generation
counter's — is stored as **lowercase hex text**, not base64 or raw bytes
(`crates/store/src/hexutil.rs`, a ten-line codec chosen so these fields stay readable without
pulling in a full `hex` crate dependency).

`hasTotp` is written **only when true** (`#[serde(default, skip_serializing_if = "is_false")]`). That is
load-bearing: every signed store document — the manifest, a rotation snapshot, a removal archive — is
verified by re-serialising the parsed struct, so a field that serialised its default would change the
bytes of everything written before it and make every existing vault fail its HMAC at unlock.
`crates/store/tests/alpha6_golden.rs` pins the alpha.6 byte shape and loads signed documents built from it.
The flip side is the downgrade rule: an alpha build drops a `hasTotp: true` key when it re-serialises and
reports the vault as tampered (`RELEASE.md`). `counts.totp` counts entries typed `totp` **or** carrying a
TOTP-seed field, recomputed by one `ManifestBody::recount()` used by insert, update and remove — before it
existed a rotate that turned a value into a seed left the count stale. `hasTotp` tells a reader of the
plaintext manifest which entries hold a 2FA seed, the same fact `counts.totp` and the `totp` type already
tell per node and per entry.

`counts` is what the graph hover reads — which is why the two numbers are available while
locked (isolation test I-14 proves a locked vault still lists topology). `rotatedAt` is
distinct from `modified` on purpose: any mutating operation bumps `modified`, while
`rotatedAt` is set only by `entry.rotate`, so the UI can show "last rotated" separately from
"last edited" (ADR-048).

**The manifest is signed.** `hmac` is
`HMAC-SHA256(HKDF(RK, "manifest-hmac/" + nodeId), <the manifest without this field>)` — and
"without this field" is structural rather than conventional: `ManifestBody` is its own type, so
signing operates on a value that cannot contain the tag being computed. `registry.json`
records every node's `(generation, hmac)` pair. An unsigned manifest would let an attacker
delete an entry from the index (hiding a credential while its envelope sits on disk), inflate
a count, or repoint an entry id at a different envelope. Cross-binding registry ↔ manifest
means neither can be rolled back to an older validly-signed version of itself without
contradicting the other.

**Concurrency.** `generation` is also the optimistic-concurrency token, but the check is
narrower than "every mutating request": exactly ten ops read `params["generation"]` and can
return `conflict` — `entry.update`, `entry.rotate`, `entry.remove`, `entry.restore` and
`entry.undo`, since 2026-09-24 `notes.write` (ADR-072, §4), and since 2026-10-03 the four `field.*`
operations (ADR-078). (A list of line numbers was kept here until the lines moved; the arms are the
authority.) `entry.create` bumps
the manifest's `generation` on write but takes no `params.generation` at all, so it cannot return
`conflict` — nor can `entry.create_batch`, which runs each item through `entry.create`
(ADR-073); the same is true of `node.seal`, `node.create` and `grant.revoke` — none of them is
guarded by this token. **Two different mechanisms cover those, split by what each actually
touches.** `entry.create` and `node.seal` rewrite a node's manifest, and both take the broker's
exclusive in-process write lock per node (`state.rs::node_write_lock`, taken by `entry.create`
itself at `ops.rs:1211`, and by `node.seal` at `ops.rs:2225-2226` for both the target node and
`orphan`), so the CLI, the UI and several MCP servers can never interleave a manifest rewrite on
that node regardless of which ops carry the generation token. `node.create` and `grant.revoke`
never touch a manifest at all — each is a registry-only mutation (a new node record; a grant
removed from the grant list) — and both are serialised instead by `state.rs`'s
`registry: RwLock<Registry>`, taken directly as `state.registry.write()`
(`ops.rs`'s `"node.create"` arm; `state.rs::revoke_grant`, called from the `"grant.revoke"`
arm) — a different lock over a different data structure, never `node_write_lock`. Reads are
never blocked. I-25 drives sixteen concurrent writers of the token-guarded family from the same
starting generation and asserts exactly one wins.

**Closed 2026-09-24 by ADR-067 — the per-entry `sha256` now digests the sealed envelope, and
`maintenance.verify` checks it.** Since `2.0.0-alpha.6`, `entry.create`, `entry.update` and `entry.rotate` write
the SHA-256 of the exact bytes they seal into `entries/<id>.env` (or `pending/<id>.env`), so the
field reveals nothing the envelope file beside it does not, and `maintenance.verify` checks it by
hashing the file, with no key (`credmgr_store::verify::find_digest_mismatches`; a mismatch is an
error). Tests:
`durable_vault.rs::g12_no_file_in_the_vault_carries_a_digest_of_a_stored_value`. The record below
is the open item as it stood, kept rather than rewritten.

**Open item (as of 2026-08-18) — the per-entry `sha256` is a digest of the plaintext value, and
nothing checks it.** This document previously said "`sha256` per entry + `generation` give tamper detection
and let `credmgr verify` run without unlocking anything." Both halves are wrong as built.
`entry.create`, `entry.update` and `entry.rotate` each compute `sha256_hex(value.as_bytes())`
over the **plaintext**, and that hex digest is written into the unencrypted manifest. It is
copied on restore and undo and **compared to nothing, anywhere** — `maintenance.verify`'s
integrity story is the manifest HMAC, the registry cross-binding, the generation counter, and
a dangling/missing envelope reconciliation that works from file *names* only
(`crates/store/src/verify.rs`). Two consequences, stated rather than smoothed over:

1. **It is an exposure, not merely a dead field.** An attacker with the vault directory can test
   candidate values against the digest offline. For a high-entropy secret that is worthless;
   for a short passphrase, a PIN, or any value drawn from a guessable set, it is a confirmed
   answer. §2's "what it does not leak: any value" is therefore too strong as written, which
   is why this section corrects it rather than the summary quietly dropping the line.
2. **The fix is small and is not this document's to make.** The finished field should digest
   the **envelope bytes**, not the plaintext — that is what makes it verifiable without a key,
   which was the stated purpose, and it removes the oracle at the same time. Recording it here
   as an open item for the operator; changing what a shipped field means is a code change with
   an ADR behind it, not a documentation edit.

---

## 9. Audit log

**`partial`.** The log, its hash chain, the signed tip sidecar, and the redacted agent feed
are built (`crates/store/src/audit.rs`, `audit.tail`, `audit.get`, and
`crates/brokerd/tests/audit_ops.rs`). **Retention and purge are `planned`** — no code deletes
or rotates an old log, and no broker operation purges one.

`audit/YYYY-MM.log`, append-only, `0600`, one JSON object per line, **hash-chained**: each
record carries `prev` = SHA-256 of the previous line's raw bytes, with a fixed 64-hex genesis
value for the first record of a chain. Truncation or edit is detectable.

**The chain alone cannot catch a truncated tail**, so it is not the only mechanism. Removing
or editing any line but the last changes the hash the *next* line's `prev` must equal, which
the chain walk catches by itself. Catching removal of the *final* lines needs an anchor
outside the file: an HMAC'd `<year-month>.tip` sidecar recording the expected line count and
final hash, re-signed on every append. That is the same "unencrypted must not mean
unprotected" pattern the registry/manifest pair uses (`04_CRYPTO_AND_KEYS.md §6`), and it has
its own test, `truncating_the_tail_is_caught_by_the_tip`. The detection has one limit: `append`
re-signs the tip over the log as it stands without verifying it first, so a truncation is caught only
until the next request lands (accepted risk K-9, `PHASE8_AUDIT_REPORT.md §4`).

A record is `{id, timestamp, actor, action, nodeId, entryId, decision, detail, generation,
prev}`. **Recorded:** every access decision, allow **and** deny, written from one call site in
`crates/brokerd/src/server.rs` rather than from each dispatch arm — which is why a newly added
operation is logged without anyone remembering to log it. That covers unlock/lock, 2FA
challenge results, grant lifecycle, node create/seal/restore/reparent, and every entry
mutation. **Never recorded:** any value, any field label, any note content. A record names the
entry and the decision, never the secret.

**Two honest bounds on "every decision".** Logging is best-effort by design: it needs the
broker to re-derive the root key, and a failure to log must never turn into a second denial of
a request the access graph already decided — so a decision taken in a state where the key
cannot be re-derived is answered, not logged. And `audit.tail` filters records by the caller's
own reachable set before returning them, so "the log records everything" and "a caller can see
everything in the log" are different statements; only the second is scoped.

**Redaction is by origin, not by request.** An agent-origin caller receives
`{id, timestamp, actor, action}` and nothing else — no node, no decision, no detail, no entry.
A human-origin caller receives the full record. `audit.get`, the single-record unredacted
read, requires presence and is therefore refused on every transport this build has, exactly
like `grant.create` (§6).

**Retention — `planned`, and this document is the authority for the number.** Logs will be
rotated monthly (the file name already is the rotation) and **kept 12 months**, after which a
month's log and its tip sidecar will be deleted together — deleting one without the other
would leave an unverifiable file that looks tampered. Purge will be **human-only**:
`credmgr audit --purge`, 2FA-gated, never reachable from an agent. `audit.purge` appears in
this build only on the forbidden-tool list that test I-13 enumerates
(`crates/mcp/src/tools.rs`), which is the correct state for an operation that does not exist
yet: named as forbidden before it is named as available.

**The 12-month figure is not the 7-day figure**, and the corpus has conflated them. Seven days
is the soft-delete recovery window — `RECOVERY_WINDOW_SECONDS` in both
`crates/store/src/archive.rs` (a sealed node) and `crates/store/src/entry_archive.rs` (a
removed entry), after which the archived copy is destroyed (ADR-027, ADR-048; isolation test
I-21 proves day 6 restores byte-identically and day 8 is gone). Twelve months is how long the
record *that a thing happened* is kept. They answer different questions and neither bounds the
other: an entry removed today is unrecoverable in eight days, and the audit line saying it was
removed will still be there next August.

<!-- figure:rollback-defence -->

*No single file defends against rollback. `BrokerState::verify_and_load_vault` checks the
registry's signature, the external generation counter, and each node's manifest signature
plus its cross-binding to the registry — in that order — and fails closed, naming which
check lost, before committing anything to in-memory state.*

---

## 10. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `04_CRYPTO_AND_KEYS.md §3` | the X25519 node keypair every envelope in §7 is sealed to, and the HKDF that derives the entry key |
| depends on | `04_CRYPTO_AND_KEYS.md §6` | the plaintext-metadata integrity design §2 and §8 implement — registry/manifest cross-binding and the external generation counter |
| depends on | `05_THREAT_MODEL.md §7` | `AR-1`, the accepted risk that bounds §2's deliberate metadata leak |
| depends on | `08_FIELD_MODEL.md §6` | the inference rules §5 implements, including the `wallet` qualifier §5 records as simplified |
| depends on | `16_CROSS_PLATFORM.md §4` | the keystore tiers that decide where §2's freshness counter can live on each platform |
| feeds | `06_ACCESS_GRAPH.md §1` | the `Node`, `NodePolicy` and `Grant` shapes the R0–R8 resolution rules are evaluated over |
| feeds | `06_ACCESS_GRAPH.md §3` | the three grantable capabilities §6 narrows `scope` to |
| feeds | `07_TWO_FACTOR.md §6` | the entry-with-a-`totp-seed`-field shape that a stored TOTP item is |
| feeds | `10_API_AND_MCP.md §1` | the entity shapes every broker operation's params and results are expressed in |
| feeds | `13_TEST_PLAN.md §3` | the invariants the property suite (P-1..P-12) is written against |
| feeds | `18_ENDPOINT_INDEX.md §1.2` | the entry, field and note operations indexed there, and which of them exist |
| decided by | `11_MIGRATION.md` | that nothing is imported from V1 — which is why §3's `aliases` is a rename mechanism and not a migration one. That document numbers no sections; cite it whole |
| depends on | `14_DECISIONS.md` | `ADR-007` (removal seals), `ADR-011` (schemas deleted), `ADR-012` (inference suggests), `ADR-024`/`ADR-039` (the generation counter), `ADR-027`/`ADR-048` (the 7-day windows), `ADR-029` (`privateNames`), `ADR-030` (auto-lock), `ADR-033` (wallet hardening), `ADR-040` (epoch timestamps), `ADR-055` (`entry.undo`), `ADR-059` (the status vocabulary this rewrite applies), `ADR-071` (`node.update`/`node.policy`), `ADR-072` (notes), `ADR-073` (`entry.create_batch`) |

## 11. Source

**Design.** `ADR-007`, `ADR-011`, `ADR-012`, `ADR-024`, `ADR-027`, `ADR-029`, `ADR-030`,
`ADR-033`, `ADR-039`, `ADR-040`, `ADR-048`, `ADR-054`, `ADR-055`, `ADR-063` (write-through, the
previous registry pair), `ADR-064` (`gate.twofa`), `ADR-066` (settable workdirs), `ADR-071`
(`node.update`/`node.policy`), `ADR-072` (notes), `ADR-073` (`entry.create_batch`) in
`14_DECISIONS.md`.
`ADR-040` is the one that invalidated this document's timestamp types; `ADR-039` is the one
that moved the freshness counter out of the keystore and into a signed file.

**Code.** `crates/core/src/registry.rs` (`Node`, `NodePolicy`, `Grant`, `Capability`,
`validate_registry`) · `crates/core/src/envelope.rs` (the `CMV2` format, seal/open) ·
`crates/core/src/inference.rs` (`FieldType`, `EntryType`, `default_masked`) ·
`crates/core/src/access.rs` (where `descendantRead` and sibling visibility are consumed) ·
`crates/store/src/registry_file.rs` (`NodeDoc`, `GrantDoc`, `ManifestBinding`,
`RegistryDocument`) · `crates/store/src/manifest.rs` (`ManifestBody`, `ManifestEntry`,
`verify_cross_binding`) · `crates/store/src/generation.rs` (`FileGenerationCounter`) ·
`crates/store/src/audit.rs` (the chain and the tip sidecar) · `crates/store/src/verify.rs`
(what `maintenance.verify` actually checks, including `find_note_mismatch`) · `crates/store/src/paths.rs` (every path named in
this document) · `crates/brokerd/src/ops.rs` (`entry.*`, `node.create`, `node.update`,
`node.policy`, `notes.read`/`notes.write`, `grant.*`,
`default_sensitivity`, `new_entry_id`) · `crates/brokerd/src/scope.rs`
(`capabilities_for_agent_access`, workdir matching) · `crates/brokerd/src/server.rs`
(`record_decision`, the single audit call site).

**Tests.** `crates/core/tests/properties.rs` — P-1…P-5 (envelope), P-7/P-8 (parser), P-11
(inference never mutates). `crates/core/src/registry.rs`'s own `mod tests` — the node
invariants; note that these are **unit** tests, not property tests, which is a correction to
this document's previous claim. `crates/brokerd/tests/isolation.rs` — I-14 (locked topology),
I-18 (create while locked lands in pending), I-19 (tampered manifest refused), I-20
(rolled-back registry refused), I-21 (day 6 restores, day 8 is gone), I-25 (concurrent writers,
exactly one wins). `crates/store/src/audit.rs`'s `truncating_the_tail_is_caught_by_the_tip`.
`crates/brokerd/tests/entry_lifecycle.rs`, `entry_undo.rs`, `grant_ops.rs`, `node_ops.rs`,
`durable_vault.rs` (the persisted gate, workdir binding, a restart's reload, and — ADR-071…073 —
renaming, policy patches, notes and `entry.create_batch`).
`crates/core/tests/field_doc.rs`, `no_field_schema.rs`, `crates/store/tests/alpha6_golden.rs`,
`crates/brokerd/tests/field_model.rs`, `seal_durable.rs` (ADR-078, ADR-079).
Suite result: `cargo test --workspace -- --list` — 813 tests in 50 test binaries (2026-10-03); the last full
run recorded is 571 passed, 0 failed, 41 test binaries, exit 0 (2026-10-02; earlier: 448 passed, 37 test
binaries as of 2026-09-24, re-measured 2026-10-01; 406
passed, 35 test binaries as of 2026-09-13, run 34743281942; 397 passed, 33 test binaries on
2026-08-18).

**Verification.** `python3 -m tools.corpus_check crossrefs` proves every `NN_NAME.md §S`
reference above resolves; `python3 -m tools.docgen.cli build v2/docs/03_DATA_MODEL.md` runs the
nine gates. Neither can prove a type matches its code — that is what re-reading
`crates/core/src/registry.rs` and `crates/store/src/manifest.rs` alongside this document is
for, and it is the check this rewrite performed.

**Figures.** Both are `tools/docgen`-rendered — the first `docgen`-rendered (not
`visual-engine`-rendered) figures shipped in this project (`tools/ENGINE_ROUTING_POLICY.md`'s
own "not yet decided" note, closed by this pair). §2's `plaintext-boundary`
(`kind: "system_map"`) enumerates every path in `crates/store/src/paths.rs` on one side of the
plaintext/ciphertext boundary or the other. §9's `rollback-defence` (`kind: "sequence"`)
renders `BrokerState::verify_and_load_vault`'s exact call order against
`registry_file::load`, `generation::check_and_advance` and `manifest::load` +
`verify_cross_binding`, naming isolation tests I-19 and I-20 in its own caption. Spec file:
`v2/docs/03_DATA_MODEL_spec.json` (both figure objects). Verified rendered as real inline SVG,
not escaped source, in `v2/docs/03_DATA_MODEL.html` — two figure blocks present, zero escaped
markup.
