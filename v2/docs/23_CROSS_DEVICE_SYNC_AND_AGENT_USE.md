---
id: V2-023
classification: public
title: Cross-device sync and model-blind agent use — the first major post-release update
audience: technical
owner: credmgr-v2
status: needs-verification
export_allowed: true
surface: repo
last_reviewed: 2026-10-30
---

<!-- artifact-hardened: NOT HARDENED — first pass (creation) on 2026-10-30. Records the owner's
     2026-10-30 post-release handoff (an external design review) against the live code at
     `54b9a3e`, and turns it into the work programme for the first major update after
     2.0.0-beta.1. Nothing in it is built. Not source-of-truth until the W1 contracts are written
     and this document is three-pass hardened (`~/.claude/CLAUDE.md`, Three-Pass rule). -->
# Cross-device sync and model-blind agent use — the first major post-release update

> **Read first (2026-11-08).** This is a historical design record, merged by `ADR-153`. Its draft ADR,
> called "ADR-094" below, was never adopted; `main`'s ADR-094 is a different decision. The current plan
> is `26_PRODUCT_PLAN_2X.md`, which wins wherever the two disagree (agent use no longer waits for sync;
> sync starts with a user folder; device identity is P-256). Facts below that are now stale: security
> levels, `node.rekey`, `--age` export and Touch ID are built; `llm.*` was dropped (ADR-146); the licence
> is source-available (ADR-096), not MIT; there are 76 broker operations, not 55.

`CredMgr V2` · post-release update 1 (**PRU-1**, working milestone `2.1.0`) · `2026-10-30`

> **Status.** **Nothing in this document is built.** It records an external design review the
> owner handed over on 2026-10-30, checks every claim in it against the code at commit `54b9a3e`,
> and sets out the work for the first major update after `2.0.0-beta.1`: one personal vault on
> every device the owner uses, synchronised as ciphertext, with offline work that never loses a
> change, and AI agents that *use* credentials without the value entering the model's context.
> The decision that this is the direction is `ADR-094` (`14_DECISIONS.md`). The beta.1 release
> plan (`PRODUCTION_PLAN.md`, batches 1–6) is unchanged by this document except for one known-risk
> line added to batch 5 (§4, F01).

---

## 0. How to read this, and what it does not authorise

**Source.** The owner pasted the review into a live session on 2026-10-30. It updates an earlier
handoff of 2026-10-26 (held by the owner, not in this repository). The review read selected files
through a connector, ran a small synthetic model (§14), and wrote recommendations. It did not
build, test, deploy or run CredMgr. Its own words on that: a repository document saying a test
passed is repository-reported evidence, not a rerun; model results are not application test
results; no reuse percentage, security score or production-readiness guarantee is justified.

**What this session added.** Every requirement (R01–R10, §3) and finding (F01–F15, §4) is
classified against the source at `54b9a3e`, with a file and line where one exists. Test results
quoted here are the ones the repository reports (`PRODUCTION_PLAN.md`, 2026-10-30); none of the
CredMgr suites was rerun for this record. The synthetic model **was** rerun (§14).

**Not authorised by this document:** any deployment, release, purchase, paid API call, migration
of a live secret, change to the live V1 vault, or change to another project. Hosting a relay, a
paid service and store listings each need their own owner decision (§15).

**Five meanings of "version" — never one flag for all five.**

| Meaning | Values today | Where it lives |
|---|---|---|
| Product generation | V1 (Node, the live vault) · V2 (this project) | separate vaults, no sync between them (§8) |
| Platform | macOS (built) · Windows, Linux (planned) · iPhone, iPad, Android (not designed) | §10 |
| Release channel | alpha.6 → **beta.1** → rc.1 → 2.0.0 → PRU-1 | `PRODUCTION_PLAN.md`, GitHub milestones |
| Authority model | personal (built, one machine) · organisation (`22_ORG_VAULT_SYNC_AND_LICENSING.md`, planned) | §15 |
| Interface mode | Lite / Pro (a design idea only) | not in scope here |

The same separation applies to wire and storage formats: app release, broker IPC, MCP protocol,
local schema, encryption envelope, sync wire, policy and backup format each carry their own
version (§8).

---

## 1. Purpose

Continue V2 toward **one logical personal vault across macOS, Windows, Linux, iPhone, iPad and
Android**, with local offline work and automatic encrypted synchronisation where the platform
permits it, while keeping the project boundaries (node isolation), recovery, gradual upgrades, and
making AI-assisted credential use safe.

What stays true through all of it:

- The broker (`credmgrd`) stays the only cryptographic and authorisation authority. Every other
  process is a client (`02_ARCHITECTURE.md §1`).
- Node isolation is the product. Sync never widens a grant or exposes another node (§4, F13).
- MIT for everyone, nothing gated by payment (`ADR-074`). A commercial service is a separate,
  optional product decision (§11).
- No analytics, no telemetry, ever (`PRIVACY.md`).

Personal cross-device sync is the decided direction (`ADR-094`). **Organisation sharing, wallet
transaction signing, cloud plaintext execution and paid hosting are separate decisions** and are
not implied by anything here. An "AI suggestions" switch never implies sending vault contents to a
model.

---

## 2. Where this sits in the plan

| Order | Milestone | Content | Source |
|---|---|---|---|
| 1 | `2.0.0-beta.1` | batches 1–6 | `PRODUCTION_PLAN.md` |
| 2 | `2.0.0-rc.1` | presence / Touch ID, aliases, `.env` importer | `PRODUCTION_PLAN.md` "After beta.1" |
| 3 | `2.0.0` | `node.rekey`, machine lock, duress, `llm.*`, security levels, Windows and Linux keystores, `--age` export, org vault, … | same |
| 4 | **PRU-1 (`2.1.0`, working name)** | this document: W1–W7 (§12) | here |

Four `2.0.0` items feed PRU-1 directly and are coordinated, not duplicated: **Windows and Linux
keystores** are W2's first deliverable; **security levels** and **`llm.*`** are inputs to W5 (the
agent-use capability model must be one design, not two); **the org vault** is re-sequenced after
personal sync (`ADR-094` item 4). **W1 (contracts) is design-only** and can start as soon as the
beta.1 stamp (batch 5) is done; it touches no beta.1 code.

---

## 3. Requirements R01–R10, classified against `54b9a3e`

Classes: **implemented-and-verified** (code exists and the repository reports a passing test) ·
**implemented-unverified** · **planned** (a design or milestone exists, no code) · **missing** ·
**conflicting** (code or an accepted decision says otherwise).

| ID | Requirement | Class | Evidence |
|---|---|---|---|
| R01 | V2 is the product; keep the Rust core, tested boundaries and the Tauri desktop | **implemented-and-verified** | six crates (`crates/`), 55 broker ops, every gate green on 2026-10-30 (`PRODUCTION_PLAN.md` status line; repository-reported) |
| R02 | Installable apps on all six platforms, with feature and security differences stated | macOS **implemented-unverified**; Windows, Linux **planned**; iPhone, iPad, Android **missing** | macOS: unsigned `.app`, Developer ID is batch 6. Windows/Linux: `2.0.0` milestone; the transport is Unix-only (`crates/brokerd/src/server.rs:8`, `crates/mcp/src/transport.rs:67`, `crates/cli/src/transport.rs:64`). Mobile: no design (`16_CROSS_PLATFORM.md` has no mobile section) |
| R03 | One personal logical vault, encrypted replicas, automatic sync, honest offline/background behaviour | **missing**, and **conflicting** with today's public claim | `README.md` "What it is not": "single-user and single-machine, by design"; `22_ORG_VAULT_SYNC_AND_LICENSING.md §3` gates any sync on rewriting that claim |
| R04 | Offline reads and writes survive restart and reconcile without silent loss | one machine **implemented-and-verified**; reconcile **missing** | `crates/store/src/atomic.rs` (temp → fsync → rename; Phase 2 exit gate). The multi-file commit is F11 |
| R05 | Store API keys, passwords, tokens, notes, public wallet addresses, private wallet material, each with a fitting policy | storage **implemented-and-verified**; per-class policy **planned** | field model `ADR-078` (free-text labels, types, masking). Wallet material excluded from agent use needs the security levels of `17_AIRLOCK_AND_LLM.md §2`, still `planned` |
| R06 | Agents discover references, store through a secure channel, use credentials through constrained operations; no plaintext to the model in ordinary flows | **conflicting** — F01 | `crates/mcp/src/tools.rs:409–414` (`credmgr_get` → `entry.reveal`), `crates/mcp/src/server.rs:120` (the value is serialised into MCP text content) |
| R07 | Unified identity and cross-platform entitlements if adopted; one user / three devices as a proposal | **conflicting** with `ADR-074` (MIT, no payment gate) and `README.md` ("no account") | §11; a product decision, not an assumption |
| R08 | Recovery, safe export, device replacement and upgrades are first-class; billing or service failure cannot destroy the vault | recovery and backup **implemented-and-verified**; export **planned**; device replacement **missing** | recovery codes, signed backup, `maintenance.rotate_root` (`ADR-076`); `--age` export is in `2.0.0`; one device today. Upgrade interop: the `e2e-fields` gate runs alpha.6 binaries against current ones (repository-reported) |
| R09 | Project/node scope and authorisation enforced in trusted code, independent of prompts and UI | one machine **implemented-and-verified**; across devices **missing** | the broker is the single enforcement point; `crates/brokerd/src/scope.rs` capability ceiling; isolation suite `13_TEST_PLAN.md §4` (I-1 … I-29) |
| R10 | Reuse the canonical plan and checkpoints, preserve concurrent work, synthetic fixtures, observable evidence | **implemented** (process) | `SESSION_PROTOCOL.md`, `BUILD_LOG.md`, `PRODUCTION_PLAN.md`; this record pins `54b9a3e` and leaves the in-flight batch-2 work untouched (§12, W0) |

---

## 4. Findings F01–F15, classified against `54b9a3e`

Priorities are for the proposed extension, not public vulnerability ratings of today's local-only
product.

| ID | Priority | Gap | Live status at `54b9a3e` | Required correction |
|---|---|---|---|---|
| F01 | Critical | MCP returns credential values | **confirmed in source.** `credmgr_get` maps to `entry.reveal` (`tools.rs:409–414`); a success is serialised as `{"type":"text","text": value}` (`server.rs:120`). Existing limits: an agent token can be issued without `reveal` (`Capability` enum, `crates/core/src/registry.rs:201`; ceiling in `scope.rs`), node 2FA policy and lock state apply, approvals exist (`ADR-088`, `ADR-090`), and the forbidden-tool list holds (`10_API_AND_MCP.md §3.2`). None of these makes a granted reveal model-blind. This is a requirement gap, not an unauthorised-access exploit. | Broker-enforced agent capabilities; a separate human reveal; opaque-reference *use* through a constrained executor (§9); canary tests on every model-visible path (T16, T17). **For beta.1:** stated as a known risk in batch 5's stamp (`PRODUCTION_PLAN.md`). |
| F02 | Critical | Last-writer-wins loses concurrent secret changes | **conflicting design:** `22_ORG_VAULT_SYNC_AND_LICENSING.md §4.2` omits "conflict resolution beyond last-writer-wins per entry" on purpose. Not built. | Causal revisions, preserved conflicting heads, explicit resolution (§7.3); update/update and delete/update tests (T02, T04). |
| F03 | Critical | A short code plus X25519 is not a complete enrolment protocol | **conflicting design:** doc 22 §4.2 step 1. **No asymmetric signing primitive exists:** `crates/core/src/signing.rs` is HMAC-SHA256 over root-derived subkeys; the crypto dependencies are `x25519-dalek`, `chacha20poly1305`, `hkdf`, `hmac`, `sha2` (`crates/core/Cargo.toml`) and `argon2` (`crates/keystore/Cargo.toml`). | Reviewed authenticated pairing with transcript binding, key confirmation, owner approval, replay and guess limits (§6.2). Choose a reviewed signature scheme and its trust anchor in W1 before any enrolment code. |
| F04 | Critical | Old clients may strip unknown schema or policy | **partial:** the envelope carries a version byte (1 raw value, 2 field document) and a suite byte (`crates/core/src/envelope.rs`); field documents parse strictly (`deny_unknown_fields`, `crates/core/src/fields.rs:280, 331`), so an old reader refuses rather than strips. No required-capability list, no minimum-reader/writer matrix. | Independent versions plus authenticated required capabilities; refuse before mutation (§8; T13, T14). |
| F05 | High | Revocation races offline changes and rotation | **missing** (no membership exists) | Serialised membership and key epochs, stale-write quarantine, resumable rotation (§7.5). |
| F06 | High | Backup restore can resurrect old access or deletions | one machine: **partial** — the external `vaultGeneration` counter catches a rolled-back registry (`crates/store/src/generation.rs`, `ADR-024`, `ADR-039`). Across devices: **missing** | Fresh device identity on restore, explicit recovery/import, generation fencing (§6.3, §7.4; T05, T12). |
| F07 | High | Process separation overstates isolation | **conflicting wording:** doc 22 §3 and §4.2 say no key material "ever" reaches the network-capable process and call that the guarantee that matters. Today `credmgrd` has no network code at all (`17_AIRLOCK_AND_LLM.md §1`). | A key-free sync API plus feasible OS controls; state the same-user / unlocked-compromise limits plainly (§5). |
| F08 | High | Mobile background sync conflicts with locked keys | **missing** (no mobile) | Ciphertext-only staging; decrypt and apply after unlock; a visible "awaiting unlock" state (§10; T21). |
| F09 | High | Account reset confused with vault recovery | not applicable today (no account exists); becomes live if a managed service is adopted | Separate account recovery from cryptographic recovery; an e-mail reset never releases a key (§6.3; T07). |
| F10 | High | Three-device proposal contradicts current policy | **conflicting** with `ADR-074` | An explicit product ADR first; an optional managed service is the recommended reconciliation (§11). Not adopted by this document. |
| F11 | High | Several file renames are not one transaction | **partial:** every file write is atomic (`atomic.rs`); one writer at a time (`hold_persist_lock`, `crates/brokerd/src/ops.rs:3883`); **root rotation already has a journal and one commit point** (`crates/store/src/rotation.rs:13`, `recover_interrupted_rotation`). An ordinary entry write (envelope, manifest, audit) has no shared commit record. | One recoverable transaction over revision, manifest, outbox and audit intent, reusing the rotation journal pattern; fault-injection at every boundary (§7.2; T01). |
| F12 | High | A path or device label mistaken for authority | one machine: acceptable — a workdir maps to a node as a local hint, the token is the authority (`BrokerScope.bound_workdir`, `scope.rs`). Across devices: **planned correction** | Stable ids, scoped principals and grants; paths are per-device mappings, never portable authority (§6.1). |
| F13 | High | Broad sync keys can weaken node isolation | **compatible:** per-node keys exist (`04_CRYPTO_AND_KEYS.md §3`, envelopes sealed per node); doc 22 §4.2 re-seals per node. No distinction yet between a full-owner device and a restricted agent. | Keep per-node boundaries; distinguish full-owner devices from restricted agents (T29). |
| F14 | Medium | "All platforms" hides security differences | **partial:** `16_CROSS_PLATFORM.md §4` sets keystore tiers for macOS, Windows and Linux; nothing for mobile | Test IPC, keystore tier, lifecycle, clipboard, packaging and updates per platform (§10; T23, T26, T30). |
| F15 | Medium | Stale documentation triggers duplicate work | **confirmed:** e.g. the git-ignored local agent notes still say 53–54 ops and ADR-080/089 (live: 55 ops, ADR-092 + ADR-093 in flight); the root `README.md` mixes release statements and historical limitation lists; `OPEN_WORK_REGISTER.md` keeps dated old blocks | This table is the requirement-to-code map; dated sections are history; `PRODUCTION_PLAN.md` is the one current plan. |

---

## 5. Architecture and trust boundaries

The broker stays the cryptographic and authorisation authority. PRU-1 adds two narrow broker
operations — **export sealed changes** and **import untrusted sealed changes** — and a separate
**sync worker** that handles transport, retries and ciphertext staging. A **relay** that stores
encrypted changes lets devices that are never online together converge. The relay is a new
component, not an existing capability and not a continuation of doc 22's push-only design.

| Component | May hold | Must never hold or do |
|---|---|---|
| Vault core / broker | vault keys, authorised plaintext, verified policy | treat a prompt as authority; open unrestricted outbound network |
| Desktop UI | authorised display data, an explicit user reveal | a portable owner session in webview storage; an unrestricted command bridge |
| Sync worker | ciphertext, authenticated public metadata, scoped transport tokens | vault decryption keys, raw values, the owner session, grant creation |
| Relay | ciphertext and the minimum routing and membership metadata | plaintext, recovery keys; enrolling a decrypting device on its own |
| Account / membership service (only if adopted) | account login, coordination of the enrolment transaction | releasing a key because a login succeeded |
| Entitlement service (only if adopted) | verified purchase and service records | vault decryption; destroying data |
| Constrained credential executor | one approved credential, transiently, for one permitted operation | whole-vault or node keys; unrestricted URLs or shells; raw provider output to the model |

**Two threat models, kept apart.** Sync transport is ciphertext-only. The executor that sends an
authenticated request to a provider holds a plaintext credential for the length of one call. Never
claim "no network-capable process sees a secret" while building credential injection. Keep root
and node keys out of the executor; give it a narrowly authorised one-shot channel.

**Process separation is defence in depth, not a sandbox.** Same-user malicious code may still read
files or attack IPC. A key-free API is not an OS sandbox. Apply the file and process restrictions
each platform allows, and state the residual same-user and unlocked-compromise limits (this
corrects doc 22 §3's wording, F07).

**Mobile may need crypto and networking in one process.** Reuse the Rust logic, but document the
weaker isolation and review it. A module boundary is not a process boundary; a desktop daemon or
sidecar is not automatically valid on mobile.

**Never:** a shared plaintext database; the live vault directory inside a generic cloud-drive
folder; syncing sockets, session tokens, device private keys, local keystore wraps, lock state or
per-machine paths.

---

## 6. Identity, encryption, enrolment and recovery

### 6.1 Stable identities

Separate ids for account (if any), logical vault, device, node, record, field and operation.
Opaque ids, never names or e-mail addresses. Each device keeps its own mapping from local paths to
stable node ids; matching paths or symlinks never grant access.

Every device has its own identity. A reinstall or a cloned backup must not create two active
devices sharing a private identity key or an operation-counter namespace. A suspected duplicate
identity needs controlled re-enrolment, never a merge by name.

### 6.2 Keys, envelopes and the enrolment contract

Keep today's envelope construction (`suite 1` = X25519-HKDF-SHA512-ChaCha20Poly1305), KDF and
per-node keys until a reviewed ADR changes them. Compare recipient-specific resealing with a
reviewed content-key-wrapping design: record fan-out cost, offline behaviour, node isolation and
rotation. Familiar primitive names do not make a protocol.

For new envelopes, authenticate vault, node and record ids, revision parents, operation kind,
writer identity, membership and key epoch, format and required capabilities, and bind that routing
context to the encrypted content. Specify serialisation, domain separation, nonces, limits and the
exact verification order; ship test vectors. Separate signing and encryption keys. Design no new
primitive.

Encrypt names, labels, notes and values unless a feature justifies clear metadata. Document what
still leaks (size, timing, device count, IP address). Never expose a plaintext hash of a
low-entropy secret; use ciphertext digests or a reviewed keyed construction.

**Enrolment contract.**

1. The new device generates its identity locally and asks for a short-lived session.
2. A trusted owner device, or a deliberate recovery flow, approves the intended device key and
   vault. An account login is never enough.
3. Prefer a reviewed high-entropy QR or out-of-band pairing. A short human code needs a reviewed
   PAKE with key confirmation and guess limits (RFC 9382 is an example of a specified PAKE, not a
   choice made here); plain X25519 plus a code is incomplete (F03).
4. Bind both identities, the vault, the role, the protocol, the transcript, the expiry and a nonce.
   The session is single-use; key substitution, replay and confirmation mismatch fail closed.
5. Coordinate membership (and any service device slot) atomically. Publish membership only after
   the required key envelopes and the approval are durable. Retries are idempotent; an interrupted
   session never becomes a half-approved decrypting member.
6. Transfer only approved rights and keys, in authenticated encrypted envelopes. The relay and any
   account service never see decryption material.

The sync worker may need transport-authentication keys. The precise rule is **no vault decryption
material and no credential plaintext**, not "no cryptographic material".

The workspace has **no asymmetric signature primitive today** (F03). W1 inventories the approved
algorithms, picks one by ADR, and defines who may sign each transition and how a recipient
establishes the first trusted key. A signature without a trusted signer binding proves nothing.

### 6.3 Unlock and recovery

Biometrics authorise local key use; they are not portable keys. Device hardware protection stays
separate from portable enrolment and recovery. Test biometric changes, passcode removal, key
invalidation, locked boot and backup restore. Choose each platform's key accessibility on purpose;
never weaken it just to make background sync work.

Recommended: **user-held recovery material plus a recovery drill; no provider-held decryption key
by default.** An e-mail reset restores account access, never vault plaintext. If every trusted
device and the recovery material are lost, recovery may be impossible under this model; setup says
so, without collecting recovery secrets in chat or telemetry.

Recovery restores authenticated data **and** keys, not a root key over missing ciphertext. Keep
three recoveries apart: account, cryptographic, and data after corruption or service failure.
Backups state whether they cover deleted records, history and pending changes. Prefer restoring
into an isolated new vault (an import), not rewinding a live synced vault. A restored device never
revives a revoked membership and never clones a device identity.

---

## 7. Synchronisation and conflict protocol

### 7.1 Change representation

Stable operation ids with causal parents, or an equivalently reviewed version-vector design.
Conceptual fields (not a wire format):

```text
vault_id, node_id, record_id, op_id, writer_device_id
parent_revision_ids, membership_epoch, key_epoch
schema_version, required_capabilities, operation_kind
encrypted_payload, authenticated_context, authenticity_proof
```

Wall-clock time is for display, never for conflict authority. Clients verify writer membership and
authorisation, not only the relay. The same operation id with different bytes is an integrity
error. Bound sizes, parent counts, pending queues, retries and parsing depth.

Credential data and security-control changes are different things. Credential revisions may keep
concurrent heads. Membership, grant expansion, key epochs and recovery settings need a serialised,
owner-authorised transition anchored in the previous valid state — never merged by union or LWW.
Until a reviewed offline control-plane protocol exists, security-control changes need current
online coordination; ordinary data edits work offline. A service that orders transitions cannot
forge them.

### 7.2 Durable local work and replay

Commit the revision, the index/manifest, the outbox and the audit record (or a recoverable audit
intent) as **one recoverable transaction**. "Saved locally" is said only after that is durable;
relay acknowledgement is a separate state. Use the existing file store with a journal and commit
marker — the pattern `crates/store/src/rotation.rs` already uses for root rotation — rather than a
sequence of renames (F11).

Before applying a received change: validate bounds, authenticity, context, membership, schema and
dependencies. A change with a missing parent waits in bounded pending storage. Malformed network
data never poisons the local vault. A duplicate valid operation applies idempotently. Transient
network failures retry with backoff and jitter; integrity, authentication, rate-limit,
incompatibility and outage errors are told apart.

States the user sees: **saved locally · upload pending · stored remotely · downloaded, awaiting
unlock · applied · conflict · upgrade required · sync error.** "Uploaded" does not mean every device
applied it, nor that a restore was proven.

### 7.3 Conflict rules

| Race | Required behaviour |
|---|---|
| Two offline edits to one credential | Keep both authenticated revisions; no silent LWW |
| Related fields changed concurrently | The whole credential is one conflict unit at first; never combine a username from one revision with a password from another |
| Unrelated records | Apply independently when dependencies and authorisation allow |
| Delete versus update | Keep the tombstone/update conflict; no silent resurrection; agent use blocked by default |
| Rotation versus a stale value edit | Keep the evidence, mark it stale; the vault cannot prove which value the provider accepts |
| Grant tightening versus a stale write | The current epoch and control policy decide; quarantine writes made under stale authority |
| A resolution followed by an unseen concurrent edit | The resolution consumes only the heads it names; the new branch is a new conflict |

A conflicted credential is never used automatically until a trusted resolution. A human choice
emits a revision that names the exact heads reviewed. Field-level merge for notes can come later;
text merge never applies to passwords or private keys.

### 7.4 Tombstones, retention and compaction

Keep apart: deletion, the undo window, history, audit, backup and tombstone retention. Doc 22's
30-day organisation undo window is not automatically the personal policy. A deleted record leaves
the active view; its tombstone stays as long as needed.

Compaction needs an authenticated snapshot boundary and a minimum accepted replica generation. A
device older than the boundary must rebootstrap; its pending changes are kept in quarantine or an
export for deliberate reconciliation. Without that fence a long-offline device resurrects deleted
content (the third negative control in §14 reproduces this). Keep enough authenticated causal
summary; dropping parent history can make descendants unverifiable. Test compaction during
interrupted uploads and pending edits.

Never promise deletion from offline devices, external exports or backups already downloaded. A
secret-retention rule is not an audit-retention rule.

### 7.5 Revocation and rotation

Revoke membership through a serialised owner-authorised transition, revoke transport access, and
fence uploads made under the old epoch after the transition. Changes accepted before the
transition and those arriving after it are told apart. An old valid signature is not current
authorisation.

To keep a revoked device out of future secrets, distribute a **new key epoch** to the remaining
devices only. Re-wrapping the same content key for fewer devices is not enough if the removed
device already knows that key. Define whether current content is re-encrypted and how historical
copies stay exposed. Plaintext a device already learned cannot be made unknown.

A device returning with old-epoch edits refreshes membership before upload. Never silently re-sign
or re-encrypt stale operations under current authority: keep the queue and reconcile it against the
current authorisation. Lost device, compromised device, voluntary deactivation and billing
replacement are four different flows.

Rotation recovers from every interruption: stage keys and envelopes, commit an authenticated epoch,
track readiness, keep a recovery journal. **Reuse, do not duplicate:** root rotation's journal and
`recover_interrupted_rotation` already exist (`ADR-076`), and batch 2 of the beta.1 plan wires it
before a factor decision. Revoking a vault device does not revoke provider credentials; those may
need their own rotation.

Offline devices cannot receive an immediate revocation or be forced to forget cached keys. Say so.

### 7.6 A malicious relay, and rollback

Encryption does not give availability. A relay may suppress, replay, fork or delete changes. Keep
the highest accepted authenticated membership and snapshot state locally and verify continuity. A
new device needs a trusted enrolment or recovery checkpoint, not whatever the server offers first.

Global fork and rollback detection stays incomplete without an independent trust anchor or
device-to-device comparison. A hash chain alone does not prove freshness when the attacker controls
its starting point. Do not oversell software counters or server cursors as rollback defence (the
local `vaultGeneration` counter is a one-machine control, F06).

---

## 8. Cross-version compatibility and V1 import

Version these independently: app release, broker IPC, MCP, local schema, encryption envelope, sync
wire, policy and backup format. Keep a **minimum-reader / minimum-writer and required-capability
matrix** with generated fixtures.

An unknown **required** security feature is refused before any mutation. An optional unknown field
round-trips only when its meaning is provably preserved; otherwise the item is read-only or
refused. An older writer never drops an unknown policy field or weakens encryption. Read
compatibility is not write compatibility. Queue items are not consumed and application is not
acknowledged before these checks. (Field documents already refuse unknown keys,
`deny_unknown_fields` — the safe direction; F04.)

Prefer expand → read old and new → migrate → retire old writers at an explicit boundary. Keep safe
local access and export wherever possible. A signed update proves origin, not schema
reversibility. Roll back to a compatible binary, or recover into an isolated copy; never silently
restore old live data to make an old binary start.

**V1 import is optional and one-time:** synthetic fixtures first, a preview with record and field
counts, a destination node chosen by the user, an access-boundary mapping, an encrypted recovery
backup, and an atomic V2 result. V1 project labels are not V2 cryptographic boundaries. The V1
source stays intact; there is **no automatic round-trip sync between V1 and V2** (`11_MIGRATION.md`
stays the authority). Keep executables and data roots apart (the binary/data-path collision the
README documents).

---

## 9. Secure AI access

### 9.1 Fix the actual data flow

`credmgr_get` maps to `entry.reveal`, and a successful value is serialised into ordinary MCP text
content (F01). Masked UI or hidden panels do not make that model-blind.

Use explicit agent principals and broker-enforced capabilities. Hiding a tool is not enough if it
can still be called directly, through another client, through a raw broker op, an inherited owner
token or an unrestricted shell. Keep the legitimate human workflows through a documented
migration. Never promise isolation from malicious same-user code without effective OS containment.

| Class | Trusted behaviour | What the model sees |
|---|---|---|
| Discover | scope-filtered names and metadata; unauthorised nodes hidden | minimal allowed references; no values |
| Store | a secure UI or provider-to-vault channel captures the secret before it reaches the model | a reference and a safe status |
| Use | the trusted executor resolves the reference for a defined operation | typed, bounded, allow-listed output |
| Human reveal / export | an explicit user workflow with the required approval or presence | completion or cancellation only, never the bytes |

A CSPRNG generates secrets (`util.generate`, `ADR-087`, already does this locally). A chat form is
not a secure entry channel until the host's data flow is verified. Keep values out of URLs,
arguments, telemetry, errors and plaintext temporary files. **Environment injection** exposes the
secret to the target process and to any sufficiently powerful code around it; it is not a model
boundary when the agent can run arbitrary commands.

### 9.2 The constrained executor

Operation templates bind the provider origin, method, path, parameter schema, credential scope,
side-effect policy and response schema. Normalise destinations; block unsafe network targets; deny
or re-authorise redirects. Test DNS rebinding, private and link-local addresses, URL userinfo,
alternate ports and encoded host/path tricks. No general URL-plus-secret proxy; no unrestricted
shell wrapper.

Allow-list response fields. Providers echo tokens in bodies, headers and errors; string redaction is
not a reliable primary boundary, least of all with encodings and fragments. Suppress raw output;
return safe categories and correlation ids. A credential a provider generates is captured into the
vault before any model-visible response.

Bind each approval to caller, device, node, operation digest, credential reference and revision,
destination, parameters, expiry and use count, and re-check it immediately before dispatch. A
changed parameter invalidates the approval; a replay is refused. Cancellation before dispatch
prevents use; a provider action already sent may be irreversible. On an ambiguous timeout, reconcile
through provider idempotency or status, never by blindly retrying a mutation.

Use monotonic elapsed time for in-process approval and session lifetimes (the broker's elevation
window already does, `ADR-085`). On restart, ephemeral grants are invalid unless a verified
persistent freshness mechanism exists. Test wall-clock jumps, time-zone changes, suspend/resume and
rollback: changing the local clock never revives a consumed or expired grant or extends an
elevation. Offline policy freshness needs an explicit bounded policy, not a promise that an
untrusted local clock enforces it perfectly.

A cloud model needs an online trusted executor and a deliberate authenticated bridge; the
ciphertext relay cannot perform credential-dependent operations by itself. Hosted plaintext
execution changes the trust model and is never added silently. A suspended mobile app cannot
promise a continuous cloud service.

### 9.3 Protocol and sensitive material

The MCP server announces protocol `2024-11-05` (`crates/mcp/src/server.rs:18`). Inventory the
clients actually in use and implement version negotiation and initialisation properly; changing the
date constant alone is not an upgrade. Local stdio and remote HTTP authorisation differ; for HTTP
MCP follow the current authorisation specification (audience validation, code-flow protections),
and never pass the MCP client's own token to a provider — a separately authorised provider
credential is a different object.

Bound frame sizes, JSON depth, timeouts, concurrent work and error output. The transport reads
lines; resource-exhaustion tests have not been run (T28). Untrusted prompts, files, pages and tool
output never grant privileges or change policy (`17_AIRLOCK_AND_LLM.md §7`, AR-12).

**Wallet private keys and recovery phrases are storage-only by default and excluded from ordinary
AI access.** Signing or sending transactions is a separate feature with trusted transaction
confirmation and its own review. Public addresses are less sensitive but still reveal associations.

---

## 10. Platform delivery

| Platform | Reuse | Proof required before claiming support |
|---|---|---|
| macOS | the existing core and UI | current broker, native protection, lock/sleep, clipboard, packaged and signed build, updates; V2 Touch ID is not inferred from V1 (presence is `2.0.0-rc.1`) |
| Windows | core, schemas, most of the UI | named pipes with an explicit restricted DACL and logon scope, authenticated peers (a PID alone is not authorisation), secure files and keystore, installer, session and lock behaviour |
| Linux | core and desktop UI where supported | socket permissions, user/session identity, keystore availability, packaging and display environments; core CI does not prove desktop support |
| iPhone / iPad | portable Rust; evaluate Tauri | Swift/native key access, lifecycle, iPad layout, secure entry, physical-device behaviour; no desktop-daemon assumptions |
| Android | portable Rust; evaluate Tauri | Kotlin/native keystore, key invalidation, process death, scheduled work, hardware-tier detection, packaging |

**Mobile slice before any UI rewrite:** create a test vault, lock and unlock, edit a synthetic
credential, pair, sync ciphertext, resolve a conflict, recover from process termination — on
physical devices, measuring KDF memory and time, accessibility and store packaging. If Tauri fails
a concrete requirement, keep the Rust and replace only the shell or UI that failed.

Apple's this-device-only key protection is not portable recovery. Android non-exportable hardware
keys do not mean plaintext never appears in app memory. Windows Hello does not make existing key
bytes TPM-resident. Where Linux has no secure storage, label that tier accurately
(`16_CROSS_PLATFORM.md §4`).

Sync starts in the foreground on unlock and on edits, with bounded retry. Background work may
upload sealed changes or stage ciphertext, leaving decrypt-and-apply until unlock. A push carries an
opaque wake hint only. OS scheduling rules out a universal instant-sync promise; show "awaiting
unlock" honestly.

Test app-switcher snapshots, screenshot surfaces, notifications, accessibility output, clipboard
history and cross-device clipboard, crash dumps and diagnostics. Clearing the clipboard does not
retract copies other software already saved. Owner sessions and unlocked state never sync between
devices.

---

## 11. Commercial and store reconciliation

**Current policy: MIT, no payment gate (`ADR-074`). Not changed by this document.** The review's
recommendation, recorded as a proposal only: keep local vault functionality independent of
payment; optionally offer **managed synchronisation** as a service with a unified account and an
agreed device allowance. That needs its own product ADR; the licence text is not touched and the
withdrawn licence-key schemes are not revived.

If ever adopted: define devices versus installations, reinstalls, several OS accounts, lost-device
replacement and mobile restore; avoid invasive hardware fingerprinting. Enrolment and slot
reservation are atomic and idempotent — two concurrent requests can never both take the last slot
(§14's second negative control reproduces the check-then-insert failure). Expire incomplete
reservations without revoking an accepted member.

Billing slots and cryptographic membership are separate. A lapsed subscription never removes
decryption rights silently. Whether replacing a device cryptographically revokes the old one is
stated explicitly. Cached offline entitlements cannot give instant global enforcement; online
enrolment is the simplest enforcement point. No grace period is invented here.

Use channel-supported server-side purchase verification, account ownership and linking controls,
idempotent notifications, refund / restore / cancellation handling and cross-account replay
protection. An e-mail match does not prove purchase ownership. A purchase restore never grants a
vault key.

Apple and Google rules depend on region, channel and programme. Nothing here establishes approval
for a device-limited subscription; check device restrictions, subscription availability, external
links and account deletion against the applicable contracts before any release. Local reading,
recovery and safe export survive any billing or service failure. Stopping a paid service, revoking a
device and deleting account data on request are three separate operations; document remote
retention and backups accurately.

---

## 12. The work programme (W0–W7)

These are dependency groups inside PRU-1, not a second production numbering. Batches 1–6 of
`PRODUCTION_PLAN.md` remain the release authority for beta.1.

| Work | Deliverable | Depends on | Done when (evidence) | Status |
|---|---|---|---|---|
| **W0** Reconcile | pin the source; record concurrent work; R/F map; plan amendment | none | no closed item reopened without evidence | **done 2026-10-30** — this document, `ADR-094`, `PRODUCTION_PLAN.md`, `OPEN_WORK_REGISTER.md`; pinned `54b9a3e`; batch-2 work in flight in the main checkout (uncommitted edits to `ops.rs`, `state.rs`, two test files and an `ADR-093`) left untouched |
| **W1** Contracts | threat model for the new boundary (`05_THREAT_MODEL.md` extension); ADRs: device identity and signature scheme, enrolment/pairing, recovery, membership and key epochs, change envelope and compatibility matrix, agent-use capability model (merged with `17_AIRLOCK_AND_LLM.md §2` security levels) | W0 | every ADR reviewed by an independent Opus pass; open choices listed explicitly | **ready** — first package; design only, no code; starts after the beta.1 stamp |
| **W2** Platforms | IPC, keystore and lifecycle adapters; the Windows named-pipe slice; Linux keystore tier; mobile feasibility slice (§10) | W0; W1 for any security change | macOS regression green; evidence from real target devices | blocked on W1 for security changes; the `2.0.0` Windows/Linux keystores are its first deliverable |
| **W3** Data | revisions, the one-transaction local commit (F11), outbox and inbox, conflicts, tombstones, version checks | W1 | fault injection at every boundary, property tests, a real Rust end-to-end run (T01–T06, T13, T14, T28) | blocked on W1 |
| **W4** Sync | membership, pairing, the ciphertext relay integration | W1, W3 | two real clients; offline, revoke, rotate and restore evidence (T07–T12, T15, T29) | blocked on W1, W3 |
| **W5** Agent use | opaque-reference executor; migration away from raw reveal for agents; capability model | W1, existing broker work (`llm.*`, security levels) | canary leakage and bypass tests; external-idempotency tests (T16–T20) | blocked on W1; see owner decision D2 |
| **W6** Entitlement | only after a commercial decision | product ADR, W4 | store sandbox; refund/restore; device-slot races (T24, T25) | **not scheduled** (D3) |
| **W7** Release | platform matrix, recovery drill, signing, independent security review; the README / threat-model / release-note rewrite that doc 22 §3 requires to ship as one change | applicable prior work | evidence per feature and platform; bounded known risks | — |

After W1 settles the interfaces, platform adapters, synthetic sync models and agent-use tests can
proceed independently on isolated branches. Enrolment depends on the identity and crypto contracts;
end-to-end acceptance depends on persistence. Licensing never blocks encryption correctness. Do not
redesign keys, relay and every UI at once before the interfaces settle.

Build synthetic vertical slices: two desktop replicas, then one mobile client, then mixed versions.
Reuse parsers, broker enforcement, fields, UI components, fixtures and docs only after checking the
fit. Local rollback counters, path scope and the old LWW semantics are not distributed
authorisation.

Preserve recovery and concurrent changes before every edit. No unrelated refactors. Run the
changed-boundary tests and the relevant existing gates, persist the receipts, and do not rerun
accepted work without a reason.

**Exact next ready action.** (1) In beta.1 batch 5, describe F01 as a stated known risk in the stamp
(description, bound, owner, resolution path — §15). (2) Once the beta.1 stamp lands, start W1 with
the agent-use capability ADR and the threat-model extension, since F01 touches a surface that ships
today.

---

## 13. Acceptance matrix T01–T30

All of these are **future application tests**. None has passed; the synthetic model in §14 is not
any of them.

| ID | Scenario | Required observation |
|---|---|---|
| T01 | Crash at every local commit boundary | an acknowledged save survives; an incomplete revision/manifest/outbox/audit transaction recovers consistently |
| T02 | Concurrent offline password edits | both revisions kept; automatic use blocked until resolved |
| T03 | Child before parent; duplicate or reversed delivery | bounded pending queue, idempotent application, the same final state everywhere |
| T04 | Delete versus update, both orders | no silent resurrection; the conflict and the undo policy kept |
| T05 | Long-offline device after compaction | generation fence; rebootstrap; its pending edits kept for reconciliation |
| T06 | A new branch arrives after a conflict resolution | the unseen edit is a new conflict |
| T07 | Account takeover without a trusted device or recovery material | no new decrypting member; no key released |
| T08 | Pair-code guess, replay, key swap, version downgrade | refused with no membership published; a safe audit record |
| T09 | Upload races a revocation; old-grant replay | serialised cut-off; stale writes quarantined |
| T10 | A removed device receives new-epoch ciphertext | cannot decrypt future secrets; its old cached knowledge stated as unaffected |
| T11 | Rotation interrupted at every stage | consistent recovery; the sole recovery route never lost |
| T12 | An old backup that lists revoked devices | no revived membership; a fresh identity; current authority reconciled |
| T13 | An old client writes an unsupported schema or policy | refused before any byte changes or a queue item is consumed |
| T14 | Minimum-supported and latest version exchange data | supported meaning kept; unsupported features fail explicitly |
| T15 | Relay changes context or bytes, replays, forks, deletes | integrity enforced; freshness and availability limits reported honestly |
| T16 | Canary secret in success, store and error paths | absent from every model-visible input and result, logs, debug output and telemetry |
| T17 | Direct hidden tool, raw broker op, another client, owner-token bypass | capability checks hold; any same-user residual risk is stated |
| T18 | Redirect, DNS rebinding, private IP, provider echo | no unauthorised credential delivery; no model-visible echo |
| T19 | Approval replay, change, cancellation (with clock skew, restart and suspend variants) | the bound request is enforced; one-shot; dispatch-race limits explicit |
| T20 | Provider accepts a mutation but the response times out | no blind duplicate; idempotency or status reconciliation |
| T21 | Mobile suspension, reboot, unavailable key (and a full account-service outage) | ciphertext kept, vault locked, applied in the foreground later |
| T22 | Biometrics, passcode or keystore invalidation (with clock variants) | an accurate protection tier; safe recovery without silent weakening |
| T23 | Wrong Windows user or session, remote peer, pipe squatting | connection or authorisation refused; the genuine local client succeeds |
| T24 | Two requests for the final device slot | at most one enrolment succeeds; retries do not leak slots |
| T25 | Billing expiry, refund, outage, purchase replay (and a full service outage) | no vault destruction; no unauthorised entitlement or decryption |
| T26 | UI lock, snapshots, clipboard, diagnostics | no unapproved disclosure; unavoidable limits documented |
| T27 | Synthetic V1 import with collisions and unsupported fields | preview and boundary mapping; atomic V2 output; V1 intact |
| T28 | Huge or deep messages, missing-parent flood, malformed envelopes | bounded memory and work; the existing vault stays usable |
| T29 | Cross-node and restricted-agent access (with cross-vault ciphertext substitution) | sync never widens a grant or exposes global or another node's data |
| T30 | Install, update, recover, uninstall on every claimed platform | verifiable distribution; compatible data handling; clear retention |

Each receipt records the commit, binary hash, OS/device, toolchain, command or action, synthetic
fixture id, result, evidence path and reviewer. No real secret in any test or log. A skipped or
quarantined test is not a pass. Existing release evidence (`RELEASE_VERIFICATION.md`) is extended,
never overwritten.

Audit records carry safe identifiers, actor, policy outcome and operation status — never a secret
value or a reusable token. When the audit sink is unavailable, a privileged mutation either
persists a local recoverable audit intent atomically or fails safely; it never proceeds silently
without the promised audit.

---

## 14. The synthetic model — what it shows, and the rerun

The review included a deterministic Python model (standard library only, synthetic values;
Appendix A). It checks causal heads and a few policy examples: 398 cases in nine groups, plus three
negative controls that reproduce the unsafe designs this programme must avoid — **LWW drops a
concurrent credential revision; check-then-insert enrolment admits four devices into three slots;
a purged tombstone without a generation fence resurrects a deleted entry.**

360 of the 398 cases are delivery orders generated from permutations of five operations with
duplicate and reversed variants — not 360 features or 360 distinct states. The model contains no
cryptography, no real concurrency, no network, no disk persistence, no mobile lifecycle and no
CredMgr code. It is bounded logic validation, not a proof of a secure distributed protocol.
Translate the cases into real integration and property tests (W3, W4); never ship the script as a
sync engine.

**Rerun on 2026-10-30 in this session:** `python3 -I verify_design_model.py`, Python 3.15.0, exit
code 0; output: `case_count` 398, nine groups all `PASS`, three negative controls, four stated
limitations — identical to the review's own receipt (30 October 2026). Script SHA-256
`5b14a6eae69922f0a474ddf840c0a32cc8f0816d189f673a323881e081fdcbe1`.

---

## 15. Decisions: defaults and what stays open

**Decided (`ADR-094`, owner direction 2026-10-30):** personal cross-device sync is the direction
and the first major post-release update — do not re-ask. MIT stands. Doc 22 §3's rule stands: the
README claim, the threat model and the release note change together, in the same release as sync.

| Decision | Default (applies unless the owner says otherwise) | Boundary |
|---|---|---|
| Personal versus organisation | personal device sync first; the org vault (doc 22) after | no new multi-person grants or hierarchy implied |
| Recovery | user-held recovery material plus a trusted device; no provider decryption | escrow or social recovery needs its own design and approval |
| Hosting | a provider-neutral relay; approved infrastructure only after a fit review | no deployment or spending implied |
| Mobile UI | feasibility-test Tauri; keep portable Rust | a native rewrite only for a demonstrated need |
| Agent access | opaque references, constrained use, deliberate human reveal | migrate existing raw-value clients; never call them model-blind |
| Wallet operations | secure storage only | signing needs its own review and authorisation |

**Open owner decisions:**

| # | Decision | Default until decided |
|---|---|---|
| D1 | The milestone number for PRU-1 | `2.1.0` (set at W7 by the compatibility matrix, §8) |
| D2 | Whether W5 (the F01 fix) moves forward into `2.0.0`, alongside `llm.*` and security levels | F01 is a stated known risk for beta.1 and `2.0.0`, fixed in PRU-1; **recommended:** pull W5 into `2.0.0` if `llm.*` is built there, since both change the agent surface |
| D3 | A commercial managed-sync service with a device allowance | not adopted; W6 not scheduled; `ADR-074` unchanged |
| D4 | Who hosts the relay, if anyone | none; W4 tests run against a local relay |
| D5 | Batch 5 wording of the F01 known risk | *description:* a granted `credmgr_get` puts the value into the agent's model context; *bound:* only with a token holding `reveal` on that node, subject to the node's 2FA policy, lock state and approvals; *owner:* the operator; *resolution path:* PRU-1 W5 (or `2.0.0` under D2) |

---

## 16. Evidence limits, sources and references

**Source identities read by the review** (git blob SHAs of the files it fetched; they identify
content, not verified builds, and were not one atomic checkout):

| Source | Blob SHA |
|---|---|
| `README.md` | `57c8df74685792e1088939e4c35a6b45cf702f11` |
| `v2/docs/22_ORG_VAULT_SYNC_AND_LICENSING.md` | `c44a0dceb6f1ba1189efa383dfaf5a3dd5496a59` |
| `v2/docs/02_ARCHITECTURE.md` | `24a8ec4fadea2d02cd707d172e77a1770d810a40` |
| `OPEN_WORK_REGISTER.md` | `cf04cbbd53c130cdf021443457d6781a21f8e6de` |
| `v2/docs/PRODUCTION_PLAN.md` | `04a29d30e2760f78acf1e5730d17a677924836e9` |
| `v2/Cargo.toml` | `45274a2fb9c6e0eb00520f4c1d27c46f5798b1d7` |
| `v2/crates/mcp/src/tools.rs` | `796abfd7778644b7d2f27bc14087fe41c3f8ad74` |
| `v2/crates/mcp/src/transport.rs` | `33e49cc51504abb121e62432197b9beb74b02906` |
| `v2/crates/mcp/src/lib.rs` | `68b7378a8d4f066f5c9ee2cf83429c5fa472aa5f` |
| `v2/crates/mcp/src/server.rs` | `4af059b9203ff8282ce517713cadcd339ac21a70` |

This record's own classification (§3, §4) was made against commit `54b9a3e` in this repository,
where every file above is current or newer.

**Official references the review checked** (they support narrow factual statements; the
architecture and tests are the review's proposals, not endorsed by these sources; recheck at
implementation and release):

- Tauri capability boundaries — https://v2.tauri.app/security/capabilities/
- Tauri native mobile plugins — https://v2.tauri.app/develop/plugins/develop-mobile/
- MCP authorisation security considerations — https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations
- RFC 9382 (SPAKE2), an example of a specified PAKE, not a selection — https://www.rfc-editor.org/rfc/rfc9382.html
- Apple background scheduling — https://developer.apple.com/documentation/BackgroundTasks/choosing-background-strategies-for-your-app
- Android persistent background work — https://developer.android.com/develop/background-work/background-tasks/persistent
- Apple device-bound key accessibility — https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly
- Android keystore — https://developer.android.com/privacy-and-security/keystore
- Windows named-pipe security and access rights — https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ipc/named-pipe-security-and-access-rights.md
- Windows named-pipe client process id — https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid
- Apple App Review Guidelines — https://developer.apple.com/app-store/review/guidelines/
- Google Play payments policy — https://support.google.com/googleplay/android-developer/answer/9858738

**Not done by anyone yet:** a CredMgr build or test run for this programme, device testing,
penetration testing, an independent cryptographic review, a mobile build, a deployment. The
independent security review of the new cryptographic and network boundary is a release gate (W7).

---

## Appendix A — the synthetic model

Save as `verify_design_model.py`, run `python3 -I verify_design_model.py`. Standard library only;
every value is synthetic. A review model, not application code.

```python
"""Synthetic design model only; not CredMgr code, crypto, storage or platform tests."""
from dataclasses import dataclass
from itertools import permutations
import hashlib, json

@dataclass(frozen=True)
class Op:
    id: str
    parents: tuple
    kind: str
    payload: str
    epoch: int = 1

class Replica:
    def __init__(self):
        self.ops = {'root': Op('root', (), 'put', 'synthetic-initial')}
        self.pending = {}
    def ingest(self, op):
        old = self.ops.get(op.id, self.pending.get(op.id))
        if old is not None:
            if old != op:
                raise ValueError('same-id-different-content')
            return
        self.pending[op.id] = op
        while True:
            ready = [k for k, v in self.pending.items()
                     if all(p in self.ops for p in v.parents)]
            if not ready:
                return
            for k in sorted(ready):
                self.ops[k] = self.pending.pop(k)
    def heads(self):
        consumed = {p for op in self.ops.values() for p in op.parents}
        return set(self.ops) - consumed
    def snapshot(self):
        return sorted(self.heads()), sorted(self.ops), sorted(self.pending)

checks = []
def record(name, cases):
    checks.append({'name': name, 'cases': cases, 'result': 'PASS'})

a = Op('a', ('root',), 'put', 'synthetic-A')
b = Op('b', ('root',), 'put', 'synthetic-B')
c = Op('c', ('a',), 'put', 'synthetic-A2')
d = Op('d', ('b',), 'delete', '')
e = Op('e', ('c', 'd'), 'resolve-put', 'synthetic-selected')
count = 0
for order in permutations((a,b,c,d,e)):
    for stream in (order, order + order, tuple(reversed(order)) + order):
        r = Replica()
        for op in stream:
            r.ingest(op)
        assert r.heads() == {'e'} and not r.pending and len(r.ops) == 6
        count += 1
record('causal convergence under ordering and duplicate delivery', count)

for order in permutations((a,b)):
    r = Replica()
    for op in order: r.ingest(op)
    assert r.heads() == {'a','b'}
record('concurrent secret edits both retained', 2)

for order in permutations((a,b,c,d)):
    r = Replica()
    for op in order: r.ingest(op)
    assert r.heads() == {'c','d'}
    assert {r.ops[x].kind for x in r.heads()} == {'put','delete'}
record('delete versus update remains an explicit conflict', 24)

r = Replica(); r.ingest(e)
assert r.heads() == {'root'} and 'e' in r.pending
record('missing parents do not apply early', 1)
r = Replica(); r.ingest(a); before = r.snapshot()
try:
    r.ingest(Op('a', ('root',), 'put', 'tampered'))
    raise AssertionError('collision accepted')
except ValueError:
    assert r.snapshot() == before
record('same operation id different content rejected', 1)

# Server epoch fencing is modeled as a serialized policy transition.
# Authentication and revocation proofs are deliberately NOT modeled.
for order in permutations(('upload','revoke')):
    epoch = 1; revoked = False; accepted = []; quarantine = []
    for event in order:
        if event == 'revoke': epoch = 2; revoked = True
        elif a.epoch != epoch or revoked: quarantine.append(a)
        else: accepted.append(a)
    assert (len(accepted),len(quarantine)) == ((1,0) if order[0]=='upload' else (0,1))
record('serialized revocation fences late old-epoch uploads', 2)

# Loss of a tombstone is safe only when generation fencing rejects old replicas.
for old_generation in range(1,5):
    minimum_generation = 5
    result = 'quarantine-and-rebootstrap' if old_generation < minimum_generation else 'apply'
    assert result == 'quarantine-and-rebootstrap'
record('retired replica generation cannot resurrect a tombstone', 4)

for request_order in permutations(('device-C','device-D')):
    enrolled = {'A','B'}; results = {}
    for device in request_order:
        if len(enrolled) < 3:
            enrolled.add(device); results[device] = 'accepted'
        else: results[device] = 'limit'
    assert len(enrolled) == 3 and sorted(results.values()) == ['accepted','limit']
record('atomic enrollment permits only one final slot', 2)

original = {'format':2,'required':['sealed-notes-v2'],'field':'synthetic','unknown':{'keep':7}}
for capabilities in (set(), {'legacy'}):
    before = json.dumps(original, sort_keys=True)
    allowed = set(original['required']) <= capabilities
    assert not allowed and json.dumps(original, sort_keys=True) == before
record('incompatible writer refuses before modifying bytes', 2)

# Adversarial negative controls: reproduce flaws the proposal must eliminate.
negative = []
lww = max(((100,'A'), (200,'B')))[1]
assert lww == 'B'  # Concurrent A disappears from the active value.
negative.append('last-writer-wins drops a concurrent credential revision')
slots_seen_by_C = slots_seen_by_D = 2
naive_count = 2 + int(slots_seen_by_C < 3) + int(slots_seen_by_D < 3)
assert naive_count == 4
negative.append('check-then-insert device enrollment admits four devices')
naive_live = {}; naive_live['entry'] = 'stale-offline-update'
assert 'entry' in naive_live
negative.append('purged tombstone without generation fence resurrects deleted entry')

result = {'scope':'abstract deterministic synthetic model, not application validation',
          'groups':checks, 'case_count':sum(x['cases'] for x in checks),
          'negative_controls':negative,
          'limitations':['No cryptography or authenticated protocol',
             'No actual concurrency: serial order enumeration only',
             'No disk transactions, mobile lifecycle, broker execution or network',
             'No proof of unbounded distributed convergence or security']}
print(json.dumps(result, indent=2))
```
