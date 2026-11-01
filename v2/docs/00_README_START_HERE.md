---
id: V2-000
classification: public
title: Start here
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21). Every factual claim in this document was checked against live
     source in that pass, but the corpus-wide hardening stamp is the operator's to assign after
     their own review, not this session's to self-award. The seven stamps that were carried here
     before this rewrite had all silently gone invalid — see §5. Updated 2026-09-24 for
     ADR-062…066 (42 ops, the bridge at 42/42, the live vault, the first unsigned release).
     Updated 2026-09-24 for ADR-070…073 (47 ops, the bridge at 47/47, ADR-001…ADR-073; the
     status line's CLI count corrected from 20 to the table's 21). Updated 2026-10-02 for ADR-074
     (ADR-001…ADR-074; the licence is MIT for everyone, and the licensing row of §2 is now the
     optional commercial-licence certificate) and the test count re-measured at 448 / 37 binaries (superseded 2026-10-02: 571 / 41).
     Updated 2026-10-02 for ADR-075…077 (48 ops with `maintenance.rotate_root`, the bridge at 48/48,
     25 broker error codes, 23 top-level CLI subcommands, ADR-001…ADR-077, the desktop app hosted on
     the precompiled design, tests re-measured at 571 / 41 binaries and the shell's own 156).
     Updated 2026-10-03 for ADR-078/079 (53 ops with `entry.get` and `field.*`, the bridge at 53/53 plus
     three shell commands, 15 MCP tools, 24 top-level CLI subcommands, ADR-001…ADR-079, every screen wired to
     the broker, tests listed at 813 / 50 binaries and the shell's own 186).
     Updated 2026-10-24 for ADR-083…089 (54 ops with `util.generate`, the bridge at 54/54, 26 top-level CLI
     subcommands with `generate` and `approve`, ADR-001…ADR-089; `privateNames`, `requireTwoFactor`, canonical
     names, field-edit undo, approval 4b and the K-7 follow-ups built; 15 MCP tools and 25 error codes unchanged).
     Updated 2026-10-26 for ADR-090/091 (55 ops with `vault.approval_get`, the bridge at 55/55, 27 top-level CLI
     subcommands with `approvals`, ADR-001…ADR-091). -->
> **Licence update, 2026-10-31 (`ADR-096`, supersedes `ADR-074`):** CredMgr is source-available under the FreexStudio Source-Available Licence 1.0 (`LICENSE`), not MIT. Wherever this document says "MIT" it records the earlier decision and is kept as history; the licence in force is the one in `LICENSE`.

# CredMgr V2 — "Vault Next" · start here

`CredMgr V2` · the index to the design corpus, and the contract every document in it follows · `2026-08-18`

> **Status.** The **backend is built and audited**: 55 broker ops, 15 MCP tools, 27 CLI
> subcommands, the workspace suite green (see `BUILD_LOG.md`'s latest entry for the current
> count). Since 2026-09-24 the running daemon opens its own vault — passphrase unlock, load from
> disk, write-through (`ADR-063`) — and the first packaged build, `2.0.0-alpha.6`, is an
> **unsigned**, Software-tier CLI-and-broker release (`v2/RELEASE.md`, K-5); the build in progress
> is `2.0.0-beta.1`. Entries hold **several fields** (`ADR-078`) and a vault made by `credmgr init`
> can **seal and restore** a project across restarts (`ADR-079`). The **desktop application is built
> and wired**: `v2/apps/desktop/` hosts the KEEP design, precompiled and served under the strict CSP
> (`ADR-075`), and a command bridge reaches all 55 broker ops (`ADR-057`, `ADR-062`, `ADR-076`,
> `ADR-078`, `ADR-087`, `ADR-090`); every screen reads from the broker and every change goes to it — first run, unlock with
> the second factor, the graph and inspector, entries with their fields, the review tray, nodes, grants,
> the audit trail and maintenance. Five operations are sent for real and refused with `presence_required`
> until a presence transport exists (`10 §4.2`). What is *not* done is the real-app verification pass
> (`RELEASE_VERIFICATION.md`), signing and notarisation (K-5), and presence (Touch ID, K-1). The
> **organisation vault and sync, and an optional commercial-licence certificate, are designed but
> unbuilt**. The licence itself is settled: **MIT for everyone, organisations included, with
> nothing gated by payment** (`ADR-074`). This corpus describes all three states and labels which
> is which on every subsystem it touches; §2 is the honest map, and nothing marked `planned` below
> is written anywhere in this corpus as though it exists.

---

## 1. What this is

The complete design for a **node-scoped credential and privacy vault**, and the record of every
decision that produced it.

**The one-sentence change from V1:** in V1 a project is a label; in V2 a node is a boundary.
A label organises; a boundary *enforces*. Everything else in this corpus follows from taking that
seriously — the key hierarchy (`04`), the access rules (`06`), the isolation suite (`13`), and the
reason there is no migration (`11`).

V1 remains the running system and is untouched by this project. It is not modified, read, or
imported by any V2 code path; `11_MIGRATION.md` explains why that is a decision rather than an
omission.

## 2. What exists today — the honest map

Every subsystem below carries one of three words, used consistently throughout the corpus and
defined in `ADR-059`: **`built`** (exists and is covered by a passing test), **`partial`** (exists
but does not yet do everything its document specifies), **`planned`** (does not exist in any form).

| Subsystem | Status | Evidence |
|---|---|---|
| Envelope crypto (versions 1 and 2), node keys, durable seal/restore, the orphan cold key | `built` | `crates/core/`, `crates/keystore/`, `ADR-078`, `ADR-079`, `crates/brokerd/tests/seal_durable.rs` |
| Multi-field entries — the field document, `entry.get`, `field.*` | `built` | `ADR-078`, `crates/core/src/fields.rs`, `crates/brokerd/tests/field_model.rs` |
| Storage, manifests, generation counter | `built` | `crates/store/` |
| Broker, 55 ops, access resolution | `built` | `crates/brokerd/src/ops.rs` |
| Root-key rotation, crash-safe (`maintenance.rotate_root`) | `partial` | `ADR-076`, `crates/brokerd/tests/rotate_root.rs`; built and tested directly, but on the wire it answers `presence_required` until presence can be attested |
| Live vault — passphrase unlock, load from disk, write-through | `built` | `ADR-063`, `crates/brokerd/src/state/durable.rs`, `durable_vault.rs` |
| CLI, 27 top-level subcommands | `built` | `crates/cli/src/main.rs` |
| MCP server, 15 tools | `built` | `crates/mcp/src/tools.rs` |
| Two-factor gate (TOTP + recovery codes), persisted, with the last door | `built` | `crates/brokerd/`, `phase5_gate.rs`, `durable_vault.rs` (`ADR-064`) |
| Session login (`vault.unlock` mints a real token that reaches every node but Orphaned) | `built` | `ADR-056`, `ADR-065`, `session_login.rs`, `durable_vault.rs` |
| Node isolation suite | `partial` | `isolation.rs` runs I-1…I-25 and I-27…I-29 (27 tests; I-26 was never written); **I-10 is implemented nowhere** — accepted risk K-1 |
| Cross-platform keystore | `partial` | trait + macOS path built; Windows and Linux backends designed, see `16` |
| Desktop application (screens) | `built` | the KEEP design, precompiled and hosted under the strict CSP (`ADR-075`, `apps/desktop/`); every screen goes through the broker, with no demo data and no local-only write path in a release build — see `09`, `19`, and `RELEASE_VERIFICATION.md` for the control-by-control map (its real-app result column is filled by the verification pass, so the claim is `built`, not yet `verified in the real app`) |
| Tauri↔broker command bridge | `built` | all 54 ops reachable from `invoke()` (`ADR-057`, `ADR-062`, `ADR-078`) plus three shell commands (`entry_copy`, `copy_text`, `fields_preview`), a typed client `apps/desktop/src/lib/bridge.ts`, a real CSP, a concealed clipboard and lock-on-sleep in the shell; the shell's suite lists 186 tests, in CI. Until 2026-09-24: 8 of 40 |
| Organisation vault, departments | `planned` | `22` |
| Pairing-code sync between vaults | `planned` | `22` |
| Optional commercial-licence certificate (offline-verifiable; gates nothing) | `planned` | `22 §4.4`, `ADR-074` |
| Release signing and update channel | `planned` | `21`. A minimal unsigned path is `built`: `scripts/release.sh` (tarball + `SHA256SUMS`) and `credmgr --version`/`credmgrd --version` — K-5 |

**The counts are load-bearing and were re-derived from source on 2026-10-26**, not carried
forward: 55 broker ops (counted with `tools.corpus_check.broker_ops()`, never a grep —
ADR-064 added `vault.gate_recover`, ADR-066 `node.set_workdirs`, ADR-071…073 `node.update`,
`node.policy`, `notes.read`, `notes.write` and `entry.create_batch`, ADR-076
`maintenance.rotate_root`, ADR-078 `entry.get` and `field.add`/`update`/`remove`/`reorder`, ADR-087
`util.generate`, and ADR-090 `vault.approval_get`), 15 MCP
tools (ADR-078 added `credmgr_get_metadata` and `credmgr_field_add`/`_update`/`_remove`), 27 top-level
CLI subcommands (ADR-078 added `field`; 2026-10-24 `generate` and `approve`; 2026-10-26 `approvals`), ADR-001…ADR-091 (ADR-083…089 the
2026-10-24 backend wave: private names, canonical names, per-node second factor, field-edit undo, the
generator, approval 4b, the K-7 follow-ups; ADR-075 the front-end hosting, ADR-076 the
root-key rotation, ADR-077 the audit actor, `node_locked` and the 80-bit TOTP floor, ADR-078 the field model,
ADR-079 the K-7 remainder; ADR-057 and ADR-062 from the bridge track; ADR-061 from the
vault-bootstrap track, which added `vault.init_begin` and `vault.init_confirm`; ADR-063…066 from
the live-vault work; ADR-067…069 from its review — the envelope digest, the refused dead token,
the durable tray; ADR-070…073 from the design side's handoff — the one-hour backoff cap, node
rename and policy patch, notes, the batch create; ADR-074 the licensing decision —
MIT for everyone, 2026-10-01), 25 broker error codes (ADR-077 added `node_locked`; ADR-078 and ADR-079 added
none), isolation tests I-1…I-25 (except the unimplemented I-10) and I-27…I-29.
`cargo test --workspace -- --list` lists 813 tests in 50 test binaries (45 compiled test executables plus
five doc-test targets that find no doc test), counted 2026-10-03; the last full pass/fail run recorded is 571
passing, 0 failing, in 41 test binaries (2026-10-02; 406 passing on 2026-09-13; 443 on 2026-09-24; 448 in 37
binaries after ADR-070…073, re-measured 2026-10-01), and the run on this tree is the orchestrator's gate in
`BUILD_LOG.md`. The desktop shell's own suite, run outside the workspace count, lists 186 tests in 12 test
executables. The desktop front end (`apps/desktop`): `npm test` runs 550 unit tests in 21 files;
`npm run test:e2e` lists 552 end-to-end tests (276 specs, each in WebKit and Chromium); `npm run test:real` lists
66 end-to-end tests over the real broker. Where any document states one of these numbers it states this one.

## 3. Read in this order

| # | Document | Read it when | State |
|---|---|---|---|
| **01** | [Concept](01_CONCEPT.md) | Always first. The model, the four promises, and what is deliberately deleted. | `built` model |
| **02** | [Architecture](02_ARCHITECTURE.md) | Before any code. Processes, crates, the transport. | `built` |
| **03** | [Data model](03_DATA_MODEL.md) | Building storage, entries, the registry. | `built` |
| **04** | [Cryptography & keys](04_CRYPTO_AND_KEYS.md) | Anything that touches a secret. | `built` |
| **05** | [Threat model](05_THREAT_MODEL.md) | Before arguing any security decision. Adversaries, and the accepted risks. | `built` |
| **06** | [Access graph](06_ACCESS_GRAPH.md) | Grants, capabilities, the R0–R8 resolution rules. | `built` |
| **07** | [Two-factor](07_TWO_FACTOR.md) | The gate, enrolment, recovery codes. | `built` |
| **08** | [Field model](08_FIELD_MODEL.md) | Entry fields, sensitivity, inference. | `built` — the broker side ships (`ADR-078`) |
| **09** | [UI/UX spec](09_UI_UX_SPEC.md) | Building any screen. | `built`, pending the real-app pass |
| **10** | [API & MCP](10_API_AND_MCP.md) | The wire format and the op surface. | mixed — read its status column |
| **11** | [Migration](11_MIGRATION.md) | Before assuming V1 data moves. It does not. | decided |
| **12** | [Build plan](12_BUILD_PLAN.md) | Phase sequencing and exit gates. | phases 0–4, 7, 8 closed; 5 partial |
| **13** | [Test plan](13_TEST_PLAN.md) | Writing or judging a test. | `built` |
| **14** | [Decisions](14_DECISIONS.md) | Whenever "why is it this way" comes up. ADR-001…ADR-079; the next is ADR-080. | record |
| **15** | [Pass 2 review](15_PASS2_REVIEW.md) | The adversarial review record. | record |
| **16** | [Cross-platform](16_CROSS_PLATFORM.md) | Windows or Linux work. | `partial` |
| **17** | [Airlock & LLM](17_AIRLOCK_AND_LLM.md) | Anything an agent or model can reach. | `built` |
| **18** | [Endpoint index](18_ENDPOINT_INDEX.md) | Mapping a V1 route to its V2 op. | mixed — read its status column |
| **19** | [Frontend delivery scope](19_FRONTEND_DELIVERY_SCOPE.md) | Scoping the UI hand-off. | `partial` |
| **20** | [Theming](20_THEMING.md) | Colour, mode, the graph's visual language. | `planned` |
| **21** | [Release & integrity](21_RELEASE_AND_INTEGRITY.md) | Shipping a build. | `planned`, with a minimal unsigned path `built` |
| **22** | [Org vault, sync & licensing](22_ORG_VAULT_SYNC_AND_LICENSING.md) | The organisation product, and what remains of licensing (MIT; `ADR-074`). | `planned` |

`PHASE8_AUDIT_REPORT.md` sits alongside these as the record of the final backend audit, including
the accepted risks K-1…K-8 (K-3 since closed, K-7 closed by `ADR-079` apart from its factor-bearing half;
K-5…K-7 added 2026-09-24) that this corpus does not re-litigate. `RELEASE_VERIFICATION.md` is the
checklist of the real-app pass: every screen and control of the shipped app, the bridge command and broker
op behind it, and the result expected — its results column is empty until a person has run the app.

## 4. How this corpus is written

Every document follows the same contract, so that 25 documents read as one system.

### 4.1 Three questions, never blurred

Each document answers, in order: **what is this part of the system and why is it this way**
(timeless, no status), **what exists today** (`built`/`partial`, with evidence), and **what is the
finished thing, in full** (`planned`, designed completely, claimed nowhere).

**A `planned` subsystem is never written in the present tense** (`ADR-059`). Not "the org vault
syncs over a pairing code" — that reads as shipped. "Will sync", "is designed to sync", "the
target design is". A reader who cannot tell design from implementation can use the document for
neither purpose.

### 4.2 Mandatory sections

Every document ends with two:

- **`## Connections`** — a table of real dependencies, each row citing `NN_NAME.md §S`. This is
  how the corpus states how its parts connect, and it is machine-checked: the JSON sibling
  extracts exactly that shape and `tools/corpus_check.py crossrefs` proves every cited section
  exists.
- **`## Source`** — where every claim in the document can be re-checked: the ADRs behind it, the
  code that implements it, the tests that prove it, and the job file behind its figure.

### 4.3 Figures

A figure is specified by a **figure brief** at the point it belongs — naming the reader question,
the one claim the figure must carry, the engine (`tools/ENGINE_ROUTING_POLICY.md` decides which),
and the **real source** of its content. A brief that cannot cite a real source says so and marks
the figure illustrative. No figure in this corpus carries an invented number: once rendered,
nobody can tell an invented number from a sourced one.

Authoring artifacts live beside their document as `<stem>_spec.json` and nowhere else
(`ADR-060`) — the one time this project kept a figure's job in two places, the two copies had
already drifted within a single session.

### 4.4 What never appears

Real emails, brands, domains, hostnames, usernames or absolute home paths; loopback and private
network literals; and any number that was not verified against source. The first two are enforced
mechanically (§5), the third by the discipline of citing evidence for every count.

## 5. How this corpus is verified

Four independent mechanisms, because prose review alone has repeatedly failed here.

1. **`tools/corpus_check.py`** — three checks. `endpoints` proves every op named in
   `18_ENDPOINT_INDEX.md` exists and every op the broker dispatches is documented. `crossrefs`
   proves every `NN_NAME.md §S` reference resolves. `stamps` proves every `artifact-hardened`
   stamp still matches the body it names.
2. **`tools/docgen`'s nine gates**, run on every document build: classification, secret-value,
   PII/path/internal, implementation-internal, manifest drift, WCAG contrast, variant overlap.
3. **`v2/scripts/guard-no-personal-data.mjs` and `v1/scripts/guard-no-secrets.mjs`**, in the
   pre-commit hook and in CI.
4. **The stamp contract.** A document is source-of-truth only while its `artifact-hardened` stamp
   matches its body. **This is the mechanism that had quietly failed**: before this rewrite, seven
   documents — including `14_DECISIONS.md` and `PHASE8_AUDIT_REPORT.md` — carried `Approved`
   stamps whose bodies had changed since the commit each named. None of them was actually
   source-of-truth, and nothing detected it, because nothing checked. Check 1 now does.

**A green gate is not a correct artifact.** A figure once shipped as visible escaped source
through every gate, because no gate asserted that a figure had appeared. Verify the output, not
the exit code.

## 6. The security chain, end to end

The operator asked that security be explained as one connected thing rather than five documents
that each assume the others. It is one chain, and it reads in this order:

1. **`04_CRYPTO_AND_KEYS.md`** establishes the material: a root key wrapped by the platform
   keystore, and one X25519 keypair per node. Nothing is encrypted to a user; everything is
   encrypted to a node.
2. **`06_ACCESS_GRAPH.md`** decides who may reach which node, via the R0–R8 resolution rules.
   Because keys are per-node, a grant is not advisory — an unreachable node's ciphertext cannot be
   opened at all.
3. **`07_TWO_FACTOR.md`** gates the moment the node keys enter memory. The gate is on *unlock*,
   not on each read, because the threat it answers is a stolen vault directory, not a mistyped
   command.
4. **`05_THREAT_MODEL.md`** states which adversaries the above defeats, and — the part that gives
   the rest its credibility — which it does not: the accepted risks AR-1…AR-6, each named, bounded
   and owned rather than quietly omitted.
5. **`17_AIRLOCK_AND_LLM.md`** closes the last surface: rules A-1…A-6, of which A-1 (no outbound
   network, ever) is the one the whole agent story rests on. An LLM reaches this vault through the
   MCP tool surface or not at all.

Read those five in that order and the security model is complete. Read any one alone and it is
not — which is why each of them carries a `## Connections` table pointing at the others.

<!-- figure:security-chain -->

The four edges above are real rows pulled from the five documents' own `## Connections` tables —
`04_CRYPTO_AND_KEYS.md §10`, `06_ACCESS_GRAPH.md §11`, `07_TWO_FACTOR.md §9`,
`05_THREAT_MODEL.md §10` — not a hand-drawn impression of how they relate. Each of the five also
names further connections into the wider corpus (`10_API_AND_MCP.md`, `13_TEST_PLAN.md`,
`22_ORG_VAULT_SYNC_AND_LICENSING.md` among them); this figure draws only the chain the claim above
is about, not every edge each document carries.

## 7. Connections

| Direction | Document | What flows across |
|---|---|---|
| feeds | `01_CONCEPT.md §1` | the node-as-boundary model this index summarises in one sentence |
| feeds | `12_BUILD_PLAN.md §0` | the phase status this index reports as closed |
| depends on | `14_DECISIONS.md` | `ADR-058` (this document's own header contract), `ADR-059` (the status vocabulary §2 and §4.1 use), `ADR-060` (the figure-artifact rule §4.3 states) |
| depends on | `05_THREAT_MODEL.md §7` | the accepted risks AR-1…AR-6 that §6's chain ends on |
| depends on | `PHASE8_AUDIT_REPORT.md` | the accepted risks K-1…K-8, including the I-10 gap §2 reports |
| feeds | `RELEASE_VERIFICATION.md` | the screens and controls whose real-app result that checklist records |

## 8. Source

**Design.** `ADR-058` (header contract), `ADR-059` (status vocabulary), `ADR-060` (figure
artifacts). The corpus-wide convention this document states in §4 is those three ADRs in prose.

**Code.** The counts in §2 come from `crates/brokerd/src/ops.rs` (53 dispatched ops, counted
with `tools.corpus_check.broker_ops()`), `crates/mcp/src/tools.rs` (15 registered tools), and
`crates/cli/src/main.rs` (24 top-level match arms — counting every nested
`node`/`grant`/`gate`/`pending`/`notes`/`field` arm as well gives 47 by `10 §2.1`'s method; earlier counts in this
corpus disagreed because they mixed methods).

**Tests.** `cargo test --workspace -- --list` reports 813 tests in 50 test binaries (45 test
executables — 44 of them carry tests — plus five doc-test harnesses that find no doc test), counted
2026-10-03; the last full pass/fail run recorded is 571 passing, 0 failing, 41 binaries (2026-10-02) and the
gate run on this tree is in `BUILD_LOG.md`. The desktop shell's own suite (`apps/desktop/src-tauri`, outside the
workspace) lists 186 tests in 12 test executables. Earlier dated figures: 571 passing in 41 binaries (2026-10-02); 448 passing, 0
failing, 37 test binaries, exit code 0 (2026-09-24, re-measured 2026-10-01); 406 passing, 35 test
binaries on 2026-09-13 (run 34743281942); 397 passing, 33 test binaries on 2026-08-18.
`crates/brokerd/tests/isolation.rs` for I-1…I-25 (the comment records I-10 as
unimplemented) and I-27…I-29.

**Verification.** `tools/corpus_check.py` (endpoints, crossrefs, stamps);
`tools/docgen/tests/` (52 tests — `grep -rn "def test_" tools/docgen/tests/*.py`, 2026-09-24).

**Figure.** `security-chain` (§6): `v2/docs/00_README_START_HERE_spec.json`, `kind: "flowchart"`,
rendered by `tools/docgen/visual.py` — the first `docgen`-native structural figure built for this
project (`tools/ENGINE_ROUTING_POLICY.md` §"What is not decided here" named this as the natural
next proof). Its four edges are drawn from `04_CRYPTO_AND_KEYS.md §10`, `06_ACCESS_GRAPH.md §11`,
`07_TWO_FACTOR.md §9` and `05_THREAT_MODEL.md §10` — each document's own `## Connections` table,
re-read for this build on 2026-08-23, not re-derived from memory.
