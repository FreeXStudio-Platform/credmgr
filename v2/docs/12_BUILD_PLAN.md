---
id: V2-012
classification: public
title: Build plan
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-10-31
---

<!-- artifact-hardened: Approved With Known Risks @ 3d8545f on 2026-10-31 via three-pass-v1. Evidence: every gate green on the code at 34542f8 (workspace 910 tests in 59 binaries, desktop bridge 202, endpoint matrix 55/55 operations and 243 rows, clippy, fmt, cargo deny, cargo audit, desktop unit, e2e and real-daemon suites, strict public export PASS); final adversarial audit v2/docs/release-verification/AUDIT_2026-10-31.md (the P0 and both P1 fixed, re-verified twice); known risks K-1 to K-19 in v2/docs/PHASE8_AUDIT_REPORT.md sections 4 and 7, each with bound, owner and resolution. Known risks that bear on this document: K-12 GitHub CI has not run on this release (billing); K-14 the idle lock and a real sleep or screen lock were not exercised by hand on this build; K-19 a seed in an unrecognised shape is not protected until its owner types it. Not a claim about anything after 3d8545f. -->
# Build plan — empty repo to shipped organisation product

`CredMgr V2` · every phase, what closed, what only partly closed, and what remains after the UI lands · `2026-10-31`

> **Status (re-checked against `main` at `b94443c`, 2026-10-31).** Phases 0–4, 7 and 8 are **closed with cited
> evidence**; the whole backend chain ran to completion and `v2/.build-complete` exists. Phase 5 is **partial**
> and this document has said so since its 2026-08-18 rewrite: gate 2FA, TOTP items and the MCP registry are
> built and tested, but of its seven exit-gate lines two are fully met, three are partial and two were never
> started — the hardware keystore tiers and the per-platform tier report. (A third line was unmet in the
> 2026-08-18 pass — a gate re-enrolment path no test exercised — and was met on 2026-09-24 by the last door,
> `ADR-064`.) `ADR-046` required exactly this reporting. Phase 6 (the UI) was not built by this chain;
> `v2/apps/desktop/` hosts the finished design, precompiled under the strict CSP (`ADR-075`), with every screen
> wired to the broker — reads and writes — over a **built** command bridge reaching all 55 broker ops
> (`ADR-062`, `ADR-078`, `ADR-087`, `ADR-090`). Its exit gate is **partly met**: the real-app pass was walked by a
> person on 2026-10-18 (190 rows pass, 7 fail, 85 not pressed; no P0) and its B20 merge re-walked in the built
> `.app` on 2026-10-31 (`RELEASE_VERIFICATION.md` §8, §13), the real-daemon journey suite exists and its drift
> guard passes (`npm run test:real:drift`, 44 tests, run 2026-10-31), but §4 lists the gate lines no test or recorded run evidences. **Phases 9–12 —
> integration, native platform completion, release, and the organisation product — are not fully built.**
> Phase 9 is mostly done (the bridge, the wired screens, the end-to-end suites); Phase 11's unsigned
> release path covers the command-line tarball, the desktop app bundle, the bills of materials, `--verify` and a
> fresh-install check (`scripts/release.sh`, `release-app.sh`, `fresh-install-check.sh`; K-4, K-5) and produced
> 2.0.0-beta.1 rehearsal artefacts; signing, notarisation, self-integrity and the updater are not built (GitHub
> issue #28, milestone `2.0.0`). Presence (#18) and the Secure Enclave tier (#19) are `2.0.0-rc.1`; the Windows and
> Linux keystores (#29) and the organisation vault (#30) are `2.0.0`. §5 designs the rest in full and claims none
> of it. Evidence for every `built` marking is a file path and a test name in that phase's own section; the suite
> behind them is `cargo test --workspace`: **905 tests listed in 59 test binaries on 2026-10-31** (`cargo test
> --workspace --locked --offline -- --list` on the pinned 1.78 toolchain; the 59 count includes five doc-test
> binaries). The last full *run* recorded in `BUILD_LOG.md`: 900 passing, 0 failing, 59 binaries on 2026-10-26
> (820/50 on 2026-10-19, 813 listed/50 on 2026-10-03, 571 passing/41 on 2026-10-02, 448/37 on 2026-09-24, 406/35
> on 2026-09-13); the batch-2 commit `a73446b` (2026-10-30) records the workspace tests passing without a count.
> The desktop's own checks are separate invocations: 703 unit tests (26 files, run 2026-10-31), 664 Playwright tests
> listed (both engines) and 80 real-daemon journeys listed, 202 bridge tests listed in `apps/desktop/src-tauri`,
> a design audit of 87 states (`PRODUCTION_PLAN.md`, 2026-10-30; not re-run).
> GitHub-hosted CI has not run green since the account's billing block (issue #33): the `security` runs on `main`
> fail in seconds, `build.yml` is dispatch-only and was not dispatched in batch 4, and only the
> self-hosted `workspace-tests` job passes (its `promotion-readiness` job fails by design until issue #3 closes).

---

## 0. Where the plan stands — the phase ledger

Every row was checked against source in this pass. The vocabulary is the corpus-wide one
(`ADR-059`): **`built`** means it exists and a passing test covers it; **`partial`** means it
exists but does not do everything this document specifies; **`planned`** means it does not
exist in any form.

| Phase | Status | What the evidence is |
|---|---|---|
| 0 · Toolchain and skeleton | `built` | `v2/Cargo.toml` (6 members), `rust-toolchain.toml`, `deny.toml`, and the repo-root `.github/workflows/{build,security,selfhosted-heavy-check,selfhosted-smoke-test}.yml` (GitHub-hosted jobs blocked by billing, issue #33) |
| 1 · Core primitives | `built` | `crates/core/`; `tests/access_matrix.rs`, `tests/properties.rs`, `tests/isolation_i17.rs` |
| 2 · Storage and registry | `built` | `crates/store/` (15 modules, unit-tested in place); `isolation.rs::i19_…`, `::i20_…`, `::i21_…` |
| 3 · Broker | `built` | `crates/brokerd/`; `tests/phase3_exit_gate.rs`, `tests/isolation.rs` |
| 4 · CLI | `built` | `crates/cli/`; `tests/broker_integration.rs`, `tests/no_secret_in_argv.rs`, `tests/emergency_decrypt.rs` |
| 5 · 2FA and the native shell | **`partial`** | built: `tests/phase5_gate.rs`, `tests/phase5_totp_items.rs`, `tests/durable_vault.rs`, `crates/mcp/tests/i13_tool_registry.rs`. **2 of 7 gate lines fully met** (gate re-enrolment after device loss met 2026-09-24, `ADR-064`) — unbuilt: the three hardware keystore tiers, the per-platform tier report (`ADR-046`, and §2.6). The second factor is one vault-wide gate; a per-node secret is deferred to `2.0.0` (`ADR-093`, issue #16) |
| 6 · UI | **`partial`** | `v2/apps/desktop/` hosts the precompiled design (`ADR-075`) and every screen is wired to the broker; 703 front-end unit tests, 664 Playwright tests listed, 80 real-daemon journeys, a design audit probe (87 states); the human checklist was walked 2026-10-18 (190 pass, 7 fail, 85 not pressed) and the B20 merge re-walked 2026-10-31 (`RELEASE_VERIFICATION.md` §8, §13); gate lines not evidenced remain (§4); open P2/P3 findings are issues #23–#27 (`2.0.0-rc.1`) |
| — · Tauri↔broker bridge | `built` | `apps/desktop/src-tauri/src/commands.rs`, 55 of 55 ops (`ADR-057`, `ADR-062`, `ADR-078`, `ADR-087`, `ADR-090`) plus four shell commands; 202 tests listed (2026-10-31), in CI as `security.yml` → `v2-desktop-bridge` |
| 7 · Hardening and closeout | `built` | `crates/cli/tests/success_criteria.rs`; `BUILD_LOG.md` Session 15; `v2/.phase7-gate-green` |
| 8 · Final adversarial audit | `built` | `docs/PHASE8_AUDIT_REPORT.md`, **Approved With Known Risks**; `v2/.build-complete` |
| 9 · Integration | `partial` | the bridge is built (`ADR-062`) and the screens are wired to it; the end-to-end flows against a real vault (80 journeys) and the human checklist (2026-10-18, 2026-10-31) now exist; still missing: the performance budget measured, and the rows the checklist marks fail or not pressed (§5.1) |
| 10 · Native platform completion | `planned` | nothing exists (§5.2). Presence / Touch ID is `2.0.0-rc.1` (#18), the Secure Enclave tier `2.0.0-rc.1` (#19), the Windows and Linux keystores and the named-pipe transport `2.0.0` (#29) |
| 11 · Release and integrity | `partial` | an unsigned path: `scripts/release.sh` (deterministic tarball, CycloneDX bills of materials, `SHA256SUMS`, `--verify`), `scripts/release-app.sh` (ad-hoc sealed `CredMgr.app`, `.dmg`, `.zip`), `scripts/fresh-install-check.sh`, a prepared Homebrew formula; workspace, desktop app and bundle all at `2.0.0-beta.1`, rehearsal artefacts built and verified 2026-10-18 (`dist/`); signing, notarisation, self-integrity and the updater are `planned`, milestone `2.0.0` (#28; §5.3, K-4, K-5) |
| 12 · Org vault, sync, licensing | `planned` | nothing exists (§5.4); milestone `2.0.0` (#30) |

**Two corrections this rewrite makes to its own previous text.**

1. **Phase 5 was reported as closed and is not.** `ADR-046`'s Consequence paragraph is explicit:
   *"Phase 5's exit gate is partially closed, and must be reported that way, not rounded up."*
   The build chain moved past Phase 5 legitimately — the plan's own sequencing rule says phases
   4, 5 and 6 are independent — but a moved-past phase is not a met gate. §2.6 lists which
   lines hold and which do not.
2. **Phase 0's CI workflows are not under `v2/`.** `v2/.github/` contains no files; the two
   workflows live at the repository root and are shared with `v1/`, because GitHub Actions only
   reads workflows from the real repository root. The previous text listed them as a Phase 0
   deliverable without saying where, which cost a later session real time to re-derive
   (`BUILD_LOG.md` Session 15, trap 2).

<!-- figure:build-phase-ledger -->

The two chains read left to right: the closed backend chain (top) carries one partial phase and a
built bridge; the chain below it holds the UI, integration and release phases, which are partial,
and the two phases that have not started, blocked by two different kinds of thing, none of which is
more engineering effort. Every status and count in the figure was the one in §0's table when it was
rendered (2026-10-02), re-derived from live source for the figure rather than copied — see the
figure's own caption and §10 "Source" for exactly which files. **It is stale on 2026-10-31**: it shows the bridge at 48
of 48 (now 55 of 55), and the UI and integration phases as they stood before the 2026-10-18 real-app pass. §0's
table is the record; the figure was not re-rendered in this pass.

---

## 1. How to run this plan

These rules are the plan's operating contract and have not changed since Pass 1. They are
stated without status because they are procedure, not code.

- **One phase per session.** Each phase has an explicit exit gate. A phase is not done until
  its gate passes with cited evidence — a file path plus a test result, a command's captured
  output, or a live check. Compiling is not evidence. No phase begins before the previous
  phase's gate is green.
- **A gate line that cannot be met is reported unmet, never rounded up.** This is the single
  rule the plan has already had to enforce against itself: `ADR-046` closed the part of Phase 5
  it could actually build and named the rest as unbuilt rather than stubbing it, and §2.6 below
  now carries that verdict into this document, which until this rewrite did not.
- **`crates/core` is written test-first.** It is pure and I/O-free, so there is no excuse.
- **Nothing touches any pre-existing vault, ever.** V2 creates and uses its own
  (`11_MIGRATION.md §1`).
- **Every phase ends with a portfolio checkpoint** (the session-closeout contract in the
  portfolio rules, referenced and not restated here).
- Read `00_README_START_HERE.md` and the phase's listed documents before writing code. Do not
  re-derive a decision that is already in `14_DECISIONS.md`; if it is wrong, supersede it with
  a new ADR rather than diverging quietly.

**Stack.** The core, broker, CLI and MCP server are **Rust**; the desktop shell is **Tauri 2**;
the UI is the KEEP design, precompiled to React 19 + Vite 8 + TypeScript (`ADR-075`; Svelte 5 was
the plan until the design arrived). `16_CROSS_PLATFORM.md §2` is the authority and supersedes ADR-008. Anything
in this corpus that reads like Node in a V2 build context is a leftover — `crates/`, never
`packages/`. The one deliberate exception is `v2/scripts/emergency-decrypt.mjs` (§2.5), which
is Node on purpose.

## 2. The construction phases — Phase 0 to Phase 5

These are the six phases that built the backend. Phase 6 comes next in the numbering and is not
part of this chain at all — it has its own section (§4) — so the autonomous build's real path was
`0 → 1 → 2 → 3 → 4 → 5 → 7 → 8`, and §3 is where it ended.

### 2.1 Phase 0 · Toolchain and skeleton — **`built`**

**Built.** The Cargo workspace (`crates/{core,store,keystore,brokerd,cli,mcp}`) with a pinned
`rust-toolchain.toml` at MSRV 1.78; `apps/desktop` as a Tauri 2 + Svelte 5 + Vite + TypeScript
scaffold (since replaced by the hosted design, `ADR-075`) held in **its own workspace**, deliberately
excluded from the MSRV pin (`ADR-035`);
`deny.toml`; the two CI workflows at the repository root; and the secret guard with its
pre-commit hook.

**Exit gate — met.**
- [x] `cargo build --workspace --locked` succeeds. The CI matrix in `.github/workflows/build.yml` is two jobs: the
      crates workspace on `{macos-14, ubuntu-22.04}` × `{1.78.0, stable}` (the `windows-latest` leg was removed
      2026-09-24: the broker and the MCP transport are Unix-socket only until the named-pipe transport exists, issue #29),
      and the desktop app on `{macos-14, windows-latest, ubuntu-22.04}`. `build.yml` is dispatch-only; its last
      dispatch is not in the batch-4 evidence (GitHub-hosted jobs are blocked by billing, issue #33).
- [x] The Tauri scaffold opens a window on the host platform.
- [x] `node scripts/guard-no-secrets.mjs --all` clean; hook installed. A second guard,
      `scripts/guard-no-personal-data.mjs`, was added later and runs the same way.
- [x] `cargo deny check` and `cargo audit` clean and wired into `.github/workflows/security.yml`.

### 2.2 Phase 1 · Core primitives — **`built`**

**Built.** `crates/core`: the CMV2 envelope format, X25519 + HKDF + ChaCha20-Poly1305
seal/open, key wrapping, the registry types and their invariants, the access-graph `resolve()`,
the bulk parser and type inference. The crate is pure and I/O-free and carries
`#![forbid(unsafe_code)]`.

**What it deliberately does not contain, and why it matters later.** There is **no signature
primitive** — the dependency set (`crates/core/Cargo.toml`) is `base32`, `chacha20poly1305`,
`hkdf`, `hmac`, `rand_core`, `secrecy`, `serde`, `serde_json` (ADR-078), `sha2`, `totp-rs`,
`unicode-normalization` (ADR-084), `x25519-dalek`, `zeroize` and
`zeroize_derive` (re-read from `crates/core/Cargo.toml` 2026-10-31) — with no Ed25519 or other public-key signing anywhere in it. (`x25519-dalek`
and `zeroize` supply the X25519 keypair material and hot-buffer zeroisation this same section
credits above; they are key-agreement and hygiene primitives, not signing ones.) Two later
phases need a signature primitive (§5.3 release signing; §5.4's optional commercial-licence
certificate), so introducing one is real work with a real MSRV constraint, not a line of
configuration.

**Read first:** `03_DATA_MODEL.md §1`, `04_CRYPTO_AND_KEYS.md §1`, `06_ACCESS_GRAPH.md §1`,
`08_FIELD_MODEL.md §3`.

**Exit gate — met.**
- [x] Seal/open round-trips for 1 KiB, 1 MiB, binary, UTF-8 and empty payloads.
- [x] Cross-node decrypt fails for every A ≠ B (property test).
- [x] AAD binding: relocated and swapped envelopes fail (`04_CRYPTO_AND_KEYS.md §8`).
- [x] `resolve()` matches every cell of the matrix in `06_ACCESS_GRAPH.md §2`
      (`crates/core/tests/access_matrix.rs`, table-driven).
- [x] `resolve()` default-denies on malformed or unknown input
      (`crates/core/tests/properties.rs`, `crates/core/tests/isolation_i17.rs`).
- [x] The parser is lossless on random inputs and matches every row of
      `08_FIELD_MODEL.md §3`.
- [x] The dependency set matches `16_CROSS_PLATFORM.md §2`; `cargo deny` and `cargo audit` clean.
- [x] `cargo clippy -- -D warnings` clean.

### 2.3 Phase 2 · Storage and the registry — **`built`**

**Built.** The on-disk layout of `02_ARCHITECTURE.md §7`, atomic writes, manifests, registry
HMAC and cross-binding, the hash-chained audit log, the 7-day archive, the external generation
counter and `doctor --rebuild-registry` with its diff, plus the backup primitive
(`create_backup`, `maintenance.backup`). **Automatic backup scheduling is not built**: nothing in `crates/brokerd` has a
timer, so no backup fires daily or before a destructive operation (`ADR-039`; `04_CRYPTO_AND_KEYS.md §7`). Fifteen
modules in `crates/store/` (plus `lib.rs`), each unit-tested in place rather than through an integration
directory (`crates/store/tests/` holds one golden test, `alpha6_golden.rs`).

**Read first:** `02_ARCHITECTURE.md §7`, `03_DATA_MODEL.md §2`, `03_DATA_MODEL.md §8`,
`03_DATA_MODEL.md §9`.

**Exit gate — met.**
- [x] Kill during a write leaves the vault consistent (temp + fsync + rename).
- [x] A tampered `registry.json` makes the broker refuse to start and name the failure.
- [x] A tampered `manifest.json` does the same — `isolation.rs::i19_tampered_manifest_is_refused_at_broker_open_naming_the_node`.
- [x] A rolled-back registry is refused on the generation check —
      `isolation.rs::i20_rolled_back_registry_is_refused_on_the_generation_check`.
- [x] Seal then restore on day 6 succeeds byte-identically and on day 8 is gone —
      `isolation.rs::i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone`.
- [x] An audit-chain break is detected and reported by `verify`.
- [x] Manifest counts are readable with no key present — the locked-graph requirement.
- [ ] Backups fire on schedule and before destructive operations — **not met, and marked met in every earlier
      revision of this plan.** An operator-invoked backup works (`maintenance.backup`, `credmgr backup`); no scheduler
      exists to fire it, so the line stays open. No GitHub issue or milestone tracks it.
- [x] File modes are asserted, not assumed: `0700` directories, `0600` files.

**One retention number, to stop a recurring conflation.** The 7-day window above is the
soft-delete and seal recovery window. It is **not** the audit-log retention period, which is
**12 months** (`03_DATA_MODEL.md §9`). The two have been read as one figure before; they are
different mechanisms with different owners.

### 2.4 Phase 3 · Broker — **`built`**

**Built.** `credmgrd`: the UDS server, peer identification from kernel-supplied credentials,
cwd-derived scope resolution, tokens and sessions, rate limiting, lock/unlock, auto-lock, the
hot key set and its zeroisation. Plus everything Pass 2 added: the `create`/`update` split with
the pending tray, per-node write serialisation with a `conflict` result, node-level lock, the
re-parent gate, approval-on-demand, and `whoami` scope narrowing.

**Read first:** `02_ARCHITECTURE.md §1`, `06_ACCESS_GRAPH.md §4`, `10_API_AND_MCP.md §1`.

**Exit gate — met.**
- [x] A different uid is rejected before the first frame is read.
- [x] Scope resolves from cwd for a process started in a registered path.
- [x] Denials return the full structured shape of `06_ACCESS_GRAPH.md §5`, `remedy` included.
- [x] `create` while locked lands in the tray; `update` while locked is refused —
      `isolation.rs::i18_create_while_locked_lands_in_pending_and_update_is_refused_until_accepted`.
- [x] `whoami` names no out-of-scope node — `isolation.rs::i22_…`.
- [x] Re-parenting is refused on every surface that exists — `isolation.rs::i23_…`.
- [x] An entry-level grant does not expose the node's inventory — `isolation.rs::i24_…`.
- [x] Concurrent writers get `conflict`, never a lost write — `isolation.rs::i25_…`.
- [x] After `lock`, every hot-set buffer is all-zero, asserted by inspecting the buffers.
- [x] The rate limiter backs off as specified and shares its counter across auth paths.
- [~] **The isolation suite passes — 24 of 25.** `crates/brokerd/tests/isolation.rs` runs
      I-1…I-25 with I-13 in `crates/mcp/tests/` and I-17 in `crates/core/tests/`. **I-10 is
      implemented nowhere.** Its denial half is proven transitively and by
      `success_criteria.rs`; its positive half needs a transport that can set
      `presence_attested: true`, which no built transport can. This is accepted risk **K-1**
      in `PHASE8_AUDIT_REPORT.md §4` and closes in §5.2, not here.

### 2.5 Phase 4 · CLI — **`built`**

**Built.** The `credmgr` CLI in Rust, 27 top-level subcommands (the `field` family and `get --field`, `set --bulk` among them, ADR-078; `generate`, `approve` and `approvals`, ADR-087, 088, 090), every one of them a socket
client that never decrypts anything itself. Plus `v2/scripts/emergency-decrypt.mjs` — a
standalone, dependency-free Node script that recovers a V2 vault from a recovery code alone, so
disaster recovery never requires a Rust toolchain to be installable first. That is the reason
it is Node in a Rust project, and the only such reason.

**There is no migration tooling, and there never will be.** V2 ships empty and does not read
V1 (`11_MIGRATION.md §1`). An earlier draft of this plan had a whole phase for it.

**Read first:** `10_API_AND_MCP.md §2`.

**Exit gate — met.**
- [x] Every command works against the broker; none decrypts directly —
      `crates/cli/tests/broker_integration.rs`, against a real compiled binary and a real socket.
- [x] No command accepts a secret in `argv` — `crates/cli/tests/no_secret_in_argv.rs`.
- [x] `emergency-decrypt.mjs` recovers a value from the recovery code, and is tested —
      `crates/cli/tests/emergency_decrypt.rs`.

**The scope hole this exit gate had, and why it mattered.** None of the three bullets above ever
named vault *creation* — every one of them assumes a vault already exists. That silence stood for
weeks as an implicit, undocumented gap: this phase was marked `built`, 397 tests passed, and there
was still no way for a stranger cloning the repo to create a vault at all (`PROJECT_MAP.md §5`
item 21, found 2026-08-29). Closed 2026-08-31 by `credmgr init` (`vault.init_begin`/
`vault.init_confirm`, `14_DECISIONS.md` ADR-061, `04_CRYPTO_AND_KEYS.md §2.3`) — added here as a
fourth exit-gate bullet rather than folded silently into the first, so a future reader can see
that it was once missing, not just that it now passes:
- [x] A vault can be created from nothing — `crates/brokerd/tests/vault_init.rs` (direct-dispatch,
      proves the on-disk artifacts are cryptographically correct) and `crates/cli/tests/
      vault_init.rs` (the real binary, over a real socket, with real interactive stdin/stdout).

### 2.6 Phase 5 · Gate 2FA, TOTP items, and the native shell — **`partial`**

This is the one phase inside the closed chain whose gate is not met, and the previous version of
this document did not say so.

**Built.** Vault-wide gate 2FA: enrolment, verification, the replay ledger, recovery codes, and
the state machine that sits between "passphrase correct" and "node keys loaded", wired into
`vault.unlock`'s sequence exactly as `07_TWO_FACTOR.md §3` specifies. TOTP items with the
seed/code split of `07_TWO_FACTOR.md §6`. The MCP tool registry and its stdio JSON-RPC loop.
The `PlatformKeystore` trait, its `Capabilities`/`Tier` vocabulary, and
`software::SoftwareKeystore` — which is not a placeholder: `16_CROSS_PLATFORM.md §4` defines
`Software` as the permanent escrow wrap present on every platform. Since 2026-09-24 (`ADR-064`):
the confirmed gate is persisted in the registry — its seed sealed under a root-derived key, its
recovery codes as hashes, its last accepted counter — so it survives a restart; a re-enrolment
started and abandoned leaves the old gate in force; the last door (`vault.gate_recover`) exists;
and the CLI has `credmgr gate enroll` and `credmgr gate recover`.

**Not built, and not started.** The three hardware `PlatformKeystore` implementations named in
`16_CROSS_PLATFORM.md §4` — macOS Secure Enclave, Windows Hello/TPM+DPAPI, Linux
TPM2/secret-service. `crates/keystore/src/` contains `lib.rs`, `error.rs`,
`backup_passphrase.rs` and `software.rs`, and nothing else. Tauri's presence command does not exist
either (the shell's concealed-clipboard commands, `entry_copy` and `copy_text`, were built later —
`02_ARCHITECTURE.md §6.2`).

**Why, stated once so it is not re-derived.** `ADR-046`: the build sessions ran
non-interactively on a single macOS machine. Two of the three tiers were unwritable *and*
unverifiable there by construction, and the third needs a live human's finger on a live sensor
at the moment `unwrap_root` runs. Writing that FFI untested would produce precisely the artifact
this plan's own sentence forbids — *"a keystore that compiles for Windows but has never
unlocked a vault on Windows is not implemented"* — so it was named as unbuilt instead of stubbed.

**Read first:** `16_CROSS_PLATFORM.md §3`, `16_CROSS_PLATFORM.md §4`,
`04_CRYPTO_AND_KEYS.md §2`, `07_TWO_FACTOR.md §3`.

**Exit gate — two lines fully met, three partial, two never started** (one met and three never
started when this rewrite first made the accounting; the last line below was met on 2026-09-24).
This accounting is finer than the one this document carried before, and finer than "Phase 5
closed": each line was checked against a named test rather than against the phase's reputation.

- [x] **Recovery codes work exactly once each** —
      `phase5_gate.rs::item5_a_recovery_code_works_exactly_once`.
- [~] **All eight tests in `07_TWO_FACTOR.md §8` pass** — **seven of the eight.** That document's
      own table marks obligation 7 (orphan reveal never accepts an elevation, only a fresh
      challenge) `partial`: `phase5_gate.rs::item7_a_successful_vault_gate_challenge_never_elevates_orphan`
      covers the negative half, and the positive half needs the same live presence factor I-10
      does. The other seven are `built` and each names its test there.
- [~] **Orphan reveal requires a fresh code and presence, and is impossible from CLI and MCP** —
      the denial half is fully proven: `isolation.rs::i21_…` and `::i21b_…` drive
      `credmgr_brokerd::ops::dispatch` in-process, and `success_criteria.rs`'s criterion 2 proves
      the same denial over a real socket against a real broker, including the harder case that an
      orphan-scoped `List` token is refused too. The positive half is I-10's unimplemented half.
      Completes in §5.2.
- [~] **Presence unlock works on each platform's real mechanism, and a wrong TOTP loads no node
      key on each** — the second clause is proven on the software path
      (`phase5_gate.rs::item3_wrong_totp_after_a_correct_passphrase_loads_no_node_key`,
      `isolation.rs::i15_wrong_passphrase_leaves_the_hot_set_empty`); the first has no mechanism
      to be proven against. Completes in §5.2.
- [ ] **Keystore conformance suite green on macOS, Windows and Linux** — the suite
      (`13_TEST_PLAN.md §2`) does not exist as code: `grep -rn conformance v2/crates/` returns
      nothing, and there would be exactly one implementation for it to run against. Moves to §5.2.
- [ ] **The Security panel reports the correct tier per platform, including the honest
      `Software` case on a TPM-less machine** — needs both the tiers and a panel. Moves to §5.2.
- [x] **Passphrase plus root recovery code re-enrols the gate after a simulated device loss** —
      **met 2026-09-24** (`ADR-064`) by
      `durable_vault.rs::the_last_door_passphrase_plus_root_recovery_code_re_enrols_the_gate_after_device_loss`:
      gated and factor-less after a restart, either factor alone refused, both together reset the
      gate (and leave the vault locked), the passphrase alone then unlocks, and a new gate enrols
      and gates across the next restart. The 2026-08-18 pass had found this line unproven and
      marked it unmet rather than assumed: the recovery code's own wrap and unwrap of the root key
      were unit-tested in `crates/core/src/recovery.rs`, but no test exercised re-enrolling the
      *gate*, and the operation (`vault.gate_recover`) did not exist.

**Known defect in this phase's own test file, not in its code.**
`phase5_gate.rs::item2_failed_gate_attempts_back_off_and_share_the_passphrase_counter` is
load-sensitive: the fifth consecutive auth failure sets a 30-second wall-clock lockout, and the
test then performs five Argon2id-bearing calls inside that window, so a heavily loaded machine
lets the lockout legitimately expire and the assertion sees the wrong error. The production
logic is correct; the test encodes a wall-clock race. The fix is this project's own established
pattern — drive it through `ops::dispatch` with an explicit fixed `now` rather than through
`server::handle_request`, which always stamps the real clock. Tracked in `PROJECT_MAP.md §5`.

## 3. Closeout — Phases 7 and 8

The two phases that ended the chain: one that hardened what the construction phases built, and
one whose only job was to doubt it.

### 3.1 Phase 7 · Hardening and closeout — **`built`**

**Built and closed** 2026-08-10 (`BUILD_LOG.md` Session 15). Security review, a performance
pass, documentation reconciled against reality, and the corpus's stamps reconciled to commits
that actually resolve.

**One correction this phase itself had to make, kept because it is instructive.** This phase
used to carry "V1 archived per `11 §5`". `11_MIGRATION.md` has no such section and its actual
answer is the opposite: the maintainer's vault stays on V1, and that is not a migration problem.
The line was removed from the gate in 2026-08-08. Separately, `01_CONCEPT.md §7`'s success
criteria split into backend-observable (1, 2, 6) and UI-observable (3, 4, 5, 7); only the first
three are this phase's to prove, and the rest belong to Phase 6's gate word for word.

**Exit gate — met.**
- [x] Semgrep and both guards clean.
- [x] Every document's `artifact-hardened` stamp matched its commit at closure. That property
      has since lapsed corpus-wide and is now machine-checked by `tools/corpus_check.py stamps`
      rather than by a phase gate that only fires once.
- [x] Success criteria 1, 2 and 6 from `01_CONCEPT.md §7` demonstrated against a real compiled
      binary and a real socket — `crates/cli/tests/success_criteria.rs`.
- [x] The portfolio registry row reflects reality.

### 3.2 Phase 8 · Final adversarial audit — **`built`**

**Built and closed** 2026-08-16, verdict **Approved With Known Risks**
(`docs/PHASE8_AUDIT_REPORT.md`). Not a build phase: one adversarial verification pass by a
stronger model at maximum reasoning effort, added because every real bug this build produced was
found by a *second look* and never by the session that introduced it. It found one genuine
security defect — `node.restore` authorising against the calling token rather than against the
sealed node (`ADR-053`) — proved it with a failing test, fixed it, and added the regression test
that fails if the fix is reverted. Of `PHASE8_AUDIT_REPORT.md §2`'s six total findings (F-1..F-6),
that security defect is F-1; the other five were stale documentation claims, one of which would
have made an agent refuse work the operator had already authorised.

**Exit gate — met**, including the parts that are easy to fake: the full suite was re-run from
scratch rather than trusted from a prior session's claim, with output captured in full;
`git status` and `git log` were cross-checked against `BUILD_LOG.md`; and `v2/.build-complete`
was created only because the verdict was `Approved With Known Risks`. Four risks were left open
with owner, bound and resolution path: **K-1** (I-10 unimplemented), **K-2** (ancestor-restore
narrowed, deliberate), **K-3** (named non-gate items unbuilt — since closed by the
Backend-finish sessions, `ADR-054`/`ADR-055`/`ADR-056`), **K-4** (signing certificates,
operator, pre-release).

### 3.3 How the audit switch fired

Recorded because it is the pattern the remaining phases should reuse. A control signal must
never be expressible only as prose: the session that first closed Phase 7's gate created the
file flag `v2/.phase7-gate-green`, and `v2/scripts/autobuild.sh` checked for that flag before
every session. Flag present and `.build-complete` absent meant the next session ran on the
audit prompt at maximum effort instead of the usual build prompt. Both files exist today, which
is why the loop reports the build complete and stops. An earlier version of the same check
grepped `BUILD_LOG.md` for a literal completion string and was defeated by that string appearing
in prose — the reason the flag is a file.

---

## 4. Phase 6 · The UI — **`partial`**: hosted and wired over a **`built`** bridge, walked once by a person, gate only partly evidenced

**Not built by this chain, by operator directive** (2026-08-07): the UI is designed properly
first, through the external design track, rather than assembled mechanically by an unattended
session with no visual design input. The autonomous build skipped Phase 6 and went 5 → 7. This
is a scope note, not an architecture change — nothing about Phase 6's requirements moved, only
who does the work and in which session.

**What exists.** `v2/apps/desktop/` hosts the finished app design (`ADR-075`): precompiled at build
time, bundled by Vite and served under the unchanged strict CSP, with every read **and every change** of vault data
going through one model (`src/vault/`) and the typed client `src/lib/bridge.ts`. Boot, unlock with the second factor,
first run, lock, the graph and tree, the inspector with an entry's fields, the add-entry dialog with its single and bulk
modes and a live preview, field add, edit, remove and reorder, the review tray, node create, rename, lock and seal, grants,
notes, search, settings, backup, verify, doctor (with its separate purge row, `ADR-092`) and root-key rotation are wired,
and so are the later additions: Undo (`entry.undo`), the password generator (`util.generate`), the deliberate "Give the
second factor" step-up, and the Lock screen's list of waiting agent requests with a decision made by the unlock factors
(`ADR-088`, `ADR-090`, `ADR-091`). A control with no operation behind it was removed rather than left mocked, and no
screen carries a "mock" or "not built" marker (`tests/e2e/no-mock-badges.spec.ts`; an in-memory demo vault exists only
for development and test builds and is dropped from release bundles). Beneath it, the Tauri↔broker command bridge
(`src-tauri/src/commands.rs`), exposing **all 55 broker ops** — eight hand-written by `ADR-057`
(`vault.status`, `vault.unlock`, `vault.gate_verify`, `vault.lock`, `whoami`, `graph.snapshot`,
`entry.list`, `entry.reveal`) and the other 47 generated from one `bridge_ops!` table — plus four shell
commands of its own (`entry_copy` and `copy_text` for the concealed clipboard, `fields_preview`, which runs the bulk
grammar locally so the broker never parses it, and `app_icon_set`) and lock-on-sleep, with a typed TypeScript client and a real Content
Security Policy in `tauri.conf.json`. The bridge holds the session token in Rust and never returns it to the webview;
tests hold that invariant (`tests/bridge_wire.rs::the_session_token_is_captured_attached_and_never_returned`,
`::no_command_result_ever_serialises_a_token_shaped_string`, and across every command
`tests/bridge_ops.rs::no_result_across_every_command_carries_a_token_shaped_string`), and another proves by parsing
`ops.rs` that every op has a command and every command names a real op
(`tests/drift_guards.rs::the_bridge_covers_every_op_the_broker_dispatches_and_nothing_else`).
**Those tests are not part of the workspace count**: `apps/desktop/src-tauri` is its own
workspace, excluded from the MSRV pin by `ADR-035`, so it is a separate `cargo test` invocation —
202 listed on 2026-10-31 (194 on 2026-10-24, 186 on 2026-10-03, 65 on 2026-09-24), run in CI as `security.yml` →
`v2-desktop-bridge`. The front end's own suites: 703 unit tests (`npm test`), 664 Playwright tests listed
(`npm run test:e2e`, Chromium and WebKit), 80 journeys against a real `credmgrd` (`npm run test:real`), and a design
audit over 87 states (`npm run test:design`; 0 dead, unlabelled, clipped, squashed or low-contrast elements).

**What a person has done.** `RELEASE_VERIFICATION.md` was walked in the built, unsigned `.app` on 2026-10-18
(chunk C4: 190 rows pass, 7 fail, 85 not pressed, no P0; the one P1, autocorrect on text fields, fixed) and the B20 merge
was re-walked on 2026-10-31 at `709840c` (§13: all pass; one cosmetic stale line recorded). Open from those passes:
four P2 findings (a note's text shown while Help says masked, selecting a node not re-reading its entries, the narrow
inspector clipping names, Orphaned listing nothing after a seal — issues #23–#26) and the cosmetic ones (#27), all
`2.0.0-rc.1`; a VoiceOver pass (#22, `2.0.0-rc.1`); the 5-minute idle lock and a real sleep, which stay the
operator's (issue #9; the sleep check passed once, 2026-10-18, and the idle lock was not waited out on the B20 build).
The checker `tools/release_verification_check.py` reports 48 findings on 2026-10-31 (template bindings in `dlg-touch` that
no row names), so the checklist no longer covers every control the template binds.

**What does not exist.** A control to delete an entry (no screen sends `entry.remove`; the bridge carries it), and
search inside values (by design, never). The five presence-gated operations are sent for real and refused in words
(`presence_required`), pending issue #18. `v2/design/handoff/` — where delivered design output was to land — has
never been created; the design arrived as an export and is committed as a sanitised snapshot under
`apps/desktop/design-upstream/` (`ADR-075`).

**Target scope.** The application specified by `09_UI_UX_SPEC.md` — delivered as the precompiled
design rather than as the Svelte rewrite this plan was written for (`ADR-075`): shell,
graph canvas, tree view, inspector, add/edit flows, node add and seal, the orphan panel,
grants, settings, the Pro/Lite split, the lock screen and first run, themed per `20_THEMING.md`
and rendered per `design/graph-engine/VAULT_GRAPH_SPEC.md`.

**Read first when the work starts:** `09_UI_UX_SPEC.md`, `20_THEMING.md`,
`design/graph-engine/VAULT_GRAPH_SPEC.md`, `design/tokens/`, and whatever the design track
returns into `v2/design/handoff/`.

**Exit gate — partly met.** The screens are hosted, wired and walked, but the gate's own lines are not each backed by
a named test or recorded run. Checked against the repository on 2026-10-31:
- [~] The graph renders with correct counts **while locked** — the broker half is met
      (`crates/brokerd/tests/graph_snapshot.rs::renders_the_ancestor_chain_with_correct_counts_while_the_vault_is_locked`);
      the app shows the Lock screen while locked and loads nothing (`tests/e2e/wp-b-browse.spec.ts`), so a rendered locked
      graph is not drawn and no test asserts one. The line needs the owner's decision on whether it still applies.
- [ ] Hover shows exactly two numbers, asserted in a test — no such test found.
- [ ] The inspector shows only the selected node's own entries, asserted — no such named test found; open finding F-6 (#23)
      concerns what selecting a node reads.
- [ ] Lite search's empty state has exactly one row — no such test found.
- [x] No predefined field name appears anywhere in the UI (grep gate) —
      `crates/core/tests/no_field_schema.rs::no_source_file_references_a_predefined_field_name_list` scans `crates/`
      and `apps/desktop/src*`.
- [~] Keyboard-only: create a node, add an entry, create a grant, seal a node — individual keyboard paths are tested
      (`tests/e2e/c2-ui.spec.ts`, `field-ui-edit.spec.ts`); the whole no-pointer flow is not, and grant creation is
      refused until presence exists.
- [~] Axe clean; AA contrast in both themes; greyscale screenshot review — no axe run exists; the design audit
      (`scripts/verify-design-audit.mjs`) checks contrast (AA, AAA in high-contrast mode), dead and unlabelled controls over 87
      states in both engines, and the by-hand pass covered dark, light, high contrast and greyscale (§8 of
      `RELEASE_VERIFICATION.md`).
- [ ] A 500-node synthetic graph holds under 16 ms frame time while dragging — no benchmark or test found.
- [ ] Success criteria 3, 4, 5 and 7 from `01_CONCEPT.md §7` are demonstrated here, word for word — not claimed by any
      document found; `RELEASE_VERIFICATION.md §7`'s journeys J1–J12 cover the same ground in other words.

**Collision rule.** The front-end lanes own `apps/desktop/src/` (`src/design/` and `src/vault/`), the
KEEP tokens and the screen specs; the shell lane owns `src-tauri/`, where the bridge and the
shell's own commands live.

---

## 5. The ultimate destination — the four phases after the UI lands

Everything in this section is **`planned`** except two slices built since 2026-09-24 and marked
where they sit: Phase 9's bridge, wired screens and end-to-end suites (§5.1) and Phase 11's unsigned release path (§5.3).
Nothing else in it has code, a test or a file. Milestones below are the GitHub ones (`2.0.0-rc.1`, `2.0.0`),
checked against the open issues on 2026-10-31. The phase numbers 9–12 are introduced by this rewrite so the remaining work has the same shape
as the work already done — a scope, a read list, a blocker, and an exit gate. They are this
document's sequencing and are not ratified by any ADR; a session that disagrees with the
ordering should say so before starting, not after.

Each phase below names the one thing that blocks it, because all four blockers are of different
kinds and none of them is time.

### 5.1 Phase 9 · Integration — the delivered screens, and the full command surface — **`partial`**

**Blocked on:** nothing now; the screens were delivered (§4). What remains is evidence.

**Scope.** This phase wires the delivered UI to the broker over the bridge. Two halves; the
second was built ahead of the first:

1. **Screen integration — `built` and walked once, not fully evidenced (§4).** The delivered design is placed under
   `v2/apps/desktop/src/` (`ADR-075`), recorded in `09_UI_UX_SPEC.md`, and driven entirely through
   `invoke()` — never through a direct socket connection from the webview, which would put a
   session token in JavaScript and is the exact thing `ADR-057` exists to prevent.
2. **The full command surface — `built`** (`ADR-062`, 2026-09-24). The bridge carries one thin
   pass-through command per broker op, 55 in all (48 at the time of `ADR-062`, five more with `ADR-078`, then `util.generate` with `ADR-087` and `vault.approval_get` with `ADR-090`): the mutating `entry.*` family (including
   `entry.create_batch`) and `field.*`, `node.*` (including `node.set_workdirs`, `node.update` and
   `node.policy`), `notes.*`, `grant.*`, `totp.*`, `vault.pending_*`, `vault.node_*`,
   `vault.init_*`, `vault.gate_enroll_*`, `vault.gate_recover`, `maintenance.*`, `audit.*` and
   `search`, beside the original eight. Each command whose op takes the optimistic-concurrency
   `generation` value carries it (`entry.create` and `entry.create_batch` take none — a name
   collision is `entry_exists`) and surfaces `conflict` rather than retrying silently; the bridge's error
   vocabulary covers every denial they can raise, which
   `drift_guards.rs::the_bridges_error_vocabulary_matches_the_brokers_exactly` keeps true. The
   bridge adds no authorization decision, no reshaping and no vocabulary of its own — it is a
   transport, and `18_ENDPOINT_INDEX.md §4` is the list it stays equal to.

**Read first:** `18_ENDPOINT_INDEX.md §4`, `10_API_AND_MCP.md §1`, `19_FRONTEND_DELIVERY_SCOPE.md §5`,
`09_UI_UX_SPEC.md §13`.

**Exit gate.**
- [ ] Phase 6's exit gate passes in full, against the real application rather than a fixture — partly (§4).
- [x] All 55 broker ops are reachable from `invoke()` —
      `drift_guards.rs::the_bridge_covers_every_op_the_broker_dispatches_and_nothing_else` proves
      it in both directions: every op has a command, and no command names an op the broker does
      not dispatch (`ADR-062`).
- [x] No command result serialises a token-shaped string across the full command set —
      `bridge_ops.rs::no_result_across_every_command_carries_a_token_shaped_string` sweeps all
      every command and asserts it swept exactly the bridged surface (`ADR-062`).
- [x] The UI tests that encode product rules (`13_TEST_PLAN.md §7`) and the end-to-end flows
      against a throwaway vault (`13_TEST_PLAN.md §8`) exist and were green at the last recorded gate run
      (2026-10-30, `PRODUCTION_PLAN.md`): 703 unit, 664 Playwright tests listed, 80 journeys against a real `credmgrd`.
      Re-run in this pass: the unit suite (703 pass) and the real-suite drift guard (44 pass); the e2e and real journeys were
      listed, not run.
- [ ] The performance budget of `13_TEST_PLAN.md §9` is measured, not asserted — no measurement found.
- [x] The desktop workspace's own `cargo test` is run and reported separately from the
      workspace count, because it is a separate workspace and always has been: 202 tests listed on
      2026-10-31; in CI on its own as `security.yml` → `v2-desktop-bridge` since 2026-09-24 (GitHub-hosted runs are
      blocked by billing, issue #33).

### 5.2 Phase 10 · Native platform completion — **`planned`**

**Milestones:** presence / Touch ID `2.0.0-rc.1` (#18, needs the Apple Developer ID first, #28); the Secure Enclave tier
`2.0.0-rc.1` (#19); the Windows and Linux keystores and the named-pipe transport `2.0.0` (#29).

**Blocked on:** a Windows host and a Linux host that can actually run the suite, plus — for
macOS specifically — either an interactive session with a human present to complete real
biometric prompts, or a deliberately designed and separately justified test seam that exercises
the real platform FFI for everything except the prompt itself. This is not a scheduling problem
and cannot be solved from one non-interactive macOS machine, which is why `ADR-046` deferred it
rather than attempting it.

**Scope.** The three hardware `PlatformKeystore` implementations of `16_CROSS_PLATFORM.md §4`,
each behind the existing trait, plus the presence attestation that the rest of the system has
been designed around and has never been able to obtain:

- **macOS** — Secure Enclave key with `kSecAttrTokenIDSecureEnclave` and a
  `biometryCurrentSet` access control, so re-enrolling a fingerprint will invalidate the wrap.
- **Windows** — Windows Hello where available, TPM plus DPAPI where not, reported honestly as
  two different `KeystoreId` values because they are two different guarantees.
- **Linux** — TPM2 where present, the secret-service where not, and `Tier::Software` stated in
  plain words where neither is, rather than a lock icon that means less than the user thinks.
- **Tauri's presence command**, which is the only transport that will ever be able to set
  `presence_attested: true`. (The concealed-clipboard commands, `entry_copy` and `copy_text`, are
  built and the app's Copy buttons use them; `02_ARCHITECTURE.md §6.2`.)

**What this phase closes elsewhere.** It will be the change that makes **I-10** implementable,
and `ADR-046`, `ADR-047` and `PHASE8_AUDIT_REPORT.md §4` all name it as the resolution point:

- **K-1 will close here**, in full, in the same change that first makes presence reachable — both
  halves, not the denial half alone. A green checkbox over an untested guarantee is worse than
  an open one.
- **K-2 will become decidable here**: ancestor-restore of a sealed descendant was narrowed by
  `ADR-053` in the safe direction, and re-widening it needs its own explicit decision plus the
  temporary-registry-view approach that ADR rejected. It is not to be relaxed quietly as a side
  effect of this phase.
- All five of Phase 5's open gate lines (§2.6) will be met here or nowhere: everything that needs
  a hardware tier, a real presence factor, or a per-platform tier report. A sixth — gate
  re-enrolment after a device loss — needed only a test, and was met on 2026-09-24 without
  waiting for this phase (`ADR-064`).

**Read first:** `16_CROSS_PLATFORM.md §3`, `16_CROSS_PLATFORM.md §4`, `13_TEST_PLAN.md §2`,
`04_CRYPTO_AND_KEYS.md §2`, `05_THREAT_MODEL.md §7`.

**Exit gate.**
- [ ] The keystore conformance suite (`13_TEST_PLAN.md §2`) will run the identical tests against
      every implementation, on all three CI matrix targets, and be green — or the platform will
      ship as `Tier::Software` and say so, which is honest; silently degrading is not.
- [ ] A real presence prompt will unlock a real vault on each platform's real mechanism.
- [ ] A wrong TOTP will load no node key on each platform, asserted by an empty hot set.
- [ ] **I-10 will be implemented in full** and the isolation suite will run 25 of 25.
- [ ] The Security panel will report the correct tier per platform, including the honest
      `Software` case.
- [ ] No implementation will report `hardware_backed: true` without calling a real platform API.
      A mocked hardware tier is the one outcome this phase is forbidden to produce.

### 5.3 Phase 11 · Release and integrity — **`partial`**

**Blocked on:** an Apple Developer ID and a Windows code-signing certificate — accepted risk
**K-4**, an operator purchase. Neither blocks source publication and neither ever blocked the
build; both block shipping a signed binary.

**Scope.** Everything in `21_RELEASE_AND_INTEGRITY.md`, which this phase will execute rather than
extend:

- **Version stamping** (`21 §1`) — **`partial`**. The workspace version is real since
  2026-09-24 and is `2.0.0-beta.1` since the C3 bump (2026-10-18): `v2/Cargo.toml`'s `[workspace.package]` carries
  `version = "2.0.0-beta.1"` and `license = "MIT"` (matching `v2/LICENSE`), every crate inherits both with
  `version.workspace = true`/`license.workspace = true`, and the desktop app's `tauri.conf.json`,
  `package.json` and `src-tauri/Cargo.toml` say `2.0.0-beta.1` too (they said `0.1.0` until the bump).
  `credmgr --version` and `credmgrd --version` print a minimal stamp —
  version, commit, dirty flag, platform — that `scripts/release.sh` sets at build time. The full
  `BuildStamp` struct of `21 §1.3`, and the stamp in `vault.status` (which answers `locked`, `initialized`,
  `pendingApprovals` and nothing else), remain `planned`.
- **An unsigned release path — `built`** (`OPEN_WORK_REGISTER.md` M3; K-5). `scripts/release.sh` refuses a dirty
  tree, builds `credmgr` and `credmgrd` with `--release --locked`, remaps the build machine's paths out of the
  binaries, stages them with the launchd unit (`packaging/com.credmgr.brokerd.plist`), the bills of materials and
  `RELEASE.md`, writes a **deterministic** tarball (sorted members, fixed mtime, owner 0:0 with no names), writes
  `SHA256SUMS` over everything it publishes, checks each binary's stamp names the commit, and runs its own
  `--verify`. `scripts/release-app.sh` builds `CredMgr.app` (bundled with `tauri bundle`, sealed ad-hoc), a `.dmg`
  and a `.zip` into the same `dist/` and starts the built app against a throwaway vault, requiring a real window.
  `scripts/fresh-install-check.sh` installs the tarball into an empty folder the way a user would;
  `scripts/release-selftest.sh` corrupts copies of a good release and requires `--verify` to refuse each.
  A Homebrew formula is prepared under `packaging/homebrew/` and not published. Nothing signs, notarises, uploads
  or publishes; `SHA256SUMS` is the only provenance (K-4, K-5). Measured reproducibility (2026-10-03): the same
  commit in the same checkout is byte-identical; in a second checkout the bills of materials are identical and the
  binaries differ in 47–48 bytes (the Mach-O UUID and the ad-hoc signature hash).
- **Signing and publication** (`21 §2`), `planned`, milestone `2.0.0` (#28, Apple Developer ID, notarisation and updater): codesigned and notarised macOS artefacts,
  Authenticode-signed Windows artefacts, Linux packages, per-platform CLI binaries,
  `SHA256SUMS`, and a detached signature over it (the CycloneDX bills of materials already exist, above). The signing key will not live in
  CI; releases will be signed on a machine the maintainer controls and the CI job will only
  build and attest, so a compromised CI can produce an unsigned artefact and never a signed one.
- **Self-integrity** (`21 §3`): the start-up check that will run before the vault is touched.
- **The update channel** (`21 §4`).

**The primitive that does not exist yet.** Verifying a detached signature needs a signature
algorithm, and `crates/core` has none (§2.2). Introducing one is this phase's first task and
carries the same MSRV constraint that shaped every other dependency choice in the workspace.
The same primitive serves §5.4, so whichever phase runs first pays for it once.

**Read first:** `21_RELEASE_AND_INTEGRITY.md §1`–`§4`, `16_CROSS_PLATFORM.md §8`.

**Exit gate.**
- [ ] A tagged release will produce every artefact listed in `21 §2`, signed, with the signature
      verifiable from a clean machine using only the published public key.
- [ ] The self-integrity check will refuse to open a vault under a tampered binary, proven by
      tampering with one.
- [ ] The update channel will refuse an unsigned or downgrade update, proven by offering both.
- [x] The workspace version is real and consistent across all six manifests, and the
      `license` field matches the actual licence — `v2/Cargo.toml` (`2.0.0-beta.1`, `MIT`),
      every crate's `version.workspace = true`, `v2/LICENSE` (re-read 2026-10-31).
- [x] The SBOMs are generated by the release script, not by hand: CycloneDX, sanitised of local paths, one per binary and one for the app (`release.sh`, 2026-10-03).

### 5.4 Phase 12 · Organisation vault, sync and licensing — **`planned`**

**Milestone:** `2.0.0` (issue #30, "org vault, sync and licensing").

**Blocked on:** the single product-positioning decision that `22_ORG_VAULT_SYNC_AND_LICENSING.md §3`
reserves for the operator. That decision is a gate on implementation, not on design — §4 of that
document is a resolved specification, not a proposal set.

**Scope**, as decided in `22 §4`:

- **Organisation hierarchy** (`22 §4.1`) — the mother vault, departments beneath it, and who may
  reach which credential, expressed in the same node-as-boundary model the rest of the system
  uses rather than as a second parallel permission system.
- **Vault-to-vault sync over a pairing code** (`22 §4.2`) — gated on the §3 decision.
- **Retention, deletion and purge scope** (`22 §4.3`), which must not be conflated with either
  the 7-day soft-delete window or the 12-month audit retention (§2.3).
- **Licensing** (`22 §4.4`, `ADR-074`) — CredMgr is **MIT for everyone and nothing is gated by a
  licence or a payment**. The only licensing work left is an *optional* commercial-licence
  certificate: if it is a signed file it is **Ed25519, one keypair, no machine binding**, and it
  would be a later consumer of the signature primitive that Phase 11 (§5.3) adds — worth adding
  once, deliberately, rather than twice under two different constraints. No phase depends on it.
- **The remaining organisation features** (`22 §4.5`).

**The rule this phase inherits and must not break.** Any licence-certificate check will be
offline, and an offline check must never become a network call. `17_AIRLOCK_AND_LLM.md`'s rule
A-1 — no outbound network, ever — is the guarantee the whole agent story rests on, and a licence
server would repeal it silently. If a future requirement genuinely needs online activation, it
needs a superseding ADR that says out loud that A-1 is being changed.

**Read first:** `22_ORG_VAULT_SYNC_AND_LICENSING.md §2`, `§3`, `§4`; `06_ACCESS_GRAPH.md §10`;
`05_THREAT_MODEL.md §7`.

**Exit gate.**
- [ ] The operator's §3 decision will be recorded as an ADR before any code is written.
- [ ] A department will be unable to read a sibling department's credentials, proven by an
      isolation test in the same style as I-1…I-25, not by inspection of the UI.
- [ ] A pairing-code sync will move only what the design says it moves, proven against a second
      vault on a second machine.
- [ ] If a commercial-licence certificate is verified in the application, it will verify offline
      with the network unavailable, proven with the interface down, and its absence or failure
      will change nothing the application does (`ADR-074`). Optional; not a release blocker.
- [ ] No outbound network connection will be made by any licensing or sync path, asserted the
      same way A-1 is asserted elsewhere.
- [ ] Retention and purge will behave as `22 §4.3` specifies and will leave the audit chain
      intact, because deleting one record from a hash-chained log breaks it.

### 5.5 Work that is real but is not a phase

Tracked in `PROJECT_MAP.md §5`, listed here so nobody promotes one of them into a phase or
forgets it because it is not one:

- **Dependency alerts.** `glib` (medium, Dependabot #4) in the desktop shell is the one that stays: blocked
  upstream (Tauri 2.12.1, the version `apps/desktop/src-tauri/Cargo.lock` resolved when this was last
  read, still pulls `gtk` 0.18.2, which requires `glib ^0.18` and locks 0.18.5; nil exposure on macOS today, since
  the gtk stack is Linux-only and not compiled there); it is a recorded known risk, issue #15, milestone `2.0.0`.
  Commit `b94443c` (2026-10-31) fixed the other 13 open alerts (`tools/visual-engine`'s MCP SDK, `zod` and transitives,
  `v1`'s `body-parser`/`qs`); `npm audit` reports 0 in `v2/apps/desktop` and `tools/visual-engine` as of that
  commit, and GitHub's own list still showed all 14 open at the time of this check (the closure is Dependabot's to
  confirm after its rescan). The earlier alerts `cookie` (low) and `nanoid` (high) are gone: `cookie` left with the
  Svelte scaffold (ADR-075), `nanoid` was fixed 2026-08-18.
- **`tools/docgen` has an automated test suite** — `tools/docgen/tests/` (`test_doc_outline.py`,
  `test_generator_build.py`, `test_markdown_blocks.py`), 52 test functions. "52 tests, green" was not reproduced on
  2026-10-31: with the default `python3` here (`python3 -m unittest discover -s tools/docgen/tests -t .`) 33 run
  and pass, and `test_generator_build` does not import (it needs PyYAML, which is not installed in that
  interpreter), so the other 19 were not run. No workflow in `.github/workflows/` runs the suite.
- **The `phase5_gate.rs` wall-clock flake** (§2.6).
- **The endpoint index's drift guard** — for months three documents claimed a test `I-26`
  enforced it, and no such test has ever existed. The guard is now real, as
  `tools/corpus_check.py endpoints`, which proves in both directions that every op named in
  `18_ENDPOINT_INDEX.md` exists and every op the broker dispatches is named. It is not a Rust
  test because the artifact being checked is a document; the guarantee is identical. Anything
  still describing a Rust `I-26` is stale.

---

## 6. Sequencing

```
CLOSED — the backend chain

  0 toolchain ─► 1 core ─► 2 storage ─► 3 broker ─┬─► 4 cli ───────────────┐
                                                  ├─► 5 2fa (PARTIAL) ─────┼─► 7 hardening ─► 8 audit
                                                  └─► bridge (BUILT) ──────┘

NOT FULLY BUILT — Phase 6 is hosted and wired; Phase 9's bridge and Phase 11's unsigned release path exist

  6 ui ─► 9 integration ─► 10 native platform ─► 11 release ─► 12 org vault
    ^            ^                 ^                 ^              ^
    |            |                 |                 |              |
  needs      needs the        needs Windows +     needs the      needs the
 delivered   screens          Linux hosts and    signing         operator's
  screens                     a human factor     certificates    22 §3 decision

  Phase 10 is where I-10 and K-1 will close, where K-2 will become decidable, and where all
  five of Phase 5's open gate lines will be met. (Gate re-enrolment was met 2026-09-24 — 2.6.)
```

**What the arrows mean, and what they do not.** Phases 4, 5 and the bridge were independent once
the broker existed and were interleaved. Phase 9 needs Phase 6's output and nothing else. Phase
10 needs no UI at all — it is transport and platform work — but it is drawn after Phase 9
because Tauri's presence command is the transport that makes I-10 provable, and that command
lives in the same shell the screens do. Phase 11 depends on Phase 10 only for the platform
artefacts it signs, not for the signing itself. Phase 12 depends on Phase 11 for the signature
primitive, and on nothing else in the diagram.

**The one ordering that is not negotiable:** Phase 10 will close K-1, or nothing will. Shipping a
release (Phase 11) that describes the isolation suite as complete while I-10 remains
unimplemented would restate exactly the claim `PHASE8_AUDIT_REPORT.md` refused to round up.

## 7. Estimates

Sessions, not calendar time. The first column is what the closed phases actually took; the
second is an estimate for what has not started and is labelled as such.

| Phase | Sessions | Risk |
|---|---|---|
| 0 toolchain | 0.5 (actual) | Low — but it was not skipped, and that mattered |
| 1 core | 3–4 (actual) | Medium — crypto correctness, first Rust surface |
| 2 storage | 1–2 (actual) | Low |
| 3 broker | 5 (actual, more than the 2–3 estimated) | **High** — the security boundary lives here |
| 4 cli | 2 (actual) | Medium |
| 5 2fa + keystore | 1 (actual, for the part that could be built) | **High** — and it is why the phase is partial |
| 7 hardening | 1 + one rescued session (actual) | Low |
| 8 final audit | 1 (actual) | High-value by design — stronger model, maximum effort |
| 6 ui | estimate 4–6 | Medium — largest surface — external, not autobuild sessions; the actual (design drops, merges, the real-app pass, B20) is in `BUILD_LOG.md`, not re-estimated here |
| 9 integration | estimate 3–5 | Medium — the bridge commands (`ADR-062`) and the end-to-end suites are built; the performance measurement is not |
| 10 native platform | estimate 4–6 | **High** — three platforms, real hardware, a human in the loop |
| 11 release | estimate 2–3 | Medium — gated on certificates, not on effort |
| 12 org vault | estimate 5–8 | **High** — a new product surface with its own isolation obligations |

**What the actuals teach.** Phase 3 took roughly twice its estimate, and Phase 5 finished one
session by shrinking honestly rather than by finishing. The plan is written so that an
interrupted session leaves a green gate behind it rather than a half-built subsystem, and twice
that property is what let a rescue session recover work rather than redo it.

## 8. Explicitly deferred to V2.1+

Recorded so they are decisions and not oversights: security-key (WebAuthn) as a second factor ·
3D graph · QR-image import for TOTP seeds · remote backup destinations · multi-machine sync
beyond `22 §4.2`'s pairing-code design · per-entry expiry automation · bit-reproducible desktop
bundles (`21_RELEASE_AND_INTEGRITY.md §6`).

**No longer deferred — moved into scope by Pass 3 and since built:** the Rust broker (ADR-009,
resolved), Windows and Linux support as a target (the *support* is designed and in §5.2; the
*decision* to support them is closed), and Argon2id.

## 9. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `16_CROSS_PLATFORM.md §4` | the four keystore implementations, of which Phase 5 built one and §5.2 finishes three |
| depends on | `13_TEST_PLAN.md §4` | the isolation suite that is Phase 3's real gate, and the I-10 line §5.2 closes |
| depends on | `13_TEST_PLAN.md §2` | the keystore conformance suite §2.6 could not run and §5.2's gate requires |
| depends on | `PHASE8_AUDIT_REPORT.md` | the accepted risks K-1…K-7 (K-3 closed, K-7 closed in part), of which §5.2 and §5.3 name the resolution points for K-1, K-2, K-4 and K-5 |
| depends on | `01_CONCEPT.md §7` | the success criteria split 1/2/6 (Phase 7) from 3/4/5/7 (Phase 6) |
| depends on | `21_RELEASE_AND_INTEGRITY.md §2` | the artefact and signing requirements Phase 11 executes |
| depends on | `22_ORG_VAULT_SYNC_AND_LICENSING.md §4` | the resolved organisation design Phase 12 implements |
| depends on | `14_DECISIONS.md` | `ADR-035` (the desktop workspace exclusion), `ADR-046` (Phase 5's honest split), `ADR-053` (K-2's narrowing), `ADR-057` (the bridge), `ADR-059` (this document's status vocabulary), `ADR-062` (the bridge's full surface), `ADR-064` (the last door that met §2.6's sixth line), `ADR-075` (the hosted design), `ADR-093` (the second factor stays vault-wide for beta.1) |
| feeds | `18_ENDPOINT_INDEX.md §4` | the 55 bridged ops — §5.1's bridge, built (`ADR-062`, `ADR-078`, `ADR-087`, `ADR-090`) |
| feeds | `19_FRONTEND_DELIVERY_SCOPE.md §5` | which phase owns the glue between a delivered screen and a live op |
| feeds | `09_UI_UX_SPEC.md §13` | the states Phase 6's gate requires to be designed rather than improvised |

## 10. Source

**Design.** `ADR-035` (the desktop app is its own workspace, outside the MSRV pin), `ADR-041`
(the keystore trait and the software tier, hardware deferred), `ADR-046` (Phase 5's exit gate is
partially closed and must be reported that way — the source for §2.6), `ADR-047` (presence is
unreachable without a native transport), `ADR-053` (K-2's deliberate narrowing), `ADR-056` (the
session/login mechanism), `ADR-057` (the Tauri↔broker bridge), `ADR-059` (the status vocabulary),
`ADR-062` (every op bridged), `ADR-063` (the live unlock and write-through), `ADR-064` (the persisted
gate and the last door).

**Code.** `v2/Cargo.toml` for the six workspace members and the `apps/desktop/src-tauri`
exclusion; `crates/keystore/src/` for what Phase 5 did and did not build (`lib.rs`, `error.rs`,
`backup_passphrase.rs`, `software.rs` — no platform module of any kind); `crates/core/Cargo.toml`
for the absence of a signature primitive; `apps/desktop/src-tauri/src/commands.rs` for the
bridge's 55 of 55 ops; `crates/brokerd/src/ops.rs` for the 55 (counted with
`tools.corpus_check.broker_ops()`); `crates/cli/src/main.rs` for the 27 top-level subcommands;
`scripts/release.sh`, `release-app.sh`, `release-lib.sh`, `fresh-install-check.sh` and `v2/Cargo.toml` for §5.3's built slice.

**Tests.** `crates/brokerd/tests/isolation.rs` — I-1…I-25 and I-27…I-29 (there is no I-26) with I-10 implemented nowhere, stated
in that file's own module header. `crates/brokerd/tests/phase3_exit_gate.rs`,
`phase5_gate.rs`, `phase5_totp_items.rs`, `durable_vault.rs`; `crates/cli/tests/success_criteria.rs`,
`broker_integration.rs`, `no_secret_in_argv.rs`, `emergency_decrypt.rs`, `mcp_integration.rs`;
`crates/mcp/tests/i13_tool_registry.rs`; `crates/core/tests/{access_matrix,properties,isolation_i17}.rs`.
`cargo test --workspace --locked --offline -- --list`: 905 tests in 59 test binaries (2026-10-31, five of them doc-test
binaries); the last full run recorded in `BUILD_LOG.md`: 900 passing, 0 failing, 59 binaries (2026-10-26; earlier: 820/50
on 2026-10-19, 571/41 on 2026-10-02, 448/37 on 2026-09-24, re-measured 2026-10-01; 406/35 on 2026-09-13 — run
`34743281942`; 397/33, verified 2026-08-18).
The desktop workspace's `tests/bridge_wire.rs` and `tests/drift_guards.rs` — and, since
2026-09-24, `tests/bridge_ops.rs`, `tests/ts_client.rs` and `tests/shell_config.rs`, plus `shell_ipc.rs`,
`fields_preview.rs`, `real_broker.rs`, `dependency_policy.rs` and `macos_pasteboard.rs`: 202 listed on 2026-10-31 (65 on 2026-09-24,
186 on 2026-10-03) — are a separate invocation and are not in the workspace count.

**Records.** `docs/PHASE8_AUDIT_REPORT.md` (the audit, its verdict, K-1…K-4, and the 2026-09-24
addendum's K-5…K-7);
`v2/BUILD_LOG.md` (Sessions 3–31 and the finish-plan chunks C0–C4, the per-phase story, including Session 9's backfilled Phase 5
entry and Session 15's Phase 7 closure; it has no entry for batches 1–4 of `PRODUCTION_PLAN.md` — those are in the commit messages and `OPEN_WORK_REGISTER.md`); `PROJECT_MAP.md §4` and `§5` (phase status and the open
items §5.5 lists); `v2/scripts/autobuild.sh` (the flag mechanism §3.3 describes);
`v2/.phase7-gate-green` and `v2/.build-complete` (both present).

**Verification.** `python3 -m tools.corpus_check crossrefs` for every `NN_NAME.md §S` reference
above; `tools/corpus_check.py endpoints` for the op surface §5.1 commits to.

**Figure.** The `build-phase-ledger` figure (§0) is a `docgen` `kind: "state"` diagram —
`v2/docs/12_BUILD_PLAN_spec.json`, built via `tools/ENGINE_ROUTING_POLICY.md`'s directive
mechanism. Its per-phase status and counts were re-derived fresh for this figure, independent of
this document's own prose: `v2/crates/keystore/src/` (four files, no hardware module) for Phase
5's gap; the bridge's `HAND_WRITTEN` (8) and `TABLE` (45; 47 since the figure was rendered) in `v2/apps/desktop/src-tauri/src/commands.rs`
against `tools.corpus_check.broker_ops()` (53; 55 now) for the bridge fraction; `v2/crates/brokerd/tests/isolation.rs`'s
own `i`-numbered test functions (26 — I-1…I-25 minus I-10, which is implemented nowhere, plus I-27…I-29 and `i21b`)
plus I-13/I-17 living in `crates/mcp/tests/` and `crates/core/tests/` respectively, for "27 of
28"; and `v2/docs/14_DECISIONS.md` ADR-046 plus `v2/docs/PHASE8_AUDIT_REPORT.md` §4 for the K-1…
K-4 framing behind the two unstarted phases' distinct blockers. The figure was re-derived on
2026-10-03 (the bridge fraction read 8 of 38 until 2026-09-24 and 48 of 48 until the field model, and the UI, integration and release
phases are partial, as §0 says).
