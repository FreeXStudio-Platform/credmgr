---
id: V2-013
classification: public
title: Test plan
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-19
---

<!-- artifact-hardened: NEEDS RE-HARDENING — corrected 2026-08-19 (Session 21, round 2, closing
     this document's entry in VERIFICATION_BACKLOG_S21_ROUND2.md). The previous stamp (rewritten
     2026-08-18, pre-round-2-verification) attested to a body an independent skeptic pass then
     found three surviving defects in: the docgen row and the §13 Runs line both stated 48 tests
     for `tools/docgen/tests` when a live run returns 52 (the suite grew after the rewrite last
     counted it); the keystore-conformance paragraph said all 18 `crates/keystore` unit tests
     exercise the `Software` tier, when only 12 do and the other 6 test an unrelated
     backup-passphrase helper its own doc comment disclaims; and the §4.1 note calling
     `isolation.rs`'s module-doc index "maintained" was true for its I-13 status fix but silent
     about that same comment, and five sibling source comments, still citing this document's own
     stale section numbers (`§3` where the isolation suite is now `§4`; `§2` where the property
     tests are now `§3`) — drift `tools/corpus_check.py crossrefs` cannot see because it only
     globs `*.md`. All three, re-derived from a live test run and live greps rather than patched
     from the finding text, are corrected below. The corpus-wide hardening stamp remains the
     operator's to assign after their own review, not this session's to self-award. Updated
     2026-09-24 for ADR-062…066 (durable_vault.rs, the bridge's new suites, the bridge in CI).
     Updated 2026-09-24 for ADR-071…073 (the bridge at 47 commands, §2; `node.policy` and
     `node.update` on the forbidden list I-13 walks, §4.6). Updated 2026-10-03 for ADR-078 and ADR-079 (P-13…P-18, I-27…I-29, the
     new broker and store test files, the wired front end's runners, the endpoint matrix at 53 ops and 224 rows (54 ops and 237 on 2026-10-24, 55 ops and 243 on 2026-10-26), and the
     real-broker suite). Corrected 2026-10-17: the real-suite drift guard passes (43/43); the earlier "fails" statements are removed. -->
# Test plan

`CredMgr V2` · every layer of the suite — what runs today, what it proves, and what the finished suite will contain · `2026-08-18`

> **Status.** The backend suite is **built**: `cargo test --workspace -- --list` lists **813 tests in 50 test
> binaries** (counted 2026-10-03), and the last full pass/fail run recorded is **571 passed, 0 failed across 41
> test binaries** (2026-10-02; 448 across 37 on 2026-09-24, re-measured 2026-10-01; 406 across 35 on
> 2026-09-13). The gate run on this tree is the orchestrator's and is recorded in `BUILD_LOG.md`, not here. The
> desktop shell is a **separate** Cargo workspace and is **not** in that number — its own `cargo test` lists
> **186 tests in 12 test executables** (2026-10-03; 156 passed on 2026-10-02; 65 on 2026-09-24, ADR-062; 40 on
> 2026-08-18), and it runs in CI. The **isolation suite is 27 of 28**: I-1…I-25 and I-27…I-29 are implemented
> (there is no I-26, see §1), and I-10 is implemented nowhere, an accepted risk (K-1) rather than an oversight.
> Above the broker the front end has its own runners in `apps/desktop/` (`ADR-075`): **550 unit tests in 21 files**
> (Vitest, `npm test`, passing 2026-10-03), **552 Playwright tests in 22 files** (276 per browser project; listed,
> not run, 2026-10-03), a design audit probe, and a real-broker suite that drives the built app against a real
> `credmgrd` (`npm run test:real`; its drift guard, `npm run test:real:drift`, passes: 43/43, 2026-10-17). The product-rule assertions of
> §7 are partly covered and the eight end-to-end flows of §8 only in part; performance measurement, coverage
> measurement, fuzzing, and the cross-platform keystore conformance run are **`planned`**: none of those exists in
> any form, and §2.2 gives each its full target design in the future tense. Three claims this document previously
> made are false and are corrected here: RFC test vectors are not pinned (§5), no golden envelope is committed for
> the file format as a whole (§5; the version-1 envelope and the alpha.6 manifest have one each, §5), and there is
> no pre-push hook running tests (§10).

---

## 1. What this suite is for

V1 ships 190 tests and they are the reason it can be changed safely — re-run on 2026-08-18 by
`node tests/run-all.js`: **190 passed, 0 failed**. V2 inherits that standard and adds the class
V1 could not have had, because V1 had no boundary to prove: **tests that prove a boundary
exists.**

That distinction organises everything below. Most of the suite is ordinary engineering hygiene —
does the parser round-trip, does the manifest verify, does `entry.rotate` keep the old value
recoverable. One part of it is not: the **isolation suite** (§4) exists because
`05_THREAT_MODEL.md §3` makes claims about what a caller cannot reach, and a security claim
without a test is a hope. Each isolation test names the claim it discharges, and the suite runs
on push to `main`, on every pull request, and on a weekly schedule as the project's security gate
(§10).

Two rules follow from that, and they are why several tests in this repository are shaped oddly:

1. **A test that proves a negative must observe the real surface, not a copy of it.** I-13
   enumerates the live MCP tool registry rather than a hard-coded list, so a tool added in a
   future session fails the test instead of slipping past it. The desktop bridge's drift guards
   parse `crates/brokerd/src/ops.rs` off disk rather than comparing a constant against itself.
   The corpus has already paid for the alternative: three documents asserted for months that a
   test `I-26` parsed `18_ENDPOINT_INDEX.md` and made drift impossible. No such test has ever
   existed (`grep -rn "I-26" v2/crates/` returns nothing), so the index drifted freely while
   everyone believed it could not.
2. **A gate that has never run has not passed.** Stated as portfolio CI policy, and load-bearing
   here: the `v2 build` workflow — the only thing that would compile or test this workspace on
   Windows or Linux — has **zero runs** in the repository's entire history (§10). Its matrix is
   designed, committed, and unexecuted.

## 2. Layers

### 2.1 The layers that exist — **`built`**, with one **`partial`**

| Layer | Runner | Scope | Status |
|---|---|---|---|
| Core unit | `cargo test -p credmgr-core` | envelopes, key wrapping, `resolve()`, the bulk parser, type inference, TOTP, recovery codes | **`built`** |
| Core property | `proptest` (pinned `=1.4.0`, ADR-036) | invariants over generated inputs — §3: P-1…P-12 in `properties.rs` and P-13…P-18 in `field_doc.rs` (the field document, ADR-078) | **`partial`**, 17 of 18 |
| Storage | `cargo test -p credmgr-store` | atomic writes, manifests, registry signature, generation counter, hash-chained audit log | **`built`** — but in-crate: `crates/store/tests/` is an empty directory, so every storage test is a `#[cfg(test)]` module inside `src/` |
| Broker integration | `cargo test -p credmgr-brokerd` | 22 integration binaries under `crates/brokerd/tests/` over the real dispatch path with real fixtures — among them `durable_vault.rs` (2026-09-24), over a real on-disk vault that is created, unlocked by passphrase, restarted and reloaded (ADR-063…066); `field_model.rs` (27 tests, ADR-078); `seal_durable.rs` (37), `approval_locked.rs` (19), `seal_digest.rs` and `field_seal_joint.rs` (ADR-079); and `rotate_root.rs` (39, ADR-076) | **`built`** |
| CLI / MCP end-to-end | `cargo test -p credmgr-cli` | spawns the **real compiled binaries** against a **real `credmgrd`** over a **real socket** — never a mock, never an in-process call standing in for the wire | **`built`** |
| **Isolation suite** | `cargo test -p credmgr-brokerd --test isolation` (+ two tests elsewhere) | §4 — the security claims, including I-27…I-29 for the field ops | **`partial`**, 27 of 28 |
| Access matrix | `cargo test -p credmgr-core --test access_matrix` | all 8×8 cells of `06_ACCESS_GRAPH.md §2`'s worked example, table-driven | **`built`** |
| Argv hygiene | `cargo test -p credmgr-cli --test no_secret_in_argv` | a structural grep over the one file that defines every flag the binary accepts | **`built`** |
| Desktop bridge | `cargo test` inside `apps/desktop/src-tauri` | the Tauri↔broker command bridge (all 53 op commands, plus the shell's own three), its drift guards, the typed client's guard and the CSP guard — **a separate workspace** (ADR-035), excluded from `cargo test --workspace` and its count; runs in CI as `security.yml` → `v2-desktop-bridge` since 2026-09-24 | **`built`** |
| Endpoint matrix | `python3 scripts/endpoint-matrix.py` (after `cargo build --workspace`) | every one of the 55 broker ops over the real socket against the real `credmgrd`, in a throwaway vault: 243 rows (2 probes) — 243 pass, 0 known-gap, 0 blocked, 0 failed (the three known-gap rows and two blocked rows that pinned K-7 are gone: ADR-079 closed it) — and five invariants (no plaintext under the vault directory across 38 generated secrets including four session tokens, socket and directory modes, the daemon survives, no unexpected panic, the real default locations untouched). `--check-coverage` fails if an op has no row. A known gap is pinned strictly: the run fails the day it stops holding. In CI as `security.yml` → `v2-endpoint-matrix` (PRs) and in `build.yml` (all legs) | **`built`** — re-measured 2026-10-24 |
| Real-binary journey | `scripts/e2e-journey.sh` and `scripts/e2e-fields.sh` (after `cargo build --workspace`) | the path a user takes with the real binaries: init, unlock, projects and workdirs, restart, a locked write that survives a restart, import and notes, two-factor, the last door, a second daemon, a seal and a restore across a restart, and no plaintext value or token-shaped string under the vault directory (`e2e-journey.sh`, 61 checks, exit 0 on 2026-10-03); and the multi-field entry through the same binaries — bulk paste, selection, field edits, undo, a seal and a restore with fields, a restart (`e2e-fields.sh`, 59 checks — 44 in the multi-field segments and 15 in the alpha.6 compatibility segment, which needs the alpha.6 binaries and counts as a failure when they are absent; exit 0 on 2026-10-03) | **`built`** — run before calling a release real |
| Corpus integrity | `python3 -m tools.corpus_check` | `endpoints`, `crossrefs`, `stamps` — the guards the documentation has never had | **`built`** |
| Checklist drift | `python3 -m tools.release_verification_check` (`--self-test` proves it can fail) | `docs/RELEASE_VERIFICATION.md` §2 against the front-end templates: one row per control, every bound handler named, the Size line true (212 rows in 22 templates on 2026-10-03). Local-only and deliberately outside `corpus_check`'s default run, which also runs in the published tree | **`built`**, not in CI |
| Docgen | `python3 -m unittest discover -s tools/docgen/tests -t .` | 52 tests over the document build pipeline; **52 passed** on 2026-08-19 | **`built`** |
| Front-end unit | `npm test` in `apps/desktop` (Vitest) | **550 tests in 21 files, all passing 2026-10-03**: the model, the error router, the bridge mapping, the importer's refusals, compiler semantics, every name the templates read in each of 55 states driven through the real bridge client, local-storage hashing, the architecture rules, the release-build rules | **`built`** |
| Front-end flows | `npm run test:csp`, `npm run test:e2e`, `npm run test:design` in `apps/desktop` (Playwright, WebKit and Chromium) | the release build and the test build under the production CSP against a fixture broker held to `bridge.ts`'s shapes: **276 tests per browser project, 552 in 22 files** (listed, 2026-10-03); every spec ends on 0 violations, 0 console errors, 0 external requests; no screen may show a "mock" or "not built" marker; the design audit probe finds 0 dead, unlabelled, clipped, squashed or low-contrast controls | **`built`** — listed, not run, in this pass |
| Real-broker UI suite | `npm run test:real` in `apps/desktop` | the built app driven by Playwright in front of a **real `credmgrd`** on a throwaway vault, through a Node rewrite of the Tauri command layer (`tests/real/shim/`); 10 spec files, a drift guard that holds the shim to `commands.rs` | **`partial`** — built; `npm run test:real:drift` passes (43/43, 2026-10-17) and the suite gates the unlock, lock, node-lock, tray, presence, second-factor and field paths it covers |

**Why the "real binary, real socket" standard matters enough to name.** `broker_integration.rs`,
`mcp_integration.rs` and `success_criteria.rs` each start an actual `credmgrd` and drive an actual
`credmgr` process against it. That is more expensive than calling `ops::dispatch` directly, and it
is the only way a test can falsify a claim about the *transport* — peer credentials, framing,
denial codes surviving serialisation. It is also why the suite takes tens of minutes rather than
seconds, and why §11's flake is a wall-clock race rather than a logic error.

### 2.2 The layers that do not exist — **`planned`**

None of the following is present in any form. Each is designed here in full, and none of it is
written as though it runs.

**Fuzzing — `cargo-fuzz`.** There is no `fuzz/` directory anywhere in the repository. The finished
suite will carry two harnesses, chosen because they are the two places untrusted bytes enter the
system: the **bulk parser** (`crates/core/src/parser.rs`, which consumes whatever a user pastes)
and the **envelope decoder** (`crates/core/src/envelope.rs`, which consumes whatever is on disk).
Both targets will assert only totality and determinism — no panic, no unbounded allocation, no
non-deterministic output — because those are the properties a fuzzer can actually falsify. Corpus
seeds will be the worked examples of `08_FIELD_MODEL.md §3.1` plus every envelope the crypto tests
already build. The proptest coverage in §3 is a weaker substitute for this, not a replacement:
proptest generates from a strategy the author chose, and a fuzzer does not.

**Coverage measurement — `cargo llvm-cov`.** Nothing in this repository measures coverage: there is
no llvm-cov invocation, no tarpaulin configuration, and no coverage job in either workflow. The
targets this document has always stated therefore describe an unmeasured quantity, and are
restated here as what they will be once measurement exists: `crates/core` **100 % branch** — it is
pure and I/O-free, so anything less is a choice not to test — `crates/brokerd` **≥ 90 %**, and the
UI **≥ 70 %** once a UI exists. Coverage will be a floor, never the goal; the isolation suite is
the part of this plan that carries real weight, and it would be satisfiable at low coverage and
unsatisfiable at high.

**Keystore conformance across platforms.** `crates/keystore` has 18 unit tests, but only 12 of them
exercise the `PlatformKeystore` trait's `Software` tier (`software.rs` — `wrap_root`/`unwrap_root`,
`capabilities()`, `verify_presence`, the counter tests) on the one platform this project has ever
been built on. The other 6 (`backup_passphrase.rs`) test a separate maintenance-backup
passphrase-encryption helper that the module's own doc comment disclaims as unrelated to this
trait: "a standalone public function rather than a method on `crate::software::SoftwareKeystore`
... has no relationship to the vault's own unlock passphrase." It shares the crate for its Argon2id
dependency, not for tier conformance. The finished
design is **one conformance suite, run unchanged against every implementation of the
`PlatformKeystore` trait** — macOS Secure Enclave, Windows Hello/DPAPI, Linux TPM2/secret-service,
and the universal `Software` fallback — across the CI matrix of `16_CROSS_PLATFORM.md §8.2`. That
is the mitigation `16_CROSS_PLATFORM.md §10` records for **AR-9** ("three keystore implementations
= three places to get it wrong"), and it is blocked on exactly what ADR-041 and ADR-046 already
name: the hardware tiers are unwritten, two of the three platforms have no host to run on, and the
macOS tier needs a live human's biometric at the moment `unwrap_root` executes. The suite will
assert tier reporting honestly — a backend that cannot reach hardware must report
`Tier::Software`, never a lock icon that means less than the user thinks.

**UI tests — mostly `built` now (§2.1).** What stays `planned` is narrower than it used to be: the product-rule
assertions of §7 (several are covered by the specs, several are not) and the eight end-to-end flows of §8 against a
real vault, which the real-broker suite (`apps/desktop/tests/real/`) covers in part.

**Performance measurement.** No benchmark harness, no `criterion` dependency, no `[[bench]]`
target. The budgets in §9 are design budgets that nothing has ever measured against.

### 2.3 What this plan no longer contains

**Migration testing is removed, not deferred.** This document previously listed a layer of
"`cargo test` + a Node fixture harness reading V1's format, fixture-based, then the live dry run."
There is no migration to test: `11_MIGRATION.md §1` records the decision that V2 ships empty and
imports nothing, and it is verifiable rather than merely asserted — `grep -rni "migrat"` over
`v2/crates/**/*.rs` returns nothing and no crate contains a reader for any V1 file format. A
fixture harness for a format nothing reads would be a test of code that does not exist.

## 3. Property tests (core) — **`partial`**

`crates/core/tests/properties.rs`, using `proptest`. Each property runs proptest's default case
count with its own seed printed on failure. Eleven of the twelve properties this plan specifies
are implemented; the twelfth cannot be, and the reason is more interesting than the property. P-13…P-18, added with the
field model (ADR-078), live in `crates/core/tests/field_doc.rs` and are all implemented.

| # | Property | Status |
|---|---|---|
| P-1 | `open(seal(m, K), K) == m` for arbitrary bytes | **`built`** — `p1_seal_open_round_trips`; the 1 MiB end of the range is covered by a dedicated unit test rather than by generation, for wall-clock reasons |
| P-2 | `open(seal(m, K_a), K_b)` fails for all a ≠ b | **`built`** — `p2_cross_node_decrypt_always_fails` |
| P-3 | An envelope opened under a different asserted node id fails (AAD binds `nodeId`) | **`built`** — `p3_wrong_asserted_node_id_fails` |
| P-4 | An envelope opened under a different asserted entry id fails (AAD binds `entryId`) | **`built`** — `p4_wrong_asserted_entry_id_fails` |
| P-5 | `seal(m,K)` twice yields different ciphertexts | **`built`** — `p5_sealing_is_nondeterministic` |
| P-6 | `parse(bulk)` is lossless | **`partial`** — `p6_case_a_round_trips` proves losslessness against the documented canonical form of `08_FIELD_MODEL.md §3.1` (single-line `label: value` pairs), not against arbitrary unstructured text, because "reassembly == input" presupposes a reassembly function the grammar does not define for freeform input. A companion generated test proves the multiline case's one documented lossy edge: a value's trailing empty line is trimmed |
| P-7 | `parse` is total — no input panics | **`built`** — `p7_parse_is_total` |
| P-8 | `parse` is deterministic | **`built`** — `p8_parse_is_deterministic` |
| P-9 | `resolve()` is default-deny: any allow is traceable to a named rule | **`built`** — `p9_resolve_allow_always_has_a_named_rule`; the `Decision::Allow` type carries its rule, so an unjustified allow is unrepresentable rather than merely untested |
| P-10 | `resolve()` is monotone in grants: removing a grant never turns a deny into an allow | **`built`** — `p10_resolve_is_monotone_in_grants` |
| P-11 | Type inference never mutates the value it classifies | **`built`** — `p11_inference_never_mutates_value` |
| P-12 | Refs are never reused across create/delete cycles | **`planned`, and the property is currently unstatable** — see below |

**P-12 is not merely unwritten.** `03_DATA_MODEL.md §3` records that
`next_ref()` is an in-process `AtomicU32` seeded at 1000 on broker start
(`crates/brokerd/src/state.rs`) and is **not persisted**, so refs restart rather than continue
across a restart. Within one broker lifetime the counter is monotonic and non-reclaiming, which
makes reuse unrepresentable rather than untested; across restarts the property as stated is
simply false. The test will be written against the finished counter — which will persist its
high-water mark beside the registry and take the maximum of that and the highest ref present in
any manifest at load — and will assert monotonicity across a simulated restart, which is the case
that can actually fail. Writing it today against the in-memory counter would pass while proving
nothing about the failure mode.

**The field document, P-13 … P-18 — `built`** (`crates/core/tests/field_doc.rs`, ADR-078).

| # | Property | Status |
|---|---|---|
| P-13 | A field document survives encode → decode untouched (1–20 fields, arbitrary valid labels) | **`built`** — `p13_field_doc_round_trips`, 1,000 cases |
| P-14 | Decode is total: arbitrary bytes, 0–4096 of them, are `Ok` or `Err`, never a panic | **`built`** — `p14_decode_is_total`, 10,000 cases; its companion `p14b_decode_is_total_on_mutated_valid_documents` flips, drops or duplicates a byte of a real encoding, 1,000 cases (10,000 took over 200 s in a debug build) |
| P-15 | A legacy raw value, read in place, projects exactly the manifest entry it was written under — any value × any stored entry type × any stored sensitivity | **`built`** — `p15_legacy_projection_is_preserved`, 1,000 cases |
| P-16 | The payload kind is authenticated: flipping the version byte of a sealed envelope fails the tag | **`built`** — `p16_payload_kind_is_authenticated`, 1,000 cases |
| P-17 | Parse a bulk paste, build a document from each segment, seal it as a version-2 envelope, open and decode it: every label and value is byte-identical to what the parser produced, a PEM-shaped value included | **`built`** — `p17_parse_seal_open_preserves_every_field`, 1,000 cases |
| P-18 | Flattening the segments is the plain parse, and no segment is empty | **`built`** — `p18_segments_flatten_to_parse_bulk`, 10,000 cases |

`no_field_schema.rs` (5 tests) is the grep gate `08 §8` row 7 asked for: no predefined field-name list anywhere in the
product code.

## 4. The isolation suite — the tests that justify the rewrite

Each test corresponds to a claim in `05_THREAT_MODEL.md §3`. The fixture is
`06_ACCESS_GRAPH.md §2`'s own worked example — Global; projects A, B, C, D; sub-nodes X and Y
under A; one human grant X → B at list+read but not reveal — so every assertion can be checked
directly against that section's table rather than against a graph invented for the test.

### 4.1 Coverage — **`partial`**, 27 of 28

The table in §4.2 and §4.3 is the **specification** and is deliberately not edited to match the
code. This subsection is where the code's actual coverage is recorded, so the two can disagree
visibly instead of silently.

| Where | Tests |
|---|---|
| `crates/brokerd/tests/isolation.rs` | I-1…I-9, I-11, I-12, I-14, I-15, I-16, I-18…I-25, I-27…I-29 (§4.3b), plus `i21b` (§4.5) and the zeroisation assertion of §5 |
| `crates/mcp/tests/i13_tool_registry.rs` | I-13 — four tests, written once Phase 4 gave the MCP crate a real registry to enumerate |
| `crates/core/tests/isolation_i17.rs` | I-17 — `i17_every_allow_is_independently_justified`, a proptest over random graphs, living in `core` because it is a pure access-graph property and `core` cannot touch a file |
| nowhere | **I-10** — §4.4 |

`isolation.rs`'s module doc carries this same index, deliberately duplicated at the code end so a
reader who never opens this document still learns which tests are missing. That comment is
maintained for coverage: it previously said I-13 was "unbuilt until Phase 4" long after Phase 4
shipped, and the Phase 8 audit corrected it. It is **not** maintained for section numbers, though:
the same comment, plus `isolation_i17.rs:1`, `i13_tool_registry.rs:1`, `phase3_exit_gate.rs:2` and
`main.rs:10`, all still cite this document's isolation suite as "§3" — it is §4 as this document is
now structured (§1 What this suite is for, §2 Layers, §3 Property tests (core), §4 The isolation
suite). `properties.rs:1` has the sibling error: it cites "§2" for the property tests, which are
§3. `tools/corpus_check.py crossrefs` cannot see any of this — it only globs `*.md` under `docs/`,
so a Rust doc-comment's citation to this document sits outside its coverage. Fixing those six
comments is `v2/crates/` work and out of scope for this document.

<!-- figure:isolation-suite-coverage -->

### 4.2 The specification — I-1 … I-17

| # | Setup | Assert |
|---|---|---|
| **I-1** | Broker with nodes `global, a, b`; token scoped to `a` | `entry.reveal` on a `b` entry → `node_access_denied`, rule `R8`, and the response contains no value, no name, no metadata of `b` |
| **I-2** | Same | `entry.list` returns exactly `a` ∪ `global`, never `b` |
| **I-3** | Same | `search` for a string that only matches in `b` returns zero results **and** logs no leak — the result count itself must not differ from a search that matches nothing |
| **I-4** | Sub-nodes `x`, `y` under `a` | `x` reads `a` (R4) and `y` (R6) and `global` (R3); `x` does **not** read `b`, `c`, `d` |
| **I-5** | Grant `x → b (read)` | `x` reads `b` at `read`, **not** at `reveal`; `y` still cannot read `b` |
| **I-6** | Grant revoked | The very next request from `x` is denied — no cached allow, no session survival |
| **I-7** | Grant with `expiresAt` in the past | Denied, and reported as expired rather than as absent |
| **I-8** | `a.policy.descendantRead = false` (default) | `a` cannot read `x` or `y` |
| **I-9** | `a.policy.descendantRead = true` | `a` can read `x` and `y`, and still not `b` |
| **I-10** | Sealed node → orphan | Every transport except native-with-presence is denied; **names remain listable**; values unreachable via CLI, MCP and the non-HTTP UI path |
| **I-11** | Agent process whose working directory sits under a directory registered to node `a`, presenting no token | Scope resolves to `a`; a reveal aimed at `b` is refused under `R8` or for want of the capability, whatever argument shape it is asked in |
| **I-12** | Caller presents a token whose `boundWorkdir` ≠ its cwd | The request proceeds under the token, **and** an anomaly record is written to the audit log |
| **I-13** | Enumerate **every** exported MCP tool | None can create a grant, return a TOTP seed, read orphan data, alter node policy, or purge audit — asserted over the live registry, so a newly added tool fails the test |
| **I-14** | Vault locked | Graph data (topology + counts) available; every `reveal` denied, routed to approval rather than answered |
| **I-15** | Wrong passphrase at unlock | The hot key set is empty — asserted by inspecting broker internals through the crate's `test-utils` feature, not inferred from a subsequent request's failure |
| **I-16** | 6 cross-node denials in 10 minutes | Anomaly event emitted |
| **I-17** | Fuzz: random `(scope, target, capability)` triples against random graphs | Never an allow that `resolve()`'s rule trace cannot justify |

### 4.3 Added by Pass 2 — I-18 … I-25

Each of these exists because Pass 2's adversarial review found a hole the original table did not
think to specify; the `Finding` column names it.

| # | Setup | Assert | Finding |
|---|---|---|---|
| **I-18** | Vault locked; caller has `create` + `update` on node `a` | `entry.create` succeeds into `pending/` and does **not** appear in the manifest; `entry.update` on an existing entry returns `vault_locked`. After unlock + accept, the created entry appears exactly once | F-1 |
| **I-19** | Edit `manifest.json` by hand (remove an entry / bump a count) | `verify` and broker start both reject it, naming the node and the mismatch | F-2 |
| **I-20** | Restore an older, validly-signed `registry.json` in which a revoked grant reappears | The broker refuses to open on the `vaultGeneration` check; `doctor --rebuild-registry` shows the resurrected grant **in its diff** before writing anything | F-3 |
| **I-21** | Seal a node, then restore it on day 6 and again on day 8 | Day 6: one-click restore succeeds from `archive/`, values byte-identical. Day 8: archive and node key are gone; the same entries are reachable only via presence + a fresh TOTP, one at a time | F-4 |
| **I-22** | `whoami` from a scope with no grants | The response names only the caller's node, its ancestors and Global — asserted by scanning the serialised response for every out-of-scope node label, not by reading one field | F-6 |
| **I-23** | Re-parent node `x` from `a` to `b` via every surface | CLI, MCP and non-native UI paths all refuse; native + presence + 2FA + a stated reason succeeds; the audit record carries the before/after readable sets | F-8 |
| **I-24** | Entry-level grant `b → a.entry(e1)` | `b` can read `e1`; `entry.list` against `a` from `b` returns **exactly one** entry, not `a`'s inventory | F-14 |
| **I-25** | Two clients write the same node concurrently from the same starting generation | Exactly one wins; the other receives `conflict` with the current state and no manifest entry is lost | F-9 |

**Three specification rows are only half-discharged, and the missing halves share one cause.**
I-20's second clause (`doctor --rebuild-registry` showing the resurrected grant in a diff before
writing), I-21's day-8 clause (the entries reachable via presence and a fresh TOTP), and I-23's
positive path (native + presence + 2FA + reason succeeds) all require **presence attestation**,
which no transport in this build can supply — the same wall that leaves I-10 open (§4.4).
`maintenance.doctor --rebuild-registry` exists and is dispatched
(`crates/brokerd/src/maintenance.rs`), and is unconditionally `presence_required` once the caller
holds Admin, so its refusal is tested and its diff is not. Each implementing test therefore proves
its row's **denial** clauses today and will be extended to the positive clauses in the change that
first makes presence real. This is recorded here rather than by quietly trimming the specification
rows to match what runs: a table edited down to the code stops being a specification.

### 4.3b Added with the field model — I-27 … I-29

There is no I-26 (§1). These three were added with ADR-078 and live in `isolation.rs`, the file `security.yml` runs as
the security gate, so a new op that reads or writes an entry's fields is inside the same graph, the same lock rules
and the same envelope authentication as every op before it.

| # | Setup | Assert |
|---|---|---|
| **I-27** | The five ops ADR-078 added (`entry.get`, `field.add`, `field.update`, `field.remove`, `field.reorder`), each with a body that would succeed for the owner of node `a`; a stale generation isolates the graph decision from the generation check | For every relationship in the fixture graph (parent → child, shared depth-2 siblings, child → parent, unrelated projects, reached only through the grant X → B) all five get **exactly** the graph decision `entry.update` gets — a denial is `node_access_denied` with its rule (R8 for an unrelated node), the read-only `entry.get` is allowed where the grant carries `read`; a cwd-derived agent scope is denied on a foreign node; a read-only agent reads metadata but every field write is `capability_not_held` for `update`; and `entry.get` never returns a value |
| **I-28** | Vault locked, then one node locked on an otherwise unlocked vault | Whole vault locked: all five answer `vault_locked`, while `entry.create` with fields still lands in the review tray (F-1) and says how many fields it holds. One node locked: `node_locked` (ADR-077) for every one of them, the tray still takes writes, and another node is unaffected |
| **I-29** | A field document written by this build, and a legacy version-1 envelope | The payload kind is authenticated: relabelling a version-2 envelope as version 1 on disk, or a version-1 envelope as version 2, fails authentication and the JSON text is never returned as if it were a single raw value; a version-2 envelope copied under another entry id or into another node does not open (the entry id and node id are in the AAD); and no refusal, and no field op on an unrelated entry, reveals the document |

### 4.3c Added with the 2026-10-24 backend wave — names, second factor, factors, K-7

Real server wiring on throwaway `vault.init_*` vaults (`crates/brokerd/tests/common/mod.rs`), each test mutation-checked
(the fix removed, the test seen to fail). They are isolation tests in the §4 sense: each states what a reader that is
**not** the owner can or cannot learn or do.

| File | What it pins |
|---|---|
| `part4_names.rs` + `core/tests/names.rs` | a Cyrillic or Greek look-alike of an existing name is refused as the existing duplicate (entry, batch item, tray, restore collision); an agent's twin write through the broker is refused; a pure-Cyrillic name is not; mixed script is accepted with `warnings`; the table equals the threat model's table; the canonical form is idempotent |
| `part4_private_names.rs` | `privateNames`: the opaque snapshot row, `entry.list` `{entries:[], nameHidden, count}`, a count below three hidden, the owner's badge, and no name, label or note through `entry.get`, `search`, the pending tray, `notes.read` or the audit feed |
| `part4_two_factor.rs` | `requireTwoFactor` `reveal` / `always` / `never`; nothing asked without a gate; the step-up and the closing window; a wrong code; the policy and the gate surviving a restart |
| `part4_field_undo.rs` | each `field.*` op taken back through `entry.undo` (`ok`, `restored`); the seven-day window (day 6 yes, day 13 no); a rotation's undo unchanged |
| `part4_generate.rs` + `core/src/generate.rs` | `util.generate`: bounds at both ends, character classes, entropy, uniformity, the bias zone, capability, no audit of the value, the value entering a field through the broker |
| `part4_approval_factors.rs` | approval 4b: the release while locked, the backoff, gate / code / recovery-code refusals, the spent step across a restart, deny, the closed paths, unknown field ids not burning the approval, the audit record, the TTL |
| `seal_durable.rs` (four + two) | a child created between a seal's check and its lock is found; `node.create` / `node.set_workdirs` wait for a seal's / restore's window; a directory claimed before a restore's lock is dropped; the expired-seal purge |

### 4.4 I-10 — the one that is not implemented

**`planned`.** I-10 is not implemented anywhere, and it is recorded as accepted risk **K-1** in
`PHASE8_AUDIT_REPORT.md` rather than quietly rounded up to "24 is basically 25".

Its **denial half** — a sealed node's values are unreachable on every transport this build has —
is proven three times over: `i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone`,
`i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node`, and criterion 2 of
`crates/cli/tests/success_criteria.rs`, which drives a real `credmgr` against a real `credmgrd`
over a real socket and includes the harder case that an orphan-scoped `List` token is refused too,
because R0 has no exception. Nothing about sealed data is unproven-but-assumed.

Its **positive half** — "names remain listable" via native-with-presence — is untestable today
because **nothing in this build can set `presence_attested: true`**. That is the same honest gap
ADR-046 names for the hardware keystores and ADR-047 names for sessions: the native shell that
would attest presence does not exist.

**Why it is not closed with a denial-only test.** A test asserting only the denial would make I-10
read as satisfied while the half that needs a transport went unbuilt — a green checkbox over an
untested guarantee, which is worse than an open one. The resolution is fixed and recorded in two
places so it cannot lapse: I-10 will be implemented **in full, in the same change that first makes
`presence_attested: true` reachable**, owned by whoever builds the native shell.

### 4.5 Beyond the table

**`built`.** `i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node` (ADR-053) tests
`node.restore`'s authorisation — a hole the specification table never thought to name, because
I-21 only ever exercised the *rightful* holder's restore. It is recorded here rather than
renumbered into the table, so the table stays the record of what was specified and this line stays
the record of what was found.

### 4.6 I-13 is the anti-regression test for the whole design

**`built`.** `10_API_AND_MCP.md §3.2` lists the tools that must never exist — grant creation,
orphan read, TOTP seed return, node policy change, audit purge. That list is only as strong as its
enforcement, so I-13 walks the live `credmgr_mcp::tools::registry()` — the actual list `tools/list`
serves — against `credmgr_mcp::tools::FORBIDDEN_OPS`, in four tests: no registered tool maps to a
forbidden op, no tool *name* contains a forbidden fragment, the registry is non-empty (so an empty
registry cannot pass vacuously), and `totp.seed` appears under no tool name whatsoever. Since
`ADR-071` `FORBIDDEN_OPS` names the real policy and rename ops, `node.policy` and `node.update`,
so a tool mapped to either fails I-13 as well.

The vacuity check is the part worth copying. A test that enumerates a list and asserts a property
of every member passes trivially when the list is empty, and an empty registry is a plausible
refactoring accident. The future session that helpfully adds `credmgr_grant_create` gets a red
test whose message explains why the tool must not exist.

## 5. Crypto conformance

**`partial`.** Three of the four mechanisms this plan specifies are built; the fourth is not, and
the description of the first was wrong.

**Fixed interop vectors — `built`, and not what this document used to claim.** This plan
previously said "pinned test vectors for X25519, HKDF-SHA-512 and ChaCha20-Poly1305 **from the
RFCs**." No RFC vector is pinned anywhere in this repository. What exists is better suited to the
actual risk and should not be described as something it is not: `crates/core/src/envelope.rs`'s
`node_interop_vectors` module pins hex constants for the X25519 shared secret, the HKDF-SHA-512
entry-key derivation, the AAD encoding and the ChaCha20-Poly1305 output — **each computed
independently by a from-scratch `node:crypto` re-implementation before the test was written**. The
risk that guards against is specific: `scripts/emergency-decrypt.mjs` is JavaScript and must read
what Rust writes, forever. If `derive_entry_key`, `build_aad` or the AEAD call ever drift, this
fails in Rust at the primitive level rather than surfacing as an inexplicable authentication
failure in an end-to-end fixture — or, worse, as an unreadable backup discovered in a crisis.
Pinning published RFC vectors as well remains worthwhile and is **`planned`**: it would catch a
dependency upgrade that changes a primitive's behaviour, which the interop vectors would also
catch but would attribute to the wrong layer.

**The recovery path is exercised end to end — `built`.**
`crates/cli/tests/emergency_decrypt.rs` builds a real fixture vault with the real Rust crypto
(`recovery::wrap_root_with_recovery_code`, `keys::wrap_node_key`, `envelope::seal`) — not a
hand-crafted byte string standing in for what those functions produce — then shells out to the
real `scripts/emergency-decrypt.mjs` and asserts the recovered plaintext is byte-identical. The
recovery path cannot rot silently (ADR-045).

**Zeroisation — `built`.** `after_lock_every_hot_set_buffer_is_all_zero` in `isolation.rs` asserts
that after `lock()`, every buffer previously in the hot key set is all-zero. It can see inside the
broker because `credmgr-brokerd` exposes hot-key-set inspection behind a `test-utils` feature,
enabled for `cargo test` through a self-dependency and never in a release build of `credmgrd` —
`#[cfg(test)]` alone would not reach an external integration binary. The bound on what this proves
is `05_THREAT_MODEL.md §7`'s **AR-3**: zeroisation is best-effort against the operating system,
not against the language, and this test cannot see a swapped page or a hibernation image.

**A golden envelope — `partial`.** One is pinned (ADR-078): a version-1 envelope exactly as the
unmodified alpha.6 `seal` produced it, held as a hex literal in
`crates/core/src/envelope.rs::an_alpha6_version_1_envelope_still_opens_byte_for_byte`, which opens it
with both entry points and requires the raw value back. Not yet there: no version-2 golden, and no
`.cmv2` file committed beside its key. The finished design is one envelope file, committed with its key,
that must open byte-identically
forever, so that format drift becomes a failing test on the day it is introduced rather than an
unreadable backup found later. It is distinct from the interop vectors: those pin the
*primitives*, this pins the *file format* — the magic, version, suite byte, header layout and
field order that a future envelope-writer change could alter without touching a single primitive.

## 6. Drift guards — tests that read the real source

**`built`, and the pattern is deliberate.** Ten tests in this repository do not test behaviour at
all (six until ADR-062 widened the bridge's guards on 2026-09-24), and the real-broker UI suite carries an eleventh
(`apps/desktop/tests/real/drift-guard.test.mjs`, §11). They parse the real source file
off disk and assert that a copy elsewhere still matches it — the shape the corpus spent months
*believing* it had in the phantom `I-26`.

- `apps/desktop/src-tauri/tests/drift_guards.rs::the_bridge_covers_every_op_the_broker_dispatches_and_nothing_else`
  parses `crates/brokerd/src/ops.rs` and proves, in both directions, that every op the broker
  dispatches has a command and every command names a real dispatch arm.
- `…::every_param_the_bridge_sends_is_one_the_broker_reads_and_every_required_one_is_sent` holds
  each command's wire keys against its op's own arm (one forward-declared exception, `audit.get`'s
  `id`, is listed with its reason), and `…::every_bridged_command_is_registered_with_tauri` holds
  `src/lib.rs`'s `generate_handler!` against the command table.
- `…::the_bridges_error_vocabulary_matches_the_brokers_exactly` does the same for all 25 error
  discriminants against `crates/brokerd/src/protocol.rs`.
- `apps/desktop/src-tauri/tests/ts_client.rs::the_client_calls_every_bridged_command_once_with_exactly_its_wire_keys`
  and `…::the_clients_error_union_is_the_brokers_vocabulary_exactly` hold the typed TypeScript
  client `apps/desktop/src/lib/bridge.ts` to the same table and vocabulary.
- `…::the_socket_path_rule_still_matches_crates_store` and
  `…::the_per_platform_vault_defaults_still_match_crates_store` pin the bridge's copies of the
  vault-directory and socket-path rules against `crates/store/src/paths.rs`.
- `crates/cli/tests/no_secret_in_argv.rs::no_forbidden_flag_is_ever_defined` greps the one file
  that defines every CLI flag, because no behavioural test can prove "there is no such flag" by
  trying every possible input. `…::unlock_and_set_read_their_secret_from_stdin`, in the same file,
  parses the same source to assert that `cmd_unlock` and `cmd_set` both call
  `read_stdin_value()` — so a secret's *only* entry path is checked structurally too, not only its
  absence from argv.

A sibling of the pattern reads a config file rather than a source file:
`apps/desktop/src-tauri/tests/shell_config.rs` parses `tauri.conf.json` and fails closed if the
production Content Security Policy is `null` or admits any remote origin, and if the development
one admits anything beyond the local dev server (ADR-062).

`tools/corpus_check.py` is the same idea applied to documents rather than code: `endpoints` proves
in both directions that every op named in `18_ENDPOINT_INDEX.md` exists in `ops.rs` and every op
`ops.rs` dispatches is named there; `crossrefs` proves every `NN_NAME.md §S` reference resolves to
a section that exists; `stamps` proves every `artifact-hardened` stamp still matches the body it
names — the check that found this document's own stamp invalid. It is Python rather than a Rust
test because the artifact under test is a document; the guarantee is identical.

## 7. UI tests that encode product rules — **`partial`**

A UI test runner now exists — Vitest and Playwright in `apps/desktop/` (`ADR-075`; `npm test`,
`npm run test:e2e`, `npm run test:csp`) — and its specs run the hosted design under the production CSP
against a fixture broker held to `bridge.ts`'s declared shapes, asserting 0 CSP violations, 0 console
errors and 0 external requests, and walking every screen from broker-shaped data; the architecture rules of
`npm test` forbid a logic file from editing the view in place and `navigator.clipboard` from appearing anywhere in
`src/`, and the grep gate for a predefined field-name list is `crates/core/tests/no_field_schema.rs` (§3). Of the
rules below, the ones not yet asserted by any spec (checked 2026-10-03: the hover card's two numbers, the Lite
search rows, the 20-second re-mask and the desaturated screenshot pass) are written as assertions to be written,
because each is a product rule that a future change will otherwise erode without anyone noticing:

- The node hover card will render **exactly two** numeric values, asserted by counting DOM nodes
  rather than by checking that the two expected ones are present (`09_UI_UX_SPEC.md §4`).
- The inspector's entry list will be sourced from exactly one node id, and will contain no entry
  whose `nodeId` differs from the selection.
- Lite mode: the search empty state will have exactly one row, labelled "Add new".
- Lite mode: no Operations panel will exist in the DOM at all — absent, not hidden.
- No element in the app will render a value drawn from a predefined field-name list, asserted by a
  grep gate over `apps/desktop/src/**`. (This plan previously named `packages/ui/**`, a directory
  that has never existed in this repository.)
- Every reveal will re-mask after 20 seconds, and the concealed clipboard will clear after 30
  (`09_UI_UX_SPEC.md §8`).
- With `prefers-reduced-motion`, every node state in `09_UI_UX_SPEC.md §3` will remain
  distinguishable.
- A scripted screenshot pass will render the main views desaturated and diff them against approved
  baselines, so a colour-only state can never ship (`09_UI_UX_SPEC.md §14`).

The last two exist because the states in question are specified as *not* colour-dependent, and
that is precisely the kind of requirement that survives review and dies in implementation.

## 8. End-to-end flows — **`partial`**

The real-broker suite (`apps/desktop/tests/real/`, §2.1) drives the built app against a throwaway vault created for
each run and destroyed after it, and covers the unlock, lock, node-lock, pending-tray, presence-refusal and
second-factor paths; the field-editing journeys are not all in it yet. Its drift guard passes (2026-10-17), so what it
covers is a gate. The full set, against a throwaway vault, is eight flows,
chosen to cross every boundary at least once:

1. First run → create vault → passphrase → recovery code → 2FA enrolment → first node.
2. Add entry (single field) → reveal (2FA) → copy → auto-remask.
3. Add entry (bulk paste, PEM + `///`) → preview → save → value byte-identical on read-back.
4. Create sub-nodes → verify sibling visibility → verify parent cannot read child.
5. Create grant by drag → dashed edge appears → revoke → edge disappears → access denied.
6. Seal a node → orphan panel → names visible → reveal requires presence → restore within the
   window.
7. Lock → graph still renders with counts → reveal denied → unlock → reveal works.
8. Switch Pro ⇄ Lite → Operations panel appears/disappears → data unchanged.

Flows 4, 5, 6 and 7 will duplicate isolation-suite assertions on purpose. The isolation suite
proves the broker refuses; these will prove the refusal **reaches the user as a legible state**
rather than as a spinner that never resolves. Both halves will be required, and they will fail
differently.

## 9. Performance — **`planned`**

Nothing measures any of this today: there is no benchmark harness and no `criterion` dependency.
These are design budgets, and they will be enforced as regression bounds — a build that exceeds
one fails — rather than reported as a number nobody reads.

| Check | Budget |
|---|---|
| Cold broker start → ready | < 400 ms |
| Unlock → node keys loaded (200 nodes) | < 800 ms |
| `entry.reveal` p95 | < 25 ms |
| `entry.list` for a 200-entry node | < 40 ms |
| Graph first paint, 50 nodes | < 120 ms |
| Graph drag frame time, 500 nodes | < 16 ms |

One budget deserves its caveat now rather than at measurement time: **unlock is deliberately slow**
at the Argon2id step, and the 800 ms figure is the work *after* the root key is available, not
including the KDF. Measuring them together would create pressure to weaken the KDF to hit a
performance target, which is the wrong trade in a vault.

## 10. Continuous integration

**`built`, and narrower than this document used to claim.** Per the portfolio CI cost-control
rule, security gates run freely and build/test gates do not trigger on git events.

**What runs, verified against the repository's own run history on 2026-08-18.** The `security`
workflow triggers on push to `main`, on every pull request, on a weekly schedule floor, and on
dispatch. It has **34 runs** as of this pass; the most recent completed with every job green, including
**`v2 — isolation suite (I-1..I-25)`**, whose job runs
`cargo test -p credmgr-brokerd --test isolation --locked` every time that workflow runs (the job's name predates
I-27…I-29; the same command runs them, and renaming the job is a change to a workflow file outside this document). That job
is the project's security gate and is exempt from run-restraint by design. Alongside it: `cargo deny`, `cargo
audit`, Semgrep SAST, the V1 dependency audit and test suite, and both secret guards
(`guard-no-secrets.mjs --all`, `guard-no-personal-data.mjs --all`). **Since 2026-09-24 the same
workflow also runs the desktop bridge's own suite** — job `v2-desktop-bridge`, `cargo test --locked`
inside `apps/desktop/src-tauri` — because its token-custody tests are security tests (ADR-062). It
had sat red for three weeks, from 2026-08-31, while nothing ran it.

**What is not wired into CI at all — `planned`.** Neither `tools/corpus_check.py` nor the
docgen test suite runs in any workflow; both are local-only today. That is the wrong place for
them: the drift classes they catch — a cross-reference to a section that no longer exists, an
`artifact-hardened` stamp whose body has moved, an op documented in `18_ENDPOINT_INDEX.md` that
the broker does not dispatch — are exactly the ones that accumulate silently between sessions.
They will join the `security` workflow, which is where fail-closed checks already live, and they
are cheap enough (stdlib Python, seconds) that no cost argument applies.

**What has never run.** The `v2 build` workflow — `cargo build`/`test`/`clippy -D warnings`/`fmt
--check` across `{macos-14, windows-latest, ubuntu-22.04} × {1.78.0, stable}`, plus a Tauri debug
build of the desktop app on all three — is `workflow_dispatch`-only and has **zero runs in the
repository's history**. This is the single most important honest statement in this section: **the
workspace has never been compiled, let alone tested, on Windows or Linux.** Every "green" claim in
this document is a claim about one macOS machine. The cross-platform matrix is designed,
committed, and unexecuted, which under the portfolio's own rule means it has not passed. It should
be dispatched once, deliberately, before any claim of cross-platform support is made.

**The local layer, corrected.** This document previously described a "local pre-push (free)" stage
running `cargo test`, `cargo clippy -D warnings`, the property and isolation suites, `svelte-check`
and a secret scan. **There is no pre-push hook in this repository.** The only installed hook is
`pre-commit`, and it runs exactly two things: `guard-no-secrets.mjs` and
`guard-no-personal-data.mjs`, both failing closed. Correctness at commit time is therefore
entirely a matter of the author remembering to run the suite — which is survivable only because
the isolation gate runs server-side on push to `main` and on every pull request regardless of
what the local hook checks. The finished local layer will add a **pre-push**
hook running `cargo clippy -D warnings`, `cargo fmt --check` and the isolation suite, chosen
because those three are fast enough to run at push time; the full workspace run takes tens
of minutes and belongs in a deliberate local run, not in a hook that will be bypassed.

**No deploy workflow exists, and none will.** This application is not deployed; it is installed.
Release signing and publication are `21_RELEASE_AND_INTEGRITY.md`'s subject, and its certificates
are outstanding as accepted risk K-4.

## 11. Known weaknesses of this suite

Named and bounded, because a test plan that only lists what it proves is the same failure mode as
a threat model that only lists defeated adversaries.

1. **One platform.** Every green result in this document comes from one macOS development machine
   (§10). Two of the three `PlatformKeystore` tiers cannot be written, let alone tested, from here.
2. **A known load-sensitive flake.**
   `phase5_gate.rs::item2_failed_gate_attempts_back_off_and_share_the_passphrase_counter` failed
   once, on 2026-08-17, under heavy machine load, in a session that changed zero Rust. The
   mechanism was read from `auth_backoff.rs` rather than guessed: the fifth consecutive auth
   failure sets a **30-second real-wall-clock** lockout, and the test performs five Argon2id-backed
   `vault.unlock` calls plus two assertions inside that window; on a slow enough machine the
   lockout legitimately expires and `gate_verify` reaches the gate, returning
   `GateVerificationFailed` where the test expects `RateLimited`. **The production logic is
   correct; the test encodes a wall-clock race.** The fix is this project's own established
   pattern: drive it through `ops::dispatch` with an explicit fixed `now` instead of
   `server::handle_request`, which always stamps the real clock — the same file already uses that
   pattern for its other timing tests. Tracked in `PROJECT_MAP.md §5`.
3. **Coverage is unmeasured**, so the targets in §2.2 are aspirations rather than facts, and a
   whole untested branch would currently be invisible.
4. **No fuzzing**, so the two parsers that consume untrusted bytes are protected only by
   author-chosen proptest strategies.
5. **The front end is tested far better than it was, and not yet end to end.** The desktop app's own runners
   (550 Vitest tests, 552 Playwright tests, a design audit probe — §2.1) check the wired app under the production
   CSP against a fixture broker held to `bridge.ts`'s shapes. The real-broker suite is the layer that catches a
   screen claiming "Saved" while the vault holds nothing. On the merged tree of 2026-10-03 its drift guard
   (`npm run test:real:drift`) failed (the shim's table listed 48 commands against the bridge's 53 plus
   `fields_preview`); it was brought level afterwards and passes today (43/43, 2026-10-17). A "Saved" over the field
   ops that the suite's journeys do not reach is still checked only by the broker-side tests and `scripts/e2e-fields.sh`. There is no performance measurement, and the real-app checklist
   (`RELEASE_VERIFICATION.md`) is a human pass whose result column is empty. The workspace figure describes a
   backend; do not read it as a measure of the product.
6. **A harness can report success over a failing run.** During the 2026-08-17 closeout the shell
   wrapper reported exit code 0 while the captured `CARGO_TEST_EXIT` was 101. Read the suite's own
   summary line, not the wrapper's exit code — the same discipline `18_ENDPOINT_INDEX.md`'s
   correction note applies to documents, applied to test runs.

## 12. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `05_THREAT_MODEL.md §3` | the trust-boundary claims each isolation test in §4 discharges |
| depends on | `05_THREAT_MODEL.md §7` | AR-3, the bound on what §5's zeroisation test can prove |
| depends on | `06_ACCESS_GRAPH.md §2` | the worked example used verbatim as the isolation suite's fixture |
| depends on | `10_API_AND_MCP.md §3.2` | the forbidden-tool list that I-13 enumerates the live registry against |
| depends on | `08_FIELD_MODEL.md §3.1` | the canonical bulk grammar P-6 proves losslessness against |
| depends on | `16_CROSS_PLATFORM.md §8.2` | the CI matrix §10 reports has never run |
| depends on | `11_MIGRATION.md §1` | the decision that removes this plan's migration layer (§2.3) |
| feeds | `12_BUILD_PLAN.md §1` | the "exit gate passes with cited evidence" rule every phase is judged by |
| feeds | `09_UI_UX_SPEC.md §4` | the hover-card rule §7 will assert by counting DOM nodes |
| feeds | `18_ENDPOINT_INDEX.md §4` | the bridge invariants §6's drift guards hold |
| depends on | `14_DECISIONS.md` | `ADR-036` (proptest pinned for the MSRV), `ADR-041`/`ADR-046` (why keystore conformance is deferred), `ADR-045` (the emergency-decrypt test obligation), `ADR-053` (`i21b`), `ADR-059` (the status vocabulary this rewrite applies) |
| depends on | `PHASE8_AUDIT_REPORT.md` | K-1, the accepted risk that I-10 is unimplemented |
| depends on | `RELEASE_VERIFICATION.md` | the human pass over every control of the built app that §8 cannot replace |

## 13. Source

**Design.** `ADR-036` (proptest and the crypto crates pinned below latest for the 1.78 MSRV);
`ADR-041` and `ADR-046` (the hardware keystore tiers and their conformance suite deferred, with
the reason); `ADR-045` (`emergency-decrypt.mjs` must be exercised by a test); `ADR-053`
(`node.restore` authorisation, which produced `i21b`); `ADR-057` (the bridge whose drift guards
§6 describes); `ADR-059` (the `built`/`partial`/`planned` vocabulary); `ADR-062` (the bridge's full
surface, its widened guards, and its CI job); `ADR-063`…`ADR-066` (what `durable_vault.rs` proves).

**Code and tests.** `crates/core/tests/properties.rs` (§3), `crates/core/tests/access_matrix.rs`,
`crates/core/tests/isolation_i17.rs` (I-17), `crates/brokerd/tests/isolation.rs` (the suite and
its module-doc index), `crates/mcp/tests/i13_tool_registry.rs` (I-13),
`crates/cli/tests/success_criteria.rs` (`01_CONCEPT.md §7`'s criteria 1, 2 and 6, backend half),
`crates/cli/tests/emergency_decrypt.rs`, `crates/cli/tests/no_secret_in_argv.rs`,
`crates/core/src/envelope.rs`'s `node_interop_vectors`, `crates/brokerd/tests/durable_vault.rs`
(the live unlock, load-from-disk and write-through, the persisted gate and the last door, the
owner session's reach, and workdir binding — ADR-063…066), and
`apps/desktop/src-tauri/tests/{bridge_wire,bridge_ops,drift_guards,ts_client,shell_config}.rs`; for ADR-078 and ADR-079,
`crates/core/tests/{field_doc,no_field_schema}.rs`, `crates/store/tests/alpha6_golden.rs` (the alpha.6 manifest HMAC
re-serialisation trap), `crates/brokerd/tests/{field_model,seal_durable,approval_locked,seal_digest,field_seal_joint}.rs`,
the version-2 cases of `crates/cli/tests/emergency_decrypt.rs`, and the golden version-1 envelope in
`crates/core/src/envelope.rs`.

**Runs.** `cargo test --workspace -- --list` lists **813 tests in 50 test binaries** (counted 2026-10-03: 45 compiled
test executables, 44 of which carry tests, plus 5 doc-test targets that find no doc test). The last full pass/fail
run recorded is `cargo test --workspace` — **571 passed, 0 failed, 41 test binaries, exit 0** (2026-10-02; earlier:
**448 passed, 37 test binaries** on 2026-09-24, re-measured 2026-10-01; **406 passed, 35 test binaries** on
2026-09-13 — run `34743281942` — and **397 passed, 33 test binaries** on 2026-08-18). The gate run on this tree is
the orchestrator's (`BUILD_LOG.md`). A listed count is not a result: `-- --list` proves what exists, not what passes.
`cargo test` in `apps/desktop/src-tauri` — **40 passed, 0 failed** across 5 targets (re-run
2026-09-24: **65 passed, 0 failed**, with `bridge_ops.rs`, `ts_client.rs` and `shell_config.rs`
added — ADR-062; re-run 2026-10-02: **156 passed, 0 failed** across 10 test executables and a
doc-test target, with the concealed clipboard, the lock-on-sleep observers, the dependency policy
and the macOS pasteboard added; **186 listed in 12 test executables** on 2026-10-03, with the field and
approval commands).
`npm test` in `apps/desktop` — **550 passed, 0 failed, 21 files, exit 0** (2026-10-03).
`python3 scripts/endpoint-matrix.py` — **55 ops, 243 rows (2 probes), 243 passed, 0 known-gap, 0 failed, 5
invariants, exit 0** (2026-10-24; 53 ops and 224 rows on 2026-10-03). `scripts/e2e-journey.sh` — **ALL PASSED, exit 0**, and `scripts/e2e-fields.sh` —
**ALL PASSED, exit 0** (2026-10-03).
`node tests/run-all.js` in `v1/` — **190 passed, 0 failed**.
`python3 -m unittest discover -s tools/docgen/tests -t .` — **52 tests, OK** (re-verified
2026-08-19; `grep -rn "def test_" tools/docgen/tests/*.py | wc -l` also returns 52 — 12 in
`test_doc_outline.py`, 19 in `test_generator_build.py`, 21 in `test_markdown_blocks.py`. The
docgen suite grew after this document's 2026-08-18 rewrite last counted it).

**CI history.** As of 2026-08-18, `gh run list` and `gh run view` against the repository showed
`security` with 34 runs, its latest green in every job including the isolation suite, and `v2 build`
with **no runs at all**. That second half stopped being true on 2026-09-24: `build.yml` run
`35969837662` and `security.yml` run `35969832464` were both green (`BUILD_LOG.md`, "M6 closed").
Workflows added since then (the endpoint-matrix steps in `build.yml`, `security.yml` and
`selfhosted-heavy-check.yml`) have not yet run in CI and are dispatched once on landing.

**Absences verified, not assumed.** No `fuzz/` directory; no `cargo llvm-cov` or `tarpaulin`
invocation; no `criterion` dependency and no `[[bench]]` target; no `vitest` or `playwright` in any
`package.json` as of 2026-08-18 (both are in `apps/desktop/package.json` now, `ADR-075`); no `.cmv2` golden fixture; no pre-push hook; and
`grep -rn "I-26" v2/crates/` returns nothing. (`crates/store/tests/` is no longer empty: it holds `alpha6_golden.rs`.)

**Figure.** §4.1's `isolation-suite-coverage` matrix: `v2/docs/13_TEST_PLAN_spec.json`, rendered by
`tools/visual-engine` (ECharts, `selected_visual: "heatmap"`, family `matrix`) through docgen's
`echarts_bridge`, per `tools/ENGINE_ROUTING_POLICY.md`. 28 rows (I-1…I-25 and I-27…I-29; there is no I-26) × 3
columns (`crates/brokerd/tests/isolation.rs`, `crates/mcp/tests/i13_tool_registry.rs`,
`crates/core/tests/isolation_i17.rs`), re-derived on 2026-10-03 from a live `grep -n "^fn i" ...` over the three
files rather than transcribed from this document's own §4.1 table — 25 claims land in `isolation.rs`
(I-1…I-9, I-11, I-12, I-14…I-16, I-18…I-25, I-27…I-29; the file holds 26 test functions because `i21b` is a
second test for I-21's row), one in `i13_tool_registry.rs` (I-13), one in `isolation_i17.rs` (I-17), and I-10's row is
entirely empty, matching §4.4.
