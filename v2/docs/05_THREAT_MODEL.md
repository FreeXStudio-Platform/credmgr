---
id: V2-005
classification: public
title: Threat model
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-19
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21). The previous stamp (Approved With Known Risks @ d15a5c7, pass 2,
     reconciled 2026-08-10 under ADR-052) attested a body written before the Rust broker existed:
     it described a Node.js runtime (AR-3), a JavaScript crypto library as the remedy for AR-6,
     per-client token *files* that this codebase never writes, a Secure Enclave tier that is not
     built, and a `PT_DENY_ATTACH` mitigation that appears nowhere in the tree. Every claim below
     was re-derived from live source in this pass and the corrections are itemised in §0. The
     hardening stamp is the operator's to assign after their own review; this session is not
     authorised to self-award one.

     Verification-backlog pass, same day (`VERIFICATION_BACKLOG_S21.md`, `05_THREAT_MODEL.md`
     section): seven further findings were re-derived from live source and fixed. Three false
     claims that survived the rewrite — §9.1's "three hardware tiers (Secure Enclave, CNG,
     TPM2)" corrected to the five real `KeystoreId` variants; §0's "`zeroize` in every crate
     manifest" corrected to the three manifests that actually declare it; an un-scoped
     `PT_DENY_ATTACH` grep claim in §0 and §6, narrowed to `v2/crates`/`v2/apps` since the
     string does appear in the corpus's own planned-mitigation rows. Three convention
     violations — a present-tense `planned` row in §4's screenshot line; a `13_TEST_PLAN.md §3`
     citation corrected to §4 (the isolation suite, not the property tests); a
     `04_CRYPTO_AND_KEYS.md §9` register range corrected from the stated R-1…R-6 to its real
     R-1…R-10, with the actual non-1:1 AR↔R correspondence stated in place of the implied one.
     The §4 KeystoreId hardware-tier row was checked against the same live enum and left
     untouched — it already names all five real variants correctly.

     Round 2 verification-backlog pass, 2026-08-19 (`VERIFICATION_BACKLOG_S21_ROUND2.md`,
     `05_THREAT_MODEL.md` section): two further findings were re-derived from live source and
     fixed. §8.1 ("What is built") claimed the audit log's 12-month retention and human-only
     purge were live mechanisms; no retention- or purge-enforcement code exists anywhere for the
     audit log (`03_DATA_MODEL.md §9` states it plainly as `planned`, and `audit.purge` appears
     in this build only on the forbidden-tool list I-13 enumerates). The claim is moved to §8.2
     and rewritten in the future tense the status vocabulary requires (`ADR-059`). §0's own
     citation of `04_CRYPTO_AND_KEYS.md:578` for the `PT_DENY_ATTACH` planned-mitigation row had
     drifted 11 lines from the live location (the string is at line 589 today, inside §9,
     Residual weaknesses) — replaced with a section citation, `§9`, which does not rot as the
     target file is edited. Updated 2026-09-24 for ADR-062…066 (the webview's CSP, all 42 ops
     bridged, the live unlock, the root key resident while unlocked, the login's whole-vault
     reach, K-5…K-7). Updated 2026-09-24 for ADR-070…073 (the bridge at 47 ops, §3.4; the
     backoff's 1-hour cap in the Source list). Updated 2026-10-02 for ADR-075…077 (the bridge at 48
     ops; the hosted design replaces the scaffold, §3.4; the concealed clipboard and lock-on-sleep;
     the audit log no longer holds a session bearer, §3.2 and §8.1; stored TOTP seeds of 80 bits).
     Updated 2026-10-03 for ADR-078/079 (the bridge at 53 ops, every screen wired, the Copy button on the
     concealed clipboard, §3.4; the manifest's `hasTotp` and the field labels' place in the plaintext
     boundary, §3.1; the orphan cold key and seal records, K-5 and K-7, §7; I-27…I-29, §4). -->
# Threat model

`CredMgr V2` · which adversaries this design defeats, which it does not, and the risks accepted on the record · `2026-08-18`

> **Status.** The controls in §4 are **built and tested in-process**: the isolation suite runs
> I-1…I-25 with I-10 unimplemented, plus I-27…I-29 for the field model (`crates/brokerd/tests/isolation.rs`; accepted risk K-1 in
> `PHASE8_AUDIT_REPORT.md`), and `cargo test --workspace -- --list` lists 813 tests across 50 binaries (2026-10-03; the last full run recorded passed 571 across 41 on 2026-10-02, 448 across 37 on 2026-09-24).
> Since 2026-08-31 they are also **reachable at runtime**: `crates/brokerd/src/main.rs` calls
> `server::run` and serves the socket, and `credmgr init` creates a vault (`ADR-061`) — so the
> guarantees below are now properties of a daemon an attacker could actually meet, not only of
> code that has been exercised. A **new trust boundary appeared on 2026-08-18** and is the
> largest change to this document since Pass 2: a Tauri↔broker bridge now makes `entry.reveal`
> reachable from a webview process (ADR-057), where previously the only clients were a terminal
> and a test harness. That boundary is `partial` — the bridge, the wired application, the CSP and the
> concealed clipboard exist; a distinct audit origin for the webview does not — and §3.4 gives its full target design. The hardware keystore tiers, the org vault,
> sync, the optional commercial-licence certificate and release signing are `planned`; §9 states the threat model each of them will
> have to satisfy, and none of it is written here as though it exists.

---

## 0. What this rewrite corrected

Listed rather than silently fixed, because a threat model that quietly changes its claims teaches
readers to trust the wrong thing. Each row was checked against source on 2026-08-18.

| Was | Is | Evidence |
|---|---|---|
| AR-3: "Node.js heap cannot be reliably zeroised" | The broker is Rust (ADR-009, adopted). `BrokerState::lock()` zeroises every hot-key buffer in place. AR-3 now names the residual that actually survives that. | `crates/brokerd/src/state.rs::lock`; `zeroize` is declared in three of the six crate manifests (`core`, `keystore`, `brokerd`) — `store`, `mcp` and `cli` have no `zeroize` dependency, and nothing in this claim depends on them having one |
| AR-6 resolution: "adopt `@noble/ciphers`" | A JavaScript package, unreachable from a Rust workspace. The construction is assembled from RustCrypto crates; the residual is that it is hand-assembled, not that its primitives are. | `crates/core/src/envelope.rs`, `crates/core/Cargo.toml` |
| AR-2 resolution: "Rust broker if the threat model widens" | Already done. AR-2's resolution path is now the auto-lock default and the hot-set scope. | ADR-009 · `crates/brokerd/` |
| §4: "tokens are per-client files it can also read" | No token is ever written to disk. `TokenStore` is an in-memory map in the broker process. The real hole is different and worse — see AR-5 and §5. | `crates/brokerd/src/token.rs`; no token path in `crates/store/src/paths.rs` |
| §6: "`PT_DENY_ATTACH`, hardened runtime" mitigate debugger attach | Neither string appears anywhere in the code. The mitigation is planned, not present. | `grep -rn "PT_DENY_ATTACH" v2/crates v2/apps` → no matches (the string does appear in the corpus itself, as a `planned` mitigation row in the R-3 entry of `04_CRYPTO_AND_KEYS.md §9` — which is not code) |
| §4: "RK is behind the Secure Enclave" | Only the `Software` tier (Argon2id, m=256 MiB, t=3, p=4) is built. The three hardware tiers are enum variants with no implementation (ADR-041). | `crates/keystore/src/software.rs`, `crates/keystore/src/lib.rs` |
| §4: "auto-lock on sleep/screen-lock" | Only the idle timer fires in production. `external_lock_signal` is built and tested but has no native caller. | `crates/brokerd/src/server.rs` autolock thread; `grep -rn external_lock_signal` → tests only |
| §8: "5 cross-node denials raise a UI alert" | The limiter is built and I-16 proves it trips. The boolean it returns is discarded at the call site, and no screen is wired to raise anything. | `crates/brokerd/src/rate_limit.rs`, `server.rs` denial hook |
| §8: "`credmgr verify` reports the break without unlocking" | `audit::verify` walks the chain and checks the tip HMAC, and is unit-tested — but nothing calls it. `maintenance.verify` checks manifests, cross-binding and dangling envelopes, not the audit chain. | `crates/store/src/audit.rs::verify`; `grep -rn "audit::verify" crates/` → no callers |
| §8: "`credmgr audit` … grants unused for 30+ days" | `credmgr audit` reads the log. No stale-grant sweep exists; `audit.report` is dispatched nowhere. | `crates/cli/src/main.rs::cmd_audit`, `crates/brokerd/src/ops.rs` |
| AR-1 resolution: "Pass 2 to decide" | Pass 2 decided it (A-7 → ADR-029): plaintext names by default, per-node `privateNames` opt-out. The field exists on the node policy and **no code reads it**. | `crates/core/src/registry.rs` `private_names`; `grep` finds no consumer |

## 1. What is being protected

Timeless. The asset list does not change with build status; only the controls do.

| Asset | Sensitivity | Loss means |
|---|---|---|
| Credential values — infrastructure root passwords, wallet private keys, seed phrases, API tokens | **Critical** | Live infrastructure and funds |
| TOTP seeds held as vault items | Critical | Second factor defeated on the services they protect |
| Node notes — operational context | High | The attacker learns *how* to use what they stole |
| Vault topology — node names, entry names, counts, grant edges | Low–Medium | Reconnaissance, and a target list |
| Audit log | Medium | The ability to detect and reconstruct an incident |

For scale: the V1 vault this product replaces holds 185 credentials of exactly these classes.
V2 creates its own vault and imports nothing (`11_MIGRATION.md`), so that number is a measure of
what a single operator's vault realistically contains, not of what any V2 vault holds today.

## 2. Adversaries

| ID | Adversary | Realistic? | Priority |
|---|---|---|---|
| **A1** | **Confused agent** — a coding-agent session scoped to project B that asks for project A's secret, by mistake or by following a stale document | **Happens today** | **P0** |
| **A2** | **Injected agent** — the same session, steered by prompt injection in a scraped page, a README, or a tool result, deliberately exfiltrating | Plausible and rising | **P0** |
| **A3** | **Operator error** — removing the wrong node, pasting a secret into the wrong place, destroying something still needed | **Happens** | **P0** |
| **A4** | **Offline disk** — a stolen or lost laptop, an old backup image, a synced folder, external media | Plausible | P1 |
| **A5** | **Shoulder and screen** — screen share, screenshot, recording, a value left visible | Plausible | P1 |
| **A6** | **Local malware running as the user** — anything with the owner's uid | Possible | P2 |
| **A7** | **Supply chain** — a compromised dependency inside the vault process | Possible | P2 |
| **A8** | **Broker compromise** — code execution inside `credmgrd` while unlocked | Low, catastrophic | P2 |
| **A9** | **Root, kernel, physical DMA, cold boot** | Very low | **Out of scope** |
| **A10** | **Coerced operator** | — | **Out of scope** |

**A1–A3 are the design centre.** They are the threats that actually materialise on a one-person,
agent-heavy machine, and they are the ones a user-space vault can genuinely address. Everything
this project deletes relative to V1 — the HTTP surface, the second export password, the
schema-driven field types — was deleted because it bought nothing against A1–A3 while adding a
place for A6–A8 to stand.

## 3. Trust boundaries — every process a plaintext secret can occupy

A control is only as good as the boundary it sits on, so the boundaries are enumerated before the
controls. A secret in this system exists as plaintext in exactly three places, and one of them is
new as of 2026-08-18.

### 3.1 The vault directory — **`built`**

Ciphertext only. Every entry is a `CMV2` envelope sealed to one node's X25519 public key, with
the magic, version, suite, node id and entry id bound into the AEAD's additional data, so
relocating an envelope into another node's directory fails the tag check rather than decrypting
under the wrong key (`crates/core/src/envelope.rs`; property-tested in
`crates/core/tests/properties.rs`).

What is **deliberately** plaintext beside it: `registry.json` and the per-node manifests — node
names, tree shape, grant edges, entry counts, entry names, each entry's type, sensitivity, field *count* and
whether it holds a TOTP seed (`hasTotp`, ADR-078) — so the graph can draw and locked
search can work without unlocking. **No field label, field type or value is ever in the clear:** they live in
the version-2 envelope with the values (`03 §3`), never in the manifest, the pending-tray sidecar or the audit
log (D12), and a message about a rejected field names an index or an id. They are HMAC-SHA256-signed under a root-key-derived subkey
(`crates/core/src/signing.rs`), so the shape can be read but not rewritten, and a rolled-back
registry is caught by a monotonic generation counter kept in a separate per-user state directory,
outside the vault (`crates/store/src/generation.rs`, `paths.rs::default_state_dir`). I-19 proves
a tampered manifest is refused at broker open; I-20 proves a validly-signed but older registry is
refused on the generation check. The exposure itself is AR-1.

### 3.2 The broker process — **`built`**

The single enforcement point (ADR-001). It is the only process that ever holds an unwrapped node
key, and it holds every unlocked one at once, in a hot set that `lock()` zeroises in place. Its
ingress is one Unix domain socket at `<vault>/run/broker.sock`, mode `0600`, and every connection
is identified by `getsockopt` peer credentials before a single byte of the request is parsed —
uid as a hard gate, pid→cwd as an advisory signal only (`crates/brokerd/src/peer.rs`).

`crates/core` is I/O-free by construction, which is what makes the access rules exhaustively
testable: I-17 fuzzes `resolve()` over random graphs in a crate that cannot touch a file.

### 3.3 The client process — **`built` for the CLI and the MCP server**

A revealed value crosses the socket into whichever client asked for it. For the CLI that is a
terminal, where the operator's own scrollback is the residual exposure (A5), and `set` takes its
value from stdin or `$EDITOR` rather than argv precisely so it never reaches shell history or
`ps` (`crates/cli/tests/no_secret_in_argv.rs`). For the MCP server it is an agent's context
window, which is the whole reason the access graph exists.

### 3.4 The webview process — **`partial`, and new**

**This boundary did not exist when Pass 2 was written.** Until 2026-08-18 the only clients of
`entry.reveal` were a terminal and a test harness. A Tauri↔broker bridge now exposes **all 53**
of the broker's operations to a webview (ADR-057 wired the first eight — `vault.status`,
`vault.unlock`, `vault.gate_verify`, `vault.lock`, `whoami`, `graph.snapshot`, `entry.list`,
`entry.reveal` — and ADR-062 the other thirty-four, on 2026-09-24, with five more the same day
for ADR-071…073, among them `notes.read`, whose payload is a node's decrypted note, and
`maintenance.rotate_root` for ADR-076, whose response carries a new recovery code once;
`apps/desktop/src-tauri/src/commands.rs`). `entry.reveal` is the one whose response payload *is*
the secret, so decrypted plaintext now crosses into a renderer that executes web content — and
since ADR-065 the desktop's own login reaches every node but Orphaned, so that plaintext can be
any project's.

**What is built, and is genuinely load-bearing:**

- **The session token never crosses the IPC boundary.** `vault.unlock` and `vault.gate_verify`
  mint an ADR-056 capability token scoped `global` with every capability including `Admin`,
  evaluated since ADR-065 as each target node it names, so it reaches every node but Orphaned; the
  bridge strips the `token` field from the response body, stores it in Tauri managed state, and
  attaches it to outbound calls Rust-side. The commands return `{locked, authenticated}` and
  nothing token-shaped. `session.rs`'s own tests assert the field does not survive into the value
  handed to the webview, and that a non-string token is stripped but never stored.
- **A dead token is refused, not silently demoted** (ADR-068, 2026-09-24). Until then the broker did
  not reject an unknown token id — `resolve_scope` step 1 failed to match it and fell through to
  cwd resolution as `Origin::Agent` — so a revoked token quietly *reduced* its holder's
  capabilities. It now answers `session_expired` (except on the seven ops that report or
  re-establish a session, or lock). The bridge treats that, and `locked: true` — from the body of one of the four vault-state ops
  (`session::VAULT_STATE_OPS`; `vault.node_lock`'s `locked` is about one node and is not read as
  the vault's, ADR-062), from `graph.snapshot`'s `meta.vaultLocked`, or from a `vault_locked`
  denial — as proof its token is dead, and drops it.
  Since nothing pushes the idle auto-lock to a client, an ordinary status poll is the only way it
  can be observed, which makes that path load-bearing rather than defensive. The revocation no
  lock signal covers — a login unused for the idle timeout, revoked on its own clock while agent
  traffic keeps the vault unlocked (ADR-065) — was an open gap until ADR-068: the bridge kept the
  dead token and its next call was resolved from the app's cwd. It is now refused as
  `session_expired` on that next call, and the bridge drops the token.
- **The copied constants are pinned against the real source.** `tests/drift_guards.rs` parses
  `crates/brokerd/src/protocol.rs`, `ops.rs` and `crates/store/src/paths.rs` off disk, rather than
  comparing the copy against itself. This is the shape the corpus spent months wrongly believing
  a test `I-26` had for `18_ENDPOINT_INDEX.md`.
- **The window has a real Content Security Policy** (ADR-062, 2026-09-24). Production is
  `default-src 'self'`, no `unsafe-*`, no origin but Tauri's own IPC, `data:` for images only;
  only the development policy may reach the local Vite server. `tests/shell_config.rs` reads
  `tauri.conf.json` and fails closed on `null` or on any remote origin.
- **The passphrase argument to `vault.unlock` is honoured** (ADR-063): the broker builds its
  Software keystore from it per request. It still arrives as a JavaScript string already copied by
  the IPC layer, and is dropped without a zeroisation guarantee — a real limitation, bounded here
  rather than hidden.

- **The shell reaches nothing it does not need.** The capability file grants `core:default` only; the
  stock scaffold's `greet` command and the `opener` plugin are gone (ADR-075), nothing in the app opens
  an external URL, and `tests/shell_config.rs` fails if either returns. `tests/dependency_policy.rs`
  fails if an HTTP client, server or TLS binding appears in the tree linked on macOS.
- **A secret copied through the shell is concealed, host-only and short-lived.** `entry_copy` reveals the entry Rust-side — the value never
  reaches the webview — and writes the clipboard with the `ConcealedType` and `TransientType` markers and `CurrentHostOnly` (so it stays out of Universal
  Clipboard and Handoff), clears it 30 seconds later only if it is still the app's own content, and
  clears it at once on a lock, sleep, screen lock, session switch or quit. A copy whose reveal is in
  flight when a lock lands is refused. Residual: a clipboard manager that ignores the markers can still
  read the value during those 30 seconds. **Reachable from every Copy button:** a field's Copy goes through
  `entry_copy` with the field's id, and `navigator.clipboard` appears nowhere in `apps/desktop/src`
  (`tests/unit/architecture.test.ts` fails if it does), so the value never enters the webview on that path.
- **The vault locks when the machine does.** On sleep, display sleep, a session switch or a screen lock
  the shell sends `vault.lock` whether or not this app holds a login, and clears the clipboard before
  the machine can sleep (`apps/desktop/src-tauri/src/autolock.rs`). Residual, stated in that file: the
  broker's own idle lock and the screen lock are what remain when the app is not running.
- **Local storage names nothing.** The few keys the window writes to the webview's local storage
  (`PRIVACY.md` lists them) hold layout and cosmetic choices only; any key that could name a vault
  object is hashed (`hid(kind, id)`, 16 hex of SHA-256). Hashing keeps names out of the clear but ids
  are low-entropy, so it is not a defence against someone who can already read the profile directory.

**What is built, and what is not.** `v2/apps/desktop/` hosts the design (ADR-075) and **every screen goes
through the broker, writes included**: an action makes one bridge call and re-reads what it touched, and a
release build has no demo data and no local-only write path (`scripts/dc/verify-build.mjs` asserts the built
bundle contains neither the fixture broker nor the demo vault). Not done is the real-app pass
(`RELEASE_VERIFICATION.md`) and the items below. (Until 2026-09-24 this
paragraph also recorded that the window shipped with **no Content Security Policy** — `"csp": null` —
and that the broker ignored `vault.unlock`'s passphrase; both are now built, above.)

**The full target design for this boundary.** The first item is built; items 2–4 do not exist
yet, and item 5 was superseded:

1. **A restrictive CSP is set and is a release gate — `built`** (ADR-062). `default-src 'self'`,
   no `unsafe-inline`, no remote origin of any kind, asserted by `tests/shell_config.rs`, which
   reads `tauri.conf.json` and fails closed on `null` — the same read-the-real-source pattern the
   drift guards use. A vault window that can load a remote script is a vault window that can
   exfiltrate what `entry.reveal` just handed it, and A-1's no-outbound-network property protects
   the *broker* process, not the renderer.
2. **A revealed value has a lifetime, not just a recipient — `partial`.** Built: the concealed
   clipboard with a time-to-live (above; every Copy button reaches it), and a front-end model that keeps a revealed value in a
   private store the rendered view never holds, expiring with the reveal window and wiped on lock,
   when the window is hidden and when the selected node changes. Not built: a guarantee about what a
   crash dump or a devtools snapshot of the renderer contains — the value is, for as long as it is
   shown, a string in the renderer.
3. **Devtools will be compiled out of release builds**, and the release build will assert it.
4. **The webview will get its own origin entry in the audit record.** `Origin::HumanUi` today
   cannot distinguish a native window from a webview inside one; the target is a distinct origin
   so a reveal into a renderer is legible in `audit.tail` as exactly that.
5. **~~Mutating operations will be wired only alongside the screens that drive them~~ —
   superseded by ADR-062.** ADR-057 held this because each mutating op carries an
   optimistic-concurrency `generation` and several sit behind presence or approval gates. ADR-062
   wired every op anyway, with the bridge making no UX decision for any of them: `generation`,
   presence and approval stay broker-side and reach the UI as the broker's own error codes, and
   every command inherits the same token custody.

**Why this is not yet numbered as an accepted risk.** The accepted-risk register in §7 is cited
corpus-wide by its identifiers, and `16_CROSS_PLATFORM.md §10` independently numbers its own
`AR-7`…`AR-10` — four identifiers, not three. Adding an `AR-7` here would create two different
risks under one name in a corpus that cites them by bare identifier. The boundary is therefore
stated in full here and will be given an identifier in a single pass that renumbers both registers
together — recorded as open work rather than resolved by picking a number unilaterally.

<!-- figure:plaintext-trust-boundaries -->

Which processes can a decrypted secret be inside, and which of those boundaries is new: the
vault directory itself never holds one (ciphertext only); the broker and the CLI/MCP clients
have carried plaintext since Pass 2; the webview (ADR-057) is the one new boundary, and it is
the only one drawn dashed above because it alone still lacked a CSP, a value lifetime, and a
distinct audit origin when the figure was rendered. The CSP has since been built (ADR-062), and a
revealed value's lifetime in part (above); the distinct audit origin is still `planned`.

## 4. Attack → control matrix

Each row states V1's outcome, V2's control, V2's outcome, and the **status** of the control with
its evidence. `crates/brokerd/tests/isolation.rs`'s own module documentation states the contract
in the other direction: "each test corresponds to a claim in `05_THREAT_MODEL.md §3`, and a claim
without a test here is a hope, not a claim." This section is that claim list, and the test column
is what makes the statement checkable rather than mutual flattery.

| Attack | V1 outcome | V2 control | V2 outcome | Status · evidence |
|---|---|---|---|---|
| Agent in project B asks for project A's credential | **succeeds** | Broker resolves the caller's scope, checks the access graph, denies | Structured refusal, no leak in the error, audit record naming the requesting cwd | **`built`** — `i1_cross_node_reveal_is_denied_with_no_leak` |
| Agent lists every credential to find targets | returns all 185 | `entry.list` is scope-filtered at the broker | Only its own node, its ancestors, and granted targets | **`built`** — `i2_entry_list_covers_self_and_global_never_out_of_scope` |
| Agent searches for a name it should not see | matches | `search` spans only reachable nodes; an out-of-scope hit is indistinguishable from no match | Zero results, identical to a genuine miss | **`built`** — `i3_search_only_matches_in_out_of_scope_node_returns_zero_results_same_as_no_match` |
| Sub-node reads sideways into an unrelated project | n/a | R0–R8 resolution: ancestors and depth-2 siblings yes, other projects never | Denied | **`built`** — `i4_subnode_reads_parent_and_sibling_and_global_never_other_projects` |
| Parent node reads its children by default | n/a | Descendant read is opt-in, never implied by the tree | Denied unless enabled | **`built`** — `i8_parent_cannot_read_children_by_default`, `i9_descendant_read_opt_in_reaches_children_but_not_other_projects` |
| Grant is over-broad, stale, or revoked mid-session | n/a | Grants carry an explicit capability set, an expiry, and take effect on the next request | A revoked grant denies immediately; an expired one reports as expired | **`built`** — `i5_…`, `i6_revoked_grant_denies_the_very_next_request`, `i7_expired_grant_is_denied_and_reported_as_expired`, `i24_entry_level_grant_narrows_list_to_exactly_the_granted_entry` |
| Injected agent tries every project name in turn | eventually finds one | Cross-node denials are counted per uid in a 10-minute window; the fifth trips an anomaly | Loud failure — **but nothing consumes the signal yet** | **`partial`** — limiter and trip proven by `i16_five_cross_node_denials_in_ten_minutes_trip_the_anomaly`; `server.rs` discards the returned boolean and no surface renders it |
| Agent tries to widen its own scope | n/a | A token's `node_id` and capabilities are fixed at issue; nothing in the crate mutates them. `node.reparent` refuses on every transport this build has | Impossible via any tool | **`built`** — `crates/brokerd/src/token.rs`, `i23_reparent_refuses_on_every_phase3_surface_admin_included` |
| Agent presents a token from the wrong directory | n/a | The token remains the authority; the mismatch is written to the audit log as an anomaly | Proceeds, and is legible afterwards | **`built`** — `i12_token_workdir_mismatch_proceeds_and_writes_an_anomaly_to_the_audit_log` |
| Agent reads another node's operational notes | succeeds — notes were a free-text field | `Capability::Notes` is never inherited from `agentAccess`; it must be granted explicitly | Denied | **`built`** — `crates/brokerd/src/scope.rs::capabilities_for_agent_access` |
| MCP tool surface grows a forbidden capability | n/a | I-13 walks the live tool registry, not a copy, and fails on a forbidden op or name fragment | A forbidden tool cannot ship | **`built`** — `crates/mcp/tests/i13_tool_registry.rs` |
| Operator removes the wrong node | data gone unless changelog undo caught it | Seal, never delete (ADR-007). Names retained, 7-day archive, one-click restore | Recoverable for 7 days, byte-identical | **`built`** — `i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone`, `i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node` |
| Two writers race on the same entry | last write wins silently | Every mutation echoes the manifest generation it read; the broker answers `conflict` if it moved | Exactly one wins, loudly | **`built`** — `i25_concurrent_writers_same_starting_generation_exactly_one_wins` |
| Vault directory is tampered with offline | undetected | Registry and manifests are HMAC-signed and cross-bound; generation is checked against an external counter. Since ADR-063 the live daemon checks all of it at unlock, in one read of each file, all or nothing; a **missing** counter is refused (override: start `credmgrd` with `CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1`, for a vault moved between machines), and a vault file that is a symlink or FIFO is refused | Refused at broker open or unlock, naming the node; nothing is loaded | **`built`** — `i19_tampered_manifest_is_refused_at_broker_open_naming_the_node`, `i20_rolled_back_registry_is_refused_on_the_generation_check`, `durable_vault.rs::a_tampered_registry_is_refused_at_unlock_and_nothing_is_loaded`, `::a_rolled_back_registry_is_refused_at_unlock` |
| Laptop stolen, vault **locked** | one key file and one archive; machine-lock helps | Per-node keys, all wrapped; the root key unwraps only through the keystore | Reduces to the strength of the Argon2id passphrase (or of the recovery code, if it is lost with the machine) — **two-factor does not help here: it is checked by `credmgrd`, not by the encryption (K-5, `04 §2.1`)**, and **the hardware tiers that would make this a device-bound problem are not built** | **`partial`** — `crates/keystore/src/software.rs` built; `MacosSecureEnclave`/`WindowsHello`/`WindowsDpapi`/`LinuxTpm`/`LinuxSecretService` are enum variants only (ADR-041) |
| Laptop stolen, vault **unlocked** | everything | Node keys — and, on a live vault, the root key (ADR-063) — are in memory; sealed nodes stay unreachable; the idle timer locks | Partial by design — see AR-2 | **`partial`** — idle auto-lock runs on a 30-second tick in `server.rs`; `external_lock_signal` (sleep, screen lock, session end) is tested but has no native caller |
| Wrong factor presented at unlock | n/a | A failed unwrap leaves the hot set exactly as it was | No node key loads on a wrong factor | **`built`** — `i15_wrong_passphrase_leaves_the_hot_set_empty` |
| Old backup image found | full vault | Backups are Argon2id-sealed under a separate backup passphrase; per-node keys still apply | Improved, still a passphrase-strength problem | **`built`** — `crates/keystore/src/backup_passphrase.rs`, `crates/store/src/backup.rs` |
| Screenshot of the main screen | credential list visible | The home screen will be a graph: node labels and two counts, no entry names, no values | Will leak topology only | **`planned`** as a verified property — the hosted design (ADR-075) draws a graph home screen, but no test of `13_TEST_PLAN.md §7` asserts what the live screen shows (`09_UI_UX_SPEC.md`) |
| Reveal while the vault is locked | n/a | Topology still lists; a reveal that would otherwise be permitted opens a one-tap approval path instead of failing | `approval_pending`, not a denial | **`built`** — `i14_locked_vault_still_lists_topology_but_reveal_requires_approval`, `i18_create_while_locked_lands_in_pending_and_update_is_refused_until_accepted` |
| Per-node "always require 2FA" policy on a wallet node | n/a | `requireTwoFactor` is stored, published in `graph.snapshot` and **enforced** since 2026-10-24: with a confirmed gate, a reader that is not the owner's own login gets `two_factor_required` for a value (`reveal`) or any read (`always`) until a fresh gate verification | The factor and its five-minute window are the **vault's**, not the node's; a per-node gate secret is unbuilt | **`built`** against the vault gate (ADR-085) — `crates/brokerd/tests/part4_two_factor.rs` |
| Malware as the user, vault **locked** | reads the key file → everything | The root key is behind the keystore; no file on disk is usable alone | Meaningfully improved, bounded by the Software tier | **`partial`** — same tier gap as the stolen-laptop row |
| Malware as the user, vault **unlocked** | everything | It connects as the right uid and needs no token at all: with no token presented, `resolve_scope` falls through to cwd, so a `chdir` into a registered workdir yields that node's `agentAccess` capabilities | **Not stopped.** See §5 | **`built` as described** — `crates/brokerd/src/scope.rs` steps 2–3; AR-5 |
| Code execution inside the broker while unlocked | n/a | — | **Not stopped.** Every unlocked node key, and the resident root key, is exposed | AR-2, accepted |

## 5. Why scope resolution still helps against A2 — and exactly where it stops

The obvious objection is that an injected agent runs as the same user, so any boundary drawn in
user space is decorative. The precise answer matters, because the imprecise version of it in the
previous revision was wrong in a way that flattered the design.

**The wrong version.** The previous text said an attacker would have to steal "another project's
token file". There are no token files. `TokenStore` is a `Mutex<HashMap>` inside the broker
process and nothing writes a token to disk.

**The actual position.** A caller with no token gets a scope derived from its working directory
(`resolve_scope` step 2), and a caller whose cwd matches nothing gets `global` with `list` only
(step 3). So local malware running as the owner does not need to steal anything: it changes
directory into a registered workdir and connects. What it gets there is bounded by that node's
`agentAccess` policy, which can include `Reveal`.

Scoping still buys four things, and they are worth stating exactly because they are what the
design actually delivers:

1. **It converts an accident into a deliberate act.** A1 — by far the most common case —
   disappears completely. There is no honest path to another node's data, so a confused agent
   fails rather than succeeding quietly.
2. **It converts a silent success into a legible one.** Reaching another node means either
   presenting a token bound to a different directory, which is logged as an anomaly (I-12), or
   changing directory into a project that is not yours, which is a portfolio-rule violation with
   its own trail.
3. **It removes single-call exfiltration.** A `list` that returns 185 names is a reconnaissance
   gift. Scope-filtered listing means the attacker must already know what to look for (I-2, I-3,
   I-22).
4. **It bounds a partial compromise.** One workdir, or one leaked agent token, is one node — not
   the vault. **A leaked login token is the exception** since ADR-065: a token minted by
   `vault.unlock`/`vault.gate_verify` reaches every node but Orphaned until the vault locks or the
   session goes unused for the idle timeout (15 minutes by default, on its own clock even while
   agent traffic keeps the vault unlocked). That is accepted risk K-6
   (`PHASE8_AUDIT_REPORT.md §4`); the CLI prints a warning beside the exported token.

What it does **not** do is stop a determined attacker with code execution as the owner. No
user-space vault does. That is the honest line, and it is the same line V1's own documentation
draws.

## 6. Explicitly out of scope

- **Root, kernel, DMA, cold boot, hardware implants.** A9.
- **A debugger attached to the unlocked broker.** Undefended today: neither `PT_DENY_ATTACH` nor
  a hardened-runtime entitlement appears anywhere in `v2/crates` or `v2/apps`. `04_CRYPTO_AND_KEYS.md
  §9`'s R-3 row names both as `planned`, with no target design elaborated yet — `21_RELEASE_AND_INTEGRITY.md`
  does not cover this (its §3 is code-signature and resource-hash self-verification, a different
  mechanism). Until an anti-debugging design is written and built, this is stated as absent rather
  than mitigated.
- **The operator's own authority.** A human with the passphrase and the gate code can read
  anything, including sealed data. That is the definition of a vault, not a hole in one.
- **Defending against the operating system.** If the OS is compromised, everything is.
- **Multi-user and multi-tenant use.** V2 is single-user, single-machine; the peer-credential
  check rejects every other uid outright before parsing a request.
- **Denial of service by the owner against themselves.** Filling the disk, deleting the vault
  directory, or forgetting both the passphrase and the recovery codes are recoverable only from
  backups, by design — there is no escrow the vendor holds, because there is no vendor path
  into the vault at all.

## 7. Accepted risks

Each carries a description, a bound, an owner and a resolution path, per the portfolio's
`Approved With Known Risks` contract. **These six identifiers are cited across the corpus and are
stable**; their contents were corrected in this pass where source disagreed with them (§0).

| ID | Risk | Bound — what it does **not** affect | Owner | Resolution path / trigger |
|---|---|---|---|---|
| **AR-1** | Registry and manifest metadata is plaintext: node names, tree shape, grant edges, entry counts, and **entry names** | No field label, no value, no note, no TOTP seed. Tamper-evident: HMAC-SHA256 under a root-derived subkey, plus a generation counter held outside the vault directory | CredMgr agent | **Decided, not built.** ADR-029 resolves it — plaintext by default, per-node `privateNames` opt-out for wallet-class nodes. `Node.policy.private_names` exists in `crates/core/src/registry.rs` and **no code reads it**; the risk stands undiminished until a manifest writer honours it |
| **AR-2** | The broker holds every unlocked node key in memory simultaneously — and, on a live passphrase-unlocked vault, the root key (ADR-063, as amended 2026-09-24) | Sealed nodes and explicitly node-locked nodes are excluded; the passphrase is never resident; `lock()` zeroises the hot buffers and the resident root key in place. *(Corrected 2026-09-24: this cell said the root key is not retained after the hot set is derived — true only before the live unlock existed. The Software tier must keep either the root key or the passphrase resident to write, and the passphrase re-derives the same key.)* | CredMgr agent | Accepted, bounded by auto-lock. The idle timer is built (30-second tick); the sleep/screen-lock half needs a native observer to call `external_lock_signal`, which nothing does yet |
| **AR-3** | Zeroisation is best-effort against the operating system, not against the language | Ciphertext at rest is unaffected. Rust's `zeroize` covers the buffers the broker owns, and `StaticSecret`'s `Drop` covers transient per-use copies | CredMgr agent | Accepted permanently. What survives: pages the OS may have swapped or captured in a hibernation image, and transient copies the JSON response path makes on the way out of the process — neither is addressable from user space. *(Superseded the Node.js-heap framing, which described a runtime this project no longer uses.)* |
| **AR-4** | Grants are enforced at the broker rather than cryptographically wrapped, so they collapse if the broker is compromised | The same blast radius as AR-2 — no *additional* exposure beyond what a compromised broker already has | CredMgr agent | Accepted permanently. The alternative — key-wrapped grants — loses instant revocation, which is the property that makes granting safe enough to do at all |
| **AR-5** | Working-directory-derived scoping is spoofable by `chdir` | A presented token overrides cwd entirely, and a token/cwd disagreement is logged as an anomaly (I-12). **The bound is narrower than previously stated:** when *no* token is presented, cwd is not merely an audit signal — it is the authority (`resolve_scope` step 2) | CredMgr agent | Accepted permanently for the agent path. Mitigated in the human path by session tokens (ADR-056), which the CLI and the desktop bridge both hold |
| **AR-6** | The sealed box is a hand-assembled HPKE-shaped construction rather than a reviewed HPKE implementation | The primitives are not hand-rolled: `x25519-dalek`, `hkdf`, `sha2` and `chacha20poly1305` from the RustCrypto set, following the RFC 9180 DHKEM(X25519, HKDF-SHA512) shape, with the node id and entry id bound into the AEAD's additional data | CredMgr agent | Re-review when the MSRV pin permits. *(The previous resolution named a JavaScript package, which is unreachable from this workspace; the real candidate is a maintained Rust HPKE crate whose dependency tree clears the 1.78 pin.)* |

Four further risks — **K-1** (I-10 unimplemented), **K-2** (ancestor-restore narrowed), **K-3**
(named non-gate items unbuilt, since closed) and **K-4** (release signing certificates
outstanding) — belong to the Phase 8 backend audit and are recorded in `PHASE8_AUDIT_REPORT.md`,
which added three more on 2026-09-24: **K-5** (the first release is Software-tier and unsigned),
**K-6** (an exported login reaches every project) and **K-7** (the locked-write tray's metadata and
in-window seal records were memory-only; **closed apart from its factor-bearing half by ADR-069 and
ADR-079**), and **K-8** (the rollback counter is a user-writable file). This document does not
re-litigate them; K-1 is the one that bears on §4, because it is why the isolation suite runs I-1…I-25
minus I-10, and I-27…I-29, rather than every number in its range. **K-5 bears on §4 too:** two-factor is a
check made by `credmgrd`, not part of the encryption, so the controls in §4 that rest on the gate defend a
*running broker*, not a copied vault directory (`04 §2.1`).

## 8. Detection — because prevention will not be complete

Prevention that cannot fail is a fantasy. Detection is the other half, and it is the half this
build has least of.

### 8.1 What is built

- **Every access decision is recorded, allow and deny alike**, with the deciding scope and the
  requesting process's working directory. Denials are the highest-signal event in the system.
- **The record names a session, never its bearer** (ADR-077). The audit `actor` is
  `<Origin>:s_<16 hex>` — a public id drawn independently of the session token — and bearer-shaped
  strings are redacted on the way into the log and on the way out of `audit.tail`. Until ADR-077 the
  token itself was the actor, in the plaintext file and in a feed any caller holding `list` could
  read, so any process running as the owner could replay it (`SECURITY.md`, "Session token in the
  audit log"). Vaults written by alpha.4–alpha.6 still hold dead `cmt_…` strings in their audit
  files; they are deliberately not rewritten, because that would break the hash chain.
- **The audit log is hash-chained.** Each line's `prev` is the SHA-256 of the previous line's raw
  bytes, so editing or removing any line but the last breaks the next line's link. Truncating the
  *last* line is caught by an HMAC'd tip sidecar recording the expected count and final hash —
  the same "unencrypted must not mean unprotected" pattern as the registry — **until the next
  request**: `audit::append` signs the tip over the log as it stands without verifying it first, so
  a truncated tail followed by any request is signed as the new truth (accepted risk K-9,
  `PHASE8_AUDIT_REPORT.md §4`). `credmgr verify` before the next use sees it.
- **Anomalies are written to the log as first-class records**, not inferred later. Today exactly
  one kind exists: a token whose bound workdir disagrees with the presenting process's cwd
  (I-12).
- **Cross-node denials are counted** per uid over a 10-minute window, and the fifth trips
  (I-16).

### 8.2 What is not — the target design, stated in full

None of the following exists; each is written as future work, because writing it otherwise is
precisely the defect this rewrite removes.

1. **The anomaly signal will be consumed.** `RateLimiter::record_denial` returns `true` exactly on
   the request that crosses the threshold, and the call site currently discards it. The target is
   that this boolean raises a durable anomaly record and, once a UI exists, a banner and a system
   notification — with the transition semantics preserved: once per crossing, not once per denial
   while still over.
2. **The anomaly vocabulary will widen.** Three kinds this document has described since Pass 2
   have never existed in code — an orphan-reveal attempt from a non-native transport, a registry
   or manifest HMAC failure surfaced as an anomaly rather than only as a refusal to open, and an
   unlock from an executable path never seen before. §3.4 adds a fourth: a reveal whose
   destination is a webview origin.
3. **Chain verification will be reachable by an operator.** `audit::verify` walks the chain and
   checks the tip HMAC today, and is unit-tested — and no operation and no CLI subcommand calls
   it. The target is that `maintenance.verify` runs it alongside the manifest checks it already
   performs, and reports a break without unlocking anything, since chain verification needs the
   root key only for the tip HMAC and never touches an envelope.
4. **Retention and purge will be enforced.** Logs will be rotated monthly (the file name is
   already the rotation) and kept 12 months, after which a month's log and its tip sidecar will
   be deleted together; purge will be human-only, 2FA-gated (`credmgr audit --purge`), never
   reachable from an agent (`03_DATA_MODEL.md §9`, the document that is the authority for this
   number). No retention- or purge-enforcement code exists for the audit log today —
   `audit.purge` appears in this build only on the forbidden-tool list I-13 enumerates, which is
   the correct state for an operation that does not exist yet. This is a different mechanism from
   the 7-day seal-recovery window, and the two are routinely conflated: the audit log will keep a
   year of decisions; the archive keeps a sealed node's ciphertext for a week, and that half is
   already built.
5. **A stale-grant sweep will exist.** The target is that `audit.report` answers, in one command:
   which nodes were read in a period, by what origin, and which grants have gone unused for 30 or
   more days. Unused grants are the slow leak — they are how a boundary erodes without anyone
   deciding to erode it. No such operation is dispatched today.
6. **The airlock's absence-based guarantees will be asserted rather than assumed.** A-1 (no
   outbound network, ever) holds today by absence — no HTTP client crate appears in any
   `crates/*/Cargo.toml`, verified 2026-08-18 — but nothing prevents one appearing. The target is
   a `cargo deny` ban entry naming the HTTP client crates alongside the existing `openssl` ban,
   so the property is enforced by the same job that already runs in CI, rather than by everyone
   remembering.

## 9. The threat model of what is not built

Four subsystems are designed and unbuilt. Each widens this model, and each is stated here as the
threat statement its future implementation must satisfy — so that the day it is built, the bar it
has to clear is already written down.

### 9.1 Hardware keystore tiers — **`planned`**

Only the `Software` tier exists. The five hardware tiers — `MacosSecureEnclave`, `WindowsHello`,
`WindowsDpapi`, `LinuxTpm`, `LinuxSecretService` — are enum variants with no implementation
(ADR-041), which is why the stolen-laptop rows in §4 reduce to passphrase strength. When they
land, the threat statement is: **an attacker holding the vault directory and the disk image, but
not the machine, must gain nothing** — the wrapping key must be non-extractable and device-bound,
and the UI must state the achieved tier honestly rather than implying the strongest one. A tier
that silently degrades to Software is worse than no tier, since it converts a real guarantee into
a believed one.

### 9.2 Release signing and self-integrity — **`planned`**

No signing certificate exists (K-4 / O-3). Until one does, there is no distributed binary and
therefore no supply-chain surface beyond the source tree — which is why A7 sits at P2. When
signing lands the threat statement is: **a modified binary must not run, and must not be
distributable under this name.** That means a signed and notarised bundle, a self-integrity check
after the version stamp, an opt-in signed updater that updates the *application* and never the
*vault* (A-6), and reproducible builds so a third party can confirm the published binary matches
the published source. The debugger-attach mitigations named as absent in §6 belong to this same
build.

### 9.3 Organisation vault, departments and pairing-code sync — **`planned`**

Nothing here is built. The design (`22_ORG_VAULT_SYNC_AND_LICENSING.md`) introduces the first
adversary this model has never had to consider: **a second machine, and therefore a second
operator.** The threat statement it must satisfy:

- **A11 — a malicious or compromised peer in the pairing.** A paired device must not be able to
  read beyond the departments it was granted, and revocation must be enforced by key material
  rather than by a peer's cooperation.
- **A12 — the transport itself.** Any sync path is an outbound network connection, which is the
  one thing A-1 forbids the vault process to have. The design must therefore keep sync in a
  separate process that never holds a node key, or the whole airlock argument collapses.
- **A13 — an insider inside the organisation.** Departments must be boundaries in the same sense
  nodes are — enforced by key scope, not by a label — or the org product reproduces exactly the
  V1 defect V2 exists to fix.

Note that the codebase carries **no signature primitive at all**: `crates/core` has X25519 and
HMAC-SHA256 and nothing else. Any claim that pairing, licensing or release manifests can be
signed with material this project already has is false today; an EdDSA or equivalent primitive is
a dependency the org product will have to add, review and pin.

### 9.4 The optional commercial-licence certificate — **`planned`**

Also unbuilt, and since `ADR-074` (2026-10-01) much smaller than it was: CredMgr is MIT for
everyone and **nothing is gated by a licence**, so there is no commercial term for a check to
enforce and no activation to attack. What remains is an *optional* commercial-licence certificate
(`22_ORG_VAULT_SYNC_AND_LICENSING.md §4.4`). Its threat statement keeps the constraint that
mattered: **a licence check must never become a path into the vault, and must never require a
network call**, or it violates A-1. If the certificate is verified in the application at all, it
is an offline-verifiable signed file checked by the application shell, never by the broker, so
that a failed or absent certificate changes nothing the application does and can never refuse to
decrypt data the operator already owns.

## 10. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `04_CRYPTO_AND_KEYS.md §9` | the residual-weakness register R-1…R-10, of which R-1, R-3, R-4, R-5 and R-6 are the crypto-layer view of AR-3, AR-2, AR-1, AR-6 and AR-4 respectively; AR-5 (cwd-scoping spoofability) has no counterpart there, since it is an access-control risk rather than a cryptographic one |
| depends on | `06_ACCESS_GRAPH.md §4` | the scope-resolution order whose tokenless cwd fallback is the whole content of AR-5 and §5 |
| depends on | `03_DATA_MODEL.md §2` | the plaintext registry metadata AR-1 accepts, and the HMAC plus generation counter that bound it |
| depends on | `03_DATA_MODEL.md §9` | the hash-chained audit log and its 12-month retention, which §8 relies on and which is not the 7-day seal window |
| feeds | `13_TEST_PLAN.md §4` | §4's claim list — the isolation suite exists to make each row checkable, and I-10 is the row that is not |
| feeds | `07_TWO_FACTOR.md §2` | the reason the gate is on unlock rather than on each read: the threat is a stolen vault directory, not a mistyped command |
| feeds | `17_AIRLOCK_AND_LLM.md §1` | the adversaries A1, A2 and A6 that A-1's no-outbound-network invariant is the last line against |
| feeds | `22_ORG_VAULT_SYNC_AND_LICENSING.md §4` | the threat statement §9.3 sets for any multi-machine design |
| depends on | `16_CROSS_PLATFORM.md §3` | the keystore trait whose unbuilt hardware tiers bound the stolen-laptop rows in §4 |
| depends on | `21_RELEASE_AND_INTEGRITY.md §3` | the code-signature/resource-hash self-integrity check §6 names as absent today — a different mechanism from the debugger-attach mitigation, which has no elaborated target design anywhere yet (`04_CRYPTO_AND_KEYS.md §9`'s R-3 row names it `planned` only) |
| depends on | `14_DECISIONS.md` | `ADR-001` (single enforcement point), `ADR-007` (seal, never delete), `ADR-009` (the Rust broker, which retires AR-3's old framing), `ADR-029` (`privateNames`), `ADR-041` (keystore tiers), `ADR-043` (auto-lock), `ADR-044` (auth backoff), `ADR-070` (its 1-hour cap), `ADR-056` (session login), `ADR-057` (the webview boundary §3.4 exists because of) |

## 11. Source

**Design.** `ADR-001`, `ADR-007`, `ADR-009`, `ADR-029`, `ADR-041`, `ADR-042`, `ADR-043`,
`ADR-044`, `ADR-056`, `ADR-057`, `ADR-070`. `ADR-057`'s own Consequence section states the requirement this
rewrite discharges: "`05_THREAT_MODEL.md` has to consider that boundary explicitly."

**Code.** `crates/brokerd/src/scope.rs` (resolution order, §5 and AR-5) · `peer.rs` (uid gate,
cwd advisory) · `token.rs` (in-memory token store — the correction in §0) · `rate_limit.rs`
(the 10-minute denial window) · `auth_backoff.rs` (the separate uid-keyed lockout — 30 s doubling to a 1-hour cap, ADR-070) ·
`state.rs::lock` (in-place zeroisation, session-token revocation) · `crates/core/src/envelope.rs`
(the sealed box AR-6 describes) · `signing.rs` (the HMAC AR-1's bound rests on) ·
`crates/store/src/audit.rs` (chain and tip) · `generation.rs` (rollback detection) ·
`crates/keystore/src/software.rs` (the only built tier) ·
`apps/desktop/src-tauri/src/{commands,session}.rs` (§3.4).

**Tests.** `crates/brokerd/tests/isolation.rs` — I-1…I-9, I-11, I-12, I-14…I-16, I-18…I-25 by the
exact function names cited in §4, and I-27…I-29 (`i27_entry_get_and_field_ops_obey_the_access_graph`,
`i28_field_ops_and_entry_get_refuse_while_locked`, `i29_payload_kind_cannot_be_flipped_or_moved`; there is no I-26). `crates/mcp/tests/i13_tool_registry.rs` — I-13.
`crates/core/tests/isolation_i17.rs` — I-17. **I-10 is implemented nowhere** and must not be
marked done until a transport exists that can set `presence_attested: true`; it is accepted risk
K-1 in `PHASE8_AUDIT_REPORT.md`. `cargo test --workspace -- --list`: 813 tests in 50 test binaries (2026-10-03); the last full run recorded: 571 passing, 0 failing, 41 test binaries, exit code 0 (2026-10-02; earlier: 448 passing, 37 test binaries on 2026-09-24, re-measured 2026-10-01; 406 passing, 35 test binaries
on 2026-09-13 — run `34743281942`; 397 passing, 33 test binaries, verified 2026-08-18). `crates/brokerd/tests/durable_vault.rs` (2026-09-24) covers
the live unlock, tamper and rollback refusal at unlock, and the owner session's reach (ADR-063,
ADR-065). `apps/desktop/src-tauri/tests/drift_guards.rs` is the guard that keeps §3.4's copied
constants honest, and `tests/shell_config.rs` holds its CSP.

**Verification.** `.github/workflows/security.yml` runs the isolation suite, `cargo deny`,
`cargo audit`, Semgrep, the two credential guards, and — since 2026-09-24 — the desktop bridge's
token-custody suite (`v2-desktop-bridge`) on every pull request — security checks are exempt from
the portfolio's CI run-restraint. `python3 -m tools.corpus_check crossrefs` proves
every `NN_NAME.md §S` reference in §10 resolves to a section that exists.

**Figure.** §3's `plaintext-trust-boundaries` system map: `v2/docs/05_THREAT_MODEL_spec.json`,
rendered by `tools/docgen` (`kind: "system_map"`) — five nodes (the vault directory, the broker,
the CLI client, the MCP client, and the webview) and the operations that cross between them, per
`tools/ENGINE_ROUTING_POLICY.md`. Node/edge counts are re-derived from the same three sources
§3.4 already cites, not transcribed: the 56 commands in `apps/desktop/src-tauri/src/lib.rs`'s
`invoke_handler` (53 broker-op commands and the shell's own three), the 53 dispatched ops in
`crates/brokerd/src/ops.rs` (count ops with `tools.corpus_check.broker_ops()` — a raw `=>` count
overcounts nested arms), and the `getsockopt`-based peer contract in `crates/brokerd/src/peer.rs`.
The figure was re-derived on 2026-10-02 (from 50 commands and 48 ops; the counts in this paragraph are those of
2026-10-03 and the rendered figure has not been redrawn since); before 2026-09-24 it read 8 of 38.
