---
id: V2-007
classification: public
title: Two-factor authentication
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-19
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21), then corrected again the same day closing the independent
     verifier's findings (`v2/VERIFICATION_BACKLOG_S21.md` — `07_TWO_FACTOR.md` section), then
     corrected once more on 2026-08-19 closing the round-2 verifier's finding
     (`v2/VERIFICATION_BACKLOG_S21_ROUND2.md` — `07_TWO_FACTOR.md` section): §2's presence-refusal
     enumeration named four op arms and omitted `audit.get`, which reaches the identical
     capability-checked-then-unconditional-`PresenceRequired` shape at `ops.rs:939`; the sentence
     now names all five, matching `16_CROSS_PLATFORM.md §3`'s own count. The stamp the rewrite
     replaced (Approved With Known Risks @ d15a5c7, pass 2, reconciled 2026-08-10 under ADR-052)
     no longer matched the body it named, and the body itself described a subsystem in the present
     tense that was in places only designed: per-node gates, on-disk gate secrets, elevation-gated
     reveals and a clock-drift check are all unbuilt, and this rewrite says so. The first closure
     pass fixed two false claims that survived the rewrite — §5a called `v2/apps/desktop/` the
     stock scaffold when a real 8-command broker bridge (`ADR-057`) exists there, and §5's
     Elevation row stated per-node 0–30-minute configurability as a built property when
     `NodePolicy` has no elevation field at all — plus two `05_THREAT_MODEL.md` section citations
     that pointed at the wrong heading. Every remaining claim was re-derived from
     `crates/core/src/totp.rs`, `crates/brokerd/src/{state,ops,server,auth_backoff}.rs`,
     `apps/desktop/src-tauri/src/`, and `docs/05_THREAT_MODEL.md`'s live headings in the first
     pass, and `crates/brokerd/src/ops.rs`'s live `PresenceRequired` sites (`ops.rs:939, 1172,
     2460, 2570, 2763`) in the round-2 pass. The hardening status is the operator's to assign
     after their own review, not this session's to self-award. Updated 2026-09-24 for
     ADR-062…066 (the persisted gate, the last door, CLI enrolment, the re-enrolment elevation
     check, the replay floor, the live passphrase unlock). Updated 2026-09-24 for ADR-070 (the
     auth backoff capped at 1 hour, §5) and ADR-071 (a policy change drops elevations, §5). Updated
     2026-10-03 for ADR-079: §3 and §4 corrected — two-factor is enforced by `credmgrd`, not by the
     encryption, so "one TOTP code short" and "the root recovery code alone does not open the vault" hold
     through the broker only; §5a for the staged approval (a locked vault answers `vault_locked`; a lock
     drops the value) and for the absence of any approval screen or command. -->
# Two-factor authentication

`CredMgr V2` · the gate that stands between a correct passphrase and a loaded node key, and the TOTP seeds the vault stores for other services · `2026-08-18`

> **Status.** The **vault-wide gate is built and tested**: enrolment, confirmation, TOTP
> verification with a replay ledger, ten single-use recovery codes, uid-keyed exponential
> backoff shared with the passphrase path, and the ordering property that makes the whole thing
> worth having — a correct passphrase plus a wrong code loads *no* node key. Evidence:
> `crates/brokerd/tests/phase5_gate.rs` (9 tests), `crates/brokerd/tests/phase5_totp_items.rs`
> (7), `crates/core/src/totp.rs`'s own unit tests, `crates/mcp/tests/i13_tool_registry.rs`.
> Since `ADR-056` a successful `vault.gate_verify` is also one of exactly two places in this
> system where a real session token is minted — the other being a `vault.unlock` on a vault with
> no gate enrolled. **Since 2026-09-24 (`ADR-064`) the confirmed gate is persisted** in the
> registry's `gate.twofa` — its seed sealed under a root-derived key, recovery codes as hashes,
> the last accepted TOTP step — so it survives a broker restart; an abandoned re-enrolment keeps
> the gate in force; the **last door** (`vault.gate_recover`) exists; and the CLI has
> `credmgr gate enroll` and `credmgr gate recover`. Evidence: `crates/brokerd/tests/durable_vault.rs`.
> **Two-factor guards the door, not the safe (K-5, `04 §2.4`).** With the gate on, `credmgrd` will not
> unlock the vault — or, on the wholly locked vault, release a value — without a fresh code. That check is
> made by `credmgrd`, **not by the encryption**: anyone who has the passphrase or the root recovery code *and*
> a copy of the vault folder can decrypt it offline with no second factor (`scripts/emergency-decrypt.mjs` does
> exactly that, by design). Treat each of the two as a complete key to the vault.
> **Two parts of this document are designed and not built**, and are written throughout in the
> future tense: per-node gates (`GATE_SCOPE_VAULT` is the global node id and nothing else is a
> scope yet), and enforcement of the `requireTwoFactor` node policy (stored and reported,
> consulted by no operation). A third is **partial**: the scoped elevation window is granted on
> success and read by exactly one thing — re-enrolling a gate that is already confirmed (§4) —
> and gates nothing else. Everything a live presence check gates is likewise unreachable today —
> no transport in this codebase can set `presence_attested`.

---

## 1. Two different things are called "2FA". Name them apart.

This section is definitional and carries no build status; the two nouns it fixes are used
without variation for the rest of the corpus.

| | **Gate 2FA** | **TOTP items** |
|---|---|---|
| What | A second factor that protects *the vault or a node* | 2FA seeds for *other services*, stored like any credential |
| Direction | Protects CredMgr | CredMgr serves them to you |
| Enrolled per | vault (global), and — as target design — per node | per entry |
| Storage | the gate's own keystore, never the vault's own data path (§3) | ordinary entry, `EntryType::Totp` |
| Shown in the UI as | a notch on the node ring and a chip | the second number on the hover card |
| Failure mode | you cannot open the node | you cannot log in to that service |

The operator's brief asks for both — *"implement a 2FA system for each work tree and
globally"* (gate) and *"only two numbers (crds entry and 2FA number)"* (items). Collapsing them
into one concept is the single most likely way to build this wrong, so they never share a word
in the UI, the API, or the code. `gate` and `totp` are the two nouns, and the code holds the
line: the gate's own recovery codes live in `crates/core/src/totp.rs` next to a header comment
whose entire job is to stop a reader confusing them with the *root* recovery code of
`crates/core/src/recovery.rs`, which is a third thing again (`04_CRYPTO_AND_KEYS.md §2`).

---

## 2. Gate 2FA — what it protects

**`partial`.** One scope exists: the vault-wide gate, keyed by the global node id
(`GATE_SCOPE_VAULT` in `crates/brokerd/src/state.rs`). It is enforced at exactly one moment —
unlock — and nothing re-challenges after that. The per-operation and per-node columns below are
the target design.

Factor one is **something you are or know**: a platform presence check, or the passphrase.
Factor two is **something you have**: a TOTP code from an authenticator.

The finished gating matrix, which the built system implements only in its first row:

| Action | Factor 1 | Gate 2FA | Presence (live check at the time of the action) |
|---|---|---|---|
| Unlock vault | yes | yes — global · **built** | — |
| List / read metadata | — | — | — |
| **Reveal** a value | session | the vault gate, if `requireTwoFactor` ≥ `reveal` · **built** (ADR-085; a per-node gate secret is *planned*) | — |
| Export a node to a file | session | node · *planned* | yes · *planned* |
| Create or modify a **grant** | session | global **and** target node · *planned* | yes · *planned* |
| Remove (seal) a node | session | global · *planned* | yes · *planned* |
| **Reveal orphaned data** | session | global, fresh code every time · *planned* | yes, every time · *planned* |
| **Rotate root key** | session | global · **built** (a fresh `vault.gate_verify` elevation is required when a gate is enrolled; the check precedes presence — `ADR-076`) | yes · *planned* — the wire refuses with `presence_required` |
| Change gate enrolment · disable 2FA | session | global · **built** for changing a confirmed gate's enrolment (a fresh `vault.gate_verify` elevation, §4); *planned* for the rest | yes · *planned* |
| Switch Pro / Lite | session | — | — |
| Change a node's `agentAccess` or policy | session | node · *planned* | — |

**What is true today, precisely.** The presence column is inert everywhere: `PresenceProof` and
`PlatformKeystore::verify_presence` exist as a trait contract (`crates/keystore/src/lib.rs`), the
only implemented tier is `SoftwareKeystore` and it reports `user_presence: false`, and no
transport can construct a `Scope` with `presence_attested: true` (`ADR-046`). The operations that
would sit behind presence therefore refuse rather than pretend: **six** op arms are
capability-checked and then reach an unconditional `PresenceRequired` — `audit.get`'s full-record
path, `totp.seed`, `node.reparent`, `grant.create`'s non-presence half,
`maintenance.doctor --rebuild-registry`, and `maintenance.rotate_root` (after its human, Admin and
fresh-second-factor checks, `ADR-076`; `16_CROSS_PLATFORM.md §3` names the first five by file and
line). A seventh refusal is conditional: `node.policy` answers `PresenceRequired` only for a patch
that widens reach (`ADR-071`). That is the honest shape, and it is deliberate — a lock icon that means less than the
reader thinks is the failure this project refuses.

**Node policy `requireTwoFactor`** — **`built`** against the vault gate (ADR-085, 2026-10-24). The field is real
(`crates/core/src/registry.rs`: `never` · `reveal`, the default · `always`), is persisted with the node, and
`node.policy` sets it (its `notEnforced` list is now empty). `graph.snapshot` publishes a per-node `gate.twofa` value of
`none`, `enrolled` or `required`, so the UI draws the notch honestly. It is **enforced** by `ops.rs`
(`second_factor_gate`) when the vault gate is confirmed: `reveal` asks before a value leaves the vault (`entry.reveal`,
`totp.code`); `always` asks before any read of the node as well (`entry.list`, `entry.get`, `notes.read`,
`vault.pending_list`; `search` skips the node). The owner's own login satisfies it (it passed the gate to exist); anyone
else needs a live elevation — a fresh `vault.gate_verify`, which for a logged-in owner is a **step-up** (no token,
`{elevated: true, expiresIn}`). Otherwise the answer is `two_factor_required`. What is still unbuilt: a **per-node** gate
secret and elevation (§3 — the factor and the window are the vault's), and a window screen for the step-up.

The finished meanings: `never` for convenience nodes · `reveal` — the default — metadata free,
values gated · `always`, gating every operation including `list`, for the node that holds a
wallet.

---

## 3. Where gate secrets live — resolving the chicken-and-egg

**`partial`.** The ordering property is built and tested, and since 2026-09-24 so is
persistence (`ADR-064`) — built differently from the separate-file design this section first
specified. Per-node gate secrets are the unbuilt part.

Gate 2FA cannot live inside the vault it protects, or checking it would require opening what it
guards. The unlock sequence is ordered to solve that without introducing a second trust root:

```
1. platform keystore / passphrase   -> unwrap ROOT KEY (RK)
2. load the gate keystore            -> gate secrets only, nothing else
3. challenge: global TOTP            <- the operator submits 6 digits
4. on success ONLY                   -> derive and load node private keys into the hot set
5. RK zeroised — at once on the Pass-1 design; on the live Software-tier unlock it stays
   resident until lock() (ADR-063, as amended; 04 §6)
```

**What the code does today**, in `crates/brokerd/src/state.rs` and `state/durable.rs`:

- On the live daemon, `unlock_with_passphrase()` builds a `Software` keystore from the passphrase
  `vault.unlock` sent, unwraps RK against `keys/root.wrap.pass`, and loads and verifies the vault
  from disk — the persisted gate included — before step 3 (`ADR-063`). A passphrase-less
  `vault.unlock` is refused on any disk-backed vault; `unlock()`, which unwraps RK through the
  broker's own keystore, now serves only in-memory test fixtures. Either way, if
  `is_gate_confirmed(GATE_SCOPE_VAULT)` is false it goes straight to step 4
  (`install_hot_keys_from_root`) and returns `Ok(false)`.
- If a confirmed gate exists it returns `Ok(true)` **without touching the hot set**, parking RK
  in a `PendingGateUnlock` — a `SecretBox<[u8; 32]>` that zeroises on drop — with a 120-second
  expiry (`GATE_UNLOCK_TTL_SECONDS`, deliberately reusing the approval TTL rather than inventing
  a second unexplained constant). `ops::dispatch` turns that into a `two_factor_required` error
  naming the challenge, the scope and the remaining seconds. **No token is minted here**; the
  login is not complete until the second factor lands.
- `gate_verify()` checks the code, and only on success consumes the parked RK and calls
  `install_hot_keys_from_root`. A failure leaves the hot set exactly as it was.

That is the property worth having, and it is a real test rather than a claim:
`phase5_gate.rs::item3_wrong_totp_after_a_correct_passphrase_loads_no_node_key` asserts the hot
set is empty afterwards. Through `credmgrd`, a stolen machine with a captured factor one is still one TOTP
code short of every credential in the vault. Offline it is not: the gate is not part of the encryption
(`04 §2.1`), so a copy of the vault folder plus the passphrase opens everything without a code.

**Step 2 — `built`, in the registry rather than a separate file** (`ADR-064`, 2026-09-24).
Until then the built gate kept its enrolment in broker process memory only, the registry's
`GateDoc { twofa }` slot was never populated, and a restarted `credmgrd` had no gate. Once the
vault itself became durable (`ADR-063`) that stopped being safe — a restart would silently
unlock on the passphrase alone — so the confirmed gate is now written into the scope's own node
record (`global` for the vault gate) as `gate.twofa`: `{ v: 1, confirmed, secret,
recoveryHashes, lastCounter }`. The TOTP secret is sealed with ChaCha20-Poly1305 under
`HKDF(RK, "credmgr/v2/gate-secret/<scope>")` (`credmgr_core::keys::seal_under_root`), so reading
the registry does not reveal the seed; the registry's HMAC stops anyone without RK from stripping
or altering a gate. Recovery codes stay SHA-256 hashes (`null` once burned). The document is read
and opened while the vault is loaded, after step 1 and before step 3, so a process that fails the
challenge holds nothing that can open a credential. **An unreadable gate document is a hard load
failure, never "no gate"** — silently dropping one would turn corruption into a 2FA bypass.
Tests: `durable_vault.rs::an_enrolled_gate_survives_a_restart_and_still_gates_the_unlock`,
`::the_gate_seed_is_never_written_to_disk_in_the_clear`.

*Superseded design, kept for the record:* a single gate-keystore file under `keys/`, encrypted
under `HKDF(RK, "gate-keystore")`. ADR-064 chose the registry field instead, so the gate rides the
registry's existing integrity and rollback protection rather than needing its own.
**Per-node gate secrets remain `planned`:** they will live in each node's own `gate.twofa`, keyed
by node id through the same `String`-scoped maps, so unlocking a node's gate will never require
touching that node's data key.

Step 1 on the live daemon takes the passphrase over the wire: `vault.unlock {passphrase}` builds
the keystore per request (`ADR-063`) — until 2026-09-24 the broker ignored it and used the
keystore it started with.

<!-- figure:gate-unlock-sequence -->

---

## 4. Enrolment, recovery, and the lockout trap

**`partial`.** The protocol is built end to end over the broker, and since 2026-09-24 so are the
CLI enrol command and the last door (`ADR-064`). The rest of the human-facing half — the QR, the
"I have stored these" confirmation, the recovery-code-use banner — is not.

**Enrolment**, as built, is two operations:

1. `vault.gate_enroll_begin` generates a 160-bit secret (`GATE_SECRET_LEN = 20`, CSPRNG, never
   derived from anything else) and returns its
   `otpauth://totp/CredMgr:<scope>?secret=…&issuer=CredMgr&period=30&digits=6` URI. The
   enrolment is stored **unconfirmed** and gates nothing.
2. `vault.gate_enroll_confirm` requires one correct code. Only then does `confirmed` become
   true, and only then does it generate and return the ten recovery codes — once. An enrolment
   that was never confirmed is the classic self-lockout, and `is_gate_confirmed` is the single
   predicate that keeps an unconfirmed one from ever gating an unlock
   (`item4_an_unconfirmed_enrolment_never_activates`).

Both ops require `Capability::Admin` resolved against the global node — the same substitution for
the missing presence factor that `node.seal`, `node.restore`, and `grant.create`'s non-presence
half already make, recorded in `ADR-056`. The confirming code is written to the replay ledger
like any other accepted code, so
it cannot double as the second factor of the very first real unlock.

**Re-enrolling over a confirmed gate** (`ADR-064`, as amended after review). A first enrolment
needs nothing extra. Replacing a gate that is already in force needs the second factor it guards,
fresh: both ops answer `two_factor_required` unless the elevation window a successful
`vault.gate_verify` opened (§5) is still live — otherwise anything holding the owner's login could
swap in an authenticator of its own, durably. A re-enrolment is **staged** (`gate_pending`) and
replaces the gate only when confirmed with a code from the new secret; started and abandoned, it
leaves the old gate and its recovery codes in force
(`durable_vault.rs::starting_a_re_enrolment_and_walking_away_leaves_the_gate_in_force`).

**Recovery codes**, as built: ten of them, 128 bits each, formatted as upper-case hex in
four-character groups, stored only as SHA-256 hashes (`recovery_hashes: Vec<Option<[u8; 32]>>`,
the slot set to `None` on use). Any one satisfies a gate challenge exactly once and is then
burned — `consume_gate_code` tries the TOTP window first and falls through to the unconsumed
recovery hashes. `item5_a_recovery_code_works_exactly_once` proves the burn. The parser accepts
lower-case and ungrouped input, because a human retyping a printed code will not preserve either.

**The finished enrolment experience**, none of which exists yet:

- The URI will be shown alongside a QR rendered **in-process**. No image will ever leave the
  machine and no remote QR service will be called — a QR API request would hand a 2FA seed to a
  stranger, which is not a trade-off, it is a defect.
- The ten codes will be shown once, and the flow will require the operator to tick "I have stored
  these" before continuing.
- Using a recovery code will raise a banner that persists until the operator re-enrols.

**The CLI enrolment path — `built`** (2026-09-24). `credmgr gate` has three subcommands:
`verify`, `enroll` (prints the `otpauth://` URI, then asks for a code and prints the ten recovery
codes once) and `recover`. Until then it had `verify` alone and enrolment was reachable only by
calling the two broker ops directly.

**The last door — `built`** (`ADR-064`, 2026-09-24). If all ten recovery codes are spent and the
authenticator is lost, the vault passphrase **plus** the printed root recovery code together reset
the gate: `vault.gate_recover {passphrase, recoveryCode}`, or `credmgr gate recover`. It is
deliberately a different pair of factors, so that losing a phone is never terminal. Both factors
must independently open the *same* root key — the passphrase through `keys/root.wrap.pass`, the
recovery code through `keys/root.wrap.recovery` (written by `credmgr init` since `ADR-061`) —
compared in constant time. On success it removes the gate, any staged re-enrolment and any parked
unlock, and writes the vault through; it **does not unlock**. The operator then unlocks on the
passphrase and enrols a new gate. A wrong pair answers `wrong_passphrase` without saying which
factor failed; there is no capability check, because the caller is locked out by definition and
the two factors are the authorisation, but the op shares `vault.unlock`'s per-uid auth backoff
(`server.rs`). It is not an MCP tool. Test:
`durable_vault.rs::the_last_door_passphrase_plus_root_recovery_code_re_enrols_the_gate_after_device_loss`.

> **The root recovery code does not open the vault through `credmgrd`.** It is one of three independently
> sufficient wraps of the *root key* (`04_CRYPTO_AND_KEYS.md §2`) — and through the broker the root key alone
> opens nothing, because the gate is checked after RK and before any node key is loaded (§3). **Offline, with a
> copy of the vault directory, the recovery code opens everything** — that is what makes it a recovery code
> (`scripts/emergency-decrypt.mjs`); keep it as you keep the passphrase. The passphrase **+** recovery-code pair described above is a
> different operation with a different purpose: re-enrolling a lost gate, not bypassing one.
> Pass 1 stated these two facts in two documents in a way that read as a contradiction; they are
> one policy, stated here once.

**Refusal to build a lockout.** In the finished product, setup will not let the operator set
`requireTwoFactor: always` on a node before the vault-level gate is enrolled and confirmed, and
every toggle will state in words what it can cost. Today neither the enforcement nor the refusal
exists, but the policy it would guard is enforced since 2026-10-24 (ADR-085) — and a node set to `always` before a gate
exists simply asks for nothing (no factor is enrolled to ask for), so the owner cannot be locked out by it. The setup-time
refusal is still unbuilt.

---

## 5. Verification rules

**`partial`.** Rows marked `built` were read out of `crates/core/src/totp.rs`,
`crates/brokerd/src/state.rs` and `crates/brokerd/src/auth_backoff.rs` in this pass.

| Rule | Value | State |
|---|---|---|
| Algorithm | TOTP, RFC 6238, HMAC-SHA-1 for the gate; SHA-256/512 available in `crates/core` for items | `built` (gate); item algorithms are not yet selectable through any op — see §6 |
| Period · digits | 30 s · 6 digits (`DEFAULT_PERIOD`, `DEFAULT_DIGITS`) | `built` |
| Clock skew | ±1 step accepted, a 90-second acceptance window (`DEFAULT_SKEW = 1`) | `built` |
| **Replay** | Every accepted `(scope, counterStep)` is recorded in `gate_replay` and refused again. `Totp::verify` returns the matched counter rather than a bool precisely so the ledger can key on it. A code an agent read off a screen cannot be reused inside its own validity window. The rule survives a restart as a **floor**: the last accepted step is persisted in `gate.twofa` and re-entered at load, and no step at or below it is accepted afterwards (`ADR-064`; `durable_vault.rs::a_totp_step_accepted_before_a_restart_is_refused_after_it`). | `built` |
| **Rate limit** | 5 consecutive failures, then 30 s → 1 m → 2 m → 4 m → 8 m → 16 m → 32 m, capped at 1 h (`ADR-070`, superseding `ADR-044`'s 15-minute cap). Keyed by uid. `server::handle_request` treats `vault.unlock`, `vault.gate_verify` and — since `ADR-064` — `vault.gate_recover` as one auth path, so an attacker cannot alternate between factors to dodge the counter. | `built` |
| Comparison | Constant-time over the two digit strings (`constant_time_eq_str`); a length mismatch rejects early, which leaks nothing an attacker did not already choose | `built` |
| Elevation | A scoped window: `DEFAULT_ELEVATION_SECONDS` (5 minutes) today, applied the same way to every scope. Will be per-node configurable 0–30 minutes, `0` meaning every operation re-challenges | `partial` — `gate_verify` grants the window and `is_elevated` answers correctly, and since `ADR-064` exactly one thing consults it: re-enrolling a gate that is already confirmed (`vault.gate_enroll_begin`/`_confirm`, §4). It gates nothing else; per-node configurability is unbuilt in a stronger sense than that — `NodePolicy` (`crates/core/src/registry.rs`) has no elevation field at all, and `elevate()`'s one call site (in `BrokerState::gate_verify`, `crates/brokerd/src/state.rs`) always passes the fixed constant, so there is no 0–30 bound anywhere to consult |
| Orphan | Never elevated. Every orphan reveal is designed to take a fresh code and a fresh presence check | `built` in the negative sense that matters: a vault gate success does not elevate the orphan scope (`item7`), and orphan reveal is R0-denied to everything without live presence |

**Backoff is deliberately two mechanisms, not one.** `auth_backoff.rs` answers "is this uid
allowed another authentication attempt right now"; `rate_limit.rs` answers a different question —
five cross-node denials inside ten minutes raises an anomaly (`05_THREAT_MODEL.md §8.1`) — off a
different input. Merging them would make each worse at its own job.

**Elevations are dropped on lock**, and `lock()` is the single funnel for idle timeout, an
explicit `vault.lock`, and the sleep / screen-lock / session-end signal that
`external_lock_signal` forwards into it. One call clears the hot set, clears every elevation,
discards any in-flight gate challenge, and — since `ADR-056` — revokes every session token minted
since the last unlock. Since `ADR-065` a login session is also revoked on its own when unused for
the vault idle timeout (15 minutes by default), even while agent traffic keeps the vault itself
unlocked. The three `item8_*` tests cover the elevation, the external signal and the
in-flight challenge separately, because each was a distinct way to leave something alive across a
lock. Dropping elevations on a node policy change is built since 2026-09-24 — `node.policy`
calls `BrokerState::drop_elevations` after it applies a patch (`ADR-071`); dropping them on a
registry signature failure is target design, not built.

### 5a · Approval on demand — the answer to long agent sessions

**`partial`.** The broker half, the CLI and the window's Lock screen are built and tested. The half the
operator would see without looking at the window — the native notification — is not.

A 15-minute auto-lock will interrupt an hour-long agent run. The tempting fix — a long-lived
"agent session" unlock — reintroduces exactly the permanently-open vault this design exists to
end. **There is no agent bypass.** Instead:

```
agent -- entry.reveal --> broker
                            |  vault locked (or node locked)
                            v
      { "error": "approval_pending", "request": "rq_8f2c", "expiresIn": 120 }
                            |
                            v   a notification, from the native app:
              +--------------------------------------------------+
              |  credmgr                                          |
              |  An agent in <working directory> wants <entry>     |
              |               [ Approve ]      [ Deny ]            |
              +--------------------------------------------------+
                            |  presence check on Approve
                            v
agent <-- the value, for that one request. The vault stays locked.
```

Built, and readable in `ops::reveal_via_approval` and the `vault.approval_decide` arm:

- The approval covers **one request**: one entry, once. It creates no session and no elevation.
  Since `ADR-079` (4a) the value is **decrypted and staged when the owner decides**, while a root key
  is resident, and the agent's retry only hands it over (`take_approved`) — the retry derives no key. A lock of
  any kind — explicit, idle, sleep — drops every staged value, so a staged approval never survives a lock
  (`approval_denied` with reason `locked`); expiry and consumption zeroise it too. **On a wholly locked live
  vault** a disk-backed vault's root key is not resident (`ADR-063` as amended) and nobody holds the owner
  session, so a reveal there records the request (`approval_pending`, `ADR-088`) and a person decides it **with
  the unlock factors** — `vault.approval_decide {request, approved, passphrase, code?}` or `credmgr approve`
  — while the vault stays locked: the passphrase yields the root key for that one decision, the value is
  decrypted and staged, the key is dropped, a recovery code is refused, and failures share the unlock back-off.
  What the person decides is described first by `vault.approval_get` (`ADR-090`): the node and the entry (by
  name when the broker holds the names and the node's name is not private), the command, the seconds left;
  `vault.status` carries the bare count as `pendingApprovals`, and the window's Lock screen lists the waiting
  requests. `approval_get` is read-only and decrypts nothing.
- It expires after 120 seconds (`APPROVAL_TTL_SECONDS`) and **defaults to deny**: an undecided
  request past its TTL is reported as denied-because-expired exactly once and then discarded, so
  the next reveal starts a clean cycle rather than silently re-extending a stale one.
- The pending response carries the request id and the remaining seconds, so a client can poll the
  same request rather than opening a second one.
- `totp.code` deliberately does **not** route through this path when the vault is locked. Its
  response shape would be the raw stored value, and that value is a TOTP seed; reusing the
  approval path there would leak the seed through a differently-named channel. A locked
  `totp.code` is an ordinary denial, full stop
  (`totp_code_on_a_locked_vault_is_an_ordinary_denial_not_an_approval`).

What is built and what is not: the broker half, the CLI (`credmgr approvals`, `credmgr approve`) and the window's
Lock screen (the list, the passphrase, the second-factor code) are built and tested against a real daemon. **Still
planned:** the native notification — a prompt that appears while the vault is locked without anyone looking at the
window — and the presence check on `[ Approve ]`, which no transport can supply yet (the bridge constructs no
`Origin::Native` and sets `presence_attested` nowhere). The description a notification would show is what
`vault.approval_get` already answers; the requesting process's working directory (`PendingApproval.cwd`) is in it only
for the owner's login, so a locked vault (no owner login) names no requester and a notification would need a
broker-side way to show one. `credmgr_get`'s tool description will tell agents to fetch what they need early and to expect
a possible short wait, so that the pause is a designed interaction rather than a surprise timeout.

**The second factor for agents, as built (`ADR-085`, `ADR-091`).** `requireTwoFactor` is enforced for every caller
except the owner's own login session, which passed the gate to exist. A valid code from that session
(`vault.gate_verify`, a step-up, or the code of a login) opens a **vault-wide, five-minute** window in which agents and
other tools pass the gate on every node; a lock and any `node.policy` change end it early. The window's chip on a node
that asks for a factor is the deliberate "give it" action; the dialog never opens from the owner's own reveal.

### 5b · When codes fail because the clock is wrong

**`planned`.** No part of this exists.

TOTP is a function of time. A drifted system clock makes every code fail, which presents to the
operator as "2FA is broken" and invites them to turn it off — the worst available outcome, and
one that no amount of correct cryptography prevents.

The design: after three consecutive failures the broker will compare its own clock against the
window implied by the submitted codes, and when the pattern matches drift rather than wrong
codes it will say so in those words — that the codes are failing consistently by roughly a fixed
offset, that this usually means the system clock is wrong rather than the code, and where to
check. `maintenance.doctor` will report measured clock skew as a first-class check.

Today `maintenance.doctor` performs exactly one class of repair — manifest / registry
cross-binding resync — and has no clock check at all. The verification path knows a code failed
and nothing about why.

---

## 6. TOTP items — 2FA seeds you store

**`partial`.** The storage model, the type inference, the count and the seed/code split are
built. Everything that would make an arbitrary real-world authenticator seed usable is not.

A stored 2FA seed is an ordinary entry. A field whose value is an `otpauth://` URI or a bare
base32 string of 16, 26 or 32 characters infers as `FieldType::TotpSeed`
(`crates/core/src/inference.rs`), which infers the entry as `EntryType::Totp`, which increments
the manifest's `counts.totp` alongside `counts.entries` when the entry is inserted. That count is
what `graph.snapshot` publishes per node, and it is the second of the two numbers on the hover
card — one credential count, one 2FA count, nothing else (`09_UI_UX_SPEC.md §4`). It obeys node
scoping like every other entry, because it *is* every other entry.

All three lengths work with `totp.code`. The minimum is 80 bits (16 base32 characters), a recorded
deviation from RFC 4226 §4's 128: a stored seed is issued by the service that checks the codes, not
chosen here, and many services still issue 80-bit seeds (`ADR-077`). Anything shorter is a typed
`malformed_request` that names the length in bits and never the value, and so is a value that is not
base32 at all; a seed may be stored padded with `=`, in lower case, or grouped with spaces or dashes.
A panic on a short seed (MX-1) is what this replaced.

**The seed/code split — the important part.** Two capabilities, not one:

| Request | Returns | Gate | State |
|---|---|---|---|
| `totp.code(node, entry)` | the current digits, and only that | `Reveal` on the entry's node | `built` |
| `totp.seed(node, entry)` | the base32 secret itself | `Reveal` **+ gate 2FA + presence** | `built as a refusal` — capability-checked, then unconditionally `PresenceRequired` |

An agent that has to log into a service can get a code. It cannot get the seed, so it cannot
generate codes tomorrow, cannot exfiltrate a durable capability, and cannot clone the factor. A
leaked code is worth 30 seconds; a leaked seed is worth forever. `totp.code`'s response object is
asserted to have exactly the keys `code`, `entry`, `node` — there is no field under any name that
could carry the seed. And `totp.seed` is unreachable end to end on every transport that exists:
the MCP registry is enumerated by `crates/mcp/tests/i13_tool_registry.rs`, which asserts no
registered tool maps to the op under any name, and the op itself refuses even a fully-capable
caller against an unlocked vault. That is not a defensive stub; it is the correct behaviour until
a real presence factor exists, and it is tested from both directions.

**What is not built, and what the finished item support will do.** Adding a seed today goes
through the ordinary single-field add path (`08_FIELD_MODEL.md §2`), which stores the value
verbatim — including, if that is what was pasted, the whole `otpauth://` URI. `totp.code` reads
the stored value and base32-decodes it with fixed SHA-1 / 6 digits / 30 seconds, so:

- an `otpauth://` URI **will not** produce a code today; it stores and classifies correctly and
  then fails to decode. The finished add flow will parse the URI into issuer, account, secret,
  period and digits at entry time, keeping the components rather than the string, and will accept
  a bare base32 secret with a typed-in issuer as the alternative — both through the ordinary add
  flow, with no special screen;
- an item that uses 8 digits, SHA-256 or SHA-512 cannot be served, even though `crates/core`
  supports all three: no op stores or reads per-item parameters, so `totp.code` has nothing to
  read them from. The finished manifest entry will carry them beside the seed;
- the countdown is UI, and the desktop application draws it: a TOTP-seed field's reveal button reads
  `totp.code` (with the field's id, `ADR-078`) and shows the current code with a bar that runs to the end of
  its 30-second step; the code is shown and never copied, and the seed is never shown (its "show seed" button
  sends `totp.seed` and is refused with `presence_required`). The concealed copy with a 30-second clear
  (`entry_copy`, `copy_text`) serves every other field's Copy button.

---

## 7. Security-key support

**`planned`.** Deferred, not forgotten, and deliberately not started.

A hardware key (WebAuthn / FIDO2) would be a stronger second factor than TOTP for the global
gate. It is deferred because WebAuthn inside the shell's webview needs native platform
authorisation plumbing that shares its dependency with the hardware keystore tiers
(`16_CROSS_PLATFORM.md §4`), and because it must never become the *only* factor — a lost key with
no TOTP fallback is an unrecoverable vault. When it is built it will be an **additional** factor
alongside TOTP, never a replacement, and the enrolment flow will refuse to remove the last TOTP
enrolment while a key is the only remaining factor.

There is a second, quieter reason to wait. This project has one signing-adjacent capability gap
already: `crates/core` holds X25519 and HMAC-SHA-256 and **no EdDSA or other signature
primitive**. Any assertion that the pieces for attestation verification are already present would
be false, and building a factor on that assumption is how a stub ships wearing a lock icon.

---

## 8. What must be tested, and what is

The eight obligations this document has always named, each with its current evidence. Every test
named below was located by grep in this pass; nothing here is asserted from memory.

| # | Obligation | Evidence | State |
|---|---|---|---|
| 1 | A code accepted once is refused for the rest of its window | `phase5_gate.rs::item1_a_code_accepted_once_is_refused_for_the_rest_of_its_window` | `built` |
| 2 | Failed attempts back off, and the passphrase path shares the counter | `phase5_gate.rs::item2_failed_gate_attempts_back_off_and_share_the_passphrase_counter`; `auth_backoff.rs::schedule_matches_07_5_exactly` | `built` |
| 3 | A correct factor one and a wrong code load **no** node key | `phase5_gate.rs::item3_wrong_totp_after_a_correct_passphrase_loads_no_node_key` — asserts the hot set is empty | `built` |
| 4 | An unconfirmed enrolment never activates | `phase5_gate.rs::item4_an_unconfirmed_enrolment_never_activates` | `built` |
| 5 | A recovery code works exactly once | `phase5_gate.rs::item5_a_recovery_code_works_exactly_once` | `built` |
| 6 | `totp.seed` is unreachable from the MCP transport, for every scope and grant | `i13_tool_registry.rs::totp_seed_op_never_appears_in_the_registry_under_any_tool_name`; `phase5_totp_items.rs::totp_seed_is_unreachable_even_with_full_capabilities_and_an_unlocked_vault` | `built` |
| 7 | Orphan reveal never accepts an elevation, only a fresh challenge | `phase5_gate.rs::item7_a_successful_vault_gate_challenge_never_elevates_orphan` covers the negative half; the positive half needs a live presence factor and a reachable orphan path, and has neither | `partial` |
| 8 | Lock, sleep and screen-lock each drop every elevation | `phase5_gate.rs::item8_lock_drops_the_elevation_and_any_in_flight_challenge`, `item8_external_lock_signal_drops_the_elevation_too`, `item8_lock_drops_an_in_flight_unconsumed_challenge` | `built` |

Obligations this document adds. Four are **met since 2026-09-24** (`ADR-064`), each in
`crates/brokerd/tests/durable_vault.rs`: a gate enrolment survives a broker restart
(`an_enrolled_gate_survives_a_restart_and_still_gates_the_unlock`); a TOTP step accepted before a
restart is refused after it (`a_totp_step_accepted_before_a_restart_is_refused_after_it`); a
burned recovery code stays burned (`a_burned_gate_recovery_code_stays_burned_across_a_restart`);
and the passphrase plus root recovery code reset a lost gate
(`the_last_door_passphrase_plus_root_recovery_code_re_enrols_the_gate_after_device_loss`). The
rest are unmet because their subsystems are unbuilt: a node with `requireTwoFactor: reveal`
refuses a reveal
without a gate challenge; an elevation actually satisfies a re-challenge, and its expiry actually
forces one; an `otpauth://` URI added as an entry yields a working code; the drift advisory fires
on a skewed clock and not on genuinely wrong codes.

One caution that belongs with a test list rather than in it: `crates/brokerd/tests/isolation.rs`
runs I-1 through I-25, and **I-10 is implemented nowhere** — an accepted risk, K-1 in
`PHASE8_AUDIT_REPORT.md`. There is no test I-26 in this codebase and there never has been; three
documents cited one for months. Do not add a row to any table above without running the grep.

---

## 9. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `04_CRYPTO_AND_KEYS.md §2` | the root key and its three independent wraps — the material this gate is ordered *after*, and the root recovery code §4 is careful not to conflate with a gate recovery code |
| depends on | `03_DATA_MODEL.md §1` | the `requireTwoFactor` node-policy field §2 reports and does not yet enforce |
| depends on | `06_ACCESS_GRAPH.md §3` | the capability every gated op is resolved against before the gate is ever consulted |
| feeds | `05_THREAT_MODEL.md §7` | the bound on AR-2 — the gate is what keeps a stolen vault directory from becoming a loaded hot set |
| feeds | `10_API_AND_MCP.md §3` | the forbidden-tool list that keeps `totp.seed` off the agent surface |
| feeds | `13_TEST_PLAN.md §4` | the isolation-suite obligations §8 reports against, including I-13's tool-registry enumeration |
| feeds | `09_UI_UX_SPEC.md §11` | the lock and unlock screens that will present the challenge, the drift advisory and the approval prompt |
| depends on | `16_CROSS_PLATFORM.md §3` | the platform keystore tier and its presence capability, which every presence-gated row in §2 waits on |
| depends on | `14_DECISIONS.md` | `ADR-044` (the shared backoff counter), `ADR-070` (its 1-hour cap), `ADR-046` (what Phase 5 built and what it honestly deferred), `ADR-056` (a completed gate mints the session token), `ADR-059` (the status vocabulary this rewrite applies), `ADR-063` (the live unlock that loads the gate), `ADR-064` (the persisted gate, staged re-enrolment and the last door) |

---

## 10. Source

**Design.** `ADR-044` · `ADR-070` · `ADR-046` · `ADR-056` · `ADR-063` · `ADR-064` · `ADR-071` · `ADR-045` for the root recovery code this
document deliberately keeps distinct from gate recovery codes · `ADR-059` for the
`built`/`partial`/`planned` vocabulary.

**Code.** `crates/core/src/totp.rs` — RFC 6238 verification returning the matched counter step,
the 160-bit secret, the hand-built `otpauth://` URI, the ten 128-bit recovery codes and their
SHA-256 storage. `crates/brokerd/src/state.rs` — `GateEnrollment`, `PendingGateUnlock`,
`gate_enroll_begin`, `gate_enroll_confirm`, `gate_verify`, `consume_gate_code`, `elevate`,
`is_elevated`, `lock`, `external_lock_signal`, and the constants `GATE_SCOPE_VAULT`,
`GATE_UNLOCK_TTL_SECONDS`, `APPROVAL_TTL_SECONDS`, `DEFAULT_ELEVATION_SECONDS`.
`crates/brokerd/src/ops.rs` — the `vault.gate_*`, `totp.code`, `totp.seed`,
`vault.approval_decide` arms, `reveal_via_approval`, `mint_session_token`, and the `gate.twofa`
field of `graph.snapshot`. `crates/brokerd/src/auth_backoff.rs` — the 5-then-30/60/120/240/480/
960/1920 schedule and its 1-hour cap (`ADR-070`). `crates/brokerd/src/server.rs` — the `is_auth_path` wiring that
makes `vault.unlock` and `vault.gate_verify` share one counter. `crates/core/src/inference.rs` —
`looks_like_totp_seed`, `FieldType::TotpSeed`, `EntryType::Totp`. `crates/store/src/manifest.rs` —
`Counts { entries, totp }`. `crates/store/src/registry_file.rs` — `GateDoc`, the persistence
slot §3 names, populated since `ADR-064`. `crates/brokerd/src/state/durable.rs` — the persisted
gate's write and load, the replay floor, and `gate_recover`. `crates/cli/src/main.rs` —
`credmgr gate verify`, `gate enroll`, `gate recover`, and `print_unlock_result`.

**Tests.** `crates/brokerd/tests/phase5_gate.rs` · `crates/brokerd/tests/phase5_totp_items.rs` ·
`crates/brokerd/tests/session_login.rs` · `crates/brokerd/tests/durable_vault.rs` ·
`crates/mcp/tests/i13_tool_registry.rs` · the unit tests
inside `crates/core/src/totp.rs` and `crates/brokerd/src/auth_backoff.rs`. `crates/brokerd/tests/approval_locked.rs` (19 tests, ADR-079). Workspace-wide
(2026-10-03): `cargo test --workspace -- --list` lists 813 tests in 50 test binaries; the last full run
recorded (2026-10-02) is 571 passing, 0 failing, 41 test binaries, exit code 0
(earlier: 448 passing, 37 test binaries on 2026-09-24, re-measured 2026-10-01; 406 passing, 35 test
binaries on 2026-09-13 — run `34743281942`; 397 passing, 33 test binaries on 2026-08-18).

**Figure.** `07_TWO_FACTOR_spec.json`, beside this document — the single source of truth for the
figure per `ADR-060` (no separate golden-job file; that convention is `echarts`-kind-only). `kind:
"sequence"`, id `gate-unlock-sequence`, rendered by `tools/docgen/sequence_diagram.py`. Content
re-derived directly from `crates/brokerd/src/state.rs` (`unlock()`, `PendingGateUnlock`,
`gate_verify()`, `consume_gate_code()`, `install_hot_keys_from_root()`, `GATE_UNLOCK_TTL_SECONDS =
120`, aliasing `APPROVAL_TTL_SECONDS`), `crates/brokerd/src/ops.rs` (the `"vault.unlock"` /
`"vault.gate_verify"` dispatch arms), and `crates/brokerd/src/protocol.rs` (the `two_factor_required`
/ `gate_verification_failed` wire envelopes). The "load gate keystore" step is drawn dashed and
labelled planned — true when rendered; since `ADR-064` the gate is loaded from the registry's
`gate.twofa` during the vault load instead, and no separate gate keystore file will exist (§3).
