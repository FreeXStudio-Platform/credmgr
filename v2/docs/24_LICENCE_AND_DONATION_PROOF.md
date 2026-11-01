---
id: V2-024
classification: public
title: Licence and donation proof — signed, machine-bound, expiring, never locking the vault
audience: technical
owner: credmgr-v2
status: planned
export_allowed: true
surface: repo
last_reviewed: 2026-10-31
---

<!-- artifact-hardened: NEEDS RE-HARDENING — first draft (pass 1) written 2026-10-31 after the operator's
     live-chat brief of the same day. Design only: nothing here is built, nothing ships in 2.0.0-beta.1,
     and every section is `planned`. Not source-of-truth until a second pass and a hardening pass have
     run (three-pass rule). -->
# Licence and donation proof — signed, machine-bound, expiring, never locking the vault

`CredMgr V2` · the proof a donor or buyer sends, the token they get back, and what a tampered install may and may not do · `2026-10-31`

> **Status.** **Nothing in this document is built and nothing in it ships in `2.0.0-beta.1`.** CredMgr is free
> today; from the release in which the operator announces paid tiers it will not be, on every operating system.
> This document is the design for that. Cross-device sync is **not** designed here — it is `PRU-1`
> (`ADR-094`, the sibling post-release document on the `claude/credmgr-v2-post-release-7630e4` branch, working name
> `23_CROSS_DEVICE_SYNC_AND_AGENT_USE.md`); §8 states only what this document needs from it.

---

## 1. Requirements (operator, live chat, 2026-10-31)

1. A donor sends the transaction hash; it is protected in transit, bound to a moment in time, and changes.
2. The licence is **tied to the computer** it runs on and cannot be shared, copied or replayed.
3. If the app is manipulated, the licensed part stops working.
4. A passcode / product licence the user receives for what they paid — **a code that changes over time, not a static one**.
5. Free now; **paid later**, on all operating systems and devices.
6. Decide between our own database and a one-time connection that moves a user's data between their own installs
   without us keeping it (nothing kept, for legal and security reasons).

## 2. What no licence scheme can do — read before the design

- **A client-side check can always be patched out by someone who controls their own machine.** The goal is not
  "unbreakable". It is: (a) a licence **cannot be forged** from the shipped app (an asymmetric signature; the signing
  key never ships), (b) **cannot be shared** (machine-bound), (c) **cannot be replayed** (one payment, a short lease),
  and (d) tampering costs more than paying. Claiming more would be a false security claim (`SECURITY.md`).
- **Tamper response never touches the vault.** The brief says a manipulated system should be "locked and not working
  anymore". For a credential manager that aims at the wrong thing: a lock on a false positive (a motherboard swap, a
  reinstall, a wrong clock) is a user locked out of their own secrets, and anyone able to patch the app can read the
  vault another way. **Decision (`ADR-095`): a failed or tampered licence switches off the licensed *entitlements* only.
  Unlock, read, write, export and backup always work.** This is the one place the design departs from the brief; §9
  states what overruling it costs.
- **A key hidden in the bundle is static by construction.** The sealed cosmetic pack of `ADR-082` opens with a key
  derived from a code; once extracted it can be shared forever. Acceptable for cosmetics, unacceptable for anything
  paid for. Paid features are gated by **a valid signature checked by the shell**, never by a secret in the bundle (§5.5).
- **Hardware serial numbers are not available.** Apple Silicon and most x86 machines expose no CPU serial. The stable,
  OS-supported anchors are the macOS `IOPlatformUUID`, the Windows `MachineGuid` and the Linux `/etc/machine-id` —
  identifiers, not secrets: a binding, not a key (§5.2).

## 3. Keys

| Key | Where it lives | What it does |
|---|---|---|
| **Root signing key** (Ed25519) | Offline, in the maintainer's own vault or a hardware key. Never on a build machine, in CI, or in this repository. | Signs licence tokens and the delegation certificate of §7. |
| **Request-sealing key** (X25519) | Offline, separate from the root key. | Opens the sealed request of §5.3. |
| **Delegate key** (Ed25519, from the renewal service, §7) | On the service, valid ≤ 90 days, renew-only. | Signs renewals of licences already issued; never a new licence. |
| **Public keys** | Compiled into the desktop shell. | Verify tokens; seal requests. |

The shipped app holds public keys only. An HMAC scheme is rejected for the reason in
`22_ORG_VAULT_SYNC_AND_LICENSING.md §4.4`: an HMAC verifier is also a forger.

## 4. Two products, one proof

| | **Supporter** (donation) | **Licence** (paid, later) |
|---|---|---|
| Buys | Cosmetic extras (`ADR-082`). Nothing functional. | Entitlements: more devices, sync, organisation features, support. |
| Gates a feature? | **Never** (`DONATE.md`, `ADR-074`, `ADR-082`). | **Only from the release where the operator announces paid tiers**; nothing in 2.0 or 2.1 is gated. |
| Proof | The flow of §5, a smaller amount, `ent: ["extras"]`. | The flow of §5, the tier price, `ent` from the tier table. |

`DONATE.md` says donations "buy nothing, grant no licence". That stays true until a paid tier ships; it is rewritten in the same
change that adds the first gate, never before.

## 5. The flow (offline first; no network call by the app; `A-1` unchanged)

```
 donor's app                     donor's mail / chat          maintainer's offline Mac
 ───────────                     ───────────────────          ────────────────────────
 Settings → Support → Start
   builds REQUEST CODE  ────────►  sends it  ─────────────►   credmgr-licence issue
   (sealed, one-time)                                           opens it, checks it, checks the chain,
                                                                signs a TOKEN bound to that machine
 pastes TOKEN  ◄─────────────────  replies  ◄───────────────   prints the token
   the shell verifies it offline and stores it, sealed to the device
```

### 5.1 Machine binding

`fp = SHA-256("credmgr-licence-fp-v1" ‖ platform_id)`. The fingerprint is **never sent in the clear**: it is inside
the sealed request. A token for one `fp` fails on every other machine. A hardware change or reinstall produces a new
request, answered by a **free re-bind** (the ledger allows `n` re-binds per licence id). Phase 2.2 adds a Secure
Enclave / TPM-resident device key: the token binds to a public key whose private half cannot leave the chip, and the app
proves possession by signing a fresh challenge. That — not the UUID — is the strong form of "tied to the machine".

### 5.2 The request code — encrypted, time-bound, never the same twice

A **sealed box** (ephemeral X25519 → the maintainer's request-sealing public key; ChaCha20-Poly1305) over
`{ v, fp, t, nonce, os, app_ver, kind, tier, chain, txid, tag }`.

- **Encrypted.** A mail relay, a clipboard reader or a screenshot sees an opaque base32 string, not the hash.
- **Different every time.** A fresh ephemeral key and nonce per request.
- **Time-bound.** `t` is authenticated by the AEAD. The tool refuses a request older than 48 hours, and a chain
  transaction whose block time lies outside `[t − 24 h, t + 48 h]`.
- **Bound to the payment, not only the hash.** A transaction hash is public once mined, so a stranger could paste a
  donor's hash into their own request. The defence is an **amount tag**: the app shows an exact amount whose last digits
  are the request's `tag` (for example `25.000417` USDT). The tool accepts the transaction only if its amount carries
  that tag; a copied hash cannot match a stranger's request. The first valid request for a transaction wins and the
  ledger records it.
- Format `CMQ1-` + base32 in groups of five, with a check value so a typo is caught before it is mailed.

### 5.3 Issuing — the owner's offline tool (`credmgr-licence`, never shipped to users)

1. Open the request with the sealing key; reject if malformed, stale or from the future.
2. Check the transaction: recipient is an address in `DONATE.md`, amount ≥ price with the right tag, enough
   confirmations. In 2.2 the tool prints these expectations and the operator confirms them on a block explorer
   (`--confirm`); an automatic RPC check is a later option.
3. Check the **ledger** — an append-only file in the maintainer's vault (`txid`, licence id, `fp`, date, re-binds).
   A `txid` already present is refused.
4. Sign and print the token.

### 5.4 The token, its lease, and "a code that changes"

```
LIC1.<base64url(payload)>.<base64url(Ed25519 over "credmgr-licence-v1" ‖ payload)>
payload = { v, id, fp, ent:[…], iat, nbf, exp, epoch, seats }
```

A token is a **lease**: 35 days for a monthly licence, 400 for an annual one or a supporter code. Near the end the app
shows "renew"; renewal is a new request/response, or an automatic call to the renewal service (§7, opt-in). Each token
has a higher `epoch`; an older token never validates once a newer one has been seen. So **the code the user holds
changes every lease**, and a code posted online expires on its own.

### 5.5 Verification and storage

The **shell** verifies, in Rust, with the embedded public key — never the page, never the broker
(`05_THREAT_MODEL.md §9.4`). The page learns only `{state, entitlements, expiresIn}`. The token sits in the app-data
directory beside a **sealed state record** (AEAD under a key from the platform keystore) holding the highest time and
the highest `epoch` ever seen. The supporter pack of `ADR-082` is released by a valid `extras` entitlement; the static
`credmgr_extras_key` mechanism is retired when this ships.

### 5.6 States — and no state locks the vault

| State | When | Effect |
|---|---|---|
| `valid` | signature, `fp`, window and epoch all good | entitlements on |
| `grace` | expired < 14 days, or the clock cannot be trusted this session | entitlements on, "renew" banner |
| `unlicensed` | no token, or expired > 14 days | the free tier |
| `tampered` | bad signature, wrong `fp`, state record fails its seal, clock rolled back > 24 h, `epoch` lower than seen | **licensed entitlements off**; Settings says why; the vault is untouched |

**Clock.** The sealed state keeps `max_seen`. A clock earlier than `max_seen − 24 h` is `tampered` until a token with a later
`iat` is installed. A clock far in the future makes a licence look expired, never extended.

## 6. Threat table

| Attacker | Move | Result |
|---|---|---|
| Passer-by with the app | read the public key from the binary | cannot sign; nothing gained |
| Sharer | post a token online | wrong `fp` everywhere else; expires with the lease |
| Replayer | reuse a donor's hash | tag mismatch; the ledger refuses a second use |
| Eavesdropper on the mail | read the request | sealed; reveals nothing; each request differs |
| Clock editor | roll the clock back | `tampered` (> 24 h) |
| Store editor | edit the token or state | signature or seal fails → `tampered` |
| Patcher | patch out the verifier | defeats the check on **their own** machine only. Developer ID + hardened runtime make a modified bundle fail to launch normally, and 2.2 adds a self-signature check. Not preventable on a machine the attacker owns — said plainly |
| Thief of the maintainer's key | forge tokens | offline, hardware-backed where possible; the delegate key of §7 can only renew |

## 7. Renewal service and seats (optional, announced in `PRIVACY.md`)

Monthly tiers and several devices cannot rely on hand-signing every renewal. The service is a **stateless edge function**
holding a **delegate key** certified by the root key (`{delegate_pk, not_after ≤ 90 days, scope: renew}`) and a table
`(licence id, fp, seat, status)` — **no vault data, no e-mail required**. It renews only ids the offline tool already
issued; revocation is refusing the next renewal (it lapses within one lease). A compromise of the service yields renewals
for ≤ 90 days and never a new licence. Seats (`seats: N`) are N registered `fp` values. It speaks only sealed requests.

## 8. Data between devices — the decision, and what this document needs from PRU-1

**Decision (`ADR-095`): CredMgr does not run a database of users' vaults, by default and in every phase this document
covers.** `PRU-1` (`ADR-094`) already designs personal sync as ciphertext replicas; this document adds only the licence
side and one constraint:

| Option | What we hold | Verdict |
|---|---|---|
| **Direct device transfer** — two of the user's own installs pair on the LAN / by QR or short code; a PAKE-authenticated channel carries an encrypted bundle; a dumb relay (if needed) holds ciphertext ≤ 10 minutes and deletes it on delivery | **Nothing.** | **Recommended first.** Nothing stored = nothing to breach, subpoena or retain. |
| End-to-end-encrypted sync (the `PRU-1` direction) | Opaque encrypted entries and sizes. The key is derived from the passphrase **and a device Secret Key**, so a stolen blob cannot be brute-forced even with a weak passphrase. | The `PRU-1` programme; only as designed there. |
| A conventional hosted vault database | Everything, or ciphertext under a server-known key | **Rejected** — the one design where a breach is catastrophic. |

**Constraint for `PRU-1`:** sync must not require a licence account to *read your own vault*; a licence may gate the
*convenience* of hosted sync, never access to local data (`R08`: "billing or service failure cannot destroy the vault").
**Interchange.** A versioned, documented exchange format (`credmgr-transfer/1`: nodes, entries, multi-field values,
types, notes, timestamps — no audit chain, no keys) readable by any implementation; the same reader imports other
managers' exports. Import is all-or-nothing, previewed and never overwrites (`ADR-073`).
**What we keep.** Licensing needs `licence id`, `fp`, `seat`, tier, expiry and the public transaction hash. Nothing about a
user's vault, names, secrets or usage is retained, so there is no retention duty beyond that table and the operator's own books.

## 9. If the operator overrules "never lock the vault"

A lock on a false positive is unrecoverable for a user without a backup; the tamper path then needs an escape hatch (a
recovery-code unlock that ignores the licence), which is not locking; and a user able to tamper can read the vault with a
debugger anyway. If a harder response is still wanted, the supported form is: **`tampered` ⇒ the app refuses to sync or
transfer and shows a full-screen notice** — never a refusal to unlock.

## 10. Where this lands in the version plan

Extends `PRODUCTION_PLAN.md` ("After beta.1") and `PRU-1`; it does not re-sequence them.

| Release | Licence-side content | Gate |
|---|---|---|
| `2.0.0-beta.1` | Frozen. Free. No licence code. | The operator's go-live items (batch 6). |
| `2.0.0-rc.1` | Beside the `.env` importer: the **V1→V2 read-only pipe** (§11); a real GitHub CI run; Developer ID + notarisation; idle-lock and sleep exercised by hand; the daemon started by the app or a launch agent. | K-12 and K-14 cleared. |
| `2.0.0` | Stable. No licence code. | No open P0/P1; the operator's soak period. |
| `PRU-1` (`2.1.0`) | Sync per `ADR-094`; nothing gated. | Its own gates. |
| `2.2` | Licence core: token, request code, `credmgr-licence`, shell verifier, sealed state; the supporter pack released by a signed `extras` entitlement; Windows/Linux licence anchors; device-resident key. **Nothing gated.** | This document hardened + a licence-specific adversarial audit. |
| `2.3` | Renewal service, seats, **the first paid tier**; `DONATE.md`, `PRIVACY.md` and the licence text rewritten in the same change. | The operator's pricing and legal sign-off. |

## 11. Moving from V1 to V2 yourself

V2 has **no import from V1 by design** (`11_MIGRATION.md §1`) and never writes to the live V1 vault. For a V1 user the safe path
is a **one-way, read-only pipe**, not a migration:

1. V1 stays the system of record; V2 starts empty and runs **beside** it.
2. A script reads V1 through its own CLI one project at a time and pipes `NAME=value` lines into
   `credmgr import - --node <project>` — values never touch a file or the screen; each project becomes a V2 node; a name
   collision is reported, never overwritten.
3. A **diff report** (names and counts only, no values) must match before anything is retired in V1.
4. V1 is not retired until the operator has used V2 for a soak period.

Until that script exists: `11_MIGRATION.md §6` (one value by hand) or a `.env` file through `credmgr import`.

## 12. Decisions this document needs from the operator

1. **The tamper policy** (§2, §9): entitlements off, vault never locked — recommended; the alternative is in §9.
2. **Where donors send the request** — the proof dialog ships a placeholder address (issue 34).
3. **Pricing and tiers** — not needed before 2.3.
4. **Whether the V1→V2 pipe may be built and run against the live vault** — read-only, run by the operator, the agent never sees a value.

## 13. Connections

| Direction | Document | What flows across |
|---|---|---|
| supersedes in part | `14_DECISIONS.md` `ADR-074` | "no licence server, no activation step" — from 2.3 only, for paid entitlements only |
| supersedes in part | `14_DECISIONS.md` `ADR-082` | the static supporter code → a signed, machine-bound, expiring token |
| depends on | `22_ORG_VAULT_SYNC_AND_LICENSING.md §4.4` | Ed25519, offline key, the shell does the check |
| depends on | `16_CROSS_PLATFORM.md` | per-OS keystores for the sealed state and the device key |
| depends on | `05_THREAT_MODEL.md §9.4` | licence checks live in the shell, not the broker |
| depends on | `11_MIGRATION.md` | the "no import" decision §11 narrows |
| feeds | `PRODUCTION_PLAN.md` | the post-release batches |

## 14. Source

**Requirements.** §1, the operator's chat of 2026-10-31. **Ground truth.** No licence code exists: `crates/` has no Ed25519
primitive (`x25519-dalek`, `chacha20poly1305`, `sha2` and `hkdf` are in `Cargo.lock`; `ed25519-dalek` is not and would be
added, with `cargo deny` review). The static supporter pack and code are in `apps/desktop/src/design/logic/extras.js`.
**Decision.** `ADR-095`.
