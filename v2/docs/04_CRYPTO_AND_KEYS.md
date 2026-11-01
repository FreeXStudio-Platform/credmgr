---
id: V2-004
classification: public
title: Cryptography and keys
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-19
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21), then corrected again on 2026-08-19 closing the round-2 independent
     verifier's findings (`v2/VERIFICATION_BACKLOG_S21_ROUND2.md` — `04_CRYPTO_AND_KEYS.md`
     section). The previous stamp (Approved With Known Risks @ d15a5c7, pass 2, reconciled
     2026-08-10 under ADR-052) is void: it named a document that described a Node.js
     implementation, a scrypt passphrase KDF and a Secure Enclave root wrap, none of which is
     what `v2/crates/` contains. Every primitive, parameter and status was re-derived from live
     source in the rewrite pass. The round-2 closure fixed a wrong-section citation (§8 cited
     `13 §2` for the property tests that are actually specified in `13 §3`), disclosed that
     `grant.create` reaches an unconditional `PresenceRequired` for every caller rather than
     being grouped under an unqualified "Built" banner with `grant.list`/`grant.revoke` (§4,
     now `partial`), corrected the §2 hierarchy diagram's `manifest.sig`, which does not exist
     as a file — the manifest HMAC is an embedded `hmac` field, per §6a — and fixed §11's
     undercount of the `root_wrap_*` test fixtures (two, in two files, not one). The corpus-wide
     hardening stamp is the operator's to assign after their own review, not this session's to
     self-award. Updated 2026-09-24 for ADR-062…066 (the live request-scoped unlock, the root key
     resident while unlocked, the gate-secret seal, the last door's use of `root.wrap.recovery`).
     Updated 2026-09-24 for ADR-071…073 (47 broker ops, §5.2). Updated 2026-10-03 for ADR-078/079: the
     envelope's version 2 (§3.1, `03 §7`); the orphan cold key is built, unsealing is still planned (§5);
     §2.1 corrected — two-factor is enforced by `credmgrd`, not by the encryption, so "RK alone opens
     nothing" is true only through the broker; the Software-tier disclosure (§2.4); emergency decryption reads
     both envelope versions (§7.3). -->
# Cryptography and the key hierarchy

`CredMgr V2` · the key material every other guarantee in this corpus is built on, and exactly how much of it exists · `2026-08-18`

> **Status.** The **envelope layer is built and tested**: X25519 sealed boxes, HKDF-SHA512
> derivation, ChaCha20-Poly1305 AEAD, per-node keypairs, and HMAC-SHA256 integrity over every
> plaintext metadata file — all in `crates/core` and `crates/store`, covered by property tests
> P-1…P-5 and by a cross-implementation vector test. The **root-key layer is partial**:
> **vault bootstrap is built** (`credmgr init`, ADR-061 — §2.3), so a real run now writes the
> passphrase and recovery-code root wraps and the `global` node's wrapped private key to disk.
> What remains partial is the keystore tier: the only implementation that exists is
> `SoftwareKeystore` (Argon2id over a passphrase), there is no Secure Enclave, Windows Hello or
> TPM code anywhere in `v2/crates`, so the hardware wrap (`root.wrap.se`) is the one wrap nothing
> writes. Per-request passphrase selection at `vault.unlock` is **built** since 2026-09-24
> (ADR-063 — §2.3), and on that live Software-tier unlock **the root key stays resident until
> lock** (§6) — a change from this document's earlier "RK is not kept resident", stated plainly
> there rather than left to contradict it.
> The **orphan cold key is built** (`keys/cold/orphan.key`, ADR-079 — §5.2): sealing a node works
> across restarts and the key that protects its orphaned copies exists, but **unsealing is still planned** —
> no operation opens that key to read data. **Two-factor is a check made by `credmgrd`, not part of the
> encryption** (§2.1): the passphrase or the recovery code, plus a copy of the vault folder, opens everything
> offline with no second factor. **This system contains no signature primitive at all** — see §1.1,
> which is a section rather than a sentence because that absence has already been asserted the
> other way round in this project's own writing.

---

## 1. Primitives — **`built`**

Every primitive below is a live dependency of `crates/core` or `crates/keystore` and is
exercised by that crate's own tests. Nothing in this table is aspirational.

| Role | Algorithm | Crate | Why |
|---|---|---|---|
| Key agreement | **X25519** | `x25519-dalek` 2 | Misuse-resistant, no parameter choices to get wrong, and the same curve `age` uses, so a cold-storage export stays interoperable. |
| KDF | **HKDF-SHA512** | `hkdf` 0.12 + `sha2` 0.10 | Domain-separated derivation with an explicit `info` label at every call site. |
| AEAD | **ChaCha20-Poly1305** (IETF, 96-bit nonce, 128-bit tag) | `chacha20poly1305` 0.10 | Constant-time in software; no AES-NI dependence, so the guarantee does not vary by machine. |
| Passphrase KDF | **Argon2id**, m=256 MiB, t=3, p=4, 32-byte output | `argon2` 0.5 | Memory-hard. `16 §4.1` fixes these parameters. `crates/keystore` defines `argon2_params()` **twice** — once in `software.rs` for the root wrap, once in `backup_passphrase.rs` for the backup wrap — with identical literals but no shared function; the two wraps agree today by coincidence, not by construction. |
| Metadata integrity | **HMAC-SHA256** over an HKDF-derived subkey | `hmac` 0.12 | Authorship proof for the plaintext registry, manifests, generation counter and audit tip. |
| Content hashing / audit chain | **SHA-256** | `sha2` 0.10 | Entry content hashes and the audit log's `prev` chain. |
| Randomness | `OsRng` (CSPRNG) | `rand_core` 0.6 | Every nonce, ephemeral key, salt, node key, recovery code and token id. |
| Secret handling | `SecretBox`, `Zeroize` | `secrecy` 0.10, `zeroize` 1.7 | Plaintext and key buffers zeroise on drop; the hot key set zeroises in place. |

Every derivation is domain-separated. `keys::derive_subkey` is the single function that turns
the root key into a purpose-bound 32-byte subkey — `HKDF-SHA512(ikm = RK, info = label)` — and
the label is always a literal at the call site, so two purposes cannot accidentally share a
key. **No key is ever used for two purposes.**

**Why these versions and not the latest.** `crates/core`'s crypto dependencies are pinned
below their newest majors because `sha2` 0.11 / `hkdf` 0.13 / `chacha20poly1305` 0.11 pull
`block-buffer` ≥ 0.12.1, which needs Cargo's `edition2024` feature and therefore Rust ≥ 1.85 —
above this workspace's 1.78 MSRV pin. That is a deliberate, recorded trade (`ADR-036`), not
neglect; the pins carry their reasons inline in `crates/core/Cargo.toml`.

### 1.1 There is no signature primitive in this system — **`planned`**, and nothing may assume otherwise

`crates/core` contains **X25519 and HMAC-SHA256, and nothing else**. It has **no Ed25519, no
EdDSA, and no public-key signature scheme of any kind.** `grep -rni 'ed25519|eddsa' v2/crates/`
returns zero matches, and no signature crate appears in any `Cargo.toml` or in `Cargo.lock`.

This is stated at the top of the document, in its own subsection, because the project has
already written the opposite down and acted on it: `POST_LAUNCH_ROADMAP.md` claimed CredMgr
"already has the primitives" for offline-signed licences via "X25519/ed25519 machinery", and
that claim stood until a source grep on 2026-08-10 falsified it. It is corrected there now, and
`22 §2` records the correction. The reason it was believable is the naming:
`crates/core/src/signing.rs` is named `signing.rs` and its functions are
called `sign`/`verify`, but what that module computes is
`HMAC-SHA256(HKDF(root_key, label), data)` — a
**symmetric MAC**, verifiable only by a holder of the root key. It proves that whoever wrote a
manifest held the vault's own key. It cannot prove anything to anybody else, and it cannot be
verified by a party who is not also able to forge it.

Two consequences, both load-bearing elsewhere in this corpus:

- **Offline verification of a signed licence certificate cannot reuse anything here.** A
  certificate must be verifiable by a party that must *not* be able to mint one. HMAC cannot do
  that: the verifier would carry the same key the issuer uses, so the verifier is the forger.
  `22 §4.4` keeps Ed25519 for exactly this reason and records that it is a **new dependency, new
  work** — wrapping nothing that exists. Since `ADR-074` (MIT for everyone) the certificate is
  optional and gates nothing; the argument about the primitive is unchanged.
- **Release integrity does not come from this layer either.** `21 §2` signs shipped artefacts
  with platform code-signing identities (Developer ID, Authenticode) and a detached signature
  over the checksum file. Those are OS and toolchain mechanisms held on a maintainer machine;
  none of them is a vault primitive, and none of them is implemented in `v2/crates`.

**If a document asserts that CredMgr "already has the signing machinery" for anything, it is
wrong.** The target design for a signature primitive is: add one audited Ed25519
implementation as a `crates/core` dependency behind a `verify`-only surface, ship only the
public key in the application, and keep the private key off every build machine. Until that
lands, every design that needs a signature is `planned` and will say so.

---

## 2. The hierarchy — **`partial`**

```
        ┌──────────────────────────────────────────────────────────┐
        │  PLATFORM KEYSTORE — one PlatformKeystore implementation │
        │  built: Software (Argon2id over a passphrase)            │
        │  planned: Secure Enclave · Windows Hello/TPM · Linux TPM │
        └───────────────────────┬──────────────────────────────────┘
                                │ wrap_root / unwrap_root
                                ▼               ┌── recovery code (256-bit, printed once)
        ┌───────────────────────────────────────┴──┐
        │        ROOT KEY  (RK, 32 bytes)          │  resident only while unlocked (§6)
        └───────┬───────────────────────┬──────────┘
     HKDF("node-wrap/<id>")     HKDF(integrity labels)
                │                       └──► registry.sig · manifest.hmac<node> (an embedded
                │                            field, not a file — §6a) · counter · audit tip
                ▼
    ┌────────────────────────────────────────────────────┐
    │  NODE KEYS — one X25519 keypair per node           │
    │  · public  → registry.json (cleartext, by design)  │
    │  · private → wrapped under RK, bound to the node id│
    └──────────────────────┬─────────────────────────────┘
                           │ ECDH(ephemeral, node.pub) → HKDF("credmgr/v2/entry")
                           ▼
    ┌────────────────────────────────────────────────────┐
    │  ENTRY ENVELOPES — one per credential (CMV2 fmt)   │
    └────────────────────────────────────────────────────┘

    ┌────────────────────────────────────────────────────┐
    │  ORPHAN COLD KEY — keys/cold/orphan.key (CMCK v1): │
    │  the orphan node's private half, sealed under      │
    │  HKDF(RK, "orphan-cold"); never loaded; no op      │
    │  opens it for use — unsealing is planned (§5)      │
    └────────────────────────────────────────────────────┘
```

### 2.1 Three independent wraps of the root key

Losing the vault is a worse outcome than any attack in `05 §2`, so the root key is designed to
be recoverable three independent ways.

| Wrap | On-disk name | Unlocks with | Portable? | Status |
|---|---|---|---|---|
| Hardware | `keys/root.wrap.se` | platform presence (biometric / PIN / touch) | no — device-bound | **`planned`** — no hardware keystore exists |
| Passphrase | `keys/root.wrap.pass` | operator passphrase, Argon2id | yes | **`built`** — the wrap/unwrap (`SoftwareKeystore`) and the write at init (`vault.init_confirm`, ADR-061 — §2.3) |
| Recovery code | `keys/root.wrap.recovery` | a 256-bit code, shown once | yes | **`built`** — the wrap format, generation, parsing and unwrap (`recovery.rs`), the write at init (`vault.init_confirm`, ADR-061 — §2.3), and the read by the last door (`vault.gate_recover`, ADR-064) |

**Any one wrap recovers RK. Through `credmgrd`, RK alone opens nothing; offline, RK opens
everything.** [Pass 2 · F-5, corrected 2026-10-03] Three independent doors to the same key is what stops a
re-enrolled fingerprint or a lost machine from being terminal. Through the broker it is not a bypass of
two-factor, because the gate is checked *after* RK is in hand and *before* any node key is unwrapped
(`07 §3`). **That is a property of `credmgrd`, not of the cryptography:** every node key is wrapped under a
key derived from RK, so anyone who derives RK — from the passphrase *or* from the recovery code — and holds a
copy of the vault directory can decrypt every entry offline with no second factor. `scripts/emergency-decrypt.mjs`
does exactly that, from the recovery code alone, by design (§7.3). The passphrase and the recovery code
are therefore each, on their own, a complete key for anyone who also holds the vault folder; two-factor is a
broker-enforced gate on every tier (`16 §4.2`). The ordering through the broker is built and tested: on a gate-
enrolled vault, `BrokerState::unlock_with_passphrase` (the live daemon's path, ADR-063) and
`BrokerState::unlock` (in-memory fixtures) both park the unwrapped root key in a short-lived
`PendingGateUnlock` and return without touching the hot set; only `vault.gate_verify` calls
`install_hot_keys_from_root`. `crates/brokerd/tests/phase5_gate.rs`'s
`item3_wrong_totp_after_a_correct_passphrase_loads_no_node_key` is the proof. A stolen recovery
card, with no copy of the vault folder, opens nothing; with one, it opens everything offline.

The *combination* of passphrase **+** root recovery code **is** a different operation with a
different purpose — **`built`** since 2026-09-24 as `vault.gate_recover` (ADR-064, `07 §4`):
resetting a lost gate once all ten gate recovery codes are spent. Both factors must independently
open the *same* RK — the passphrase through `keys/root.wrap.pass`, the recovery code through
`keys/root.wrap.recovery` — compared in constant time; on success the gate is removed and the
vault is **not** unlocked. It resets a gate, it never bypasses one, and it is not the same door as
either wrap alone.

### 2.2 What is built, precisely

- `keys::derive_subkey`, `keys::wrap_node_key`, `keys::unwrap_node_key`,
  `keys::generate_node_keypair` — `crates/core/src/keys.rs`, with round-trip, wrong-root-key,
  wrong-node-id, non-determinism and truncation tests.
- `recovery::generate_recovery_code` / `format_recovery_code` / `parse_recovery_code` /
  `wrap_root_with_recovery_code` / `unwrap_root_with_recovery_code` —
  `crates/core/src/recovery.rs`. The code is hex, grouped in four-character blocks, and parsing
  accepts it lower-case and ungrouped, because the failure mode it must survive is a human
  retyping it years later on unfamiliar hardware (`ADR-045`).
- `PlatformKeystore` + `Capabilities`/`Tier` + `SoftwareKeystore` — `crates/keystore/`, per
  `ADR-041`. `SoftwareKeystore` reports `Tier::Software`, `hardware_backed: false`,
  `user_presence: false`, so no UI built on it can overstate what it protects.
- `keys::seal_under_root` / `keys::open_under_root` — `crates/core/src/keys.rs`, ADR-064.
  ChaCha20-Poly1305 under `HKDF(RK, label)`, one label per use; the persisted 2FA gate's TOTP
  secret is sealed under `credmgr/v2/gate-secret/<scope>` (`global` for the vault gate), so the
  registry that stores it does not reveal the seed (`07 §3`). Tested for round-trip, wrong root
  key, wrong label, tampering and truncation.

The node-key wrap folds the node id into the HKDF `info` label —
`credmgr/v2/node-wrap/<node_id>` — which is one step stronger than the diagram above spells
out: a wrapped key blob is bound to the specific node it belongs to, so relocating a key file
fails to unwrap rather than succeeding into the wrong slot.

### 2.3 Vault bootstrap — **built** (ADR-061)

**`credmgr init` exists.** `crates/cli/src/main.rs` now dispatches 24 top-level subcommands,
`init` among them, and `credmgrd`'s `main` actually runs the broker (`server::run`) instead of
printing a status line and exiting. Two ops carry it — `vault.init_begin`/`vault.init_confirm`
(`crates/brokerd/src/ops.rs`), a two-phase shape mirroring `vault.gate_enroll_begin`/`_confirm`,
because `04_CRYPTO_AND_KEYS.md`'s own target design (below) requires the recovery code be shown
once and re-entered *before* anything is written, which one synchronous op cannot do without
either blocking the broker on interactive input or writing the vault before the operator has
proven they saved the code. Full design record: `14_DECISIONS.md` ADR-061.

What actually happens, matching every one of the four target-design steps below: `begin_init`
generates RK from `OsRng` and the `global` node's keypair, wraps RK two ways — a request-scoped
`SoftwareKeystore`'s Argon2id passphrase wrap and a freshly generated 256-bit recovery-code wrap
(`credmgr_core::recovery`) — and holds everything in memory, ciphertext only past that point,
until `confirm_init` matches the retyped recovery code and writes `root.wrap.pass`,
`root.wrap.recovery`, `keys/nodes/global.key` (all `0600` under a `0700` `keys/` directory), an
initial empty manifest for `global`, `registry.json`+`registry.sig`, and the external generation
counter, in that crash-safe order. `BrokerState::load_key_material` (new, alongside the
already-existing `verify_and_load_vault`) commits the same material into the *running* broker, so
the vault a real `credmgr init` just created is immediately loaded, not only present on disk.

**The boundary ADR-061 did not close — closed by ADR-063 (2026-09-24, as amended after
review).** The keystore `credmgrd` constructs at its own process start is a placeholder (an empty
passphrase); `vault.init_begin` never reads it (it builds its own request-scoped keystore from the
passphrase in the op's own params), and until 2026-09-24 `vault.unlock` unwrapped against it,
ignoring `params.passphrase`, so a live daemon answered `wrong_passphrase` to the right
passphrase. **The live unlock now mirrors `init_begin`:** `vault.unlock {passphrase}` builds a
request-scoped `SoftwareKeystore` from the passphrase (ADR-041's permanent tier), proves it
against `keys/root.wrap.pass`, and loads and verifies the vault from disk before anything is
committed (`crates/brokerd/src/state/durable.rs`). The passphrase keystore is dropped at once and
never installed as the broker's own — the passphrase is never resident — and the unwrapped RK is
kept resident until `lock()` (§6). For a disk-backed vault `reauth_root_key` reads only that
resident RK and never the start-up keystore, so a passphrase-less `vault.unlock` can never open a
live vault: it is refused. Proof: `crates/brokerd/tests/durable_vault.rs`
(`a_vault_created_by_init_unlocks_with_its_passphrase_on_the_same_broker`,
`after_a_restart_the_passphrase_unlock_loads_the_vault_from_disk`,
`a_wrong_passphrase_opens_nothing_and_loads_nothing`), alongside `vault_init.rs`'s original
`init → lock → unlock` round-trip over the real on-disk files.

The target design steps this closes:

1. First run **generates** RK from `OsRng` and the `global` node's keypair. ✅
2. It **wraps** RK two ways — the passphrase wrap and the recovery-code wrap — and writes both
   files at `0600` under a `0700` `keys/` directory. ✅ The platform-keystore hardware wrap
   (`root.wrap.se`) is the one wrap this does NOT write, because no hardware keystore is built
   yet (N3, macOS Secure Enclave — `16_CROSS_PLATFORM.md §4.2`); "**setup will refuse to finish
   with only a hardware wrap**" is satisfied vacuously on the Software tier, since there is no
   hardware-only path to finish with.
3. It **displays** the recovery code exactly once (`vault.init_begin`'s response value, never
   stored, never re-fetchable — same shape `gate_enroll_confirm` already uses) and **requires**
   the operator to re-enter it (`vault.init_confirm`) before anything is written. ✅ *(The broker requires it; the desktop may send the code it shows when the person skips the retype — ADR-081.)*
4. It **writes** the registry, its HMAC, and the initial external generation counter, in that
   order (plus the initial empty manifest ahead of the registry that cross-binds to it, a real
   requirement `verify_and_load_vault` enforces that this list didn't originally name), so a
   crash mid-init leaves a vault that fails closed rather than one that opens with an unanchored
   counter. ✅

<!-- figure:key-hierarchy-built-vs-planned -->

*The chain is complete and tested from the root key downward. Solid edges are built and
persisted: the passphrase and recovery-code root wraps, and every node's wrapped private key
(ADR-061 closed both root-wrap edges this session — previously dashed, now solid). The one edge
still dashed is the hardware/platform-keystore wrap (`root.wrap.se`) — no hardware keystore
exists yet (N3), so nothing writes it; the orphan cold key is likewise dashed, unaffected by this
session's work. **Caption text corrected 2026-08-31; the rendered figure itself has not been
regenerated and may still show the pre-ADR-061 edge states** — re-run `tools/docgen` for this
document before trusting the image over this text.*

---

### 2.4 What the Software tier protects and does not — the release disclosure (K-5)

This release has **one** keystore tier, `Software`. The wording below is the product's own statement of it
and is repeated, verbatim in substance, in `README.md`, `RELEASE.md`, `SECURITY.md`, `07 §3` and `16 §3`; if
it changes, it changes in all of them.

- **Your passphrase is the key.** The vault's root key is stored in the vault folder encrypted two ways:
  under a key derived from your passphrase with Argon2id (256 MiB of memory, 3 passes, 4 lanes), and under
  the 256-bit recovery code printed at `credmgr init`. Nothing is held in the Mac's Secure Enclave and nothing
  is tied to this Mac: a copy of the vault folder can be attacked offline on any computer, slowed only by the
  Argon2id cost of each passphrase guess. Use a long, unique passphrase and keep the recovery code offline.
- **While the vault is unlocked,** `credmgrd` holds the root key and every unlocked project key in memory
  until it locks (idle timeout or `credmgr lock`; the desktop app also locks it when the Mac sleeps, the screen locks or the session switches, but a daemon running without the app does not). It does not lock its memory pages or block
  debuggers, so software able to read its memory — anything running as root, for example — can read those
  keys (R-1, R-3).
- **No Touch ID, no presence.** Reading a sealed (Orphaned) entry is refused with `node_access_denied` (rule R0 in
  `crates/core/src/access.rs`: the sealed store opens only to a native caller with a live presence attestation, and
  none can give one yet); creating a grant, re-parenting a node and widening a node's sharing are refused with
  `presence_required` (K-1).
- **Two-factor guards the door, not the safe.** With two-factor on, `credmgrd` will not unlock your vault
  without a fresh code. That check is made by `credmgrd`, not by the encryption: anyone who has your
  passphrase or your recovery code *and* a copy of your vault folder can decrypt it without the second factor.
  Treat each of the passphrase and the recovery code as a complete key to your vault.
- **The binaries are not code-signed or notarised;** check them against `SHA256SUMS` (`21 §2`). Hardware-backed
  protection (Secure Enclave with Touch ID) is planned and is not part of this release.

---

## 3. Node keys are asymmetric — and that buys something real — **`built`**

Each node holds an X25519 **keypair**. The public half lives unencrypted in the registry. That
single decision (`ADR-002`) yields three properties symmetric keys cannot:

1. **Write without read.** A client can encrypt a new entry to a node's public key without RK,
   without the node's private key, and **without the vault being unlocked**. An agent granted
   write-only access can deposit a rotated token and provably cannot read anything — including
   what it just wrote.
2. **Add-to-locked-vault.** "Save this credential" works on a locked vault. The entry lands
   sealed and is readable at next unlock. This removes the single most common reason people
   leave a vault unlocked all day.
3. **Cheap node rotation.** Compromise or paranoia about one node re-keys only that node.

Property 2 is why `BrokerState` keeps `node_public_keys` outside the hot set entirely: public
keys survive `lock()` untouched, because `entry.create` must still be able to seal to them
with no private key material unwrapped at all.

> ### ⚠ `create` while locked — yes. `update` while locked — no. [Pass 2 · F-1]
>
> The obvious reading of "write without read" is an attack: anyone who can encrypt to a node's
> public key can **overwrite an existing credential with one they control**. The ciphertext is
> perfectly valid, so encryption cannot detect it, and the operator then uses the attacker's
> password against the attacker's server. This is credential substitution, and it is a worse
> outcome than a read.
>
> The capability is therefore split, and the split is enforced in the broker, not the UI:
>
> | | while **locked** | while **unlocked** |
> |---|---|---|
> | `create` — a new entry, a name not already present in the node | ✅ → **pending tray** | ✅ direct |
> | `update` — modify an existing entry or field | ❌ `vault_locked` | ✅ |
>
> Anything created while locked is written to `nodes/<id>/pending/` and does **not** enter the
> manifest. At the next unlock a human accepts or discards each. An `update` requires the vault
> open, because a legitimate update implies you could have read what you are replacing.
>
> Built and tested: `crates/brokerd/tests/isolation.rs`'s
> `i18_create_while_locked_lands_in_pending_and_update_is_refused_until_accepted`.

### 3.1 Deriving the entry key

The sealed-box construction, exactly as `crates/core/src/envelope.rs` implements it:

```
ephemeral      = X25519 keygen                       (fresh per envelope)
shared         = ECDH(ephemeral.priv, node.pub)
key            = HKDF-SHA512(ikm  = shared,
                             salt = ephemeral.pub ‖ node.pub,
                             info = "credmgr/v2/entry",
                             len  = 32)
nonce          = OsRng, 12 bytes
ct ‖ tag       = ChaCha20-Poly1305(key, nonce, plaintext,
                                   aad = magic ‖ version ‖ suite ‖ nodeId ‖ entryId)
```

A fresh ephemeral key per envelope means the derived key is unique per envelope, so nonce
reuse is structurally impossible even before the random nonce is considered. Binding
`nodeId ‖ entryId` into the AAD means an envelope cannot be relocated into another node's
directory, nor swapped with a sibling, without failing authentication.

**Which `nodeId` the AAD binds is a decision, not an implementation detail** (`ADR-037`). The
AAD uses the **caller's asserted** node and entry id — the values the storage layer derives
from *where the file lives* — for both the header field written at seal time and the AAD at
seal and open. That is the only reading under which relocation is guaranteed to fail: the ECDH
already uses a different node key, and the AAD the receiver reconstructs from its own
path-derived context disagrees with the AAD that authenticated the ciphertext. The stored
header field is a redundant, unauthenticated hint — useful for "which key do I need without
decrypting" (`03 §7`) — and a mismatch is rejected before the AEAD call runs purely to give a
clearer error. The tag is what enforces it.

The byte layout of the CMV2 envelope is specified in `03 §7` and implemented in the same file;
this document owns the key derivation, that one owns the format.

**Two envelope versions, one construction (ADR-078).** Version 1 is an envelope whose plaintext is one raw
value (everything `2.0.0-alpha.6` wrote; a node's note still is). Version 2 is an envelope whose plaintext is a
field document (`03 §3`). The suite, the derivation above, the header and the nonce and tag are identical; the
only difference is the version byte, and because `version` is in the AAD the payload kind is authenticated —
changing the byte fails the tag (P-16). `build_aad` takes the version being sealed or read, and the version-1
AAD is byte for byte what it has always been, so no existing envelope is affected. Nothing is migrated: a
version-1 envelope is read in place, and the first write re-seals it as version 2.

---

## 4. Grants are enforced, not wrapped — and why — **`partial`**

Two ways to express "node B may read node A":

| | **Soft grant** — broker-enforced *(chosen)* | **Hard grant** — cryptographic |
|---|---|---|
| Mechanism | Broker checks the graph before unwrapping A's key | A's private key wrapped to B's public key |
| Revocation | **Instant**, one write to the registry | Requires re-keying A and re-encrypting every A entry |
| Works if broker bypassed | ❌ | ✅ |
| Grant is visible on disk | in the registry, HMAC'd | as a key file |

**Decision: all grants are soft** (`ADR-003`). The broker is already the single, mandatory
enforcement point (`02 §1`) — a hard grant would only help against an attacker who has already
bypassed the broker, and in exchange it makes revocation an expensive, forgettable, partial
operation. A grant you cannot instantly revoke is not a grant, it is a copy.

This is written down explicitly because it is the design's most attackable seam: **if the
broker is compromised, grants mean nothing.** That is stated in `05 §7` as an accepted risk
rather than smoothed over.

`grant.list` and `grant.revoke` are **`built`**: both are dispatched by
`crates/brokerd/src/ops.rs` and gated on `Capability::Admin` resolved against the grant's `to`
node, not `from` (`ADR-050`); revocation taking effect on the very next request is asserted by
`isolation.rs`'s `i6_revoked_grant_denies_the_very_next_request`, and expiry by
`i7_expired_grant_is_denied_and_reported_as_expired`. Both tests seed their grant directly into
the fixture registry rather than through `grant.create` — the op that would actually create one.

**`grant.create` is `partial`, the same shape as `node.reparent` (§6).** It validates the reason
(≥ 8 characters), rejects `orphan` as either endpoint, restricts the requested scope to the
`read`/`reveal`/`notes` set `03 §6` defines, checks the caller's capability ceiling, and resolves
`Capability::Admin` against `to` for real — then reaches an unconditional
`Err(OpError::PresenceRequired)` for every caller, including one already holding Admin
(`crates/brokerd/src/ops.rs`, the `"grant.create"` arm). `ADR-050`'s own title says so:
"`revoke` genuinely executes, `create` is presence-blocked like `node.reparent`." No live
transport can ever complete it today, because `presence_attested` is hardcoded `false`
everywhere (§5.2) and no presence-capable keystore exists to attest it. There is no working
grant-creation path yet — every grant a test exercises was placed in the registry directly, not
minted by this op.

---

## 5. The orphan cold key — **`partial`**

Sealing (node removal) must produce data that is unreadable by *every automated path*,
including a fully unlocked broker serving a fully authorised agent.

### 5.1 What sealing does today — **`built`**

`node.seal` is dispatched and covered by `isolation.rs`'s
`i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone` and, on a vault that lives on disk, by
`seal_durable.rs` (ADR-079). For each entry in the target node it opens the envelope with the node's hot
private key, re-seals the payload — as the same kind, version 1 or 2 (ADR-078) — to the **orphan node's public
key**, writes it into the orphan node's entry directory, and adds a manifest row that keeps the name, ref, type
and the **digest of the resealed envelope** (it used to copy the original's, a defect fixed in ADR-079). It
then moves the **original** ciphertexts and the node's own key material into `archive/<nodeId>/` for exactly
seven days (`crates/store/src/archive.rs`, `RECOVERY_WINDOW_SECONDS`).

**Seal and restore are crash-safe commit protocols (ADR-079).** The seal record lives in the **signed
registry** (`sealed[<id>]`: the node's own record, `sealedAt`, a binding to the archived manifest's
generation and HMAC, the SHA-256 of the archived node key, and the orphan entry ids), so it is covered by the
registry HMAC and the external generation counter and a restart no longer forgets an in-window seal. The
registry write is the commit point and is made inside the op; the orphan envelopes and `meta.json` written
before it are unread until the registry names them, and the file moves after it are idempotent and finished by
load-time housekeeping if a crash cut them short. A crash at any step leaves a vault that unlocks, with the node
either still live or sealed and restorable (the table is `seal_durable.rs`'s). Restore moves the files back
*while the registry still says sealed*, verifies them against the signed record (manifest binding, node-key
digest, the derived public key), and only then commits the registry without the record; any mismatch puts the
files back and refuses. `node.seal` refuses a node with live sub-nodes, an unsafe id and an id that is already
sealed; `node.create` refuses the id of a sealed node whose archive exists.

> **Why the archive keeps the original, not just the orphan copy.** [Pass 2 · F-4] Pass 1
> discarded the source material at seal time and separately promised a one-click "Restore node"
> for 7 days. Those two statements were incompatible: restoring from the orphan copy would need
> the **cold** key, which by design costs a presence prompt and a fresh code *per item* — not a
> one-click restore, and not something to do twelve times in a row. Restore within the window
> is therefore a **move**, using the retained key (`ADR-027`). At day 7 the archive and the node
> key are destroyed and only the orphan copy remains.

**One half of the day-7 line is not yet wired.** `archive::restore` correctly refuses past the
window and `archive::purge_if_expired` correctly destroys both the retained ciphertexts and the
retained node key — both are implemented and covered by
`archive.rs::day_8_restore_is_refused_and_purge_destroys_both_copies`. But **nothing calls
`purge_if_expired`**: no broker op invokes it and no scheduler exists to invoke it on a
timer. (`grep -rn 'purge_if_expired' v2/crates/` returned eight lines across two files when measured: this
function's own definition and two tests in `archive.rs`, plus a second, independent
`purge_if_expired` in `crates/store/src/entry_archive.rs` — the entry-level soft-delete purge,
a different mechanism from the node-seal archive this section is about. Neither function has a
caller outside its own test module.) The
*authorisation* boundary therefore holds today — an expired archive cannot be restored — while
the *destruction* does not happen on schedule, so a sealed node's private key can sit on disk
past its stated lifetime. The finished design calls `purge_if_expired` from the same daily
maintenance pass that `ADR-039` defers automatic backups to; until that pass exists, the
seven-day figure is a refusal deadline, not a deletion deadline. This distinction is why R-3's
blast radius is stated as it is: an on-disk key that should have been destroyed is a broader
target than a hot-set key that was.

Sealing needs only the orphan **public** key, which is why it is fast and needs no extra
prompt. `BrokerState::seed_public_key_only` exists precisely so the orphan node can be
registered with a public half and no private half — there is nothing in the hot set that could
ever be unwrapped for it. Before sealing commits anything, `node.seal` opens the cold key once
(§5.2) to prove it is recoverable.

### 5.2 The cold key — **`built`**; unsealing — **`planned`**

**The cold key exists (ADR-079).** One X25519 keypair. The public half is `orphan.publicKey` in the registry;
the private half is the file `keys/cold/orphan.key`, format **`CMCK` v1**, exactly 98 bytes
(`crates/core/src/cold.rs`):

```
magic    "CMCK"                                         4
version  0x01                                           1
kind     0x01 = root-derived (Software tier)            1   (0x02 is reserved for a Secure-Enclave wrap)
pub      the orphan X25519 public key                  32
sealed   seal_under_root(RK, "credmgr/v2/orphan-cold/v1", private)
                                                       60   nonce(12) ‖ ciphertext(32) ‖ tag(16)
```

Opening derives the public key from the private half and requires it to equal **both** the header's `pub`
and the registry's `orphan.publicKey`, so a swapped or rolled-back cold file cannot be mistaken for the real
one. The HKDF label differs from `credmgr/v2/node-wrap/orphan`, so a cold blob never opens as a node wrap and
the reverse. **Custody rules, enforced and tested:** the key is never in the hot set or in `node_wrapped_keys`;
the loader treats `orphan` as public-only whatever is on disk (a `keys/nodes/orphan.key` is ignored and
reported by `maintenance.verify`); unlock never opens it; the only code that does is `node.seal`'s pre-flight,
transient and zeroised. A missing or mismatched cold key refuses the seal and writes nothing. `credmgr init`
creates it with the `orphan` node; an older vault gets both on its first `node.seal` or on
`maintenance.doctor` — never as a side effect of unlock. The backup includes the file
(without it a restored backup holds orphan envelopes with no key), and `maintenance.rotate_root` re-seals it
under the new root key (the keypair itself does not change, so no orphan envelope is re-encrypted).

**Why root-derived, and what "cold" means on this tier.** This section's earlier formula took "a fresh,
single-use gate proof" as the HKDF salt, which can never reopen a stored blob — a fresh salt per use is
a different key each time. The gate proof is an authorisation precondition of a future unseal, never key
material. The Software tier has two faithful choices, a key derived from RK or one derived from the
passphrase (a second Argon2id); ADR-079 chose RK, because it adds no exposure (RK already opens every live and
archived node key), survives a passphrase change, and is recoverable from the recovery code alone, where a
passphrase-derived key would strand orphaned data. **So on the Software tier the cold property is enforced
by the broker — R0 denies the orphan to everyone but a present human, no operation uses the key, no
resident copy exists — and not by cryptography against a compromised broker:** RK, resident while the vault is
unlocked (§6), derives it. A hardware tier would rewrap it under a Secure Enclave key with a per-use presence
ACL and drop the root-derived wrap.

**Unsealing remains `planned`.** There is **no unseal operation** among the 53 broker ops: nothing reads an
orphaned value, and sealed data past day 7 is, at this moment, unreadable by anyone including the operator —
the key to read it exists, and no code path is allowed to use it. The target design for the operation:

- The orphan key will **never enter the broker's hot key set**. Unlocking the vault will not
  unlock orphaned data. (Already true, and now by construction rather than absence.)
- Every single reveal will cost one presence prompt **and** one fresh TOTP code. There will be
  no session, no cache, no batch mode, no `--yes`.
- There will be **no MCP tool and no CLI flag** that can reveal orphaned content. Not gated —
  absent. The pure access resolver already enforces the authorisation half: `access.rs`'s rule
  **R0** denies `orphan` as a target to every caller except one whose origin is the native app
  *and* who carries a live presence attestation, and denies `orphan` as a *subject*
  unconditionally under R8. Neither condition can be satisfied today — a Tauri bridge exists
  (`ADR-057`, `ADR-062`), but that bridge, like every other transport, never constructs
  `Origin::Native` with `presence_attested: true`, and no presence-capable keystore exists to attest it.
- Names, refs and types stay in the manifest so a human can find what they are looking for.
  That is the whole "only the name is available" requirement, and it is built.

<!-- figure:seal-to-orphan-timeline -->

*Removal has three distinct states, not two — reversible-by-move for seven days, then
cold-copy-only forever; the fourth, per-item unseal, is a planned state with no implementation
today.*

---

## 6. Key lifecycle — **`partial`**

| Operation | What happens | Gate | Status |
|---|---|---|---|
| **Vault init** | RK generated; keystore wrap + passphrase wrap + recovery wrap written; `global` and `orphan` nodes created | first run | **`partial`** — `credmgr init` is built (`vault.init_begin`/`vault.init_confirm`, ADR-061 — §2.3): RK, the passphrase and recovery-code wraps, the `global` node key, the cold key `keys/cold/orphan.key`, the empty `orphan` node and its manifest, the initial manifest, the registry and the counter are all written (ADR-079). The **keystore (hardware) wrap is not** — no hardware keystore exists (§2.1) |
| **Unlock** | one wrap unwraps RK → gate 2FA → all node private keys unwrapped into the hot set → RK dropped on the Pass-1 design; on the live Software-tier unlock, RK stays resident until lock (below) | passphrase (+ gate, when enrolled) | **`built`** — on the live daemon `BrokerState::unlock_with_passphrase` (a request-scoped keystore, load-and-verify from disk, ADR-063); `BrokerState::unlock` for in-memory fixtures; `install_hot_keys_from_root` |
| **Lock** | every hot key zeroised **in place**, and the resident RK; elevations and in-flight gate challenges dropped | idle, explicit; the desktop shell adds sleep / screen lock / session switch (`external_lock_signal`; the daemon alone has no such observer) | **`built`** — `isolation.rs::after_lock_every_hot_set_buffer_is_all_zero`; `durable_vault.rs::locking_drops_the_passphrase_keystore_so_nothing_can_be_written_while_locked` |
| **Create node** | new X25519 pair; private wrapped to RK, bound to the node id | unlock + `Capability::Admin` | **`built`** — `node.create` (`ADR-051`) |
| **Rotate node key** | new pair; every entry in the node re-encrypted; old private retained 7 days then destroyed | unlock + 2FA | **`planned`** — no `node.rotate_key` op exists |
| **Rotate root key** | new RK; all node keys re-wrapped; both root wraps that exist (passphrase, recovery) rewritten — the hardware wrap is `planned`, §2.1; every root-signed file re-signed together; recovery code reissued, shown once | unlock + Admin + 2FA + presence | **`partial`** — `maintenance.rotate_root` is built and tested (`ADR-076`, `crates/brokerd/tests/rotate_root.rs`): crash-safe by a stage / single commit record / roll-forward journal, so the vault opens with the old root key or the new one at every instant, and a per-vault lock serialises it against every recovery. On the wire it answers `presence_required` after the human, Admin and second-factor checks, because no transport can attest presence yet (`ADR-047`); the rotation itself is exercised directly. It re-seals the orphan cold key under the new root and refreshes every seal record's bindings (ADR-079), and refuses, changing nothing, while `keys/` holds a file it cannot re-wrap (`root.wrap.se`, any other file under `cold/`, a later build's addition) or a sealed node's files are not yet all in its archive. A copy of the vault made before a rotation still opens with the old passphrase and recovery code |
| **Seal node** | entries re-encrypted to the orphan public key; originals + node key retained in `archive/` for 7 days; the seal recorded in the signed registry | unlock + `Capability::Admin` | **`built`** — §5.1; durable and crash-safe since ADR-079 |
| **Purge the archive** (day 7) | retained ciphertexts and the retained node key destroyed | automatic, no operator action | **`partial`** — `archive::purge_if_expired` is written and tested, but has no caller; §5.1 |
| **Restore node** (≤ 7 d) | move originals back from `archive/`; verify against the signed seal record; re-register the node key | unlock + `Capability::Admin`, resolved against the *sealed* node | **`built`** — `ADR-053`, `i21b`; across restarts since ADR-079 |
| **Unseal entry** (> 7 d) | orphan private unwrapped for one operation, zeroised immediately after | presence + fresh TOTP, native app only | **`planned`** — §5.2: the key exists, no operation uses it |
| **Re-parent node** | ancestor set changes ⇒ readable set changes; treated as scope-widening | unlock + 2FA + presence + reason | **`partial`** — `node.reparent` is dispatched and validates its reason, capability and target, then returns `PresenceRequired` unconditionally; the re-parenting itself is unimplemented because presence attestation does not exist |

**RK is resident while a live vault is unlocked — corrected 2026-09-24 (ADR-063, as amended
after review).** This paragraph used to read "RK is not kept resident", and for the live
Software-tier unlock that no longer holds. After a passphrase unlock the broker keeps the
unwrapped RK in memory (`BrokerState`'s `session_root`, a `SecretBox` that zeroises on drop)
until `lock()`, and drops the passphrase keystore at once, so the passphrase itself is never
resident. The reason is structural, not convenience: every write re-derives node keys and the
metadata HMACs from RK, and the Software tier's only other way to reach RK on demand would be to
keep the *passphrase* resident — which re-derives the same key, at the cost of an Argon2id
derivation per request, and makes the broker a passphrase-holding process. For a disk-backed
vault, `BrokerState::reauth_root_key` — which sealing a node, verifying the vault, writing a
backup and every write-through call — reads only that resident RK and never the start-up
keystore, and a locked disk-backed vault answers at once without any derivation. **The
consequence, stated rather than softened:** a memory capture of a running, unlocked broker yields
node keys *and* the root key, so it also yields the ability to unwrap future nodes and to forge
the metadata HMACs until the vault locks (AR-2 in `05 §7`; R-3 below). Before the live unlock
existed, RK went out of scope after unlock and `reauth_root_key` re-derived it through the keystore
per use; in-memory fixtures still behave that way. Hardware tiers are `planned` and may choose
otherwise — a Secure Enclave wrap can re-derive RK per use without keeping a passphrase resident.

### 6a · Integrity of the plaintext metadata — **`built`** [Pass 2 · F-2, F-3]

The registry and the manifests are unencrypted by design (`03 §2`). Unencrypted must not mean
unprotected, and two distinct attacks apply.

**Forgery** — editing a manifest to hide an entry, change a count, or repoint an entry id at
another envelope. Countered by an HMAC on *every* plaintext metadata file:

```
registry.sig        = HMAC-SHA256( HKDF(RK, "registry-hmac"),         registry.json )
manifest.hmac<node> = HMAC-SHA256( HKDF(RK, "manifest-hmac/"+nodeId), manifest body )
counter             = HMAC-SHA256( HKDF(RK, "generation-counter/"+name), value )
audit tip           = HMAC-SHA256( HKDF(RK, "audit-tip/"+yearMonth),  lineCount|lastHash )
```

`registry.json` additionally records each node's `manifestGeneration` and `manifestHmac`, so
registry and manifests are **cross-bound** — neither can be swapped for an older
validly-signed version of itself without contradicting the other
(`crates/store/src/manifest.rs::verify_cross_binding`). The manifest HMAC deliberately covers
a body type that structurally cannot contain the `hmac` field, so signing can never accidentally
include the tag it is producing.

**Rollback** — restoring yesterday's registry, which verifies perfectly and quietly reinstates
a revoked grant or a loosened policy. An HMAC proves authorship, never freshness. Countered by
a monotonic `vaultGeneration` counter held **outside the vault directory**, in the platform
state directory (`crates/store/src/generation.rs`, `ADR-024`/`ADR-039`). Restoring a copy of
the vault directory does not restore the counter; a lower generation makes the broker refuse to
open and name the discrepancy, pointing at `credmgr doctor --rebuild-registry` (`02 §7`). Since
ADR-063 the live daemon applies this at unlock, and a **missing** counter is refused too, unless
`credmgrd` is started with `CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1` (the one legitimate case: a
vault moved between machines). The counter only moves forward; a write interrupted between its
manifests and its registry is recovered from the previous signed registry pair
(`registry.json.prev`/`registry.sig.prev`) and a manifest exactly one generation ahead of its
binding — each still authenticated under RK, and the counter still refusing anything older than
the last completed write.

**The audit log gets the same treatment, one layer further.** Each line's `prev` is the SHA-256
of the previous line's raw bytes, so an edit anywhere but the last line breaks the chain walk.
Truncating or editing the *final* line needs an anchor outside the file: an HMAC'd
`<year-month>.tip` sidecar recording the expected line count and final hash, updated on every
append and checked by `credmgr_store::audit::verify`. A plain hash chain with no external
anchor is recomputable by anyone who can write the file; the tip is what makes it not — with one stated limit: `append`
re-signs the tip over the log as it stands without verifying it first, so a truncation is detected
only until the next request lands (accepted risk K-9, `PHASE8_AUDIT_REPORT.md §4`).

Rollback and truncation become loud, named failures rather than silent reversals of a security
decision.

---

## 7. Backup and portability — **`partial`**

### 7.1 Backup — **`built`**

`maintenance.backup` is dispatched, gated on `Capability::Admin` resolved against Global
(`ADR-054`), and produces a **single encrypted archive**. The bundle
(`crates/store/src/backup.rs`) contains every entry envelope, every manifest, the registry and
its signature, the passphrase and recovery root wraps, the orphan cold key `keys/cold/orphan.key` (ADR-079), and every *wrapped* node key file —
that last item was not named in earlier revisions of this section but is structurally required,
since without it the envelopes are undecryptable even after recovering the root key. It
excludes `root.wrap.se` (meaningless off the machine that made it), everything under `run/`,
the audit log, notes, TOTP seeds, and archived sealed-node contents.

The bundle is then encrypted with `credmgr_keystore::backup_passphrase::encrypt_with_passphrase`
— Argon2id at `16 §4.1`'s parameters, then ChaCha20-Poly1305 — under a passphrase the caller
supplies. Old backups are pruned to a retention count.

**Not yet built:** deriving the backup key from the *recovery code* as an alternative to a
separate backup passphrase, and firing backups automatically (daily, and before a destructive
operation). Both are named in `ADR-039`/`ADR-054` as deferred, and the second needs a running
scheduler the daemon does not yet have.

### 7.2 Export — **`planned`**

No export operation is dispatched. `node.export` is designed here and indexed as `planned` in
`18 §1.4`; `credmgr export --age <recipient>` for `age`-encrypted cold storage is designed and
unimplemented. The target design is that an export **will** be gated on 2FA plus presence plus
an explicit `--out` path — piping a vault into a terminal is how it reaches scrollback — and
that its contents **will** be exactly:

| Will be included | Will never be included, under any flag |
|---|---|
| entry names, refs, types, field labels and **values** for the exported nodes | node **notes** — opt-in only, see below |
| | **gate 2FA secrets** — they protect the vault; exporting them is self-defeating |
| | **stored TOTP seeds** — `--include-totp` will exist, will require presence, and will warn |
| | the **audit log** |
| | any **orphaned** content — sealed data will never leave through an export |
| | key material of any kind |

`--include-notes` will exist for a full personal archive, will require presence, and will print
a warning naming what is about to be written in the clear. A `.env` export is values only, by
definition of the format.

### 7.3 Emergency decryption — **`built`**

`scripts/emergency-decrypt.mjs` recovers one entry's plaintext given a vault directory, a node
id, an entry id and the root recovery code — with no Rust toolchain and no running broker. It
imports only Node built-ins, so there is nothing an install step could fail to fetch. The
recovery code is read from an environment variable or stdin, never from argv, for the same
reason no other secret is passed in argv (`10 §2`). It reads **both envelope versions** (ADR-078): for a
version-1 entry it prints the raw value; for a version-2 entry it prints the canonical JSON field document
verbatim (lossless, and parseable by any tool), and `--pretty` indents it. The AAD is built from the version
byte actually read. It reads live nodes only: orphaned entries have no private key a recovery code can
unwrap (§5.2).

This claim is testable and tested: `crates/cli/tests/emergency_decrypt.rs` builds a fixture
vault using the real Rust primitives, shells out to the real script, and asserts the recovered
plaintext is byte-identical. `crates/core/src/envelope.rs`'s `node_interop_vectors` test pins
the same agreement one layer lower, at the primitive level, so a drift in HKDF salt
construction or AAD assembly fails in Rust rather than surfacing as an inexplicable
authentication failure during a disaster.

---

## 8. What must be property-tested — **`partial`**

These are correctness claims, not aspirations. `13 §3` (`Property tests (core)`, P-1…P-5, which
back items 1–5 below) and `13 §4` (the isolation suite, which backs items 6, 8 and 9) turn each
into a test. `13 §2` is the layers overview table, not the property tests themselves — its own
`Core property` row points onward to `13 §3`.

| # | Claim | Status |
|---|---|---|
| 1 | An envelope for node A **never** decrypts under node B's key, for all A ≠ B | **`built`** — `properties.rs::p2_cross_node_decrypt_always_fails` |
| 2 | Relocating an envelope between node directories fails (AAD `nodeId`) | **`built`** — `p3_wrong_asserted_node_id_fails` |
| 3 | Swapping two envelopes within one node fails (AAD `entryId`) | **`built`** — `p4_wrong_asserted_entry_id_fails` |
| 4 | `open(seal(m, K), K) == m` for arbitrary bytes, including empty and multi-megabyte | **`built`** — `p1_seal_open_round_trips`, plus `envelope.rs::round_trip_empty_and_large` |
| 5 | Ciphertext is non-deterministic: the same plaintext twice gives different bytes | **`built`** — `p5_sealing_is_nondeterministic` |
| 6 | After `lock()`, every buffer previously in the hot set is all-zero | **`built`** — `isolation.rs::after_lock_every_hot_set_buffer_is_all_zero` |
| 7 | A tampered `registry.json` fails HMAC verification and the vault refuses to load | **`built`** — `registry_file.rs::tampered_registry_json_is_refused`, `tampered_registry_sig_is_refused`, `wrong_root_key_is_refused` |
| 8 | Unwrapping RK with a wrong passphrase fails cleanly, with no partial state | **`built`** — `software.rs::wrong_passphrase_fails_authentication`; `i15_wrong_passphrase_leaves_the_hot_set_empty` |
| 9 | Sealing then unsealing round-trips byte-exactly, including non-UTF-8 bytes | **`partial`** — seal→archive→restore is proven byte-identical by `i21` and, across restarts, by `seal_durable.rs`; the cold unseal half has no implementation to test (§5.2) |
| 10 | A **golden envelope** committed to the repo opens byte-identically forever | **`partial`** — an envelope exactly as the unmodified alpha.6 `seal` produced it is pinned as a hex literal in `envelope.rs::an_alpha6_version_1_envelope_still_opens_byte_for_byte` (ADR-078); no version-2 golden and no `.cmv2` file is committed |
| 10a | The payload kind is authenticated: flipping the version byte, or moving an envelope, fails the tag | **`built`** — `field_doc.rs::p16_payload_kind_is_authenticated` (1,000 cases), `isolation.rs` I-29 |
| 11 | **RFC test vectors** for X25519, HKDF-SHA512 and ChaCha20-Poly1305 | **`planned`** — the vectors that exist (`node_interop_vectors`) are cross-implementation agreement checks between this codebase's Rust and an independent `node:crypto` computation, which is a different and weaker guarantee than conformance to the RFCs |

Items 10 and 11 matter more than their size suggests: they are what would catch a *dependency*
changing behaviour under us, which the current tests, all of which compare this code to itself,
structurally cannot.

---

## 9. Residual weaknesses — stated, not hidden

Rewritten this pass. Two entries in the previous version described a Node.js implementation
that no longer exists and had to be replaced rather than edited.

| # | Weakness | Severity | Mitigation | Owner / trigger |
|---|---|---|---|---|
| R-1 | Key material can still be paged to disk or captured in a core dump; Rust zeroises but does not lock pages | Medium | `SecretBox`/`Zeroize` everywhere; hot set zeroised in place on lock; short auto-lock | Open — `mlock`-equivalent page pinning and core-dump suppression are unimplemented |
| R-2 | ~~scrypt rather than Argon2id~~ — **RESOLVED.** The built passphrase KDF is Argon2id at m=256 MiB, t=3, p=4 | — | `crates/keystore/src/software.rs::argon2_params` and `crates/keystore/src/backup_passphrase.rs::argon2_params` — two independent functions with identical literals, not one shared policy (§1) | Closed 2026-08-18 by source verification |
| R-3 | Broker memory compromise yields every unlocked node key — and, on a live unlocked vault, RK (§6) | **High if it happens** | Hot set only; the passphrase is never resident; RK and the hot set are zeroised on lock; short auto-lock; `PT_DENY_ATTACH` in the native shell is `planned`. *(This cell said "RK never resident" until 2026-09-24, ADR-063.)* | Accepted — inherent to any always-on agent |
| R-4 | Registry metadata (names, shape, counts) is plaintext | Medium | HMAC prevents tampering; contents leak no values; `ADR-029` adds a per-node name opt-out | Accepted, with the opt-out designed |
| R-5 | Hand-rolled sealed-box construction rather than a reviewed HPKE library | Medium | Follows the RFC 9180 DHKEM(X25519, HKDF-SHA512) shape; cross-implementation vectors pinned. **The pinned vectors are not RFC vectors** (§8 item 11) | Open — adopting an audited HPKE crate is blocked on the same MSRV wall as `ADR-036` |
| R-6 | Soft grants are void if the broker is compromised | **High if it happens** | Same blast radius as R-3; grants are logged, expiring and instantly revocable | Accepted, documented in §4 |
| R-7 | ~~**No root wrap is ever written to disk**, so there is no vault to attack yet — and no vault to use~~ — **RESOLVED.** `credmgr init` writes the passphrase and recovery-code root wraps | — | `vault.init_begin`/`vault.init_confirm` (§2.3), round-tripped over real on-disk files by `crates/brokerd/tests/vault_init.rs` | Closed 2026-08-31 by ADR-061. The hardware wrap is still never written — that remainder is R-8, not this row |
| R-8 | The only keystore tier is `Software`; no hardware backing exists on any platform | **High for the shipped product** | `Capabilities` reports `hardware_backed: false` honestly, so nothing can overstate it | `ADR-041` — Phase 5, all three platform implementations behind the same trait |
| R-9 | Sealed data past the 7-day window is recoverable with the cold key by no shipped path — in practice unrecoverable, including by the operator | **High** | The 7-day archive path is built and covers the realistic case; the cold key exists (ADR-079), so the data is not lost, only unreachable | §5.2 — the unseal operation (presence-gated) is unimplemented |
| R-10 | A sealed node's private key is not actually destroyed at day 7, because nothing calls the purge | Medium | Restore past the window is refused, so the key grants no in-product access; the destruction routine itself is written and tested | §5.1 — needs the daily maintenance pass `ADR-039` defers |

`05 §7`'s accepted-risk register AR-1…AR-6 and `PHASE8_AUDIT_REPORT.md`'s K-1…K-8 are the
authoritative lists for the system as a whole; this table is the cryptography layer's own view
and does not supersede either.

---

## 10. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `02_ARCHITECTURE.md §1` | the single-enforcement-point property that makes §4's soft grants sound rather than optimistic |
| depends on | `03_DATA_MODEL.md §7` | the CMV2 byte layout this document's §3.1 derivation fills |
| feeds | `06_ACCESS_GRAPH.md §1` | the per-node keypair that makes a denial cryptographic rather than advisory, and R0's orphan rule |
| feeds | `07_TWO_FACTOR.md §3` | the ordering the gate depends on — RK first, gate second, node keys third |
| feeds | `05_THREAT_MODEL.md §7` | the residual weaknesses §9 names, which the accepted-risk register bounds |
| feeds | `13_TEST_PLAN.md §5` | the crypto-conformance claims §8 enumerates, including the two that are unbuilt |
| depends on | `16_CROSS_PLATFORM.md §4` | the four `PlatformKeystore` implementations, of which one exists |
| feeds | `22_ORG_VAULT_SYNC_AND_LICENSING.md §4` | the fact that §1.1 establishes: an optional signed licence certificate needs a signature primitive this layer does not provide |
| feeds | `21_RELEASE_AND_INTEGRITY.md §2` | the same fact, from the other side: artefact signing is a platform mechanism, not a vault primitive |
| depends on | `14_DECISIONS.md` | `ADR-002` (per-node asymmetric keys), `ADR-003` (soft grants), `ADR-024`/`ADR-039` (external freshness counter), `ADR-027` (restore is a move), `ADR-036` (MSRV-driven crypto pins), `ADR-037` (AAD binds asserted context), `ADR-041` (Software tier only), `ADR-045` (recovery-code wrap), `ADR-054` (backup), `ADR-063` (the live unlock; RK resident while unlocked), `ADR-064` (the gate-secret seal; the last door's use of the recovery wrap) |

## 11. Source

**Design.** `ADR-002`, `ADR-003`, `ADR-024`, `ADR-027`, `ADR-036`, `ADR-037`, `ADR-039`,
`ADR-041`, `ADR-045`, `ADR-050`, `ADR-051`, `ADR-053`, `ADR-054`, `ADR-063`, `ADR-064`, and
`ADR-059` for the status vocabulary every heading in this document uses.

**Code.** `crates/core/src/keys.rs` (subkey derivation, node keypairs, node-key wrapping,
`seal_under_root`/`open_under_root`),
`crates/core/src/envelope.rs` (the CMV2 sealed box, its AAD, and the two payload kinds), `crates/core/src/cold.rs`
(the orphan cold key, ADR-079), `crates/core/src/fields.rs` (the version-2 payload), `crates/core/src/recovery.rs`
(the 256-bit recovery code and its root wrap), `crates/core/src/signing.rs` (HMAC-SHA256 — a
MAC, not a signature; §1.1), `crates/keystore/src/lib.rs` (the `PlatformKeystore` trait and the
`KeystoreId` variants that have no implementation), `crates/keystore/src/software.rs` (Argon2id
parameters), `crates/keystore/src/backup_passphrase.rs`, `crates/store/src/registry_file.rs`,
`crates/store/src/manifest.rs`, `crates/store/src/generation.rs`, `crates/store/src/audit.rs`,
`crates/store/src/archive.rs`, `crates/store/src/backup.rs`, `crates/store/src/paths.rs`,
`crates/brokerd/src/state.rs` (unlock, the hot key set, the resident `session_root`,
`reauth_root_key`, `lock`), `crates/brokerd/src/state/durable.rs` (`unlock_with_passphrase`,
load-and-verify, write-through, `gate_recover`),
`crates/brokerd/src/state/seal.rs` (the seal and restore commit protocols), `crates/brokerd/src/ops.rs`
(`node.seal`, `maintenance.backup`), and `scripts/emergency-decrypt.mjs`.

**Tests.** `crates/core/tests/properties.rs` (P-1…P-5), `crates/core/src/envelope.rs`'s
`node_interop_vectors`, `crates/brokerd/tests/isolation.rs`
(`after_lock_every_hot_set_buffer_is_all_zero`, `i15`, `i18`, `i21`, `i21b`),
`crates/brokerd/tests/phase5_gate.rs` (`item3`), `crates/brokerd/tests/durable_vault.rs` (§2.3's
live unlock, §6's lock, and the last door), `crates/keystore/src/software.rs`'s own unit tests,
`crates/cli/tests/emergency_decrypt.rs`, and — ADR-078/079 — `crates/core/tests/field_doc.rs` (P-13…P-18),
`crates/brokerd/tests/seal_durable.rs` and `rotate_root.rs`'s cold-key tests. `cargo test --workspace -- --list`:
813 tests in 50 test binaries (2026-10-03); the last full run recorded: 571 passing, 0 failing, 41 test binaries, exit 0 (2026-10-02; earlier: 448 passing, 37 test binaries on 2026-09-24, re-measured 2026-10-01; 406 passing, 35
test binaries as of 2026-09-13, run `34743281942`; 397 passing, 33 test binaries, verified
2026-08-18).

**Absence, verified.** `grep -rni 'ed25519|eddsa' v2/crates/` and the same search over
`Cargo.lock` both return zero matches (2026-08-18). `grep -rn 'orphan_key' v2/crates/` returned
only its definition in `paths.rs` and that definition's own test on 2026-08-18; since ADR-079 it has readers
and writers (`crates/core/src/cold.rs`, `crates/brokerd/src/state/seal.rs`, the backup). `grep -rn
'root_wrap_se|root_wrap_pass|root_wrap_recovery' v2/crates/` returns eight lines: the three path
definitions in `paths.rs`, `backup.rs`'s selection list (the `for f in [paths.root_wrap_pass(),
paths.root_wrap_recovery()]` candidate check), and **two independent test fixtures** —
`backup.rs`'s own test module, which writes all three wraps to exercise that selection list, and
`crates/cli/tests/emergency_decrypt.rs`, which writes `root_wrap_recovery()` to build a fixture
vault. No writer outside a test exists in either case. **That third grep is a 2026-08-18
measurement and no longer holds:** ADR-061 added the first non-test writer on 2026-08-31 —
`vault.init_confirm` writes `root.wrap.pass` and `root.wrap.recovery` (§2.3). The first
absence remains the evidence behind §1.1; the second is now the record of what §5.2 closed (ADR-079), the
third of what §2.3 closed, and each is a one-command re-check.

**Figures.** `key-hierarchy-built-vs-planned` (§2.3, `docgen` `kind: "flowchart"`) and
`seal-to-orphan-timeline` (§5.2, `docgen` `kind: "state"`) are both built, per
`tools/ENGINE_ROUTING_POLICY.md`'s directive-plus-sidecar mechanism. Both figures' node/edge
built-vs-planned marking was re-derived from the same absences this section cites — a live
`grep` for a writer of `root_wrap_pass`/`root_wrap_recovery`/`node_key`/`orphan_key` outside a
test, and for `purge_if_expired`'s callers — not asserted by hand. Spec:
`v2/docs/04_CRYPTO_AND_KEYS_spec.json` (a two-element array, one object per figure).
