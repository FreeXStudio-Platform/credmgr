---
id: V2-016
classification: public
title: Cross-platform architecture
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21), then corrected again the same day against the S21 verification
     backlog. The previous stamp (Approved With Known Risks @ 6ee1e5f) attested a body that had
     been contradicted by source in three places the rewrite corrected: the document claimed
     secrets are `mlock`ed (no `mlock` call exists anywhere in `crates/`), listed a `keyring`
     crate that is in no manifest, and described the macOS Secure Enclave path as merely
     "unchanged from Pass 2, now behind the trait" when no hardware keystore has ever been
     implemented on any platform. This backlog-closing pass fixed four further defects a verifier
     found in that rewrite: two present-tense misstatements of cwd's role (§5.2, §5.3 — cwd is the
     scope authority `resolve_scope` step 2 uses on the tokenless agent path, not a mere audit
     signal, and losing it on Windows is a real narrowing of capability, not a formality); a §12
     Source citation of a `12_BUILD_PLAN.md` sentence that had been dropped from that document
     during the same rewrite; and an incomplete list, in §3, of the ops `verify_presence`'s
     unconditional refusal reaches (three named where five exist — `grant.create` and
     `maintenance.doctor --rebuild-registry` were missing). One convention violation was also
     fixed: the AR-10 row in §10 stated a planned Windows mechanism in the present tense. A second
     round of the same backlog (round 2, same day) found three more defects, now fixed: §3 said
     "no Security panel, because there is no application" — a real Tauri application exists
     (ADR-057, commit b23a5ae) with an 8-command bridge, so the accurate claim is that no UI
     screens exist, not that no application does; §9 (and, propagating from it, the §12 Source
     list) attributed the pre-Tauri native-shell decision to ADR-022, which is actually the
     frontend-framework decision (Svelte 5, no Tailwind, vendored graph engine) and never mentions
     Swift or WKWebView — the shell decision is ADR-025 ("the native shell serves the UI via
     `WKURLSchemeHandler`"); and three citations of
     `13_TEST_PLAN.md §1` (§10's AR-9 row and its Resolution-path cell, and §11's Connections row)
     named the wrong section — the AR-9 discussion is under that document's §2 ("Layers"), not §1.
     Every claim below was re-derived from live source in this pass. The corpus-wide hardening
     status is the operator's to assign after their own review. Updated 2026-09-24 for
     ADR-062…066 (the bridge at 42 ops, the real CSP, the Software tier as the live unlock's
     keystore, the release tarball's launchd unit). Updated 2026-09-24 for ADR-071…073 (the
     bridge at 47 ops; `node.policy`'s conditional presence refusal, §3). Updated 2026-10-03 for ADR-076, ADR-078 and ADR-079 (the bridge at
     53 ops and wired end to end, the MCP server at 15 tools, the Software-tier disclosure of §3, the release tooling's Apple-Silicon
     target, the test counts). -->
# Cross-platform architecture

`CredMgr V2` · what actually runs on macOS, Windows and Linux — and the complete design for the two platforms that have never executed a line of this code · `2026-08-18`

> **Status.** The **portable half is built**: one Rust workspace of six crates, a
> `PlatformKeystore` trait, and per-OS path resolution that resolves correctly on all three
> targets (`crates/store/src/paths.rs`). The **platform-specific half is almost entirely
> unbuilt.** There is exactly one keystore implementation — `SoftwareKeystore`, Argon2id over a
> passphrase — and **no hardware backend on any platform**, macOS included: `MacosSecureEnclave`,
> `WindowsHello`, `WindowsDpapi`, `LinuxTpm` and `LinuxSecretService` are enum variants with
> nothing behind them (`crates/keystore/src/lib.rs`; `grep -rn "impl PlatformKeystore" v2/crates/`
> returns `software.rs` and nothing else). The transport is Unix-only — `crates/brokerd`'s `peer`
> and `server` modules are both `#[cfg(unix)]`, so on Windows the broker has no listener at all.
> Nothing in this repository has ever been built or tested on Windows or Linux: the `v2 build`
> workflow that declares the three-OS matrix is `workflow_dispatch`-only and has **zero runs**
> (`gh run list --workflow=build.yml` returns an empty list, checked 2026-08-18). Everything
> marked `planned` below is the full target design and is written in the future tense throughout.

---

## 1. What this document is for

Passes 1 and 2 designed a macOS product and never said so. Secure Enclave, `LAContext`,
`WKWebView`, `LOCAL_PEERCRED`, an application-support vault directory, a Swift shell — every
security-critical mechanism was Apple-only, and the documents read as though that were universal.

That is not a portability inconvenience. **The entire key hierarchy rested on one vendor's
hardware**, so "Linux support" would have meant "a different, weaker product wearing the same
name". Fixing it properly changed the stack, and this document is the record of that change plus
the specification each platform must be built to.

It has since acquired a second job, which is the reason for this rewrite. The document went on to
describe the macOS path as finished, and the corpus believed it: a reader who wanted to know
whether a stolen laptop's vault was protected by hardware would have concluded yes on macOS.
It is not, on any platform. §4 states what exists and what does not, per platform, with the file
that proves each answer.

**A note on how to read the tiers.** The tier vocabulary in this document describes *what protects
the root key at rest*. It says nothing about whether the ciphertext is sound — envelope encryption
(`04_CRYPTO_AND_KEYS.md §3`) is identical on every platform and is `built` everywhere. A
`Tier::Software` vault is a real vault whose root key is guarded by Argon2id instead of by
silicon. That is a meaningful difference and a bounded one, and the product is required to say
which it has rather than showing every user the same padlock.

---

## 2. The stack — **`built`**

| Layer | Was (Pass 1–2) | Now | Status | Why |
|---|---|---|---|---|
| Core + broker | Node.js 22 | Rust 2021, MSRV 1.78 (`crates/` only, ADR-035) | **`built`** — 6 crates | Real `zeroize`, no GC copies, no runtime, one static binary, identical on all three OSes |
| Desktop shell | Swift + WKWebView | Tauri 2 | **`partial`** — the precompiled design (ADR-075) over a bridge reaching all 53 broker ops (ADR-057, ADR-062, ADR-078) and wired end to end, a real CSP, a concealed clipboard and lock-on-sleep; built ad-hoc sealed by `scripts/release-app.sh` (Apple Silicon only) | System webview on every OS, IPC allowlist, signing and notarisation support, built-in updater |
| UI | Svelte 5 + Vite + TS | the KEEP design precompiled to React 19 + Vite 8 + TS (ADR-075) | **`built`** — hosted and wired: every screen reads from the broker and every change goes to it, no demo data in a release build; the real-app pass (`RELEASE_VERIFICATION.md`) is a human checklist not yet signed off | Already portable; a webview app (`19_FRONTEND_DELIVERY_SCOPE.md §1`) |
| Graph | vendored `force-graph` | unchanged | **`planned`** | Canvas, portable |
| CLI | Node | Rust, single binary | **`built`** — 24 top-level subcommands | No Node runtime required to use the vault |
| MCP server | Node | Rust, same binary (`credmgr mcp`) | **`built`** — 15 tools | One artefact to sign, one to trust |

`crates/core` is I/O-free by construction, which is what keeps the access rules exhaustively
testable on a platform that has no vault on it at all.

### 2.1 Crate selection — **`built`**, and narrower than this document used to claim

Verified against the manifests, not from the design's wish list:

| Purpose | Crate | Where | Note |
|---|---|---|---|
| AEAD | `chacha20poly1305` 0.10 | `core`, `keystore` | RustCrypto |
| KEM | `x25519-dalek` 2 | `core`, `brokerd` | `static_secrets` + `zeroize` features |
| KDF | `hkdf` 0.12 + `sha2` 0.10 | `core` | |
| MAC | `hmac` 0.12 | `core` | registry and manifest signing |
| Password hash | `argon2` 0.5 | `keystore` | **Argon2id**, m=256 MiB t=3 p=4 |
| Memory hygiene | `zeroize` 1.7, `secrecy` 0.10 | every crate that holds a secret | |
| TOTP | `totp-rs` 5.7 | `core` | RFC 6238, `default-features = false` |
| IPC | `interprocess` 2 | `brokerd` | **declared and currently unused** — see §5 |
| Shell | `tauri` 2 | `apps/desktop/src-tauri` | separate workspace, ADR-035 |

Two entries the previous revision carried are **not** in any manifest and have been removed rather
than left to be believed: a `keyring` crate (no per-OS keystore dependency exists, because no
per-OS keystore exists), and the implication that `interprocess` is what carries the transport —
it is a declared dependency held for the Windows named pipe, and the Unix path is written directly
against `std::os::unix::net` so that raw peer-credential syscalls are unambiguous about which file
descriptor they interrogate.

**Every version above is a generation behind crates.io's latest, deliberately.** ADR-036 records
why: the current majors pull `block-buffer` and `zeroize_derive` releases whose manifests need
Cargo's `edition2024` feature, unavailable below Rust 1.85, and the security crates are pinned at
MSRV 1.78. Re-attempt the latest versions only when that pin moves.

### 2.2 Memory hygiene — **`partial`**, and one claim retracted

What is real: secrets live in `secrecy::SecretBox`, buffers are wiped on drop by `zeroize` rather
than by remembering to call a fill, and `x25519-dalek`'s `StaticSecret` zeroises transient per-use
copies. `crates/brokerd`'s hot node-key set is zeroised in place on `vault.lock`.

What is **not** real, and what the previous revision asserted: **nothing in this workspace calls
`mlock`.** `grep -rn "mlock" v2/crates/` returns nothing, and no crate declares a memory-locking
dependency. Pages this process holds may therefore be swapped to disk or captured in a hibernation
image, exactly as `05_THREAT_MODEL.md §7`'s AR-3 already states — that risk entry is accepted
permanently and describes user-space zeroisation only. Locking pages is `planned`, not built, and
it is worth naming the cost before someone adds it casually: `mlock` limits are per-process and
small by default on Linux, so the target design is to lock only the root-key and hot-node-key
buffers, to treat a failed lock as a logged degradation rather than a fatal error, and to say so
in the Security panel — never to lock silently and imply more than the OS granted.

---

## 3. The platform abstraction — **`built`**

One trait, in `crates/keystore/src/lib.rs`. Everything above it is platform-agnostic. The trait
deliberately never exposes the wrapping key itself — only wrap and unwrap operations — so a weak
platform cannot silently hand out something a strong one would not.

```rust
pub trait PlatformKeystore: Send + Sync {
    fn id(&self) -> KeystoreId;
    fn capabilities(&self) -> Capabilities;

    /// Wrap the root key. May prompt (biometric enrolment) on hardware tiers.
    fn wrap_root(&self, root: &SecretBox<[u8; 32]>) -> Result<WrappedKey>;

    /// Unwrap. MUST require user presence when `capabilities().user_presence`.
    fn unwrap_root(&self, wrapped: &WrappedKey, reason: &str) -> Result<SecretBox<[u8; 32]>>;

    /// A single presence check, for grants / orphan reveal / approval-on-demand.
    /// Returns `PresenceUnavailable` when `capabilities().user_presence` is false.
    fn verify_presence(&self, reason: &str) -> Result<PresenceProof>;

    /// Monotonic counter storage, OUTSIDE the vault directory.
    fn read_counter(&self, name: &str) -> Result<u64>;
    fn write_counter(&self, name: &str, value: u64) -> Result<()>;
}

pub struct Capabilities {
    pub hardware_backed: bool,   // key material cannot be exported
    pub user_presence: bool,     // biometric / PIN prompt available
    pub anti_hammering: bool,    // the platform rate-limits guesses
    pub survives_reboot: bool,
    pub tier: Tier,              // Hardware | OsProtected | Software
}
```

Three properties of this trait are load-bearing and are worth stating as design, not as API
documentation.

**`Capabilities` is a report, not a promise.** A caller asks what it got; it is never told what it
wanted. This is what makes an honest degradation expressible at all.

**`verify_presence` refuses rather than fakes.** `SoftwareKeystore` returns `PresenceUnavailable`
instead of succeeding, and that is correct rather than a gap: a caller that skips the capability
check and relies on presence for an orphan reveal or a grant must get a hard error, never a free
pass (`crates/keystore/src/software.rs::verify_presence_is_refused_not_faked`). The consequence
runs all the way up the stack — **five** op arms are capability-checked and then refused with
`PresenceRequired` unconditionally, because no surface in this build can attest presence:
`audit.get`'s full-record path (`ops.rs:939`), `totp.seed` (`:1172`), `node.reparent` (`:2460`),
`grant.create` (`:2570`), and `maintenance.doctor --rebuild-registry` (`:2763`). When a real
implementation lands, none of those dispatch arms change; only the hardcoded refusal is removed.
(Those line numbers predate 2026-09-24 and have since moved. Since then two more arms refuse after their other
checks: `node.policy` conditionally, for a patch that widens reach (ADR-071), and `maintenance.rotate_root` on the
wire, after the human, Admin and second-factor checks (ADR-076). Reading a sealed — Orphaned — entry has no
operation at all yet: ADR-079 built the cold key and the seal, and left the reveal behind presence.)
This is also why isolation test I-10 cannot be closed (`PHASE8_AUDIT_REPORT.md` accepted risk
K-1): its denial half is proven, and its positive half needs a transport that can set
`presence_attested: true`, which does not exist.

**What the Software tier protects, and what it does not — the release disclosure (K-5).** The wording is the product's
own statement of this tier; the canonical copy is `04_CRYPTO_AND_KEYS.md §2.4`, repeated in `README.md`, `RELEASE.md`,
`SECURITY.md` and `07_TWO_FACTOR.md §3`, and if it changes it changes in all of them.

- **Your passphrase is the key.** The vault's root key is stored in the vault folder encrypted two ways: under a key
  derived from your passphrase with Argon2id (256 MiB of memory, 3 passes, 4 lanes), and under the 256-bit recovery
  code printed at `credmgr init`. Nothing is held in the Mac's Secure Enclave and nothing is tied to this Mac: a copy
  of the vault folder can be attacked offline on any computer, slowed only by the Argon2id cost of each passphrase
  guess. Use a long, unique passphrase and keep the recovery code offline.
- **While the vault is unlocked,** `credmgrd` holds the root key and every unlocked project key in memory until it
  locks (idle timeout or `credmgr lock`; the desktop app also locks it when the Mac sleeps, the screen locks or the session switches, but a daemon running without the app does not). It does not lock its memory pages or block debuggers, so software
  able to read its memory — anything running as root, for example — can read those keys.
- **No Touch ID, no presence.** Reading a sealed (Orphaned) entry is refused with `node_access_denied` (rule R0: the
  sealed store opens only to a native caller with a live presence attestation, and none can give one yet); creating a
  grant, re-parenting a node and widening a node's sharing are refused with `presence_required`.
- **Two-factor guards the door, not the safe.** With two-factor on, `credmgrd` will not unlock your vault without a
  fresh code. That check is made by `credmgrd`, not by the encryption: anyone who has your passphrase or your recovery
  code *and* a copy of your vault folder can decrypt it without the second factor. Treat each of the passphrase and the
  recovery code as a complete key to your vault.
- **The binaries and the app are not code-signed or notarised;** check them against `SHA256SUMS`. Hardware-backed
  protection (Secure Enclave with Touch ID) is planned and is not part of this release.

On the Software tier the orphan cold key (`04_CRYPTO_AND_KEYS.md §5.2`, ADR-079) is wrapped under a key derived from the
root key, so "cold" is enforced by the broker — no operation unseals it and it is never resident — and not by
cryptography against a compromised broker; the hardware tier would rewrap it under a Secure Enclave key with a per-use
presence requirement.

**Counters live outside the vault directory**, so rolling the vault directory back to a snapshot
does not roll the anti-rollback counter back with it (`04_CRYPTO_AND_KEYS.md §6`, ADR-039).

**The UI will state the tier in plain words** — *"Protected by your passphrase only; no hardware
key store was found"*, not a lock icon that implies more than is true. That sentence is `planned`
in the strict sense: a Tauri application already exists, hosts the design (ADR-075) and its command
bridge already reaches `vault.status` (§2, ADR-057), but **no Security panel reads a tier**: the
Security settings are wired to the broker (the second factor, locks and backups), yet nothing reports a tier to the window yet
(`keystore_status()` is `planned`, `02_ARCHITECTURE.md §6.2`; `09_UI_UX_SPEC.md §2`). The gap is "no
tier report", not "no application"; conflating the two is exactly the stale-claim pattern this
document exists to eliminate. Overstating protection is the
failure mode this whole project exists to avoid, so the requirement is recorded here and gated in
`12_BUILD_PLAN.md`'s Phase 5 exit criteria rather than left to whoever builds the screen.

---

## 4. The keystore implementations

Four are specified. **One exists.**

### 4.1 Universal software tier — **`built`**

`SoftwareKeystore` (`crates/keystore/src/software.rs`), the escrow wrap that is present on every
platform unconditionally, because a vault whose only key is in hardware is one dead motherboard
away from gone (`04_CRYPTO_AND_KEYS.md §2`).

One primitive backs both of its jobs. Derive a 32-byte key from the operator passphrase with a
freshly generated 16-byte salt via **Argon2id (m=256 MiB, t=3, p=4)**, then seal the payload with
ChaCha20-Poly1305 under that key, storing `salt ‖ nonce ‖ ciphertext‖tag`. Root-key wrapping and
counter sealing use the identical construction, so there is one thing to review rather than two.
Tampering with either the payload or its salt fails the same AEAD tag check — there is deliberately
nothing to distinguish "wrong passphrase" from "corrupted blob".

It reports `Tier::Software`, `hardware_backed: false`, `user_presence: false`,
`anti_hammering: false`, `survives_reboot: true`. Twelve unit tests cover it, including
`wrap_unwrap_round_trips`, `wrong_passphrase_fails_authentication`, `wrapping_is_nondeterministic`,
`capabilities_are_honest_about_the_software_tier`, `tampered_counter_file_is_refused`,
`wrong_passphrase_cannot_read_the_counter`, and
`counter_persists_across_a_fresh_instance_over_the_same_state_dir`.

ADR-041 records why this tier was built first and alone: it is the only one with no hardware and
no interactive dependency, and it is not a placeholder for the other three — it is a permanent
part of the design that the other three sit on top of. Since 2026-09-24 it is also what the live
daemon unlocks with: `vault.unlock {passphrase}` builds a request-scoped `SoftwareKeystore` from the
caller's passphrase, proves it against `keys/root.wrap.pass`, and then drops it, keeping the root
key resident until lock (ADR-063; `04_CRYPTO_AND_KEYS.md §6`).

### 4.2 macOS — **`planned`** · target `Tier::Hardware`

Nothing of this exists. `grep -rn "SecureEnclave\|LocalAuthentication\|kSecAttr\|security-framework"
v2/crates/` returns the `MacosSecureEnclave` enum variant and nothing else. **The macOS *vault
path* is built; the macOS *keystore* is not**, and the two have been conflated in this corpus
before.

The target design, in full:

- A **P-256 keypair generated inside the Secure Enclave** (`kSecAttrTokenIDSecureEnclave`), access
  control `biometryCurrentSet | privateKeyUsage`, will wrap the vault root key. The private half
  will be non-exportable by construction, so a stolen disk image will not contain it.
- **Presence will be `LocalAuthentication`.** `verify_presence` will return a `PresenceProof` only
  after a real Touch ID or watch-unlock prompt completes; a cancelled prompt will be an error, never
  a silent success.
- **Counters will be a Keychain generic password item**, outside the vault directory, so the
  anti-rollback anchor is not restorable from a vault backup.
- **`biometryCurrentSet` will invalidate the key when a fingerprint is enrolled or removed.** That
  is the desired behaviour and precisely why the §4.1 passphrase wrap is mandatory alongside it: the
  hardware wrap is an access-control convenience layered over an escrow that always works.

What closing this needs, named so nobody re-derives it: an **interactive** session where a human can
complete a real biometric prompt, or a deliberately designed and separately justified test seam that
exercises the real Security-framework calls for everything except the prompt itself (ADR-046). Code
written without ever completing a real prompt is exactly the artifact `12_BUILD_PLAN.md`'s own rule
forbids.

### 4.3 Windows — **`planned`** · target `Tier::Hardware` (Hello) or `OsProtected` (DPAPI)

Nothing of this exists, and the gap is wider than the keystore: see §5, where Windows has no
transport either.

The target design, in full:

- **Preferred:** Windows Hello via `KeyCredentialManager` — a TPM-backed key behind a biometric or
  PIN gate. `verify_presence` will map to `RequestSignAsync`, so presence will be a real
  cryptographic operation the TPM performs, not a boolean the process decides.
- **Fallback:** CNG/NCrypt against the Platform Crypto Provider (TPM 2.0) for the root wrap, with
  DPAPI (`CryptProtectData`, `CRYPTPROTECT_LOCAL_MACHINE` **off**, so the blob is bound to the user
  and not to the machine) for counters. This tier will report `OsProtected`, not `Hardware`, because
  DPAPI protects against another user rather than against someone holding the disk.
- **Neither tier will be selected silently.** Whichever is obtained will be reported through
  `Capabilities`, and the escrow passphrase wrap will still be written.

`crates/store` will additionally need a Windows answer for file permissions: it asserts `0700`
directories and `0600` files under `#[cfg(unix)]` only, and the equivalent ACL story is unwritten.

### 4.4 Linux — **`planned`** · target `Tier::Hardware` (TPM) / `OsProtected` (Secret Service) / `Software`

Nothing of this exists. Linux is the platform where the design must probe rather than assume,
because the same distribution will present three different security postures on three different
machines.

The target design is a probe **in this order**, with the result reported and never assumed:

1. **TPM 2.0 via `tpm2-tss`.** Seal the root wrap to the TPM under a PCR policy. Presence will fall back to the
   passphrase, since no biometric standard exists to rely on. An optional **FIDO2 token**
   (`libfido2`) will supply genuine presence via a physical touch, and the UI will recommend one
   when a token is detected — this is the only route to `user_presence: true` on Linux.
2. **Secret Service via D-Bus** (`libsecret`: GNOME Keyring or KWallet) → `OsProtected`. This tier
   will protect against another local user and against a casually copied home directory, and not
   against someone holding the disk with the login keyring unlocked.
3. **Software** → §4.1, unchanged.

Counters will be a TPM NV index where one is available. Where none is, they will fall back to the
`0600` HMAC-tagged file under the per-user state directory that `crates/store`'s
`FileGenerationCounter` already implements (ADR-039) — the weakest case, and the UI will say so.
Socket and peer identity are covered in §5.

### 4.5 Selection, probing and honest reporting — **`planned`**

Today the keystore is fixed at broker start: `BrokerState::new` takes a `Box<dyn PlatformKeystore>`
and the only constructible implementation is `SoftwareKeystore`. There is no probe, no ranking, no
fallback chain, because there is nothing to fall back from.

The finished mechanism will be a single ordered probe run once at first unlock, not per operation:

1. Attempt each platform tier in descending order for the running OS (§4.2–§4.4).
2. Take the **first that both constructs and completes a wrap/unwrap self-test.** A backend that
   constructs but cannot round-trip is a failed backend, not a degraded one — this is the check that
   prevents "compiles for Windows, has never unlocked on Windows" from passing as implemented.
3. Record the achieved `Capabilities` in the vault's config so the tier is stable across restarts,
   and re-probe only on explicit user action, so a transient D-Bus failure does not silently and
   permanently downgrade a vault.
4. **Always** write the §4.1 escrow wrap in addition to whatever hardware wrap succeeded.
5. Surface the achieved tier, in words, in the Security panel — and surface a *downgrade* as an
   event the user must acknowledge, because a tier that silently degrades converts a real guarantee
   into a believed one (`05_THREAT_MODEL.md §9`).

Six layers, by platform, read straight from the `#[cfg(...)]` gates rather than transcribed from
the prose above — a transcribed grid is exactly how the macOS keystore previously came to be
described as finished. Note where this figure sharpens the "macOS alone" framing from the rest of
this document: the hardware-keystore row is `planned` on **all three** platforms, macOS included —
there is no platform where a hardware backend exists, so "one platform runs it" does not hold for
that layer specifically, only for transport/peer-identity.

<!-- figure:platform-surface-built-vs-planned -->

This document warrants one figure and no more. The key hierarchy already has its own
(`04_CRYPTO_AND_KEYS.md §2`), and a second diagram of the same wrap/unwrap flow from a
platform angle would restate it without adding a fact.

---

## 5. Transport and peer identity — **`partial`**

The broker is the single enforcement point, so how a client reaches it — and how the broker knows
who the client is — is a security mechanism, not plumbing.

### 5.1 Unix domain socket — **`built`**

`crates/brokerd/src/server.rs` binds a `UnixListener` at `<vault>/run/broker.sock` and chmods it
`0600` immediately after bind. The run directory is `0700`, like every directory the vault owns
(`crates/store/src/atomic.rs::dir_and_file_modes_are_owner_only`). **There is no listening TCP
socket anywhere in `crates/`** — no `TcpListener`, no `TcpStream`, no HTTP client crate. That makes
ADR-019 (no HTTP surface) and `17_AIRLOCK_AND_LLM.md`'s rule A-1 (no outbound network) properties
of the code rather than promises about it.

### 5.2 Peer identity — **`built`** on macOS **and now verified on Linux** (2026-08-29)

Every connection is identified before a byte of the request is parsed, and a connection that cannot
be identified is closed silently with no error frame.

- **macOS:** `getsockopt(LOCAL_PEERCRED)` → uid, `getsockopt(LOCAL_PEERPID)` → pid, then
  `proc_pidinfo(PROC_PIDVNODEPATHINFO)` → the peer's working directory. Exercised on every test run.
- **Linux:** `getsockopt(SO_PEERCRED)` returns uid, gid and pid in one call, with the working
  directory read from the per-process `cwd` symlink. **Corrected 2026-08-29 — this used to say "it
  has never been executed," true until this date.** `cargo test --workspace` ran clean (397/397)
  on a self-hosted Linux runner, including
  `crates/cli/tests/broker_integration.rs`, which drives a real `server::run` over a real Unix
  socket rather than a hand-constructed `PeerInfo` — the first real exercise of this code path on
  Linux.

The uid check is the hard gate: anything that is not the owning uid is rejected
(`server.rs::peer_uid_gate_rejects_any_non_owning_uid`). The working directory is **not** merely a
convenience or an audit signal: when no session token is presented, it **is** the scope authority.
`resolve_scope` step 2 matches the peer's cwd against the registry's `workdirs[]` entries and, on a
hit, returns a `BrokerScope` whose `node_id` is that node and whose `capabilities` come from
`capabilities_for_agent_access(node.policy.agent_access)` (`crates/brokerd/src/scope.rs:122-141`).
A `chdir` into a registered project directory therefore changes what an unauthenticated agent may
read — a boundary, not a convenience. A presented token overrides cwd entirely, and a token/cwd
disagreement is logged as an anomaly rather than blocking the request (I-12). This is accepted risk
AR-5 in `05_THREAT_MODEL.md §7`, whose own wording is the framing this document now matches: "the
bound is narrower than previously stated — when *no* token is presented, cwd is not merely an audit
signal, it is the authority."

### 5.3 Windows named pipe — **`planned`**

Windows has no transport. `crates/brokerd/src/lib.rs` gates both `peer` and `server` behind
`#[cfg(unix)]`, so a Windows build of `credmgrd` compiles with no listener in it.

The target design, in full:

- A named pipe at `\\.\pipe\credmgr-<sid-hash>`, created with a **DACL granting only the current
  user's SID** and inheriting nothing.
- Peer identity by `GetNamedPipeClientProcessId` → `OpenProcess` → token SID comparison, **rejecting
  any SID that is not the owner's**. This is the exact analogue of the `LOCAL_PEERCRED` uid gate and
  must be enforced in code, not merely expressed in the DACL — a DACL is a configuration and the
  check is an invariant.
- The `interprocess` crate is already a declared dependency of `credmgr-brokerd` for precisely this,
  and is currently unused.
- The peer's working directory has no cheap Windows equivalent, so the target design will treat
  cwd resolution as unavailable there. **This is a real narrowing, not a formality** — on the
  platforms where cwd resolves, an untokened agent connection landing inside a registered
  `workdirs[]` entry gets that node's `agentAccess` capabilities (`resolve_scope` step 2, §5.2);
  cwd is a genuine authority there today. Without a Windows equivalent, the tokenless agent path
  on Windows will always fall through to `resolve_scope` step 3 instead — global scope, `List`
  only — which is a smaller capability set than the same unauthenticated connection gets on macOS
  or Linux. The mitigation the design leans on is session tokens (ADR-056), which the CLI and the
  desktop bridge both hold and which will carry a Windows client's real scope in place of cwd.

Any statement elsewhere in this corpus that V2 "runs on Windows" describes this section's target,
not the code.

---

## 6. Paths — **`built`**

The resolution order below is the code's, read from `crates/store/src/paths.rs::default_vault_dir`,
not the design's intent.

**Vault directory**, first match wins:

1. `CREDMGR_VAULT_DIR`, if set — overrides everything, on every platform.
2. macOS: `~/Library/Application Support/credmgr`.
3. Windows: `%APPDATA%\credmgr`, falling back to the user profile directory when `%APPDATA%` is
   unset.
4. Everything else: `$XDG_DATA_HOME/credmgr`, falling back to `~/.local/share/credmgr`.

**The socket is always `<vault>/run/broker.sock`.** There is no socket-specific override, by
design — one variable moves an entire vault, socket included, which is what lets a test point at a
throwaway directory without a second knob.

**State directory** — the generation counter and the keystore's counters, deliberately *outside* the
vault so a vault rollback does not roll the anti-rollback anchor back with it (ADR-039). Same
shape: `CREDMGR_STATE_DIR` overrides; else `~/Library/Application Support/credmgr-state` on macOS,
`%LOCALAPPDATA%\credmgr\state` on Windows, `$XDG_STATE_HOME/credmgr` or `~/.local/state/credmgr`
elsewhere. `paths.rs::vault_and_state_dirs_never_coincide` asserts the two can never resolve to the
same place; `crates/keystore` puts its own counters in a `keystore/` subdirectory beneath the state
root so the two crates' files cannot collide even if both roots are overridden to one path.

**Never inside a repository, on any platform.** This is not a stylistic rule — it is a live bug the
V1 package had, where the vault defaulted to the checkout root and `credmgr init` wrote a master key
into a git working tree. Found and fixed in V1 first (`v1/CHANGELOG.md` 1.9.0), and structurally
prevented here by resolving from the OS's own per-user location rather than from the process's
working directory.

**The rule is duplicated once, and the duplication is pinned.** The desktop shell lives in a
separate Cargo workspace and cannot link `credmgr-store` without dragging the security crates off
their MSRV pin (ADR-035), so `apps/desktop/src-tauri/src/vault_paths.rs` re-implements the branch
table. It is held honest by `tests/drift_guards.rs`, which reads `crates/store/src/paths.rs` **off
disk** and asserts the original still mentions every branch the copy mirrors, plus
`the_socket_path_rule_still_matches_crates_store`. A test that compared the copy against itself
would pass on both sides of any divergence.

**Which of these branches has actually executed.** The desktop copy has a unit test per platform,
and they are `cfg`-gated to the platform they describe: `macos_uses_application_support_and_ignores_xdg`
runs here, while `unix_prefers_xdg_then_falls_back_to_dot_local_share` and
`windows_prefers_appdata_then_falls_back_to_the_profile` are compiled out on a macOS host and have
therefore never run. The platform-independent assertions do run everywhere:
`the_override_wins_over_every_platform_default`, `the_socket_always_hangs_off_the_vault_root`,
`no_home_and_no_override_resolves_to_nothing_rather_than_a_wrong_path` — the last of which exists
because the dangerous failure is not an error, it is silently returning a relative path and
connecting to whatever happens to be at the process's working directory.

### 6.1 Paths that do not exist yet — **`planned`**

| | macOS | Windows | Linux |
|---|---|---|---|
| Logs | `~/Library/Logs/credmgr` | `%LOCALAPPDATA%\credmgr\logs` | `$XDG_STATE_HOME/credmgr/logs` |
| Autostart | `launchd` LaunchAgent | Task Scheduler, at logon | systemd user unit |

`paths.rs` defines no log directory, and the broker writes no log file. Do not mistake the audit
log for one: that is vault data, hash-chained and built, with a twelve-month retention that
`03_DATA_MODEL.md §9` specifies and nothing implements. A **diagnostic** log is a separate,
unbuilt thing, and when it lands it must be designed on the assumption that users will paste it
into a bug report — no entry names, no node names, no values.

Autostart is one file short of existing on macOS. `crates/brokerd/packaging/com.credmgr.brokerd.plist`
is a written and reviewed launchd user agent, and since 2026-09-24 the release tarball ships a copy
as `packaging/com.credmgr.brokerd.plist` with `v2/RELEASE.md` telling the operator to copy it into
`~/Library/LaunchAgents/` by hand; **nothing installs it** — and the reason is packaging, not
bootstrap. A vault *can* be created: `credmgr init`, and a `credmgrd` whose `main` actually
calls `server::run` and serves the socket, both landed with ADR-061 on 2026-08-31. What is still
`planned` is any code path that writes a LaunchAgent to disk. The Windows and Linux equivalents are
not written. All three will be installed by the application at first run, never by a package
postinstall script running as root: a per-user vault daemon that a system installer registers is a
privilege boundary nobody asked for.

---

## 7. What each platform will cost the user

Stated as the target, and required to be shown in the app's Security panel. **Every "will" below is
a specification; today every column reduces to the final one**, because §4.1 is the only
implementation that exists.

| | macOS | Windows | Linux + TPM | Linux, no TPM | **Today, all platforms** |
|---|---|---|---|---|---|
| Root key non-exportable | Secure Enclave | TPM via Hello | TPM | ✗ | ✗ |
| Presence prompt | Touch ID | Hello | FIDO2 touch (optional) | ✗ passphrase | ✗ refused, not faked |
| Hardware anti-hammering | ✓ | ✓ | ✓ | ✗ Argon2id only | ✗ Argon2id only |
| Monotonic counter anchor | Keychain item | TPM NV | TPM NV | signed file | signed file |
| **Achieved tier** | **Hardware** | **Hardware** | **Hardware** | **Software** | **Software** |

A Software-tier vault is still meaningfully protected — Argon2id at 256 MiB, t=3, p=4 makes offline
guessing expensive, and every value at rest is sealed to a node's X25519 key regardless of tier. But
it is not equivalent, and the difference is exactly what an attacker holding the disk image gets to
attack: a passphrase, rather than a key they cannot extract. The product is required to state
which of the two it achieved, and §4.5 is the mechanism that will let it.

---

## 8. Build, sign, distribute — **`partial`**

### 8.1 The toolchain split — **`built`**

`crates/` is pinned to Rust **1.78** and `apps/desktop/src-tauri` to current stable, in two separate
Cargo workspaces with two lockfiles. This is not untidiness: Tauri 2 pulls `idna_adapter` via `url`,
whose manifest requires Cargo's `edition2024` feature, unavailable below 1.85. The security crates
keep the old pin because they ship as long-lived signed binaries where reproducibility matters most;
the desktop shell already tracks a fast-moving GUI toolkit and gains nothing from an artificially old
compiler. **Do not merge the two workspaces without re-solving this** (ADR-035).

### 8.2 The CI matrix — declared, and **never run**

`.github/workflows/build.yml` declares `{macos-14, windows-latest, ubuntu-22.04} × {1.78.0, stable}`
for the crates workspace and the three OSes for the desktop app. It is `workflow_dispatch`-only, per
the portfolio CI policy that build jobs never trigger on a git event while security jobs run freely.

**It has zero runs.** `gh run list --workflow=build.yml` returns an empty list (2026-08-18). Under
that same policy's rule that a gate which has never run has not passed, the three-OS matrix is a
declaration, not evidence — and it is the single cheapest thing anyone could do to convert most of
this document's "compiles but never executed" claims into either a green result or a real bug.
Security jobs, by contrast, do run: the isolation suite, `cargo deny`, `cargo audit`, Semgrep and
both secret guards execute on every push to `main`, on every pull request, and on a weekly
schedule floor (`.github/workflows/security.yml`).

### 8.3 Packaging and signing — **`planned`**

| | macOS | Windows | Linux |
|---|---|---|---|
| Artefact | `.dmg`, universal2 | `.msi` + portable `.exe` | `.AppImage`, `.deb`, `.rpm` |
| Signing | Developer ID + notarisation + stapling | Authenticode, EV preferred | detached GPG signature |
| CLI | `credmgr` static binary | `credmgr.exe` | static musl binary |
| Updates | Tauri updater, signed manifest, opt-in | same | same |
| Reproducibility | pinned toolchain, `cargo --locked`, `SOURCE_DATE_EPOCH` | same | same |

None of this exists — beyond one unsigned slice: since 2026-09-24 `v2/scripts/release.sh` builds
the CLI and the broker with `--locked`, tars them with the launchd unit, and writes `SHA256SUMS`,
with no signature (`21_RELEASE_AND_INTEGRITY.md §8`, K-5). `tauri.conf.json` is no longer the generated
scaffold's in packaging terms — product name `CredMgr`, version `2.0.0-beta.1`, identifier
`com.credmgr.desktop`, the KEEP app icon, a 1280×820 window, macOS 13.1 as the minimum — and it
carries a real Content Security Policy in place of `"csp": null` (ADR-062); there is still no
updater endpoint and no signing configuration. Every
release will publish `SHA256SUMS` with a detached signature and an SPDX SBOM, and the signing key
will live on a machine the maintainer controls rather than in CI, so a compromised CI can produce an
unsigned artefact but never a signed one (`21_RELEASE_AND_INTEGRITY.md §2`).

Two prerequisites are outstanding and are not merely paperwork. An Apple Developer ID and a Windows
code-signing certificate are open item **O-3** and accepted risk **K-4** — an operator purchase,
needed before any binary ships. And the app's own start-time self-verification
(`21_RELEASE_AND_INTEGRITY.md §3`) will need a **signature primitive this workspace does not
contain**: `crates/core` has X25519 and HMAC-SHA256 and no Ed25519, no EdDSA, nothing that verifies
a detached signature. Any plan that assumes signing primitives are already available is wrong.

---

## 9. What this document supersedes — and two corrections to its own previous revision

**Superseded decisions.**

- **ADR-008 (Node.js core, zero dependencies)** — superseded. Node cannot deliver memory hygiene, a
  single signed binary, or TPM/Hello access. **V1 stays Node**; it is a working, shipped product.
  V2 is Rust.
- **ADR-009 (a Rust broker is deferred)** — resolved, adopted. Its stated trigger was "the vault
  leaves this machine". Shipping publicly to Windows and Linux users is that trigger.
- **ADR-025's native shell** — decision: "the native shell serves the UI via
  `WKURLSchemeHandler` from the app bundle," with no listening socket — replaced by Tauri 2's own
  webview-serving mechanism. The macOS-specific mechanisms that shell was written to call — Secure
  Enclave, `LocalAuthentication` — survive as the design of the macOS `PlatformKeystore`
  implementation in §4.2, now to be called through Tauri's Rust side instead. (Not ADR-022, which
  is unrelated: it settled the frontend JS framework — Svelte 5, no Tailwind, vendored graph
  engine — and never mentions Swift, WKWebView, or a native shell at all.)

**Two corrections to what this document previously claimed it had closed.** The previous revision
ended by declaring accepted risks "AR-2 (scrypt not Argon2id)" and "AR-3 (Node heap zeroisation)"
closed. Both statements are now wrong, in a way that matters more than the wording:

- Those were **Pass-2 identifiers**. `05_THREAT_MODEL.md §7` has since renumbered the register
  around six stable identifiers, in which **AR-2 is "the broker holds every unlocked node key in
  memory at once"** and **AR-3 is "zeroisation is best-effort against the operating system"** —
  both **open**, AR-3 permanently so. A reader following the citation would have concluded that two
  live risks were closed.
- The underlying Pass-2 concerns are genuinely addressed — the password hash *is* Argon2id
  (`argon2` 0.5, §4.1) and the runtime *is* Rust with `zeroize`/`secrecy` — but "the concern is
  addressed" and "accepted risk AR-*n* is closed" are different claims, and only the first is this
  document's to make. Risk identifiers are owned by `05_THREAT_MODEL.md §7`.

---

## 10. Residual risks this architecture adds

These four are numbered in this document's own sequence, and **that sequence collides with
`05_THREAT_MODEL.md §7`'s** — which now defines AR-1…AR-6 with different content. The collision is
known and deliberately not resolved here: `AR-9` is cited by `13_TEST_PLAN.md §2` and by ADR-046,
and `05_THREAT_MODEL.md §3.4` explicitly declines to mint an `AR-7` for the same reason. Renumbering
both registers together is open work; picking a number unilaterally in one document is how two risks
end up under one name in a corpus that cites them bare.

| ID | Risk | Bound — what it does **not** affect | Owner | Resolution path |
|---|---|---|---|---|
| **AR-7** | A Linux machine without a TPM is `Tier::Software` | Ciphertext at rest is unaffected; Argon2id at 256 MiB still guards the root wrap | CredMgr agent | The UI will state the achieved tier in words, and will recommend a FIDO2 token when one is detected (§4.4) |
| **AR-8** | Tauri pulls a real dependency tree, unlike the zero-dependency Node core it replaced | The security crates are a separate workspace with a separate lockfile; the core crypto set stays small and audited (§2.1) | CredMgr agent | `cargo deny` and `cargo audit` run on every pull request and every push to `main` today; an SBOM per release is planned (§8.3) |
| **AR-9** | Three keystore implementations are three places to get it wrong | The trait keeps the surface to seven methods, and `Capabilities` makes a weak result reportable rather than silent | whoever builds §4.2–§4.4 | One conformance suite run against every implementation on the CI matrix (`13_TEST_PLAN.md §2`) — the suite does not exist yet, and neither do the implementations |
| **AR-10** | Windows named-pipe DACLs are easy to get subtly wrong | The owner-SID comparison **will be** an invariant enforced in code, not only a DACL configuration (§5.3) — planned, and true of nothing in this workspace today: `brokerd` has no Windows code at all (`grep -rn 'cfg(target_os = "windows")' v2/crates/` returns only `paths.rs` and `software.rs`) | whoever builds §5.3 | A dedicated test asserting a second user's connection is refused, mirroring the uid gate's existing test |

A fifth risk is worth stating without numbering it, because it is the one this rewrite exists to
stop: **a document describing three platforms is read as three platforms working.** The mitigation
is structural rather than procedural — every subsystem heading in this document carries its status,
and §7's final column shows what every platform actually reduces to today.

---

## 11. Connections

| Direction | Document | What flows across |
|---|---|---|
| feeds | `02_ARCHITECTURE.md §6` | the keystore and presence status the architecture reports; §6.3 there is the same finding stated from the architecture's angle |
| feeds | `04_CRYPTO_AND_KEYS.md §2` | the platform wrap of the root key, and why the passphrase escrow wrap is mandatory beside it |
| feeds | `05_THREAT_MODEL.md §9` | the hardware-tier gap that reduces the stolen-laptop rows to passphrase strength |
| feeds | `13_TEST_PLAN.md §2` | the keystore conformance suite and the CI matrix it must run on (AR-9) |
| feeds | `21_RELEASE_AND_INTEGRITY.md §2` | the per-platform artefacts and signing mechanisms a release must produce |
| depends on | `10_API_AND_MCP.md §1` | the wire protocol the per-platform transports in §5 must carry unchanged |
| depends on | `06_ACCESS_GRAPH.md §4` | the subject scope that peer identity in §5.2 resolves |
| depends on | `07_TWO_FACTOR.md §3` | the gate that runs before node keys load, on every platform |
| depends on | `03_DATA_MODEL.md §9` | the audit log, which is vault data and is distinct from the diagnostic log §6.1 plans |
| depends on | `14_DECISIONS.md` | `ADR-035` (the toolchain split), `ADR-036` (the MSRV-driven crate pins), `ADR-039` (path resolution and the counter seam), `ADR-041` (software tier only), `ADR-046` (why the hardware tiers are deferred honestly), `ADR-057` (the desktop bridge) |
| depends on | `PHASE8_AUDIT_REPORT.md` | accepted risks K-1 (I-10 needs a presence-capable transport) and K-4 (signing certificates) |

## 12. Source

**Design.** `ADR-008` and `ADR-009` (superseded and resolved by this document), `ADR-025`
(replaced), `ADR-035`, `ADR-036`, `ADR-039`, `ADR-041`, `ADR-046`, `ADR-057`.
`12_BUILD_PLAN.md §2.6`'s Phase 5 carries the rule that §4 and §8.2 are measured against — not the
"do this phase on all three OSes, or do not claim it" sentence (that line was dropped from the
plan during this rewrite; its only surviving copy is inside `ADR-046`'s quotation of the
pre-rewrite text, `14_DECISIONS.md:849`), but the plan's current wording: *"a keystore that
compiles for Windows but has never unlocked a vault on Windows is not implemented"*, plus the
phase's per-platform exit-gate checkboxes.

**Code.** `crates/keystore/src/lib.rs` (the trait, `KeystoreId`, `Capabilities`, `Tier`);
`crates/keystore/src/software.rs` (the only `impl PlatformKeystore` in the workspace);
`crates/store/src/paths.rs` (`default_vault_dir`, `default_state_dir`, `run_socket`);
`crates/store/src/atomic.rs` (the `0700`/`0600` modes, Unix-gated);
`crates/brokerd/src/lib.rs` (`#[cfg(unix)]` on `peer` and `server`);
`crates/brokerd/src/peer.rs` (the macOS and Linux `platform` modules);
`crates/brokerd/src/server.rs` (socket bind and chmod);
`crates/brokerd/packaging/com.credmgr.brokerd.plist` and `v2/packaging/com.credmgr.brokerd.plist`
(written, installed only by hand per `v2/RELEASE.md`); `v2/scripts/release.sh`;
`apps/desktop/src-tauri/src/vault_paths.rs` and `tauri.conf.json`;
the six crate manifests for §2.1's versions.

**Tests.** `crates/keystore/src/software.rs` — twelve unit tests, named in §4.1.
`crates/store/src/paths.rs::env_override_wins_on_every_platform` and
`::vault_and_state_dirs_never_coincide`.
`crates/store/src/atomic.rs::dir_and_file_modes_are_owner_only`.
`crates/brokerd/src/server.rs::peer_uid_gate_rejects_any_non_owning_uid`.
`apps/desktop/src-tauri/tests/drift_guards.rs::the_per_platform_vault_defaults_still_match_crates_store`
and `::the_socket_path_rule_still_matches_crates_store`.
`crates/brokerd/tests/isolation.rs` runs I-1…I-25 and I-27…I-29 (there is no I-26); **I-10 is implemented nowhere** (K-1), for the
presence reason §3 gives. `cargo test --workspace -- --list`: 813 tests in 50 test binaries (2026-10-03); the last full run recorded: 571 passing, 0 failing, 41 test binaries (2026-10-02; earlier: 448 passing, 37 test binaries on 2026-09-24, re-measured 2026-10-01; 406 passing, 35 test binaries as of 2026-09-13, run
`34743281942`; 397 passing, 33 test binaries, verified 2026-08-18).

**Verification of the never-run claim.** `gh run list --workflow=build.yml` returned an empty list
on 2026-08-18. Re-run it before trusting §8.2 — it is the one fact in this document that can change
without any file in the repository changing.

**Figure.** §4.5's `platform-surface-built-vs-planned` — `tools/docgen`, `kind: "system_map"` (see
`tools/ENGINE_ROUTING_POLICY.md`). Spec: `v2/docs/16_CROSS_PLATFORM_spec.json`. Re-derived
2026-08-23 straight from the `#[cfg(...)]` gates, not transcribed from this document's own prose:
`crates/brokerd/src/lib.rs` (`peer`/`server` are `#[cfg(unix)]`; `ops`/`state`/`scope`/`protocol`/
`token` carry no OS gate at all); `crates/brokerd/src/peer.rs` (a macOS module plus a
`#[cfg(all(unix, not(target_os = "macos")))]` module — zero Windows code, confirmed by grep);
`crates/keystore/src/lib.rs` (`KeystoreId`'s six variants) against `crates/keystore/src/software.rs`
(the workspace's one and only `impl PlatformKeystore`); `crates/store/src/paths.rs`
(`default_vault_dir`/`default_state_dir`, each with a real per-`target_os` branch for macOS, Windows
and the XDG fallback). Rendered and collision-checked via `tools.docgen.diagram_graphs.check_system_map`/
`render_system_map` before being committed to the sidecar — zero blocking findings, byte-identical on
a second render.
