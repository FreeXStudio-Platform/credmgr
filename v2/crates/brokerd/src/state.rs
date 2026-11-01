//! `BrokerState` — everything `credmgrd` holds in memory: the registry and
//! per-node manifests (cached once loaded; they stay available across a
//! lock, since only key material is lock-sensitive — the graph must render
//! while locked, `02_ARCHITECTURE.md §7`), the hot node-key set, and the
//! keystore that guards the root key.
//!
//! **Locking zeroises the hot key set, not the broker's whole state**
//! (`02 §2`). That is what makes "topology + counts visible while locked"
//! and "reveal denied while locked" both true at once: `R1` in
//! `credmgr_core::access` denies `reveal`/`update` while locked regardless
//! of what's in the hot set, and the hot set being empty is what makes that
//! denial airtight rather than merely policy.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use credmgr_core::keys::{generate_node_keypair, unwrap_node_key, wrap_node_key, WrappedNodeKey};
use credmgr_core::recovery::{
    format_recovery_code, generate_recovery_code, wrap_root_with_recovery_code, RootRecoveryWrap,
};
use credmgr_core::registry::{Grant, Node, Registry, GLOBAL_ID, ORPHAN_ID};
use credmgr_core::totp::{
    format_gate_recovery_code, generate_gate_recovery_codes, generate_gate_secret,
    hash_gate_recovery_code, parse_gate_recovery_code, Totp,
};

use credmgr_keystore::software::SoftwareKeystore;
use credmgr_keystore::{KeystoreError, PlatformKeystore, WrappedKey};
use credmgr_store::atomic;
use credmgr_store::error::StoreError;
use credmgr_store::generation::{
    check_and_advance, FileGenerationCounter, GenerationCounter, VAULT_GENERATION,
};
use credmgr_store::manifest::{self, ManifestBody, ManifestEntry};
use credmgr_store::paths::VaultPaths;
use credmgr_store::registry_file::{self, GateDoc, NodeDoc, RegistryDocument};

use crate::auth_backoff::AuthBackoff;
use crate::rate_limit::RateLimiter;
use crate::token::TokenStore;

/// ADR-061. Same manual-hex-digit style `ops.rs::sha256_hex`/`new_entry_id`
/// already use — no new dependency for something this small.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// ADR-030: "Vault idle auto-lock 15 min."
const DEFAULT_VAULT_IDLE_SECONDS: u32 = 15 * 60;
/// `07_TWO_FACTOR.md §5a`: "It times out in 120 seconds and defaults to deny."
const APPROVAL_TTL_SECONDS: i64 = 120;
/// A request is a slot per (node, entry, requester) (audit P1-1), and a requester is as many as there are tokens and work
/// folders, so the table is bounded: past this many slots the oldest undecided one is dropped to make room (its
/// requester asks again and gets a fresh request, nothing is released).
const MAX_APPROVAL_SLOTS: usize = 512;
/// How long factor 1 (passphrase) stays valid waiting for factor 2 (gate
/// TOTP/recovery code) before `vault.gate_verify` must be re-started from
/// `vault.unlock` — `07_TWO_FACTOR.md §3` doesn't name a figure for this
/// specific window, so this reuses `APPROVAL_TTL_SECONDS`'s already-precedented
/// value rather than inventing a second unexplained constant.
pub const GATE_UNLOCK_TTL_SECONDS: i64 = APPROVAL_TTL_SECONDS;
/// `07_TWO_FACTOR.md §5`: "Elevation ... default 5 min."
const DEFAULT_ELEVATION_SECONDS: i64 = 5 * 60;
/// `07_TWO_FACTOR.md §4`: "Enrolled per: vault (global) and per node." This
/// session builds the vault-wide gate only (see `BUILD_LOG.md`) — `GLOBAL_ID`
/// doubles as that gate's scope key today; a per-node gate would use the
/// node's own id in the same `gate`/`gate_replay`/`elevations` maps, which is
/// why those are keyed by `String` scope rather than hard-coded to one name.
pub const GATE_SCOPE_VAULT: &str = GLOBAL_ID;

/// One `entry.create` deposited while locked (`06_ACCESS_GRAPH.md §3`, F-1).
/// Holds exactly what `vault.pending_accept` needs to build the eventual
/// [`ManifestEntry`] — everything about the *value* was already fixed at
/// create time (the plaintext is sealed and on disk); only `ref` and
/// `modified` are decided at accept time, because a pending item that is
/// never accepted must never have consumed a vault-global ref.
#[derive(Debug, Clone)]
pub struct PendingEntry {
    pub id: String,
    pub name: String,
    pub entry_type: credmgr_core::inference::EntryType,
    pub sensitivity: credmgr_store::manifest::Sensitivity,
    pub field_count: u32,
    pub sha256: String,
    /// Unix epoch seconds — when `entry.create` deposited it.
    pub created: i64,
}

/// An approval-on-demand request (F-15, `07_TWO_FACTOR.md §5a`, ADR-042):
/// created the moment a `reveal` on a locked target would otherwise have
/// succeeded. `decision` is `None` until `vault.approval_decide` resolves
/// it; there is no separate "expired" state stored — expiry is `now >=
/// expires_at`, checked wherever a request is next read, which is enough
/// because nothing observes one between creation and its next read.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub id: String,
    pub node_id: String,
    pub entry_id: String,
    /// The requesting process's cwd, if known — `07 §5a`: "The notification
    /// names the requesting process's cwd and the entry."
    pub cwd: Option<String>,
    /// Who asked, as an opaque in-memory key (never printed or returned): an approval is consumed only by a request
    /// from the same requester. Audit finding P1-1: keyed by (node, entry) alone, one caller's approval was taken,
    /// whole, by any other caller in reach.
    pub request_key: String,
    /// The field ids the request asked for (sorted, de-duplicated); `None` means every field. The approval releases
    /// only a selection inside this set, so it cannot be widened by a later request.
    pub fields: Option<Vec<String>>,
    pub created: i64,
    pub expires_at: i64,
    pub decision: Option<bool>,
    /// ADR-079 (4a): the vault locked after this request was approved, so the
    /// value staged for it was dropped and the approval turned into a denial
    /// (`decision` is `Some(false)`). The requester is told `locked`, not
    /// `denied` — nobody refused it; the human walked away.
    pub voided_by_lock: bool,
}

/// An approval-on-demand request and — from the moment a human approves it
/// until the requester takes it, it expires, or the vault locks — the one value
/// it releases, already decrypted (ADR-079, 4a). Held apart from
/// [`PendingApproval`] so the record handed to callers by value can never carry
/// plaintext, and so that value is zeroised on every path that ends the request.
struct ApprovalSlot {
    record: PendingApproval,
    staged: Option<SecretBox<String>>,
}

/// What a human decided about a request. The value of an approval is bound into
/// the verdict, so a request can never be recorded as approved with nothing to
/// release (ADR-079, 4a: the value is decrypted when the decision is made, never
/// when the requester comes back for it).
pub enum ApprovalVerdict {
    Deny,
    Approve {
        /// The one entry value this approval releases, decrypted at decide time.
        staged: SecretBox<String>,
        /// [`BrokerState::lock_epoch`] as read **before** the decider checked the
        /// lock state or touched any key. If the vault locked at any point since,
        /// the value is refused rather than stored: a staged approval never
        /// survives a `lock()`, including one that raced the decision itself.
        lock_epoch: u64,
    },
}

/// ADR-088: why [`BrokerState::approval_factors`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalFactorError {
    WrongPassphrase,
    /// A gate is confirmed and no code was given.
    SecondFactorRequired,
    WrongCode,
    /// ADR-092: an interrupted root-key rotation could not be finished (or
    /// dropped) before the root wrap was read. Nothing was decided.
    RotationRecovery,
}

/// Why `BrokerState::decide_approval` refused to record a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecideError {
    NotFound,
    AlreadyDecided,
    /// The vault locked between the start of an approving decision and the
    /// moment its value would have been stored (ADR-079, 4a). Nothing is stored.
    LockedMeanwhile,
}

/// One scope's gate 2FA enrolment (`07_TWO_FACTOR.md §3-4`). Not `Clone`:
/// the `totp::Totp` secret has no business being copied around, only read
/// through `&self` access to the map that owns it.
pub struct GateEnrollment {
    totp: Totp,
    /// `07 §4`: "Require one successful confirming code before the
    /// enrolment is activated" — an unconfirmed entry exists (so
    /// `gate_enroll_confirm` has something to check the code against) but
    /// `unlock()` must never treat it as gating anything (`is_gate_confirmed`).
    confirmed: bool,
    /// SHA-256 hashes of the 10 gate recovery codes (`07 §4`), `None` once
    /// consumed. The plaintext codes themselves are never stored anywhere —
    /// they exist only in the `Vec<String>` `gate_enroll_confirm` returns
    /// once, at issuance.
    recovery_hashes: Vec<Option<[u8; 32]>>,
}

/// Factor 1 (passphrase) succeeded and a confirmed gate is enrolled for the
/// scope being unlocked — `07 §3` steps 1-2 are done, waiting on step 3
/// (`vault.gate_verify`). Holds the unwrapped root key so step 4 (derive
/// every node key) never has to re-authenticate against the keystore; zeroed
/// on drop via `SecretBox`, and dropped outright — never leaked into a
/// second pending challenge — by `lock()`/`external_lock_signal` (`07 §8`
/// test: "lock, sleep and screen lock each drop every elevation", read to
/// include this in-flight challenge, not just elevations proper).
struct PendingGateUnlock {
    root_key: SecretBox<[u8; 32]>,
    expires_at: i64,
}

/// Why `BrokerState::gate_verify` refused. Internally distinguished (unlike
/// the wire layer, which collapses both into one undifferentiated
/// `OpError::GateVerificationFailed` — `07 §5`'s replay rule exists
/// specifically so an observer cannot learn *why* a code failed) so tests
/// can assert the right failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateVerifyError {
    /// No `vault.unlock` factor-1 success is currently waiting on this
    /// scope's gate — expired, already consumed, or never started.
    NoChallengePending,
    /// The code did not match the current TOTP window, a previously-used
    /// TOTP step (replay), or any unconsumed recovery code.
    WrongCode,
}

/// Why `BrokerState::gate_enroll_confirm` refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateEnrollError {
    /// `gate_enroll_begin` was never called for this scope (or it was
    /// already confirmed and no new enrolment is in flight).
    NotEnrolling,
    /// `07 §4`'s confirming code did not match.
    WrongCode,
}

/// An in-flight `credmgr init` (ADR-061), set by `begin_init` and consumed
/// by `confirm_init`. Everything here except the root key is ciphertext or
/// a one-way hash: the node's private key and the recovery code's own raw
/// bytes are zeroised before `begin_init` returns and never enter this
/// struct at all. The root key is the one exception — `confirm_init` needs
/// it again to sign the registry it writes, and generating a second one
/// there would not help, since every wrap already committed to this one —
/// so it is held here the same way `PendingGateUnlock` already holds an
/// unwrapped root key across an equally-interactive two-step flow,
/// TTL-bounded and zeroised on drop by the same `SecretBox` discipline.
struct PendingInit {
    root_key: SecretBox<[u8; 32]>,
    node_public_key: PublicKey,
    wrapped_root_pass: WrappedKey,
    wrapped_root_recovery: RootRecoveryWrap,
    wrapped_node_key: WrappedNodeKey,
    /// ADR-079: the `orphan` node's public key and its cold-key file
    /// (`credmgr_core::cold`, already sealed under the root key — the orphan
    /// private half exists unsealed only inside `generate_orphan_cold`).
    /// `confirm_init` writes the file before the registry that names it.
    orphan_public_key: PublicKey,
    orphan_cold_key: Vec<u8>,
    /// SHA-256 of the formatted recovery code — see `confirm_init`'s own
    /// doc comment for why a plain array compare against this, not a
    /// constant-time one, is the considered choice here.
    recovery_code_sha256: [u8; 32],
    expires_at: i64,
}

/// Why `BrokerState::begin_init` refused (ADR-061).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultInitError {
    /// `paths.registry()` already exists — refuse rather than overwrite.
    AlreadyInitialized,
    /// V1 parity (`v1/CHANGELOG.md` 1.9.0): the resolved vault root sits
    /// inside a `.git` working tree, whether by the default path (which
    /// cannot happen — `default_vault_dir` never reads cwd) or by an
    /// override pointed at a checkout.
    InsideGitWorkingTree,
}

/// Why `BrokerState::confirm_init` refused (ADR-061).
#[derive(Debug)]
pub enum VaultInitConfirmError {
    /// `paths.registry()` already exists — a second confirm after a first
    /// one already succeeded, or a vault appeared by some other path.
    AlreadyInitialized,
    /// No `begin_init` is in flight for this broker.
    NotPending,
    /// A `begin_init` was in flight but its TTL elapsed; cleared, and the
    /// caller must restart from `begin_init`.
    Expired,
    /// The retyped recovery code's hash did not match — the pending init
    /// is left in place so the operator can simply retry `confirm_init`.
    RecoveryCodeMismatch,
    /// A real filesystem failure partway through the write sequence.
    Store(StoreError),
}

/// A sealed node's registry + manifest snapshot, kept in memory so
/// `node.restore` can put it back exactly (`06_ACCESS_GRAPH.md §9`, F-4).
///
/// **This is the in-memory fixture's record only.** On a disk-backed vault
/// (every real daemon) the seal record is part of the signed registry —
/// `registry_file::SealedNodeDoc`, ADR-079 — and survives a restart; this type
/// is never populated there. It remains so the suites that build a `BrokerState`
/// by hand (`tests/isolation.rs` I-21) keep exercising the seal/restore
/// authorisation without a vault on disk.
#[derive(Debug, Clone)]
pub struct SealedNodeRecord {
    pub node: Node,
    pub manifest: Option<ManifestBody>,
    /// Entry ids this seal deposited into the orphan node's manifest —
    /// `node.restore` removes exactly these, never "everything currently in
    /// orphan", so restoring node A can never touch node B's older seal.
    pub orphan_entry_ids: Vec<String>,
    /// `None` only if the node somehow had no key material at seal time —
    /// should not happen in practice (`04 §2`: every node gets a real
    /// keypair), kept `Option` so a seal can't panic on that surprise.
    pub key_material: Option<(WrappedNodeKey, PublicKey)>,
    pub sealed_at: i64,
}

pub struct BrokerState {
    pub registry: RwLock<Registry>,
    pub manifests: RwLock<HashMap<String, ManifestBody>>,
    /// Node id → the node's own raw X25519 private key bytes, present only
    /// between a successful `unlock` and the next `lock`. A plain
    /// `[u8; 32]` rather than a `StaticSecret`, deliberately: `lock()`
    /// zeroises these bytes **in place** and leaves them inspectable for
    /// exactly one purpose — proving zeroisation happened, per the Phase 3
    /// exit gate ("asserted by inspecting the buffers", not by a subsequent
    /// request). A `StaticSecret` gives no way to observe that.
    hot_keys: RwLock<HashMap<String, [u8; 32]>>,
    node_wrapped_keys: RwLock<HashMap<String, WrappedNodeKey>>,
    /// A node's public key is registry cleartext (`04 §2`) and, unlike the
    /// hot private-key set, is never zeroised on lock — `entry.create` seals
    /// to it while locked (F-1) and must be able to do so with no key
    /// material unwrapped at all.
    node_public_keys: RwLock<HashMap<String, PublicKey>>,
    wrapped_root: RwLock<Option<WrappedKey>>,
    locked: RwLock<bool>,
    /// Nodes individually locked while the vault stays open (`06 §1a`).
    pub locked_nodes: RwLock<HashSet<String>>,
    /// One exclusive lock per node, held across an entire mutating op
    /// (`02_ARCHITECTURE.md §2`, F-9): "the broker holds an exclusive
    /// in-process write lock **per node**". The outer `Mutex` only protects
    /// get-or-insert into this map; the returned `Arc<Mutex<()>>` is what a
    /// caller actually holds for the duration of its write.
    node_write_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// `nodes/<id>/pending/` (`02 §7`). The running tray; since ADR-069 each
    /// entry's metadata is also written beside its envelope and the tray is
    /// rebuilt from disk at the first unlock after a restart (`state/tray.rs`).
    pending: RwLock<HashMap<String, Vec<PendingEntry>>>,
    /// The vault-global ref counter (`03_DATA_MODEL.md §3`: "unique
    /// vault-wide, never reused"). A single atomic rather than a per-node
    /// scan-and-increment: refs are global, so a per-node write lock (which
    /// is exactly what F-9 serialises) cannot by itself keep two concurrent
    /// creates on *different* nodes from computing the same "next" ref —
    /// only a counter with no node in its critical section can.
    next_ref: AtomicU32,
    /// Nodes currently sealed, keyed by id — `06_ACCESS_GRAPH.md §9`/F-4.
    sealed_nodes: RwLock<HashMap<String, SealedNodeRecord>>,
    /// Approval-on-demand requests in flight, keyed by request id (F-15,
    /// ADR-042). Each slot also holds, once approved, the one decrypted value
    /// it releases (ADR-079, 4a) — which `lock()`, expiry and consumption all
    /// zeroise.
    approvals: RwLock<HashMap<String, ApprovalSlot>>,
    /// Counts every `lock()` (ADR-079, 4a), bumped after the `locked` flag is
    /// set and before staged values are voided (see `lock_inner` for why that
    /// order matters). An approving decision reads it before it checks the lock
    /// state or touches a key, and the store step refuses if it moved — so a
    /// lock that races a decision cannot leave a staged value behind it.
    lock_epoch: std::sync::atomic::AtomicU64,
    /// Vault-wide idle auto-lock threshold in seconds (ADR-030, ADR-043).
    /// `RwLock` rather than a plain field so a future settings op can change
    /// it without restarting the broker.
    vault_idle_seconds: RwLock<u32>,
    /// Unix epoch seconds of the most recent request the broker processed,
    /// vault-wide (ADR-043).
    last_activity: RwLock<i64>,
    /// Per-node last-activity, for `NodePolicy::lock_after_seconds`'s
    /// individual timer (ADR-030, ADR-043).
    node_last_activity: RwLock<HashMap<String, i64>>,
    /// Gate 2FA enrolments (`07_TWO_FACTOR.md §3-4`), keyed by scope —
    /// `GATE_SCOPE_VAULT` today; a future per-node gate reuses this same map
    /// under the node's id.
    gate: RwLock<HashMap<String, GateEnrollment>>,
    /// `07 §5`: "every accepted `(scope, counterStep)` is recorded and
    /// refused again" — the replay ledger, shared across every scope's gate.
    gate_replay: RwLock<HashSet<(String, u64)>>,
    /// At most one in-flight two-step unlock per scope: factor 1 succeeded,
    /// factor 2 has not yet been presented (or failed). `Mutex` because a
    /// successful `gate_verify` both reads and clears this atomically with
    /// respect to a concurrent second attempt.
    pending_gate_unlock: Mutex<HashMap<String, PendingGateUnlock>>,
    /// `07 §5`: a scoped elevation window granted on a successful gate
    /// challenge, keyed by scope, holding the Unix-epoch-second it expires.
    /// Cleared unconditionally by `lock()` — "elevations are dropped on
    /// lock, sleep, screen lock" (`07 §5`), and ADR-043 already funnels
    /// idle/sleep/screen-lock/explicit-lock through that one function.
    elevations: RwLock<HashMap<String, i64>>,
    // `RwLock`, not a plain field: the isolation suite needs to simulate
    // "the operator typed the wrong passphrase at unlock" without also
    // faking a different wrapped-root blob, which means swapping the
    // *decrypting* keystore instance while the wrapped material stays
    // fixed. `replace_keystore_for_test` (below) is the only writer.
    keystore: RwLock<Box<dyn PlatformKeystore>>,
    pub paths: VaultPaths,
    pub tokens: TokenStore,
    pub rate_limiter: RateLimiter,
    /// `07 §5`, ADR-044 — distinct from `rate_limiter` above, which is the
    /// cross-node-denial anomaly counter (`05 §7`), a different threat.
    pub auth_backoff: AuthBackoff,
    /// Ids of tokens minted by a real `vault.unlock`/`vault.gate_verify`
    /// success (ADR-056) — never a fixture-issued token, which never passes
    /// through `register_session_token`. `lock()` drains and revokes every
    /// id here so a login session does not outlive the unlock it came from,
    /// the same "elevations are dropped on lock" discipline `07 §5` already
    /// applies to gate 2FA's own scoped elevations.
    session_tokens: RwLock<HashSet<String>>,
    /// At most one in-flight `credmgr init` (ADR-061) — `Mutex` for the same
    /// reason `pending_gate_unlock` is one: a successful `confirm_init` both
    /// reads and clears this atomically with respect to a concurrent second
    /// attempt.
    pending_init: Mutex<Option<PendingInit>>,
    /// Where `begin_init`/`confirm_init` (ADR-061) resolve a
    /// [`credmgr_store::generation::FileGenerationCounter`] and the
    /// throwaway `SoftwareKeystore`'s own (unused by a plain `wrap_root`
    /// call, but constructed regardless) state directory — defaults to the
    /// real OS location, same as every other caller of
    /// `credmgr_store::paths::default_state_dir()` in this workspace, and
    /// overridable only by `set_state_dir_for_test` so a test never touches
    /// a real machine's state directory. `RwLock`, matching `keystore`
    /// above's own reasoning for why this needs to be swappable after
    /// construction, not just at it.
    state_dir: RwLock<std::path::PathBuf>,
    /// ADR-063: `true` once this vault is backed by disk — set by
    /// `confirm_init`, or by the first passphrase unlock that loads an
    /// existing vault. While `true`, every successful mutating op is written
    /// through to disk (`durable::persist`). An in-memory fixture — every
    /// pre-ADR-063 test — never sets it, so its behaviour is unchanged.
    durable: std::sync::atomic::AtomicBool,
    /// ADR-063: the registry document as last written, carrying the
    /// persistence-only fields the core `Registry` drops (`created`,
    /// `pinned`, `publicKey`, a grant's `createdAt`/`lastUsedAt`). `persist`
    /// merges the live registry into this rather than inventing those fields.
    registry_meta: RwLock<RegistryDocument>,
    /// ADR-063 (as amended after review, 2026-09-24): the root key of a
    /// **live, passphrase-unlocked** vault, held only while it is unlocked
    /// and zeroised by `lock()` (a `SecretBox` zeroises on drop). The
    /// passphrase keystore that produced it is dropped at once, so the
    /// passphrase is never resident. `reauth_root_key` reads this and never
    /// touches `keystore` for a disk-backed vault — which is what stops a
    /// passphrase-less `vault.unlock` from ever succeeding on the daemon.
    session_root: RwLock<Option<SecretBox<[u8; 32]>>>,
    /// One authentication transition at a time: unlock (either path),
    /// `gate_verify`, `gate_recover` and `lock()` take this, so a lock can
    /// never interleave with an unlock that is half-installed.
    auth_lock: Mutex<()>,
    /// ADR-064: per scope, the highest TOTP step accepted before this
    /// process loaded the vault. A code at or below it is refused, so the
    /// replay rule survives a restart even for a step the in-memory ledger
    /// never saw.
    gate_replay_floor: RwLock<HashMap<String, u64>>,
    /// ADR-065: when each live login session was last used. A session idle
    /// for `vault_idle_seconds` is revoked by `tick_autolock` on its own,
    /// even while agents keep the vault itself busy — so an exported owner
    /// token dies when its owner stops using it (K-6's bound).
    session_last_used: RwLock<HashMap<String, i64>>,
    /// ADR-064: a re-enrolment in flight for a scope that already has a
    /// **confirmed** gate. Kept apart from `gate` so starting a re-enrolment
    /// and walking away leaves the existing gate in force — before ADR-064,
    /// `gate_enroll_begin` replaced it outright, which a persisted gate would
    /// have turned into a durable, silent 2FA removal.
    gate_pending: RwLock<HashMap<String, Totp>>,
    /// ADR-063: one writer at a time. `persist` snapshots the whole live
    /// state and bumps the vault generation; two interleaved writers could
    /// otherwise land an older snapshot over a newer one.
    persist_lock: Mutex<()>,
    /// ADR-076: every request holds this shared for its whole life; a root-key
    /// rotation takes it exclusive, so no other request can sign anything
    /// under the old root key (an audit tip, say) between the plan and the
    /// switch. See [`BrokerState::request_barrier`].
    request_barrier: RwLock<()>,
    /// ADR-079's crash-injection seams: where the next persist, seal or restore
    /// should "die". `crash_injected` is set when one fires, so the cleanup a
    /// real crash would never have run is skipped too.
    #[cfg(feature = "test-utils")]
    persist_fault: Mutex<Option<(usize, PersistFault)>>,
    #[cfg(feature = "test-utils")]
    seal_fault: Mutex<Option<SealFault>>,
    /// C1: parks the next seal or restore (persist lock held) so a test can race
    /// another client's write-through against it.
    #[cfg(feature = "test-utils")]
    seal_pause: Mutex<Option<SealPauseSlot>>,
    #[cfg(feature = "test-utils")]
    crash_injected: std::sync::atomic::AtomicBool,
    /// ADR-076's crash-injection seam: where the next rotation should "die".
    #[cfg(feature = "test-utils")]
    rotation_fault: Mutex<Option<RotationFault>>,
    /// ADR-076's concurrency seam: freeze the next rotation half-way through
    /// staging, running this hook, so a test can start a second broker state or
    /// daemon over the same vault at the worst moment.
    #[cfg(feature = "test-utils")]
    rotation_pause: Mutex<Option<RotationPause>>,
}

/// `(files staged before the pause, hook to run there)` — see
/// [`BrokerState::set_rotation_pause_for_test`].
#[cfg(feature = "test-utils")]
type RotationPause = (usize, Arc<dyn Fn() + Send + Sync>);

mod durable;
mod rotate;
mod seal;
mod tray;
#[cfg(feature = "test-utils")]
pub use durable::PersistFault;
pub use durable::{GateRecoverError, UnlockError};
#[cfg(feature = "test-utils")]
pub use rotate::RotationFault;
pub use rotate::{
    RotateRootError, RotationOutcome, VaultLock, RECOVER_LOCK_WAIT, ROOT_BOUND_ARTEFACTS,
    ROTATE_LOCK_WAIT,
};
pub use seal::{PurgedSeal, RestoreOutcome, SealOutcome};
#[cfg(feature = "test-utils")]
pub use seal::{SealFault, SealPause};

/// Where a test parked a seal/restore, and the two channel ends it talks through.
#[cfg(feature = "test-utils")]
type SealPauseSlot = (
    SealPause,
    std::sync::mpsc::Sender<()>,
    std::sync::mpsc::Receiver<()>,
);

/// What [`BrokerState::request_barrier`] hands back: held for as long as the
/// request is being served.
pub enum RequestGuard<'a> {
    Shared(std::sync::RwLockReadGuard<'a, ()>),
    Exclusive(std::sync::RwLockWriteGuard<'a, ()>),
}

impl BrokerState {
    pub fn new(keystore: Box<dyn PlatformKeystore>, paths: VaultPaths) -> Self {
        BrokerState {
            registry: RwLock::new(Registry::new()),
            manifests: RwLock::new(HashMap::new()),
            hot_keys: RwLock::new(HashMap::new()),
            node_wrapped_keys: RwLock::new(HashMap::new()),
            node_public_keys: RwLock::new(HashMap::new()),
            wrapped_root: RwLock::new(None),
            locked: RwLock::new(true),
            locked_nodes: RwLock::new(HashSet::new()),
            node_write_locks: Mutex::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            next_ref: AtomicU32::new(1000),
            sealed_nodes: RwLock::new(HashMap::new()),
            approvals: RwLock::new(HashMap::new()),
            lock_epoch: std::sync::atomic::AtomicU64::new(0),
            vault_idle_seconds: RwLock::new(DEFAULT_VAULT_IDLE_SECONDS),
            last_activity: RwLock::new(0),
            node_last_activity: RwLock::new(HashMap::new()),
            gate: RwLock::new(HashMap::new()),
            gate_replay: RwLock::new(HashSet::new()),
            pending_gate_unlock: Mutex::new(HashMap::new()),
            elevations: RwLock::new(HashMap::new()),
            keystore: RwLock::new(keystore),
            paths,
            tokens: TokenStore::new(),
            rate_limiter: RateLimiter::new(),
            auth_backoff: AuthBackoff::new(),
            session_tokens: RwLock::new(HashSet::new()),
            pending_init: Mutex::new(None),
            state_dir: RwLock::new(credmgr_store::paths::default_state_dir()),
            durable: std::sync::atomic::AtomicBool::new(false),
            registry_meta: RwLock::new(RegistryDocument::new()),
            session_root: RwLock::new(None),
            auth_lock: Mutex::new(()),
            gate_replay_floor: RwLock::new(HashMap::new()),
            session_last_used: RwLock::new(HashMap::new()),
            gate_pending: RwLock::new(HashMap::new()),
            persist_lock: Mutex::new(()),
            request_barrier: RwLock::new(()),
            #[cfg(feature = "test-utils")]
            persist_fault: Mutex::new(None),
            #[cfg(feature = "test-utils")]
            seal_fault: Mutex::new(None),
            #[cfg(feature = "test-utils")]
            seal_pause: Mutex::new(None),
            #[cfg(feature = "test-utils")]
            crash_injected: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "test-utils")]
            rotation_fault: Mutex::new(None),
            #[cfg(feature = "test-utils")]
            rotation_pause: Mutex::new(None),
        }
    }

    /// ADR-076: the gate every request passes through. Most requests share it;
    /// `maintenance.rotate_root` (`exclusive = true`) waits for the in-flight
    /// ones to finish, runs alone, and holds off the next until it is done —
    /// including the audit record its own outcome writes, which must be signed
    /// under the *new* root key. A poisoned barrier is recovered, not
    /// propagated: it guards no data, only ordering.
    pub fn request_barrier(&self, exclusive: bool) -> RequestGuard<'_> {
        if exclusive {
            RequestGuard::Exclusive(
                self.request_barrier
                    .write()
                    .unwrap_or_else(|e| e.into_inner()),
            )
        } else {
            RequestGuard::Shared(
                self.request_barrier
                    .read()
                    .unwrap_or_else(|e| e.into_inner()),
            )
        }
    }

    /// ADR-065: whether `scope` is a real login session — a token minted by
    /// a full unlock and still live (`lock()` revokes and forgets every one).
    /// `Origin::HumanUi` alone is not enough: a fixture or any future token
    /// path can claim that origin, but only `mint_session_token` ever
    /// registers an id here.
    pub fn is_owner_session(&self, scope: &crate::scope::BrokerScope) -> bool {
        scope.origin == credmgr_core::access::Origin::HumanUi
            && scope.token_id.as_ref().is_some_and(|id| {
                self.session_tokens
                    .read()
                    .expect("session tokens poisoned")
                    .contains(id)
            })
    }

    /// Records a token minted by a real login (ADR-056) so `lock()` can
    /// revoke it later. Not `pub(crate)`-narrowed to `ops::dispatch` alone
    /// only because Rust visibility doesn't offer a tighter grain than the
    /// crate here; nothing else in this crate calls it.
    pub fn register_session_token(&self, token_id: &str, now: i64) {
        self.session_tokens
            .write()
            .expect("session tokens poisoned")
            .insert(token_id.to_string());
        self.session_last_used
            .write()
            .expect("session last used poisoned")
            .insert(token_id.to_string(), now);
    }

    /// ADR-065: a live login session was just used — restart its idle clock.
    pub fn touch_session(&self, token_id: &str, now: i64) {
        if let Some(last) = self
            .session_last_used
            .write()
            .expect("session last used poisoned")
            .get_mut(token_id)
        {
            *last = now;
        }
    }

    /// ADR-065: revoke every login session idle for `vault_idle_seconds`,
    /// independently of whether the vault itself is idle.
    fn expire_idle_sessions(&self, now: i64) {
        let limit = self.vault_idle_seconds() as i64;
        let expired: Vec<String> = self
            .session_last_used
            .read()
            .expect("session last used poisoned")
            .iter()
            .filter(|(_, last)| now.saturating_sub(**last) >= limit)
            .map(|(id, _)| id.clone())
            .collect();
        if expired.is_empty() {
            return;
        }
        let mut tokens = self
            .session_tokens
            .write()
            .expect("session tokens poisoned");
        let mut last_used = self
            .session_last_used
            .write()
            .expect("session last used poisoned");
        for id in expired {
            tokens.remove(&id);
            last_used.remove(&id);
            self.tokens.revoke(&id);
        }
    }

    #[cfg(feature = "test-utils")]
    pub fn replace_keystore_for_test(&self, keystore: Box<dyn PlatformKeystore>) {
        *self.keystore.write().expect("keystore lock poisoned") = keystore;
    }

    /// ADR-061's own test seam, same shape as `replace_keystore_for_test`
    /// above: without this, `begin_init`/`confirm_init` would resolve
    /// `credmgr_store::paths::default_state_dir()` for real, which in a
    /// test means the actual machine's `~/Library/Application Support/
    /// credmgr-state` (or platform equivalent) — never exists in a release
    /// build of `credmgrd`, which is content with the real default.
    #[cfg(feature = "test-utils")]
    pub fn set_state_dir_for_test(&self, dir: std::path::PathBuf) {
        *self.state_dir.write().expect("state dir poisoned") = dir;
    }

    // --- test/bootstrap seeding -------------------------------------------------

    pub fn set_registry(&self, registry: Registry) {
        *self.registry.write().expect("registry lock poisoned") = registry;
    }

    pub fn set_manifest(&self, node_id: impl Into<String>, body: ManifestBody) {
        self.manifests
            .write()
            .expect("manifests lock poisoned")
            .insert(node_id.into(), body);
    }

    /// Seal `root_key` under the broker's keystore and record the wrapped
    /// blob — the "vault creation" moment, before any `unlock` call exists.
    pub fn seed_root_key(&self, root_key: &secrecy::SecretBox<[u8; 32]>) {
        let wrapped = self
            .keystore
            .read()
            .expect("keystore lock poisoned")
            .wrap_root(root_key)
            .expect("wrapping the root key under a freshly-constructed keystore cannot fail");
        *self.wrapped_root.write().expect("wrapped root poisoned") = Some(wrapped);
    }

    /// Generate a node keypair, register its public id → wrapped-private-key
    /// mapping, and return the public key so the caller can also register
    /// it wherever the registry ends up storing node public keys (Node
    /// itself has no such field yet — see BUILD_LOG's "design problems
    /// found" for this session; not needed for read/reveal, which this
    /// function's caller is setting up).
    ///
    /// If the vault is currently unlocked, also promotes the new key into
    /// the hot set directly (the plaintext private key is already in hand
    /// here, unlike `restore_node_key_material`, which only ever receives
    /// the wrapped form and must re-derive the root key to unwrap it) —
    /// `node.create` (ADR-051) depends on this so a node created live, after
    /// unlock, is immediately usable by `entry.reveal`/`totp.code`, not only
    /// by `entry.create` (which needs no hot key at all, `04 §2`). Every
    /// pre-unlock caller (every existing test fixture) is unaffected:
    /// `is_locked()` is `true` until that fixture's own later `unlock()`
    /// call, so this block is simply skipped for them, exactly as before.
    pub fn seed_node_key(
        &self,
        root_key: &secrecy::SecretBox<[u8; 32]>,
        node_id: &str,
    ) -> x25519_dalek::PublicKey {
        let pair = credmgr_core::keys::generate_node_keypair();
        // ADR-079, custody rule 1: the orphan node's private half is never
        // wrapped, never resident and never written to `keys/nodes/`. A fixture
        // that "seeds" it gets exactly what `node.seal` needs — the public key —
        // and the private half is dropped (and zeroised) here, so there is no
        // way for this method to put it in the hot set.
        if node_id == ORPHAN_ID {
            self.seed_public_key_only(ORPHAN_ID, pair.public);
            return pair.public;
        }
        let wrapped = wrap_node_key(root_key.expose_secret(), node_id, &pair.private);
        self.node_wrapped_keys
            .write()
            .expect("node wrapped keys poisoned")
            .insert(node_id.to_string(), wrapped);
        self.node_public_keys
            .write()
            .expect("node public keys poisoned")
            .insert(node_id.to_string(), pair.public);
        if !self.is_locked() {
            self.hot_keys
                .write()
                .expect("hot keys poisoned")
                .insert(node_id.to_string(), pair.private.to_bytes());
        }
        pair.public
    }

    /// Register a public key with no corresponding wrapped private key at
    /// all — for the orphan node specifically, whose private half must
    /// never enter `node_wrapped_keys`/the hot set (`04_CRYPTO_AND_KEYS.md
    /// §5`: "the orphan key never enters the broker's hot key set";
    /// `seed_node_key` above always wraps and registers a private half
    /// too, which is correct for every *other* node but wrong here). A
    /// fixture calling this for `ORPHAN_ID` gets exactly what `node.seal`'s
    /// real dispatch path needs (`state.node_public_key(ORPHAN_ID)`) and
    /// nothing that could ever be unwrapped.
    pub fn seed_public_key_only(&self, node_id: &str, public: PublicKey) {
        self.node_public_keys
            .write()
            .expect("node public keys poisoned")
            .insert(node_id.to_string(), public);
    }

    /// A node's public key, available regardless of lock state — it is
    /// registry cleartext, not key material the hot set guards.
    pub fn node_public_key(&self, node_id: &str) -> Option<PublicKey> {
        self.node_public_keys
            .read()
            .expect("node public keys poisoned")
            .get(node_id)
            .copied()
    }

    // --- vault bootstrap (ADR-061) -----------------------------------------

    /// How long an unconfirmed `credmgr init` stays live before a retry must
    /// restart from `begin_init` — reuses `GATE_UNLOCK_TTL_SECONDS` rather
    /// than inventing a second unexplained window, the same reasoning that
    /// constant's own doc comment already applies to the gate-unlock case.
    pub const VAULT_INIT_CONFIRM_TTL_SECONDS: i64 = GATE_UNLOCK_TTL_SECONDS;

    /// Step 1 of `credmgr init` (ADR-061). Generates the root key and the
    /// `global` node's keypair, wraps the root key two ways — a **throwaway**
    /// `SoftwareKeystore` built from `passphrase` (never `self.keystore`,
    /// never stored; ADR-061's whole reason for a request-scoped keystore
    /// here) and a freshly generated recovery code — and wraps the node's
    /// private key under the root key. Nothing touches disk yet. Returns the
    /// plaintext recovery code exactly once; the caller must show it to the
    /// operator and pass it back to `confirm_init` before anything is
    /// written, the same "shown once, never re-fetchable" shape
    /// `gate_enroll_confirm` already uses.
    pub fn begin_init(
        &self,
        passphrase: SecretBox<String>,
        now: i64,
    ) -> Result<String, VaultInitError> {
        if self.paths.registry().exists() {
            return Err(VaultInitError::AlreadyInitialized);
        }
        if credmgr_store::paths::is_inside_git_working_tree(self.paths.root()) {
            return Err(VaultInitError::InsideGitWorkingTree);
        }

        let mut root_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut root_bytes);
        let root_key: SecretBox<[u8; 32]> = SecretBox::new(Box::new(root_bytes));
        root_bytes.zeroize();

        let node_pair = generate_node_keypair();

        // Request-scoped, discarded at the end of this function — never
        // becomes `self.keystore`, never read by anything else (ADR-061).
        let state_dir = self.state_dir.read().expect("state dir poisoned").clone();
        let throwaway_keystore = SoftwareKeystore::new(passphrase, state_dir);
        let wrapped_root_pass = throwaway_keystore
            .wrap_root(&root_key)
            .expect("wrapping the root key under a freshly-constructed keystore cannot fail");

        let mut recovery_code = generate_recovery_code();
        let wrapped_root_recovery =
            wrap_root_with_recovery_code(&recovery_code, root_key.expose_secret());
        let formatted_code = format_recovery_code(&recovery_code);
        recovery_code.zeroize();

        let wrapped_node_key =
            wrap_node_key(root_key.expose_secret(), GLOBAL_ID, &node_pair.private);
        // `node_pair.private` (a `StaticSecret`) zeroises on drop at the end
        // of this function, per this crate's existing convention — its only
        // further use is already captured, above, in `wrapped_node_key`.

        // ADR-079: the orphan node's keypair, private half sealed under the
        // root key into the cold-key file. Done here, while the root key is in
        // hand, so `confirm_init` needs nothing more than a write.
        let (orphan_public_key, orphan_cold_key) =
            credmgr_core::cold::generate_orphan_cold(root_key.expose_secret());

        let recovery_code_sha256 = sha256_of(formatted_code.as_bytes());

        *self.pending_init.lock().expect("pending init poisoned") = Some(PendingInit {
            root_key,
            node_public_key: node_pair.public,
            wrapped_root_pass,
            wrapped_root_recovery,
            wrapped_node_key,
            orphan_public_key,
            orphan_cold_key,
            recovery_code_sha256,
            expires_at: now + Self::VAULT_INIT_CONFIRM_TTL_SECONDS,
        });

        Ok(formatted_code)
    }

    /// Step 2 of `credmgr init` (ADR-061). On a matching recovery code,
    /// writes the vault to disk in the crash-safe order
    /// `04_CRYPTO_AND_KEYS.md §2.3` specifies — the key files, then the
    /// registry that names them, then the external generation counter that
    /// anchors it — and commits the same material into this **running**
    /// `BrokerState` via `load_key_material`/`set_registry`, so the vault
    /// this process just created is immediately usable without a restart.
    pub fn confirm_init(
        &self,
        recovery_code_input: &str,
        now: i64,
    ) -> Result<(), VaultInitConfirmError> {
        if self.paths.registry().exists() {
            return Err(VaultInitConfirmError::AlreadyInitialized);
        }

        let mut guard = self.pending_init.lock().expect("pending init poisoned");
        let still_live = match guard.as_ref() {
            Some(p) => p.expires_at > now,
            None => return Err(VaultInitConfirmError::NotPending),
        };
        if !still_live {
            *guard = None;
            return Err(VaultInitConfirmError::Expired);
        }

        // Plain equality, not a constant-time compare — a considered choice,
        // not an oversight (ADR-061): this is a same-process, no-network
        // "did you copy this down" check on a wrap that has already
        // succeeded cryptographically, not a remote authentication decision
        // with a timing oracle to defend against (unlike
        // `credmgr_core::signing::verify`, which guards exactly that and
        // does use a constant-time compare for exactly that reason).
        let input_hash = sha256_of(recovery_code_input.trim().as_bytes());
        if input_hash
            != guard
                .as_ref()
                .expect("checked Some above")
                .recovery_code_sha256
        {
            return Err(VaultInitConfirmError::RecoveryCodeMismatch);
        }

        let pending = guard.take().expect("checked Some above");
        drop(guard);

        let write_result = (|| -> Result<(), StoreError> {
            atomic::write(
                &self.paths.root_wrap_pass(),
                &pending.wrapped_root_pass.bytes,
            )?;
            atomic::write(
                &self.paths.root_wrap_recovery(),
                &pending.wrapped_root_recovery.to_bytes(),
            )?;
            atomic::write(
                &self.paths.node_key(GLOBAL_ID),
                &pending.wrapped_node_key.to_bytes(),
            )?;
            // ADR-079: the orphan cold key — a file nothing reads until the
            // registry written below names the `orphan` node, so a crash
            // before that leaves a stray file the next `credmgr init` (which
            // refuses only when `registry.json` exists) overwrites.
            atomic::write(&self.paths.orphan_key(), &pending.orphan_cold_key)?;

            // `global`'s own manifest — empty, but it must exist: every node
            // named in the registry needs one on disk, or a later
            // `verify_and_load_vault` (which iterates `doc.nodes.keys()`)
            // fails outright on the very first vault it ever tries to load.
            // Discovered by this ADR's own integration test driving that
            // exact load path, not assumed. Written and cross-bound before
            // the registry that references it — `manifest::save`'s own doc
            // comment: "the cross-binding is only as good as both sides
            // being updated in the same ... write that this manifest write
            // precedes."
            let manifest_binding = manifest::save(
                &self.paths,
                pending.root_key.expose_secret(),
                &ManifestBody::new(GLOBAL_ID),
            )?;
            // …and `orphan`'s, for the same reason: a sealed node's entries
            // become rows in it, and the registry names it from the first write.
            let orphan_binding = manifest::save(
                &self.paths,
                pending.root_key.expose_secret(),
                &ManifestBody::new(ORPHAN_ID),
            )?;

            let mut doc = RegistryDocument::new();
            doc.nodes.insert(
                GLOBAL_ID.to_string(),
                NodeDoc {
                    node: Node::global(),
                    created: now,
                    gate: GateDoc::default(),
                    pinned: None,
                    public_key: hex_encode(pending.node_public_key.as_bytes()),
                },
            );
            doc.manifests
                .insert(GLOBAL_ID.to_string(), manifest_binding);
            // ADR-079: the `orphan` node, public-only — its private half is in
            // `keys/cold/orphan.key` and nowhere else. Created here so
            // `node.seal` works in a vault `credmgr init` made (K-7).
            doc.nodes.insert(
                ORPHAN_ID.to_string(),
                NodeDoc {
                    node: Node::orphan(),
                    created: now,
                    gate: GateDoc::default(),
                    pinned: None,
                    public_key: hex_encode(pending.orphan_public_key.as_bytes()),
                },
            );
            doc.manifests.insert(ORPHAN_ID.to_string(), orphan_binding);
            doc.vault_generation = 1;
            registry_file::save(&self.paths, pending.root_key.expose_secret(), &doc)?;

            let state_dir = self.state_dir.read().expect("state dir poisoned").clone();
            FileGenerationCounter::new(state_dir).write(
                pending.root_key.expose_secret(),
                VAULT_GENERATION,
                doc.vault_generation,
            )?;

            self.set_registry(doc.to_core_registry());
            // ADR-063: from here on this vault lives on disk, and every
            // mutation this process makes to it is written through.
            *self.registry_meta.write().expect("registry meta poisoned") = doc.clone();
            self.durable
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let mut node_keys = HashMap::new();
            node_keys.insert(
                GLOBAL_ID.to_string(),
                (pending.wrapped_node_key.clone(), pending.node_public_key),
            );
            self.load_key_material(pending.wrapped_root_pass.clone(), node_keys);
            self.seed_public_key_only(ORPHAN_ID, pending.orphan_public_key);

            Ok(())
        })();

        write_result.map_err(VaultInitConfirmError::Store)
    }

    /// Load key material for a vault that already exists on disk — the
    /// counterpart to `verify_and_load_vault`'s plaintext-metadata load,
    /// deliberately kept separate (see that function's own doc comment on
    /// why key material was out of scope for it — ADR-061 is what lands it).
    /// Commits the wrapped root and every node's wrapped-private + public
    /// key in one step, so `unlock()`/`hot_node_key()` never observe a
    /// partially-loaded set.
    pub fn load_key_material(
        &self,
        wrapped_root: WrappedKey,
        node_keys: HashMap<String, (WrappedNodeKey, PublicKey)>,
    ) {
        *self.wrapped_root.write().expect("wrapped root poisoned") = Some(wrapped_root);
        let mut wrapped_map = self
            .node_wrapped_keys
            .write()
            .expect("node wrapped keys poisoned");
        let mut pub_map = self
            .node_public_keys
            .write()
            .expect("node public keys poisoned");
        for (id, (wrapped, public)) in node_keys {
            wrapped_map.insert(id.clone(), wrapped);
            pub_map.insert(id, public);
        }
    }

    // --- lock state --------------------------------------------------------

    pub fn is_locked(&self) -> bool {
        *self.locked.read().expect("locked flag poisoned")
    }

    /// `06_ACCESS_GRAPH.md §1a`. Independent of the vault-wide lock.
    pub fn lock_node(&self, node_id: &str) {
        self.locked_nodes
            .write()
            .expect("locked_nodes poisoned")
            .insert(node_id.to_string());
        let mut hot = self.hot_keys.write().expect("hot keys poisoned");
        if let Some(bytes) = hot.get_mut(node_id) {
            bytes.zeroize();
        }
    }

    pub fn unlock_node(&self, node_id: &str) {
        // `lock_node` zeroises this node's hot key IN PLACE, so clearing the lock
        // flag alone leaves the node "unlocked" with a key of 32 zero bytes — every
        // decrypt of its entries fails until the whole vault is unlocked again.
        // That went unnoticed while the ops that follow a node unlock (`update`,
        // `rotate`, `pending_accept`) only ever needed the node's PUBLIC key; ADR-078
        // made them read-modify-write, and the endpoint matrix caught it. So the key
        // is re-derived first, and only then does the node stop being locked. When
        // the root key is not resident (the whole vault is locked too) there is
        // nothing to re-derive from and `hot_node_key` still refuses on the vault
        // lock, which is the right answer.
        if let Ok(root_key) = self.reauth_root_key("node unlock") {
            if let Some(key) = self.unwrap_node_key_with_root(node_id, root_key.expose_secret()) {
                self.hot_keys
                    .write()
                    .expect("hot keys poisoned")
                    .insert(node_id.to_string(), key.to_bytes());
            }
        }
        self.locked_nodes
            .write()
            .expect("locked_nodes poisoned")
            .remove(node_id);
    }

    /// Attempt to unwrap the root key and, if no gate is confirmed-enrolled
    /// for [`GATE_SCOPE_VAULT`], derive every node's private key into the
    /// hot set immediately — `07 §3`'s five-step sequence, for a vault that
    /// never enrolled a gate at all (steps 2-3 don't apply; go straight from
    /// step 1 to step 4). On failure (wrong passphrase / tampered blob) the
    /// hot set is left exactly as it was — empty, if this is the first
    /// unlock attempt — "a wrong factor loads no node key" (I-15).
    ///
    /// Returns `Ok(true)` when a confirmed gate exists: the root key is
    /// unwrapped and held (`PendingGateUnlock`) but **not** yet used to
    /// derive any node key — the hot set stays exactly as it was, `07 §3`
    /// steps 2-4 are still ahead, and the caller (`ops::dispatch`) must
    /// report `two_factor_required` rather than "unlocked". `Ok(false)`
    /// means the vault is fully unlocked already, the pre-Phase-5 shape.
    pub fn unlock(&self, now: i64) -> Result<bool, KeystoreError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        // ADR-063, review C1: on a disk-backed vault the only unlock is the
        // passphrase one. This path unwraps with whatever keystore the
        // process holds — a test fixture's own, or the daemon's inert
        // placeholder — and must never be a way into a live vault.
        if self.is_durable() {
            return Err(KeystoreError::AuthenticationFailed);
        }
        let wrapped_root = self
            .wrapped_root
            .read()
            .expect("wrapped root poisoned")
            .clone();
        let Some(wrapped_root) = wrapped_root else {
            return Err(KeystoreError::Truncated);
        };
        let root_key = self
            .keystore
            .read()
            .expect("keystore lock poisoned")
            .unwrap_root(&wrapped_root, "vault unlock")?;

        if self.is_gate_confirmed(GATE_SCOPE_VAULT) {
            self.pending_gate_unlock
                .lock()
                .expect("pending gate unlock poisoned")
                .insert(
                    GATE_SCOPE_VAULT.to_string(),
                    PendingGateUnlock {
                        root_key,
                        expires_at: now + GATE_UNLOCK_TTL_SECONDS,
                    },
                );
            return Ok(true);
        }

        self.install_hot_keys_from_root(root_key.expose_secret())?;
        Ok(false)
    }

    /// `07 §3` steps 4-5, shared by the no-gate `unlock()` path and
    /// `gate_verify`'s success path: unwrap every node's private key under
    /// `root_key` and replace the hot set. The root key itself is never
    /// stored by this function — the caller's copy (a `SecretBox` in
    /// `unlock()`'s local, or `PendingGateUnlock` consumed by `gate_verify`)
    /// goes out of scope and zeroises right after this returns.
    fn install_hot_keys_from_root(&self, root_key: &[u8; 32]) -> Result<(), KeystoreError> {
        let wrapped_nodes = self
            .node_wrapped_keys
            .read()
            .expect("node wrapped keys poisoned")
            .clone();
        let mut new_hot = HashMap::new();
        for (node_id, wrapped) in &wrapped_nodes {
            // ADR-079, custody rule 1: whatever else is in the map, the orphan
            // node's private half never reaches the hot set.
            if node_id == ORPHAN_ID {
                continue;
            }
            let priv_key: StaticSecret = unwrap_node_key(root_key, node_id, wrapped)
                .map_err(|_| KeystoreError::AuthenticationFailed)?;
            new_hot.insert(node_id.clone(), priv_key.to_bytes());
        }

        *self.hot_keys.write().expect("hot keys poisoned") = new_hot;
        *self.locked.write().expect("locked flag poisoned") = false;
        Ok(())
    }

    // --- gate 2FA (`07_TWO_FACTOR.md §3-5`) ---------------------------------

    pub fn is_gate_confirmed(&self, scope: &str) -> bool {
        self.gate
            .read()
            .expect("gate poisoned")
            .get(scope)
            .is_some_and(|g| g.confirmed)
    }

    /// `07 §4` steps 1-2: generate a fresh secret and return its
    /// `otpauth://` URI, **not yet active** — `gate_enroll_confirm` must
    /// see one successful code before `unlock()` starts gating on it.
    /// Calling this again for a scope that already has an *unconfirmed*
    /// enrolment replaces it (the old secret was never activated, so there
    /// is nothing to preserve); calling it for an already-*confirmed* scope
    /// also replaces it — re-enrolling is exactly `07 §4`'s "device loss"
    /// path, and this function does not gate who may call it (`ops::dispatch`
    /// does, via capability checks, same as every other op).
    pub fn gate_enroll_begin(&self, scope: &str) -> String {
        let secret = generate_gate_secret();
        let totp = Totp::new_gate(secret);
        let uri = totp.otpauth_uri("CredMgr", scope);
        // ADR-064: a re-enrolment over a *confirmed* gate is staged apart
        // and replaces it only when confirmed, so a re-enrolment that is
        // started and abandoned never leaves the vault without its gate.
        if self.is_gate_confirmed(scope) {
            self.gate_pending
                .write()
                .expect("gate pending poisoned")
                .insert(scope.to_string(), totp);
            return uri;
        }
        self.gate.write().expect("gate poisoned").insert(
            scope.to_string(),
            GateEnrollment {
                totp,
                confirmed: false,
                recovery_hashes: Vec::new(),
            },
        );
        uri
    }

    /// `07 §4` steps 3-4: the first successful code activates the
    /// enrolment and issues 10 recovery codes, returned once — the caller
    /// (`ops::dispatch`) is responsible for never logging or re-serving
    /// them. The confirming code itself is recorded in the replay ledger
    /// (same as any other accepted code), so it cannot double as the very
    /// first real unlock's factor 2.
    pub fn gate_enroll_confirm(
        &self,
        scope: &str,
        code: &str,
        now: i64,
    ) -> Result<Vec<String>, GateEnrollError> {
        // ADR-064: a staged re-enrolment over a confirmed gate — verify
        // against the *new* secret, then swap it in with fresh recovery
        // codes; the old gate and its codes stop working at that moment.
        let staged = self
            .gate_pending
            .write()
            .expect("gate pending poisoned")
            .remove(scope);
        if let Some(totp) = staged {
            let Some(counter) = totp.verify(code, now.max(0) as u64) else {
                // Put it back: a mistyped code must not cancel the re-enrolment.
                self.gate_pending
                    .write()
                    .expect("gate pending poisoned")
                    .insert(scope.to_string(), totp);
                return Err(GateEnrollError::WrongCode);
            };
            self.gate_replay
                .write()
                .expect("gate replay poisoned")
                .insert((scope.to_string(), counter));
            let codes = generate_gate_recovery_codes();
            self.gate.write().expect("gate poisoned").insert(
                scope.to_string(),
                GateEnrollment {
                    totp,
                    confirmed: true,
                    recovery_hashes: codes
                        .iter()
                        .map(|c| Some(hash_gate_recovery_code(c)))
                        .collect(),
                },
            );
            return Ok(codes.iter().map(format_gate_recovery_code).collect());
        }

        let mut gate = self.gate.write().expect("gate poisoned");
        let entry = gate.get_mut(scope).ok_or(GateEnrollError::NotEnrolling)?;
        if entry.confirmed {
            return Err(GateEnrollError::NotEnrolling);
        }
        let Some(counter) = entry.totp.verify(code, now.max(0) as u64) else {
            return Err(GateEnrollError::WrongCode);
        };
        self.gate_replay
            .write()
            .expect("gate replay poisoned")
            .insert((scope.to_string(), counter));

        let codes = generate_gate_recovery_codes();
        entry.recovery_hashes = codes
            .iter()
            .map(|c| Some(hash_gate_recovery_code(c)))
            .collect();
        entry.confirmed = true;
        Ok(codes.iter().map(format_gate_recovery_code).collect())
    }

    /// `07 §3` step 3 + `§4`'s "any recovery code satisfies gate 2FA once,
    /// then is burned": completes a `vault.unlock` that returned
    /// `two_factor_required`. On success, derives the hot set from the root
    /// key `unlock()` set aside (`07 §3` steps 4-5) and grants this scope a
    /// default elevation window (`07 §5`).
    pub fn gate_verify(&self, scope: &str, code: &str, now: i64) -> Result<(), GateVerifyError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        let root_key = {
            let mut pending = self
                .pending_gate_unlock
                .lock()
                .expect("pending gate unlock poisoned");
            match pending.get(scope) {
                Some(p) if p.expires_at > now => {}
                Some(_) => {
                    pending.remove(scope); // expired — do not leave it around for a later retry.
                    return Err(GateVerifyError::NoChallengePending);
                }
                None => return Err(GateVerifyError::NoChallengePending),
            }

            if !self.consume_gate_code(scope, code, now, true) {
                return Err(GateVerifyError::WrongCode);
            }
            pending
                .remove(scope)
                .expect("presence just checked above under the same lock")
                .root_key
        };

        self.install_hot_keys_from_root(root_key.expose_secret())
            .map_err(|_| GateVerifyError::WrongCode)?;
        // ADR-063: the unlock is now complete — for a disk-backed vault the
        // root key stays resident until `lock()`, so writes can be persisted
        // without re-deriving it (and without the passphrase ever being kept).
        if self.is_durable() {
            *self.session_root.write().expect("session root poisoned") = Some(root_key);
        }
        self.elevate(scope, now, DEFAULT_ELEVATION_SECONDS);
        Ok(())
    }

    /// ADR-085 (4.3): a second factor **mid-session**. `gate_verify` completes a
    /// login that `vault.unlock` left pending; this is the other time a human
    /// needs to prove the second factor — when a node's `requireTwoFactor` policy
    /// asks for one and the vault is already open. It checks the same code the
    /// same way (TOTP window with the replay ledger, or a recovery code once),
    /// under the same lock, and grants the scope the default elevation window; it
    /// derives no key and mints no token. `Err(NoChallengePending)` is returned
    /// when no gate is confirmed (there is no factor to check).
    pub fn gate_step_up(&self, scope: &str, code: &str, now: i64) -> Result<(), GateVerifyError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        if !self.is_gate_confirmed(scope) {
            return Err(GateVerifyError::NoChallengePending);
        }
        if !self.consume_gate_code(scope, code, now, true) {
            return Err(GateVerifyError::WrongCode);
        }
        self.elevate(scope, now, DEFAULT_ELEVATION_SECONDS);
        Ok(())
    }

    /// ADR-088 (4b): the two unlock factors, checked on their own — the
    /// passphrase, then (when a gate is confirmed) a fresh authenticator code,
    /// never a recovery code — to authorise **one** decision while the vault stays
    /// locked. Returns the root key the passphrase yielded, so the caller can open
    /// the one value being released and sign its audit record; the caller drops it
    /// (zeroised) when done. Nothing becomes resident, no session or elevation is
    /// created, and the passphrase is never kept. Serialised with every other
    /// authentication step, like `unlock_with_passphrase`.
    pub fn approval_factors(
        &self,
        passphrase: SecretBox<String>,
        code: Option<&str>,
        now: i64,
    ) -> Result<SecretBox<[u8; 32]>, ApprovalFactorError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        // ADR-076 / ADR-092: like an unlock, this reads the root wrap, which a
        // crash mid-rotation may have left half-replaced. Finish (or drop) the
        // rotation first; if that cannot be done, decide nothing.
        self.recover_interrupted_rotation()
            .map_err(|_| ApprovalFactorError::RotationRecovery)?;
        let root = self
            .root_from_passphrase(passphrase, "approval decision")
            .map_err(|_| ApprovalFactorError::WrongPassphrase)?;
        if self.is_gate_confirmed(GATE_SCOPE_VAULT) {
            let Some(code) = code else {
                return Err(ApprovalFactorError::SecondFactorRequired);
            };
            if !self.consume_gate_code(GATE_SCOPE_VAULT, code, now, false) {
                return Err(ApprovalFactorError::WrongCode);
            }
        }
        Ok(root)
    }

    /// ADR-088: writes the authenticator step [`BrokerState::approval_factors`]
    /// just spent through to disk under `root_key`, so a restart cannot accept it
    /// again. The vault is locked, so this is the one persist that does not use
    /// the resident session root.
    pub fn persist_spent_step(&self, root_key: &[u8; 32], now: i64) -> Result<(), StoreError> {
        self.persist_with_root(root_key, now)
    }

    /// How long a granted elevation lasts (`07 §5`: default 5 minutes).
    #[must_use]
    pub fn elevation_seconds(&self) -> i64 {
        DEFAULT_ELEVATION_SECONDS
    }

    /// Checks `code` against the scope's current TOTP window (respecting
    /// the replay ledger) and, failing that, its unconsumed recovery codes —
    /// `07 §4`: "Any recovery code satisfies gate 2FA once, then is burned."
    /// `true` iff one of the two matched and was recorded/burned.
    fn consume_gate_code(&self, scope: &str, code: &str, now: i64, allow_recovery: bool) -> bool {
        let totp_step = {
            let gate = self.gate.read().expect("gate poisoned");
            let Some(entry) = gate.get(scope) else {
                return false;
            };
            entry.totp.verify(code, now.max(0) as u64)
        };
        if let Some(counter) = totp_step {
            let floor = self
                .gate_replay_floor
                .read()
                .expect("gate replay floor poisoned")
                .get(scope)
                .copied();
            if floor.is_some_and(|f| counter <= f) {
                return false; // ADR-064: at or below the last step accepted before a restart.
            }
            let mut replay = self.gate_replay.write().expect("gate replay poisoned");
            let key = (scope.to_string(), counter);
            if replay.contains(&key) {
                return false; // `07 §5`: a replayed code is refused, not re-accepted.
            }
            replay.insert(key);
            return true;
        }

        // ADR-088: a decision made while the vault is locked takes the
        // authenticator code only — burning a recovery code cannot be persisted
        // from here, so it is not offered.
        if !allow_recovery {
            return false;
        }
        let Ok(parsed) = parse_gate_recovery_code(code) else {
            return false;
        };
        let hash = hash_gate_recovery_code(&parsed);
        let mut gate = self.gate.write().expect("gate poisoned");
        let Some(entry) = gate.get_mut(scope) else {
            return false;
        };
        if let Some(slot) = entry.recovery_hashes.iter_mut().find(|h| **h == Some(hash)) {
            *slot = None; // single-use — burned on the first successful match.
            return true;
        }
        false
    }

    /// `07 §5`: "a scoped elevation ... default 5 min." `duration_seconds`
    /// of `0` grants no window at all (`is_elevated` sees an already-past
    /// expiry) — "`0` = every operation re-challenges."
    pub fn elevate(&self, scope: &str, now: i64, duration_seconds: i64) {
        self.elevations
            .write()
            .expect("elevations poisoned")
            .insert(scope.to_string(), now + duration_seconds);
    }

    /// Drop every gate elevation — `07_TWO_FACTOR.md §5`: on lock, and on a
    /// node policy change (ADR-071), a fresh second factor is required.
    pub fn drop_elevations(&self) {
        self.elevations
            .write()
            .expect("elevations poisoned")
            .clear();
    }

    pub fn is_elevated(&self, scope: &str, now: i64) -> bool {
        self.elevations
            .read()
            .expect("elevations poisoned")
            .get(scope)
            .is_some_and(|&expires_at| expires_at > now)
    }

    /// The broker-start integrity check (`04_CRYPTO_AND_KEYS.md §6a`, I-19,
    /// I-20): load `registry.json` (HMAC-verified), check its
    /// `vaultGeneration` against the external counter, then load and
    /// cross-bind every node's `manifest.json`. Any failure — a tampered
    /// manifest, a rolled-back registry, a broken cross-binding — returns
    /// the named [`StoreError`] and **leaves this `BrokerState` untouched**:
    /// verification happens entirely against locally-built values first,
    /// and only a fully-verified result is committed to `self.registry`/
    /// `self.manifests`, the same peek-then-commit shape `node.restore`
    /// already uses for the same reason (no half-loaded state on failure).
    ///
    /// Deliberately scoped to the plaintext metadata side only — the
    /// "locked graph" data (`03_DATA_MODEL.md §2`). It does not touch node
    /// key material: Phase 3 has never written an on-disk node-key file
    /// (`BUILD_LOG.md`'s Session 5 trap note), so there is nothing for this
    /// function to load there yet — that lands with Phase 4/5's vault
    /// bootstrap. Call it with a [`crate::state::BrokerState::reauth_root_key`]-obtained
    /// key, used once and dropped, exactly like the seal/restore call sites.
    pub fn verify_and_load_vault(
        &self,
        root_key: &[u8; 32],
        counter: &dyn GenerationCounter,
    ) -> Result<(), StoreError> {
        let doc = registry_file::load(&self.paths, root_key)?;
        check_and_advance(root_key, counter, doc.vault_generation)?;

        let mut loaded_manifests = HashMap::new();
        for node_id in doc.nodes.keys() {
            let manifest_doc = manifest::load(&self.paths, root_key, node_id)?;
            manifest::verify_cross_binding(&doc, node_id, &manifest_doc)?;
            loaded_manifests.insert(node_id.clone(), manifest_doc.body);
        }

        // Every check passed — commit both maps together so no reader ever
        // observes a registry with only some of its manifests loaded.
        *self.registry.write().expect("registry poisoned") = doc.to_core_registry();
        *self.manifests.write().expect("manifests poisoned") = loaded_manifests;
        Ok(())
    }

    /// Zeroises every hot-set buffer **in place** rather than dropping the
    /// map — the Phase 3 exit gate wants zeroisation asserted by inspecting
    /// the buffers, which requires them to still exist, now all-zero.
    ///
    /// Also drops every in-flight gate challenge and every elevation
    /// (`07 §5`/`§8`: "lock, sleep and screen lock each drop every
    /// elevation") — ADR-043 already funnels idle timeout, explicit lock,
    /// and sleep/screen-lock/session-end (`external_lock_signal`) through
    /// this one function, so gating both here covers all three by
    /// construction rather than needing three separate call sites.
    pub fn lock(&self) {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        self.lock_inner();
    }

    /// [`BrokerState::lock`] for a caller that already holds `auth_lock`
    /// (a rotation whose roll-forward failed, ADR-076).
    fn lock_inner(&self) {
        // ADR-063: the resident root key goes first (zeroised on drop).
        self.session_root
            .write()
            .expect("session root poisoned")
            .take();
        // ADR-064 (review L5): a staged re-enrolment does not outlive the unlock.
        self.gate_pending
            .write()
            .expect("gate pending poisoned")
            .clear();
        let mut hot = self.hot_keys.write().expect("hot keys poisoned");
        for bytes in hot.values_mut() {
            bytes.zeroize();
        }
        *self.locked.write().expect("locked flag poisoned") = true;
        // ADR-079 (4a): count the lock — strictly AFTER the flag above is set, and
        // before the void at the end of this function. The order is the whole
        // argument. A decider reads the epoch, then checks `is_locked()`, then
        // stores its value. If it read the epoch *before* this line, its store is
        // either refused (epoch moved) or lands before the void and is voided by
        // it. If it read the epoch *after* this line, the flag was already set
        // (this thread wrote it first, and the SeqCst increment publishes that
        // write), so its `is_locked()` check refuses. Bumping the epoch any
        // earlier would open a window in which a decider sees the new epoch and an
        // unlocked flag, and stores after the void.
        self.lock_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.pending_gate_unlock
            .lock()
            .expect("pending gate unlock poisoned")
            .clear();
        self.elevations
            .write()
            .expect("elevations poisoned")
            .clear();
        // ADR-056: a login session does not outlive the unlock it came from.
        let mut session_tokens = self
            .session_tokens
            .write()
            .expect("session tokens poisoned");
        for id in session_tokens.drain() {
            self.tokens.revoke(&id);
        }
        drop(session_tokens);
        self.session_last_used
            .write()
            .expect("session last used poisoned")
            .clear();
        // ADR-079 (4a): last, once `locked` is already true. A value decrypted
        // for an approval is plaintext a locked vault must not hold — the human
        // who approved it has walked away (idle, sleep, explicit lock).
        self.void_staged_approvals();
    }

    /// Drops (zeroising) every value staged for an approved request, and turns
    /// each such approval into a denial the requester is told was caused by the
    /// lock. Pending (undecided) requests are left alone: they hold no value,
    /// nobody can decide them on a locked live vault, and they expire by
    /// default-deny at their own TTL.
    fn void_staged_approvals(&self) {
        let mut approvals = self.approvals.write().expect("approvals poisoned");
        for slot in approvals.values_mut() {
            // The taken value is dropped at the end of this statement, which
            // zeroises it (`SecretBox`).
            if slot.staged.take().is_some() {
                slot.record.decision = Some(false);
                slot.record.voided_by_lock = true;
            }
        }
    }

    /// The unwrapped private key for `node_id`, if the vault (and the node
    /// individually) is unlocked and that node's key is in the hot set.
    /// Returns a fresh `StaticSecret` built from the hot bytes for one use;
    /// the `StaticSecret`'s own `Drop` (the `zeroize` feature,
    /// `crates/core`'s existing convention) zeroises that transient copy —
    /// the persistent copy this function reads from is the one `lock()`
    /// zeroises in place.
    pub fn hot_node_key(&self, node_id: &str) -> Option<StaticSecret> {
        if self.is_locked() || self.is_node_locked(node_id) {
            return None;
        }
        self.hot_keys
            .read()
            .expect("hot keys poisoned")
            .get(node_id)
            .map(|bytes| StaticSecret::from(*bytes))
    }

    pub fn is_node_locked(&self, node_id: &str) -> bool {
        self.locked_nodes
            .read()
            .expect("locked_nodes poisoned")
            .contains(node_id)
    }

    /// Unwraps one node's private key directly from an already-obtained
    /// `root_key`, without touching (or requiring anything already present
    /// in) the hot key set — the same per-node unwrap `unlock()` performs
    /// for every node, done here for exactly one, for a caller
    /// (approval-on-demand, ADR-042) that must decrypt precisely one entry
    /// while the vault stays locked. The returned `StaticSecret` is never
    /// stored; its own `Drop` zeroises it once the caller is done.
    pub fn unwrap_node_key_with_root(
        &self,
        node_id: &str,
        root_key: &[u8; 32],
    ) -> Option<StaticSecret> {
        let wrapped = self
            .node_wrapped_keys
            .read()
            .expect("node wrapped keys poisoned")
            .get(node_id)
            .cloned()?;
        unwrap_node_key(root_key, node_id, &wrapped).ok()
    }

    // --- approval-on-demand (F-15, ADR-042) ---------------------------------

    /// `"rq_"` + 16 random bytes hex: a 128-bit id (ADR-079, 4a). It used to be
    /// 6 bytes (`07 §5a`), which is 48 bits — enough to tell requests apart, not
    /// enough to be a capability. A request id is now the thing a requester
    /// holds to take its value, so it is drawn from the OS RNG at full width.
    fn new_approval_id() -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let mut s = String::from("rq_");
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Zeroises (by dropping) the staged value of every request whose TTL has
    /// passed. A staged value is plaintext, so "expired" must not wait for the
    /// requester's next read to be noticed (ADR-079, 4a): every approval accessor
    /// calls this first, and `tick_autolock` calls it on a timer through
    /// [`BrokerState::expire_staged_approvals`]. The *record* is kept — the
    /// requester is still told `expired` once.
    fn drop_expired_staged(approvals: &mut HashMap<String, ApprovalSlot>, now: i64) {
        for slot in approvals.values_mut() {
            if now >= slot.record.expires_at {
                slot.staged = None;
            }
        }
    }

    /// The timer-driven half of [`Self::drop_expired_staged`], called from
    /// `tick_autolock`: a value staged for an approval nobody came back for is
    /// zeroised when its TTL ends, not whenever somebody next happens to ask.
    pub fn expire_staged_approvals(&self, now: i64) {
        let mut approvals = self.approvals.write().expect("approvals poisoned");
        Self::drop_expired_staged(&mut approvals, now);
    }

    /// How many approvals currently hold a decrypted value. A count only — it
    /// exposes nothing — for tests that must show a lock, an expiry or a
    /// consumption really dropped the value, not merely hid it.
    #[cfg(feature = "test-utils")]
    pub fn staged_approval_count_for_test(&self) -> usize {
        self.approvals
            .read()
            .expect("approvals poisoned")
            .values()
            .filter(|slot| slot.staged.is_some())
            .count()
    }

    /// How many approval requests are on record at all, decided or not.
    #[cfg(feature = "test-utils")]
    pub fn approval_count_for_test(&self) -> usize {
        self.approvals.read().expect("approvals poisoned").len()
    }

    /// The current lock epoch — see the `lock_epoch` field. An approving
    /// decision reads this before it checks the lock state or touches a key and
    /// hands it back in [`ApprovalVerdict::Approve`].
    pub fn lock_epoch(&self) -> u64 {
        self.lock_epoch.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The request for `(node_id, entry_id)`, if one is on record at all —
    /// reused so a caller retrying `entry.reveal` while a decision is still
    /// pending sees the *same* request rather than spawning a fresh
    /// notification on every retry, and so a decision made since the
    /// caller's last try is visible on this one. Creates one, undecided, if
    /// none exists yet. Deliberately does **not** prune or otherwise treat
    /// an expired-and-undecided record specially — "defaults to deny" is a
    /// terminal outcome the caller (`ops::reveal_via_approval`) must be able
    /// to observe and report exactly once, which pruning it away silently
    /// here would prevent (the caller would just see "no record" and start
    /// a fresh, unbounded TTL — never actually denying anything). Returned
    /// by value so the caller can read `decision`/`expires_at` without
    /// holding the lock this method took internally.
    pub fn approval_for_reveal(
        &self,
        node_id: &str,
        entry_id: &str,
        cwd: Option<String>,
        request_key: &str,
        fields: Option<Vec<String>>,
        now: i64,
    ) -> PendingApproval {
        let mut approvals = self.approvals.write().expect("approvals poisoned");
        Self::drop_expired_staged(&mut approvals, now);
        if let Some(existing) = approvals.values().find(|a| {
            a.record.node_id == node_id
                && a.record.entry_id == entry_id
                && a.record.request_key == request_key
        }) {
            return existing.record.clone();
        }
        if approvals.len() >= MAX_APPROVAL_SLOTS {
            if let Some(oldest) = approvals
                .iter()
                .filter(|(_, a)| a.record.decision.is_none())
                .min_by_key(|(_, a)| a.record.created)
                .map(|(k, _)| k.clone())
            {
                approvals.remove(&oldest);
            }
        }
        let id = Self::new_approval_id();
        let record = PendingApproval {
            id: id.clone(),
            node_id: node_id.to_string(),
            entry_id: entry_id.to_string(),
            cwd,
            request_key: request_key.to_string(),
            fields,
            created: now,
            expires_at: now + APPROVAL_TTL_SECONDS,
            decision: None,
            voided_by_lock: false,
        };
        approvals.insert(
            id,
            ApprovalSlot {
                record: record.clone(),
                staged: None,
            },
        );
        record
    }

    /// A request that has reached a terminal state — decided, or expired
    /// without a decision — is only useful to its caller for one more read;
    /// after that it must not keep matching future `approval_for_reveal`
    /// calls for the same `(node, entry)` pair (which would otherwise wedge
    /// every future reveal of that pair behind a decision nobody can act on
    /// any more, or silently re-serve a stale denial). Called by
    /// `ops::reveal_via_approval` immediately after it reports a terminal
    /// state to the requester.
    pub fn discard_approval(&self, request_id: &str) {
        // Removing the slot drops any staged value with it (zeroised).
        self.approvals
            .write()
            .expect("approvals poisoned")
            .remove(request_id);
    }

    /// The request named `request_id`, without creating or mutating
    /// anything, and only if it has not yet expired — used by
    /// `vault.approval_decide` to learn which node the decision is about
    /// (so it can gate on `Capability::Admin` for *that* node) before
    /// recording anything. An expired request cannot be decided even if it
    /// still physically sits in the map awaiting the requester's next
    /// `entry.reveal` to discard it.
    pub fn peek_approval(&self, request_id: &str, now: i64) -> Option<PendingApproval> {
        self.approvals
            .read()
            .expect("approvals poisoned")
            .get(request_id)
            .filter(|a| now < a.record.expires_at)
            .map(|a| a.record.clone())
    }

    /// Every request still waiting for a human (ADR-090): unexpired and
    /// undecided, oldest first. Read-only — it creates, prunes and decides
    /// nothing, and it carries no value (a [`PendingApproval`] never does).
    pub fn pending_approvals(&self, now: i64) -> Vec<PendingApproval> {
        let mut live: Vec<PendingApproval> = self
            .approvals
            .read()
            .expect("approvals poisoned")
            .values()
            .map(|slot| &slot.record)
            .filter(|r| r.decision.is_none() && now < r.expires_at)
            .cloned()
            .collect();
        live.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
        live
    }

    /// Records a human decision on a still-live (unexpired), not-yet-decided
    /// request — "creates no session and no elevation" (`07 §5a`): a request
    /// is answerable exactly once. `Err` for an unknown, expired (removed
    /// here, since nothing else was ever going to act on it again) or
    /// already-decided id, so the caller (`vault.approval_decide`) can tell
    /// those apart in its response.
    ///
    /// An approval carries the value it releases (ADR-079, 4a), decrypted by
    /// the decider before this call, and is stored only if the vault has not
    /// locked since the decider read [`BrokerState::lock_epoch`]. The check and
    /// the store happen under the same lock `lock()` takes to void staged
    /// values, and `lock()` bumps the epoch before it voids — so whichever way
    /// the two interleave, a value staged by an approval does not survive a lock.
    pub fn decide_approval(
        &self,
        request_id: &str,
        verdict: ApprovalVerdict,
        now: i64,
    ) -> Result<(), ApprovalDecideError> {
        let mut approvals = self.approvals.write().expect("approvals poisoned");
        Self::drop_expired_staged(&mut approvals, now);
        let Some(slot) = approvals.get_mut(request_id) else {
            return Err(ApprovalDecideError::NotFound);
        };
        if now >= slot.record.expires_at {
            approvals.remove(request_id);
            return Err(ApprovalDecideError::NotFound);
        }
        if slot.record.decision.is_some() {
            return Err(ApprovalDecideError::AlreadyDecided);
        }
        match verdict {
            ApprovalVerdict::Deny => {
                slot.record.decision = Some(false);
            }
            ApprovalVerdict::Approve { staged, lock_epoch } => {
                if self.lock_epoch() != lock_epoch {
                    // `staged` is dropped here, which zeroises it.
                    return Err(ApprovalDecideError::LockedMeanwhile);
                }
                slot.record.decision = Some(true);
                slot.staged = Some(staged);
            }
        }
        Ok(())
    }
    /// Read the staged value of an approved request **without consuming it**
    /// (C1, ADR-079 amendment). The retry builds its whole answer from the staged
    /// document first and consumes the approval only once that answer exists: a
    /// malformed request (an unknown `fieldIds` entry) must not burn the one-time
    /// approval a human just gave.
    pub fn with_approved<R>(
        &self,
        request_id: &str,
        now: i64,
        f: impl FnOnce(&SecretBox<String>) -> R,
    ) -> Option<R> {
        let mut approvals = self.approvals.write().expect("approvals poisoned");
        Self::drop_expired_staged(&mut approvals, now);
        let slot = approvals.get(request_id)?;
        let live = slot.record.decision == Some(true) && now < slot.record.expires_at;
        if !live {
            return None;
        }
        slot.staged.as_ref().map(f)
    }

    /// Consumes an approved, still-live request and hands back the value that
    /// was staged for it when it was approved — "one entry, one field, once"
    /// (`07 §5a`). The slot is removed, so the value exists exactly once more:
    /// in the caller's hands. `None` for anything else (pending, denied, voided
    /// by a lock, expired or unknown); the caller is expected to have already
    /// branched on `approval_for_reveal`'s `decision` field before calling this,
    /// so a `None` here only means "raced with expiry between the two calls" —
    /// the caller discards the record itself in that case, same as any other
    /// terminal read.
    ///
    /// Never re-derives a key (ADR-079, 4a): on a locked live vault there is no
    /// root key to derive one from, and the decision to release was already
    /// taken, with the key, when the human approved.
    pub fn take_approved(&self, request_id: &str, now: i64) -> Option<SecretBox<String>> {
        let mut approvals = self.approvals.write().expect("approvals poisoned");
        Self::drop_expired_staged(&mut approvals, now);
        let live = approvals.get(request_id).is_some_and(|slot| {
            slot.record.decision == Some(true)
                && now < slot.record.expires_at
                && slot.staged.is_some()
        });
        if !live {
            return None;
        }
        approvals.remove(request_id).and_then(|slot| slot.staged)
    }

    // --- auto-lock (ADR-030, ADR-043) ---------------------------------------

    pub fn vault_idle_seconds(&self) -> u32 {
        *self
            .vault_idle_seconds
            .read()
            .expect("vault idle seconds poisoned")
    }

    pub fn set_vault_idle_seconds(&self, seconds: u32) {
        *self
            .vault_idle_seconds
            .write()
            .expect("vault idle seconds poisoned") = seconds;
    }

    /// Records that the broker just did something for `node_id` at `now` —
    /// called once per request (`server::handle_request`), for both the
    /// vault-wide idle clock and that node's own, so an active session in
    /// one node never gets silently timed out by another node's silence.
    pub fn touch_activity(&self, node_id: &str, now: i64) {
        *self.last_activity.write().expect("last activity poisoned") = now;
        self.node_last_activity
            .write()
            .expect("node last activity poisoned")
            .insert(node_id.to_string(), now);
    }

    /// The idle-timeout half of ADR-030/ADR-043: locks the vault if it has
    /// been idle past `vault_idle_seconds`, and individually locks any node
    /// whose own `NodePolicy::lock_after_seconds` has elapsed since that
    /// node's last activity. A node with no recorded activity yet is not
    /// timed out by this call — `touch_activity` is what starts its clock,
    /// consistent with "idle" meaning "went quiet", not "was never used".
    /// Returns the nodes individually locked by this tick, for callers that
    /// want to log or test what happened.
    pub fn tick_autolock(&self, now: i64) -> Vec<String> {
        self.expire_idle_sessions(now);
        // ADR-079 (4a): a value staged for an approval nobody retried is plaintext
        // sitting in memory — drop it when its TTL ends, on this timer, not only
        // when somebody next asks about it.
        self.expire_staged_approvals(now);
        let last = *self.last_activity.read().expect("last activity poisoned");
        if last != 0 && now.saturating_sub(last) >= self.vault_idle_seconds() as i64 {
            self.lock();
        }

        let mut newly_locked = Vec::new();
        let thresholds: Vec<(String, u32)> = self
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .values()
            .filter_map(|n| n.policy.lock_after_seconds.map(|s| (n.id.clone(), s)))
            .collect();
        let node_activity = self
            .node_last_activity
            .read()
            .expect("node last activity poisoned")
            .clone();
        for (node_id, threshold_seconds) in thresholds {
            let Some(&last) = node_activity.get(&node_id) else {
                continue;
            };
            if !self.is_node_locked(&node_id)
                && now.saturating_sub(last) >= threshold_seconds as i64
            {
                self.lock_node(&node_id);
                newly_locked.push(node_id);
            }
        }
        newly_locked
    }

    /// The one entry point sleep, screen-lock and session-end all reduce to
    /// (ADR-043) — an unconditional, immediate vault lock, regardless of any
    /// idle timer's state. Phase 5's native shell calls this from each of
    /// the three OS notifications it subscribes to.
    pub fn external_lock_signal(&self, _reason: &str) {
        self.lock();
    }

    #[cfg(feature = "test-utils")]
    pub fn hot_key_bytes_for_test(&self, node_id: &str) -> Option<[u8; 32]> {
        self.hot_keys
            .read()
            .expect("hot keys poisoned")
            .get(node_id)
            .copied()
    }

    #[cfg(feature = "test-utils")]
    pub fn hot_key_node_ids_for_test(&self) -> Vec<String> {
        self.hot_keys
            .read()
            .expect("hot keys poisoned")
            .keys()
            .cloned()
            .collect()
    }

    // --- write serialisation (F-9) ------------------------------------------

    /// The exclusive lock for `node_id`'s writes. A caller holds the
    /// returned guard for the whole read-check-write sequence of a mutating
    /// op, so a concurrent writer either sees the pre-write state (and gets
    /// `conflict` off a generation it can no longer match) or the post-write
    /// state — never a value torn between the two.
    pub fn node_write_lock(&self, node_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self
            .node_write_locks
            .lock()
            .expect("node write locks poisoned");
        locks
            .entry(node_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    // --- pending tray (F-1) -------------------------------------------------

    pub fn add_pending(&self, node_id: &str, entry: PendingEntry) {
        self.pending
            .write()
            .expect("pending poisoned")
            .entry(node_id.to_string())
            .or_default()
            .push(entry);
    }

    pub fn list_pending(&self, node_id: &str) -> Vec<PendingEntry> {
        self.pending
            .read()
            .expect("pending poisoned")
            .get(node_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Removes and returns the named pending entry, if it exists.
    pub fn take_pending(&self, node_id: &str, entry_id: &str) -> Option<PendingEntry> {
        let mut pending = self.pending.write().expect("pending poisoned");
        let list = pending.get_mut(node_id)?;
        let idx = list.iter().position(|e| e.id == entry_id)?;
        Some(list.remove(idx))
    }

    // --- manifest mutation (F-9's generation, and F-1's accept path) -------

    pub fn manifest_generation(&self, node_id: &str) -> Option<u64> {
        self.manifests
            .read()
            .expect("manifests poisoned")
            .get(node_id)
            .map(|m| m.generation)
    }

    /// The next vault-global ref (`03_DATA_MODEL.md §3`: "unique vault-wide,
    /// never reused"), monotonic for the broker's in-memory lifetime. Phase 3
    /// has no persisted `deletedRefs` ledger yet (there is no `entry.remove`
    /// op built this session) — a real one is Phase 4/CLI-adjacent work,
    /// once entries can be removed.
    pub fn next_ref(&self) -> u32 {
        self.next_ref.fetch_add(1, Ordering::SeqCst)
    }

    /// Insert a newly-accepted entry into `node_id`'s manifest (creating the
    /// manifest if this is the node's first entry), bump its generation, and
    /// return the new generation.
    pub fn insert_manifest_entry(&self, node_id: &str, entry: ManifestEntry) -> u64 {
        let mut manifests = self.manifests.write().expect("manifests poisoned");
        let body = manifests
            .entry(node_id.to_string())
            .or_insert_with(|| ManifestBody::new(node_id));
        body.entries.push(entry);
        body.recount();
        body.generation += 1;
        body.generation
    }

    /// ADR-072: record the node's note digest (`None` = no note) and bump
    /// the manifest generation — a note write is a node write (F-9).
    pub fn set_manifest_notes(&self, node_id: &str, digest: Option<String>) -> u64 {
        let mut manifests = self.manifests.write().expect("manifests poisoned");
        let body = manifests
            .entry(node_id.to_string())
            .or_insert_with(|| ManifestBody::new(node_id));
        body.notes_sha256 = digest;
        body.generation += 1;
        body.generation
    }

    /// The note digest the (HMAC-verified) manifest records for `node_id`.
    pub fn manifest_notes_digest(&self, node_id: &str) -> Option<String> {
        self.manifests
            .read()
            .expect("manifests poisoned")
            .get(node_id)
            .and_then(|m| m.notes_sha256.clone())
    }

    /// Apply `mutate` to the named entry in `node_id`'s manifest and bump
    /// the generation. `None` if the node or the entry does not exist.
    pub fn update_manifest_entry(
        &self,
        node_id: &str,
        entry_id: &str,
        mutate: impl FnOnce(&mut ManifestEntry),
    ) -> Option<u64> {
        let mut manifests = self.manifests.write().expect("manifests poisoned");
        let body = manifests.get_mut(node_id)?;
        let entry = body.entries.iter_mut().find(|e| e.id == entry_id)?;
        mutate(entry);
        // ADR-078: an update can change what `counts.totp` should be (a rotate
        // that turns a text value into a TOTP seed), and it used to leave the
        // count stale. One recount, shared with insert and remove.
        body.recount();
        body.generation += 1;
        Some(body.generation)
    }

    /// Remove entries matching `ids` from `node_id`'s manifest (used by
    /// `node.restore` to undo exactly the entries a matching seal deposited
    /// into orphan — never "everything currently in orphan").
    pub fn remove_manifest_entries(&self, node_id: &str, ids: &[String]) {
        let mut manifests = self.manifests.write().expect("manifests poisoned");
        if let Some(body) = manifests.get_mut(node_id) {
            body.entries.retain(|e| !ids.contains(&e.id));
            body.recount();
            body.generation += 1;
        }
    }

    // --- sealing (F-4, F-8) --------------------------------------------------

    /// Re-derive `RK` from the wrapped blob via the keystore — for a caller
    /// that needs the literal root key for one `crates/store` signing call
    /// (the archive meta HMAC) even though the hot set only ever holds
    /// *derived* node keys (`04_CRYPTO_AND_KEYS.md §6`: "RK is not kept
    /// resident"). Distinct from `unlock()`, which does the same unwrap but
    /// then also derives and stores every node's hot key; this returns the
    /// transient `RK` alone, for a caller that uses it once and lets it drop.
    pub fn reauth_root_key(
        &self,
        reason: &str,
    ) -> Result<secrecy::SecretBox<[u8; 32]>, KeystoreError> {
        // ADR-063: a live vault's root key is resident while it is unlocked,
        // and nowhere else — a locked disk-backed vault answers at once,
        // without an Argon2id derivation (review M1: every request used to
        // pay one, which any local caller could turn into memory exhaustion).
        if let Some(root) = self
            .session_root
            .read()
            .expect("session root poisoned")
            .as_ref()
        {
            return Ok(secrecy::SecretBox::new(Box::new(*root.expose_secret())));
        }
        if self.is_durable() {
            return Err(KeystoreError::AuthenticationFailed);
        }
        let wrapped_root = self
            .wrapped_root
            .read()
            .expect("wrapped root poisoned")
            .clone();
        let Some(wrapped_root) = wrapped_root else {
            return Err(KeystoreError::Truncated);
        };
        self.keystore
            .read()
            .expect("keystore lock poisoned")
            .unwrap_root(&wrapped_root, reason)
    }

    pub fn remove_node(&self, node_id: &str) -> Option<Node> {
        self.registry
            .write()
            .expect("registry poisoned")
            .nodes
            .remove(node_id)
    }

    pub fn insert_node(&self, node: Node) {
        self.registry
            .write()
            .expect("registry poisoned")
            .nodes
            .insert(node.id.clone(), node);
    }

    /// Removes and returns the one grant with `grant_id`, if it exists —
    /// `ops::dispatch`'s `grant.revoke`, `06_ACCESS_GRAPH.md §6`:
    /// "Revocation is one click and takes effect on the next request — no
    /// re-encryption."
    pub fn revoke_grant(&self, grant_id: &str) -> Option<Grant> {
        let mut registry = self.registry.write().expect("registry poisoned");
        let idx = registry.grants.iter().position(|g| g.id == grant_id)?;
        Some(registry.grants.remove(idx))
    }

    /// Removes and returns every grant touching `node_id` as either endpoint
    /// — `06_ACCESS_GRAPH.md §6`: "Grants ... do not survive seal".
    pub fn revoke_grants_touching(&self, node_id: &str) -> Vec<Grant> {
        let mut registry = self.registry.write().expect("registry poisoned");
        let mut revoked = Vec::new();
        registry.grants.retain(|g| {
            let touches = g.from == node_id || g.to.node_id() == node_id;
            if touches {
                revoked.push(g.clone());
            }
            !touches
        });
        revoked
    }

    pub fn take_manifest(&self, node_id: &str) -> Option<ManifestBody> {
        self.manifests
            .write()
            .expect("manifests poisoned")
            .remove(node_id)
    }

    /// Removes a node's key material from every in-memory map — the hot
    /// bytes, the wrapped private key, the public key, and its individual
    /// lock flag — and returns the wrapped+public pair so a caller can hand
    /// it to [`SealedNodeRecord`] for restore. There is no on-disk
    /// `node.key` file to move in Phase 3 (nothing writes one yet — see
    /// `BUILD_LOG.md`), so this in-memory removal *is* the seal, for key
    /// material purposes.
    pub fn take_node_key_material(&self, node_id: &str) -> Option<(WrappedNodeKey, PublicKey)> {
        let wrapped = self
            .node_wrapped_keys
            .write()
            .expect("node wrapped keys poisoned")
            .remove(node_id)?;
        let public = self
            .node_public_keys
            .write()
            .expect("node public keys poisoned")
            .remove(node_id);
        // ADR-079 (F-g, corrected in C1): the hot key is zeroised IN PLACE and only
        // then removed. `HashMap::remove` moves the value out and leaves the old
        // bytes in the table's allocation; zeroising the returned copy (the first
        // version of this fix) wiped nothing that `lock()` could no longer reach.
        wipe_then_remove(
            &mut self.hot_keys.write().expect("hot keys poisoned"),
            node_id,
        );
        self.locked_nodes
            .write()
            .expect("locked_nodes poisoned")
            .remove(node_id);
        public.map(|p| (wrapped, p))
    }

    /// Reinstates a sealed node's key material. If the vault is currently
    /// unlocked, also rehydrates the hot key immediately — restore is
    /// documented as "puts everything back intact" (`09_UI_UX_SPEC.md §9`),
    /// not "unlock again to actually use it".
    pub fn restore_node_key_material(
        &self,
        node_id: &str,
        wrapped: WrappedNodeKey,
        public: PublicKey,
    ) {
        self.node_wrapped_keys
            .write()
            .expect("node wrapped keys poisoned")
            .insert(node_id.to_string(), wrapped.clone());
        self.node_public_keys
            .write()
            .expect("node public keys poisoned")
            .insert(node_id.to_string(), public);
        if !self.is_locked() {
            if let Ok(root_key) = self.reauth_root_key("node restore") {
                let unwrapped: Result<StaticSecret, _> =
                    unwrap_node_key(root_key.expose_secret(), node_id, &wrapped);
                if let Ok(priv_key) = unwrapped {
                    self.hot_keys
                        .write()
                        .expect("hot keys poisoned")
                        .insert(node_id.to_string(), priv_key.to_bytes());
                }
            }
        }
    }

    /// Peeks a sealed node's record without consuming it — `node.restore`
    /// needs the snapshot to attempt `crates/store::archive::restore`
    /// *before* deciding whether the seal is actually undone (a day-8
    /// attempt must leave the record and the seal exactly as they were).
    pub fn sealed_record(&self, node_id: &str) -> Option<SealedNodeRecord> {
        self.sealed_nodes
            .read()
            .expect("sealed nodes poisoned")
            .get(node_id)
            .cloned()
    }

    pub fn record_sealed(&self, node_id: &str, record: SealedNodeRecord) {
        self.sealed_nodes
            .write()
            .expect("sealed nodes poisoned")
            .insert(node_id.to_string(), record);
    }

    pub fn discard_sealed_record(&self, node_id: &str) {
        self.sealed_nodes
            .write()
            .expect("sealed nodes poisoned")
            .remove(node_id);
    }
}

/// Zeroise the value where it sits in the table, *then* remove it. Returns
/// whether there was one. `HashMap::remove` moves the value out and only marks
/// the bucket free, so wiping the *returned* copy leaves the original bytes in
/// the allocation; wiping first leaves zeroes there.
fn wipe_then_remove<V: Zeroize>(map: &mut HashMap<String, V>, id: &str) -> bool {
    match map.get_mut(id) {
        Some(value) => {
            value.zeroize();
            map.remove(id);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod wipe_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Remembers the address `zeroize` was called on.
    struct Probe {
        zeroised_at: Arc<AtomicUsize>,
    }
    impl Zeroize for Probe {
        fn zeroize(&mut self) {
            self.zeroised_at
                .store(self as *const Probe as usize, Ordering::SeqCst);
        }
    }

    #[test]
    fn the_value_is_wiped_where_it_sits_in_the_table_not_on_a_moved_copy() {
        let seen = Arc::new(AtomicUsize::new(0));
        let mut map = HashMap::new();
        map.insert(
            "acme".to_string(),
            Probe {
                zeroised_at: Arc::clone(&seen),
            },
        );
        let in_table = map.get("acme").unwrap() as *const Probe as usize;
        assert!(wipe_then_remove(&mut map, "acme"));
        assert_eq!(
            seen.load(Ordering::SeqCst),
            in_table,
            "zeroize ran on a copy that had already left the table"
        );
        assert!(map.is_empty());
        assert!(!wipe_then_remove(&mut map, "acme"), "nothing left to wipe");
    }
}
