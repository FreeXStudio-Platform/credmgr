//! ADR-063 and ADR-064 — the vault on disk, not only in memory.
//!
//! Until 2026-09-24 the running `credmgrd` could create a vault
//! (`credmgr init`, ADR-061) and then never open it again: `vault.unlock`
//! unwrapped the root key with the daemon's start-up placeholder keystore
//! (an empty passphrase), so every real passphrase answered
//! `wrong_passphrase`; nothing loaded an existing vault from disk after a
//! restart; and every mutation — entry names, nodes, grants, the 2FA gate —
//! lived only in this process's memory, so a restart kept the ciphertext
//! files and lost what they meant. Measured end to end with the real
//! `credmgrd` and `credmgr` binaries before this module existed.
//!
//! This module closes all three, and adds the gate's "last door"
//! (`07_TWO_FACTOR.md §4`). Its first version was adversarially reviewed the
//! same day and rebuilt around what that review found (ADR-063's amendment):
//!
//! * [`BrokerState::unlock_with_passphrase`] — the live unlock. Builds the
//!   `Software` keystore from the passphrase the caller sent (ADR-041's
//!   permanent tier), proves it against `keys/root.wrap.pass`, loads and
//!   verifies the vault from disk if this process has not, consults the gate,
//!   and — once the vault is actually unlocked — keeps the **root key**
//!   resident (`session_root`) until `lock()`. The passphrase keystore is
//!   dropped at once; it is never installed as the broker's own, so the
//!   daemon's inert placeholder is all a passphrase-less unlock ever meets.
//! * [`BrokerState::persist`] — write-through. After every successful
//!   mutating op on an unlocked, disk-backed vault, the live state is written
//!   in `04 §2.3`'s order: node key files, then every manifest, then the
//!   HMAC-signed registry that binds them, then the external generation
//!   counter — which only ever moves forward. Everything is computed before
//!   the first byte is written.
//! * Loading is **one read, all or nothing**: the registry is read once and
//!   every other check is made against that one verified document; nothing
//!   is committed to the running state until every file has verified. A
//!   write interrupted between its manifests and its registry is recovered
//!   (the previous signed registry pair, and a manifest exactly one
//!   generation ahead of its binding, are both accepted — each is still
//!   authenticated under the root key, and the external counter still
//!   refuses anything older than the last completed write).
//! * The vault gate is persisted in the registry's `gate.twofa` field
//!   (ADR-064) — its TOTP secret sealed under a root-derived key, recovery
//!   codes as the SHA-256 hashes the broker already keeps, and the last
//!   accepted TOTP step, re-entered as a replay floor on load.
//! * [`BrokerState::gate_recover`] — the passphrase **plus** the printed root
//!   recovery code together reset a lost gate. It resets; it never unlocks.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::{json, Value};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use credmgr_core::keys::{open_under_root, seal_under_root, WrappedNodeKey};
use credmgr_core::recovery::{
    parse_recovery_code, unwrap_root_with_recovery_code, RootRecoveryWrap,
};
use credmgr_core::registry::{is_path_safe_node_id, ORPHAN_ID};
use credmgr_core::totp::Totp;
use credmgr_keystore::machine_lock::MachineLockError;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_keystore::{KeystoreId, PlatformKeystore, WrappedKey};
use credmgr_store::error::StoreError;
use credmgr_store::generation::{FileGenerationCounter, GenerationCounter, VAULT_GENERATION};
use credmgr_store::manifest::{ManifestBody, ManifestDoc};
use credmgr_store::registry_file::{
    self, CreatedByHuman, GateDoc, GrantDoc, NodeDoc, RegistryDocument, REGISTRY_FORMAT,
    SEALED_RECORD_VERSION,
};
use credmgr_store::{atomic, manifest};

use super::GATE_UNLOCK_TTL_SECONDS;
use super::{hex_encode, BrokerState, GateEnrollment, PendingGateUnlock, GATE_SCOPE_VAULT};

/// The daemon-environment override for a vault whose external rollback
/// counter is missing — the one legitimate case being a vault directory
/// moved to a new machine or account, whose state directory did not come
/// with it. Deliberately not a request parameter: it has to be set by
/// whoever starts `credmgrd`, on purpose, for that one start.
pub const ACCEPT_MISSING_COUNTER_ENV: &str = "CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER";

/// A constant-time compare of two 32-byte keys, without a new dependency.
pub(super) fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Version of the `gate.twofa` document this build writes and reads.
const GATE_DOC_VERSION: u64 = 1;

fn gate_secret_label(scope: &str) -> String {
    format!("credmgr/v2/gate-secret/{scope}")
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub(super) fn corrupt(path: std::path::PathBuf, what: &str) -> StoreError {
    StoreError::Io {
        path,
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string()),
    }
}

/// Why the passphrase did not yield the root key.
#[derive(Debug)]
pub(super) enum PassRootError {
    /// The passphrase does not open the wrap (or there is no wrap).
    Wrong,
    /// ADR-165: the wrap is bound to a device key this Mac does not hold, or is damaged. The passphrase was
    /// never tried.
    MachineLock(MachineLockError),
}

/// Why a live unlock refused (ADR-063).
#[derive(Debug)]
pub enum UnlockError {
    /// The passphrase does not open `root.wrap.pass` — or no vault exists
    /// to open. Deliberately one case on the wire: whether a vault exists at
    /// a path is not something to confirm to an unauthenticated caller.
    WrongPassphrase,
    /// The passphrase was right, but the vault on disk failed its own
    /// integrity checks — a tampered or rolled-back registry, a manifest
    /// that does not match its binding, a missing rollback counter. Refused;
    /// nothing is loaded.
    Integrity(StoreError),
    /// ADR-165: the passphrase wrap is bound to a device key this Mac does not hold (or is damaged). The
    /// passphrase was not tried; the recovery code opens the vault without the device key.
    MachineLock(MachineLockError),
}

/// Why `gate_recover` refused (ADR-064).
#[derive(Debug)]
pub enum GateRecoverError {
    /// The passphrase and the root recovery code did not both open the
    /// vault's root key — which of the two failed is not said.
    WrongFactors,
    /// ADR-165: the passphrase wrap is bound to a device key this Mac does not hold (or is damaged).
    MachineLock(MachineLockError),
    /// Both factors were right, but the vault failed an integrity check, or
    /// the reset could not be written.
    Store(StoreError),
}

/// Where the test suite can make [`BrokerState::persist`] "die" part-way
/// (ADR-079's crash tables): the process is gone, so whatever the writes so far
/// left on disk is what the next start meets. Compiled only with `test-utils`.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistFault {
    /// After every node key and every manifest is written, before the registry.
    /// The manifests are one generation ahead of the registry that binds them —
    /// the interrupted-write shape the loader accepts (ADR-063).
    BeforeRegistry,
    /// After the registry pair is written, before the external counter moves.
    AfterRegistryBeforeCounter,
    /// Not a crash: the same point as [`PersistFault::BeforeRegistry`], but the
    /// write merely *fails* (a full disk, a permission) and the process lives on.
    /// The seal and restore that called it must roll their memory and their
    /// files back — the path a crash never takes.
    FailBeforeRegistry,
}

/// The complete next on-disk state, computed but not yet written — see
/// [`BrokerState::build_next_state`] (ADR-063, ADR-076).
pub(super) struct NextState {
    pub manifests: HashMap<String, ManifestBody>,
    pub wrapped_keys: HashMap<String, WrappedNodeKey>,
    pub doc: RegistryDocument,
    /// The external generation counter's value when the state was built.
    pub external: u64,
}

/// Everything a load verified, held apart from the running state until every
/// check has passed — then committed in one step.
pub(super) struct LoadedVault {
    doc: RegistryDocument,
    manifests: HashMap<String, ManifestBody>,
    wrapped_root: WrappedKey,
    node_keys: HashMap<String, (WrappedNodeKey, PublicKey)>,
    public_only: Vec<(String, PublicKey)>,
    gates: Vec<(String, GateEnrollment, Option<u64>)>,
    highest_ref: u32,
}

impl BrokerState {
    /// Whether this vault is disk-backed and written through (ADR-063).
    pub fn is_durable(&self) -> bool {
        self.durable.load(Ordering::SeqCst)
    }

    pub fn state_dir(&self) -> std::path::PathBuf {
        self.state_dir.read().expect("state dir poisoned").clone()
    }

    /// The state directory, for the registry rebuild's generation counter.
    pub fn state_dir_path(&self) -> std::path::PathBuf {
        self.state_dir()
    }

    /// `root.wrap.pass` — from memory if this process holds it, else off disk.
    fn wrapped_root_pass(&self) -> Option<WrappedKey> {
        if let Some(w) = self
            .wrapped_root
            .read()
            .expect("wrapped root poisoned")
            .clone()
        {
            return Some(w);
        }
        let bytes = atomic::read(&self.paths.root_wrap_pass()).ok()?;
        Some(WrappedKey {
            keystore: KeystoreId::Software,
            bytes,
        })
    }

    /// The root key `passphrase` opens, through a request-scoped keystore
    /// that is dropped before this returns.
    ///
    /// ADR-165: a bound `root.wrap.pass` is opened with this Mac's device key first
    /// ([`BrokerState::plain_pass_wrap`]); an unbound one goes to the Argon2id open byte for byte as before.
    /// A machine-lock refusal is its own error, so no caller reports it as a wrong passphrase (which would
    /// also feed the guessing back-off for a passphrase that was never tried).
    pub(super) fn root_from_passphrase(
        &self,
        passphrase: SecretBox<String>,
        reason: &str,
    ) -> Result<SecretBox<[u8; 32]>, PassRootError> {
        let wrapped = self.wrapped_root_pass().ok_or(PassRootError::Wrong)?;
        let plain = self
            .plain_pass_wrap(&wrapped)
            .map_err(PassRootError::MachineLock)?;
        SoftwareKeystore::new(passphrase, self.state_dir())
            .unwrap_root(&plain, reason)
            .map_err(|_| {
                // ADR-165 review P2-5: a sealed wrap cut down to the plain wrap's length is opened as plain
                // first (so an unbound vault opens exactly as before); when that fails, it is the damaged seal
                // it looks like — pointing to the recovery code, and not a guess for the back-off.
                if credmgr_keystore::machine_lock::looks_like_truncated_seal(&plain.bytes) {
                    PassRootError::MachineLock(
                        credmgr_keystore::machine_lock::MachineLockError::Damaged,
                    )
                } else {
                    PassRootError::Wrong
                }
            })
    }

    /// ADR-063: `vault.unlock` with the caller's passphrase — the live
    /// daemon's real unlock. Same return shape as [`BrokerState::unlock`]:
    /// `Ok(true)` when a confirmed gate now wants its second factor,
    /// `Ok(false)` when the vault is fully unlocked.
    ///
    /// Order matters: the passphrase is proven first; the vault is loaded
    /// and verified second (under the root key the passphrase yielded — an
    /// unverified registry is never loaded); the gate is consulted third,
    /// from what was just verified; and the root key becomes resident only
    /// once the vault is actually unlocked. Serialised against `lock()` and
    /// every other authentication transition.
    pub fn unlock_with_passphrase(
        &self,
        passphrase: SecretBox<String>,
        now: i64,
    ) -> Result<bool, UnlockError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        // ADR-076: a root-key rotation a crash interrupted is finished — or, if
        // it never committed, dropped — before a single vault file is read.
        // Without this the passphrase could meet a half-rotated vault.
        self.recover_interrupted_rotation()
            .map_err(UnlockError::Integrity)?;
        let root = self
            .root_from_passphrase(passphrase, "vault unlock")
            .map_err(|e| match e {
                PassRootError::MachineLock(m) => UnlockError::MachineLock(m),
                PassRootError::Wrong => UnlockError::WrongPassphrase,
            })?;
        // ADR-165 review P0-1: the passphrase opened a plain wrap, but this Mac bound the vault, and the root key
        // it gave does not open the vault — an older, pre-bind wrap was put back. Say that (the recovery code
        // opens it), rather than an integrity failure or a wrong passphrase: the passphrase was right.
        let plain_while_bound = self.plain_wrap_while_bound();
        self.complete_unlock_locked(root, now).map_err(|e| match e {
            UnlockError::Integrity(_) | UnlockError::WrongPassphrase if plain_while_bound => {
                UnlockError::MachineLock(
                    credmgr_keystore::machine_lock::MachineLockError::PlainWhileBound,
                )
            }
            other => other,
        })
    }

    /// ADR-098: the unlock that starts from a root key already in hand — the Touch ID path. Everything
    /// after "we have the root key" is shared with the passphrase unlock, so the registry HMAC, the
    /// rollback counter and the second-factor gate apply identically.
    pub fn unlock_with_root(
        &self,
        root: SecretBox<[u8; 32]>,
        now: i64,
    ) -> Result<bool, UnlockError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        self.recover_interrupted_rotation()
            .map_err(UnlockError::Integrity)?;
        self.complete_unlock_locked(root, now)
    }

    /// The tail of an unlock, `auth_lock` already held.
    fn complete_unlock_locked(
        &self,
        root: SecretBox<[u8; 32]>,
        now: i64,
    ) -> Result<bool, UnlockError> {
        if !self.is_durable() && self.paths.registry().exists() {
            self.load_from_disk(root.expose_secret())
                .map_err(UnlockError::Integrity)?;
        }

        if self.is_gate_confirmed(GATE_SCOPE_VAULT) {
            self.pending_gate_unlock
                .lock()
                .expect("pending gate unlock poisoned")
                .insert(
                    GATE_SCOPE_VAULT.to_string(),
                    PendingGateUnlock {
                        root_key: root,
                        expires_at: now + GATE_UNLOCK_TTL_SECONDS,
                    },
                );
            return Ok(true);
        }

        self.install_hot_keys_from_root(root.expose_secret())
            .map_err(|_| UnlockError::WrongPassphrase)?;
        if self.is_durable() {
            *self.session_root.write().expect("session root poisoned") = Some(root);
        }
        Ok(false)
    }

    /// ADR-098: after something rewrote the registry on disk behind this process's back (the
    /// registry rebuild), lock and forget that this process holds the vault, so the next unlock loads
    /// and verifies it from disk exactly as a fresh daemon would. Nothing is persisted in between: a
    /// write-through needs a durable, unlocked vault, and this leaves neither.
    pub fn invalidate_loaded_vault(&self) {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        self.lock_inner();
        self.durable.store(false, Ordering::SeqCst);
    }

    /// Load an existing vault from disk under `root_key` and commit it —
    /// only after every check has passed.
    pub(super) fn load_from_disk(&self, root_key: &[u8; 32]) -> Result<(), StoreError> {
        let loaded = self.verify_vault_on_disk(root_key)?;

        let counter = FileGenerationCounter::new(self.state_dir());
        let external = counter.read(root_key, VAULT_GENERATION)?.unwrap_or(0);
        if loaded.doc.vault_generation > external {
            counter.write(root_key, VAULT_GENERATION, loaded.doc.vault_generation)?;
        }

        // ADR-069: the locked-write tray, rebuilt from disk. Untrusted input —
        // scanned after everything signed has verified, and never able to fail
        // the load (`state/tray.rs`).
        let tray = self.scan_pending_tray(&loaded.manifests);
        *self.registry.write().expect("registry poisoned") = loaded.doc.to_core_registry();
        *self.manifests.write().expect("manifests poisoned") = loaded.manifests;
        self.merge_pending_tray(tray);
        self.load_key_material(loaded.wrapped_root, loaded.node_keys);
        // ADR-098: the enrolled presence keys, verified under the same root key as everything else. A
        // file that fails its tag is an integrity error, never "nothing enrolled".
        // ADR-148 §P2-4: the list that counts is the one in the signed registry; the file is still verified
        // when present (a tampered file is an integrity error, as before), and is the source only for a
        // registry written before ADR-148 — whose next write carries the list into the registry.
        let file_keys = credmgr_store::presence_file::load_presence(&self.paths, root_key)?;
        self.set_presence_keys(loaded.doc.presence_keys.clone().unwrap_or(file_keys));
        // ADR-148 addendum: the Touch ID unlock wraps the registry names. A registry written before the
        // addendum names none; the wrap on disk now (unless its tag fails under this root key) is carried into
        // the registry by the next write — the same one-time window as the presence keys above.
        let wraps = match loaded.doc.device_wraps.clone() {
            Some(named) => named,
            None => self.device_wraps_to_carry(root_key),
        };
        self.set_device_wraps(Some(wraps));
        for (id, public) in loaded.public_only {
            self.seed_public_key_only(&id, public);
        }
        {
            let mut gate = self.gate.write().expect("gate poisoned");
            let mut floor = self
                .gate_replay_floor
                .write()
                .expect("gate replay floor poisoned");
            for (id, enrollment, last_counter) in loaded.gates {
                if let Some(counter) = last_counter {
                    floor.insert(id.clone(), counter);
                }
                gate.insert(id, enrollment);
            }
        }
        // Review L3: entry refs continue past the highest one on disk rather
        // than restarting at the in-memory default on every broker start.
        self.next_ref
            .fetch_max(loaded.highest_ref.saturating_add(1), Ordering::SeqCst);
        *self.registry_meta.write().expect("registry meta poisoned") = loaded.doc;
        self.durable.store(true, Ordering::SeqCst);
        // ADR-079: finish what an interrupted seal or restore left on the file
        // system. After everything signed has verified; best effort; it never
        // fails the unlock and never writes signed state.
        self.housekeep_after_load();
        // ADR-131: and finish a destroy of sealed entries the process did not live to finish.
        self.finish_interrupted_destroy(root_key);
        Ok(())
    }

    /// Every check a load makes, against one read of each file, touching no
    /// running state. See the module docs for the two interrupted-write
    /// recoveries it accepts and why neither weakens rollback detection.
    pub(super) fn verify_vault_on_disk(
        &self,
        root_key: &[u8; 32],
    ) -> Result<LoadedVault, StoreError> {
        let counter = FileGenerationCounter::new(self.state_dir());
        let external = counter.read(root_key, VAULT_GENERATION)?;
        let Some(external) = external else {
            // Review H1(a): a missing counter used to read as generation 0,
            // so deleting it let an older, validly signed registry — one from
            // before the gate was enrolled — load as current. It is refused
            // unless whoever started the daemon said, on purpose, that this
            // vault was moved from another machine.
            if std::env::var(ACCEPT_MISSING_COUNTER_ENV).as_deref() == Ok("1") {
                return self.verify_registry_and_rest(
                    root_key,
                    registry_file::load(&self.paths, root_key)?,
                );
            }
            // ADR-148 amendment (K-23 (e)): a restore-scoped acceptance. `credmgr restore` wrote a
            // marker from the archive's restore ticket; it is accepted only if the ticket was signed under
            // this vault's root key, and only for the exact `registry.json` bytes on disk and their
            // generation. Then the counter is written and the marker consumed.
            let marker_path = credmgr_store::restore_marker::marker_path(&self.state_dir());
            if !marker_path.exists() {
                return Err(corrupt(
                    self.state_dir(),
                    "the vault's rollback counter is missing — refusing to trust the registry. \
                     If this vault was moved from another machine or account, start credmgrd \
                     once with CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1",
                ));
            }
            let marker = atomic::read(&marker_path)?;
            let registry_json = atomic::read(&self.paths.registry())?;
            let doc = registry_file::load(&self.paths, root_key)?;
            let generation = credmgr_store::restore_marker::check_marker(
                root_key,
                &marker,
                &registry_json,
                doc.vault_generation,
            )
            .map_err(|refusal| {
                corrupt(
                    marker_path.clone(),
                    &format!(
                        "the vault's rollback counter is missing and {} — refusing to trust the \
                         registry. Restore again with `credmgr restore`, or, if this vault was moved \
                         from another machine or account, start credmgrd once with \
                         CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1",
                        refusal.reason()
                    ),
                )
            })?;
            let loaded = self.verify_registry_and_rest(root_key, doc)?;
            // Consumed once: the counter first (so a crash between the two leaves a counter, which then
            // decides, and the marker is never consulted again), then the marker.
            counter.write(root_key, VAULT_GENERATION, generation)?;
            atomic::remove_durable(&marker_path)?;
            return Ok(loaded);
        };

        // Review H2: `registry.json`/`registry.sig` are two writes. If the
        // current pair does not verify, the previous complete pair is tried
        // — and used only if it is not older than the last completed write.
        let doc = match registry_file::load(&self.paths, root_key) {
            Ok(doc) => doc,
            // ADR-079: a registry that authenticates but is a NEWER format is not
            // an interrupted write — it is a vault a newer CredMgr wrote. Falling
            // back to the previous pair would quietly open the older state of a
            // vault whose newer state this build cannot read, and the next write
            // would drop what it could not see. Refused by name instead.
            Err(primary @ StoreError::RegistryFormatTooNew { .. }) => return Err(primary),
            Err(primary) => match registry_file::load_previous(&self.paths, root_key) {
                Ok(prev) if prev.vault_generation >= external => prev,
                _ => return Err(primary),
            },
        };
        if doc.vault_generation < external {
            return Err(StoreError::GenerationRolledBack {
                on_disk: doc.vault_generation,
                external,
            });
        }
        self.verify_registry_and_rest(root_key, doc)
    }

    fn verify_registry_and_rest(
        &self,
        root_key: &[u8; 32],
        doc: RegistryDocument,
    ) -> Result<LoadedVault, StoreError> {
        // ADR-079: the seal records are part of the signed registry, so what they
        // say is authentic — but an id is joined into filesystem paths, and a
        // record must be self-consistent before anything acts on it. The
        // archive itself is NOT read here: it is read lazily, at restore, so a
        // damaged archive can never fail an unlock.
        for (id, record) in &doc.sealed {
            if record.v != SEALED_RECORD_VERSION
                || record.node.node.id != *id
                || doc.nodes.contains_key(id)
                || !is_path_safe_node_id(id)
            {
                return Err(corrupt(
                    self.paths.registry(),
                    "a seal record in the registry is not self-consistent",
                ));
            }
        }

        // ADR-130: a `node.rekey` the process did not live to finish is settled — forward or back, by what
        // the (now verified) registry says the node's public key is — before any key or manifest is read.
        self.recover_interrupted_rekeys(root_key, &doc)?;
        // ADR-158: likewise an `entry.move`, by the manifest generations the registry binds.
        self.recover_interrupted_moves(root_key, &doc)?;

        let mut manifests = HashMap::new();
        let mut highest_ref = 0u32;
        for node_id in doc.nodes.keys() {
            let manifest_doc: ManifestDoc = manifest::load(&self.paths, root_key, node_id)?;
            match manifest::verify_cross_binding(&doc, node_id, &manifest_doc) {
                Ok(()) => {}
                // An interrupted write: manifests are written before the
                // registry that binds them. A manifest exactly one generation
                // ahead of its binding — still authenticated under the root
                // key by `manifest::load` — is that case and nothing else can
                // produce it; anything behind, or further ahead, is refused.
                Err(e) => {
                    let bound = doc.manifests.get(node_id).map(|b| b.generation);
                    if bound != Some(manifest_doc.body.generation.saturating_sub(1)) {
                        return Err(e);
                    }
                }
            }
            highest_ref = manifest_doc
                .body
                .entries
                .iter()
                .map(|e| e.r#ref)
                .fold(highest_ref, u32::max);
            manifests.insert(node_id.clone(), manifest_doc.body);
        }

        let wrapped_root = WrappedKey {
            keystore: KeystoreId::Software,
            bytes: atomic::read(&self.paths.root_wrap_pass())?,
        };

        let mut node_keys = HashMap::new();
        let mut public_only = Vec::new();
        for (id, node_doc) in &doc.nodes {
            let public_bytes: [u8; 32] = hex_decode(&node_doc.public_key)
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| {
                    corrupt(
                        self.paths.registry(),
                        "a node's publicKey is not 32 hex bytes",
                    )
                })?;
            let public = PublicKey::from(public_bytes);
            // ADR-079, custody rule 1: the orphan node is public-only whatever
            // is on disk. A `keys/nodes/orphan.key` is never read — it would put
            // the orphan's private half in the hot set — and
            // `maintenance.verify` reports one.
            if id == ORPHAN_ID {
                public_only.push((id.clone(), public));
                continue;
            }
            let key_path = self.paths.node_key(id);
            if std::fs::symlink_metadata(&key_path).is_ok() {
                let bytes = atomic::read(&key_path)?;
                let wrapped = WrappedNodeKey::from_bytes(&bytes)
                    .map_err(|_| corrupt(key_path.clone(), "not a wrapped node key"))?;
                node_keys.insert(id.clone(), (wrapped, public));
            } else {
                public_only.push((id.clone(), public));
            }
        }

        let mut gates = Vec::new();
        for (id, node_doc) in &doc.nodes {
            if let Some(twofa) = &node_doc.gate.twofa {
                let (enrollment, last) = decode_gate(root_key, id, twofa)?;
                gates.push((id.clone(), enrollment, last));
            }
        }

        Ok(LoadedVault {
            doc,
            manifests,
            wrapped_root,
            node_keys,
            public_only,
            gates,
            highest_ref,
        })
    }

    /// Write the live vault through to disk (ADR-063). Needs the resident
    /// root key of an unlocked, disk-backed vault; a locked broker cannot
    /// persist and says so. A no-op for a vault that is not disk-backed.
    pub fn persist(&self, now: i64) -> Result<(), StoreError> {
        if !self.is_durable() {
            return Ok(());
        }
        let root = self
            .session_root
            .read()
            .expect("session root poisoned")
            .as_ref()
            .map(|r| SecretBox::new(Box::new(*r.expose_secret())))
            .ok_or(StoreError::VaultLocked)?;
        self.persist_with_root(root.expose_secret(), now)
    }

    /// The write itself, for a caller that already holds the root key.
    /// Builds the complete next state first — every manifest body, every
    /// public key, the whole registry document — and only then writes.
    pub(super) fn persist_with_root(
        &self,
        root_key: &[u8; 32],
        now: i64,
    ) -> Result<(), StoreError> {
        self.persist_with_root_edit(root_key, now, &mut |_| {})
    }

    /// [`BrokerState::persist_with_root`] with one more step: `edit` is applied
    /// to the registry document after it is built and every manifest binding is
    /// in it, immediately before it is signed and written. ADR-079's seal and
    /// restore use it to move a node between `nodes` and `sealed` **in the very
    /// registry write that is the commit point** — and `registry_meta` (the
    /// memory copy) only takes the edit if the write succeeded.
    pub(super) fn persist_with_root_edit(
        &self,
        root_key: &[u8; 32],
        now: i64,
        edit: &mut dyn FnMut(&mut RegistryDocument),
    ) -> Result<(), StoreError> {
        let held = self.lock_persist();
        self.persist_with_root_edit_locked(&held, root_key, now, edit)
    }

    /// The one-writer guard. A caller that must change memory **and** commit that
    /// change in one step (ADR-079's seal and restore) takes it **before** the
    /// first memory mutation and passes it to
    /// [`BrokerState::persist_with_root_edit_locked`]: otherwise another client's
    /// write-through, running between the two, would write the half-done memory
    /// (node gone, no seal record) to disk, and a crash right there leaves a vault
    /// that will not unlock. Lock order: node write locks first, then this one —
    /// the order every existing caller already follows.
    pub(super) fn lock_persist(&self) -> std::sync::MutexGuard<'_, ()> {
        self.persist_lock.lock().expect("persist lock poisoned")
    }

    /// [`BrokerState::persist_with_root_edit`] for a caller that already holds the
    /// guard from [`BrokerState::lock_persist`]. The guard is a witness only — it
    /// makes calling this without the lock a type error.
    pub(super) fn persist_with_root_edit_locked(
        &self,
        _held: &std::sync::MutexGuard<'_, ()>,
        root_key: &[u8; 32],
        now: i64,
        edit: &mut dyn FnMut(&mut RegistryDocument),
    ) -> Result<(), StoreError> {
        let NextState {
            manifests,
            wrapped_keys,
            mut doc,
            external,
        } = self.build_next_state(root_key, root_key, None, now)?;
        let counter = FileGenerationCounter::new(self.state_dir());

        // --- write, in `04 §2.3`'s order ------------------------------------
        for (id, wrapped) in &wrapped_keys {
            atomic::write(&self.paths.node_key(id), &wrapped.to_bytes())?;
        }
        for (id, body) in &manifests {
            let binding = manifest::save(&self.paths, root_key, body)?;
            doc.manifests.insert(id.clone(), binding);
        }
        edit(&mut doc);
        #[cfg(feature = "test-utils")]
        {
            self.trip_persist_fault(PersistFault::BeforeRegistry)?;
            self.trip_persist_fault(PersistFault::FailBeforeRegistry)?;
        }
        registry_file::save(&self.paths, root_key, &doc)?;
        #[cfg(feature = "test-utils")]
        self.trip_persist_fault(PersistFault::AfterRegistryBeforeCounter)?;
        // Last, and only ever forward.
        if doc.vault_generation > external {
            counter.write(root_key, VAULT_GENERATION, doc.vault_generation)?;
        }

        // Keep memory in step with what is now on disk.
        {
            let mut live = self.manifests.write().expect("manifests poisoned");
            for (id, body) in manifests {
                live.entry(id).or_insert(body);
            }
        }
        *self.registry_meta.write().expect("registry meta poisoned") = doc;
        Ok(())
    }

    /// Compute — touching nothing on disk and nothing in memory — the whole
    /// next on-disk state of the vault: every manifest, the wrapped node keys,
    /// and the registry document with its generation advanced. Shared by the
    /// ordinary write-through ([`BrokerState::persist_with_root`]) and by
    /// root-key rotation (ADR-076), which stages the same state under a
    /// **new** root key.
    ///
    /// `root_key` is the key the gate seed is sealed under in the document it
    /// returns; `counter_key` is the key the external generation counter is
    /// *currently* signed under, needed only to read it. They are the same key
    /// except mid-rotation. `wrapped_override` replaces the wrapped node keys
    /// (rotation passes the re-wrapped set); `None` takes the live ones. The
    /// document's `manifests` bindings are left for the caller to fill as it
    /// signs each manifest.
    pub(super) fn build_next_state(
        &self,
        root_key: &[u8; 32],
        counter_key: &[u8; 32],
        wrapped_override: Option<HashMap<String, WrappedNodeKey>>,
        now: i64,
    ) -> Result<NextState, StoreError> {
        let registry = self.registry.read().expect("registry poisoned").clone();
        let mut manifests = self.manifests.read().expect("manifests poisoned").clone();
        let mut wrapped_keys = wrapped_override.unwrap_or_else(|| {
            self.node_wrapped_keys
                .read()
                .expect("node wrapped keys poisoned")
                .clone()
        });
        let mut doc = self
            .registry_meta
            .read()
            .expect("registry meta poisoned")
            .clone();

        // A manifest for every registry node, including one that has never
        // held an entry: a registry naming a node with no manifest on disk
        // fails its own next load (the trap `confirm_init` hit for `global`).
        for id in registry.nodes.keys() {
            manifests
                .entry(id.clone())
                .or_insert_with(|| ManifestBody::new(id));
        }
        manifests.retain(|id, _| registry.nodes.contains_key(id));
        // ADR-079, custody rule 1: `keys/nodes/orphan.key` is never written.
        wrapped_keys.retain(|id, _| registry.nodes.contains_key(id) && id != ORPHAN_ID);
        doc.format = REGISTRY_FORMAT;
        // ADR-148 §P2-4: the enrolled presence keys travel inside the signed registry.
        doc.presence_keys = Some(self.presence_keys());
        // ADR-148 addendum: and so do the Touch ID unlock wraps this vault set up.
        if let Some(wraps) = self.device_wraps() {
            doc.device_wraps = Some(wraps);
        }

        doc.nodes.retain(|id, _| registry.nodes.contains_key(id));
        for (id, node) in &registry.nodes {
            match doc.nodes.get_mut(id) {
                Some(existing) => existing.node = node.clone(),
                None => {
                    let public = self.node_public_key(id).ok_or_else(|| {
                        corrupt(self.paths.node_key(id), "a registry node has no public key")
                    })?;
                    doc.nodes.insert(
                        id.clone(),
                        NodeDoc {
                            node: node.clone(),
                            created: now,
                            gate: GateDoc::default(),
                            pinned: None,
                            public_key: hex_encode(public.as_bytes()),
                        },
                    );
                }
            }
        }
        {
            let gate = self.gate.read().expect("gate poisoned");
            let replay = self.gate_replay.read().expect("gate replay poisoned");
            let floor = self
                .gate_replay_floor
                .read()
                .expect("gate replay floor poisoned");
            for (id, node_doc) in doc.nodes.iter_mut() {
                node_doc.gate.twofa = gate.get(id).filter(|g| g.confirmed).map(|g| {
                    let last = replay
                        .iter()
                        .filter(|(scope, _)| scope == id)
                        .map(|(_, c)| *c)
                        .chain(floor.get(id).copied())
                        .max();
                    encode_gate(root_key, id, g, last)
                });
            }
        }
        let previous_grants = std::mem::take(&mut doc.grants);
        doc.grants = registry
            .grants
            .iter()
            .map(
                |grant| match previous_grants.iter().find(|g| g.grant.id == grant.id) {
                    Some(kept) => GrantDoc {
                        grant: grant.clone(),
                        ..kept.clone()
                    },
                    None => GrantDoc {
                        grant: grant.clone(),
                        created_at: now,
                        created_by: CreatedByHuman::Human,
                        last_used_at: None,
                    },
                },
            )
            .collect();
        doc.manifests
            .retain(|id, _| registry.nodes.contains_key(id));

        // The next generation is past both what this process last wrote and
        // what the external counter says — so a registry written by anything
        // else in between (a second daemon, `maintenance.doctor`) can never
        // be overwritten by a lower-numbered one (review M4).
        let counter = FileGenerationCounter::new(self.state_dir());
        let external = counter.read(counter_key, VAULT_GENERATION)?.unwrap_or(0);
        doc.vault_generation = doc.vault_generation.max(external) + 1;

        Ok(NextState {
            manifests,
            wrapped_keys,
            doc,
            external,
        })
    }

    /// Re-read the registry document after something other than `persist`
    /// wrote it (`maintenance.doctor`), so the next `persist` merges into
    /// what is actually on disk.
    pub fn refresh_registry_meta(&self, root_key: &[u8; 32]) -> Result<(), StoreError> {
        let doc = registry_file::load(&self.paths, root_key)?;
        *self.registry_meta.write().expect("registry meta poisoned") = doc;
        Ok(())
    }

    /// Hold the persist lock across an out-of-band registry write.
    pub fn with_persist_lock<T>(&self, f: impl FnOnce() -> T) -> T {
        let _one_writer = self.persist_lock.lock().expect("persist lock poisoned");
        f()
    }

    /// Arm a fault for the next [`BrokerState::persist`] (test seam, ADR-079).
    #[cfg(feature = "test-utils")]
    pub fn set_persist_fault_for_test(&self, fault: Option<PersistFault>) {
        self.set_persist_fault_after_for_test(0, fault);
    }

    /// Arm a fault for the persist **after** `skip` more of them have passed
    /// that point. A seal writes the vault through once before it starts (to put
    /// the disk level with memory) and once to commit; `skip == 1` is the
    /// second — the commit.
    #[cfg(feature = "test-utils")]
    pub fn set_persist_fault_after_for_test(&self, skip: usize, fault: Option<PersistFault>) {
        *self.persist_fault.lock().expect("persist fault poisoned") =
            fault.map(|fault| (skip, fault));
    }

    /// If `at` is the armed fault (and its `skip` is spent), consume it and
    /// "die": the error is an injected crash, and `crash_injected` says so to
    /// every cleanup path that a real crash would have skipped.
    #[cfg(feature = "test-utils")]
    fn trip_persist_fault(&self, at: PersistFault) -> Result<(), StoreError> {
        let mut armed = self.persist_fault.lock().expect("persist fault poisoned");
        if let Some((skip, fault)) = armed.as_mut() {
            if *fault == at {
                if *skip == 0 {
                    *armed = None;
                    if at == PersistFault::FailBeforeRegistry {
                        return Err(corrupt(
                            self.paths.registry(),
                            "injected failure (test seam): the write failed here",
                        ));
                    }
                    self.crash_injected.store(true, Ordering::SeqCst);
                    return Err(corrupt(
                        self.paths.registry(),
                        "injected crash (test seam): the process died here",
                    ));
                }
                *skip -= 1;
            }
        }
        Ok(())
    }

    /// ADR-064 — the last door (`07_TWO_FACTOR.md §4`). The vault
    /// passphrase **and** the printed root recovery code together reset the
    /// vault gate, so an operator who has lost the authenticator and spent
    /// every gate recovery code is not locked out for good.
    ///
    /// Both factors must independently open the *same* root key: the
    /// passphrase through `root.wrap.pass`, the recovery code through
    /// `root.wrap.recovery`. The passphrase is checked first, so a wrong
    /// recovery code costs the same Argon2id derivation a wrong passphrase
    /// does (review L7). It resets; it does not unlock. Returns whether a
    /// gate was actually in force to reset.
    pub fn gate_recover(
        &self,
        passphrase: SecretBox<String>,
        root_recovery_code: &str,
        now: i64,
    ) -> Result<bool, GateRecoverError> {
        self.gate_recover_scope(passphrase, root_recovery_code, GATE_SCOPE_VAULT, now)
    }

    /// [`BrokerState::gate_recover`] for any gate scope: the vault's (`global`) or one node's own second
    /// factor (ADR-135). The factors are the same two; only the gate that is reset differs.
    pub fn gate_recover_scope(
        &self,
        passphrase: SecretBox<String>,
        root_recovery_code: &str,
        gate_scope: &str,
        now: i64,
    ) -> Result<bool, GateRecoverError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        // ADR-076: the recovery wrap this reads may be mid-rotation.
        self.recover_interrupted_rotation()
            .map_err(GateRecoverError::Store)?;
        let from_passphrase = self.root_from_passphrase(passphrase, "gate recovery");
        let from_code = parse_recovery_code(root_recovery_code.trim())
            .ok()
            .and_then(|code| {
                let bytes = atomic::read(&self.paths.root_wrap_recovery()).ok()?;
                let wrap = RootRecoveryWrap::from_bytes(&bytes).ok()?;
                unwrap_root_with_recovery_code(&code, &wrap).ok()
            })
            .map(|root| SecretBox::new(Box::new(root)));
        if let Err(PassRootError::MachineLock(m)) = from_passphrase {
            return Err(GateRecoverError::MachineLock(m));
        }
        let (Ok(from_passphrase), Some(from_code)) = (from_passphrase, from_code) else {
            return Err(GateRecoverError::WrongFactors);
        };
        if !ct_eq_32(from_code.expose_secret(), from_passphrase.expose_secret()) {
            return Err(GateRecoverError::WrongFactors);
        }
        let root = from_passphrase.expose_secret();

        if !self.is_durable() && self.paths.registry().exists() {
            self.load_from_disk(root).map_err(GateRecoverError::Store)?;
        }

        let had_gate = self
            .gate
            .write()
            .expect("gate poisoned")
            .remove(gate_scope)
            .is_some_and(|g| g.confirmed);
        self.gate_pending
            .write()
            .expect("gate pending poisoned")
            .remove(gate_scope);
        self.pending_gate_unlock
            .lock()
            .expect("pending gate unlock poisoned")
            .remove(gate_scope);

        if self.is_durable() {
            self.persist_with_root(root, now)
                .map_err(GateRecoverError::Store)?;
        }
        Ok(had_gate)
    }
}

/// The persisted form of one confirmed gate (ADR-064): the TOTP secret
/// sealed under the root key, the recovery-code hashes the broker already
/// holds (a burned code is `null`), and the last accepted TOTP step.
fn encode_gate(
    root_key: &[u8; 32],
    scope: &str,
    gate: &GateEnrollment,
    last_counter: Option<u64>,
) -> Value {
    let mut secret = credmgr_core::totp::decode_gate_secret_base32(&gate.totp.secret_base32())
        .expect("a gate's own secret round-trips through its own base32");
    let sealed = seal_under_root(root_key, &gate_secret_label(scope), &secret);
    secret.zeroize();
    json!({
        "v": GATE_DOC_VERSION,
        "confirmed": true,
        "secret": hex_encode(&sealed),
        "recoveryHashes": gate
            .recovery_hashes
            .iter()
            .map(|h| h.map(|h| hex_encode(&h)))
            .collect::<Vec<_>>(),
        "lastCounter": last_counter,
    })
}

/// Reverse of [`encode_gate`]. A gate document this build cannot read is a
/// hard failure, never "no gate": silently dropping an unreadable gate would
/// turn corruption into a 2FA bypass.
fn decode_gate(
    root_key: &[u8; 32],
    scope: &str,
    doc: &Value,
) -> Result<(GateEnrollment, Option<u64>), StoreError> {
    let bad = |what: &str| corrupt(std::path::PathBuf::from("registry.json#gate.twofa"), what);
    if doc["v"].as_u64() != Some(GATE_DOC_VERSION) {
        return Err(bad("unknown gate document version"));
    }
    if doc["confirmed"].as_bool() != Some(true) {
        return Err(bad("a persisted gate must be confirmed"));
    }
    let sealed = doc["secret"]
        .as_str()
        .and_then(hex_decode)
        .ok_or_else(|| bad("gate secret is not hex"))?;
    let mut secret = open_under_root(root_key, &gate_secret_label(scope), &sealed)
        .map_err(|_| bad("gate secret does not open under this vault's root key"))?;
    // The checked constructor: a stored gate secret that authenticated but is not
    // a usable TOTP secret is a corrupt document, never a panic at vault load.
    let built = Totp::try_new(
        secret.clone(),
        credmgr_core::totp::TotpAlgorithm::Sha1,
        credmgr_core::totp::DEFAULT_DIGITS,
        credmgr_core::totp::DEFAULT_PERIOD,
    );
    secret.zeroize();
    let totp = built.map_err(|_| bad("gate secret is not a usable TOTP secret"))?;
    let recovery_hashes = doc["recoveryHashes"]
        .as_array()
        .ok_or_else(|| bad("recoveryHashes missing"))?
        .iter()
        .map(|h| match h {
            Value::Null => Ok(None),
            Value::String(s) => hex_decode(s)
                .and_then(|v| v.try_into().ok())
                .map(Some)
                .ok_or_else(|| bad("a recovery hash is not 32 hex bytes")),
            _ => Err(bad("a recovery hash is neither hex nor null")),
        })
        .collect::<Result<Vec<Option<[u8; 32]>>, StoreError>>()?;
    Ok((
        GateEnrollment {
            totp,
            confirmed: true,
            recovery_hashes,
        },
        doc["lastCounter"].as_u64(),
    ))
}
