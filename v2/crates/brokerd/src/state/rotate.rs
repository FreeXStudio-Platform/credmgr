//! ADR-076 — root-key rotation (`04_CRYPTO_AND_KEYS.md §6`): "new RK; all node
//! keys re-wrapped; all three root wraps rewritten; recovery code reissued".
//!
//! [`BrokerState::rotate_root`] generates a new root key, re-wraps every node
//! key under it, writes a fresh passphrase wrap and a fresh recovery-code wrap,
//! and re-signs every file that was HMAC'd or sealed under the old key — the
//! registry, every manifest, the external rollback counter, the audit tips,
//! the gate seed inside the registry, the seal archives, the removed-entry
//! records and the rotation snapshots. Entry envelopes are **not** touched:
//! they are sealed to node *public* keys, and a rotation re-wraps node private
//! keys, it does not replace them (`node.rotate_key` is a different, planned
//! operation).
//!
//! **Crash safety** is `credmgr_store::rotation`'s: every replacement file is
//! staged and fsynced first, one atomic commit record makes the set binding,
//! and the live files are then moved into place by an idempotent roll-forward
//! that [`BrokerState::unlock_with_passphrase`] and `gate_recover` finish before
//! they read anything. A crash before the commit leaves a vault that opens with
//! the old root key; a crash after it, with the new one; there is no instant
//! at which it opens with neither.
//!
//! **The set of artefacts is closed and enumerated** — see
//! [`ROOT_BOUND_ARTEFACTS`], which names every kind of file a rotation must
//! replace, and the `rotate_root.rs` test that diffs the whole vault before and
//! after and fails on any file nobody classified. A later change that makes a
//! new kind of file root-bound trips that test until the new kind is added here
//! *and* to [`rotation::plan_resigned_artifacts`]. ADR-079 was exactly such a
//! change: the orphan cold key (`keys/cold/orphan.key`) is re-sealed under the
//! new root, and the seal records in the registry (which bind the archived
//! node key's digest and the archived manifest's generation and HMAC) are
//! refreshed to the re-wrapped and re-signed archive files — a half-rotated
//! cold key or a stale binding would leave every sealed node unrestorable and
//! every orphaned entry unrecoverable.
//!
//! This is pure mechanism. *Who may call it* — `Capability::Admin` on `global`,
//! never an agent, the 2FA elevation when a gate is enrolled, and a presence
//! attestation that no transport can supply yet — is `ops.rs`'s
//! `maintenance.rotate_root` arm, which answers `presence_required` today. The
//! rotation logic is exercised directly through this method, not through the
//! wire, for exactly that reason (`maintenance.doctor --rebuild-registry` is
//! the precedent).
//!
//! **Caller contract.** The caller holds [`BrokerState::request_barrier`]
//! exclusively for the whole call (the server does, for this op), so no request
//! is mid-flight while the root key is replaced. A direct caller with no other
//! threads — every test — needs nothing.
//!
//! **Between processes** the exclusion is [`VaultLock`], taken here for the
//! whole rotation and by [`BrokerState::recover_interrupted_rotation_at`] for
//! every recovery: a second `credmgrd` (or a second broker state) that starts
//! while a rotation is staging waits for it instead of deleting its stage as a
//! crash leftover. See `vault_lock.rs` for what went wrong without it.

mod vault_lock;

use std::collections::HashMap;
use std::path::Path;

use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use credmgr_core::keys::{rewrap_node_key, WrappedNodeKey};
use credmgr_core::recovery::{
    format_recovery_code, generate_recovery_code, wrap_root_with_recovery_code,
};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_keystore::PlatformKeystore;
use credmgr_store::error::StoreError;
use credmgr_store::generation::{signed_counter_bytes, FileGenerationCounter, VAULT_GENERATION};
use credmgr_store::manifest::ManifestDoc;
use credmgr_store::paths::VaultPaths;
use credmgr_store::registry_file::ManifestBinding;
use credmgr_store::{archive, audit, manifest, registry_file, rotation};

use super::durable::{corrupt, ct_eq_32, NextState};
use super::{hex_encode, sha256_of, BrokerState};
pub use vault_lock::{VaultLock, RECOVER_LOCK_WAIT, ROTATE_LOCK_WAIT};

/// Every kind of file that is signed or wrapped under the root key, and so is
/// replaced by a rotation — `(what, where it lives, how it is bound)`. The
/// complement is what a rotation must leave byte-for-byte alone: entry
/// envelopes and notes (sealed to node *public* keys), the audit logs
/// themselves (a hash chain; only each month's *tip* is signed), and the
/// archived envelope copies.
///
/// This table is documentation that a test holds to account: the
/// `rotate_root.rs` file-diff test classifies every file in a populated vault,
/// requires each one listed here to have changed, requires every other one to
/// be identical, and fails on a file that matches neither — so a new
/// root-bound kind cannot be added to the vault without being added here.
pub const ROOT_BOUND_ARTEFACTS: &[(&str, &str, &str)] = &[
    (
        "passphrase wrap of the root key",
        "keys/root.wrap.pass",
        "Argon2id(passphrase) → ChaCha20-Poly1305 of RK; rewritten from the new RK",
    ),
    (
        "recovery-code wrap of the root key",
        "keys/root.wrap.recovery",
        "HKDF(recovery code) wrap of RK; re-issued — a NEW recovery code",
    ),
    (
        "wrapped node private keys",
        "keys/nodes/<id>.key",
        "credmgr/v2/node-wrap/<id>; re-wrapped, the node keypair is unchanged",
    ),
    (
        "registry + signature + previous pair",
        "registry.json, registry.sig, registry.json.prev, registry.sig.prev",
        "registry-hmac; carries the gate seeds sealed under RK (gate-secret/<scope>)",
    ),
    (
        "manifests",
        "nodes/<id>/manifest.json",
        "manifest-hmac/<id>; re-bound in the registry",
    ),
    (
        "external rollback counter",
        "<state dir>/vaultGeneration.counter",
        "generation-counter/<name>; lives OUTSIDE the vault, so it is staged in its own base",
    ),
    (
        "audit tips",
        "audit/<yyyy-mm>.tip",
        "audit-tip/<yyyy-mm>; only if the whole month verifies under the old RK first",
    ),
    (
        "orphan cold key",
        "keys/cold/orphan.key",
        "credmgr/v2/orphan-cold/v1; re-sealed, the orphan keypair is unchanged (ADR-079)",
    ),
    (
        "sealed-node archive metadata",
        "archive/<id>/meta.json",
        "archive-meta/<id>",
    ),
    (
        "sealed-node retained node key",
        "archive/<id>/node.key",
        "node-wrap/<id>; `node.restore` moves it back and it must open; the digest the seal \
         record binds in the registry is refreshed",
    ),
    (
        "sealed-node retained manifest",
        "archive/<id>/node/manifest.json",
        "manifest-hmac/<id>; the (generation, hmac) the seal record binds in the registry is \
         refreshed",
    ),
    (
        "removed-entry records",
        "archive/removed-entries/<node>/<entry>/removed.json",
        "removed-entry HMAC under RK",
    ),
    (
        "rotation snapshots (entry-history)",
        "archive/entry-history/<node>/<entry>/<generation>.json",
        "entry-history HMAC under RK",
    ),
];

/// Appended to the `reason` of an audit month the rotation left unsigned when
/// that month is also the one the rotation's own audit record was written to.
const CURRENT_MONTH_CAVEAT: &str = " — NOTE: this is the month the rotation's own audit record \
was appended to, and appending signs a month's tip over the log as it now stands, so the month \
verifies again under the new key and the damage is no longer visible to maintenance.verify. \
Only months nothing is appended to keep failing verification";

/// A point in a rotation at which the test suite can make the process "die".
/// Compiled only with the `test-utils` feature, like the other test seams.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationFault {
    /// After exactly this many replacement files have been staged — a crash
    /// in the middle of staging. Nothing live has been touched and there is no
    /// commit record: the vault must still open with the **old** root key.
    DuringStaging(usize),
    /// After everything is staged, before the commit record is written: the
    /// vault must still open with the **old** root key.
    BeforeCommit,
    /// The commit record lands and the commit call then *reports* an error (a
    /// directory sync that failed after the rename). The record on disk is what
    /// binds, so the rotation must carry on as committed — once a retry of the
    /// sync (which succeeds here) proves the record durable.
    CommitReportsFailure,
    /// As [`RotationFault::CommitReportsFailure`], and the retry of the
    /// directory sync fails too, so the record's durability cannot be proven.
    /// No live file may be moved: a power loss could keep some moved files and
    /// lose the record that says to finish. The rotation hands over its outcome
    /// as `completion_pending`, locks, and leaves the roll-forward to recovery.
    CommitNeverBecomesDurable,
    /// Immediately after the commit record, before a single live file has been
    /// replaced: the vault must open with the **new** root key.
    AfterCommit,
    /// After exactly this many live files have been replaced; `n` equal to the
    /// number of staged files is "all moved, commit record not yet retired".
    DuringRollForward(usize),
}

/// What a completed rotation did. The recovery code is the one thing in it
/// that is secret: it is shown to the operator once and nothing keeps it.
pub struct RotationOutcome {
    /// The new root recovery code, grouped for display. The previous code no
    /// longer opens anything.
    pub recovery_code: String,
    /// Registry nodes whose private key was re-wrapped under the new root.
    pub nodes_rewrapped: usize,
    /// The vault generation the rotation wrote.
    pub vault_generation: u64,
    /// Live files the rotation replaces (every staged file).
    pub files_replaced: usize,
    /// Audit tips, archives, removed-entry records and rotation snapshots
    /// that were re-signed or re-wrapped.
    pub artifacts_resigned: usize,
    /// Artefacts that did not verify under the old root key and were left
    /// exactly as they were — see [`rotation::Skipped`].
    pub skipped: Vec<rotation::Skipped>,
    /// **The rotation is committed and the new root key is in force, but moving
    /// the staged files into place did not finish** — a move failed part-way, or
    /// the commit record could not be proven durable and no file was moved at
    /// all. The vault has been locked; the next unlock finishes the move before
    /// it reads anything. The outcome — recovery code included — is returned
    /// anyway, because the code is already the live one and this is the only
    /// moment it is ever shown. (In the unproven-durability case a power loss
    /// before the record reaches the disk leaves the vault on the **old** key
    /// and this code unused; nothing is ever half-applied.)
    pub completion_pending: bool,
    /// Whether the rotation's own audit record was written (it cannot be while
    /// `completion_pending`: the vault is locked and its tips are mid-move).
    pub audited: bool,
}

impl Drop for RotationOutcome {
    /// The new recovery code is the one secret in the outcome; it does not
    /// outlive the value that carries it (the copy handed to the wire is the
    /// caller's to clear).
    fn drop(&mut self) {
        self.recovery_code.zeroize();
    }
}

impl std::fmt::Debug for RotationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationOutcome")
            .field("recovery_code", &"<redacted>")
            .field("nodes_rewrapped", &self.nodes_rewrapped)
            .field("vault_generation", &self.vault_generation)
            .field("files_replaced", &self.files_replaced)
            .field("artifacts_resigned", &self.artifacts_resigned)
            .field("skipped", &self.skipped)
            .field("completion_pending", &self.completion_pending)
            .field("audited", &self.audited)
            .finish()
    }
}

/// Why [`BrokerState::rotate_root`] refused. Every variant means **nothing was
/// changed** — the vault is exactly as it was and the old root key still opens
/// it. (A rotation that got past its commit point does not fail: it returns an
/// outcome, with [`RotationOutcome::completion_pending`] set if the final file
/// moves could not all be made.)
#[derive(Debug)]
pub enum RotateRootError {
    /// This broker holds an in-memory vault (a fixture), not one on disk.
    NotDurable,
    /// The vault is locked. A rotation needs the resident root key.
    Locked,
    /// The passphrase does not open the vault's passphrase wrap — checked
    /// before anything is generated, so a typo can never become the new
    /// passphrase wrap. Which factor failed is not a question that has an
    /// answer here: there is only one.
    WrongPassphrase,
    /// A node's private key did not open under the current root key. Nothing
    /// was changed.
    NodeKey(String),
    /// Failed before the commit point. **Nothing was changed**: the vault is
    /// exactly as it was and the old root key still opens it.
    Store(StoreError),
    /// Test seam: the process "died" at a [`RotationFault`] point. What a real
    /// crash would leave is on disk; the caller drops the broker and restarts.
    #[cfg(feature = "test-utils")]
    InjectedCrash,
}

impl std::fmt::Display for RotateRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotateRootError::NotDurable => write!(f, "this vault is not backed by disk"),
            RotateRootError::Locked => write!(f, "the vault is locked"),
            RotateRootError::WrongPassphrase => write!(f, "wrong passphrase"),
            RotateRootError::NodeKey(id) => write!(
                f,
                "node {id}'s key did not open under the current root key — nothing was changed"
            ),
            RotateRootError::Store(e) => {
                write!(
                    f,
                    "could not prepare the rotation — nothing was changed: {e}"
                )
            }
            #[cfg(feature = "test-utils")]
            RotateRootError::InjectedCrash => write!(f, "injected crash (test seam)"),
        }
    }
}

impl std::error::Error for RotateRootError {}

fn clone_passphrase(p: &SecretBox<String>) -> SecretBox<String> {
    SecretBox::new(Box::new(p.expose_secret().clone()))
}

#[cfg(feature = "test-utils")]
fn injected_crash() -> StoreError {
    StoreError::Io {
        path: std::path::PathBuf::from("rotation-pending"),
        source: std::io::Error::other("injected crash"),
    }
}

impl BrokerState {
    /// Finish whatever an interrupted rotation left behind (ADR-076), **under
    /// the per-vault lock**: waits for a rotation another process or broker
    /// state is running instead of mistaking its stage for a crash's. Used by
    /// `credmgrd`'s start-up (before any `BrokerState` exists, hence no `self`)
    /// and, through [`BrokerState::recover_interrupted_rotation`], by every
    /// unlock.
    ///
    /// A vault directory that does not exist yet has nothing to recover and is
    /// not created by asking. `Err` — including "another process holds the
    /// lock and did not let go within [`RECOVER_LOCK_WAIT`]" — changes nothing.
    pub fn recover_interrupted_rotation_at(
        paths: &VaultPaths,
        state_dir: &Path,
    ) -> Result<rotation::Recovery, StoreError> {
        if !paths.root().exists() {
            return Ok(rotation::Recovery::Nothing);
        }
        let _exclusive = VaultLock::acquire(paths, RECOVER_LOCK_WAIT)?;
        rotation::recover(paths, state_dir)
    }

    /// Finish whatever an interrupted rotation left behind (ADR-076). Called
    /// first thing by every path that is about to read a root wrap, a node
    /// key, the registry or a manifest.
    pub(super) fn recover_interrupted_rotation(&self) -> Result<rotation::Recovery, StoreError> {
        Self::recover_interrupted_rotation_at(&self.paths, &self.state_dir())
    }

    /// Rotate the root key. See the module docs for what it does and what
    /// protects it; the contract, in short:
    ///
    /// * needs an unlocked, disk-backed vault and the passphrase (factor one
    ///   again — it is also what the new `root.wrap.pass` is made from, and
    ///   the passphrase is never resident);
    /// * on any error before the commit point, **nothing has changed**;
    /// * on success the new recovery code is in the outcome, once, the old one
    ///   is dead, and the broker already runs under the new root key;
    /// * if moving the staged files into place fails *after* the commit, that
    ///   is still a success — the new key is binding and the new recovery code
    ///   is the live one, so it is returned — but the vault is locked and
    ///   [`RotationOutcome::completion_pending`] says the next unlock finishes
    ///   the move. (Returning an error there would throw away the only copy of
    ///   a recovery code that already works.)
    pub fn rotate_root(
        &self,
        passphrase: SecretBox<String>,
        now: i64,
    ) -> Result<RotationOutcome, RotateRootError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        if !self.is_durable() {
            return Err(RotateRootError::NotDurable);
        }
        let old_root: SecretBox<[u8; 32]> = match self
            .session_root
            .read()
            .expect("session root poisoned")
            .as_ref()
        {
            Some(root) if !self.is_locked() => SecretBox::new(Box::new(*root.expose_secret())),
            _ => return Err(RotateRootError::Locked),
        };

        // Factor one, again — and proof that the passphrase about to be
        // re-wrapped is the one that opens the wrap being replaced.
        let proven = self
            .root_from_passphrase(clone_passphrase(&passphrase), "root rotation")
            .map_err(|_| RotateRootError::WrongPassphrase)?;
        if !ct_eq_32(proven.expose_secret(), old_root.expose_secret()) {
            return Err(RotateRootError::WrongPassphrase);
        }
        drop(proven);

        // One writer at a time, for the whole rotation: nothing may persist
        // an old-key file between the plan below and the switch of memory.
        let _one_writer = self.persist_lock.lock().expect("persist lock poisoned");

        // The vault-wide exclusion, held to the end of this function: from here
        // no other process (a second `credmgrd` starting up, a second broker
        // state) can run `recover`, which would delete our stage as a crash
        // leftover, or begin a rotation of its own. Taken after the cheap
        // refusals above and the passphrase proof, and before the first read of
        // anything a recovery could change.
        let _exclusive =
            VaultLock::acquire(&self.paths, ROTATE_LOCK_WAIT).map_err(RotateRootError::Store)?;

        // 0. The closed set. A key file under `keys/` that this build does not
        // know how to re-wrap (the hardware-keystore wrap, a cold orphan key, a
        // later build's addition) is wrapped under the OLD root key; rotating
        // past it would strand it for good, and a rotation cannot be undone.
        // Refusing changes nothing.
        let unknown =
            rotation::unrecognised_key_files(&self.paths).map_err(RotateRootError::Store)?;
        if let Some(first) = unknown.first() {
            let names: Vec<String> = unknown
                .iter()
                .filter_map(|p| {
                    p.strip_prefix(self.paths.keys_dir())
                        .ok()
                        .map(|r| r.display().to_string())
                })
                .collect();
            return Err(RotateRootError::Store(corrupt(
                first.clone(),
                &format!(
                    "this vault holds key material this build cannot re-wrap under a new root \
                     key ({}) — rotating would leave it opening the OLD one",
                    names.join(", ")
                ),
            )));
        }

        // 0b. ADR-079: a seal whose post-commit file moves did not finish leaves a
        // sealed node's files at `nodes/<id>` and `keys/nodes/<id>.key` — a place
        // a rotation does not look, since a sealed id is not a registry node.
        // They would stay wrapped under the OLD root. Finish the moves (they are
        // idempotent) or refuse; a refusal changes nothing.
        for id in self.sealed_ids() {
            if !credmgr_core::registry::is_path_safe_node_id(&id) {
                continue;
            }
            let _ = archive::move_in(&self.paths, &id);
            if archive::has_live_files(&self.paths, &id) {
                return Err(RotateRootError::Store(corrupt(
                    self.paths.node_dir(&id),
                    &format!(
                        "sealed node {id}'s files are not all in its archive yet — a rotation \
                         would leave them wrapped under the OLD root key; unlock again so the \
                         move can finish"
                    ),
                )));
            }
        }

        // 1. The new root key.
        let mut fresh = [0u8; 32];
        OsRng.fill_bytes(&mut fresh);
        let new_root: SecretBox<[u8; 32]> = SecretBox::new(Box::new(fresh));
        fresh.zeroize();
        let old = old_root.expose_secret();
        let new = new_root.expose_secret();

        // 2. Every node key, re-wrapped — from the wrapped blobs, not the hot
        // set (a node locked on its own has a zeroised hot key and a perfectly
        // good wrapped one). All or nothing: one that will not open stops the
        // rotation before anything is written.
        let current_wrapped = self
            .node_wrapped_keys
            .read()
            .expect("node wrapped keys poisoned")
            .clone();
        let mut new_wrapped: HashMap<String, WrappedNodeKey> =
            HashMap::with_capacity(current_wrapped.len());
        for (id, wrapped) in &current_wrapped {
            let rewrapped = rewrap_node_key(old, new, id, wrapped)
                .map_err(|_| RotateRootError::NodeKey(id.clone()))?;
            new_wrapped.insert(id.clone(), rewrapped);
        }
        // A sealed node's retained key lives in memory too (`node.restore`
        // moves it back); under the old root it would not open after this.
        let mut sealed_rewrapped = Vec::new();
        for (id, record) in self
            .sealed_nodes
            .read()
            .expect("sealed nodes poisoned")
            .iter()
        {
            if let Some((wrapped, _)) = &record.key_material {
                let rewrapped = rewrap_node_key(old, new, id, wrapped)
                    .map_err(|_| RotateRootError::NodeKey(id.clone()))?;
                sealed_rewrapped.push((id.clone(), rewrapped));
            }
        }

        // 3. The two root wraps that exist. (`root.wrap.se` is never written —
        // no hardware keystore is built, `04 §2.1` — and if one ever appears,
        // step 0 above has already refused to rotate past it.)
        let state_dir = self.state_dir();
        let pass_wrap = SoftwareKeystore::new(clone_passphrase(&passphrase), state_dir.clone())
            .wrap_root(&new_root)
            .map_err(|_| {
                RotateRootError::Store(corrupt(
                    self.paths.root_wrap_pass(),
                    "could not wrap the new root key under the passphrase",
                ))
            })?;
        let mut code = generate_recovery_code();
        let recovery_wrap = wrap_root_with_recovery_code(&code, new);
        let recovery_code = format_recovery_code(&code);
        code.zeroize();

        // 4. The next on-disk state, computed under the new root key. The
        // external counter is still signed under the old one, so that is the
        // key it is read with.
        let NextState {
            manifests,
            wrapped_keys,
            mut doc,
            external: _,
        } = self
            .build_next_state(new, old, Some(new_wrapped.clone()), now)
            .map_err(RotateRootError::Store)?;

        // 5. Everything else that is signed or wrapped under the root key.
        let mut plan = rotation::plan_resigned_artifacts(&self.paths, old, new)
            .map_err(RotateRootError::Store)?;
        // A key file on disk for a node the registry does not name was not
        // re-wrapped; say so rather than leave it silently undecryptable.
        if let Ok(entries) = std::fs::read_dir(self.paths.keys_dir().join("nodes")) {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(id) = name.strip_suffix(".key") {
                    if !wrapped_keys.contains_key(id) {
                        plan.skipped.push(rotation::Skipped {
                            kind: "stale-node-key",
                            id: id.to_string(),
                            reason:
                                "a key file for a node the registry does not list; left as it was"
                                    .to_string(),
                        });
                    }
                }
            }
        }

        // 5b. ADR-079: the seal records bind the archived node key (a digest) and
        // the archived manifest (generation and HMAC) — both change when the
        // archive's files are re-wrapped and re-signed above, so the records are
        // refreshed in the same registry write. An archive the plan SKIPPED (its
        // `meta.json` did not verify) is left as it is, and so is its record: the
        // files and the binding stay consistent with each other, and a restore
        // refuses them, loudly, as it already would.
        for resigned in &plan.resigned {
            match resigned.kind {
                "seal-archive-key" => {
                    if let Some(record) = doc.sealed.get_mut(&resigned.id) {
                        record.node_key_sha256 = hex_encode(&sha256_of(&resigned.bytes));
                    }
                }
                "seal-archive-manifest" => {
                    if let Some(record) = doc.sealed.get_mut(&resigned.id) {
                        let resigned_doc: ManifestDoc = serde_json::from_slice(&resigned.bytes)
                            .map_err(|e| {
                                RotateRootError::Store(corrupt(
                                    resigned.path.clone(),
                                    &format!("a re-signed archived manifest does not parse: {e}"),
                                ))
                            })?;
                        record.manifest = ManifestBinding {
                            generation: resigned_doc.body.generation,
                            manifest_hmac: resigned_doc.hmac,
                        };
                    }
                }
                _ => {}
            }
        }

        // 6. Stage. Nothing live is touched until the commit record exists.
        let stage_err = RotateRootError::Store;
        let mut stage =
            rotation::RotationStage::begin(&self.paths, &state_dir).map_err(stage_err)?;
        #[cfg(feature = "test-utils")]
        if let Some(n) = self.rotation_fault_staging() {
            stage.crash_after_staged(n);
        }
        #[cfg(feature = "test-utils")]
        if let Some((n, hook)) = self.take_rotation_pause() {
            stage.pause_after_staged(n, hook);
        }
        for resigned in &plan.resigned {
            stage
                .stage_vault_file(&resigned.path, &resigned.bytes)
                .map_err(RotateRootError::Store)?;
        }
        for (id, wrapped) in &wrapped_keys {
            stage
                .stage_vault_file(&self.paths.node_key(id), &wrapped.to_bytes())
                .map_err(RotateRootError::Store)?;
        }
        for (id, body) in &manifests {
            let (bytes, binding) =
                manifest::signed_bytes(&self.paths, new, body).map_err(RotateRootError::Store)?;
            stage
                .stage_vault_file(&self.paths.manifest(id), &bytes)
                .map_err(RotateRootError::Store)?;
            doc.manifests.insert(id.clone(), binding);
        }
        let (registry_bytes, registry_sig) =
            registry_file::signed_bytes(new, &doc).map_err(RotateRootError::Store)?;
        // `.prev` must verify under the new key too, or a later interrupted
        // registry write has nothing to fall back to. The previous pair is
        // signed under the old key — exactly what a rotation retires — so the
        // new pair stands in for it.
        for (path, bytes) in [
            (self.paths.registry(), &registry_bytes),
            (self.paths.registry_sig(), &registry_sig),
            (self.paths.registry_prev(), &registry_bytes),
            (self.paths.registry_sig_prev(), &registry_sig),
        ] {
            stage
                .stage_vault_file(&path, bytes)
                .map_err(RotateRootError::Store)?;
        }
        let counter_bytes = signed_counter_bytes(new, VAULT_GENERATION, doc.vault_generation)
            .map_err(RotateRootError::Store)?;
        stage
            .stage_state_file(
                &FileGenerationCounter::new(state_dir.clone()).file_path(VAULT_GENERATION),
                &counter_bytes,
            )
            .map_err(RotateRootError::Store)?;
        // The two root wraps go last: `root.wrap.pass` is the file that decides
        // which root key the passphrase yields, so it is the final thing to
        // flip.
        stage
            .stage_vault_file(&self.paths.root_wrap_recovery(), &recovery_wrap.to_bytes())
            .map_err(RotateRootError::Store)?;
        stage
            .stage_vault_file(&self.paths.root_wrap_pass(), &pass_wrap.bytes)
            .map_err(RotateRootError::Store)?;

        #[cfg(feature = "test-utils")]
        if self.rotation_fault_is(RotationFault::BeforeCommit) {
            return Err(RotateRootError::InjectedCrash);
        }

        // --- the point of no return -----------------------------------------
        let files_replaced = stage.len();
        let committed = stage.commit();
        #[cfg(feature = "test-utils")]
        let committed = if self.rotation_fault_is(RotationFault::CommitReportsFailure)
            || self.rotation_fault_is(RotationFault::CommitNeverBecomesDurable)
        {
            committed.and_then(|_| Err(injected_crash()))
        } else {
            committed
        };
        // Whether the commit record is known to be on the disk for good — the
        // condition for moving the first live file.
        let mut commit_durable = true;
        if let Err(e) = committed {
            // The commit record is the only thing that binds. If the call
            // reported an error but the record is on disk (the rename landed,
            // a later directory sync did not), the rotation IS committed and
            // must be carried through: reporting "nothing changed" would hide
            // a new recovery code the operator never learns. If the record is
            // not there, nothing changed and the stale stage is dropped by the
            // next `begin`/`recover`.
            if !rotation::is_committed(&self.paths) {
                return Err(RotateRootError::Store(e));
            }
            // …but "on disk" is not "durable": the sync that failed is the one
            // that makes the record survive a power loss. Moving a live file
            // before that is proven could leave, after such a loss, some files
            // moved and no record to finish the job — a vault that opens with
            // neither key. Retry the sync; if it still fails, move nothing and
            // leave the roll-forward to the next recovery (below).
            #[cfg(feature = "test-utils")]
            let retried = if self.rotation_fault_is(RotationFault::CommitNeverBecomesDurable) {
                Err(injected_crash())
            } else {
                rotation::make_commit_durable(&self.paths)
            };
            #[cfg(not(feature = "test-utils"))]
            let retried = rotation::make_commit_durable(&self.paths);
            commit_durable = retried.is_ok();
        }

        #[cfg(feature = "test-utils")]
        if self.rotation_fault_is(RotationFault::AfterCommit) {
            return Err(RotateRootError::InjectedCrash);
        }

        // 7. Memory follows the commit. Nothing here can fail.
        *self.session_root.write().expect("session root poisoned") =
            Some(SecretBox::new(Box::new(*new)));
        *self.wrapped_root.write().expect("wrapped root poisoned") = Some(pass_wrap);
        *self
            .node_wrapped_keys
            .write()
            .expect("node wrapped keys poisoned") = new_wrapped;
        {
            let mut sealed = self.sealed_nodes.write().expect("sealed nodes poisoned");
            for (id, rewrapped) in sealed_rewrapped {
                if let Some(record) = sealed.get_mut(&id) {
                    if let Some((_, public)) = record.key_material.take() {
                        record.key_material = Some((rewrapped, public));
                    }
                }
            }
        }
        {
            let mut live = self.manifests.write().expect("manifests poisoned");
            for (id, body) in manifests {
                live.entry(id).or_insert(body);
            }
        }
        let vault_generation = doc.vault_generation;
        *self.registry_meta.write().expect("registry meta poisoned") = doc;
        // An unlock parked under the old root key must never be completed
        // under it, and a rotation spends the second-factor elevation it
        // needed (`07 §5`: the next high-risk act re-challenges).
        self.pending_gate_unlock
            .lock()
            .expect("pending gate unlock poisoned")
            .clear();
        self.drop_elevations();

        // 8. Roll forward. A failure here is not a failed rotation — it is a
        // committed one that has not finished moving files. Lock, so nothing
        // runs against a half-moved vault; the next unlock finishes the job.
        // The outcome is still returned: the new recovery code is already the
        // live one, and this is the only time it is ever shown.
        #[cfg(feature = "test-utils")]
        if let Some(n) = self.rotation_fault_roll_forward() {
            let _ = rotation::roll_forward_first(&self.paths, &state_dir, n);
            return Err(RotateRootError::InjectedCrash);
        }
        //
        // No file moves until the commit record is proven durable
        // (`commit_durable`): the roll-forward is then left to the next
        // recovery, which runs before anything is read.
        let completion_pending =
            !commit_durable || rotation::roll_forward(&self.paths, &state_dir).is_err();
        let audited = if completion_pending {
            // Locked, and the audit tips are still mid-move — appending now
            // would be overwritten by the staged (older) tip. The next unlock
            // finishes the move; the dispatcher's own decision record covers
            // the request itself when the vault is unlocked to write it.
            self.lock_inner();
            false
        } else {
            // The first record signed under the new key: that a rotation
            // happened, by whom it was asked, and what it touched. No secret —
            // counts only. Best effort, like every audit write: a full disk
            // must not turn a completed, irreversible rotation into an error
            // that hides its recovery code.
            let event = audit::NewEvent {
                actor: "system:maintenance.rotate_root".to_string(),
                action: "maintenance.root_rotated".to_string(),
                node_id: Some(credmgr_core::registry::GLOBAL_ID.to_string()),
                entry_id: None,
                decision: Some("allow".to_string()),
                detail: Some(format!(
                    "root key replaced: {} node keys re-wrapped, {} artefacts re-signed, {} left unsigned",
                    wrapped_keys.len(),
                    plan.resigned.len(),
                    plan.skipped.len()
                )),
                generation: Some(vault_generation),
            };
            let month = audit::year_month_for(now);
            let appended = audit::append(&self.paths, new, &month, event, now).is_ok();
            if appended {
                // The rotation left a month's tip unsigned because the month did
                // not verify (a truncated or edited log). Appending to a month
                // signs its tip over the log *as it now stands* — that is how
                // `audit::append` has always worked, for every request — so the
                // month the rotation's own record lands in verifies again under
                // the new key, damage and all. Say so: "keeps failing
                // verification" holds only for months nothing is appended to.
                for skipped in plan
                    .skipped
                    .iter_mut()
                    .filter(|s| s.kind == "audit-tip" && s.id == month)
                {
                    skipped.reason.push_str(CURRENT_MONTH_CAVEAT);
                }
            }
            appended
        };

        Ok(RotationOutcome {
            recovery_code,
            nodes_rewrapped: wrapped_keys.len(),
            vault_generation,
            files_replaced,
            artifacts_resigned: plan.resigned.len(),
            skipped: plan.skipped,
            completion_pending,
            audited,
        })
    }

    /// Arm a fault for the next [`BrokerState::rotate_root`] (test seam).
    #[cfg(feature = "test-utils")]
    pub fn set_rotation_fault_for_test(&self, fault: Option<RotationFault>) {
        *self.rotation_fault.lock().expect("rotation fault poisoned") = fault;
    }

    /// Freeze the next [`BrokerState::rotate_root`] in the middle of staging
    /// (test seam): when `after_staged` replacement files are on disk and the
    /// next is about to be written, `hook` runs — once — on the rotating
    /// thread, which does not continue until it returns. The concurrency suites
    /// use it to start a second broker state, or a second daemon, while this
    /// rotation holds the vault lock with a half-written stage on disk.
    #[cfg(feature = "test-utils")]
    pub fn set_rotation_pause_for_test(
        &self,
        after_staged: usize,
        hook: std::sync::Arc<dyn Fn() + Send + Sync>,
    ) {
        *self.rotation_pause.lock().expect("rotation pause poisoned") = Some((after_staged, hook));
    }

    #[cfg(feature = "test-utils")]
    fn take_rotation_pause(&self) -> Option<super::RotationPause> {
        self.rotation_pause
            .lock()
            .expect("rotation pause poisoned")
            .take()
    }

    #[cfg(feature = "test-utils")]
    fn rotation_fault_is(&self, fault: RotationFault) -> bool {
        *self.rotation_fault.lock().expect("rotation fault poisoned") == Some(fault)
    }

    #[cfg(feature = "test-utils")]
    fn rotation_fault_staging(&self) -> Option<usize> {
        match *self.rotation_fault.lock().expect("rotation fault poisoned") {
            Some(RotationFault::DuringStaging(n)) => Some(n),
            _ => None,
        }
    }

    #[cfg(feature = "test-utils")]
    fn rotation_fault_roll_forward(&self) -> Option<usize> {
        match *self.rotation_fault.lock().expect("rotation fault poisoned") {
            Some(RotationFault::DuringRollForward(n)) => Some(n),
            _ => None,
        }
    }
}
