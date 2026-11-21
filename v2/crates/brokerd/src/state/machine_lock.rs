//! ADR-165 — the machine lock in the broker (ADR-144's smallest safe version, the file tier).
//!
//! The format and the device key live in `credmgr_keystore::machine_lock`. This module is where the broker
//! meets them:
//!
//! * [`BrokerState::plain_pass_wrap`] turns whatever `root.wrap.pass` holds into the Argon2id wrap the
//!   passphrase opens. An unbound wrap is returned **unchanged**, byte for byte: a vault that was never bound
//!   opens exactly as it did before ADR-165. A bound one is opened with this Mac's device key first; a
//!   missing or different key, or a damaged file, is a [`MachineLockError`] that every passphrase path
//!   reports as `machine_lock_refused`, pointing to the recovery code — never as `wrong_passphrase`, which
//!   would send the owner guessing.
//! * [`BrokerState::machine_lock_reseal`] is called by the root rotation (`rotate.rs`, step 3): a bound vault
//!   stays bound, its new passphrase wrap sealed under this Mac's device key (made if there is none — the
//!   case of a recovery on a new Mac). Unbound stays unbound.
//! * `keystore.bind` is two calls (review N1). [`BrokerState::machine_lock_bind_prepare`] proves the
//!   passphrase and the current recovery code, checks the vault, and draws the new root key, its passphrase
//!   wrap and the new recovery code **in memory only**, answering the code; nothing durable changes, so an
//!   abandoned prepare leaves the old code and root key fully valid. [`BrokerState::machine_lock_bind_commit`]
//!   takes the new code typed back, and only then writes anything.
//! * The commit is **a root rotation** (review P0-1), not a re-seal of the wrap that is
//!   already there: every plain wrap of the old root key that a synced folder, a snapshot or a copy still
//!   holds then wraps a root key nothing signed accepts. The rotation also gives the orphan node a new cold
//!   keypair (when it holds no entries), and then every live node is re-keyed (`node.rekey`'s protocol), so
//!   a whole pre-bind copy of the folder — old wrap **and** old node-key wraps — plus the passphrase opens
//!   nothing written after the bind. What such a copy held before the bind it still opens: that is said
//!   wherever the lock is described. It needs the passphrase (the new wrap is made from it) and the current
//!   recovery code, proven against the root key (review P1-1), and it issues a new recovery code.
//! * [`BrokerState::machine_lock_unbind`] rewrites the one file with an atomic write (temporary file, fsync,
//!   rename, fsync of the directory), so a crash leaves the sealed or the plain form of the same wrap, both
//!   openable. A temporary file a crash leaves is removed under the vault lock before the next bind, unbind
//!   or unlock (review P1-2). The device key is made, durably, before the first wrap sealed under it is
//!   written, and is never deleted.
//! * The **bind record** (`<state>/machine/vaults/<vault id>.json`, outside the vault folder) says that this
//!   Mac bound this vault and lists the node public keys from before the bind. It is keyed by the vault's
//!   identity (`vault.id`, a random id the first bind writes into the vault folder and every copy and backup
//!   carries), never by the folder's path (review N4): a vault re-created at the same path has no identity
//!   or a new one, so it never inherits the record. An unbind removes the record **before** it writes the
//!   plain wrap, so a crash leaves a sealed file with no record (still bound, still opening, and said) and
//!   never a plain file with a record, which the next rotation would seal again. With it, a plain wrap put back
//!   into a bound vault is noticed and named (`plainWhileBound`, and `plain_wrap_while_bound` when it does
//!   not open), a rotation keeps the vault bound even if the sealed file was replaced, and a node whose key
//!   still dates from before the bind (an interrupted bind, a sealed project restored later) is listed so a
//!   second bind can re-key it.
//!
//! The recovery wrap (`root.wrap.recovery`) is never sealed: `vault.recover` does not depend on the device key.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use credmgr_core::recovery::{
    format_recovery_code, generate_recovery_code, parse_recovery_code,
    unwrap_root_with_recovery_code, RootRecoveryWrap, RECOVERY_CODE_LEN,
};
use credmgr_core::registry::ORPHAN_ID;
use credmgr_keystore::machine_lock::{
    self, DeviceKey, KeyFileHealth, MachineLockError, SyncedFolder, WrapForm,
};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_keystore::{KeystoreId, PlatformKeystore, WrappedKey};
use credmgr_store::atomic;
use credmgr_store::error::StoreError;

use super::durable::{ct_eq_32, PassRootError};
use super::rotate::{
    MachineLockIntent, RotateRootError, RotationAudit, RotationOutcome, VaultLock, ROTATE_LOCK_WAIT,
};
use super::{hex_encode, sha256_of, BrokerState};

/// What `keystore.status` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineLockStatus {
    /// The passphrase wrap on disk is sealed to a device key.
    pub bound: bool,
    /// The passphrase wrap starts like a sealed one but is damaged.
    pub damaged: bool,
    /// The id of the key the wrap is sealed to (hex), when bound.
    pub sealed_key_id: Option<String>,
    /// This Mac's device key file is there and readable.
    pub device_key_present: bool,
    /// The id of this Mac's device key (hex), when present.
    pub device_key_id: Option<String>,
    /// Something is at the device key's path that is not a readable 32-byte key.
    pub device_key_unreadable: bool,
    /// The recovery code can open this vault (the recovery wrap exists).
    pub recovery_unlock: bool,
    /// This Mac's bind record for the vault exists: this Mac bound it and has not unbound it.
    pub marked_bound: bool,
    /// Review P0-1: this Mac bound the vault, but the passphrase file on disk is plain. Either an unbind was
    /// interrupted after it wrote the plain wrap, or an older plain wrap was put back (which no longer opens
    /// the vault, because the bind replaced the root key), or a rotation could not seal its new wrap.
    pub plain_while_bound: bool,
    /// Live nodes whose key is still one from before the bind (an interrupted bind, or a sealed project
    /// restored after it): a pre-bind copy of the folder opens what is written to them. A second bind re-keys
    /// them.
    pub pre_bind_nodes: Vec<String>,
    /// The device key file's owner and mode (review P2-3), when it is a regular file.
    pub key_file: Option<KeyFileHealth>,
    /// Review M1: while bound, CredMgr archives still in the vault folder's `backups/` (from before the bind,
    /// a move that failed, or one put back), which every copy of the folder carries. Zero when unbound.
    pub in_folder_archives: usize,
    /// ADR-165 M5: a bind record on this Mac names this folder under another vault id (see
    /// [`DetachedBindRecord`]).
    pub record_detached: Option<DetachedBindRecord>,
    /// ADR-174 O-2: this Mac's device key file carries Time Machine's exclusion. `None` when there is no key
    /// file or it cannot be told (not macOS).
    pub device_key_time_machine_excluded: Option<bool>,
    /// ADR-174 O-2: a Time Machine backup of the vault folder is covered: bound, the wrap sealed to this Mac's
    /// key, that key made already excluded from Time Machine (its provenance says so) and still excluded. A key
    /// made before ADR-174 may be in older backups, so it is never claimed.
    pub device_key_time_machine_covered: bool,
    /// ADR-174 O-3: the vault folder sits in a folder a sync service shares with other Macs; bind refuses it.
    pub synced_folder: Option<SyncedFolder>,
    /// ADR-174 O-5: what each phase of turning the lock on asks for beyond the passphrase and the recovery codes:
    /// `"presence"` (a presence key is enrolled), `"secondFactor"` (a gate is, and no presence key) or `"none"`.
    pub bind_proof: &'static str,
}

impl MachineLockStatus {
    /// Bound, and this Mac holds the key it is bound to: the passphrase opens the vault here.
    pub fn opens_here(&self) -> bool {
        !self.damaged
            && (!self.bound
                || (self.device_key_present && self.sealed_key_id == self.device_key_id))
    }
}

/// How long a prepared bind waits for its recovery code to be typed back (review N1), in seconds.
pub const BIND_PREPARE_SECONDS: i64 = 600;

/// What a bind's prepare drew (review N1), held in memory until the commit: the new root key, its plain
/// passphrase wrap (made from the proven passphrase) and the new recovery code. Zeroised on drop.
pub(crate) struct PreparedBind {
    pub(super) new_root: SecretBox<[u8; 32]>,
    pub(super) pass_wrap: WrappedKey,
    pub(super) code: Zeroizing<[u8; RECOVERY_CODE_LEN]>,
}

/// A prepared bind waiting for its code: tied to the root key it was prepared under (a digest), and to a
/// deadline. `material` is `None` for a vault that was already bound (the commit only re-keys).
pub(crate) struct PendingBind {
    material: Option<PreparedBind>,
    root_digest: [u8; 32],
    expires_at: i64,
    /// SHA-256 of the login token that prepared it (review M4): only that login may commit or cancel it,
    /// and another login's prepare does not overwrite it while it waits. A digest, so the bearer secret is
    /// not copied here.
    session: [u8; 32],
}

/// What a bind's prepare answers.
#[derive(Debug)]
pub struct MachineLockPrepared {
    /// The vault is already bound to this Mac's key: no code was drawn; the commit re-keys stale nodes.
    pub already: bool,
    /// The new recovery code, shown once; the commit takes it typed back. `None` when `already`.
    pub recovery_code: Option<String>,
    /// Seconds the prepared bind waits for the commit.
    pub expires_in: i64,
    /// When `already`: the nodes the commit will re-key.
    pub pre_bind_nodes: Vec<String>,
}

/// The vault's identity file's contents are 32 lower-case hex digits.
fn valid_vault_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `<state>/machine/vaults/<vault id>.json`: this Mac bound the vault whose identity is `vault_id` (review
/// N4). See the module docs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BindRecord {
    v: u32,
    /// The vault's identity (`vault.id`); a record whose id is not the vault's is ignored.
    vault_id: String,
    /// The folder the vault was at when the record was written, for a person reading the file; never used.
    vault: String,
    /// Every node public key (live, sealed, the orphan's) from just before the bind, lower-case hex.
    #[serde(default)]
    pre_bind_public_keys: Vec<String>,
    /// Review M2: written by a bind's commit before its rotation, cleared right after the rotation returns.
    /// A pending record counts only once the passphrase file on disk is sealed (the rotation committed); beside
    /// a plain file it means the commit died before the rotation, and it is ignored: no `plainWhileBound`, and
    /// no rotation seals because of it.
    #[serde(default)]
    pending: bool,
    /// ADR-165 M5: the vault id (`"none"` for no valid `vault.id`) under which this record was last found
    /// detached from the vault folder it names and audited; the audit record is written once per detached
    /// state, not on every status read. Never used to decide anything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detached_noticed: Option<String>,
}

/// ADR-165 M5: this Mac holds a bind record written for this vault folder (its `vault` path) under a vault id
/// that is not the one the folder's `vault.id` holds now — `vault.id` was edited or removed, or the folder was
/// put back to a copy from before the bind (or replaced by another vault). The lock itself still holds for
/// everything written after the bind (the root key was replaced); what is lost is `plainWhileBound` and
/// `preBindNodes`, which are read through the record. Reported, never repaired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedBindRecord {
    /// The vault id the record names.
    pub record_vault_id: String,
    /// What `vault.id` holds now; `None` when it is missing or not a valid id.
    pub vault_id: Option<String>,
}

/// The `vault.status` `warnings` code for a [`DetachedBindRecord`] (ADR-165 M5).
pub const WARN_BIND_RECORD_DETACHED: &str = "machine_lock_record_detached";

/// What a bind did.
#[derive(Debug)]
pub struct MachineLockBound {
    /// The vault was already bound to this Mac's key; no rotation was made (stale node keys, if any, were
    /// still re-keyed).
    pub already: bool,
    /// A device key was made by this call (first bind on this Mac).
    pub device_key_created: bool,
    /// ADR-174 O-2: an older device key that may be in Time Machine was put aside (`machine/retired/`) and the
    /// key made by this call replaces it.
    pub device_key_replaced: bool,
    /// The device key id the wrap is sealed to.
    pub key_id: Option<String>,
    /// The bind's root rotation (its new recovery code, once). `None` when `already`.
    pub rotation: Option<RotationOutcome>,
    /// Nodes given a new key by this call.
    pub nodes_rekeyed: Vec<String>,
    /// Nodes that could not be re-keyed, with why; a pre-bind copy still opens what is written to them until
    /// a second bind (or `node.rekey`) succeeds. Status lists them as `preBindNodes`.
    pub rekey_failed: Vec<(String, String)>,
    /// Review M1: backup archives moved out of the vault folder's `backups/` into the state-side folder.
    pub archives_moved: usize,
    /// Archives that could not be moved, with why; status keeps counting them (`inFolderArchives`).
    pub archives_not_moved: Vec<(String, String)>,
}

/// What a bind or an unbind did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineLockChange {
    /// The file was already in the asked-for form; nothing was written.
    pub already: bool,
    /// A device key was made by this call (first bind on this Mac).
    pub device_key_created: bool,
    /// The device key id the wrap is now sealed to (bind), or was sealed to (unbind).
    pub key_id: Option<String>,
}

/// What a root rotation did to the machine lock (ADR-165).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationMachineLock {
    /// The new passphrase wrap is sealed to this Mac's device key.
    pub bound: bool,
    /// The rotation made this Mac's device key (a recovery on a Mac that had none).
    pub device_key_created: bool,
    /// The vault was bound but this Mac's device key could neither be read nor made, so the new passphrase
    /// wrap was written unsealed rather than refuse the rotation (the reason). Only a recovery can reach this:
    /// every other rotation proves the passphrase through the device key first.
    pub unsealed_because: Option<String>,
}

/// Why a bind or an unbind refused. Nothing was changed, except where a variant says otherwise.
#[derive(Debug)]
pub enum MachineLockOpError {
    /// Bind: the recovery code does not open this vault's recovery wrap to the current root key. Counted as a
    /// failed guess.
    WrongRecoveryCode,
    /// The passphrase does not open the vault. Counted as a failed guess.
    WrongPassphrase,
    /// Unbind: no Touch ID key and no second factor are enrolled, so the passphrase is required.
    PassphraseRequired,
    /// Bind: something in the vault keeps the bind from re-keying every node (a locked node, writes in the
    /// locked-write tray, sealed copies under the orphan key); the reason says what.
    NotReady(String),
    /// Bind: the root rotation refused (nothing changed) or committed and then failed in a way it reports.
    Rotate(RotateRootError),
    /// Bind's commit (review N1): no prepared bind is waiting, it expired, or the vault changed since; the
    /// reason says which. Nothing changed; start again.
    NotPrepared(String),
    /// Bind's commit (review N1): the code typed back is not the new recovery code the prepare showed.
    /// Nothing changed and the prepared bind still waits. Not a guess at anything, so not counted.
    ConfirmMismatch,
    /// Bind (review M4): a bind prepared by another login is waiting; nothing changed.
    BindElsewhere,
    /// Unbind (review M3): this Mac's bind record could not be removed, so the lock was left on (a plain file
    /// beside a record would turn the lock back on at the next rotation). Nothing changed.
    RecordNotRemoved(StoreError),
    /// The passphrase file **was** replaced, and then a later step (the directory fsync) failed: the vault is
    /// now bound (`true`) or unbound (`false`), but the change may not survive a power loss.
    ChangedNotDurable { bound: bool, source: StoreError },
    /// The vault is locked, or not backed by disk.
    Locked,
    /// Bind only: the vault has no recovery wrap, so a lost device key would lock the owner out.
    NoRecoveryCode,
    /// Bind only: the device key would sit inside the vault folder, where every copy of the folder carries it.
    KeyInsideVault(PathBuf),
    /// Bind only (ADR-174 O-3): the vault folder is in a folder a sync service shares with other Macs.
    SyncedFolder(SyncedFolder),
    /// The device key or the sealed wrap could not be used.
    MachineLock(MachineLockError),
    /// A file could not be read or written.
    Store(StoreError),
}

impl std::fmt::Display for MachineLockOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MachineLockOpError::WrongRecoveryCode => write!(f, "the recovery code does not open this vault"),
            MachineLockOpError::WrongPassphrase => write!(f, "wrong passphrase"),
            MachineLockOpError::PassphraseRequired => write!(f, "the passphrase is required"),
            MachineLockOpError::NotReady(why) => write!(f, "{why}"),
            MachineLockOpError::Rotate(e) => write!(f, "{e}"),
            MachineLockOpError::NotPrepared(why) => write!(f, "{why}"),
            MachineLockOpError::ConfirmMismatch => write!(
                f,
                "the code typed back is not the new recovery code; check what you wrote down and type it again"
            ),
            MachineLockOpError::BindElsewhere => write!(
                f,
                "a machine-lock bind is already waiting in another window or terminal; finish or close it there \
                 (locking the vault also forgets it, and it lapses after ten minutes)"
            ),
            MachineLockOpError::RecordNotRemoved(e) => write!(
                f,
                "this Mac's machine-lock record could not be removed ({e}), so the lock was left on; fix the \
                 state folder (its machine/vaults directory) and turn the lock off again"
            ),
            MachineLockOpError::ChangedNotDurable { bound, source } => write!(
                f,
                "the passphrase file was changed (the vault is now {}), but the change may not survive a \
                 power loss: {source}",
                if *bound { "bound" } else { "not bound" }
            ),
            MachineLockOpError::Locked => write!(f, "the vault is locked"),
            MachineLockOpError::NoRecoveryCode => write!(
                f,
                "this vault has no recovery code yet; bind needs one, so that a lost device key \
                 cannot lock you out"
            ),
            MachineLockOpError::KeyInsideVault(p) => write!(
                f,
                "the device key would be stored inside the vault folder ({}), where every copy of \
                 the folder would carry it",
                p.display()
            ),
            MachineLockOpError::SyncedFolder(found) => write!(
                f,
                "the vault folder is in {}, which another Mac can open too",
                found.label()
            ),
            MachineLockOpError::MachineLock(e) => write!(f, "{e}"),
            MachineLockOpError::Store(e) => write!(f, "{e}"),
        }
    }
}

/// Where a test can make a bind or an unbind "die" (ADR-165's crash tests). Compiled only with `test-utils`.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineLockFault {
    /// Bind: the device key is made and on disk and the (pending) bind record written; the rotation has not
    /// started.
    AfterDeviceKey,
    /// Bind: the rotation committed (the wrap is sealed, a new recovery code issued); no node is re-keyed yet.
    AfterRotation,
    /// Unbind: the plain wrap is in **the atomic writer's own temporary file** beside `root.wrap.pass`, written
    /// and fsynced, not yet renamed (exactly what a crash between the fsync and the rename leaves).
    BeforeRename,
    /// Unbind: the rename landed, and then the directory fsync "failed".
    AfterRename,
    /// Unbind (review N4): the bind record is removed and the sealed wrap not yet replaced (a crash between
    /// the two steps).
    AfterRecordRemoved,
}

/// A file's own name, for a report.
fn file_label(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn same_or_inside(path: &Path, dir: &Path) -> bool {
    let canon = |p: &Path| -> PathBuf {
        // The key's own file may not exist yet: resolve the deepest ancestor that does.
        let mut existing = p.to_path_buf();
        let mut rest = Vec::new();
        while !existing.exists() {
            match (
                existing.file_name().map(|n| n.to_os_string()),
                existing.parent(),
            ) {
                (Some(name), Some(parent)) => {
                    rest.push(name);
                    existing = parent.to_path_buf();
                }
                _ => break,
            }
        }
        let mut out = existing.canonicalize().unwrap_or(existing);
        for name in rest.into_iter().rev() {
            out.push(name);
        }
        out
    };
    canon(path).starts_with(canon(dir))
}

impl BrokerState {
    /// `<state>/machine/lock.key` — this Mac's device key. In the state directory, outside the vault folder.
    pub fn device_key_path(&self) -> PathBuf {
        self.state_dir().join("machine").join("lock.key")
    }

    /// The vault's identity (review N4): `vault.id` in the vault folder, when it holds a valid one.
    pub fn vault_id(&self) -> Option<String> {
        let bytes = atomic::read(&self.paths.vault_id()).ok()?;
        let text = String::from_utf8(bytes).ok()?;
        let id = text.trim();
        valid_vault_id(id).then(|| id.to_string())
    }

    /// The vault's identity, written now (a random id) if it has none or a damaged one.
    fn ensure_vault_id(&self) -> Result<String, StoreError> {
        if let Some(id) = self.vault_id() {
            return Ok(id);
        }
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let id = hex_encode(&raw);
        atomic::write(&self.paths.vault_id(), format!("{id}\n").as_bytes())?;
        Ok(id)
    }

    /// `<state>/machine/vaults/<vault id>.json` (several vaults can share one state directory); `None` when
    /// the vault has no identity, which means this Mac never bound it.
    fn bind_record_path_for(&self, vault_id: &str) -> PathBuf {
        self.state_dir()
            .join("machine")
            .join("vaults")
            .join(format!("{vault_id}.json"))
    }

    /// This Mac's record for this vault, as it counts (review M2): a pending record counts only once the
    /// passphrase file on disk is sealed, which happens only when the bind's rotation committed.
    fn read_bind_record(&self) -> Option<BindRecord> {
        let record = self.read_bind_record_raw()?;
        if record.pending {
            let sealed = atomic::read(&self.paths.root_wrap_pass())
                .ok()
                .is_some_and(|b| machine_lock::classify(&b) != WrapForm::Plain);
            if !sealed {
                return None;
            }
        }
        Some(record)
    }

    fn read_bind_record_raw(&self) -> Option<BindRecord> {
        let id = self.vault_id()?;
        let bytes = atomic::read(&self.bind_record_path_for(&id)).ok()?;
        let record: BindRecord = serde_json::from_slice(&bytes).ok()?;
        (record.vault_id == id).then_some(record)
    }

    /// Drop a pending record a commit that died before its rotation left beside a plain file (review M2).
    /// Under the auth lock, so no commit is running.
    fn tidy_pending_bind_record(&self) {
        if let Some(raw) = self.read_bind_record_raw() {
            if raw.pending && self.read_bind_record().is_none() {
                let _ = self.remove_bind_record();
            }
        }
    }

    /// A record for this vault (its identity written now if it has none).
    fn new_bind_record(
        &self,
        pre_bind_public_keys: Vec<String>,
    ) -> Result<BindRecord, MachineLockOpError> {
        Ok(BindRecord {
            v: 2,
            vault_id: self.ensure_vault_id().map_err(MachineLockOpError::Store)?,
            vault: self.paths.root().display().to_string(),
            pre_bind_public_keys,
            pending: false,
            detached_noticed: None,
        })
    }

    fn write_bind_record(&self, record: &BindRecord) -> Result<(), StoreError> {
        let path = self.bind_record_path_for(&record.vault_id);
        let bytes = serde_json::to_vec_pretty(record).map_err(|e| StoreError::Json {
            path: path.clone(),
            source: e,
        })?;
        atomic::write(&path, &bytes)
    }

    /// Remove this Mac's record for this vault. A record that is not there is fine; any other failure is
    /// returned (review M3), so unbind can refuse rather than leave a record that would re-lock later.
    fn remove_bind_record(&self) -> Result<(), StoreError> {
        let Some(id) = self.vault_id() else {
            return Ok(());
        };
        let path = self.bind_record_path_for(&id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io { path, source: e }),
        }
    }

    /// ADR-165 M5: a bind record on this Mac that names this vault folder but a vault id other than the one
    /// `vault.id` holds now (see [`DetachedBindRecord`]). Reads the state folder's records only; changes
    /// nothing. A vault whose current id has its own record is attached (an older record for the same path
    /// is then another vault's, long gone), and a pending record (a bind whose rotation never committed) is
    /// not counted.
    pub fn detached_bind_record(&self) -> Option<DetachedBindRecord> {
        let current = self.vault_id();
        if current.is_some() && self.read_bind_record_raw().is_some() {
            return None;
        }
        let dir = self.state_dir().join("machine").join("vaults");
        let here = self.paths.root();
        let here_text = here.display().to_string();
        let here_canon = std::fs::canonicalize(here).ok();
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .map(|r| {
                r.flatten()
                    .filter_map(|d| d.file_name().into_string().ok())
                    .filter(|n| n.ends_with(".json"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        for name in names {
            let Ok(bytes) = atomic::read(&dir.join(&name)) else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<BindRecord>(&bytes) else {
                continue;
            };
            if record.pending
                || !valid_vault_id(&record.vault_id)
                || name != format!("{}.json", record.vault_id)
                || current.as_deref() == Some(record.vault_id.as_str())
            {
                continue;
            }
            let same_folder = record.vault == here_text
                || (here_canon.is_some()
                    && std::fs::canonicalize(&record.vault).ok() == here_canon);
            if same_folder {
                return Some(DetachedBindRecord {
                    record_vault_id: record.vault_id,
                    vault_id: current,
                });
            }
        }
        None
    }

    /// ADR-165 M5: write the audit record for `detached` once (per detached state: the record remembers the
    /// vault id it was audited under), when the vault is open. The record's other fields are not touched and
    /// nothing is repaired. Best effort, like every audit write.
    pub fn note_detached_bind_record(&self, detached: &DetachedBindRecord, now: i64) {
        let seen = detached
            .vault_id
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let path = self.bind_record_path_for(&detached.record_vault_id);
        let Some(mut record) = atomic::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<BindRecord>(&b).ok())
        else {
            return;
        };
        if record.detached_noticed.as_deref() == Some(seen.as_str()) {
            return;
        }
        let Ok(root) = self.reauth_root_key("machine lock record check") else {
            return;
        };
        let event = credmgr_store::audit::NewEvent {
            actor: "system:keystore".to_string(),
            action: "keystore.bind_record_detached".to_string(),
            node_id: Some(credmgr_core::registry::GLOBAL_ID.to_string()),
            entry_id: None,
            decision: None,
            detail: Some(format!(
                "this Mac's machine-lock record for this vault folder names vault id {}, but the folder's \
                 vault.id {}; the record was left as it is (nothing repaired)",
                detached.record_vault_id,
                match &detached.vault_id {
                    Some(id) => format!("holds {id}"),
                    None => "is missing or damaged".to_string(),
                }
            )),
            generation: None,
        };
        let month = credmgr_store::audit::year_month_for(now);
        if credmgr_store::audit::append(&self.paths, root.expose_secret(), &month, event, now)
            .is_ok()
        {
            record.detached_noticed = Some(seen);
            let _ = self.write_bind_record(&record);
        }
    }

    /// Review M1: move every CredMgr archive out of the vault folder's `backups/` into the state-side folder
    /// (a rename on the same volume; otherwise a durable copy, then the original removed). What could not be
    /// moved is returned with why, and status keeps counting it.
    fn move_in_folder_archives(&self) -> (usize, Vec<(String, String)>) {
        let found = crate::maintenance::list_backup_files_in(&[self.paths.backups_dir()]);
        if found.is_empty() {
            return (0, Vec::new());
        }
        let dest = self.backup_dir();
        if dest == self.paths.backups_dir() {
            return (0, Vec::new());
        }
        let mut moved = 0;
        let mut failed = Vec::new();
        if let Err(e) = std::fs::create_dir_all(&dest) {
            for src in &found {
                failed.push((file_label(src), format!("{}: {e}", dest.display())));
            }
            return (0, failed);
        }
        for src in found {
            let name = file_label(&src);
            let target = dest.join(&name);
            if target.exists() {
                failed.push((name, format!("{} already exists", target.display())));
                continue;
            }
            let result = std::fs::rename(&src, &target).or_else(|_| {
                let bytes = std::fs::read(&src)?;
                atomic::write(&target, &bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
                std::fs::remove_file(&src)
            });
            match result {
                Ok(()) => moved += 1,
                Err(e) => failed.push((name, e.to_string())),
            }
        }
        if let Ok(dir) = std::fs::File::open(&dest) {
            let _ = dir.sync_all();
        }
        if let Ok(dir) = std::fs::File::open(self.paths.backups_dir()) {
            let _ = dir.sync_all();
        }
        (moved, failed)
    }

    /// Every node public key this vault knows now (live nodes, the orphan, sealed nodes' kept keys), hex.
    fn every_public_key(&self) -> Vec<String> {
        let mut keys: BTreeSet<String> = self
            .node_public_keys
            .read()
            .expect("node public keys poisoned")
            .values()
            .map(|k| hex_encode(k.as_bytes()))
            .collect();
        for record in self
            .sealed_nodes
            .read()
            .expect("sealed nodes poisoned")
            .values()
        {
            if let Some((_, public)) = &record.key_material {
                keys.insert(hex_encode(public.as_bytes()));
            }
        }
        keys.into_iter().collect()
    }

    /// Live registry nodes (not the orphan) whose public key is one `record` lists from before the bind.
    fn pre_bind_nodes(&self, record: &BindRecord) -> Vec<String> {
        if record.pre_bind_public_keys.is_empty() {
            return Vec::new();
        }
        let old: BTreeSet<&str> = record
            .pre_bind_public_keys
            .iter()
            .map(String::as_str)
            .collect();
        let live: Vec<String> = self
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .keys()
            .filter(|id| id.as_str() != ORPHAN_ID)
            .cloned()
            .collect();
        let mut out: Vec<String> = live
            .into_iter()
            .filter(|id| {
                self.node_public_key(id)
                    .is_some_and(|k| old.contains(hex_encode(k.as_bytes()).as_str()))
            })
            .collect();
        out.sort();
        out
    }

    /// Review P0-1: this Mac bound the vault, and `root.wrap.pass` on disk is plain.
    pub(super) fn plain_wrap_while_bound(&self) -> bool {
        self.read_bind_record().is_some()
            && atomic::read(&self.paths.root_wrap_pass())
                .ok()
                .is_some_and(|b| machine_lock::classify(&b) == WrapForm::Plain)
    }

    /// The Argon2id wrap the passphrase opens, from the bytes of `root.wrap.pass` (ADR-165). An unbound wrap
    /// is returned as it is; a bound one is opened with this Mac's device key.
    pub(super) fn plain_pass_wrap(
        &self,
        stored: &WrappedKey,
    ) -> Result<WrappedKey, MachineLockError> {
        match machine_lock::classify(&stored.bytes) {
            WrapForm::Plain => Ok(stored.clone()),
            WrapForm::Damaged => Err(MachineLockError::Damaged),
            WrapForm::Sealed { .. } => {
                let key = DeviceKey::load(&self.device_key_path())?
                    .ok_or(MachineLockError::DeviceKeyMissing)?;
                let bytes = machine_lock::open(&key, &stored.bytes)?;
                Ok(WrappedKey {
                    keystore: KeystoreId::Software,
                    bytes,
                })
            }
        }
    }

    /// The plain passphrase wrap of the file on disk, for `maintenance.backup` (review P0-2): `None` when the
    /// vault is not bound (the archive keeps the file as it is), the plain form when it is.
    pub fn plain_pass_wrap_for_backup(&self) -> Result<Option<Vec<u8>>, MachineLockError> {
        let Ok(stored) = atomic::read(&self.paths.root_wrap_pass()) else {
            return Ok(None);
        };
        if machine_lock::classify(&stored) == WrapForm::Plain {
            return Ok(None);
        }
        self.plain_pass_wrap(&WrappedKey {
            keystore: KeystoreId::Software,
            bytes: stored,
        })
        .map(|w| Some(w.bytes))
    }

    /// Whether this vault counts as machine-locked here: its passphrase file is sealed (or damaged-sealed),
    /// or this Mac's bind record says it bound it.
    fn bound_here_or_marked(&self) -> bool {
        let sealed = atomic::read(&self.paths.root_wrap_pass())
            .ok()
            .is_some_and(|b| machine_lock::classify(&b) != WrapForm::Plain);
        sealed || self.read_bind_record().is_some()
    }

    /// Where `maintenance.backup` writes its archives (review N2). An archive of a bound vault holds the
    /// passphrase file unsealed (review P0-2), so it is written outside the vault folder, where no copy of
    /// the folder carries it: `<state>/backups/<vault id>/`, beside the device key (which opens the sealed
    /// file anyway, so the archive adds nothing a holder of the state folder lacks). An unbound vault's
    /// archives stay in `<vault>/backups/`, as before.
    pub fn backup_dir(&self) -> PathBuf {
        if !self.bound_here_or_marked() {
            return self.paths.backups_dir();
        }
        let id = self
            .ensure_vault_id()
            .unwrap_or_else(|_| "unidentified".to_string());
        self.state_dir().join("backups").join(id)
    }

    /// Every folder this vault's archives may be in (the newest across them is the rebuild candidate): the
    /// vault folder's `backups/`, and the state-side folder of a vault that has an identity.
    pub fn backup_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![self.paths.backups_dir()];
        if let Some(id) = self.vault_id() {
            dirs.push(self.state_dir().join("backups").join(id));
        }
        dirs
    }

    /// What `keystore.status` answers. Reads files only; changes nothing.
    pub fn machine_lock_status(&self) -> MachineLockStatus {
        #[cfg(feature = "test-utils")]
        self.machine_lock_touched();
        let stored = atomic::read(&self.paths.root_wrap_pass()).ok();
        let form = stored.as_deref().map(machine_lock::classify);
        let (bound, damaged, sealed_key_id) = match form {
            Some(WrapForm::Sealed { key_id }) => {
                (true, false, Some(machine_lock::key_id_hex(&key_id)))
            }
            Some(WrapForm::Damaged) => (true, true, None),
            _ => (false, false, None),
        };
        let key_path = self.device_key_path();
        let (device_key_present, device_key_id, device_key_unreadable, born_excluded) =
            match DeviceKey::load(&key_path) {
                Ok(Some(k)) => (
                    true,
                    Some(machine_lock::key_id_hex(&k.id())),
                    false,
                    machine_lock::key_born_excluded(&key_path, &k.id()),
                ),
                Ok(None) => (false, None, false, false),
                Err(_) => (false, None, true, false),
            };
        // ADR-174 O-2: Time Machine coverage is claimed only for the key the wrap is sealed to, made already
        // excluded (so no backup ever held it) and still excluded now.
        let excluded = if device_key_present {
            machine_lock::backup_excluded(&key_path)
        } else {
            None
        };
        let time_machine_covered = bound
            && excluded == Some(true)
            && device_key_id.is_some()
            && device_key_id == sealed_key_id
            && born_excluded;
        let record = self.read_bind_record();
        let plain_while_bound = record.is_some() && form == Some(WrapForm::Plain);
        let pre_bind_nodes = match (&record, bound) {
            (Some(r), true) => self.pre_bind_nodes(r),
            _ => Vec::new(),
        };
        let in_folder_archives = if bound || record.is_some() {
            crate::maintenance::list_backup_files_in(&[self.paths.backups_dir()]).len()
        } else {
            0
        };
        MachineLockStatus {
            bound,
            damaged,
            sealed_key_id,
            device_key_present,
            device_key_id,
            device_key_unreadable,
            recovery_unlock: self.recovery_unlock_available(),
            marked_bound: record.is_some(),
            plain_while_bound,
            pre_bind_nodes,
            key_file: machine_lock::key_file_health(&key_path),
            in_folder_archives,
            record_detached: self.detached_bind_record(),
            device_key_time_machine_excluded: excluded,
            device_key_time_machine_covered: time_machine_covered,
            synced_folder: self.vault_synced_folder(),
            bind_proof: if !self.presence_keys().is_empty() {
                "presence"
            } else if self.is_gate_confirmed(super::GATE_SCOPE_VAULT) {
                "secondFactor"
            } else {
                "none"
            },
        }
    }

    /// ADR-174 O-5: what a bind phase checks before it asks for Touch ID or the second factor (so a request that
    /// is refused anyway never costs a prompt): the vault is open and its folder is not shared by a sync service.
    pub fn machine_lock_bind_precheck(&self) -> Result<(), MachineLockOpError> {
        self.require_open_for_machine_lock()?;
        self.refuse_synced_folder_if_plain()
    }

    /// ADR-174 O-2: whether a bind record on this Mac names another vault (a non-pending record for another vault
    /// id and another folder; a record for this folder under an old id is this vault's own, detached). Such a
    /// vault may be sealed under this Mac's device key, so the key is never put aside for it.
    fn another_vault_bound_here(&self) -> bool {
        let dir = self.state_dir().join("machine").join("vaults");
        let current = self.vault_id();
        let here = self.paths.root();
        let here_text = here.display().to_string();
        let here_canon = std::fs::canonicalize(here).ok();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        entries.flatten().any(|e| {
            let Ok(bytes) = atomic::read(&e.path()) else {
                return false;
            };
            let Ok(record) = serde_json::from_slice::<BindRecord>(&bytes) else {
                // An unreadable record may be another vault's: keep the key (the conservative side).
                return true;
            };
            let same_folder = record.vault == here_text
                || (here_canon.is_some()
                    && std::fs::canonicalize(&record.vault).ok() == here_canon);
            !record.pending && current.as_deref() != Some(record.vault_id.as_str()) && !same_folder
        })
    }

    /// ADR-174 O-2: at a bind of a plain vault, put this Mac's device key aside when it may already be in Time
    /// Machine — on a Mac with Time Machine, a key whose provenance does not say it was made already excluded
    /// (made before ADR-174, or its exclusion failed) — unless another vault on this Mac is bound and may be
    /// sealed under it. Answers whether it was put aside. Crash-safe: this vault is plain, so until the bind's
    /// rotation commits no wrap of it needs any key, and the old key is renamed, never deleted.
    fn retire_device_key_if_it_may_be_in_time_machine(
        &self,
        key_path: &Path,
    ) -> Result<bool, MachineLockOpError> {
        let Some(existing) = DeviceKey::load(key_path).map_err(MachineLockOpError::MachineLock)?
        else {
            return Ok(false);
        };
        let time_machine_here = machine_lock::backup_excluded(key_path).is_some();
        if !time_machine_here
            || machine_lock::key_born_excluded(key_path, &existing.id())
            || self.another_vault_bound_here()
        {
            return Ok(false);
        }
        machine_lock::retire_device_key(key_path, &existing)
            .map_err(MachineLockOpError::MachineLock)?;
        Ok(true)
    }

    /// ADR-174 O-3: whether the vault folder sits in iCloud Drive, a CloudStorage provider, a Dropbox folder or a
    /// File Provider domain, where another Mac can open the same folder.
    pub fn vault_synced_folder(&self) -> Option<SyncedFolder> {
        machine_lock::synced_folder(self.paths.root(), self.sync_home().as_deref())
    }

    /// ADR-174 O-3: a bind that would tie a plain vault to this Mac refuses a shared folder, before anything is
    /// proven or written. A vault already bound is not refused here (its "bind again" only finishes re-keying).
    fn refuse_synced_folder_if_plain(&self) -> Result<(), MachineLockOpError> {
        let plain = atomic::read(&self.paths.root_wrap_pass())
            .ok()
            .is_some_and(|b| machine_lock::classify(&b) == WrapForm::Plain);
        if plain {
            if let Some(found) = self.vault_synced_folder() {
                return Err(MachineLockOpError::SyncedFolder(found));
            }
        }
        Ok(())
    }

    /// ADR-174 O-2: keep this Mac's device key out of Time Machine. Called when a bind or a rotation has made or
    /// used the key, and on every passphrase unlock of a sealed vault (re-asserted, since a restore from another
    /// tool or a copy can drop the attribute). Never fatal: a failure is logged name-free (the diagnostic log
    /// holds static words only) and `keystore.status` says so in its warning until a later call succeeds.
    pub(super) fn exclude_device_key_from_time_machine(
        &self,
    ) -> Result<bool, machine_lock::BackupExcludeError> {
        let result = machine_lock::exclude_from_backups(&self.device_key_path());
        if let Err(e) = result {
            crate::diag_log::event(
                "machine_lock_time_machine_exclusion",
                &[
                    ("result", crate::diag_log::Value::Str("failed")),
                    ("reason", crate::diag_log::Value::Str(e.reason())),
                ],
            );
        }
        result
    }

    /// Called by the root rotation with the new plain passphrase wrap: seal it when the vault is bound now
    /// (the current `root.wrap.pass` on disk is sealed or damaged-sealed, **or this Mac's bind record says it
    /// bound the vault** — a sealed file swapped for a plain one does not unbind it), or when `force` (the
    /// bind's own rotation), under this Mac's device key, made if there is none. See
    /// [`RotationMachineLock::unsealed_because`] for when it does not seal.
    pub(super) fn machine_lock_reseal(
        &self,
        plain: WrappedKey,
        force: bool,
    ) -> (WrappedKey, RotationMachineLock) {
        let current = atomic::read(&self.paths.root_wrap_pass()).ok();
        let sealed_now = current
            .as_deref()
            .map(machine_lock::classify)
            .is_some_and(|f| f != WrapForm::Plain);
        let record = self.read_bind_record();
        if !(sealed_now || force || record.is_some()) {
            return (plain, RotationMachineLock::default());
        }
        let unsealed = |why: String| {
            (
                plain.clone(),
                RotationMachineLock {
                    bound: false,
                    device_key_created: false,
                    unsealed_because: Some(why),
                },
            )
        };
        // Review P2-2: the same guard as bind. A key made inside the vault folder travels with every copy.
        let key_path = self.device_key_path();
        if same_or_inside(&key_path, self.paths.root()) {
            return unsealed(format!(
                "the device key would be stored inside the vault folder ({})",
                key_path.display()
            ));
        }
        match DeviceKey::load_or_create(&key_path) {
            Ok((key, created)) => {
                // ADR-174 O-2 (not for the bind's own rotation: its commit has just done it).
                if !force {
                    let _ = self.exclude_device_key_from_time_machine();
                }
                if record.is_none() && !force {
                    // (Not for the bind's own rotation: its commit writes and finishes its record, review M2.)
                    // A recovery that kept a vault bound on a Mac that had no record of it (a new Mac): from
                    // now on this Mac notices a plain wrap put back. Best effort; nothing depends on it.
                    if let Ok(r) = self.new_bind_record(Vec::new()) {
                        let _ = self.write_bind_record(&r);
                    }
                }
                let sealed = machine_lock::seal(&key, &plain.bytes);
                (
                    WrappedKey {
                        keystore: KeystoreId::Software,
                        bytes: sealed,
                    },
                    RotationMachineLock {
                        bound: true,
                        device_key_created: created,
                        unsealed_because: None,
                    },
                )
            }
            Err(e) => unsealed(e.to_string()),
        }
    }

    /// `keystore.bind`, phase one (review N1): check everything a bind needs and draw what it will commit,
    /// **changing nothing durable**. Needs the vault open, the passphrase (proven: the new wrap is made from
    /// it) and the current recovery code (proven to open the recovery wrap to the current root key, so a bind
    /// never leaves an owner whose only other way in is a code that does not work). Refuses when a node cannot
    /// be re-keyed.
    ///
    /// On an unbound vault it draws the new root key, makes its plain passphrase wrap (Argon2id, from the
    /// proven passphrase) and draws the new recovery code, and keeps all three **in memory only**, tied to the
    /// root key the vault runs under now, for [`BIND_PREPARE_SECONDS`]. The answer carries the new code; the
    /// commit takes it typed back. Nothing is written: no device key, no bind record, no wrap. An abandoned
    /// prepare (the owner closes the dialog, the broker restarts, the vault locks, the time runs out, any
    /// rotation happens) leaves the vault exactly as it was, and the old code and the old root key keep
    /// working. A second prepare replaces the first.
    ///
    /// On a vault already bound to this Mac nothing is drawn (no new code); the commit then re-keys the nodes
    /// whose key dates from before the bind.
    ///
    /// `session` is the caller's login token (review M4): the prepared bind belongs to that login, and a
    /// prepare from another login is refused while one waits (unless that login has ended).
    pub fn machine_lock_bind_prepare(
        &self,
        passphrase: SecretBox<String>,
        recovery_code: &str,
        session: &str,
        now: i64,
    ) -> Result<MachineLockPrepared, MachineLockOpError> {
        #[cfg(feature = "test-utils")]
        self.machine_lock_touched();
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        self.require_open_for_machine_lock()?;
        let session_root = self.session_root_copy()?;
        let session = sha256_of(session.as_bytes());
        if self.pending_bind_held_elsewhere(&session, now) {
            return Err(MachineLockOpError::BindElsewhere);
        }
        // ADR-174 O-3: a folder another Mac can open is refused before anything is proven, drawn or written.
        self.refuse_synced_folder_if_plain()?;
        self.tidy_pending_bind_record();

        // A lockout guard (review P1-1): the code the owner holds must open the recovery wrap to the root key
        // the vault runs under now. A wrap that exists but that their code does not open is no way back in.
        let recovery = atomic::read(&self.paths.root_wrap_recovery())
            .ok()
            .and_then(|b| RootRecoveryWrap::from_bytes(&b).ok())
            .ok_or(MachineLockOpError::NoRecoveryCode)?;
        let code = Zeroizing::new(
            parse_recovery_code(recovery_code)
                .map_err(|_| MachineLockOpError::WrongRecoveryCode)?,
        );
        let opened = Zeroizing::new(
            unwrap_root_with_recovery_code(&code, &recovery)
                .map_err(|_| MachineLockOpError::WrongRecoveryCode)?,
        );
        if !ct_eq_32(&opened, session_root.expose_secret()) {
            return Err(MachineLockOpError::WrongRecoveryCode);
        }
        drop(opened);
        drop(code);

        let key_path = self.device_key_path();
        if same_or_inside(&key_path, self.paths.root()) {
            return Err(MachineLockOpError::KeyInsideVault(key_path));
        }

        // The passphrase: proven (the new wrap is made from it, so a typo must not become it).
        let proven = self
            .root_from_passphrase(clone_secret(&passphrase), "machine lock bind")
            .map_err(|e| match e {
                PassRootError::MachineLock(m) => MachineLockOpError::MachineLock(m),
                PassRootError::Wrong => MachineLockOpError::WrongPassphrase,
            })?;
        if !ct_eq_32(proven.expose_secret(), session_root.expose_secret()) {
            return Err(MachineLockOpError::WrongPassphrase);
        }
        drop(proven);

        self.sweep_pass_wrap_temps()?;
        let stored =
            atomic::read(&self.paths.root_wrap_pass()).map_err(MachineLockOpError::Store)?;
        let root_digest = sha256_of(session_root.expose_secret());
        let expires_at = now.saturating_add(BIND_PREPARE_SECONDS);
        match machine_lock::classify(&stored) {
            WrapForm::Sealed { .. } => {
                // Already bound. Say so only when this Mac's key is the one it is bound to and it opens;
                // otherwise report why the passphrase would not open it here.
                self.open_sealed_here(&stored)?;
                let stale = self
                    .read_bind_record()
                    .map(|r| self.pre_bind_nodes(&r))
                    .unwrap_or_default();
                self.check_rekeyable(&stale)?;
                self.set_pending_bind(Some(PendingBind {
                    material: None,
                    root_digest,
                    expires_at,
                    session,
                }));
                return Ok(MachineLockPrepared {
                    already: true,
                    recovery_code: None,
                    expires_in: BIND_PREPARE_SECONDS,
                    pre_bind_nodes: stale,
                });
            }
            WrapForm::Damaged => {
                return Err(MachineLockOpError::MachineLock(MachineLockError::Damaged));
            }
            WrapForm::Plain => {}
        }

        // Everything that would stop the commit is refused now, before the owner is shown a code.
        self.bind_preflight()?;
        // A key file that is there but unusable (a directory, a symlink, another user's) would stop the
        // commit; say so now. A missing one is fine: the commit makes it.
        DeviceKey::load(&key_path).map_err(MachineLockOpError::MachineLock)?;

        let mut fresh = [0u8; 32];
        OsRng.fill_bytes(&mut fresh);
        let new_root: SecretBox<[u8; 32]> = SecretBox::new(Box::new(fresh));
        fresh.zeroize();
        let pass_wrap = SoftwareKeystore::new(clone_secret(&passphrase), self.state_dir())
            .wrap_root(&new_root)
            .map_err(|e| MachineLockOpError::MachineLock(MachineLockError::Io(e.to_string())))?;
        drop(passphrase);
        let new_code = Zeroizing::new(generate_recovery_code());
        let shown = format_recovery_code(&new_code);
        self.set_pending_bind(Some(PendingBind {
            material: Some(PreparedBind {
                new_root,
                pass_wrap,
                code: new_code,
            }),
            root_digest,
            expires_at,
            session,
        }));
        Ok(MachineLockPrepared {
            already: false,
            recovery_code: Some(shown),
            expires_in: BIND_PREPARE_SECONDS,
            pre_bind_nodes: Vec::new(),
        })
    }

    /// `keystore.bind`, phase two (review N1): the owner has typed the new recovery code back, so they
    /// provably hold the code the bind is about to make the only one that works. Only then is anything
    /// written: the vault's identity file (if it has none), this Mac's device key (if it has none), the bind
    /// record, and the root rotation that seals the new passphrase wrap and commits the new code; then every
    /// live node is re-keyed. A crash before the rotation's commit record leaves the old root key, the old
    /// code and the plain wrap fully valid (the rotation's own contract); after it, the new code, which the
    /// owner has typed back.
    ///
    /// The whole code is typed back, as at `vault.init_confirm`: the commit proves exactly the code that will
    /// be needed, not a part of it. A wrong code is refused and the prepared bind kept, so the owner can try
    /// again; it guesses at nothing (the code was just shown to this login), so it is not counted. A prepared
    /// bind that is missing, has expired, or was made under a root key the vault no longer runs under is
    /// refused (`NotPrepared`), and the owner starts again.
    pub fn machine_lock_bind_commit(
        &self,
        typed_code: Option<&str>,
        session: &str,
        now: i64,
    ) -> Result<MachineLockBound, MachineLockOpError> {
        let session = sha256_of(session.as_bytes());
        #[cfg(feature = "test-utils")]
        self.machine_lock_touched();
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        self.require_open_for_machine_lock()?;
        let session_root = self.session_root_copy()?;
        // ADR-174 O-3, again at the commit (the folder may have become synced since the prepare). The prepared
        // bind keeps waiting; nothing was written.
        self.refuse_synced_folder_if_plain()?;

        let pending = {
            let mut slot = self
                .machine_lock_pending
                .lock()
                .expect("machine lock pending poisoned");
            let Some(waiting) = slot.as_ref() else {
                return Err(MachineLockOpError::NotPrepared(
                    "no bind is waiting for its recovery code (it was never started, was abandoned, or the \
                     vault was locked since); start again"
                        .into(),
                ));
            };
            if !ct_eq_32(&waiting.session, &session) {
                // Another login's bind (review M4): not this caller's to commit; it keeps waiting.
                return Err(MachineLockOpError::BindElsewhere);
            }
            if now > waiting.expires_at {
                *slot = None;
                return Err(MachineLockOpError::NotPrepared(
                    "the prepared bind expired before its recovery code was typed back; nothing changed, so \
                     start again (the old recovery code still works)"
                        .into(),
                ));
            }
            if !ct_eq_32(
                &waiting.root_digest,
                &sha256_of(session_root.expose_secret()),
            ) {
                *slot = None;
                return Err(MachineLockOpError::NotPrepared(
                    "the vault's root key changed since the bind was prepared (a passphrase change, a \
                     rotation or a recovery); start again"
                        .into(),
                ));
            }
            if let Some(material) = &waiting.material {
                let typed = typed_code
                    .and_then(|c| parse_recovery_code(c).ok())
                    .map(Zeroizing::new);
                let matches = typed.as_ref().is_some_and(|t| ct_eq_32(t, &material.code));
                if !matches {
                    return Err(MachineLockOpError::ConfirmMismatch);
                }
            }
            slot.take().expect("checked above")
        };

        let key_path = self.device_key_path();
        if same_or_inside(&key_path, self.paths.root()) {
            return Err(MachineLockOpError::KeyInsideVault(key_path));
        }
        self.sweep_pass_wrap_temps()?;
        let stored =
            atomic::read(&self.paths.root_wrap_pass()).map_err(MachineLockOpError::Store)?;

        let Some(prepared) = pending.material else {
            // The vault was bound at the prepare: finish any re-key an interrupted bind (or a later restore
            // of a sealed project) left.
            let key_id = self.open_sealed_here(&stored)?;
            // ADR-174 O-2: verified on every bind; a failure is a status warning, never a refusal.
            let _ = self.exclude_device_key_from_time_machine();
            let record = match self.read_bind_record() {
                Some(r) => r,
                None => {
                    let r = self.new_bind_record(Vec::new())?;
                    self.write_bind_record(&r)
                        .map_err(MachineLockOpError::Store)?;
                    r
                }
            };
            let stale = self.pre_bind_nodes(&record);
            self.check_rekeyable(&stale)?;
            let (nodes_rekeyed, rekey_failed) = self.rekey_for_bind(&stale, now);
            // Review M1: archives still in the vault folder (a move that failed, or one put back) go now.
            let (archives_moved, archives_not_moved) = self.move_in_folder_archives();
            return Ok(MachineLockBound {
                already: true,
                device_key_created: false,
                device_key_replaced: false,
                key_id: Some(key_id),
                rotation: None,
                nodes_rekeyed,
                rekey_failed,
                archives_moved,
                archives_not_moved,
            });
        };
        if machine_lock::classify(&stored) != WrapForm::Plain {
            return Err(MachineLockOpError::NotPrepared(
                "the passphrase file changed since the bind was prepared; start again".into(),
            ));
        }
        // The vault may have changed between the phases (a node locked, a write queued): refuse again.
        let live = self.bind_preflight()?;

        // ADR-174 O-2: a key that may already be in Time Machine (made before ADR-174, or its exclusion never
        // held) is put aside and a fresh one, excluded before it reaches its path, is made: this vault is plain,
        // so no wrap of it needs the old key. Not when another vault on this Mac is sealed under it.
        let device_key_replaced = self.retire_device_key_if_it_may_be_in_time_machine(&key_path)?;
        let (key, created) =
            DeviceKey::load_or_create(&key_path).map_err(MachineLockOpError::MachineLock)?;
        // The exclusion verified (and set, for a key kept); a failure is a status warning, never a refusal.
        let _ = self.exclude_device_key_from_time_machine();
        // Review M2: the record (with the pre-bind public keys) is durable before the rotation, but marked
        // pending: it counts only once the passphrase file is sealed, so a crash before the rotation commits
        // leaves no record that matters (no false `plainWhileBound`, no re-lock at the next rotation).
        let mut record = self.new_bind_record(self.every_public_key())?;
        record.pending = true;
        self.write_bind_record(&record)
            .map_err(MachineLockOpError::Store)?;
        #[cfg(feature = "test-utils")]
        if self.machine_lock_fault_is(MachineLockFault::AfterDeviceKey) {
            return Err(MachineLockOpError::Store(injected()));
        }

        let rotation = match self.rotate_root_locked(
            &session_root,
            RotationAudit::MACHINE_LOCK_BIND,
            MachineLockIntent::Bind(&prepared),
            // The bind re-keys every live node itself, after the rotation (`rekey_for_bind`).
            super::rotate::NodeKeys::Rewrap,
            now,
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                // Nothing changed (that is the rotation's contract for every error but a test's injected
                // crash): this Mac did not bind the vault after all.
                // (A pending record beside the plain file is ignored anyway; this only tidies.)
                #[cfg(feature = "test-utils")]
                if !matches!(e, RotateRootError::InjectedCrash) {
                    let _ = self.remove_bind_record();
                }
                #[cfg(not(feature = "test-utils"))]
                let _ = self.remove_bind_record();
                return Err(MachineLockOpError::Rotate(e));
            }
        };
        // The rotation committed: the record is final. If this write fails the pending record still counts
        // (the file is sealed now), so nothing depends on it.
        record.pending = false;
        let _ = self.write_bind_record(&record);
        // Review M1: archives written before the bind leave the vault folder, so later copies do not carry them.
        let (archives_moved, archives_not_moved) = self.move_in_folder_archives();
        drop(prepared);
        drop(session_root);
        #[cfg(feature = "test-utils")]
        if self.machine_lock_fault_is(MachineLockFault::AfterRotation) {
            return Ok(MachineLockBound {
                already: false,
                device_key_created: created,
                device_key_replaced,
                key_id: Some(machine_lock::key_id_hex(&key.id())),
                rotation: Some(rotation),
                nodes_rekeyed: Vec::new(),
                rekey_failed: Vec::new(),
                archives_moved,
                archives_not_moved,
            });
        }

        // A committed rotation that could not finish moving its files locked the vault; the next unlock
        // finishes it and a second bind then re-keys. Otherwise re-key every live node now.
        let (nodes_rekeyed, rekey_failed) = if rotation.completion_pending {
            (
                Vec::new(),
                live.iter()
                    .map(|id| {
                        (
                            id.clone(),
                            "the vault locked to finish the root rotation; unlock and bind again"
                                .to_string(),
                        )
                    })
                    .collect(),
            )
        } else {
            self.rekey_for_bind(&live, now)
        };
        Ok(MachineLockBound {
            already: false,
            device_key_created: created,
            device_key_replaced,
            key_id: Some(machine_lock::key_id_hex(&key.id())),
            rotation: Some(rotation),
            nodes_rekeyed,
            rekey_failed,
            archives_moved,
            archives_not_moved,
        })
    }

    /// Whether a prepared bind is waiting for its code (for status and tests).
    pub fn machine_lock_bind_pending(&self, now: i64) -> bool {
        self.machine_lock_pending
            .lock()
            .expect("machine lock pending poisoned")
            .as_ref()
            .is_some_and(|p| now <= p.expires_at)
    }

    /// ADR-174 O-5: whether this login's commit would go past its own checks (a bind prepared by this login, not
    /// expired, under the root key the vault runs under now). Only then does the commit ask for Touch ID or the
    /// second factor; any other commit refuses on its own, at no prompt. Reads memory only.
    pub fn machine_lock_bind_commit_would_proceed(&self, session: &str, now: i64) -> bool {
        let session = sha256_of(session.as_bytes());
        let Ok(root) = self.session_root_copy() else {
            return false;
        };
        let digest = sha256_of(root.expose_secret());
        self.machine_lock_pending
            .lock()
            .expect("machine lock pending poisoned")
            .as_ref()
            .is_some_and(|p| {
                now <= p.expires_at
                    && ct_eq_32(&p.session, &session)
                    && ct_eq_32(&p.root_digest, &digest)
            })
    }

    /// `keystore.bind` `cancel`: forget this login's prepared bind. Nothing durable was changed by it. Another
    /// login's waiting bind is not this caller's to forget (review M4).
    pub fn cancel_machine_lock_bind(
        &self,
        session: &str,
        now: i64,
    ) -> Result<(), MachineLockOpError> {
        #[cfg(feature = "test-utils")]
        self.machine_lock_touched();
        let session = sha256_of(session.as_bytes());
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        if self.pending_bind_held_elsewhere(&session, now) {
            return Err(MachineLockOpError::BindElsewhere);
        }
        self.set_pending_bind(None);
        Ok(())
    }

    /// A bind prepared by another login is waiting (not expired, and that login is still live).
    fn pending_bind_held_elsewhere(&self, session: &[u8; 32], now: i64) -> bool {
        let slot = self
            .machine_lock_pending
            .lock()
            .expect("machine lock pending poisoned");
        let Some(waiting) = slot.as_ref() else {
            return false;
        };
        if ct_eq_32(&waiting.session, session) || now > waiting.expires_at {
            return false;
        }
        self.session_tokens
            .read()
            .expect("session tokens poisoned")
            .iter()
            .any(|t| ct_eq_32(&sha256_of(t.as_bytes()), &waiting.session))
    }

    /// Forget a prepared bind (the vault locked, or the owner cancelled).
    pub(crate) fn set_pending_bind(&self, pending: Option<PendingBind>) {
        *self
            .machine_lock_pending
            .lock()
            .expect("machine lock pending poisoned") = pending;
    }

    fn session_root_copy(&self) -> Result<SecretBox<[u8; 32]>, MachineLockOpError> {
        self.session_root
            .read()
            .expect("session root poisoned")
            .as_ref()
            .map(|r| SecretBox::new(Box::new(*r.expose_secret())))
            .ok_or(MachineLockOpError::Locked)
    }

    /// Open a sealed `root.wrap.pass` with this Mac's key (proving it is bound here); its key id, hex.
    fn open_sealed_here(&self, stored: &[u8]) -> Result<String, MachineLockOpError> {
        let WrapForm::Sealed { key_id } = machine_lock::classify(stored) else {
            return Err(MachineLockOpError::NotPrepared(
                "the passphrase file changed since the bind was prepared; start again".into(),
            ));
        };
        let key = DeviceKey::load(&self.device_key_path())
            .map_err(MachineLockOpError::MachineLock)?
            .ok_or(MachineLockOpError::MachineLock(
                MachineLockError::DeviceKeyMissing,
            ))?;
        machine_lock::open(&key, stored).map_err(MachineLockOpError::MachineLock)?;
        Ok(machine_lock::key_id_hex(&key_id))
    }

    /// The bind's checks on the vault (every live node can be re-keyed, the orphan holds no sealed copy);
    /// the live node ids.
    fn bind_preflight(&self) -> Result<Vec<String>, MachineLockOpError> {
        let live = self.live_node_ids();
        self.check_rekeyable(&live)?;
        let orphan_rows = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(ORPHAN_ID)
            .map(|m| m.entries.len())
            .unwrap_or(0);
        if orphan_rows > 0 {
            return Err(MachineLockOpError::NotReady(format!(
                "this vault holds {orphan_rows} sealed {} under the orphan key, and the bind cannot yet \
                 move {} to a new orphan key; restore or destroy the sealed projects first",
                if orphan_rows == 1 { "copy" } else { "copies" },
                if orphan_rows == 1 { "it" } else { "them" }
            )));
        }
        Ok(live)
    }

    /// Live registry nodes, not the orphan, sorted.
    fn live_node_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .keys()
            .filter(|id| id.as_str() != ORPHAN_ID)
            .cloned()
            .collect();
        ids.sort();
        ids
    }

    /// The bind's pre-flight: every node in `ids` can be re-keyed (`rekey_node_durable`'s own refusals, asked
    /// before anything changes).
    fn check_rekeyable(&self, ids: &[String]) -> Result<(), MachineLockOpError> {
        for id in ids {
            if self.is_node_locked(id) {
                return Err(MachineLockOpError::NotReady(format!(
                    "node {id} is locked; unlock it first, so the bind can give it a new key"
                )));
            }
            let pending_dir = self.paths.node_dir(id).join("pending");
            let on_disk_pending = std::fs::read_dir(pending_dir)
                .map(|r| {
                    r.flatten()
                        .any(|d| d.path().extension().and_then(|e| e.to_str()) == Some("env"))
                })
                .unwrap_or(false);
            if !self.list_pending(id).is_empty() || on_disk_pending {
                return Err(MachineLockOpError::NotReady(format!(
                    "node {id} has writes waiting in the locked-write tray; accept or discard them first"
                )));
            }
        }
        Ok(())
    }

    fn rekey_for_bind(&self, ids: &[String], now: i64) -> (Vec<String>, Vec<(String, String)>) {
        let mut done = Vec::new();
        let mut failed = Vec::new();
        for id in ids {
            match self.rekey_node_durable(id, now) {
                Ok(_) => done.push(id.clone()),
                Err(e) => failed.push((
                    id.clone(),
                    match e {
                        crate::protocol::OpError::Internal(m)
                        | crate::protocol::OpError::Malformed(m)
                        | crate::protocol::OpError::NotFound(m) => m,
                        other => format!("{other:?}"),
                    },
                )),
            }
        }
        (done, failed)
    }

    /// `keystore.unbind`: write the plain passphrase wrap back (the caller has checked presence and the second
    /// factor where they are enrolled). `passphrase`, when given, is proven first (review P2-4: the caller
    /// sends `require_passphrase` when neither a presence key nor a second factor is enrolled). The device key
    /// is kept. Idempotent: a plain file answers `already` (and finishes an interrupted unbind by removing the
    /// bind record).
    pub fn machine_lock_unbind(
        &self,
        passphrase: Option<SecretBox<String>>,
        require_passphrase: bool,
    ) -> Result<MachineLockChange, MachineLockOpError> {
        #[cfg(feature = "test-utils")]
        self.machine_lock_touched();
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        self.require_open_for_machine_lock()?;
        match passphrase {
            Some(p) => {
                let proven = self
                    .root_from_passphrase(p, "machine lock unbind")
                    .map_err(|e| match e {
                        PassRootError::MachineLock(m) => MachineLockOpError::MachineLock(m),
                        PassRootError::Wrong => MachineLockOpError::WrongPassphrase,
                    })?;
                let same = self
                    .session_root
                    .read()
                    .expect("session root poisoned")
                    .as_ref()
                    .is_some_and(|r| ct_eq_32(r.expose_secret(), proven.expose_secret()));
                if !same {
                    return Err(MachineLockOpError::WrongPassphrase);
                }
            }
            None if require_passphrase => return Err(MachineLockOpError::PassphraseRequired),
            None => {}
        }
        let _one_writer = self.persist_lock.lock().expect("persist lock poisoned");
        let _exclusive =
            VaultLock::acquire(&self.paths, ROTATE_LOCK_WAIT).map_err(MachineLockOpError::Store)?;
        let _ = atomic::remove_stray_temps(&self.paths.root_wrap_pass());
        let stored =
            atomic::read(&self.paths.root_wrap_pass()).map_err(MachineLockOpError::Store)?;
        let key_id = match machine_lock::classify(&stored) {
            WrapForm::Plain => {
                // Not bound; a leftover record goes, and one that cannot go is said (review M3).
                self.remove_bind_record()
                    .map_err(MachineLockOpError::RecordNotRemoved)?;
                return Ok(MachineLockChange {
                    already: true,
                    device_key_created: false,
                    key_id: None,
                });
            }
            WrapForm::Damaged => {
                return Err(MachineLockOpError::MachineLock(MachineLockError::Damaged))
            }
            WrapForm::Sealed { key_id } => key_id,
        };
        let key = DeviceKey::load(&self.device_key_path())
            .map_err(MachineLockOpError::MachineLock)?
            .ok_or(MachineLockOpError::MachineLock(
                MachineLockError::DeviceKeyMissing,
            ))?;
        let plain = machine_lock::open(&key, &stored).map_err(MachineLockOpError::MachineLock)?;
        // Review N4: the record goes first. A crash after this line leaves the sealed file and no record:
        // still bound, still opening with the passphrase here, and status says it is bound. The other order
        // could leave a plain file with a record, and the next rotation would turn the lock back on.
        // Review M3: a record that cannot be removed stops the unbind here, with the file still sealed.
        let record = self.read_bind_record_raw();
        self.remove_bind_record()
            .map_err(MachineLockOpError::RecordNotRemoved)?;
        #[cfg(feature = "test-utils")]
        if self.machine_lock_fault_is(MachineLockFault::AfterRecordRemoved) {
            return Err(MachineLockOpError::Store(injected()));
        }
        let replaced = self.replace_pass_wrap(&stored, &plain);
        if let Err(MachineLockOpError::Store(_)) = &replaced {
            // The file was not replaced (`replace_pass_wrap` read it back): the vault is still bound, so its
            // record is put back.
            let still_sealed = atomic::read(&self.paths.root_wrap_pass())
                .ok()
                .is_some_and(|b| machine_lock::classify(&b) != WrapForm::Plain);
            if let (true, Some(r)) = (still_sealed, record) {
                let _ = self.write_bind_record(&r);
            }
        }
        replaced?;
        Ok(MachineLockChange {
            already: false,
            device_key_created: false,
            key_id: Some(machine_lock::key_id_hex(&key_id)),
        })
    }

    /// Remove the temporary files a crash inside an earlier write of `root.wrap.pass` left (review P1-2),
    /// under the vault lock, so no other writer's file is mistaken for one.
    fn sweep_pass_wrap_temps(&self) -> Result<(), MachineLockOpError> {
        let _exclusive =
            VaultLock::acquire(&self.paths, ROTATE_LOCK_WAIT).map_err(MachineLockOpError::Store)?;
        atomic::remove_stray_temps(&self.paths.root_wrap_pass())
            .map_err(MachineLockOpError::Store)?;
        Ok(())
    }

    fn require_open_for_machine_lock(&self) -> Result<(), MachineLockOpError> {
        let open = self.is_durable()
            && !self.is_locked()
            && self
                .session_root
                .read()
                .expect("session root poisoned")
                .is_some();
        if open {
            Ok(())
        } else {
            Err(MachineLockOpError::Locked)
        }
    }

    /// Replace `root.wrap.pass` (`old` → `new`, two forms of the same wrap) with one atomic write, check what
    /// landed, and keep memory in step with **what is on disk** (review P1-2): on an error the file is read
    /// again, and the answer says whether it was changed. On a write that does not read back, the old bytes
    /// are put back.
    fn replace_pass_wrap(&self, old: &[u8], new: &[u8]) -> Result<(), MachineLockOpError> {
        let path = self.paths.root_wrap_pass();
        #[cfg(feature = "test-utils")]
        if self.machine_lock_fault_is(MachineLockFault::BeforeRename) {
            // What a crash between the fsync and the rename leaves: the atomic writer's own temporary file,
            // holding `new`, beside the untouched old file.
            atomic::write_temp(&path, new).map_err(MachineLockOpError::Store)?;
            return Err(MachineLockOpError::Store(injected()));
        }
        let written = atomic::write(&path, new);
        #[cfg(feature = "test-utils")]
        let written = if self.machine_lock_fault_is(MachineLockFault::AfterRename) {
            written.and(Err(injected()))
        } else {
            written
        };
        if let Err(source) = written {
            let on_disk = atomic::read(&path).ok();
            if let Some(bytes) = on_disk {
                self.set_wrapped_root(&bytes);
                if bytes == new {
                    return Err(MachineLockOpError::ChangedNotDurable {
                        bound: machine_lock::classify(new) != WrapForm::Plain,
                        source,
                    });
                }
            }
            return Err(MachineLockOpError::Store(source));
        }
        let landed = atomic::read(&path).map_err(MachineLockOpError::Store)?;
        if landed != new {
            let _ = atomic::write(&path, old);
            if let Ok(bytes) = atomic::read(&path) {
                self.set_wrapped_root(&bytes);
            }
            return Err(MachineLockOpError::Store(super::durable::corrupt(
                path,
                "the passphrase wrap did not read back as written; the previous one was put back",
            )));
        }
        self.set_wrapped_root(new);
        Ok(())
    }

    fn set_wrapped_root(&self, bytes: &[u8]) {
        *self.wrapped_root.write().expect("wrapped root poisoned") = Some(WrappedKey {
            keystore: KeystoreId::Software,
            bytes: bytes.to_vec(),
        });
    }
}

fn clone_secret(s: &SecretBox<String>) -> SecretBox<String> {
    SecretBox::new(Box::new(s.expose_secret().clone()))
}

#[cfg(feature = "test-utils")]
fn injected() -> StoreError {
    StoreError::Io {
        path: PathBuf::from("<machine-lock fault>"),
        source: std::io::Error::other("injected crash (test seam)"),
    }
}

#[cfg(feature = "test-utils")]
impl BrokerState {
    /// ADR-165's crash seam: the next bind or unbind stops at `fault`, leaving on disk what a crash there would.
    pub fn set_machine_lock_fault_for_test(&self, fault: Option<MachineLockFault>) {
        *self
            .machine_lock_fault
            .lock()
            .expect("machine lock fault poisoned") = fault;
    }

    /// How many times a `keystore.*` op reached the state (review P2-8: proves an agent's request is refused
    /// before anything is read).
    pub fn machine_lock_touches_for_test(&self) -> usize {
        self.machine_lock_touches
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn machine_lock_touched(&self) {
        self.machine_lock_touches
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn machine_lock_fault_is(&self, fault: MachineLockFault) -> bool {
        *self
            .machine_lock_fault
            .lock()
            .expect("machine lock fault poisoned")
            == Some(fault)
    }
}
