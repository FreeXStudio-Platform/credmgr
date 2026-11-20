//! ADR-130 — `node.rekey`: replace a node's keypair and re-seal everything that was sealed to the old
//! one, as a **commit protocol** on a vault that lives on disk.
//!
//! A node's private key opens every envelope sealed to its public key: the live entries, the node's
//! note, the retained history of rotated and edited entries (`archive/entry-history`), and the entries
//! removed inside their seven days (`archive/removed-entries`). A rekey generates a new keypair, opens
//! each of those with the old key and seals it to the new one, then makes the new key *the* key. It must
//! never leave a vault in which some file is sealed to a key the registry no longer names.
//!
//! # The protocol (the registry write is the commit point)
//!
//! | step | what | status |
//! |---|---|---|
//! | K0 | authorise; refuse the orphan, a sealed id, a locked node, a node with locked-write tray entries; write the vault through so disk is level with memory; check the manifest on disk is the one the registry binds | — |
//! | K1 | new keypair; open and re-seal every file; compute every new digest | memory only |
//! | K2 | stage in `rekey-pending/<node>/`: the new wrapped key, **copies of the old key file and the old manifest**, every re-sealed file, and a plan sealed under the root key (**written last**) | pre-commit, **unread** |
//! | K3 | memory (persist lock held): the new key becomes the node's key, the manifest rows take their new digests, one generation bump | memory |
//! | K4 | **commit**: the ordinary write-through (node key files, manifests, then the registry) with the node's `publicKey` in the registry replaced — inside the op | **commit** |
//! | K5 | install the staged files over the live ones (idempotent), then remove the stage | post-commit |
//!
//! Who decides what a stage means is **the registry alone**: the signed `publicKey` of the node.
//!
//! * the registry names the **new** key → the commit happened → recovery rolls **forward**: it installs
//!   every staged file (each checked against the digest in the plan) and the new key file;
//! * the registry names the **old** key → the commit did not happen → recovery rolls **back**: it puts the
//!   old key file and the old manifest back (the write-through writes both *before* the registry, so a
//!   crash between could have replaced them) and the live envelopes, untouched until K5, are as they were;
//! * no plan on disk → the crash came before K2 finished; nothing live was touched; the stage is removed.
//!
//! Recovery runs on every load, after the registry has verified and before any key or manifest is read
//! (`BrokerState::verify_registry_and_rest`). A crash at any step therefore leaves a vault that unlocks,
//! with the node either exactly as it was or completely re-keyed — see `tests/rekey.rs`.
//!
//! The op runs under the exclusive request barrier (as `maintenance.rotate_root` does), so no other
//! request reads an envelope between K4 and the end of K5.

use std::collections::HashMap;

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use credmgr_core::envelope;
use credmgr_core::keys::{
    generate_node_keypair, open_under_root, seal_under_root, unwrap_node_key, wrap_node_key,
    WrappedNodeKey,
};
use credmgr_core::registry::{is_path_safe_node_id, ORPHAN_ID};
use credmgr_store::error::StoreError;
use credmgr_store::manifest;
use credmgr_store::registry_file::RegistryDocument;
use credmgr_store::{atomic, entry_archive, rotation_history};

use super::durable::corrupt;
use super::{hex_encode, sha256_of, BrokerState};
use crate::protocol::OpError;

/// The note's "entry id" in its envelope — `ops.rs`'s `NOTE_ENVELOPE_ID`.
const NOTE_ENVELOPE_ID: &str = "notes";
/// ADR-168: the merge decision memory's "entry id" in its envelope — `ops/merge_ops.rs`'s `MEMORY_ENVELOPE_ID`.
const MERGE_ENVELOPE_ID: &str = "merge-memory";
const PLAN_VERSION: u32 = 1;

/// A step of a rekey at which the test suite can make the process "die" (ADR-130's crash table). What the
/// steps so far left on disk is what the next start meets, and no cleanup runs. The two crashes inside the
/// write-through are [`super::PersistFault`]'s. Compiled only with `test-utils`.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyFault {
    /// After K2: the stage is complete, nothing live has changed.
    AfterStage,
    /// After K4: committed, no staged file installed.
    AfterCommit,
    /// After the first install of K5: one file new, the rest old.
    AfterFirstInstall,
    /// ADR-148 §P2-3 and its addendum: after K5, the stage's removal fails (it is left whole, for a later start
    /// to meet). The rekey committed, so the op answers success carrying a `cleanupWarning`.
    StageLeftBehind,
    /// ADR-148 §P2-3: the process dies in the middle of removing the stage, after the staged files and the new
    /// key went but before the plan did — the order a plain `remove_dir_all` may take.
    CleanupCutShort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ItemKind {
    Entry,
    Notes,
    /// ADR-168: the node's sealed merge decision memory, re-sealed with the note.
    MergeMemory,
    HistoryEnv,
    HistoryMeta,
    RemovedEnv,
    RemovedMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlanItem {
    kind: ItemKind,
    entry: Option<String>,
    generation: Option<u64>,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Plan {
    v: u32,
    node: String,
    old_public: String,
    new_public: String,
    old_key_sha256: String,
    old_manifest_sha256: String,
    items: Vec<PlanItem>,
}

/// What a durable rekey did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyOutcome {
    /// The node's new public key, lower-case hex.
    pub public_key: String,
    pub entries: usize,
    pub note: bool,
    /// Retained rotation / edit histories re-sealed.
    pub history: usize,
    /// Removed-entry archives re-sealed.
    pub removed: usize,
    /// ADR-148 addendum: the rekey committed but its stage could not be cleared. Not an error — the new key is
    /// live and every file follows it; the next unlock settles the stage (it rolls nothing back over newer
    /// data, §P2-3). Said to the caller rather than swallowed.
    pub cleanup_warning: Option<String>,
}

fn internal(what: impl std::fmt::Display) -> OpError {
    OpError::Internal(what.to_string())
}

fn plan_label(node: &str) -> String {
    format!("credmgr/v2/rekey-plan/{node}")
}

/// A directory name that is a plain id (never a path).
fn plain_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn item_target(
    paths: &credmgr_store::paths::VaultPaths,
    node: &str,
    item: &PlanItem,
) -> Result<std::path::PathBuf, StoreError> {
    let entry = || -> Result<&str, StoreError> {
        item.entry
            .as_deref()
            .filter(|e| plain_component(e))
            .ok_or_else(|| {
                corrupt(
                    paths.rekey_stage(node),
                    "a rekey plan item has no valid entry id",
                )
            })
    };
    let generation = || -> Result<u64, StoreError> {
        item.generation.ok_or_else(|| {
            corrupt(
                paths.rekey_stage(node),
                "a rekey plan item has no generation",
            )
        })
    };
    Ok(match item.kind {
        ItemKind::Entry => paths.entry_env(node, entry()?),
        ItemKind::Notes => paths.notes_env(node),
        ItemKind::MergeMemory => paths.merge_env(node),
        ItemKind::HistoryEnv => paths.entry_history_env(node, entry()?, generation()?),
        ItemKind::HistoryMeta => paths.entry_history_meta(node, entry()?, generation()?),
        ItemKind::RemovedEnv => paths.removed_entry_env(node, entry()?),
        ItemKind::RemovedMeta => paths.removed_entry_meta(node, entry()?),
    })
}

/// Open `bytes` with the old key and seal the same payload (same kind) to `new_public`.
fn reseal(
    bytes: &[u8],
    old: &StaticSecret,
    new_public: &PublicKey,
    node: &str,
    entry: &str,
) -> Result<(Vec<u8>, String), OpError> {
    let (kind, plaintext) = envelope::open_any(bytes, old, node, entry).map_err(|_| {
        internal(format!(
            "a stored file for {node} did not open under its key — nothing was re-keyed; run `credmgr verify`"
        ))
    })?;
    let sealed = envelope::seal_as(kind, plaintext.expose_secret(), new_public, node, entry)
        .map_err(|_| internal("failed to re-seal a stored file"))?;
    let sha = hex_encode(&sha256_of(&sealed));
    Ok((sealed, sha))
}

/// ADR-148 §P2-3: remove a rekey stage, its plan first and durably (unlink + directory fsync), then the rest.
/// The plan is what gives a stage meaning; once it is gone, whatever a crash leaves behind is inert.
fn remove_stage(stage: &std::path::Path) -> Result<(), StoreError> {
    let plan = stage.join("plan.sealed");
    if atomic::exists(&plan) {
        atomic::remove_durable(&plan)?;
    }
    std::fs::remove_dir_all(stage).map_err(|e| StoreError::Io {
        path: stage.to_path_buf(),
        source: e,
    })
}

fn list_dirs(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .filter(|d| d.path().is_dir())
                .filter_map(|d| d.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// One envelope re-sealed from a node's old key to its new one: what [`reseal_node_files`] hands both
/// re-key paths — `node.rekey` (this module's own stage) and ADR-165 N5's re-key inside a root rotation
/// (`rotate/rekey_live.rs`, the rotation's stage). The signed records that describe a retained history slot
/// or a removed entry (`HistoryMeta`, `RemovedMeta`) are not here: each path re-signs them under its own root
/// key.
pub(super) struct Resealed {
    pub kind: ItemKind,
    pub entry: Option<String>,
    pub generation: Option<u64>,
    /// The live file the bytes replace.
    pub path: std::path::PathBuf,
    /// SHA-256 of `bytes`, lower-case hex.
    pub sha256: String,
    pub bytes: Vec<u8>,
}

/// What [`reseal_node_files`] could not re-seal under [`OnUnreadable::LeaveAndName`]: `(what, reason)`.
pub(super) type LeftAsItWas = Vec<(String, String)>;

/// How [`reseal_node_files`] treats a file it cannot read or open under the old key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OnUnreadable {
    /// `node.rekey`: refuse the whole re-key, nothing changed (ADR-130).
    Refuse,
    /// ADR-165 N5, inside a passphrase change or a recovery: leave the file exactly as it is and name it. It
    /// opened nothing before and opens nothing after; refusing would turn one damaged file into an owner who
    /// cannot change a leaked passphrase, or cannot get back in with the recovery code.
    LeaveAndName,
}

/// Open every envelope `node` holds with `old` and seal the same payload to `new_public`: the live entries
/// (`rows`, the manifest's ids), the note, the merge memory, every retained history slot and every removed
/// entry still in its archive — ADR-130's list. Reads only; writes nothing.
///
/// With [`OnUnreadable::LeaveAndName`] a file that cannot be read or opened is left out of the result and
/// named in the second list as `(what, reason)` instead of failing.
pub(super) fn reseal_node_files(
    paths: &credmgr_store::paths::VaultPaths,
    node: &str,
    rows: &[String],
    old: &StaticSecret,
    new_public: &PublicKey,
    on_unreadable: OnUnreadable,
) -> Result<(Vec<Resealed>, LeftAsItWas), OpError> {
    let mut out: Vec<Resealed> = Vec::new();
    let mut left: LeftAsItWas = Vec::new();
    // One file: read, re-seal, or (lenient) name it and go on.
    let mut one = |kind: ItemKind,
                   entry: Option<&str>,
                   generation: Option<u64>,
                   path: std::path::PathBuf,
                   envelope_id: &str,
                   read_what: &str|
     -> Result<(), OpError> {
        let what = match (entry, generation) {
            (Some(e), Some(g)) => format!("{node}/{e}@{g}"),
            (Some(e), None) => format!("{node}/{e}"),
            _ => format!("{node}/{envelope_id}"),
        };
        let bytes = match atomic::read(&path) {
            Ok(b) => b,
            Err(e) => {
                return match on_unreadable {
                    OnUnreadable::Refuse => Err(internal(format!("reading {read_what}: {e}"))),
                    OnUnreadable::LeaveAndName => {
                        left.push((what, format!("could not be read ({e}); left as it was")));
                        Ok(())
                    }
                }
            }
        };
        match reseal(&bytes, old, new_public, node, envelope_id) {
            Ok((sealed, sha)) => {
                out.push(Resealed {
                    kind,
                    entry: entry.map(str::to_string),
                    generation,
                    path,
                    sha256: sha,
                    bytes: sealed,
                });
                Ok(())
            }
            Err(e) => match on_unreadable {
                OnUnreadable::Refuse => Err(e),
                OnUnreadable::LeaveAndName => {
                    left.push((
                        what,
                        "did not open under the node's key; left as it was (it opened nothing before either)"
                            .to_string(),
                    ));
                    Ok(())
                }
            },
        }
    };

    for id in rows {
        if !plain_component(id) {
            match on_unreadable {
                OnUnreadable::Refuse => {
                    return Err(internal(
                        "an entry id is not a plain id — nothing was re-keyed",
                    ))
                }
                OnUnreadable::LeaveAndName => continue,
            }
        }
        one(
            ItemKind::Entry,
            Some(id),
            None,
            paths.entry_env(node, id),
            id,
            "an entry to re-key",
        )?;
    }
    if atomic::exists(&paths.notes_env(node)) {
        one(
            ItemKind::Notes,
            None,
            None,
            paths.notes_env(node),
            NOTE_ENVELOPE_ID,
            "the note to re-key",
        )?;
    }
    if atomic::exists(&paths.merge_env(node)) {
        one(
            ItemKind::MergeMemory,
            None,
            None,
            paths.merge_env(node),
            MERGE_ENVELOPE_ID,
            "the merge memory to re-key",
        )?;
    }
    // Retained histories: archive/entry-history/<node>/<entry>/<generation>.env (+ a signed .json).
    let history_root = paths.archive_root().join("entry-history").join(node);
    for entry in list_dirs(&history_root) {
        if !plain_component(&entry) {
            continue;
        }
        let mut gens: Vec<u64> = std::fs::read_dir(history_root.join(&entry))
            .map(|r| {
                r.flatten()
                    .filter_map(|d| {
                        let p = d.path();
                        (p.extension().and_then(|e| e.to_str()) == Some("env"))
                            .then(|| p.file_stem()?.to_str()?.parse::<u64>().ok())
                            .flatten()
                    })
                    .collect()
            })
            .unwrap_or_default();
        gens.sort_unstable();
        for generation in gens {
            one(
                ItemKind::HistoryEnv,
                Some(&entry),
                Some(generation),
                paths.entry_history_env(node, &entry, generation),
                &entry,
                "retained history to re-key",
            )?;
        }
    }
    // Removed entries inside their window: archive/removed-entries/<node>/<entry>/entry.env + removed.json.
    let removed_root = paths.archive_root().join("removed-entries").join(node);
    for entry in list_dirs(&removed_root) {
        if !plain_component(&entry) || !atomic::exists(&paths.removed_entry_env(node, &entry)) {
            continue;
        }
        one(
            ItemKind::RemovedEnv,
            Some(&entry),
            None,
            paths.removed_entry_env(node, &entry),
            &entry,
            "a removed entry to re-key",
        )?;
    }
    Ok((out, left))
}

impl BrokerState {
    /// Rekey `target` on a disk-backed vault. See the module docs for the protocol.
    ///
    /// The caller has authorised the request (owner, `Admin`, presence, a fresh second factor), and has
    /// found `target` live and unlocked. The caller holds the exclusive request barrier.
    pub fn rekey_node_durable(&self, target: &str, now: i64) -> Result<RekeyOutcome, OpError> {
        let root = self
            .reauth_root_key("node rekey")
            .map_err(|_| OpError::VaultLocked)?;
        let rk = root.expose_secret();

        // --- K0 --------------------------------------------------------------------
        if target == ORPHAN_ID {
            return Err(OpError::Malformed(
                "the orphan node's key is a cold key and is not re-keyed".into(),
            ));
        }
        if !is_path_safe_node_id(target) || self.is_id_sealed(target) {
            return Err(OpError::Malformed(format!(
                "node {target} cannot be re-keyed: it is not a live node"
            )));
        }
        let node_lock = self.node_write_lock(target);
        let _node = node_lock.lock().expect("node write lock poisoned");
        if !self
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .contains_key(target)
        {
            return Err(OpError::NotFound(format!("no node {target}")));
        }
        if self.is_node_locked(target) {
            return Err(OpError::Malformed(format!(
                "node {target} is locked — unlock it first"
            )));
        }
        // A locked-write tray entry is sealed to the old public key and is not in any manifest yet:
        // refuse rather than leave one nobody can open.
        let pending_dir = self.paths.node_dir(target).join("pending");
        let on_disk_pending = std::fs::read_dir(pending_dir)
            .map(|r| {
                r.flatten()
                    .any(|d| d.path().extension().and_then(|e| e.to_str()) == Some("env"))
            })
            .unwrap_or(false);
        if !self.list_pending(target).is_empty() || on_disk_pending {
            return Err(OpError::Malformed(format!(
                "node {target} has writes waiting in the locked-write tray — accept or discard them first"
            )));
        }
        // A leftover stage from a crash this process is the first to see (the daemon recovers at load; an
        // embedded broker may not have): settle it against the registry now.
        {
            let doc = self
                .registry_meta
                .read()
                .expect("registry meta poisoned")
                .clone();
            self.recover_interrupted_rekeys(rk, &doc)
                .map_err(|e| internal(format!("settling an earlier rekey: {e}")))?;
        }
        self.persist_with_root(rk, now)
            .map_err(|e| internal(format!("saving the vault before the rekey: {e}")))?;

        let (node_doc, binding) = {
            let meta = self.registry_meta.read().expect("registry meta poisoned");
            (
                meta.nodes.get(target).cloned(),
                meta.manifests.get(target).cloned(),
            )
        };
        let (Some(node_doc), Some(binding)) = (node_doc, binding) else {
            return Err(internal(format!(
                "the registry has no record of node {target}"
            )));
        };
        let on_disk = manifest::load(&self.paths, rk, target)
            .map_err(|e| internal(format!("reading {target}'s manifest: {e}")))?;
        let memory_generation = self.manifest_generation(target).unwrap_or(0);
        if on_disk.body.generation != binding.generation
            || on_disk.hmac != binding.manifest_hmac
            || on_disk.body.generation != memory_generation
        {
            return Err(internal(format!(
                "{target}'s manifest on disk is not the one the registry binds — nothing was re-keyed; run `credmgr doctor`"
            )));
        }

        let wrapped_old = self
            .node_wrapped_keys
            .read()
            .expect("node wrapped keys poisoned")
            .get(target)
            .cloned()
            .ok_or_else(|| internal(format!("node {target} has no wrapped key")))?;
        let old_priv = unwrap_node_key(rk, target, &wrapped_old)
            .map_err(|_| internal(format!("node {target}'s key did not unwrap")))?;
        let old_public = self
            .node_public_key(target)
            .ok_or_else(|| internal(format!("node {target} has no public key")))?;
        if PublicKey::from(&old_priv).as_bytes() != old_public.as_bytes()
            || hex_encode(old_public.as_bytes()) != node_doc.public_key
        {
            return Err(internal(format!(
                "node {target}'s private key does not match its public key — nothing was re-keyed; run `credmgr verify`"
            )));
        }
        let old_key_bytes = atomic::read(&self.paths.node_key(target))
            .map_err(|e| internal(format!("reading {target}'s node key file: {e}")))?;
        let old_manifest_bytes = atomic::read(&self.paths.manifest(target))
            .map_err(|e| internal(format!("reading {target}'s manifest file: {e}")))?;

        // --- K1 --------------------------------------------------------------------
        let pair = generate_node_keypair();
        let new_public = pair.public;
        let new_wrapped = wrap_node_key(rk, target, &pair.private);
        let new_public_hex = hex_encode(new_public.as_bytes());

        let rows: Vec<String> = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(target)
            .map(|m| m.entries.iter().map(|e| e.id.clone()).collect())
            .unwrap_or_default();

        let (resealed, _) = reseal_node_files(
            &self.paths,
            target,
            &rows,
            &old_priv,
            &new_public,
            OnUnreadable::Refuse,
        )?;
        let mut items: Vec<(PlanItem, Vec<u8>)> = Vec::new();
        let mut new_row_sha: HashMap<String, String> = HashMap::new();
        let mut new_note_sha: Option<String> = None;
        let mut new_merge_sha: Option<String> = None;
        let mut history = 0usize;
        let mut removed = 0usize;
        for file in resealed {
            let Resealed {
                kind,
                entry,
                generation,
                sha256: sha,
                bytes: sealed,
                ..
            } = file;
            match kind {
                ItemKind::Entry => {
                    if let Some(id) = &entry {
                        new_row_sha.insert(id.clone(), sha.clone());
                    }
                }
                ItemKind::Notes => new_note_sha = Some(sha.clone()),
                ItemKind::MergeMemory => new_merge_sha = Some(sha.clone()),
                _ => {}
            }
            items.push((
                PlanItem {
                    kind,
                    entry: entry.clone(),
                    generation,
                    sha256: sha.clone(),
                },
                sealed,
            ));
            match (kind, entry.as_deref(), generation) {
                (ItemKind::HistoryEnv, Some(entry), Some(generation)) => {
                    if atomic::exists(&self.paths.entry_history_meta(target, entry, generation)) {
                        let meta = rotation_history::with_sha256(
                            &self.paths,
                            rk,
                            target,
                            entry,
                            generation,
                            &sha,
                        )
                        .map_err(|e| internal(format!("re-signing retained history: {e}")))?;
                        items.push((
                            PlanItem {
                                kind: ItemKind::HistoryMeta,
                                entry: Some(entry.to_string()),
                                generation: Some(generation),
                                sha256: hex_encode(&sha256_of(&meta)),
                            },
                            meta,
                        ));
                    }
                    history += 1;
                }
                (ItemKind::RemovedEnv, Some(entry), _) => {
                    let meta = entry_archive::with_sha256(&self.paths, rk, target, entry, &sha)
                        .map_err(|e| {
                            internal(format!("re-signing a removed entry's record: {e}"))
                        })?;
                    items.push((
                        PlanItem {
                            kind: ItemKind::RemovedMeta,
                            entry: Some(entry.to_string()),
                            generation: None,
                            sha256: hex_encode(&sha256_of(&meta)),
                        },
                        meta,
                    ));
                    removed += 1;
                }
                _ => {}
            }
        }

        // --- K2: the stage, plan last ------------------------------------------------
        let stage = self.paths.rekey_stage(target);
        if stage.exists() {
            std::fs::remove_dir_all(&stage)
                .map_err(|e| internal(format!("clearing an old rekey stage: {e}")))?;
        }
        let staged = (|| -> Result<(), StoreError> {
            atomic::ensure_dir(&stage.join("files"))?;
            for (i, (_, bytes)) in items.iter().enumerate() {
                atomic::write(&stage.join("files").join(i.to_string()), bytes)?;
            }
            atomic::write(&stage.join("new.key"), &new_wrapped.to_bytes())?;
            atomic::write(&stage.join("old.key"), &old_key_bytes)?;
            atomic::write(&stage.join("old.manifest"), &old_manifest_bytes)?;
            let plan = Plan {
                v: PLAN_VERSION,
                node: target.to_string(),
                old_public: node_doc.public_key.clone(),
                new_public: new_public_hex.clone(),
                old_key_sha256: hex_encode(&sha256_of(&old_key_bytes)),
                old_manifest_sha256: hex_encode(&sha256_of(&old_manifest_bytes)),
                items: items.iter().map(|(p, _)| p.clone()).collect(),
            };
            let json = serde_json::to_vec(&plan).expect("a plan always serialises");
            atomic::write(
                &stage.join("plan.sealed"),
                &seal_under_root(rk, &plan_label(target), &json),
            )
        })();
        if let Err(e) = staged {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(internal(format!("staging the rekey: {e}")));
        }
        #[cfg(feature = "test-utils")]
        self.rekey_fault_point(RekeyFault::AfterStage)?;

        // --- K3: memory ---------------------------------------------------------------
        let one_writer = self.lock_persist();
        let manifest_before = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(target)
            .cloned();
        let hot_before = self
            .hot_keys
            .read()
            .expect("hot keys poisoned")
            .get(target)
            .cloned();
        {
            let mut manifests = self.manifests.write().expect("manifests poisoned");
            let Some(body) = manifests.get_mut(target) else {
                drop(manifests);
                drop(one_writer);
                let _ = std::fs::remove_dir_all(&stage);
                return Err(internal(format!(
                    "node {target} lost its manifest during the rekey"
                )));
            };
            for row in body.entries.iter_mut() {
                if let Some(sha) = new_row_sha.get(&row.id) {
                    row.sha256.clone_from(sha);
                }
            }
            if let Some(sha) = &new_note_sha {
                body.notes_sha256 = Some(sha.clone());
            }
            if let Some(sha) = &new_merge_sha {
                body.merge_sha256 = Some(sha.clone());
            }
            body.generation += 1;
        }
        self.node_wrapped_keys
            .write()
            .expect("node wrapped keys poisoned")
            .insert(target.to_string(), new_wrapped.clone());
        self.node_public_keys
            .write()
            .expect("node public keys poisoned")
            .insert(target.to_string(), new_public);
        if hot_before.is_some() {
            self.hot_keys.write().expect("hot keys poisoned").insert(
                target.to_string(),
                crate::locked_key::LockedKey::from_secret(&pair.private),
            );
        }

        // --- K4: the commit --------------------------------------------------------------
        let committed = self.persist_with_root_edit_locked(&one_writer, rk, now, &mut |doc| {
            if let Some(n) = doc.nodes.get_mut(target) {
                n.public_key.clone_from(&new_public_hex);
            }
        });
        if let Err(e) = committed {
            if self.was_crash_injected() {
                return Err(internal(format!("injected crash: {e}")));
            }
            // An error after the registry landed is a commit that reported failure: read the disk.
            let landed = credmgr_store::registry_file::load(&self.paths, rk)
                .ok()
                .and_then(|d| d.nodes.get(target).map(|n| n.public_key == new_public_hex))
                == Some(true);
            if landed {
                let _ = self.refresh_registry_meta(rk);
            } else {
                // Not committed: memory and files back to the old key.
                match manifest_before {
                    Some(body) => self.set_manifest(target, body),
                    None => {
                        self.take_manifest(target);
                    }
                }
                self.node_wrapped_keys
                    .write()
                    .expect("node wrapped keys poisoned")
                    .insert(target.to_string(), wrapped_old);
                self.node_public_keys
                    .write()
                    .expect("node public keys poisoned")
                    .insert(target.to_string(), old_public);
                if let Some(bytes) = hot_before {
                    self.hot_keys
                        .write()
                        .expect("hot keys poisoned")
                        .insert(target.to_string(), bytes);
                }
                let restored = atomic::write(&self.paths.node_key(target), &old_key_bytes)
                    .and_then(|_| atomic::write(&self.paths.manifest(target), &old_manifest_bytes));
                let _ = std::fs::remove_dir_all(&stage);
                return Err(internal(match restored {
                    Ok(()) => format!("re-keying {target} failed and was rolled back: {e}"),
                    Err(r) => format!(
                        "re-keying {target} failed ({e}) and its old files could not be put back ({r}); \
                         restart credmgrd — the next unlock finishes the rollback"
                    ),
                }));
            }
        }
        drop(one_writer);
        #[cfg(feature = "test-utils")]
        self.rekey_fault_point(RekeyFault::AfterCommit)?;

        // --- K5: install ---------------------------------------------------------------------
        for (i, (item, bytes)) in items.iter().enumerate() {
            let installed =
                item_target(&self.paths, target, item).and_then(|path| atomic::write(&path, bytes));
            if let Err(e) = installed {
                return Err(internal(format!(
                    "{target} was re-keyed but a file could not be rewritten ({e}); the stage is kept — \
                     restart credmgrd and unlock to finish it"
                )));
            }
            #[cfg(feature = "test-utils")]
            if i == 0 {
                self.rekey_fault_point(RekeyFault::AfterFirstInstall)?;
            }
            #[cfg(not(feature = "test-utils"))]
            let _ = i;
        }
        #[cfg(feature = "test-utils")]
        let fail_cleanup = self.rekey_fault_take(RekeyFault::StageLeftBehind);
        #[cfg(not(feature = "test-utils"))]
        let fail_cleanup = false;
        #[cfg(feature = "test-utils")]
        if self.rekey_fault_take(RekeyFault::CleanupCutShort) {
            let _ = std::fs::remove_dir_all(stage.join("files"));
            let _ = std::fs::remove_file(stage.join("new.key"));
            self.crash_injected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Err(internal(
                "injected crash (test seam): the process died while removing the rekey stage",
            ));
        }
        // ADR-148 §P2-3: the plan goes first and durably; only then the rest. A stage without its plan is
        // inert (the next start removes it), so a crash part-way through can no longer leave a plan that
        // points at staged files which are gone.
        let cleared = if fail_cleanup {
            Err("injected cleanup failure (test seam)".to_string())
        } else {
            remove_stage(&stage).map_err(|e| e.to_string())
        };
        // ADR-148 addendum: the rekey has committed (K4) and every file is installed (K5), so a stage that will
        // not go is a warning, not a failure: answering an error here would tell the owner a rekey that
        // happened did not.
        let cleanup_warning = match cleared {
            Ok(()) => {
                let _ = std::fs::remove_dir(self.paths.rekey_stage_root());
                None
            }
            Err(e) => {
                let warning = format!(
                    "{target} was re-keyed, but its stage could not be cleared ({e}); nothing is lost — the \
                     next unlock settles it"
                );
                eprintln!("credmgrd: warning: {warning}");
                Some(warning)
            }
        };

        Ok(RekeyOutcome {
            public_key: new_public_hex,
            entries: rows.len(),
            note: new_note_sha.is_some(),
            history,
            removed,
            cleanup_warning,
        })
    }

    // --- recovery -----------------------------------------------------------------------

    /// Settle every `rekey-pending/<node>/` against `doc`, the registry that has just verified. See the
    /// module docs: the registry's `publicKey` for the node says whether the commit happened.
    pub(super) fn recover_interrupted_rekeys(
        &self,
        root_key: &[u8; 32],
        doc: &RegistryDocument,
    ) -> Result<(), StoreError> {
        let stage_root = self.paths.rekey_stage_root();
        let Ok(read) = std::fs::read_dir(&stage_root) else {
            return Ok(());
        };
        let mut nodes: Vec<String> = read
            .flatten()
            .filter_map(|d| d.file_name().into_string().ok())
            .collect();
        nodes.sort();
        for node in nodes {
            let stage = stage_root.join(&node);
            if !is_path_safe_node_id(&node) {
                continue; // not ours to interpret; nothing ever writes such a directory.
            }
            self.settle_rekey_stage(root_key, doc, &node, &stage)?;
        }
        let _ = std::fs::remove_dir(&stage_root); // best effort; only if empty.
        Ok(())
    }

    fn settle_rekey_stage(
        &self,
        root_key: &[u8; 32],
        doc: &RegistryDocument,
        node: &str,
        stage: &std::path::Path,
    ) -> Result<(), StoreError> {
        let plan_path = stage.join("plan.sealed");
        if !atomic::exists(&plan_path) {
            // The crash came before the plan (written last) existed: nothing live was touched.
            return std::fs::remove_dir_all(stage).map_err(|e| StoreError::Io {
                path: stage.to_path_buf(),
                source: e,
            });
        }
        let sealed = atomic::read(&plan_path)?;
        let plan: Plan = open_under_root(root_key, &plan_label(node), &sealed)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(|p: &Plan| p.v == PLAN_VERSION && p.node == node)
            .ok_or_else(|| {
                corrupt(
                    plan_path.clone(),
                    "a rekey stage's plan failed its authentication",
                )
            })?;
        let registry_public = doc.nodes.get(node).map(|n| n.public_key.as_str());
        if registry_public == Some(plan.new_public.as_str()) {
            self.roll_rekey_forward(root_key, node, stage, &plan)
        } else if registry_public == Some(plan.old_public.as_str()) {
            self.roll_rekey_back(node, stage, &plan)
        } else {
            // The registry names a key this stage knows nothing of (the node was re-created, or the vault
            // restored): the stage is stale. Remove it.
            std::fs::remove_dir_all(stage).map_err(|e| StoreError::Io {
                path: stage.to_path_buf(),
                source: e,
            })
        }
    }

    /// ADR-148 §P2-3: rolling forward installs a staged file only when the live file still needs it. A live
    /// file that already has the planned digest was installed before the crash (or before a cleanup that went
    /// wrong) and is left alone — so a stage whose staged copies are already gone still settles. A live entry
    /// or note whose **manifest** digest has moved on from the plan's was edited after the commit, and the
    /// edit is newer than the staged bytes: it is left alone too, never overwritten by a stale stage.
    fn roll_rekey_forward(
        &self,
        root_key: &[u8; 32],
        node: &str,
        stage: &std::path::Path,
        plan: &Plan,
    ) -> Result<(), StoreError> {
        let manifest = manifest::load(&self.paths, root_key, node).ok();
        for (i, item) in plan.items.iter().enumerate() {
            let target = item_target(&self.paths, node, item)?;
            let live_matches = atomic::read(&target)
                .map(|live| hex_encode(&sha256_of(&live)) == item.sha256)
                .unwrap_or(false);
            if live_matches {
                continue;
            }
            let moved_on = match (&manifest, item.kind) {
                (Some(doc), ItemKind::Entry) => {
                    let row = doc
                        .body
                        .entries
                        .iter()
                        .find(|e| Some(e.id.as_str()) == item.entry.as_deref());
                    row.map_or(true, |row| row.sha256 != item.sha256)
                }
                (Some(doc), ItemKind::Notes) => {
                    doc.body.notes_sha256.as_deref() != Some(item.sha256.as_str())
                }
                (Some(doc), ItemKind::MergeMemory) => {
                    doc.body.merge_sha256.as_deref() != Some(item.sha256.as_str())
                }
                _ => false,
            };
            if moved_on {
                continue;
            }
            let bytes = atomic::read(&stage.join("files").join(i.to_string()))?;
            if hex_encode(&sha256_of(&bytes)) != item.sha256 {
                return Err(corrupt(
                    stage.join("files").join(i.to_string()),
                    "a staged rekey file does not match its plan",
                ));
            }
            atomic::write(&target, &bytes)?;
        }
        let live_key_is_new = atomic::read(&self.paths.node_key(node))
            .ok()
            .and_then(|bytes| WrappedNodeKey::from_bytes(&bytes).ok())
            .and_then(|wrapped| unwrap_node_key(root_key, node, &wrapped).ok())
            .is_some_and(|secret| {
                hex_encode(PublicKey::from(&secret).as_bytes()) == plan.new_public
            });
        if !live_key_is_new {
            let new_key = atomic::read(&stage.join("new.key"))?;
            let wrapped = WrappedNodeKey::from_bytes(&new_key)
                .map_err(|_| corrupt(stage.join("new.key"), "not a wrapped node key"))?;
            let secret = unwrap_node_key(root_key, node, &wrapped).map_err(|_| {
                corrupt(stage.join("new.key"), "the staged node key does not unwrap")
            })?;
            if hex_encode(PublicKey::from(&secret).as_bytes()) != plan.new_public {
                return Err(corrupt(
                    stage.join("new.key"),
                    "the staged node key does not match the plan",
                ));
            }
            atomic::write(&self.paths.node_key(node), &new_key)?;
        }
        remove_stage(stage)
    }

    fn roll_rekey_back(
        &self,
        node: &str,
        stage: &std::path::Path,
        plan: &Plan,
    ) -> Result<(), StoreError> {
        let old_key = atomic::read(&stage.join("old.key"))?;
        let old_manifest = atomic::read(&stage.join("old.manifest"))?;
        if hex_encode(&sha256_of(&old_key)) != plan.old_key_sha256
            || hex_encode(&sha256_of(&old_manifest)) != plan.old_manifest_sha256
        {
            return Err(corrupt(
                stage.to_path_buf(),
                "the staged copies of the old key or manifest do not match the plan",
            ));
        }
        atomic::write(&self.paths.node_key(node), &old_key)?;
        atomic::write(&self.paths.manifest(node), &old_manifest)?;
        remove_stage(stage)
    }

    // --- test seams ---------------------------------------------------------------------

    /// Arm a fault for the next rekey (test seam, ADR-130).
    #[cfg(feature = "test-utils")]
    pub fn set_rekey_fault_for_test(&self, fault: Option<RekeyFault>) {
        *self
            .stable
            .rekey_fault
            .lock()
            .expect("rekey fault poisoned") = fault;
    }

    /// Whether `at` is armed (disarming it). For the faults that change behaviour rather than crash.
    #[cfg(feature = "test-utils")]
    fn rekey_fault_take(&self, at: RekeyFault) -> bool {
        let mut armed = self
            .stable
            .rekey_fault
            .lock()
            .expect("rekey fault poisoned");
        if *armed == Some(at) {
            *armed = None;
            return true;
        }
        false
    }

    #[cfg(feature = "test-utils")]
    fn rekey_fault_point(&self, at: RekeyFault) -> Result<(), OpError> {
        let mut armed = self
            .stable
            .rekey_fault
            .lock()
            .expect("rekey fault poisoned");
        if *armed == Some(at) {
            *armed = None;
            self.crash_injected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Err(internal(format!(
                "injected crash (test seam): the process died at {at:?}"
            )));
        }
        Ok(())
    }
}
