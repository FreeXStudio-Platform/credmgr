//! ADR-158 — `entry.move`: take one entry out of one node and put it in another, re-encrypted to the
//! destination node's key, as a **commit protocol** on a vault that lives on disk.
//!
//! An entry's envelope is sealed to its node's public key, and the node id is in the envelope's AAD, so a
//! move is never a metadata edit: the value is opened with the source node's key and sealed again to the
//! destination's. Two manifests change (a row leaves one, the same row joins the other), and the signed
//! registry binds both. A move must never leave both copies readable, and must never lose the entry.
//!
//! # The protocol (the registry write is the commit point)
//!
//! | step | what | status |
//! |---|---|---|
//! | M0 | the caller authorised; both node write locks held (in id order); settle any earlier stage; write the vault through so disk is level with memory | — |
//! | M1 | open the source envelope with the source key, seal it to the destination key under the same entry id | memory only |
//! | M2 | stage in `move-pending/<entry>/`: **copies of both manifests as they are now**, then a plan sealed under the root key (**written last**); then write the new envelope at its destination path | pre-commit, **unread** (no manifest names it) |
//! | M3 | memory (persist lock held): the row leaves the source manifest and joins the destination's (one generation bump each); entry-level grants on the entry are revoked | memory |
//! | M4 | **commit**: the ordinary write-through (manifests, then the registry), inside the op | **commit** |
//! | M5 | delete the source envelope and the source's retained history for the entry, then the stage | post-commit |
//!
//! Who decides what a stage means is **the registry alone**: the generation it binds for the two manifests.
//! The plan records both generations as they were at M0, when the disk had just been levelled with memory
//! and both node write locks were held, so nothing else could have moved them.
//!
//! * both bindings are **past** the plan's → the commit happened → recovery rolls **forward**: it deletes the
//!   source envelope and retained history (once the committed source manifest no longer names the entry);
//! * both bindings **equal** the plan's → the commit did not happen → recovery rolls **back**: it puts both
//!   manifests back from the stage (the write-through writes manifests *before* the registry, and the loader
//!   accepts a manifest one generation ahead as an interrupted write — so without this a crash between the
//!   two manifest writes could leave the entry in both nodes, or in neither) and deletes the new envelope;
//! * anything else, or no plan → the stage is stale or incomplete and nothing live depends on it: it is
//!   removed.
//!
//! Recovery runs on every load, after the registry has verified and before any manifest is read
//! (`BrokerState::verify_registry_and_rest`). The op runs under the exclusive request barrier (like
//! `node.rekey`), so no reader is between a manifest and the envelope it names while the files change.

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use credmgr_core::envelope;
use credmgr_core::keys::{open_under_root, seal_under_root};
use credmgr_core::registry::{is_path_safe_node_id, Grant, GrantTarget, ORPHAN_ID};
use credmgr_store::atomic;
use credmgr_store::error::StoreError;
use credmgr_store::manifest;
use credmgr_store::registry_file::RegistryDocument;

use super::durable::corrupt;
use super::{hex_encode, sha256_of, BrokerState};
use crate::protocol::OpError;

const PLAN_VERSION: u32 = 1;

/// A step of a move at which the test suite can make the process "die" (ADR-158's crash table). What the
/// steps so far left on disk is what the next start meets, and no cleanup runs. The two crashes inside the
/// write-through are [`super::PersistFault`]'s. Compiled only with `test-utils`.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveFault {
    /// After M2: the stage and the new envelope are on disk, nothing is committed.
    AfterStage,
    /// After M4: committed, the source envelope and history not yet deleted.
    AfterCommit,
    /// After M5's deletes, the stage's removal fails (it is left whole). The move committed, so the op
    /// answers success carrying a `cleanupWarning`.
    StageLeftBehind,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Plan {
    v: u32,
    entry: String,
    from: String,
    to: String,
    /// The manifest generations the registry bound at M0.
    from_generation: u64,
    to_generation: u64,
    from_manifest_sha256: String,
    to_manifest_sha256: String,
    /// The new envelope's digest at its destination path.
    envelope_sha256: String,
}

/// What a durable move did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveOutcome {
    /// The entry's id, unchanged by the move.
    pub entry: String,
    /// The entry's vault-global ref, unchanged by the move.
    pub r#ref: u32,
    pub name: String,
    /// The source node's manifest generation after the move.
    pub from_generation: u64,
    /// The destination node's manifest generation after the move.
    pub to_generation: u64,
    /// Entry-level grants that named the entry on the source node, revoked in the commit.
    pub grants_revoked: Vec<String>,
    /// Retained earlier values (`entry.undo`'s history) destroyed with the source copy.
    pub history_dropped: usize,
    /// The move committed but its stage could not be cleared; the next unlock settles it.
    pub cleanup_warning: Option<String>,
}

fn internal(what: impl std::fmt::Display) -> OpError {
    OpError::Internal(what.to_string())
}

fn plan_label(entry: &str) -> String {
    format!("credmgr/v2/move-plan/{entry}")
}

/// An entry id is `e_` + hex; anything else is never joined into a path here.
fn plain_entry_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Remove a stage, its plan first and durably, then the rest (ADR-148 §P2-3's order: a stage without its
/// plan is inert).
fn remove_stage(stage: &std::path::Path) -> Result<(), StoreError> {
    let plan = stage.join("plan.sealed");
    if atomic::exists(&plan) {
        atomic::remove_durable(&plan)?;
    }
    match std::fs::remove_dir_all(stage) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::Io {
            path: stage.to_path_buf(),
            source: e,
        }),
    }
}

/// How many retained history slots (`archive/entry-history/<node>/<entry>/<generation>.env`) there are.
fn history_slots(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .filter(|d| d.path().extension().and_then(|e| e.to_str()) == Some("env"))
                .count()
        })
        .unwrap_or(0)
}

fn remove_dir_if_present(dir: &std::path::Path) -> Result<(), StoreError> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::Io {
            path: dir.to_path_buf(),
            source: e,
        }),
    }
}

impl BrokerState {
    /// Move `entry` from `from` to `to` on a disk-backed vault. See the module docs for the protocol.
    ///
    /// The caller has authorised the request (the owner's login, `Admin` on both nodes, fresh second
    /// factors, a presence proof) and has found both nodes live and unlocked. It holds the exclusive request
    /// barrier when it comes through the server. `expected_generation` is the source node's generation the
    /// caller last read (F-9); a stale one is `conflict` and nothing changes.
    pub fn move_entry_durable(
        &self,
        from: &str,
        entry: &str,
        to: &str,
        expected_generation: u64,
        now: i64,
    ) -> Result<MoveOutcome, OpError> {
        let root = self
            .reauth_root_key("entry move")
            .map_err(|_| OpError::VaultLocked)?;
        let rk = root.expose_secret();

        // --- M0 --------------------------------------------------------------------
        if from == to {
            return Err(OpError::Malformed(
                "params.to is the node the entry is already in".into(),
            ));
        }
        if from == ORPHAN_ID || to == ORPHAN_ID {
            return Err(OpError::Malformed(
                "entries move in and out of the orphan node only by sealing and restoring a node"
                    .into(),
            ));
        }
        if !is_path_safe_node_id(from) || !is_path_safe_node_id(to) {
            return Err(OpError::Malformed("not a node id".into()));
        }
        if !plain_entry_id(entry) {
            return Err(OpError::NotFound(format!(
                "no entry {entry} on node {from}"
            )));
        }
        // Both write locks, always in id order, so two moves between the same pair cannot deadlock.
        let (first, second) = if from < to { (from, to) } else { (to, from) };
        let first_lock = self.node_write_lock(first);
        let _first = first_lock.lock().expect("node write lock poisoned");
        let second_lock = self.node_write_lock(second);
        let _second = second_lock.lock().expect("node write lock poisoned");
        {
            let registry = self.registry.read().expect("registry poisoned");
            for node in [from, to] {
                if !registry.nodes.contains_key(node) {
                    return Err(OpError::NotFound(format!("no node {node}")));
                }
            }
        }
        for node in [from, to] {
            if self.is_node_locked(node) {
                return Err(OpError::NodeLocked {
                    node: node.to_string(),
                });
            }
        }
        let (row, current_generation, to_names) = {
            let manifests = self.manifests.read().expect("manifests poisoned");
            let source = manifests.get(from);
            let row = source.and_then(|m| m.entries.iter().find(|e| e.id == entry).cloned());
            let current = source.map_or(0, |m| m.generation);
            let to_names: Vec<String> = manifests
                .get(to)
                .map(|m| {
                    m.entries
                        .iter()
                        .flat_map(|e| std::iter::once(e.name.clone()).chain(e.aliases.clone()))
                        .collect()
                })
                .unwrap_or_default();
            let clash = manifests
                .get(to)
                .is_some_and(|m| m.entries.iter().any(|e| e.id == entry));
            if clash {
                return Err(internal(format!(
                    "node {to} already holds an entry with the id {entry} — nothing was moved"
                )));
            }
            (row, current, to_names)
        };
        let Some(row) = row else {
            return Err(OpError::NotFound(format!(
                "no entry {entry} on node {from}"
            )));
        };
        if expected_generation != current_generation {
            return Err(OpError::Conflict {
                node_id: from.to_string(),
                expected_generation,
                current_generation,
            });
        }
        // ADR-084 / ADR-121: one name space per node, compared canonically, over names, aliases and the
        // locked-write tray. The entry's name and every alias it carries must be free at the destination.
        {
            use credmgr_core::names::canonical_name;
            let pending = self.list_pending(to);
            let taken: std::collections::HashSet<String> = to_names
                .iter()
                .map(String::as_str)
                .chain(pending.iter().map(|p| p.name.as_str()))
                .map(canonical_name)
                .collect();
            for name in std::iter::once(&row.name).chain(row.aliases.iter()) {
                if taken.contains(&canonical_name(name)) {
                    return Err(OpError::EntryExists {
                        node: to.to_string(),
                        name: name.clone(),
                    });
                }
            }
        }
        let dest_env = self.paths.entry_env(to, entry);
        if atomic::exists(&dest_env) {
            return Err(internal(format!(
                "a file for {entry} already sits in {to} — nothing was moved; run `credmgr verify`"
            )));
        }

        self.recover_interrupted_moves(rk, &self.registry_meta_snapshot())
            .map_err(|e| internal(format!("settling an earlier move: {e}")))?;
        self.persist_with_root(rk, now)
            .map_err(|e| internal(format!("saving the vault before the move: {e}")))?;
        let (from_generation, to_generation) = {
            let meta = self.registry_meta.read().expect("registry meta poisoned");
            let gen_of = |node: &str| meta.manifests.get(node).map(|b| b.generation);
            match (gen_of(from), gen_of(to)) {
                (Some(f), Some(t)) => (f, t),
                _ => {
                    return Err(internal(
                        "the registry does not bind both manifests — nothing was moved; run `credmgr doctor`",
                    ))
                }
            }
        };
        if Some(from_generation) != self.manifest_generation(from) {
            return Err(internal(format!(
                "{from}'s manifest on disk is not the one in memory — nothing was moved; run `credmgr doctor`"
            )));
        }
        let from_manifest = atomic::read(&self.paths.manifest(from))
            .map_err(|e| internal(format!("reading {from}'s manifest file: {e}")))?;
        let to_manifest = atomic::read(&self.paths.manifest(to))
            .map_err(|e| internal(format!("reading {to}'s manifest file: {e}")))?;

        // --- M1 --------------------------------------------------------------------
        let source_bytes = atomic::read(&self.paths.entry_env(from, entry))
            .map_err(|e| internal(format!("reading the entry to move: {e}")))?;
        if hex_encode(&sha256_of(&source_bytes)) != row.sha256 {
            return Err(internal(
                "the entry's file does not match its manifest digest — nothing was moved; run `credmgr verify`",
            ));
        }
        let from_key = self.hot_node_key(from).ok_or_else(|| OpError::NodeLocked {
            node: from.to_string(),
        })?;
        let to_public = self
            .node_public_key(to)
            .ok_or_else(|| internal(format!("node {to} has no public key")))?;
        let (kind, plaintext) = envelope::open_any(&source_bytes, &from_key, from, entry)
            .map_err(|_| {
                internal(format!(
                    "the entry did not open under {from}'s key — nothing was moved; run `credmgr verify`"
                ))
            })?;
        let sealed = envelope::seal_as(kind, plaintext.expose_secret(), &to_public, to, entry)
            .map_err(|_| internal("failed to seal the entry to the destination key"))?;
        drop(plaintext);
        let envelope_sha = hex_encode(&sha256_of(&sealed));

        // --- M2: the stage, plan last; then the new envelope ----------------------------
        let stage = self.paths.move_stage(entry);
        remove_stage(&stage).map_err(|e| internal(format!("clearing an old move stage: {e}")))?;
        let staged = (|| -> Result<(), StoreError> {
            atomic::write(&stage.join("from.manifest"), &from_manifest)?;
            atomic::write(&stage.join("to.manifest"), &to_manifest)?;
            let plan = Plan {
                v: PLAN_VERSION,
                entry: entry.to_string(),
                from: from.to_string(),
                to: to.to_string(),
                from_generation,
                to_generation,
                from_manifest_sha256: hex_encode(&sha256_of(&from_manifest)),
                to_manifest_sha256: hex_encode(&sha256_of(&to_manifest)),
                envelope_sha256: envelope_sha.clone(),
            };
            let json = serde_json::to_vec(&plan).expect("a plan always serialises");
            atomic::write(
                &stage.join("plan.sealed"),
                &seal_under_root(rk, &plan_label(entry), &json),
            )?;
            atomic::write(&dest_env, &sealed)
        })();
        if let Err(e) = staged {
            let _ = atomic::remove_durable(&dest_env);
            let _ = remove_stage(&stage);
            return Err(internal(format!("staging the move: {e}")));
        }
        #[cfg(feature = "test-utils")]
        self.move_fault_point(MoveFault::AfterStage)?;

        // --- M3: memory ---------------------------------------------------------------
        let one_writer = self.lock_persist();
        let (from_before, to_before) = {
            let manifests = self.manifests.read().expect("manifests poisoned");
            (manifests.get(from).cloned(), manifests.get(to).cloned())
        };
        let grants_before: Vec<Grant> = self
            .registry
            .read()
            .expect("registry poisoned")
            .grants
            .clone();
        let (new_from_generation, new_to_generation) = {
            let mut manifests = self.manifests.write().expect("manifests poisoned");
            let source = manifests
                .get_mut(from)
                .expect("checked under the held write lock");
            source.entries.retain(|e| e.id != entry);
            source.recount();
            source.generation += 1;
            let new_from = source.generation;
            let dest = manifests
                .entry(to.to_string())
                .or_insert_with(|| manifest::ManifestBody::new(to));
            let mut moved = row.clone();
            moved.sha256.clone_from(&envelope_sha);
            moved.modified = now;
            dest.entries.push(moved);
            dest.recount();
            dest.generation += 1;
            (new_from, dest.generation)
        };
        // Grants that name this entry on the source node would, after the move, name nothing; they are
        // never carried to a different node (that would widen a grant nobody made). Revoked in this commit.
        let grants_revoked: Vec<String> = {
            let mut registry = self.registry.write().expect("registry poisoned");
            let mut revoked = Vec::new();
            registry.grants.retain(|g| {
                let names_it = matches!(&g.to, GrantTarget::Entry { node_id, entry_id }
                    if node_id == from && entry_id == entry);
                if names_it {
                    revoked.push(g.id.clone());
                }
                !names_it
            });
            revoked
        };

        // --- M4: the commit --------------------------------------------------------------
        let committed = self.persist_with_root_edit_locked(&one_writer, rk, now, &mut |_| {});
        if let Err(e) = committed {
            if self.was_crash_injected() {
                return Err(internal(format!("injected crash: {e}")));
            }
            // An error after the registry landed is a commit that reported failure: read the disk.
            let landed = credmgr_store::registry_file::load(&self.paths, rk)
                .ok()
                .and_then(|d| {
                    d.manifests
                        .get(from)
                        .map(|b| b.generation > from_generation)
                })
                == Some(true);
            if landed {
                let _ = self.refresh_registry_meta(rk);
            } else {
                // Not committed: memory and files back to before.
                for (node, body) in [(from, from_before), (to, to_before)] {
                    match body {
                        Some(body) => self.set_manifest(node, body),
                        None => {
                            self.take_manifest(node);
                        }
                    }
                }
                self.registry.write().expect("registry poisoned").grants = grants_before;
                let restored = atomic::write(&self.paths.manifest(from), &from_manifest)
                    .and_then(|_| atomic::write(&self.paths.manifest(to), &to_manifest))
                    .and_then(|_| atomic::remove_durable(&dest_env));
                drop(one_writer);
                let _ = remove_stage(&stage);
                return Err(internal(match restored {
                    Ok(()) => format!("moving the entry failed and was rolled back: {e}"),
                    Err(r) => format!(
                        "moving the entry failed ({e}) and its old files could not be put back ({r}); \
                         restart credmgrd — the next unlock finishes the rollback"
                    ),
                }));
            }
        }
        drop(one_writer);
        #[cfg(feature = "test-utils")]
        self.move_fault_point(MoveFault::AfterCommit)?;

        // --- M5: the source copy goes, then the stage ------------------------------------------
        let history_dir = self
            .paths
            .archive_root()
            .join("entry-history")
            .join(from)
            .join(entry);
        let history_dropped = history_slots(&history_dir);
        let cleaned = atomic::remove_durable(&self.paths.entry_env(from, entry))
            .and_then(|_| remove_dir_if_present(&history_dir));
        if let Err(e) = cleaned {
            return Err(internal(format!(
                "the entry was moved to {to} but its old copy could not be deleted ({e}); the stage is kept — \
                 restart credmgrd and unlock to finish it"
            )));
        }
        // An approval waiting on the old address would release nothing now; drop its staged value.
        for pending in self.pending_approvals(now) {
            if pending.node_id == from && pending.entry_id == entry {
                self.discard_approval(&pending.id);
            }
        }
        #[cfg(feature = "test-utils")]
        let fail_cleanup = self.move_fault_take(MoveFault::StageLeftBehind);
        #[cfg(not(feature = "test-utils"))]
        let fail_cleanup = false;
        let cleared = if fail_cleanup {
            Err("injected cleanup failure (test seam)".to_string())
        } else {
            remove_stage(&stage).map_err(|e| e.to_string())
        };
        let cleanup_warning = match cleared {
            Ok(()) => {
                let _ = std::fs::remove_dir(self.paths.move_stage_root());
                None
            }
            Err(e) => {
                let warning = format!(
                    "the entry was moved to {to}, but its stage could not be cleared ({e}); nothing is lost — \
                     the next unlock settles it"
                );
                eprintln!("credmgrd: warning: {warning}");
                Some(warning)
            }
        };

        Ok(MoveOutcome {
            entry: entry.to_string(),
            r#ref: row.r#ref,
            name: row.name,
            from_generation: new_from_generation,
            to_generation: new_to_generation,
            grants_revoked,
            history_dropped,
            cleanup_warning,
        })
    }

    fn registry_meta_snapshot(&self) -> RegistryDocument {
        self.registry_meta
            .read()
            .expect("registry meta poisoned")
            .clone()
    }

    // --- recovery -----------------------------------------------------------------------

    /// Settle every `move-pending/<entry>/` against `doc`, the registry that has just verified. See the
    /// module docs: the generations it binds for the two manifests say whether the commit happened.
    pub(super) fn recover_interrupted_moves(
        &self,
        root_key: &[u8; 32],
        doc: &RegistryDocument,
    ) -> Result<(), StoreError> {
        let stage_root = self.paths.move_stage_root();
        let Ok(read) = std::fs::read_dir(&stage_root) else {
            return Ok(());
        };
        let mut entries: Vec<String> = read
            .flatten()
            .filter_map(|d| d.file_name().into_string().ok())
            .collect();
        entries.sort();
        for entry in entries {
            if !plain_entry_id(&entry) {
                continue; // not ours to interpret; nothing ever writes such a directory.
            }
            self.settle_move_stage(root_key, doc, &entry, &stage_root.join(&entry))?;
        }
        let _ = std::fs::remove_dir(&stage_root); // best effort; only if empty.
        Ok(())
    }

    fn settle_move_stage(
        &self,
        root_key: &[u8; 32],
        doc: &RegistryDocument,
        entry: &str,
        stage: &std::path::Path,
    ) -> Result<(), StoreError> {
        let plan_path = stage.join("plan.sealed");
        if !atomic::exists(&plan_path) {
            // The crash came before the plan (written before the new envelope) existed: nothing was written
            // outside the stage.
            return remove_stage(stage);
        }
        let sealed = atomic::read(&plan_path)?;
        let plan: Plan = open_under_root(root_key, &plan_label(entry), &sealed)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(|p: &Plan| {
                p.v == PLAN_VERSION
                    && p.entry == entry
                    && is_path_safe_node_id(&p.from)
                    && is_path_safe_node_id(&p.to)
                    && p.from != p.to
            })
            .ok_or_else(|| {
                corrupt(
                    plan_path.clone(),
                    "a move stage's plan failed its authentication",
                )
            })?;
        let bound = |node: &str| doc.manifests.get(node).map(|b| b.generation);
        match (bound(&plan.from), bound(&plan.to)) {
            (Some(f), Some(t)) if f > plan.from_generation && t > plan.to_generation => {
                self.roll_move_forward(root_key, &plan, stage)
            }
            (Some(f), Some(t)) if f == plan.from_generation && t == plan.to_generation => {
                self.roll_move_back(&plan, stage)
            }
            // A node went, or the vault was restored from elsewhere: the stage describes nothing live.
            _ => remove_stage(stage),
        }
    }

    /// Committed: the destination holds the entry. The source copy and its retained history go — but only
    /// once the committed source manifest is seen not to name the entry.
    fn roll_move_forward(
        &self,
        root_key: &[u8; 32],
        plan: &Plan,
        stage: &std::path::Path,
    ) -> Result<(), StoreError> {
        let source = manifest::load(&self.paths, root_key, &plan.from)?;
        if !source.body.entries.iter().any(|e| e.id == plan.entry) {
            atomic::remove_durable(&self.paths.entry_env(&plan.from, &plan.entry))?;
            remove_dir_if_present(
                &self
                    .paths
                    .archive_root()
                    .join("entry-history")
                    .join(&plan.from)
                    .join(&plan.entry),
            )?;
        }
        remove_stage(stage)
    }

    /// Not committed: both manifests back as they were, and the new envelope (which no manifest names) goes.
    fn roll_move_back(&self, plan: &Plan, stage: &std::path::Path) -> Result<(), StoreError> {
        let from_manifest = atomic::read(&stage.join("from.manifest"))?;
        let to_manifest = atomic::read(&stage.join("to.manifest"))?;
        if hex_encode(&sha256_of(&from_manifest)) != plan.from_manifest_sha256
            || hex_encode(&sha256_of(&to_manifest)) != plan.to_manifest_sha256
        {
            return Err(corrupt(
                stage.to_path_buf(),
                "the staged copies of the manifests do not match the move plan",
            ));
        }
        atomic::write(&self.paths.manifest(&plan.from), &from_manifest)?;
        atomic::write(&self.paths.manifest(&plan.to), &to_manifest)?;
        let dest_env = self.paths.entry_env(&plan.to, &plan.entry);
        let ours = atomic::read(&dest_env)
            .map(|b| hex_encode(&sha256_of(&b)) == plan.envelope_sha256)
            .unwrap_or(false);
        if ours {
            atomic::remove_durable(&dest_env)?;
        }
        remove_stage(stage)
    }

    // --- test seams ---------------------------------------------------------------------

    /// Arm a fault for the next move (test seam, ADR-158).
    #[cfg(feature = "test-utils")]
    pub fn set_move_fault_for_test(&self, fault: Option<MoveFault>) {
        *self.stable.move_fault.lock().expect("move fault poisoned") = fault;
    }

    #[cfg(feature = "test-utils")]
    fn move_fault_take(&self, at: MoveFault) -> bool {
        let mut armed = self.stable.move_fault.lock().expect("move fault poisoned");
        if *armed == Some(at) {
            *armed = None;
            return true;
        }
        false
    }

    #[cfg(feature = "test-utils")]
    fn move_fault_point(&self, at: MoveFault) -> Result<(), OpError> {
        if self.move_fault_take(at) {
            self.crash_injected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Err(internal(format!(
                "injected crash (test seam): the process died at {at:?}"
            )));
        }
        Ok(())
    }
}
