//! ADR-079 (K-7) — the orphan node's life cycle, and seal / restore as a
//! **commit protocol** on a vault that lives on disk.
//!
//! Until ADR-079 four things were missing (`PHASE8_AUDIT_REPORT.md §4`, K-7):
//! `credmgr init` made no `orphan` node and no cold key, so `node.seal` answered
//! `internal` in a real vault; seal records lived only in memory, so a restart
//! forgot every seal still inside its 7-day window; and a seal moved its files
//! *before* the registry committed, so a crash in between left a vault that
//! would not unlock. This module is the second and third, and the lazy half of
//! the first.
//!
//! # The orphan node
//!
//! `credmgr init` writes it (public key in the registry, private half sealed in
//! `keys/cold/orphan.key` — `credmgr_core::cold`). A vault an older build
//! initialised has none; it gets one the first time something needs it —
//! `node.seal` ([`BrokerState::ensure_orphan`]) or `maintenance.doctor` — and
//! **never as a side effect of unlock**, which stays free of signed-state writes.
//! Its private half is never loaded: not into the hot set, not into
//! `node_wrapped_keys`, not written to `keys/nodes/`.
//!
//! # Seal, as a commit protocol (the registry write is the commit point)
//!
//! | step | what | status |
//! |---|---|---|
//! | S0 | authorise (the caller); refuse live children, an already-sealed id, an unsafe id; make sure the orphan exists; open the cold key once to prove it is recoverable; write the vault through so disk is level with memory | — |
//! | S1 | decrypt each entry, re-encrypt to the orphan public key, digest the new envelope; read the node key file's digest and the manifest's binding | memory only |
//! | S2 | write the orphan envelopes and `archive/<id>/meta.json` | pre-commit, **unread** |
//! | S3 | memory: orphan rows (one generation bump), node removed, grants revoked, hot key zeroised | memory |
//! | S4 | **commit**: the registry is written with `sealed[id]` — inside the op | **commit** |
//! | S5 | `nodes/<id>` → `archive/<id>/node`, `keys/nodes/<id>.key` → `archive/<id>/node.key` | post-commit, idempotent |
//!
//! Everything before S4 is a file nothing reads until the registry names it;
//! everything after is a move the registry has already authorised, and which
//! load-time housekeeping ([`BrokerState::housekeep_after_load`]) finishes if a
//! crash cut it short. A crash at any step therefore leaves a vault that
//! unlocks, with the node either still live (before S4) or sealed and
//! restorable (after) — see the crash table in `tests/seal_durable.rs`.
//!
//! Restore is the same shape in reverse: move the files back *while the
//! registry still says sealed* (unread there, so a refusal at any later check
//! puts them back and nothing observable changed), verify them against the
//! signed record, commit the registry without the record, then clean up.
//!
//! # What housekeeping may and may not do
//!
//! It runs once, after everything signed has verified, and is best-effort: it
//! never fails an unlock and **never writes signed state** (the same discipline
//! as the ADR-069 tray scan). It moves files the signed registry says belong in
//! the archive, removes a `meta.json` left by an aborted seal or a finished
//! restore, and deletes orphan envelopes no manifest row refers to and a live
//! node's manifest does. Anything that would need a manifest or registry write
//! — the orphan *rows* an interrupted seal left — is `maintenance.doctor`'s.

use std::collections::{HashMap, HashSet};

use secrecy::ExposeSecret;
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

use credmgr_core::keys::{unwrap_node_key, WrappedNodeKey};
use credmgr_core::registry::{
    is_path_safe_node_id, validate_registry, Grant, Node, GLOBAL_ID, ORPHAN_ID,
};
use credmgr_core::{cold, envelope};
use credmgr_store::archive::{self, RECOVERY_WINDOW_SECONDS};
use credmgr_store::error::StoreError;
use credmgr_store::manifest::{self, ManifestBody, ManifestEntry};
use credmgr_store::registry_file::{
    self, NodeDoc, RegistryDocument, SealedNodeDoc, SEALED_RECORD_VERSION,
};
use credmgr_store::{atomic, verify};

use super::{hex_encode, sha256_of, BrokerState};
use crate::protocol::OpError;

/// A step of seal or restore at which the test suite can make the process
/// "die" (ADR-079's crash tables). What the steps so far left on disk is what
/// the next start meets, and no cleanup runs. The two crashes that happen
/// *inside* the registry write are [`super::PersistFault`]'s. Compiled only with
/// `test-utils`.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealFault {
    /// Seal, after S2: the orphan envelopes and `meta.json` are on disk, nothing
    /// is committed, nothing in memory has changed.
    SealAfterPreCommit,
    /// Seal, after S4: committed, neither file has moved.
    SealAfterCommit,
    /// Seal, after S5's first move: the node directory is in the archive, the
    /// key is not.
    SealAfterNodeDirMoved,
    /// Restore, after R1: the files are back in their live places, the registry
    /// still says sealed.
    RestoreAfterMoveOut,
    /// Restore, after R5: committed, the orphan envelopes and `meta.json` remain.
    RestoreAfterCommit,
}

/// Where a test parks a seal or restore (see `set_seal_pause_for_test`).
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealPause {
    /// Seal, after its pre-commit files are written and **before** it takes the
    /// persist lock: another client's `node.create` can still run here (4.11).
    SealBeforeLock,
    /// Restore, after its pre-checks and its files are moved out, **before** it
    /// takes the persist lock: another client's `node.set_workdirs` can still
    /// run here (4.11).
    RestoreBeforeLock,
    /// Seal, the persist lock held, memory half-changed, nothing committed.
    SealBeforeCommit,
    /// Restore, the persist lock held, memory half-changed, nothing committed.
    RestoreBeforeCommit,
}

/// What [`BrokerState::purge_expired_seals`] removed for one sealed node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgedSeal {
    pub id: String,
    pub sealed_at: i64,
    /// `archive/<id>/` is gone. `false` means the seal record was dropped (the
    /// commit) but removing the directory failed; it holds nothing the vault reads.
    pub archive_removed: bool,
}

/// What a durable seal did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealOutcome {
    /// The seal is committed, but moving the node's files into the archive did
    /// not finish. The next unlock finishes it; until then the files sit where
    /// they were. (They are unreachable either way: the registry no longer
    /// names the node.)
    pub archive_move_pending: bool,
}

/// What a durable restore did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Workdirs the node had when it was sealed that another node has taken
    /// since. They are **dropped**, not reassigned — two nodes owning one
    /// directory would make auto-scoping ambiguous (`03 §1`).
    pub workdirs_dropped: Vec<String>,
}

fn internal(what: impl std::fmt::Display) -> OpError {
    OpError::Internal(what.to_string())
}

/// One thing `maintenance.verify` found about the orphan node or the seal records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanFinding {
    /// `true`: the vault is not sound (`ok: false`). `false`: worth knowing.
    pub is_error: bool,
    /// Which node the finding is about (`"orphan"`, or a sealed node's id).
    pub node: String,
    pub detail: String,
}

impl BrokerState {
    // --- reading the seal records -------------------------------------------

    /// The ids of every node with a durable seal record (inside its window, or
    /// past it and not yet purged).
    pub fn sealed_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .registry_meta
            .read()
            .expect("registry meta poisoned")
            .sealed
            .keys()
            .cloned()
            .collect();
        ids.sort();
        ids
    }

    /// The durable seal record for `node_id`, if there is one.
    pub fn sealed_doc(&self, node_id: &str) -> Option<SealedNodeDoc> {
        self.registry_meta
            .read()
            .expect("registry meta poisoned")
            .sealed
            .get(node_id)
            .cloned()
    }

    /// Whether `node_id` is spoken for by a seal — a durable record, or (for an
    /// in-memory fixture) the in-memory one. `node.create` refuses such an id
    /// (ADR-079, F-d): a new node of the same id would put its files where the
    /// archive's are.
    pub fn is_id_sealed(&self, node_id: &str) -> bool {
        self.registry_meta
            .read()
            .expect("registry meta poisoned")
            .sealed
            .contains_key(node_id)
            || self
                .sealed_nodes
                .read()
                .expect("sealed nodes poisoned")
                .contains_key(node_id)
    }

    /// Put grants back that [`BrokerState::revoke_grants_touching`] removed —
    /// the revert of a seal whose commit failed.
    fn reinstate_grants(&self, grants: Vec<Grant>) {
        self.registry
            .write()
            .expect("registry poisoned")
            .grants
            .extend(grants);
    }

    /// ADR-089 (4.11): the persist lock, for an op that changes the registry
    /// in memory and must not do so while a seal or restore is between its first
    /// memory change and its commit (`node.create`, `node.set_workdirs`). Held
    /// across the check and the insert only — never across the write-through the
    /// dispatcher makes afterwards, which takes the same lock. Lock order: the
    /// same as everywhere (node write locks first, then this).
    pub fn hold_persist_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock_persist()
    }

    /// ADR-079: add `rows` to `node_id`'s manifest as **one** write — a single
    /// generation bump however many rows — replacing any row that already has
    /// the same id (an aborted seal's residue). The single bump matters: the
    /// loader accepts a manifest exactly one generation ahead of its binding
    /// (an interrupted write) and refuses one further ahead, so a seal that
    /// bumped once per entry would turn a crash into a vault that will not open.
    fn put_manifest_rows(&self, node_id: &str, rows: Vec<ManifestEntry>) {
        let mut manifests = self.manifests.write().expect("manifests poisoned");
        let body = manifests
            .entry(node_id.to_string())
            .or_insert_with(|| ManifestBody::new(node_id));
        let replacing: HashSet<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        body.entries.retain(|e| !replacing.contains(e.id.as_str()));
        body.entries.extend(rows);
        // ADR-078: the one place `counts` is defined. An entry counts as TOTP when
        // it is typed `totp` OR carries a TOTP-seed field (`has_totp`); counting
        // `entry_type` alone here left an orphaned server-with-a-seed uncounted.
        body.recount();
        body.generation += 1;
    }

    // --- the orphan node ----------------------------------------------------

    /// Make sure this vault has an `orphan` node with a recoverable cold key,
    /// creating both if it has neither (a vault an older build initialised).
    /// `Ok(true)` when it created them.
    ///
    /// Creating writes `keys/cold/orphan.key` (overwriting a stray file — an
    /// interrupted earlier attempt; nothing was ever sealed to it, because no
    /// registry named it) and adds the node to the **running** registry. The
    /// registry and the orphan's manifest reach disk with the caller's next
    /// persist. Existing: the cold file is checked against the registry's public
    /// key, and a mismatch refuses ([`BrokerState::cold_key_preflight`]).
    ///
    /// The caller holds the `orphan` node's write lock.
    pub(crate) fn ensure_orphan(&self, root_key: &[u8; 32]) -> Result<bool, OpError> {
        let have_node = self
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .contains_key(ORPHAN_ID);
        if have_node {
            self.cold_key_preflight(root_key)?;
            return Ok(false);
        }
        let (public, file) = cold::generate_orphan_cold(root_key);
        atomic::write(&self.paths.orphan_key(), &file)
            .map_err(|e| internal(format!("writing the orphan cold key: {e}")))?;
        self.seed_public_key_only(ORPHAN_ID, public);
        self.insert_node(Node::orphan());
        Ok(true)
    }

    /// ADR-079, custody rule 3: before a seal commits data to the orphan key,
    /// prove that key is recoverable — open the cold file under the resident
    /// root key, require the private half to match **both** the file's header and
    /// the registry's public key, and drop it (zeroised) at once. A seal is
    /// irreversible after day 7; one transient materialisation, inside a broker
    /// that already holds the root key, is the price of knowing the key exists.
    pub(crate) fn cold_key_preflight(&self, root_key: &[u8; 32]) -> Result<(), OpError> {
        let bad = || {
            internal(
                "the orphan cold key is missing or does not match the registry — nothing was \
                 sealed; run `credmgr doctor`",
            )
        };
        let public = self.node_public_key(ORPHAN_ID).ok_or_else(bad)?;
        let bytes = atomic::read(&self.paths.orphan_key()).map_err(|_| bad())?;
        let secret = cold::open_orphan_cold(root_key, &bytes, Some(&public)).map_err(|_| bad())?;
        drop(secret);
        Ok(())
    }

    // --- seal ---------------------------------------------------------------

    /// ADR-079 (F-c): `Err` when `target` has live sub-nodes. Asked twice by a
    /// seal — at S0, and again once the persist lock is held (ADR-089): a
    /// `node.create` under `target` that landed between the two would otherwise
    /// be committed beside a registry that no longer has its parent.
    fn refuse_if_sub_nodes(&self, target: &str) -> Result<(), OpError> {
        let registry = self.registry.read().expect("registry poisoned");
        let mut children: Vec<&str> = registry
            .nodes
            .values()
            .filter(|n| n.parent_id.as_deref() == Some(target))
            .map(|n| n.id.as_str())
            .collect();
        if children.is_empty() {
            return Ok(());
        }
        children.sort_unstable();
        Err(OpError::Malformed(format!(
            "{target} has sub-nodes ({}) — seal them first",
            children.join(", ")
        )))
    }

    /// Seal `target` on a disk-backed vault. See the module docs for the protocol.
    ///
    /// The caller has authorised the request, found `target` live, refused one
    /// with live sub-nodes, obtained its hot key (`node_priv`), and holds the
    /// write locks of `target` and `orphan`.
    pub fn seal_node_durable(
        &self,
        target: &str,
        node_priv: &StaticSecret,
        now: i64,
    ) -> Result<SealOutcome, OpError> {
        let root = self
            .reauth_root_key("node seal")
            .map_err(|_| OpError::VaultLocked)?;
        let rk = root.expose_secret();

        // --- S0 ----------------------------------------------------------------
        if !is_path_safe_node_id(target) {
            return Err(OpError::Malformed(format!(
                "node id {target:?} cannot be sealed: it is not a safe file name"
            )));
        }
        if self.is_id_sealed(target) {
            return Err(OpError::Malformed(format!("{target} is already sealed")));
        }
        // ADR-079 (F-c): a project with live sub-nodes cannot be sealed — they
        // would stay in the registry with a `parentId` that no longer resolves.
        // Seal them first. (This guard lives here, on the disk-backed path every
        // real daemon takes, and not in the in-memory fixture path
        // `tests/isolation.rs` I-21 exercises: that fixture seals a project that
        // has two sub-nodes, to prove the authorisation, not the tree.)
        self.refuse_if_sub_nodes(target)?;
        // A directory left by an aborted seal holds only a `meta.json`. Anything
        // else in there is not ours to delete.
        if !archive::retire_archive_dir(&self.paths, target)
            .map_err(|e| internal(format!("clearing an aborted seal's leftovers: {e}")))?
        {
            return Err(internal(format!(
                "archive/{target} already exists and holds files — refusing to seal over it"
            )));
        }
        self.ensure_orphan(rk)?;
        self.cold_key_preflight(rk)?;
        // Disk level with memory — and the orphan, if it was just created, in its
        // own earlier commit, so a crash anywhere below leaves it in place.
        self.persist_with_root(rk, now)
            .map_err(|e| internal(format!("saving the vault before sealing: {e}")))?;

        // --- S1 ----------------------------------------------------------------
        let live_node = self
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .get(target)
            .cloned()
            .ok_or_else(|| OpError::NotFound(format!("no node {target}")))?;
        let (node_doc, binding) = {
            let meta = self.registry_meta.read().expect("registry meta poisoned");
            (
                meta.nodes.get(target).cloned(),
                meta.manifests.get(target).cloned(),
            )
        };
        let (Some(node_doc), Some(binding)) = (node_doc, binding) else {
            return Err(internal(format!(
                "the registry has no record of node {target} to seal"
            )));
        };
        // The manifest that will be archived must be exactly the one the signed
        // registry binds, or the restore that checks it would refuse its own seal.
        let on_disk = manifest::load(&self.paths, rk, target)
            .map_err(|e| internal(format!("reading {target}'s manifest: {e}")))?;
        let memory_generation = self.manifest_generation(target).unwrap_or(0);
        if on_disk.body.generation != binding.generation
            || on_disk.hmac != binding.manifest_hmac
            || on_disk.body.generation != memory_generation
        {
            return Err(internal(format!(
                "{target}'s manifest on disk is not the one the registry binds — nothing was \
                 sealed; run `credmgr doctor`"
            )));
        }
        let key_bytes = atomic::read(&self.paths.node_key(target))
            .map_err(|e| internal(format!("reading {target}'s node key: {e}")))?;
        let node_key_sha256 = hex_encode(&sha256_of(&key_bytes));

        let orphan_public = self
            .node_public_key(ORPHAN_ID)
            .ok_or_else(|| internal("orphan has no public key registered"))?;
        let entries: Vec<ManifestEntry> = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(target)
            .map(|m| m.entries.clone())
            .unwrap_or_default();
        let (recorded_ids, orphan_names, orphan_ids_before): (
            HashSet<String>,
            HashSet<String>,
            HashSet<String>,
        ) = {
            let recorded = self
                .registry_meta
                .read()
                .expect("registry meta poisoned")
                .sealed
                .values()
                .flat_map(|r| r.orphan_entry_ids.iter().cloned())
                .collect();
            let manifests = self.manifests.read().expect("manifests poisoned");
            let rows = manifests.get(ORPHAN_ID);
            // A row this very seal is about to replace (an aborted seal's
            // residue) does not make its name "taken".
            let ours: HashSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
            (
                recorded,
                rows.map(|m| {
                    m.entries
                        .iter()
                        .filter(|e| !ours.contains(e.id.as_str()))
                        .map(|e| credmgr_core::names::canonical_name(&e.name))
                        .collect()
                })
                .unwrap_or_default(),
                rows.map(|m| m.entries.iter().map(|e| e.id.clone()).collect())
                    .unwrap_or_default(),
            )
        };

        let mut rows: Vec<(ManifestEntry, Vec<u8>)> = Vec::with_capacity(entries.len());
        for entry in &entries {
            if recorded_ids.contains(&entry.id) {
                return Err(internal(format!(
                    "entry id {} is already held by another sealed node — nothing was sealed",
                    entry.id
                )));
            }
            let bytes = atomic::read(&self.paths.entry_env(target, &entry.id))
                .map_err(|e| internal(format!("reading entry to seal: {e}")))?;
            // ADR-078: an entry is a version-1 raw value (alpha.6) or a version-2
            // field document. The payload is carried across **unchanged and of the
            // same kind** — sealing re-encrypts, it never reads, edits or migrates
            // a field — so a multi-field entry comes out of the orphan node as the
            // same document it went in as.
            let (kind, plaintext) = envelope::open_any(&bytes, node_priv, target, &entry.id)
                .map_err(|_| internal("failed to open entry being sealed"))?;
            let resealed = envelope::seal_as(
                kind,
                plaintext.expose_secret(),
                &orphan_public,
                ORPHAN_ID,
                &entry.id,
            )
            .map_err(|_| internal("failed to reseal entry under the orphan key"))?;
            // Names are unique per node and the orphan is a node too: on the
            // rare collision between two sealed nodes' entry names, disambiguate
            // rather than drop one.
            // ADR-084: names are compared canonically, here as everywhere.
            let name = if orphan_names.contains(&credmgr_core::names::canonical_name(&entry.name)) {
                format!("{} ({target})", entry.name)
            } else {
                entry.name.clone()
            };
            rows.push((
                ManifestEntry {
                    id: entry.id.clone(),
                    name,
                    r#ref: self.next_ref(),
                    entry_type: entry.entry_type,
                    sensitivity: entry.sensitivity,
                    field_count: entry.field_count,
                    has_totp: entry.has_totp,
                    // ADR-067 (F-b): the digest of the NEW envelope — the orphan
                    // row used to carry the original envelope's digest.
                    sha256: hex_encode(&sha256_of(&resealed)),
                    modified: now,
                    expires_at: entry.expires_at,
                    rotated_at: entry.rotated_at,
                },
                resealed,
            ));
        }
        let orphan_entry_ids: Vec<String> = rows.iter().map(|(r, _)| r.id.clone()).collect();

        // --- S2: pre-commit files, unread until the registry names them ---------
        let mut written: Vec<String> = Vec::new();
        let pre_commit = (|| -> Result<(), StoreError> {
            for (row, bytes) in &rows {
                atomic::write(&self.paths.entry_env(ORPHAN_ID, &row.id), bytes)?;
                written.push(row.id.clone());
            }
            archive::write_meta_file(&self.paths, rk, target, now)
        })();
        if let Err(e) = pre_commit {
            self.discard_seal_files(target, &written, &orphan_ids_before);
            return Err(internal(format!("writing the sealed entries: {e}")));
        }
        #[cfg(feature = "test-utils")]
        self.seal_fault_point(SealFault::SealAfterPreCommit)?;

        // --- S3: memory ---------------------------------------------------------
        // The persist lock is held from the first memory change to the end of the
        // commit (and any rollback), so no other client's write-through can put
        // this half-done state on disk (C1 / ADR-079 amendment).
        #[cfg(feature = "test-utils")]
        self.seal_pause_point(SealPause::SealBeforeLock);
        let one_writer = self.lock_persist();
        // ADR-089 (4.11): the sub-node check at S0 ran a long time ago (S1 and S2
        // decrypt and write). A child created since is found now, before anything
        // in memory has changed, and nothing is committed.
        if let Err(e) = self.refuse_if_sub_nodes(target) {
            drop(one_writer);
            self.discard_seal_files(target, &written, &orphan_ids_before);
            return Err(e);
        }
        let target_manifest = self.take_manifest(target);
        let orphan_manifest_before = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(ORPHAN_ID)
            .cloned();
        // F-8/06 §6: "Grants ... do not survive seal".
        let revoked = self.revoke_grants_touching(target);
        self.remove_node(target);
        self.put_manifest_rows(ORPHAN_ID, rows.into_iter().map(|(r, _)| r).collect());
        let key_material = self.take_node_key_material(target);
        // (test seam: memory is half-changed, the commit has not happened)
        #[cfg(feature = "test-utils")]
        self.seal_pause_point(SealPause::SealBeforeCommit);

        // --- S4: the commit -----------------------------------------------------
        let record = SealedNodeDoc {
            v: SEALED_RECORD_VERSION,
            node: NodeDoc {
                node: live_node.clone(),
                created: node_doc.created,
                gate: node_doc.gate.clone(),
                pinned: node_doc.pinned,
                public_key: node_doc.public_key.clone(),
            },
            sealed_at: now,
            manifest: binding,
            node_key_sha256,
            orphan_entry_ids,
        };
        let committed = self.persist_with_root_edit_locked(&one_writer, rk, now, &mut |doc| {
            doc.sealed.insert(target.to_string(), record.clone());
        });
        if let Err(e) = committed {
            if self.was_crash_injected() {
                return Err(internal(format!("injected crash: {e}")));
            }
            // The registry write is two files and a counter; an error after the
            // registry landed is a commit that reported failure. Read the disk
            // before deciding which of the two this was.
            if self.registry_on_disk_has_sealed(rk, target) == Some(true) {
                let _ = self.refresh_registry_meta(rk);
            } else {
                self.insert_node(live_node);
                self.reinstate_grants(revoked);
                if let Some(body) = target_manifest {
                    self.set_manifest(target, body);
                }
                match orphan_manifest_before {
                    Some(body) => self.set_manifest(ORPHAN_ID, body),
                    None => {
                        self.take_manifest(ORPHAN_ID);
                    }
                }
                if let Some((wrapped, public)) = key_material {
                    self.restore_node_key_material(target, wrapped, public);
                }
                self.discard_seal_files(target, &written, &orphan_ids_before);
                return Err(internal(format!(
                    "sealing {target} failed and was rolled back: {e}"
                )));
            }
        }
        drop(key_material);
        drop(one_writer);
        #[cfg(feature = "test-utils")]
        self.seal_fault_point(SealFault::SealAfterCommit)?;

        // --- S5: post-commit moves ----------------------------------------------
        let mut pending = false;
        match archive::move_node_dir_in(&self.paths, target) {
            Ok(_) => {}
            Err(_) => pending = true,
        }
        #[cfg(feature = "test-utils")]
        self.seal_fault_point(SealFault::SealAfterNodeDirMoved)?;
        if archive::move_key_in(&self.paths, target).is_err() {
            pending = true;
        }
        Ok(SealOutcome {
            archive_move_pending: pending,
        })
    }

    /// Remove what a seal that did not commit wrote: the orphan envelopes it
    /// created (not a row that was already there — an earlier aborted seal's
    /// residue is not this call's to delete) and its `meta.json`.
    fn discard_seal_files(
        &self,
        target: &str,
        written: &[String],
        existed_before: &HashSet<String>,
    ) {
        for id in written {
            if !existed_before.contains(id) {
                let _ = atomic::remove_durable(&self.paths.entry_env(ORPHAN_ID, id));
            }
        }
        let _ = archive::retire_archive_dir(&self.paths, target);
    }

    /// Whether the registry **now on disk** carries a seal record for `id` —
    /// `None` if it cannot be read (a torn pair, which is not a commit).
    fn registry_on_disk_has_sealed(&self, root_key: &[u8; 32], id: &str) -> Option<bool> {
        registry_file::load(&self.paths, root_key)
            .ok()
            .map(|doc| doc.sealed.contains_key(id))
    }

    // --- restore ------------------------------------------------------------

    /// Restore a sealed `target` on a disk-backed vault. See the module docs.
    ///
    /// The caller has authorised the request and holds the write locks of
    /// `target` and `orphan`.
    pub fn restore_node_durable(&self, target: &str, now: i64) -> Result<RestoreOutcome, OpError> {
        let root = self
            .reauth_root_key("node restore")
            .map_err(|_| OpError::VaultLocked)?;
        let rk = root.expose_secret();

        // --- R0 ----------------------------------------------------------------
        let record = self
            .sealed_doc(target)
            .ok_or_else(|| OpError::NotFound(format!("no sealed node {target}")))?;
        if now - record.sealed_at > RECOVERY_WINDOW_SECONDS {
            return Err(OpError::ArchiveExpired {
                node: target.to_string(),
            });
        }
        match archive::read_sealed_at(&self.paths, rk, target) {
            Ok(at) if at == record.sealed_at => {}
            Ok(_) => {
                return Err(internal(
                    "the archive's metadata does not match its seal record — nothing was restored",
                ))
            }
            Err(StoreError::ArchiveNotFound { .. }) => {
                return Err(OpError::NotFound(format!(
                    "no archive for sealed node {target}"
                )))
            }
            Err(e) => return Err(internal(format!("reading the archive's metadata: {e}"))),
        }

        // --- R3 (first: pure checks, nothing on disk moves yet) ------------------
        let (_, _) = self.restore_candidate(&record, target)?;

        // --- R1: bring the files back while the registry still says sealed -------
        archive::move_out(&self.paths, target)
            .map_err(|e| internal(format!("moving the archived node back: {e}")))
            .inspect_err(|_| {
                let _ = archive::move_in(&self.paths, target);
            })?;
        #[cfg(feature = "test-utils")]
        self.seal_fault_point(SealFault::RestoreAfterMoveOut)?;

        // --- R2: they are the files the signed record names ----------------------
        let verified = self.verify_restored_files(rk, target, &record);
        let (manifest_body, wrapped, public) = match verified {
            Ok(v) => v,
            Err(why) => {
                let _ = archive::move_in(&self.paths, target);
                return Err(internal(format!(
                    "the archive does not match its seal record ({why}) — nothing was restored"
                )));
            }
        };

        // --- R4: memory ---------------------------------------------------------
        // Held to the end of the commit and any rollback; see S3.
        #[cfg(feature = "test-utils")]
        self.seal_pause_point(SealPause::RestoreBeforeLock);
        let one_writer = self.lock_persist();
        // ADR-089 (4.11): R3 ran before the files moved. A `node.set_workdirs`
        // or `node.create` that claimed one of this node's directories (or took
        // the parent away) since is found now, under the lock, and decides what
        // is restored: a directory another node owns is dropped and reported, a
        // gone parent refuses — and the files go back to the archive. Committing
        // the stale answer would write a registry that fails its own next load.
        let (candidate, workdirs_dropped) = match self.restore_candidate(&record, target) {
            Ok(v) => v,
            Err(e) => {
                drop(one_writer);
                let _ = archive::move_in(&self.paths, target);
                return Err(e);
            }
        };
        let orphan_manifest_before = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(ORPHAN_ID)
            .cloned();
        self.insert_node(candidate.clone());
        self.set_manifest(target, manifest_body);
        self.restore_node_key_material(target, wrapped, public);
        self.remove_manifest_entries(ORPHAN_ID, &record.orphan_entry_ids);
        // (test seam: memory is half-changed, the commit has not happened)
        #[cfg(feature = "test-utils")]
        self.seal_pause_point(SealPause::RestoreBeforeCommit);

        // --- R5: the commit -----------------------------------------------------
        let restored = NodeDoc {
            node: candidate.clone(),
            created: record.node.created,
            gate: record.node.gate.clone(),
            pinned: record.node.pinned,
            public_key: record.node.public_key.clone(),
        };
        let committed = self.persist_with_root_edit_locked(&one_writer, rk, now, &mut |doc| {
            doc.sealed.remove(target);
            doc.nodes.insert(target.to_string(), restored.clone());
        });
        if let Err(e) = committed {
            if self.was_crash_injected() {
                return Err(internal(format!("injected crash: {e}")));
            }
            if self.registry_on_disk_has_sealed(rk, target) == Some(false) {
                let _ = self.refresh_registry_meta(rk);
            } else {
                self.remove_node(target);
                self.take_manifest(target);
                self.take_node_key_material(target);
                match orphan_manifest_before {
                    Some(body) => self.set_manifest(ORPHAN_ID, body),
                    None => {
                        self.take_manifest(ORPHAN_ID);
                    }
                }
                let _ = archive::move_in(&self.paths, target);
                return Err(internal(format!(
                    "restoring {target} failed and was rolled back: {e}"
                )));
            }
        }
        drop(one_writer);
        #[cfg(feature = "test-utils")]
        self.seal_fault_point(SealFault::RestoreAfterCommit)?;

        // The node's locked-write tray (ADR-069) was not scanned while it was
        // sealed — a sealed node has no manifest to scan against. Rebuild it now.
        if let Some(body) = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(target)
            .cloned()
        {
            let scanned = self.scan_pending_tray(&HashMap::from([(target.to_string(), body)]));
            self.merge_pending_tray(scanned);
        }

        // --- R6: post-commit cleanup (best effort; housekeeping repeats it) ------
        for id in &record.orphan_entry_ids {
            let _ = atomic::remove_durable(&self.paths.entry_env(ORPHAN_ID, id));
        }
        let _ = archive::retire_archive_dir(&self.paths, target);

        Ok(RestoreOutcome { workdirs_dropped })
    }

    /// R3: what restoring `target` would insert right now — its node record with
    /// any directory another live node already owns dropped (and listed), checked
    /// against the registry's own invariants. Pure: it reads the registry and
    /// changes nothing. A restore asks it twice (ADR-089): before it moves any
    /// file, and again under the persist lock, because the registry can change in
    /// between.
    fn restore_candidate(
        &self,
        record: &SealedNodeDoc,
        target: &str,
    ) -> Result<(Node, Vec<String>), OpError> {
        let mut candidate = record.node.node.clone();
        let registry = self.registry.read().expect("registry poisoned");
        if registry.nodes.contains_key(target) {
            return Err(OpError::Malformed(format!(
                "a live node named {target} already exists"
            )));
        }
        match &candidate.parent_id {
            Some(parent) if registry.nodes.contains_key(parent) => {}
            Some(parent) => {
                return Err(OpError::Malformed(format!(
                    "restore {parent} first — {target}'s parent is sealed or gone"
                )))
            }
            None => {
                return Err(internal(format!(
                    "the seal record for {target} has no parent to restore it under"
                )))
            }
        }
        let owned: HashSet<&str> = registry
            .nodes
            .values()
            .flat_map(|n| n.workdirs.iter().map(String::as_str))
            .collect();
        let (dropped, kept): (Vec<String>, Vec<String>) = candidate
            .workdirs
            .iter()
            .cloned()
            .partition(|w| owned.contains(w.as_str()));
        candidate.workdirs = kept;
        let mut scratch = (*registry).clone();
        scratch.nodes.insert(target.to_string(), candidate.clone());
        let violations = validate_registry(&scratch);
        if !violations.is_empty() {
            return Err(OpError::Malformed(format!(
                "restoring {target} would violate a registry invariant: {violations:?}"
            )));
        }
        Ok((candidate, dropped))
    }

    /// R2: the manifest now at `nodes/<id>/manifest.json` carries the generation
    /// and HMAC the signed record binds, the key file at `keys/nodes/<id>.key`
    /// the digest it names, and that key — unwrapped under the root key — is the
    /// one whose public half the record holds. `Err` is the reason, in words.
    fn verify_restored_files(
        &self,
        root_key: &[u8; 32],
        target: &str,
        record: &SealedNodeDoc,
    ) -> Result<(ManifestBody, WrappedNodeKey, PublicKey), String> {
        let doc = manifest::load(&self.paths, root_key, target)
            .map_err(|e| format!("its manifest: {e}"))?;
        if doc.body.generation != record.manifest.generation
            || doc.hmac != record.manifest.manifest_hmac
        {
            return Err("its manifest is not the one that was sealed".to_string());
        }
        let key_bytes =
            atomic::read(&self.paths.node_key(target)).map_err(|e| format!("its node key: {e}"))?;
        if hex_encode(&sha256_of(&key_bytes)) != record.node_key_sha256 {
            return Err("its node key is not the one that was sealed".to_string());
        }
        let wrapped = WrappedNodeKey::from_bytes(&key_bytes)
            .map_err(|_| "its node key is not a wrapped key".to_string())?;
        let secret = unwrap_node_key(root_key, target, &wrapped)
            .map_err(|_| "its node key does not open under this vault's root key".to_string())?;
        let public = PublicKey::from(&secret);
        drop(secret);
        if hex_encode(public.as_bytes()) != record.node.public_key {
            return Err("its node key is not the keypair that was sealed".to_string());
        }
        Ok((doc.body, wrapped, public))
    }

    // --- load-time housekeeping ---------------------------------------------

    /// Finish what an interrupted seal or restore left on the file system
    /// (module docs). Best effort, silent, idempotent.
    pub(super) fn housekeep_after_load(&self) {
        let sealed: HashSet<String> = self.sealed_ids().into_iter().collect();

        // A sealed node's files belong in the archive: roll a seal's moves forward,
        // and put back what a restore moved out before it committed.
        for id in &sealed {
            if is_path_safe_node_id(id) {
                let _ = archive::move_in(&self.paths, id);
            }
        }

        // A live node with an `archive/<id>/meta.json` and no record is an
        // aborted seal's or a finished restore's leftover.
        let live: Vec<String> = self
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .keys()
            .filter(|id| {
                id.as_str() != GLOBAL_ID
                    && id.as_str() != ORPHAN_ID
                    && is_path_safe_node_id(id)
                    && !sealed.contains(id.as_str())
            })
            .cloned()
            .collect();
        for id in &live {
            if std::fs::symlink_metadata(self.paths.archive_dir(id)).is_ok() {
                let _ = archive::retire_archive_dir(&self.paths, id);
            }
        }

        // Orphan envelopes no row refers to, whose id a live node's manifest
        // holds: the copies an aborted seal wrote, or a restore left behind.
        let (live_ids, orphan_rows): (HashSet<String>, HashSet<String>) = {
            let manifests = self.manifests.read().expect("manifests poisoned");
            (
                manifests
                    .iter()
                    .filter(|(id, _)| id.as_str() != ORPHAN_ID)
                    .flat_map(|(_, m)| m.entries.iter().map(|e| e.id.clone()))
                    .collect(),
                manifests
                    .get(ORPHAN_ID)
                    .map(|m| m.entries.iter().map(|e| e.id.clone()).collect())
                    .unwrap_or_default(),
            )
        };
        let recorded: HashSet<String> = self
            .registry_meta
            .read()
            .expect("registry meta poisoned")
            .sealed
            .values()
            .flat_map(|r| r.orphan_entry_ids.iter().cloned())
            .collect();
        let dir = self.paths.node_dir(ORPHAN_ID).join("entries");
        if let Ok(read) = std::fs::read_dir(dir) {
            for file in read.flatten() {
                let path = file.path();
                if path.extension().and_then(|e| e.to_str()) != Some("env") {
                    continue;
                }
                let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                if live_ids.contains(id) && !orphan_rows.contains(id) && !recorded.contains(id) {
                    let _ = atomic::remove_durable(&path);
                }
            }
        }
    }

    // --- maintenance.verify -------------------------------------------------

    /// What `maintenance.verify` reports about the orphan node and the seal
    /// records, checked against `disk` — the registry as it is on disk.
    /// Transient: the cold key is opened under `root_key` and dropped.
    pub fn orphan_findings(
        &self,
        root_key: &[u8; 32],
        disk: &RegistryDocument,
    ) -> Vec<OrphanFinding> {
        let mut out = Vec::new();
        let mut add = |is_error: bool, node: &str, detail: String| {
            out.push(OrphanFinding {
                is_error,
                node: node.to_string(),
                detail,
            })
        };

        let cold_path = self.paths.orphan_key();
        let cold_present = std::fs::symlink_metadata(&cold_path).is_ok();
        match disk.nodes.get(ORPHAN_ID) {
            Some(orphan) => {
                if !cold_present {
                    add(
                        true,
                        ORPHAN_ID,
                        "the orphan cold key (keys/cold/orphan.key) is missing — sealing is \
                         refused until `credmgr doctor` repairs it"
                            .to_string(),
                    );
                } else {
                    match atomic::read(&cold_path) {
                        Err(e) => add(true, ORPHAN_ID, format!("the orphan cold key: {e}")),
                        Ok(bytes) => match cold::parse_header(&bytes) {
                            Err(e) => add(true, ORPHAN_ID, format!("the orphan cold key: {e}")),
                            Ok(header) => {
                                if hex_encode(header.public.as_bytes()) != orphan.public_key {
                                    add(
                                        true,
                                        ORPHAN_ID,
                                        "the orphan cold key does not match the registry's orphan \
                                         public key"
                                            .to_string(),
                                    );
                                } else if cold::open_orphan_cold(
                                    root_key,
                                    &bytes,
                                    Some(&header.public),
                                )
                                .is_err()
                                {
                                    add(
                                        true,
                                        ORPHAN_ID,
                                        "the orphan cold key does not open under this vault's root key"
                                            .to_string(),
                                    );
                                }
                            }
                        },
                    }
                }
            }
            None => {
                if cold_present {
                    add(
                        false,
                        ORPHAN_ID,
                        "keys/cold/orphan.key exists but the registry has no orphan node (an \
                         interrupted migration); it is replaced the next time something is sealed"
                            .to_string(),
                    );
                }
            }
        }
        if std::fs::symlink_metadata(self.paths.node_key(ORPHAN_ID)).is_ok() {
            add(
                false,
                ORPHAN_ID,
                "keys/nodes/orphan.key exists and is ignored — the orphan's private half is never \
                 loaded into the hot key set"
                    .to_string(),
            );
        }

        let mut ids: Vec<&String> = disk.sealed.keys().collect();
        ids.sort();
        for id in ids {
            let record = &disk.sealed[id];
            if !is_path_safe_node_id(id) {
                add(
                    true,
                    id,
                    "sealed under an id that is not a safe file name".to_string(),
                );
                continue;
            }
            if archive::has_live_files(&self.paths, id) {
                add(
                    false,
                    id,
                    "sealed, but its files are not yet in the archive (the move is finished at \
                     the next unlock)"
                        .to_string(),
                );
                continue;
            }
            let dir = self.paths.archive_dir(id);
            match atomic::read(&dir.join("node.key")) {
                Err(_) => add(
                    true,
                    id,
                    "sealed, but its archived node key is missing".to_string(),
                ),
                Ok(bytes) => {
                    if hex_encode(&sha256_of(&bytes)) != record.node_key_sha256 {
                        add(
                            true,
                            id,
                            "its archived node key is not the one the seal record names"
                                .to_string(),
                        );
                    }
                }
            }
            match manifest::load_at(&dir.join("node").join("manifest.json"), root_key, id) {
                Err(e) => add(
                    true,
                    id,
                    format!("its archived manifest does not verify: {e}"),
                ),
                Ok(m) => {
                    if m.body.generation != record.manifest.generation
                        || m.hmac != record.manifest.manifest_hmac
                    {
                        add(
                            true,
                            id,
                            "its archived manifest is not the one the seal record names"
                                .to_string(),
                        );
                    }
                }
            }
            match archive::read_sealed_at(&self.paths, root_key, id) {
                Ok(at) if at == record.sealed_at => {}
                Ok(_) => add(
                    true,
                    id,
                    "the archive's metadata disagrees with the seal record about when it was sealed"
                        .to_string(),
                ),
                Err(e) => add(true, id, format!("the archive's metadata: {e}")),
            }
        }
        out
    }

    // --- maintenance.doctor -------------------------------------------------

    /// The orphan-node repairs `maintenance.doctor` owns (ADR-079):
    ///
    /// * **no orphan node** (an older build's vault): create it;
    /// * **a missing or non-matching cold key**: regenerate it — but only while
    ///   nothing is sealed to the old one. With any orphaned data, regenerating
    ///   would strand it, so it is reported unfixable instead;
    /// * **orphan rows an interrupted seal left** for entries a live node still
    ///   holds, with no seal record: remove the rows and their envelopes.
    ///
    /// Returns `(fixes, unfixable)` as wire JSON. With `apply == false` nothing is
    /// changed and `fixes` is what would be.
    pub fn doctor_orphan(
        &self,
        root_key: &[u8; 32],
        apply: bool,
        now: i64,
    ) -> Result<(Vec<Value>, Vec<Value>), OpError> {
        let mut fixes = Vec::new();
        let mut unfixable = Vec::new();
        let orphan_lock = self.node_write_lock(ORPHAN_ID);
        let _guard = orphan_lock.lock().expect("node write lock poisoned");

        let have_node = self
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .contains_key(ORPHAN_ID);
        let sealed_any = !self.sealed_ids().is_empty();
        let rows_any = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(ORPHAN_ID)
            .is_some_and(|m| !m.entries.is_empty());

        if !have_node {
            fixes.push(json!({ "node": ORPHAN_ID, "type": "orphan-created" }));
            if apply {
                self.ensure_orphan(root_key)?;
                self.persist_with_root(root_key, now)
                    .map_err(|e| internal(format!("saving the new orphan node: {e}")))?;
            }
        } else if self.cold_key_preflight(root_key).is_err() {
            if sealed_any || rows_any {
                unfixable.push(json!({
                    "node": ORPHAN_ID,
                    "detail": "the orphan cold key is missing or does not match, and orphaned \
                               data exists: regenerating the key would strand it",
                }));
            } else {
                fixes.push(json!({ "node": ORPHAN_ID, "type": "orphan-cold-key-regenerated" }));
                if apply {
                    let (public, file) = cold::generate_orphan_cold(root_key);
                    atomic::write(&self.paths.orphan_key(), &file)
                        .map_err(|e| internal(format!("writing the orphan cold key: {e}")))?;
                    self.seed_public_key_only(ORPHAN_ID, public);
                    let public_hex = hex_encode(public.as_bytes());
                    self.persist_with_root_edit(root_key, now, &mut |doc| {
                        if let Some(orphan) = doc.nodes.get_mut(ORPHAN_ID) {
                            orphan.public_key.clone_from(&public_hex);
                        }
                    })
                    .map_err(|e| internal(format!("saving the regenerated orphan key: {e}")))?;
                }
            }
        }

        // Residue rows.
        let (live_ids, recorded): (HashSet<String>, HashSet<String>) = {
            let manifests = self.manifests.read().expect("manifests poisoned");
            (
                manifests
                    .iter()
                    .filter(|(id, _)| id.as_str() != ORPHAN_ID)
                    .flat_map(|(_, m)| m.entries.iter().map(|e| e.id.clone()))
                    .collect(),
                self.registry_meta
                    .read()
                    .expect("registry meta poisoned")
                    .sealed
                    .values()
                    .flat_map(|r| r.orphan_entry_ids.iter().cloned())
                    .collect(),
            )
        };
        let residue: Vec<String> = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(ORPHAN_ID)
            .map(|m| {
                m.entries
                    .iter()
                    .filter(|e| live_ids.contains(&e.id) && !recorded.contains(&e.id))
                    .map(|e| e.id.clone())
                    .collect()
            })
            .unwrap_or_default();
        if !residue.is_empty() {
            fixes.push(json!({
                "node": ORPHAN_ID,
                "type": "orphan-residue-removed",
                "entries": residue.len(),
            }));
            if apply {
                self.remove_manifest_entries(ORPHAN_ID, &residue);
                self.persist_with_root(root_key, now)
                    .map_err(|e| internal(format!("saving the orphan node: {e}")))?;
                for id in &residue {
                    let _ = atomic::remove_durable(&self.paths.entry_env(ORPHAN_ID, id));
                }
            }
        }
        Ok((fixes, unfixable))
    }

    /// `find_digest_mismatches` for the orphan node's own rows — used by tests
    /// to prove ADR-067's digest holds for resealed envelopes (F-b).
    pub fn orphan_digest_mismatches(&self) -> Result<Vec<String>, StoreError> {
        let body = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(ORPHAN_ID)
            .cloned()
            .unwrap_or_else(|| ManifestBody::new(ORPHAN_ID));
        verify::find_digest_mismatches(&self.paths, ORPHAN_ID, &body)
    }

    /// `(id, label, sealedAt)` for every sealed node, sorted by id — what
    /// `graph.snapshot` lists for a human who may restore (ADR-080). Reads the
    /// signed registry's in-memory copy; names and the window only.
    pub fn sealed_node_summaries(&self) -> Vec<(String, String, i64)> {
        let doc = self.registry_meta.read().expect("registry meta poisoned");
        let mut rows: Vec<(String, String, i64)> = doc
            .sealed
            .iter()
            .map(|(id, rec)| (id.clone(), rec.node.node.label.clone(), rec.sealed_at))
            .collect();
        rows.sort();
        rows
    }

    // --- purge (K-7 WP6, ADR-089) -------------------------------------------

    /// The sealed nodes whose seven days are over at `now`: `(id, sealedAt)`,
    /// sorted by id. Pure; changes nothing.
    pub fn expired_seals(&self, now: i64) -> Vec<(String, i64)> {
        self.sealed_node_summaries()
            .into_iter()
            .filter(|(id, _, at)| now - at > RECOVERY_WINDOW_SECONDS && is_path_safe_node_id(id))
            .map(|(id, _, at)| (id, at))
            .collect()
    }

    /// K-7 WP6 (ADR-089): destroy the retained originals of every sealed node whose
    /// recovery window has closed — its `archive/<id>/` (the node's envelopes and
    /// its wrapped key) — and forget its seal record. What the node held stays in
    /// `orphan`, sealed to the cold key; only the way back to the *live node* ends.
    /// The id becomes free for a new node.
    ///
    /// A commit protocol like seal and restore: the registry write that drops the
    /// record is the commit point (under the persist lock and the node's own write
    /// lock), and removing the directory comes after it. A crash in between leaves
    /// a vault that opens, with a stray `archive/<id>/` nothing reads; a second
    /// purge run does not remove it (it is no longer anyone's record), so
    /// `archiveRemoved: false` is reported when the removal itself failed.
    pub fn purge_expired_seals(&self, now: i64) -> Result<Vec<PurgedSeal>, OpError> {
        let root = self
            .reauth_root_key("purge expired seals")
            .map_err(|_| OpError::VaultLocked)?;
        let rk = root.expose_secret();
        let mut purged = Vec::new();
        for (id, _) in self.expired_seals(now) {
            let node_lock = self.node_write_lock(&id);
            let _node = node_lock.lock().expect("node write lock poisoned");
            let one_writer = self.lock_persist();
            // Re-read under both locks: a restore may have won the race.
            let Some(record) = self.sealed_doc(&id) else {
                continue;
            };
            if now - record.sealed_at <= RECOVERY_WINDOW_SECONDS {
                continue;
            }
            self.persist_with_root_edit_locked(&one_writer, rk, now, &mut |doc| {
                doc.sealed.remove(&id);
            })
            .map_err(|e| internal(format!("forgetting the seal of {id}: {e}")))?;
            drop(one_writer);
            let dir = self.paths.archive_dir(&id);
            let archive_removed = match std::fs::remove_dir_all(&dir) {
                Ok(()) => true,
                Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            };
            let _ = credmgr_store::audit::append(
                &self.paths,
                rk,
                &credmgr_store::audit::year_month_for(now),
                credmgr_store::audit::NewEvent {
                    actor: "system:maintenance.doctor".to_string(),
                    action: "maintenance.purge_seal".to_string(),
                    node_id: Some(id.clone()),
                    entry_id: None,
                    decision: Some("allow".to_string()),
                    detail: Some("expired seal purged; the entries stay in orphan".to_string()),
                    generation: None,
                },
                now,
            );
            purged.push(PurgedSeal {
                id,
                sealed_at: record.sealed_at,
                archive_removed,
            });
        }
        Ok(purged)
    }

    // --- test seams ---------------------------------------------------------

    /// Arm a fault for the next seal or restore (test seam, ADR-079).
    #[cfg(feature = "test-utils")]
    pub fn set_seal_fault_for_test(&self, fault: Option<SealFault>) {
        *self.seal_fault.lock().expect("seal fault poisoned") = fault;
    }

    /// Park the next seal or restore at `at` — with the persist lock already
    /// held, memory half-changed, nothing committed — until the test sends on the returned
    /// channel's partner. Test seam for the race between a seal/restore and
    /// another client's write-through (C1).
    #[cfg(feature = "test-utils")]
    pub fn set_seal_pause_for_test(
        &self,
        at: SealPause,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel();
        *self.seal_pause.lock().expect("seal pause poisoned") = Some((at, reached_tx, go_rx));
        (reached_rx, go_tx)
    }

    #[cfg(feature = "test-utils")]
    fn seal_pause_point(&self, at: SealPause) {
        let armed = {
            let mut slot = self.seal_pause.lock().expect("seal pause poisoned");
            match slot.take() {
                Some((p, tx, rx)) if p == at => Some((tx, rx)),
                other => {
                    *slot = other;
                    None
                }
            }
        };
        if let Some((reached, go)) = armed {
            let _ = reached.send(());
            let _ = go.recv();
        }
    }

    #[cfg(feature = "test-utils")]
    fn seal_fault_point(&self, at: SealFault) -> Result<(), OpError> {
        let mut armed = self.seal_fault.lock().expect("seal fault poisoned");
        if *armed == Some(at) {
            *armed = None;
            self.crash_injected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Err(internal(format!("injected crash at {at:?} (test seam)")));
        }
        Ok(())
    }

    /// Whether an injected crash has fired: every cleanup and revert a real
    /// crash would never have run is skipped.
    #[cfg(feature = "test-utils")]
    fn was_crash_injected(&self) -> bool {
        self.crash_injected
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(not(feature = "test-utils"))]
    fn was_crash_injected(&self) -> bool {
        false
    }
}
