//! ADR-131 — Destroy orphans: permanently delete sealed entries and the material archived behind them.
//!
//! A sealed node leaves two things behind: its entries, re-encrypted to the orphan node's cold key and
//! listed as the orphan node's manifest rows (`nodes/orphan/entries/<id>.env`), and — for the seven-day
//! recovery window and until a purge — the retained originals (`archive/<id>/`, plus the removed-entry
//! and history archives that belonged to that node) and a seal record in the registry. This module ends
//! both, on purpose, for good.
//!
//! # As a commit protocol (the registry write is the commit point)
//!
//! | step | what | status |
//! |---|---|---|
//! | D0 | authorise (the caller); choose the entries; check the caller's count; write the vault through | — |
//! | D1 | write the **journal** (`orphan-destroy.pending`, sealed under the root key): which envelopes and which archive directories are to go | pre-commit; inert until the commit shows |
//! | D2 | memory (persist lock held): the orphan manifest loses the rows, one generation bump | memory |
//! | D3 | **commit**: the write-through, with the forgotten seal records dropped from the registry — inside the op | **commit** |
//! | D4 | delete the envelopes (zero-overwritten first), the archive directories, then the journal | post-commit, idempotent |
//!
//! The journal is what makes the *deletion* survive a crash that follows the commit; the registry and the
//! orphan manifest are what say the journal applies. On every load the journal is read and each item is
//! removed **only if the signed state no longer names it** (no orphan row for the entry; no seal record
//! for the archive). A journal left by a crash before the commit therefore deletes nothing and is dropped.
//!
//! # What "permanently" means here
//!
//! The files are overwritten with zeros, synced and unlinked. On a copy-on-write or journalled file
//! system that does not reach every old block; and a backup, a Time Machine snapshot or a copy of the
//! vault directory made earlier still holds the ciphertext. What this does guarantee: the vault no longer
//! lists, opens or can restore them, and the orphan cold key is the only key that could ever have opened
//! the copies. `docs/05_THREAT_MODEL.md` says the same in plainer words.

use std::collections::HashSet;

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use credmgr_core::keys::{open_under_root, seal_under_root};
use credmgr_core::registry::{is_path_safe_node_id, ORPHAN_ID};
use credmgr_store::atomic;
use credmgr_store::error::StoreError;
use credmgr_store::manifest::ManifestBody;

use super::BrokerState;
use crate::protocol::OpError;

const JOURNAL_VERSION: u32 = 1;
const JOURNAL_LABEL: &str = "credmgr/v2/orphan-destroy-journal";

/// A step of a destroy at which the test suite can make the process "die" (ADR-131's crash table).
/// Compiled only with `test-utils`.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyFault {
    /// After D1: the journal is on disk, nothing is committed.
    AfterJournal,
    /// After D3: committed, nothing deleted.
    AfterCommit,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Journal {
    v: u32,
    /// Orphan entry ids whose envelope files are to go.
    entries: Vec<String>,
    /// Sealed node ids whose archive directories are to go.
    archives: Vec<String>,
}

/// What a destroy did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestroyOutcome {
    /// Sealed entries removed from the orphan node.
    pub entries: usize,
    /// Seal records forgotten (their restore window ends with them).
    pub seals_forgotten: usize,
    /// Archive directories removed (the retained originals).
    pub archives_removed: usize,
}

fn internal(what: impl std::fmt::Display) -> OpError {
    OpError::Internal(what.to_string())
}

/// Overwrite with zeros, sync, unlink. Best effort on the overwrite, strict on the unlink.
fn shred(path: &std::path::Path) -> Result<(), StoreError> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.is_file() {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                use std::io::Write;
                let zeros = [0u8; 8192];
                let mut left = meta.len();
                while left > 0 {
                    let n = left.min(zeros.len() as u64) as usize;
                    if f.write_all(&zeros[..n]).is_err() {
                        break;
                    }
                    left -= n as u64;
                }
                let _ = f.sync_all();
            }
        }
    }
    atomic::remove_durable(path)
}

impl BrokerState {
    /// Destroy `wanted` orphan entries (all of them when `None`) and what was archived behind them, on a
    /// disk-backed vault. See the module docs. The caller has authorised the request (owner, `Admin`,
    /// presence, a fresh second factor, the explicit confirmation) and has checked nothing about *which*
    /// entries: that is decided here, under the lock, and `expected` is compared to it.
    pub fn destroy_orphans_durable(
        &self,
        wanted: Option<&[String]>,
        expected: usize,
        now: i64,
    ) -> Result<DestroyOutcome, OpError> {
        let root = self
            .reauth_root_key("destroy orphans")
            .map_err(|_| OpError::VaultLocked)?;
        let rk = root.expose_secret();

        // --- D0 ----------------------------------------------------------------------
        let orphan_lock = self.node_write_lock(ORPHAN_ID);
        let _orphan = orphan_lock.lock().expect("node write lock poisoned");
        let rows: Vec<String> = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(ORPHAN_ID)
            .map(|m| m.entries.iter().map(|e| e.id.clone()).collect())
            .unwrap_or_default();
        let targets: Vec<String> = match wanted {
            None => rows.clone(),
            Some(ids) => {
                let have: HashSet<&str> = rows.iter().map(String::as_str).collect();
                let mut seen = HashSet::new();
                let mut out = Vec::new();
                for id in ids {
                    if !have.contains(id.as_str()) {
                        return Err(OpError::NotFound(format!("no sealed entry {id}")));
                    }
                    if seen.insert(id.as_str()) {
                        out.push(id.clone());
                    }
                }
                out
            }
        };
        if targets.len() != expected {
            return Err(OpError::Malformed(format!(
                "params.count is {expected}, but {} sealed entr{} would be destroyed — nothing was destroyed",
                targets.len(),
                if targets.len() == 1 { "y" } else { "ies" }
            )));
        }
        let target_set: HashSet<&str> = targets.iter().map(String::as_str).collect();
        // The seal records that go: all of them for "everything"; otherwise those whose deposit is touched
        // (a seal missing some of its entries cannot be restored faithfully, so its record ends too).
        let forgotten: Vec<String> = {
            let meta = self.registry_meta.read().expect("registry meta poisoned");
            let mut ids: Vec<String> = meta
                .sealed
                .iter()
                .filter(|(_, r)| {
                    wanted.is_none()
                        || r.orphan_entry_ids
                            .iter()
                            .any(|e| target_set.contains(e.as_str()))
                })
                .map(|(id, _)| id.clone())
                .collect();
            ids.sort();
            ids
        };
        if let Some(bad) = forgotten.iter().find(|id| !is_path_safe_node_id(id)) {
            return Err(internal(format!(
                "a seal record names an unsafe id ({bad}) — nothing was destroyed"
            )));
        }
        if targets.is_empty() && forgotten.is_empty() {
            return Ok(DestroyOutcome {
                entries: 0,
                seals_forgotten: 0,
                archives_removed: 0,
            });
        }
        self.persist_with_root(rk, now)
            .map_err(|e| internal(format!("saving the vault before destroying: {e}")))?;

        // --- D1: the journal ---------------------------------------------------------
        let journal = Journal {
            v: JOURNAL_VERSION,
            entries: targets.clone(),
            archives: forgotten.clone(),
        };
        let json = serde_json::to_vec(&journal).expect("a journal always serialises");
        atomic::write(
            &self.paths.orphan_destroy_journal(),
            &seal_under_root(rk, JOURNAL_LABEL, &json),
        )
        .map_err(|e| internal(format!("writing the destroy journal: {e}")))?;
        #[cfg(feature = "test-utils")]
        self.destroy_fault_point(DestroyFault::AfterJournal)?;

        // --- D2: memory --------------------------------------------------------------
        let one_writer = self.lock_persist();
        let before: Option<ManifestBody> = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(ORPHAN_ID)
            .cloned();
        {
            let mut manifests = self.manifests.write().expect("manifests poisoned");
            if let Some(body) = manifests.get_mut(ORPHAN_ID) {
                body.entries.retain(|e| !target_set.contains(e.id.as_str()));
                body.recount();
                body.generation += 1;
            }
        }

        // --- D3: the commit -------------------------------------------------------------
        let committed = self.persist_with_root_edit_locked(&one_writer, rk, now, &mut |doc| {
            for id in &forgotten {
                doc.sealed.remove(id);
            }
        });
        if let Err(e) = committed {
            if self.was_crash_injected() {
                return Err(internal(format!("injected crash: {e}")));
            }
            let landed = credmgr_store::registry_file::load(&self.paths, rk)
                .ok()
                .map(|d| forgotten.iter().all(|id| !d.sealed.contains_key(id)))
                == Some(true);
            if landed {
                let _ = self.refresh_registry_meta(rk);
            } else {
                if let Some(body) = before {
                    self.set_manifest(ORPHAN_ID, body);
                }
                let _ = atomic::remove_durable(&self.paths.orphan_destroy_journal());
                return Err(internal(format!(
                    "destroying the sealed entries failed and was rolled back: {e}"
                )));
            }
        }
        drop(one_writer);
        #[cfg(feature = "test-utils")]
        self.destroy_fault_point(DestroyFault::AfterCommit)?;

        // --- D4: delete ----------------------------------------------------------------
        let archives_removed = self.apply_destroy_journal(&journal);
        Ok(DestroyOutcome {
            entries: targets.len(),
            seals_forgotten: forgotten.len(),
            archives_removed,
        })
    }

    /// Delete what `journal` lists — **only what the signed state no longer names** — and then the journal.
    /// Returns how many archive directories were removed. Idempotent.
    fn apply_destroy_journal(&self, journal: &Journal) -> usize {
        let still_rows: HashSet<String> = self
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(ORPHAN_ID)
            .map(|m| m.entries.iter().map(|e| e.id.clone()).collect())
            .unwrap_or_default();
        let still_sealed: HashSet<String> = self.sealed_ids().into_iter().collect();
        for id in &journal.entries {
            if still_rows.contains(id) || id.is_empty() || id.contains(['/', '\\', '.']) {
                continue;
            }
            let _ = shred(&self.paths.entry_env(ORPHAN_ID, id));
        }
        let mut removed = 0usize;
        for id in &journal.archives {
            if still_sealed.contains(id) || !is_path_safe_node_id(id) {
                continue;
            }
            // `archive/<id>` goes LAST: `node.create` refuses an id while that directory exists
            // (ADR-079 F-d), so it is the guard that keeps a new node of this id from putting
            // files into the sibling archives while they are being deleted (ADR-148 P3).
            let dirs = [
                self.paths.archive_root().join("removed-entries").join(id),
                self.paths.archive_root().join("entry-history").join(id),
                self.paths.archive_dir(id),
            ];
            for (i, dir) in dirs.iter().enumerate() {
                let is_archive = i == 2;
                if dir.exists() {
                    shred_tree(dir);
                    if std::fs::remove_dir_all(dir).is_ok() && is_archive {
                        removed += 1;
                    }
                } else if is_archive {
                    removed += 1; // already gone: the archive is, as asked, not there.
                }
            }
        }
        let _ = atomic::remove_durable(&self.paths.orphan_destroy_journal());
        removed
    }

    /// Load-time: finish a destroy the process did not live to finish. Best effort; never fails an
    /// unlock. The journal is read under the root key and applied only where the signed state agrees.
    pub(super) fn finish_interrupted_destroy(&self, root_key: &[u8; 32]) {
        let path = self.paths.orphan_destroy_journal();
        if !atomic::exists(&path) {
            return;
        }
        let parsed = atomic::read(&path)
            .ok()
            .and_then(|sealed| open_under_root(root_key, JOURNAL_LABEL, &sealed).ok())
            .and_then(|bytes| serde_json::from_slice::<Journal>(&bytes).ok())
            .filter(|j| j.v == JOURNAL_VERSION);
        match parsed {
            Some(journal) => {
                self.apply_destroy_journal(&journal);
            }
            // A journal that does not authenticate is not acted on; it is just removed.
            None => {
                let _ = atomic::remove_durable(&path);
            }
        }
    }

    // --- test seams -----------------------------------------------------------------------

    /// Arm a fault for the next destroy (test seam, ADR-131).
    #[cfg(feature = "test-utils")]
    pub fn set_destroy_fault_for_test(&self, fault: Option<DestroyFault>) {
        *self
            .stable
            .destroy_fault
            .lock()
            .expect("destroy fault poisoned") = fault;
    }

    #[cfg(feature = "test-utils")]
    fn destroy_fault_point(&self, at: DestroyFault) -> Result<(), OpError> {
        let mut armed = self
            .stable
            .destroy_fault
            .lock()
            .expect("destroy fault poisoned");
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

/// Zero every regular file under `dir` (best effort), before the tree is unlinked.
fn shred_tree(dir: &std::path::Path) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => shred_tree(&path),
            Ok(t) if t.is_file() => {
                let _ = shred(&path);
            }
            _ => {}
        }
    }
}
