//! ADR-069 — the locked-write tray survives a restart.
//!
//! An `entry.create` against a locked node seals the value to the node's
//! public key and leaves it in `nodes/<id>/pending/<entry>.env` for a human
//! to accept or discard (F-1, ADR-023). The envelope was always on disk; what
//! it *was* — its name, type, sensitivity, when it arrived — lived only in
//! this process, so a restart kept the ciphertext and forgot the tray (K-7).
//!
//! That metadata now sits beside the envelope as `<entry>.meta.json`. It is
//! deliberately **not** under the registry's HMAC: a locked write happens with
//! no root key resident, so nothing could sign it, and it does not need to be
//! signed — the tray is untrusted input by design (anyone the node's
//! `agentAccess` admits may deposit into it, and nothing leaves it except by a
//! human's `vault.pending_accept`). So the loader treats every tray file as
//! untrusted: the digest is recomputed from the envelope bytes rather than
//! read, the entry id must be one this broker could have minted, and a
//! malformed or orphaned file is **skipped and left on disk**, never allowed
//! to fail an unlock — otherwise dropping one bad file into `pending/` would
//! lock the owner out of their own vault.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use credmgr_core::inference::EntryType;
use credmgr_store::atomic;
use credmgr_store::error::StoreError;
use credmgr_store::manifest::{ManifestBody, Sensitivity};

use super::{BrokerState, PendingEntry};

/// The sidecar's shape. `v` lets a later format refuse to be misread by this
/// one; `deny_unknown_fields` keeps a hand-edited file from smuggling fields
/// this version would silently drop.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingMeta {
    v: u32,
    name: String,
    #[serde(rename = "type")]
    entry_type: EntryType,
    sensitivity: Sensitivity,
    field_count: u32,
    created: i64,
}

const PENDING_META_VERSION: u32 = 1;

/// `e_` plus twelve lowercase hex digits — exactly what `ops::new_entry_id`
/// mints. A tray file named anything else was not written by this broker.
fn is_entry_id(s: &str) -> bool {
    s.len() == 14
        && s.starts_with("e_")
        && s[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

impl BrokerState {
    /// Record a pending entry's metadata beside its envelope. Called after
    /// the envelope itself is written, so a sidecar never names a value that
    /// is not there.
    pub fn write_pending_meta(
        &self,
        node_id: &str,
        entry: &PendingEntry,
    ) -> Result<(), StoreError> {
        let meta = PendingMeta {
            v: PENDING_META_VERSION,
            name: entry.name.clone(),
            entry_type: entry.entry_type,
            sensitivity: entry.sensitivity,
            field_count: entry.field_count,
            created: entry.created,
        };
        let bytes = serde_json::to_vec(&meta).expect("PendingMeta always serialises");
        atomic::write(&self.paths.pending_meta(node_id, &entry.id), &bytes)
    }

    /// Remove a pending entry's envelope and sidecar — accept (after the
    /// envelope has been copied into `entries/`) and discard both end here.
    pub fn remove_pending_files(&self, node_id: &str, entry_id: &str) {
        let _ = std::fs::remove_file(self.paths.pending_env(node_id, entry_id));
        let _ = std::fs::remove_file(self.paths.pending_meta(node_id, entry_id));
    }

    /// Rebuild the tray for `nodes` from disk. Everything here is untrusted
    /// (module docs): a file that does not check out is skipped, and the
    /// caller never fails an unlock on account of the tray.
    pub(super) fn scan_pending_tray(
        &self,
        manifests: &HashMap<String, ManifestBody>,
    ) -> HashMap<String, Vec<PendingEntry>> {
        let mut tray: HashMap<String, Vec<PendingEntry>> = HashMap::new();
        for (node_id, manifest) in manifests {
            let dir = self.paths.node_dir(node_id).join("pending");
            let Ok(read_dir) = std::fs::read_dir(&dir) else {
                continue;
            };
            for dirent in read_dir.flatten() {
                let path = dirent.path();
                if path.extension().and_then(|e| e.to_str()) != Some("env") {
                    continue;
                }
                let Some(entry_id) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                if !is_entry_id(entry_id) || manifest.entries.iter().any(|e| e.id == entry_id) {
                    continue;
                }
                let Some(entry) = self.read_pending(node_id, entry_id) else {
                    continue;
                };
                tray.entry(node_id.clone()).or_default().push(entry);
            }
        }
        for list in tray.values_mut() {
            list.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
        }
        tray
    }

    fn read_pending(&self, node_id: &str, entry_id: &str) -> Option<PendingEntry> {
        // `atomic::read` refuses symlinks and anything but a regular file
        // (review H1), so a planted link cannot point the tray elsewhere.
        let envelope = atomic::read(&self.paths.pending_env(node_id, entry_id)).ok()?;
        let meta_bytes = atomic::read(&self.paths.pending_meta(node_id, entry_id)).ok()?;
        let meta: PendingMeta = serde_json::from_slice(&meta_bytes).ok()?;
        if meta.v != PENDING_META_VERSION || meta.name.is_empty() {
            return None;
        }
        Some(PendingEntry {
            id: entry_id.to_string(),
            name: meta.name,
            entry_type: meta.entry_type,
            sensitivity: meta.sensitivity,
            field_count: meta.field_count,
            // ADR-067: the digest of the sealed envelope, recomputed — never
            // taken from the untrusted sidecar.
            sha256: sha256_hex(&envelope),
            created: meta.created,
        })
    }

    /// Merge a scanned tray into the running one, skipping ids already held
    /// (a process only loads from disk once, so this is belt and braces).
    pub(super) fn merge_pending_tray(&self, scanned: HashMap<String, Vec<PendingEntry>>) {
        let mut pending = self.pending.write().expect("pending poisoned");
        for (node_id, entries) in scanned {
            let list = pending.entry(node_id).or_default();
            for entry in entries {
                if !list.iter().any(|p| p.id == entry.id) {
                    list.push(entry);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_entry_id;

    #[test]
    fn only_ids_this_broker_could_mint_are_accepted() {
        assert!(is_entry_id("e_0123456789ab"));
        assert!(!is_entry_id("e_0123456789AB"));
        assert!(!is_entry_id("e_0123456789a"));
        assert!(!is_entry_id("x_0123456789ab"));
        assert!(!is_entry_id("e_0123456789ag"));
        assert!(!is_entry_id("../e_012345678"));
    }
}
