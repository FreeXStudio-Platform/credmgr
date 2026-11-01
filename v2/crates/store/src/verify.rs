//! Cross-checking a node's manifest against its envelope files on disk —
//! the V2-shaped analogue of V1's "vault entry has no matching index entry"
//! check (ADR-054, `maintenance.verify`). Named **dangling**, never
//! "orphan": `orphan` already names a sealed-node state elsewhere in this
//! codebase (`03_DATA_MODEL.md §1`), and reusing it for an unrelated
//! integrity condition would collide with that meaning.
//!
//! This module answers one question only: does the manifest's own entry
//! list agree with what's actually in `entries/` on disk? It does not
//! verify the manifest's HMAC (`manifest::load` already does that — a
//! caller must load-and-verify first) and does not decrypt anything —
//! envelope file *names* are `<entry_id>.env`, readable without any key.
//! Its companion [`find_digest_mismatches`] (ADR-067) checks each envelope's
//! *bytes* against the manifest's digest — also without any key.

use std::collections::HashSet;
use std::fs;

use sha2::{Digest, Sha256};

use crate::error::{Result, StoreError};
use crate::manifest::ManifestBody;
use crate::paths::VaultPaths;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DanglingReport {
    /// `entries/*.env` files with no manifest entry pointing at them.
    pub dangling_envelopes: Vec<String>,
    /// Manifest entries with no `entries/<id>.env` file on disk.
    pub missing_envelopes: Vec<String>,
}

impl DanglingReport {
    pub fn is_clean(&self) -> bool {
        self.dangling_envelopes.is_empty() && self.missing_envelopes.is_empty()
    }
}

fn io_err(path: &std::path::Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Compare one node's (already-verified) manifest against its `entries/`
/// directory. A missing `entries/` directory (a brand-new node with zero
/// entries) is not an error — it just means both sides are empty.
pub fn find_dangling(
    paths: &VaultPaths,
    node_id: &str,
    manifest: &ManifestBody,
) -> Result<DanglingReport> {
    let manifest_ids: HashSet<&str> = manifest.entries.iter().map(|e| e.id.as_str()).collect();

    let entries_dir = paths.node_dir(node_id).join("entries");
    let mut on_disk_ids: HashSet<String> = HashSet::new();
    if entries_dir.exists() {
        for entry in fs::read_dir(&entries_dir).map_err(|e| io_err(&entries_dir, e))? {
            let entry = entry.map_err(|e| io_err(&entries_dir, e))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("env") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    on_disk_ids.insert(stem.to_string());
                }
            }
        }
    }

    let mut dangling_envelopes: Vec<String> = on_disk_ids
        .iter()
        .filter(|id| !manifest_ids.contains(id.as_str()))
        .cloned()
        .collect();
    dangling_envelopes.sort();

    let mut missing_envelopes: Vec<String> = manifest_ids
        .iter()
        .filter(|id| !on_disk_ids.contains(**id))
        .map(|s| s.to_string())
        .collect();
    missing_envelopes.sort();

    Ok(DanglingReport {
        dangling_envelopes,
        missing_envelopes,
    })
}

/// ADR-067: a manifest entry's `sha256` is the digest of its sealed
/// envelope — the exact bytes of `entries/<id>.env` — so it can be checked
/// with no key at all. Returns the ids whose file on disk is not the one the
/// (already HMAC-verified) manifest recorded: tampered, corrupted, or left by
/// an update interrupted between its envelope and its manifest. An entry
/// whose file is absent is `find_dangling`'s `missing_envelopes`, not this.
pub fn find_digest_mismatches(
    paths: &VaultPaths,
    node_id: &str,
    manifest: &ManifestBody,
) -> Result<Vec<String>> {
    let mut mismatched = Vec::new();
    for entry in &manifest.entries {
        let path = paths.entry_env(node_id, &entry.id);
        if !path.exists() {
            continue;
        }
        let bytes = crate::atomic::read(&path)?;
        let digest = crate::hexutil::encode(&Sha256::digest(&bytes));
        if digest != entry.sha256 {
            mismatched.push(entry.id.clone());
        }
    }
    mismatched.sort();
    Ok(mismatched)
}

/// ADR-072: the node's note file against the digest its (HMAC-verified)
/// manifest records — key-free, like [`find_digest_mismatches`]. `None` when
/// they agree (including "no note, none recorded"); otherwise what is wrong.
pub fn find_note_mismatch(
    paths: &VaultPaths,
    node_id: &str,
    manifest: &ManifestBody,
) -> Result<Option<&'static str>> {
    let path = paths.notes_env(node_id);
    let on_disk = if path.exists() {
        Some(crate::hexutil::encode(&Sha256::digest(
            crate::atomic::read(&path)?,
        )))
    } else {
        None
    };
    Ok(match (&manifest.notes_sha256, on_disk) {
        (None, None) => None,
        (Some(_), None) => Some("the manifest records a note but its file is missing"),
        (None, Some(_)) => Some("a note file exists that the manifest does not record"),
        (Some(want), Some(got)) if *want != got => {
            Some("the note file does not match the digest its manifest records")
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomic;
    use credmgr_core::inference::EntryType;

    fn entry(id: &str) -> crate::manifest::ManifestEntry {
        crate::manifest::ManifestEntry {
            id: id.to_string(),
            name: id.to_string(),
            r#ref: 1,
            entry_type: EntryType::Login,
            sensitivity: crate::manifest::Sensitivity::Low,
            field_count: 1,
            sha256: "deadbeef".to_string(),
            modified: 0,
            expires_at: None,
            rotated_at: None,
            has_totp: false,
        }
    }

    #[test]
    fn agreeing_manifest_and_files_report_clean() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        atomic::write(&paths.entry_env("a", "e_1"), b"envelope").unwrap();

        let mut body = ManifestBody::new("a");
        body.entries.push(entry("e_1"));

        let report = find_dangling(&paths, "a", &body).unwrap();
        assert!(report.is_clean());
    }

    #[test]
    fn envelope_with_no_manifest_entry_is_dangling() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        atomic::write(&paths.entry_env("a", "e_orphaned"), b"envelope").unwrap();

        let body = ManifestBody::new("a"); // no entries recorded

        let report = find_dangling(&paths, "a", &body).unwrap();
        assert_eq!(report.dangling_envelopes, vec!["e_orphaned".to_string()]);
        assert!(report.missing_envelopes.is_empty());
        assert!(!report.is_clean());
    }

    #[test]
    fn manifest_entry_with_no_envelope_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        // No file written for e_2 at all.
        let mut body = ManifestBody::new("a");
        body.entries.push(entry("e_2"));

        let report = find_dangling(&paths, "a", &body).unwrap();
        assert_eq!(report.missing_envelopes, vec!["e_2".to_string()]);
        assert!(report.dangling_envelopes.is_empty());
    }

    #[test]
    fn an_envelope_that_is_not_the_one_its_manifest_recorded_is_a_digest_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        atomic::write(&paths.entry_env("a", "e_ok"), b"envelope-one").unwrap();
        atomic::write(&paths.entry_env("a", "e_bad"), b"swapped").unwrap();
        let mut body = ManifestBody::new("a");
        let mut ok = entry("e_ok");
        ok.sha256 = crate::hexutil::encode(&Sha256::digest(b"envelope-one"));
        let mut bad = entry("e_bad");
        bad.sha256 = crate::hexutil::encode(&Sha256::digest(b"the original"));
        body.entries.push(ok);
        body.entries.push(bad);
        body.entries.push(entry("e_absent")); // missing, not mismatched

        assert_eq!(
            find_digest_mismatches(&paths, "a", &body).unwrap(),
            vec!["e_bad".to_string()]
        );
    }

    #[test]
    fn a_note_is_checked_against_its_manifest_digest_without_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let mut body = ManifestBody::new("a");
        assert_eq!(find_note_mismatch(&paths, "a", &body).unwrap(), None);
        atomic::write(&paths.notes_env("a"), b"sealed-note").unwrap();
        assert!(
            find_note_mismatch(&paths, "a", &body).unwrap().is_some(),
            "unrecorded file"
        );
        body.notes_sha256 = Some(crate::hexutil::encode(&Sha256::digest(b"sealed-note")));
        assert_eq!(find_note_mismatch(&paths, "a", &body).unwrap(), None);
        atomic::write(&paths.notes_env("a"), b"an older note").unwrap();
        assert!(
            find_note_mismatch(&paths, "a", &body).unwrap().is_some(),
            "swapped file"
        );
        std::fs::remove_file(paths.notes_env("a")).unwrap();
        assert!(
            find_note_mismatch(&paths, "a", &body).unwrap().is_some(),
            "missing file"
        );
    }

    #[test]
    fn empty_node_with_no_entries_directory_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let body = ManifestBody::new("fresh-node");
        let report = find_dangling(&paths, "fresh-node", &body).unwrap();
        assert!(report.is_clean());
    }

    #[test]
    fn non_env_files_in_the_entries_directory_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let entries_dir = paths.node_dir("a").join("entries");
        atomic::write(&entries_dir.join("stray.txt"), b"not an envelope").unwrap();

        let body = ManifestBody::new("a");
        let report = find_dangling(&paths, "a", &body).unwrap();
        assert!(report.is_clean());
    }
}
