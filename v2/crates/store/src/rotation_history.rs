//! `entry.rotate`'s retained pre-rotate snapshot, signed (ADR-055) — the
//! metadata half of what `entry.undo` needs to restore a rotate correctly.
//! Sibling to `entry_history_env`'s existing raw ciphertext file, mirroring
//! `entry_archive.rs`'s own split of a removed entry's envelope (unsigned,
//! moved file) from its manifest snapshot (signed, JSON) — the same reason
//! applies here: the ciphertext's own AEAD tag already makes tampering with
//! *its* contents detectable, but nothing protected the claim "this is what
//! `sha256`/`entryType`/`sensitivity` were before the rotate" until now,
//! because nothing needed to restore from it before `entry.undo` existed.
//!
//! No expiry window, unlike the 7-day removal archive (`entry_archive.rs`):
//! nothing purges rotation history today, and inventing a retention policy
//! for it was not asked for and does not block `entry.undo`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::error::{Result, StoreError};
use crate::hexutil;
use crate::manifest::ManifestEntry;
use crate::paths::VaultPaths;

fn rotation_history_label(node_id: &str, entry_id: &str) -> String {
    format!("rotation-history/{node_id}/{entry_id}")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotationHistoryBody {
    node_id: String,
    /// The entry's fields **before** this rotation — content-derived fields
    /// (`sha256`/`entryType`/`sensitivity`) describe the ciphertext retained
    /// alongside this record at the same generation, not the entry's
    /// current (post-rotate) state.
    entry: ManifestEntry,
    /// The manifest generation this snapshot is *from* — the pre-rotate
    /// generation, matching `entry_history_env`'s own keying.
    generation: u64,
    /// Unix epoch seconds — ADR-040.
    recorded_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RotationHistoryDoc {
    #[serde(flatten)]
    body: RotationHistoryBody,
    hmac: String,
}

fn json_err(path: &Path, source: serde_json::Error) -> StoreError {
    StoreError::Json {
        path: path.to_path_buf(),
        source,
    }
}

fn sign_body(root_key: &[u8; 32], body: &RotationHistoryBody) -> String {
    let label = rotation_history_label(&body.node_id, &body.entry.id);
    let bytes = serde_json::to_vec(body).expect("RotationHistoryBody is always valid JSON");
    let tag = credmgr_core::signing::sign(root_key, &label, &bytes);
    hexutil::encode(&tag)
}

/// Record what `entry`'s fields were **before** a rotate that will land at
/// `generation + 1` — call this with the manifest entry as it stood
/// immediately before the mutation, keyed by that pre-rotate generation
/// (the same generation `entry_history_env`'s raw-ciphertext write already
/// uses, so the two files for one rotation always share a key).
pub fn save(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry: &ManifestEntry,
    generation: u64,
    now: i64,
) -> Result<()> {
    let body = RotationHistoryBody {
        node_id: node_id.to_string(),
        entry: entry.clone(),
        generation,
        recorded_at: now,
    };
    let hmac = sign_body(root_key, &body);
    let doc = RotationHistoryDoc { body, hmac };
    let path = paths.entry_history_meta(node_id, &entry.id, generation);
    let bytes = serde_json::to_vec(&doc).map_err(|e| json_err(&path, e))?;
    atomic::write(&path, &bytes)
}

/// Load and verify a rotation snapshot — the pre-rotate `ManifestEntry` as
/// it stood at `generation`. `StoreError::Io` (not found) if this rotation
/// was never recorded (e.g. `generation` names a write that was never a
/// rotate, or is out of range).
pub fn load(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry_id: &str,
    generation: u64,
) -> Result<ManifestEntry> {
    let path = paths.entry_history_meta(node_id, entry_id, generation);
    let bytes = atomic::read(&path)?;
    let doc: RotationHistoryDoc = serde_json::from_slice(&bytes).map_err(|e| json_err(&path, e))?;

    let expected = sign_body(root_key, &doc.body);
    if expected != doc.hmac {
        return Err(StoreError::ManifestTampered {
            node_id: node_id.to_string(),
        });
    }
    Ok(doc.body.entry)
}

/// [`load`], and when the snapshot was recorded (unix seconds) — the age
/// `entry.undo` measures a field edit's seven-day window from (ADR-086).
pub fn load_with_time(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry_id: &str,
    generation: u64,
) -> Result<(ManifestEntry, i64)> {
    let path = paths.entry_history_meta(node_id, entry_id, generation);
    let bytes = atomic::read(&path)?;
    let doc: RotationHistoryDoc = serde_json::from_slice(&bytes).map_err(|e| json_err(&path, e))?;
    if sign_body(root_key, &doc.body) != doc.hmac {
        return Err(StoreError::ManifestTampered {
            node_id: node_id.to_string(),
        });
    }
    Ok((doc.body.entry, doc.body.recorded_at))
}

/// A rotation snapshot re-signed under `new_root`, **only if it verifies
/// under `old_root` first** (root-key rotation, ADR-076). Returns the bytes
/// to write; touches nothing.
pub fn resigned(
    paths: &VaultPaths,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    node_id: &str,
    entry_id: &str,
    generation: u64,
) -> Result<Vec<u8>> {
    let path = paths.entry_history_meta(node_id, entry_id, generation);
    let bytes = atomic::read(&path)?;
    let doc: RotationHistoryDoc = serde_json::from_slice(&bytes).map_err(|e| json_err(&path, e))?;
    if sign_body(old_root, &doc.body) != doc.hmac {
        return Err(StoreError::ManifestTampered {
            node_id: node_id.to_string(),
        });
    }
    let hmac = sign_body(new_root, &doc.body);
    let resigned = RotationHistoryDoc {
        body: doc.body,
        hmac,
    };
    serde_json::to_vec(&resigned).map_err(|e| json_err(&path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Sensitivity;
    use credmgr_core::inference::EntryType;

    fn sample_entry() -> ManifestEntry {
        ManifestEntry {
            id: "e_bbbbbbbbbbbb".to_string(),
            name: "vps-root".to_string(),
            r#ref: 3060,
            entry_type: EntryType::Server,
            sensitivity: Sensitivity::Critical,
            field_count: 1,
            sha256: "deadbeef".to_string(),
            modified: 1_700_000_000,
            expires_at: None,
            rotated_at: None,
            has_totp: false,
        }
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        save(&paths, &rk, "a", &sample_entry(), 5, 1_700_000_000).unwrap();

        let loaded = load(&paths, &rk, "a", "e_bbbbbbbbbbbb", 5).unwrap();
        assert_eq!(loaded, sample_entry());
    }

    #[test]
    fn wrong_root_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        save(&paths, &[4u8; 32], "a", &sample_entry(), 5, 1_700_000_000).unwrap();

        let err = load(&paths, &[9u8; 32], "a", "e_bbbbbbbbbbbb", 5).unwrap_err();
        assert!(matches!(err, StoreError::ManifestTampered { .. }));
    }

    #[test]
    fn tampered_body_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        save(&paths, &rk, "a", &sample_entry(), 5, 1_700_000_000).unwrap();

        let path = paths.entry_history_meta("a", "e_bbbbbbbbbbbb", 5);
        let mut doc: RotationHistoryDoc =
            serde_json::from_slice(&atomic::read(&path).unwrap()).unwrap();
        doc.body.entry.sha256 = "attacker-controlled".to_string();
        atomic::write(&path, &serde_json::to_vec(&doc).unwrap()).unwrap();

        let err = load(&paths, &rk, "a", "e_bbbbbbbbbbbb", 5).unwrap_err();
        assert!(matches!(err, StoreError::ManifestTampered { .. }));
    }

    #[test]
    fn a_generation_never_recorded_is_a_named_io_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let err = load(&paths, &[4u8; 32], "a", "never-rotated", 1).unwrap_err();
        assert!(matches!(err, StoreError::Io { .. }));
    }

    #[test]
    fn distinct_generations_of_the_same_entry_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        let mut v1 = sample_entry();
        v1.sha256 = "v1-hash".to_string();
        let mut v2 = sample_entry();
        v2.sha256 = "v2-hash".to_string();

        save(&paths, &rk, "a", &v1, 3, 1_700_000_000).unwrap();
        save(&paths, &rk, "a", &v2, 5, 1_700_000_100).unwrap();

        assert_eq!(
            load(&paths, &rk, "a", "e_bbbbbbbbbbbb", 3).unwrap().sha256,
            "v1-hash"
        );
        assert_eq!(
            load(&paths, &rk, "a", "e_bbbbbbbbbbbb", 5).unwrap().sha256,
            "v2-hash"
        );
    }
}
