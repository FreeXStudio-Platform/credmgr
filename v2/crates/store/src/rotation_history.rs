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

/// A rotation snapshot with `entry.sha256` replaced and re-signed under the same root key, **only if it
/// verifies first** (`node.rekey`, ADR-130: the retained ciphertext it describes was re-sealed, so its
/// digest changed). Returns the bytes to write; touches nothing.
pub fn with_sha256(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry_id: &str,
    generation: u64,
    sha256: &str,
) -> Result<Vec<u8>> {
    let path = paths.entry_history_meta(node_id, entry_id, generation);
    let bytes = atomic::read(&path)?;
    let doc: RotationHistoryDoc = serde_json::from_slice(&bytes).map_err(|e| json_err(&path, e))?;
    if sign_body(root_key, &doc.body) != doc.hmac {
        return Err(StoreError::ManifestTampered {
            node_id: node_id.to_string(),
        });
    }
    let mut body = doc.body;
    body.entry.sha256 = sha256.to_string();
    let hmac = sign_body(root_key, &body);
    serde_json::to_vec(&RotationHistoryDoc { body, hmac }).map_err(|e| json_err(&path, e))
}

/// ADR-165 N5: [`with_sha256`] over bytes already in hand rather than the live file — the bytes a root
/// rotation has just re-signed under `root_key` (the NEW root), whose retained ciphertext the same rotation
/// re-seals to the node's new key. Verifies under `root_key` first; `path` only names the file in an error.
/// Touches nothing.
pub fn resign_bytes_with_sha256(
    root_key: &[u8; 32],
    path: &Path,
    node_id: &str,
    bytes: &[u8],
    sha256: &str,
) -> Result<Vec<u8>> {
    let doc: RotationHistoryDoc = serde_json::from_slice(bytes).map_err(|e| json_err(path, e))?;
    if sign_body(root_key, &doc.body) != doc.hmac {
        return Err(StoreError::ManifestTampered {
            node_id: node_id.to_string(),
        });
    }
    let mut body = doc.body;
    body.entry.sha256 = sha256.to_string();
    let hmac = sign_body(root_key, &body);
    serde_json::to_vec(&RotationHistoryDoc { body, hmac }).map_err(|e| json_err(path, e))
}

/// K-10 (e), ADR-156: how many of an entry's most recent retained generations
/// are always kept, whatever their age.
pub const KEEP_LATEST: usize = 20;

/// K-10 (e), ADR-156: drop the retained history of `entry_id` that no undo
/// can still need cheaply — a slot goes only when it is **both** outside the
/// entry's `keep_latest` most recent generations **and** older than
/// `window` seconds (the seven days a field edit can be undone in). A slot
/// whose snapshot is missing or does not verify is kept, so `credmgr verify`
/// still finds it. Returns how many generations were dropped.
pub fn prune(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry_id: &str,
    keep_latest: usize,
    window: i64,
    now: i64,
) -> Result<usize> {
    let dir = paths.entry_history_env(node_id, entry_id, 0);
    let Some(dir) = dir.parent() else {
        return Ok(0);
    };
    let mut generations: Vec<u64> = match std::fs::read_dir(dir) {
        Ok(read) => read
            .flatten()
            .filter_map(|d| {
                let p = d.path();
                matches!(p.extension().and_then(|e| e.to_str()), Some("env" | "json"))
                    .then(|| p.file_stem()?.to_str()?.parse::<u64>().ok())
                    .flatten()
            })
            .collect(),
        Err(_) => return Ok(0),
    };
    generations.sort_unstable();
    generations.dedup();
    let older = generations.len().saturating_sub(keep_latest);
    let mut dropped = 0;
    for &generation in &generations[..older] {
        let Ok((_, recorded_at)) = load_with_time(paths, root_key, node_id, entry_id, generation)
        else {
            continue;
        };
        if now - recorded_at <= window {
            continue;
        }
        for path in [
            paths.entry_history_env(node_id, entry_id, generation),
            paths.entry_history_meta(node_id, entry_id, generation),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(StoreError::Io { path, source: e }),
            }
        }
        dropped += 1;
    }
    Ok(dropped)
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
            aliases: Vec::new(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn prune_keeps_the_latest_and_the_recent_and_drops_only_what_is_both_old_and_beyond_them() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        let id = "e_bbbbbbbbbbbb";
        let day = 24 * 60 * 60;
        let now = 1_800_000_000;
        // Generations 1..=6: 1-4 are ten days old, 5-6 are one day old.
        for g in 1..=6u64 {
            let at = if g <= 4 { now - 10 * day } else { now - day };
            save(&paths, &rk, "a", &sample_entry(), g, at).unwrap();
            atomic::write(&paths.entry_history_env("a", id, g), b"sealed").unwrap();
        }
        // Keep the latest 3 (4, 5, 6); of 1-3 only the ones older than 7 days go.
        let dropped = prune(&paths, &rk, "a", id, 3, 7 * day, now).unwrap();
        assert_eq!(dropped, 3);
        for g in 1..=3u64 {
            assert!(!paths.entry_history_env("a", id, g).exists(), "{g}");
            assert!(!paths.entry_history_meta("a", id, g).exists(), "{g}");
        }
        for g in 4..=6u64 {
            assert!(load(&paths, &rk, "a", id, g).is_ok(), "{g}");
        }
        // Recent slots beyond the keep count stay inside the window.
        assert_eq!(
            prune(&paths, &rk, "a", id, 1, 7 * day, now).unwrap(),
            1,
            "only 4 is old"
        );
        assert!(paths.entry_history_env("a", id, 5).exists());

        // A snapshot that does not verify is never pruned.
        save(&paths, &[9u8; 32], "a", &sample_entry(), 0, now - 30 * day).unwrap();
        assert_eq!(prune(&paths, &rk, "a", id, 0, 7 * day, now).unwrap(), 0);
        assert!(paths.entry_history_meta("a", id, 0).exists());
        // An entry with no history is not an error.
        assert_eq!(prune(&paths, &rk, "a", "e_none", 0, 0, now).unwrap(), 0);
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
