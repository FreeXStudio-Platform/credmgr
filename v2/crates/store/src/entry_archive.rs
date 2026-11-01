//! `entry.remove`'s 7-day soft-delete archive (ADR-048). Distinct from
//! `archive.rs`'s whole-node seal in the way that matters: removing and
//! restoring an entry never leaves its owning node, so no re-encryption is
//! ever needed (unlike `node.seal`, which moves ciphertext to *orphan's*
//! key). This module only ever moves one envelope file and carries its full
//! manifest snapshot, signed, so a restore can put the entry back exactly
//! as it was — same id, same ref, same type — without re-inferring anything.
//!
//! This module owns the storage mechanics only. Deciding what to do about a
//! name a live entry has since reclaimed (`replace` refuses, `keep-both`
//! renames — `ADR-048`, mirroring V1's `changelog.js` undo-delete) is the
//! broker's job, not this crate's: it belongs with the rest of scope
//! resolution and manifest bookkeeping, the same split `archive.rs` already
//! makes between "move the files" and "who is allowed to ask for that".

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::error::{Result, StoreError};
use crate::hexutil;
use crate::manifest::ManifestEntry;
use crate::paths::VaultPaths;

pub const RECOVERY_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

fn removed_entry_label(node_id: &str, entry_id: &str) -> String {
    format!("removed-entry/{node_id}/{entry_id}")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemovedEntryBody {
    node_id: String,
    entry: ManifestEntry,
    /// Unix epoch seconds — ADR-040.
    removed_at: i64,
}

/// The on-disk shape: [`RemovedEntryBody`]'s fields plus the HMAC tag over
/// them, matching `manifest.rs::ManifestDoc`'s flatten-plus-hmac pattern —
/// whole-body signing rather than a signed digest string, so restoring
/// *any* field (not just `removedAt`) is what the tag actually covers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RemovedEntryDoc {
    #[serde(flatten)]
    body: RemovedEntryBody,
    hmac: String,
}

fn json_err(path: &Path, source: serde_json::Error) -> StoreError {
    StoreError::Json {
        path: path.to_path_buf(),
        source,
    }
}

fn io_err(path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn archive_dir_of(paths: &VaultPaths, node_id: &str, entry_id: &str) -> std::path::PathBuf {
    paths
        .removed_entry_env(node_id, entry_id)
        .parent()
        .expect("removed_entry_env always has a parent directory")
        .to_path_buf()
}

/// Sign a [`RemovedEntryBody`] over its full canonical bytes (matching
/// `manifest.rs`'s whole-body-signing convention, not `archive.rs`'s
/// signed-digest-string one) — serialising a value this crate just built
/// from typed fields cannot realistically fail, so this panics rather than
/// threading a `Result` through call sites that could never observe `Err`.
fn sign_body(root_key: &[u8; 32], body: &RemovedEntryBody) -> String {
    let label = removed_entry_label(&body.node_id, &body.entry.id);
    let bytes = serde_json::to_vec(body).expect("RemovedEntryBody is always valid JSON");
    let tag = credmgr_core::signing::sign(root_key, &label, &bytes);
    hexutil::encode(&tag)
}

/// Move `entry`'s envelope out of `nodes/<nodeId>/entries/` into the
/// removed-entry archive and record its full manifest snapshot, signed.
/// The caller (the broker, holding the node's write lock) removes the entry
/// from the *live* manifest in the same transaction — this function only
/// owns the storage mechanics, the identical split `archive::seal` makes.
pub fn remove(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry: &ManifestEntry,
    now: i64,
) -> Result<()> {
    let dst = paths.removed_entry_env(node_id, &entry.id);
    let dir = archive_dir_of(paths, node_id, &entry.id);
    atomic::ensure_dir(&dir)?;

    let src = paths.entry_env(node_id, &entry.id);
    std::fs::rename(src, &dst).map_err(|e| io_err(&dst, e))?;

    let body = RemovedEntryBody {
        node_id: node_id.to_string(),
        entry: entry.clone(),
        removed_at: now,
    };
    let hmac = sign_body(root_key, &body);
    let doc = RemovedEntryDoc { body, hmac };
    let meta_path = paths.removed_entry_meta(node_id, &entry.id);
    let meta_bytes = serde_json::to_vec(&doc).map_err(|e| json_err(&meta_path, e))?;
    atomic::write(&meta_path, &meta_bytes)
}

fn read_meta(paths: &VaultPaths, node_id: &str, entry_id: &str) -> Result<RemovedEntryDoc> {
    let meta_path = paths.removed_entry_meta(node_id, entry_id);
    if !meta_path.exists() {
        return Err(StoreError::EntryArchiveNotFound {
            node_id: node_id.to_string(),
            entry_id: entry_id.to_string(),
        });
    }
    let bytes = atomic::read(&meta_path)?;
    let doc: RemovedEntryDoc =
        serde_json::from_slice(&bytes).map_err(|e| json_err(&meta_path, e))?;
    Ok(doc)
}

fn verify_meta(root_key: &[u8; 32], doc: &RemovedEntryDoc) -> Result<()> {
    let expected = sign_body(root_key, &doc.body);
    if expected != doc.hmac {
        return Err(StoreError::EntryArchiveMetaTampered {
            node_id: doc.body.node_id.clone(),
            entry_id: doc.body.entry.id.clone(),
        });
    }
    Ok(())
}

/// A removed entry's signed record re-signed under `new_root`, **only if it
/// verifies under `old_root` first** (root-key rotation, ADR-076). Returns
/// the bytes to write; touches nothing.
pub fn resigned_meta(
    paths: &VaultPaths,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    node_id: &str,
    entry_id: &str,
) -> Result<Vec<u8>> {
    let doc = read_meta(paths, node_id, entry_id)?;
    verify_meta(old_root, &doc)?;
    let hmac = sign_body(new_root, &doc.body);
    let resigned = RemovedEntryDoc {
        body: doc.body,
        hmac,
    };
    let path = paths.removed_entry_meta(node_id, entry_id);
    serde_json::to_vec(&resigned).map_err(|e| json_err(&path, e))
}

fn read_verified_and_unexpired(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry_id: &str,
    now: i64,
) -> Result<RemovedEntryDoc> {
    let doc = read_meta(paths, node_id, entry_id)?;
    verify_meta(root_key, &doc)?;
    if now - doc.body.removed_at > RECOVERY_WINDOW_SECONDS {
        return Err(StoreError::EntryArchiveExpired {
            node_id: node_id.to_string(),
            entry_id: entry_id.to_string(),
            removed_at: doc.body.removed_at,
        });
    }
    Ok(doc)
}

/// Look up a removed entry's retained snapshot without restoring it — the
/// broker's `entry.restore` uses this to decide name-collision handling
/// (`replace`/`keep-both`) *before* committing to the file move, so a
/// refused restore never touches disk at all. Shares `restore`'s own
/// expiry check (via `now`) so a caller can never see a past-window removal
/// as "restorable" at peek time only to have the later `restore` call
/// disagree — the same failure modes, not two slightly different views of
/// the same archive.
pub fn peek(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry_id: &str,
    now: i64,
) -> Result<ManifestEntry> {
    let doc = read_verified_and_unexpired(paths, root_key, node_id, entry_id, now)?;
    Ok(doc.body.entry)
}

/// Move a removed entry's envelope back into `nodes/<nodeId>/entries/` and
/// return its retained manifest snapshot. Refuses once the 7-day window has
/// passed — unlike a sealed *node*, there is no cold orphan copy behind a
/// removed *entry*; a removal past its window is final (`ADR-048`).
pub fn restore(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry_id: &str,
    now: i64,
) -> Result<ManifestEntry> {
    let doc = read_verified_and_unexpired(paths, root_key, node_id, entry_id, now)?;

    let dst = paths.entry_env(node_id, entry_id);
    let src = paths.removed_entry_env(node_id, entry_id);
    if let Some(parent) = dst.parent() {
        atomic::ensure_dir(parent)?;
    }
    std::fs::rename(src, &dst).map_err(|e| io_err(&dst, e))?;

    let dir = archive_dir_of(paths, node_id, entry_id);
    std::fs::remove_file(paths.removed_entry_meta(node_id, entry_id))
        .map_err(|e| io_err(&dir, e))?;
    let _ = std::fs::remove_dir(&dir); // best-effort; non-empty is a caller bug, not fatal here

    Ok(doc.body.entry)
}

/// Destroy an expired removal for good. Returns `true` if something was
/// purged, `false` if nothing exists or the window hasn't elapsed — a
/// periodic sweep can call this on every removed `(node, entry)` pair
/// without checking expiry itself first, mirroring `archive::purge_if_expired`.
pub fn purge_if_expired(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    entry_id: &str,
    now: i64,
) -> Result<bool> {
    let dir = archive_dir_of(paths, node_id, entry_id);
    if !dir.exists() {
        return Ok(false);
    }
    let doc = match read_meta(paths, node_id, entry_id) {
        Ok(doc) => doc,
        Err(StoreError::EntryArchiveNotFound { .. }) => return Ok(false),
        Err(e) => return Err(e),
    };
    if verify_meta(root_key, &doc).is_err() {
        // A meta that fails its own HMAC is itself a sign something is
        // wrong with this archive; purge it rather than leave it dangling
        // (same call `archive::purge_if_expired` makes for a tampered
        // node-seal meta).
        std::fs::remove_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
        return Ok(true);
    }
    if now - doc.body.removed_at <= RECOVERY_WINDOW_SECONDS {
        return Ok(false);
    }
    std::fs::remove_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Sensitivity;
    use credmgr_core::inference::EntryType;

    const DAY: i64 = 24 * 60 * 60;

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

    fn seed_active_entry(paths: &VaultPaths, node_id: &str, entry_id: &str) {
        atomic::write(&paths.entry_env(node_id, entry_id), b"ciphertext-bytes").unwrap();
    }

    #[test]
    fn remove_moves_the_envelope_out_of_the_live_entries_dir() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        seed_active_entry(&paths, "a", "e_bbbbbbbbbbbb");

        remove(&paths, &rk, "a", &sample_entry(), 1_700_000_000).unwrap();

        assert!(!paths.entry_env("a", "e_bbbbbbbbbbbb").exists());
        assert_eq!(
            atomic::read(&paths.removed_entry_env("a", "e_bbbbbbbbbbbb")).unwrap(),
            b"ciphertext-bytes"
        );
    }

    #[test]
    fn peek_returns_the_snapshot_without_moving_anything() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        seed_active_entry(&paths, "a", "e_bbbbbbbbbbbb");
        remove(&paths, &rk, "a", &sample_entry(), 1_700_000_000).unwrap();

        let snap = peek(&paths, &rk, "a", "e_bbbbbbbbbbbb", 1_700_000_000).unwrap();
        assert_eq!(snap, sample_entry());
        // peek must not restore — the envelope stays archived.
        assert!(paths.removed_entry_env("a", "e_bbbbbbbbbbbb").exists());
        assert!(!paths.entry_env("a", "e_bbbbbbbbbbbb").exists());
    }

    #[test]
    fn day_6_restore_returns_the_exact_snapshot_and_byte_identical_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        seed_active_entry(&paths, "a", "e_bbbbbbbbbbbb");
        let removed_at = 1_700_000_000;
        remove(&paths, &rk, "a", &sample_entry(), removed_at).unwrap();

        let restored = restore(&paths, &rk, "a", "e_bbbbbbbbbbbb", removed_at + 6 * DAY).unwrap();

        assert_eq!(restored, sample_entry());
        assert_eq!(
            atomic::read(&paths.entry_env("a", "e_bbbbbbbbbbbb")).unwrap(),
            b"ciphertext-bytes"
        );
        assert!(!paths.removed_entry_env("a", "e_bbbbbbbbbbbb").exists());
    }

    #[test]
    fn day_8_restore_is_refused_and_purge_destroys_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        seed_active_entry(&paths, "a", "e_bbbbbbbbbbbb");
        let removed_at = 1_700_000_000;
        remove(&paths, &rk, "a", &sample_entry(), removed_at).unwrap();

        let day_8 = removed_at + 8 * DAY;
        let err = restore(&paths, &rk, "a", "e_bbbbbbbbbbbb", day_8).unwrap_err();
        assert!(matches!(err, StoreError::EntryArchiveExpired { .. }));

        let purged = purge_if_expired(&paths, &rk, "a", "e_bbbbbbbbbbbb", day_8).unwrap();
        assert!(purged);
        assert!(!paths.removed_entry_env("a", "e_bbbbbbbbbbbb").exists());

        let err = restore(&paths, &rk, "a", "e_bbbbbbbbbbbb", day_8).unwrap_err();
        assert!(matches!(err, StoreError::EntryArchiveNotFound { .. }));
    }

    #[test]
    fn purge_before_expiry_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        seed_active_entry(&paths, "a", "e_bbbbbbbbbbbb");
        let removed_at = 1_700_000_000;
        remove(&paths, &rk, "a", &sample_entry(), removed_at).unwrap();

        let purged =
            purge_if_expired(&paths, &rk, "a", "e_bbbbbbbbbbbb", removed_at + 6 * DAY).unwrap();
        assert!(!purged);
        assert!(paths.removed_entry_env("a", "e_bbbbbbbbbbbb").exists());
    }

    #[test]
    fn tampered_removed_at_is_refused_even_within_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [4u8; 32];
        seed_active_entry(&paths, "a", "e_bbbbbbbbbbbb");
        remove(&paths, &rk, "a", &sample_entry(), 1_700_000_000).unwrap();

        let meta_path = paths.removed_entry_meta("a", "e_bbbbbbbbbbbb");
        let mut doc: RemovedEntryDoc =
            serde_json::from_slice(&atomic::read(&meta_path).unwrap()).unwrap();
        doc.body.removed_at = 1_900_000_000; // attacker tries to make an expired removal look fresh
        atomic::write(&meta_path, &serde_json::to_vec(&doc).unwrap()).unwrap();

        let err = restore(&paths, &rk, "a", "e_bbbbbbbbbbbb", 1_700_000_000 + 8 * DAY).unwrap_err();
        assert!(matches!(err, StoreError::EntryArchiveMetaTampered { .. }));
    }

    #[test]
    fn no_archive_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let err = restore(&paths, &[4u8; 32], "a", "never-removed", 1_700_000_000).unwrap_err();
        assert!(matches!(err, StoreError::EntryArchiveNotFound { .. }));
    }

    #[test]
    fn wrong_root_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        seed_active_entry(&paths, "a", "e_bbbbbbbbbbbb");
        remove(&paths, &[4u8; 32], "a", &sample_entry(), 1_700_000_000).unwrap();

        let err = restore(&paths, &[9u8; 32], "a", "e_bbbbbbbbbbbb", 1_700_000_000).unwrap_err();
        assert!(matches!(err, StoreError::EntryArchiveMetaTampered { .. }));
    }
}
