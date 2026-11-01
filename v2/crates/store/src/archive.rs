//! The 7-day seal archive. See `docs/02_ARCHITECTURE.md §7`,
//! `docs/04_CRYPTO_AND_KEYS.md §6`, ADR-027.
//!
//! Sealing a node retains its originals **and** its node key in
//! `archive/<nodeId>/` for 7 days, so "Restore node" is a move, not 12
//! biometric prompts. At day 7 both are destroyed and the node's entries
//! are reachable only through the orphan cold copy, one at a time, with
//! presence and a fresh code.
//!
//! This module owns the storage mechanics — the move, the retention
//! window, the destruction — not the authorization (unlock + 2FA +
//! presence, `04 §6`'s key-lifecycle table) or the orphan re-encryption,
//! both of which need the broker's key material and belong to Phase 3.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::error::{Result, StoreError};
use crate::hexutil;
use crate::paths::VaultPaths;

pub const RECOVERY_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

fn meta_label(node_id: &str) -> String {
    format!("archive-meta/{node_id}")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SealedMeta {
    node_id: String,
    /// Unix epoch seconds — ADR-040.
    sealed_at: i64,
    hmac: String,
}

fn meta_path(archive_dir: &Path) -> std::path::PathBuf {
    archive_dir.join("meta.json")
}

fn json_err(path: &Path, source: serde_json::Error) -> StoreError {
    StoreError::Json {
        path: path.to_path_buf(),
        source,
    }
}

fn write_meta(
    archive_dir: &Path,
    root_key: &[u8; 32],
    node_id: &str,
    sealed_at: i64,
) -> Result<()> {
    let signed = format!("{node_id}|{sealed_at}");
    let tag = credmgr_core::signing::sign(root_key, &meta_label(node_id), signed.as_bytes());
    let meta = SealedMeta {
        node_id: node_id.to_string(),
        sealed_at,
        hmac: hexutil::encode(&tag),
    };
    let path = meta_path(archive_dir);
    let bytes = serde_json::to_vec(&meta).map_err(|e| json_err(&path, e))?;
    atomic::write(&path, &bytes)
}

fn read_meta(archive_dir: &Path, root_key: &[u8; 32], node_id: &str) -> Result<SealedMeta> {
    let path = meta_path(archive_dir);
    if !path.exists() {
        return Err(StoreError::ArchiveNotFound {
            node_id: node_id.to_string(),
        });
    }
    let bytes = atomic::read(&path)?;
    let meta: SealedMeta = serde_json::from_slice(&bytes).map_err(|e| json_err(&path, e))?;
    let tag = hexutil::decode_32(&meta.hmac).ok_or_else(|| StoreError::ArchiveMetaTampered {
        node_id: node_id.to_string(),
    })?;
    let signed = format!("{}|{}", meta.node_id, meta.sealed_at);
    if meta.node_id != node_id
        || !credmgr_core::signing::verify(root_key, &meta_label(node_id), signed.as_bytes(), &tag)
    {
        return Err(StoreError::ArchiveMetaTampered {
            node_id: node_id.to_string(),
        });
    }
    Ok(meta)
}

fn io_err(path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The seal archive's `meta.json` for `node_id` re-signed under `new_root`,
/// **only if it verifies under `old_root` first** (root-key rotation,
/// ADR-076 — see `audit::resigned_tip` for why a record that fails is never
/// re-signed). Returns the bytes to write; touches nothing.
pub fn resigned_meta(
    archive_dir: &Path,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    node_id: &str,
) -> Result<Vec<u8>> {
    let meta = read_meta(archive_dir, old_root, node_id)?;
    let signed = format!("{}|{}", meta.node_id, meta.sealed_at);
    let tag = credmgr_core::signing::sign(new_root, &meta_label(node_id), signed.as_bytes());
    let resigned = SealedMeta {
        hmac: hexutil::encode(&tag),
        ..meta
    };
    let path = meta_path(archive_dir);
    serde_json::to_vec(&resigned).map_err(|e| json_err(&path, e))
}

/// Where `archive_dir`'s signed metadata lives.
pub fn meta_file(archive_dir: &Path) -> std::path::PathBuf {
    meta_path(archive_dir)
}

/// ADR-079: write the signed `archive/<id>/meta.json` for a seal whose commit
/// has not happened yet. Pre-commit and unread — nothing refers to it until
/// the registry's seal record does — so a crash after this and before the
/// commit leaves only a stray file that load-time housekeeping removes.
pub fn write_meta_file(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    sealed_at: i64,
) -> Result<()> {
    let archive_dir = paths.archive_dir(node_id);
    atomic::ensure_dir(&archive_dir)?;
    write_meta(&archive_dir, root_key, node_id, sealed_at)
}

/// ADR-079: the `sealed_at` in an archive's HMAC-verified `meta.json`.
/// [`StoreError::ArchiveNotFound`] when there is no `meta.json`;
/// [`StoreError::ArchiveMetaTampered`] when it does not verify. `node.restore`
/// requires this to agree with the signed registry's own `sealedAt`.
pub fn read_sealed_at(paths: &VaultPaths, root_key: &[u8; 32], node_id: &str) -> Result<i64> {
    read_meta(&paths.archive_dir(node_id), root_key, node_id).map(|m| m.sealed_at)
}

/// What a pair of idempotent moves did (ADR-079).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Moved {
    /// The node's directory (entries, manifest, notes, pending tray) moved.
    pub node_dir: bool,
    /// The wrapped node key moved.
    pub key: bool,
}

/// Move `from` to `to` if — and only if — there is something to move and
/// nowhere it would be merged into. `Ok(false)` is "nothing to do": the source
/// is absent, which is exactly the state after a completed earlier attempt, so
/// a retry (or load-time housekeeping) can call this blindly. Both present is
/// an error: two copies of one thing is never silently merged.
fn move_if_present(from: &Path, to: &Path) -> Result<bool> {
    if fs::symlink_metadata(from).is_err() {
        return Ok(false);
    }
    if fs::symlink_metadata(to).is_ok() {
        return Err(io_err(
            to,
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "both the live copy and the archived copy exist — refusing to merge them",
            ),
        ));
    }
    atomic::move_file(from, to)?;
    Ok(true)
}

/// Step 1 of [`move_in`]: `nodes/<id>` → `archive/<id>/node`.
pub fn move_node_dir_in(paths: &VaultPaths, node_id: &str) -> Result<bool> {
    move_if_present(
        &paths.node_dir(node_id),
        &paths.archive_dir(node_id).join("node"),
    )
}

/// Step 2 of [`move_in`]: `keys/nodes/<id>.key` → `archive/<id>/node.key`.
pub fn move_key_in(paths: &VaultPaths, node_id: &str) -> Result<bool> {
    move_if_present(
        &paths.node_key(node_id),
        &paths.archive_dir(node_id).join("node.key"),
    )
}

/// ADR-079, post-commit half of a seal: put a sealed node's files where the
/// signed registry now says they are — `archive/<id>/{node, node.key}`.
/// **Idempotent**: a file already in the archive is left; a second call after
/// a completed first is a no-op. Safe to call blindly at load.
pub fn move_in(paths: &VaultPaths, node_id: &str) -> Result<Moved> {
    Ok(Moved {
        node_dir: move_node_dir_in(paths, node_id)?,
        key: move_key_in(paths, node_id)?,
    })
}

/// Step 1 of [`move_out`]: `archive/<id>/node` → `nodes/<id>`.
pub fn move_node_dir_out(paths: &VaultPaths, node_id: &str) -> Result<bool> {
    move_if_present(
        &paths.archive_dir(node_id).join("node"),
        &paths.node_dir(node_id),
    )
}

/// Step 2 of [`move_out`]: `archive/<id>/node.key` → `keys/nodes/<id>.key`.
pub fn move_key_out(paths: &VaultPaths, node_id: &str) -> Result<bool> {
    move_if_present(
        &paths.archive_dir(node_id).join("node.key"),
        &paths.node_key(node_id),
    )
}

/// ADR-079, first move of a restore: bring the archived files back to their
/// live places **while the registry still says the node is sealed** — unread
/// there, so a failure at any later step can put them back ([`move_in`]) and
/// nothing observable has changed. Idempotent, like [`move_in`].
pub fn move_out(paths: &VaultPaths, node_id: &str) -> Result<Moved> {
    Ok(Moved {
        node_dir: move_node_dir_out(paths, node_id)?,
        key: move_key_out(paths, node_id)?,
    })
}

/// Whether a live copy of the node's files is sitting where a *sealed* node's
/// files should not be (`nodes/<id>`, `keys/nodes/<id>.key`).
pub fn has_live_files(paths: &VaultPaths, node_id: &str) -> bool {
    fs::symlink_metadata(paths.node_dir(node_id)).is_ok()
        || fs::symlink_metadata(paths.node_key(node_id)).is_ok()
}

/// ADR-079 (post-commit half of a restore, and housekeeping of an aborted
/// seal): delete `archive/<id>/meta.json` and the then-empty directory — but
/// **only if `meta.json` is the sole thing in it**. If anything else is there
/// (the node's archived files, say) nothing is deleted at all, `meta.json`
/// included: it is the anchor of whatever is left. Returns `true` when
/// `archive/<id>` is gone afterwards, `false` when it was left alone.
pub fn retire_archive_dir(paths: &VaultPaths, node_id: &str) -> Result<bool> {
    let archive_dir = paths.archive_dir(node_id);
    let read = match fs::read_dir(&archive_dir) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(io_err(&archive_dir, e)),
    };
    for entry in read {
        let entry = entry.map_err(|e| io_err(&archive_dir, e))?;
        if entry.file_name() != "meta.json" {
            return Ok(false);
        }
    }
    atomic::remove_durable(&meta_path(&archive_dir))?;
    fs::remove_dir(&archive_dir).map_err(|e| io_err(&archive_dir, e))?;
    if let Some(parent) = archive_dir.parent() {
        atomic::sync_dir(parent)?;
    }
    Ok(true)
}

/// Move a node's entry tree and its wrapped node key into
/// `archive/<nodeId>/`, and record the seal time. Idempotent-unsafe by
/// design — sealing an already-sealed node is a caller error the broker
/// should have already prevented (node-level lock, Phase 3), so this
/// returns whatever `fs::rename` reports rather than silently merging.
pub fn seal(paths: &VaultPaths, root_key: &[u8; 32], node_id: &str, now: i64) -> Result<()> {
    let archive_dir = paths.archive_dir(node_id);
    atomic::ensure_dir(&archive_dir)?;

    let node_src = paths.node_dir(node_id);
    if node_src.exists() {
        let node_dst = archive_dir.join("node");
        fs::rename(&node_src, &node_dst).map_err(|e| io_err(&node_dst, e))?;
    }

    let key_src = paths.node_key(node_id);
    if key_src.exists() {
        let key_dst = archive_dir.join("node.key");
        fs::rename(&key_src, &key_dst).map_err(|e| io_err(&key_dst, e))?;
    }

    write_meta(&archive_dir, root_key, node_id, now)
}

/// Restore is a move back — "one click" (`ADR-027`). Refuses once the
/// 7-day window has passed; the caller's remedy at that point is the
/// orphan cold-copy path (broker + presence + fresh code), not this
/// function.
pub fn restore(paths: &VaultPaths, root_key: &[u8; 32], node_id: &str, now: i64) -> Result<()> {
    let archive_dir = paths.archive_dir(node_id);
    let meta = read_meta(&archive_dir, root_key, node_id)?;
    if now - meta.sealed_at > RECOVERY_WINDOW_SECONDS {
        return Err(StoreError::ArchiveExpired {
            node_id: node_id.to_string(),
            sealed_at: meta.sealed_at,
        });
    }

    let node_dst = paths.node_dir(node_id);
    let node_src = archive_dir.join("node");
    if node_src.exists() {
        if let Some(parent) = node_dst.parent() {
            atomic::ensure_dir(parent)?;
        }
        fs::rename(&node_src, &node_dst).map_err(|e| io_err(&node_dst, e))?;
    }

    let key_dst = paths.node_key(node_id);
    let key_src = archive_dir.join("node.key");
    if key_src.exists() {
        if let Some(parent) = key_dst.parent() {
            atomic::ensure_dir(parent)?;
        }
        fs::rename(&key_src, &key_dst).map_err(|e| io_err(&key_dst, e))?;
    }

    fs::remove_file(meta_path(&archive_dir)).map_err(|e| io_err(&archive_dir, e))?;
    let _ = fs::remove_dir(&archive_dir); // best-effort; non-empty is a caller bug, not fatal here
    Ok(())
}

/// Destroy an expired archive — both the retained originals and the node
/// key, per ADR-027's day-7 line. Returns `true` if something was purged,
/// `false` if the archive doesn't exist or hasn't expired yet (a caller
/// running a periodic sweep can just call this on every archived node id
/// without checking expiry itself first).
pub fn purge_if_expired(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    node_id: &str,
    now: i64,
) -> Result<bool> {
    let archive_dir = paths.archive_dir(node_id);
    if !archive_dir.exists() {
        return Ok(false);
    }
    let meta = match read_meta(&archive_dir, root_key, node_id) {
        Ok(m) => m,
        // A meta that fails its own HMAC is itself a sign something is
        // wrong with this archive; purge it rather than leave it dangling.
        Err(StoreError::ArchiveMetaTampered { .. }) => {
            fs::remove_dir_all(&archive_dir).map_err(|e| io_err(&archive_dir, e))?;
            return Ok(true);
        }
        Err(e) => return Err(e),
    };
    if now - meta.sealed_at <= RECOVERY_WINDOW_SECONDS {
        return Ok(false);
    }
    fs::remove_dir_all(&archive_dir).map_err(|e| io_err(&archive_dir, e))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60;

    fn seal_a_node(paths: &VaultPaths, rk: &[u8; 32], now: i64) {
        atomic::write(&paths.entry_env("a", "e_1"), b"ciphertext-1").unwrap();
        atomic::write(&paths.manifest("a"), b"{\"nodeId\":\"a\"}").unwrap();
        atomic::write(&paths.node_key("a"), b"wrapped-key-bytes").unwrap();
        seal(paths, rk, "a", now).unwrap();
    }

    #[test]
    fn seal_moves_entries_and_key_into_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];
        seal_a_node(&paths, &rk, 1_700_000_000);

        assert!(!paths.entry_env("a", "e_1").exists());
        assert!(!paths.node_key("a").exists());
        assert!(paths.archive_dir("a").join("node/entries/e_1.env").exists());
        assert!(paths.archive_dir("a").join("node.key").exists());
    }

    #[test]
    fn day_6_restore_is_one_click() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];
        let sealed_at = 1_700_000_000;
        seal_a_node(&paths, &rk, sealed_at);

        restore(&paths, &rk, "a", sealed_at + 6 * DAY).unwrap();

        assert_eq!(
            atomic::read(&paths.entry_env("a", "e_1")).unwrap(),
            b"ciphertext-1"
        );
        assert_eq!(
            atomic::read(&paths.node_key("a")).unwrap(),
            b"wrapped-key-bytes"
        );
        assert!(
            !paths.archive_dir("a").exists()
                || fs::read_dir(paths.archive_dir("a"))
                    .unwrap()
                    .next()
                    .is_none()
        );
    }

    #[test]
    fn day_8_restore_is_refused_and_purge_destroys_both_copies() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];
        let sealed_at = 1_700_000_000;
        seal_a_node(&paths, &rk, sealed_at);

        let day_8 = sealed_at + 8 * DAY;
        let err = restore(&paths, &rk, "a", day_8).unwrap_err();
        assert!(matches!(err, StoreError::ArchiveExpired { .. }));

        let purged = purge_if_expired(&paths, &rk, "a", day_8).unwrap();
        assert!(purged);
        assert!(!paths.archive_dir("a").join("node").exists());
        assert!(!paths.archive_dir("a").join("node.key").exists());

        let err = restore(&paths, &rk, "a", day_8).unwrap_err();
        assert!(matches!(err, StoreError::ArchiveNotFound { .. }));
    }

    #[test]
    fn purge_before_expiry_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];
        let sealed_at = 1_700_000_000;
        seal_a_node(&paths, &rk, sealed_at);

        let purged = purge_if_expired(&paths, &rk, "a", sealed_at + 6 * DAY).unwrap();
        assert!(!purged);
        assert!(paths.archive_dir("a").join("node.key").exists());
    }

    #[test]
    fn tampered_sealed_at_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];
        seal_a_node(&paths, &rk, 1_700_000_000);

        let meta_p = meta_path(&paths.archive_dir("a"));
        let mut meta: SealedMeta = serde_json::from_slice(&atomic::read(&meta_p).unwrap()).unwrap();
        meta.sealed_at = 1_900_000_000; // attacker tries to make an expired archive look fresh
        atomic::write(&meta_p, &serde_json::to_vec(&meta).unwrap()).unwrap();

        let err = restore(&paths, &rk, "a", 1_700_000_000 + 8 * DAY).unwrap_err();
        assert!(matches!(err, StoreError::ArchiveMetaTampered { .. }));
    }

    fn live_node(paths: &VaultPaths, rk: &[u8; 32]) {
        atomic::write(&paths.entry_env("a", "e_1"), b"ciphertext-1").unwrap();
        atomic::write(&paths.manifest("a"), b"{\"nodeId\":\"a\"}").unwrap();
        atomic::write(&paths.node_key("a"), b"wrapped-key-bytes").unwrap();
        write_meta_file(paths, rk, "a", 1_700_000_000).unwrap();
    }

    /// ADR-079: the seal's file moves are post-commit and may be repeated by
    /// load-time housekeeping, so each is idempotent — a retry after a
    /// completed or half-completed attempt finishes the job and never fails.
    #[test]
    fn move_in_is_idempotent_and_finishes_a_half_done_move() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];
        live_node(&paths, &rk);
        assert!(has_live_files(&paths, "a"));

        // Crash after the first move: the node dir is in the archive, the key is not.
        assert!(move_node_dir_in(&paths, "a").unwrap());
        assert!(has_live_files(&paths, "a"), "the key is still live");
        let finished = move_in(&paths, "a").unwrap();
        assert_eq!(
            finished,
            Moved {
                node_dir: false,
                key: true
            }
        );
        assert!(!has_live_files(&paths, "a"));
        assert!(paths.archive_dir("a").join("node/entries/e_1.env").exists());
        assert!(paths.archive_dir("a").join("node.key").exists());

        // And again: nothing left to do, nothing fails.
        assert_eq!(move_in(&paths, "a").unwrap(), Moved::default());
    }

    #[test]
    fn move_out_then_move_in_puts_the_bytes_back_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];
        live_node(&paths, &rk);
        move_in(&paths, "a").unwrap();

        assert_eq!(
            move_out(&paths, "a").unwrap(),
            Moved {
                node_dir: true,
                key: true
            }
        );
        assert_eq!(
            atomic::read(&paths.entry_env("a", "e_1")).unwrap(),
            b"ciphertext-1"
        );
        assert_eq!(
            atomic::read(&paths.node_key("a")).unwrap(),
            b"wrapped-key-bytes"
        );
        assert_eq!(move_out(&paths, "a").unwrap(), Moved::default());
        move_in(&paths, "a").unwrap();
        assert!(!has_live_files(&paths, "a"));
    }

    #[test]
    fn two_copies_are_never_merged() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];
        live_node(&paths, &rk);
        move_in(&paths, "a").unwrap();
        // A second live copy appears while the archive still holds its own.
        atomic::write(&paths.node_key("a"), b"another").unwrap();
        assert!(
            move_in(&paths, "a").is_err(),
            "the archived key is not overwritten"
        );
        assert_eq!(
            atomic::read(&paths.archive_dir("a").join("node.key")).unwrap(),
            b"wrapped-key-bytes"
        );
    }

    #[test]
    fn the_signed_sealed_at_is_readable_and_a_forged_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];
        assert!(matches!(
            read_sealed_at(&paths, &rk, "a"),
            Err(StoreError::ArchiveNotFound { .. })
        ));
        write_meta_file(&paths, &rk, "a", 1_700_000_000).unwrap();
        assert_eq!(read_sealed_at(&paths, &rk, "a").unwrap(), 1_700_000_000);
        assert!(matches!(
            read_sealed_at(&paths, &[7u8; 32], "a"),
            Err(StoreError::ArchiveMetaTampered { .. })
        ));
    }

    #[test]
    fn retiring_an_archive_dir_removes_only_a_directory_that_holds_nothing_but_the_meta() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [6u8; 32];

        // An aborted seal's residue: meta.json alone. Gone, directory and all.
        write_meta_file(&paths, &rk, "a", 1_700_000_000).unwrap();
        assert!(retire_archive_dir(&paths, "a").unwrap());
        assert!(!paths.archive_dir("a").exists());
        // Already gone is success.
        assert!(retire_archive_dir(&paths, "a").unwrap());

        // With the archived key still in it, NOTHING is deleted — the meta.json is
        // the anchor of what remains, and the directory is not ours to clear.
        live_node(&paths, &rk);
        move_in(&paths, "a").unwrap();
        assert!(!retire_archive_dir(&paths, "a").unwrap());
        assert!(paths.archive_dir("a").join("node.key").exists());
        assert!(paths.archive_dir("a").join("node/entries/e_1.env").exists());
        assert!(meta_path(&paths.archive_dir("a")).exists());
    }

    #[test]
    fn no_archive_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let err = restore(&paths, &[6u8; 32], "never-sealed", 1_700_000_000).unwrap_err();
        assert!(matches!(err, StoreError::ArchiveNotFound { .. }));
    }
}
