//! Helpers behind `maintenance.backup`/`maintenance.doctor --rebuild-registry`
//! (ADR-054) that need no `&BrokerState` at all — pure `&VaultPaths` +
//! filesystem + the backup passphrase, so they're testable directly, the
//! same way `credmgr_store::rebuild::{diff, apply}` are: a dispatch arm
//! gated `PresenceRequired` on every transport this build has would
//! otherwise leave everything behind it permanently unreachable by any test
//! that goes through `ops::dispatch` normally (`audit.get`/`grant.create`
//! already accept that trade for the gate check itself; the *logic* behind
//! `--rebuild-registry` is substantial enough that it must not share that
//! fate).

use std::path::{Path, PathBuf};

use secrecy::SecretBox;

use credmgr_keystore::backup_passphrase;
use credmgr_store::backup as store_backup;
use credmgr_store::paths::VaultPaths;
use credmgr_store::registry_file::RegistryDocument;

/// `credmgr-backup-<unix-seconds>.enc` — sorts chronologically as a string
/// (fixed-width decimal would be nicer; `now` is always positive and this
/// format only needs to sort correctly among files this op itself wrote, not
/// externally, so plain decimal is enough) and is distinctive enough that a
/// manually-placed or renamed file is never mistaken for one of these
/// (matches V1's own backup-retention safety property, ADR-054).
pub fn backup_file_name(now: i64) -> String {
    format!("credmgr-backup-{now}.enc")
}

fn parse_backup_timestamp(file_name: &str) -> Option<i64> {
    file_name
        .strip_prefix("credmgr-backup-")
        .and_then(|s| s.strip_suffix(".enc"))
        .and_then(|s| s.parse::<i64>().ok())
}

/// Every file in `backups_dir()` matching this op's own naming scheme,
/// oldest first — never a manually renamed or placed file (ADR-054's
/// retention-pruning safety property).
pub fn list_backup_files(paths: &VaultPaths) -> Vec<PathBuf> {
    let dir = paths.backups_dir();
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<(i64, PathBuf)> = read_dir
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_str()?;
            let ts = parse_backup_timestamp(name)?;
            Some((ts, e.path()))
        })
        .collect();
    found.sort_by_key(|(ts, _)| *ts);
    found.into_iter().map(|(_, p)| p).collect()
}

pub fn find_latest_backup(paths: &VaultPaths) -> Option<PathBuf> {
    list_backup_files(paths).into_iter().next_back()
}

/// Delete the oldest backups beyond `retain`, returning the file names
/// removed. `retain == 0` disables pruning entirely (V1's own convention,
/// kept). Only ever called after a fresh backup has just been written, so
/// "oldest beyond `retain`" always includes the one just created if `retain`
/// is 0.
pub fn prune_backups(paths: &VaultPaths, retain: usize) -> Vec<String> {
    if retain == 0 {
        return Vec::new();
    }
    let files = list_backup_files(paths);
    if files.len() <= retain {
        return Vec::new();
    }
    let excess = files.len() - retain;
    let mut pruned = Vec::new();
    for path in &files[..excess] {
        if std::fs::remove_file(path).is_ok() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                pruned.push(name.to_string());
            }
        }
    }
    pruned
}

#[derive(Debug)]
pub enum RebuildCandidateError {
    /// No file under `backups_dir()` matches the naming scheme at all.
    NoBackupFound,
    Io(std::io::Error),
    /// Wrong passphrase, or the file was corrupted/tampered — AEAD cannot
    /// distinguish the two (`keystore::backup_passphrase`'s own convention).
    DecryptFailed,
    /// Decrypted, but the bundle's own framing is truncated/malformed.
    UnpackFailed,
    /// Decrypted and unpacked fine, but the bundle has no `registry.json`
    /// entry at all — `store::backup::select_files` always includes it when
    /// present, so this means the backup predates a registry existing, or
    /// the file is not actually a `maintenance.backup` output.
    RegistryMissingFromBundle,
    RegistryMalformed(serde_json::Error),
}

impl std::fmt::Display for RebuildCandidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RebuildCandidateError::NoBackupFound => {
                write!(f, "no backup found under backups_dir() to rebuild from — run `credmgr backup` first")
            }
            RebuildCandidateError::Io(e) => write!(f, "reading backup file: {e}"),
            RebuildCandidateError::DecryptFailed => {
                write!(
                    f,
                    "could not decrypt the backup — wrong passphrase, or the file is corrupted"
                )
            }
            RebuildCandidateError::UnpackFailed => {
                write!(f, "backup file is truncated or malformed")
            }
            RebuildCandidateError::RegistryMissingFromBundle => {
                write!(
                    f,
                    "the backup has no registry.json — not a usable rebuild candidate"
                )
            }
            RebuildCandidateError::RegistryMalformed(e) => {
                write!(f, "backup's registry.json does not parse: {e}")
            }
        }
    }
}

/// Locate the most recent backup, decrypt it with `passphrase`, and read its
/// bundled `registry.json` back into a [`RegistryDocument`] — the
/// reconstruction candidate `store::rebuild::diff`/`apply` compare/write
/// against. Deliberately does **not** verify the candidate's own HMAC/sig
/// here (`RegistryDocument` as unpacked from a backup is exactly the bytes
/// `registry_file::save` wrote at backup time, including its embedded
/// binding data) — `store::rebuild::diff` is the thing that decides whether
/// the candidate is actually trustworthy to apply, not this loader.
pub fn load_rebuild_candidate(
    paths: &VaultPaths,
    passphrase: &SecretBox<String>,
) -> Result<RegistryDocument, RebuildCandidateError> {
    let latest = find_latest_backup(paths).ok_or(RebuildCandidateError::NoBackupFound)?;
    load_rebuild_candidate_from(&latest, passphrase)
}

/// Same as [`load_rebuild_candidate`] but against an explicit file — split
/// out so tests can point it at a backup they just built without needing a
/// real `backups_dir()` naming round trip.
pub fn load_rebuild_candidate_from(
    backup_path: &Path,
    passphrase: &SecretBox<String>,
) -> Result<RegistryDocument, RebuildCandidateError> {
    let ciphertext = std::fs::read(backup_path).map_err(RebuildCandidateError::Io)?;
    let plaintext = backup_passphrase::decrypt_with_passphrase(passphrase, &ciphertext)
        .map_err(|_| RebuildCandidateError::DecryptFailed)?;
    let entries =
        store_backup::unpack(&plaintext).map_err(|_| RebuildCandidateError::UnpackFailed)?;
    let registry_entry = entries
        .iter()
        .find(|e| e.relative_path == "registry.json")
        .ok_or(RebuildCandidateError::RegistryMissingFromBundle)?;
    serde_json::from_slice(&registry_entry.contents)
        .map_err(RebuildCandidateError::RegistryMalformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use credmgr_store::atomic;

    fn pass(s: &str) -> SecretBox<String> {
        SecretBox::new(Box::new(s.to_string()))
    }

    #[test]
    fn backup_file_name_round_trips_through_parse() {
        let name = backup_file_name(1_700_000_000);
        assert_eq!(parse_backup_timestamp(&name), Some(1_700_000_000));
    }

    #[test]
    fn list_backup_files_ignores_non_matching_names_and_sorts_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let backups = paths.backups_dir();
        atomic::write(&backups.join("credmgr-backup-300.enc"), b"c").unwrap();
        atomic::write(&backups.join("credmgr-backup-100.enc"), b"a").unwrap();
        atomic::write(&backups.join("credmgr-backup-200.enc"), b"b").unwrap();
        atomic::write(&backups.join("not-a-backup.txt"), b"x").unwrap();
        atomic::write(&backups.join("credmgr-backup-oops.enc"), b"y").unwrap();

        let files: Vec<String> = list_backup_files(&paths)
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
            .collect();
        assert_eq!(
            files,
            vec![
                "credmgr-backup-100.enc".to_string(),
                "credmgr-backup-200.enc".to_string(),
                "credmgr-backup-300.enc".to_string(),
            ]
        );
    }

    #[test]
    fn find_latest_backup_picks_the_newest_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let backups = paths.backups_dir();
        atomic::write(&backups.join("credmgr-backup-100.enc"), b"a").unwrap();
        atomic::write(&backups.join("credmgr-backup-999.enc"), b"b").unwrap();
        let latest = find_latest_backup(&paths).unwrap();
        assert_eq!(
            latest.file_name().unwrap().to_str().unwrap(),
            "credmgr-backup-999.enc"
        );
    }

    #[test]
    fn no_backups_directory_yields_no_latest_backup() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        assert!(find_latest_backup(&paths).is_none());
    }

    #[test]
    fn prune_keeps_only_the_newest_retain_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let backups = paths.backups_dir();
        for ts in [100, 200, 300, 400, 500] {
            atomic::write(&backups.join(backup_file_name(ts)), b"x").unwrap();
        }
        let pruned = prune_backups(&paths, 2);
        assert_eq!(
            pruned,
            vec![
                backup_file_name(100),
                backup_file_name(200),
                backup_file_name(300),
            ]
        );
        assert_eq!(list_backup_files(&paths).len(), 2);
    }

    #[test]
    fn prune_with_retain_zero_disables_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let backups = paths.backups_dir();
        for ts in [100, 200, 300] {
            atomic::write(&backups.join(backup_file_name(ts)), b"x").unwrap();
        }
        let pruned = prune_backups(&paths, 0);
        assert!(pruned.is_empty());
        assert_eq!(list_backup_files(&paths).len(), 3);
    }

    #[test]
    fn prune_never_touches_a_file_outside_its_own_naming_scheme() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let backups = paths.backups_dir();
        atomic::write(&backups.join("my-manual-backup.enc"), b"keep me").unwrap();
        for ts in [100, 200, 300] {
            atomic::write(&backups.join(backup_file_name(ts)), b"x").unwrap();
        }
        prune_backups(&paths, 1);
        assert!(backups.join("my-manual-backup.enc").exists());
    }

    fn build_test_backup(paths: &VaultPaths, passphrase: &SecretBox<String>) -> Vec<u8> {
        atomic::write(
            &paths.registry(),
            br#"{"nodes":{},"grants":[],"manifests":{},"vaultGeneration":1}"#,
        )
        .unwrap();
        let plaintext = store_backup::create_backup(paths).unwrap();
        backup_passphrase::encrypt_with_passphrase(passphrase, &plaintext)
    }

    #[test]
    fn load_rebuild_candidate_from_round_trips_a_real_backup() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let pass = pass("a backup passphrase");
        let ciphertext = build_test_backup(&paths, &pass);
        let backup_path = dir.path().join("test-backup.enc");
        std::fs::write(&backup_path, ciphertext).unwrap();

        let candidate = load_rebuild_candidate_from(&backup_path, &pass).unwrap();
        assert_eq!(candidate.vault_generation, 1);
    }

    #[test]
    fn load_rebuild_candidate_wrong_passphrase_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let correct = pass("correct");
        let ciphertext = build_test_backup(&paths, &correct);
        let backup_path = dir.path().join("test-backup.enc");
        std::fs::write(&backup_path, ciphertext).unwrap();

        let err = load_rebuild_candidate_from(&backup_path, &pass("wrong")).unwrap_err();
        assert!(matches!(err, RebuildCandidateError::DecryptFailed));
    }

    #[test]
    fn load_rebuild_candidate_no_backup_found_is_a_named_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let err = load_rebuild_candidate(&paths, &pass("x")).unwrap_err();
        assert!(matches!(err, RebuildCandidateError::NoBackupFound));
    }

    #[test]
    fn load_rebuild_candidate_finds_the_latest_of_several_backups() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let pass = pass("correct");

        atomic::write(
            &paths.registry(),
            br#"{"nodes":{},"grants":[],"manifests":{},"vaultGeneration":1}"#,
        )
        .unwrap();
        let old_plain = store_backup::create_backup(&paths).unwrap();
        let old_cipher = backup_passphrase::encrypt_with_passphrase(&pass, &old_plain);
        atomic::write(
            &paths.backups_dir().join(backup_file_name(100)),
            &old_cipher,
        )
        .unwrap();

        atomic::write(
            &paths.registry(),
            br#"{"nodes":{},"grants":[],"manifests":{},"vaultGeneration":7}"#,
        )
        .unwrap();
        let new_plain = store_backup::create_backup(&paths).unwrap();
        let new_cipher = backup_passphrase::encrypt_with_passphrase(&pass, &new_plain);
        atomic::write(
            &paths.backups_dir().join(backup_file_name(200)),
            &new_cipher,
        )
        .unwrap();

        let candidate = load_rebuild_candidate(&paths, &pass).unwrap();
        assert_eq!(
            candidate.vault_generation, 7,
            "must pick the newer of the two backups"
        );
    }
}
