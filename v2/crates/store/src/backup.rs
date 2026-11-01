//! The backup primitive. See `docs/04_CRYPTO_AND_KEYS.md §7`, ADR-039.
//!
//! `create_backup` decides *what* belongs in a backup and bundles it into
//! one deterministic, restorable blob. Two things it deliberately does not
//! do, per ADR-039: fire on a schedule (needs a running process — Phase 3),
//! and encrypt the bundle to a recovery-code/passphrase-derived key (needs
//! Argon2id and the recovery-code format — both Phase 5). What comes out of
//! this module today is exactly what Phase 5 will encrypt, unchanged.
//!
//! **What's included** (`04 §7`, read literally plus the one addition this
//! module's doc comment records): every entry envelope, every node's
//! manifest, the registry and its signature, the passphrase and recovery
//! root-key wraps, and — not explicitly named in `04 §7`'s prose but
//! structurally required — every *wrapped* node key file, and (ADR-079) the
//! orphan cold key. Without them the envelopes are undecryptable even after
//! recovering the root key, so "every envelope" is only meaningfully
//! restorable with them included.
//! **Never included:** `root.wrap.se` ("never the SE wrap, which is
//! meaningless off this machine" — `04 §7`), anything under `run/`
//! (ephemeral, not vault state), the audit log, notes, TOTP seeds, and
//! archived (sealed-but-not-yet-purged) node contents — all excluded for
//! the same reason `04 §7`'s own export table excludes them from
//! `credmgr export`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Result, StoreError};
use crate::paths::VaultPaths;

fn io_err(path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// One file's relative path (from the vault root) and raw bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleEntry {
    pub relative_path: String,
    pub contents: Vec<u8>,
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Collect every file this backup should contain, as vault-root-relative
/// paths. Pure filesystem selection — no signing, no encryption.
///
/// Deliberately selective inside each node directory, rather than a blanket
/// walk of `nodes/`: only `entries/*.env` (the envelopes `04 §7` names) and
/// `manifest.json` are pulled in. `notes.env` and `pending/*.env` are left
/// out — notes aren't "envelopes" in the sense `04 §7` means, and pending
/// (not-yet-reviewed, created-while-locked) entries aren't yet part of the
/// vault's committed state per ADR-023.
pub fn select_files(paths: &VaultPaths) -> Result<Vec<BundleEntry>> {
    let root = paths.root();
    let mut candidates = Vec::new();

    let nodes_dir = paths.nodes_dir();
    if nodes_dir.exists() {
        for entry in fs::read_dir(&nodes_dir).map_err(|e| io_err(&nodes_dir, e))? {
            let entry = entry.map_err(|e| io_err(&nodes_dir, e))?;
            let node_path = entry.path();
            if !node_path.is_dir() {
                continue;
            }
            walk_files(&node_path.join("entries"), &mut candidates)?;
            let manifest = node_path.join("manifest.json");
            if manifest.exists() {
                candidates.push(manifest);
            }
        }
    }

    for f in [paths.registry(), paths.registry_sig()] {
        if f.exists() {
            candidates.push(f);
        }
    }
    for f in [paths.root_wrap_pass(), paths.root_wrap_recovery()] {
        if f.exists() {
            candidates.push(f);
        }
    }
    walk_files(&paths.keys_dir().join("nodes"), &mut candidates)?;
    // ADR-079: the orphan cold key. Without it a restored backup holds orphan
    // envelopes (every sealed node's entries) that nothing can ever open.
    if paths.orphan_key().exists() {
        candidates.push(paths.orphan_key());
    }

    let mut entries = Vec::with_capacity(candidates.len());
    for path in candidates {
        let contents = fs::read(&path).map_err(|e| io_err(&path, e))?;
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        entries.push(BundleEntry {
            relative_path,
            contents,
        });
    }
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(entries)
}

/// Serialise entries into one self-describing blob: repeated
/// `<u32 path_len><path bytes><u64 content_len><content bytes>` records, in
/// `select_files`'s sorted order so the same vault state always produces
/// byte-identical output. No external archive-format dependency — this
/// crate reads its own format back with [`unpack`], and Phase 5 is the only
/// other consumer, which encrypts these bytes rather than parsing them.
pub fn pack(entries: &[BundleEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        let path_bytes = e.relative_path.as_bytes();
        out.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(path_bytes);
        out.extend_from_slice(&(e.contents.len() as u64).to_be_bytes());
        out.extend_from_slice(&e.contents);
    }
    out
}

#[derive(Debug)]
pub enum UnpackError {
    Truncated,
}

pub fn unpack(bytes: &[u8]) -> std::result::Result<Vec<BundleEntry>, UnpackError> {
    let mut entries = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 4 > bytes.len() {
            return Err(UnpackError::Truncated);
        }
        let path_len = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + path_len > bytes.len() {
            return Err(UnpackError::Truncated);
        }
        let relative_path = String::from_utf8_lossy(&bytes[i..i + path_len]).into_owned();
        i += path_len;

        if i + 8 > bytes.len() {
            return Err(UnpackError::Truncated);
        }
        let content_len = u64::from_be_bytes(bytes[i..i + 8].try_into().unwrap()) as usize;
        i += 8;
        if i + content_len > bytes.len() {
            return Err(UnpackError::Truncated);
        }
        let contents = bytes[i..i + content_len].to_vec();
        i += content_len;

        entries.push(BundleEntry {
            relative_path,
            contents,
        });
    }
    Ok(entries)
}

/// Select and pack in one call — what a Phase-3 scheduler or Phase-4 `credmgr
/// backup` command invokes. Encryption of the returned bytes is layered on
/// top by the caller once Phase 5 exists (ADR-039).
pub fn create_backup(paths: &VaultPaths) -> Result<Vec<u8>> {
    let entries = select_files(paths)?;
    Ok(pack(&entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomic;

    fn populate(paths: &VaultPaths) {
        atomic::write(&paths.entry_env("a", "e_1"), b"envelope-1").unwrap();
        atomic::write(&paths.manifest("a"), b"manifest-a").unwrap();
        atomic::write(&paths.node_key("a"), b"wrapped-node-key-a").unwrap();
        atomic::write(&paths.registry(), b"registry-json").unwrap();
        atomic::write(&paths.registry_sig(), b"registry-sig").unwrap();
        atomic::write(&paths.root_wrap_pass(), b"pass-wrap").unwrap();
        atomic::write(&paths.root_wrap_recovery(), b"recovery-wrap").unwrap();
        atomic::write(&paths.orphan_key(), b"cold-orphan-key").unwrap();
        // Deliberately excluded:
        atomic::write(&paths.root_wrap_se(), b"se-wrap-NEVER").unwrap();
        atomic::write(&paths.run_socket(), b"not-a-real-socket").unwrap();
        atomic::write(&paths.audit_log("2026-08"), b"{}\n").unwrap();
        atomic::write(&paths.notes_env("a"), b"encrypted-notes").unwrap();
    }

    #[test]
    fn includes_envelopes_manifests_node_keys_registry_and_recovery_wraps() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        populate(&paths);

        let entries = select_files(&paths).unwrap();
        let paths_in_bundle: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert!(paths_in_bundle.contains(&"nodes/a/entries/e_1.env"));
        assert!(paths_in_bundle.contains(&"nodes/a/manifest.json"));
        assert!(paths_in_bundle.contains(&"keys/nodes/a.key"));
        assert!(paths_in_bundle.contains(&"registry.json"));
        assert!(paths_in_bundle.contains(&"registry.sig"));
        assert!(paths_in_bundle.contains(&"keys/root.wrap.pass"));
        assert!(paths_in_bundle.contains(&"keys/root.wrap.recovery"));
    }

    /// ADR-079: a backup that omits the cold key restores orphan envelopes
    /// nobody can open.
    #[test]
    fn includes_the_orphan_cold_key() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        populate(&paths);

        let entries = select_files(&paths).unwrap();
        let cold = entries
            .iter()
            .find(|e| e.relative_path == "keys/cold/orphan.key")
            .expect("keys/cold/orphan.key is in the bundle");
        assert_eq!(cold.contents, b"cold-orphan-key");
    }

    #[test]
    fn never_includes_the_se_wrap_the_socket_the_audit_log_or_notes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        populate(&paths);

        let entries = select_files(&paths).unwrap();
        let paths_in_bundle: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert!(!paths_in_bundle.iter().any(|p| p.contains("root.wrap.se")));
        assert!(!paths_in_bundle.iter().any(|p| p.contains("broker.sock")));
        assert!(!paths_in_bundle.iter().any(|p| p.contains("audit")));
        assert!(!paths_in_bundle.iter().any(|p| p.contains("notes.env")));
    }

    #[test]
    fn pack_unpack_round_trips_byte_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        populate(&paths);

        let entries = select_files(&paths).unwrap();
        let packed = pack(&entries);
        let unpacked = unpack(&packed).unwrap();
        assert_eq!(unpacked, entries);
    }

    #[test]
    fn same_vault_state_produces_byte_identical_backups() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        populate(&paths);

        let b1 = create_backup(&paths).unwrap();
        let b2 = create_backup(&paths).unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn truncated_bundle_is_a_named_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        populate(&paths);
        let packed = create_backup(&paths).unwrap();
        let truncated = &packed[..packed.len() - 3];
        assert!(matches!(unpack(truncated), Err(UnpackError::Truncated)));
    }
}
