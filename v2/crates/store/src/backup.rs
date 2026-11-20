//! The backup archive and its restore. See `docs/04_CRYPTO_AND_KEYS.md §7`, ADR-039,
//! ADR-054 and (issue #36) ADR-112.
//!
//! `create_backup` decides *what* belongs in a backup and bundles it into one
//! deterministic blob; the broker encrypts that blob to a backup passphrase
//! (`credmgr_keystore::backup_passphrase`) and `credmgr restore` reverses it.
//! [`restore_bundle`] is the other half: it turns a decrypted bundle back into a
//! vault directory and a generation counter, all or nothing.
//!
//! **What is included (ADR-112, the complete archive).** Everything that is the
//! vault's own state, so that a restore into a fresh directory is the same vault:
//! `config.json`; the registry pair and its previous pair; every key file but the
//! machine-bound `keys/root.wrap.se` (the passphrase and recovery wraps, every
//! wrapped node key, the orphan cold key); every node directory whole - entry
//! envelopes, the manifest, the sealed note `notes.env`, and the locked-write tray
//! `pending/`; `totp/`; the audit log; and the whole `archive/` tree - sealed nodes
//! (`archive/<id>/`), removed entries (`archive/removed-entries/`) and rotation
//! history (`archive/entry-history/`). The external generation counter
//! (`vaultGeneration.counter`, outside the vault directory) rides along under
//! `_state/`, and a manifest (`_archive/manifest.json`) lists every vault file so
//! a restore can tell a truncated archive from a complete one.
//!
//! **Never included:** `keys/root.wrap.se` ("never the SE wrap, which is
//! meaningless off this machine" - `04 §7`), `run/` (sockets and locks), `backups/`
//! (a backup of backups), `rotation-pending/` (a half-finished root-key rotation:
//! a backup taken while one exists is refused, not silently made inconsistent), dot
//! files (the atomic writer's temporary files), and anything that is not a regular
//! file (a link is not followed).
//!
//! **The generation counter on restore.** It is rollback protection that lives
//! *outside* the vault directory so that restoring an old copy of the directory does
//! not restore it. A restore therefore writes the archived counter only when the
//! target state directory has none; an existing counter is kept, and when it is
//! ahead of the restored registry the vault will refuse to open as rolled back -
//! which is the counter doing its job, reported by [`CounterOutcome`].
//!
//! **Since the ADR-148 amendment (K-23 (e)) the counter is no longer archived.**
//! [`create_backup_with_ticket`] (what `maintenance.backup` runs) puts a restore ticket
//! (`_state/restore.ticket`, `restore_marker.rs`) in its place: signed under the root key,
//! naming the archived registry and its generation, and not usable as a counter. A restore
//! into a state directory with no counter writes it as a one-shot marker that the first
//! unlock of that folder checks and consumes ([`CounterOutcome::AcceptMarker`]). An archive
//! that carries a counter (made before the amendment) is still restored as before.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::error::{Result, StoreError};
use crate::generation::VAULT_GENERATION;
use crate::paths::{is_inside_git_working_tree, VaultPaths};

fn io_err(path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn refused(reason: impl Into<String>) -> StoreError {
    StoreError::ArchiveRefused {
        reason: reason.into(),
    }
}

/// The archive's own manifest: `{"format":"credmgr-archive","version":2,...}`.
pub const MANIFEST_PATH: &str = "_archive/manifest.json";
/// Files that live outside the vault directory travel under this prefix.
pub const STATE_PREFIX: &str = "_state/";
/// What [`ArchiveManifest::format`] says.
pub const ARCHIVE_FORMAT: &str = "credmgr-archive";
/// 1 was the incomplete archive (envelopes, manifests, registry and keys only; no
/// manifest file). 2 is complete (ADR-112).
pub const ARCHIVE_VERSION: u32 = 2;

/// Top-level files of a vault directory that belong in an archive.
const VAULT_FILES: &[&str] = &[
    "config.json",
    "registry.json",
    "registry.sig",
    "registry.json.prev",
    "registry.sig.prev",
    // ADR-165 (review N4): the vault's identity, so a restored vault is still the vault a machine bound.
    "vault.id",
];
/// Top-level directories that belong in an archive. Anything else under the vault
/// root (`backups/`, `run/`, `rotation-pending/`, strays) does not.
const VAULT_DIRS: &[&str] = &["keys", "nodes", "totp", "audit", "archive"];

/// What the archive says it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub format: String,
    pub version: u32,
    /// Every vault file, vault-root-relative, sorted.
    pub files: Vec<String>,
    /// Files from the state directory, by name (today `vaultGeneration.counter`).
    #[serde(default)]
    pub state_files: Vec<String>,
}

/// One file's relative path (from the vault root) and raw bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleEntry {
    pub relative_path: String,
    pub contents: Vec<u8>,
}

fn counter_file_name() -> String {
    format!("{VAULT_GENERATION}.counter")
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let path = entry.path();
        // A temporary file of the atomic writer, or any dot file: not vault state.
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let kind = entry.file_type().map_err(|e| io_err(&path, e))?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            walk_files(&path, out)?;
        } else if kind.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

/// Collect every file this backup should contain: the vault's own state as
/// vault-root-relative paths, the state-directory counter under `_state/` when
/// `state_dir` is given and holds one, and the manifest. Pure filesystem selection
/// - no signing, no encryption. Refuses while a root-key rotation is half done.
pub fn select_files(paths: &VaultPaths, state_dir: Option<&Path>) -> Result<Vec<BundleEntry>> {
    select_files_with_pass_wrap(paths, state_dir, None)
}

/// [`select_files`], with the archived `keys/root.wrap.pass` replaced by `pass_wrap` when it is given.
///
/// ADR-165 (review P0-2): a vault bound to this Mac's device key has a sealed passphrase wrap on disk, and an
/// archive that kept it sealed would open, after this Mac is lost, only with the recovery code of the day it
/// was made — every later rotation retires that code. So a bound vault's archive carries the **plain**
/// passphrase wrap instead (the broker opens the seal and passes it here). The archive is still encrypted to
/// its own backup passphrase; what the machine lock does not cover is this archive, and that is said
/// wherever the lock is described.
pub fn select_files_with_pass_wrap(
    paths: &VaultPaths,
    state_dir: Option<&Path>,
    pass_wrap: Option<&[u8]>,
) -> Result<Vec<BundleEntry>> {
    let root = paths.root();
    if paths.rotation_stage().exists() {
        return Err(refused(
            "a root-key rotation is half finished (rotation-pending/ exists): unlock the vault \
             so it can finish, then back up - an archive taken now would mix two keys",
        ));
    }

    let mut candidates = Vec::new();
    for name in VAULT_FILES {
        let f = root.join(name);
        if f.is_file() {
            candidates.push(f);
        }
    }
    for dir in VAULT_DIRS {
        walk_files(&root.join(dir), &mut candidates)?;
    }
    let se_wrap = paths.root_wrap_se();
    candidates.retain(|p| p != &se_wrap);

    let pass_path = paths.root_wrap_pass();
    let mut entries = Vec::with_capacity(candidates.len() + 2);
    for path in candidates {
        let contents = match pass_wrap {
            Some(bytes) if path == pass_path => bytes.to_vec(),
            _ => fs::read(&path).map_err(|e| io_err(&path, e))?,
        };
        entries.push(BundleEntry {
            relative_path: relative(root, &path),
            contents,
        });
    }
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let mut manifest = ArchiveManifest {
        format: ARCHIVE_FORMAT.to_string(),
        version: ARCHIVE_VERSION,
        files: entries.iter().map(|e| e.relative_path.clone()).collect(),
        state_files: Vec::new(),
    };
    if let Some(dir) = state_dir {
        let counter = dir.join(counter_file_name());
        if counter.is_file() {
            let contents = fs::read(&counter).map_err(|e| io_err(&counter, e))?;
            manifest.state_files.push(counter_file_name());
            entries.push(BundleEntry {
                relative_path: format!("{STATE_PREFIX}{}", counter_file_name()),
                contents,
            });
        }
    }
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|e| StoreError::Json {
        path: PathBuf::from(MANIFEST_PATH),
        source: e,
    })?;
    entries.push(BundleEntry {
        relative_path: MANIFEST_PATH.to_string(),
        contents: manifest_bytes,
    });
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(entries)
}

/// Serialise entries into one self-describing blob: repeated
/// `<u32 path_len><path bytes><u64 content_len><content bytes>` records, in
/// `select_files`'s sorted order so the same vault state always produces
/// byte-identical output. No external archive-format dependency - this crate reads
/// its own format back with [`unpack`].
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
        if i.checked_add(path_len)
            .map_or(true, |end| end > bytes.len())
        {
            return Err(UnpackError::Truncated);
        }
        let relative_path = String::from_utf8_lossy(&bytes[i..i + path_len]).into_owned();
        i += path_len;

        if i + 8 > bytes.len() {
            return Err(UnpackError::Truncated);
        }
        let content_len = usize::try_from(u64::from_be_bytes(bytes[i..i + 8].try_into().unwrap()))
            .map_err(|_| UnpackError::Truncated)?;
        i += 8;
        if i.checked_add(content_len)
            .map_or(true, |end| end > bytes.len())
        {
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

/// Select and pack in one call. `state_dir` is the directory holding the generation
/// counter; `None` leaves the counter out (an archive of a vault directory alone).
/// `maintenance.backup` runs [`create_backup_with_ticket`] instead (ADR-148 amendment).
pub fn create_backup(paths: &VaultPaths, state_dir: Option<&Path>) -> Result<Vec<u8>> {
    create_backup_with_pass_wrap(paths, state_dir, None)
}

/// [`create_backup`] with the archived passphrase wrap replaced (see [`select_files_with_pass_wrap`]).
pub fn create_backup_with_pass_wrap(
    paths: &VaultPaths,
    state_dir: Option<&Path>,
    pass_wrap: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let entries = select_files_with_pass_wrap(paths, state_dir, pass_wrap)?;
    Ok(pack(&entries))
}

/// ADR-148 amendment (K-23 (e)): what `maintenance.backup` archives. The vault's own files
/// and, under `_state/`, a restore ticket signed under `root_key` for the exact
/// `registry.json` the archive carries - never the generation counter, which stays on
/// this machine. Refused when the vault has no readable registry generation.
pub fn create_backup_with_ticket(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    issued_at: i64,
) -> Result<Vec<u8>> {
    create_backup_with_ticket_and_pass_wrap(paths, root_key, issued_at, None)
}

/// [`create_backup_with_ticket`] with the archived `keys/root.wrap.pass` replaced by `pass_wrap` when it is
/// given (ADR-165 review P0-2: a vault bound to this Mac archives its passphrase wrap unsealed, inside the
/// archive's own encryption). The ticket signs `registry.json` only, so the two compose: the restored vault
/// opens with the passphrase on any Mac and is accepted once through the marker the ticket becomes.
pub fn create_backup_with_ticket_and_pass_wrap(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    issued_at: i64,
    pass_wrap: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut entries = select_files_with_pass_wrap(paths, None, pass_wrap)?;
    let registry = entries
        .iter()
        .find(|e| e.relative_path == "registry.json")
        .ok_or_else(|| refused("the vault has no registry.json to back up"))?;
    let ticket = crate::restore_marker::ticket_bytes(root_key, &registry.contents, issued_at)
        .ok_or_else(|| refused("the registry carries no vaultGeneration; nothing was backed up"))?;
    let manifest_at = entries
        .iter()
        .position(|e| e.relative_path == MANIFEST_PATH)
        .expect("select_files always adds the manifest");
    let mut manifest: ArchiveManifest = serde_json::from_slice(&entries[manifest_at].contents)
        .map_err(|e| StoreError::Json {
            path: PathBuf::from(MANIFEST_PATH),
            source: e,
        })?;
    manifest
        .state_files
        .push(crate::restore_marker::TICKET_STATE_FILE.to_string());
    entries[manifest_at].contents =
        serde_json::to_vec(&manifest).map_err(|e| StoreError::Json {
            path: PathBuf::from(MANIFEST_PATH),
            source: e,
        })?;
    entries.push(BundleEntry {
        relative_path: format!("{STATE_PREFIX}{}", crate::restore_marker::TICKET_STATE_FILE),
        contents: ticket,
    });
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(pack(&entries))
}

// ---- restore -------------------------------------------------------------

/// What happened to the generation counter on a restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterOutcome {
    /// The archived counter was written into the empty state directory.
    Restored,
    /// The state directory already had a counter; it was left alone. If it is ahead
    /// of the restored registry the vault will be refused as rolled back.
    KeptExisting,
    /// The archive carries neither a counter nor a restore ticket (it was made without
    /// a state directory, or before ADR-112). With no counter in the state directory the
    /// vault opens only with `CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1` for one start.
    NotInArchive,
    /// ADR-148 amendment: the archive carries a restore ticket and the state directory had
    /// no counter, so the restore wrote the one-shot marker the first unlock of this folder
    /// checks and consumes (writing the counter then).
    AcceptMarker,
}

/// What [`restore_bundle`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Vault files written.
    pub files: usize,
    /// Their size in bytes.
    pub bytes: u64,
    pub counter: CounterOutcome,
    /// The archive carried a manifest and matched it. `false` for a version-1 archive,
    /// which never held notes, sealed-node or history archives (it says so).
    pub complete: bool,
}

/// A vault-root-relative archive path that is safe to write: forward slashes only,
/// no empty, `.` or `..` component, no NUL or backslash, not absolute, and under a
/// known top-level name.
fn safe_vault_path(p: &str) -> bool {
    if p.is_empty() || p.starts_with('/') || p.contains('\\') || p.contains('\0') {
        return false;
    }
    let parts: Vec<&str> = p.split('/').collect();
    if parts
        .iter()
        .any(|c| c.is_empty() || *c == "." || *c == "..")
    {
        return false;
    }
    let top = parts[0];
    if parts.len() == 1 {
        VAULT_FILES.contains(&top)
    } else {
        VAULT_DIRS.contains(&top)
    }
}

/// Turn a decrypted archive back into a vault directory at `target` and, when the
/// archive carries one and `state_dir` has none, the generation counter.
///
/// All or nothing. The bundle is validated first (every path safe and known, the
/// manifest matching what is there, a registry and the passphrase wrap present);
/// the vault is then written into a sibling staging directory and moved into place
/// with one rename, so a failure leaves `target` as it was. `target` must not
/// exist, or be an empty directory, and must not sit inside a git working tree
/// (V1 parity): a restore never merges into, or overwrites, a vault.
pub fn restore_bundle(plaintext: &[u8], target: &Path, state_dir: &Path) -> Result<RestoreReport> {
    let entries = unpack(plaintext).map_err(|_| refused("the archive is truncated or damaged"))?;

    // ---- validate everything before touching the disk ----
    let mut manifest: Option<ArchiveManifest> = None;
    let mut vault_entries: Vec<&BundleEntry> = Vec::new();
    let mut state_entries: Vec<&BundleEntry> = Vec::new();
    for e in &entries {
        if e.relative_path == MANIFEST_PATH {
            if manifest.is_some() {
                return Err(refused("the archive holds two manifests"));
            }
            manifest = Some(
                serde_json::from_slice(&e.contents)
                    .map_err(|_| refused("the archive's manifest does not parse"))?,
            );
        } else if let Some(name) = e.relative_path.strip_prefix(STATE_PREFIX) {
            if name != counter_file_name() && name != crate::restore_marker::TICKET_STATE_FILE {
                return Err(refused(format!(
                    "the archive names a state file this version does not know: {name}"
                )));
            }
            state_entries.push(e);
        } else if safe_vault_path(&e.relative_path) {
            vault_entries.push(e);
        } else {
            return Err(refused(format!(
                "the archive holds a path this version will not write: {:?}",
                e.relative_path.chars().take(80).collect::<String>()
            )));
        }
    }
    let mut seen = std::collections::HashSet::new();
    // ADR-148 (P3): two names that differ only in case are one file on a case-insensitive volume (the macOS
    // default); the second would silently replace the first.
    let mut folded = std::collections::HashSet::new();
    for e in &vault_entries {
        if !seen.insert(e.relative_path.as_str()) || !folded.insert(e.relative_path.to_lowercase())
        {
            return Err(refused(format!(
                "the archive holds {} twice",
                e.relative_path
            )));
        }
        // ADR-148 (P3): the Touch ID unlock wrap is never archived (it is meaningful only beside the Secure
        // Enclave key that made it); one in an archive was put there by hand, and a restore will not write it.
        if e.relative_path.eq_ignore_ascii_case("keys/root.wrap.se") {
            return Err(refused(
                "the archive holds keys/root.wrap.se, which a backup never contains; nothing was restored",
            ));
        }
    }
    let complete = match &manifest {
        Some(m) => {
            if m.format != ARCHIVE_FORMAT || m.version != ARCHIVE_VERSION {
                return Err(refused(format!(
                    "the archive is {} version {}, this build restores {ARCHIVE_FORMAT} version \
                     {ARCHIVE_VERSION}",
                    m.format, m.version
                )));
            }
            let mut listed = m.files.clone();
            listed.sort();
            let mut present: Vec<String> = vault_entries
                .iter()
                .map(|e| e.relative_path.clone())
                .collect();
            present.sort();
            if listed != present {
                return Err(refused(
                    "the archive is incomplete or has extra files: its manifest and its contents \
                     disagree. Nothing was restored",
                ));
            }
            true
        }
        None => false,
    };
    // ADR-148 amendment: a ticket is checked for structure before anything is written.
    let ticket = match state_entries.iter().find(|e| {
        e.relative_path
            .ends_with(crate::restore_marker::TICKET_STATE_FILE)
    }) {
        None => None,
        Some(e) => Some(
            crate::restore_marker::parse_ticket(&e.contents).ok_or_else(|| {
                refused("the archive's restore ticket is damaged; nothing was restored")
            })?,
        ),
    };
    for needed in ["registry.json", "registry.sig", "keys/root.wrap.pass"] {
        if !seen.contains(needed) {
            return Err(refused(format!(
                "this is not a vault archive: {needed} is missing"
            )));
        }
    }

    // ---- the target ----
    if is_inside_git_working_tree(target) {
        return Err(refused(
            "the target is inside a git working tree; a vault must not live in a repository",
        ));
    }
    if target.exists() {
        if !target.is_dir() {
            return Err(refused("the target exists and is not a directory"));
        }
        let mut it = fs::read_dir(target).map_err(|e| io_err(target, e))?;
        if it.next().is_some() {
            return Err(refused(
                "the target directory is not empty: a restore never merges into, or overwrites, \
                 a vault. Restore into an empty directory",
            ));
        }
    }

    // ---- stage, then move into place ----
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    atomic::ensure_dir(parent)?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_string());
    // ADR-148 (P3): an unpredictable staging name, so another local process cannot pre-create (or link) it.
    let mut salt = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut salt);
    let stage = parent.join(format!(
        ".{name}.restoring.{}.{}",
        std::process::id(),
        crate::hexutil::encode(&salt)
    ));
    if stage.exists() {
        fs::remove_dir_all(&stage).map_err(|e| io_err(&stage, e))?;
    }
    let result = (|| -> Result<(usize, u64)> {
        atomic::ensure_dir(&stage)?;
        let mut bytes = 0u64;
        for e in &vault_entries {
            atomic::write(&stage.join(&e.relative_path), &e.contents)?;
            bytes += e.contents.len() as u64;
        }
        atomic::sync_tree(&stage)?;
        Ok((vault_entries.len(), bytes))
    })();
    let (files, bytes) = match result {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_dir_all(&stage);
            return Err(e);
        }
    };
    if target.exists() {
        // Empty (checked above): a rename onto an empty directory is not portable.
        if let Err(e) = fs::remove_dir(target) {
            let _ = fs::remove_dir_all(&stage);
            return Err(io_err(target, e));
        }
    }
    if let Err(e) = fs::rename(&stage, target) {
        let _ = fs::remove_dir_all(&stage);
        return Err(io_err(target, e));
    }
    atomic::sync_dir(parent)?;

    // ---- the generation counter ----
    let archived_counter = state_entries
        .iter()
        .find(|e| e.relative_path.ends_with(&counter_file_name()));
    let dest = state_dir.join(counter_file_name());
    let counter = match (archived_counter, ticket) {
        // An existing counter is kept and decides, whatever the archive carries.
        (Some(_), _) | (None, Some(_)) if dest.exists() => CounterOutcome::KeptExisting,
        // An archive made before the ADR-148 amendment: its counter, as before.
        (Some(e), _) => {
            atomic::write(&dest, &e.contents)?;
            CounterOutcome::Restored
        }
        // ADR-148 amendment: the one-shot marker the first unlock of `target` consumes.
        (None, Some(t)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            let marker = crate::restore_marker::marker_bytes(t, target, now)
                .ok_or_else(|| refused("could not write the restore marker"))?;
            atomic::ensure_dir(state_dir)?;
            atomic::write(&crate::restore_marker::marker_path(state_dir), &marker)?;
            CounterOutcome::AcceptMarker
        }
        (None, None) => CounterOutcome::NotInArchive,
    };
    Ok(RestoreReport {
        files,
        bytes,
        counter,
        complete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomic;

    fn populate(paths: &VaultPaths) {
        atomic::write(&paths.config(), b"{}").unwrap();
        atomic::write(&paths.entry_env("a", "e_1"), b"envelope-1").unwrap();
        atomic::write(&paths.manifest("a"), b"manifest-a").unwrap();
        atomic::write(&paths.notes_env("a"), b"encrypted-notes").unwrap();
        atomic::write(&paths.pending_env("a", "e_p"), b"pending-envelope").unwrap();
        atomic::write(&paths.node_key("a"), b"wrapped-node-key-a").unwrap();
        atomic::write(&paths.registry(), b"registry-json").unwrap();
        atomic::write(&paths.registry_sig(), b"registry-sig").unwrap();
        atomic::write(&paths.registry_prev(), b"registry-prev").unwrap();
        atomic::write(&paths.root_wrap_pass(), b"pass-wrap").unwrap();
        atomic::write(&paths.root_wrap_recovery(), b"recovery-wrap").unwrap();
        atomic::write(&paths.orphan_key(), b"cold-orphan-key").unwrap();
        atomic::write(&paths.audit_log("2026-08"), b"{}\n").unwrap();
        atomic::write(&paths.archive_dir("sealed").join("node.key"), b"sealed-key").unwrap();
        atomic::write(&paths.removed_entry_env("a", "e_gone"), b"removed-env").unwrap();
        atomic::write(&paths.removed_entry_meta("a", "e_gone"), b"removed-meta").unwrap();
        atomic::write(&paths.entry_history_env("a", "e_1", 3), b"history-env").unwrap();
        atomic::write(&paths.entry_history_meta("a", "e_1", 3), b"history-meta").unwrap();
        atomic::write(&paths.totp_item("a", "t_1"), b"totp-item").unwrap();
        // Deliberately excluded:
        atomic::write(&paths.root_wrap_se(), b"se-wrap-NEVER").unwrap();
        atomic::write(&paths.run_socket(), b"not-a-real-socket").unwrap();
        atomic::write(&paths.backups_dir().join("credmgr-backup-1.enc"), b"old").unwrap();
        atomic::write(&paths.root().join(".stray.tmp.1.2"), b"temp").unwrap();
        atomic::write(&paths.root().join("stray.txt"), b"not vault state").unwrap();
    }

    fn names(entries: &[BundleEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.relative_path.as_str()).collect()
    }

    #[test]
    fn the_archive_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let state = dir.path().join("state");
        atomic::write(&state.join("vaultGeneration.counter"), b"counter-bytes").unwrap();

        let entries = select_files(&paths, Some(&state)).unwrap();
        let got = names(&entries);
        for want in [
            "config.json",
            "nodes/a/entries/e_1.env",
            "nodes/a/manifest.json",
            "nodes/a/notes.env",
            "nodes/a/pending/e_p.env",
            "keys/nodes/a.key",
            "registry.json",
            "registry.sig",
            "registry.json.prev",
            "keys/root.wrap.pass",
            "keys/root.wrap.recovery",
            "keys/cold/orphan.key",
            "audit/2026-08.log",
            "archive/sealed/node.key",
            "archive/removed-entries/a/e_gone/entry.env",
            "archive/removed-entries/a/e_gone/removed.json",
            "archive/entry-history/a/e_1/3.env",
            "archive/entry-history/a/e_1/3.json",
            "totp/a/t_1.env",
            "_state/vaultGeneration.counter",
            "_archive/manifest.json",
        ] {
            assert!(got.contains(&want), "missing {want}: {got:?}");
        }
    }

    #[test]
    fn never_includes_the_se_wrap_the_socket_old_backups_temp_files_or_strays() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let entries = select_files(&paths, None).unwrap();
        let got = names(&entries);
        for never in [
            "root.wrap.se",
            "broker.sock",
            "backups/",
            ".stray",
            "stray.txt",
        ] {
            assert!(!got.iter().any(|p| p.contains(never)), "{never} in {got:?}");
        }
        assert!(
            !got.iter().any(|p| p.starts_with("_state/")),
            "no state dir given"
        );
    }

    /// ADR-165 (review P0-2): the archive can carry another passphrase wrap than the file on disk (the plain
    /// form of a sealed one), and nothing else changes.
    #[test]
    fn the_archived_passphrase_wrap_can_be_replaced_and_nothing_else_changes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let plain = select_files(&paths, None).unwrap();
        let swapped = select_files_with_pass_wrap(&paths, None, Some(b"plain form")).unwrap();
        assert_eq!(names(&plain), names(&swapped));
        for (a, b) in plain.iter().zip(&swapped) {
            if a.relative_path == "keys/root.wrap.pass" {
                assert_eq!(a.contents, b"pass-wrap");
                assert_eq!(b.contents, b"plain form");
            } else {
                assert_eq!(a.contents, b.contents, "{}", a.relative_path);
            }
        }
        assert_eq!(atomic::read(&paths.root_wrap_pass()).unwrap(), b"pass-wrap");
    }

    #[test]
    fn a_half_finished_rotation_refuses_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        atomic::write(&paths.rotation_stage().join("COMMIT"), b"x").unwrap();
        let err = select_files(&paths, None).unwrap_err();
        assert!(err.to_string().contains("half finished"), "{err}");
    }

    #[test]
    fn pack_unpack_round_trips_byte_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let entries = select_files(&paths, None).unwrap();
        assert_eq!(unpack(&pack(&entries)).unwrap(), entries);
    }

    #[test]
    fn same_vault_state_produces_byte_identical_backups() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        assert_eq!(
            create_backup(&paths, None).unwrap(),
            create_backup(&paths, None).unwrap()
        );
    }

    #[test]
    fn truncated_bundle_is_a_named_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let packed = create_backup(&paths, None).unwrap();
        assert!(matches!(
            unpack(&packed[..packed.len() - 3]),
            Err(UnpackError::Truncated)
        ));
        let err = restore_bundle(
            &packed[..packed.len() - 3],
            &dir.path().join("out"),
            &dir.path().join("st"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    // ---- restore ----

    fn read_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut files = Vec::new();
        walk_files(root, &mut files).unwrap();
        let mut out: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|p| (relative(root, p), fs::read(p).unwrap()))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn restore_rebuilds_the_same_tree_and_the_counter() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let state = dir.path().join("state");
        atomic::write(&state.join("vaultGeneration.counter"), b"counter-bytes").unwrap();
        let bundle = create_backup(&paths, Some(&state)).unwrap();

        let out = dir.path().join("fresh").join("vault");
        let out_state = dir.path().join("fresh-state");
        let report = restore_bundle(&bundle, &out, &out_state).unwrap();
        assert!(report.complete);
        assert_eq!(report.counter, CounterOutcome::Restored);
        assert_eq!(
            fs::read(out_state.join("vaultGeneration.counter")).unwrap(),
            b"counter-bytes"
        );
        // Every archived file is there, byte for byte; nothing else is.
        let want: Vec<_> = read_tree(paths.root())
            .into_iter()
            .filter(|(p, _)| {
                !(p.starts_with("keys/root.wrap.se")
                    || p.starts_with("run/")
                    || p.starts_with("backups/")
                    || p == "stray.txt")
            })
            .collect();
        assert_eq!(read_tree(&out), want);
        assert_eq!(report.files, want.len());
        // No staging directory is left behind.
        let left: Vec<_> = fs::read_dir(out.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["vault".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn restored_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let bundle = create_backup(&paths, None).unwrap();
        let out = dir.path().join("out");
        restore_bundle(&bundle, &out, &dir.path().join("st")).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&out.join("registry.json")), 0o600);
        assert_eq!(mode(&out.join("keys")), 0o700);
    }

    #[test]
    fn restore_refuses_a_target_that_is_not_empty_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let bundle = create_backup(&paths, None).unwrap();
        let out = dir.path().join("out");
        atomic::write(&out.join("keep.txt"), b"mine").unwrap();
        let err = restore_bundle(&bundle, &out, &dir.path().join("st")).unwrap_err();
        assert!(err.to_string().contains("not empty"), "{err}");
        assert_eq!(
            read_tree(&out),
            vec![("keep.txt".to_string(), b"mine".to_vec())]
        );
        // An empty existing directory is fine.
        let empty = dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        restore_bundle(&bundle, &empty, &dir.path().join("st")).unwrap();
        assert!(empty.join("registry.json").is_file());
    }

    #[test]
    fn restore_refuses_a_touch_id_wrap_and_names_that_differ_only_in_case() {
        let dir = tempfile::tempdir().unwrap();
        let min: Vec<(&str, &[u8])> = vec![
            ("registry.json", b"r"),
            ("registry.sig", b"s"),
            ("keys/root.wrap.pass", b"p"),
        ];
        for (extra, why) in [
            ("keys/root.wrap.se", "root.wrap.se"),
            ("keys/ROOT.WRAP.PASS", "twice"),
        ] {
            let mut all = min.clone();
            all.push((extra, b"x"));
            let out = dir.path().join("out");
            let err = restore_bundle(&bundle_of(&all), &out, &dir.path().join("st")).unwrap_err();
            assert!(err.to_string().contains(why), "{extra}: {err}");
            assert!(!out.exists(), "{extra}: nothing was written");
        }
    }

    #[test]
    fn unpack_refuses_a_length_that_overflows() {
        let mut bytes = 4u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"abcd");
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(unpack(&bytes).is_err());
    }

    #[test]
    fn restore_keeps_an_existing_counter() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let state = dir.path().join("state");
        atomic::write(&state.join("vaultGeneration.counter"), b"from-backup").unwrap();
        let bundle = create_backup(&paths, Some(&state)).unwrap();

        let other_state = dir.path().join("other-state");
        atomic::write(
            &other_state.join("vaultGeneration.counter"),
            b"newer-on-this-machine",
        )
        .unwrap();
        let report = restore_bundle(&bundle, &dir.path().join("out"), &other_state).unwrap();
        assert_eq!(report.counter, CounterOutcome::KeptExisting);
        assert_eq!(
            fs::read(other_state.join("vaultGeneration.counter")).unwrap(),
            b"newer-on-this-machine"
        );
    }

    fn bundle_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        pack(
            &entries
                .iter()
                .map(|(p, c)| BundleEntry {
                    relative_path: (*p).to_string(),
                    contents: c.to_vec(),
                })
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn restore_refuses_unsafe_or_unknown_paths_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let min: [(&str, &[u8]); 3] = [
            ("registry.json", b"r"),
            ("registry.sig", b"s"),
            ("keys/root.wrap.pass", b"k"),
        ];
        for bad in [
            "../escape.txt",
            "nodes/../../escape.txt",
            "/etc/passwd",
            "nodes//x",
            "nodes/./x",
            "nodes\\x",
            "unknown-top/file",
            "stray.txt",
            "keys/../..",
        ] {
            let mut all: Vec<(&str, &[u8])> = min.to_vec();
            all.push((bad, b"x"));
            let out = dir.path().join("out");
            let err = restore_bundle(&bundle_of(&all), &out, &dir.path().join("st")).unwrap_err();
            assert!(err.to_string().contains("will not write"), "{bad}: {err}");
            assert!(!out.exists(), "{bad}: nothing was written");
            assert!(!dir.path().join("escape.txt").exists());
        }
        // A path under `_state/` that this version does not know.
        let mut all: Vec<(&str, &[u8])> = min.to_vec();
        all.push(("_state/other.counter", b"x"));
        let err = restore_bundle(
            &bundle_of(&all),
            &dir.path().join("out"),
            &dir.path().join("st"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("state file"), "{err}");
    }

    #[test]
    fn restore_refuses_an_archive_that_does_not_match_its_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let mut entries = select_files(&paths, None).unwrap();
        // Drop the sealed note: the manifest still lists it.
        entries.retain(|e| e.relative_path != "nodes/a/notes.env");
        let err = restore_bundle(
            &pack(&entries),
            &dir.path().join("out"),
            &dir.path().join("st"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("incomplete"), "{err}");
        assert!(!dir.path().join("out").exists());
    }

    #[test]
    fn restore_refuses_something_that_is_not_a_vault() {
        let dir = tempfile::tempdir().unwrap();
        let err = restore_bundle(
            &bundle_of(&[("config.json", b"{}")]),
            &dir.path().join("out"),
            &dir.path().join("st"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not a vault archive"), "{err}");
    }

    #[test]
    fn a_version_one_archive_restores_and_says_it_is_not_complete() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let report = restore_bundle(
            &bundle_of(&[
                ("registry.json", b"r"),
                ("registry.sig", b"s"),
                ("keys/root.wrap.pass", b"k"),
                ("nodes/a/entries/e.env", b"e"),
            ]),
            &out,
            &dir.path().join("st"),
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.counter, CounterOutcome::NotInArchive);
        assert!(out.join("nodes/a/entries/e.env").is_file());
    }

    /// ADR-148 amendment (K-23 (e)): the archive carries a restore ticket and never the counter; a restore into a
    /// state directory with no counter writes the one-shot marker, one with a counter keeps it and writes none,
    /// and a damaged ticket restores nothing.
    #[test]
    fn a_ticketed_archive_leaves_the_counter_behind_and_restores_a_marker_only_where_none_is() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        populate(&paths);
        let registry = br#"{"format":2,"vaultGeneration":4}"#;
        atomic::write(&paths.registry(), registry).unwrap();
        let rk = [5u8; 32];
        let bundle = create_backup_with_ticket(&paths, &rk, 1_800_000_000).unwrap();
        let unpacked = unpack(&bundle).unwrap();
        let got = names(&unpacked);
        assert!(got.contains(&"_state/restore.ticket"), "{got:?}");
        assert!(
            !got.iter().any(|p| p.ends_with("vaultGeneration.counter")),
            "{got:?}"
        );

        // No counter in the state directory: the marker, which the first unlock will accept.
        let state = dir.path().join("state");
        let out = dir.path().join("out");
        let report = restore_bundle(&bundle, &out, &state).unwrap();
        assert!(report.complete);
        assert_eq!(report.counter, CounterOutcome::AcceptMarker);
        assert!(!state.join("vaultGeneration.counter").exists());
        let marker = fs::read(crate::restore_marker::marker_path(&state)).unwrap();
        assert_eq!(
            crate::restore_marker::check_marker(&rk, &marker, registry, 4),
            Ok(4)
        );

        // A counter already there: kept, and no marker.
        let kept = dir.path().join("kept-state");
        atomic::write(&kept.join("vaultGeneration.counter"), b"newer").unwrap();
        let report = restore_bundle(&bundle, &dir.path().join("out2"), &kept).unwrap();
        assert_eq!(report.counter, CounterOutcome::KeptExisting);
        assert!(!crate::restore_marker::marker_path(&kept).exists());

        // A damaged ticket: nothing restored.
        let mut entries = unpack(&bundle).unwrap();
        for e in &mut entries {
            if e.relative_path == "_state/restore.ticket" {
                e.contents = b"not a ticket".to_vec();
            }
        }
        let target = dir.path().join("out3");
        let err = restore_bundle(&pack(&entries), &target, &dir.path().join("s3")).unwrap_err();
        assert!(err.to_string().contains("restore ticket"), "{err}");
        assert!(!target.exists());

        // A vault whose registry carries no generation is not backed up with a ticket.
        atomic::write(&paths.registry(), b"{}").unwrap();
        assert!(create_backup_with_ticket(&paths, &rk, 1).is_err());
    }
}
