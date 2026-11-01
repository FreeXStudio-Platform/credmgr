//! Every failure mode this crate can hand back. Per `05_THREAT_MODEL.md` and
//! `02_ARCHITECTURE.md §7a`, a storage-integrity failure must **fail closed
//! and name itself** — never a silent fallback, never a bare `io::Error`
//! that loses *which* file and *which* check failed.

use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum StoreError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// `registry.sig` does not verify against `registry.json`'s bytes.
    RegistryTampered { path: PathBuf },
    /// A node's `manifest.json` hmac field does not verify.
    ManifestTampered { node_id: String },
    /// The registry's recorded `manifestHmac`/`manifestGeneration` for a node
    /// disagrees with that node's own manifest file (`04 §6a` cross-binding).
    ManifestRegistryMismatch {
        node_id: String,
        detail: &'static str,
    },
    /// The registry's `vaultGeneration` is lower than the last value recorded
    /// in the external counter — a rolled-back registry (`04 §6a`, ADR-024).
    GenerationRolledBack { on_disk: u64, external: u64 },
    /// The generation counter file itself failed its own HMAC.
    GenerationCounterTampered { path: PathBuf },
    /// The audit log's hash chain is broken at the given zero-indexed line.
    AuditChainBroken { path: PathBuf, at_line: usize },
    /// A caller's mutating request carried a stale generation for this node
    /// (`03 §8`'s optimistic-concurrency token).
    Conflict { node_id: String, current: u64 },
    /// Attempted a locked-vault `update`; only `create` is permitted while
    /// locked (ADR-023).
    VaultLocked,
    /// No sealed archive exists for this node (never sealed, already
    /// restored, or already purged past the 7-day window).
    ArchiveNotFound { node_id: String },
    /// The archive exists but its 7-day recovery window has passed
    /// (ADR-027) — restorable only via presence + fresh code, from the
    /// orphan cold copy, not from this archive.
    ArchiveExpired { node_id: String, sealed_at: i64 },
    /// The archive's own `meta.json` failed its HMAC — tampering with
    /// `sealed_at` could otherwise make an expired archive look fresh.
    ArchiveMetaTampered { node_id: String },
    /// No soft-deleted archive exists for this entry (never removed,
    /// already restored, or already purged past the 7-day window) — the
    /// per-entry analogue of `ArchiveNotFound` (ADR-048).
    EntryArchiveNotFound { node_id: String, entry_id: String },
    /// The entry's soft-delete archive exists but its 7-day recovery window
    /// has passed (ADR-048) — permanently gone, unlike a sealed node there
    /// is no cold orphan copy to fall back to; removal was final at day 7.
    EntryArchiveExpired {
        node_id: String,
        entry_id: String,
        removed_at: i64,
    },
    /// The removed entry's own signed record failed its HMAC — tampering
    /// with `removedAt` could otherwise make an expired removal look fresh.
    EntryArchiveMetaTampered { node_id: String, entry_id: String },
    /// ADR-079: `registry.json` authenticates but declares a `format` newer than
    /// this build understands. Refused whole, not best-effort-read: an older
    /// build would silently drop what it cannot see (the seal records) on its
    /// next write.
    RegistryFormatTooNew { found: u32, supported: u32 },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            StoreError::Json { path, source } => {
                write!(f, "{}: malformed JSON: {source}", path.display())
            }
            StoreError::RegistryTampered { path } => {
                write!(f, "{}: registry.sig does not verify — refusing to open the vault. Run `credmgr doctor --rebuild-registry`.", path.display())
            }
            StoreError::ManifestTampered { node_id } => {
                write!(f, "node {node_id}: manifest.json hmac does not verify — refusing to trust its contents")
            }
            StoreError::ManifestRegistryMismatch { node_id, detail } => {
                write!(f, "node {node_id}: registry and manifest disagree ({detail})")
            }
            StoreError::GenerationRolledBack { on_disk, external } => write!(
                f,
                "registry.json generation {on_disk} is behind the last known generation {external} — this looks like a rolled-back registry. Refusing to open. Run `credmgr doctor --rebuild-registry`."
            ),
            StoreError::GenerationCounterTampered { path } => {
                write!(f, "{}: generation counter hmac does not verify", path.display())
            }
            StoreError::AuditChainBroken { path, at_line } => {
                write!(f, "{}: audit chain broken at line {at_line}", path.display())
            }
            StoreError::Conflict { node_id, current } => {
                write!(f, "node {node_id}: conflict — current generation is {current}")
            }
            StoreError::VaultLocked => write!(f, "vault is locked; only `create` is permitted"),
            StoreError::ArchiveNotFound { node_id } => {
                write!(f, "node {node_id}: no sealed archive found")
            }
            StoreError::ArchiveExpired { node_id, sealed_at } => write!(
                f,
                "node {node_id}: sealed at {sealed_at}, the 7-day recovery window has passed — restore via presence + a fresh code from the orphan node instead"
            ),
            StoreError::ArchiveMetaTampered { node_id } => {
                write!(f, "node {node_id}: archive metadata hmac does not verify")
            }
            StoreError::EntryArchiveNotFound { node_id, entry_id } => {
                write!(f, "node {node_id}: entry {entry_id}: no removed-entry archive found")
            }
            StoreError::EntryArchiveExpired {
                node_id,
                entry_id,
                removed_at,
            } => write!(
                f,
                "node {node_id}: entry {entry_id}: removed at {removed_at}, the 7-day recovery window has passed — this removal is final"
            ),
            StoreError::EntryArchiveMetaTampered { node_id, entry_id } => {
                write!(f, "node {node_id}: entry {entry_id}: removed-entry metadata hmac does not verify")
            }
            StoreError::RegistryFormatTooNew { found, supported } => write!(
                f,
                "registry.json is format {found}, but this build of CredMgr understands up to \
                 format {supported} — refusing to open a vault written by a newer CredMgr. \
                 Update CredMgr; do not edit the file."
            ),
        }
    }
}

impl std::error::Error for StoreError {}

pub type Result<T> = std::result::Result<T, StoreError>;
