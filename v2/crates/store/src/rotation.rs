//! Crash-safe root-key rotation — stage, commit, roll forward (ADR-076).
//!
//! `04 §6`: rotating the root key means a new RK, every node key re-wrapped
//! under it, the passphrase and recovery-code wraps rewritten, and every file
//! that is HMAC'd or sealed under the old RK signed again. That is a dozen or
//! more files in two directories (the vault and the state directory that holds
//! the rollback counter), and a filesystem offers no transaction across them.
//! A crash in the middle of replacing them one by one would leave some under
//! the old key and some under the new — a vault that opens with **neither**.
//!
//! The rule this module exists to keep: **at every instant, and after a crash
//! at any instant, the vault opens with the old root key or with the new one,
//! never with neither.** It does that with a journal and one commit point:
//!
//! 1. **Stage.** Every replacement file is written, atomically and fsynced,
//!    under `<vault>/rotation-pending/{vault,state}/…`. No live file is touched.
//!    A crash here leaves a stale stage and an untouched vault.
//! 2. **Commit.** One atomic write of `rotation-pending/COMMIT` — the ordered
//!    list of files with the SHA-256 of each — after the whole staged tree has
//!    been fsynced. **This write is the point of no return.** A crash before
//!    it means the old root key; a crash after it means the new one.
//! 3. **Roll forward.** First every file is *checked* — a staged copy against
//!    its recorded digest, and a staged copy that is already gone against its
//!    **live twin's** digest (it must be there, already moved, with exactly the
//!    committed bytes) — and only if all of them check out is the first one
//!    moved. Then each staged file is renamed over its live twin (fsync both
//!    directories). The move is idempotent — a file already in place is skipped
//!    — so [`recover`] can finish a roll-forward that any number of crashes
//!    interrupted. When the last file is in place `COMMIT` is removed and the
//!    stage deleted.
//!
//! [`recover`] is **key-free**: it renames files, it never reads a secret, so
//! it can and must run *before* anything tries to open the vault. Nothing is
//! moved on a stage that fails its checks: a torn, tampered or missing staged
//! file is refused up front, so the vault is left wholly in its old state
//! rather than half-applied.
//!
//! **Exclusion is the caller's job.** Everything here assumes it is the only
//! thing touching `rotation-pending/` and the files it names. A second process
//! that ran [`recover`] while a first was still *staging* would delete the
//! first's work (an uncommitted stage looks exactly like a crashed one). The
//! broker therefore holds an exclusive per-vault lock across `recover` and
//! across a whole rotation (`credmgr-brokerd`'s `VaultLock`; this crate forbids
//! `unsafe`, which `flock(2)` needs). The checks above are the second line:
//! with the lock bypassed, a stage that lost files is refused, not half-applied.
//!
//! What this module deliberately does not do: keep the old files. A rotation
//! that retained the old wrapped node keys "for rollback" would leave exactly
//! what the rotation is meant to retire sitting on the disk. The price is that
//! after the commit there is no going back — which is also what makes the
//! commit point unambiguous.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use credmgr_core::cold;
use credmgr_core::keys::{rewrap_node_key, WrappedNodeKey};

use crate::error::{Result, StoreError};
use crate::paths::VaultPaths;
use crate::{archive, atomic, audit, entry_archive, hexutil, manifest, rotation_history};

const COMMIT_FILE: &str = "COMMIT";
const COMMIT_VERSION: u64 = 1;

/// Which directory a staged file's path is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Base {
    /// The vault directory (`VaultPaths::root`).
    Vault,
    /// The state directory outside the vault — where the rollback counter lives.
    State,
}

impl Base {
    fn dir_name(self) -> &'static str {
        match self {
            Base::Vault => "vault",
            Base::State => "state",
        }
    }
}

/// One entry of the commit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StagedFile {
    base: Base,
    /// `/`-separated, relative, no `..` — validated on write and on read.
    rel: String,
    /// Lower-case hex SHA-256 of the staged bytes.
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CommitDoc {
    v: u64,
    files: Vec<StagedFile>,
}

/// What [`recover`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// No stage directory: the vault is in whatever state its last complete
    /// write left it.
    Nothing,
    /// A stage directory existed with **no commit record**, and was deleted.
    /// That is one of two things, and the files left on disk cannot tell which:
    /// the rotation never reached its point of no return (the vault is exactly
    /// as it was — the **old** root key), *or* it had completed and a crash
    /// came after the commit record was retired but before the stage directory
    /// was removed (the **new** root key is in force). Deleting the stage
    /// changes no live file either way; the vault opens with whichever root key
    /// the passphrase wrap yields. A caller must not say which.
    DiscardedStage,
    /// A committed rotation was finished (or found already finished): the
    /// vault opens with the **new** root key. `files` is how many staged
    /// files this call moved into place (0 when only cleanup was left).
    RolledForward { files: usize },
}

fn io_err(path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn invalid(path: &Path, what: &str) -> StoreError {
    io_err(
        path,
        std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string()),
    )
}

fn json_err(path: &Path, source: serde_json::Error) -> StoreError {
    StoreError::Json {
        path: path.to_path_buf(),
        source,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hexutil::encode(&Sha256::digest(bytes))
}

fn commit_path(paths: &VaultPaths) -> PathBuf {
    paths.rotation_stage().join(COMMIT_FILE)
}

/// `rel` as a `/`-separated string, refusing anything that is not a plain
/// descent (`..`, an absolute path, an empty path).
fn rel_string(rel: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| invalid(rel, "a staged path is not valid UTF-8"))?
                    .to_string(),
            ),
            _ => return Err(invalid(rel, "a staged path must be a plain relative path")),
        }
    }
    if parts.is_empty() {
        return Err(invalid(rel, "a staged path must not be empty"));
    }
    Ok(parts.join("/"))
}

fn rel_path(rel: &str) -> Result<PathBuf> {
    let path = PathBuf::from(rel);
    rel_string(&path)?;
    Ok(path)
}

/// A rotation being prepared. Nothing a `RotationStage` does touches a live
/// file; the first live file changes only inside [`roll_forward`], after
/// [`RotationStage::commit`] has made the whole set binding.
pub struct RotationStage {
    stage_root: PathBuf,
    vault_root: PathBuf,
    state_dir: PathBuf,
    files: Vec<StagedFile>,
    /// Crash-injection seam: refuse to stage the file after this many.
    #[cfg(any(test, feature = "test-utils"))]
    crash_after_staged: Option<usize>,
    /// Concurrency seam: call this (once) when this many files are staged and
    /// the next is about to be — the process "frozen" in the middle of staging.
    #[cfg(any(test, feature = "test-utils"))]
    pause_after_staged: Option<(usize, std::sync::Arc<dyn Fn() + Send + Sync>)>,
}

impl RotationStage {
    /// Open a fresh stage. Refuses while a **committed** rotation is waiting
    /// to be finished — [`recover`] that first — and deletes a stale
    /// *uncommitted* stage (a crash before an earlier commit), which by
    /// definition never changed anything.
    pub fn begin(paths: &VaultPaths, state_dir: &Path) -> Result<RotationStage> {
        let stage_root = paths.rotation_stage();
        if fs::symlink_metadata(commit_path(paths)).is_ok() {
            return Err(invalid(
                &stage_root,
                "a committed root-key rotation is waiting to be completed — unlock to finish it first",
            ));
        }
        if fs::symlink_metadata(&stage_root).is_ok() {
            fs::remove_dir_all(&stage_root).map_err(|e| io_err(&stage_root, e))?;
        }
        atomic::ensure_dir(&stage_root)?;
        Ok(RotationStage {
            stage_root,
            vault_root: paths.root().to_path_buf(),
            state_dir: state_dir.to_path_buf(),
            files: Vec::new(),
            #[cfg(any(test, feature = "test-utils"))]
            crash_after_staged: None,
            #[cfg(any(test, feature = "test-utils"))]
            pause_after_staged: None,
        })
    }

    /// Run `hook` — once — at the moment `n` files are staged and the next one
    /// is about to be: the rotation "frozen" half-way through its staging while
    /// the test does something else to the vault (a second process starting up
    /// and recovering, say) and then lets it carry on. Test seam for the
    /// concurrency suites.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn pause_after_staged(&mut self, n: usize, hook: std::sync::Arc<dyn Fn() + Send + Sync>) {
        self.pause_after_staged = Some((n, hook));
    }

    /// Make the stage "die" — every further `stage_*` call fails — once `n`
    /// files are on disk: a crash in the middle of staging, made on purpose.
    /// `n == 0` is a crash after the stage directory was created and before
    /// anything was written into it. Test seam for the crash-injection suites.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn crash_after_staged(&mut self, n: usize) {
        self.crash_after_staged = Some(n);
    }

    /// Stage `bytes` as the replacement for the live vault file `live`
    /// (which may not exist yet).
    pub fn stage_vault_file(&mut self, live: &Path, bytes: &[u8]) -> Result<()> {
        self.stage(Base::Vault, live, bytes)
    }

    /// Stage `bytes` as the replacement for the live state-directory file `live`.
    pub fn stage_state_file(&mut self, live: &Path, bytes: &[u8]) -> Result<()> {
        self.stage(Base::State, live, bytes)
    }

    /// How many files are staged so far.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    fn stage(&mut self, base: Base, live: &Path, bytes: &[u8]) -> Result<()> {
        #[cfg(any(test, feature = "test-utils"))]
        if self
            .crash_after_staged
            .is_some_and(|limit| self.files.len() >= limit)
        {
            return Err(io_err(
                &self.stage_root,
                std::io::Error::other("injected crash while staging"),
            ));
        }
        #[cfg(any(test, feature = "test-utils"))]
        if self
            .pause_after_staged
            .as_ref()
            .is_some_and(|(n, _)| *n == self.files.len())
        {
            if let Some((_, hook)) = self.pause_after_staged.take() {
                hook();
            }
        }
        let root = match base {
            Base::Vault => &self.vault_root,
            Base::State => &self.state_dir,
        };
        let rel = live
            .strip_prefix(root)
            .map_err(|_| invalid(live, "a staged file must live under its base directory"))?;
        let rel_str = rel_string(rel)?;
        if self
            .files
            .iter()
            .any(|f| f.base == base && f.rel == rel_str)
        {
            return Err(invalid(live, "a file is staged twice in one rotation"));
        }
        let staged = self.stage_root.join(base.dir_name()).join(rel);
        atomic::write(&staged, bytes)?;
        self.files.push(StagedFile {
            base,
            rel: rel_str,
            sha256: sha256_hex(bytes),
        });
        Ok(())
    }

    /// Make the staged set binding. Fsyncs the whole stage tree, then writes
    /// the commit record atomically — **after this returns the rotation
    /// cannot be abandoned, only finished.** Returns the number of files.
    pub fn commit(self) -> Result<usize> {
        atomic::sync_tree(&self.stage_root)?;
        let count = self.files.len();
        let doc = CommitDoc {
            v: COMMIT_VERSION,
            files: self.files,
        };
        let path = self.stage_root.join(COMMIT_FILE);
        let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| json_err(&path, e))?;
        atomic::write(&path, &bytes)?;
        Ok(count)
    }
}

/// Finish whatever an interrupted rotation left behind. Run it **before** any
/// code reads a root wrap, a node key, the registry or a manifest — at every
/// unlock, and when the daemon starts. See [`Recovery`] for the three outcomes.
///
/// Fails closed: a commit record that does not parse, a staged file whose
/// digest disagrees with it (or one that is gone without its live twin carrying
/// the committed bytes), or a filesystem error leaves the stage where it is and
/// returns the error — before any file has moved, for the first three — so the
/// next call retries from the same point.
///
/// **Not safe against a concurrent rotation.** The caller must hold the
/// per-vault lock (see the module docs): an uncommitted stage that another
/// process is still writing looks, to this function, like a crashed one.
pub fn recover(paths: &VaultPaths, state_dir: &Path) -> Result<Recovery> {
    let stage_root = paths.rotation_stage();
    match fs::symlink_metadata(&stage_root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Recovery::Nothing),
        Err(e) => return Err(io_err(&stage_root, e)),
        Ok(meta) if !meta.file_type().is_dir() => {
            return Err(invalid(
                &stage_root,
                "the rotation stage is not a directory",
            ))
        }
        Ok(_) => {}
    }
    if fs::symlink_metadata(commit_path(paths)).is_err() {
        // No commit record: either never committed (the live files were never
        // touched) or finished and cut off before the stage was removed (the
        // live files are final). Neither needs the stage. Drop it.
        fs::remove_dir_all(&stage_root).map_err(|e| io_err(&stage_root, e))?;
        if let Some(parent) = stage_root.parent() {
            atomic::sync_dir(parent)?;
        }
        return Ok(Recovery::DiscardedStage);
    }
    let files = roll_forward_n(paths, state_dir, None)?;
    Ok(Recovery::RolledForward { files })
}

/// Apply a committed rotation: move every staged file over its live twin,
/// then remove the commit record and the stage. Idempotent — safe to call
/// again after any interruption. `Ok(0)` when no commit record exists.
pub fn roll_forward(paths: &VaultPaths, state_dir: &Path) -> Result<usize> {
    roll_forward_n(paths, state_dir, None)
}

/// [`roll_forward`] that stops after moving `n` files and **leaves the commit
/// record in place** — a crash in the middle of the roll-forward, made on
/// purpose. `n == 0` is "crashed right after the commit record"; `n` equal to
/// the number of staged files is "every file moved, the commit record not yet
/// retired" — the last instant at which a crash still has anything to finish.
/// Test seam for the crash-injection suites (this module's and
/// `credmgr-brokerd`'s `rotate_root.rs`); a real recovery never calls it.
#[cfg(any(test, feature = "test-utils"))]
pub fn roll_forward_first(paths: &VaultPaths, state_dir: &Path, n: usize) -> Result<usize> {
    roll_forward_n(paths, state_dir, Some(n))
}

/// Whether a commit record exists — i.e. whether a rotation is **binding**
/// (its new root key is the one that will open this vault once the
/// roll-forward finishes). The single fact [`recover`] branches on, exposed
/// so a caller whose own `commit` call reported an error can tell "the record
/// never landed" from "it landed and only the directory sync failed".
pub fn is_committed(paths: &VaultPaths) -> bool {
    fs::symlink_metadata(commit_path(paths)).is_ok()
}

/// Make sure a commit record that is already on disk is also **durable**: fsync
/// the stage directory it was renamed into. For a caller whose own
/// [`RotationStage::commit`] reported an error after the record landed (the
/// rename succeeded, the directory sync did not): a live file must not be
/// replaced until the record that justifies it can survive a power loss, or a
/// crash could keep some moved files and lose the record that says to finish.
/// `Err` means durability is unproven — leave the roll-forward to [`recover`].
pub fn make_commit_durable(paths: &VaultPaths) -> Result<()> {
    let stage_root = paths.rotation_stage();
    atomic::sync_dir(&stage_root)?;
    if let Some(parent) = stage_root.parent() {
        atomic::sync_dir(parent)?;
    }
    Ok(())
}

/// `path` must be a regular file whose SHA-256 is `file.sha256`.
fn check_digest(path: &Path, file: &StagedFile, what: &str) -> Result<()> {
    let bytes = atomic::read(path)?;
    if sha256_hex(&bytes) != file.sha256 {
        return Err(invalid(path, what));
    }
    Ok(())
}

fn roll_forward_n(
    paths: &VaultPaths,
    state_dir: &Path,
    stop_after: Option<usize>,
) -> Result<usize> {
    let stage_root = paths.rotation_stage();
    let commit = commit_path(paths);
    let bytes = match atomic::read(&commit) {
        Ok(b) => b,
        Err(StoreError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(0)
        }
        Err(e) => return Err(e),
    };
    let doc: CommitDoc = serde_json::from_slice(&bytes).map_err(|e| json_err(&commit, e))?;
    if doc.v != COMMIT_VERSION {
        return Err(invalid(&commit, "unknown rotation commit version"));
    }
    // Validate every path before the first byte moves: a commit record with
    // one bad entry must not be half-applied.
    let mut plan = Vec::with_capacity(doc.files.len());
    for file in &doc.files {
        let rel = rel_path(&file.rel)?;
        let root = match file.base {
            Base::Vault => paths.root(),
            Base::State => state_dir,
        };
        plan.push((
            file,
            stage_root.join(file.base.dir_name()).join(&rel),
            root.join(&rel),
        ));
    }

    // Pass 1 — check **everything** before moving **anything**. A stage that
    // fails any check leaves the vault wholly as it was: a torn or tampered
    // file at position k must not leave the k files before it already
    // replaced (a vault that then opens with neither root key).
    //
    // A staged copy must carry its recorded digest. A staged copy that is
    // *gone* is only acceptable when an earlier, interrupted pass moved it: its
    // live twin must then exist with exactly the committed bytes. "Gone" with
    // anything else at the live path means the stage lost work it did not
    // finish moving (a second process deleted it, a disk lost it) — and
    // treating that as "already moved" would retire the commit record over a
    // vault that mixes the old and new root keys.
    let mut to_move = Vec::with_capacity(plan.len());
    for (file, staged, live) in plan {
        match fs::symlink_metadata(&staged) {
            Ok(meta) if meta.file_type().is_file() => {
                check_digest(&staged, file, "a staged file does not match the rotation's commit record — refusing to move it into place")?;
                to_move.push((file, staged, live));
            }
            Ok(_) => return Err(invalid(&staged, "a staged path is not a regular file")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let already_in_place = atomic::read(&live)
                    .map(|bytes| sha256_hex(&bytes) == file.sha256)
                    .unwrap_or(false);
                if !already_in_place {
                    return Err(invalid(
                        &live,
                        "a staged file is gone and its live twin does not carry the committed content — the rotation cannot be completed, and nothing has been moved",
                    ));
                }
            }
            Err(e) => return Err(io_err(&staged, e)),
        }
    }

    // Pass 2 — move. The digest is re-read immediately before each rename, so
    // a stage that changes underneath this call is still refused per file.
    let mut moved = 0usize;
    for (file, staged, live) in to_move {
        if stop_after.is_some_and(|limit| moved >= limit) {
            return Ok(moved);
        }
        check_digest(
            &staged,
            file,
            "a staged file changed while the rotation was being applied — refusing to move it into place",
        )?;
        atomic::move_file(&staged, &live)?;
        moved += 1;
    }

    // The seam's last cut: every file moved, the record not yet retired.
    if stop_after.is_some_and(|limit| moved >= limit) {
        return Ok(moved);
    }

    // Every staged file is in place. Retire the record first — its absence is
    // what says "done" — then the (now empty) stage, best effort: a leftover
    // directory with no commit record is simply discarded by the next call.
    atomic::remove_durable(&commit)?;
    let _ = fs::remove_dir_all(&stage_root);
    if let Some(parent) = stage_root.parent() {
        let _ = atomic::sync_dir(parent);
    }
    Ok(moved)
}

// ---------------------------------------------------------------------------
// Re-signing the artefacts that are not part of the live vault state.
// ---------------------------------------------------------------------------

/// One artefact re-signed (or re-wrapped) under the new root key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resigned {
    /// `"audit-tip"`, `"seal-archive"`, `"seal-archive-key"`,
    /// `"seal-archive-manifest"`, `"orphan-cold-key"`, `"removed-entry"` or
    /// `"entry-history"`.
    pub kind: &'static str,
    pub id: String,
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

/// An artefact that did **not** verify under the old root key and was
/// therefore left exactly as it is. Re-signing it would stamp a tamper or a
/// truncation as authentic; left alone it keeps failing verification — the
/// evidence the rotation must not destroy — for as long as nothing is appended
/// to it (an audit append signs a month's tip over the log as it stands, so a
/// month that is still being written to verifies again after the next record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub kind: &'static str,
    pub id: String,
    pub reason: String,
}

/// Everything beyond the live registry, manifests and node keys that is
/// signed or wrapped under the root key.
#[derive(Debug, Default)]
pub struct ArtifactPlan {
    pub resigned: Vec<Resigned>,
    pub skipped: Vec<Skipped>,
}

/// `(name, path)` of every real subdirectory of `dir`, sorted by name. A
/// missing `dir` is empty; a symlink is not followed.
fn child_dirs(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(io_err(dir, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let path = entry.path();
        let is_dir = fs::symlink_metadata(&path)
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false);
        if let (true, Some(name)) = (is_dir, entry.file_name().to_str()) {
            out.push((name.to_string(), path));
        }
    }
    out.sort();
    Ok(out)
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

/// The fail-closed half of the closed set of root-bound files: everything
/// under `keys/` that this build does **not** know how to re-wrap.
///
/// A rotation replaces exactly the key material it was written to know about —
/// `root.wrap.pass`, `root.wrap.recovery`, `nodes/<id>.key` and (ADR-079) the
/// one file `cold/orphan.key`, which [`plan_resigned_artifacts`] re-seals. A
/// file here it does not recognise (the hardware-keystore wrap
/// `root.wrap.se`, any other file under `cold/`, whatever a later build adds)
/// is, until proven otherwise, wrapped under the *old* root key — and a
/// rotation that carried on would leave it opening nothing. So the caller refuses to rotate while
/// this list is non-empty: a rotation that is refused changes nothing; one that
/// strands a key cannot be undone. Dot-files (a Finder's `.DS_Store`, an
/// editor's swap file) are ignored.
pub fn unrecognised_key_files(paths: &VaultPaths) -> Result<Vec<PathBuf>> {
    fn visible(name: &std::ffi::OsStr) -> Option<&str> {
        name.to_str().filter(|n| !n.starts_with('.'))
    }
    let keys = paths.keys_dir();
    let mut found = Vec::new();
    let entries = match fs::read_dir(&keys) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(e) => return Err(io_err(&keys, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| io_err(&keys, e))?;
        let name = entry.file_name();
        let path = entry.path();
        let Some(name) = visible(&name) else {
            if name.to_str().is_none() {
                found.push(path);
            }
            continue;
        };
        match name {
            "root.wrap.pass" | "root.wrap.recovery" if is_regular_file(&path) => {}
            "nodes" if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_dir()) => {
                for node in fs::read_dir(&path).map_err(|e| io_err(&path, e))? {
                    let node = node.map_err(|e| io_err(&path, e))?;
                    let file = node.file_name();
                    let Some(file) = visible(&file) else {
                        if file.to_str().is_none() {
                            found.push(node.path());
                        }
                        continue;
                    };
                    if !(file.ends_with(".key") && is_regular_file(&node.path())) {
                        found.push(node.path());
                    }
                }
            }
            "cold" if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_dir()) => {
                for cold_file in fs::read_dir(&path).map_err(|e| io_err(&path, e))? {
                    let cold_file = cold_file.map_err(|e| io_err(&path, e))?;
                    let file = cold_file.file_name();
                    let Some(file) = visible(&file) else {
                        if file.to_str().is_none() {
                            found.push(cold_file.path());
                        }
                        continue;
                    };
                    if !(file == "orphan.key" && is_regular_file(&cold_file.path())) {
                        found.push(cold_file.path());
                    }
                }
            }
            _ => found.push(path),
        }
    }
    found.sort();
    Ok(found)
}

/// Plan the re-signing of every audit tip, sealed-node archive, removed-entry
/// record and rotation snapshot (ADR-076). Each is verified under `old_root`
/// first; one that does not verify is reported in [`ArtifactPlan::skipped`]
/// and left untouched. Reads only — nothing is written.
pub fn plan_resigned_artifacts(
    paths: &VaultPaths,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> Result<ArtifactPlan> {
    let mut plan = ArtifactPlan::default();

    // Audit tips.
    for year_month in audit::year_months(paths)? {
        match audit::resigned_tip(paths, old_root, new_root, &year_month) {
            Ok(bytes) => plan.resigned.push(Resigned {
                kind: "audit-tip",
                path: audit::tip_file(paths, &year_month),
                id: year_month,
                bytes,
            }),
            Err(e) => plan.skipped.push(Skipped {
                kind: "audit-tip",
                id: year_month,
                reason: e.to_string(),
            }),
        }
    }

    let archive_root = paths.archive_root();

    // Sealed-node archives: the signed metadata, the retained wrapped node key
    // (which `node.restore` moves back to `keys/nodes/` and must still open
    // under the new root), and the retained manifest.
    for (id, dir) in child_dirs(&archive_root)? {
        if id == "removed-entries" || id == "entry-history" {
            continue;
        }
        match archive::resigned_meta(&dir, old_root, new_root, &id) {
            Ok(bytes) => plan.resigned.push(Resigned {
                kind: "seal-archive",
                id: id.clone(),
                path: archive::meta_file(&dir),
                bytes,
            }),
            Err(e) => {
                plan.skipped.push(Skipped {
                    kind: "seal-archive",
                    id,
                    reason: e.to_string(),
                });
                continue;
            }
        }
        let key_path = dir.join("node.key");
        if is_regular_file(&key_path) {
            let rewrapped = atomic::read(&key_path).and_then(|bytes| {
                WrappedNodeKey::from_bytes(&bytes)
                    .and_then(|w| rewrap_node_key(old_root, new_root, &id, &w))
                    .map(|w| w.to_bytes())
                    .map_err(|_| {
                        invalid(
                            &key_path,
                            "the retained node key does not open under the current root key",
                        )
                    })
            });
            match rewrapped {
                Ok(bytes) => plan.resigned.push(Resigned {
                    kind: "seal-archive-key",
                    id: id.clone(),
                    path: key_path,
                    bytes,
                }),
                Err(e) => plan.skipped.push(Skipped {
                    kind: "seal-archive-key",
                    id: id.clone(),
                    reason: e.to_string(),
                }),
            }
        }
        let manifest_path = dir.join("node").join("manifest.json");
        if is_regular_file(&manifest_path) {
            match manifest::resigned_at(&manifest_path, &id, old_root, new_root) {
                Ok(bytes) => plan.resigned.push(Resigned {
                    kind: "seal-archive-manifest",
                    id: id.clone(),
                    path: manifest_path,
                    bytes,
                }),
                Err(e) => plan.skipped.push(Skipped {
                    kind: "seal-archive-manifest",
                    id: id.clone(),
                    reason: e.to_string(),
                }),
            }
        }
    }

    // ADR-079: the orphan cold key. Its keypair is unchanged by a rotation (every
    // orphan envelope still opens); only the blob that protects the private half
    // moves to the new root. A half-rotated cold key would strand every sealed
    // entry, so it is staged with everything else and replaced by the same
    // commit point — and one that does not open under the old root key is left
    // exactly as it is and reported, never re-stamped.
    let cold_path = paths.orphan_key();
    if is_regular_file(&cold_path) {
        let resealed = atomic::read(&cold_path).and_then(|bytes| {
            cold::reseal_orphan_cold(old_root, new_root, &bytes).map_err(|_| {
                invalid(
                    &cold_path,
                    "the orphan cold key does not open under the current root key",
                )
            })
        });
        match resealed {
            Ok(bytes) => plan.resigned.push(Resigned {
                kind: "orphan-cold-key",
                id: "orphan".to_string(),
                path: cold_path,
                bytes,
            }),
            Err(e) => plan.skipped.push(Skipped {
                kind: "orphan-cold-key",
                id: "orphan".to_string(),
                reason: e.to_string(),
            }),
        }
    }

    // Soft-deleted entries: `archive/removed-entries/<node>/<entry>/removed.json`.
    for (node_id, node_dir) in child_dirs(&archive_root.join("removed-entries"))? {
        for (entry_id, _) in child_dirs(&node_dir)? {
            if !is_regular_file(&paths.removed_entry_meta(&node_id, &entry_id)) {
                continue;
            }
            let label = format!("{node_id}/{entry_id}");
            match entry_archive::resigned_meta(paths, old_root, new_root, &node_id, &entry_id) {
                Ok(bytes) => plan.resigned.push(Resigned {
                    kind: "removed-entry",
                    id: label,
                    path: paths.removed_entry_meta(&node_id, &entry_id),
                    bytes,
                }),
                Err(e) => plan.skipped.push(Skipped {
                    kind: "removed-entry",
                    id: label,
                    reason: e.to_string(),
                }),
            }
        }
    }

    // Rotation snapshots: `archive/entry-history/<node>/<entry>/<generation>.json`.
    for (node_id, node_dir) in child_dirs(&archive_root.join("entry-history"))? {
        for (entry_id, entry_dir) in child_dirs(&node_dir)? {
            let entries = match fs::read_dir(&entry_dir) {
                Ok(e) => e,
                Err(e) => return Err(io_err(&entry_dir, e)),
            };
            let mut generations: Vec<u64> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_str()?.to_string();
                    name.strip_suffix(".json")?.parse::<u64>().ok()
                })
                .collect();
            generations.sort_unstable();
            for generation in generations {
                let path = paths.entry_history_meta(&node_id, &entry_id, generation);
                if !is_regular_file(&path) {
                    continue;
                }
                let label = format!("{node_id}/{entry_id}/{generation}");
                match rotation_history::resigned(
                    paths, old_root, new_root, &node_id, &entry_id, generation,
                ) {
                    Ok(bytes) => plan.resigned.push(Resigned {
                        kind: "entry-history",
                        id: label,
                        path,
                        bytes,
                    }),
                    Err(e) => plan.skipped.push(Skipped {
                        kind: "entry-history",
                        id: label,
                        reason: e.to_string(),
                    }),
                }
            }
        }
    }

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        paths: VaultPaths,
        state: PathBuf,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        let state = dir.path().join("state");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&state).unwrap();
        Fixture {
            paths: VaultPaths::new(vault),
            state,
            _dir: dir,
        }
    }

    fn stage_three(fx: &Fixture) -> RotationStage {
        let mut stage = RotationStage::begin(&fx.paths, &fx.state).unwrap();
        stage
            .stage_vault_file(&fx.paths.root_wrap_recovery(), b"new-recovery")
            .unwrap();
        stage
            .stage_vault_file(&fx.paths.node_key("global"), b"new-node-key")
            .unwrap();
        stage
            .stage_state_file(&fx.state.join("vaultGeneration.counter"), b"new-counter")
            .unwrap();
        stage
    }

    fn seed_old(fx: &Fixture) {
        atomic::write(&fx.paths.root_wrap_recovery(), b"old-recovery").unwrap();
        atomic::write(&fx.paths.node_key("global"), b"old-node-key").unwrap();
        atomic::write(&fx.state.join("vaultGeneration.counter"), b"old-counter").unwrap();
    }

    fn live(fx: &Fixture) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            atomic::read(&fx.paths.root_wrap_recovery()).unwrap(),
            atomic::read(&fx.paths.node_key("global")).unwrap(),
            atomic::read(&fx.state.join("vaultGeneration.counter")).unwrap(),
        )
    }

    #[test]
    fn staging_touches_no_live_file() {
        let fx = fixture();
        seed_old(&fx);
        let stage = stage_three(&fx);
        assert_eq!(stage.len(), 3);
        assert_eq!(
            live(&fx),
            (
                b"old-recovery".to_vec(),
                b"old-node-key".to_vec(),
                b"old-counter".to_vec()
            )
        );
    }

    #[test]
    fn a_stage_that_never_committed_is_discarded_and_changes_nothing() {
        let fx = fixture();
        seed_old(&fx);
        drop(stage_three(&fx)); // the crash: staged, never committed
        assert!(fx.paths.rotation_stage().exists());

        assert_eq!(
            recover(&fx.paths, &fx.state).unwrap(),
            Recovery::DiscardedStage
        );
        assert!(!fx.paths.rotation_stage().exists());
        assert_eq!(live(&fx).0, b"old-recovery");
        assert_eq!(recover(&fx.paths, &fx.state).unwrap(), Recovery::Nothing);
    }

    #[test]
    fn a_committed_rotation_rolls_forward_into_both_directories() {
        let fx = fixture();
        seed_old(&fx);
        stage_three(&fx).commit().unwrap();
        // Committed but not a single live file replaced yet.
        assert_eq!(live(&fx).0, b"old-recovery");

        assert_eq!(
            recover(&fx.paths, &fx.state).unwrap(),
            Recovery::RolledForward { files: 3 }
        );
        assert_eq!(
            live(&fx),
            (
                b"new-recovery".to_vec(),
                b"new-node-key".to_vec(),
                b"new-counter".to_vec()
            )
        );
        assert!(
            !fx.paths.rotation_stage().exists(),
            "neither the commit record nor the stage survives a completed roll-forward"
        );
        assert_eq!(recover(&fx.paths, &fx.state).unwrap(), Recovery::Nothing);
    }

    /// The property the whole module is for: a roll-forward interrupted after
    /// *any* number of files is finished by the next `recover`, and the end
    /// state is identical no matter where it was cut.
    #[test]
    fn a_roll_forward_cut_at_every_point_still_finishes() {
        for cut in 0..=3 {
            let fx = fixture();
            seed_old(&fx);
            stage_three(&fx).commit().unwrap();

            let moved = roll_forward_first(&fx.paths, &fx.state, cut).unwrap();
            assert_eq!(moved, cut);
            // Including the last cut — every file moved, the record not yet
            // retired — an interrupted roll-forward keeps its commit record,
            // because the record is what says the rotation is still binding.
            assert!(
                commit_path(&fx.paths).exists(),
                "an interrupted roll-forward keeps its commit record (cut at {cut})"
            );
            assert!(is_committed(&fx.paths), "cut at {cut}");

            assert_eq!(
                recover(&fx.paths, &fx.state).unwrap(),
                Recovery::RolledForward { files: 3 - cut },
                "cut at {cut}: recovery moves exactly what the crash left"
            );
            assert_eq!(live(&fx).0, b"new-recovery", "cut at {cut}");
            assert_eq!(live(&fx).1, b"new-node-key", "cut at {cut}");
            assert_eq!(live(&fx).2, b"new-counter", "cut at {cut}");
            assert!(!fx.paths.rotation_stage().exists(), "cut at {cut}");
            assert!(!is_committed(&fx.paths), "cut at {cut}");
        }
    }

    /// The other half of the guarantee: a crash while the stage is still being
    /// written — after any number of files, including none — changes nothing
    /// live, and `recover` throws the stage away. Every cut, both directories.
    #[test]
    fn a_crash_while_staging_at_every_point_leaves_the_old_files_in_force() {
        for staged_before_crash in 0..=3 {
            let fx = fixture();
            seed_old(&fx);
            let mut stage = RotationStage::begin(&fx.paths, &fx.state).unwrap();
            stage.crash_after_staged(staged_before_crash);
            let results = [
                stage.stage_vault_file(&fx.paths.root_wrap_recovery(), b"new-recovery"),
                stage.stage_vault_file(&fx.paths.node_key("global"), b"new-node-key"),
                stage.stage_state_file(&fx.state.join("vaultGeneration.counter"), b"new-counter"),
            ];
            assert_eq!(
                results.iter().filter(|r| r.is_ok()).count(),
                staged_before_crash,
                "the seam lets exactly {staged_before_crash} files through"
            );
            // The process is gone: no commit, no cleanup.
            drop(stage);
            assert!(!is_committed(&fx.paths));

            assert_eq!(
                live(&fx),
                (
                    b"old-recovery".to_vec(),
                    b"old-node-key".to_vec(),
                    b"old-counter".to_vec()
                ),
                "staging {staged_before_crash} files touched a live file"
            );
            assert_eq!(
                recover(&fx.paths, &fx.state).unwrap(),
                Recovery::DiscardedStage
            );
            assert!(!fx.paths.rotation_stage().exists());
            assert_eq!(live(&fx).0, b"old-recovery");
        }
    }

    /// A stage with no commit record is also what a rotation that FINISHED and
    /// was cut off before removing its stage directory leaves. Discarding it
    /// must change no live file, whichever of the two it was — which is why
    /// [`Recovery::DiscardedStage`] does not claim to know.
    #[test]
    fn a_leftover_stage_after_a_finished_rotation_is_discarded_without_touching_the_vault() {
        let fx = fixture();
        seed_old(&fx);
        stage_three(&fx).commit().unwrap();
        roll_forward(&fx.paths, &fx.state).unwrap();
        // The crash: the commit record is retired (above), the stage directory
        // is not. Put a leftover file back where the stage was.
        atomic::write(
            &fx.paths.rotation_stage().join("vault").join("leftover"),
            b"x",
        )
        .unwrap();
        assert!(!is_committed(&fx.paths));
        let finished = live(&fx);
        assert_eq!(finished.0, b"new-recovery");

        assert_eq!(
            recover(&fx.paths, &fx.state).unwrap(),
            Recovery::DiscardedStage
        );
        assert!(!fx.paths.rotation_stage().exists());
        assert_eq!(live(&fx), finished, "the new files are final and stay");
    }

    /// The P3 finding: digests used to be checked one file at a time inside the
    /// move loop, so a torn file at position k left the k files before it
    /// already replaced. Every check now runs before the first rename.
    #[test]
    fn a_corrupt_staged_file_late_in_the_set_is_refused_before_any_file_moves() {
        for corrupt_index in 0..3usize {
            let fx = fixture();
            seed_old(&fx);
            stage_three(&fx).commit().unwrap();
            let staged = [
                fx.paths
                    .rotation_stage()
                    .join("vault")
                    .join("keys")
                    .join("root.wrap.recovery"),
                fx.paths
                    .rotation_stage()
                    .join("vault")
                    .join("keys")
                    .join("nodes")
                    .join("global.key"),
                fx.paths
                    .rotation_stage()
                    .join("state")
                    .join("vaultGeneration.counter"),
            ];
            atomic::write(&staged[corrupt_index], b"torn").unwrap();

            assert!(
                recover(&fx.paths, &fx.state).is_err(),
                "index {corrupt_index}"
            );
            assert_eq!(
                live(&fx),
                (
                    b"old-recovery".to_vec(),
                    b"old-node-key".to_vec(),
                    b"old-counter".to_vec()
                ),
                "corrupting staged file {corrupt_index} must leave every live file old — \
                 not move the ones before it"
            );
            assert!(is_committed(&fx.paths), "the record stays for the retry");
            for (i, path) in staged.iter().enumerate() {
                assert!(
                    path.exists(),
                    "no staged file was consumed (index {i}, corrupt {corrupt_index})"
                );
            }
        }
    }

    /// The P2 finding's second line of defence: a staged file that is simply
    /// *gone* — deleted by a second process's recovery, say — used to be read as
    /// "already moved" and skipped, so the roll-forward moved the rest and
    /// retired the commit record over a vault mixing both root keys.
    #[test]
    fn a_staged_file_that_vanished_without_being_moved_is_refused_and_nothing_moves() {
        for vanished in 0..3usize {
            let fx = fixture();
            seed_old(&fx);
            stage_three(&fx).commit().unwrap();
            let stage = fx.paths.rotation_stage();
            let path = [
                stage.join("vault").join("keys").join("root.wrap.recovery"),
                stage
                    .join("vault")
                    .join("keys")
                    .join("nodes")
                    .join("global.key"),
                stage.join("state").join("vaultGeneration.counter"),
            ][vanished]
                .clone();
            fs::remove_file(&path).unwrap();

            let err = recover(&fx.paths, &fx.state).expect_err("a stage that lost a file");
            assert!(
                err.to_string().contains("cannot be completed"),
                "the error says why: {err}"
            );
            assert_eq!(
                live(&fx),
                (
                    b"old-recovery".to_vec(),
                    b"old-node-key".to_vec(),
                    b"old-counter".to_vec()
                ),
                "file {vanished} vanished: nothing may have moved"
            );
            assert!(is_committed(&fx.paths), "vanished {vanished}");
            // …and it fails the same way next time (it does not "heal" into a
            // half-applied vault by being tried again).
            assert!(recover(&fx.paths, &fx.state).is_err());
            assert_eq!(live(&fx).0, b"old-recovery");
        }
    }

    /// "Already moved" is only believed when the live twin proves it: a moved
    /// file whose live copy no longer carries the committed bytes is refused.
    #[test]
    fn a_moved_file_whose_live_twin_changed_is_not_taken_for_applied() {
        let fx = fixture();
        seed_old(&fx);
        stage_three(&fx).commit().unwrap();
        assert_eq!(roll_forward_first(&fx.paths, &fx.state, 1).unwrap(), 1);
        // First file is in place; tamper with it, as if something else wrote it.
        atomic::write(&fx.paths.root_wrap_recovery(), b"someone else's bytes").unwrap();

        assert!(recover(&fx.paths, &fx.state).is_err());
        assert_eq!(
            live(&fx).1,
            b"old-node-key",
            "the unmoved files stay as they were"
        );
        assert_eq!(live(&fx).2, b"old-counter");
        assert!(is_committed(&fx.paths));
    }

    /// The legitimate shape of "gone": every file moved by an earlier pass, the
    /// commit record not yet retired. Each live twin proves it, and recovery
    /// finishes by retiring the record.
    #[test]
    fn a_fully_moved_rotation_whose_record_was_not_retired_is_finished_not_refused() {
        let fx = fixture();
        seed_old(&fx);
        stage_three(&fx).commit().unwrap();
        assert_eq!(roll_forward_first(&fx.paths, &fx.state, 3).unwrap(), 3);
        assert!(is_committed(&fx.paths));
        assert_eq!(
            recover(&fx.paths, &fx.state).unwrap(),
            Recovery::RolledForward { files: 0 }
        );
        assert!(!fx.paths.rotation_stage().exists());
        assert_eq!(live(&fx).0, b"new-recovery");
    }

    #[test]
    fn a_commit_record_that_landed_can_be_made_durable_again() {
        let fx = fixture();
        seed_old(&fx);
        stage_three(&fx).commit().unwrap();
        make_commit_durable(&fx.paths).expect("the stage directory syncs");
        // With no stage there is nothing to sync, and it says so.
        recover(&fx.paths, &fx.state).unwrap();
        assert!(make_commit_durable(&fx.paths).is_err());
    }

    /// The seam the concurrency suites use: a hook runs exactly once, at the
    /// requested point, with exactly that many files staged.
    #[test]
    fn the_pause_hook_runs_once_with_the_requested_number_of_files_staged() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let fx = fixture();
        let seen = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let stage_dir = fx.paths.rotation_stage();
        let mut stage = RotationStage::begin(&fx.paths, &fx.state).unwrap();
        {
            let (seen, calls) = (Arc::clone(&seen), Arc::clone(&calls));
            stage.pause_after_staged(
                2,
                Arc::new(move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let mut staged = 0;
                    for dir in ["vault", "state"] {
                        let mut files = Vec::new();
                        let root = stage_dir.join(dir);
                        fn walk(p: &Path, out: &mut Vec<PathBuf>) {
                            if let Ok(rd) = fs::read_dir(p) {
                                for e in rd.flatten() {
                                    if e.path().is_dir() {
                                        walk(&e.path(), out);
                                    } else {
                                        out.push(e.path());
                                    }
                                }
                            }
                        }
                        walk(&root, &mut files);
                        staged += files.len();
                    }
                    seen.store(staged, Ordering::SeqCst);
                }),
            );
        }
        stage
            .stage_vault_file(&fx.paths.root_wrap_recovery(), b"a")
            .unwrap();
        stage
            .stage_vault_file(&fx.paths.node_key("global"), b"b")
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0, "not yet");
        stage
            .stage_state_file(&fx.state.join("vaultGeneration.counter"), b"c")
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            seen.load(Ordering::SeqCst),
            2,
            "two files were on disk when it ran"
        );
    }

    #[test]
    fn begin_refuses_while_a_committed_rotation_is_waiting() {
        let fx = fixture();
        seed_old(&fx);
        stage_three(&fx).commit().unwrap();
        assert!(RotationStage::begin(&fx.paths, &fx.state).is_err());
        // …and a stale uncommitted stage is cleared, not refused.
        recover(&fx.paths, &fx.state).unwrap();
        drop(stage_three(&fx));
        assert!(RotationStage::begin(&fx.paths, &fx.state).is_ok());
    }

    #[test]
    fn a_staged_file_that_no_longer_matches_its_digest_is_not_moved() {
        let fx = fixture();
        seed_old(&fx);
        stage_three(&fx).commit().unwrap();
        let staged = fx
            .paths
            .rotation_stage()
            .join("vault")
            .join("keys")
            .join("nodes")
            .join("global.key");
        atomic::write(&staged, b"not what was committed").unwrap();

        assert!(recover(&fx.paths, &fx.state).is_err());
        assert_eq!(
            live(&fx).1,
            b"old-node-key",
            "the live file is untouched when its replacement fails the digest check"
        );
        assert!(
            commit_path(&fx.paths).exists(),
            "a refused roll-forward keeps the stage so the failure can be read"
        );
    }

    #[test]
    fn a_commit_record_naming_a_path_outside_the_vault_is_refused() {
        let fx = fixture();
        seed_old(&fx);
        let stage = stage_three(&fx);
        stage.commit().unwrap();
        let commit = commit_path(&fx.paths);
        let mut doc: CommitDoc = serde_json::from_slice(&fs::read(&commit).unwrap()).unwrap();
        doc.files[0].rel = "../escaped".to_string();
        atomic::write(&commit, &serde_json::to_vec(&doc).unwrap()).unwrap();

        assert!(recover(&fx.paths, &fx.state).is_err());
        assert!(
            !fx.paths.root().join("../escaped").exists(),
            "nothing was moved — validation runs before the first rename"
        );
        assert_eq!(live(&fx).0, b"old-recovery");
    }

    #[test]
    fn key_files_a_rotation_does_not_know_how_to_rewrap_are_found() {
        let fx = fixture();
        // The known set, plus noise a rotation ignores: nothing found.
        atomic::write(&fx.paths.root_wrap_pass(), b"p").unwrap();
        atomic::write(&fx.paths.root_wrap_recovery(), b"r").unwrap();
        atomic::write(&fx.paths.node_key("global"), b"k").unwrap();
        atomic::write(&fx.paths.keys_dir().join(".DS_Store"), b"x").unwrap();
        atomic::write(&fx.paths.keys_dir().join("nodes").join(".swp"), b"x").unwrap();
        assert_eq!(
            unrecognised_key_files(&fx.paths).unwrap(),
            Vec::<PathBuf>::new()
        );

        // ADR-079: the one cold file this build re-seals is recognised.
        atomic::write(&fx.paths.orphan_key(), b"cold").unwrap();
        assert_eq!(
            unrecognised_key_files(&fx.paths).unwrap(),
            Vec::<PathBuf>::new()
        );

        // A hardware-keystore wrap, any other cold file, a stray file in
        // `keys/nodes/`: each is key material wrapped under a root key this
        // build would leave behind, so each is reported.
        atomic::write(&fx.paths.root_wrap_se(), b"se").unwrap();
        atomic::write(&fx.paths.keys_cold_dir().join("orphan.key.bak"), b"cold").unwrap();
        atomic::write(
            &fx.paths.keys_dir().join("nodes").join("global.key.bak"),
            b"b",
        )
        .unwrap();
        let found = unrecognised_key_files(&fx.paths).unwrap();
        let names: Vec<String> = found
            .iter()
            .map(|p| {
                p.strip_prefix(fx.paths.keys_dir())
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(
            names,
            [
                "cold/orphan.key.bak",
                "nodes/global.key.bak",
                "root.wrap.se"
            ],
            "{names:?}"
        );
    }

    #[test]
    fn staging_the_same_file_twice_or_outside_its_base_is_refused() {
        let fx = fixture();
        let mut stage = RotationStage::begin(&fx.paths, &fx.state).unwrap();
        stage
            .stage_vault_file(&fx.paths.node_key("global"), b"a")
            .unwrap();
        assert!(stage
            .stage_vault_file(&fx.paths.node_key("global"), b"b")
            .is_err());
        assert!(stage
            .stage_vault_file(&fx.state.join("elsewhere"), b"c")
            .is_err());
    }

    #[test]
    fn a_staged_tree_is_owner_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let fx = fixture();
            drop(stage_three(&fx));
            let staged = fx
                .paths
                .rotation_stage()
                .join("vault")
                .join("keys")
                .join("nodes")
                .join("global.key");
            assert_eq!(
                fs::metadata(staged).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(fx.paths.rotation_stage())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    // --- the pieces a rotation re-signs -----------------------------------

    const OLD: [u8; 32] = [1u8; 32];
    const NEW: [u8; 32] = [2u8; 32];

    fn entry(id: &str) -> crate::manifest::ManifestEntry {
        crate::manifest::ManifestEntry {
            id: id.to_string(),
            name: "vps-root".to_string(),
            r#ref: 3060,
            entry_type: credmgr_core::inference::EntryType::Server,
            sensitivity: crate::manifest::Sensitivity::Critical,
            field_count: 1,
            sha256: "deadbeef".to_string(),
            modified: 1_700_000_000,
            expires_at: None,
            rotated_at: None,
            has_totp: false,
        }
    }

    fn event(action: &str) -> audit::NewEvent {
        audit::NewEvent {
            actor: "cli".to_string(),
            action: action.to_string(),
            node_id: Some("a".to_string()),
            entry_id: None,
            decision: Some("allow".to_string()),
            detail: None,
            generation: None,
        }
    }

    /// A vault directory holding one of every artefact the plan re-signs, all
    /// signed under [`OLD`].
    fn signed_under_old(fx: &Fixture) {
        let paths = &fx.paths;
        // Audit: two records and a tip.
        audit::append(paths, &OLD, "2026-10", event("one"), 1).unwrap();
        audit::append(paths, &OLD, "2026-10", event("two"), 2).unwrap();
        // A sealed-node archive: node dir (with a signed manifest), wrapped key, entry.
        let pair = credmgr_core::keys::generate_node_keypair();
        atomic::write(
            &paths.node_key("a"),
            &credmgr_core::keys::wrap_node_key(&OLD, "a", &pair.private).to_bytes(),
        )
        .unwrap();
        manifest::save(paths, &OLD, &manifest::ManifestBody::new("a")).unwrap();
        atomic::write(&paths.entry_env("a", "e_1"), b"ciphertext").unwrap();
        archive::seal(paths, &OLD, "a", 1_700_000_000).unwrap();
        // The orphan cold key, sealed under the old root.
        let (_, cold_file) = cold::generate_orphan_cold(&OLD);
        atomic::write(&paths.orphan_key(), &cold_file).unwrap();
        // A removed entry and a rotation snapshot on another node.
        atomic::write(&paths.entry_env("b", "e_bbbbbbbbbbbb"), b"ciphertext").unwrap();
        entry_archive::remove(paths, &OLD, "b", &entry("e_bbbbbbbbbbbb"), 1_700_000_000).unwrap();
        rotation_history::save(paths, &OLD, "b", &entry("e_bbbbbbbbbbbb"), 3, 1_700_000_000)
            .unwrap();
    }

    #[test]
    fn every_signed_artefact_is_planned_and_verifies_under_the_new_key_only_once_written() {
        let fx = fixture();
        signed_under_old(&fx);
        let plan = plan_resigned_artifacts(&fx.paths, &OLD, &NEW).unwrap();
        assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
        let mut kinds: Vec<&str> = plan.resigned.iter().map(|r| r.kind).collect();
        kinds.sort_unstable();
        assert_eq!(
            kinds,
            [
                "audit-tip",
                "entry-history",
                "orphan-cold-key",
                "removed-entry",
                "seal-archive",
                "seal-archive-key",
                "seal-archive-manifest"
            ]
        );

        // Planning wrote nothing: everything still verifies under OLD, nothing under NEW.
        assert!(audit::verify(&fx.paths, &OLD, "2026-10").is_ok());
        assert!(audit::verify(&fx.paths, &NEW, "2026-10").is_err());
        assert!(rotation_history::load(&fx.paths, &OLD, "b", "e_bbbbbbbbbbbb", 3).is_ok());
        assert!(rotation_history::load(&fx.paths, &NEW, "b", "e_bbbbbbbbbbbb", 3).is_err());

        for item in &plan.resigned {
            atomic::write(&item.path, &item.bytes).unwrap();
        }
        assert!(audit::verify(&fx.paths, &NEW, "2026-10").is_ok());
        assert!(audit::verify(&fx.paths, &OLD, "2026-10").is_err());
        assert!(rotation_history::load(&fx.paths, &NEW, "b", "e_bbbbbbbbbbbb", 3).is_ok());
        assert!(entry_archive::peek(&fx.paths, &NEW, "b", "e_bbbbbbbbbbbb", 1_700_000_100).is_ok());
        assert!(
            entry_archive::peek(&fx.paths, &OLD, "b", "e_bbbbbbbbbbbb", 1_700_000_100).is_err()
        );
        // The retained node key opens under the new root, and the retained
        // manifest verifies under it.
        let key = fs::read(fx.paths.archive_dir("a").join("node.key")).unwrap();
        let key = WrappedNodeKey::from_bytes(&key).unwrap();
        assert!(credmgr_core::keys::unwrap_node_key(&NEW, "a", &key).is_ok());
        assert!(credmgr_core::keys::unwrap_node_key(&OLD, "a", &key).is_err());
        assert!(manifest::load_at(
            &fx.paths.archive_dir("a").join("node").join("manifest.json"),
            &NEW,
            "a"
        )
        .is_ok());
        // The cold key opens under the new root and not the old one, and is the
        // same orphan keypair (every orphan envelope still opens).
        let cold_bytes = fs::read(fx.paths.orphan_key()).unwrap();
        let header = cold::parse_header(&cold_bytes).unwrap();
        assert!(cold::open_orphan_cold(&NEW, &cold_bytes, Some(&header.public)).is_ok());
        assert!(cold::open_orphan_cold(&OLD, &cold_bytes, None).is_err());
        // …and the archive restores under the new key (its meta verifies).
        archive::restore(&fx.paths, &NEW, "a", 1_700_000_100).unwrap();
    }

    /// Re-signing something that already fails verification would stamp the
    /// damage authentic. Each kind is left alone and reported instead.
    #[test]
    fn what_does_not_verify_under_the_old_key_is_reported_and_never_resigned() {
        let fx = fixture();
        signed_under_old(&fx);
        // Tamper with three of the five: truncate the audit log, flip a
        // removed-entry record's HMAC, and corrupt the archive's meta.
        let log = fx.paths.audit_log("2026-10");
        let text = fs::read_to_string(&log).unwrap();
        let first_line = text.lines().next().unwrap();
        fs::write(&log, format!("{first_line}\n")).unwrap();
        let removed = fx.paths.removed_entry_meta("b", "e_bbbbbbbbbbbb");
        let mut doc: serde_json::Value =
            serde_json::from_slice(&fs::read(&removed).unwrap()).unwrap();
        doc["hmac"] = serde_json::Value::String("0".repeat(64));
        fs::write(&removed, serde_json::to_vec(&doc).unwrap()).unwrap();
        let meta = archive::meta_file(&fx.paths.archive_dir("a"));
        fs::write(meta, b"{\"nodeId\":\"a\"}").unwrap();
        // …and the orphan cold key is torn.
        let mut cold_bytes = fs::read(fx.paths.orphan_key()).unwrap();
        let last = cold_bytes.len() - 1;
        cold_bytes[last] ^= 1;
        fs::write(fx.paths.orphan_key(), &cold_bytes).unwrap();

        let plan = plan_resigned_artifacts(&fx.paths, &OLD, &NEW).unwrap();
        let skipped: Vec<&str> = plan.skipped.iter().map(|s| s.kind).collect();
        for kind in [
            "audit-tip",
            "removed-entry",
            "seal-archive",
            "orphan-cold-key",
        ] {
            assert!(
                skipped.contains(&kind),
                "{kind} must be reported: {skipped:?}"
            );
            assert!(
                plan.resigned.iter().all(|r| r.kind != kind),
                "{kind} must not be re-signed"
            );
        }
        // A damaged archive meta takes the whole archive's other artefacts out
        // of the plan with it; the untouched snapshot is still planned.
        assert!(plan.resigned.iter().any(|r| r.kind == "entry-history"));
        assert!(plan
            .resigned
            .iter()
            .all(|r| !r.kind.starts_with("seal-archive")));
    }

    #[test]
    fn staged_registry_counter_and_manifest_bytes_are_exactly_what_a_save_writes() {
        let fx = fixture();
        let mut doc = crate::registry_file::RegistryDocument::new();
        doc.vault_generation = 7;
        let (json, sig) = crate::registry_file::signed_bytes(&NEW, &doc).unwrap();
        crate::registry_file::save(&fx.paths, &NEW, &doc).unwrap();
        assert_eq!(json, fs::read(fx.paths.registry()).unwrap());
        assert_eq!(sig, fs::read(fx.paths.registry_sig()).unwrap());

        let counter = crate::generation::FileGenerationCounter::new(fx.state.clone());
        let bytes =
            crate::generation::signed_counter_bytes(&NEW, crate::generation::VAULT_GENERATION, 7)
                .unwrap();
        atomic::write(
            &counter.file_path(crate::generation::VAULT_GENERATION),
            &bytes,
        )
        .unwrap();
        use crate::generation::GenerationCounter;
        assert_eq!(
            counter
                .read(&NEW, crate::generation::VAULT_GENERATION)
                .unwrap(),
            Some(7)
        );

        let body = manifest::ManifestBody::new("a");
        let (manifest_bytes, binding) = manifest::signed_bytes(&fx.paths, &NEW, &body).unwrap();
        let saved = manifest::save(&fx.paths, &NEW, &body).unwrap();
        assert_eq!(binding, saved);
        assert_eq!(manifest_bytes, fs::read(fx.paths.manifest("a")).unwrap());
    }
}
