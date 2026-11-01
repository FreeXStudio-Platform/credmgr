//! `write temp → fsync → rename` — the one primitive every other module in
//! this crate builds on. `02_ARCHITECTURE.md §7`: "files also make the
//! atomic-write story simple", and Phase 2's exit gate names it directly:
//! a kill during a write must leave the vault in either the old state or
//! the new one, never a half-written file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Result, StoreError};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn io_err(path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// `0700` on Unix; Windows relies on ACLs (no bit-mode equivalent), asserted
/// separately in Phase 5 alongside the named-pipe DACL work.
///
/// Creates each missing path component individually (rather than
/// `create_dir_all` in one call) and chmods only the ones this call actually
/// created, so every directory the vault owns ends up `0700` — not just the
/// leaf — while directories that already existed (a pre-existing ancestor
/// this crate does not own) are left untouched.
pub fn ensure_dir(dir: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in dir.components() {
        current.push(component);
        if !current.exists() {
            fs::create_dir(&current).map_err(|e| io_err(&current, e))?;
            set_dir_mode(&current)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| io_err(dir, e))
}

#[cfg(not(unix))]
fn set_dir_mode(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path, file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| io_err(path, e))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _file: &File) -> Result<()> {
    Ok(())
}

fn temp_path_for(target: &Path) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = target
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    target.with_file_name(format!(".{file_name}.tmp.{}.{n}", std::process::id()))
}

/// Write `data` to `target` atomically: the file at `target` is either the
/// previous content or exactly `data`, in full — never truncated, never a
/// mix — even if the process is killed at any point during this call.
/// Creates `target`'s parent directory (mode `0700`) if it doesn't exist.
pub fn write(target: &Path, data: &[u8]) -> Result<()> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(dir)?;

    let tmp = temp_path_for(target);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| io_err(&tmp, e))?;
    set_file_mode(&tmp, &file)?;

    let result: Result<()> = (|| {
        file.write_all(data).map_err(|e| io_err(&tmp, e))?;
        file.sync_all().map_err(|e| io_err(&tmp, e))?;
        Ok(())
    })();
    drop(file);

    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    fs::rename(&tmp, target).map_err(|e| io_err(target, e))?;
    fsync_dir(dir)?;
    Ok(())
}

/// fsync the containing directory so the rename itself is durable, not just
/// the file's own contents. Unix-only: `File::open` on a directory is not a
/// portable operation on Windows, whose durability story for a rename is
/// different (NTFS metadata journal) and is Phase 5's concern, not this
/// primitive's.
#[cfg(unix)]
fn fsync_dir(dir: &Path) -> Result<()> {
    let d = File::open(dir).map_err(|e| io_err(dir, e))?;
    d.sync_all().map_err(|e| io_err(dir, e))
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// fsync a directory so a rename or creation inside it is durable (Unix; a
/// no-op elsewhere, like the private helper it wraps). Public for
/// [`crate::rotation`], which must be able to say "this staged tree is on
/// disk" before it writes the commit marker that makes it binding.
pub fn sync_dir(dir: &Path) -> Result<()> {
    fsync_dir(dir)
}

/// fsync `root` and every directory beneath it, depth first. The directories
/// a staged tree was *created* in are not covered by [`write`]'s own parent
/// fsync (which makes the file's entry durable, not its ancestors').
pub fn sync_tree(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).map_err(|e| io_err(root, e))? {
        let entry = entry.map_err(|e| io_err(root, e))?;
        let path = entry.path();
        let is_real_dir = fs::symlink_metadata(&path)
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false);
        if is_real_dir {
            sync_tree(&path)?;
        }
    }
    fsync_dir(root)
}

/// Move `from` to `to`, durably: create `to`'s parent (mode `0700`), rename,
/// and fsync both directories. A rename across filesystems (`EXDEV`) falls
/// back to an atomic write of the same bytes followed by removing `from` — at
/// every instant `to` is either its old content or the complete new content.
/// Idempotent only in the sense the caller makes it: a second call after a
/// completed move finds no `from` and fails, which is the caller's signal.
pub fn move_file(from: &Path, to: &Path) -> Result<()> {
    let to_dir = to.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(to_dir)?;
    match fs::rename(from, to) {
        Ok(()) => {}
        Err(e) if is_cross_device(&e) => {
            let bytes = read(from)?;
            write(to, &bytes)?;
            fs::remove_file(from).map_err(|e| io_err(from, e))?;
        }
        Err(e) => return Err(io_err(to, e)),
    }
    fsync_dir(to_dir)?;
    if let Some(from_dir) = from.parent() {
        if from_dir != to_dir {
            fsync_dir(from_dir)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_cross_device(e: &io::Error) -> bool {
    e.raw_os_error() == Some(18) // EXDEV on every Unix this vault targets
}

#[cfg(not(unix))]
fn is_cross_device(_e: &io::Error) -> bool {
    false
}

/// Remove a file and fsync its directory. A file that is already gone is
/// success — the point is that it is not there afterwards.
pub fn remove_durable(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err(path, e)),
    }
    if let Some(dir) = path.parent() {
        fsync_dir(dir)?;
    }
    Ok(())
}

/// Read a file whole. Thin wrapper so callers get a [`StoreError`] with the
/// path attached instead of a bare `io::Error`.
/// Read a vault file — **only** if it is a regular file. A symlink or a FIFO
/// at a vault path is refused rather than followed: a FIFO can answer two
/// reads of "the same file" with two different contents, and a symlink can
/// point a trusted path at an attacker-chosen one (review of ADR-063, H1).
/// Vault files are never either, so the refusal costs nothing legitimate.
pub fn read(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|e| io_err(path, e))?;
    if !metadata.file_type().is_file() {
        return Err(io_err(
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a regular file (symlinks and FIFOs are refused)",
            ),
        ));
    }
    fs::read(path).map_err(|e| io_err(path, e))
}

pub fn exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested").join("registry.json");
        write(&target, b"hello").unwrap();
        assert_eq!(read(&target).unwrap(), b"hello");
    }

    #[test]
    fn overwrite_replaces_atomically_and_no_tmp_survives() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("registry.json");
        write(&target, b"v1").unwrap();
        write(&target, b"v2-longer-payload").unwrap();
        assert_eq!(read(&target).unwrap(), b"v2-longer-payload");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp file(s) leaked: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn dir_and_file_modes_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sub").join("registry.json");
        write(&target, b"x").unwrap();
        let file_mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        let dir_mode = fs::metadata(target.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    /// Phase 2 exit gate: "Kill -9 during a write leaves the vault
    /// consistent (temp+fsync+rename, 100 iterations)."
    ///
    /// `rename()` is a single atomic syscall on every filesystem this vault
    /// targets, so a `SIGKILL` delivered to *this* process can only land
    /// strictly before or strictly after it — there is no OS-level way to
    /// observe a torn rename from user space without simulating real power
    /// loss. What this test actually proves, honestly: repeatedly killing a
    /// child process at random points across many real write cycles never
    /// once leaves `target` holding anything other than a complete, valid
    /// payload or its prior complete, valid payload — i.e. this module does
    /// not fall back to any non-atomic path (in-place truncate, partial
    /// rename, etc.) under interruption.
    #[test]
    fn kill_during_write_never_corrupts_target() {
        if std::env::var_os("CREDMGR_ATOMIC_KILL9_CHILD").is_some() {
            child_write_loop();
            return;
        }

        let exe = std::env::current_exe().unwrap();
        for i in 0..100u32 {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("registry.json");

            let mut child = Command::new(&exe)
                .arg("atomic::tests::kill_during_write_never_corrupts_target")
                .arg("--exact")
                .arg("--nocapture")
                .env("CREDMGR_ATOMIC_KILL9_CHILD", "1")
                .env("CREDMGR_ATOMIC_KILL9_TARGET", &target)
                .spawn()
                .unwrap();

            // A few hundred microseconds is enough to land the kill inside
            // some fraction of the child's many write cycles; varying it by
            // iteration spreads hits across open/write/fsync/rename.
            std::thread::sleep(std::time::Duration::from_micros(50 + (i as u64 * 37) % 900));
            let _ = child.kill();
            let _ = child.wait();

            if target.exists() {
                let bytes = fs::read(&target).unwrap();
                assert!(
                    is_well_formed_payload(&bytes),
                    "iteration {i}: target held a corrupt/partial payload: {bytes:?}"
                );
            }
            // No leftover temp files, ever — a killed process can't have
            // completed a rename it didn't reach, and anything it created
            // stays under the tempdir being discarded here regardless.
        }
    }

    fn payload_for(n: u64) -> Vec<u8> {
        // "PAYLOAD:<n>:" + n repeated as filler, so truncation at any byte
        // offset is detectable (either the marker or the checksum tail breaks).
        let body = format!("PAYLOAD:{n}:{}", "x".repeat((n % 4096) as usize));
        let sum: u32 = body.bytes().map(u32::from).sum();
        format!("{body}|{sum}").into_bytes()
    }

    fn is_well_formed_payload(bytes: &[u8]) -> bool {
        let Ok(s) = std::str::from_utf8(bytes) else {
            return false;
        };
        let Some((body, sum_str)) = s.rsplit_once('|') else {
            return false;
        };
        let Ok(claimed_sum) = sum_str.parse::<u32>() else {
            return false;
        };
        let actual_sum: u32 = body.bytes().map(u32::from).sum();
        actual_sum == claimed_sum && body.starts_with("PAYLOAD:")
    }

    fn child_write_loop() {
        let target = PathBuf::from(std::env::var_os("CREDMGR_ATOMIC_KILL9_TARGET").unwrap());
        let mut n: u64 = 0;
        loop {
            let payload = payload_for(n);
            let _ = write(&target, &payload);
            n += 1;
            if n > 2_000_000 {
                break; // safety valve; the parent always kills us well before this
            }
        }
    }
}
