//! ADR-076 — the per-vault rotation lock.
//!
//! `credmgr_store::rotation::recover` deletes an uncommitted stage, because an
//! uncommitted stage is what a crashed rotation leaves. It cannot tell that
//! from a stage a *live* process is still writing. Two processes over one
//! vault — a second `credmgrd` starting while the first is mid-rotation, or two
//! broker states in one test — would therefore let the second delete the
//! first's staged files; the first would carry on, commit a record naming files
//! that no longer exist, and roll forward over a vault whose registry and node
//! keys stayed under the old root while `root.wrap.pass` moved to the new one:
//! a vault that opens with neither (the P2 finding of the ADR-076 review).
//!
//! The cure is exclusion, not cleverness: **one exclusive advisory lock per
//! vault, held across `recover` and across the whole of a rotation.** `flock(2)`
//! on `<vault>/run/rotation.lock`:
//!
//! * it belongs to an open file description, so two `VaultLock`s in one
//!   process (two broker states) exclude each other exactly as two processes do
//!   — unlike `fcntl` record locks, which are per-process;
//! * the kernel releases it when its holder dies, however it dies, so a crashed
//!   rotation can never leave a lock behind to wedge the vault — the very case
//!   `recover` exists for;
//! * it carries no data, so there is nothing in the file to forge or leak.
//!
//! This is the one module of the crate (besides `peer.rs`) that needs
//! `unsafe`: `flock` has no safe wrapper in `std` at this crate's 1.78 MSRV
//! (`File::lock` is 1.89). The crate-wide `deny` is relaxed here only, for two
//! calls whose preconditions are a valid descriptor owned by the `File` they are
//! made on.
//!
//! **Not a replacement for the socket guard.** `server::run` still refuses to
//! start a second broker over a live socket (Review M4). This lock only makes
//! the one thing a second process *does* do before that check — recovery —
//! safe.
#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::time::{Duration, Instant};

use credmgr_store::atomic;
use credmgr_store::error::StoreError;
use credmgr_store::paths::VaultPaths;

/// How long recovery waits for another holder before giving up. A rotation
/// holds the lock for seconds (fsyncs, a handful of renames); recovery has to
/// outlast it, because the alternative to waiting is reading a vault that is
/// being replaced.
pub const RECOVER_LOCK_WAIT: Duration = Duration::from_secs(30);

/// How long a rotation waits for the lock. Shorter on purpose: it is an
/// operator's interactive request, and "another credmgr process is recovering
/// this vault right now, try again" is a better answer than a long hang.
pub const ROTATE_LOCK_WAIT: Duration = Duration::from_secs(2);

/// How often a waiting acquirer tries again.
const POLL: Duration = Duration::from_millis(20);

/// The held lock. Dropping it closes the descriptor, which releases it.
#[derive(Debug)]
pub struct VaultLock {
    // Held open for its lifetime; never read.
    _file: File,
}

impl VaultLock {
    /// Take the exclusive lock for `paths`' vault, waiting up to `wait` for a
    /// current holder to let go. Creates `<vault>/run/` (`0700`) and the
    /// (empty, `0600`) lock file if they are missing. A symlink at the lock
    /// path is refused, not followed.
    ///
    /// `Err` is either an I/O failure or `TimedOut` — "another credmgr process
    /// holds this vault's rotation lock" — and in both cases nothing has been
    /// touched, so the caller can simply report it.
    pub fn acquire(paths: &VaultPaths, wait: Duration) -> Result<VaultLock, StoreError> {
        let path = paths.rotation_lock();
        let fail = |source: io::Error| StoreError::Io {
            path: path.clone(),
            source,
        };
        atomic::ensure_dir(&paths.run_dir())?;
        let file = open_lock_file(&path).map_err(fail)?;
        let deadline = Instant::now() + wait;
        loop {
            match try_lock_exclusive(&file) {
                Ok(()) => return Ok(VaultLock { _file: file }),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(fail(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "another credmgr process holds this vault's rotation lock — a \
                             root-key rotation, or the recovery of one, is in progress; \
                             try again in a moment",
                        )));
                    }
                    std::thread::sleep(POLL);
                }
                Err(e) => return Err(fail(e)),
            }
        }
    }
}

#[cfg(unix)]
fn open_lock_file(path: &std::path::Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `file` owns a valid, open descriptor for the whole call, and
    // `flock` only reads that integer and the two flag bits — it touches no
    // memory of ours. `LOCK_NB` keeps it from blocking, so the caller's own
    // deadline governs how long we wait.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// The broker only runs where `std::os::unix::net` exists (the Windows named-pipe
// transport is not built), so this stub keeps `state` compiling elsewhere
// without pretending to exclude anyone: there is no second process to exclude
// until that transport exists, and it will need `LockFileEx` here.
#[cfg(not(unix))]
fn open_lock_file(path: &std::path::Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

#[cfg(not(unix))]
fn try_lock_exclusive(_file: &File) -> io::Result<()> {
    Ok(())
}
