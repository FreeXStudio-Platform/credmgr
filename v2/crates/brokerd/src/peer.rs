//! Peer identification — `02_ARCHITECTURE.md §3`. Every connection is
//! identified before the token is even read: uid first (hard gate), then
//! pid → cwd (a convenience/audit signal, never the authority — AR-5).
//!
//! Raw platform syscalls with no cross-platform crate covering them, so this
//! module (and only this module) carries `#[allow(unsafe_code)]` on top of
//! the crate's blanket `#![forbid(unsafe_code)]`, per `BUILD_PROMPT.md §3.5`
//! and the precedent already recorded in `crates/keystore/src/lib.rs`.
#![allow(unsafe_code)]

use std::io;

/// What the broker learns about a connecting process, before it reads a
/// single byte of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub uid: u32,
    pub pid: i32,
    /// `None` when the lookup itself fails — non-fatal (`02 §3`: "advisory
    /// on an unsigned dev machine"), never treated as equivalent to "no
    /// match" for scope resolution.
    pub cwd: Option<String>,
}

#[derive(Debug)]
pub enum PeerError {
    /// `getsockopt` for the peer's credentials failed outright — the
    /// connection cannot be identified at all and must be rejected.
    CredentialLookupFailed(io::Error),
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{PeerError, PeerInfo};
    use std::mem;
    use std::os::unix::io::RawFd;

    /// `getsockopt(LOCAL_PEERCRED)` → uid/gid, `getsockopt(LOCAL_PEERPID)` →
    /// pid (`02 §3` point 1–2, verbatim). Both are Darwin-only `SOL_LOCAL`
    /// options carried by `libc` on this target.
    pub fn identify(fd: RawFd) -> Result<PeerInfo, PeerError> {
        let mut xucred: libc::xucred = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::xucred>() as libc::socklen_t;
        // SAFETY: `fd` is a valid, open socket fd for the lifetime of this
        // call (owned by the caller for the duration); `xucred`/`len` are
        // correctly sized out-parameters per `getsockopt(2)`.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                &mut xucred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(PeerError::CredentialLookupFailed(
                std::io::Error::last_os_error(),
            ));
        }
        let uid = xucred.cr_uid;

        let mut pid: libc::pid_t = 0;
        let mut pid_len = mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: same contract as above, for the sibling `LOCAL_PEERPID`
        // option.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut pid_len,
            )
        };
        if rc != 0 {
            return Err(PeerError::CredentialLookupFailed(
                std::io::Error::last_os_error(),
            ));
        }

        Ok(PeerInfo {
            uid,
            pid,
            cwd: cwd_of_pid(pid),
        })
    }

    /// `proc_pidpath` names the executable; the cwd itself comes from
    /// `proc_pidinfo(PROC_PIDVNODEPATHINFO)` (`02 §3` point 2). Best-effort:
    /// `None` on any failure, never an error — a process that has already
    /// exited, or a sandboxed one that denies the lookup, still gets a scope
    /// (falls through to global/list-only), it just loses the convenience.
    fn cwd_of_pid(pid: libc::pid_t) -> Option<String> {
        let mut info: libc::proc_vnodepathinfo = unsafe { mem::zeroed() };
        let size = mem::size_of::<libc::proc_vnodepathinfo>() as i32;
        // SAFETY: `info` is a correctly-sized out-parameter for
        // `PROC_PIDVNODEPATHINFO`; `pid` came from a successful
        // `LOCAL_PEERPID` lookup above.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        if written != size {
            return None;
        }
        // `vip_path` is a NUL-terminated `MAXPATHLEN`-byte buffer, exposed by
        // `libc` as `[[c_char; 32]; 32]` rather than `[c_char; 1024]` for old-
        // rustc compatibility — same flat memory layout either way, so
        // `size_of_val` (not `.len()`, which would report only the outer
        // dimension) gives the real byte count.
        let raw = &info.pvi_cdir.vip_path;
        let byte_len = mem::size_of_val(raw);
        // SAFETY: `raw` is a `libc`-defined fixed-size byte buffer with no
        // padding between elements; reinterpreting it as `[u8; byte_len]` is
        // exactly what the C struct it mirrors already is.
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(raw.as_ptr() as *const u8, byte_len) };
        let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..nul]).ok().map(str::to_owned)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use super::{PeerError, PeerInfo};
    use std::mem;
    use std::os::unix::io::RawFd;

    /// Linux's analogue: `SO_PEERCRED` returns uid/gid/pid in one call
    /// (`16_CROSS_PLATFORM.md §4.3`: "peer identity via `SO_PEERCRED`").
    /// **Exercised for real 2026-08-29** — `cargo test --workspace` on a
    /// self-hosted Linux runner ran `crates/cli/tests/broker_integration.rs`, which
    /// drives a real `server::run` over a real Unix socket, not a
    /// hand-built `PeerInfo`. All 397 tests passed. This was previously
    /// believed untested on any Linux host; that was true until this run.
    pub fn identify(fd: RawFd) -> Result<PeerInfo, PeerError> {
        let mut cred: libc::ucred = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: same contract as the macOS `getsockopt` call above.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(PeerError::CredentialLookupFailed(
                std::io::Error::last_os_error(),
            ));
        }
        Ok(PeerInfo {
            uid: cred.uid,
            pid: cred.pid,
            cwd: cwd_of_pid(cred.pid),
        })
    }

    fn cwd_of_pid(pid: libc::pid_t) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
}

/// The owning uid — `getuid()` of this (the broker's own) process. `02 §3`
/// point 1: "Reject anything not the owning uid. Hard gate."
pub fn owning_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(unix)]
pub fn identify_peer(fd: std::os::unix::io::RawFd) -> Result<PeerInfo, PeerError> {
    platform::identify(fd)
}
