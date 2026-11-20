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

    /// ADR-148 §P1-5: a process's short name and parent pid, from `proc_pidinfo(PROC_PIDTBSDINFO)`.
    /// Best-effort, like the cwd: `None` when the process is gone or the lookup is denied.
    pub fn name_and_parent(pid: libc::pid_t) -> Option<(String, libc::pid_t)> {
        let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
        let size = mem::size_of::<libc::proc_bsdinfo>() as i32;
        // SAFETY: `info` is a correctly-sized out-parameter for `PROC_PIDTBSDINFO`.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        if written != size {
            return None;
        }
        // `pbi_name` is the longer name when set, else `pbi_comm`; both are NUL-terminated byte buffers.
        let pick = |raw: &[libc::c_char]| -> String {
            let bytes: Vec<u8> = raw
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let name = pick(&info.pbi_name);
        let name = if name.is_empty() {
            pick(&info.pbi_comm)
        } else {
            name
        };
        Some((name, info.pbi_ppid as libc::pid_t))
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

    /// ADR-148 §P1-5: `/proc/<pid>/comm` and the parent pid from `/proc/<pid>/stat`. Best-effort.
    pub fn name_and_parent(pid: libc::pid_t) -> Option<(String, libc::pid_t)> {
        let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // `pid (comm) state ppid ...` — the comm may hold spaces or parentheses, so split after the last ')'.
        let after = stat.rsplit_once(')')?.1;
        let ppid = after.split_whitespace().nth(1)?.parse().ok()?;
        Some((name.trim().to_string(), ppid))
    }
}

/// The owning uid — `getuid()` of this (the broker's own) process. `02 §3`
/// point 1: "Reject anything not the owning uid. Hard gate."
pub fn owning_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

/// How many ancestors [`describe`] walks looking for the system's root process before it gives up.
#[cfg(unix)]
const MAX_ANCESTORS: usize = 32;
/// How many process names [`describe`] shows before it elides the middle of the chain.
#[cfg(unix)]
const SHOWN_NAMES: usize = 4;
/// What the root of the process tree is called in the dialog.
#[cfg(unix)]
const ROOT_NAME: &str = if cfg!(target_os = "macos") {
    "launchd"
} else {
    "init"
};

/// ADR-148 §P1-5 (and its addendum): who is asking, in words a person reads in the Touch ID dialog — the
/// requesting process, its ancestors up to the system's root process, and its working directory:
/// `credmgr (pid 4021) <- zsh <- Terminal <- launchd, in ~/projects/acme`. The chain is walked all the
/// way to pid 1 (at most [`MAX_ANCESTORS`] steps); the first [`SHOWN_NAMES`] names are shown, then
/// `<- … (N more)`, then the root. When a lookup fails before pid 1 is reached the chain ends in
/// `<- ? (chain cut short)`, and a requester whose own parent is pid 1 (a double-forked or detached process,
/// or an app the system launched) shows `<- launchd` directly after it.
///
/// **A hint, not proof.** Every name here comes from the process table, which the requester controls: a
/// program can copy itself to a file called `zsh`, `cd` to the person's home folder, or detach so its parent
/// is pid 1. Advisory, like the cwd (AR-5): it informs the person, it decides nothing.
pub fn describe(peer: &PeerInfo) -> String {
    let mut chain: Vec<String> = Vec::new();
    #[cfg(unix)]
    {
        let mut names: Vec<String> = Vec::new();
        let mut pid = peer.pid as libc::pid_t;
        let mut reached_root = false;
        for _ in 0..MAX_ANCESTORS {
            if pid <= 1 {
                reached_root = true;
                break;
            }
            let Some((name, parent)) = platform::name_and_parent(pid) else {
                break;
            };
            let name: String = name.chars().filter(|c| !c.is_control()).take(40).collect();
            names.push(if names.is_empty() {
                format!("{name} (pid {pid})")
            } else {
                name
            });
            pid = parent;
        }
        if !names.is_empty() {
            let hidden = names.len().saturating_sub(SHOWN_NAMES);
            chain.extend(names.into_iter().take(SHOWN_NAMES));
            if hidden > 0 {
                chain.push(format!("… ({hidden} more)"));
            }
            chain.push(if reached_root {
                ROOT_NAME.to_string()
            } else {
                "? (chain cut short)".to_string()
            });
        }
    }
    if chain.is_empty() {
        chain.push(format!("pid {} (not found)", peer.pid));
    }
    let mut out = chain.join(" <- ");
    if let Some(cwd) = &peer.cwd {
        let cwd: String = cwd.chars().filter(|c| !c.is_control()).collect();
        out.push_str(", in ");
        out.push_str(&cwd);
    }
    out
}

#[cfg(unix)]
pub fn identify_peer(fd: std::os::unix::io::RawFd) -> Result<PeerInfo, PeerError> {
    platform::identify(fd)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// ADR-148 addendum: the chain is walked to the system's root process and says so, so a person sees where
    /// it ends; a pid that does not exist is said to be not found rather than shown as a bare number.
    #[test]
    fn the_requester_chain_is_walked_to_the_root_or_marked_cut_short() {
        let me = PeerInfo {
            uid: 0,
            pid: std::process::id() as i32,
            cwd: Some("/tmp/x".into()),
        };
        let text = describe(&me);
        assert!(
            text.contains(&format!("(pid {})", std::process::id())),
            "{text}"
        );
        assert!(text.ends_with(", in /tmp/x"), "{text}");
        let chain = text.trim_end_matches(", in /tmp/x");
        assert!(
            chain.ends_with(&format!(" <- {ROOT_NAME}"))
                || chain.ends_with(" <- ? (chain cut short)"),
            "the chain ends at the root or says it was cut short: {text}"
        );
        assert!(
            chain.split(" <- ").count() <= SHOWN_NAMES + 2,
            "at most {SHOWN_NAMES} names, an elision and the end: {text}"
        );

        let gone = PeerInfo {
            uid: 0,
            pid: i32::MAX - 7,
            cwd: None,
        };
        assert_eq!(describe(&gone), format!("pid {} (not found)", i32::MAX - 7));
    }
}
