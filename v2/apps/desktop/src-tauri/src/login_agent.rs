//! Start the broker at login (ADR-156, post-launch quick win 2).
//!
//! `credmgrd` is meant to be kept running by a launchd **user** agent,
//! `com.credmgr.brokerd` (`02_ARCHITECTURE.md §2`). Until now the agent file
//! (`crates/brokerd/packaging/com.credmgr.brokerd.plist`) was copied by hand.
//! These three shell commands do it from Settings and from the "cannot reach
//! its broker" screen, after the user asks:
//!
//! * `login_agent_status` — is the agent file there, is it what we would write,
//!   is it loaded, and which `credmgrd` it would start;
//! * `login_agent_install` — write `~/Library/LaunchAgents/com.credmgr.brokerd.plist`
//!   pointing at the bundled `credmgrd` **by absolute path**, then
//!   `launchctl bootstrap gui/<uid>` it (which starts the broker now, and at
//!   every login). Idempotent: an agent already in place and loaded is left
//!   alone, so a second click restarts nothing;
//! * `login_agent_uninstall` — `launchctl bootout gui/<uid>/com.credmgr.brokerd`
//!   (which stops the broker it started) and remove the file. Idempotent.
//!
//! **Never root.** Only the user's own `gui/<uid>` domain is ever named, uid 0
//! is refused, the plist carries no `UserName`/`GroupName`, and nothing here
//! asks for elevation. The broker's peer gate is uid-only, so a broker running
//! as anyone else could not be reached by its owner's clients anyway.
//!
//! Local to the shell: no broker op, no session, no vault data. Elsewhere than
//! macOS every command answers `platform_unsupported`.
//!
//! The rendering ([`render_plist`]), the path rules and the file write are plain
//! functions with no launchd in them, so their tests run on Linux.
//!
//! **ADR-162, the Mac App Store edition** (the `mas` cargo feature). A sandboxed app may not write
//! `~/Library/LaunchAgents` or run `launchctl`. There the same three commands drive `SMAppService`: the
//! agent's plist ships inside the bundle (`Contents/Library/LaunchAgents/com.credmgr.brokerd.plist`,
//! `packaging/mas/LaunchAgents/`) with a `BundleProgram` of `Contents/MacOS/credmgrd`, and
//! `login_agent_install` registers it (`-[SMAppService registerAndReturnError:]`), which is the user's
//! consent: nothing registers it but that button. macOS lists it under System Settings > General > Login
//! Items, where the user can switch it off at any time; when macOS wants the user to approve it there
//! (`requiresApproval`), install opens that pane. The same answer shape is kept, so the page needs no
//! change: `installed` = registered, `loaded` = enabled, `current` = registered or waiting for approval.

use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use crate::error::{BridgeError, ErrorSource};

/// The launchd label, the same as the packaged template's.
pub const LABEL: &str = "com.credmgr.brokerd";

/// The broker's executable name.
pub const DAEMON_NAME: &str = "credmgrd";

/// What the page is told. No vault data; the one path is the daemon's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginAgentStatus {
    /// `~/Library/LaunchAgents/com.credmgr.brokerd.plist` exists.
    pub installed: bool,
    /// It is byte-for-byte what [`install`] would write now.
    pub current: bool,
    /// launchd has the agent in this user's `gui/<uid>` domain.
    pub loaded: bool,
    /// The absolute path of the `credmgrd` the agent would start, or `None` when none was found.
    pub daemon: Option<String>,
}

fn failed(code: &str, message: impl Into<String>) -> BridgeError {
    BridgeError {
        source: ErrorSource::Bridge,
        code: code.to_string(),
        message: message.into(),
        detail: None,
    }
}

/// The error every command answers off macOS.
pub fn unsupported() -> BridgeError {
    failed(
        "platform_unsupported",
        "Start at login is not supported on this platform: it uses a macOS launchd user agent",
    )
}

/// Escape the five characters XML gives meaning to. A path may hold any of them
/// (`&` in a folder name is common); left raw, it would break the plist or add a key.
pub fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Remove `.` and resolve `..` lexically (no file-system access, so a symlinked
/// Homebrew path stays the stable symlink rather than one versioned Cellar path).
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// A path the plist may carry: absolute, already normalised, UTF-8, and free of
/// the control characters XML 1.0 cannot hold at all.
fn plist_safe(path: &Path, what: &str) -> Result<String, BridgeError> {
    if !path.is_absolute() {
        return Err(failed(
            "login_agent_failed",
            format!("the {what} path is not absolute"),
        ));
    }
    // Compared as text: `Path::components` hides a `.` in the middle, and the text is what goes into the file.
    if path
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        || normalize(path).as_os_str() != path.as_os_str()
    {
        return Err(failed(
            "login_agent_failed",
            format!("the {what} path is not normalised"),
        ));
    }
    let text = path.to_str().ok_or_else(|| {
        failed(
            "login_agent_failed",
            format!("the {what} path is not valid UTF-8"),
        )
    })?;
    if text.chars().any(char::is_control) {
        return Err(failed(
            "login_agent_failed",
            format!("the {what} path holds a control character"),
        ));
    }
    Ok(text.to_string())
}

/// Where the agent file lives: the user's own `~/Library/LaunchAgents`, never
/// `/Library/LaunchDaemons` (root's).
pub fn plist_path(home: &Path) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

/// The folder an earlier build pointed the broker's stdout and stderr at
/// (`~/Library/Logs/credmgr`). The agent now writes no such files (ADR-159 amendment); this is
/// only where [`remove_legacy_logs`] looks for the two it left behind.
fn legacy_log_dir(home: &Path) -> PathBuf {
    home.join("Library").join("Logs").join("credmgr")
}

/// The two uncapped files earlier builds' agents wrote (`brokerd.log`, `brokerd.err.log`). They
/// can hold the vault path and so the user name, and launchd never rotates them: removed when the
/// agent file is rewritten. Best effort; a file that is absent or cannot be removed is left.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn remove_legacy_logs(home: &Path) {
    let dir = legacy_log_dir(home);
    for name in ["brokerd.log", "brokerd.err.log"] {
        let _ = std::fs::remove_file(dir.join(name));
    }
}

/// The launchd domain the agent is loaded into: this user's GUI session. uid 0 is
/// refused: this app never installs anything as root.
pub fn domain_target(uid: u32) -> Result<String, BridgeError> {
    if uid == 0 {
        return Err(failed(
            "login_agent_failed",
            "refusing to install the broker for root: start at login is a per-user agent",
        ));
    }
    Ok(format!("gui/{uid}"))
}

/// The agent file, from the packaged template's choices (KeepAlive unless it exits
/// cleanly, RunAtLoad, a Background process), with the daemon by absolute path: launchd expands
/// no `~`. Standard output and error go to `/dev/null` (ADR-159 amendment): launchd never rotates
/// a log file, and the daemon's own rotated, name-free diagnostic log is the record.
pub fn render_plist(daemon: &Path, home: &Path) -> Result<String, BridgeError> {
    let daemon = xml_escape(&plist_safe(daemon, "credmgrd")?);
    plist_safe(home, "home folder")?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by the CredMgr app (Settings, Security, Start the broker at login). A per-user agent: never root. -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{daemon}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#
    ))
}

/// Write `content` to `path` unless it already holds exactly that. Writes a
/// sibling temporary file and renames it over, so a crash leaves the old file or
/// the new one, never half of one. Answers whether anything was written.
pub fn write_if_changed(path: &Path, content: &str) -> std::io::Result<bool> {
    if std::fs::read_to_string(path).is_ok_and(|old| old == content) {
        return Ok(false);
    }
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("the agent path has no folder"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{LABEL}.plist.tmp"));
    std::fs::write(&tmp, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(true)
}

/// Where a bundled or installed `credmgrd` can be, given the app's own executable:
/// beside it in `Contents/MacOS`, in `../Resources` or `../libexec`, then the two
/// install locations `RELEASE.md` names. Absolute and normalised.
pub fn daemon_candidates(exe: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = exe.parent() {
        out.push(normalize(&dir.join(DAEMON_NAME)));
        out.push(normalize(&dir.join("../Resources").join(DAEMON_NAME)));
        out.push(normalize(&dir.join("../libexec").join(DAEMON_NAME)));
    }
    out.push(PathBuf::from("/usr/local/bin").join(DAEMON_NAME));
    out.push(PathBuf::from("/opt/homebrew/bin").join(DAEMON_NAME));
    out.retain(|p| p.is_absolute());
    out
}

/// The `credmgrd` the agent would start: the first candidate that is a file.
pub fn locate_daemon() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    daemon_candidates(&exe).into_iter().find(|p| p.is_file())
}

/// ADR-162: the agent plist's file name inside the bundle's `Contents/Library/LaunchAgents` (the name
/// `+[SMAppService agentServiceWithPlistName:]` takes).
pub const MAS_AGENT_PLIST: &str = "com.credmgr.brokerd.plist";

/// ADR-162: the `BundleProgram` that plist names: the bundled broker, relative to the bundle root.
pub const MAS_BUNDLE_PROGRAM: &str = "Contents/MacOS/credmgrd";

/// `SMAppServiceStatus`, by raw value (ServiceManagement, macOS 13).
pub const SM_NOT_REGISTERED: isize = 0;
pub const SM_ENABLED: isize = 1;
pub const SM_REQUIRES_APPROVAL: isize = 2;
pub const SM_NOT_FOUND: isize = 3;

/// The page's answer for an `SMAppService` status (ADR-162). Pure, so the mapping is tested on Linux.
pub fn status_from_sm(raw: isize, daemon: Option<String>) -> Result<LoginAgentStatus, BridgeError> {
    let (installed, current, loaded) = match raw {
        SM_NOT_REGISTERED => (false, false, false),
        SM_ENABLED => (true, true, true),
        // Registered, but the user has to allow it in System Settings > Login Items before it runs.
        SM_REQUIRES_APPROVAL => (true, true, false),
        // The bundle carries no agent plist by that name: a broken MAS bundle, never a normal state.
        SM_NOT_FOUND => {
            return Err(failed(
                "login_agent_failed",
                format!(
                    "the app bundle carries no Contents/Library/LaunchAgents/{MAS_AGENT_PLIST}"
                ),
            ))
        }
        other => {
            return Err(failed(
                "login_agent_failed",
                format!("SMAppService answered an unknown status ({other})"),
            ))
        }
    };
    Ok(LoginAgentStatus {
        installed,
        current,
        loaded,
        daemon,
    })
}

/// ADR-162: `SMAppService`, for the sandboxed Mac App Store edition. Compiled only on macOS with the `mas`
/// feature. Written against the ServiceManagement API through `objc2`'s runtime messaging (no binding crate
/// is in the tree, and adding one would grow the dependency tree `tests/dependency_policy.rs` watches).
#[cfg(all(target_os = "macos", feature = "mas"))]
mod sm {
    use super::*;
    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject};
    use objc2_foundation::{NSError, NSString};

    // Links ServiceManagement.framework so the SMAppService class is registered with the runtime.
    #[link(name = "ServiceManagement", kind = "framework")]
    extern "C" {}

    fn class() -> Result<&'static AnyClass, BridgeError> {
        AnyClass::get(c"SMAppService").ok_or_else(|| {
            failed(
                "login_agent_failed",
                "SMAppService is not available (it needs macOS 13 or later)",
            )
        })
    }

    fn service() -> Result<Retained<AnyObject>, BridgeError> {
        let name = NSString::from_str(MAS_AGENT_PLIST);
        // SAFETY: `+agentServiceWithPlistName:` takes an NSString and returns an SMAppService (never nil
        // per its header; checked anyway).
        let svc: Option<Retained<AnyObject>> =
            unsafe { msg_send![class()?, agentServiceWithPlistName: &*name] };
        svc.ok_or_else(|| failed("login_agent_failed", "SMAppService gave no agent service"))
    }

    fn raw_status(svc: &AnyObject) -> isize {
        // SAFETY: `status` is a readonly NSInteger property (SMAppServiceStatus).
        unsafe { msg_send![svc, status] }
    }

    fn open_login_items() {
        if let Ok(cls) = class() {
            // SAFETY: a class method taking and returning nothing (macOS 13).
            let _: () = unsafe { msg_send![cls, openSystemSettingsLoginItems] };
        }
    }

    fn describe(err: &NSError) -> String {
        err.localizedDescription().to_string()
    }

    /// The bundled broker the agent starts: `Contents/MacOS/credmgrd` beside the app's executable.
    fn bundled_daemon() -> Option<String> {
        let exe = std::env::current_exe().ok()?;
        let daemon = exe.parent()?.join(DAEMON_NAME);
        daemon.is_file().then(|| daemon.display().to_string())
    }

    pub fn status() -> Result<LoginAgentStatus, BridgeError> {
        status_from_sm(raw_status(&service()?), bundled_daemon())
    }

    pub fn install() -> Result<LoginAgentStatus, BridgeError> {
        let svc = service()?;
        match raw_status(&svc) {
            SM_ENABLED => return status(), // already registered and allowed: nothing restarted
            SM_REQUIRES_APPROVAL => {
                open_login_items();
                return status();
            }
            _ => {}
        }
        // SAFETY: `-registerAndReturnError:` returns BOOL and fills an NSError** on failure, which the
        // `_` marker turns into the Err side.
        let done: Result<(), Retained<NSError>> =
            unsafe { msg_send![&*svc, registerAndReturnError: _] };
        if let Err(e) = done {
            if raw_status(&svc) == SM_REQUIRES_APPROVAL {
                open_login_items();
                return status();
            }
            return Err(failed(
                "login_agent_failed",
                format!("macOS refused to register the broker: {}", describe(&e)),
            ));
        }
        if raw_status(&svc) == SM_REQUIRES_APPROVAL {
            open_login_items();
        }
        status()
    }

    pub fn uninstall() -> Result<LoginAgentStatus, BridgeError> {
        let svc = service()?;
        if raw_status(&svc) == SM_NOT_REGISTERED {
            return status();
        }
        // SAFETY: as for register.
        let done: Result<(), Retained<NSError>> =
            unsafe { msg_send![&*svc, unregisterAndReturnError: _] };
        if let Err(e) = done {
            if raw_status(&svc) != SM_NOT_REGISTERED {
                return Err(failed(
                    "login_agent_failed",
                    format!("macOS refused to unregister the broker: {}", describe(&e)),
                ));
            }
        }
        status()
    }
}

#[cfg(all(target_os = "macos", not(feature = "mas")))]
mod mac {
    use super::*;
    use std::process::{Command, Stdio};

    /// Absolute, so a `PATH` entry cannot stand in for them.
    const LAUNCHCTL: &str = "/bin/launchctl";
    const ID: &str = "/usr/bin/id";

    fn uid() -> Result<u32, BridgeError> {
        let out = Command::new(ID)
            .arg("-u")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| failed("login_agent_failed", format!("could not run id: {e}")))?;
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<u32>()
            .map_err(|_| failed("login_agent_failed", "could not read this user's id"))
    }

    fn home() -> Result<PathBuf, BridgeError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| failed("login_agent_failed", "HOME is not set"))?;
        if !home.is_absolute() {
            return Err(failed("login_agent_failed", "HOME is not an absolute path"));
        }
        Ok(normalize(&home))
    }

    fn launchctl(args: &[&str]) -> Result<std::process::Output, BridgeError> {
        Command::new(LAUNCHCTL)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                failed(
                    "login_agent_failed",
                    format!("could not run launchctl: {e}"),
                )
            })
    }

    fn loaded(domain: &str) -> Result<bool, BridgeError> {
        Ok(launchctl(&["print", &format!("{domain}/{LABEL}")])?
            .status
            .success())
    }

    pub fn status() -> Result<LoginAgentStatus, BridgeError> {
        let domain = domain_target(uid()?)?;
        let home = home()?;
        let path = plist_path(&home);
        let daemon = locate_daemon();
        let on_disk = std::fs::read_to_string(&path).ok();
        let current = match (&on_disk, &daemon) {
            (Some(text), Some(d)) => render_plist(d, &home).is_ok_and(|want| &want == text),
            _ => false,
        };
        Ok(LoginAgentStatus {
            installed: on_disk.is_some(),
            current,
            loaded: loaded(&domain)?,
            daemon: daemon.map(|d| d.display().to_string()),
        })
    }

    pub fn install() -> Result<LoginAgentStatus, BridgeError> {
        let domain = domain_target(uid()?)?;
        let home = home()?;
        let daemon = locate_daemon().ok_or_else(|| {
            failed(
                "login_agent_failed",
                "no credmgrd was found beside the app, in /usr/local/bin or in /opt/homebrew/bin",
            )
        })?;
        let content = render_plist(&daemon, &home)?;
        let path = plist_path(&home);
        let was_loaded = loaded(&domain)?;
        remove_legacy_logs(&home);
        let changed = write_if_changed(&path, &content).map_err(|e| {
            failed(
                "login_agent_failed",
                format!("could not write the agent file: {e}"),
            )
        })?;
        if was_loaded && !changed {
            return status(); // already in place and running: nothing to do, nothing restarted
        }
        if was_loaded {
            // A loaded agent keeps the definition it was loaded with: reload it so the new file counts.
            let _ = launchctl(&["bootout", &format!("{domain}/{LABEL}")]);
        }
        let path_text = path
            .to_str()
            .ok_or_else(|| failed("login_agent_failed", "the agent path is not valid UTF-8"))?;
        let out = launchctl(&["bootstrap", &domain, path_text])?;
        if !out.status.success() && !loaded(&domain)? {
            return Err(failed(
                "login_agent_failed",
                format!(
                    "launchctl bootstrap {domain} refused the agent: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            ));
        }
        status()
    }

    pub fn uninstall() -> Result<LoginAgentStatus, BridgeError> {
        let domain = domain_target(uid()?)?;
        let path = plist_path(&home()?);
        if loaded(&domain)? {
            let out = launchctl(&["bootout", &format!("{domain}/{LABEL}")])?;
            if !out.status.success() && loaded(&domain)? {
                return Err(failed(
                    "login_agent_failed",
                    format!(
                        "launchctl bootout refused: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                ));
            }
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(failed(
                    "login_agent_failed",
                    format!("could not remove the agent file: {e}"),
                ))
            }
        }
        status()
    }
}

/// `login_agent_status`.
pub fn status() -> Result<LoginAgentStatus, BridgeError> {
    #[cfg(all(target_os = "macos", not(feature = "mas")))]
    {
        mac::status()
    }
    #[cfg(all(target_os = "macos", feature = "mas"))]
    {
        sm::status()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(unsupported())
    }
}

/// `login_agent_install`.
pub fn install() -> Result<LoginAgentStatus, BridgeError> {
    #[cfg(all(target_os = "macos", not(feature = "mas")))]
    {
        mac::install()
    }
    #[cfg(all(target_os = "macos", feature = "mas"))]
    {
        sm::install()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(unsupported())
    }
}

/// `login_agent_uninstall`.
pub fn uninstall() -> Result<LoginAgentStatus, BridgeError> {
    #[cfg(all(target_os = "macos", not(feature = "mas")))]
    {
        mac::uninstall()
    }
    #[cfg(all(target_os = "macos", feature = "mas"))]
    {
        sm::uninstall()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/Users/alice";

    fn rendered(daemon: &str) -> String {
        render_plist(Path::new(daemon), Path::new(HOME)).expect("renders")
    }

    #[test]
    fn the_daemon_is_named_by_its_absolute_path_and_its_output_goes_nowhere() {
        let p = rendered("/Applications/CredMgr.app/Contents/MacOS/credmgrd");
        assert!(p.contains(
            "<array>\n        <string>/Applications/CredMgr.app/Contents/MacOS/credmgrd</string>\n    </array>"
        ));
        assert!(p.contains("<key>StandardOutPath</key>\n    <string>/dev/null</string>"));
        assert!(p.contains("<key>StandardErrorPath</key>\n    <string>/dev/null</string>"));
        assert!(
            !p.contains(HOME),
            "the agent file names no home folder: nothing in it carries the user name"
        );
        assert!(
            !p.contains('~'),
            "launchd expands no ~: every path is absolute"
        );
        assert!(p.contains(&format!("<string>{LABEL}</string>")));
    }

    #[test]
    fn a_relative_or_unnormalised_daemon_path_is_refused() {
        for bad in [
            "credmgrd",
            "./credmgrd",
            "bin/credmgrd",
            "/Applications/../tmp/credmgrd",
            "/a/./credmgrd",
        ] {
            let e = render_plist(Path::new(bad), Path::new(HOME)).unwrap_err();
            assert_eq!(e.code, "login_agent_failed", "{bad}");
        }
        let e = render_plist(
            Path::new("/usr/local/bin/credmgrd"),
            Path::new("Users/alice"),
        )
        .unwrap_err();
        assert_eq!(
            e.code, "login_agent_failed",
            "a relative home is refused too"
        );
        let e = render_plist(Path::new("/tmp/a\nb/credmgrd"), Path::new(HOME)).unwrap_err();
        assert_eq!(
            e.code, "login_agent_failed",
            "a control character cannot go into XML"
        );
    }

    #[test]
    fn the_agent_is_per_user_and_never_root() {
        let p = rendered("/usr/local/bin/credmgrd");
        for key in [
            "UserName",
            "GroupName",
            "InitGroups",
            "RootDirectory",
            "sudo",
        ] {
            assert!(!p.contains(key), "the agent must not carry {key}");
        }
        assert_eq!(domain_target(501).unwrap(), "gui/501");
        assert!(
            domain_target(501).unwrap().starts_with("gui/"),
            "the user's own GUI domain, never system/"
        );
        assert_eq!(
            domain_target(0).unwrap_err().code,
            "login_agent_failed",
            "uid 0 is refused"
        );
        let path = plist_path(Path::new(HOME));
        assert_eq!(
            path,
            Path::new("/Users/alice/Library/LaunchAgents/com.credmgr.brokerd.plist")
        );
        assert!(
            !path.starts_with("/Library"),
            "never the system-wide folders"
        );
    }

    #[test]
    fn a_path_with_xml_characters_is_escaped_and_cannot_add_a_key() {
        let p = rendered("/Users/alice/Tools & <Apps>/\"x\"/it's/credmgrd");
        assert!(p.contains(
            "<string>/Users/alice/Tools &amp; &lt;Apps&gt;/&quot;x&quot;/it&apos;s/credmgrd</string>"
        ));
        let injected = rendered("/x/</string><key>UserName</key><string>root/credmgrd");
        assert!(!injected.contains("<key>UserName</key>"));
        assert_eq!(
            injected.matches("<key>").count(),
            rendered("/x/credmgrd").matches("<key>").count()
        );
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn the_template_keeps_the_packaged_agents_lifecycle() {
        let p = rendered("/usr/local/bin/credmgrd");
        assert!(p.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(p.contains(
            "<key>KeepAlive</key>\n    <dict>\n        <key>SuccessfulExit</key>\n        <false/>"
        ));
        assert!(p.contains("<key>ProcessType</key>\n    <string>Background</string>"));
        assert!(p.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        // The packaged template agrees on the label and the lifecycle keys.
        let packaged =
            include_str!("../../../../crates/brokerd/packaging/com.credmgr.brokerd.plist");
        for key in [
            "<string>com.credmgr.brokerd</string>",
            "<key>RunAtLoad</key>",
            "<key>SuccessfulExit</key>",
            "<string>Background</string>",
        ] {
            assert!(packaged.contains(key) && p.contains(key), "{key}");
        }
    }

    #[test]
    fn writing_is_idempotent_and_replaces_a_different_file_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = plist_path(dir.path());
        let a = rendered("/usr/local/bin/credmgrd");
        assert!(
            write_if_changed(&path, &a).unwrap(),
            "first write creates the folder and the file"
        );
        assert!(
            !write_if_changed(&path, &a).unwrap(),
            "the same content is not written again"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), a);
        let b = rendered("/opt/homebrew/bin/credmgrd");
        assert!(write_if_changed(&path, &b).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), b);
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "no temporary file is left behind");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
    }

    #[test]
    fn the_daemon_candidates_are_absolute_and_normalised_beside_the_app_first() {
        let c = daemon_candidates(Path::new(
            "/Applications/CredMgr.app/Contents/MacOS/CredMgr",
        ));
        assert_eq!(
            c[0],
            Path::new("/Applications/CredMgr.app/Contents/MacOS/credmgrd")
        );
        assert_eq!(
            c[1],
            Path::new("/Applications/CredMgr.app/Contents/Resources/credmgrd")
        );
        assert_eq!(
            c[2],
            Path::new("/Applications/CredMgr.app/Contents/libexec/credmgrd")
        );
        assert_eq!(c[3], Path::new("/usr/local/bin/credmgrd"));
        for p in &c {
            assert!(p.is_absolute());
            assert!(render_plist(p, Path::new(HOME)).is_ok(), "{}", p.display());
        }
    }

    #[test]
    fn the_sm_app_service_statuses_map_onto_the_same_answer_the_page_reads() {
        let d = || Some("/Applications/CredMgr.app/Contents/MacOS/credmgrd".to_string());
        let s = status_from_sm(SM_NOT_REGISTERED, d()).unwrap();
        assert!(!s.installed && !s.current && !s.loaded);
        let s = status_from_sm(SM_ENABLED, d()).unwrap();
        assert!(s.installed && s.current && s.loaded);
        assert_eq!(s.daemon, d());
        let s = status_from_sm(SM_REQUIRES_APPROVAL, None).unwrap();
        assert!(
            s.installed && s.current && !s.loaded,
            "registered but not yet allowed: installed, not running"
        );
        assert_eq!(
            status_from_sm(SM_NOT_FOUND, d()).unwrap_err().code,
            "login_agent_failed"
        );
        assert_eq!(
            status_from_sm(7, d()).unwrap_err().code,
            "login_agent_failed"
        );
    }

    #[test]
    fn the_bundled_mas_agent_plist_names_the_bundled_broker_and_nothing_outside_the_bundle() {
        let plist =
            include_str!("../../../../packaging/mas/LaunchAgents/com.credmgr.brokerd.plist");
        assert!(plist.contains(&format!("<key>Label</key>\n    <string>{LABEL}</string>")));
        assert!(plist.contains(&format!(
            "<key>BundleProgram</key>\n    <string>{MAS_BUNDLE_PROGRAM}</string>"
        )));
        assert_eq!(MAS_AGENT_PLIST, format!("{LABEL}.plist"));
        assert!(MAS_BUNDLE_PROGRAM.ends_with(&format!("/{DAEMON_NAME}")));
        // Inside the bundle only: no absolute program path, no log file outside the sandbox, never root.
        for key in [
            "<key>Program</key>",
            "<key>ProgramArguments</key>",
            "StandardOutPath",
            "StandardErrorPath",
            "UserName",
            "GroupName",
            "/usr/local",
            "/Users/",
        ] {
            assert!(
                !plist.contains(key),
                "the MAS agent plist must not carry {key}"
            );
        }
        // The packaged agent's lifecycle, kept.
        for key in [
            "<key>RunAtLoad</key>\n    <true/>",
            "<key>SuccessfulExit</key>\n        <false/>",
            "<key>ProcessType</key>\n    <string>Background</string>",
        ] {
            assert!(plist.contains(key), "{key}");
        }
    }

    #[test]
    fn the_two_uncapped_logs_of_earlier_builds_are_removed_and_nothing_else() {
        let home = tempfile::tempdir().unwrap();
        let logs = home.path().join("Library").join("Logs").join("credmgr");
        std::fs::create_dir_all(&logs).unwrap();
        for name in [
            "brokerd.log",
            "brokerd.err.log",
            "credmgrd.log",
            "desktop.log",
        ] {
            std::fs::write(logs.join(name), "x").unwrap();
        }
        remove_legacy_logs(home.path());
        assert!(!logs.join("brokerd.log").exists());
        assert!(!logs.join("brokerd.err.log").exists());
        assert!(
            logs.join("credmgrd.log").exists() && logs.join("desktop.log").exists(),
            "the capped diagnostic logs (ADR-159) are not touched"
        );
        remove_legacy_logs(&home.path().join("nowhere")); // absent folder: no panic
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn off_macos_every_command_says_not_supported() {
        for r in [status(), install(), uninstall()] {
            let e = r.unwrap_err();
            assert_eq!(e.code, "platform_unsupported");
            assert!(e.message.contains("not supported on this platform"));
        }
    }
}
