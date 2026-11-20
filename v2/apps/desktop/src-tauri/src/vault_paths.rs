//! Where the broker's socket is — a deliberate, guarded re-implementation of
//! `crates/store/src/paths.rs`.
//!
//! **Why this is copied rather than imported.** ADR-035 puts
//! `apps/desktop/src-tauri` in its own Cargo workspace on current stable,
//! precisely so Tauri's edition-2024 dependency tree cannot drag the
//! security crates off their 1.78 MSRV pin. Taking a path dependency on
//! `credmgr-store` to obtain four lines of path arithmetic would pull the
//! whole crypto tree, and that pin, back across the boundary the ADR drew —
//! a real coupling bought for a trivial gain.
//!
//! **Why that is safe anyway.** A hand-copied rule drifts in silence, and a
//! test that only checked this copy against itself would pass on both sides
//! of any divergence. So `tests/drift_guards.rs` reads
//! `crates/store/src/paths.rs` *from disk* and asserts the rule below still
//! matches the original. The duplication is real; the drift risk is pinned.
//!
//! The rule, verbatim from `paths.rs`: resolve the vault directory, then
//! append `run/broker.sock`. `CREDMGR_VAULT_DIR` overrides the vault
//! directory unconditionally on every platform. Nothing else is consulted —
//! no config file, no socket-specific override. (`CREDMGR_STATE_DIR` exists
//! but is unrelated: it points at the generation counter, which lives
//! outside the vault by design — ADR-039, `04_CRYPTO_AND_KEYS.md §6a`.)
//!
//! Resolution is split into a **pure** [`vault_dir_from`] plus a thin
//! environment read, so the branch table can be tested exhaustively without
//! mutating process-global state. `cargo test` runs unit tests on parallel
//! threads in one process; a test that called `env::set_var` would be
//! reaching into every other test's world at the same time.

//!
//! **ADR-162, the Mac App Store flavour.** With the `mas` cargo feature the vault defaults to the
//! app-group container, `<real home>/Library/Group Containers/<group>/vault`, as `paths.rs::mas_vault_dir`
//! does. The group id is read from the very file `crates/store` reads (`packaging/mas/identity.conf`,
//! `include_str!` on both sides), so the two workspaces cannot name different groups; the layout around
//! it is held to `paths.rs` by the drift guard like the rest of this file.

use std::env;
use std::path::{Path, PathBuf};

/// The one override, honoured on every platform. A constant because the
/// drift guard greps for this exact string in both trees.
pub const VAULT_DIR_ENV: &str = "CREDMGR_VAULT_DIR";
pub const RUN_DIR_NAME: &str = "run";
pub const SOCKET_FILE_NAME: &str = "broker.sock";

/// ADR-162: whether this shell was built as the Mac App Store edition (the `mas` feature).
pub const MAS: bool = cfg!(feature = "mas");

/// `packaging/mas/identity.conf` - the same bytes `crates/store/src/paths.rs` includes.
pub const MAS_IDENTITY: &str = include_str!("../../../../packaging/mas/identity.conf");
pub const GROUP_CONTAINERS: &str = "Group Containers";
pub const MAS_VAULT_SUBDIR: &str = "vault";

/// The value of `key` in `identity.conf` text, parsed as `paths.rs::mas_identity_value` parses it.
pub fn mas_identity_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// `<MAS_TEAM_ID>.<MAS_APP_GROUP_NAME>`.
pub fn mas_app_group() -> Option<String> {
    let team = mas_identity_value(MAS_IDENTITY, "MAS_TEAM_ID")?;
    let name = mas_identity_value(MAS_IDENTITY, "MAS_APP_GROUP_NAME")?;
    Some(format!("{team}.{name}"))
}

/// The real home folder behind a sandbox container home (`<home>/Library/Containers/<id>/Data`), as
/// `paths.rs::real_home` computes it.
pub fn real_home(home: &Path) -> PathBuf {
    let parts: Vec<_> = home.components().collect();
    let n = parts.len();
    if n >= 4
        && parts[n - 1].as_os_str() == "Data"
        && parts[n - 3].as_os_str() == "Containers"
        && parts[n - 4].as_os_str() == "Library"
    {
        return parts[..n - 4].iter().collect();
    }
    home.to_path_buf()
}

/// `<real home>/Library/Group Containers/<group>/vault`.
pub fn mas_vault_dir(home: &Path, group: &str) -> PathBuf {
    real_home(home)
        .join("Library")
        .join(GROUP_CONTAINERS)
        .join(group)
        .join(MAS_VAULT_SUBDIR)
}

/// The per-OS default, as a pure function of the two things it depends on.
///
/// `platform_base` is `%APPDATA%` on Windows and `$XDG_DATA_HOME` elsewhere;
/// it is ignored on macOS, which has a fixed location. `home` is `None` only
/// when the process has no `HOME`/`USERPROFILE` at all — see
/// [`resolve_socket_path`] for why that is reported rather than panicked on.
pub fn vault_dir_from(
    override_dir: Option<PathBuf>,
    platform_base: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(over) = override_dir {
        return Some(over);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = platform_base;
        Some(
            home?
                .join("Library")
                .join("Application Support")
                .join("credmgr"),
        )
    }
    #[cfg(target_os = "windows")]
    {
        Some(platform_base.or(home)?.join("credmgr"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let base = match platform_base {
            Some(base) => base,
            None => home?.join(".local").join("share"),
        };
        Some(base.join("credmgr"))
    }
}

/// `<vault>/run/broker.sock`.
pub fn socket_in(vault_dir: &Path) -> PathBuf {
    vault_dir.join(RUN_DIR_NAME).join(SOCKET_FILE_NAME)
}

/// ADR-159: the diagnostic log's override, honoured on every platform, and the directory name the
/// non-macOS defaults end in. Constants because the drift guard greps for them in `crates/store`.
pub const LOG_DIR_ENV: &str = "CREDMGR_LOG_DIR";
pub const LOGS_DIR_NAME: &str = "logs";

/// `crates/store/src/paths.rs::default_log_dir`, as a pure function (ADR-159, `16 §6.1`).
///
/// `platform_base` is `%LOCALAPPDATA%` on Windows and `$XDG_STATE_HOME` elsewhere; ignored on macOS,
/// which uses `~/Library/Logs/credmgr`. `None` only when there is no override and no home.
pub fn log_dir_from(
    override_dir: Option<PathBuf>,
    platform_base: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(over) = override_dir {
        return Some(over);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = platform_base;
        Some(home?.join("Library").join("Logs").join("credmgr"))
    }
    #[cfg(target_os = "windows")]
    {
        Some(platform_base.or(home)?.join("credmgr").join(LOGS_DIR_NAME))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let base = match platform_base {
            Some(base) => base,
            None => home?.join(".local").join("state"),
        };
        Some(base.join("credmgr").join(LOGS_DIR_NAME))
    }
}

/// The live log directory for this process; `None` with no home and no override.
pub fn resolve_log_dir() -> Option<PathBuf> {
    let platform_base = if cfg!(target_os = "windows") {
        env::var_os("LOCALAPPDATA")
    } else {
        env::var_os("XDG_STATE_HOME")
    };
    let home = if cfg!(target_os = "windows") {
        env::var_os("USERPROFILE")
    } else {
        env::var_os("HOME")
    };
    log_dir_from(
        env::var_os(LOG_DIR_ENV).map(PathBuf::from),
        platform_base.map(PathBuf::from),
        home.map(PathBuf::from),
    )
}

/// The live socket path for this process.
///
/// `None` when the vault directory cannot be resolved at all — a process
/// with no `HOME`. `crates/store` panics in that case, which is right for a
/// CLI; a desktop app that did the same would show the user a crash instead
/// of "I cannot find your vault", so this reports it and the caller turns it
/// into an ordinary transport error.
pub fn resolve_socket_path() -> Option<PathBuf> {
    let platform_base = if cfg!(target_os = "windows") {
        env::var_os("APPDATA")
    } else {
        env::var_os("XDG_DATA_HOME")
    };
    let home = if cfg!(target_os = "windows") {
        env::var_os("USERPROFILE")
    } else {
        env::var_os("HOME")
    };
    let override_dir = env::var_os(VAULT_DIR_ENV).map(PathBuf::from);
    if MAS {
        return flavour_vault_dir(true, override_dir, home.map(PathBuf::from))
            .as_deref()
            .map(socket_in);
    }
    vault_dir_from(
        override_dir,
        platform_base.map(PathBuf::from),
        home.map(PathBuf::from),
    )
    .as_deref()
    .map(socket_in)
}

/// The MAS flavour's branch of [`resolve_socket_path`], pure: the override still wins (as in
/// `paths.rs`), then the group container. `mas == false` answers `None` (the caller uses
/// [`vault_dir_from`] then).
pub fn flavour_vault_dir(
    mas: bool,
    override_dir: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    if !mas {
        return None;
    }
    if let Some(over) = override_dir {
        return Some(over);
    }
    Some(mas_vault_dir(&home?, &mas_app_group()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<PathBuf> {
        Some(PathBuf::from(s))
    }

    #[test]
    fn the_override_wins_over_every_platform_default() {
        let dir = vault_dir_from(p("/tmp/explicit"), p("/tmp/platform"), p("/home/alice"));
        assert_eq!(dir, p("/tmp/explicit"));
    }

    #[test]
    fn the_socket_always_hangs_off_the_vault_root() {
        assert_eq!(
            socket_in(Path::new("/tmp/explicit")),
            PathBuf::from("/tmp/explicit/run/broker.sock")
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_uses_application_support_and_ignores_xdg() {
        let dir = vault_dir_from(None, p("/tmp/xdg"), p("/home/alice"));
        assert_eq!(
            dir,
            p("/home/alice/Library/Application Support/credmgr"),
            "macOS has a fixed location; XDG_DATA_HOME must not influence it"
        );
    }

    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn unix_prefers_xdg_then_falls_back_to_dot_local_share() {
        assert_eq!(
            vault_dir_from(None, p("/tmp/xdg"), p("/home/alice")),
            p("/tmp/xdg/credmgr")
        );
        assert_eq!(
            vault_dir_from(None, None, p("/home/alice")),
            p("/home/alice/.local/share/credmgr")
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_prefers_appdata_then_falls_back_to_the_profile() {
        assert_eq!(
            vault_dir_from(
                None,
                p("C:/Users/alice/AppData/Roaming"),
                p("C:/Users/alice")
            ),
            p("C:/Users/alice/AppData/Roaming/credmgr")
        );
        assert_eq!(
            vault_dir_from(None, None, p("C:/Users/alice")),
            p("C:/Users/alice/credmgr")
        );
    }

    #[test]
    fn the_log_override_wins_and_no_home_resolves_to_nothing() {
        assert_eq!(
            log_dir_from(p("/tmp/logs"), p("/tmp/state"), p("/home/alice")),
            p("/tmp/logs")
        );
        assert_eq!(log_dir_from(None, None, None), None);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_logs_go_to_library_logs() {
        assert_eq!(
            log_dir_from(None, p("/tmp/xdg-state"), p("/home/alice")),
            p("/home/alice/Library/Logs/credmgr")
        );
    }

    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn unix_logs_prefer_xdg_state_then_dot_local_state() {
        assert_eq!(
            log_dir_from(None, p("/tmp/xdg-state"), p("/home/alice")),
            p("/tmp/xdg-state/credmgr/logs")
        );
        assert_eq!(
            log_dir_from(None, None, p("/home/alice")),
            p("/home/alice/.local/state/credmgr/logs")
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_logs_prefer_localappdata_then_the_profile() {
        assert_eq!(
            log_dir_from(None, p("C:/Users/alice/AppData/Local"), p("C:/Users/alice")),
            p("C:/Users/alice/AppData/Local/credmgr/logs")
        );
        assert_eq!(
            log_dir_from(None, None, p("C:/Users/alice")),
            p("C:/Users/alice/credmgr/logs")
        );
    }

    #[test]
    fn the_mas_flavour_resolves_into_the_group_container_and_the_override_still_wins() {
        let group = mas_app_group().expect("identity.conf names the group");
        let dir = flavour_vault_dir(
            true,
            None,
            p("/Users/alice/Library/Containers/com.credmgr.desktop/Data"),
        );
        assert_eq!(
            dir,
            Some(PathBuf::from(format!(
                "/Users/alice/Library/Group Containers/{group}/vault"
            )))
        );
        assert_eq!(
            flavour_vault_dir(true, p("/tmp/explicit"), p("/Users/alice")),
            p("/tmp/explicit")
        );
        assert_eq!(
            flavour_vault_dir(true, None, None),
            None,
            "no home: nothing, never a relative path"
        );
        assert_eq!(flavour_vault_dir(false, None, p("/Users/alice")), None);
        assert_eq!(MAS, cfg!(feature = "mas"));
    }

    #[test]
    fn no_home_and_no_override_resolves_to_nothing_rather_than_a_wrong_path() {
        // The dangerous failure would be silently returning a relative path
        // like "credmgr/run/broker.sock" and connecting to whatever happens
        // to be at the process's cwd.
        assert_eq!(vault_dir_from(None, None, None), None);
    }
}
