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

use std::env;
use std::path::{Path, PathBuf};

/// The one override, honoured on every platform. A constant because the
/// drift guard greps for this exact string in both trees.
pub const VAULT_DIR_ENV: &str = "CREDMGR_VAULT_DIR";
pub const RUN_DIR_NAME: &str = "run";
pub const SOCKET_FILE_NAME: &str = "broker.sock";

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
    vault_dir_from(
        env::var_os(VAULT_DIR_ENV).map(PathBuf::from),
        platform_base.map(PathBuf::from),
        home.map(PathBuf::from),
    )
    .as_deref()
    .map(socket_in)
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
    fn no_home_and_no_override_resolves_to_nothing_rather_than_a_wrong_path() {
        // The dangerous failure would be silently returning a relative path
        // like "credmgr/run/broker.sock" and connecting to whatever happens
        // to be at the process's cwd.
        assert_eq!(vault_dir_from(None, None, None), None);
    }
}
