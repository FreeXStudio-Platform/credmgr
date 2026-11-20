//! On-disk layout (`docs/02_ARCHITECTURE.md §7`) and per-OS default
//! locations (`docs/16_CROSS_PLATFORM.md §5`).
//!
//! Path resolution is hand-rolled from environment variables rather than
//! pulling in a `dirs`-family crate — see ADR-039. `VaultPaths` itself is a
//! plain struct over a base directory so every test constructs one over a
//! throwaway `tempdir()` instead of touching a real home directory.

use std::env;
use std::path::{Path, PathBuf};

/// The vault root and every path inside it. Construct with an explicit
/// `base` (tests, `--vault-dir`) or [`VaultPaths::default_location`].
#[derive(Debug, Clone)]
pub struct VaultPaths {
    base: PathBuf,
}

impl VaultPaths {
    pub fn new(base: PathBuf) -> Self {
        VaultPaths { base }
    }

    /// `16_CROSS_PLATFORM.md §5`, "Vault" row. Never inside a repository —
    /// the same rule V1's `lib/paths.js` enforces (`16 §5`'s own note).
    pub fn default_location() -> Self {
        VaultPaths::new(default_vault_dir())
    }

    pub fn root(&self) -> &Path {
        &self.base
    }

    pub fn config(&self) -> PathBuf {
        self.base.join("config.json")
    }

    /// ADR-165 (review N4): `vault.id`, the vault's random identity, written by the first machine-lock bind.
    /// It travels with every copy and backup of the folder; a machine's bind record is keyed by it, never by
    /// the folder's path. Not secret.
    pub fn vault_id(&self) -> PathBuf {
        self.base.join("vault.id")
    }

    pub fn registry(&self) -> PathBuf {
        self.base.join("registry.json")
    }

    pub fn registry_sig(&self) -> PathBuf {
        self.base.join("registry.sig")
    }

    /// The previous signed registry pair, kept by `registry_file::save` so an
    /// interrupted two-file write can be recovered (ADR-063). The external
    /// generation counter decides whether it may ever be used: once a newer
    /// write completed, this pair is one generation behind and is refused.
    pub fn registry_prev(&self) -> PathBuf {
        self.base.join("registry.json.prev")
    }

    pub fn registry_sig_prev(&self) -> PathBuf {
        self.base.join("registry.sig.prev")
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.base.join("keys")
    }

    pub fn root_wrap_se(&self) -> PathBuf {
        self.keys_dir().join("root.wrap.se")
    }

    /// ADR-098: the enrolled presence public keys, HMAC'd under the root key.
    pub fn presence_enroll(&self) -> PathBuf {
        self.keys_dir().join("presence.enroll")
    }

    pub fn root_wrap_pass(&self) -> PathBuf {
        self.keys_dir().join("root.wrap.pass")
    }

    pub fn root_wrap_recovery(&self) -> PathBuf {
        self.keys_dir().join("root.wrap.recovery")
    }

    pub fn node_key(&self, node_id: &str) -> PathBuf {
        self.keys_dir().join("nodes").join(format!("{node_id}.key"))
    }

    /// ADR-079: `keys/cold/` — the one directory that holds a key the broker
    /// never loads into its hot set. Today exactly one file lives in it,
    /// [`VaultPaths::orphan_key`].
    pub fn keys_cold_dir(&self) -> PathBuf {
        self.keys_dir().join("cold")
    }

    /// The orphan node's private half, sealed under a key derived from the root
    /// key (`credmgr_core::cold`, format `CMCK` v1). Not a node key: it is never
    /// under `keys/nodes/`, never wrapped by `node-wrap/<id>`, never resident.
    pub fn orphan_key(&self) -> PathBuf {
        self.keys_cold_dir().join("orphan.key")
    }

    pub fn nodes_dir(&self) -> PathBuf {
        self.base.join("nodes")
    }

    pub fn node_dir(&self, node_id: &str) -> PathBuf {
        self.base.join("nodes").join(node_id)
    }

    pub fn entry_env(&self, node_id: &str, entry_id: &str) -> PathBuf {
        self.node_dir(node_id)
            .join("entries")
            .join(format!("{entry_id}.env"))
    }

    pub fn pending_env(&self, node_id: &str, entry_id: &str) -> PathBuf {
        self.node_dir(node_id)
            .join("pending")
            .join(format!("{entry_id}.env"))
    }

    /// ADR-069: the locked-write tray's metadata for one pending envelope —
    /// untrusted, like the envelope beside it; a human reviews both at
    /// `vault.pending_accept`.
    pub fn pending_meta(&self, node_id: &str, entry_id: &str) -> PathBuf {
        self.node_dir(node_id)
            .join("pending")
            .join(format!("{entry_id}.meta.json"))
    }

    pub fn notes_env(&self, node_id: &str) -> PathBuf {
        self.node_dir(node_id).join("notes.env")
    }

    /// ADR-168: the node's merge decision memory (dismissed suggestions), sealed to the node's key like
    /// the note, its digest recorded in the signed manifest (`mergeSha256`).
    pub fn merge_env(&self, node_id: &str) -> PathBuf {
        self.node_dir(node_id).join("merge.env")
    }

    pub fn manifest(&self, node_id: &str) -> PathBuf {
        self.node_dir(node_id).join("manifest.json")
    }

    pub fn totp_item(&self, node_id: &str, item_id: &str) -> PathBuf {
        self.base
            .join("totp")
            .join(node_id)
            .join(format!("{item_id}.env"))
    }

    /// `year_month` is `"YYYY-MM"`.
    pub fn audit_log(&self, year_month: &str) -> PathBuf {
        self.base.join("audit").join(format!("{year_month}.log"))
    }

    pub fn audit_dir(&self) -> PathBuf {
        self.base.join("audit")
    }

    /// `maintenance.backup`'s output directory (ADR-054). Files are named
    /// `credmgr-backup-<unix-seconds>.enc` — never touched by anything but
    /// that op's own create/list/prune logic.
    pub fn backups_dir(&self) -> PathBuf {
        self.base.join("backups")
    }

    pub fn archive_dir(&self, sealed_id: &str) -> PathBuf {
        self.base.join("archive").join(sealed_id)
    }

    /// `archive/` itself — holds one directory per sealed node, plus the two
    /// reserved siblings `removed-entries/` and `entry-history/`.
    pub fn archive_root(&self) -> PathBuf {
        self.base.join("archive")
    }

    /// ADR-076: where a root-key rotation stages its replacement files until
    /// the commit marker inside makes them binding. Inside the vault
    /// directory so it is the same filesystem as the files it replaces, and
    /// outside every directory a backup, `verify` or `doctor` walks.
    pub fn rotation_stage(&self) -> PathBuf {
        self.base.join("rotation-pending")
    }

    /// ADR-130: where `node.rekey` stages everything it is about to replace for one node
    /// (`rekey-pending/<node>/`): the new wrapped key, copies of the old key file and manifest, and
    /// every re-sealed file. Nothing reads it except the rekey recovery; like the rotation stage it
    /// sits on the same filesystem as the files it replaces and outside every directory a backup,
    /// `verify` or `doctor` walks.
    pub fn rekey_stage_root(&self) -> PathBuf {
        self.base.join("rekey-pending")
    }

    pub fn rekey_stage(&self, node_id: &str) -> PathBuf {
        self.rekey_stage_root().join(node_id)
    }

    /// ADR-158: where `entry.move` stages one move (`move-pending/<entry>/`): copies of both nodes'
    /// manifests as they were before the move, and a plan sealed under the root key. Nothing reads it
    /// except the move recovery; like the rekey stage it sits outside every directory a backup,
    /// `verify` or `doctor` walks.
    pub fn move_stage_root(&self) -> PathBuf {
        self.base.join("move-pending")
    }

    pub fn move_stage(&self, entry_id: &str) -> PathBuf {
        self.move_stage_root().join(entry_id)
    }

    /// ADR-131: the journal `orphan.destroy` writes before its commit so a crash after the commit
    /// still ends with the files gone (`<vault>/orphan-destroy.pending`, sealed under the root key).
    pub fn orphan_destroy_journal(&self) -> PathBuf {
        self.base.join("orphan-destroy.pending")
    }

    /// `entry.remove`'s 7-day soft-delete archive (ADR-048) — distinct from
    /// `archive_dir`'s whole-node seal: this holds one entry's envelope plus
    /// its signed manifest snapshot, never a node key.
    fn removed_entry_dir(&self, node_id: &str, entry_id: &str) -> PathBuf {
        self.base
            .join("archive")
            .join("removed-entries")
            .join(node_id)
            .join(entry_id)
    }

    pub fn removed_entry_env(&self, node_id: &str, entry_id: &str) -> PathBuf {
        self.removed_entry_dir(node_id, entry_id).join("entry.env")
    }

    pub fn removed_entry_meta(&self, node_id: &str, entry_id: &str) -> PathBuf {
        self.removed_entry_dir(node_id, entry_id)
            .join("removed.json")
    }

    /// `entry.rotate`'s retained previous ciphertext (ADR-048) — a plain
    /// file copy of the envelope being replaced, keyed by the manifest
    /// generation it was current as of. Not integrity-signed on its own:
    /// nothing restores from it yet (that's `entry.history`'s future job),
    /// so there is no freshness claim to forge — the envelope's own AEAD tag
    /// already makes silent tampering with its *contents* detectable.
    pub fn entry_history_env(&self, node_id: &str, entry_id: &str, generation: u64) -> PathBuf {
        self.base
            .join("archive")
            .join("entry-history")
            .join(node_id)
            .join(entry_id)
            .join(format!("{generation}.env"))
    }

    /// `rotation_history`'s signed snapshot of a manifest entry's fields as
    /// of `generation` (ADR-055) — sibling to `entry_history_env`'s raw
    /// ciphertext at the same generation, the identical split
    /// `removed_entry_env`/`removed_entry_meta` already use for a removed
    /// entry. Added once `entry.undo` needed to restore *correctly*, not
    /// merely prove a prior value existed.
    pub fn entry_history_meta(&self, node_id: &str, entry_id: &str, generation: u64) -> PathBuf {
        self.base
            .join("archive")
            .join("entry-history")
            .join(node_id)
            .join(entry_id)
            .join(format!("{generation}.json"))
    }

    pub fn run_dir(&self) -> PathBuf {
        self.base.join("run")
    }

    pub fn run_socket(&self) -> PathBuf {
        self.run_dir().join("broker.sock")
    }

    /// ADR-076: the advisory lock file every process holds exclusively while it
    /// recovers an interrupted root-key rotation or runs one. It lives under
    /// `run/` — runtime state, never walked by a backup, a verify or the
    /// root-key rotation itself — and carries no data: the lock is the open
    /// file description, released by the OS the instant its holder dies.
    pub fn rotation_lock(&self) -> PathBuf {
        self.run_dir().join("rotation.lock")
    }
}

/// `16 §5` "Vault" row. In the Mac App Store flavour (ADR-162) the default is
/// the app-group container instead: [`mas_vault_dir`].
pub fn default_vault_dir() -> PathBuf {
    if let Some(over) = env::var_os("CREDMGR_VAULT_DIR") {
        return PathBuf::from(over);
    }
    if FLAVOUR == Flavour::Mas {
        return mas_vault_dir(&home_dir(), &mas_app_group());
    }
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .join("Library")
            .join("Application Support")
            .join("credmgr")
    }
    #[cfg(target_os = "windows")]
    {
        env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home_dir)
            .join("credmgr")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".local").join("share"))
            .join("credmgr")
    }
}

/// ADR-061: V1 parity (`v1/CHANGELOG.md` 1.9.0 — "`credmgr init` refuses to
/// create a vault inside a git repository, and every command warns if an
/// existing vault is in one"). `default_vault_dir` above never reads cwd, so
/// the *default* path is structurally safe already; a `CREDMGR_VAULT_DIR`
/// override pointed at a checkout is not, which is what this exists to
/// catch. Shared by `credmgr-cli` (a courtesy, fast, no-broker-round-trip
/// check before even calling `vault.init_begin`) and `credmgr-brokerd` (the
/// authoritative check, inside `BrokerState::begin_init`) — one
/// implementation rather than two that could quietly disagree.
///
/// Walks up from `path` looking for a `.git` entry. Works whether or not
/// `path` itself exists yet, since `Path::join`/`Path::exists` need no part
/// of the tree to be real.
pub fn is_inside_git_working_tree(path: &Path) -> bool {
    let mut current = Some(path);
    while let Some(dir) = current {
        if dir.join(".git").exists() {
            return true;
        }
        current = dir.parent();
    }
    false
}

/// A per-user location for state that must live **outside** the vault
/// directory — currently only the [`crate::generation`] counter file, per
/// `04_CRYPTO_AND_KEYS.md §6a` ("outside the vault directory") and
/// `16_CROSS_PLATFORM.md §4.3`'s own Linux fallback path, generalised to
/// every platform per ADR-039.
pub fn default_state_dir() -> PathBuf {
    if let Some(over) = env::var_os("CREDMGR_STATE_DIR") {
        return PathBuf::from(over);
    }
    if FLAVOUR == Flavour::Mas {
        return mas_state_dir(&home_dir(), &mas_app_group());
    }
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .join("Library")
            .join("Application Support")
            .join("credmgr-state")
    }
    #[cfg(target_os = "windows")]
    {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home_dir)
            .join("credmgr")
            .join("state")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".local").join("state"))
            .join("credmgr")
    }
}

/// ADR-159: the diagnostic log's directory (`16_CROSS_PLATFORM.md §6.1`, "Logs" row). Outside the
/// vault on purpose: nothing in it is vault data, a backup never carries it, and deleting it loses
/// nothing but history. `CREDMGR_LOG_DIR` overrides, the same way `CREDMGR_VAULT_DIR` moves a vault;
/// else `~/Library/Logs/credmgr` on macOS, `%LOCALAPPDATA%\credmgr\logs` on Windows, and
/// `$XDG_STATE_HOME/credmgr/logs` or `~/.local/state/credmgr/logs` elsewhere. The desktop shell
/// mirrors this table in `apps/desktop/src-tauri/src/vault_paths.rs::log_dir_from`, held to it by
/// `tests/drift_guards.rs`.
pub fn default_log_dir() -> PathBuf {
    if let Some(over) = env::var_os("CREDMGR_LOG_DIR") {
        return PathBuf::from(over);
    }
    #[cfg(target_os = "macos")]
    {
        home_dir().join("Library").join("Logs").join("credmgr")
    }
    #[cfg(target_os = "windows")]
    {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home_dir)
            .join("credmgr")
            .join("logs")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".local").join("state"))
            .join("credmgr")
            .join("logs")
    }
}

// ---------------------------------------------------------------------------------------------
// ADR-162: the Mac App Store flavour.
//
// A sandboxed process sees only its own container and the app-group containers its signature names, so
// the MAS edition keeps the vault, the socket and the state directory in the group container
// `~/Library/Group Containers/<TEAMID>.<name>/`, shared by the app, `credmgrd` (an SMAppService agent),
// the bundled CLI and the Touch ID helper. Selected at compile time by the `mas` cargo feature, so a
// default build cannot reach any of it. The group id is read from `packaging/mas/identity.conf`, the one
// file the operator edits when the final ids are chosen (26_PRODUCT_PLAN_2X.md §9 decision 4).

/// Which edition this binary is (ADR-162).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// The Developer ID edition: LaunchAgent broker, CLI on PATH, Application Support paths.
    Direct,
    /// The Mac App Store edition: sandboxed, everything in the app-group container.
    Mas,
}

/// The flavour this binary was compiled as: [`Flavour::Mas`] only with the `mas` feature.
pub const FLAVOUR: Flavour = if cfg!(feature = "mas") {
    Flavour::Mas
} else {
    Flavour::Direct
};

/// `packaging/mas/identity.conf`, compiled in. The desktop shell includes the same file
/// (`vault_paths.rs`), so the two workspaces cannot disagree on the group id.
pub const MAS_IDENTITY: &str = include_str!("../../../packaging/mas/identity.conf");

/// The vault's folder inside the group container. Short on purpose: see [`SOCKET_PATH_MAX`].
pub const MAS_VAULT_SUBDIR: &str = "vault";

/// The state directory's folder inside the group container: a sibling of the vault, never inside it
/// (ADR-039 holds in both flavours).
pub const MAS_STATE_SUBDIR: &str = "state";

/// The longest socket path `bind`/`connect` take on macOS: `sun_path` is 104 bytes, one of them the NUL.
pub const SOCKET_PATH_MAX: usize = 103;

/// The value of `key` in an `identity.conf`-format text (`KEY=VALUE` lines, `#` comments).
pub fn mas_identity_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// `<MAS_TEAM_ID>.<MAS_APP_GROUP_NAME>` from `text`. A group id that starts with the Team ID is what
/// macOS 15 accepts without asking the user for access (memo 04 §1.1).
pub fn mas_app_group_from(text: &str) -> Option<String> {
    let team = mas_identity_value(text, "MAS_TEAM_ID")?;
    let name = mas_identity_value(text, "MAS_APP_GROUP_NAME")?;
    Some(format!("{team}.{name}"))
}

/// The compiled-in app-group id.
pub fn mas_app_group() -> String {
    mas_app_group_from(MAS_IDENTITY)
        .expect("packaging/mas/identity.conf names MAS_TEAM_ID and MAS_APP_GROUP_NAME")
}

/// The user's real home folder, given `$HOME`. Inside the sandbox `$HOME` may be the app's own container,
/// `<home>/Library/Containers/<bundle id>/Data`; the group container hangs off the real home, so that
/// suffix is removed. Lexical only: no file-system access, no `getpwuid` (this crate forbids `unsafe`).
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

/// `<real home>/Library/Group Containers/<group>`.
pub fn group_container(home: &Path, group: &str) -> PathBuf {
    real_home(home)
        .join("Library")
        .join("Group Containers")
        .join(group)
}

/// The MAS flavour's vault directory: `<group container>/vault`.
pub fn mas_vault_dir(home: &Path, group: &str) -> PathBuf {
    group_container(home, group).join(MAS_VAULT_SUBDIR)
}

/// The MAS flavour's state directory: `<group container>/state`.
pub fn mas_state_dir(home: &Path, group: &str) -> PathBuf {
    group_container(home, group).join(MAS_STATE_SUBDIR)
}

/// Whether `socket` is short enough for a Unix socket on macOS ([`SOCKET_PATH_MAX`]).
pub fn socket_path_fits(socket: &Path) -> bool {
    socket.as_os_str().len() <= SOCKET_PATH_MAX
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
fn home_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .expect("USERPROFILE must be set on Windows")
    }
    #[cfg(not(target_os = "windows"))]
    {
        env::var_os("HOME")
            .map(PathBuf::from)
            .expect("HOME must be set")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests that change `CREDMGR_VAULT_DIR`/`CREDMGR_STATE_DIR` hold this, so they cannot see each
    /// other's half-restored environment (`cargo test` runs them on parallel threads in one process).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn layout_matches_02_architecture_7() {
        let p = VaultPaths::new(PathBuf::from("/vault"));
        assert_eq!(p.registry(), PathBuf::from("/vault/registry.json"));
        assert_eq!(p.registry_sig(), PathBuf::from("/vault/registry.sig"));
        assert_eq!(
            p.node_key("n_aaaaaaaa"),
            PathBuf::from("/vault/keys/nodes/n_aaaaaaaa.key")
        );
        assert_eq!(p.orphan_key(), PathBuf::from("/vault/keys/cold/orphan.key"));
        assert_eq!(
            p.entry_env("n_aaaaaaaa", "e_bbbbbbbbbbbb"),
            PathBuf::from("/vault/nodes/n_aaaaaaaa/entries/e_bbbbbbbbbbbb.env")
        );
        assert_eq!(
            p.pending_env("n_aaaaaaaa", "e_bbbbbbbbbbbb"),
            PathBuf::from("/vault/nodes/n_aaaaaaaa/pending/e_bbbbbbbbbbbb.env")
        );
        assert_eq!(
            p.pending_meta("n_aaaaaaaa", "e_bbbbbbbbbbbb"),
            PathBuf::from("/vault/nodes/n_aaaaaaaa/pending/e_bbbbbbbbbbbb.meta.json")
        );
        assert_eq!(
            p.manifest("n_aaaaaaaa"),
            PathBuf::from("/vault/nodes/n_aaaaaaaa/manifest.json")
        );
        assert_eq!(
            p.audit_log("2026-08"),
            PathBuf::from("/vault/audit/2026-08.log")
        );
        assert_eq!(
            p.archive_dir("n_aaaaaaaa"),
            PathBuf::from("/vault/archive/n_aaaaaaaa")
        );
        assert_eq!(p.run_socket(), PathBuf::from("/vault/run/broker.sock"));
    }

    #[test]
    fn entry_archive_paths_stay_under_archive_and_never_collide_with_node_seal() {
        let p = VaultPaths::new(PathBuf::from("/vault"));
        assert_eq!(
            p.removed_entry_env("n_aaaaaaaa", "e_bbbbbbbbbbbb"),
            PathBuf::from("/vault/archive/removed-entries/n_aaaaaaaa/e_bbbbbbbbbbbb/entry.env")
        );
        assert_eq!(
            p.removed_entry_meta("n_aaaaaaaa", "e_bbbbbbbbbbbb"),
            PathBuf::from("/vault/archive/removed-entries/n_aaaaaaaa/e_bbbbbbbbbbbb/removed.json")
        );
        assert_eq!(
            p.entry_history_env("n_aaaaaaaa", "e_bbbbbbbbbbbb", 5),
            PathBuf::from("/vault/archive/entry-history/n_aaaaaaaa/e_bbbbbbbbbbbb/5.env")
        );
        // A node-sealed archive (`archive/<nodeId>/...`) and a removed-entry
        // archive (`archive/removed-entries/<nodeId>/...`) must never share a
        // path even when `node_id` and `entry_id` collide as strings — the
        // `removed-entries`/`entry-history` path segments are what keep
        // `archive_dir`'s flat namespace from ever aliasing with either.
        assert_ne!(
            p.archive_dir("n_aaaaaaaa"),
            p.removed_entry_env("n_aaaaaaaa", "e_bbbbbbbbbbbb")
                .parent()
                .unwrap()
        );
    }

    #[test]
    fn env_override_wins_on_every_platform() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY-of-intent note (not unsafe code): this mutates process-wide
        // env state, which is inherently test-order-sensitive; scoped to this
        // single assertion and restored immediately.
        let prev = env::var_os("CREDMGR_VAULT_DIR");
        env::set_var("CREDMGR_VAULT_DIR", "/tmp/credmgr-test-vault");
        assert_eq!(
            default_vault_dir(),
            PathBuf::from("/tmp/credmgr-test-vault")
        );
        match prev {
            Some(v) => env::set_var("CREDMGR_VAULT_DIR", v),
            None => env::remove_var("CREDMGR_VAULT_DIR"),
        }
    }

    // ---- ADR-162: the Mac App Store flavour -------------------------------------------------

    const IDENTITY: &str = "# comment\nMAS_TEAM_ID=ABCDE12345\nMAS_BUNDLE_ID=com.example.app\n\
                            MAS_APP_GROUP_NAME=credmgr\nMAS_IDS_FINAL=no\n";

    #[test]
    fn the_default_build_is_the_direct_flavour_and_the_mas_feature_selects_mas() {
        assert_eq!(
            FLAVOUR,
            if cfg!(feature = "mas") {
                Flavour::Mas
            } else {
                Flavour::Direct
            }
        );
    }

    #[test]
    fn the_identity_file_is_parsed_key_by_key_and_comments_are_skipped() {
        assert_eq!(
            mas_identity_value(IDENTITY, "MAS_TEAM_ID"),
            Some("ABCDE12345")
        );
        assert_eq!(mas_identity_value(IDENTITY, "MAS_IDS_FINAL"), Some("no"));
        assert_eq!(mas_identity_value(IDENTITY, "MISSING"), None);
        assert_eq!(
            mas_identity_value("# MAS_TEAM_ID=commented\n", "MAS_TEAM_ID"),
            None
        );
        assert_eq!(
            mas_identity_value("MAS_TEAM_ID=\n", "MAS_TEAM_ID"),
            None,
            "empty is absent"
        );
        assert_eq!(
            mas_app_group_from(IDENTITY).as_deref(),
            Some("ABCDE12345.credmgr")
        );
    }

    #[test]
    fn the_compiled_in_identity_is_the_marked_placeholder_until_the_operator_chooses() {
        // The real file: a group prefixed by a ten-character team id, and the final flag present.
        let group = mas_app_group();
        let team = mas_identity_value(MAS_IDENTITY, "MAS_TEAM_ID").unwrap();
        assert_eq!(
            team.len(),
            10,
            "a Team ID is ten characters (the placeholder too)"
        );
        assert!(group.starts_with(&format!("{team}.")), "{group}");
        let final_flag = mas_identity_value(MAS_IDENTITY, "MAS_IDS_FINAL").unwrap();
        assert!(final_flag == "yes" || final_flag == "no");
        if final_flag == "no" {
            assert_eq!(
                team, "XXXXXXXXXX",
                "until chosen, the placeholder is the marked one"
            );
        } else {
            assert_ne!(
                team, "XXXXXXXXXX",
                "MAS_IDS_FINAL=yes with the placeholder team id"
            );
        }
        assert!(mas_identity_value(MAS_IDENTITY, "MAS_BUNDLE_ID").is_some());
    }

    #[test]
    fn the_real_home_is_recovered_from_a_sandbox_container_home() {
        assert_eq!(
            real_home(Path::new(
                "/Users/alice/Library/Containers/com.example.app/Data"
            )),
            PathBuf::from("/Users/alice")
        );
        assert_eq!(
            real_home(Path::new("/Users/alice")),
            PathBuf::from("/Users/alice")
        );
        // Only the exact container shape is stripped.
        assert_eq!(
            real_home(Path::new("/Users/alice/Library/Data")),
            PathBuf::from("/Users/alice/Library/Data")
        );
    }

    #[test]
    fn the_mas_layout_puts_vault_and_state_side_by_side_in_the_group_container() {
        let home = Path::new("/Users/alice/Library/Containers/com.example.app/Data");
        let vault = mas_vault_dir(home, "ABCDE12345.credmgr");
        let state = mas_state_dir(home, "ABCDE12345.credmgr");
        assert_eq!(
            vault,
            PathBuf::from("/Users/alice/Library/Group Containers/ABCDE12345.credmgr/vault")
        );
        assert_eq!(
            state,
            PathBuf::from("/Users/alice/Library/Group Containers/ABCDE12345.credmgr/state")
        );
        assert_ne!(vault, state);
        assert!(
            !state.starts_with(&vault) && !vault.starts_with(&state),
            "ADR-039"
        );
        assert_eq!(
            VaultPaths::new(vault).run_socket(),
            PathBuf::from(
                "/Users/alice/Library/Group Containers/ABCDE12345.credmgr/vault/run/broker.sock"
            )
        );
    }

    #[test]
    fn the_mas_socket_fits_the_104_byte_limit_for_a_thirty_character_user_name() {
        let group = mas_app_group();
        let user = "a".repeat(30);
        let socket = VaultPaths::new(mas_vault_dir(&PathBuf::from("/Users").join(user), &group))
            .run_socket();
        assert!(
            socket_path_fits(&socket),
            "{} bytes: {}",
            socket.as_os_str().len(),
            socket.display()
        );
        // The limit is real: a path one byte over is refused.
        let long = PathBuf::from(format!("/{}", "a".repeat(SOCKET_PATH_MAX)));
        assert!(!socket_path_fits(&long));
        assert!(socket_path_fits(&PathBuf::from(format!(
            "/{}",
            "a".repeat(SOCKET_PATH_MAX - 1)
        ))));
    }

    #[test]
    #[cfg(feature = "mas")]
    fn the_mas_flavour_defaults_to_the_group_container_and_the_override_still_wins() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_vault = env::var_os("CREDMGR_VAULT_DIR");
        let prev_state = env::var_os("CREDMGR_STATE_DIR");
        env::remove_var("CREDMGR_VAULT_DIR");
        env::remove_var("CREDMGR_STATE_DIR");
        let vault = default_vault_dir();
        let state = default_state_dir();
        assert!(
            vault.ends_with(PathBuf::from(mas_app_group()).join("vault")),
            "{}",
            vault.display()
        );
        assert!(
            state.ends_with(PathBuf::from(mas_app_group()).join("state")),
            "{}",
            state.display()
        );
        assert!(vault
            .to_string_lossy()
            .contains("/Library/Group Containers/"));
        env::set_var("CREDMGR_VAULT_DIR", "/tmp/credmgr-mas-override");
        assert_eq!(
            default_vault_dir(),
            PathBuf::from("/tmp/credmgr-mas-override")
        );
        match prev_vault {
            Some(v) => env::set_var("CREDMGR_VAULT_DIR", v),
            None => env::remove_var("CREDMGR_VAULT_DIR"),
        }
        if let Some(v) = prev_state {
            env::set_var("CREDMGR_STATE_DIR", v);
        }
    }

    #[test]
    fn the_log_dir_is_never_the_vault_and_its_override_wins() {
        // ADR-159: the diagnostic log lives outside the vault, so a backup never carries it.
        let prev_vault = env::var_os("CREDMGR_VAULT_DIR");
        let prev_log = env::var_os("CREDMGR_LOG_DIR");
        env::remove_var("CREDMGR_VAULT_DIR");
        env::remove_var("CREDMGR_LOG_DIR");
        let log = default_log_dir();
        assert!(!log.starts_with(default_vault_dir()));
        assert!(log.ends_with("credmgr") || log.ends_with("logs"));
        env::set_var("CREDMGR_LOG_DIR", "/tmp/credmgr-test-logs");
        assert_eq!(default_log_dir(), PathBuf::from("/tmp/credmgr-test-logs"));
        match prev_log {
            Some(v) => env::set_var("CREDMGR_LOG_DIR", v),
            None => env::remove_var("CREDMGR_LOG_DIR"),
        }
        if let Some(v) = prev_vault {
            env::set_var("CREDMGR_VAULT_DIR", v);
        }
    }

    #[test]
    fn vault_and_state_dirs_never_coincide() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // ADR-039: the generation counter must live outside the vault
        // directory, or a rollback of the vault directory rolls it back too.
        let prev_vault = env::var_os("CREDMGR_VAULT_DIR");
        let prev_state = env::var_os("CREDMGR_STATE_DIR");
        env::remove_var("CREDMGR_VAULT_DIR");
        env::remove_var("CREDMGR_STATE_DIR");
        assert_ne!(default_vault_dir(), default_state_dir());
        if let Some(v) = prev_vault {
            env::set_var("CREDMGR_VAULT_DIR", v);
        }
        if let Some(v) = prev_state {
            env::set_var("CREDMGR_STATE_DIR", v);
        }
    }
}
