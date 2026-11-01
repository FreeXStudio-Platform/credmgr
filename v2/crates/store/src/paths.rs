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

/// `16 §5` "Vault" row.
pub fn default_vault_dir() -> PathBuf {
    if let Some(over) = env::var_os("CREDMGR_VAULT_DIR") {
        return PathBuf::from(over);
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

    #[test]
    fn vault_and_state_dirs_never_coincide() {
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
