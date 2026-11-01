//! The CredMgr desktop shell's Rust side — the bridge between the webview
//! and `credmgrd`.
//!
//! `02_ARCHITECTURE.md §3` and ADR-001: the broker is the single enforcement
//! point, and every client is a socket peer that holds no node key. This
//! crate is one such client. It does not decrypt, does not read key files,
//! and makes no authorization decision of its own — it carries requests to
//! `credmgrd` and answers back, and the one piece of state it owns is
//! custody of the session token (see [`session`], and ADR-057).
//!
//! ## Layout
//!
//! | module | job |
//! |---|---|
//! | [`vault_paths`] | resolve `<vault>/run/broker.sock`, guarded against drift from `crates/store` |
//! | [`transport`] | one request, one response, over the UDS |
//! | [`error`] | the single error shape, carrying the broker's own vocabulary |
//! | [`session`] | holds the ADR-056 token; never lets it reach the webview |
//! | [`commands`] | the `#[tauri::command]` surface `invoke()` can reach |
//! | [`clipboard`] | the concealed, self-clearing pasteboard (`entry_copy`, `copy_text`) |
//! | [`fields_preview`] | the live preview of a bulk paste (`fields_preview`) - local, no broker call |
//! | [`autolock`] | lock the vault on sleep, screen lock and session switch |
//! | [`shell`] | window-inactive events and the clear on quit |
//!
//! ## The shell's own commands
//!
//! Three commands are not broker ops: `entry_copy` (reveals Rust-side and writes
//! the concealed clipboard, so the value never enters the webview), `copy_text`
//! (non-secret text) and `fields_preview` (ADR-078: parses and infers a bulk paste
//! with `credmgr-core`, locally - no socket, no session, no audit record; what it
//! shows is what `entry_create` will store). They are listed in
//! [`commands::SHELL_COMMANDS`] and held to `bridge.ts` and to this file's
//! `generate_handler!` by the same tests as the rest. Two events flow the
//! other way, from the shell to the webview: [`autolock::EVENT_LOCKED`] and
//! [`shell::EVENT_WINDOW_INACTIVE`].
//!
//! ## No network stack
//!
//! This crate links no HTTP client and opens no socket but the broker's Unix
//! one. `tests/dependency_policy.rs` runs `cargo tree` for the shipped targets
//! and fails if `reqwest`, `hyper`, `ureq` or `isahc` appears; `deny.toml` bans
//! the same crates in CI.
//!
//! ## Coverage
//!
//! All 55 of the broker's operations are reachable here (completed
//! 2026-09-24, ADR-062; `node.update`/`node.policy` added by ADR-071,
//! `notes.read`/`notes.write` by ADR-072, `entry.create_batch` by ADR-073,
//! `maintenance.rotate_root` by ADR-076, `entry.get` and the four `field.*`
//! operations by ADR-078): eight hand-written commands for the
//! read and authentication surface, plus forty-five generated from one table in
//! [`commands`] (`bridge_ops!`). Each is a thin pass-through — one op, the
//! caller's params, the broker's answer unreshaped. The screens that drive
//! the mutating families do not exist yet (Phase 6); wiring the bridge ahead
//! of them is safe because the bridge makes no UX decision — `generation`,
//! presence and approval semantics all live broker-side and reach the UI as
//! the broker's own error codes ([`error::BROKER_ERROR_CODES`]).
//! `tests/drift_guards.rs` holds the table against `ops.rs` on disk in both
//! directions, and holds this file's `generate_handler!` against the table.

pub mod autolock;
pub mod clipboard;
pub mod commands;
pub mod error;
pub mod fields_preview;
pub mod icon;
pub mod session;
pub mod shell;
pub mod transport;
pub mod tray;
pub mod vault_paths;

/// Wire the shell onto a builder: the managed state, the OS observers, the
/// window and run-event handlers and the command table.
///
/// Generic over the runtime so `tests/shell_ipc.rs` builds *this exact
/// configuration* on Tauri's mock runtime and drives it through the real IPC
/// path. `run()` is this plus the real window; there is no second wiring to
/// drift from the tested one.
pub fn configure<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    clipboard: clipboard::Clipboard,
) -> tauri::Builder<R> {
    builder
        // One `Session` for the whole app: the login is the process's, not a
        // window's, exactly as the broker models it (`vault.lock` revokes
        // every outstanding token at once, not per-connection).
        .manage(session::Session::new())
        // One clipboard owner, so "clear only if it is still ours" has exactly
        // one definition of "ours".
        .manage(clipboard)
        .setup(|app| {
            autolock::observers::install(app.handle());
            shell::apply_content_protection(app.handle());
            // The menu-bar icon. A shell without one (a mock runtime, a desktop with no tray) still works: the window is the app.
            if let Err(e) = tray::install(app.handle()) {
                eprintln!("credmgr: no menu-bar icon: {e}");
            }
            Ok(())
        })
        .on_window_event(shell::on_window_event)
        .invoke_handler(tauri::generate_handler![
            // The shell's own (commands::SHELL_COMMANDS) — not broker ops.
            commands::entry_copy,
            commands::copy_text,
            commands::fields_preview,
            commands::app_icon_set,
            commands::capture_protection_set,
            // Hand-written — token custody and AuthState (commands::HAND_WRITTEN).
            commands::vault_status,
            commands::vault_unlock,
            commands::vault_gate_verify,
            commands::vault_lock,
            commands::whoami,
            commands::graph_snapshot,
            commands::entry_list,
            commands::entry_reveal,
            // Generated by bridge_ops! (commands::TABLE). tests/drift_guards.rs
            // fails if a row there is missing here.
            commands::vault_init_begin,
            commands::vault_init_confirm,
            commands::vault_gate_enroll_begin,
            commands::vault_gate_enroll_confirm,
            commands::vault_gate_recover,
            commands::vault_pending_list,
            commands::vault_pending_accept,
            commands::vault_pending_discard,
            commands::vault_approval_decide,
            commands::vault_approval_get,
            commands::vault_node_lock,
            commands::vault_node_unlock,
            commands::node_list,
            commands::node_create,
            commands::node_set_workdirs,
            commands::node_update,
            commands::node_policy,
            commands::notes_read,
            commands::notes_write,
            commands::node_seal,
            commands::node_restore,
            commands::node_reparent,
            commands::grant_list,
            commands::grant_create,
            commands::grant_revoke,
            commands::entry_create,
            commands::entry_create_batch,
            commands::entry_update,
            commands::entry_rotate,
            commands::entry_remove,
            commands::entry_restore,
            commands::entry_undo,
            commands::entry_get,
            commands::field_add,
            commands::field_update,
            commands::field_remove,
            commands::field_reorder,
            commands::totp_code,
            commands::totp_seed,
            commands::search,
            commands::audit_tail,
            commands::audit_get,
            commands::maintenance_verify,
            commands::maintenance_doctor,
            commands::maintenance_backup,
            commands::maintenance_rotate_root,
            commands::util_generate,
        ])
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    configure(tauri::Builder::default(), clipboard::Clipboard::system())
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(shell::on_run_event);
}
