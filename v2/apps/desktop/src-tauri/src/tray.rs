//! The menu-bar icon: the app stays reachable after its window is closed.
//!
//! Closing the main window hides it instead of ending the process
//! ([`crate::shell::on_window_event`]); the icon in the macOS menu bar is how
//! the user gets it back, and how they end it on purpose.
//!
//! | gesture | result |
//! |---|---|
//! | left click on the icon | show and focus the main window |
//! | right click (or ctrl-click) | the menu: Open CredMgr · Lock vault · Quit CredMgr |
//! | Dock icon click | show the main window ([`crate::shell::on_run_event`], `Reopen`) |
//! | Quit CredMgr / ⌘Q | the only ways the process ends |
//!
//! "Lock vault" takes the same path as a sleep or a screen lock
//! ([`crate::autolock::on_os_trigger`]): clipboard cleared, `vault.lock` sent
//! from Rust, the webview told with `credmgr://locked`.
//!
//! Closing the window locks the vault first (`LockReason::WindowClosed`, whatever
//! the auto-lock setting says), so the next open shows the Lock screen: a vault
//! does not stay open behind a window nobody sees. "Quit" locks it too, best effort.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

use crate::autolock::{self, LockReason};

/// The tray icon's id, so a test or a later change can find it again.
pub const TRAY_ID: &str = "credmgr-tray";
/// The label of the window the icon reopens (`tauri.conf.json`).
pub const MAIN_WINDOW: &str = "main";

/// What a menu item asks for. The ids are the strings the menu was built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Open,
    Lock,
    Quit,
}

impl TrayAction {
    pub const ALL: [TrayAction; 3] = [TrayAction::Open, TrayAction::Lock, TrayAction::Quit];

    pub const fn id(self) -> &'static str {
        match self {
            TrayAction::Open => "tray-open",
            TrayAction::Lock => "tray-lock",
            TrayAction::Quit => "tray-quit",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            TrayAction::Open => "Open CredMgr",
            TrayAction::Lock => "Lock vault",
            TrayAction::Quit => "Quit CredMgr",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.id() == id)
    }
}

/// Bring the main window back: un-minimise, show, focus. A missing window is not an error.
pub fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Do what a menu item asks.
pub fn perform<R: Runtime>(app: &AppHandle<R>, action: TrayAction) {
    match action {
        TrayAction::Open => show_main(app),
        TrayAction::Lock => autolock::on_os_trigger(app, LockReason::Tray),
        TrayAction::Quit => {
            // Best effort: lock the vault (and clear the clipboard) before the process ends. A broker that is not running is not an error.
            tauri::async_runtime::block_on(autolock::lock_and_notify(app, LockReason::Tray));
            app.exit(0);
        }
    }
}

/// Build the icon and its menu. Called once from `Builder::setup`.
pub fn install<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let open = MenuItem::with_id(
        app,
        TrayAction::Open.id(),
        TrayAction::Open.label(),
        true,
        None::<&str>,
    )?;
    let lock = MenuItem::with_id(
        app,
        TrayAction::Lock.id(),
        TrayAction::Lock.label(),
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(
        app,
        TrayAction::Quit.id(),
        TrayAction::Quit.label(),
        true,
        None::<&str>,
    )?;
    let menu = Menu::with_items(
        app,
        &[&open, &lock, &PredefinedMenuItem::separator(app)?, &quit],
    )?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("CredMgr")
        .menu(&menu)
        // Left click reopens the window; the menu is the right click.
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            if let Some(action) = TrayAction::from_id(event.id.as_ref()) {
                perform(app, action);
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_menu_id_maps_back_to_its_action_and_nothing_else_does() {
        for action in TrayAction::ALL {
            assert_eq!(TrayAction::from_id(action.id()), Some(action));
        }
        assert_eq!(TrayAction::from_id("tray-"), None);
        assert_eq!(TrayAction::from_id(""), None);
    }

    #[test]
    fn the_ids_are_distinct_and_the_menu_offers_open_lock_and_quit() {
        let ids: Vec<_> = TrayAction::ALL.iter().map(|a| a.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
        let labels: Vec<_> = TrayAction::ALL.iter().map(|a| a.label()).collect();
        assert_eq!(labels, ["Open CredMgr", "Lock vault", "Quit CredMgr"]);
    }
}
