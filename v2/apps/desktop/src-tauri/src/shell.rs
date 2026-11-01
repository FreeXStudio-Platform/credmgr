//! The shell's own behaviour that is not a broker command: what happens when
//! the window goes away, and when the app quits.
//!
//! ## Window inactive (C12)
//!
//! A revealed secret on screen is one the user is looking at. When they are not
//! — the window was minimised, the app hidden, focus moved to another app — the
//! webview should wipe what it revealed (it already does on `visibilitychange`,
//! which WebKit fires for minimise and hide). The shell adds the one signal the
//! page cannot see for itself, **focus loss**, as `credmgr://window-inactive`
//! with a payload that says which kind it was, best effort:
//!
//! | payload | meaning |
//! |---|---|
//! | `minimized` | focus was lost because the window went into the Dock |
//! | `hidden` | focus was lost because the window or the app was hidden |
//! | `blurred` | focus moved to another window or app; this one is still visible |
//!
//! The UI treats all three as "wipe revealed values". The words differ so a
//! setting can treat `blurred` more gently than the other two; the *distinction*
//! is the OS's to get wrong (it reports focus before minimise on some macOS
//! versions), the *signal* is not.
//!
//! The clipboard is **not** cleared on any of these. Clearing on an app switch
//! would make pasting into the app you copied for impossible (decision D5).
//!
//! ## Closing the window is not quitting
//!
//! The red close button locks the vault, hides the window and the process keeps
//! running, so the menu-bar icon ([`crate::tray`]) stays. The process ends only through the
//! icon's "Quit CredMgr", ⌘Q or the app menu's Quit. Clicking the Dock icon
//! (`RunEvent::Reopen`) brings the window back.
//!
//! ## Quit
//!
//! `RunEvent::Exit` clears the pasteboard if it still holds a secret this app
//! copied. A force-quit or a crash cannot run this; the 30 s clock is then the
//! only cover, and it dies with the process — stated in `SECURITY.md`, not
//! papered over.

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, RunEvent, Runtime, WebviewWindow, Window, WindowEvent};

use crate::clipboard::Clipboard;

/// Emitted when the window stops being the one the user is looking at.
pub const EVENT_WINDOW_INACTIVE: &str = "credmgr://window-inactive";

/// Why the window is no longer active. Serialised as the `snake_case` word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Inactive {
    Minimized,
    Hidden,
    Blurred,
}

impl Inactive {
    pub const ALL: [Inactive; 3] = [Inactive::Minimized, Inactive::Hidden, Inactive::Blurred];

    pub const fn as_str(self) -> &'static str {
        match self {
            Inactive::Minimized => "minimized",
            Inactive::Hidden => "hidden",
            Inactive::Blurred => "blurred",
        }
    }

    /// Classify a focus loss from what the window reports about itself.
    pub fn classify(minimized: bool, visible: bool) -> Self {
        if minimized {
            Inactive::Minimized
        } else if !visible {
            Inactive::Hidden
        } else {
            Inactive::Blurred
        }
    }
}

/// Screen capture and screen sharing show the window blank (threat T10): the window is created with
/// `contentProtected: true` in `tauri.conf.json` (macOS `NSWindow.sharingType = none`, Windows `WDA_EXCLUDEFROMCAPTURE`),
/// so every new install, and every start before the page has said anything, is protected.
///
/// Two things can turn it off, and nothing else:
/// * the user, in Settings: the page remembers the choice (`credmgr_prefs`, `captureProtection`) and, only when that
///   stored choice is *off*, calls [`crate::commands::capture_protection_set`] once the page has booted. An unreadable or
///   missing choice never calls anything, so it stays protected;
/// * the environment variable below, read at start-up and on every call. It is the developer override (the real-app pass
///   and support screenshots) and it wins: while it says `off`, no setting turns protection back on.
pub const ENV_CONTENT_PROTECTION: &str = "CREDMGR_CONTENT_PROTECTION";

/// True unless `CREDMGR_CONTENT_PROTECTION=off`.
pub fn content_protection_wanted(value: Option<&str>) -> bool {
    !matches!(value, Some("off"))
}

/// What the window should be, given the environment override and the user's stored choice. `preference` is `None` when
/// the page never said (a new install, or storage it could not read): that is protected. The environment wins when it says
/// `off`.
pub fn capture_protection_wanted(env: Option<&str>, preference: Option<bool>) -> bool {
    content_protection_wanted(env) && preference.unwrap_or(true)
}

/// What `capture_protection_set` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CaptureReceipt {
    /// Whether the window is now hidden from capture, as the shell set it (the environment override included).
    pub enabled: bool,
    /// The operating system accepted the call. `false` leaves the window as it was (protected, unless it was already off).
    pub applied: bool,
}

/// Set the window's protection to the user's choice (the environment override still wins). Carries no vault data.
pub fn set_capture_protection<R: Runtime>(
    window: &WebviewWindow<R>,
    enabled: bool,
) -> CaptureReceipt {
    let wanted = capture_protection_wanted(
        std::env::var(ENV_CONTENT_PROTECTION).ok().as_deref(),
        Some(enabled),
    );
    let applied = match window.set_content_protected(wanted) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("credmgr: could not set content protection ({wanted}): {e}");
            false
        }
    };
    CaptureReceipt {
        enabled: wanted,
        applied,
    }
}

/// Re-apply the window's protection at start-up (the config sets it at creation; this is the env opt-out and a belt for
/// a window created some other way).
pub fn apply_content_protection<R: Runtime>(app: &AppHandle<R>) {
    let wanted = content_protection_wanted(std::env::var(ENV_CONTENT_PROTECTION).ok().as_deref());
    if let Some(window) = app.get_webview_window("main") {
        if let Err(e) = window.set_content_protected(wanted) {
            eprintln!("credmgr: could not set content protection ({wanted}): {e}");
        }
    }
}

/// `Builder::on_window_event`.
pub fn on_window_event<R: Runtime>(window: &Window<R>, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        // Hide, do not end: the menu-bar icon is how the window comes back. The vault is locked first, whatever the
        // auto-lock setting says: a vault must not stay open behind a window nobody can see.
        api.prevent_close();
        crate::autolock::on_os_trigger(
            window.app_handle(),
            crate::autolock::LockReason::WindowClosed,
        );
        let _ = window.hide();
        return;
    }
    if let WindowEvent::Focused(false) = event {
        let minimized = window.is_minimized().unwrap_or(false);
        // An unreadable `visible` is read as visible: the weaker claim
        // (`blurred`) is the one that cannot cause a missed wipe, because the UI
        // wipes on every variant.
        let visible = window.is_visible().unwrap_or(true);
        let why = Inactive::classify(minimized, visible);
        let _ = window.emit(EVENT_WINDOW_INACTIVE, why.as_str());
    }
}

/// `App::run`'s callback.
pub fn on_run_event<R: Runtime>(app: &AppHandle<R>, event: RunEvent) {
    match event {
        RunEvent::Exit => {
            if let Some(clipboard) = app.try_state::<Clipboard>() {
                clipboard.clear_if_owned();
            }
        }
        // A click on the Dock icon while the window is hidden brings it back.
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => crate::tray::show_main(app),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_focus_loss_is_classified_by_what_the_window_reports() {
        assert_eq!(Inactive::classify(true, true), Inactive::Minimized);
        assert_eq!(Inactive::classify(true, false), Inactive::Minimized);
        assert_eq!(Inactive::classify(false, false), Inactive::Hidden);
        assert_eq!(Inactive::classify(false, true), Inactive::Blurred);
    }

    #[test]
    fn content_protection_is_on_unless_the_env_says_off() {
        assert!(content_protection_wanted(None));
        assert!(content_protection_wanted(Some("on")));
        assert!(content_protection_wanted(Some("")));
        assert!(
            content_protection_wanted(Some("OFF")),
            "only the exact word 'off' turns it off"
        );
        assert!(!content_protection_wanted(Some("off")));
    }

    #[test]
    fn capture_protection_is_on_unless_the_user_chose_off_or_the_env_says_off() {
        // No choice (a new install, unreadable storage): protected.
        assert!(capture_protection_wanted(None, None));
        assert!(capture_protection_wanted(Some("on"), None));
        // The user's choice decides when the environment is silent.
        assert!(capture_protection_wanted(None, Some(true)));
        assert!(!capture_protection_wanted(None, Some(false)));
        // The developer override wins when it says off, whatever the user chose.
        assert!(!capture_protection_wanted(Some("off"), None));
        assert!(!capture_protection_wanted(Some("off"), Some(true)));
        assert!(!capture_protection_wanted(Some("off"), Some(false)));
        // Anything but the exact word 'off' leaves the choice alone.
        assert!(capture_protection_wanted(Some("OFF"), Some(true)));
        assert!(!capture_protection_wanted(Some("OFF"), Some(false)));
    }

    #[test]
    fn the_capture_receipt_serialises_with_its_two_words() {
        assert_eq!(
            serde_json::to_string(&CaptureReceipt {
                enabled: false,
                applied: true
            })
            .unwrap(),
            r#"{"enabled":false,"applied":true}"#
        );
    }

    #[test]
    fn the_payload_words_match_their_serde_form() {
        for why in Inactive::ALL {
            assert_eq!(
                serde_json::to_string(&why).unwrap(),
                format!("\"{}\"", why.as_str())
            );
        }
    }
}
