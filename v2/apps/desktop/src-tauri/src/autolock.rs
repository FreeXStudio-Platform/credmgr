//! Auto-lock on sleep, screen lock and session switch (C1).
//!
//! The idle auto-lock lives in the broker (ADR-043). It cannot see the things
//! only the desktop knows: the lid closing, the screen locking, another user
//! taking the session. For those the shell watches the OS and, when one
//! happens, locks the vault **itself, from Rust**:
//!
//! 1. empty the clipboard if it still holds a secret this app copied
//!    ([`Clipboard::clear_if_owned`]);
//! 2. send `vault.lock` ([`crate::commands::vault_lock_at`]), which also drops
//!    the token;
//! 3. tell the webview with `credmgr://locked` and the reason, so it can wipe
//!    what it has revealed and show the lock screen.
//!
//! 4. reload the main webview ([`reload_main_webview`], ADR-091): a page that held
//!    typed secrets, reveals or an undo snapshot cannot zeroise JavaScript strings,
//!    so the surest way to drop them is to drop the page. The Lock screen comes
//!    back from a fresh boot (`vault.status` says locked), with the reason in the
//!    words the event would have given it.
//!
//! The order matters. Steps 1 and 2 do not depend on the webview, so a wedged
//! or crashed web layer cannot keep the vault open; step 3 is a courtesy to a
//! UI that is still alive. A broker that is not running is not an error here —
//! there is nothing to lock — and the token is dropped regardless.
//!
//! ## Step 2 is unconditional
//!
//! `vault.lock` is sent whether or not this app holds a login. The broker
//! accepts it with no token (it is in `TOKENLESS_OK_OPS` in
//! `crates/brokerd/src/server.rs`, "which must always work", and `credmgr lock`
//! sends it bare), and the vault it locks is **the broker's, not this window's**:
//! it may have been unlocked by the CLI, by another client's login, or by this
//! app before its own login idled out (ADR-065) while other clients kept the
//! vault open. Each of those leaves node keys in the broker's memory, which is
//! exactly what locking on sleep exists to end. An earlier version of this code
//! skipped the call when the app held no login, on the premise that a tokenless
//! `vault.lock` "would be refused"; the broker does not refuse it, so that left
//! the vault open across sleep in every state where this app was not the one
//! logged in. A pending second factor is the same case: the broker's
//! `state.lock()` also drops the half-finished unlock.
//!
//! ## What runs on the OS thread, and what does not
//!
//! The observer block runs on the thread that posts the notification, and
//! macOS goes on to sleep once every observer has returned. So step 1 (local,
//! microseconds, thread-safe) runs **inside** the block ([`on_os_trigger`]):
//! the secret is off the pasteboard before the machine can sleep. Steps 2 and 3
//! need the async runtime and a socket round trip, so they are spawned; they
//! normally finish in milliseconds, but the OS does not wait for them. That is
//! stated rather than hidden: the broker's own idle lock and the screen lock are
//! the backstops, and this module does not claim to be a barrier the OS honours.
//!
//! ## What is watched (macOS)
//!
//! | OS notification | center | [`LockReason`] |
//! |---|---|---|
//! | `NSWorkspaceWillSleepNotification` | workspace | `sleep` |
//! | `NSWorkspaceScreensDidSleepNotification` | workspace | `screens_sleep` |
//! | `NSWorkspaceSessionDidResignActiveNotification` | workspace | `session_resign` |
//! | `com.apple.screenIsLocked` | distributed | `screen_locked` |
//!
//! The last is an undocumented-but-stable name that Apple's own tooling and
//! most password managers rely on; it is the only way to learn of a screen lock
//! that is not a sleep. If a future macOS renames it, sleep and session-switch
//! still lock, and the "screen locked" row of the manual test plan fails first.
//!
//! A screensaver that starts without requiring a password does **not** lock the
//! vault: the screen is not locked, and locking on every screensaver would make
//! the app unusable for anyone who reads a long entry.

use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::clipboard::Clipboard;
use crate::commands;
use crate::session::Session;
use crate::vault_paths;

/// The event the webview listens to (`@tauri-apps/api/event`, permitted by
/// `core:default`). Its payload is the [`LockReason`] as a JSON string.
pub const EVENT_LOCKED: &str = "credmgr://locked";

/// Why the shell locked the vault. Serialised as the `snake_case` word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockReason {
    /// The Mac is about to sleep.
    Sleep,
    /// The displays went to sleep.
    ScreensSleep,
    /// Another user's session became active (fast user switching, login window).
    SessionResign,
    /// The screen was locked.
    ScreenLocked,
    /// The user chose "Lock vault" in the menu-bar icon's menu.
    Tray,
    /// The main window was closed (it hides; the app keeps running in the menu bar).
    WindowClosed,
}

impl LockReason {
    pub const ALL: [LockReason; 6] = [
        LockReason::Sleep,
        LockReason::ScreensSleep,
        LockReason::SessionResign,
        LockReason::ScreenLocked,
        LockReason::Tray,
        LockReason::WindowClosed,
    ];

    /// The payload word the webview receives.
    pub const fn as_str(self) -> &'static str {
        match self {
            LockReason::Sleep => "sleep",
            LockReason::ScreensSleep => "screens_sleep",
            LockReason::SessionResign => "session_resign",
            LockReason::ScreenLocked => "screen_locked",
            LockReason::Tray => "tray",
            LockReason::WindowClosed => "window_closed",
        }
    }
}

/// The `sessionStorage` key the reload leaves the reason under, for the page's
/// next boot to show as the Lock screen's note and delete. A closed word from
/// [`LockReason::as_str`], never anything typed or revealed.
pub const RELOAD_REASON_KEY: &str = "cm.lockreason";

/// The script that drops the page after a lock: leave the reason, reload. The
/// reason is one of six fixed words, so nothing in it can be script.
pub fn reload_script(reason: LockReason) -> String {
    format!(
        "try{{sessionStorage.setItem('{RELOAD_REASON_KEY}','{}')}}catch(e){{}}location.reload();",
        reason.as_str()
    )
}

/// Reload the main webview after a lock, whatever the reason and whether or not
/// the window is visible (a hidden window holds the same memory). `false` when
/// there is no such window or the reload could not be sent; the lock has already
/// happened either way.
pub fn reload_main_webview<R: Runtime>(app: &AppHandle<R>, reason: LockReason) -> bool {
    app.get_webview_window(crate::tray::MAIN_WINDOW)
        .is_some_and(|window| window.eval(reload_script(reason)).is_ok())
}

/// The page's own lock (the Lock button, ⌘L, the page's idle timer) goes through the `vault_lock` command, not through
/// [`lock_and_notify`], so it used to leave the page alive (found 2026-10-27 in the built app: no main-resource load after ⌘L).
/// ADR-091 amendment: it reloads the page too. The script carries no reason word (the page keeps its own note, see
/// `src/vault/shell-events.ts` `rememberPageLockNote`); it is a constant, so nothing can be injected into it.
pub const PAGE_LOCK_RELOAD_SCRIPT: &str = "location.reload();";

/// How long the reload waits so the answer to the page's own `invoke("vault_lock")` is delivered first.
pub const PAGE_LOCK_RELOAD_DELAY: std::time::Duration = std::time::Duration::from_millis(150);

/// Reload the main webview after the page locked the vault itself. `false` when there is no such window or the script could not be
/// sent; the lock has already happened either way.
pub fn reload_after_page_lock<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.get_webview_window(crate::tray::MAIN_WINDOW)
        .is_some_and(|window| window.eval(PAGE_LOCK_RELOAD_SCRIPT).is_ok())
}

/// Schedule [`reload_after_page_lock`] after [`PAGE_LOCK_RELOAD_DELAY`], off the command's own task.
pub fn schedule_page_lock_reload<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio_sleep(PAGE_LOCK_RELOAD_DELAY).await;
        let _ = reload_after_page_lock(&app);
    });
}

async fn tokio_sleep(d: std::time::Duration) {
    // Tauri's async runtime is tokio; a blocking thread keeps this free of a direct tokio dependency.
    let _ = tauri::async_runtime::spawn_blocking(move || std::thread::sleep(d)).await;
}

/// What one trigger did, for the tests and for nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoLockReport {
    /// The main webview was told to reload (module docs, step 4).
    pub webview_reloaded: bool,
    /// A secret this app had copied was still on the pasteboard and was cleared.
    pub clipboard_cleared: bool,
    /// `vault.lock` was dispatched to the broker's socket, login or no login.
    /// `false` only when no vault directory resolves, so there was no socket.
    pub vault_lock_sent: bool,
}

/// Steps 1 and 2 of the module docs, against an explicit socket.
pub async fn lock_for(session: &Session, socket: PathBuf, clipboard: &Clipboard) -> AutoLockReport {
    let clipboard_cleared = clipboard.clear_if_owned();

    // Always sent: with the token if this app holds one, without if it does not
    // (module docs, "Step 2 is unconditional"). The result is ignored on
    // purpose: `vault_lock_at` drops the token on every path, an unreachable
    // broker means there is nothing to lock, and there is no one to report a
    // failure to at the moment the lid closes.
    let _ = commands::vault_lock_at(session, socket).await;

    AutoLockReport {
        webview_reloaded: false,
        clipboard_cleared,
        vault_lock_sent: true,
    }
}

/// All three steps, against an explicit socket. Managed `Session` and
/// `Clipboard` are looked up on `app`; a build that did not manage them has
/// nothing to lock and still tells the webview.
pub async fn lock_and_notify_at<R: Runtime>(
    app: &AppHandle<R>,
    socket: Option<PathBuf>,
    reason: LockReason,
) -> AutoLockReport {
    let report = match (app.try_state::<Session>(), app.try_state::<Clipboard>()) {
        (Some(session), Some(clipboard)) => match socket {
            Some(socket) => lock_for(&session, socket, &clipboard).await,
            None => {
                // No vault directory resolves: nothing to lock, but the token
                // and the clipboard are still ours to drop.
                session.clear();
                AutoLockReport {
                    webview_reloaded: false,
                    clipboard_cleared: clipboard.clear_if_owned(),
                    vault_lock_sent: false,
                }
            }
        },
        _ => AutoLockReport {
            webview_reloaded: false,
            clipboard_cleared: false,
            vault_lock_sent: false,
        },
    };
    // Emission failing means no webview is listening; the lock already happened.
    let _ = app.emit(EVENT_LOCKED, reason.as_str());
    // After the event, so a live page has already begun to forget; then the page itself goes.
    AutoLockReport {
        webview_reloaded: reload_main_webview(app, reason),
        ..report
    }
}

/// The production entry: resolve the real socket, lock, notify.
pub async fn lock_and_notify<R: Runtime>(app: &AppHandle<R>, reason: LockReason) -> AutoLockReport {
    lock_and_notify_at(app, vault_paths::resolve_socket_path(), reason).await
}

/// What an OS notification block does, on the thread the OS posted it from.
///
/// The clipboard is cleared **here, synchronously**, before this returns and so
/// before the OS can carry on to sleep; the broker lock and the webview event
/// are spawned (module docs, "What runs on the OS thread"). Kept separate from
/// the macOS observer glue so the split is testable without posting a real
/// system notification to every other app on the machine.
pub fn on_os_trigger<R: Runtime>(app: &AppHandle<R>, reason: LockReason) {
    if let Some(clipboard) = app.try_state::<Clipboard>() {
        clipboard.clear_if_owned();
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = lock_and_notify(&app, reason).await;
    });
}

// ---------------------------------------------------------------------------
// macOS: the OS observers
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub mod observers {
    //! `NSNotificationCenter` block observers. The block runs on the thread
    //! that posts the notification (the main thread, for the workspace center),
    //! so it does the one thing that must beat the OS to sleep (the clipboard
    //! clear) and schedules the rest ([`super::on_os_trigger`]).

    use std::ptr::NonNull;
    use std::sync::Once;

    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::ProtocolObject;
    use objc2_app_kit::{
        NSWorkspace, NSWorkspaceScreensDidSleepNotification,
        NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillSleepNotification,
    };
    use objc2_foundation::{
        NSDistributedNotificationCenter, NSNotification, NSNotificationCenter, NSNotificationName,
        NSObjectProtocol, NSString,
    };
    use tauri::{AppHandle, Runtime};

    use super::{on_os_trigger, LockReason};

    /// Posted on the distributed center when the screen locks.
    pub const SCREEN_LOCKED_NOTIFICATION: &str = "com.apple.screenIsLocked";

    /// The workspace notifications that lock the vault, and why.
    pub fn workspace_triggers() -> [(&'static NSNotificationName, LockReason); 3] {
        // SAFETY: framework-provided constants, valid for the life of the process.
        unsafe {
            [
                (NSWorkspaceWillSleepNotification, LockReason::Sleep),
                (
                    NSWorkspaceScreensDidSleepNotification,
                    LockReason::ScreensSleep,
                ),
                (
                    NSWorkspaceSessionDidResignActiveNotification,
                    LockReason::SessionResign,
                ),
            ]
        }
    }

    /// Run `handler` each time `name` is posted on `center`. The center keeps
    /// the returned token alive until it is removed, so ignoring it is fine for
    /// an observer that lives as long as the process.
    pub fn observe(
        center: &NSNotificationCenter,
        name: &NSString,
        handler: impl Fn() + 'static,
    ) -> Retained<ProtocolObject<dyn NSObjectProtocol>> {
        let block = RcBlock::new(move |_note: NonNull<NSNotification>| handler());
        // SAFETY: `name` is a notification name; a nil object matches any
        // sender; a nil queue runs the block synchronously on the posting
        // thread; the block is `'static` and copied by the center.
        unsafe { center.addObserverForName_object_queue_usingBlock(Some(name), None, None, &block) }
    }

    /// Register every observer once. Called from `setup()` on the main thread;
    /// a second call is a no-op, so a test harness that builds two apps cannot
    /// double-lock.
    pub fn install<R: Runtime>(app: &AppHandle<R>) {
        static INSTALLED: Once = Once::new();
        INSTALLED.call_once(|| {
            let schedule = |reason: LockReason| {
                let app = app.clone();
                move || on_os_trigger(&app, reason)
            };

            let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
            for (name, reason) in workspace_triggers() {
                observe(&workspace, name, schedule(reason));
            }

            let distributed = NSDistributedNotificationCenter::defaultCenter();
            observe(
                &distributed,
                &NSString::from_str(SCREEN_LOCKED_NOTIFICATION),
                schedule(LockReason::ScreenLocked),
            );
        });
    }
}

#[cfg(not(target_os = "macos"))]
pub mod observers {
    //! No OS observers off macOS: the idle lock still runs broker-side.
    use tauri::{AppHandle, Runtime};

    pub fn install<R: Runtime>(_app: &AppHandle<R>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_has_a_distinct_snake_case_word_that_matches_its_serde_form() {
        let mut words = Vec::new();
        for reason in LockReason::ALL {
            let json = serde_json::to_string(&reason).unwrap();
            assert_eq!(json, format!("\"{}\"", reason.as_str()));
            assert!(reason
                .as_str()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_'));
            words.push(reason.as_str());
        }
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), LockReason::ALL.len());
    }

    #[test]
    fn the_reload_script_leaves_only_a_fixed_word_and_reloads_for_every_reason() {
        for reason in LockReason::ALL {
            let script = reload_script(reason);
            assert!(script.ends_with("location.reload();"), "{script}");
            assert!(
                script.contains(&format!("'{RELOAD_REASON_KEY}','{}'", reason.as_str())),
                "{script}"
            );
            // Nothing but fixed words and punctuation: no way for a payload to become script.
            assert_eq!(script.matches('\'').count(), 4, "{script}");
        }
        assert_eq!(RELOAD_REASON_KEY, "cm.lockreason");
    }

    #[test]
    fn the_event_name_is_the_one_the_front_end_spec_froze() {
        assert_eq!(EVENT_LOCKED, "credmgr://locked");
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use objc2_foundation::{NSNotificationCenter, NSString};

        use super::super::observers::{observe, workspace_triggers, SCREEN_LOCKED_NOTIFICATION};
        use super::super::LockReason;

        #[test]
        fn the_workspace_names_are_the_ones_apple_documents() {
            let found: Vec<(String, LockReason)> = workspace_triggers()
                .into_iter()
                .map(|(name, reason)| (name.to_string(), reason))
                .collect();
            assert_eq!(
                found,
                vec![
                    (
                        "NSWorkspaceWillSleepNotification".to_string(),
                        LockReason::Sleep
                    ),
                    (
                        "NSWorkspaceScreensDidSleepNotification".to_string(),
                        LockReason::ScreensSleep
                    ),
                    (
                        "NSWorkspaceSessionDidResignActiveNotification".to_string(),
                        LockReason::SessionResign
                    ),
                ]
            );
            assert_eq!(SCREEN_LOCKED_NOTIFICATION, "com.apple.screenIsLocked");
        }

        #[test]
        fn an_observer_runs_its_handler_each_time_its_name_is_posted_and_only_then() {
            // A private center and a private name: posting the real
            // `NSWorkspaceWillSleepNotification` or `com.apple.screenIsLocked`
            // would make every other app on the machine believe it was sleeping.
            let center = NSNotificationCenter::new();
            let ours = NSString::from_str("com.credmgr.test.autolock.ours");
            let other = NSString::from_str("com.credmgr.test.autolock.other");
            let hits = Arc::new(AtomicUsize::new(0));
            let seen = Arc::clone(&hits);
            let _token = observe(&center, &ours, move || {
                seen.fetch_add(1, Ordering::SeqCst);
            });

            // SAFETY: plain notification posts with no object and no userInfo.
            unsafe {
                center.postNotificationName_object(&ours, None);
                center.postNotificationName_object(&other, None);
                center.postNotificationName_object(&ours, None);
            }
            assert_eq!(hits.load(Ordering::SeqCst), 2);
        }
    }
}
