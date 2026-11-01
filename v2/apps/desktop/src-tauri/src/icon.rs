//! `app_icon_set` — the app's own icon, chosen at run time (X9 in the design's supporter extras; ADR-082).
//!
//! The six choices are the KEEP Identity marks rendered to 1024 px PNGs (`icons/marks/`, made by
//! `scripts/icons/make-marks.mjs` and committed, so a build needs no extra tool). The bundle's own static icon stays the
//! `keep` mark; this command changes what the window and the Dock or taskbar show **until the app quits**. Remembering the
//! choice is the window's job (`credmgr_cosmetics`, `PRIVACY.md`): it calls this command again after each unlock.
//!
//! Per OS, because Tauri has no Dock API:
//! * macOS: `NSApplication.applicationIconImage` through AppKit, on the main thread. The window itself has no per-window icon.
//! * Windows and Linux: the window icon, from the same PNG.
//! * The command refuses an unknown id before touching anything (`unknown_icon`), so the argument can never name a path.
//!
//! No network, no file read: the PNGs are `include_bytes!`'d, and an icon change carries no vault data.

use serde::Serialize;
use tauri::{AppHandle, Runtime, WebviewWindow};

use crate::error::BridgeError;

/// The ids `app_icon_set` accepts, in the order the design lists them.
pub const MARK_IDS: &[&str] = &["keep", "keepbone", "cells", "node", "seal", "keepsig"];

/// The 1024 px PNG for one id, or `None` for anything else.
pub fn mark_png(id: &str) -> Option<&'static [u8]> {
    Some(match id {
        "keep" => include_bytes!("../icons/marks/keep.png"),
        "keepbone" => include_bytes!("../icons/marks/keepbone.png"),
        "cells" => include_bytes!("../icons/marks/cells.png"),
        "node" => include_bytes!("../icons/marks/node.png"),
        "seal" => include_bytes!("../icons/marks/seal.png"),
        "keepsig" => include_bytes!("../icons/marks/keepsig.png"),
        _ => return None,
    })
}

/// What `app_icon_set` answers: which icon, and which surfaces it reached on this OS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IconReceipt {
    pub icon: String,
    /// The Dock icon changed (macOS only).
    pub dock: bool,
    /// The window or taskbar icon changed (Windows and Linux only).
    pub window: bool,
}

/// Apply `id` to the app. `window` is the calling window, if any.
pub fn set<R: Runtime>(
    app: &AppHandle<R>,
    window: Option<&WebviewWindow<R>>,
    id: &str,
) -> Result<IconReceipt, BridgeError> {
    let png = mark_png(id).ok_or_else(|| {
        BridgeError::bridge(
            "unknown_icon",
            format!("app_icon_set takes one of: {}", MARK_IDS.join(", ")),
        )
    })?;
    let mut receipt = IconReceipt {
        icon: id.to_string(),
        dock: false,
        window: false,
    };
    #[cfg(target_os = "macos")]
    {
        let _ = window;
        receipt.dock = macos::set_dock_icon(app, png);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        if let Some(window) = window {
            let image = tauri::image::Image::from_bytes(png).map_err(|e| {
                BridgeError::bridge("icon_failed", format!("the icon could not be decoded: {e}"))
            })?;
            window.set_icon(image).map_err(|e| {
                BridgeError::bridge("icon_failed", format!("the window refused the icon: {e}"))
            })?;
            receipt.window = true;
        }
    }
    Ok(receipt)
}

#[cfg(target_os = "macos")]
mod macos {
    //! AppKit has no Tauri binding for the Dock icon. One call chain: `NSImage` from the PNG bytes, set on
    //! the shared application, on the main thread (AppKit requires it; the one `unsafe` is the setter. Off the main thread there is no marker and the
    //! call reports `false` instead of guessing).
    use objc2::AllocAnyThread;
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;
    use tauri::{AppHandle, Runtime};

    pub fn set_dock_icon<R: Runtime>(app: &AppHandle<R>, png: &'static [u8]) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        let queued = app.run_on_main_thread(move || {
            let done = match MainThreadMarker::new() {
                Some(mtm) => {
                    let data = NSData::with_bytes(png);
                    match NSImage::initWithData(NSImage::alloc(), &data) {
                        Some(image) => {
                            let ns_app = NSApplication::sharedApplication(mtm);
                            unsafe { ns_app.setApplicationIconImage(Some(&image)) };
                            true
                        }
                        None => false,
                    }
                }
                None => false,
            };
            let _ = tx.send(done);
        });
        queued.is_ok()
            && rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_id_has_a_png_and_nothing_else_does() {
        for id in MARK_IDS {
            let png = mark_png(id).unwrap_or_else(|| panic!("{id}"));
            assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "{id} is a PNG");
            // 1024 x 1024: the IHDR width and height are bytes 16..24, big-endian.
            assert_eq!(
                u32::from_be_bytes(png[16..20].try_into().unwrap()),
                1024,
                "{id} width"
            );
            assert_eq!(
                u32::from_be_bytes(png[20..24].try_into().unwrap()),
                1024,
                "{id} height"
            );
        }
        for bad in ["", "Keep", "../keep", "keep.png", "/etc/passwd", "mark"] {
            assert!(mark_png(bad).is_none(), "{bad}");
        }
    }
}
