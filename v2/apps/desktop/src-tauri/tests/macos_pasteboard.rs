//! The real AppKit pasteboard, on a **private** one.
//!
//! `MacPasteboard::private()` is a pasteboard with a unique name: it exercises
//! exactly the code path the general pasteboard takes (same methods, same
//! change-count semantics, same marker types) without ever reading or writing
//! the user's clipboard. A second handle on the same name plays "another
//! application". Nothing here touches `generalPasteboard`.
//!
//! These are what justify the fake in `tests/common/fake_pasteboard.rs`: the
//! rules the shell tests rely on (a change count that moves when ownership
//! changes, and not otherwise; markers that are really declared) are checked
//! here against the real thing.

#![cfg(target_os = "macos")]

use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use desktop_lib::clipboard::macos::{
    contents_options, MacPasteboard, CONCEALED_TYPE, TRANSIENT_TYPE,
};
use desktop_lib::clipboard::{Clipboard, Pasteboard};
use objc2_app_kit::NSPasteboardContentsOptions;

const STRING_TYPE: &str = "public.utf8-plain-text";

/// A private pasteboard that is handed back to the pasteboard server when the
/// test ends. A named pasteboard otherwise outlives the process that made it,
/// for the rest of the login session, and every run of this file used to leave
/// one per test behind. Derefs to the pasteboard, so `.clone()` is still the
/// "another application" handle; declare it before any [`Clipboard`] built on it
/// so the clipboard drops (and clears) first.
struct Private(MacPasteboard);

impl Private {
    fn new() -> Self {
        Private(MacPasteboard::private())
    }
}

impl Deref for Private {
    type Target = MacPasteboard;
    fn deref(&self) -> &MacPasteboard {
        &self.0
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        self.0.release_globally();
    }
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_concealed_write_declares_the_text_and_both_markers() {
    let board = Private::new();
    let count = board.replace("s3cret-value", true).expect("write");

    assert_eq!(board.text().as_deref(), Some("s3cret-value"));
    let types = board.types();
    for expected in [STRING_TYPE, CONCEALED_TYPE, TRANSIENT_TYPE] {
        assert!(
            types.iter().any(|t| t == expected),
            "{expected} missing from {types:?}"
        );
    }
    assert_eq!(
        board.change_count().unwrap(),
        count,
        "the count `replace` returns is the pasteboard's count after the whole write"
    );
}

#[test]
fn a_plain_write_declares_the_text_and_no_marker() {
    let board = Private::new();
    board.replace("an address", false).expect("write");
    assert_eq!(board.text().as_deref(), Some("an address"));
    let types = board.types();
    assert!(types.iter().any(|t| t == STRING_TYPE));
    assert!(
        !types
            .iter()
            .any(|t| t == CONCEALED_TYPE || t == TRANSIENT_TYPE),
        "plain text must not be hidden from clipboard managers: {types:?}"
    );
}

#[test]
fn a_second_write_replaces_the_first_whole_including_its_markers() {
    let board = Private::new();
    board.replace("secret", true).unwrap();
    board.replace("public", false).unwrap();
    assert_eq!(board.text().as_deref(), Some("public"));
    assert!(
        !board.types().iter().any(|t| t == CONCEALED_TYPE),
        "the previous write's marker must not outlive it"
    );
}

#[test]
fn the_change_count_moves_when_ownership_changes_and_not_otherwise() {
    let board = Private::new();
    let other_app = board.clone();

    let ours = board.replace("secret", true).unwrap();
    // Reading, however often, does not move it.
    for _ in 0..5 {
        assert_eq!(board.change_count().unwrap(), ours);
        let _ = board.text();
        let _ = board.types();
    }
    // Another application taking the pasteboard does.
    let theirs = other_app.replace("their text", false).unwrap();
    assert_ne!(theirs, ours);
    assert_eq!(board.change_count().unwrap(), theirs);
    // And clearing does.
    let cleared = board.clear().unwrap();
    assert_ne!(cleared, theirs);
    assert_eq!(board.text(), None);
    assert!(board.types().is_empty());
}

#[test]
fn the_clock_clears_a_secret_from_a_real_pasteboard() {
    let board = Private::new();
    let clipboard = Clipboard::with(Arc::new(board.clone()), Duration::from_millis(150));
    clipboard.copy_secret("s3cret-value").expect("copy");
    assert_eq!(board.text().as_deref(), Some("s3cret-value"));
    wait_until("the 150 ms clock to clear a real pasteboard", || {
        board.text().is_none()
    });
    assert!(board.types().is_empty());
}

#[test]
fn the_clock_leaves_a_later_copy_on_a_real_pasteboard_alone() {
    let board = Private::new();
    let other_app = board.clone();
    let ttl = Duration::from_millis(150);
    let clipboard = Clipboard::with(Arc::new(board.clone()), ttl);
    clipboard.copy_secret("s3cret-value").expect("copy");
    other_app.replace("typed afterwards", false).unwrap();

    std::thread::sleep(ttl * 6);
    assert_eq!(
        board.text().as_deref(),
        Some("typed afterwards"),
        "the clear must only ever clear what this app wrote"
    );
}

#[test]
fn clear_if_owned_on_a_real_pasteboard_is_conditional_too() {
    let board = Private::new();
    let other_app = board.clone();
    let clipboard = Clipboard::with(Arc::new(board.clone()), Duration::from_secs(30));

    clipboard.copy_secret("s3cret-value").unwrap();
    assert!(clipboard.clear_if_owned());
    assert_eq!(board.text(), None);

    clipboard.copy_secret("s3cret-value").unwrap();
    other_app.replace("theirs", false).unwrap();
    assert!(!clipboard.clear_if_owned());
    assert_eq!(board.text().as_deref(), Some("theirs"));
}

#[test]
fn non_ascii_and_empty_and_large_values_survive_the_round_trip() {
    let board = Private::new();
    for text in ["", "naïve — ключ — 鍵 — 🔑", &"x".repeat(100_000)] {
        board.replace(text, true).expect("write");
        // An empty string is "no text" to AppKit; everything else is exact.
        if text.is_empty() {
            assert!(board.text().is_none_or(|t| t.is_empty()));
        } else {
            assert_eq!(board.text().as_deref(), Some(text));
        }
    }
}

// ---------------------------------------------------------------------------
// This Mac only (no Universal Clipboard / Handoff) for a secret
// ---------------------------------------------------------------------------
//
// What these can and cannot prove, stated plainly: whether a pasteboard is
// offered to the user's *other devices* is decided by the pasteboard server and
// is not observable from this process (measured: a `CurrentHostOnly` write and a
// plain one declare the same types and the same change count here). So the
// proof is in three parts: the option a concealed write asks for is exactly
// `CurrentHostOnly` and a plain one asks for none; `replace` takes ownership
// through that function and never through a bare `clearContents`; and every
// real-pasteboard test above runs through the new call, so the ownership and
// change-count rules the clipboard depends on hold on it. The cross-device
// effect itself is a row of the manual test plan.

#[test]
fn a_concealed_write_asks_for_this_host_only_and_a_plain_one_asks_for_nothing() {
    assert_eq!(
        contents_options(true),
        NSPasteboardContentsOptions::CurrentHostOnly
    );
    assert!(contents_options(false).is_empty());
}

#[test]
fn replace_takes_ownership_through_contents_options_and_never_a_bare_clear() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/clipboard.rs"))
            .expect("read src/clipboard.rs");
    // Only code counts: a comment that quotes the old call must not satisfy or
    // trip the check.
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let start = code
        .find("impl Pasteboard for MacPasteboard")
        .expect("the macOS impl");
    let replace = &code[start..];
    let replace = &replace[replace.find("fn replace").expect("fn replace")..];
    let replace = &replace[..replace.find("fn change_count").expect("fn change_count")];

    let take = replace
        .find("prepareForNewContentsWithOptions(contents_options(concealed))")
        .expect("replace must take ownership with contents_options(concealed)");
    let first_write = replace.find("setString_forType").expect("the text write");
    assert!(
        take < first_write,
        "ownership is taken before anything is written"
    );
    assert!(
        !replace[..first_write].contains("clearContents"),
        "a bare clearContents before the write would drop the host-only option"
    );
}

#[test]
fn a_concealed_write_still_hands_back_the_pasteboards_own_change_count() {
    // The ownership rule is "the pasteboard is ours while its count is the one
    // our write produced". That has to be the count of the *host-only* take-over
    // too, or every clear would be skipped as "somebody else's".
    let board = Private::new();
    let other_app = board.clone();
    let count = board.replace("s3cret-value", true).expect("write");
    assert_eq!(board.change_count().unwrap(), count);
    other_app.replace("theirs", false).unwrap();
    assert_ne!(board.change_count().unwrap(), count);
}

#[test]
fn releasing_a_private_pasteboard_frees_it_on_the_server() {
    let board = MacPasteboard::private();
    let another_handle = board.clone();
    board.replace("s3cret-value", true).expect("write");
    assert_eq!(another_handle.text().as_deref(), Some("s3cret-value"));

    board.release_globally();

    // The same name now reaches a fresh, empty pasteboard: the old contents did
    // not stay behind in the server for the rest of the login session.
    assert_eq!(another_handle.text(), None);
    assert!(another_handle.types().is_empty());
    another_handle.release_globally();
}
