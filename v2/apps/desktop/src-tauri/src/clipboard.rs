//! The concealed clipboard (C2): a secret reaches the pasteboard without ever
//! reaching the webview, and leaves it again on its own.
//!
//! ## Why this lives in Rust
//!
//! `navigator.clipboard.writeText(secret)` needs the secret in JavaScript
//! first, writes it with no marker a clipboard manager would honour, and has no
//! way to clear it only if it is still *ours*. [`entry_copy`](crate::commands::entry_copy)
//! therefore reveals the entry Rust-side (through the audited, token-bearing
//! dispatch path), hands the plaintext straight to a [`Clipboard`], and answers
//! the webview with a receipt that carries no part of the value.
//!
//! ## The four rules
//!
//! 1. **Concealed.** A secret is written together with the two markers every
//!    clipboard manager that follows <https://nspasteboard.org> skips:
//!    `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`.
//!    The markers are a convention, not an OS guarantee; a manager that ignores
//!    it can still record the value. That is a limit of the platform, stated
//!    rather than hidden.
//!
//!    **This Mac only.** The same write asks AppKit for
//!    `NSPasteboardContentsCurrentHostOnly`, which keeps the contents out of
//!    Universal Clipboard / Handoff. Without it a secret copied here can be
//!    offered to every other device on the same Apple ID, where the 30 s clear
//!    below cannot reach it and the nspasteboard.org markers are not an Apple
//!    contract. Plain text ([`Clipboard::copy_plain`], a donation address) is
//!    left free to travel: it is not a secret, and Universal Clipboard is a
//!    feature for it. What this does not do: it cannot stop an application on
//!    this Mac from reading the pasteboard while the secret is on it.
//! 2. **Cleared on a clock.** [`CLEAR_AFTER`] (30 s) after the write, the
//!    pasteboard is emptied.
//! 3. **Only if it is still ours.** Clearing is conditional on the pasteboard's
//!    *change count*: the number AppKit bumps every time anything takes
//!    ownership of the pasteboard. We remember the count our write produced; if
//!    it has moved, somebody else (the user copying a sentence, another app)
//!    owns the pasteboard now and we leave it alone. The same test guards every
//!    other clear (lock, sleep, quit): the clipboard is never wiped wholesale,
//!    because wiping the user's own later copy is data loss, not security.
//!
//! The check-then-clear is not atomic against another process (AppKit offers no
//! compare-and-clear). The window is the gap between two Mach calls, and the
//! failure it allows is "we cleared something that arrived in that gap" — the
//! user copies again. The opposite failure, leaving a secret behind, is the one
//! the design refuses.
//!
//! 4. **A lock closes the door behind it.** `entry_copy` fetches the value and
//!    only then writes it, and a lock, sleep or quit can land in between. A
//!    clear that ran *before* the write would then be followed by a secret
//!    written *after* the lock, with nothing left to remove it but the clock.
//!    So every [`Clipboard::clear_if_owned`] also bumps an epoch, `entry_copy`
//!    takes a [`CopyTicket`] before it asks the broker, and
//!    [`Clipboard::copy_secret_for`] refuses (`ClipboardError::Interrupted`,
//!    nothing written) if the epoch moved. The comparison and the write happen
//!    under one lock, so there is no gap to slip through.
//!
//! The 30 s clock is `std::time::Instant`, which does not advance while the Mac
//! sleeps. That is why sleep clears the clipboard itself ([`crate::autolock`])
//! rather than relying on the clock to do it on wake.
//!
//! ## Not on focus loss
//!
//! Clearing when the window loses focus would make it impossible to paste into
//! the app you just copied for (decision D5 of the front-end spec). The triggers
//! are the clock, a lock (including sleep and screen lock, [`crate::autolock`]),
//! and quit.
//!
//! ## Memory
//!
//! The plaintext the shell holds is wiped (`zeroize`) as soon as it has been
//! handed to AppKit. That is defence in depth, not a guarantee: AppKit,
//! the pasteboard server and the allocator each keep their own copies, and no
//! API reaches them. The guarantee that matters is structural — the value is
//! never serialised into the IPC response — and `tests/shell_ipc.rs` holds it.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::error::BridgeError;

/// How long a copied secret may stay on the pasteboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Why the pasteboard could not be written or inspected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    /// This platform has no pasteboard implementation.
    Unsupported,
    /// AppKit refused, or answered something unusable.
    Failed(String),
    /// Another process took the pasteboard while it was being filled, so what
    /// was written cannot be called ours. Nothing is kept or timed.
    Raced,
    /// A lock, sleep or quit cleared the clipboard between the moment the copy
    /// began and the moment the value was ready to write (rule 4). Nothing was
    /// written.
    Interrupted,
}

impl From<ClipboardError> for BridgeError {
    fn from(error: ClipboardError) -> Self {
        match error {
            ClipboardError::Unsupported => BridgeError::bridge(
                "platform_unsupported",
                "this platform has no concealed clipboard yet; the value was not copied",
            ),
            ClipboardError::Failed(why) => BridgeError::bridge(
                "clipboard_failed",
                format!("the clipboard could not be written: {why}"),
            ),
            ClipboardError::Raced => BridgeError::bridge(
                "clipboard_failed",
                "another application wrote to the clipboard while it was being filled; \
                 nothing was kept",
            ),
            ClipboardError::Interrupted => BridgeError::bridge(
                "clipboard_failed",
                "the vault was locked while the value was being copied; nothing was copied",
            ),
        }
    }
}

/// The few pasteboard operations this module needs, so the timing and
/// ownership rules above can be exercised against a fake on any platform and
/// against a private (named, not the user's) pasteboard on macOS.
pub trait Pasteboard: Send + Sync + 'static {
    /// Replace the contents with `text`. With `concealed`, also declare the
    /// concealed and transient markers and keep the contents on this host
    /// (no Universal Clipboard / Handoff; rule 1). Returns the change count that this
    /// write produced, or [`ClipboardError::Raced`] if the pasteboard changed
    /// hands before the write finished (in which case nothing of ours may be
    /// left on it). On any other failure after the pasteboard was touched, the
    /// implementation empties it again: a half-written secret must not linger
    /// untimed.
    fn replace(&self, text: &str, concealed: bool) -> Result<i64, ClipboardError>;
    /// The current change count.
    fn change_count(&self) -> Result<i64, ClipboardError>;
    /// Empty the pasteboard; returns the change count afterwards.
    fn clear(&self) -> Result<i64, ClipboardError>;
}

/// The platform pasteboard: the general one on macOS, an honest refusal
/// elsewhere.
pub fn system_pasteboard() -> Arc<dyn Pasteboard> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(macos::MacPasteboard::general())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(Unsupported)
    }
}

#[cfg(not(target_os = "macos"))]
struct Unsupported;

#[cfg(not(target_os = "macos"))]
impl Pasteboard for Unsupported {
    fn replace(&self, _text: &str, _concealed: bool) -> Result<i64, ClipboardError> {
        Err(ClipboardError::Unsupported)
    }
    fn change_count(&self) -> Result<i64, ClipboardError> {
        Err(ClipboardError::Unsupported)
    }
    fn clear(&self) -> Result<i64, ClipboardError> {
        Err(ClipboardError::Unsupported)
    }
}

/// What this module put on the pasteboard and still owes a clear for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Owned {
    /// The change count our write produced. The pasteboard is ours only while
    /// it still reads this.
    change_count: i64,
    /// When the clock clears it.
    expires: Instant,
}

/// Proof that a copy began before some point in time, so that a value fetched
/// afterwards can be refused if a lock came between (module docs, rule 4). Take
/// one with [`Clipboard::ticket`] **before** asking for the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyTicket {
    epoch: u64,
}

#[derive(Default)]
struct State {
    owned: Option<Owned>,
    /// Bumped by every [`Clipboard::clear_if_owned`], i.e. by every lock, sleep,
    /// screen lock and quit, whether or not it found anything to clear.
    epoch: u64,
    /// Set when the [`Clipboard`] goes away, so the timer thread returns.
    closed: bool,
    /// The timer thread is started by the first secret, not at construction:
    /// an app that never copies a secret never owns a thread for it.
    timer_started: bool,
}

struct Shared {
    pasteboard: Arc<dyn Pasteboard>,
    ttl: Duration,
    state: Mutex<State>,
    wake: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A poisoned lock means a panic while a `State` was being edited; every
        // edit is a whole-field assignment, so the value is never half-written.
        // Recovering beats a clipboard that stays locked forever.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Empty the pasteboard if, and only if, `owned` is still what is on it.
    /// Returns whether it was cleared.
    fn clear_if_unchanged(&self, owned: Owned) -> bool {
        match self.pasteboard.change_count() {
            Ok(now) if now == owned.change_count => self.pasteboard.clear().is_ok(),
            // Moved on (somebody else owns it), or unreadable: leave it.
            _ => false,
        }
    }

    /// Run the clock at `now`: clear what is due, and say how long until the
    /// next deadline (`None` = nothing pending).
    fn tick(&self, state: &mut State, now: Instant) -> Option<Duration> {
        let owned = state.owned?;
        if now >= owned.expires {
            state.owned = None;
            self.clear_if_unchanged(owned);
            return None;
        }
        Some(owned.expires - now)
    }
}

/// Managed state: the owner of the pasteboard contents this app has written.
pub struct Clipboard {
    shared: Arc<Shared>,
}

impl Clipboard {
    /// The production clipboard: the system pasteboard, [`CLEAR_AFTER`].
    pub fn system() -> Self {
        Clipboard::with(system_pasteboard(), CLEAR_AFTER)
    }

    /// A clipboard over any [`Pasteboard`] with any lifetime. Tests use a short
    /// one; production never does.
    pub fn with(pasteboard: Arc<dyn Pasteboard>, ttl: Duration) -> Self {
        Clipboard {
            shared: Arc::new(Shared {
                pasteboard,
                ttl,
                state: Mutex::new(State::default()),
                wake: Condvar::new(),
            }),
        }
    }

    /// How long a secret stays, for the receipt the webview is given.
    pub fn ttl(&self) -> Duration {
        self.shared.ttl
    }

    /// Put a secret on the pasteboard, concealed, and start its clock. A
    /// previous secret (or plain text) is replaced; its clock is forgotten.
    ///
    /// `text` is borrowed so the caller keeps the only owned copy and can wipe
    /// it: this function stores nothing but the change count.
    pub fn copy_secret(&self, text: &str) -> Result<(), ClipboardError> {
        self.write_secret(text, Instant::now(), None)
    }

    /// Begin a copy. Call this before asking the broker for the value and pass
    /// the result to [`Clipboard::copy_secret_for`].
    pub fn ticket(&self) -> CopyTicket {
        CopyTicket {
            epoch: self.shared.lock().epoch,
        }
    }

    /// Like [`Clipboard::copy_secret`], but refuses with
    /// [`ClipboardError::Interrupted`], writing nothing, if a lock, sleep or
    /// quit cleared the clipboard since `ticket` was taken.
    pub fn copy_secret_for(&self, ticket: CopyTicket, text: &str) -> Result<(), ClipboardError> {
        self.write_secret(text, Instant::now(), Some(ticket))
    }

    #[cfg(test)]
    pub(crate) fn copy_secret_at(&self, text: &str, now: Instant) -> Result<(), ClipboardError> {
        self.write_secret(text, now, None)
    }

    fn write_secret(
        &self,
        text: &str,
        now: Instant,
        ticket: Option<CopyTicket>,
    ) -> Result<(), ClipboardError> {
        let mut state = self.shared.lock();
        if ticket.is_some_and(|t| t.epoch != state.epoch) {
            // Nothing has been touched yet: what we owned is still owned.
            return Err(ClipboardError::Interrupted);
        }
        // Whatever we owned is being overwritten (or destroyed) by this call,
        // whether it succeeds or not.
        state.owned = None;
        let change_count = self.shared.pasteboard.replace(text, true)?;
        let owned = Owned {
            change_count,
            expires: now + self.shared.ttl,
        };
        // No clock, no secret: if the OS will not give us the thread that
        // clears it, the value must not be left on the pasteboard untimed.
        if let Err(error) = self.start_timer(&mut state) {
            self.shared.clear_if_unchanged(owned);
            return Err(error);
        }
        state.owned = Some(owned);
        self.shared.wake.notify_all();
        Ok(())
    }

    /// Put non-secret text on the pasteboard: no markers, no clock. It also
    /// ends any secret's ownership, because the pasteboard no longer holds it.
    pub fn copy_plain(&self, text: &str) -> Result<(), ClipboardError> {
        let mut state = self.shared.lock();
        state.owned = None;
        self.shared.pasteboard.replace(text, false)?;
        self.shared.wake.notify_all();
        Ok(())
    }

    /// Empty the pasteboard now **if it still holds what this app put there**.
    /// The call for lock, sleep, screen lock and quit. Returns whether it
    /// cleared anything.
    ///
    /// It also closes the door on any copy already in flight: a [`CopyTicket`]
    /// taken before this call is refused by [`Clipboard::copy_secret_for`]
    /// afterwards (module docs, rule 4). That happens even when there was
    /// nothing to clear, which is exactly the in-flight case.
    pub fn clear_if_owned(&self) -> bool {
        let mut state = self.shared.lock();
        state.epoch = state.epoch.wrapping_add(1);
        let Some(owned) = state.owned.take() else {
            return false;
        };
        self.shared.wake.notify_all();
        self.shared.clear_if_unchanged(owned)
    }

    /// Whether this app believes it still owes the pasteboard a clear.
    pub fn owns_pasteboard(&self) -> bool {
        self.shared.lock().owned.is_some()
    }

    /// Advance the clock to `now` (the unit tests drive this directly with
    /// explicit instants; the timer thread drives it in production).
    #[cfg(test)]
    pub(crate) fn expire_due(&self, now: Instant) -> Option<Duration> {
        let mut state = self.shared.lock();
        self.shared.tick(&mut state, now)
    }

    fn start_timer(&self, state: &mut State) -> Result<(), ClipboardError> {
        if state.timer_started {
            return Ok(());
        }
        let shared = Arc::clone(&self.shared);
        std::thread::Builder::new()
            .name("credmgr-clipboard-clock".into())
            .spawn(move || run_clock(&shared))
            .map_err(|e| {
                ClipboardError::Failed(format!("could not start the clipboard clock: {e}"))
            })?;
        state.timer_started = true;
        Ok(())
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        let owned = {
            let mut state = self.shared.lock();
            state.closed = true;
            state.owned.take()
        };
        self.shared.wake.notify_all();
        if let Some(owned) = owned {
            self.shared.clear_if_unchanged(owned);
        }
    }
}

/// The clock thread: sleep until the earliest deadline, clear what is due,
/// repeat. It holds the state lock only while deciding, never while asleep.
fn run_clock(shared: &Arc<Shared>) {
    let mut state = shared.lock();
    loop {
        if state.closed {
            return;
        }
        match shared.tick(&mut state, Instant::now()) {
            None => {
                state = shared
                    .wake
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            Some(wait) => {
                state = shared
                    .wake
                    .wait_timeout(state, wait)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS: NSPasteboard
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub mod macos {
    //! The AppKit side. Nearly every call here is a plain NSPasteboard method.
    //! The `unsafe` blocks are two kinds: reads of framework constants, and one
    //! `msg_send!` for `releaseGlobally`, which has no binding. The module exists
    //! so that the one platform type is in one place.

    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2_app_kit::{NSPasteboard, NSPasteboardContentsOptions, NSPasteboardTypeString};
    use objc2_foundation::{NSData, NSString};

    use super::{ClipboardError, Pasteboard};

    /// How a write takes ownership of the pasteboard. A concealed write is also
    /// `CurrentHostOnly`: AppKit keeps the contents off Universal Clipboard /
    /// Handoff, so a secret copied here is not offered to the user's other
    /// devices. Plain text takes ownership with no option, and so may travel.
    pub fn contents_options(concealed: bool) -> NSPasteboardContentsOptions {
        if concealed {
            NSPasteboardContentsOptions::CurrentHostOnly
        } else {
            NSPasteboardContentsOptions::empty()
        }
    }

    /// <https://nspasteboard.org>: clipboard managers skip an item that carries
    /// this type…
    pub const CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";
    /// …or this one (a value that is meant to disappear).
    pub const TRANSIENT_TYPE: &str = "org.nspasteboard.TransientType";

    /// A pasteboard by name. The general pasteboard is the user's clipboard;
    /// tests use a uniquely named private one so they never touch it.
    /// `Clone` is a second handle on the *same* pasteboard (a name, not a copy
    /// of its contents), which is how a test plays "another application".
    #[derive(Clone)]
    pub struct MacPasteboard {
        /// `None` = the general pasteboard.
        name: Option<String>,
    }

    impl MacPasteboard {
        /// The user's clipboard.
        pub fn general() -> Self {
            MacPasteboard { name: None }
        }

        /// A private pasteboard: same code path, nobody else's clipboard.
        pub fn named(name: String) -> Self {
            MacPasteboard { name: Some(name) }
        }

        /// A fresh, uniquely named private pasteboard, for tests.
        ///
        /// The name is built here (process id, nanosecond clock and a process-wide
        /// counter) rather than taken from `pasteboardWithUniqueName`, whose
        /// `CFPasteboardUnique-<hex>` names are clock-derived and are handed back
        /// as plain strings after the object that reserved them is dropped. Eight
        /// parallel tests each asked for one in the same instant, and in one full
        /// run a test read a value only its sibling writes, i.e. two of them
        /// shared a pasteboard (not reproducible in 40 quiet runs, so the cause is
        /// inferred from that symptom, not observed). A counter makes two
        /// handles in one process unable to alias by construction.
        pub fn private() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::time::{SystemTime, UNIX_EPOCH};

            static NEXT: AtomicU64 = AtomicU64::new(0);
            let serial = NEXT.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos());
            MacPasteboard::named(format!(
                "com.credmgr.test.pasteboard.{}.{nanos}.{serial}",
                std::process::id()
            ))
        }

        pub(crate) fn board(&self) -> Retained<NSPasteboard> {
            match &self.name {
                None => NSPasteboard::generalPasteboard(),
                Some(name) => NSPasteboard::pasteboardWithName(&NSString::from_str(name)),
            }
        }

        /// Give a **named** pasteboard back to the pasteboard server (AppKit's
        /// `releaseGlobally`). Without it a private pasteboard outlives the
        /// process that made it, for the rest of the login session. Refused for
        /// the general pasteboard, which is the user's and not ours to release.
        pub fn release_globally(&self) {
            if self.name.is_none() {
                return;
            }
            // SAFETY: `releaseGlobally` takes no arguments and returns void; it is
            // only sent to a pasteboard obtained by name, never a standard one.
            // objc2-app-kit has no binding for it, hence `msg_send!`.
            let _: () = unsafe { msg_send![&*self.board(), releaseGlobally] };
        }

        /// The types currently declared on the pasteboard.
        pub fn types(&self) -> Vec<String> {
            self.board()
                .types()
                .map(|types| types.iter().map(|t| t.to_string()).collect())
                .unwrap_or_default()
        }

        /// The plain-text contents, if any.
        pub fn text(&self) -> Option<String> {
            // SAFETY: `NSPasteboardTypeString` is a valid, immutable
            // framework-provided constant.
            let ty = unsafe { NSPasteboardTypeString };
            self.board().stringForType(ty).map(|s| s.to_string())
        }
    }

    impl Pasteboard for MacPasteboard {
        fn replace(&self, text: &str, concealed: bool) -> Result<i64, ClipboardError> {
            let board = self.board();
            // `prepareForNewContentsWithOptions` is `clearContents` plus the
            // option that keeps a secret on this Mac (see `contents_options`);
            // like it, it takes ownership and returns the change count that
            // ownership produced. Every `set…forType` below adds to that same
            // ownership and does not bump the count, so this one number is the
            // identity of everything we write.
            let owned = board.prepareForNewContentsWithOptions(contents_options(concealed)) as i64;

            let wrote = (|| {
                let string = NSString::from_str(text);
                // SAFETY: framework constant.
                let ty = unsafe { NSPasteboardTypeString };
                if !board.setString_forType(&string, ty) {
                    return Err(ClipboardError::Failed(
                        "the pasteboard refused the text".into(),
                    ));
                }
                if concealed {
                    let marker = NSData::new();
                    for name in [CONCEALED_TYPE, TRANSIENT_TYPE] {
                        if !board.setData_forType(Some(&marker), &NSString::from_str(name)) {
                            return Err(ClipboardError::Failed(format!(
                                "the pasteboard refused the {name} marker"
                            )));
                        }
                    }
                }
                Ok(())
            })();

            let now = board.changeCount() as i64;
            if now != owned {
                // Somebody took the pasteboard between our clear and our last
                // write. Whatever we added went into *their* contents, and
                // clearing would destroy their copy, so do neither.
                return Err(ClipboardError::Raced);
            }
            match wrote {
                Ok(()) => Ok(owned),
                Err(error) => {
                    // The pasteboard is still ours and holds a partial secret.
                    board.clearContents();
                    Err(error)
                }
            }
        }

        fn change_count(&self) -> Result<i64, ClipboardError> {
            Ok(self.board().changeCount() as i64)
        }

        fn clear(&self) -> Result<i64, ClipboardError> {
            Ok(self.board().clearContents() as i64)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: the ownership and clock rules, against a fake pasteboard
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod fake {
    //! A pasteboard that behaves like AppKit's where it matters: a change count
    //! that moves only when someone takes ownership.

    use super::{ClipboardError, Pasteboard};
    use std::sync::Mutex;

    #[derive(Default, Debug, Clone)]
    pub struct Contents {
        pub change_count: i64,
        pub text: Option<String>,
        pub concealed: bool,
        /// Counts `replace` calls, so a test can see what was attempted.
        pub writes: u32,
    }

    #[derive(Default)]
    pub struct FakePasteboard {
        pub inner: Mutex<Contents>,
        /// Make the next `replace` fail with this error after clearing, the way
        /// a half-written pasteboard would.
        pub fail_next: Mutex<Option<ClipboardError>>,
    }

    impl FakePasteboard {
        pub fn snapshot(&self) -> Contents {
            self.inner.lock().unwrap().clone()
        }

        /// Another application copies something.
        pub fn external_copy(&self, text: &str) {
            let mut c = self.inner.lock().unwrap();
            c.change_count += 1;
            c.text = Some(text.to_string());
            c.concealed = false;
        }
    }

    impl Pasteboard for FakePasteboard {
        fn replace(&self, text: &str, concealed: bool) -> Result<i64, ClipboardError> {
            let mut c = self.inner.lock().unwrap();
            c.writes += 1;
            if let Some(error) = self.fail_next.lock().unwrap().take() {
                // The attempt cleared the old contents and then failed; the
                // implementation contract is that it empties what it started.
                c.change_count += 2;
                c.text = None;
                c.concealed = false;
                return Err(error);
            }
            c.change_count += 1;
            c.text = Some(text.to_string());
            c.concealed = concealed;
            Ok(c.change_count)
        }
        fn change_count(&self) -> Result<i64, ClipboardError> {
            Ok(self.inner.lock().unwrap().change_count)
        }
        fn clear(&self) -> Result<i64, ClipboardError> {
            let mut c = self.inner.lock().unwrap();
            c.change_count += 1;
            c.text = None;
            c.concealed = false;
            Ok(c.change_count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakePasteboard;
    use super::*;

    const TTL: Duration = Duration::from_secs(30);

    fn clipboard() -> (Clipboard, Arc<FakePasteboard>) {
        let board = Arc::new(FakePasteboard::default());
        // The real timer thread is exercised in `tests/shell_ipc.rs`; here every
        // test drives the clock itself, with explicit instants, so none of them
        // depends on how fast the machine runs.
        (Clipboard::with(board.clone(), TTL), board)
    }

    #[test]
    fn a_secret_is_written_concealed_and_cleared_when_its_time_comes() {
        let (clip, board) = clipboard();
        let t0 = Instant::now();
        clip.copy_secret_at("s3cret", t0).unwrap();
        let c = board.snapshot();
        assert_eq!(c.text.as_deref(), Some("s3cret"));
        assert!(c.concealed, "a secret must carry the concealed markers");
        assert!(clip.owns_pasteboard());

        // One second before the deadline: still there. The answer is how long
        // is left, which is what the timer thread sleeps for.
        assert_eq!(
            clip.expire_due(t0 + TTL - Duration::from_secs(1)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(board.snapshot().text.as_deref(), Some("s3cret"));

        // At the deadline: gone, and nothing more is owed.
        assert_eq!(clip.expire_due(t0 + TTL), None);
        assert_eq!(board.snapshot().text, None);
        assert!(!clip.owns_pasteboard());
    }

    #[test]
    fn the_clock_never_clears_something_the_user_copied_afterwards() {
        let (clip, board) = clipboard();
        let t0 = Instant::now();
        clip.copy_secret_at("s3cret", t0).unwrap();
        board.external_copy("my own sentence");

        clip.expire_due(t0 + TTL);
        assert_eq!(
            board.snapshot().text.as_deref(),
            Some("my own sentence"),
            "the 30 s clear must only clear its own content"
        );
        assert!(!clip.owns_pasteboard(), "and it is no longer owed");
    }

    #[test]
    fn a_second_secret_restarts_the_clock_and_the_first_clock_cannot_clear_it_early() {
        let (clip, board) = clipboard();
        let t0 = Instant::now();
        clip.copy_secret_at("first", t0).unwrap();
        let t1 = t0 + Duration::from_secs(20);
        clip.copy_secret_at("second", t1).unwrap();

        // Past the first secret's deadline, before the second's.
        clip.expire_due(t0 + TTL + Duration::from_secs(1));
        assert_eq!(board.snapshot().text.as_deref(), Some("second"));

        clip.expire_due(t1 + TTL);
        assert_eq!(board.snapshot().text, None);
    }

    #[test]
    fn plain_text_has_no_markers_and_no_clock_and_ends_a_secrets_ownership() {
        let (clip, board) = clipboard();
        let t0 = Instant::now();
        clip.copy_secret_at("s3cret", t0).unwrap();
        clip.copy_plain("a public address").unwrap();

        let c = board.snapshot();
        assert_eq!(c.text.as_deref(), Some("a public address"));
        assert!(!c.concealed);
        assert!(!clip.owns_pasteboard());

        clip.expire_due(t0 + TTL * 10);
        assert_eq!(
            board.snapshot().text.as_deref(),
            Some("a public address"),
            "plain text is never timed out"
        );
    }

    #[test]
    fn clear_if_owned_clears_a_live_secret_at_once() {
        let (clip, board) = clipboard();
        clip.copy_secret("s3cret").unwrap();
        assert!(clip.clear_if_owned());
        assert_eq!(board.snapshot().text, None);
        assert!(!clip.owns_pasteboard());
        // Nothing more to do: a second call, a lock with nothing copied.
        assert!(!clip.clear_if_owned());
    }

    #[test]
    fn clear_if_owned_leaves_a_later_copy_alone() {
        // The lock / sleep / quit path must not wipe what the user copied after.
        let (clip, board) = clipboard();
        clip.copy_secret("s3cret").unwrap();
        board.external_copy("not ours");
        assert!(!clip.clear_if_owned());
        assert_eq!(board.snapshot().text.as_deref(), Some("not ours"));
    }

    #[test]
    fn a_failed_write_leaves_nothing_owned_and_nothing_timed() {
        let (clip, board) = clipboard();
        clip.copy_secret("old").unwrap();
        *board.fail_next.lock().unwrap() = Some(ClipboardError::Failed("no".into()));
        assert!(clip.copy_secret("new").is_err());
        assert!(!clip.owns_pasteboard());
        assert_eq!(
            board.snapshot().text,
            None,
            "the implementation empties what a failed write started"
        );
    }

    #[test]
    fn a_raced_write_is_reported_and_keeps_nothing() {
        let (clip, board) = clipboard();
        *board.fail_next.lock().unwrap() = Some(ClipboardError::Raced);
        assert_eq!(clip.copy_secret("s3cret"), Err(ClipboardError::Raced));
        assert!(!clip.owns_pasteboard());
    }

    #[test]
    fn dropping_the_clipboard_clears_what_it_still_owns() {
        let (clip, board) = clipboard();
        clip.copy_secret("s3cret").unwrap();
        drop(clip);
        assert_eq!(board.snapshot().text, None);

        let (clip, board) = clipboard();
        clip.copy_secret("s3cret").unwrap();
        board.external_copy("not ours");
        drop(clip);
        assert_eq!(board.snapshot().text.as_deref(), Some("not ours"));
    }

    #[test]
    fn the_receipt_ttl_is_the_one_the_clock_uses() {
        let (clip, _) = clipboard();
        assert_eq!(clip.ttl(), TTL);
        assert_eq!(CLEAR_AFTER, Duration::from_secs(30), "the documented 30 s");
    }

    #[test]
    fn clipboard_errors_map_onto_the_bridges_vocabulary() {
        assert_eq!(
            BridgeError::from(ClipboardError::Unsupported).code,
            "platform_unsupported"
        );
        assert_eq!(
            BridgeError::from(ClipboardError::Failed("x".into())).code,
            "clipboard_failed"
        );
        assert_eq!(
            BridgeError::from(ClipboardError::Raced).code,
            "clipboard_failed"
        );
        assert_eq!(
            BridgeError::from(ClipboardError::Interrupted).code,
            "clipboard_failed"
        );
    }

    #[test]
    fn a_copy_that_began_before_a_lock_writes_nothing_after_it() {
        let (clip, board) = clipboard();
        let ticket = clip.ticket();
        // The lock lands while the value is still being fetched. Nothing is
        // owned yet, so there is nothing for it to clear, and it must still
        // close the door.
        assert!(!clip.clear_if_owned());

        assert_eq!(
            clip.copy_secret_for(ticket, "s3cret"),
            Err(ClipboardError::Interrupted)
        );
        let c = board.snapshot();
        assert_eq!(c.text, None, "no secret after the lock");
        assert_eq!(c.writes, 0, "and the pasteboard was never touched");
        assert!(!clip.owns_pasteboard());
    }

    #[test]
    fn a_copy_with_no_lock_in_between_is_written_and_timed_as_usual() {
        let (clip, board) = clipboard();
        let ticket = clip.ticket();
        clip.copy_secret_for(ticket, "s3cret").unwrap();
        assert_eq!(board.snapshot().text.as_deref(), Some("s3cret"));
        assert!(board.snapshot().concealed);
        assert!(clip.owns_pasteboard());
    }

    #[test]
    fn a_stale_ticket_stays_refused_and_a_fresh_one_works() {
        let (clip, board) = clipboard();
        let stale = clip.ticket();
        clip.clear_if_owned();
        clip.clear_if_owned();
        assert_eq!(
            clip.copy_secret_for(stale, "first try"),
            Err(ClipboardError::Interrupted)
        );
        // The user tries again after the lock: a new ticket, a new epoch.
        let fresh = clip.ticket();
        clip.copy_secret_for(fresh, "second try").unwrap();
        assert_eq!(board.snapshot().text.as_deref(), Some("second try"));
    }

    #[test]
    fn a_refused_copy_after_a_lock_leaves_the_pasteboard_empty() {
        // An earlier secret is on the pasteboard when the next copy begins; the
        // lock clears it, and the late copy then writes nothing back.
        let (clip, board) = clipboard();
        clip.copy_secret("already there").unwrap();
        let ticket = clip.ticket();
        assert!(clip.clear_if_owned());
        assert_eq!(board.snapshot().text, None);
        assert!(clip.copy_secret_for(ticket, "late").is_err());
        assert_eq!(board.snapshot().text, None);
    }
}
