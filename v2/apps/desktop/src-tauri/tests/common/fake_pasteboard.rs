//! A pasteboard that behaves like AppKit's where the clipboard rules depend on
//! it: a change count that moves only when somebody takes ownership. The
//! macOS-only `tests/macos_pasteboard.rs` proves the real one behaves that way;
//! the tests that use this one prove what the shell does *given* that behaviour.

#![allow(dead_code)]

use std::sync::Mutex;
use std::thread::ThreadId;

use desktop_lib::clipboard::{ClipboardError, Pasteboard};

#[derive(Default, Debug, Clone)]
pub struct Contents {
    pub change_count: i64,
    pub text: Option<String>,
    pub concealed: bool,
    /// How many `replace` calls reached the pasteboard.
    pub writes: u32,
    /// The thread that performed each `clear`, in order. A test that needs to
    /// know *where* a clear ran (inside an OS notification block, or later on
    /// the async runtime) compares these with its own thread id.
    pub clear_threads: Vec<ThreadId>,
}

#[derive(Default)]
pub struct FakePasteboard {
    inner: Mutex<Contents>,
}

impl FakePasteboard {
    pub fn snapshot(&self) -> Contents {
        self.inner.lock().unwrap().clone()
    }

    pub fn text(&self) -> Option<String> {
        self.snapshot().text
    }

    /// Another application (or the user) copies something.
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
        c.clear_threads.push(std::thread::current().id());
        c.change_count += 1;
        c.text = None;
        c.concealed = false;
        Ok(c.change_count)
    }
}
