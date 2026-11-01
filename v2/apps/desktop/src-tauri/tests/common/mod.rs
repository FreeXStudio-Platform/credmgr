//! A stand-in `credmgrd` that speaks the real protocol over a real Unix
//! domain socket.
//!
//! **Why a fake broker and not the real one.** `crates/cli/tests/broker_integration.rs`
//! drives an actual `BrokerState` — the right shape for testing the *broker*.
//! It is the wrong shape here for one hard reason and one soft one. The hard
//! one: ADR-035 puts this crate in a separate Cargo workspace specifically so
//! Tauri's edition-2024 tree cannot drag the security crates off their 1.78
//! MSRV pin, so `src-tauri` cannot depend on `credmgr-brokerd` to build a
//! fixture without undoing that. The soft one: what is under test here is the
//! *bridge* — framing, id echo, token custody, error mapping, lock
//! reconciliation — and every one of those is a property of what crosses the
//! socket, which this exercises exactly.
//!
//! What is deliberately **not** claimed: this proves nothing about whether
//! the broker's answers are correct. `tests/drift_guards.rs` is what keeps
//! the shapes asserted here honest against the real `protocol.rs`.

#![allow(dead_code)] // each test file uses a different subset of this helper

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde_json::{json, Value};

/// A response body as a handler returns it — everything but `id`, which the
/// harness echoes from the request exactly as `server.rs` does.
pub type Handler = Arc<dyn Fn(&Value) -> Value + Send + Sync>;

pub struct FakeBroker {
    pub socket: PathBuf,
    received: Arc<Mutex<Vec<Value>>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    _tmp: Option<tempfile::TempDir>,
}

impl FakeBroker {
    pub fn spawn<H>(handler: H) -> FakeBroker
    where
        H: Fn(&Value) -> Value + Send + Sync + 'static,
    {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Short filename on purpose: a Unix socket path is capped near 104
        // bytes on macOS, and a long temp prefix plus a long name silently
        // fails to bind.
        let socket = tmp.path().join("b.sock");
        FakeBroker::start(socket, Some(tmp), handler)
    }

    /// Bind at a path the caller chose (and owns the directory of) — for tests
    /// that reach the broker the way the app does, through
    /// `CREDMGR_VAULT_DIR` → `<dir>/run/broker.sock`.
    pub fn spawn_at<H>(socket: PathBuf, handler: H) -> FakeBroker
    where
        H: Fn(&Value) -> Value + Send + Sync + 'static,
    {
        FakeBroker::start(socket, None, handler)
    }

    fn start<H>(socket: PathBuf, tmp: Option<tempfile::TempDir>, handler: H) -> FakeBroker
    where
        H: Fn(&Value) -> Value + Send + Sync + 'static,
    {
        let listener = UnixListener::bind(&socket).expect("bind fake broker socket");

        let received = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let handler: Handler = Arc::new(handler);

        let thread = {
            let received = Arc::clone(&received);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                for incoming in listener.incoming() {
                    if shutdown.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(stream) = incoming else { return };
                    serve(stream, &handler, &received);
                }
            })
        };

        FakeBroker {
            socket,
            received,
            shutdown,
            thread: Some(thread),
            _tmp: tmp,
        }
    }

    /// Every request frame the bridge sent, in order.
    pub fn received(&self) -> Vec<Value> {
        self.received.lock().expect("received mutex").clone()
    }

    /// The `token` field of the nth request — `None` covers both "absent"
    /// and "explicitly null", which is what the bridge sends when it holds
    /// no session.
    pub fn token_on(&self, index: usize) -> Option<String> {
        self.received()
            .get(index)
            .and_then(|r| r.get("token"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    pub fn op_on(&self, index: usize) -> Option<String> {
        self.received()
            .get(index)
            .and_then(|r| r.get("op"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

impl Drop for FakeBroker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept() the listener thread is parked in.
        let _ = UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(stream: UnixStream, handler: &Handler, received: &Arc<Mutex<Vec<Value>>>) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(trimmed) else {
            let _ = writeln!(
                writer,
                "{}",
                json!({ "id": "?", "ok": false, "error": "malformed_request" })
            );
            continue;
        };
        received
            .lock()
            .expect("received mutex")
            .push(request.clone());

        let mut response = handler(&request);
        if let Some(object) = response.as_object_mut() {
            // `server.rs` echoes the request's own id. Only fill it in when
            // the handler did not deliberately set one (a test that wants to
            // prove the id check works sets a wrong one on purpose).
            object
                .entry("id")
                .or_insert_with(|| request.get("id").cloned().unwrap_or(json!("?")));
        }
        if writeln!(writer, "{response}").is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Response builders, shaped exactly like `protocol.rs::to_wire`.
// ---------------------------------------------------------------------------

pub fn ok(value: Value) -> Value {
    json!({ "ok": true, "value": value })
}

pub fn err(code: &str, extra: Value) -> Value {
    let mut body = json!({ "ok": false, "error": code });
    if let (Some(target), Some(source)) = (body.as_object_mut(), extra.as_object()) {
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    }
    body
}

pub mod fake_pasteboard;
