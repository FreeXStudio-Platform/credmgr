//! The shell's own commands and events, driven through Tauri's real IPC
//! dispatch.
//!
//! `desktop_lib::configure` is the function `run()` calls to wire the app; here
//! it is handed Tauri's mock runtime and a fake pasteboard, and every scenario
//! goes in by `get_ipc_response` — the same path `invoke()` takes from a
//! webview — against a stand-in `credmgrd` on a real Unix socket. So what is
//! proven is the whole chain (command registration, argument decoding, the
//! token the shell attaches, the broker round trip, the clipboard, the
//! response that comes back), not a function that a command happens to call.
//!
//! The headline property — **a secret copied with `entry_copy` never crosses the
//! IPC boundary** — is checked on the serialised response text itself, for
//! success and for every refusal, with a needle no real value would contain.
//!
//! These tests set `CREDMGR_VAULT_DIR`, which is process-global, so they hold
//! one lock for their whole lifetime; each test file is its own process, so
//! nothing else sees the variable.

mod common;

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeBody, InvokeResponseBody};
use tauri::test::{
    get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY,
};
use tauri::webview::InvokeRequest;
use tauri::{Listener, Manager, RunEvent, WebviewWindow, WebviewWindowBuilder, WindowEvent};

use common::fake_pasteboard::FakePasteboard;
use common::{err, ok, FakeBroker};
use desktop_lib::autolock::{self, LockReason, EVENT_LOCKED};
use desktop_lib::clipboard::Clipboard;
use desktop_lib::session::Session;
use desktop_lib::shell::{self, EVENT_WINDOW_INACTIVE};

/// Serialises the tests in this file (they share one process environment).
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// A value no genuine secret, id or label would ever equal or contain.
const SECRET: &str = "hunter2-NEEDLE-4f9c1b7e";
const TOKEN: &str = "cmt_test_token_0001";

fn broker_handler(request: &Value) -> Value {
    match request["op"].as_str() {
        Some("vault.unlock") => ok(json!({ "locked": false, "token": TOKEN })),
        Some("vault.lock") => ok(json!({ "locked": true })),
        Some("entry.reveal") => ok(json!({
            "node": request["params"]["node"],
            "entry": request["params"]["entry"],
            "value": SECRET,
        })),
        _ => err("malformed_request", json!({})),
    }
}

struct Harness {
    app: tauri::App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
    board: Arc<FakePasteboard>,
    broker: FakeBroker,
    socket: PathBuf,
    // Declared last so they drop last: the lock must outlive the app and broker.
    _vault: tempfile::TempDir,
    _guard: MutexGuard<'static, ()>,
}

fn harness_with<H>(ttl: Duration, handler: H) -> Harness
where
    H: Fn(&Value) -> Value + Send + Sync + 'static,
{
    let guard = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let vault = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(vault.path().join("run")).expect("run dir");
    let socket = vault.path().join("run").join("broker.sock");
    std::env::set_var("CREDMGR_VAULT_DIR", vault.path());

    let broker = FakeBroker::spawn_at(socket.clone(), handler);
    let board = Arc::new(FakePasteboard::default());
    let clipboard = Clipboard::with(board.clone(), ttl);
    let app = desktop_lib::configure(mock_builder(), clipboard)
        .build(mock_context(noop_assets()))
        .expect("build the app on the mock runtime");
    let webview = WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("mock window");
    Harness {
        app,
        webview,
        board,
        broker,
        socket,
        _vault: vault,
        _guard: guard,
    }
}

fn harness() -> Harness {
    harness_with(Duration::from_secs(30), broker_handler)
}

impl Harness {
    /// One `invoke()`: `Ok(serialised body)` or `Err(serialised error)`. Text,
    /// not `Value`, so a test can search the very bytes the webview receives.
    fn invoke_raw(&self, cmd: &str, body: Value) -> Result<String, String> {
        let request = InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: "tauri://localhost".parse().unwrap(),
            body: InvokeBody::Json(body),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        };
        match get_ipc_response(&self.webview, request) {
            Ok(InvokeResponseBody::Json(text)) => Ok(text),
            Ok(InvokeResponseBody::Raw(bytes)) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
            Err(value) => Err(value.to_string()),
        }
    }

    fn invoke(&self, cmd: &str, body: Value) -> Result<Value, Value> {
        self.invoke_raw(cmd, body)
            .map(|t| serde_json::from_str(&t).expect("JSON response"))
            .map_err(|t| serde_json::from_str(&t).expect("JSON error"))
    }

    fn log_in(&self) {
        let state = self
            .invoke("vault_unlock", json!({ "passphrase": "pw" }))
            .expect("unlock");
        assert_eq!(state["authenticated"], true);
    }

    /// Point the app at a vault directory with no broker in it, the way a
    /// stopped `credmgrd` looks. The fake keeps its socket: removing the file
    /// would leave its listener thread parked in `accept()` with no way for its
    /// `Drop` to wake it. Returns the socket path that now resolves.
    fn take_the_broker_away(&self) -> PathBuf {
        let empty = self._vault.path().join("nowhere");
        std::env::set_var("CREDMGR_VAULT_DIR", &empty);
        empty.join("run").join("broker.sock")
    }

    fn session(&self) -> tauri::State<'_, Session> {
        self.app.state::<Session>()
    }

    fn ops(&self) -> Vec<String> {
        (0..self.broker.received().len())
            .filter_map(|i| self.broker.op_on(i))
            .collect()
    }

    /// Listen for an app event; payloads arrive as JSON text.
    fn events(&self, name: &str) -> Receiver<String> {
        let (tx, rx) = channel();
        self.app.listen(name, move |event| {
            let _ = tx.send(event.payload().to_string());
        });
        rx
    }
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// entry_copy
// ---------------------------------------------------------------------------

#[test]
fn entry_copy_puts_the_secret_on_the_concealed_clipboard_and_returns_none_of_it() {
    let h = harness();
    h.log_in();

    let raw = h
        .invoke_raw("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .expect("entry_copy succeeds");

    // What crossed the IPC boundary: a receipt, byte for byte, and no secret.
    assert!(
        !raw.contains(SECRET),
        "the secret reached the webview in: {raw}"
    );
    let receipt: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(receipt, json!({ "copied": true, "clearAfterSeconds": 30 }));

    // Where it went instead.
    let pasteboard = h.board.snapshot();
    assert_eq!(pasteboard.text.as_deref(), Some(SECRET));
    assert!(
        pasteboard.concealed,
        "a copied secret must carry the concealed and transient markers"
    );

    // And how it got there: through the audited reveal, with the session token
    // the shell holds attached Rust-side (the webview never had it).
    assert_eq!(h.ops(), vec!["vault.unlock", "entry.reveal"]);
    assert_eq!(h.broker.token_on(1).as_deref(), Some(TOKEN));
    let reveal = &h.broker.received()[1];
    assert_eq!(reveal["params"], json!({ "node": "acme", "entry": "e_1" }));
}

#[test]
fn the_leak_check_can_fail_because_entry_reveal_does_return_the_value() {
    // Canary for the headline test above. `entry_reveal` is the command whose job
    // is to hand the plaintext to the webview; if searching its serialised
    // response for the needle did not find it, "entry_copy's response does not
    // contain the secret" would prove nothing.
    let h = harness();
    h.log_in();
    let raw = h
        .invoke_raw("entry_reveal", json!({ "node": "acme", "entry": "e_1" }))
        .expect("entry_reveal");
    assert!(
        raw.contains(SECRET),
        "the needle is not visible in a response that carries it: {raw}"
    );
    assert_eq!(h.board.snapshot().writes, 0, "and it touches no clipboard");
}

#[test]
fn entry_copy_without_a_login_asks_the_broker_anyway_and_passes_its_denial_through() {
    // The shell decides nothing: no token means the broker resolves the caller
    // as the agent it would be, and says no in its own words.
    let h = harness_with(Duration::from_secs(30), |request| {
        match request["op"].as_str() {
            Some("entry.reveal") => err(
                "node_access_denied",
                json!({ "rule": "R8", "message": "no grant", "value": SECRET }),
            ),
            _ => err("malformed_request", json!({})),
        }
    });

    let raw = h
        .invoke_raw("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .expect_err("a denial");
    // The stand-in broker above put the needle in the refusal's `value` field, as a
    // buggy broker might. `entry_copy` exists so that no secret reaches the webview,
    // and that has to hold on the refusal path too, not only on success.
    assert!(
        !raw.contains(SECRET),
        "a value in a broker refusal reached the webview through entry_copy: {raw}"
    );
    let error: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(error["code"], "node_access_denied");
    assert_eq!(error["source"], "broker");
    assert_eq!(
        error["detail"]["rule"], "R8",
        "the refusal's reasons still arrive unchanged"
    );
    assert_eq!(h.broker.token_on(0), None, "no login, no token on the wire");
    assert_eq!(h.board.snapshot().writes, 0, "a denial copies nothing");
    assert_eq!(h.board.text(), None);
}

#[test]
fn every_refusal_leaves_the_clipboard_untouched_and_the_response_secret_free() {
    for code in [
        "node_locked",
        "approval_pending",
        "vault_locked",
        "capability_not_held",
        "session_expired",
    ] {
        let h = harness_with(Duration::from_secs(30), move |request| {
            match request["op"].as_str() {
                Some("vault.unlock") => ok(json!({ "locked": false, "token": TOKEN })),
                Some("entry.reveal") => err(code, json!({ "message": "refused" })),
                _ => err("malformed_request", json!({})),
            }
        });
        h.log_in();
        h.board.external_copy("the user's own text");

        let raw = h
            .invoke_raw("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
            .expect_err(code);
        assert!(!raw.contains(SECRET));
        assert_eq!(serde_json::from_str::<Value>(&raw).unwrap()["code"], code);
        assert_eq!(
            h.board.text().as_deref(),
            Some("the user's own text"),
            "{code}: a refusal must not touch what is on the clipboard"
        );
    }
}

#[test]
fn a_node_lock_refusal_does_not_log_the_desktop_out() {
    // ADR-077 (G3): `node_locked` is a refusal about one node, not the vault.
    let h = harness_with(Duration::from_secs(30), |request| {
        match request["op"].as_str() {
            Some("vault.unlock") => ok(json!({ "locked": false, "token": TOKEN })),
            Some("entry.reveal") => err("node_locked", json!({ "node": "acme" })),
            _ => err("malformed_request", json!({})),
        }
    });
    h.log_in();
    let _ = h.invoke_raw("entry_copy", json!({ "node": "acme", "entry": "e_1" }));
    assert!(h.session().is_authenticated());
}

#[test]
fn entry_copy_refuses_a_value_that_is_not_text_and_writes_nothing() {
    for odd in [
        json!(42),
        json!(["a", SECRET]),
        json!({ "nested": SECRET }),
        json!(null),
    ] {
        let odd_for_handler = odd.clone();
        let h = harness_with(Duration::from_secs(30), move |request| {
            match request["op"].as_str() {
                Some("entry.reveal") => ok(json!({ "value": odd_for_handler })),
                _ => err("malformed_request", json!({})),
            }
        });
        let raw = h
            .invoke_raw("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
            .expect_err("a non-text value is refused");
        assert!(!raw.contains(SECRET), "{odd}: {raw}");
        assert_eq!(
            serde_json::from_str::<Value>(&raw).unwrap()["code"],
            "malformed_response"
        );
        assert_eq!(h.board.snapshot().writes, 0, "{odd}");
    }
}

/// A stand-in for the ADR-078 `entry.reveal`: two fields, and — like the real
/// `entry_doc::reveal_json` — `value` only when exactly one field is returned.
fn two_field_broker(request: &Value) -> Value {
    const OTHER: &str = "other-NEEDLE-77aa";
    let fields = [
        ("f_0a1b2c3d", "host", SECRET),
        ("f_4e5f6a7b", "password", OTHER),
    ];
    match request["op"].as_str() {
        Some("vault.unlock") => ok(json!({ "locked": false, "token": TOKEN })),
        Some("entry.reveal") => {
            let wanted = request["params"]["fieldIds"].as_array();
            let rows: Vec<Value> = fields
                .iter()
                .filter(|(id, _, _)| wanted.is_none_or(|w| w.iter().any(|x| x == id)))
                .map(|(id, label, value)| {
                    json!({ "id": id, "label": label, "value": value, "type": "text", "masked": false })
                })
                .collect();
            let mut body = json!({
                "node": request["params"]["node"], "entry": request["params"]["entry"],
                "fields": rows,
            });
            if let [only] = rows.as_slice() {
                body["value"] = only["value"].clone();
            }
            ok(body)
        }
        _ => err("malformed_request", json!({})),
    }
}

#[test]
fn entry_copy_of_one_field_asks_for_only_that_field_and_the_value_never_crosses_ipc() {
    let h = harness_with(Duration::from_secs(30), two_field_broker);
    h.log_in();

    let raw = h
        .invoke_raw(
            "entry_copy",
            json!({ "node": "acme", "entry": "e_1", "field": "f_0a1b2c3d" }),
        )
        .expect("a named field copies");
    assert!(
        !raw.contains(SECRET) && !raw.contains("other-NEEDLE"),
        "a value reached the webview: {raw}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&raw).unwrap(),
        json!({ "copied": true, "clearAfterSeconds": 30 })
    );
    assert_eq!(h.board.snapshot().text.as_deref(), Some(SECRET));
    // The reveal was narrowed on the wire: the other field's value never came this way.
    let reveal = &h.broker.received()[1];
    assert_eq!(reveal["op"], "entry.reveal");
    assert_eq!(
        reveal["params"],
        json!({ "node": "acme", "entry": "e_1", "fieldIds": ["f_0a1b2c3d"] })
    );
}

#[test]
fn entry_copy_of_a_several_field_entry_with_no_field_is_refused_and_copies_nothing() {
    let h = harness_with(Duration::from_secs(30), two_field_broker);
    h.log_in();

    let raw = h
        .invoke_raw("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .expect_err("no field named on a two-field entry");
    // The refusal says what to do, and carries none of the values the reveal returned.
    assert!(
        !raw.contains(SECRET) && !raw.contains("other-NEEDLE"),
        "a value reached the webview in a refusal: {raw}"
    );
    let error: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(error["code"], "field_required");
    assert_eq!(error["source"], "bridge");
    assert!(
        error["message"].as_str().unwrap().contains("2 fields"),
        "{raw}"
    );
    assert_eq!(h.board.snapshot().writes, 0, "nothing was copied");
    // No `fieldIds` went out: the app asked for the whole entry, and was refused locally.
    assert_eq!(
        h.broker.received()[1]["params"],
        json!({ "node": "acme", "entry": "e_1" })
    );
}

#[test]
fn entry_reveal_carries_field_ids_and_hands_the_webview_the_brokers_fields() {
    // The command whose job is to return plaintext: `fieldIds` out, `fields` back.
    let h = harness_with(Duration::from_secs(30), two_field_broker);
    h.log_in();
    let one = h
        .invoke(
            "entry_reveal",
            json!({ "node": "acme", "entry": "e_1", "fieldIds": ["f_4e5f6a7b"] }),
        )
        .expect("entry_reveal");
    assert_eq!(one["fields"].as_array().unwrap().len(), 1);
    assert_eq!(one["value"], "other-NEEDLE-77aa");
    let all = h
        .invoke("entry_reveal", json!({ "node": "acme", "entry": "e_1" }))
        .expect("entry_reveal");
    assert_eq!(all["fields"].as_array().unwrap().len(), 2);
    assert!(
        all.get("value").is_none(),
        "no single value for two fields: {all}"
    );
    assert_eq!(h.board.snapshot().writes, 0, "and it touches no clipboard");
}

#[test]
fn fields_preview_is_local_it_reaches_no_broker_and_needs_no_login() {
    let h = harness();
    // Deliberately not logged in: the preview has no session, no socket, no audit record.
    let preview = h
        .invoke(
            "fields_preview",
            json!({ "text": "host: db.example.test\npassword: pw-test-1\n" }),
        )
        .expect("fields_preview");
    assert_eq!(preview["singleBlobHint"], false);
    let segment = &preview["segments"][0];
    assert_eq!(segment["fieldCount"], 2);
    assert_eq!(segment["suggestedName"], "host");
    assert_eq!(segment["fields"][1]["label"], "password");
    assert_eq!(segment["fields"][1]["value"], "pw-test-1");
    assert_eq!(segment["fields"][1]["masked"], true);
    assert!(
        h.broker.received().is_empty(),
        "the preview reached the broker: {:?}",
        h.ops()
    );
    assert_eq!(h.board.snapshot().writes, 0);

    // Optional arguments may be left out entirely, as `bridge.ts` does.
    let from_fields = h
        .invoke(
            "fields_preview",
            json!({ "fields": [{ "label": "token", "value": "t-1" }], "split": null }),
        )
        .expect("fields_preview from structured fields");
    assert_eq!(from_fields["segments"][0]["fieldCount"], 1);

    // A refusal is the bridge's own, and quotes nothing it was given.
    let error = h
        .invoke(
            "fields_preview",
            json!({ "text": "a: b", "fields": [{ "label": "x", "value": "LEAKCHECK-1" }] }),
        )
        .expect_err("both text and fields");
    assert_eq!(error["code"], "invalid_fields");
    assert_eq!(error["source"], "bridge");
    assert!(!error.to_string().contains("LEAKCHECK-1"), "{error}");
    assert!(h.broker.received().is_empty());
}

#[test]
fn entry_copy_with_the_broker_down_says_so_and_copies_nothing() {
    let h = harness();
    h.take_the_broker_away();
    let raw = h
        .invoke_raw("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .expect_err("broker unreachable");
    assert_eq!(
        serde_json::from_str::<Value>(&raw).unwrap()["code"],
        "broker_unreachable"
    );
    assert_eq!(h.board.snapshot().writes, 0);
}

#[test]
fn the_real_clock_clears_a_copied_secret_but_not_what_the_user_copied_next() {
    // The only test in this file that waits on real time, and it only ever waits
    // for something to *happen* (never for something not to), with a 10 s
    // ceiling against a 150 ms clock, so a loaded machine slows it down without
    // failing it.
    let ttl = Duration::from_millis(150);

    let h = harness_with(ttl, broker_handler);
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .expect("copy");
    assert_eq!(h.board.text().as_deref(), Some(SECRET));
    wait_until("the clock to clear the secret", || h.board.text().is_none());
    // One harness at a time: each holds the environment lock.
    drop(h);

    let h = harness_with(ttl, broker_handler);
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .expect("copy");
    h.board.external_copy("typed after");
    // Long enough for the clock to have come and gone several times over.
    std::thread::sleep(ttl * 6);
    assert_eq!(
        h.board.text().as_deref(),
        Some("typed after"),
        "the clear must only ever clear its own content"
    );
}

// ---------------------------------------------------------------------------
// app_icon_set
// ---------------------------------------------------------------------------

#[test]
fn app_icon_set_takes_each_of_the_six_marks_and_never_talks_to_the_broker() {
    let h = harness();
    for id in desktop_lib::icon::MARK_IDS {
        let receipt = h.invoke("app_icon_set", json!({ "icon": id })).expect(id);
        assert_eq!(receipt["icon"], json!(id));
        // Which surface it reached depends on the OS and, in the mock runtime, on whether AppKit gave a main thread; the
        // fact that matters here is that the command answered and named the icon.
        assert!(receipt["dock"].is_boolean() && receipt["window"].is_boolean());
    }
    assert!(
        h.ops().is_empty(),
        "an icon change is not a broker op (ops: {:?})",
        h.ops()
    );
}

#[test]
fn app_icon_set_refuses_anything_but_a_known_id_before_touching_anything() {
    let h = harness();
    for bad in ["", "Keep", "../keep", "/etc/passwd", "keep.png", "default"] {
        let error = h
            .invoke("app_icon_set", json!({ "icon": bad }))
            .unwrap_err();
        assert_eq!(error["code"], json!("unknown_icon"), "{bad}");
    }
}

// ---------------------------------------------------------------------------
// capture_protection_set
// ---------------------------------------------------------------------------

#[test]
fn capture_protection_set_answers_the_choice_and_never_talks_to_the_broker() {
    let h = harness();
    // The harness holds the process-wide lock, so the developer override can be cleared and set safely here.
    std::env::remove_var(shell::ENV_CONTENT_PROTECTION);
    let off = h
        .invoke("capture_protection_set", json!({ "enabled": false }))
        .expect("off");
    assert_eq!(off, json!({ "enabled": false, "applied": true }));
    let on = h
        .invoke("capture_protection_set", json!({ "enabled": true }))
        .expect("on");
    assert_eq!(on, json!({ "enabled": true, "applied": true }));

    // The developer override wins: while it says off, switching protection on in Settings leaves the window unprotected.
    std::env::set_var(shell::ENV_CONTENT_PROTECTION, "off");
    let overridden = h
        .invoke("capture_protection_set", json!({ "enabled": true }))
        .expect("overridden");
    std::env::remove_var(shell::ENV_CONTENT_PROTECTION);
    assert_eq!(overridden, json!({ "enabled": false, "applied": true }));

    assert!(
        h.ops().is_empty(),
        "capture protection is not a broker op (ops: {:?})",
        h.ops()
    );
}

#[test]
fn capture_protection_set_needs_no_session_and_refuses_a_missing_argument() {
    let h = harness();
    std::env::remove_var(shell::ENV_CONTENT_PROTECTION);
    // Never unlocked: still answers.
    assert!(h
        .invoke("capture_protection_set", json!({ "enabled": false }))
        .is_ok());
    // A missing argument is refused, never read as a default.
    let error = h.invoke("capture_protection_set", json!({})).unwrap_err();
    assert!(error.to_string().contains("enabled"), "{error}");
}

// ---------------------------------------------------------------------------
// copy_text
// ---------------------------------------------------------------------------

#[test]
fn copy_text_writes_plain_text_with_no_markers_and_no_clock() {
    let h = harness();
    let receipt = h
        .invoke("copy_text", json!({ "text": "an address, not a secret" }))
        .expect("copy_text");
    assert_eq!(
        receipt,
        json!({ "copied": true, "clearAfterSeconds": null })
    );
    let c = h.board.snapshot();
    assert_eq!(c.text.as_deref(), Some("an address, not a secret"));
    assert!(!c.concealed);
    assert!(
        h.ops().is_empty(),
        "copy_text never talks to the broker (ops: {:?})",
        h.ops()
    );
}

#[test]
fn copy_text_after_a_secret_replaces_it_and_the_secrets_clock_is_forgotten() {
    let h = harness_with(Duration::from_millis(100), broker_handler);
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    h.invoke("copy_text", json!({ "text": "public" })).unwrap();
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(h.board.text().as_deref(), Some("public"));
}

#[test]
fn copy_text_is_bounded() {
    let h = harness();
    let at_limit = "x".repeat(desktop_lib::commands::COPY_TEXT_MAX_BYTES);
    assert!(h.invoke("copy_text", json!({ "text": at_limit })).is_ok());
    let over = "x".repeat(desktop_lib::commands::COPY_TEXT_MAX_BYTES + 1);
    let error = h.invoke("copy_text", json!({ "text": over })).unwrap_err();
    assert_eq!(error["code"], "text_too_large");
    assert_eq!(error["source"], "bridge");
}

// ---------------------------------------------------------------------------
// The lock event
// ---------------------------------------------------------------------------

#[test]
fn a_lock_trigger_locks_the_vault_clears_the_clipboard_and_tells_the_webview() {
    let h = harness();
    let locked = h.events(EVENT_LOCKED);
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    assert_eq!(h.board.text().as_deref(), Some(SECRET));

    let report = tauri::async_runtime::block_on(autolock::lock_and_notify_at(
        h.app.handle(),
        Some(h.socket.clone()),
        LockReason::ScreenLocked,
    ));

    assert!(report.clipboard_cleared);
    assert!(report.vault_lock_sent);
    assert_eq!(
        h.board.text(),
        None,
        "the secret is gone from the clipboard"
    );
    assert!(!h.session().is_authenticated(), "the token is dropped");
    // `vault.lock` went out carrying the token that was valid when it was sent.
    assert_eq!(h.ops().last().map(String::as_str), Some("vault.lock"));
    assert_eq!(
        h.broker.token_on(h.broker.received().len() - 1).as_deref(),
        Some(TOKEN)
    );
    // The webview is told why, in the frozen event name.
    let payload = locked.recv_timeout(Duration::from_secs(5)).expect("event");
    assert_eq!(payload, "\"screen_locked\"");
}

#[test]
fn every_lock_reason_reloads_the_main_webview_and_a_missing_window_is_not_an_error() {
    // ADR-091: a page that held typed secrets, reveals or an undo snapshot is dropped, not just told.
    let h = harness();
    for reason in LockReason::ALL {
        let report = tauri::async_runtime::block_on(autolock::lock_and_notify_at(
            h.app.handle(),
            Some(h.socket.clone()),
            reason,
        ));
        assert!(report.webview_reloaded, "{reason:?} must reload the window");
        assert!(report.vault_lock_sent);
    }
    // No vault directory (no socket): the lock cannot be sent, the window is still dropped.
    let report = tauri::async_runtime::block_on(autolock::lock_and_notify_at(
        h.app.handle(),
        None,
        LockReason::Tray,
    ));
    assert!(!report.vault_lock_sent && report.webview_reloaded);
    // No main window at all: nothing to reload, and nothing breaks.
    let windowless = desktop_lib::configure(
        mock_builder(),
        Clipboard::with(Arc::new(FakePasteboard::default()), Duration::from_secs(30)),
    )
    .build(mock_context(noop_assets()))
    .expect("an app with no window");
    assert!(!autolock::reload_main_webview(
        windowless.handle(),
        LockReason::Sleep
    ));
}

#[test]
fn the_pages_own_lock_reloads_the_main_webview_too() {
    // ADR-091 amendment (2026-10-27): the Lock button, ⌘L and the page's idle timer reach the shell as `vault_lock`, which used to leave
    // the page alive. The reload is scheduled after the command's answer, so the page receives it first.
    let h = harness();
    assert!(
        autolock::reload_after_page_lock(h.app.handle()),
        "a window is there: the reload is sent"
    );
    // The command itself answers first and schedules the reload; it must still answer `{locked:true}` through the real IPC.
    h.log_in();
    let answer = h.invoke("vault_lock", json!({})).expect("vault_lock");
    assert_eq!(answer["locked"], true);
    assert_eq!(answer["authenticated"], false);
    // No window at all: nothing to reload, nothing breaks.
    let windowless = desktop_lib::configure(
        mock_builder(),
        Clipboard::with(Arc::new(FakePasteboard::default()), Duration::from_secs(30)),
    )
    .build(mock_context(noop_assets()))
    .expect("an app with no window");
    assert!(!autolock::reload_after_page_lock(windowless.handle()));
    // The script is a constant with no reason word: nothing from the page can be injected into it.
    assert_eq!(autolock::PAGE_LOCK_RELOAD_SCRIPT, "location.reload();");
}

#[test]
fn the_vault_lock_command_schedules_the_page_reload() {
    // A source-level pin, like the drift guards: the command must call the scheduler, or the page's own lock stops dropping the page.
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/commands.rs"))
        .expect("commands.rs");
    let at = src.find("pub async fn vault_lock<").expect("vault_lock");
    let body = &src[at..at + 900.min(src.len() - at)];
    assert!(
        body.contains("schedule_page_lock_reload"),
        "vault_lock must schedule the reload: {body}"
    );
}

#[test]
fn every_lock_reason_reaches_the_webview_under_its_own_word() {
    let h = harness();
    let locked = h.events(EVENT_LOCKED);
    for reason in LockReason::ALL {
        tauri::async_runtime::block_on(autolock::lock_and_notify_at(
            h.app.handle(),
            Some(h.socket.clone()),
            reason,
        ));
        let payload = locked.recv_timeout(Duration::from_secs(5)).expect("event");
        assert_eq!(payload, format!("\"{}\"", reason.as_str()));
    }
}

#[test]
fn a_lock_trigger_leaves_a_later_user_copy_alone() {
    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    h.board.external_copy("copied after the secret");

    let report = tauri::async_runtime::block_on(autolock::lock_and_notify_at(
        h.app.handle(),
        Some(h.socket.clone()),
        LockReason::Sleep,
    ));
    assert!(!report.clipboard_cleared);
    assert_eq!(h.board.text().as_deref(), Some("copied after the secret"));
    assert!(!h.session().is_authenticated(), "the vault still locks");
}

#[test]
fn pressing_lock_in_the_ui_also_takes_a_copied_secret_off_the_clipboard() {
    // `vault_lock` is the command the Lock button invokes, not an OS trigger; C2
    // says the clipboard is cleared "on lock", and the 30 s clock alone would
    // leave a secret on it for up to 29 s after the user locked.
    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    assert_eq!(h.board.text().as_deref(), Some(SECRET));

    let state = h.invoke("vault_lock", json!({})).expect("vault_lock");
    assert_eq!(state["locked"], true);
    assert_eq!(h.board.text(), None, "the secret is gone once locked");
    assert!(!h.session().is_authenticated());
}

#[test]
fn pressing_lock_leaves_what_the_user_copied_after_the_secret_alone() {
    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    h.board.external_copy("typed after the secret");

    h.invoke("vault_lock", json!({})).expect("vault_lock");
    assert_eq!(
        h.board.text().as_deref(),
        Some("typed after the secret"),
        "lock clears only what this app put there"
    );
}

#[test]
fn pressing_lock_with_the_broker_down_still_clears_the_clipboard() {
    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    h.take_the_broker_away();

    let error = h
        .invoke("vault_lock", json!({}))
        .expect_err("the broker is gone, so the lock call itself fails");
    assert_eq!(error["code"], "broker_unreachable");
    assert_eq!(h.board.text(), None, "but the secret is off the clipboard");
    assert!(!h.session().is_authenticated(), "and the token is dropped");
}

#[test]
fn a_lock_trigger_with_no_login_still_locks_the_vault_with_no_token_and_notifies() {
    // The vault is the broker's, not this window's. With no login here it may
    // still have been unlocked by the CLI or by another client, and sleeping
    // with its keys in the broker's memory is exactly what this trigger exists
    // to end. The broker accepts a tokenless `vault.lock` (TOKENLESS_OK_OPS),
    // so the shell must send it. (An earlier version skipped the call here.)
    let h = harness();
    let locked = h.events(EVENT_LOCKED);
    let report = tauri::async_runtime::block_on(autolock::lock_and_notify_at(
        h.app.handle(),
        Some(h.socket.clone()),
        LockReason::SessionResign,
    ));
    assert!(report.vault_lock_sent);
    assert_eq!(h.ops(), vec!["vault.lock"]);
    assert_eq!(h.broker.token_on(0), None, "there was no token to send");
    assert_eq!(
        locked.recv_timeout(Duration::from_secs(5)).unwrap(),
        "\"session_resign\""
    );
}

#[test]
fn a_lock_trigger_after_this_apps_own_login_was_dropped_still_locks_the_vault() {
    // The app's login idled out (ADR-065) and the app noticed, so it holds no
    // token any more; other clients kept the vault open meanwhile.
    let h = harness();
    h.log_in();
    h.session().clear();
    assert!(!h.session().is_authenticated());

    let report = tauri::async_runtime::block_on(autolock::lock_and_notify_at(
        h.app.handle(),
        Some(h.socket.clone()),
        LockReason::Sleep,
    ));
    assert!(report.vault_lock_sent);
    assert_eq!(h.ops(), vec!["vault.unlock", "vault.lock"]);
    assert_eq!(h.broker.token_on(1), None);
}

#[test]
fn a_lock_trigger_while_a_second_factor_is_pending_still_locks_the_vault() {
    // Factor 1 passed, factor 2 not yet entered: the bridge holds no session,
    // but the broker holds a half-finished unlock that `vault.lock` ends.
    let h = harness_with(Duration::from_secs(30), |request| {
        match request["op"].as_str() {
            Some("vault.unlock") => err(
                "two_factor_required",
                json!({ "challenge": "totp", "scope": "vault", "expiresIn": 120 }),
            ),
            Some("vault.lock") => ok(json!({ "locked": true })),
            _ => err("malformed_request", json!({})),
        }
    });
    let error = h
        .invoke("vault_unlock", json!({ "passphrase": "pw" }))
        .expect_err("a gated vault asks for the second factor");
    assert_eq!(error["code"], "two_factor_required");
    assert!(!h.session().is_authenticated());

    tauri::async_runtime::block_on(autolock::lock_and_notify_at(
        h.app.handle(),
        Some(h.socket.clone()),
        LockReason::ScreenLocked,
    ));
    assert_eq!(h.ops(), vec!["vault.unlock", "vault.lock"]);
}

#[test]
fn the_os_trigger_empties_the_clipboard_on_the_calling_thread_before_it_returns() {
    // `NSWorkspaceWillSleepNotification` is posted on the main thread and the OS
    // goes on to sleep once the observer block returns. The clipboard half has
    // to be done by then, so it runs *in* the block; the broker half is spawned.
    let h = harness();
    let locked = h.events(EVENT_LOCKED);
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    assert_eq!(h.board.text().as_deref(), Some(SECRET));
    let me = std::thread::current().id();

    autolock::on_os_trigger(h.app.handle(), LockReason::Sleep);

    // No waiting, no polling: it is already gone.
    assert_eq!(h.board.text(), None, "the secret is off the pasteboard");
    assert_eq!(
        h.board.snapshot().clear_threads,
        vec![me],
        "and it was this thread, not the async runtime, that took it off"
    );

    // The rest still happens, asynchronously.
    assert_eq!(
        locked.recv_timeout(Duration::from_secs(5)).unwrap(),
        "\"sleep\""
    );
    assert_eq!(h.ops().last().map(String::as_str), Some("vault.lock"));
    assert!(!h.session().is_authenticated());
}

#[test]
fn the_os_trigger_leaves_a_later_user_copy_alone() {
    let h = harness();
    let locked = h.events(EVENT_LOCKED);
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    h.board.external_copy("copied after the secret");

    autolock::on_os_trigger(h.app.handle(), LockReason::ScreensSleep);
    locked.recv_timeout(Duration::from_secs(5)).unwrap();

    assert_eq!(h.board.text().as_deref(), Some("copied after the secret"));
    assert!(h.board.snapshot().clear_threads.is_empty());
}

#[test]
fn a_lock_that_lands_while_entry_copy_is_waiting_for_the_reveal_leaves_nothing_on_the_clipboard() {
    // The ordering the clear-then-write race needs: the reveal is in flight, the
    // lock (here: the no-broker lock path, because the stand-in broker serves one
    // connection at a time) clears and closes the door, and only then does the
    // broker answer with the value. Without the ticket the answer would be
    // written *after* the lock, with nothing left to remove it but the clock.
    let (reveal_started_tx, reveal_started) = channel::<()>();
    let (release_reveal, release_rx) = channel::<()>();
    let reveal_started_tx = Mutex::new(reveal_started_tx);
    let release_rx = Mutex::new(release_rx);
    let h = harness_with(Duration::from_secs(30), move |request| {
        match request["op"].as_str() {
            Some("vault.unlock") => ok(json!({ "locked": false, "token": TOKEN })),
            Some("entry.reveal") => {
                reveal_started_tx.lock().unwrap().send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
                ok(json!({ "value": SECRET }))
            }
            _ => err("malformed_request", json!({})),
        }
    });
    h.log_in();

    let handle = h.app.handle().clone();
    let locker = std::thread::spawn(move || {
        reveal_started
            .recv_timeout(Duration::from_secs(10))
            .expect("entry_copy reached the broker");
        tauri::async_runtime::block_on(autolock::lock_and_notify_at(
            &handle,
            None,
            LockReason::Sleep,
        ));
        release_reveal.send(()).unwrap();
    });

    let error = h
        .invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .expect_err("the copy is refused: the vault locked underneath it");
    locker.join().expect("locker thread");

    assert_eq!(error["code"], "clipboard_failed");
    assert_eq!(h.board.text(), None, "no secret after the lock");
    assert_eq!(
        h.board.snapshot().writes,
        0,
        "the pasteboard was never written"
    );
}

#[test]
fn entry_copy_after_a_lock_works_again() {
    // The door a lock closes is on copies already in flight, not on the next one.
    let h = harness();
    let locked = h.events(EVENT_LOCKED);
    h.log_in();
    autolock::on_os_trigger(h.app.handle(), LockReason::Sleep);
    // The event is emitted after the lock call has returned and the token has
    // been dropped, so a login made after this cannot be undone by it.
    locked.recv_timeout(Duration::from_secs(5)).expect("event");
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .expect("a copy that begins after the lock is allowed");
    assert_eq!(h.board.text().as_deref(), Some(SECRET));
}

#[test]
fn a_lock_trigger_with_the_broker_down_still_drops_the_token_and_the_clipboard() {
    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    let nowhere = h.take_the_broker_away();

    let locked = h.events(EVENT_LOCKED);
    tauri::async_runtime::block_on(autolock::lock_and_notify_at(
        h.app.handle(),
        Some(nowhere),
        LockReason::Sleep,
    ));
    assert!(!h.session().is_authenticated());
    assert_eq!(h.board.text(), None);
    assert!(locked.recv_timeout(Duration::from_secs(5)).is_ok());
}

#[test]
fn a_lock_trigger_with_no_vault_directory_still_drops_the_token_and_the_clipboard() {
    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    let ops_before = h.ops().len();

    tauri::async_runtime::block_on(autolock::lock_and_notify_at(
        h.app.handle(),
        None,
        LockReason::Sleep,
    ));
    assert!(!h.session().is_authenticated());
    assert_eq!(h.board.text(), None);
    assert_eq!(h.ops().len(), ops_before, "no socket, no call");
}

// ---------------------------------------------------------------------------
// Window and quit
// ---------------------------------------------------------------------------

#[test]
fn losing_focus_tells_the_webview_to_wipe_what_it_revealed() {
    let h = harness();
    let inactive = h.events(EVENT_WINDOW_INACTIVE);
    let window = h.webview.as_ref().window();

    // Gaining focus says nothing; losing it does.
    shell::on_window_event(&window, &WindowEvent::Focused(true));
    assert!(inactive.try_recv().is_err());
    shell::on_window_event(&window, &WindowEvent::Focused(false));
    let payload = inactive
        .recv_timeout(Duration::from_secs(5))
        .expect("event");
    assert!(
        ["\"minimized\"", "\"hidden\"", "\"blurred\""].contains(&payload.as_str()),
        "unexpected payload {payload}"
    );
}

#[test]
fn losing_focus_does_not_clear_the_clipboard() {
    // D5: clearing on an app switch would make pasting into the app you copied
    // for impossible.
    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    shell::on_window_event(&h.webview.as_ref().window(), &WindowEvent::Focused(false));
    assert_eq!(h.board.text().as_deref(), Some(SECRET));
}

#[test]
fn quitting_clears_a_secret_it_still_owns_and_only_that() {
    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    shell::on_run_event(h.app.handle(), RunEvent::Exit);
    assert_eq!(h.board.text(), None);
    // One harness at a time: each holds the environment lock.
    drop(h);

    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    h.board.external_copy("the user's");
    shell::on_run_event(h.app.handle(), RunEvent::Exit);
    assert_eq!(h.board.text().as_deref(), Some("the user's"));
}

#[test]
fn other_run_events_do_not_touch_the_clipboard() {
    let h = harness();
    h.log_in();
    h.invoke("entry_copy", json!({ "node": "acme", "entry": "e_1" }))
        .unwrap();
    shell::on_run_event(h.app.handle(), RunEvent::Ready);
    assert_eq!(h.board.text().as_deref(), Some(SECRET));
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[test]
fn the_removed_scaffold_commands_are_not_reachable() {
    let h = harness();
    // `greet` was the create-tauri-app hello-world; nothing may answer to it.
    let error = h
        .invoke("greet", json!({ "name": "x" }))
        .expect_err("greet is gone");
    assert!(
        error.to_string().contains("greet"),
        "expected a 'command greet not found' style error, got {error}"
    );
    // …and the opener plugin's commands were never granted.
    assert!(h
        .invoke(
            "plugin:opener|open_url",
            json!({ "url": "https://example.com" })
        )
        .is_err());
}
