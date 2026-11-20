//! ADR-173: the shell notices an agent request that waits, against a stand-in `credmgrd` on a real socket.
//!
//! What is proved: the look sends **no token** (a token-less `vault.status` is not activity for the idle
//! lock); the notice names the project and nothing else (no entry name, no request id, no value); a
//! `privateNames` project is "a private project"; one request is one notice across looks; several are one
//! notice; the count follows the queue and clears at zero; a broker that is not there, or that refuses to
//! list, is handled quietly.

mod common;

use std::sync::Mutex;

use serde_json::{json, Value};

use common::{err, ok, FakeBroker};
use desktop_lib::approval_notify::{poll_once, Notice, Sink, Tracker};

#[derive(Default)]
struct Recorder {
    counts: Mutex<Vec<u32>>,
    notices: Mutex<Vec<Notice>>,
}

impl Sink for Recorder {
    fn show_count(&self, count: u32) {
        self.counts.lock().unwrap().push(count);
    }
    fn notify(&self, notice: &Notice) {
        self.notices.lock().unwrap().push(notice.clone());
    }
}

/// A distinctive value and entry name that must never reach a notice.
const SECRET_NAME: &str = "STRIPE_LIVE_KEY_NEEDLE";
const REQUEST_ID: &str = "rq_NEEDLE0001";

fn waiting(request: &str, label: Value, hidden: bool) -> Value {
    let mut item = json!({
        "request": request, "node": "alpha", "entry": "e_1",
        "nodeLabel": label, "entryName": SECRET_NAME, "command": "entry.reveal",
        "state": "pending", "expiresIn": 90, "requestedAt": 1800000000,
    });
    if hidden {
        item["nameHidden"] = json!(true);
    }
    item
}

fn broker_with(pending: Vec<Value>) -> FakeBroker {
    FakeBroker::spawn(move |request| match request["op"].as_str() {
        Some("vault.status") => ok(json!({
            "locked": true, "initialized": true, "pendingApprovals": pending.len(),
        })),
        Some("vault.approval_get") => ok(json!({ "pending": pending })),
        _ => err("malformed_request", json!({})),
    })
}

#[test]
fn a_waiting_request_is_one_notice_that_names_the_project_and_nothing_else() {
    let broker = broker_with(vec![waiting(REQUEST_ID, json!("Alpha"), false)]);
    let sink = Recorder::default();
    let mut tracker = Tracker::new();

    poll_once(&broker.socket, &mut tracker, &sink);
    poll_once(&broker.socket, &mut tracker, &sink);

    let notices = sink.notices.lock().unwrap();
    assert_eq!(notices.len(), 1, "one request, one notice: {notices:?}");
    let text = format!("{} {}", notices[0].title, notices[0].body);
    assert!(text.contains("Alpha"), "{text}");
    for needle in [SECRET_NAME, REQUEST_ID, "alpha", "e_1"] {
        assert!(!text.contains(needle), "{needle} leaked into {text}");
    }
    assert_eq!(
        *sink.counts.lock().unwrap(),
        vec![1, 1],
        "the count stays while it waits"
    );

    // The looks carried no token, so they are not activity for the idle lock.
    let sent = broker.received();
    assert_eq!(sent.len(), 4, "status + list, twice");
    for i in 0..sent.len() {
        assert_eq!(broker.token_on(i), None, "request {i} carried a token");
    }
}

#[test]
fn a_private_project_is_not_named() {
    let broker = broker_with(vec![waiting(REQUEST_ID, Value::Null, true)]);
    let sink = Recorder::default();
    poll_once(&broker.socket, &mut Tracker::new(), &sink);
    let notices = sink.notices.lock().unwrap();
    assert_eq!(notices.len(), 1);
    assert!(notices[0].body.contains("a private project"), "{notices:?}");
    assert!(!format!("{notices:?}").contains(SECRET_NAME));
}

#[test]
fn several_waiting_at_once_are_one_notice_and_the_count_says_how_many() {
    let broker = broker_with(vec![
        waiting("rq_a", json!("Alpha"), false),
        waiting("rq_b", json!("Beta"), false),
    ]);
    let sink = Recorder::default();
    poll_once(&broker.socket, &mut Tracker::new(), &sink);
    let notices = sink.notices.lock().unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].title, "2 agent requests are waiting");
    assert!(!notices[0].body.contains("Alpha"), "{notices:?}");
    assert_eq!(*sink.counts.lock().unwrap(), vec![2]);
}

#[test]
fn nothing_waiting_clears_the_count_and_says_nothing() {
    let broker = broker_with(vec![]);
    let sink = Recorder::default();
    poll_once(&broker.socket, &mut Tracker::new(), &sink);
    assert_eq!(*sink.counts.lock().unwrap(), vec![0]);
    assert!(sink.notices.lock().unwrap().is_empty());
    // Only the status was asked: the list is not read when nothing waits.
    assert_eq!(broker.received().len(), 1);
}

#[test]
fn a_broker_that_refuses_to_list_still_counts_and_announces_once_without_a_name() {
    // An unlocked vault: the status count is public, the list is the owner's.
    let broker = FakeBroker::spawn(|request| match request["op"].as_str() {
        Some("vault.status") => ok(json!({ "locked": false, "pendingApprovals": 1 })),
        Some("vault.approval_get") => err("capability_not_held", json!({})),
        _ => err("malformed_request", json!({})),
    });
    let sink = Recorder::default();
    let mut tracker = Tracker::new();
    poll_once(&broker.socket, &mut tracker, &sink);
    poll_once(&broker.socket, &mut tracker, &sink);
    let notices = sink.notices.lock().unwrap();
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0].body, "Open CredMgr to decide.");
    assert_eq!(*sink.counts.lock().unwrap(), vec![1, 1]);
}

#[test]
fn no_broker_is_nothing_waiting() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Recorder::default();
    poll_once(&tmp.path().join("b.sock"), &mut Tracker::new(), &sink);
    assert_eq!(*sink.counts.lock().unwrap(), vec![0]);
    assert!(sink.notices.lock().unwrap().is_empty());
}
