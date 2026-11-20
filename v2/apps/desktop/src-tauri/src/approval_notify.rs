//! A waiting agent request is shown to the person even when the window is hidden (ADR-173).
//!
//! An agent that asks for a secret while the vault is locked leaves an approval request behind
//! (ADR-042, ADR-088). Until now the person only learned of it by opening the window: the Lock
//! screen lists the requests (ADR-090). This module watches for one and makes three things appear,
//! best effort, none of which carries a value:
//!
//! * a **count beside the menu-bar icon** and in its tooltip, for as long as a request waits;
//! * **one macOS notification per request**, coalesced when several arrive between two looks
//!   ([`macos`], the UserNotifications framework; nothing is sent anywhere, ADR-001);
//! * a **Dock bounce** when the app is not the active one.
//!
//! Clicking the notification (or the menu-bar icon) brings the window back ([`crate::tray::show_main`]);
//! a locked vault then shows the Lock screen with the request listed. The decision itself is never
//! made here: it needs the unlock factors (locked, ADR-088) or the owner's login and a presence
//! proof (unlocked, ADR-173).
//!
//! ## What the text may say
//!
//! The broker does not name the requester (`vault.approval_get` carries no agent label, and the
//! working directory only goes to an owner session), so the text says "an agent". It names the
//! **project** the request is for, and nothing else: never a value, never an entry name, never a
//! request id. A project that hides its names (`privateNames`, ADR-083) comes back from the broker
//! with a `null` label and is shown as "a private project". Text that came from the broker is
//! stripped of control characters and cut short ([`clean_label`]).
//!
//! ## How it looks
//!
//! A thread asks the broker, without a token, for `vault.status` every [`POLL_EVERY`]; a token-less
//! status is not activity, so the look cannot keep another client's session from idle-locking
//! (ADR-090). Only when `pendingApprovals` is above zero does it ask `vault.approval_get`, which
//! also answers any caller while the vault is locked. On an unlocked vault only the owner's login
//! may list the requests; there the thread has no login and falls back to the count.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

use crate::transport;

/// How often the broker is asked while the app runs.
pub const POLL_EVERY: Duration = Duration::from_secs(4);

/// The longest a project label is shown for, in characters.
const LABEL_MAX: usize = 48;

/// One waiting request, as much of it as a notification may say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    /// The broker's request id. Used to tell a request already announced from a new one; never shown.
    pub request: String,
    /// The project's label, or `None` when the project hides its names (or the label is unknown).
    pub project: Option<String>,
}

/// What a notification says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub title: String,
    pub body: String,
}

/// What one look at the broker asks the shell to show.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Step {
    /// Requests waiting now, for the menu-bar count. Zero removes it.
    pub count: u32,
    /// A notification, when there is a request that has not been announced yet.
    pub notice: Option<Notice>,
}

/// Where a step goes: the shell implements it with the tray and the OS notification, a test with a recorder.
pub trait Sink {
    fn show_count(&self, count: u32);
    fn notify(&self, notice: &Notice);
}

/// Remembers what was already announced, so one request is one notification.
#[derive(Debug, Default)]
pub struct Tracker {
    announced: HashSet<String>,
    /// The count at the last look, for the case where the broker would not list the requests.
    last_count: u32,
}

/// Strip control characters and cut a broker-supplied label short. An empty result is `None`.
pub fn clean_label(raw: &str) -> Option<String> {
    let kept: String = raw.chars().filter(|c| !c.is_control()).collect();
    let kept = kept.trim();
    if kept.is_empty() {
        return None;
    }
    let mut out: String = kept.chars().take(LABEL_MAX).collect();
    if kept.chars().count() > LABEL_MAX {
        out.push('…');
    }
    Some(out)
}

/// Read the requests out of a `vault.approval_get {}` answer (`{pending: [...]}`). Anything without a
/// string `request` is skipped; a `nameHidden` project, or one with no label, has `project: None`.
pub fn parse_pending(answer: &Value) -> Vec<Waiting> {
    let Some(list) = answer.get("pending").and_then(Value::as_array) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|item| {
            let request = item.get("request")?.as_str()?.to_string();
            let hidden = item
                .get("nameHidden")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let project = if hidden {
                None
            } else {
                item.get("nodeLabel")
                    .and_then(Value::as_str)
                    .and_then(clean_label)
            };
            Some(Waiting { request, project })
        })
        .collect()
}

/// The words for `fresh` requests that were not announced before, `total` waiting in all.
pub fn compose(fresh: &[Waiting], total: u32) -> Notice {
    let place = |w: &Waiting| match &w.project {
        Some(label) => format!("\u{201c}{label}\u{201d}"),
        None => "a private project".to_string(),
    };
    match fresh {
        [one] if total <= 1 => Notice {
            title: "An agent is waiting for your approval".into(),
            body: format!(
                "It asks to read a secret in {}. Open CredMgr to decide.",
                place(one)
            ),
        },
        _ => Notice {
            title: format!("{total} agent requests are waiting"),
            body: "Open CredMgr to review them.".into(),
        },
    }
}

/// The words when the broker would not list the requests: no project, only that one or more wait.
pub fn compose_unlisted(total: u32) -> Notice {
    if total <= 1 {
        Notice {
            title: "An agent is waiting for your approval".into(),
            body: "Open CredMgr to decide.".into(),
        }
    } else {
        Notice {
            title: format!("{total} agent requests are waiting"),
            body: "Open CredMgr to review them.".into(),
        }
    }
}

/// The text for the menu-bar item: empty removes it.
pub fn badge_text(count: u32) -> Option<String> {
    (count > 0).then(|| count.min(99).to_string())
}

/// The tooltip for the menu-bar icon.
pub fn tooltip(count: u32) -> String {
    match count {
        0 => "CredMgr".to_string(),
        1 => "CredMgr: 1 agent request waiting".to_string(),
        n => format!("CredMgr: {n} agent requests waiting"),
    }
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one look at the broker into what to show. `count` is `pendingApprovals`; `listed` is the
    /// requests `vault.approval_get` named, or `None` when the broker would not say (an unlocked vault
    /// and no login here), in which case a rise in the count is announced once, without a project.
    pub fn observe(&mut self, count: u32, listed: Option<Vec<Waiting>>) -> Step {
        if count == 0 {
            self.announced.clear();
            self.last_count = 0;
            return Step::default();
        }
        let notice = match listed {
            Some(list) if !list.is_empty() => {
                let live: HashSet<&str> = list.iter().map(|w| w.request.as_str()).collect();
                // A request that expired or was decided is forgotten, so the set stays as small as the queue.
                self.announced.retain(|id| live.contains(id.as_str()));
                let fresh: Vec<Waiting> = list
                    .iter()
                    .filter(|w| !self.announced.contains(&w.request))
                    .cloned()
                    .collect();
                for w in &fresh {
                    self.announced.insert(w.request.clone());
                }
                (!fresh.is_empty()).then(|| compose(&fresh, count))
            }
            _ => (count > self.last_count).then(|| compose_unlisted(count)),
        };
        self.last_count = count;
        Step { count, notice }
    }
}

/// `pendingApprovals` out of a `vault.status` answer; anything else is zero (nothing to show).
pub fn pending_count(status: &Value) -> u32 {
    status
        .get("pendingApprovals")
        .and_then(Value::as_u64)
        .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX))
}

/// One look: ask the broker, fold the answer in, hand the result to `sink`. A broker that is not
/// running, or that refuses, is "nothing waiting": the person is not told about a problem here.
/// No token is sent, so the look is not activity for the idle lock.
pub fn poll_once(socket: &Path, tracker: &mut Tracker, sink: &dyn Sink) {
    let count = match transport::call(socket, "vault.status", None, json!({})) {
        Ok(status) => pending_count(&status),
        Err(_) => 0,
    };
    let listed = (count > 0)
        .then(|| transport::call(socket, "vault.approval_get", None, json!({})).ok())
        .flatten()
        .map(|answer| parse_pending(&answer));
    let step = tracker.observe(count, listed);
    sink.show_count(step.count);
    if let Some(notice) = &step.notice {
        sink.notify(notice);
    }
}

#[cfg(target_os = "macos")]
pub mod macos {
    //! The macOS user notification (UserNotifications framework). It needs a bundled app (`NSBundle`
    //! with an identifier): a bare `cargo run` binary has none, and is skipped rather than crashed.
    //! Every call is best effort; a refused permission is the person's choice and is not asked twice.

    use std::sync::{Once, OnceLock};

    use block2::{DynBlock, RcBlock};
    use objc2::rc::Retained;
    use objc2::runtime::{Bool, ProtocolObject};
    use objc2::{define_class, msg_send, AllocAnyThread};
    use objc2_foundation::{NSBundle, NSError, NSObject, NSObjectProtocol, NSString};
    use objc2_user_notifications::{
        UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
        UNNotificationResponse, UNUserNotificationCenter, UNUserNotificationCenterDelegate,
    };

    use super::Notice;

    /// What a click does, set once by [`on_click`].
    static ON_CLICK: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
    static DELEGATE: Once = Once::new();

    /// Register what a click on a notification does (bring the window back).
    pub fn on_click(f: impl Fn() + Send + Sync + 'static) {
        let _ = ON_CLICK.set(Box::new(f));
    }

    define_class!(
        #[unsafe(super(NSObject))]
        #[name = "CredmgrNotificationDelegate"]
        struct Delegate;

        unsafe impl NSObjectProtocol for Delegate {}

        unsafe impl UNUserNotificationCenterDelegate for Delegate {
            #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
            fn did_receive(
                &self,
                _center: &UNUserNotificationCenter,
                _response: &UNNotificationResponse,
                handler: &DynBlock<dyn Fn()>,
            ) {
                if let Some(f) = ON_CLICK.get() {
                    f();
                }
                handler.call(());
            }
        }
    );

    /// True when this process is a bundled app, the only kind UserNotifications accepts.
    fn bundled() -> bool {
        NSBundle::mainBundle().bundleIdentifier().is_some()
    }

    /// Show `notice`. Returns false when it could not even be tried (not a bundled app).
    pub fn deliver(notice: &Notice) -> bool {
        if !bundled() {
            return false;
        }
        let center = UNUserNotificationCenter::currentNotificationCenter();
        DELEGATE.call_once(|| {
            let this = Delegate::alloc().set_ivars(());
            let delegate: Retained<Delegate> = unsafe { msg_send![super(this), init] };
            center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
            // The centre holds its delegate weakly; this one lives as long as the process.
            std::mem::forget(delegate);
        });
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(&notice.title));
        content.setBody(&NSString::from_str(&notice.body));
        // One identifier per look would stack; a fixed one makes a later notice replace an earlier one.
        let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &NSString::from_str("credmgr.agent-request"),
            &content,
            None,
        );
        let center_for_add = center.clone();
        let granted = RcBlock::new(move |granted: Bool, _error: *mut NSError| {
            if granted.as_bool() {
                center_for_add.addNotificationRequest_withCompletionHandler(&request, None);
            }
        });
        center.requestAuthorizationWithOptions_completionHandler(
            UNAuthorizationOptions::Alert,
            &granted,
        );
        true
    }
}

/// The shell's [`Sink`]: the menu-bar icon, the Dock, and the OS notification.
pub struct ShellSink<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: tauri::Runtime> ShellSink<R> {
    pub fn new(app: tauri::AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: tauri::Runtime> Sink for ShellSink<R> {
    fn show_count(&self, count: u32) {
        if let Some(tray) = self.app.tray_by_id(crate::tray::TRAY_ID) {
            let _ = tray.set_tooltip(Some(tooltip(count)));
            let _ = tray.set_title(badge_text(count));
        }
    }

    fn notify(&self, notice: &Notice) {
        use tauri::Manager;
        // A window the person is looking at already shows the request (the Lock screen lists it).
        let focused = self
            .app
            .get_webview_window(crate::tray::MAIN_WINDOW)
            .map(|w| w.is_focused().unwrap_or(false) && w.is_visible().unwrap_or(false))
            .unwrap_or(false);
        if focused {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            macos::deliver(notice);
        }
        #[cfg(not(target_os = "macos"))]
        let _ = notice;
        if let Some(window) = self.app.get_webview_window(crate::tray::MAIN_WINDOW) {
            let _ = window.request_user_attention(Some(tauri::UserAttentionType::Informational));
        }
    }
}

/// Start watching. Called once, from the run loop's `Ready` event ([`crate::shell::on_run_event`]),
/// so the mock runtime the integration tests build never spawns it.
pub fn start<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let Some(socket) = crate::vault_paths::resolve_socket_path() else {
        return;
    };
    #[cfg(target_os = "macos")]
    {
        let handle = app.clone();
        macos::on_click(move || crate::tray::show_main(&handle));
    }
    let sink = ShellSink::new(app.clone());
    std::thread::Builder::new()
        .name("credmgr-approval-watch".into())
        .spawn(move || {
            let mut tracker = Tracker::new();
            loop {
                poll_once(&socket, &mut tracker, &sink);
                std::thread::sleep(POLL_EVERY);
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiting(id: &str, project: Option<&str>) -> Waiting {
        Waiting {
            request: id.into(),
            project: project.map(str::to_string),
        }
    }

    #[test]
    fn a_label_is_stripped_of_control_characters_and_cut_short() {
        assert_eq!(clean_label("  Acme\n\u{7}  ").as_deref(), Some("Acme"));
        assert_eq!(clean_label("\u{0}\u{1b}[31m").as_deref(), Some("[31m"));
        assert_eq!(clean_label("   "), None);
        let long = "x".repeat(200);
        let cut = clean_label(&long).unwrap();
        assert_eq!(cut.chars().count(), LABEL_MAX + 1);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn the_list_is_read_and_a_hidden_project_has_no_label() {
        let answer = json!({ "pending": [
            { "request": "rq_1", "node": "alpha", "entry": "e_1", "nodeLabel": "Alpha", "entryName": "OPEN_KEY" },
            { "request": "rq_2", "node": "n_9", "entry": "e_2", "nodeLabel": null, "entryName": null, "nameHidden": true },
            { "request": "rq_3", "node": "n_8", "entry": "e_3", "nodeLabel": "Leaky", "nameHidden": true },
            { "node": "no-request-id" },
        ] });
        let got = parse_pending(&answer);
        assert_eq!(
            got,
            [
                waiting("rq_1", Some("Alpha")),
                waiting("rq_2", None),
                waiting("rq_3", None)
            ]
        );
        assert!(parse_pending(&json!({})).is_empty());
        assert!(parse_pending(&json!({ "pending": "x" })).is_empty());
    }

    #[test]
    fn one_request_is_one_notification_and_it_names_the_project_only() {
        let mut t = Tracker::new();
        let step = t.observe(1, Some(vec![waiting("rq_1", Some("Alpha"))]));
        let notice = step.notice.expect("a new request is announced");
        assert_eq!(step.count, 1);
        assert_eq!(notice.title, "An agent is waiting for your approval");
        assert!(notice.body.contains("\u{201c}Alpha\u{201d}"), "{notice:?}");
        // The same request on the next look: counted, not announced again.
        let again = t.observe(1, Some(vec![waiting("rq_1", Some("Alpha"))]));
        assert_eq!(again.count, 1);
        assert_eq!(again.notice, None);
    }

    #[test]
    fn a_private_project_is_not_named() {
        let mut t = Tracker::new();
        let notice = t
            .observe(1, Some(vec![waiting("rq_1", None)]))
            .notice
            .unwrap();
        assert!(notice.body.contains("a private project"), "{notice:?}");
    }

    #[test]
    fn several_new_requests_between_two_looks_are_one_notification() {
        let mut t = Tracker::new();
        let step = t.observe(
            3,
            Some(vec![
                waiting("rq_1", Some("Alpha")),
                waiting("rq_2", Some("Beta")),
                waiting("rq_3", None),
            ]),
        );
        let notice = step.notice.unwrap();
        assert_eq!(notice.title, "3 agent requests are waiting");
        assert!(
            !notice.body.contains("Alpha") && !notice.body.contains("Beta"),
            "{notice:?}"
        );
        // One more arrives: only it is new, and the message counts all four.
        let step = t.observe(
            4,
            Some(vec![
                waiting("rq_1", Some("Alpha")),
                waiting("rq_2", Some("Beta")),
                waiting("rq_3", None),
                waiting("rq_4", Some("Gamma")),
            ]),
        );
        assert_eq!(
            step.notice.unwrap().title,
            "4 agent requests are waiting",
            "the count in the title is what waits, not what is new"
        );
    }

    #[test]
    fn a_decided_request_is_forgotten_and_nothing_waiting_clears_the_count() {
        let mut t = Tracker::new();
        t.observe(1, Some(vec![waiting("rq_1", Some("Alpha"))]));
        let none = t.observe(0, None);
        assert_eq!(none, Step::default());
        // The same id coming back after it left (a new request cannot reuse one, but the tracker must not hold it forever).
        let back = t.observe(1, Some(vec![waiting("rq_1", Some("Alpha"))]));
        assert!(back.notice.is_some());
    }

    #[test]
    fn without_a_list_only_a_rise_in_the_count_is_announced_and_nothing_is_named() {
        let mut t = Tracker::new();
        let first = t.observe(1, None).notice.expect("a first request");
        assert_eq!(first.body, "Open CredMgr to decide.");
        assert_eq!(t.observe(1, None).notice, None);
        assert!(t.observe(2, None).notice.is_some());
        assert_eq!(t.observe(1, None).notice, None, "a fall is not news");
    }

    #[test]
    fn the_badge_and_tooltip_follow_the_count() {
        assert_eq!(badge_text(0), None);
        assert_eq!(badge_text(2).as_deref(), Some("2"));
        assert_eq!(badge_text(500).as_deref(), Some("99"));
        assert_eq!(tooltip(0), "CredMgr");
        assert_eq!(tooltip(1), "CredMgr: 1 agent request waiting");
        assert_eq!(tooltip(3), "CredMgr: 3 agent requests waiting");
    }

    #[test]
    fn the_status_count_is_read_defensively() {
        assert_eq!(pending_count(&json!({ "pendingApprovals": 4 })), 4);
        assert_eq!(pending_count(&json!({ "pendingApprovals": "4" })), 0);
        assert_eq!(pending_count(&json!({})), 0);
    }
}
