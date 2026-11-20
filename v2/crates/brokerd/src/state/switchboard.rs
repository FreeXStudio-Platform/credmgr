//! ADR-155: the switchboard's waiting requests — a weakening setting change an agent asked for, held until the owner
//! decides it on their own device. In memory only: a request does not outlive the broker, the unlock it was made under
//! (every `lock()` clears them), or its ten minutes. It holds no secret: a setting value is a policy or a preference.

use std::collections::HashMap;

use rand_core::{OsRng, RngCore};
use serde_json::Value;

use super::BrokerState;

/// How long a request waits for the owner.
pub const REQUEST_TTL_SECONDS: i64 = 600;
/// At most this many requests wait at once; more is refused, so an agent cannot flood the owner.
pub const MAX_WAITING: usize = 20;

/// One waiting (or decided) request.
#[derive(Debug, Clone)]
pub struct SettingRequest {
    pub id: String,
    pub setting: String,
    pub node: Option<String>,
    pub from: Value,
    pub to: Value,
    pub reason: String,
    /// The requester's public session id or cwd-scope key (never shown): only the requester reads its own request.
    pub requester: String,
    /// The requester's working directory, for the owner to see who asked.
    pub cwd: Option<String>,
    /// ADR-164 review P1-2: the agent token that asked, if one did, for the owner to see.
    pub agent_token: Option<crate::state::AgentRequester>,
    pub created: i64,
    pub expires_at: i64,
    /// `None` while waiting; `Some(true)` approved and applied; `Some(false)` denied.
    pub decision: Option<bool>,
    /// The applied change's id, once approved.
    pub change: Option<String>,
}

impl SettingRequest {
    pub fn state(&self, now: i64) -> &'static str {
        match self.decision {
            Some(true) => "approved",
            Some(false) => "denied",
            None if now >= self.expires_at => "expired",
            None => "pending",
        }
    }
}

pub(crate) type SettingRequests = std::sync::Mutex<HashMap<String, SettingRequest>>;

pub(crate) fn new_requests() -> SettingRequests {
    std::sync::Mutex::new(HashMap::new())
}

pub(crate) fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::from(prefix);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl BrokerState {
    /// Store a new request. `Err` when too many already wait.
    #[allow(clippy::too_many_arguments, clippy::result_unit_err)]
    pub fn add_setting_request(
        &self,
        setting: &str,
        node: Option<&str>,
        from: Value,
        to: Value,
        reason: &str,
        requester: &str,
        cwd: Option<String>,
        agent_token: Option<crate::state::AgentRequester>,
        now: i64,
    ) -> Result<SettingRequest, ()> {
        let mut all = self
            .setting_requests
            .lock()
            .expect("setting requests poisoned");
        all.retain(|_, r| r.decision.is_some() || now < r.expires_at + REQUEST_TTL_SECONDS);
        if all.values().filter(|r| r.state(now) == "pending").count() >= MAX_WAITING {
            return Err(());
        }
        let req = SettingRequest {
            id: random_id("sr-"),
            setting: setting.to_string(),
            node: node.map(str::to_string),
            from,
            to,
            reason: reason.to_string(),
            requester: requester.to_string(),
            cwd,
            agent_token,
            created: now,
            expires_at: now + REQUEST_TTL_SECONDS,
            decision: None,
            change: None,
        };
        all.insert(req.id.clone(), req.clone());
        Ok(req)
    }

    pub fn setting_request(&self, id: &str) -> Option<SettingRequest> {
        self.setting_requests
            .lock()
            .expect("setting requests poisoned")
            .get(id)
            .cloned()
    }

    pub fn setting_requests_all(&self) -> Vec<SettingRequest> {
        let mut v: Vec<SettingRequest> = self
            .setting_requests
            .lock()
            .expect("setting requests poisoned")
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|r| r.created);
        v
    }

    /// Record a decision. `false` when the request is gone, decided or expired.
    pub fn decide_setting_request(
        &self,
        id: &str,
        approve: bool,
        change: Option<String>,
        now: i64,
    ) -> bool {
        let mut all = self
            .setting_requests
            .lock()
            .expect("setting requests poisoned");
        match all.get_mut(id) {
            Some(r) if r.state(now) == "pending" => {
                r.decision = Some(approve);
                r.change = change;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn clear_setting_requests(&self) {
        self.setting_requests
            .lock()
            .expect("setting requests poisoned")
            .clear();
    }
}
