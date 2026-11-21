//! ADR-155 — the switchboard (`settings.*`), end to end against a durable vault and a real login.
//!
//! * every setting is listed with its value, default, risk and the caller's rule; an agent sees project settings only
//!   for projects it reaches;
//! * the owner changes any setting; widening a project's reach needs Touch ID; loosening the reveal policy needs a fresh
//!   confirmation; the change survives a restart;
//! * an agent changes only its own node's settings (a vault setting only when its scope is Global), holding `update`
//!   there (ADR-155 amendment, Q-1; the refusals are proven in `isolation.rs` I-32); there, a cosmetic or strengthening
//!   change applies at once and a weakening one becomes a request that only the owner decides, after a fresh
//!   confirmation; an agent cannot decide or list requests;
//! * every change is recorded with the value it replaced and can be reverted under the same rules;
//! * a lock drops waiting requests; values outside the table are refused.

mod f1_support;

use serde_json::{json, Value};

use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::Capability;

use f1_support::*;

/// An agent scoped to `node` with read-write access there (`agentAccess: read-write`'s capabilities). The switchboard
/// lets it change `node`'s own settings, and the vault's only when `node` is Global (ADR-155 amendment, Q-1).
fn agent(state: &BrokerState, node: &str) -> BrokerScope {
    let token = state
        .tokens
        .issue(
            node,
            vec![
                Capability::List,
                Capability::Read,
                Capability::Reveal,
                Capability::Create,
                Capability::Update,
            ],
            Origin::Agent,
            None,
        )
        .id;
    scope_of(state, &token)
}

fn set(
    state: &BrokerState,
    scope: &BrokerScope,
    id: &str,
    node: Option<&str>,
    value: Value,
) -> Result<Value, OpError> {
    let mut p = json!({ "id": id, "value": value, "reason": "test: switchboard" });
    if let Some(n) = node {
        p["node"] = json!(n);
    }
    call(state, scope, NOW, "settings.set", p)
}

fn value_of(state: &BrokerState, scope: &BrokerScope, id: &str, node: Option<&str>) -> Value {
    let mut p = json!({ "id": id });
    if let Some(n) = node {
        p["node"] = json!(n);
    }
    call(state, scope, NOW, "settings.get", p).expect("settings.get")["value"].clone()
}

fn setup() -> (Vault, std::sync::Arc<BrokerState>, BrokerScope) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    create_node(&state, &owner, "beta");
    (v, state, owner)
}

#[test]
fn list_describes_every_setting_with_the_callers_rule() {
    let (_v, state, owner) = setup();
    let all = call(&state, &owner, NOW, "settings.list", json!({})).unwrap();
    assert_eq!(all["caller"], "owner");
    let vault_count = credmgr_core::settings::SETTINGS
        .iter()
        .filter(|d| d.scope == credmgr_core::settings::Scope::Vault)
        .count();
    assert_eq!(all["settings"].as_array().unwrap().len(), vault_count);
    let with_node = call(
        &state,
        &owner,
        NOW,
        "settings.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(
        with_node["settings"].as_array().unwrap().len(),
        credmgr_core::settings::SETTINGS.len()
    );
    let lock = all["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "app.autoLockMins")
        .unwrap();
    assert_eq!(lock["value"], 15);
    assert_eq!(lock["risk"], "security");
    assert_eq!(lock["you"], "direct");

    let a = agent(&state, "acme");
    let mine = call(&state, &a, NOW, "settings.list", json!({ "node": "acme" })).unwrap();
    assert_eq!(mine["caller"], "agent");
    let level = mine["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "node.securityLevel")
        .unwrap();
    assert_eq!(level["you"], "direct when stricter; approval when weaker");
    let rule = |id: &str| {
        mine["settings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == id)
            .unwrap()["you"]
            .clone()
    };
    // Q-1: its own access is never its request, and a vault setting is Global's, not a project agent's.
    assert_eq!(
        rule("node.agentAccess"),
        "direct when stricter; never weaker (the owner's)"
    );
    assert_eq!(rule("app.autoLockMins"), "read only");
    // Another project is indistinguishable from one that does not exist.
    let other = call(&state, &a, NOW, "settings.list", json!({ "node": "beta" }));
    assert!(matches!(other, Err(OpError::NotFound(_))), "{other:?}");
    let kb = call(&state, &a, NOW, "settings.kb", json!({})).unwrap();
    assert!(kb["markdown"]
        .as_str()
        .unwrap()
        .contains("credmgr_settings_set"));
}

#[test]
fn the_owner_changes_settings_and_they_survive_a_restart() {
    let (v, state, owner) = setup();
    let r = set(&state, &owner, "app.theme", None, json!("dark")).unwrap();
    assert_eq!(r["applied"], true);
    assert_eq!(r["change"], "cosmetic");
    set(&state, &owner, "app.autoLockMins", None, json!(60)).unwrap();
    set(
        &state,
        &owner,
        "node.requireTwoFactor",
        Some("acme"),
        json!("always"),
    )
    .unwrap();
    let (state, owner) = restart(&v, state, None);
    assert_eq!(value_of(&state, &owner, "app.theme", None), "dark");
    assert_eq!(value_of(&state, &owner, "app.autoLockMins", None), 60);
    assert_eq!(
        value_of(&state, &owner, "node.requireTwoFactor", Some("acme")),
        "always"
    );
    // Same value: nothing recorded.
    let same = set(&state, &owner, "app.theme", None, json!("dark")).unwrap();
    assert_eq!(same["change"], "same");
    assert_eq!(same["applied"], false);
}

#[test]
fn values_outside_the_table_and_wrong_scopes_are_refused() {
    let (_v, state, owner) = setup();
    for (id, node, value) in [
        ("app.autoLockMins", None, json!(7)),
        ("app.theme", None, json!("purple")),
        ("node.securityLevel", Some("acme"), json!("bogus")),
        ("node.securityLevel", None, json!("open")),
        ("app.theme", Some("acme"), json!("dark")),
        ("vault.confirmBeforeReveal.windowSeconds", None, json!(42)),
    ] {
        let r = set(&state, &owner, id, node, value.clone());
        assert!(
            matches!(r, Err(OpError::Malformed(_))),
            "{id} {node:?} {value}: {r:?}"
        );
    }
    assert!(matches!(
        set(&state, &owner, "no.such", None, json!(1)),
        Err(OpError::NotFound(_))
    ));
    let no_reason = call(
        &state,
        &owner,
        NOW,
        "settings.set",
        json!({ "id": "app.theme", "value": "dark" }),
    );
    assert!(matches!(no_reason, Err(OpError::Malformed(_))));
}

#[test]
fn owner_weakening_follows_the_existing_step_ups() {
    let (_v, state, owner) = setup();
    // Widening a project's reach needs Touch ID (ADR-098).
    let r = set(
        &state,
        &owner,
        "node.securityLevel",
        Some("acme"),
        json!("open"),
    );
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");
    // Loosening "confirm before showing secrets" needs a fresh confirmation (ADR-150).
    set(
        &state,
        &owner,
        "vault.confirmBeforeReveal.mode",
        None,
        json!("everyTime"),
    )
    .unwrap();
    let r = set(
        &state,
        &owner,
        "vault.confirmBeforeReveal.mode",
        None,
        json!("off"),
    );
    assert!(
        matches!(r, Err(OpError::ConfirmationRequired { .. })),
        "{r:?}"
    );
    call(
        &state,
        &owner,
        NOW,
        "session.confirm",
        json!({ "passphrase": PASSPHRASE }),
    )
    .unwrap();
    set(
        &state,
        &owner,
        "vault.confirmBeforeReveal.mode",
        None,
        json!("off"),
    )
    .unwrap();
    // With a presence proof the owner lowers the level.
    let key = enrol_first_key(&state, &owner);
    let params = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "settings.set",
        json!({ "id": "node.securityLevel", "node": "acme", "value": "open", "reason": "test: switchboard" }),
    );
    call(&state, &owner, NOW, "settings.set", params).expect("with presence");
    assert_eq!(
        value_of(&state, &owner, "node.securityLevel", Some("acme")),
        "open"
    );
}

#[test]
fn an_agent_applies_cosmetic_and_stricter_changes_directly() {
    let (_v, state, owner) = setup();
    let a = agent(&state, "acme");
    let g = agent(&state, "global");
    let r = set(&state, &g, "app.theme", None, json!("light")).unwrap();
    assert_eq!(r["applied"], true);
    // Q-1: a vault setting is Global's; a project agent may not change it, not even to something cosmetic.
    let r = set(&state, &a, "app.theme", None, json!("dark"));
    assert!(
        matches!(
            r,
            Err(OpError::CapabilityNotHeld {
                capability: Capability::Update
            })
        ),
        "{r:?}"
    );
    let r = set(
        &state,
        &a,
        "node.securityLevel",
        Some("acme"),
        json!("sealed"),
    )
    .unwrap();
    assert_eq!(r["change"], "strengthens");
    assert_eq!(r["applied"], true);
    let r = set(&state, &g, "app.autoLockMins", None, json!(5)).unwrap();
    assert_eq!(r["applied"], true);
    assert_eq!(
        value_of(&state, &owner, "node.securityLevel", Some("acme")),
        "sealed"
    );
    // An agent cannot reach another project's settings.
    let r = set(
        &state,
        &a,
        "node.securityLevel",
        Some("beta"),
        json!("sealed"),
    );
    assert!(matches!(r, Err(OpError::NotFound(_))), "{r:?}");
}

/// Q-1 backstop: even a scope that somehow holds `update` above its node's agent access (here a fixture token, which
/// skips the ceiling a real cwd agent or agent token gets) cannot file a request that raises its own access: it is
/// refused, not queued, and nothing changes. The owner raises it themselves.
#[test]
fn an_agent_never_asks_for_more_of_its_own_access() {
    let (_v, state, owner) = setup();
    set(
        &state,
        &owner,
        "node.agentAccess",
        Some("acme"),
        json!("read-only"),
    )
    .unwrap();
    let a = agent(&state, "acme");
    let r = set(
        &state,
        &a,
        "node.agentAccess",
        Some("acme"),
        json!("read-write"),
    );
    assert!(
        matches!(
            r,
            Err(OpError::CapabilityNotHeld {
                capability: Capability::Admin
            })
        ),
        "{r:?}"
    );
    assert!(state.setting_requests_all().is_empty(), "nothing queued");
    assert_eq!(
        value_of(&state, &owner, "node.agentAccess", Some("acme")),
        "read-only"
    );
    // Narrowing itself further is still its to do.
    let r = set(&state, &a, "node.agentAccess", Some("acme"), json!("none")).unwrap();
    assert_eq!(r["applied"], true);
}

#[test]
fn an_agents_weakening_change_waits_for_the_owner_who_confirms_first() {
    let (_v, state, owner) = setup();
    // A vault setting: the agent whose scope is Global may ask.
    let a = agent(&state, "global");
    let r = set(&state, &a, "app.autoLockMins", None, json!(0)).unwrap();
    assert_eq!(r["applied"], false);
    assert_eq!(r["state"], "pending");
    let id = r["request"].as_str().unwrap().to_string();
    assert_eq!(
        value_of(&state, &owner, "app.autoLockMins", None),
        15,
        "nothing changed yet"
    );

    // The agent polls its own request; it can neither list nor decide.
    let mine = call(
        &state,
        &a,
        NOW,
        "settings.request_get",
        json!({ "request": id }),
    )
    .unwrap();
    assert_eq!(mine["state"], "pending");
    assert!(mine.get("cwd").is_none());
    for (op, p) in [
        ("settings.request_list", json!({})),
        (
            "settings.request_decide",
            json!({ "request": id, "approve": true }),
        ),
    ] {
        let r = call(&state, &a, NOW, op, p);
        assert!(
            matches!(r, Err(OpError::CapabilityNotHeld { .. })),
            "{op}: {r:?}"
        );
    }
    // Another agent cannot see it.
    let b = agent(&state, "beta");
    assert!(matches!(
        call(
            &state,
            &b,
            NOW,
            "settings.request_get",
            json!({ "request": id })
        ),
        Err(OpError::NotFound(_))
    ));

    // The owner sees it; approving needs a fresh confirmation (the step-up).
    let list = call(&state, &owner, NOW, "settings.request_list", json!({})).unwrap();
    assert_eq!(list["requests"][0]["request"], id.as_str());
    let r = call(
        &state,
        &owner,
        NOW,
        "settings.request_decide",
        json!({ "request": id, "approve": true }),
    );
    assert!(
        matches!(r, Err(OpError::ConfirmationRequired { .. })),
        "{r:?}"
    );
    call(
        &state,
        &owner,
        NOW,
        "session.confirm",
        json!({ "passphrase": PASSPHRASE }),
    )
    .unwrap();
    let r = call(
        &state,
        &owner,
        NOW,
        "settings.request_decide",
        json!({ "request": id, "approve": true }),
    )
    .unwrap();
    assert_eq!(r["state"], "approved");
    assert_eq!(value_of(&state, &owner, "app.autoLockMins", None), 0);
    let mine = call(
        &state,
        &a,
        NOW,
        "settings.request_get",
        json!({ "request": id }),
    )
    .unwrap();
    assert_eq!(mine["state"], "approved");
    assert!(mine["changeId"].as_str().unwrap().starts_with("sc-"));
    // Decided once only.
    assert!(call(
        &state,
        &owner,
        NOW,
        "settings.request_decide",
        json!({ "request": id, "approve": true })
    )
    .is_err());
}

#[test]
fn a_denied_request_changes_nothing_and_a_lock_drops_waiting_ones() {
    let (_v, state, owner) = setup();
    let a = agent(&state, "acme");
    let g = agent(&state, "global");
    let id = set(&state, &g, "app.captureProtection", None, json!(false)).unwrap()["request"]
        .as_str()
        .unwrap()
        .to_string();
    let r = call(
        &state,
        &owner,
        NOW,
        "settings.request_decide",
        json!({ "request": id, "approve": false }),
    )
    .unwrap();
    assert_eq!(r["state"], "denied");
    assert_eq!(
        value_of(&state, &owner, "app.captureProtection", None),
        true
    );
    let id2 = set(
        &state,
        &a,
        "node.agentAccess",
        Some("acme"),
        json!("read-write"),
    );
    // read-write is the default: the same value, nothing to ask.
    assert_eq!(id2.unwrap()["change"], "same");
    let id3 = set(&state, &g, "app.revealWindowSecs", None, json!(60)).unwrap()["request"]
        .as_str()
        .unwrap()
        .to_string();
    state.lock();
    let owner = login(&state);
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "settings.request_get",
            json!({ "request": id3 })
        ),
        Err(OpError::NotFound(_))
    ));
}

#[test]
fn every_change_is_recorded_and_can_be_reverted_under_the_same_rules() {
    let (_v, state, owner) = setup();
    let a = agent(&state, "global");
    // The agent makes things stricter; its revert would weaken, so it becomes a request.
    let c = set(&state, &a, "app.autoLockMins", None, json!(5)).unwrap()["changeId"]
        .as_str()
        .unwrap()
        .to_string();
    let got = call(
        &state,
        &owner,
        NOW,
        "settings.get",
        json!({ "id": "app.autoLockMins" }),
    )
    .unwrap();
    assert_eq!(got["recentChanges"][0]["id"], c.as_str());
    assert_eq!(got["recentChanges"][0]["from"], 15);
    assert!(got["recentChanges"][0]["by"]
        .as_str()
        .unwrap()
        .starts_with("agent:"));
    let r = call(&state, &a, NOW, "settings.revert", json!({ "change": c })).unwrap();
    assert_eq!(r["state"], "pending");
    // The owner reverts it directly.
    let r = call(
        &state,
        &owner,
        NOW,
        "settings.revert",
        json!({ "change": c }),
    )
    .unwrap();
    assert_eq!(r["applied"], true);
    assert_eq!(value_of(&state, &owner, "app.autoLockMins", None), 15);
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "settings.revert",
            json!({ "change": "sc-nope" })
        ),
        Err(OpError::NotFound(_))
    ));
}

#[test]
fn nothing_is_changed_while_the_vault_is_locked() {
    let (_v, state, owner) = setup();
    let a = agent(&state, "global");
    state.lock();
    for scope in [&owner, &a] {
        let r = set(&state, scope, "app.theme", None, json!("dark"));
        assert!(r.is_err(), "{r:?}");
    }
}

#[test]
fn the_ui_and_the_switchboard_read_the_same_value() {
    // node.policy (the app's own path) and the switchboard store the same field.
    let (_v, state, owner) = setup();
    call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "acme", "reason": "test", "policy": { "requireTwoFactor": "always" } }),
    )
    .unwrap();
    assert_eq!(
        value_of(&state, &owner, "node.requireTwoFactor", Some("acme")),
        "always"
    );
    set(
        &state,
        &owner,
        "node.privateNames",
        Some("acme"),
        json!(true),
    )
    .unwrap();
    let reg = state.registry.read().unwrap();
    assert!(
        reg.nodes["acme"].policy.private_names,
        "the switchboard wrote the field node.policy reads"
    );
}
