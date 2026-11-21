//! ADR-155: the switchboard — `settings.*`. Every setting in `credmgr_core::settings::SETTINGS`, read and changed through
//! the broker by the app, the CLI and the MCP server alike, so no client can drift from another.
//!
//! Who may do what:
//! * **Read** (`settings.list`, `settings.get`): any caller but an agent holding no capability (`agentAccess: none`).
//!   A project's settings only for a project the caller reaches. `settings.kb` is the static knowledge base, the same
//!   text for every caller, and holds no vault state.
//! * **Owner** (a live login session): changes a setting as the app always let them — a node setting needs `admin` on the
//!   node and Touch ID when it widens reach (ADR-098); loosening "confirm before showing secrets" needs a fresh
//!   confirmation (ADR-150).
//! * **Agent**: reads while it holds `list` (an agent in a project set to `agentAccess: none` holds nothing and gets
//!   `capability_not_held`). It changes only the settings of **its own node** — a project setting of the node its scope
//!   sits on, a vault setting only when that node is Global — and only while it holds `update` there (ADR-155
//!   amendment, wiring audit Q-1). There, a cosmetic or strengthening change applies at once; a weakening one becomes a
//!   request (`state/switchboard.rs`) that only the owner decides (`settings.request_decide`, never an MCP tool), after a
//!   fresh confirmation (Touch ID or passphrase through `session.confirm`). Raising its own node's `agentAccess` is never
//!   an agent's request: it is refused, not queued.
//! * Every applied change is recorded in `global.policy.settingsHistory` with the value it replaced; `settings.revert`
//!   puts it back under the same rules.

use serde_json::{json, Value};

use credmgr_core::registry::Capability;
use credmgr_core::settings::{self, Change, SettingChange, SettingDef, Store, HISTORY_LIMIT};

use super::{
    confirmation_required, human_admin_on, is_agent_caller, owner_session, refuse_agent,
    require_presence, resolve_capability, session_public_id, validate_registry, OpError, GLOBAL_ID,
    ORPHAN_ID,
};
use crate::scope::BrokerScope;
use crate::state::switchboard::{random_id, SettingRequest};
use crate::state::BrokerState;

fn def_of(id: &str) -> Result<&'static SettingDef, OpError> {
    settings::find(id).ok_or_else(|| OpError::NotFound(format!("no setting {id}")))
}

/// The node a request names, required for a node setting and refused for a vault one.
fn node_of<'a>(def: &SettingDef, node: Option<&'a str>) -> Result<Option<&'a str>, OpError> {
    match (def.scope, node) {
        (settings::Scope::Node, None) => Err(OpError::Malformed(format!(
            "{} is a project setting: params.node is required",
            def.id
        ))),
        (settings::Scope::Node, Some(n)) if n == ORPHAN_ID => Err(OpError::Malformed(
            "orphan's policy is fixed by design".into(),
        )),
        (settings::Scope::Node, Some(n)) => Ok(Some(n)),
        (settings::Scope::Vault, Some(_)) => Err(OpError::Malformed(format!(
            "{} is a vault setting: leave params.node out",
            def.id
        ))),
        (settings::Scope::Vault, None) => Ok(None),
    }
}

/// An agent reads or changes a project's settings only inside its own reach.
fn check_reach(
    state: &BrokerState,
    scope: &BrokerScope,
    node: Option<&str>,
    now: i64,
) -> Result<(), OpError> {
    let Some(node) = node else { return Ok(()) };
    if !state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .contains_key(node)
    {
        return Err(OpError::NotFound(format!("no node {node}")));
    }
    if is_agent_caller(scope)
        && !resolve_capability(state, scope, node, Capability::List, now).is_allow()
    {
        // Indistinguishable from a node that does not exist (an agent learns nothing about other projects).
        return Err(OpError::NotFound(format!("no node {node}")));
    }
    Ok(())
}

/// ADR-155 amendment (wiring audit Q-1): an agent reads the switchboard only while it holds `list`. An agent in a
/// project set to `agentAccess: none` holds nothing (`scope.rs`: "`none` gets nothing, full stop"), so it is refused
/// before any node is looked at — the same answer for its own project, another one and one that does not exist.
fn agent_reads(scope: &BrokerScope) -> Result<(), OpError> {
    if is_agent_caller(scope) && !scope.holds(Capability::List) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::List,
        });
    }
    Ok(())
}

/// ADR-155 amendment (wiring audit Q-1): what an agent needs before it may change a setting at all, even make it
/// stricter. A setting is stored on one node: a project setting on `node`, a vault setting on Global. The agent must
/// hold `update` (its capability ceiling: `agentAccess: read-write`, or an agent token that carries it), the node must
/// be **its own** — the node its scope sits on, so Global only for an agent whose scope is Global — and `update` must
/// resolve there. Reaching another node through the access graph (Global for everyone, an ancestor, a shared sibling, a
/// grant) gives entry access, never a say over that node's policy. The ceiling is checked first, so an agent holding
/// nothing learns nothing about which nodes exist; an unreachable node still answers as one that does not exist.
fn agent_write_gate(
    state: &BrokerState,
    scope: &BrokerScope,
    node: Option<&str>,
    now: i64,
) -> Result<(), OpError> {
    let refused = || OpError::CapabilityNotHeld {
        capability: Capability::Update,
    };
    if !scope.holds(Capability::Update) {
        return Err(refused());
    }
    if node.is_some() {
        check_reach(state, scope, node, now)?;
    }
    let target = node.unwrap_or(GLOBAL_ID);
    if target != scope.node_id
        || !resolve_capability(state, scope, target, Capability::Update, now).is_allow()
    {
        return Err(refused());
    }
    Ok(())
}

/// ADR-155 amendment (wiring audit Q-1): the setting an agent may never ask to weaken, because the weaker value widens
/// what the asking agent itself may do. `node.agentAccess` on the agent's own node is its capability ceiling
/// (`scope.rs`); an agent asking for more of it is asking to widen its own scope (`10_API_AND_MCP.md` §3.2: "An agent
/// may not widen its own scope. This is the definition of the boundary."). The owner changes it with their own login.
fn is_own_access(def: &SettingDef, scope: &BrokerScope, node: Option<&str>) -> bool {
    def.id == "node.agentAccess" && node == Some(scope.node_id.as_str())
}

/// The setting's current value.
pub(super) fn current(
    state: &BrokerState,
    def: &SettingDef,
    node: Option<&str>,
) -> Result<Value, OpError> {
    let registry = state.registry.read().expect("registry poisoned");
    let global = registry
        .nodes
        .get(GLOBAL_ID)
        .ok_or_else(|| OpError::Internal("no global node".into()))?;
    Ok(match def.store {
        Store::AppPref(k) => global
            .policy
            .app_prefs
            .get(k)
            .cloned()
            .unwrap_or_else(|| def.default_value()),
        Store::RevealConfirm(f) => serde_json::to_value(global.policy.reveal_confirm)
            .map_err(|e| OpError::Internal(e.to_string()))?[f]
            .clone(),
        Store::NodePolicy(f) => {
            let node = node.ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let n = registry
                .nodes
                .get(node)
                .ok_or_else(|| OpError::NotFound(format!("no node {node}")))?;
            let v =
                serde_json::to_value(&n.policy).map_err(|e| OpError::Internal(e.to_string()))?;
            v.get(f).cloned().unwrap_or(Value::Null)
        }
    })
}

/// Write `value`, append the change to the history, and keep the registry valid. Authorisation is the caller's job.
#[allow(clippy::too_many_arguments)]
fn write(
    state: &BrokerState,
    def: &SettingDef,
    node: Option<&str>,
    from: &Value,
    to: &Value,
    by: &str,
    reason: &str,
    request: Option<&str>,
    reverts: Option<&str>,
    now: i64,
) -> Result<SettingChange, OpError> {
    let mut registry = state.registry.write().expect("registry poisoned");
    let mut candidate = (*registry).clone();
    {
        let target = match def.store {
            Store::NodePolicy(_) => node.expect("node settings carry a node"),
            _ => GLOBAL_ID,
        };
        let n = candidate
            .nodes
            .get_mut(target)
            .ok_or_else(|| OpError::NotFound(format!("no node {target}")))?;
        match def.store {
            Store::AppPref(k) => {
                if *to == def.default_value() {
                    n.policy.app_prefs.remove(k);
                } else {
                    n.policy.app_prefs.insert(k.to_string(), to.clone());
                }
            }
            Store::RevealConfirm(f) => {
                let mut v = serde_json::to_value(n.policy.reveal_confirm)
                    .map_err(|e| OpError::Internal(e.to_string()))?;
                v[f] = to.clone();
                let next: credmgr_core::reveal_confirm::RevealConfirm =
                    serde_json::from_value(v)
                        .map_err(|e| OpError::Malformed(format!("{}: {e}", def.id)))?;
                next.validate().map_err(OpError::Malformed)?;
                n.policy.reveal_confirm = next;
            }
            Store::NodePolicy(f) => {
                let mut v = serde_json::to_value(&n.policy)
                    .map_err(|e| OpError::Internal(e.to_string()))?;
                v[f] = to.clone();
                n.policy = serde_json::from_value(v)
                    .map_err(|e| OpError::Malformed(format!("{}: {e}", def.id)))?;
            }
        }
    }
    let violations = validate_registry(&candidate);
    if !violations.is_empty() {
        return Err(OpError::Malformed(format!(
            "would violate a registry invariant: {violations:?}"
        )));
    }
    let change = SettingChange {
        id: random_id("sc-"),
        setting: def.id.to_string(),
        node: node.map(str::to_string),
        from: from.clone(),
        to: to.clone(),
        by: by.to_string(),
        at: now,
        request: request.map(str::to_string),
        reason: reason.to_string(),
        reverts: reverts.map(str::to_string),
    };
    let global = candidate.nodes.get_mut(GLOBAL_ID).expect("global exists");
    global.policy.settings_history.push(change.clone());
    let excess = global
        .policy
        .settings_history
        .len()
        .saturating_sub(HISTORY_LIMIT);
    global.policy.settings_history.drain(..excess);
    *registry = candidate;
    drop(registry);
    if matches!(def.store, Store::NodePolicy(_) | Store::RevealConfirm(_)) {
        // `07_TWO_FACTOR.md §5`: elevations are dropped on a policy change, as they are on lock.
        state.drop_elevations();
    }
    Ok(change)
}

fn reason_of(reason: &str) -> Result<String, OpError> {
    let reason = Some(reason.trim())
        .filter(|r| !r.is_empty())
        .ok_or_else(|| {
            OpError::Malformed(
                "params.reason must not be empty — a setting change records why".into(),
            )
        })?;
    if reason.chars().count() > 500 {
        return Err(OpError::Malformed(
            "params.reason is limited to 500 characters".into(),
        ));
    }
    Ok(reason.to_string())
}

/// What the owner's own change needs before it applies — the same rules `node.policy` and the app had.
#[allow(clippy::too_many_arguments)]
fn owner_checks(
    state: &BrokerState,
    scope: &BrokerScope,
    def: &SettingDef,
    node: Option<&str>,
    from: &Value,
    to: &Value,
    op: &str,
    params: &Value,
    step_up: bool,
    now: i64,
) -> Result<(), OpError> {
    refuse_agent(scope)?;
    owner_session(state, scope)?;
    if let Some(n) = node {
        human_admin_on(state, scope, n, now)?;
    }
    let weakens = settings::classify(def, from, to) == Change::Weakens;
    // ADR-098: widening a project's reach needs the user's finger, whichever surface asks.
    let widens_reach = matches!(
        def.id,
        "node.descendantRead" | "node.siblingVisibility" | "node.securityLevel"
    ) && weakens;
    if widens_reach {
        require_presence(state, scope, op, params, now)?;
    }
    // ADR-150 (loosening "confirm before showing secrets"), and ADR-155 (approving an agent's weakening request):
    // a confirmation made in the last minute, spent by this change.
    let needs_fresh = (matches!(def.store, Store::RevealConfirm(_)) && weakens)
        || (step_up && weakens && !widens_reach);
    if needs_fresh {
        let session = session_public_id(state, scope);
        let need = credmgr_core::reveal_confirm::Need::Fresh;
        if !state.take_confirmation(session.as_deref(), need, now) {
            let policy = state
                .registry
                .read()
                .expect("registry poisoned")
                .nodes
                .get(GLOBAL_ID)
                .map(|g| g.policy.reveal_confirm)
                .unwrap_or_default();
            return Err(confirmation_required(op, &policy, need));
        }
    }
    Ok(())
}

/// ADR-164 review P1-2: an agent token is keyed by its public id, so a rotation keeps its requests its own.
fn agent_key(state: &BrokerState, scope: &BrokerScope, now: i64) -> String {
    if let Some(agent) = super::agent_requester(state, scope, now) {
        return format!("agent:{}:{}", scope.node_id, agent.id);
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    scope.token_id.hash(&mut h);
    scope.bound_workdir.hash(&mut h);
    format!("agent:{}:{:016x}", scope.node_id, h.finish())
}

fn who(state: &BrokerState, scope: &BrokerScope) -> &'static str {
    if is_agent_caller(scope) {
        "agent"
    } else if state.is_owner_session(scope) {
        "owner"
    } else {
        "session"
    }
}

/// The rule for this caller and this setting (on `node`, for a project setting), as `settings.list` says it.
fn rule_for(
    state: &BrokerState,
    scope: &BrokerScope,
    def: &SettingDef,
    node: Option<&str>,
    now: i64,
) -> &'static str {
    match who(state, scope) {
        "owner" => "direct",
        "agent" if agent_write_gate(state, scope, node, now).is_err() => "read only",
        "agent" if is_own_access(def, scope, node) => {
            "direct when stricter; never weaker (the owner's)"
        }
        "agent" if def.security_relevant() => "direct when stricter; approval when weaker",
        "agent" => "direct",
        _ => "read only",
    }
}

fn describe(
    state: &BrokerState,
    scope: &BrokerScope,
    def: &SettingDef,
    node: Option<&str>,
    value: Value,
    now: i64,
) -> Value {
    json!({
        "id": def.id,
        "scope": def.scope.as_str(),
        "group": def.group,
        "title": def.title,
        "purpose": def.purpose,
        "ui": def.ui,
        "stored": def.store.path(),
        "values": def.values_text(),
        "default": def.default_value(),
        "value": value,
        "risk": if def.security_relevant() { "security" } else { "cosmetic" },
        "you": rule_for(state, scope, def, node, now),
    })
}

pub(super) fn list(
    state: &BrokerState,
    scope: &BrokerScope,
    node: Option<&str>,
    now: i64,
) -> Result<Value, OpError> {
    agent_reads(scope)?;
    check_reach(state, scope, node, now)?;
    let mut out = Vec::new();
    for def in settings::SETTINGS {
        match (def.scope, node) {
            (settings::Scope::Node, None) => continue,
            (settings::Scope::Node, Some(n)) => out.push(describe(
                state,
                scope,
                def,
                Some(n),
                current(state, def, Some(n))?,
                now,
            )),
            (settings::Scope::Vault, _) => out.push(describe(
                state,
                scope,
                def,
                None,
                current(state, def, None)?,
                now,
            )),
        }
    }
    Ok(json!({
        "caller": who(state, scope),
        "node": node,
        "settings": out,
        "note": if node.is_none() { "Project settings are listed with params.node." } else { "" },
        "kb": "settings.kb (MCP credmgr_kb, CLI credmgr kb) explains every setting and the rules.",
    }))
}

pub(super) fn get(
    state: &BrokerState,
    scope: &BrokerScope,
    id: &str,
    node: Option<&str>,
    now: i64,
) -> Result<Value, OpError> {
    let def = def_of(id)?;
    let node = node_of(def, node)?;
    agent_reads(scope)?;
    check_reach(state, scope, node, now)?;
    let mut v = describe(state, scope, def, node, current(state, def, node)?, now);
    let history: Vec<Value> = {
        let registry = state.registry.read().expect("registry poisoned");
        registry
            .nodes
            .get(GLOBAL_ID)
            .map(|g| {
                g.policy
                    .settings_history
                    .iter()
                    .rev()
                    .filter(|c| c.setting == def.id && c.node.as_deref() == node)
                    .take(10)
                    .map(|c| json!(c))
                    .collect()
            })
            .unwrap_or_default()
    };
    v["recentChanges"] = json!(history);
    Ok(v)
}

/// The shared body of `settings.set` and `settings.revert`.
#[allow(clippy::too_many_arguments)]
fn set_value(
    state: &BrokerState,
    scope: &BrokerScope,
    def: &'static SettingDef,
    node: Option<&str>,
    to: Value,
    reason: &str,
    reverts: Option<&str>,
    op: &str,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    settings::validate(def, &to).map_err(OpError::Malformed)?;
    // A locked vault has no root key to sign the registry with: a change could not be saved, so none is taken.
    if state.is_locked() {
        return Err(OpError::VaultLocked);
    }
    if is_agent_caller(scope) {
        // Before anything is read: an agent changes only its own node's settings, holding `update` there (Q-1).
        agent_write_gate(state, scope, node, now)?;
    } else {
        check_reach(state, scope, node, now)?;
    }
    let from = current(state, def, node)?;
    let change = settings::classify(def, &from, &to);
    if change == Change::Same {
        return Ok(json!({ "applied": false, "change": "same", "id": def.id, "value": from }));
    }
    if is_agent_caller(scope) {
        if change == Change::Weakens && is_own_access(def, scope, node) {
            // Q-1: more access for the asking agent is never an agent's request; the owner changes it themselves.
            return Err(OpError::CapabilityNotHeld {
                capability: Capability::Admin,
            });
        }
        if change == Change::Weakens {
            let cwd = scope.bound_workdir.clone();
            let req = state
                .add_setting_request(
                    def.id,
                    node,
                    from.clone(),
                    to.clone(),
                    reason,
                    &agent_key(state, scope, now),
                    cwd,
                    super::agent_requester(state, scope, now),
                    now,
                )
                .map_err(|()| {
                    OpError::Malformed(
                        "too many setting requests are waiting for the owner; wait for a decision"
                            .into(),
                    )
                })?;
            return Ok(json!({
                "applied": false,
                "state": "pending",
                "request": req.id,
                "change": "weakens",
                "id": def.id,
                "from": from,
                "to": to,
                "expiresIn": req.expires_at - now,
                "next": "The owner approves or denies it in CredMgr on their device; poll it with credmgr_settings_request and do not retry the change.",
            }));
        }
        let rec = write(
            state,
            def,
            node,
            &from,
            &to,
            &agent_key(state, scope, now),
            reason,
            None,
            reverts,
            now,
        )?;
        return Ok(
            json!({ "applied": true, "change": change.as_str(), "changeId": rec.id, "id": def.id, "from": from, "to": to }),
        );
    }
    owner_checks(state, scope, def, node, &from, &to, op, params, false, now)?;
    let rec = write(
        state, def, node, &from, &to, "owner", reason, None, reverts, now,
    )?;
    Ok(
        json!({ "applied": true, "change": change.as_str(), "changeId": rec.id, "id": def.id, "from": from, "to": to }),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn set(
    state: &BrokerState,
    scope: &BrokerScope,
    id: &str,
    node: Option<&str>,
    to: Value,
    reason: &str,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    let def = def_of(id)?;
    let node = node_of(def, node)?;
    let reason = reason_of(reason)?;
    set_value(
        state,
        scope,
        def,
        node,
        to,
        &reason,
        None,
        "settings.set",
        params,
        now,
    )
}

pub(super) fn revert(
    state: &BrokerState,
    scope: &BrokerScope,
    id: &str,
    reason: Option<&str>,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    // Q-1: an agent that may change no setting learns nothing about the recorded changes either; the full gate (its own
    // node, `update` there) runs in `set_value` once the change says which node it touched.
    if is_agent_caller(scope) && !scope.holds(Capability::Update) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Update,
        });
    }
    let rec = {
        let registry = state.registry.read().expect("registry poisoned");
        registry.nodes.get(GLOBAL_ID).and_then(|g| {
            g.policy
                .settings_history
                .iter()
                .find(|c| c.id == id)
                .cloned()
        })
    }
    .ok_or_else(|| OpError::NotFound(format!("no recorded change {id}")))?;
    let def = settings::find(&rec.setting)
        .ok_or_else(|| OpError::NotFound(format!("no setting {}", rec.setting)))?;
    let reason = reason
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("revert {id}"));
    set_value(
        state,
        scope,
        def,
        rec.node.as_deref(),
        rec.from.clone(),
        &reason,
        Some(id),
        "settings.revert",
        params,
        now,
    )
}

fn request_view(r: &SettingRequest, now: i64, owner: bool) -> Value {
    let mut v = json!({
        "request": r.id,
        "id": r.setting,
        "node": r.node,
        "from": r.from,
        "to": r.to,
        "reason": r.reason,
        "state": r.state(now),
        "expiresIn": (r.expires_at - now).max(0),
        "requestedAt": r.created,
        "changeId": r.change,
    });
    if owner {
        v["cwd"] = json!(r.cwd);
        if let Some(t) = &r.agent_token {
            v["agentToken"] = json!({ "id": t.id, "label": t.label });
        }
    }
    v
}

pub(super) fn request_get(
    state: &BrokerState,
    scope: &BrokerScope,
    id: &str,
    now: i64,
) -> Result<Value, OpError> {
    agent_reads(scope)?;
    let r = state
        .setting_request(id)
        .ok_or_else(|| OpError::NotFound(format!("no request {id}")))?;
    let owner = state.is_owner_session(scope) && !is_agent_caller(scope);
    if !owner && r.requester != agent_key(state, scope, now) {
        return Err(OpError::NotFound(format!("no request {id}")));
    }
    Ok(request_view(&r, now, owner))
}

pub(super) fn request_list(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
) -> Result<Value, OpError> {
    refuse_agent(scope)?;
    owner_session(state, scope)?;
    let all: Vec<Value> = state
        .setting_requests_all()
        .iter()
        .map(|r| request_view(r, now, true))
        .collect();
    Ok(json!({ "requests": all }))
}

pub(super) fn request_decide(
    state: &BrokerState,
    scope: &BrokerScope,
    id: &str,
    approve: bool,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    refuse_agent(scope)?;
    owner_session(state, scope)?;
    let r = state
        .setting_request(id)
        .ok_or_else(|| OpError::NotFound(format!("no request {id}")))?;
    if r.state(now) != "pending" {
        return Err(OpError::Malformed(format!(
            "request {id} is {}",
            r.state(now)
        )));
    }
    if !approve {
        state.decide_setting_request(id, false, None, now);
        return Ok(json!({ "request": id, "state": "denied", "applied": false }));
    }
    let def = settings::find(&r.setting)
        .ok_or_else(|| OpError::NotFound(format!("no setting {}", r.setting)))?;
    let node = r.node.as_deref();
    let from = current(state, def, node)?;
    // The step-up: an approval of a weakening change is the owner's own change plus a fresh confirmation.
    owner_checks(
        state,
        scope,
        def,
        node,
        &from,
        &r.to,
        "settings.request_decide",
        params,
        true,
        now,
    )?;
    let reason = format!("approved agent request {id}: {}", r.reason);
    let rec = write(
        state,
        def,
        node,
        &from,
        &r.to,
        "owner",
        &reason,
        Some(id),
        None,
        now,
    )?;
    state.decide_setting_request(id, true, Some(rec.id.clone()), now);
    Ok(
        json!({ "request": id, "state": "approved", "applied": true, "changeId": rec.id, "id": def.id, "from": from, "to": r.to }),
    )
}

pub(super) fn kb() -> Value {
    json!({ "markdown": settings::kb_markdown(), "format": "text/markdown" })
}
