//! ADR-156 — the bodies of the post-launch quick-win read ops and the expiry write: `entry.set_expiry`,
//! `entry.expiring`, `entry.history`, `entry.search` and `entry.get_by_ref`. The dispatch arms in `ops.rs`
//! read the request's parameters (with literal keys, so the desktop bridge's drift guard can see them) and
//! call in here; this is a child module of `ops`, so it shares the authorisation helpers every other op uses.
//!
//! None of these answers ever carries a value: expiry, rotation time, name, ref and audit action are all
//! plaintext metadata the signed manifest or the audit log already holds.

use serde_json::{json, Value};

use credmgr_core::access::{Origin, Rule};
use credmgr_core::registry::Capability;
use credmgr_store::manifest::ManifestEntry;

use super::{
    access_denied_error, locked_refusal, narrow_entries, node_hides_names, resolve_capability,
    rule_name, sealed_change_guard, second_factor_gate, GateKind,
};
use crate::protocol::OpError;
use crate::scope::BrokerScope;
use crate::state::BrokerState;

/// `entry.expiring`: the widest look-ahead, in days (ten years).
pub(super) const EXPIRING_DAYS_MAX: u64 = 3650;
/// `entry.expiring`: the look-ahead when none is given.
pub(super) const EXPIRING_DAYS_DEFAULT: u64 = 30;
/// `entry.set_expiry`: the latest expiry accepted (year 9999, unix seconds) — anything later is a typo.
const EXPIRY_MAX: i64 = 253_402_300_799;
/// `entry.history`: the most records one answer carries (the newest are kept).
pub(super) const HISTORY_LIMIT_MAX: u64 = 500;
pub(super) const HISTORY_LIMIT_DEFAULT: u64 = 100;
/// ADR-158: how the destination's `entry.move` audit record names where the entry came from.
pub(super) const MOVED_FROM: &str = "moved from ";
/// `entry.search` / `entry.get_by_ref`: a term this long is not a name.
const TERM_MAX: usize = 200;

/// Human sessions only: the person at the keyboard, not an agent (ADR-077's reading of rotation and expiry
/// metadata, kept for the new ops until it is decided deliberately).
fn human_only(scope: &BrokerScope) -> Result<(), OpError> {
    if scope.origin == Origin::Agent {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Admin,
        });
    }
    Ok(())
}

/// The entries of `node` this caller may list (node-wide `list`, or per-entry grants narrowed), the same way
/// `entry.list` decides. `Err` when the caller may list none of the node and was not allowed it outright.
pub(super) fn listable<'a>(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    entries: &'a [ManifestEntry],
    now: i64,
) -> Result<Vec<&'a ManifestEntry>, OpError> {
    let decision = resolve_capability(state, scope, node, Capability::List, now);
    let visible = if decision.is_allow() {
        entries.iter().collect::<Vec<_>>()
    } else {
        narrow_entries(state, scope, node, Capability::List, entries, now)
    };
    if visible.is_empty() && !decision.is_allow() {
        return Err(access_denied_error(
            state,
            scope,
            node,
            Capability::List,
            rule_name(decision),
            now,
        ));
    }
    Ok(visible)
}

fn require_list(scope: &BrokerScope) -> Result<(), OpError> {
    if scope.holds(Capability::List) {
        Ok(())
    } else {
        Err(OpError::CapabilityNotHeld {
            capability: Capability::List,
        })
    }
}

fn all_node_ids(state: &BrokerState) -> Vec<String> {
    state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .keys()
        .cloned()
        .collect()
}

/// A node a cross-node scan may read names from: the caller is not name-blind there (ADR-083) and the node
/// is not asking for a second factor on every read (ADR-085). A node that fails either contributes nothing,
/// exactly as in `search`.
pub(super) fn scannable(state: &BrokerState, scope: &BrokerScope, node: &str, now: i64) -> bool {
    !node_hides_names(state, scope, node)
        && second_factor_gate(state, scope, node, GateKind::Read, now).is_ok()
}

// ---- entry.set_expiry --------------------------------------------------------

/// Sets (`Some`) or clears (`None`) an entry's expiry. Expiry is plaintext manifest metadata, so the sealed
/// envelope is not touched; the gate is `entry.update`'s (the `update` capability, R1 → locked refusal,
/// the Sealed-node agent guard, F-9's generation check under the node's write lock).
pub(super) fn set_expiry(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    entry: &str,
    expected_generation: u64,
    expires_at: Option<i64>,
    now: i64,
) -> Result<Value, OpError> {
    if let Some(at) = expires_at {
        if !(0..=EXPIRY_MAX).contains(&at) {
            return Err(OpError::Malformed(
                "params.expiresAt is unix seconds between 1970 and 9999, or null to clear it"
                    .into(),
            ));
        }
    }
    if !scope.holds(Capability::Update) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Update,
        });
    }
    let decision = resolve_capability(state, scope, node, Capability::Update, now);
    if !decision.is_allow() {
        if decision.rule() == Rule::R1 {
            return Err(locked_refusal(state, node));
        }
        return Err(access_denied_error(
            state,
            scope,
            node,
            Capability::Update,
            rule_name(decision),
            now,
        ));
    }
    sealed_change_guard(state, scope, node, Capability::Update)?;

    let node_lock = state.node_write_lock(node);
    let _guard = node_lock.lock().expect("node write lock poisoned");
    let (current_generation, exists) = {
        let manifests = state.manifests.read().expect("manifests poisoned");
        match manifests.get(node) {
            Some(body) => (body.generation, body.entries.iter().any(|e| e.id == entry)),
            None => (0, false),
        }
    };
    if !exists {
        return Err(OpError::NotFound(format!(
            "no entry {entry} on node {node}"
        )));
    }
    if expected_generation != current_generation {
        return Err(OpError::Conflict {
            node_id: node.to_string(),
            expected_generation,
            current_generation,
        });
    }
    let generation = state
        .update_manifest_entry(node, entry, |e| e.expires_at = expires_at)
        .expect("presence checked above, under the same held write lock");
    Ok(json!({
        "node": node, "entry": entry, "generation": generation, "expiresAt": expires_at,
    }))
}

// ---- entry.expiring ----------------------------------------------------------

/// The entries that expire within `days` from `now` (already expired included), across every node the
/// caller may list — or one node — soonest first. Names, ids, refs, `expiresAt` and `rotatedAt`; never a
/// value. Human sessions only.
pub(super) fn expiring(
    state: &BrokerState,
    scope: &BrokerScope,
    only_node: Option<&str>,
    days: u64,
    now: i64,
) -> Result<Value, OpError> {
    human_only(scope)?;
    require_list(scope)?;
    if days == 0 || days > EXPIRING_DAYS_MAX {
        return Err(OpError::Malformed(format!(
            "params.days is 1 to {EXPIRING_DAYS_MAX}"
        )));
    }
    let horizon = now.saturating_add((days as i64).saturating_mul(86_400));
    let manifests = state.manifests.read().expect("manifests poisoned");
    let nodes = match only_node {
        Some(n) => vec![n.to_string()],
        None => all_node_ids(state),
    };
    let mut rows = Vec::new();
    for node in &nodes {
        let entries = manifests
            .get(node.as_str())
            .map(|m| m.entries.as_slice())
            .unwrap_or(&[]);
        let visible = match only_node {
            // One named node: refuse it like `entry.list` does.
            Some(_) => {
                let visible = listable(state, scope, node, entries, now)?;
                second_factor_gate(state, scope, node, GateKind::Read, now)?;
                if node_hides_names(state, scope, node) {
                    return Err(access_denied_error(
                        state,
                        scope,
                        node,
                        Capability::List,
                        "private_names",
                        now,
                    ));
                }
                visible
            }
            // Every node: one the caller cannot read names from contributes nothing (I-3).
            None => {
                if !scannable(state, scope, node, now) {
                    continue;
                }
                match listable(state, scope, node, entries, now) {
                    Ok(v) => v,
                    Err(_) => continue,
                }
            }
        };
        for e in visible {
            if let Some(at) = e.expires_at {
                if at <= horizon {
                    rows.push(json!({
                        "node": node, "id": e.id, "name": e.name, "ref": e.r#ref,
                        "expiresAt": at, "rotatedAt": e.rotated_at, "expired": at <= now,
                    }));
                }
            }
        }
    }
    rows.sort_by_key(|r| r["expiresAt"].as_i64().unwrap_or(i64::MAX));
    Ok(json!({ "days": days, "now": now, "entries": rows }))
}

// ---- entry.history -----------------------------------------------------------

/// One entry's trail: every audit record that names it (on its node, and on every node it was moved from,
/// ADR-158), oldest first (the newest `limit` kept), plus the rotation and edit times the manifest holds.
/// Actions, times, decisions and the redacted actor only — values are never written to the audit log, so
/// none can leave here. Gated on `list` for the entry, like
/// `entry.list`; a name-blind reader of a private node is refused. Human sessions only.
pub(super) fn history(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    entry: &str,
    limit: u64,
    now: i64,
) -> Result<Value, OpError> {
    human_only(scope)?;
    require_list(scope)?;
    let limit = limit.clamp(1, HISTORY_LIMIT_MAX) as usize;
    let current = {
        let manifests = state.manifests.read().expect("manifests poisoned");
        let entries = manifests
            .get(node)
            .map(|m| m.entries.as_slice())
            .unwrap_or(&[]);
        let decision = resolve_capability(state, scope, node, Capability::List, now);
        let found = entries.iter().find(|e| e.id == entry).cloned();
        // Without node-wide `list`, the entry itself must be one of the caller's narrowed entries.
        let reachable = decision.is_allow()
            || found.as_ref().is_some_and(|f| {
                narrow_entries(
                    state,
                    scope,
                    node,
                    Capability::List,
                    std::slice::from_ref(f),
                    now,
                )
                .len()
                    == 1
            });
        if !reachable {
            return Err(access_denied_error(
                state,
                scope,
                node,
                Capability::List,
                rule_name(decision),
                now,
            ));
        }
        found
    };
    second_factor_gate(state, scope, node, GateKind::Read, now)?;
    if node_hides_names(state, scope, node) {
        return Err(access_denied_error(
            state,
            scope,
            node,
            Capability::List,
            "private_names",
            now,
        ));
    }
    let records = credmgr_store::audit::range(&state.paths, 0, now.saturating_add(1))
        .map_err(|e| OpError::Internal(format!("reading the audit log: {e}")))?;
    // ADR-158: an entry keeps its id when it moves, and the destination's `entry.move` record says where it
    // came from — so its trail before the move is followed back, node by node, through every node the caller
    // could read on its own (one it cannot contributes nothing, as in `search`).
    let mut trail: Vec<String> = vec![node.to_string()];
    loop {
        let came_from: Vec<String> = records
            .iter()
            .filter(|r| {
                r.action == "entry.move"
                    && r.decision.as_deref() == Some("allow")
                    && r.entry_id.as_deref() == Some(entry)
                    && r.node_id
                        .as_deref()
                        .is_some_and(|n| trail.iter().any(|t| t == n))
            })
            .filter_map(|r| {
                r.detail
                    .as_deref()?
                    .strip_prefix(MOVED_FROM)
                    .map(str::to_string)
            })
            .filter(|from| !trail.contains(from))
            .filter(|from| {
                scannable(state, scope, from, now)
                    && resolve_capability(state, scope, from, Capability::List, now).is_allow()
            })
            .collect();
        if came_from.is_empty() {
            break;
        }
        for from in came_from {
            if !trail.contains(&from) {
                trail.push(from);
            }
        }
    }
    let mut rows: Vec<Value> = records
        .into_iter()
        .filter(|r| {
            r.entry_id.as_deref() == Some(entry)
                && r.node_id.as_deref().is_some_and(|n| trail.iter().any(|t| t == n))
                // Looking at the history is not part of it.
                && r.action != "entry.history"
        })
        .map(|r| {
            json!({
                "id": r.id, "timestamp": r.timestamp, "node": r.node_id,
                // ADR-077: a record from a build that wrote the bearer as the actor is redacted on the way out.
                "actor": crate::token::redact_bearer_tokens(&r.actor),
                "action": r.action, "decision": r.decision, "generation": r.generation,
            })
        })
        .collect();
    let truncated = rows.len() > limit;
    if truncated {
        rows.drain(..rows.len() - limit);
    }
    let mut body = json!({
        "node": node, "entry": entry, "records": rows, "truncated": truncated,
        "exists": current.is_some(),
    });
    if let Some(e) = current {
        body["name"] = json!(e.name);
        body["ref"] = json!(e.r#ref);
        body["modified"] = json!(e.modified);
        body["rotatedAt"] = json!(e.rotated_at);
        body["expiresAt"] = json!(e.expires_at);
    }
    Ok(body)
}

// ---- entry.search ------------------------------------------------------------

/// The node-scoped variant of `search`: names and aliases on one node that contain `term`
/// (case-insensitive). Never values (F-18). The same gate as `entry.list`.
pub(super) fn search_in_node(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    term: &str,
    tag: Option<&str>,
    now: i64,
) -> Result<Value, OpError> {
    require_list(scope)?;
    if term.is_empty() || term.chars().count() > TERM_MAX {
        return Err(OpError::Malformed(format!(
            "params.term is 1 to {TERM_MAX} characters"
        )));
    }
    let term_lower = term.to_lowercase();
    let manifests = state.manifests.read().expect("manifests poisoned");
    let entries = manifests
        .get(node)
        .map(|m| m.entries.as_slice())
        .unwrap_or(&[]);
    let visible = listable(state, scope, node, entries, now)?;
    second_factor_gate(state, scope, node, GateKind::Read, now)?;
    if node_hides_names(state, scope, node) {
        return Err(access_denied_error(
            state,
            scope,
            node,
            Capability::List,
            "private_names",
            now,
        ));
    }
    let mut results = Vec::new();
    // ADR-167: `tag` narrows the search to the entries carrying it, on this one node.
    for e in visible
        .into_iter()
        .filter(|e| tag.map_or(true, |t| e.tags.iter().any(|x| x == t)))
    {
        if e.name.to_lowercase().contains(&term_lower) {
            results.push(json!({ "id": e.id, "name": e.name }));
        } else if let Some(alias) = e
            .aliases
            .iter()
            .find(|a| a.to_lowercase().contains(&term_lower))
        {
            results.push(json!({ "id": e.id, "name": e.name, "alias": alias }));
        }
    }
    let mut body = json!({ "node": node, "results": results });
    if let Some(t) = tag {
        body["tag"] = json!(t);
    }
    Ok(body)
}

// ---- entry.get_by_ref --------------------------------------------------------

/// Resolves a vault-global short reference to `{node, entry, name, ref}`. Only entries the caller could
/// already list are candidates, so "no such ref" and "a ref in a node you cannot reach" are the same
/// `not_found` (I-3).
pub(super) fn get_by_ref(
    state: &BrokerState,
    scope: &BrokerScope,
    wanted: u64,
    now: i64,
) -> Result<Value, OpError> {
    require_list(scope)?;
    let manifests = state.manifests.read().expect("manifests poisoned");
    for node in all_node_ids(state) {
        if !scannable(state, scope, &node, now) {
            continue;
        }
        let entries = manifests
            .get(node.as_str())
            .map(|m| m.entries.as_slice())
            .unwrap_or(&[]);
        let Ok(visible) = listable(state, scope, &node, entries, now) else {
            continue;
        };
        if let Some(e) = visible.into_iter().find(|e| u64::from(e.r#ref) == wanted) {
            return Ok(json!({ "node": node, "entry": e.id, "name": e.name, "ref": e.r#ref }));
        }
    }
    Err(OpError::NotFound(format!("no entry with ref {wanted}")))
}
