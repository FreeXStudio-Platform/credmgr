//! ADR-130…134 — the bodies of the 2.0.0 broker ops: `node.rekey`, `orphan.destroy`, `search.content`,
//! `node.export` and `audit.report`. The dispatch arms in `ops.rs` read the request's parameters and call
//! in here, so the authorisation helpers they share with every other op (`resolve_capability`,
//! `require_presence`, …) stay private to `ops`; this is a child module of it and sees them.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use secrecy::ExposeSecret;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use credmgr_core::age_format::{self, Recipient};
use credmgr_core::fields;
use credmgr_core::inference::FieldType;
use credmgr_core::registry::{Capability, GLOBAL_ID, ORPHAN_ID};

use super::node_gate_ops::require_fresh_factors_for;
use super::{
    access_denied_error, entry_doc, human_admin_on, locked_refusal, narrow_entries,
    node_hides_names, node_is_locked, owner_session, require_fresh_second_factor, require_presence,
    resolve_capability, rule_name, second_factor_gate, GateKind,
};
use crate::protocol::OpError;
use crate::scope::BrokerScope;
use crate::state::BrokerState;

/// `search.content`: the shortest term (a one-letter probe is an enumeration, not a search).
const CONTENT_TERM_MIN: usize = 3;
const CONTENT_TERM_MAX: usize = 200;
/// `search.content`: at most this many calls per [`CONTENT_WINDOW_SECONDS`] per caller.
pub(crate) const CONTENT_SEARCH_MAX_CALLS: usize = 12;
pub(crate) const CONTENT_WINDOW_SECONDS: i64 = 60;
/// `search.content`: the most entries one call opens. Past it the answer says `truncated`.
const CONTENT_SCAN_MAX: usize = 5000;

/// `node.export`: the shortest passphrase an export accepts.
const EXPORT_PASSPHRASE_MIN: usize = 12;
const EXPORT_RECIPIENTS_MAX: usize = 16;

/// The actions that cost a presence proof on every allowed call (the report's "presence uses").
const PRESENCE_EVERY_TIME: &[&str] = &[
    "audit.get",
    "totp.seed",
    "node.reparent",
    "grant.create",
    "maintenance.rotate_root",
    "presence.enrol",
    "presence.unenrol",
    "device.enrol",
    "device.remove",
    "keystore.unbind",
    "orphan.reveal",
    "node.rekey",
    "entry.move",
    "vault.doctor_apply",
    "orphan.destroy",
    "node.export",
    "node.gate_remove",
];

/// `audit.report`: the longest period one report covers.
const REPORT_MAX_SECONDS: i64 = 366 * 86_400;
const REPORT_ROWS_MAX: usize = 50;

fn is_seed(f: &fields::FieldDoc) -> bool {
    fields::effective_type(f) == FieldType::TotpSeed
}

// ---------------------------------------------------------------------------
// node.rekey (ADR-130)
// ---------------------------------------------------------------------------

pub(super) fn node_rekey(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    owner_session(state, scope)?;
    if target_node == ORPHAN_ID {
        return Err(OpError::Malformed(
            "the orphan node's key is a cold key and is not re-keyed".into(),
        ));
    }
    // Admin on the node itself (a name that does not exist is not_found, after the capability).
    human_admin_on(state, scope, GLOBAL_ID, now)?;
    if !state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .contains_key(target_node)
    {
        return Err(OpError::NotFound(format!("no node {target_node}")));
    }
    human_admin_on(state, scope, target_node, now)?;
    if node_is_locked(state, target_node) {
        return Err(locked_refusal(state, target_node));
    }
    if !state.is_durable() {
        return Err(OpError::Malformed(
            "node.rekey needs a vault on disk".into(),
        ));
    }
    // Everything that can be checked without the person's finger is checked before it.
    require_fresh_factors_for(state, target_node, now)?;
    require_presence(state, scope, "node.rekey", params, now)?;
    let outcome = state.rekey_node_durable(target_node, now)?;
    // No second-factor window survives a rekey: the next one costs a code of its own.
    state.drop_elevations();
    let mut out = json!({
        "node": target_node,
        "publicKey": outcome.public_key,
        "entries": outcome.entries,
        "note": outcome.note,
        "history": outcome.history,
        "removed": outcome.removed,
    });
    // ADR-148 addendum: committed, but the stage stayed — success, said in words.
    if let Some(warning) = outcome.cleanup_warning {
        out["cleanupWarning"] = json!(warning);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// orphan.destroy (ADR-131)
// ---------------------------------------------------------------------------

/// The exact word `orphan.destroy` wants in `params.confirm`.
pub(crate) const DESTROY_CONFIRM: &str = "destroy-sealed-entries";

pub(super) fn orphan_destroy(
    state: &BrokerState,
    scope: &BrokerScope,
    confirm: &str,
    count: u64,
    entries: Option<Vec<String>>,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    owner_session(state, scope)?;
    human_admin_on(state, scope, GLOBAL_ID, now)?;
    if confirm != DESTROY_CONFIRM {
        return Err(OpError::Malformed(format!(
            "params.confirm must be exactly \"{DESTROY_CONFIRM}\" — nothing was destroyed"
        )));
    }
    if !state.is_durable() {
        return Err(OpError::Malformed(
            "orphan.destroy needs a vault on disk".into(),
        ));
    }
    let expected = usize::try_from(count)
        .map_err(|_| OpError::Malformed("params.count is too large".into()))?;
    // Cheap, finger-free checks first: an empty or mismatched request never costs a prompt.
    {
        let manifests = state.manifests.read().expect("manifests poisoned");
        let have = manifests.get(ORPHAN_ID).map_or(0, |m| m.entries.len());
        let would = entries.as_ref().map_or(have, Vec::len);
        if let Some(list) = &entries {
            let rows = manifests.get(ORPHAN_ID);
            for id in list {
                if !rows.is_some_and(|m| m.entries.iter().any(|e| &e.id == id)) {
                    return Err(OpError::NotFound(format!("no sealed entry {id}")));
                }
            }
        }
        // ADR-148 (P3): an explicit list is held to `count` here too, before the presence proof is spent.
        if would != expected {
            return Err(OpError::Malformed(format!(
                "params.count is {expected}, but {would} sealed entries would be destroyed — nothing was destroyed"
            )));
        }
    }
    require_fresh_second_factor(state, now)?;
    require_presence(state, scope, "orphan.destroy", params, now)?;
    let outcome = state.destroy_orphans_durable(entries.as_deref(), expected, now)?;
    state.drop_elevations();
    Ok(json!({
        "destroyed": outcome.entries,
        "sealsForgotten": outcome.seals_forgotten,
        "archivesRemoved": outcome.archives_removed,
    }))
}

// ---------------------------------------------------------------------------
// search.content (ADR-132)
// ---------------------------------------------------------------------------

pub(super) fn content_search(
    state: &BrokerState,
    scope: &BrokerScope,
    term: &str,
    only_node: Option<&str>,
    now: i64,
) -> Result<Value, OpError> {
    if !scope.holds(Capability::Reveal) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Reveal,
        });
    }
    let chars = term.chars().count();
    if !(CONTENT_TERM_MIN..=CONTENT_TERM_MAX).contains(&chars) {
        return Err(OpError::Malformed(format!(
            "params.term must be {CONTENT_TERM_MIN} to {CONTENT_TERM_MAX} characters"
        )));
    }
    if state.is_locked() {
        return Err(OpError::VaultLocked);
    }
    // ADR-156 (supersedes the K-24 exemption of ADR-150): a search over values is a reveal by another
    // name, and any entry may match, so a person's search answers to "confirm before showing secrets" as
    // a critical value does — before any value is read or a rate slot is spent. An agent is not asked:
    // what it may search is bounded by the node's security level (ADR-148 §P2-1, below).
    if !super::is_agent_caller(scope) {
        super::confirmation_gate(
            state,
            scope,
            "search.content",
            credmgr_core::inference::Sensitivity::Critical,
            now,
        )?;
    }
    // Counted before the work, per caller (a login session by its public id, anything else by origin).
    let key = scope
        .token_id
        .as_deref()
        .and_then(|bearer| state.tokens.public_id(bearer))
        .unwrap_or_else(|| format!("{:?}:{}", scope.origin, scope.node_id));
    state
        .stable
        .content_search_admit(&key, now)
        .map_err(|retry| OpError::RateLimited {
            retry_after_seconds: retry,
        })?;

    let mut node_ids: Vec<String> = state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .keys()
        .filter(|id| id.as_str() != ORPHAN_ID)
        .cloned()
        .collect();
    node_ids.sort();
    if let Some(only) = only_node {
        if !node_ids.iter().any(|n| n == only) {
            return Err(OpError::NotFound(format!("no node {only}")));
        }
        node_ids.retain(|n| n == only);
    }

    let needle = term.to_lowercase();
    let mut results = Vec::new();
    let mut scanned = 0usize;
    let mut truncated = false;
    'nodes: for node_id in &node_ids {
        let decision = resolve_capability(state, scope, node_id, Capability::Reveal, now);
        // A reader who may not see a node's names never searches it (ADR-083); one who would be asked for
        // a second factor to reveal from it is not asked — the node is skipped (ADR-085), as `search` does.
        if node_hides_names(state, scope, node_id)
            || second_factor_gate(state, scope, node_id, GateKind::Reveal, now).is_err()
        {
            continue;
        }
        // ADR-148 §P2-1: a substring search over values is a reveal by another name. An agent never searches
        // what it could not reveal without the owner's approval (ADR-140): nothing on a Sealed node, and no
        // entry a Guarded node would hold for approval (high or critical). Otherwise a run of searches is an
        // oracle that spells the value out one guess at a time.
        let agent_level =
            super::is_agent_caller(scope).then(|| super::security_level_of(state, node_id));
        if agent_level == Some(credmgr_core::registry::SecurityLevel::Sealed) {
            continue;
        }
        let Some(node_priv) = state.hot_node_key(node_id) else {
            continue;
        };
        let rows = state
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(node_id)
            .map(|m| m.entries.clone())
            .unwrap_or_default();
        let visible: Vec<_> = if decision.is_allow() {
            rows.iter().collect()
        } else {
            narrow_entries(state, scope, node_id, Capability::Reveal, &rows, now)
        };
        for entry in visible {
            if agent_level.is_some_and(|level| level.reveal_needs_approval(entry.sensitivity)) {
                continue;
            }
            if scanned >= CONTENT_SCAN_MAX {
                truncated = true;
                break 'nodes;
            }
            scanned += 1;
            let Ok(loaded) = entry_doc::load(state, node_id, &entry.id, &node_priv, Some(entry))
            else {
                continue;
            };
            // A stored 2FA seed is never matched: the seed/code split holds for search as for reveal.
            let hit = loaded
                .doc
                .fields
                .iter()
                .any(|f| !is_seed(f) && f.value.to_lowercase().contains(&needle));
            if hit {
                results.push(json!({ "node": node_id, "id": entry.id, "name": entry.name }));
            }
        }
    }
    Ok(json!({ "results": results, "truncated": truncated }))
}

// ---------------------------------------------------------------------------
// node.export (ADR-133)
// ---------------------------------------------------------------------------

pub(super) fn node_export(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    passphrase: Option<&str>,
    recipients: Option<Vec<String>>,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    owner_session(state, scope)?;
    if !scope.holds(Capability::Reveal) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Reveal,
        });
    }
    if target_node == ORPHAN_ID {
        return Err(OpError::Malformed(
            "the orphan node is not exported — its sealed entries are read one at a time with orphan.reveal".into(),
        ));
    }
    let decision = resolve_capability(state, scope, target_node, Capability::Reveal, now);
    if !decision.is_allow() {
        return Err(access_denied_error(
            state,
            scope,
            target_node,
            Capability::Reveal,
            rule_name(decision),
            now,
        ));
    }
    // Who may open the file — decided and validated before the person is asked for anything.
    let wanted = recipients.unwrap_or_default();
    let who: Vec<Recipient> = match (passphrase, wanted.is_empty()) {
        (Some(_), false) => {
            return Err(OpError::Malformed(
                "give either params.passphrase or params.recipients, not both".into(),
            ))
        }
        (None, true) => {
            return Err(OpError::Malformed(
                "an export is always encrypted: give params.passphrase or params.recipients".into(),
            ))
        }
        (Some(pass), true) => {
            if pass.chars().count() < EXPORT_PASSPHRASE_MIN {
                return Err(OpError::Malformed(format!(
                    "the export passphrase must be at least {EXPORT_PASSPHRASE_MIN} characters"
                )));
            }
            vec![Recipient::Passphrase {
                passphrase: pass.to_string(),
                log_n: state.stable.export_work_factor(),
            }]
        }
        (None, false) => {
            if wanted.len() > EXPORT_RECIPIENTS_MAX {
                return Err(OpError::Malformed(format!(
                    "at most {EXPORT_RECIPIENTS_MAX} recipients"
                )));
            }
            wanted
                .iter()
                .map(|r| {
                    age_format::parse_recipient(r)
                        .map(Recipient::X25519)
                        .map_err(|e| OpError::Malformed(format!("params.recipients: {e}")))
                })
                .collect::<Result<_, _>>()?
        }
    };
    second_factor_gate(state, scope, target_node, GateKind::Reveal, now)?;
    let Some(node_priv) = state.hot_node_key(target_node) else {
        return Err(locked_refusal(state, target_node));
    };
    require_fresh_factors_for(state, target_node, now)?;
    require_presence(state, scope, "node.export", params, now)?;

    let (label, rows) = {
        let label = state
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .get(target_node)
            .map(|n| n.label.clone())
            .ok_or_else(|| OpError::NotFound(format!("no node {target_node}")))?;
        let rows = state
            .manifests
            .read()
            .expect("manifests poisoned")
            .get(target_node)
            .map(|m| m.entries.clone())
            .unwrap_or_default();
        (label, rows)
    };
    let mut omitted_seeds = 0usize;
    let mut out_entries = Vec::with_capacity(rows.len());
    for entry in &rows {
        let loaded = entry_doc::load(state, target_node, &entry.id, &node_priv, Some(entry))?;
        let mut field_rows = Vec::with_capacity(loaded.doc.fields.len());
        for f in &loaded.doc.fields {
            let (kind, masked) = fields::effective(f);
            let mut row = json!({ "id": f.id, "label": f.label, "type": kind, "masked": masked });
            if is_seed(f) {
                // As for a reveal: a stored 2FA seed is never handed out — an export is not a side door.
                row["value"] = Value::Null;
                row["redacted"] = json!("totp_seed");
                omitted_seeds += 1;
            } else {
                row["value"] = json!(f.value);
            }
            field_rows.push(row);
        }
        out_entries.push(json!({
            "id": entry.id, "name": entry.name, "type": entry.entry_type,
            "sensitivity": entry.sensitivity, "modified": entry.modified,
            "fields": field_rows,
        }));
    }
    let mut document = json!({
        "format": "credmgr-export", "version": 1, "exportedAt": now,
        "node": { "id": target_node, "label": label },
        "entries": out_entries,
    });
    let payload = Zeroizing::new(
        serde_json::to_vec(&document).expect("an export document always serialises"),
    );
    // ADR-148 addendum: the plaintext document is wiped once serialised (every string value in it; object
    // keys are field names, not values).
    // Stated, not solved: the serialiser's own growth reallocations and the loaded entry documents may still
    // leave copies in freed memory.
    zeroize_json(&mut document);
    let ciphertext = age_format::encrypt(&payload, &who)
        .map_err(|e| OpError::Malformed(format!("the export could not be encrypted: {e}")))?;
    state.drop_elevations();
    Ok(json!({
        "node": target_node,
        "format": "age-v1",
        "entries": rows.len(),
        "omittedSeeds": omitted_seeds,
        "archive": B64.encode(ciphertext),
    }))
}

/// Overwrite every string inside `value` with zeros before it is dropped (ADR-148 addendum).
fn zeroize_json(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_json),
        Value::Object(map) => map.values_mut().for_each(zeroize_json),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// audit.report (ADR-134)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Tally {
    count: u64,
    allow: u64,
    deny: u64,
}

impl Tally {
    fn add(&mut self, decision: Option<&str>) {
        self.count += 1;
        match decision {
            Some("allow") => self.allow += 1,
            Some("deny") => self.deny += 1,
            _ => {}
        }
    }
    fn json(&self, key: &str, name: &str) -> Value {
        json!({ key: name, "count": self.count, "allow": self.allow, "deny": self.deny })
    }
}

fn top_rows(map: BTreeMap<String, Tally>, key: &str) -> Vec<Value> {
    let mut rows: Vec<(String, Tally)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
    rows.into_iter()
        .take(REPORT_ROWS_MAX)
        .map(|(name, t)| t.json(key, &name))
        .collect()
}

pub(super) fn audit_report(
    state: &BrokerState,
    scope: &BrokerScope,
    from: i64,
    to: i64,
    only_node: Option<&str>,
    now: i64,
) -> Result<Value, OpError> {
    owner_session(state, scope)?;
    human_admin_on(state, scope, GLOBAL_ID, now)?;
    if from < 0 || to <= from {
        return Err(OpError::Malformed(
            "params.from and params.to are unix seconds, with from before to".into(),
        ));
    }
    if to - from > REPORT_MAX_SECONDS {
        return Err(OpError::Malformed(
            "an audit report covers at most 366 days".into(),
        ));
    }
    let records = credmgr_store::audit::range(&state.paths, from, to)
        .map_err(|e| OpError::Internal(format!("reading the audit log: {e}")))?;

    let mut total = 0u64;
    let mut by_decision = (0u64, 0u64, 0u64); // allow, deny, other
    let mut by_action: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_actor: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_node: BTreeMap<String, Tally> = BTreeMap::new();
    let mut denial_reasons: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut presence_ops: BTreeMap<String, u64> = BTreeMap::new();
    let mut presence_uses = 0u64;
    let mut presence_refused = 0u64;
    let mut recent_denials: Vec<Value> = Vec::new();
    for r in &records {
        if only_node.is_some() && r.node_id.as_deref() != only_node {
            continue;
        }
        total += 1;
        let decision = r.decision.as_deref();
        match decision {
            Some("allow") => by_decision.0 += 1,
            Some("deny") => by_decision.1 += 1,
            _ => by_decision.2 += 1,
        }
        let actor = crate::token::redact_bearer_tokens(&r.actor).into_owned();
        by_action.entry(r.action.clone()).or_default().add(decision);
        by_actor.entry(actor.clone()).or_default().add(decision);
        if let Some(n) = &r.node_id {
            by_node.entry(n.clone()).or_default().add(decision);
        }
        // Only actions that need a presence proof **every** time count as uses: `node.policy` and
        // `maintenance.doctor` ask for one only for a widening / a rebuild, which a record cannot tell apart.
        let presence_op = PRESENCE_EVERY_TIME.contains(&r.action.as_str());
        if presence_op && decision == Some("allow") {
            presence_uses += 1;
            *presence_ops.entry(r.action.clone()).or_default() += 1;
        }
        if decision == Some("deny") {
            // Only the broker's own error tag is reported — never the free text a person wrote.
            let tag = r
                .detail
                .as_deref()
                .filter(|d| d.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
                .unwrap_or("denied")
                .to_string();
            if tag == "presence_required" || tag == "presence_failed" {
                presence_refused += 1;
            }
            *denial_reasons
                .entry((r.action.clone(), tag.clone()))
                .or_default() += 1;
            recent_denials.push(json!({
                "id": r.id, "timestamp": r.timestamp, "actor": actor,
                "action": r.action, "node": r.node_id, "reason": tag,
            }));
        }
    }
    recent_denials.reverse();
    recent_denials.truncate(25);
    let mut reasons: Vec<Value> = denial_reasons
        .into_iter()
        .map(|((action, reason), count)| json!({ "action": action, "reason": reason, "count": count }))
        .collect();
    reasons.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    reasons.truncate(REPORT_ROWS_MAX);
    let mut presence_by_op: Vec<Value> = presence_ops
        .into_iter()
        .map(|(op, count)| json!({ "op": op, "count": count }))
        .collect();
    presence_by_op.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));

    // The hash chain of every month the period touches, verified under the root key now.
    let first = credmgr_store::audit::year_month_for(from);
    let last = credmgr_store::audit::year_month_for(to - 1);
    let months: Vec<String> = credmgr_store::audit::year_months(&state.paths)
        .map_err(|e| OpError::Internal(format!("listing the audit logs: {e}")))?
        .into_iter()
        .filter(|m| *m >= first && *m <= last)
        .collect();
    let chain_ok = match state.reauth_root_key("audit report") {
        Ok(rk) => months
            .iter()
            .all(|m| credmgr_store::audit::verify(&state.paths, rk.expose_secret(), m).is_ok()),
        Err(_) => false,
    };

    Ok(json!({
        "from": from, "to": to, "node": only_node,
        "records": total,
        "decisions": { "allow": by_decision.0, "deny": by_decision.1, "other": by_decision.2 },
        "byAction": top_rows(by_action, "action"),
        "byActor": top_rows(by_actor, "actor"),
        "byNode": top_rows(by_node, "node"),
        "denials": { "total": by_decision.1, "reasons": reasons, "recent": recent_denials },
        "presence": { "uses": presence_uses, "byOp": presence_by_op, "refused": presence_refused },
        "chain": { "months": months, "verified": chain_ok },
    }))
}
