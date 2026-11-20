//! ADR-158 — the body of `entry.move`: move one entry to another node, re-encrypted to that node's key.
//! The dispatch arm in `ops.rs` reads the request's parameters (with literal keys, so the desktop bridge's
//! drift guard can see them) and calls in here; the commit protocol itself is `state/move_entry.rs`.
//!
//! The gate is `node.rekey`'s, the stricter of the two comparable ops (`node.rekey` re-seals a node's
//! files; `entry.remove` takes an entry out of a node): the owner's login and nothing else (an agent, a
//! cwd-scoped process or an agent token can never move an entry, so none can carry one out of its scope),
//! `Admin` on both nodes, a fresh second factor (the vault's, and each node's own where it has one), and a
//! presence proof on every call.
//!
//! ADR-169 — `vault.doctor_apply` applies every move of one doctor plan in one request, through the same
//! checks and the same commit, with the factors asked for once (see [`doctor_apply`]).

use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::{json, Value};

use credmgr_core::names::canonical_name;
use credmgr_core::registry::ORPHAN_ID;

use super::node_gate_ops::require_fresh_factors_for;
use super::quick_ops::MOVED_FROM;
use super::{human_admin_on, locked_refusal, node_is_locked, owner_session, require_presence};
use crate::protocol::OpError;
use crate::scope::BrokerScope;
use crate::state::BrokerState;

/// The longest `reason` a move records in its audit record (the doctor's `doctor:<plan-id>` tag fits).
const REASON_MAX: usize = 500;

#[allow(clippy::too_many_arguments)]
pub(super) fn entry_move(
    state: &BrokerState,
    scope: &BrokerScope,
    from: &str,
    entry: &str,
    to: &str,
    expected_generation: u64,
    reason: Option<&str>,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    owner_session(state, scope)?;
    check_reason(reason)?;
    check_move(state, scope, from, to, now)?;
    // A stale generation or a missing entry costs no finger: checked before the factors and the proof.
    let (current_generation, exists) = source_state(state, from, entry);
    if !exists {
        return Err(OpError::NotFound(format!(
            "no entry {entry} on node {from}"
        )));
    }
    if expected_generation != current_generation {
        return Err(OpError::Conflict {
            node_id: from.to_string(),
            expected_generation,
            current_generation,
        });
    }
    require_fresh_factors_for(state, from, now)?;
    require_fresh_factors_for(state, to, now)?;
    require_presence(state, scope, "entry.move", params, now)?;
    commit_move(
        state,
        scope,
        from,
        entry,
        to,
        expected_generation,
        None,
        now,
    )
}

fn check_reason(reason: Option<&str>) -> Result<(), OpError> {
    if let Some(r) = reason {
        if r.trim().is_empty() || r.chars().count() > REASON_MAX {
            return Err(OpError::Malformed(format!(
                "params.reason is 1 to {REASON_MAX} characters when given"
            )));
        }
    }
    Ok(())
}

/// Everything about one move that is refused before any factor is asked for, apart from the entry and the
/// generation: not the same node, not the orphan, both nodes there, `Admin` on both, neither locked, a vault
/// on disk.
fn check_move(
    state: &BrokerState,
    scope: &BrokerScope,
    from: &str,
    to: &str,
    now: i64,
) -> Result<(), OpError> {
    if from == to {
        return Err(OpError::Malformed(
            "params.to is the node the entry is already in".into(),
        ));
    }
    if from == ORPHAN_ID || to == ORPHAN_ID {
        return Err(OpError::Malformed(
            "entries move in and out of the orphan node only by sealing and restoring a node"
                .into(),
        ));
    }
    for node in [from, to] {
        if !state
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .contains_key(node)
        {
            return Err(OpError::NotFound(format!("no node {node}")));
        }
    }
    // Admin on both ends: the source loses an entry, the destination gains one.
    human_admin_on(state, scope, from, now)?;
    human_admin_on(state, scope, to, now)?;
    for node in [from, to] {
        if node_is_locked(state, node) {
            return Err(locked_refusal(state, node));
        }
    }
    if !state.is_durable() {
        return Err(OpError::Malformed(
            "entry.move needs a vault on disk".into(),
        ));
    }
    Ok(())
}

/// The source node's generation now, and whether it holds `entry`.
fn source_state(state: &BrokerState, from: &str, entry: &str) -> (u64, bool) {
    let manifests = state.manifests.read().expect("manifests poisoned");
    manifests.get(from).map_or((0, false), |m| {
        (m.generation, m.entries.iter().any(|e| e.id == entry))
    })
}

/// The move itself, once every gate has passed: the crash-safe commit, its audit records and the answer.
/// `batch` names the plan op that asked for it; the source then gets its own record, because a plan's
/// generic per-request record names no single node.
#[allow(clippy::too_many_arguments)]
fn commit_move(
    state: &BrokerState,
    scope: &BrokerScope,
    from: &str,
    entry: &str,
    to: &str,
    expected_generation: u64,
    batch: Option<&str>,
    now: i64,
) -> Result<Value, OpError> {
    let outcome = state.move_entry_durable(from, entry, to, expected_generation, now)?;
    // ADR-055 / ADR-122: the destination's record. The generic per-request record names the source
    // (`params.node`); this one names the destination, so `entry.history` there starts with the move.
    crate::server::record_item_event(
        state,
        scope,
        now,
        "entry.move",
        to,
        entry,
        Some(outcome.to_generation),
        &format!("{MOVED_FROM}{from}"),
    );
    if let Some(op) = batch {
        // ADR-169: the source's record of a planned move (a single `entry.move`'s generic record is that).
        crate::server::record_item_event(
            state,
            scope,
            now,
            "entry.move",
            from,
            entry,
            Some(outcome.from_generation),
            &format!("{MOVED_TO}{to} by {op}"),
        );
    }
    for grant in &outcome.grants_revoked {
        crate::server::record_item_event(
            state,
            scope,
            now,
            "grant.revoke",
            from,
            entry,
            None,
            &format!("grant {grant} revoked by entry.move"),
        );
    }
    let mut out = json!({
        "node": to,
        "entry": outcome.entry,
        "ref": outcome.r#ref,
        "name": outcome.name,
        "from": from,
        // `generation` is the source's (the node this request named in `params.node`); the destination's
        // generation, which a following write to the moved entry needs, is `toGeneration`.
        "generation": outcome.from_generation,
        "toGeneration": outcome.to_generation,
        "grantsRevoked": outcome.grants_revoked,
        "historyDropped": outcome.history_dropped,
    });
    if let Some(warning) = outcome.cleanup_warning {
        out["cleanupWarning"] = json!(warning);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// vault.doctor_apply (ADR-169)

/// The most moves one plan may carry (the doctor reports at most this many findings of one kind).
pub(super) const PLAN_MAX: usize = 500;
/// How the source's record of a planned move names where the entry went.
const MOVED_TO: &str = "moved to ";
/// The op name a planned move's source record carries.
const APPLY_OP: &str = "vault.doctor_apply";

/// One step of a plan, exactly as the scan's proposal carried it: `{node, entry, to, generation}`, where
/// `generation` is the source node's generation the scan showed.
#[derive(Debug, Clone)]
pub(super) struct PlannedMove {
    pub from: String,
    pub entry: String,
    pub to: String,
    pub generation: u64,
}

/// One node as the plan's dry run sees it: the entry ids it holds and the canonical names it uses.
struct Simulated {
    ids: HashSet<String>,
    names: HashSet<String>,
}

/// ADR-169 — apply every move of one doctor plan in one request. The request carries the exact plan the
/// scan showed (entry ids, from, to, the source generations); nothing is looked up or added here. Every step
/// is checked, in order and against a dry run of the earlier steps, before any factor is asked for; the
/// factors are `entry.move`'s, obtained once for the whole plan (the owner's login, `Admin` on every node the
/// plan names, a fresh second factor for the vault and for each of those nodes that has its own, and one
/// presence proof whose signed digest covers the whole plan); then each move runs through the same
/// crash-safe commit as `entry.move`. The first move that fails stops the plan: before anything is written
/// that is the request's error; after, the answer reports what was applied (each one a whole move, moved
/// back the ordinary way) and where it stopped.
pub(super) fn doctor_apply(
    state: &BrokerState,
    scope: &BrokerScope,
    plan: &[PlannedMove],
    reason: Option<&str>,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    owner_session(state, scope)?;
    check_reason(reason)?;
    if plan.is_empty() || plan.len() > PLAN_MAX {
        return Err(OpError::Malformed(format!(
            "params.moves holds 1 to {PLAN_MAX} moves"
        )));
    }
    let mut seen = HashSet::new();
    for step in plan {
        if !seen.insert(step.entry.as_str()) {
            return Err(OpError::Malformed(format!(
                "params.moves names the entry {} twice",
                step.entry
            )));
        }
    }
    for step in plan {
        check_move(state, scope, &step.from, &step.to, now)?;
    }
    let nodes: BTreeSet<&str> = plan
        .iter()
        .flat_map(|s| [s.from.as_str(), s.to.as_str()])
        .collect();

    // The plan against the vault as it is: each step's generation is its source's now, and, in order, each
    // step seeing the earlier ones done, the entry is in its source and its names are free at its
    // destination. Anything else is refused here, before a finger is asked for and before anything moves.
    let mut sim: HashMap<String, Simulated> = HashMap::new();
    let mut row_names: HashMap<String, Vec<String>> = HashMap::new();
    {
        let manifests = state.manifests.read().expect("manifests poisoned");
        for step in plan {
            let current = manifests.get(&step.from).map_or(0, |m| m.generation);
            if step.generation != current {
                return Err(OpError::Conflict {
                    node_id: step.from.clone(),
                    expected_generation: step.generation,
                    current_generation: current,
                });
            }
        }
        for node in &nodes {
            let manifest = manifests.get(*node);
            let mut simulated = Simulated {
                ids: HashSet::new(),
                names: HashSet::new(),
            };
            if let Some(m) = manifest {
                for e in &m.entries {
                    let all: Vec<String> = std::iter::once(e.name.clone())
                        .chain(e.aliases.iter().cloned())
                        .collect();
                    simulated.ids.insert(e.id.clone());
                    simulated
                        .names
                        .extend(all.iter().map(|n| canonical_name(n)));
                    row_names.insert(e.id.clone(), all);
                }
            }
            sim.insert((*node).to_string(), simulated);
        }
    }
    for node in &nodes {
        let pending = state.list_pending(node);
        if let Some(s) = sim.get_mut(*node) {
            s.names
                .extend(pending.iter().map(|p| canonical_name(&p.name)));
        }
    }
    for step in plan {
        let in_source = sim
            .get_mut(&step.from)
            .is_some_and(|s| s.ids.remove(&step.entry));
        if !in_source {
            return Err(OpError::NotFound(format!(
                "no entry {} on node {}",
                step.entry, step.from
            )));
        }
        let names = row_names.get(&step.entry).cloned().unwrap_or_default();
        let canon: Vec<String> = names.iter().map(|n| canonical_name(n)).collect();
        if let Some(source) = sim.get_mut(&step.from) {
            for c in &canon {
                source.names.remove(c);
            }
        }
        let Some(dest) = sim.get_mut(&step.to) else {
            return Err(OpError::NotFound(format!("no node {}", step.to)));
        };
        for (name, c) in names.iter().zip(&canon) {
            if dest.names.contains(c) {
                return Err(OpError::EntryExists {
                    node: step.to.clone(),
                    name: name.clone(),
                });
            }
        }
        dest.names.extend(canon);
        dest.ids.insert(step.entry.clone());
    }

    // The factors, once for the plan: a fresh second factor for the vault and for every node it names that
    // has its own, then one presence proof over the whole request.
    for node in &nodes {
        require_fresh_factors_for(state, node, now)?;
    }
    require_presence(state, scope, APPLY_OP, params, now)?;

    // Each move through `entry.move`'s commit, carrying the generation the previous step left.
    let mut generations: HashMap<String, u64> = plan
        .iter()
        .map(|s| (s.from.clone(), s.generation))
        .collect();
    let mut applied: Vec<Value> = Vec::new();
    for (index, step) in plan.iter().enumerate() {
        let generation = generations
            .get(&step.from)
            .copied()
            .unwrap_or(step.generation);
        match commit_move(
            state,
            scope,
            &step.from,
            &step.entry,
            &step.to,
            generation,
            Some(APPLY_OP),
            now,
        ) {
            Ok(mut done) => {
                if let Some(g) = done["generation"].as_u64() {
                    generations.insert(step.from.clone(), g);
                }
                if let Some(g) = done["toGeneration"].as_u64() {
                    generations.insert(step.to.clone(), g);
                }
                done["index"] = json!(index);
                applied.push(done);
            }
            Err(e) if applied.is_empty() => return Err(e),
            Err(e) => {
                let wire = crate::protocol::to_wire("", &Err(e));
                return Ok(json!({
                    "complete": false,
                    "applied": applied,
                    "stopped": {
                        "index": index,
                        "node": step.from,
                        "entry": step.entry,
                        "to": step.to,
                        "code": wire["error"],
                        "message": wire["message"],
                    },
                    "notApplied": plan.len() - index,
                }));
            }
        }
    }
    Ok(json!({ "complete": true, "applied": applied, "notApplied": 0 }))
}
