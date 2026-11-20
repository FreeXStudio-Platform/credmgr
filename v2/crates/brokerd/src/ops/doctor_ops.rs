//! ADR-161 — the body of `vault.doctor_scan`, phase 1 of the doctor's tidy-up scan (doc 25, research memo 03
//! §3, plan 26 §7). It reads the vault and **returns a report and a preview plan; it writes nothing**. The
//! one kind of proposal that can be applied (moving an entry: a "misfiled" entry, or one copy of a value two
//! sub-nodes of one project share, to where both can read it) carries the exact `entry.move` parameters,
//! and the person applies each one through `entry.move` with its own gates (second factor, Touch ID).
//!
//! **No value leaves here.** Values are opened inside the broker, one entry at a time, only to compute:
//! an HMAC under a key drawn for this scan and dropped when it returns (raw and normalised forms, so two
//! entries can be said to "share a value" without any digest, length or part of either leaving), the weak
//! password heuristics, a JWT's `exp` claim, and the mistyped-value checks. The report carries entry and
//! node ids, refs, names, field ids and labels (what `entry.list` and `entry.get` already show the owner),
//! a reason code, and timestamps — never a value, a hash or a fragment. Nothing is stored and nothing is
//! logged beyond the generic audit record of the request (its params: the two day counts).
//!
//! **Who.** The owner's login only (`owner_session`), with `Admin` on `global`, the gate `audit.report`
//! has: no agent session, agent token or cwd-scoped process ever runs it. No second factor and no presence
//! proof, because nothing is revealed and nothing changes — the same reasoning as `audit.report`. Within
//! that, every node is read under the checks `entry.list` applies (the caller may list it, is not
//! name-blind there, and is not asked for a second factor to read it), the orphan node is never read, a
//! locked node contributes nothing, and values are read only where the caller could reveal them without
//! being asked for anything more (a node with its own second factor that is not open right now is
//! scanned by name and metadata only and said so in `skipped`).
//!
//! **Bounded.** One scan at a time (a second is `rate_limited`), at most [`ENTRY_CAP`] entries and
//! [`TIME_BUDGET`] of value reading, at most [`FINDINGS_CAP`] findings of each kind; anything cut is
//! `truncated: true`. It runs under the ordinary shared barrier, never the exclusive one, and holds the
//! manifest lock only long enough to copy the metadata it reads.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use credmgr_core::doctor::{
    is_otpauth_uri, jwt_expiry, key_environment, name_environment, normalised, skip_for_duplicates,
    weak_password, KeyEnvironment, ScanKey,
};
use credmgr_core::inference::FieldType;
use credmgr_core::names::{canonical_name, compact_key, similar_keys};
use credmgr_core::registry::{Capability, GLOBAL_ID, ORPHAN_ID};
use credmgr_store::manifest::ManifestEntry;

use super::quick_ops::{listable, scannable};
use super::{
    human_admin_on, node_is_locked, owner_session, resolve_capability, resolve_entry_capability,
    second_factor_gate, GateKind,
};
use crate::protocol::OpError;
use crate::scope::BrokerScope;
use crate::state::BrokerState;

/// "Not rotated for this many days" when the request names none (memo 03 §3.1's policy age).
pub(super) const STALE_DAYS_DEFAULT: u64 = 365;
/// "Expires within this many days" when the request names none (memo 03 §3.1, `entry.expiring`'s window).
pub(super) const EXPIRING_DAYS_DEFAULT: u64 = 30;
/// The widest either window may be (ten years, as `entry.expiring`).
pub(super) const DAYS_MAX: u64 = 3650;
/// The most entries one scan looks at.
pub(crate) const ENTRY_CAP: usize = 10_000;
/// The longest one scan spends opening values.
pub(crate) const TIME_BUDGET: Duration = Duration::from_secs(10);
/// The most findings of one kind one report carries.
pub(crate) const FINDINGS_CAP: usize = 500;
/// How long a second scan that met a running one is told to wait.
const BUSY_RETRY_SECONDS: u64 = 5;
const DAY: i64 = 86_400;

/// One entry as the report names it.
#[derive(Clone)]
struct Seen {
    node: String,
    entry: String,
    r#ref: u32,
    name: String,
    generation: u64,
}

impl Seen {
    fn to_json(&self, labels: &HashMap<String, NodeInfo>) -> Value {
        json!({
            "node": self.node,
            "nodeLabel": labels.get(&self.node).map(|n| n.label.as_str()),
            "entry": self.entry,
            "ref": self.r#ref,
            "name": self.name,
            "generation": self.generation,
        })
    }
}

#[derive(Clone)]
struct NodeInfo {
    label: String,
    parent: Option<String>,
    depth: u8,
}

/// The report under construction.
struct Report {
    findings: BTreeMap<&'static str, Vec<Value>>,
    truncated: bool,
}

impl Report {
    fn push(&mut self, kind: &'static str, finding: Value) {
        let list = self.findings.entry(kind).or_default();
        if list.len() >= FINDINGS_CAP {
            self.truncated = true;
        } else {
            list.push(finding);
        }
    }
}

/// The kinds a report may carry, in the order the app shows them.
pub(crate) const KINDS: &[&str] = &[
    "duplicate_value",
    "misfiled",
    "similar_names",
    "weak",
    "mistyped",
    "expired",
    "expiring",
    "stale",
];

pub(super) fn doctor_scan(
    state: &BrokerState,
    scope: &BrokerScope,
    stale_days: u64,
    expiring_days: u64,
    now: i64,
) -> Result<Value, OpError> {
    owner_session(state, scope)?;
    human_admin_on(state, scope, GLOBAL_ID, now)?;
    for (days, key) in [(stale_days, "staleDays"), (expiring_days, "expiringDays")] {
        if days == 0 || days > DAYS_MAX {
            return Err(OpError::Malformed(format!(
                "params.{key} is 1 to {DAYS_MAX}"
            )));
        }
    }
    // One scan at a time: a second one waits rather than doubling the work.
    let Ok(_running) = state.stable.doctor_scan_running.try_lock() else {
        return Err(OpError::RateLimited {
            retry_after_seconds: BUSY_RETRY_SECONDS,
        });
    };
    let entry_cap = state.doctor_scan_entry_cap();
    let started = Instant::now();

    // ---- what the caller may see: nodes and entries, copied out of the locks --------------------------
    let nodes: HashMap<String, NodeInfo> = state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .values()
        .map(|n| {
            (
                n.id.clone(),
                NodeInfo {
                    label: n.label.clone(),
                    parent: n.parent_id.clone(),
                    depth: n.depth,
                },
            )
        })
        .collect();
    let mut node_ids: Vec<&String> = nodes.keys().collect();
    node_ids.sort();

    let mut skipped: Vec<Value> = Vec::new();
    let mut seen: Vec<Seen> = Vec::new();
    let mut meta: Vec<ManifestEntry> = Vec::new();
    let mut value_nodes: Vec<(String, bool)> = Vec::new(); // (node, node-wide reveal)
    let mut truncated = false;
    let mut nodes_scanned = 0u64;
    for node in node_ids {
        if node == ORPHAN_ID {
            continue;
        }
        let skip = |reason: &str, what: &str| json!({ "node": node, "nodeLabel": nodes[node].label, "reason": reason, "what": what });
        if node_is_locked(state, node) {
            skipped.push(skip("locked", "all"));
            continue;
        }
        if !scannable(state, scope, node, now) {
            skipped.push(skip("second_factor", "all"));
            continue;
        }
        let (generation, visible): (u64, Vec<ManifestEntry>) = {
            let manifests = state.manifests.read().expect("manifests poisoned");
            let Some(body) = manifests.get(node.as_str()) else {
                continue;
            };
            match listable(state, scope, node, &body.entries, now) {
                Ok(v) => (body.generation, v.into_iter().cloned().collect()),
                Err(_) => {
                    skipped.push(skip("not_listed", "all"));
                    continue;
                }
            }
        };
        nodes_scanned += 1;
        let before = seen.len();
        for e in visible {
            if seen.len() >= entry_cap {
                truncated = true;
                break;
            }
            seen.push(Seen {
                node: node.clone(),
                entry: e.id.clone(),
                r#ref: e.r#ref,
                name: e.name.clone(),
                generation,
            });
            meta.push(e);
        }
        if seen.len() > before {
            // Values: only where the caller could reveal them now without being asked for more.
            if second_factor_gate(state, scope, node, GateKind::Reveal, now).is_err() {
                skipped.push(skip("second_factor", "values"));
            } else {
                let wide =
                    resolve_capability(state, scope, node, Capability::Reveal, now).is_allow();
                value_nodes.push((node.clone(), wide));
            }
        }
    }

    let mut report = Report {
        findings: BTreeMap::new(),
        truncated,
    };

    // ---- metadata: stale, expired, expiring ------------------------------------------------------------
    let stale_before = now.saturating_sub((stale_days as i64).saturating_mul(DAY));
    let horizon = now.saturating_add((expiring_days as i64).saturating_mul(DAY));
    for (s, m) in seen.iter().zip(&meta) {
        if let Some(at) = m.expires_at {
            if at <= horizon {
                let kind = if at <= now { "expired" } else { "expiring" };
                report.push(
                    kind,
                    json!({ "kind": kind, "entries": [s.to_json(&nodes)], "expiresAt": at, "source": "manifest" }),
                );
            }
        }
        let (last, basis) = match m.rotated_at {
            Some(r) => (r, "rotated"),
            None => (m.modified, "modified"),
        };
        if last < stale_before {
            report.push(
                "stale",
                json!({ "kind": "stale", "entries": [s.to_json(&nodes)], "lastChanged": last, "basis": basis }),
            );
        }
    }

    // ---- names: near-duplicates across the whole vault, and entries misfiled in global ----------------
    similar_name_findings(&seen, &nodes, started, &mut report);
    misfiled_findings(&seen, &nodes, &mut report);

    // ---- values: opened one entry at a time, digested under a key that dies with this call ------------
    let key = ScanKey::generate();
    let mut raw: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
    let mut norm: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
    let mut values_checked = 0u64;
    let wide: HashMap<&str, bool> = value_nodes.iter().map(|(n, w)| (n.as_str(), *w)).collect();
    'entries: for (idx, (s, m)) in seen.iter().zip(&meta).enumerate() {
        let Some(&node_wide) = wide.get(s.node.as_str()) else {
            continue;
        };
        if started.elapsed() > TIME_BUDGET {
            report.truncated = true;
            break 'entries;
        }
        if !node_wide
            && !resolve_entry_capability(state, scope, &s.node, &s.entry, Capability::Reveal, now)
                .is_allow()
        {
            continue;
        }
        let Some(node_priv) = state.hot_node_key(&s.node) else {
            continue; // locked since the listing: contributes nothing
        };
        let Ok(loaded) = crate::entry_doc::load(state, &s.node, &s.entry, &node_priv, Some(m))
        else {
            continue;
        };
        values_checked += 1;
        let node_env =
            name_environment(&s.node).or_else(|| name_environment(&nodes[&s.node].label));
        let entry_env = name_environment(&s.name);
        for field in &loaded.doc.fields {
            let value = field.value.as_str();
            let field_type = credmgr_core::fields::effective_type(field);
            if !skip_for_duplicates(value) {
                raw.entry(key.digest(value.as_bytes()))
                    .or_default()
                    .push(idx);
                if let Some(n) = normalised(value) {
                    let n = zeroize::Zeroizing::new(n);
                    norm.entry(key.digest(n.as_bytes())).or_default().push(idx);
                } else {
                    norm.entry(key.digest(value.as_bytes()))
                        .or_default()
                        .push(idx);
                }
            }
            let field_json = |extra: Value| {
                let mut f = json!({
                    "entries": [s.to_json(&nodes)],
                    "field": field.id,
                    "fieldLabel": field.label,
                });
                if let (Some(o), Some(e)) = (f.as_object_mut(), extra.as_object()) {
                    for (k, v) in e {
                        o.insert(k.clone(), v.clone());
                    }
                }
                f
            };
            if field_type == FieldType::Password && !is_otpauth_uri(value) {
                let reasons = weak_password(value);
                if !reasons.is_empty() {
                    let reasons: Vec<&str> = reasons.iter().map(|r| r.as_str()).collect();
                    report.push(
                        "weak",
                        field_json(json!({ "kind": "weak", "reasons": reasons })),
                    );
                }
            }
            if let Some(exp) = jwt_expiry(value) {
                // ADR-161: the one value-derived datum a report carries — a JWT's own expiry, which is what
                // `entry.set_expiry` would store for it (memo 03 §3.1), and only when it is in the window.
                if exp <= horizon && m.expires_at.is_none() {
                    let kind = if exp <= now { "expired" } else { "expiring" };
                    report.push(
                        kind,
                        field_json(json!({ "kind": kind, "expiresAt": exp, "source": "jwt" })),
                    );
                }
            }
            if field_type != FieldType::TotpSeed && is_otpauth_uri(value) {
                report.push(
                    "mistyped",
                    field_json(json!({ "kind": "mistyped", "reason": "otpauth_uri" })),
                );
            }
            if let Some(key_env) = key_environment(value) {
                let place = entry_env.or(node_env);
                let reason = match (key_env, place) {
                    (KeyEnvironment::Live, Some(KeyEnvironment::Test)) => Some("live_key_in_test"),
                    (KeyEnvironment::Test, Some(KeyEnvironment::Live)) => Some("test_key_in_live"),
                    _ => None,
                };
                if let Some(reason) = reason {
                    report.push(
                        "mistyped",
                        field_json(json!({ "kind": "mistyped", "reason": reason })),
                    );
                }
            }
        }
        drop(loaded);
    }
    drop(key);

    duplicate_findings(&seen, &nodes, raw, norm, &mut report);

    let mut counts = serde_json::Map::new();
    let mut findings: Vec<Value> = Vec::new();
    for kind in KINDS {
        let list = report.findings.remove(kind).unwrap_or_default();
        counts.insert((*kind).to_string(), json!(list.len()));
        findings.extend(list);
    }
    Ok(json!({
        "now": now,
        "staleDays": stale_days,
        "expiringDays": expiring_days,
        "nodesScanned": nodes_scanned,
        "entriesScanned": seen.len(),
        "valuesChecked": values_checked,
        "skipped": skipped,
        "truncated": report.truncated,
        "counts": counts,
        "findings": findings,
    }))
}

/// Pairs of names one separator or one edit apart (`credmgr_core::names::similar_names`, the check
/// `entry.similar` makes in one node), across every node scanned. Compared within a sliding window of
/// compact-key lengths, since a pair more than one character apart in length is never one edit apart.
fn similar_name_findings(
    seen: &[Seen],
    nodes: &HashMap<String, NodeInfo>,
    started: Instant,
    report: &mut Report,
) {
    let keys: Vec<(String, String)> = seen
        .iter()
        .map(|s| (canonical_name(&s.name), compact_key(&s.name)))
        .collect();
    let mut order: Vec<(usize, usize)> = keys
        .iter()
        .enumerate()
        .map(|(i, (_, k))| (k.chars().count(), i))
        .collect();
    order.sort_unstable();
    let mut compared = 0u64;
    for (pos, &(len_a, a)) in order.iter().enumerate() {
        for &(len_b, b) in &order[pos + 1..] {
            if len_b > len_a + 1 {
                break;
            }
            compared += 1;
            if compared % 4096 == 0 && started.elapsed() > TIME_BUDGET {
                report.truncated = true;
                return;
            }
            let Some(similarity) = similar_keys(&keys[a].0, &keys[a].1, &keys[b].0, &keys[b].1)
            else {
                continue;
            };
            let (first, second) = if a < b { (a, b) } else { (b, a) };
            report.push(
                "similar_names",
                json!({
                    "kind": "similar_names",
                    "similarity": similarity.as_str(),
                    "sameNode": seen[first].node == seen[second].node,
                    "entries": [seen[first].to_json(nodes), seen[second].to_json(nodes)],
                    "proposal": { "action": "rename_or_merge", "op": null },
                }),
            );
        }
    }
}

/// Doc 25's "misfiled scope": an entry in `global` (which every project and every agent reads) whose name
/// starts with one project's id or label as a whole word (`ACME_API_KEY` beside a project `acme`). Proposed:
/// move it to that project with `entry.move`. A name that matches more than one project proposes nothing.
fn misfiled_findings(seen: &[Seen], nodes: &HashMap<String, NodeInfo>, report: &mut Report) {
    let mut projects: Vec<(&String, Vec<String>)> = nodes
        .iter()
        .filter(|(id, n)| n.depth == 1 && id.as_str() != ORPHAN_ID)
        .map(|(id, n)| {
            let mut keys = vec![compact_key(id), compact_key(&n.label)];
            keys.retain(|k| k.chars().count() >= 3);
            keys.dedup();
            (id, keys)
        })
        .filter(|(_, keys)| !keys.is_empty())
        .collect();
    projects.sort_by(|a, b| a.0.cmp(b.0));
    for s in seen {
        if s.node != GLOBAL_ID {
            continue;
        }
        let first_word = s
            .name
            .split(|c: char| !c.is_alphanumeric())
            .find(|w| !w.is_empty())
            .map(compact_key)
            .unwrap_or_default();
        if first_word.is_empty() {
            continue;
        }
        let hits: Vec<&String> = projects
            .iter()
            .filter(|(_, keys)| keys.iter().any(|k| *k == first_word))
            .map(|(id, _)| *id)
            .collect();
        if let [to] = hits.as_slice() {
            report.push(
                "misfiled",
                json!({
                    "kind": "misfiled",
                    "entries": [s.to_json(nodes)],
                    "proposal": move_proposal(s, to, nodes, "move_to_project"),
                }),
            );
        }
    }
}

/// The applicable proposal: the exact `entry.move` parameters (the source's generation as the scan read
/// it, so a change since is `conflict` and the person re-scans).
fn move_proposal(s: &Seen, to: &str, nodes: &HashMap<String, NodeInfo>, action: &str) -> Value {
    json!({
        "action": action,
        "op": "entry.move",
        "to": to,
        "toLabel": nodes.get(to).map(|n| n.label.as_str()),
        "move": { "node": s.node, "entry": s.entry, "to": to, "generation": s.generation },
    })
}

/// The nodes from `node` up to `global`, nearest first.
fn ancestry(node: &str, nodes: &HashMap<String, NodeInfo>) -> Vec<String> {
    let mut out = vec![node.to_string()];
    let mut at = node.to_string();
    while let Some(parent) = nodes.get(&at).and_then(|n| n.parent.clone()) {
        if out.contains(&parent) {
            break;
        }
        out.push(parent.clone());
        at = parent;
    }
    out
}

/// Groups of entries that share a value: an exact (raw) match, or a probable one (equal only once
/// normalised). Each group gets the proposal memo 03 §3.2 orders by where the copies sit.
fn duplicate_findings(
    seen: &[Seen],
    nodes: &HashMap<String, NodeInfo>,
    raw: HashMap<[u8; 32], Vec<usize>>,
    norm: HashMap<[u8; 32], Vec<usize>>,
    report: &mut Report,
) {
    let groups = |map: HashMap<[u8; 32], Vec<usize>>| -> Vec<Vec<usize>> {
        let mut out: Vec<Vec<usize>> = map
            .into_values()
            .map(|mut v| {
                v.sort_unstable();
                v.dedup();
                v
            })
            .filter(|v| v.len() > 1)
            .collect();
        out.sort();
        out.dedup();
        out
    };
    let exact = groups(raw);
    let exact_sets: Vec<HashSet<usize>> =
        exact.iter().map(|g| g.iter().copied().collect()).collect();
    let probable: Vec<Vec<usize>> = groups(norm)
        .into_iter()
        .filter(|g| {
            let set: HashSet<usize> = g.iter().copied().collect();
            !exact_sets.iter().any(|e| set.is_subset(e))
        })
        .collect();
    for (group, matched) in exact
        .iter()
        .map(|g| (g, "exact"))
        .chain(probable.iter().map(|g| (g, "probable")))
    {
        let entries: Vec<Value> = group.iter().map(|i| seen[*i].to_json(nodes)).collect();
        report.push(
            "duplicate_value",
            json!({
                "kind": "duplicate_value",
                "match": matched,
                "entries": entries,
                "proposal": duplicate_proposal(group, seen, nodes),
            }),
        );
    }
}

/// Memo 03 §3.2, phase 1:
/// - every copy in one node → `merge` (one entry, the other names its aliases; report only);
/// - one copy already in a node every other copy's node descends from → `remove_copies` (the others are
///   redundant; report only);
/// - the copies' nearest common ancestor is a project (below `global`) → `move_to_parent`: move the first
///   copy there with `entry.move`, so every copy's node reads it; the person then removes the rest;
/// - otherwise (different projects) → `share`: keep it in one project and grant the others, or a shared
///   node (report only — grants need their own presence proof, a later phase).
fn duplicate_proposal(group: &[usize], seen: &[Seen], nodes: &HashMap<String, NodeInfo>) -> Value {
    let node_set: Vec<&str> = {
        let mut v: Vec<&str> = group.iter().map(|i| seen[*i].node.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    if node_set.len() == 1 {
        return json!({ "action": "merge", "op": null });
    }
    let chains: Vec<Vec<String>> = node_set.iter().map(|n| ancestry(n, nodes)).collect();
    // The nearest node on the first chain that every chain contains.
    let common = chains[0]
        .iter()
        .find(|candidate| chains.iter().all(|c| c.contains(candidate)))
        .cloned();
    if let Some(common) = common {
        if let Some(keeper) = group.iter().find(|i| seen[**i].node == common) {
            let k = &seen[*keeper];
            return json!({
                "action": "remove_copies",
                "op": null,
                "keep": { "node": k.node, "entry": k.entry, "name": k.name },
            });
        }
        if common != GLOBAL_ID {
            return move_proposal(&seen[group[0]], &common, nodes, "move_to_parent");
        }
    }
    json!({ "action": "share", "op": null, "options": ["grant", "shared_node"] })
}
