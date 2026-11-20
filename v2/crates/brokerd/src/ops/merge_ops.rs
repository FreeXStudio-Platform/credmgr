//! ADR-168 — `merge.*`: merge suggestions and merges inside one node, and the node's decision memory.
//!
//! * `merge.suggestions` — groups of entries in **one node** that look like one thing: `identical` (every
//!   entry holds the same multiset of values), `shared_value` (a value in common), `similar_names` (names a
//!   separator or an edit apart, `entry.similar`'s rule). Values are opened one entry at a time in here and
//!   digested under an HMAC key drawn for this call and dropped when it returns (`ScanKey`, ADR-161): no
//!   value, digest, length or fragment leaves, is logged or is stored.
//! * `merge.apply` — keep one entry; the others go through the `entry.remove` path (7-day archive, undoable
//!   with `entry.undo`), their names and aliases become the kept entry's aliases and their tags join its
//!   tags. The archive records what was added (`MergedInto`) so a restore takes it back off first.
//! * `merge.auto` / `merge.auto_all` — apply only `identical` groups; `auto_all` is a dry run unless told.
//! * `merge.dismiss` / `undismiss` / `dismissed_list` / `restore_all` — the decision memory, per node,
//!   sealed to the node's key in `nodes/<id>/merge.env` with its digest in the signed manifest (as a note).
//!
//! **Who:** the owner's login with `Admin` on the node, for all eight; every one is on the MCP forbidden list.
//! Never across a node: an id that is not in the named node is `not_found`, like a bogus one.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use credmgr_core::doctor::{skip_for_duplicates, ScanKey};
use credmgr_core::names::{compact_key, similar_names, ALIASES_MAX};
use credmgr_core::tags::{union_tags, TAGS_MAX};
use credmgr_store::entry_archive::MergedInto;

use super::node_gate_ops::require_fresh_factors_for;
use super::*;

/// The merge memory's "entry id" in its envelope (the AAD binds the file to its node and its purpose).
pub(crate) const MEMORY_ENVELOPE_ID: &str = "merge-memory";
/// The most entries one suggestion pass reads.
const ENTRY_CAP: usize = 2_000;
/// The most suggestions one answer carries.
const SUGGESTIONS_CAP: usize = 200;
/// The most entries one group (and so one merge) holds: one kept and up to 19 dropped.
const GROUP_MAX: usize = 20;
/// The most dismissed keys one node remembers.
const MEMORY_MAX: usize = 1_000;

// ---------------------------------------------------------------------------
// the decision memory
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct Memory {
    v: u32,
    dismissed: Vec<Dismissed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Dismissed {
    key: String,
    at: i64,
}

impl Memory {
    fn holds(&self, key: &str) -> bool {
        self.dismissed.iter().any(|d| d.key == key)
    }
}

/// The node's memory, opened under its key; empty when it has none. A file that does not match the digest
/// the signed manifest records is refused, as a note's is.
fn read_memory(state: &BrokerState, node: &str) -> Result<Memory, OpError> {
    let recorded = state.manifest_merge_digest(node);
    let path = state.paths.merge_env(node);
    let bytes = match credmgr_store::atomic::read(&path) {
        Ok(bytes) => bytes,
        Err(_) if recorded.is_none() => return Ok(Memory::default()),
        Err(_) => {
            return Err(OpError::Internal(
                "the manifest records a merge memory but its file is missing".into(),
            ))
        }
    };
    if recorded.as_deref() != Some(sha256_hex(&bytes).as_str()) {
        return Err(OpError::Internal(
            "the merge memory does not match the digest its manifest records".into(),
        ));
    }
    let Some(node_priv) = state.hot_node_key(node) else {
        return Err(locked_refusal(state, node));
    };
    let plain = envelope::open(&bytes, &node_priv, node, MEMORY_ENVELOPE_ID)
        .map_err(|_| OpError::Internal("the merge memory failed to open".into()))?;
    use secrecy::ExposeSecret;
    serde_json::from_slice(plain.expose_secret())
        .map_err(|_| OpError::Internal("the merge memory is not in the expected shape".into()))
}

/// Seal `memory` to the node's key (or remove the file when it is empty) and record its digest; returns the
/// node's new generation. The caller holds the node's write lock.
fn write_memory(state: &BrokerState, node: &str, memory: &Memory) -> Result<u64, OpError> {
    let path = state.paths.merge_env(node);
    if memory.dismissed.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(state.set_manifest_merge(node, None));
    }
    let node_pub = state
        .node_public_key(node)
        .ok_or_else(|| OpError::NotFound(format!("no node {node}")))?;
    let payload = serde_json::to_vec(&Memory {
        v: 1,
        dismissed: memory.dismissed.clone(),
    })
    .expect("a merge memory always serialises");
    let sealed = envelope::seal(&payload, &node_pub, node, MEMORY_ENVELOPE_ID)
        .map_err(|_| OpError::Internal("failed to seal the merge memory".into()))?;
    credmgr_store::atomic::write(&path, &sealed)
        .map_err(|e| OpError::Internal(format!("writing the merge memory: {e}")))?;
    Ok(state.set_manifest_merge(node, Some(sha256_hex(&sealed))))
}

// ---------------------------------------------------------------------------
// the gate every merge op shares
// ---------------------------------------------------------------------------

/// The owner's login, `Admin` on the node, a node that exists, is not the orphan node and is unlocked.
fn gate(state: &BrokerState, scope: &BrokerScope, node: &str, now: i64) -> Result<(), OpError> {
    owner_session(state, scope)?;
    if node == ORPHAN_ID {
        return Err(OpError::Malformed(
            "the orphan node holds sealed entries; nothing in it is merged".into(),
        ));
    }
    if !state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .contains_key(node)
    {
        return Err(OpError::NotFound(format!("no node {node}")));
    }
    human_admin_on(state, scope, node, now)?;
    if node_is_locked(state, node) {
        return Err(locked_refusal(state, node));
    }
    Ok(())
}

fn current_generation(state: &BrokerState, node: &str) -> u64 {
    state.manifest_generation(node).unwrap_or(0)
}

fn check_generation(state: &BrokerState, node: &str, expected: u64) -> Result<(), OpError> {
    let current = current_generation(state, node);
    if expected != current {
        return Err(OpError::Conflict {
            node_id: node.to_string(),
            expected_generation: expected,
            current_generation: current,
        });
    }
    Ok(())
}

/// A key is the group's entry ids, sorted and joined with `+` (2 to [`GROUP_MAX`] distinct ids).
fn key_of(ids: &[&str]) -> String {
    let mut sorted: Vec<&str> = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted.join("+")
}

fn parse_key(key: &str) -> Result<Vec<String>, OpError> {
    let ids: Vec<String> = key.split('+').map(str::to_string).collect();
    let well_formed = ids.len() >= 2
        && ids.len() <= GROUP_MAX
        && ids.windows(2).all(|w| w[0] < w[1])
        && ids.iter().all(|id| {
            id.starts_with("e_")
                && id.len() <= 64
                && id[2..].chars().all(|c| c.is_ascii_alphanumeric())
        });
    if well_formed {
        Ok(ids)
    } else {
        Err(OpError::Malformed(format!(
            "params.key is 2 to {GROUP_MAX} entry ids, sorted and joined with +, as merge.suggestions gives it"
        )))
    }
}

// ---------------------------------------------------------------------------
// suggestions
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Identical,
    SharedValue,
    SimilarNames,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Identical => "identical",
            Kind::SharedValue => "shared_value",
            Kind::SimilarNames => "similar_names",
        }
    }
}

struct Suggestion {
    key: String,
    kind: Kind,
    reasons: Vec<&'static str>,
    members: Vec<usize>,
    keep: usize,
}

struct Computed {
    generation: u64,
    rows: Vec<ManifestEntry>,
    values_compared: bool,
    truncated: bool,
    suggestions: Vec<Suggestion>,
}

impl Computed {
    fn to_json(&self, s: &Suggestion, dismissed: bool) -> Value {
        let entries: Vec<Value> = s
            .members
            .iter()
            .map(|&i| {
                let e = &self.rows[i];
                json!({ "entry": e.id, "ref": e.r#ref, "name": e.name })
            })
            .collect();
        let mut v = json!({
            "key": s.key,
            "kind": s.kind.as_str(),
            "reasons": s.reasons,
            "identical": s.kind == Kind::Identical,
            "keep": self.rows[s.keep].id,
            "entries": entries,
        });
        if dismissed {
            v["dismissed"] = json!(true);
        }
        v
    }
}

/// Add (or strengthen) the suggestion for `members`.
fn note_group(
    groups: &mut BTreeMap<String, Suggestion>,
    rows: &[ManifestEntry],
    mut members: Vec<usize>,
    kind: Kind,
    reason: &'static str,
    truncated: &mut bool,
) {
    members.sort_unstable();
    members.dedup();
    if members.len() < 2 {
        return;
    }
    if members.len() > GROUP_MAX {
        *truncated = true;
        return;
    }
    let ids: Vec<&str> = members.iter().map(|&i| rows[i].id.as_str()).collect();
    let key = key_of(&ids);
    let keep = *members
        .iter()
        .min_by_key(|&&i| (rows[i].r#ref, rows[i].id.clone()))
        .expect("at least two members");
    let s = groups.entry(key.clone()).or_insert(Suggestion {
        key,
        kind,
        reasons: Vec::new(),
        members,
        keep,
    });
    if kind < s.kind {
        s.kind = kind;
    }
    if !s.reasons.contains(&reason) {
        s.reasons.push(reason);
    }
}

/// Every suggestion for the node, dismissed or not. Values are compared only where the caller could reveal
/// them now without being asked for more; nothing derived from a value survives this function.
fn compute(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    now: i64,
) -> Result<Computed, OpError> {
    let (generation, mut rows): (u64, Vec<ManifestEntry>) = {
        let manifests = state.manifests.read().expect("manifests poisoned");
        manifests
            .get(node)
            .map_or((0, Vec::new()), |m| (m.generation, m.entries.clone()))
    };
    let mut truncated = false;
    if rows.len() > ENTRY_CAP {
        rows.truncate(ENTRY_CAP);
        truncated = true;
    }
    let mut groups: BTreeMap<String, Suggestion> = BTreeMap::new();

    // ---- values: digested under a key that dies with this call ---------------------------------------
    let values_compared = second_factor_gate(state, scope, node, GateKind::Reveal, now).is_ok();
    if values_compared {
        let Some(node_priv) = state.hot_node_key(node) else {
            return Err(locked_refusal(state, node));
        };
        let key = ScanKey::generate();
        let mut shared: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
        let mut whole: HashMap<Vec<[u8; 32]>, Vec<usize>> = HashMap::new();
        for (i, row) in rows.iter().enumerate() {
            let Ok(loaded) = crate::entry_doc::load(state, node, &row.id, &node_priv, Some(row))
            else {
                continue;
            };
            let mut signature: Vec<[u8; 32]> = Vec::with_capacity(loaded.doc.fields.len());
            let mut comparable = false;
            for field in &loaded.doc.fields {
                let value = field.value.as_str();
                let digest = key.digest(value.as_bytes());
                signature.push(digest);
                if !skip_for_duplicates(value) {
                    comparable = true;
                    shared.entry(digest).or_default().push(i);
                }
            }
            drop(loaded);
            if comparable {
                signature.sort_unstable();
                whole.entry(signature).or_default().push(i);
            }
        }
        drop(key);
        for (_, members) in whole {
            note_group(
                &mut groups,
                &rows,
                members,
                Kind::Identical,
                "same_values",
                &mut truncated,
            );
        }
        for (_, members) in shared {
            note_group(
                &mut groups,
                &rows,
                members,
                Kind::SharedValue,
                "shared_value",
                &mut truncated,
            );
        }
    }

    // ---- names: pairs a separator or one edit apart (a pair more than one character apart in length
    // is never one edit apart, so each name is compared only within that window) --------------------------
    let mut order: Vec<(usize, usize)> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| (compact_key(&r.name).chars().count(), i))
        .collect();
    order.sort_unstable();
    for (pos, &(len_a, a)) in order.iter().enumerate() {
        for &(len_b, b) in &order[pos + 1..] {
            if len_b > len_a + 1 {
                break;
            }
            if similar_names(&rows[a].name, &rows[b].name).is_some() {
                note_group(
                    &mut groups,
                    &rows,
                    vec![a, b],
                    Kind::SimilarNames,
                    "similar_names",
                    &mut truncated,
                );
            }
        }
    }

    let mut suggestions: Vec<Suggestion> = groups.into_values().collect();
    suggestions.sort_by(|x, y| x.kind.cmp(&y.kind).then_with(|| x.key.cmp(&y.key)));
    Ok(Computed {
        generation,
        rows,
        values_compared,
        truncated,
        suggestions,
    })
}

/// ADR-168: `merge.suggestions {node, includeDismissed?}`. Read-only.
pub(super) fn suggestions(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    include_dismissed: bool,
    now: i64,
) -> Result<Value, OpError> {
    gate(state, scope, node, now)?;
    let computed = compute(state, scope, node, now)?;
    let memory = read_memory(state, node)?;
    let mut truncated = computed.truncated;
    let mut out: Vec<Value> = Vec::new();
    for s in &computed.suggestions {
        let dismissed = memory.holds(&s.key);
        if dismissed && !include_dismissed {
            continue;
        }
        if out.len() >= SUGGESTIONS_CAP {
            truncated = true;
            break;
        }
        out.push(computed.to_json(s, dismissed));
    }
    Ok(json!({
        "node": node,
        "generation": computed.generation,
        "valuesCompared": computed.values_compared,
        "truncated": truncated,
        "dismissedCount": memory.dismissed.len(),
        "suggestions": out,
    }))
}

// ---------------------------------------------------------------------------
// applying a merge
// ---------------------------------------------------------------------------

struct Dropped {
    snapshot: ManifestEntry,
    added: Vec<String>,
}

struct Plan {
    keep: String,
    drops: Vec<Dropped>,
    aliases: Vec<String>,
    tags: Vec<String>,
    aliases_added: Vec<String>,
    tags_added: Vec<String>,
}

/// Why a group cannot be merged as asked: a code `merge.auto_all` reports, and the refusal `merge.apply`
/// answers.
struct Refusal {
    code: &'static str,
    error: Box<OpError>,
}

impl From<Refusal> for OpError {
    fn from(r: Refusal) -> Self {
        *r.error
    }
}

/// Everything a merge of `drops` into `keep` would write, checked against the node as it is now. Writes
/// nothing and asks for no factor.
fn plan(state: &BrokerState, node: &str, keep: &str, drops: &[String]) -> Result<Plan, Refusal> {
    let refuse = |code, error| Refusal {
        code,
        error: Box::new(error),
    };
    if drops.is_empty() || drops.len() >= GROUP_MAX {
        return Err(refuse(
            "shape",
            OpError::Malformed(format!(
                "params.drop holds 1 to {} entry ids",
                GROUP_MAX - 1
            )),
        ));
    }
    let mut seen: Vec<&str> = vec![keep];
    for d in drops {
        if seen.contains(&d.as_str()) {
            return Err(refuse(
                "shape",
                OpError::Malformed(format!(
                    "params.drop names {d} twice, or the entry that is kept"
                )),
            ));
        }
        seen.push(d);
    }
    let (kept, dropped): (ManifestEntry, Vec<ManifestEntry>) = {
        let manifests = state.manifests.read().expect("manifests poisoned");
        let rows = manifests
            .get(node)
            .map(|m| m.entries.as_slice())
            .unwrap_or(&[]);
        let find = |id: &str| {
            rows.iter().find(|e| e.id == id).cloned().ok_or_else(|| {
                refuse(
                    "missing",
                    OpError::NotFound(format!("no entry {id} on node {node}")),
                )
            })
        };
        let kept = find(keep)?;
        let dropped = drops
            .iter()
            .map(|d| find(d))
            .collect::<Result<Vec<_>, _>>()?;
        (kept, dropped)
    };
    {
        let registry = state.registry.read().expect("registry poisoned");
        if let Some(d) = dropped.iter().find(|d| {
            registry.grants.iter().any(|g| {
                matches!(&g.to, GrantTarget::Entry { node_id, entry_id }
                    if node_id == node && *entry_id == d.id)
            })
        }) {
            return Err(refuse(
                "grant",
                OpError::Malformed(format!(
                    "entry {} has a grant of its own; revoke it first, or keep that entry",
                    d.id
                )),
            ));
        }
    }
    let mut aliases = kept.aliases.clone();
    let mut aliases_added = Vec::new();
    let mut tags = kept.tags.clone();
    let mut plan_drops = Vec::with_capacity(dropped.len());
    for d in dropped {
        let mut added = Vec::new();
        for n in std::iter::once(&d.name).chain(d.aliases.iter()) {
            if !aliases
                .iter()
                .any(|a| canonical_name(a) == canonical_name(n))
            {
                aliases.push(n.clone());
                aliases_added.push(n.clone());
                added.push(n.clone());
            }
        }
        tags = union_tags(&tags, &d.tags);
        plan_drops.push(Dropped { snapshot: d, added });
    }
    if aliases.len() > ALIASES_MAX {
        return Err(refuse(
            "aliases",
            OpError::Malformed(format!(
                "the kept entry would answer to more than {ALIASES_MAX} aliases; merge fewer at a time"
            )),
        ));
    }
    if tags.len() > TAGS_MAX {
        return Err(refuse(
            "tags",
            OpError::Malformed(format!(
                "the kept entry would carry more than {TAGS_MAX} tags; remove some first"
            )),
        ));
    }
    let tags_added: Vec<String> = tags
        .iter()
        .filter(|t| !kept.tags.contains(t))
        .cloned()
        .collect();
    Ok(Plan {
        keep: keep.to_string(),
        drops: plan_drops,
        aliases,
        tags,
        aliases_added,
        tags_added,
    })
}

/// One planned merge to commit: the group's keep and drops, and its suggestion key when it came from one.
struct Group {
    keep: String,
    drops: Vec<String>,
    key: Option<String>,
}

/// Commit merges under the node's write lock, held from the generation check to the last manifest change:
/// the generation must still be `expected` (else `conflict`, nothing written), every group is planned again
/// against the node as it is under the lock (a group that no longer plans is refused, nothing written), and
/// each group is written so that a failure leaves it unapplied. The audit item events are appended after the
/// lock is released. Answers each group's part of the reply and the node's final generation.
fn commit(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    expected: u64,
    groups: Vec<Group>,
    now: i64,
) -> Result<(Vec<Value>, u64), OpError> {
    use secrecy::ExposeSecret;
    let node_lock = state.node_write_lock(node);
    let guard = node_lock.lock().expect("node write lock poisoned");
    check_generation(state, node, expected)?;
    let mut plans: Vec<(Plan, Option<String>)> = Vec::with_capacity(groups.len());
    for g in groups {
        let p = plan(state, node, &g.keep, &g.drops).map_err(OpError::from)?;
        plans.push((p, g.key));
    }
    let root_key = state.reauth_root_key("merge apply").map_err(|_| {
        OpError::Internal("could not re-derive the root key to archive the merged entries".into())
    })?;
    let rk = root_key.expose_secret();

    let mut written: Vec<(Plan, Option<String>, u64)> = Vec::with_capacity(plans.len());
    for (p, key) in plans {
        match write_one(state, node, &p, rk, now) {
            Ok(generation) => written.push((p, key, generation)),
            Err(e) => {
                let note = if written.is_empty() {
                    String::new()
                } else {
                    format!(
                        " ({} earlier group(s) were merged and stay undoable)",
                        written.len()
                    )
                };
                drop(guard);
                record_groups(state, scope, node, &written, now);
                return Err(OpError::Internal(format!("{e}{note}")));
            }
        }
    }
    drop(guard);
    let generation = written
        .last()
        .map_or_else(|| current_generation(state, node), |(_, _, g)| *g);
    Ok((record_groups(state, scope, node, &written, now), generation))
}

/// Write one planned merge under the held lock: every dropped entry into its removal archive (recording
/// what its names became), then the kept entry's aliases and tags, then the dropped rows out of the
/// manifest. Any failure puts the archived envelopes back and changes no manifest row.
fn write_one(
    state: &BrokerState,
    node: &str,
    plan: &Plan,
    rk: &[u8; 32],
    now: i64,
) -> Result<u64, String> {
    let rollback = |archived: &[&str]| {
        for id in archived {
            let _ = credmgr_store::entry_archive::restore(&state.paths, rk, node, id, now);
        }
    };
    let mut archived: Vec<&str> = Vec::new();
    for d in &plan.drops {
        let record = MergedInto {
            entry: plan.keep.clone(),
            aliases: d.added.clone(),
        };
        if let Err(e) = credmgr_store::entry_archive::remove_merged(
            &state.paths,
            rk,
            node,
            &d.snapshot,
            now,
            record,
        ) {
            rollback(&archived);
            return Err(format!("archiving a merged entry (rolled back): {e}"));
        }
        archived.push(&d.snapshot.id);
    }
    let kept = state.update_manifest_entry(node, &plan.keep, |e| {
        e.aliases.clone_from(&plan.aliases);
        e.tags.clone_from(&plan.tags);
        e.modified = now;
    });
    if kept.is_none() {
        rollback(&archived);
        return Err("the kept entry is gone (rolled back)".into());
    }
    let ids: Vec<String> = plan.drops.iter().map(|d| d.snapshot.id.clone()).collect();
    state.remove_manifest_entries(node, &ids);
    Ok(current_generation(state, node))
}

/// The audit item events of the written groups (one `entry.remove` per dropped entry, whose id `entry.undo`
/// takes, and one `merge.apply` on the kept entry), and each group's part of the reply.
fn record_groups(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    written: &[(Plan, Option<String>, u64)],
    now: i64,
) -> Vec<Value> {
    let mut parts = Vec::with_capacity(written.len());
    for (plan, key, generation) in written {
        let mut merged = Vec::with_capacity(plan.drops.len());
        for d in &plan.drops {
            // ADR-055: this record is what `entry.undo` takes to bring the entry back.
            let undo = crate::server::record_item_event(
                state,
                scope,
                now,
                "entry.remove",
                node,
                &d.snapshot.id,
                Some(*generation),
                &format!("merged into {}", plan.keep),
            );
            merged.push(json!({ "entry": d.snapshot.id, "name": d.snapshot.name, "undo": undo }));
        }
        crate::server::record_item_event(
            state,
            scope,
            now,
            "merge.apply",
            node,
            &plan.keep,
            Some(*generation),
            &format!("kept; absorbed {}", plan.drops.len()),
        );
        let mut part = json!({
            "keep": plan.keep,
            "merged": merged,
            "aliasesAdded": plan.aliases_added,
            "tagsAdded": plan.tags_added,
        });
        if let Some(k) = key {
            part["key"] = json!(k);
        }
        parts.push(part);
    }
    parts
}

/// The kept entry and the dropped ones of a suggestion.
fn group_of(computed: &Computed, s: &Suggestion) -> Group {
    Group {
        keep: computed.rows[s.keep].id.clone(),
        drops: s
            .members
            .iter()
            .filter(|&&i| i != s.keep)
            .map(|&i| computed.rows[i].id.clone())
            .collect(),
        key: Some(s.key.clone()),
    }
}

/// ADR-168: `merge.apply {node, keep, drop[], generation}`. The checks before the second factor (generation,
/// plan) are made again under the node's write lock in [`commit`].
pub(super) fn apply(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    keep: &str,
    drops: &[String],
    expected_generation: u64,
    now: i64,
) -> Result<Value, OpError> {
    gate(state, scope, node, now)?;
    check_generation(state, node, expected_generation)?;
    plan(state, node, keep, drops)?;
    require_fresh_factors_for(state, node, now)?;
    let group = Group {
        keep: keep.to_string(),
        drops: drops.to_vec(),
        key: None,
    };
    let (mut parts, generation) =
        commit(state, scope, node, expected_generation, vec![group], now)?;
    let mut body = parts.pop().unwrap_or_else(|| json!({}));
    body["node"] = json!(node);
    body["generation"] = json!(generation);
    Ok(body)
}

/// ADR-168: `merge.auto {node, key, generation}` — one suggestion, only when it is `identical`. The values
/// were compared at the generation the suggestion pass read; [`commit`] refuses if the node moved since.
pub(super) fn auto(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    key: &str,
    expected_generation: u64,
    now: i64,
) -> Result<Value, OpError> {
    parse_key(key)?;
    gate(state, scope, node, now)?;
    check_generation(state, node, expected_generation)?;
    let computed = compute(state, scope, node, now)?;
    if computed.generation != expected_generation {
        return Err(OpError::Conflict {
            node_id: node.to_string(),
            expected_generation,
            current_generation: computed.generation,
        });
    }
    let memory = read_memory(state, node)?;
    let Some(s) = computed
        .suggestions
        .iter()
        .find(|s| s.key == key && !memory.holds(key))
    else {
        return Err(OpError::Malformed(
            "params.key is not an open suggestion for this node (dismissed, gone, or never suggested)"
                .into(),
        ));
    };
    if s.kind != Kind::Identical {
        return Err(OpError::Malformed(
            "merge.auto merges only entries whose values are all identical; use merge.apply to choose"
                .into(),
        ));
    }
    let group = group_of(&computed, s);
    plan(state, node, &group.keep, &group.drops)?;
    require_fresh_factors_for(state, node, now)?;
    let (mut parts, generation) =
        commit(state, scope, node, expected_generation, vec![group], now)?;
    let mut body = parts.pop().unwrap_or_else(|| json!({}));
    body["node"] = json!(node);
    body["generation"] = json!(generation);
    Ok(body)
}

/// ADR-168: `merge.auto_all {node, apply?, generation?}` — every open `identical` suggestion; a dry run that
/// writes nothing unless `apply: true`. Applied groups are committed together under one hold of the node's
/// write lock, at the generation the suggestion pass read.
pub(super) fn auto_all(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    apply: bool,
    expected_generation: Option<u64>,
    now: i64,
) -> Result<Value, OpError> {
    gate(state, scope, node, now)?;
    let expected = if apply {
        let expected = expected_generation.ok_or_else(|| {
            OpError::Malformed("params.generation is required with apply: true".into())
        })?;
        check_generation(state, node, expected)?;
        Some(expected)
    } else {
        None
    };
    let computed = compute(state, scope, node, now)?;
    if let Some(expected) = expected {
        if computed.generation != expected {
            return Err(OpError::Conflict {
                node_id: node.to_string(),
                expected_generation: expected,
                current_generation: computed.generation,
            });
        }
    }
    let memory = read_memory(state, node)?;
    let mut planned: Vec<(Value, Group)> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    for s in computed
        .suggestions
        .iter()
        .filter(|s| s.kind == Kind::Identical && !memory.holds(&s.key))
    {
        let group = group_of(&computed, s);
        let row = computed.to_json(s, false);
        match plan(state, node, &group.keep, &group.drops) {
            Ok(_) => planned.push((row, group)),
            Err(r) => {
                skipped.push(json!({ "key": s.key, "reason": r.code, "entries": row["entries"] }))
            }
        }
    }
    let planned_json: Vec<Value> = planned.iter().map(|(v, _)| v.clone()).collect();
    let Some(expected) = expected else {
        return Ok(json!({
            "node": node,
            "dryRun": true,
            "valuesCompared": computed.values_compared,
            "generation": computed.generation,
            "planned": planned_json,
            "skipped": skipped,
        }));
    };
    let (merged, generation) = if planned.is_empty() {
        (Vec::new(), computed.generation)
    } else {
        require_fresh_factors_for(state, node, now)?;
        let groups: Vec<Group> = planned.into_iter().map(|(_, g)| g).collect();
        commit(state, scope, node, expected, groups, now)?
    };
    Ok(json!({
        "node": node,
        "dryRun": false,
        "valuesCompared": computed.values_compared,
        "planned": planned_json,
        "merged": merged,
        "skipped": skipped,
        "generation": generation,
    }))
}

// ---------------------------------------------------------------------------
// the decision memory ops
// ---------------------------------------------------------------------------

/// ADR-168: `merge.dismiss {node, key}` — the group never comes back until undismissed or restored.
pub(super) fn dismiss(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    key: &str,
    now: i64,
) -> Result<Value, OpError> {
    let ids = parse_key(key)?;
    gate(state, scope, node, now)?;
    let node_lock = state.node_write_lock(node);
    let _guard = node_lock.lock().expect("node write lock poisoned");
    {
        let manifests = state.manifests.read().expect("manifests poisoned");
        let rows = manifests
            .get(node)
            .map(|m| m.entries.as_slice())
            .unwrap_or(&[]);
        if let Some(missing) = ids.iter().find(|id| !rows.iter().any(|e| &e.id == *id)) {
            return Err(OpError::NotFound(format!(
                "no entry {missing} on node {node}"
            )));
        }
    }
    let mut memory = read_memory(state, node)?;
    if memory.holds(key) {
        return Ok(json!({
            "node": node, "key": key, "dismissed": true, "already": true,
            "generation": current_generation(state, node),
        }));
    }
    if memory.dismissed.len() >= MEMORY_MAX {
        return Err(OpError::Malformed(format!(
            "this node already remembers {MEMORY_MAX} dismissed suggestions; restore some first"
        )));
    }
    memory.dismissed.push(Dismissed {
        key: key.to_string(),
        at: now,
    });
    let generation = write_memory(state, node, &memory)?;
    Ok(json!({ "node": node, "key": key, "dismissed": true, "generation": generation }))
}

/// ADR-168: `merge.undismiss {node, key}` — the group is suggested again.
pub(super) fn undismiss(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    key: &str,
    now: i64,
) -> Result<Value, OpError> {
    parse_key(key)?;
    gate(state, scope, node, now)?;
    let node_lock = state.node_write_lock(node);
    let _guard = node_lock.lock().expect("node write lock poisoned");
    let mut memory = read_memory(state, node)?;
    let before = memory.dismissed.len();
    memory.dismissed.retain(|d| d.key != key);
    if memory.dismissed.len() == before {
        return Ok(json!({
            "node": node, "key": key, "restored": false,
            "generation": current_generation(state, node),
        }));
    }
    let generation = write_memory(state, node, &memory)?;
    Ok(json!({ "node": node, "key": key, "restored": true, "generation": generation }))
}

/// ADR-168: `merge.dismissed_list {node}` — what the node remembers, newest first, with the names of the
/// entries still in it (`null` for one that is gone).
pub(super) fn dismissed_list(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    now: i64,
) -> Result<Value, OpError> {
    gate(state, scope, node, now)?;
    let memory = read_memory(state, node)?;
    let manifests = state.manifests.read().expect("manifests poisoned");
    let rows = manifests
        .get(node)
        .map(|m| m.entries.as_slice())
        .unwrap_or(&[]);
    let mut list: Vec<&Dismissed> = memory.dismissed.iter().collect();
    list.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.key.cmp(&b.key)));
    let out: Vec<Value> = list
        .into_iter()
        .map(|d| {
            let entries: Vec<Value> = d
                .key
                .split('+')
                .map(|id| {
                    let name = rows.iter().find(|e| e.id == id).map(|e| e.name.clone());
                    json!({ "entry": id, "name": name })
                })
                .collect();
            json!({ "key": d.key, "entries": entries, "dismissedAt": d.at })
        })
        .collect();
    Ok(json!({ "node": node, "dismissed": out }))
}

/// ADR-168: `merge.restore_all {node}` — forget every dismissal on the node.
pub(super) fn restore_all(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    now: i64,
) -> Result<Value, OpError> {
    gate(state, scope, node, now)?;
    let node_lock = state.node_write_lock(node);
    let _guard = node_lock.lock().expect("node write lock poisoned");
    let memory = read_memory(state, node)?;
    let restored = memory.dismissed.len();
    if restored == 0 {
        return Ok(json!({
            "node": node, "restored": 0, "generation": current_generation(state, node),
        }));
    }
    let generation = write_memory(state, node, &Memory::default())?;
    Ok(json!({ "node": node, "restored": restored, "generation": generation }))
}
