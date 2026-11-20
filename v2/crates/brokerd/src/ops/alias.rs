//! ADR-121 (aliases, near-duplicate names) and ADR-122 (`.env` import) - three
//! ops that live in their own file so `ops.rs` only gains three delegating arms.
//!
//! * `entry.alias` - set the other names one entry answers to.
//! * `entry.similar` - which existing names look like a candidate name.
//! * `entry.import_env` - a parsed `.env` file into one node: a dry run that lists
//!   names and conflicts, or the write, one audited entry at a time.
//!
//! A child module of `ops`, so the private helpers of the parent (capability
//! resolution, the name-space checks, `create_entry`) are used as they are; none is
//! duplicated here. **Nothing in this file puts a value into an answer, an error or
//! an audit record.** A value appears in `entry.import_env` only as the input that
//! is sealed.

use super::*;

use credmgr_core::names::{similar_names, Similarity, ALIASES_MAX};

/// The most near-duplicates one answer lists.
const SIMILAR_MAX: usize = 20;
/// `entry.import_env` lists at most this many near-duplicates beside one name.
const IMPORT_SIMILAR_MAX: usize = 3;

/// One existing name (or alias) in the node a candidate resembles.
struct Near {
    id: String,
    name: String,
    alias: Option<String>,
    why: Similarity,
}

impl Near {
    fn to_json(&self) -> Value {
        let mut row = json!({ "id": self.id, "name": self.name, "reason": self.why.as_str() });
        if let Some(alias) = &self.alias {
            row["alias"] = json!(alias);
        }
        row
    }
}

/// The existing entries of `node` whose name or alias is a near-duplicate of
/// `candidate`, never `skip` (the entry the candidate belongs to).
fn near_names(
    state: &BrokerState,
    node: &str,
    candidate: &str,
    skip: Option<&str>,
    max: usize,
) -> Vec<Near> {
    let manifests = state.manifests.read().expect("manifests poisoned");
    let mut out = Vec::new();
    let Some(body) = manifests.get(node) else {
        return out;
    };
    for e in &body.entries {
        if skip == Some(e.id.as_str()) {
            continue;
        }
        if let Some(why) = similar_names(candidate, &e.name) {
            out.push(Near {
                id: e.id.clone(),
                name: e.name.clone(),
                alias: None,
                why,
            });
        } else if let Some((alias, why)) = e
            .aliases
            .iter()
            .find_map(|a| similar_names(candidate, a).map(|w| (a, w)))
        {
            out.push(Near {
                id: e.id.clone(),
                name: e.name.clone(),
                alias: Some(alias.clone()),
                why,
            });
        }
        if out.len() >= max {
            break;
        }
    }
    out
}

/// A name or alias the person supplies: bounded, not empty, no control characters.
fn valid_supplied_name(raw: &str, what: &str) -> Result<(), OpError> {
    valid_entry_name(raw, what)?;
    if raw.trim().is_empty() || raw.chars().any(char::is_control) {
        return Err(OpError::Malformed(format!(
            "{what} must have a visible character and no control characters"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// entry.alias
// ---------------------------------------------------------------------------

/// ADR-121: replace the aliases of one entry. Human sessions only (an alias is
/// how the owner names things; the MCP surface has no such tool), the `update`
/// capability on the node (so a locked node refuses, R1), the node's write lock
/// and F-9's generation check. Metadata only: the sealed envelope is not read or
/// rewritten, so it works on exactly the entries `entry.update` could touch and
/// reads no value.
pub(super) fn entry_alias(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    target_node: &str,
    entry_id: &str,
    expected_generation: u64,
    raw: &[Value],
) -> Result<Value, OpError> {
    if raw.len() > ALIASES_MAX {
        return Err(OpError::Malformed(format!(
            "params.aliases holds at most {ALIASES_MAX} names"
        )));
    }
    let mut aliases: Vec<String> = Vec::with_capacity(raw.len());
    let mut seen: HashSet<String> = HashSet::new();
    for (i, a) in raw.iter().enumerate() {
        let what = format!("params.aliases[{i}]");
        let a = a
            .as_str()
            .ok_or_else(|| OpError::Malformed(format!("{what} must be a string")))?;
        valid_supplied_name(a, &what)?;
        if !seen.insert(canonical_name(a)) {
            return Err(OpError::Malformed(format!(
                "{what} is the same name as an earlier alias in this list"
            )));
        }
        aliases.push(a.to_string());
    }

    // ADR-110: a caller who may not see this node's names is never told that one exists, and a refused alias would say so.
    if scope.origin == Origin::Agent
        || !scope.holds(Capability::Update)
        || node_hides_names(state, scope, target_node)
    {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Update,
        });
    }
    let decision = resolve_capability(state, scope, target_node, Capability::Update, now);
    if !decision.is_allow() {
        if decision.rule() == access::Rule::R1 {
            return Err(locked_refusal(state, target_node));
        }
        return Err(access_denied_error(
            state,
            scope,
            target_node,
            Capability::Update,
            rule_name(decision),
            now,
        ));
    }

    let node_lock = state.node_write_lock(target_node);
    let _guard = node_lock.lock().expect("node write lock poisoned");

    {
        let manifests = state.manifests.read().expect("manifests poisoned");
        let body = manifests.get(target_node);
        let current_generation = body.map_or(0, |b| b.generation);
        let Some(entry) = body.and_then(|b| b.entries.iter().find(|e| e.id == entry_id)) else {
            return Err(OpError::NotFound(format!(
                "no entry {entry_id} on node {target_node}"
            )));
        };
        if expected_generation != current_generation {
            return Err(OpError::Conflict {
                node_id: target_node.to_string(),
                expected_generation,
                current_generation,
            });
        }
        let own = canonical_name(&entry.name);
        let pending = state.list_pending(target_node);
        for (i, alias) in aliases.iter().enumerate() {
            let canon = canonical_name(alias);
            if canon == own {
                return Err(OpError::Malformed(format!(
                    "params.aliases[{i}] is the entry's own name"
                )));
            }
            let others = body
                .into_iter()
                .flat_map(|b| b.entries.iter())
                .filter(|e| e.id != entry_id)
                .flat_map(entry_names);
            if canon_taken(&canon, others)
                || canon_taken(&canon, pending.iter().map(|p| p.name.as_str()))
            {
                return Err(OpError::EntryExists {
                    node: target_node.to_string(),
                    name: alias.clone(),
                });
            }
        }
    }

    let generation = state
        .update_manifest_entry(target_node, entry_id, |e| {
            e.aliases.clone_from(&aliases);
            e.modified = now;
        })
        .expect("presence already checked above, under the same held write lock");

    let mut body = json!({
        "node": target_node, "entry": entry_id, "generation": generation,
        "aliases": aliases,
    });
    let typed: Vec<&str> = aliases.iter().map(String::as_str).collect();
    name_warnings(&mut body, &typed);
    if !node_hides_names(state, scope, target_node) {
        let mut similar: Vec<Value> = Vec::new();
        for alias in &aliases {
            for n in near_names(state, target_node, alias, Some(entry_id), SIMILAR_MAX) {
                similar.push(n.to_json());
            }
        }
        similar.truncate(SIMILAR_MAX);
        if !similar.is_empty() {
            body["similar"] = Value::Array(similar);
        }
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// entry.similar
// ---------------------------------------------------------------------------

/// ADR-121: a read. Which entries of the node have a name or an alias that is a
/// near-duplicate of `name`, and whether `name` is already taken exactly. The
/// `list` capability and exactly the entries `entry.list` would show this caller;
/// a node whose names are hidden from the caller answers `nameHidden` and lists
/// nothing (ADR-083).
pub(super) fn entry_similar(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    target_node: &str,
    name: &str,
    entry: Option<&Value>,
) -> Result<Value, OpError> {
    valid_supplied_name(name, "params.name")?;
    let skip = match entry {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => {
            return Err(OpError::Malformed(
                "params.entry must be a string when given".into(),
            ))
        }
    };
    if !scope.holds(Capability::List) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::List,
        });
    }
    let decision = resolve_capability(state, scope, target_node, Capability::List, now);
    if !decision.is_allow() {
        return Err(access_denied_error(
            state,
            scope,
            target_node,
            Capability::List,
            rule_name(decision),
            now,
        ));
    }
    second_factor_gate(state, scope, target_node, GateKind::Read, now)?;
    if node_hides_names(state, scope, target_node) {
        return Ok(json!({ "node": target_node, "nameHidden": true, "similar": [] }));
    }
    let canon = canonical_name(name);
    let taken = {
        let manifests = state.manifests.read().expect("manifests poisoned");
        let pending = state.list_pending(target_node);
        manifests.get(target_node).is_some_and(|m| {
            canon_taken(
                &canon,
                m.entries
                    .iter()
                    .filter(|e| skip != Some(e.id.as_str()))
                    .flat_map(entry_names),
            )
        }) || canon_taken(&canon, pending.iter().map(|p| p.name.as_str()))
    };
    let similar: Vec<Value> = near_names(state, target_node, name, skip, SIMILAR_MAX)
        .iter()
        .map(Near::to_json)
        .collect();
    Ok(json!({ "node": target_node, "name": name, "taken": taken, "similar": similar }))
}

// ---------------------------------------------------------------------------
// entry.import_env
// ---------------------------------------------------------------------------

/// What one pair of a `.env` import would become.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    /// A new entry.
    New,
    /// The name (or an alias) is already on the node, or waits in the tray.
    Exists,
    /// An earlier pair of this same import has the name.
    Duplicate,
    /// The value is empty: an `.env.example` placeholder, never an entry.
    Empty,
    /// The name is empty, too long or has a control character.
    Invalid,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::New => "new",
            Status::Exists => "exists",
            Status::Duplicate => "duplicate",
            Status::Empty => "empty",
            Status::Invalid => "invalid",
        }
    }
}

const IMPORT_KEYS: &[&str] = &["name", "value"];

/// ADR-122: a parsed `.env` file (name/value pairs the client read) into one
/// node. `dryRun: true` writes nothing and says, for every pair, what it would
/// become (`new`, `exists`, `duplicate`, `empty`, `invalid`) and which existing
/// names it resembles; without it the `new` pairs are written, each as its own
/// entry with its own audit record. `onConflict` is `refuse` (the default: one
/// conflicting pair and nothing is written) or `skip` (conflicts are reported
/// and left out). An invalid name is always a refusal. **No answer carries a
/// value.**
pub(super) fn entry_import_env(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    target_node: &str,
    items: &[Value],
    dry_run: Option<&Value>,
    on_conflict: Option<&Value>,
) -> Result<Value, OpError> {
    if items.is_empty() || items.len() > BATCH_MAX {
        return Err(OpError::Malformed(format!(
            "params.entries must hold 1–{BATCH_MAX} pairs"
        )));
    }
    let dry_run = match dry_run {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(OpError::Malformed("params.dryRun must be a boolean".into())),
    };
    let skip_conflicts = match on_conflict {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) if s == "refuse" => false,
        Some(Value::String(s)) if s == "skip" => true,
        Some(_) => {
            return Err(OpError::Malformed(
                "params.onConflict must be \"refuse\" or \"skip\"".into(),
            ))
        }
    };

    if !scope.holds(Capability::Create) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Create,
        });
    }
    let decision = resolve_capability(state, scope, target_node, Capability::Create, now);
    if !decision.is_allow() {
        return Err(access_denied_error(
            state,
            scope,
            target_node,
            Capability::Create,
            rule_name(decision),
            now,
        ));
    }
    // ADR-148 (P3): a dry run answers which names exist and which are near — a read of the node, so it
    // passes the node's read gate (ADR-085: `requireTwoFactor: always`, or a node's own second factor) as
    // `entry.list` and `entry.similar` do.
    if dry_run {
        super::second_factor_gate(state, scope, target_node, super::GateKind::Read, now)?;
    }

    // Shape first: every refusal here names an index, never a name or a value.
    let mut pairs: Vec<(&str, &str)> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let obj = item
            .as_object()
            .ok_or_else(|| OpError::Malformed(format!("entries[{i}] must be an object")))?;
        if obj.keys().any(|k| !IMPORT_KEYS.contains(&k.as_str())) {
            return Err(OpError::Malformed(format!(
                "entries[{i}] has a key that is not one of: {}",
                IMPORT_KEYS.join(", ")
            )));
        }
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| OpError::Malformed(format!("entries[{i}].name is required")))?;
        let value = obj
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| OpError::Malformed(format!("entries[{i}].value is required")))?;
        pairs.push((name, value));
    }

    // The plan: one status per pair, from the node as it is now. The node's write
    // lock is NOT held across the writes below: `create_entry` takes it itself
    // (and a second `lock()` on the same mutex would wait on its own thread). If
    // a name is taken between this plan and its write, `create_entry` refuses it
    // and the answer says `complete: false` with where it stopped, as a batch does.
    // ADR-110: on a `privateNames` node a name-blind caller is never told a name exists: a collision is answered like a miss and
    // `create_entry` writes it under a free name made from the typed one, as `entry.create_batch` does.
    let hidden = node_hides_names(state, scope, target_node);
    let statuses: Vec<Status> = {
        let manifests = state.manifests.read().expect("manifests poisoned");
        let pending = state.list_pending(target_node);
        let existing = manifests.get(target_node);
        let mut seen: HashSet<String> = HashSet::new();
        pairs
            .iter()
            .map(|(name, value)| {
                if valid_supplied_name(name, "name").is_err() {
                    return Status::Invalid;
                }
                if value.is_empty() {
                    return Status::Empty;
                }
                let canon = canonical_name(name);
                if !hidden
                    && (existing.is_some_and(|m| {
                        canon_taken(&canon, m.entries.iter().flat_map(entry_names))
                    }) || canon_taken(&canon, pending.iter().map(|p| p.name.as_str())))
                {
                    return Status::Exists;
                }
                if !seen.insert(canon) {
                    return Status::Duplicate;
                }
                Status::New
            })
            .collect()
    };
    let count = |s: Status| statuses.iter().filter(|x| **x == s).count();
    let counts = json!({
        "new": count(Status::New), "exists": count(Status::Exists),
        "duplicate": count(Status::Duplicate), "empty": count(Status::Empty),
        "invalid": count(Status::Invalid),
    });

    if dry_run {
        let rows: Vec<Value> = pairs
            .iter()
            .zip(&statuses)
            .map(|((name, _), status)| {
                let mut row = json!({ "name": name, "status": status.as_str() });
                if *status == Status::New && !hidden {
                    let near: Vec<Value> =
                        near_names(state, target_node, name, None, IMPORT_SIMILAR_MAX)
                            .iter()
                            .map(Near::to_json)
                            .collect();
                    if !near.is_empty() {
                        row["similar"] = Value::Array(near);
                    }
                }
                row
            })
            .collect();
        let typed: Vec<&str> = pairs.iter().map(|(n, _)| *n).collect();
        let mut body = json!({
            "node": target_node, "dryRun": true, "total": pairs.len(),
            "items": rows, "counts": counts,
        });
        name_warnings(&mut body, &typed);
        return Ok(body);
    }

    // The write. An invalid name is a refusal in either mode; a conflict is a
    // refusal unless the caller said `skip`. Nothing has been written yet.
    for (i, ((name, _), status)) in pairs.iter().zip(&statuses).enumerate() {
        match status {
            Status::Invalid => {
                return Err(OpError::Malformed(format!(
                    "entries[{i}].name is empty, longer than {ENTRY_NAME_MAX} characters, or has a control character"
                )))
            }
            Status::Exists if !skip_conflicts => {
                return Err(OpError::EntryExists {
                    node: target_node.to_string(),
                    name: (*name).to_string(),
                })
            }
            Status::Duplicate if !skip_conflicts => {
                return Err(OpError::Malformed(format!(
                    "entries[{i}]: the name {name:?} appears twice in this import"
                )))
            }
            _ => {}
        }
    }
    // Build every document before the first write, so a pair that cannot be
    // sealed refuses the whole call rather than stopping it half-way.
    let mut docs: Vec<(usize, EntryDoc)> = Vec::new();
    let mut total_bytes: usize = 0;
    for (i, ((_, value), status)) in pairs.iter().zip(&statuses).enumerate() {
        if *status != Status::New {
            continue;
        }
        let doc = CreateBody {
            value: Some(value),
            label: None,
            fields: None,
            entry_type: fields::Override::Keep,
            sensitivity: fields::Override::Keep,
        }
        .into_doc()
        .map_err(|e| match e {
            OpError::Malformed(m) => OpError::Malformed(format!("entries[{i}]: {m}")),
            other => other,
        })?;
        total_bytes = total_bytes.saturating_add(entry_doc::encoded_len(&doc)?);
        if total_bytes > entry_doc::BATCH_MAX_BYTES {
            return Err(OpError::Malformed(format!(
                "params.entries hold more than {} MiB in all; split the import",
                entry_doc::BATCH_MAX_BYTES / (1024 * 1024)
            )));
        }
        docs.push((i, doc));
    }

    let mut created = Vec::with_capacity(docs.len());
    let mut generation = Value::Null;
    let mut failed = Value::Null;
    for (i, doc) in &docs {
        let name = pairs[*i].0;
        // ADR-141: an agent on a node whose security level holds creates writes to the review tray, exactly as `entry.create_batch` does.
        let hold = is_agent_caller(scope) && security_level_of(state, target_node).create_is_held();
        match create_entry(state, target_node, name, doc, now, hidden, hold) {
            Ok(c) => {
                if let Some(g) = c.generation {
                    generation = json!(g);
                }
                // ADR-122: one audited write per entry. The request's own record
                // says "entry.import_env"; this one says "entry.create" for this
                // entry, so the trail reads as if each had been added on its own.
                // An id and a fixed word - never the name, never a value.
                let _ = crate::server::record_item_event(
                    state,
                    scope,
                    now,
                    "entry.create",
                    target_node,
                    &c.entry_id,
                    c.generation,
                    "import-env",
                );
                created.push(json!({
                    "name": name,
                    "entry": c.entry_id,
                    "pending": c.pending,
                    "fieldCount": c.field_ids.len(),
                }));
            }
            Err(e) => {
                failed = json!({ "index": i, "name": name, "error": format!("{e:?}") });
                break;
            }
        }
    }
    let skipped: Vec<Value> = pairs
        .iter()
        .zip(&statuses)
        .filter(|(_, s)| **s != Status::New)
        .map(|((name, _), s)| json!({ "name": name, "status": s.as_str() }))
        .collect();
    let mut body = json!({
        "node": target_node,
        "created": created,
        "skipped": skipped,
        "complete": failed.is_null(),
        "failed": failed,
        "total": pairs.len(),
        "counts": counts,
        "generation": generation,
    });
    let typed: Vec<&str> = pairs.iter().map(|(n, _)| *n).collect();
    name_warnings(&mut body, &typed);
    Ok(body)
}
