//! ADR-167 — entry tags. One op, `entry.tag_set`, and the `tag` filter `entry.list` and `entry.search`
//! read through [`tag_filter`].
//!
//! A tag is names-level metadata on the entry's signed manifest row (`credmgr_store::manifest::ManifestEntry
//! ::tags`), normalised by `credmgr_core::tags`. It follows the aliases of ADR-121 in every respect that
//! matters for the boundary: the owner's sessions set it (an agent session, a cwd-scoped process and an
//! agent token are refused, and no MCP tool maps to the op), it is read by whoever may list the node, it is
//! hidden from a reader the node hides its names from, and it is never an index across nodes: a filter
//! narrows the entries of the one node the request names, and only among those the caller could list.

use super::*;

use credmgr_core::tags::{normalise_tag, normalise_tags, TagsError, TAGS_MAX};

/// The `tag` parameter of `entry.list` and `entry.search` (read in their arms with a literal key, so the
/// desktop bridge's drift guard sees it), normalised; `None` when it is absent or null.
pub(super) fn tag_filter(given: Option<&Value>) -> Result<Option<String>, OpError> {
    match given {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => normalise_tag(raw)
            .map(Some)
            .map_err(|e| OpError::Malformed(format!("params.tag {}", e.as_str()))),
        Some(_) => Err(OpError::Malformed("params.tag must be a string".into())),
    }
}

/// ADR-167: replace the tags of one entry (`[]` clears them). Metadata only, exactly as `entry.alias`: the
/// owner's sessions (never `Origin::Agent`), the `update` capability on the node (so a locked node refuses,
/// R1), a node that shows the caller its names, the node's write lock and F-9's generation check. The sealed
/// envelope is neither read nor rewritten.
pub(super) fn entry_tag_set(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    target_node: &str,
    entry_id: &str,
    expected_generation: u64,
    raw: &[Value],
) -> Result<Value, OpError> {
    let mut supplied: Vec<&str> = Vec::with_capacity(raw.len());
    for (i, t) in raw.iter().enumerate() {
        supplied.push(
            t.as_str()
                .ok_or_else(|| OpError::Malformed(format!("params.tags[{i}] must be a string")))?,
        );
    }
    let tags = normalise_tags(supplied).map_err(|e| match e {
        TagsError::Tag(i, why) => OpError::Malformed(format!("params.tags[{i}] {}", why.as_str())),
        TagsError::TooMany => {
            OpError::Malformed(format!("params.tags holds at most {TAGS_MAX} tags"))
        }
    })?;

    // ADR-110 / ADR-121: a caller who may not see this node's names is never told that an entry exists.
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
        if !body.is_some_and(|b| b.entries.iter().any(|e| e.id == entry_id)) {
            return Err(OpError::NotFound(format!(
                "no entry {entry_id} on node {target_node}"
            )));
        }
        if expected_generation != current_generation {
            return Err(OpError::Conflict {
                node_id: target_node.to_string(),
                expected_generation,
                current_generation,
            });
        }
    }
    let generation = state
        .update_manifest_entry(target_node, entry_id, |e| {
            e.tags.clone_from(&tags);
            e.modified = now;
        })
        .expect("presence already checked above, under the same held write lock");
    Ok(json!({
        "node": target_node, "entry": entry_id, "generation": generation, "tags": tags,
    }))
}
