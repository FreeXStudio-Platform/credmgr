//! Registry types — `Node` and `Grant` — and their static invariants.
//! See `docs/03_DATA_MODEL.md §1, §6`.
//!
//! This is the Phase-1 subset of these types: the fields `resolve()` and the
//! invariant checks actually consume. Serialisation-only fields (`created`,
//! `gate`, `pinned`, entry/field bodies) belong to `crates/store` in Phase 2,
//! once there is a file format to serialise them into.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const GLOBAL_ID: &str = "global";
pub const ORPHAN_ID: &str = "orphan";

/// Ids no node may ever take. `global` and `orphan` are the two structural
/// nodes; `removed-entries` and `entry-history` are the names of the two
/// reserved directories beside the per-node seal archives under `archive/`
/// (`crates/store/src/paths.rs`) — a node called either would alias its seal
/// archive onto the entry archives, and a later purge or restore would
/// `remove_dir_all` them (ADR-079, F-e).
pub const RESERVED_NODE_IDS: &[&str] = &[GLOBAL_ID, ORPHAN_ID, "removed-entries", "entry-history"];

/// The longest node id `node.create` accepts.
pub const NODE_ID_MAX_LEN: usize = 64;

/// ADR-079 (F-e): the grammar of a node id that is **new**, `[a-z0-9][a-z0-9_-]{0,63}`,
/// and not one of [`RESERVED_NODE_IDS`]. A node id is joined into filesystem
/// paths (`keys/nodes/<id>.key`, `nodes/<id>/`, `archive/<id>/`) with no further
/// escaping, so an unvalidated id such as `../x` left the vault. Enforced where
/// an id is chosen (`node.create`); an id that already exists is never refused
/// at load — see [`is_path_safe_node_id`] for the weaker check the seal path
/// makes on those.
///
/// The `Err` text is the whole reason, ready to show.
pub fn validate_node_id(id: &str) -> Result<(), String> {
    if RESERVED_NODE_IDS.contains(&id) {
        return Err(format!("{id} is a reserved node id"));
    }
    let bytes = id.as_bytes();
    let first_ok = bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest_ok = bytes
        .iter()
        .skip(1)
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-');
    if bytes.is_empty() || bytes.len() > NODE_ID_MAX_LEN || !first_ok || !rest_ok {
        return Err(format!(
            "a node id is 1–{NODE_ID_MAX_LEN} characters of a–z, 0–9, '_' and '-', starting with a \
             letter or digit"
        ));
    }
    Ok(())
}

/// Whether `id` can be joined into a vault path without leaving the directory
/// it is joined into: non-empty, no separator, no NUL, no leading dot (so
/// neither `.` nor `..` nor a hidden file), not one of the reserved archive
/// names. A weaker test than [`validate_node_id`], for an id that already
/// exists (created before the grammar was enforced) and so cannot be refused
/// outright — but must not be moved around the filesystem if it is unsafe.
pub fn is_path_safe_node_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && !id.starts_with('.')
        && !id.contains(|c: char| matches!(c, '/' | '\\' | '\0'))
        && id != "removed-entries"
        && id != "entry-history"
}

// `Serialize`/`Deserialize` are derived directly on these types (rather than
// mirrored in a `crates/store`-owned DTO) so there is exactly one definition
// of what a `Node` or `Grant` is — the type `resolve()` consumes is the type
// that round-trips through `registry.json`. Deriving serde does not touch
// any file, socket, clock or env — `crates/core` stays exactly as I/O-free
// as before. Field names below use `03_DATA_MODEL.md`'s own JSON spelling.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    Global,
    Project,
    Sub,
    Orphan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiblingVisibility {
    Shared,
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TwoFactorRequirement {
    Never,
    Reveal,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentAccess {
    #[serde(rename = "read-write")]
    ReadWrite,
    #[serde(rename = "read-only")]
    ReadOnly,
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodePolicy {
    pub sibling_visibility: SiblingVisibility,
    pub descendant_read: bool,
    pub require_two_factor: TwoFactorRequirement,
    pub lock_after_seconds: Option<u32>,
    pub private_names: bool,
    pub agent_access: AgentAccess,
}

impl Default for NodePolicy {
    /// `03_DATA_MODEL.md §1` "Defaults on create".
    fn default() -> Self {
        NodePolicy {
            sibling_visibility: SiblingVisibility::Shared,
            descendant_read: false,
            require_two_factor: TwoFactorRequirement::Reveal,
            lock_after_seconds: None,
            private_names: false,
            agent_access: AgentAccess::ReadWrite,
        }
    }
}

/// The subset of `03_DATA_MODEL.md §1`'s `Node` that `resolve()` and the
/// invariant checker consume. `created`, `gate` and `pinned` are
/// persistence-only — they round-trip through storage but nothing in this
/// crate reads them — so they live in `crates/store`'s `NodeDoc`, which
/// `#[serde(flatten)]`s this type in and adds them as sibling JSON fields
/// (`crates/store/src/registry_file.rs`). One `Node` type, not two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: String,
    pub label: String,
    pub kind: NodeKind,
    pub depth: u8,
    pub parent_id: Option<String>,
    pub workdirs: Vec<String>,
    pub policy: NodePolicy,
}

impl Node {
    pub fn global() -> Self {
        Node {
            id: GLOBAL_ID.to_string(),
            label: "Global".to_string(),
            kind: NodeKind::Global,
            depth: 0,
            parent_id: None,
            workdirs: Vec::new(),
            policy: NodePolicy {
                // "the top-level partition is the product" — 06 §1b.
                sibling_visibility: SiblingVisibility::Isolated,
                ..NodePolicy::default()
            },
        }
    }

    pub fn orphan() -> Self {
        Node {
            id: ORPHAN_ID.to_string(),
            label: "Orphaned".to_string(),
            kind: NodeKind::Orphan,
            depth: 0,
            parent_id: None,
            workdirs: Vec::new(),
            policy: NodePolicy::default(),
        }
    }
}

/// `03_DATA_MODEL.md §6`. `direction: 'mutual'` is enforced in
/// `access::resolve` as if a mirror one-way grant existed with the endpoints
/// swapped — the doc defines the type but does not spell out mutual's
/// enforcement semantics, and this is the reading consistent with grants
/// being human-drawn, symmetric edges on the graph (`06 §6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    #[serde(rename = "one-way")]
    OneWay,
    #[serde(rename = "mutual")]
    Mutual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    List,
    Read,
    Reveal,
    Create,
    Update,
    Notes,
    Admin,
}

// `rename_all` on the enum itself only renames *variant* names in serde —
// it does not reach into a struct variant's own fields (unlike a plain
// struct, where a container-level `rename_all` covers every field). Each
// variant repeats `rename_all = "camelCase"` for exactly that reason: without
// it this serializes `node_id`/`entry_id`, not the `nodeId`/`entryId`
// `03_DATA_MODEL.md §6`'s TS type (and `06_ACCESS_GRAPH.md`'s worked
// examples) actually specify — caught by `grant.list`'s own wire-shape test
// (ADR-050), the first place in this workspace that ever serialized a
// `GrantTarget` to JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum GrantTarget {
    #[serde(rename = "node", rename_all = "camelCase")]
    Node { node_id: String },
    #[serde(rename = "entry", rename_all = "camelCase")]
    Entry { node_id: String, entry_id: String },
}

impl GrantTarget {
    pub fn node_id(&self) -> &str {
        match self {
            GrantTarget::Node { node_id } => node_id,
            GrantTarget::Entry { node_id, .. } => node_id,
        }
    }
}

/// The subset of `03_DATA_MODEL.md §6`'s `Grant` this crate reasons about.
/// `createdAt`, `createdBy` and `lastUsedAt` are persistence/audit-only —
/// `crates/store`'s `GrantDoc` flattens this type in and adds them, same
/// pattern as `Node`/`NodeDoc` above.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub id: String,
    /// The node that RECEIVES access.
    pub from: String,
    pub to: GrantTarget,
    pub direction: Direction,
    pub scope: Vec<Capability>,
    /// Unix epoch seconds. `None` = never expires (rendered with a warning
    /// chip in the UI, per `06 §6`, but that is not this crate's concern).
    pub expires_at: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Default, Clone)]
pub struct Registry {
    pub nodes: HashMap<String, Node>,
    pub grants: Vec<Grant>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// `candidate` is a strict ancestor of `of` — i.e. appears somewhere on
    /// `of`'s parent chain, not counting `of` itself.
    pub fn is_strict_ancestor(&self, candidate: &str, of: &str) -> bool {
        let mut current = of.to_string();
        loop {
            let node = match self.nodes.get(&current) {
                Some(n) => n,
                None => return false,
            };
            match &node.parent_id {
                Some(parent) => {
                    if parent == candidate {
                        return true;
                    }
                    current.clone_from(parent);
                }
                None => return false,
            }
        }
    }

    /// `06_ACCESS_GRAPH.md §1` R6: both nodes at depth 2, sharing a parent
    /// whose policy allows it.
    pub fn are_shared_depth2_siblings(&self, a: &str, b: &str) -> bool {
        let (Some(na), Some(nb)) = (self.nodes.get(a), self.nodes.get(b)) else {
            return false;
        };
        if na.depth != 2 || nb.depth != 2 {
            return false;
        }
        let (Some(pa), Some(pb)) = (&na.parent_id, &nb.parent_id) else {
            return false;
        };
        if pa != pb {
            return false;
        }
        match self.nodes.get(pa) {
            Some(parent) => parent.policy.sibling_visibility == SiblingVisibility::Shared,
            None => false,
        }
    }
}

/// A violated static invariant from `03_DATA_MODEL.md §1`. Runtime-only rules
/// (cannot delete/rename `orphan`, cannot be a grant endpoint) are operations,
/// not data shape, and are enforced where those operations live (Phase 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantViolation {
    /// There must be exactly one node with `depth == 0`, and its id must be `"global"`.
    NotExactlyOneGlobalNode {
        found: usize,
    },
    WrongDepthForKind {
        node_id: String,
        kind: NodeKind,
        depth: u8,
    },
    SubNodeParentNotDepth1 {
        node_id: String,
        parent_id: String,
    },
    DepthExceedsCap {
        node_id: String,
        depth: u8,
    },
    OrphanHasParent {
        node_id: String,
    },
    /// A `workdirs` entry maps to more than one node — auto-scoping would be
    /// ambiguous (`03 §1`).
    DuplicateWorkdir {
        workdir: String,
        node_a: String,
        node_b: String,
    },
}

pub fn validate_registry(registry: &Registry) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    // `orphan` is off-tree and its `depth` is not meaningful (`03 §1`: "depth:
    // null-equivalent handling") — excluded here so it can't masquerade as
    // (or collide with) the one true depth-0 node.
    let global_count = registry
        .nodes
        .values()
        .filter(|n| n.kind != NodeKind::Orphan && n.depth == 0)
        .count();
    if global_count != 1 {
        violations.push(InvariantViolation::NotExactlyOneGlobalNode {
            found: global_count,
        });
    }

    for node in registry.nodes.values() {
        match node.kind {
            NodeKind::Global => {
                if node.depth != 0 {
                    violations.push(InvariantViolation::WrongDepthForKind {
                        node_id: node.id.clone(),
                        kind: node.kind,
                        depth: node.depth,
                    });
                }
            }
            NodeKind::Project => {
                if node.depth != 1 {
                    violations.push(InvariantViolation::WrongDepthForKind {
                        node_id: node.id.clone(),
                        kind: node.kind,
                        depth: node.depth,
                    });
                }
            }
            NodeKind::Sub => {
                if node.depth != 2 {
                    violations.push(InvariantViolation::WrongDepthForKind {
                        node_id: node.id.clone(),
                        kind: node.kind,
                        depth: node.depth,
                    });
                }
                if let Some(parent_id) = &node.parent_id {
                    if let Some(parent) = registry.nodes.get(parent_id) {
                        if parent.depth != 1 {
                            violations.push(InvariantViolation::SubNodeParentNotDepth1 {
                                node_id: node.id.clone(),
                                parent_id: parent_id.clone(),
                            });
                        }
                    }
                }
            }
            NodeKind::Orphan => {
                if node.parent_id.is_some() {
                    violations.push(InvariantViolation::OrphanHasParent {
                        node_id: node.id.clone(),
                    });
                }
            }
        }

        if node.depth > 2 {
            violations.push(InvariantViolation::DepthExceedsCap {
                node_id: node.id.clone(),
                depth: node.depth,
            });
        }
    }

    let mut seen: HashMap<&str, &str> = HashMap::new();
    for node in registry.nodes.values() {
        for workdir in &node.workdirs {
            match seen.get(workdir.as_str()) {
                Some(existing) if *existing != node.id => {
                    violations.push(InvariantViolation::DuplicateWorkdir {
                        workdir: workdir.clone(),
                        node_a: existing.to_string(),
                        node_b: node.id.clone(),
                    });
                }
                _ => {
                    seen.insert(workdir.as_str(), &node.id);
                }
            }
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(id: &str) -> Node {
        Node {
            id: id.to_string(),
            label: id.to_string(),
            kind: NodeKind::Project,
            depth: 1,
            parent_id: Some(GLOBAL_ID.to_string()),
            workdirs: Vec::new(),
            policy: NodePolicy::default(),
        }
    }

    fn sub(id: &str, parent: &str) -> Node {
        Node {
            id: id.to_string(),
            label: id.to_string(),
            kind: NodeKind::Sub,
            depth: 2,
            parent_id: Some(parent.to_string()),
            workdirs: Vec::new(),
            policy: NodePolicy::default(),
        }
    }

    fn base_registry() -> Registry {
        let mut reg = Registry::new();
        reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
        reg.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());
        reg
    }

    #[test]
    fn valid_registry_has_no_violations() {
        let mut reg = base_registry();
        reg.nodes.insert("a".into(), project("a"));
        reg.nodes.insert("x".into(), sub("x", "a"));
        assert_eq!(validate_registry(&reg), vec![]);
    }

    #[test]
    fn sub_node_under_another_sub_node_is_rejected() {
        let mut reg = base_registry();
        reg.nodes.insert("a".into(), project("a"));
        reg.nodes.insert("x".into(), sub("x", "a"));
        // y's parent is x (depth 2), not a depth-1 project.
        reg.nodes.insert("y".into(), sub("y", "x"));
        let violations = validate_registry(&reg);
        assert!(violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::SubNodeParentNotDepth1 { node_id, .. } if node_id == "y")));
    }

    #[test]
    fn duplicate_workdir_is_rejected() {
        let mut reg = base_registry();
        let mut a = project("a");
        a.workdirs.push("/home/user/proj".into());
        let mut b = project("b");
        b.workdirs.push("/home/user/proj".into());
        reg.nodes.insert("a".into(), a);
        reg.nodes.insert("b".into(), b);
        let violations = validate_registry(&reg);
        assert!(violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::DuplicateWorkdir { .. })));
    }

    #[test]
    fn a_new_node_id_must_fit_the_grammar() {
        for good in [
            "a",
            "acme",
            "acme-api",
            "n_aaaaaaaa",
            "0day",
            "a-b_c",
            &"x".repeat(64),
        ] {
            assert_eq!(validate_node_id(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "Acme",
            "-lead",
            "_lead",
            "has space",
            "dot.ted",
            "a/b",
            "../x",
            "..",
            ".hidden",
            "ünï",
            "nul\0",
            &"x".repeat(65),
        ] {
            assert!(validate_node_id(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_four_reserved_ids_are_refused_and_say_so() {
        for reserved in ["global", "orphan", "removed-entries", "entry-history"] {
            let err = validate_node_id(reserved).unwrap_err();
            assert!(err.contains("reserved node id"), "{reserved}: {err}");
        }
    }

    #[test]
    fn a_path_safe_id_is_the_weaker_test_an_existing_id_must_pass() {
        // Created before the grammar was enforced: odd, but it stays inside its directory.
        for fine in ["Acme", "has space", "dot.ted", "ünï", "a"] {
            assert!(is_path_safe_node_id(fine), "{fine}");
        }
        for unsafe_id in [
            "",
            ".",
            "..",
            ".hidden",
            "../x",
            "a/b",
            "a\\b",
            "nul\0",
            "removed-entries",
            "entry-history",
        ] {
            assert!(!is_path_safe_node_id(unsafe_id), "{unsafe_id:?}");
        }
    }

    #[test]
    fn ancestor_walk_is_strict_and_transitive() {
        let mut reg = base_registry();
        reg.nodes.insert("a".into(), project("a"));
        reg.nodes.insert("x".into(), sub("x", "a"));
        assert!(reg.is_strict_ancestor(GLOBAL_ID, "x"));
        assert!(reg.is_strict_ancestor("a", "x"));
        assert!(!reg.is_strict_ancestor("x", "x"));
        assert!(!reg.is_strict_ancestor("x", "a"));
    }
}
