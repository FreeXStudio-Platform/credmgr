//! `credmgr doctor --rebuild-registry` — the fail-closed door
//! `02_ARCHITECTURE.md §7a` requires: a corrupted or rolled-back registry
//! must not open, but it also must not be a dead end.
//!
//! This module is the pure diff-and-apply core. What it deliberately does
//! **not** do: decide *when* a rebuild is authorised (presence + gate 2FA —
//! a broker/CLI concern, Phase 3/4), or discover *what* the reconstruction
//! candidate should be (walking per-node manifests plus the most recent
//! signed backup — also a caller concern, since Phase 2 alone doesn't yet
//! have every piece of that pipeline built). Given a candidate, this module
//! computes the diff `02 §7a` demands be shown "before writing anything",
//! and applies it only when the caller asks it to.

use std::collections::HashSet;

use crate::error::Result;
use crate::generation::{GenerationCounter, VAULT_GENERATION};
use crate::paths::VaultPaths;
use crate::registry_file::{self, RegistryDocument};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RebuildDiff {
    pub nodes_added: Vec<String>,
    pub nodes_removed: Vec<String>,
    pub grants_added: Vec<String>,
    pub grants_removed: Vec<String>,
    /// Grants present in the candidate whose id the caller identified as
    /// having been revoked since (typically by scanning the audit log for a
    /// later revoke record for that grant id). "A rebuild that would
    /// resurrect a revoked grant says so in words" (`02 §7a`).
    pub resurrected_revoked_grants: Vec<String>,
    pub policy_changes: Vec<String>,
    /// ADR-079: sealed nodes the candidate has that the registry on disk does
    /// not — "a rebuild that resurrects a sealed node says so" (`02 §7a`'s rule
    /// for revoked grants, applied to seal records): a node the owner sealed
    /// would come back sealed, and its 7-day window would restart from a record
    /// that may be older than the seal itself.
    pub sealed_added: Vec<String>,
    /// Sealed nodes the registry on disk has that the candidate lacks: applying
    /// the candidate would forget the seal, leaving the archive unrestorable.
    pub sealed_removed: Vec<String>,
}

impl RebuildDiff {
    pub fn is_empty(&self) -> bool {
        self.nodes_added.is_empty()
            && self.nodes_removed.is_empty()
            && self.grants_added.is_empty()
            && self.grants_removed.is_empty()
            && self.resurrected_revoked_grants.is_empty()
            && self.policy_changes.is_empty()
            && self.sealed_added.is_empty()
            && self.sealed_removed.is_empty()
    }
}

/// Compare what's currently on disk against a reconstruction candidate.
/// Pure and side-effect-free — call this before ever touching disk.
pub fn diff(
    on_disk: &RegistryDocument,
    candidate: &RegistryDocument,
    known_revoked_grant_ids: &HashSet<String>,
) -> RebuildDiff {
    let on_disk_nodes: HashSet<&String> = on_disk.nodes.keys().collect();
    let candidate_nodes: HashSet<&String> = candidate.nodes.keys().collect();

    let mut nodes_added: Vec<String> = candidate_nodes
        .difference(&on_disk_nodes)
        .map(|s| s.to_string())
        .collect();
    nodes_added.sort();
    let mut nodes_removed: Vec<String> = on_disk_nodes
        .difference(&candidate_nodes)
        .map(|s| s.to_string())
        .collect();
    nodes_removed.sort();

    let on_disk_grants: HashSet<&String> = on_disk.grants.iter().map(|g| &g.grant.id).collect();
    let candidate_grants: HashSet<&String> = candidate.grants.iter().map(|g| &g.grant.id).collect();

    let mut grants_added: Vec<String> = candidate_grants
        .difference(&on_disk_grants)
        .map(|s| s.to_string())
        .collect();
    grants_added.sort();
    let mut grants_removed: Vec<String> = on_disk_grants
        .difference(&candidate_grants)
        .map(|s| s.to_string())
        .collect();
    grants_removed.sort();

    let mut resurrected_revoked_grants: Vec<String> = candidate
        .grants
        .iter()
        .filter(|g| known_revoked_grant_ids.contains(&g.grant.id))
        .map(|g| g.grant.id.clone())
        .collect();
    resurrected_revoked_grants.sort();

    let mut policy_changes: Vec<String> = on_disk
        .nodes
        .iter()
        .filter_map(|(id, od)| {
            candidate.nodes.get(id).and_then(|cd| {
                (od.node.policy != cd.node.policy).then(|| format!("{id}: policy would change"))
            })
        })
        .collect();
    policy_changes.sort();

    let mut sealed_added: Vec<String> = candidate
        .sealed
        .keys()
        .filter(|id| !on_disk.sealed.contains_key(*id))
        .cloned()
        .collect();
    sealed_added.sort();
    let mut sealed_removed: Vec<String> = on_disk
        .sealed
        .keys()
        .filter(|id| !candidate.sealed.contains_key(*id))
        .cloned()
        .collect();
    sealed_removed.sort();

    RebuildDiff {
        nodes_added,
        nodes_removed,
        grants_added,
        grants_removed,
        resurrected_revoked_grants,
        policy_changes,
        sealed_added,
        sealed_removed,
    }
}

/// Write `candidate` as the new `registry.json`, with `vaultGeneration`
/// bumped strictly past every generation this rebuild has seen — the
/// on-disk file's own, the candidate's own, and the external counter's —
/// so the very next broker start doesn't itself look like a rollback
/// (`02 §7a` point 4).
pub fn apply(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    counter: &dyn GenerationCounter,
    on_disk: &RegistryDocument,
    mut candidate: RegistryDocument,
) -> Result<RegistryDocument> {
    let external = counter.read(root_key, VAULT_GENERATION)?.unwrap_or(0);
    let new_generation = [
        on_disk.vault_generation,
        candidate.vault_generation,
        external,
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
        + 1;
    candidate.vault_generation = new_generation;
    // Never write an older format than this build understands (ADR-079): a
    // candidate reconstructed from an alpha backup is format 1.
    candidate.format = candidate.format.max(registry_file::REGISTRY_FORMAT);
    registry_file::save(paths, root_key, &candidate)?;
    counter.write(root_key, VAULT_GENERATION, new_generation)?;
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::FileGenerationCounter;
    use crate::registry_file::{CreatedByHuman, GateDoc, GrantDoc, NodeDoc};
    use credmgr_core::registry::{Direction, Grant, GrantTarget, Node, NodeKind, NodePolicy};

    fn node_doc(id: &str) -> NodeDoc {
        NodeDoc {
            node: Node {
                id: id.to_string(),
                label: id.to_string(),
                kind: NodeKind::Project,
                depth: 1,
                parent_id: Some("global".to_string()),
                workdirs: vec![],
                policy: NodePolicy::default(),
            },
            created: 1_700_000_000,
            gate: GateDoc::default(),
            pinned: None,
            public_key: "bb".repeat(32),
        }
    }

    fn grant_doc(id: &str, from: &str, to: &str) -> GrantDoc {
        GrantDoc {
            grant: Grant {
                id: id.to_string(),
                from: from.to_string(),
                to: GrantTarget::Node {
                    node_id: to.to_string(),
                },
                direction: Direction::OneWay,
                scope: vec![],
                expires_at: None,
                reason: "test grant, min 8 chars".to_string(),
            },
            created_at: 1_700_000_000,
            created_by: CreatedByHuman::Human,
            last_used_at: None,
        }
    }

    /// I-20: a restored, older, validly-signed `registry.json` brings a
    /// revoked grant back. `doctor --rebuild-registry` must show it in the
    /// diff — before writing anything.
    #[test]
    fn resurrected_revoked_grant_shows_in_the_diff() {
        let mut on_disk = RegistryDocument::new(); // the rolled-back file, currently open
        on_disk.vault_generation = 2;
        on_disk.nodes.insert("a".to_string(), node_doc("a"));
        on_disk.grants.push(grant_doc("g_revoked", "a", "global"));

        let mut candidate = RegistryDocument::new(); // reconstructed from manifests + backup
        candidate.vault_generation = 5;
        candidate.nodes.insert("a".to_string(), node_doc("a"));
        candidate.grants.push(grant_doc("g_revoked", "a", "global")); // the backup used is itself stale

        let mut revoked = HashSet::new();
        revoked.insert("g_revoked".to_string());

        let d = diff(&on_disk, &candidate, &revoked);
        assert_eq!(d.resurrected_revoked_grants, vec!["g_revoked".to_string()]);
        assert!(!d.is_empty());
    }

    #[test]
    fn no_diff_when_candidate_matches_and_nothing_revoked() {
        let mut doc = RegistryDocument::new();
        doc.nodes.insert("a".to_string(), node_doc("a"));
        let d = diff(&doc, &doc, &HashSet::new());
        assert!(d.is_empty());
    }

    #[test]
    fn detects_added_and_removed_nodes_and_grants() {
        let mut on_disk = RegistryDocument::new();
        on_disk.nodes.insert("a".to_string(), node_doc("a"));
        on_disk.grants.push(grant_doc("g1", "a", "global"));

        let mut candidate = RegistryDocument::new();
        candidate.nodes.insert("b".to_string(), node_doc("b"));
        candidate.grants.push(grant_doc("g2", "b", "global"));

        let d = diff(&on_disk, &candidate, &HashSet::new());
        assert_eq!(d.nodes_added, vec!["b".to_string()]);
        assert_eq!(d.nodes_removed, vec!["a".to_string()]);
        assert_eq!(d.grants_added, vec!["g2".to_string()]);
        assert_eq!(d.grants_removed, vec!["g1".to_string()]);
    }

    /// ADR-079: a rebuild that would resurrect (or forget) a seal says so.
    #[test]
    fn detects_sealed_nodes_a_rebuild_would_resurrect_or_forget() {
        let sealed = |id: &str| registry_file::SealedNodeDoc {
            v: registry_file::SEALED_RECORD_VERSION,
            node: node_doc(id),
            sealed_at: 1_700_000_000,
            manifest: registry_file::ManifestBinding {
                generation: 1,
                manifest_hmac: "00".repeat(32),
            },
            node_key_sha256: "11".repeat(32),
            orphan_entry_ids: vec![],
        };
        let mut on_disk = RegistryDocument::new();
        on_disk.sealed.insert("kept".to_string(), sealed("kept"));
        on_disk.sealed.insert("gone".to_string(), sealed("gone"));
        let mut candidate = RegistryDocument::new();
        candidate.sealed.insert("kept".to_string(), sealed("kept"));
        candidate.sealed.insert("new".to_string(), sealed("new"));

        let d = diff(&on_disk, &candidate, &HashSet::new());
        assert_eq!(d.sealed_added, vec!["new".to_string()]);
        assert_eq!(d.sealed_removed, vec!["gone".to_string()]);
        assert!(!d.is_empty());
        assert!(diff(&on_disk, &on_disk, &HashSet::new()).is_empty());
    }

    #[test]
    fn detects_policy_changes_on_shared_nodes() {
        let mut on_disk = RegistryDocument::new();
        on_disk.nodes.insert("a".to_string(), node_doc("a"));

        let mut candidate = RegistryDocument::new();
        let mut changed = node_doc("a");
        changed.node.policy.descendant_read = true;
        candidate.nodes.insert("a".to_string(), changed);

        let d = diff(&on_disk, &candidate, &HashSet::new());
        assert_eq!(d.policy_changes, vec!["a: policy would change".to_string()]);
    }

    /// End-to-end: refused at open (generation check), diffed, then applied
    /// with a generation strictly past everything seen.
    #[test]
    fn rolled_back_registry_is_refused_then_rebuild_applies_with_advanced_generation() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let counter = FileGenerationCounter::new(dir.path().join("state"));
        let rk = [4u8; 32];

        // Simulate the timeline: v1 (gen 1, has the grant) -> revoke -> v2
        // (gen 2, no grant) saved and its generation recorded externally ->
        // attacker restores v1's bytes as registry.json.
        let mut v1 = RegistryDocument::new();
        v1.vault_generation = 1;
        v1.nodes.insert("a".to_string(), node_doc("a"));
        v1.grants.push(grant_doc("g_revoked", "a", "global"));

        let mut v2 = RegistryDocument::new();
        v2.vault_generation = 2;
        v2.nodes.insert("a".to_string(), node_doc("a"));
        registry_file::save(&paths, &rk, &v2).unwrap();
        counter.write(&rk, VAULT_GENERATION, 2).unwrap();

        registry_file::save(&paths, &rk, &v1).unwrap(); // the rollback

        let on_disk = registry_file::load(&paths, &rk).unwrap();
        let err = crate::generation::check_and_advance(&rk, &counter, on_disk.vault_generation)
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::StoreError::GenerationRolledBack { .. }
        ));

        // doctor --rebuild-registry: candidate reconstructed as v2-shaped
        // (no grant), diff shown, then applied.
        let mut revoked = HashSet::new();
        revoked.insert("g_revoked".to_string());
        let d = diff(&on_disk, &v2, &revoked);
        assert_eq!(d.grants_removed, vec!["g_revoked".to_string()]);
        assert!(d.resurrected_revoked_grants.is_empty());

        let applied = apply(&paths, &rk, &counter, &on_disk, v2).unwrap();
        assert!(applied.vault_generation > 2);
        assert_eq!(
            counter.read(&rk, VAULT_GENERATION).unwrap(),
            Some(applied.vault_generation)
        );

        // The very next open no longer looks like a rollback.
        let reopened = registry_file::load(&paths, &rk).unwrap();
        crate::generation::check_and_advance(&rk, &counter, reopened.vault_generation).unwrap();
    }
}
