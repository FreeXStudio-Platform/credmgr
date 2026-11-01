//! `registry.json` + `registry.sig`. See `docs/03_DATA_MODEL.md §2` and
//! `docs/04_CRYPTO_AND_KEYS.md §6a`.
//!
//! `RegistryDocument` extends `credmgr_core::registry::{Node, Grant}` with
//! the persistence-only fields those types deliberately don't carry
//! (`created`, `gate`, `pinned`, `createdBy`, `lastUsedAt`) via
//! `#[serde(flatten)]`, plus `vaultGeneration` (ADR-024) and the per-node
//! manifest cross-binding (`04 §6a` — "neither can be swapped for an older
//! validly-signed version of itself without contradicting the other").

use std::collections::HashMap;

use credmgr_core::registry::{Grant, Node};
use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::error::{Result, StoreError};
use crate::hexutil;
use crate::paths::VaultPaths;

pub const REGISTRY_HMAC_LABEL: &str = "registry-hmac";

/// ADR-079: the `registry.json` format this build writes — and the highest it
/// will read. `1` is the alpha shape (no `format` field at all, no `sealed`);
/// `2` adds [`RegistryDocument::sealed`]. A registry of a higher format is
/// refused ([`StoreError::RegistryFormatTooNew`]); an older build ignores
/// `sealed` on read and drops it on its next write, so downgrading a vault
/// below the build that wrote format 2 is unsupported (CHANGELOG says so).
pub const REGISTRY_FORMAT: u32 = 2;

/// The version of one [`SealedNodeDoc`].
pub const SEALED_RECORD_VERSION: u32 = 1;

fn format_when_absent() -> u32 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Pinned {
    pub x: f64,
    pub y: f64,
}

/// `TwoFactorEnrolment` isn't modeled until Phase 5 (`07_TWO_FACTOR.md`).
/// Phase 2 stores and round-trips whatever is there without interpreting
/// it — `serde_json::Value` rather than a typed field, so nothing here has
/// to change shape again once Phase 5 lands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GateDoc {
    pub twofa: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeDoc {
    #[serde(flatten)]
    pub node: Node,
    /// Unix epoch seconds — ADR-040.
    pub created: i64,
    #[serde(default)]
    pub gate: GateDoc,
    pub pinned: Option<Pinned>,
    /// The node's X25519 public key, hex-encoded — `04_CRYPTO_AND_KEYS.md
    /// §2`: "public half in the plaintext registry." Persistence-only, like
    /// `created`/`gate`/`pinned`: `resolve()` never reads it, only sealing an
    /// entry to this node does (`crates/core::envelope::seal`), which is a
    /// `crates/brokerd` concern, not this crate's or `crates/core`'s.
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

/// ADR-079: one sealed node's durable record — **inside the signed registry**,
/// so it rides the registry HMAC and the external generation counter. A sidecar
/// file beside the archive with its own HMAC would prove authorship, not
/// freshness: an older record of the same id, from a previous seal/restore
/// cycle, would verify and reinstate an older policy or workdir set — the
/// rollback `04 §6a` exists to stop.
///
/// The archive files (`archive/<id>/{node/, node.key, meta.json}`) stay beside
/// the registry and are **bound** by this record: `manifest` is the archived
/// manifest's own `(generation, hmac)`, `node_key_sha256` the digest of the
/// archived wrapped node key. `node` is the node's record, moved out of
/// `nodes` verbatim — `created`, `gate`, `pinned` and `publicKey` included — so
/// a restore reinstates exactly what was sealed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedNodeDoc {
    pub v: u32,
    #[serde(flatten)]
    pub node: NodeDoc,
    /// Unix epoch seconds — ADR-040. The start of the 7-day recovery window.
    pub sealed_at: i64,
    /// Binds `archive/<id>/node/manifest.json`.
    pub manifest: ManifestBinding,
    /// Lower-case hex SHA-256 of `archive/<id>/node.key`.
    pub node_key_sha256: String,
    /// The entry ids this seal deposited into the orphan node — `node.restore`
    /// removes exactly these, never "everything currently in orphan".
    pub orphan_entry_ids: Vec<String>,
}

/// `03_DATA_MODEL.md §6`: `createdBy: 'human'` is a literal type so an
/// agent-created grant is a compile error, not just a runtime check. This
/// enum has exactly one inhabitant for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CreatedByHuman {
    #[default]
    #[serde(rename = "human")]
    Human,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantDoc {
    #[serde(flatten)]
    pub grant: Grant,
    /// Unix epoch seconds — ADR-040.
    pub created_at: i64,
    pub created_by: CreatedByHuman,
    pub last_used_at: Option<i64>,
}

/// `04 §6a`'s cross-binding: what the registry believes about one node's
/// manifest, checked against that manifest's own signed generation at load
/// time (`manifest::verify_cross_binding`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBinding {
    pub generation: u64,
    /// Hex-encoded 32-byte HMAC tag.
    pub manifest_hmac: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryDocument {
    pub nodes: HashMap<String, NodeDoc>,
    pub grants: Vec<GrantDoc>,
    /// ADR-024: incremented on every write; compared against the external
    /// counter (`crate::generation`) at load time, outside this struct.
    pub vault_generation: u64,
    #[serde(default)]
    pub manifests: HashMap<String, ManifestBinding>,
    /// ADR-079: the registry's own format. Absent in an alpha registry (read as
    /// `1`); written as [`REGISTRY_FORMAT`].
    #[serde(default = "format_when_absent")]
    pub format: u32,
    /// ADR-079: every node sealed inside its 7-day window (and past it, until
    /// purged), by id. A sealed node is **absent** from `nodes` — and so from
    /// the access graph, which `to_core_registry` builds from `nodes` alone.
    #[serde(default)]
    pub sealed: HashMap<String, SealedNodeDoc>,
}

impl RegistryDocument {
    pub fn new() -> Self {
        RegistryDocument {
            nodes: HashMap::new(),
            grants: Vec::new(),
            vault_generation: 0,
            manifests: HashMap::new(),
            format: REGISTRY_FORMAT,
            sealed: HashMap::new(),
        }
    }

    /// Build the `credmgr_core::registry::Registry` view `resolve()` and the
    /// invariant checker consume — the flattened persistence fields
    /// (`created`, `gate`, `pinned`, `createdBy`, `lastUsedAt`) are simply
    /// dropped; they were never part of that type.
    pub fn to_core_registry(&self) -> credmgr_core::registry::Registry {
        let mut reg = credmgr_core::registry::Registry::new();
        for (id, doc) in &self.nodes {
            reg.nodes.insert(id.clone(), doc.node.clone());
        }
        reg.grants = self.grants.iter().map(|g| g.grant.clone()).collect();
        reg
    }
}

impl Default for RegistryDocument {
    fn default() -> Self {
        Self::new()
    }
}

fn json_err(path: &std::path::Path, source: serde_json::Error) -> StoreError {
    StoreError::Json {
        path: path.to_path_buf(),
        source,
    }
}

/// Serialise and sign a registry document without touching the disk:
/// `(registry.json bytes, registry.sig bytes)`, exactly what [`save`] writes.
/// Shared with root-key rotation (ADR-076), which stages both under the new
/// root key.
pub fn signed_bytes(root_key: &[u8; 32], doc: &RegistryDocument) -> Result<(Vec<u8>, Vec<u8>)> {
    let bytes = serde_json::to_vec_pretty(doc).map_err(|e| StoreError::Json {
        path: std::path::PathBuf::from("registry.json"),
        source: e,
    })?;
    let tag = credmgr_core::signing::sign(root_key, REGISTRY_HMAC_LABEL, &bytes);
    let sig = hexutil::encode(&tag).into_bytes();
    Ok((bytes, sig))
}

/// Serialise, sign, and atomically write both `registry.json` and
/// `registry.sig`. The signature covers exactly the bytes written to
/// `registry.json` — canonical `serde_json` output, so `load` re-signing
/// the bytes it reads back always agrees.
pub fn save(paths: &VaultPaths, root_key: &[u8; 32], doc: &RegistryDocument) -> Result<()> {
    let (bytes, sig) = signed_bytes(root_key, doc)?;
    // ADR-063: `registry.json` and `registry.sig` are two writes, so a crash
    // between them leaves a pair that does not verify. Keep the pair being
    // replaced — byte for byte, and only if it verifies — as `.prev`, so
    // `load_previous` can recover the last complete state.
    if let Ok((_, current_bytes, current_sig)) =
        read_verified(&paths.registry(), &paths.registry_sig(), root_key)
    {
        atomic::write(&paths.registry_prev(), &current_bytes)?;
        atomic::write(&paths.registry_sig_prev(), &current_sig)?;
    }
    atomic::write(&paths.registry(), &bytes)?;
    atomic::write(&paths.registry_sig(), &sig)?;
    Ok(())
}

/// Load `registry.json`, verifying `registry.sig` first. Returns
/// [`StoreError::RegistryTampered`] on any signature mismatch — a missing,
/// truncated, or wrong-key signature file included; this function never
/// returns registry contents that failed verification.
pub fn load(paths: &VaultPaths, root_key: &[u8; 32]) -> Result<RegistryDocument> {
    read_verified(&paths.registry(), &paths.registry_sig(), root_key).map(|(doc, _, _)| doc)
}

/// The previous complete pair `save` kept (ADR-063). Whether it may be used
/// is the caller's decision, made against the external generation counter —
/// this function only proves it is authentic.
pub fn load_previous(paths: &VaultPaths, root_key: &[u8; 32]) -> Result<RegistryDocument> {
    read_verified(&paths.registry_prev(), &paths.registry_sig_prev(), root_key)
        .map(|(doc, _, _)| doc)
}

/// Read one registry/signature pair, verify it, and return the document
/// with the exact bytes that verified.
fn read_verified(
    registry_path: &std::path::Path,
    sig_path: &std::path::Path,
    root_key: &[u8; 32],
) -> Result<(RegistryDocument, Vec<u8>, Vec<u8>)> {
    let bytes = atomic::read(registry_path)?;
    let sig_bytes = atomic::read(sig_path)?;
    let tampered_sig = || StoreError::RegistryTampered {
        path: sig_path.to_path_buf(),
    };
    let sig_hex = std::str::from_utf8(&sig_bytes).map_err(|_| tampered_sig())?;
    let tag = hexutil::decode_32(sig_hex).ok_or_else(tampered_sig)?;
    if !credmgr_core::signing::verify(root_key, REGISTRY_HMAC_LABEL, &bytes, &tag) {
        return Err(StoreError::RegistryTampered {
            path: registry_path.to_path_buf(),
        });
    }
    let doc: RegistryDocument =
        serde_json::from_slice(&bytes).map_err(|e| json_err(registry_path, e))?;
    // After the signature, so only an authentic document can reach this refusal.
    if doc.format > REGISTRY_FORMAT {
        return Err(StoreError::RegistryFormatTooNew {
            found: doc.format,
            supported: REGISTRY_FORMAT,
        });
    }
    Ok((doc, bytes, sig_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use credmgr_core::registry::{NodeKind, NodePolicy};

    fn sample_doc() -> RegistryDocument {
        let mut doc = RegistryDocument::new();
        doc.vault_generation = 3;
        doc.nodes.insert(
            "global".to_string(),
            NodeDoc {
                node: Node {
                    id: "global".to_string(),
                    label: "Global".to_string(),
                    kind: NodeKind::Global,
                    depth: 0,
                    parent_id: None,
                    workdirs: vec![],
                    policy: NodePolicy::default(),
                },
                created: 1_700_000_000,
                gate: GateDoc::default(),
                pinned: None,
                public_key: "aa".repeat(32),
            },
        );
        doc
    }

    #[test]
    fn public_key_round_trips_under_its_camelcase_wire_name() {
        let doc = sample_doc();
        let v = serde_json::to_value(doc).unwrap();
        assert_eq!(v["nodes"]["global"]["publicKey"], "aa".repeat(32));
        assert!(v["nodes"]["global"].get("public_key").is_none());
    }

    fn sealed_sample(id: &str) -> SealedNodeDoc {
        let mut node = sample_doc().nodes.remove("global").unwrap();
        node.node.id = id.to_string();
        node.node.kind = NodeKind::Project;
        node.node.depth = 1;
        node.node.parent_id = Some("global".to_string());
        node.pinned = Some(Pinned { x: 1.5, y: -2.0 });
        SealedNodeDoc {
            v: SEALED_RECORD_VERSION,
            node,
            sealed_at: 1_700_000_100,
            manifest: ManifestBinding {
                generation: 4,
                manifest_hmac: "ab".repeat(32),
            },
            node_key_sha256: "cd".repeat(32),
            orphan_entry_ids: vec!["e_aaaaaaaaaaaa".to_string(), "e_bbbbbbbbbbbb".to_string()],
        }
    }

    #[test]
    fn a_new_document_is_the_current_format_with_no_seals() {
        let doc = RegistryDocument::new();
        assert_eq!(doc.format, REGISTRY_FORMAT);
        assert_eq!(REGISTRY_FORMAT, 2);
        assert!(doc.sealed.is_empty());
    }

    #[test]
    fn a_seal_record_round_trips_with_every_field_of_the_node_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [9u8; 32];
        let mut doc = sample_doc();
        doc.sealed.insert("acme".to_string(), sealed_sample("acme"));
        save(&paths, &rk, &doc).unwrap();

        let loaded = load(&paths, &rk).unwrap();
        assert_eq!(loaded, doc);
        let rec = &loaded.sealed["acme"];
        assert_eq!(rec.node.node.id, "acme");
        assert_eq!(rec.node.pinned, Some(Pinned { x: 1.5, y: -2.0 }));
        assert_eq!(rec.orphan_entry_ids.len(), 2);
    }

    #[test]
    fn the_seal_record_wire_names_are_camel_case_and_the_node_is_flattened() {
        let mut doc = sample_doc();
        doc.sealed.insert("acme".to_string(), sealed_sample("acme"));
        let v = serde_json::to_value(&doc).unwrap();
        let rec = &v["sealed"]["acme"];
        assert_eq!(v["format"], 2);
        assert_eq!(rec["v"], 1);
        assert_eq!(rec["id"], "acme");
        assert_eq!(rec["parentId"], "global");
        assert_eq!(rec["publicKey"], "aa".repeat(32));
        assert_eq!(rec["sealedAt"], 1_700_000_100);
        assert_eq!(rec["manifest"]["generation"], 4);
        assert_eq!(rec["manifest"]["manifestHmac"], "ab".repeat(32));
        assert_eq!(rec["nodeKeySha256"], "cd".repeat(32));
        assert_eq!(rec["orphanEntryIds"][1], "e_bbbbbbbbbbbb");
    }

    /// A registry an alpha build wrote has no `format` and no `sealed`: it reads
    /// as format 1 with nothing sealed.
    #[test]
    fn an_alpha_registry_reads_as_format_1_with_no_seals() {
        let alpha = br#"{"nodes":{},"grants":[],"vaultGeneration":3,"manifests":{}}"#;
        let doc: RegistryDocument = serde_json::from_slice(alpha).unwrap();
        assert_eq!(doc.format, 1);
        assert!(doc.sealed.is_empty());
        assert_eq!(doc.vault_generation, 3);
    }

    #[test]
    fn a_registry_of_a_newer_format_is_refused_by_name_after_it_authenticates() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [9u8; 32];
        let mut doc = sample_doc();
        doc.format = REGISTRY_FORMAT + 1;
        save(&paths, &rk, &doc).unwrap();
        match load(&paths, &rk) {
            Err(StoreError::RegistryFormatTooNew { found, supported }) => {
                assert_eq!((found, supported), (REGISTRY_FORMAT + 1, REGISTRY_FORMAT));
            }
            other => panic!("expected RegistryFormatTooNew, got {other:?}"),
        }
        // An unauthenticated file never reaches the format check: it is a
        // tamper, not a newer format.
        let mut bytes = atomic::read(&paths.registry()).unwrap();
        let last = bytes.len() - 2;
        bytes[last] ^= 0xFF;
        atomic::write(&paths.registry(), &bytes).unwrap();
        assert!(matches!(
            load(&paths, &rk),
            Err(StoreError::RegistryTampered { .. })
        ));
    }

    /// The whole point of putting the record in the registry: editing it fails
    /// the registry HMAC.
    #[test]
    fn editing_a_seal_record_fails_the_registry_signature() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [9u8; 32];
        let mut doc = sample_doc();
        doc.sealed.insert("acme".to_string(), sealed_sample("acme"));
        save(&paths, &rk, &doc).unwrap();

        let text = String::from_utf8(atomic::read(&paths.registry()).unwrap()).unwrap();
        let edited = text.replace("1700000100", "1900000000");
        assert_ne!(text, edited, "the fixture really contains the sealedAt");
        atomic::write(&paths.registry(), edited.as_bytes()).unwrap();
        assert!(matches!(
            load(&paths, &rk),
            Err(StoreError::RegistryTampered { .. })
        ));
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [9u8; 32];
        let doc = sample_doc();
        save(&paths, &rk, &doc).unwrap();
        let loaded = load(&paths, &rk).unwrap();
        assert_eq!(loaded, doc);
    }

    #[test]
    fn tampered_registry_json_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [9u8; 32];
        save(&paths, &rk, &sample_doc()).unwrap();

        // Flip one byte in registry.json without re-signing — simulates an
        // attacker (or disk corruption) editing the plaintext metadata.
        let mut bytes = atomic::read(&paths.registry()).unwrap();
        let last = bytes.len() - 2;
        bytes[last] ^= 0xFF;
        atomic::write(&paths.registry(), &bytes).unwrap();

        let err = load(&paths, &rk).unwrap_err();
        assert!(matches!(err, StoreError::RegistryTampered { .. }));
    }

    #[test]
    fn tampered_registry_sig_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [9u8; 32];
        save(&paths, &rk, &sample_doc()).unwrap();
        atomic::write(&paths.registry_sig(), b"not-a-valid-signature").unwrap();
        let err = load(&paths, &rk).unwrap_err();
        assert!(matches!(err, StoreError::RegistryTampered { .. }));
    }

    #[test]
    fn wrong_root_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        save(&paths, &[9u8; 32], &sample_doc()).unwrap();
        let err = load(&paths, &[8u8; 32]).unwrap_err();
        assert!(matches!(err, StoreError::RegistryTampered { .. }));
    }

    #[test]
    fn grant_created_by_is_always_human_on_the_wire() {
        let json = serde_json::to_string(&CreatedByHuman::Human).unwrap();
        assert_eq!(json, "\"human\"");
    }

    #[test]
    fn to_core_registry_drops_persistence_only_fields_but_keeps_resolve_shape() {
        let doc = sample_doc();
        let core_reg = doc.to_core_registry();
        assert!(core_reg.nodes.contains_key("global"));
        assert_eq!(core_reg.nodes["global"].kind, NodeKind::Global);
    }

    /// ADR-053 depends on it: a sealed node is absent from the access graph.
    #[test]
    fn a_sealed_node_is_not_in_the_core_registry() {
        let mut doc = sample_doc();
        doc.sealed.insert("acme".to_string(), sealed_sample("acme"));
        let core_reg = doc.to_core_registry();
        assert!(!core_reg.nodes.contains_key("acme"));
        assert_eq!(core_reg.nodes.len(), 1);
    }
}
