//! Per-node `manifest.json`. See `docs/03_DATA_MODEL.md §8` and
//! `docs/04_CRYPTO_AND_KEYS.md §6a`.
//!
//! The manifest is unencrypted by design — it's what the graph hover and
//! locked search read without a key (`02 §7`, `03 §2`) — but "unencrypted"
//! must not mean "unprotected": every manifest carries its own HMAC, and
//! the registry cross-binds each node's `(generation, hmac)` so neither
//! file can be rolled back to an older validly-signed version of itself
//! without contradicting the other.

use credmgr_core::inference::EntryType;
/// Moved to `credmgr_core::inference` by ADR-078 (an entry's sensitivity is now
/// computed from its fields, which is pure); re-exported so every
/// `credmgr_store::manifest::Sensitivity` path keeps compiling.
pub use credmgr_core::inference::Sensitivity;
use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::error::{Result, StoreError};
use crate::hexutil;
use crate::paths::VaultPaths;
use crate::registry_file::{ManifestBinding, RegistryDocument};

pub fn manifest_hmac_label(node_id: &str) -> String {
    format!("manifest-hmac/{node_id}")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEntry {
    pub id: String,
    pub name: String,
    #[serde(rename = "ref")]
    pub r#ref: u32,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    pub sensitivity: Sensitivity,
    pub field_count: u32,
    pub sha256: String,
    /// Unix epoch seconds — ADR-040.
    pub modified: i64,
    pub expires_at: Option<i64>,
    /// Unix epoch seconds, set by `entry.rotate` (ADR-048) — `None` for an
    /// entry that has never been rotated. Distinct from `modified`, which
    /// any mutating op bumps; `rotatedAt` is rotate-specific so the UI can
    /// show "last rotated" separately from "last edited".
    pub rotated_at: Option<i64>,
    /// ADR-078: the entry carries a field whose effective type is a TOTP seed.
    /// It exists so `counts.totp` can count a *server* entry that holds a 2FA
    /// seed (entry type `totp` alone would miss it).
    ///
    /// **Load-bearing: `skip_serializing_if`.** Every signed store document
    /// (this manifest, a rotation snapshot, a removal archive) is verified by
    /// *re-serialising the parsed struct* and comparing the HMAC, so a field
    /// that serialises when it holds its default would change the bytes of
    /// everything written before this field existed, and every such vault
    /// would then refuse to open as tampered. Written only when `true`; absent
    /// reads as `false` and re-serialises byte-identically. The golden tests in
    /// `crates/store/tests/alpha6_golden.rs` pin this.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_totp: bool,
}

// `skip_serializing_if` hands the predicate a `&bool`, hence the reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

impl ManifestEntry {
    /// Whether this entry counts toward `counts.totp`: it is typed `totp`, or
    /// it carries a TOTP-seed field (ADR-078).
    pub fn counts_as_totp(&self) -> bool {
        self.entry_type == EntryType::Totp || self.has_totp
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Counts {
    pub entries: u32,
    pub totp: u32,
}

/// Everything the manifest hmac covers — `04 §6a`: "the manifest *without
/// this field*", i.e. without `hmac` itself. Kept as its own type so
/// signing always operates on a value that structurally cannot contain the
/// tag it's computing, rather than on a JSON object with one key stripped
/// out by convention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBody {
    pub node_id: String,
    pub entries: Vec<ManifestEntry>,
    pub counts: Counts,
    pub notes_sha256: Option<String>,
    pub generation: u64,
}

impl ManifestBody {
    pub fn new(node_id: impl Into<String>) -> Self {
        ManifestBody {
            node_id: node_id.into(),
            entries: Vec::new(),
            counts: Counts::default(),
            notes_sha256: None,
            generation: 0,
        }
    }

    /// Recompute `counts` from `entries` — the single place the counts are
    /// derived, so an insert, an update and a remove can never disagree about
    /// what `counts.totp` means (ADR-078: entries typed `totp` **or** carrying
    /// a TOTP-seed field). Before this existed, an update never recounted, so a
    /// rotate that turned a text value into a TOTP seed left `counts.totp`
    /// stale. Does not touch `generation`.
    pub fn recount(&mut self) {
        self.counts.entries = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        self.counts.totp =
            u32::try_from(self.entries.iter().filter(|e| e.counts_as_totp()).count())
                .unwrap_or(u32::MAX);
    }
}

/// The on-disk shape: [`ManifestBody`]'s fields plus the `hmac` tag over
/// them, all in one flat JSON object (matches the example in `03 §8`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestDoc {
    #[serde(flatten)]
    pub body: ManifestBody,
    pub hmac: String,
}

fn json_err(path: &std::path::Path, source: serde_json::Error) -> StoreError {
    StoreError::Json {
        path: path.to_path_buf(),
        source,
    }
}

/// Serialise and sign a node's manifest without touching the disk: the exact
/// bytes [`save`] would write, plus the [`ManifestBinding`] the registry must
/// record for them. Shared by [`save`] and by root-key rotation (ADR-076),
/// which stages these bytes under the *new* root key before anything is
/// replaced.
pub fn signed_bytes(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    body: &ManifestBody,
) -> Result<(Vec<u8>, ManifestBinding)> {
    let path = paths.manifest(&body.node_id);
    let body_bytes = serde_json::to_vec(body).map_err(|e| json_err(&path, e))?;
    let tag =
        credmgr_core::signing::sign(root_key, &manifest_hmac_label(&body.node_id), &body_bytes);
    let hmac_hex = hexutil::encode(&tag);

    let doc = ManifestDoc {
        body: body.clone(),
        hmac: hmac_hex.clone(),
    };
    let full_bytes = serde_json::to_vec_pretty(&doc).map_err(|e| json_err(&path, e))?;
    Ok((
        full_bytes,
        ManifestBinding {
            generation: body.generation,
            manifest_hmac: hmac_hex,
        },
    ))
}

/// Sign and atomically write a node's manifest. Returns the
/// [`ManifestBinding`] the caller must record in `RegistryDocument.manifests`
/// under the same node id — the cross-binding is only as good as both sides
/// being updated in the same registry write that this manifest write
/// precedes (`store::registry_file::save` after this, same node-write
/// transaction; enforced by the broker's per-node write lock in Phase 3).
pub fn save(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    body: &ManifestBody,
) -> Result<ManifestBinding> {
    let (full_bytes, binding) = signed_bytes(paths, root_key, body)?;
    atomic::write(&paths.manifest(&body.node_id), &full_bytes)?;
    Ok(binding)
}

/// Load and verify a node's manifest. The bytes verified are always a fresh
/// `serde_json` serialisation of the *parsed* body — so tampering with any
/// field (an entry removed, a count inflated, an id repointed) changes what
/// gets re-signed for comparison, and the stored `hmac` (also attacker-
/// visible but not attacker-forgeable without `root_key`) no longer matches.
pub fn load(paths: &VaultPaths, root_key: &[u8; 32], node_id: &str) -> Result<ManifestDoc> {
    load_at(&paths.manifest(node_id), root_key, node_id)
}

/// [`load`] for a manifest that lives somewhere other than its node's live
/// directory — a sealed node's copy under `archive/<id>/node/` (ADR-076).
pub fn load_at(path: &std::path::Path, root_key: &[u8; 32], node_id: &str) -> Result<ManifestDoc> {
    let full_bytes = atomic::read(path)?;
    let doc: ManifestDoc = serde_json::from_slice(&full_bytes).map_err(|e| json_err(path, e))?;

    let tag = hexutil::decode_32(&doc.hmac).ok_or_else(|| StoreError::ManifestTampered {
        node_id: node_id.to_string(),
    })?;
    let body_bytes = serde_json::to_vec(&doc.body).map_err(|e| json_err(path, e))?;
    if !credmgr_core::signing::verify(root_key, &manifest_hmac_label(node_id), &body_bytes, &tag) {
        return Err(StoreError::ManifestTampered {
            node_id: node_id.to_string(),
        });
    }
    Ok(doc)
}

/// Re-sign the manifest at `path` under `new_root`, **only if it verifies
/// under `old_root` first** — re-signing a manifest that already fails its
/// HMAC would launder the tamper (root-key rotation, ADR-076). Returns the
/// bytes to write; touches nothing.
pub fn resigned_at(
    path: &std::path::Path,
    node_id: &str,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> Result<Vec<u8>> {
    let doc = load_at(path, old_root, node_id)?;
    let body_bytes = serde_json::to_vec(&doc.body).map_err(|e| json_err(path, e))?;
    let tag = credmgr_core::signing::sign(new_root, &manifest_hmac_label(node_id), &body_bytes);
    let resigned = ManifestDoc {
        body: doc.body,
        hmac: hexutil::encode(&tag),
    };
    serde_json::to_vec_pretty(&resigned).map_err(|e| json_err(path, e))
}

/// `04 §6a`'s cross-binding check: the registry's recorded belief about this
/// node's manifest must agree with the manifest's own (already-verified)
/// generation and hmac.
pub fn verify_cross_binding(
    registry: &RegistryDocument,
    node_id: &str,
    manifest: &ManifestDoc,
) -> Result<()> {
    let binding =
        registry
            .manifests
            .get(node_id)
            .ok_or_else(|| StoreError::ManifestRegistryMismatch {
                node_id: node_id.to_string(),
                detail: "registry has no manifest binding recorded for this node",
            })?;
    if binding.generation != manifest.body.generation {
        return Err(StoreError::ManifestRegistryMismatch {
            node_id: node_id.to_string(),
            detail: "generation differs between registry and manifest",
        });
    }
    if binding.manifest_hmac != manifest.hmac {
        return Err(StoreError::ManifestRegistryMismatch {
            node_id: node_id.to_string(),
            detail: "hmac differs between registry and manifest",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_file::RegistryDocument;

    fn sample_body() -> ManifestBody {
        let mut body = ManifestBody::new("n_aaaaaaaa");
        body.generation = 5;
        body.counts = Counts {
            entries: 1,
            totp: 0,
        };
        body.entries.push(ManifestEntry {
            id: "e_bbbbbbbbbbbb".to_string(),
            name: "vps-root".to_string(),
            r#ref: 3060,
            entry_type: EntryType::Server,
            sensitivity: Sensitivity::Critical,
            field_count: 4,
            sha256: "deadbeef".to_string(),
            modified: 1_700_000_000,
            expires_at: None,
            rotated_at: None,
            has_totp: false,
        });
        body
    }

    #[test]
    fn ref_field_serialises_as_ref_not_r_hash_ref() {
        let entry = &sample_body().entries[0];
        let v = serde_json::to_value(entry).unwrap();
        assert_eq!(v["ref"], 3060);
        assert!(v.get("r#ref").is_none());
    }

    #[test]
    fn save_then_load_round_trips_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [3u8; 32];
        let body = sample_body();
        let binding = save(&paths, &rk, &body).unwrap();
        let doc = load(&paths, &rk, "n_aaaaaaaa").unwrap();
        assert_eq!(doc.body, body);
        assert_eq!(doc.hmac, binding.manifest_hmac);
    }

    #[test]
    fn tampered_manifest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [3u8; 32];
        save(&paths, &rk, &sample_body()).unwrap();

        // Attacker deletes the one entry, hoping counts/hmac aren't checked.
        let path = paths.manifest("n_aaaaaaaa");
        let mut doc: ManifestDoc = serde_json::from_slice(&atomic::read(&path).unwrap()).unwrap();
        doc.body.entries.clear();
        atomic::write(&path, &serde_json::to_vec(&doc).unwrap()).unwrap();

        let err = load(&paths, &rk, "n_aaaaaaaa").unwrap_err();
        assert!(matches!(err, StoreError::ManifestTampered { .. }));
    }

    #[test]
    fn cross_binding_catches_a_manifest_rolled_back_alone() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [3u8; 32];

        let mut body = sample_body();
        let binding_v1 = save(&paths, &rk, &body).unwrap();
        let mut registry = RegistryDocument::new();
        registry
            .manifests
            .insert("n_aaaaaaaa".to_string(), binding_v1);

        body.generation = 6;
        body.entries.clear();
        save(&paths, &rk, &body).unwrap(); // registry NOT updated — simulates rollback

        let manifest_v2 = load(&paths, &rk, "n_aaaaaaaa").unwrap(); // verifies fine on its own
        let err = verify_cross_binding(&registry, "n_aaaaaaaa", &manifest_v2).unwrap_err();
        assert!(matches!(err, StoreError::ManifestRegistryMismatch { .. }));
    }

    #[test]
    fn counts_are_readable_without_any_key_the_locked_graph_requirement() {
        // The manifest file itself is plaintext JSON — no decryption
        // involved in reading `counts`, only signature verification (which
        // needs the root key). This test documents that `serde_json` alone
        // can read the counts back out of the bytes on disk, independent of
        // `load`'s verification path — matching `02 §7`'s "manifest counts
        // readable while locked" requirement at the file-format level.
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        save(&paths, &[3u8; 32], &sample_body()).unwrap();

        let raw = atomic::read(&paths.manifest("n_aaaaaaaa")).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["counts"]["entries"], 1);
    }
}
