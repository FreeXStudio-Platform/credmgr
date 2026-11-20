//! ADR-165 N5 — a passphrase change (ADR-156) or a recovery (ADR-163) gives every live node a **new** keypair,
//! inside the root rotation's own stage and under its one commit record.
//!
//! A root rotation alone re-wraps each node's private key under the new root key; the keypair stays. A copy
//! of the vault folder from before the change, opened with the OLD passphrase (or the old recovery code),
//! still yields the old root key, then the old wrapped node keys, which open every envelope sealed to those
//! same public keys later — the entries written after the change included. So these two rotations also
//! replace the node keypairs: a fresh X25519 pair per live node, every envelope the node holds opened with the
//! old private half and sealed to the new public half (`rekey::reseal_node_files`, the code `node.rekey` uses),
//! the manifest rows carrying the new digests, the registry naming the new public keys.
//!
//! **Crash safety is the rotation's, unchanged.** Every re-sealed envelope is one more staged file under
//! `rotation-pending/`; the manifests, the node key files and the registry were already staged; the single
//! `COMMIT` record makes the whole set binding at once, and the key-free roll-forward moves every file before
//! anything reads the vault (`credmgr_store::rotation`). A crash before the record leaves every file as it
//! was (old root, old node keys); after it, every file is the new one (new root, new node keys). There is no
//! state in between to recover: no second stage, no second record.
//!
//! **Which nodes.** Every registry node but the orphan — global included, and a node that is locked on its
//! own (the root key opens its wrapped key; its hot key stays zeroised). Writes waiting in a node's
//! locked-write tray are re-sealed too (the tray is untrusted: a file there that does not open is left as it
//! is), so neither op refuses for a locked node or a full tray as `keystore.bind` does. A **sealed** node
//! keeps its keypair (its archived key is re-wrapped by the rotation, as before): nothing is written to it
//! while sealed, and `node.restore` brings it back on that key; `node.rekey` gives it a new one after. The
//! **orphan**'s cold keypair is replaced, as the bind's rotation replaces it, when it holds no sealed copy;
//! when it holds some, it is kept (re-sealed under the new root, as before) and named in `notResigned`.
//!
//! **Fail honest, never refuse on one bad file.** An envelope that does not open under its node's current
//! key opened nothing before and opens nothing after; it is left exactly as it is and named in
//! `notResigned`, rather than turning a damaged file into an owner who cannot change a leaked passphrase or
//! cannot get back in with the recovery code. A node whose wrapped key does not open under the old root
//! still refuses the whole rotation (`NodeKey`), as the re-wrap always did.

use std::collections::HashMap;
use std::path::PathBuf;

use x25519_dalek::{PublicKey, StaticSecret};

use credmgr_core::envelope;
use credmgr_core::keys::{generate_node_keypair, unwrap_node_key, wrap_node_key, WrappedNodeKey};
use credmgr_core::registry::ORPHAN_ID;
use credmgr_store::{atomic, rotation};
use secrecy::ExposeSecret;

use super::super::rekey::{reseal_node_files, ItemKind, OnUnreadable, Resealed};
use super::super::{hex_encode, sha256_of, BrokerState};

/// One node's new keypair and everything re-sealed to it.
pub(in crate::state) struct NodeRekey {
    pub id: String,
    pub private: StaticSecret,
    pub public: PublicKey,
    /// The node's envelopes (entries, note, merge memory, retained history, removed entries).
    pub files: Vec<Resealed>,
    /// Locked-write tray envelopes re-sealed: `(entry id, live path, bytes, sha256)`.
    pub tray: Vec<(String, PathBuf, Vec<u8>, String)>,
}

/// What a rotation's re-key will change, computed before anything is staged.
#[derive(Default)]
pub(in crate::state) struct LiveRekey {
    pub nodes: Vec<NodeRekey>,
    /// Whatever was left as it was, for `notResigned`.
    pub skipped: Vec<rotation::Skipped>,
}

impl LiveRekey {
    /// Every file this re-key stages (envelopes and tray envelopes).
    pub fn files_resealed(&self) -> usize {
        self.nodes
            .iter()
            .map(|n| n.files.len() + n.tray.len())
            .sum()
    }

    pub fn node_ids(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.id.clone()).collect()
    }
}

fn tray_files(
    state: &BrokerState,
    node: &str,
    old: &StaticSecret,
    new_public: &PublicKey,
    skipped: &mut Vec<rotation::Skipped>,
) -> Vec<(String, PathBuf, Vec<u8>, String)> {
    let dir = state.paths.node_dir(node).join("pending");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .filter_map(|d| {
                    let p = d.path();
                    (p.extension().and_then(|e| e.to_str()) == Some("env"))
                        .then(|| p.file_stem()?.to_str().map(str::to_string))
                        .flatten()
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let mut out = Vec::new();
    for entry in names {
        // Only a name the broker could have minted is a path component it builds (`tray.rs`).
        let plain = entry.len() <= 80
            && !entry.is_empty()
            && entry
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !plain {
            continue;
        }
        let path = state.paths.pending_env(node, &entry);
        let resealed = atomic::read(&path).ok().and_then(|bytes| {
            let (kind, plaintext) = envelope::open_any(&bytes, old, node, &entry).ok()?;
            envelope::seal_as(kind, plaintext.expose_secret(), new_public, node, &entry).ok()
        });
        match resealed {
            Some(sealed) => {
                let sha = hex_encode(&sha256_of(&sealed));
                out.push((entry, path, sealed, sha));
            }
            None => skipped.push(rotation::Skipped {
                kind: "rekey-tray",
                id: format!("{node}/{entry}"),
                reason: "a locked-write tray file that did not open under the node's key; left as it was"
                    .to_string(),
            }),
        }
    }
    out
}

impl BrokerState {
    /// Plan the re-key of every live node (module docs) against `old`, the root key the vault runs under now.
    /// Draws the new keypairs and re-seals in memory; writes nothing. `new_wrapped` (the rotation's re-wrapped
    /// node keys under `new`) gets each re-keyed node's NEW private key wrapped under `new` in place of the
    /// re-wrapped old one.
    pub(in crate::state) fn plan_live_rekey(
        &self,
        old: &[u8; 32],
        new: &[u8; 32],
        current_wrapped: &HashMap<String, WrappedNodeKey>,
        new_wrapped: &mut HashMap<String, WrappedNodeKey>,
    ) -> Result<LiveRekey, super::RotateRootError> {
        let mut ids: Vec<String> = self
            .registry
            .read()
            .expect("registry poisoned")
            .nodes
            .keys()
            .filter(|id| id.as_str() != ORPHAN_ID)
            .cloned()
            .collect();
        ids.sort();
        let registry_public: HashMap<String, String> = self
            .registry_meta
            .read()
            .expect("registry meta poisoned")
            .nodes
            .iter()
            .map(|(id, n)| (id.clone(), n.public_key.clone()))
            .collect();
        let mut plan = LiveRekey::default();
        for id in ids {
            let Some(wrapped) = current_wrapped.get(&id) else {
                plan.skipped.push(rotation::Skipped {
                    kind: "rekey-node",
                    id: id.clone(),
                    reason: "no wrapped key for this node; its keypair was left as it was"
                        .to_string(),
                });
                continue;
            };
            let old_priv = unwrap_node_key(old, &id, wrapped)
                .map_err(|_| super::RotateRootError::NodeKey(id.clone()))?;
            let old_public = PublicKey::from(&old_priv);
            if registry_public.get(&id).map(String::as_str)
                != Some(hex_encode(old_public.as_bytes()).as_str())
            {
                // The private key does not match the public key the registry names: whatever was sealed to
                // the registry's key never opened with this one. Re-wrap it as before and say so.
                plan.skipped.push(rotation::Skipped {
                    kind: "rekey-node",
                    id: id.clone(),
                    reason: "this node's private key does not match its public key; its keypair was left \
                             as it was — run `credmgr verify`"
                        .to_string(),
                });
                continue;
            }
            let rows: Vec<String> = self
                .manifests
                .read()
                .expect("manifests poisoned")
                .get(&id)
                .map(|m| m.entries.iter().map(|e| e.id.clone()).collect())
                .unwrap_or_default();
            let pair = generate_node_keypair();
            let (files, left) = reseal_node_files(
                &self.paths,
                &id,
                &rows,
                &old_priv,
                &pair.public,
                OnUnreadable::LeaveAndName,
            )
            .map_err(|e| {
                super::RotateRootError::Store(super::super::durable::corrupt(
                    self.paths.node_dir(&id),
                    &format!("re-keying node {id}: {e:?}"),
                ))
            })?;
            for (what, reason) in left {
                plan.skipped.push(rotation::Skipped {
                    kind: "rekey-file",
                    id: what,
                    reason,
                });
            }
            let tray = tray_files(self, &id, &old_priv, &pair.public, &mut plan.skipped);
            new_wrapped.insert(id.clone(), wrap_node_key(new, &id, &pair.private));
            plan.nodes.push(NodeRekey {
                id,
                private: pair.private,
                public: pair.public,
                files,
                tray,
            });
        }
        Ok(plan)
    }
}

/// The manifest digests a node's re-key changes: rows by entry id, the note, the merge memory.
pub(in crate::state) fn new_digests(
    node: &NodeRekey,
) -> (HashMap<String, String>, Option<String>, Option<String>) {
    let mut rows = HashMap::new();
    let mut note = None;
    let mut merge = None;
    for f in &node.files {
        match f.kind {
            ItemKind::Entry => {
                if let Some(e) = &f.entry {
                    rows.insert(e.clone(), f.sha256.clone());
                }
            }
            ItemKind::Notes => note = Some(f.sha256.clone()),
            ItemKind::MergeMemory => merge = Some(f.sha256.clone()),
            _ => {}
        }
    }
    (rows, note, merge)
}
