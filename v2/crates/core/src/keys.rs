//! Node keypair generation and root-key wrapping. See
//! `docs/04_CRYPTO_AND_KEYS.md §2–3`.
//!
//! This module does not implement the root key's own wraps (SE / passphrase /
//! recovery) — those need a platform keystore and belong to `crates/keystore`
//! and `crates/brokerd` (Phase 2/3). What belongs here, because it is pure
//! compute, is the one link between them: wrapping a node's private key under
//! the (already-unwrapped) root key.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::CryptoError;

const NONCE_LEN: usize = 12;
const NODE_PRIV_LEN: usize = 32;

/// One node's X25519 keypair. The public half is registry cleartext; the
/// private half only ever exists unwrapped in the broker's hot key set.
pub struct NodeKeyPair {
    pub public: PublicKey,
    pub private: StaticSecret,
}

/// Fresh X25519 keypair for a new node.
pub fn generate_node_keypair() -> NodeKeyPair {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    NodeKeyPair { public, private }
}

/// A node's private key, encrypted under a key derived from the root key.
/// Lives on disk at `keys/nodes/<id>.key` (`04 §2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedNodeKey {
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by the 16-byte AEAD tag.
    pub ciphertext: Vec<u8>,
}

impl WrappedNodeKey {
    /// On-disk wire format: `nonce (12) || ciphertext‖tag (48)` — 60 bytes,
    /// no length prefix, every field fixed-size. Mirrors
    /// `recovery::RootRecoveryWrap::to_bytes` for the same reason.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < NONCE_LEN + NODE_PRIV_LEN + 16 {
            return Err(CryptoError::Truncated);
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce);
        Ok(WrappedNodeKey {
            nonce: nonce_arr,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// `HKDF-SHA512(ikm = RK, info = label)` — every place this crate needs a
/// purpose-bound 32-byte key derived from the (already-unwrapped) root key
/// goes through here: node-key wrapping (below), and the registry/manifest/
/// generation-counter HMAC keys in `signing.rs` (`04_CRYPTO_AND_KEYS.md
/// §6a`). One derivation function means one place that can get the KDF
/// choice wrong, and it means every derived key is automatically bound to
/// its own distinct label — reusing a label across two purposes is the only
/// way to make two "unrelated" keys equal, and callers can't do that by
/// accident because the label is always a literal at the call site.
pub fn derive_subkey(root_key: &[u8; 32], label: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(None, root_key);
    let mut key = [0u8; 32];
    hk.expand(label.as_bytes(), &mut key)
        .expect("32-byte output is within HKDF-SHA512's max length");
    key
}

/// `credmgr/v2/node-wrap/` + node_id — the node id is folded into the info
/// label (beyond what `04 §2`'s diagram spells out) so a wrapped key blob is
/// bound to the specific node it wraps, consistent with this crate's general
/// principle of binding ciphertexts to their intended location (see
/// `envelope.rs`'s AAD, `06_ACCESS_GRAPH.md`).
fn derive_wrap_key(root_key: &[u8; 32], node_id: &str) -> [u8; 32] {
    derive_subkey(root_key, &format!("credmgr/v2/node-wrap/{node_id}"))
}

/// Wrap `node_priv` for storage, under a key derived from the (unwrapped)
/// root key and bound to `node_id`.
pub fn wrap_node_key(
    root_key: &[u8; 32],
    node_id: &str,
    node_priv: &StaticSecret,
) -> WrappedNodeKey {
    let mut wrap_key_bytes = derive_wrap_key(root_key, node_id);
    let key = Key::from_slice(&wrap_key_bytes);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    let mut buffer = node_priv.to_bytes().to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut buffer)
        .expect("ChaCha20Poly1305 encryption of a 32-byte key cannot fail");
    buffer.extend_from_slice(&tag);

    wrap_key_bytes.zeroize();
    WrappedNodeKey {
        nonce: nonce_bytes,
        ciphertext: buffer,
    }
}

/// Reverse of [`wrap_node_key`]. Fails if `root_key` or `node_id` do not
/// match what the key was wrapped under, or the blob was tampered with.
pub fn unwrap_node_key(
    root_key: &[u8; 32],
    node_id: &str,
    wrapped: &WrappedNodeKey,
) -> Result<StaticSecret, CryptoError> {
    if wrapped.ciphertext.len() < NODE_PRIV_LEN + 16 {
        return Err(CryptoError::Truncated);
    }
    let mut wrap_key_bytes = derive_wrap_key(root_key, node_id);
    let key = Key::from_slice(&wrap_key_bytes);
    let nonce = Nonce::from_slice(&wrapped.nonce);

    let (ct, tag) = wrapped.ciphertext.split_at(wrapped.ciphertext.len() - 16);
    let mut buffer = ct.to_vec();
    let tag_array = chacha20poly1305::Tag::from_slice(tag);

    let cipher = ChaCha20Poly1305::new(key);
    let result = cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, tag_array);
    wrap_key_bytes.zeroize();
    result.map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut arr = [0u8; NODE_PRIV_LEN];
    arr.copy_from_slice(&buffer);
    buffer.zeroize();
    Ok(StaticSecret::from(arr))
}

/// Re-wrap a node's private key from one root key to another — the one
/// per-node step of a root-key rotation (`04 §6`, ADR-076).
///
/// The node's own keypair is **unchanged**: only the blob that protects the
/// private half is replaced, so every entry envelope sealed to the node's
/// public key stays readable and nothing under `nodes/` needs re-encrypting.
/// The unwrapped private key lives in a [`StaticSecret`] for the length of
/// this call and zeroises on drop. Fails — leaving the caller holding only
/// the old blob — if `old_root` or `node_id` do not match what `wrapped` was
/// wrapped under, or the blob was tampered with.
pub fn rewrap_node_key(
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    node_id: &str,
    wrapped: &WrappedNodeKey,
) -> Result<WrappedNodeKey, CryptoError> {
    let private = unwrap_node_key(old_root, node_id, wrapped)?;
    Ok(wrap_node_key(new_root, node_id, &private))
}

/// Seal a small secret for storage inside a signed-but-plaintext metadata
/// file (`registry.json`) — ChaCha20-Poly1305 under
/// `HKDF(root_key, label)`, output `nonce ‖ ciphertext ‖ tag`.
///
/// ADR-064: the vault gate's TOTP secret is persisted in the registry's
/// `gate.twofa` field. The registry's HMAC stops anyone without the root key
/// from *removing or altering* a gate; this seal stops anyone who can merely
/// *read* the registry from learning the seed. `label` is per-purpose and
/// per-scope (`credmgr/v2/gate-secret/<scope>`), the same one-label-one-use
/// rule [`derive_subkey`] states.
pub fn seal_under_root(root_key: &[u8; 32], label: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut key_bytes = derive_subkey(root_key, label);
    let key = Key::from_slice(&key_bytes);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut buffer)
        .expect("ChaCha20Poly1305 encryption of an in-memory buffer cannot fail");
    key_bytes.zeroize();

    let mut out = Vec::with_capacity(NONCE_LEN + buffer.len() + 16);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&tag);
    buffer.zeroize();
    out
}

/// Reverse of [`seal_under_root`]. Fails on a wrong root key, a wrong label,
/// a truncated blob, or any tampering — one undifferentiated error, like
/// every other AEAD open in this crate.
pub fn open_under_root(
    root_key: &[u8; 32],
    label: &str,
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(CryptoError::Truncated);
    }
    let (nonce_bytes, rest) = sealed.split_at(NONCE_LEN);
    let (ct, tag) = rest.split_at(rest.len() - 16);
    let mut key_bytes = derive_subkey(root_key, label);
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let mut buffer = ct.to_vec();
    let result = cipher.decrypt_in_place_detached(
        Nonce::from_slice(nonce_bytes),
        b"",
        &mut buffer,
        chacha20poly1305::Tag::from_slice(tag),
    );
    key_bytes.zeroize();
    match result {
        Ok(()) => Ok(buffer),
        Err(_) => {
            buffer.zeroize();
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_under_root_round_trips_and_binds_key_and_label() {
        let rk = [3u8; 32];
        let sealed = seal_under_root(
            &rk,
            "credmgr/v2/gate-secret/global",
            b"twenty-byte-secret!!",
        );
        assert_eq!(
            open_under_root(&rk, "credmgr/v2/gate-secret/global", &sealed).unwrap(),
            b"twenty-byte-secret!!"
        );
        assert!(open_under_root(&[4u8; 32], "credmgr/v2/gate-secret/global", &sealed).is_err());
        assert!(open_under_root(&rk, "credmgr/v2/gate-secret/other", &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_under_root(&rk, "credmgr/v2/gate-secret/global", &tampered).is_err());
        assert!(open_under_root(&rk, "credmgr/v2/gate-secret/global", &sealed[..10]).is_err());
        // Fresh nonce per seal: the same input never produces the same blob.
        assert_ne!(
            sealed,
            seal_under_root(
                &rk,
                "credmgr/v2/gate-secret/global",
                b"twenty-byte-secret!!"
            )
        );
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let root_key = [7u8; 32];
        let pair = generate_node_keypair();
        let wrapped = wrap_node_key(&root_key, "n_aaaaaaaa", &pair.private);
        let unwrapped = unwrap_node_key(&root_key, "n_aaaaaaaa", &wrapped).unwrap();
        assert_eq!(unwrapped.to_bytes(), pair.private.to_bytes());
    }

    #[test]
    fn wrong_root_key_fails() {
        let root_key = [7u8; 32];
        let other_key = [9u8; 32];
        let pair = generate_node_keypair();
        let wrapped = wrap_node_key(&root_key, "n_aaaaaaaa", &pair.private);
        let err = unwrap_node_key(&other_key, "n_aaaaaaaa", &wrapped)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err, CryptoError::AuthenticationFailed);
    }

    #[test]
    fn wrong_node_id_fails() {
        let root_key = [7u8; 32];
        let pair = generate_node_keypair();
        let wrapped = wrap_node_key(&root_key, "n_aaaaaaaa", &pair.private);
        let err = unwrap_node_key(&root_key, "n_bbbbbbbb", &wrapped)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err, CryptoError::AuthenticationFailed);
    }

    #[test]
    fn wrapping_is_nondeterministic() {
        let root_key = [7u8; 32];
        let pair = generate_node_keypair();
        let w1 = wrap_node_key(&root_key, "n_aaaaaaaa", &pair.private);
        let w2 = wrap_node_key(&root_key, "n_aaaaaaaa", &pair.private);
        assert_ne!(w1, w2);
    }

    #[test]
    fn bytes_round_trip() {
        let root_key = [7u8; 32];
        let pair = generate_node_keypair();
        let wrapped = wrap_node_key(&root_key, "n_aaaaaaaa", &pair.private);
        let bytes = wrapped.to_bytes();
        let parsed = WrappedNodeKey::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, wrapped);
        let unwrapped = unwrap_node_key(&root_key, "n_aaaaaaaa", &parsed).unwrap();
        assert_eq!(unwrapped.to_bytes(), pair.private.to_bytes());
    }

    #[test]
    fn truncated_bytes_are_rejected() {
        let err = WrappedNodeKey::from_bytes(&[0u8; 4]).unwrap_err();
        assert_eq!(err, CryptoError::Truncated);
    }

    /// ADR-076: a rotation re-wraps, it does not re-key. The node keeps the
    /// same private key (so every envelope sealed to its public key still
    /// opens), the new blob opens only under the new root, and the old root
    /// opens only the old blob.
    #[test]
    fn rewrap_keeps_the_private_key_and_moves_it_to_the_new_root() {
        let old_root = [7u8; 32];
        let new_root = [8u8; 32];
        let pair = generate_node_keypair();
        let old_blob = wrap_node_key(&old_root, "n_aaaaaaaa", &pair.private);

        let new_blob = rewrap_node_key(&old_root, &new_root, "n_aaaaaaaa", &old_blob).unwrap();

        let reopened = unwrap_node_key(&new_root, "n_aaaaaaaa", &new_blob).unwrap();
        assert_eq!(reopened.to_bytes(), pair.private.to_bytes());
        assert_eq!(PublicKey::from(&reopened), pair.public);
        assert!(unwrap_node_key(&old_root, "n_aaaaaaaa", &new_blob).is_err());
        assert!(unwrap_node_key(&new_root, "n_aaaaaaaa", &old_blob).is_err());
        assert_ne!(new_blob, old_blob);
    }

    #[test]
    fn rewrap_refuses_a_wrong_old_root_or_a_relocated_node_id() {
        let old_root = [7u8; 32];
        let new_root = [8u8; 32];
        let pair = generate_node_keypair();
        let blob = wrap_node_key(&old_root, "n_aaaaaaaa", &pair.private);

        assert_eq!(
            rewrap_node_key(&[9u8; 32], &new_root, "n_aaaaaaaa", &blob).unwrap_err(),
            CryptoError::AuthenticationFailed
        );
        assert_eq!(
            rewrap_node_key(&old_root, &new_root, "n_bbbbbbbb", &blob).unwrap_err(),
            CryptoError::AuthenticationFailed
        );
        let mut tampered = blob.clone();
        *tampered.ciphertext.last_mut().unwrap() ^= 1;
        assert!(rewrap_node_key(&old_root, &new_root, "n_aaaaaaaa", &tampered).is_err());
    }
}
