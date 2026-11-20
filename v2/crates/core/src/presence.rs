//! Presence attestation — what a Secure Enclave key signs, and how the broker checks it (ADR-098).
//!
//! A *presence proof* is an ECDSA P-256 signature, made by a hardware key that only signs after the
//! user has touched the sensor (or typed the device password), over a digest that names **this**
//! broker-issued nonce, **this** operation and **these** parameters. The broker verifies it itself; it
//! never takes a client's word that "the user was there". A proof therefore cannot be replayed (single
//! use, short TTL, broker-issued nonce) and cannot be moved to a different operation or different
//! parameters (both are inside the digest).
//!
//! This module is pure compute like the rest of `credmgr-core`: byte formats and a verifier. Obtaining a
//! signature (the helper process, the sensor) and remembering nonces (the broker) are not its job.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Domain separation: no other signature this key could ever make is valid as a presence proof.
pub const DOMAIN: &[u8] = b"credmgr/v2/presence/v1\0";
/// Length of the broker-issued nonce.
pub const NONCE_LEN: usize = 32;
/// An ANSI X9.63 uncompressed P-256 point (`0x04 ‖ X ‖ Y`).
pub const PUBLIC_LEN: usize = 65;
/// A raw ECDSA signature, `r ‖ s`, 32 bytes each.
pub const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceError {
    /// The enrolled public key is not a valid P-256 point.
    BadKey,
    /// The signature is malformed.
    BadSignature,
    /// The signature is well-formed but does not verify for this key and digest.
    NotVerified,
}

impl std::fmt::Display for PresenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PresenceError::BadKey => "the enrolled presence key is not a valid P-256 point",
            PresenceError::BadSignature => "the presence signature is malformed",
            PresenceError::NotVerified => "the presence signature does not verify",
        })
    }
}

impl std::error::Error for PresenceError {}

/// Canonical JSON: object keys sorted, no insignificant whitespace, numbers and strings as `serde_json`
/// writes them. Deterministic regardless of the `preserve_order` feature any other crate enables, so the
/// client and the broker hash the same bytes for the same request.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(
                    serde_json::to_string(k)
                        .expect("a string always serialises")
                        .as_bytes(),
                );
                out.push(b':');
                write_canonical(&map[*k], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        other => out.extend_from_slice(
            serde_json::to_string(other)
                .expect("a scalar always serialises")
                .as_bytes(),
        ),
    }
}

/// The 32 bytes a presence key signs (it hashes them once more with SHA-256 internally, as every ECDSA
/// P-256 signer does).
///
/// `SHA-256( DOMAIN ‖ nonce ‖ be32(len(op)) ‖ op ‖ canonical_json(params) )`
pub fn digest(nonce: &[u8; NONCE_LEN], op: &str, params: &Value) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(nonce);
    h.update((op.len() as u32).to_be_bytes());
    h.update(op.as_bytes());
    h.update(canonical_json(params));
    h.finalize().into()
}

/// Whether `signature` (raw `r ‖ s`) is `public`'s signature over `digest`.
pub fn verify(public: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), PresenceError> {
    let key = VerifyingKey::from_sec1_bytes(public).map_err(|_| PresenceError::BadKey)?;
    let sig = Signature::from_slice(signature).map_err(|_| PresenceError::BadSignature)?;
    key.verify(digest, &sig)
        .map_err(|_| PresenceError::NotVerified)
}

// ---- the device wrap: the root key sealed to a Secure Enclave public key ----------------------------

const WRAP_MAGIC: &[u8; 4] = b"CMSE";
const WRAP_VERSION: u8 = 1;
const WRAP_INFO: &[u8] = b"credmgr/v2/se-wrap/v1";
const WRAP_HEADER: usize = 5 + PUBLIC_LEN + 12;
/// Length of every sealed root: `CMSE ‖ v ‖ ephemeral public ‖ nonce ‖ ciphertext(32) ‖ tag(16)`.
pub const SEALED_ROOT_LEN: usize = WRAP_HEADER + 32 + 16;

fn wrap_key(shared: &[u8], eph_public: &[u8]) -> [u8; 32] {
    let mut out = <[u8; 32]>::default();
    Hkdf::<Sha256>::new(Some(eph_public), shared)
        .expand(WRAP_INFO, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Seal `root` for the Secure Enclave key whose ECDH with an ephemeral key gave `shared`, the ephemeral key's
/// public point being `eph_public`. The ECDH itself is done by the Secure Enclave helper (`ephemeral`), so
/// nothing here handles a secret curve scalar: this crate keeps P-256 for *verifying* signatures, which only
/// ever touches public values (RUSTSEC-2026-0387 concerns secret integers in `crypto-bigint`).
pub fn seal_root_with_shared(
    eph_public: &[u8],
    shared: &[u8],
    root: &[u8; 32],
) -> Result<Vec<u8>, PresenceError> {
    if eph_public.len() != PUBLIC_LEN || shared.len() != 32 {
        return Err(PresenceError::BadKey);
    }
    let mut key = wrap_key(shared, eph_public);
    let mut nonce = <[u8; 12]>::default();
    OsRng.fill_bytes(&mut nonce);
    let aad = [WRAP_MAGIC.as_slice(), &[WRAP_VERSION]].concat();
    let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: root,
                aad: &aad,
            },
        )
        .expect("sealing 32 bytes cannot fail");
    key.zeroize();
    let mut out = Vec::with_capacity(SEALED_ROOT_LEN);
    out.extend_from_slice(WRAP_MAGIC);
    out.push(WRAP_VERSION);
    out.extend_from_slice(eph_public);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The ephemeral public point inside a sealed root — what the Secure Enclave must do ECDH against.
pub fn sealed_root_peer(sealed: &[u8]) -> Result<&[u8], PresenceError> {
    if sealed.len() != SEALED_ROOT_LEN || &sealed[..4] != WRAP_MAGIC || sealed[4] != WRAP_VERSION {
        return Err(PresenceError::BadSignature);
    }
    Ok(&sealed[5..5 + PUBLIC_LEN])
}

/// Open a [`seal_root_to_public`] blob given the raw ECDH `shared` secret the Secure Enclave produced
/// against [`sealed_root_peer`]. `None` on any failure, undifferentiated.
pub fn open_sealed_root(sealed: &[u8], shared: &[u8]) -> Option<[u8; 32]> {
    let eph_public = sealed_root_peer(sealed).ok()?;
    let mut key = wrap_key(shared, eph_public);
    let aad = [WRAP_MAGIC.as_slice(), &[WRAP_VERSION]].concat();
    let plain = ChaCha20Poly1305::new(Key::from_slice(&key)).decrypt(
        Nonce::from_slice(&sealed[5 + PUBLIC_LEN..WRAP_HEADER]),
        Payload {
            msg: &sealed[WRAP_HEADER..],
            aad: &aad,
        },
    );
    key.zeroize();
    let mut plain = plain.ok()?;
    let arr: Option<[u8; 32]> = plain.as_slice().try_into().ok();
    plain.zeroize();
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use serde_json::json;

    fn rnd() -> [u8; NONCE_LEN] {
        let mut n = <[u8; NONCE_LEN]>::default();
        OsRng.fill_bytes(&mut n);
        n
    }

    fn keypair() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::random(&mut OsRng);
        let public = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        (sk, public)
    }

    fn sign(sk: &SigningKey, d: &[u8; 32]) -> Vec<u8> {
        let sig: Signature = sk.sign(d);
        sig.to_bytes().to_vec()
    }

    #[test]
    fn a_proof_for_these_inputs_verifies() {
        let (sk, public) = keypair();
        let d = digest(&rnd(), "grant.create", &json!({"to": "acme"}));
        assert_eq!(public.len(), PUBLIC_LEN);
        assert_eq!(verify(&public, &d, &sign(&sk, &d)), Ok(()));
    }

    #[test]
    fn the_digest_binds_nonce_op_and_params() {
        let (n1, n2) = (rnd(), rnd());
        let base = digest(&n1, "grant.create", &json!({"a": 1}));
        assert_ne!(base, digest(&n2, "grant.create", &json!({"a": 1})));
        assert_ne!(base, digest(&n1, "node.reparent", &json!({"a": 1})));
        assert_ne!(base, digest(&n1, "grant.create", &json!({"a": 2})));
    }

    #[test]
    fn a_proof_does_not_move_to_another_request() {
        let (sk, public) = keypair();
        let n3 = rnd();
        let signed = digest(&n3, "node.reparent", &json!({"node": "a"}));
        let sig = sign(&sk, &signed);
        let other = digest(&n3, "node.reparent", &json!({"node": "b"}));
        assert_eq!(
            verify(&public, &other, &sig),
            Err(PresenceError::NotVerified)
        );
    }

    #[test]
    fn another_key_cannot_forge_it() {
        let (sk, _) = keypair();
        let (_, other_public) = keypair();
        let d = digest(&rnd(), "totp.seed", &json!({}));
        assert_eq!(
            verify(&other_public, &d, &sign(&sk, &d)),
            Err(PresenceError::NotVerified)
        );
    }

    #[test]
    fn garbage_is_refused_by_name() {
        let (_, public) = keypair();
        let d = [0u8; 32];
        assert_eq!(
            verify(&public, &d, &[1, 2, 3]),
            Err(PresenceError::BadSignature)
        );
        assert_eq!(
            verify(&[4u8; 65], &d, &[0u8; 64]),
            Err(PresenceError::BadKey)
        );
    }

    #[test]
    fn a_sealed_root_opens_only_with_the_matching_shared_secret() {
        let eph_public = [4u8; PUBLIC_LEN];
        let shared = [7u8; 32];
        let sealed = seal_root_with_shared(&eph_public, &shared, &[9u8; 32]).unwrap();
        assert_eq!(sealed.len(), SEALED_ROOT_LEN);
        assert_eq!(sealed_root_peer(&sealed).unwrap(), &eph_public[..]);
        assert_eq!(open_sealed_root(&sealed, &shared), Some([9u8; 32]));
        assert_eq!(open_sealed_root(&sealed, &[8u8; 32]), None);
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(open_sealed_root(&tampered, &shared), None);
        assert!(seal_root_with_shared(&[4u8; 10], &shared, &[0u8; 32]).is_err());
        let again = seal_root_with_shared(&eph_public, &shared, &[9u8; 32]).unwrap();
        assert_ne!(sealed, again, "a fresh nonce each time");
    }

    #[test]
    fn canonical_json_ignores_key_order_and_spacing() {
        let a: Value = serde_json::from_str(r#"{ "b": [1, {"y":2,"x":1}], "a": "s" }"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":"s","b":[1,{"x":1,"y":2}]}"#).unwrap();
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(
            String::from_utf8(canonical_json(&a)).unwrap(),
            r#"{"a":"s","b":[1,{"x":1,"y":2}]}"#
        );
    }
}
