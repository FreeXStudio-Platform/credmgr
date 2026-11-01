//! Encrypting a `maintenance.backup` bundle to an operator-supplied
//! passphrase — ADR-054/`04_CRYPTO_AND_KEYS.md §7`: "the archive is itself
//! encrypted, to a key derived from... a separate backup passphrase."
//!
//! Deliberately the same shape as [`crate::software`]'s own
//! Argon2id-then-ChaCha20-Poly1305 seal (same parameters, `16 §4.4`), but a
//! standalone public function rather than a method on [`crate::software::
//! SoftwareKeystore`] — a backup passphrase is not a root-key wrap, has no
//! relationship to the vault's own unlock passphrase (an operator may reuse
//! it or not), and living here as its own small file keeps `software.rs`'s
//! `seal`/`open` a private implementation detail of that one type, matching
//! this crate's existing one-file-per-concern shape (`recovery.rs`,
//! `keys.rs`, `signing.rs` in `crates/core` are the same pattern).
//!
//! **Why this lives in `crates/keystore` and not `crates/store`.** Argon2id
//! is a keystore-owned dependency (`16 §4.4`) — `crates/store` has no crypto
//! dependency of its own beyond `sha2` for content hashing, calling into
//! `crates/core` for every real primitive it needs (HMAC signing, envelope
//! seal/open). A passphrase-to-key derivation is exactly the kind of
//! "turn a human factor into key material" job this crate already owns;
//! duplicating Argon2id into `crates/store` for one caller would be the same
//! mistake ADR-001 exists to prevent.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::error::{KeystoreError, Result};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// `16 §4.4`'s parameters, identical to [`crate::software`]'s — one KDF
/// policy for this crate, not a second one invented for backups.
fn argon2_params() -> Params {
    Params::new(256 * 1024, 3, 4, Some(32)).expect("static Argon2id parameters are valid")
}

fn derive_key(passphrase: &SecretBox<String>, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params());
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut out)
        .expect("fixed-size salt and output are within Argon2id's bounds");
    out
}

/// `salt (16) || nonce (12) || ciphertext‖tag` — self-describing, so a
/// backup file needs nothing but the passphrase to restore, independent of
/// any other vault state surviving (the actual disaster-recovery
/// requirement ADR-054 lays out).
pub fn encrypt_with_passphrase(passphrase: &SecretBox<String>, plaintext: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut key_bytes = derive_key(passphrase, &salt);
    let key = Key::from_slice(&key_bytes);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut buffer)
        .expect("ChaCha20Poly1305 encryption cannot fail for an in-memory buffer");
    buffer.extend_from_slice(&tag);
    key_bytes.zeroize();

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + buffer.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buffer);
    out
}

/// Reverse of [`encrypt_with_passphrase`]. Wrong passphrase and a corrupted
/// blob are indistinguishable — the same "nothing to distinguish" AEAD
/// convention `crate::software`'s own `open` already follows.
pub fn decrypt_with_passphrase(passphrase: &SecretBox<String>, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(KeystoreError::Truncated);
    }
    let (salt, rest) = blob.split_at(SALT_LEN);
    let (nonce_bytes, ct_and_tag) = rest.split_at(NONCE_LEN);

    let mut key_bytes = derive_key(passphrase, salt);
    let key = Key::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(nonce_bytes);

    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
    let mut buffer = ct.to_vec();
    let tag_array = chacha20poly1305::Tag::from_slice(tag);

    let cipher = ChaCha20Poly1305::new(key);
    let result = cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, tag_array);
    key_bytes.zeroize();
    result.map_err(|_| KeystoreError::AuthenticationFailed)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(s: &str) -> SecretBox<String> {
        SecretBox::new(Box::new(s.to_string()))
    }

    #[test]
    fn round_trips() {
        let p = pass("a backup passphrase, not the vault one");
        let blob = encrypt_with_passphrase(&p, b"the packed vault bundle");
        let out = decrypt_with_passphrase(&p, &blob).unwrap();
        assert_eq!(out, b"the packed vault bundle");
    }

    #[test]
    fn wrong_passphrase_is_refused() {
        let p = pass("correct");
        let blob = encrypt_with_passphrase(&p, b"secret bundle bytes");
        let wrong = pass("incorrect");
        let err = decrypt_with_passphrase(&wrong, &blob).unwrap_err();
        assert!(matches!(err, KeystoreError::AuthenticationFailed));
    }

    #[test]
    fn tampered_blob_is_refused() {
        let p = pass("correct");
        let mut blob = encrypt_with_passphrase(&p, b"secret bundle bytes");
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        let err = decrypt_with_passphrase(&p, &blob).unwrap_err();
        assert!(matches!(err, KeystoreError::AuthenticationFailed));
    }

    #[test]
    fn truncated_blob_is_a_named_error_not_a_panic() {
        let err = decrypt_with_passphrase(&pass("x"), &[0u8; 4]).unwrap_err();
        assert!(matches!(err, KeystoreError::Truncated));
    }

    #[test]
    fn encryption_is_nondeterministic_same_plaintext_different_bytes() {
        let p = pass("correct");
        let a = encrypt_with_passphrase(&p, b"same plaintext");
        let b = encrypt_with_passphrase(&p, b"same plaintext");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let p = pass("correct");
        let blob = encrypt_with_passphrase(&p, b"");
        assert_eq!(decrypt_with_passphrase(&p, &blob).unwrap(), b"");
    }
}
