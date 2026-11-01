//! HMAC-SHA256 over root-key-derived subkeys — the integrity layer for the
//! plaintext metadata files (`registry.json`, `manifest.json`, the external
//! generation counter). See `docs/04_CRYPTO_AND_KEYS.md §6a`.
//!
//! This module is pure compute, like the rest of `credmgr-core`: it signs
//! and verifies byte slices handed to it. Reading `registry.json` off disk,
//! deciding which label to use for which file, and refusing to start the
//! broker on a bad tag are all `crates/store`'s job (Phase 2), not this
//! crate's.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::keys::derive_subkey;

/// `HMAC-SHA256( HKDF(root_key, label), data )`.
pub fn sign(root_key: &[u8; 32], label: &str, data: &[u8]) -> [u8; 32] {
    let subkey = derive_subkey(root_key, label);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&subkey).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time tag verification (delegated to `hmac`'s own
/// `verify_slice`, which is written to not leak timing on mismatch).
#[must_use]
pub fn verify(root_key: &[u8; 32], label: &str, data: &[u8], tag: &[u8; 32]) -> bool {
    let subkey = derive_subkey(root_key, label);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&subkey).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let rk = [1u8; 32];
        let tag = sign(&rk, "registry-hmac", b"hello");
        assert!(verify(&rk, "registry-hmac", b"hello", &tag));
    }

    #[test]
    fn wrong_key_fails() {
        let rk = [1u8; 32];
        let other = [2u8; 32];
        let tag = sign(&rk, "registry-hmac", b"hello");
        assert!(!verify(&other, "registry-hmac", b"hello", &tag));
    }

    #[test]
    fn wrong_label_fails() {
        let rk = [1u8; 32];
        let tag = sign(&rk, "registry-hmac", b"hello");
        assert!(!verify(&rk, "manifest-hmac/n_x", b"hello", &tag));
    }

    #[test]
    fn tampered_data_fails() {
        let rk = [1u8; 32];
        let tag = sign(&rk, "registry-hmac", b"hello");
        assert!(!verify(&rk, "registry-hmac", b"hellp", &tag));
    }
}
