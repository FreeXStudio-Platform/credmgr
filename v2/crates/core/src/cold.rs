//! The orphan cold key (ADR-079, K-7). See `docs/04_CRYPTO_AND_KEYS.md §5.2`.
//!
//! Sealing a node re-encrypts each of its entries to the `orphan` node's
//! **public** key. This module is that key's private half, and the one file
//! format that holds it, `keys/cold/orphan.key`.
//!
//! # What "cold" means on the Software tier
//!
//! The private half is sealed under a key derived from the root key
//! (`HKDF(RK, "credmgr/v2/orphan-cold/v1")`, the same [`seal_under_root`] the
//! gate's TOTP seed uses). It is **never** loaded into the broker's hot key
//! set, never written to `keys/nodes/`, and nothing in this build opens it
//! except two callers, both transient and zeroised: `node.seal`'s pre-flight
//! ("is the key I am about to commit data to actually recoverable?") and a
//! future unseal path that is `planned`, behind presence. So "cold" is
//! enforced by the broker — no operation uses it, no resident copy exists —
//! and **not** by cryptography against a compromised broker: the root key,
//! which is resident while the vault is unlocked, derives it. That is stated
//! in the release text, not softened (ADR-079 *Bound*).
//!
//! Why root-derived and not passphrase-derived, and why `04 §5.2`'s KEK
//! sketch (a fresh single-use gate proof as the HKDF salt) was replaced: a
//! fresh salt per use can never reopen a stored blob. The gate proof is an
//! authorisation precondition of a future unseal, never KDF input.
//!
//! # File format `CMCK` v1 — 98 bytes, every field fixed-size
//!
//! ```text
//! magic    "CMCK"                                            4
//! version  0x01                                              1
//! kind     0x01 = root-derived (Software tier)               1   (0x02 reserved: Secure-Enclave wrap)
//! pub      the orphan X25519 public key                     32
//! sealed   seal_under_root(RK, COLD_LABEL, private)         60   nonce(12) ‖ ct(32) ‖ tag(16)
//! ```
//!
//! Opening derives the public key from the private half and requires it to
//! equal **both** the header's `pub` and, when the caller has one, the
//! registry's `orphan.publicKey`: a swapped or rolled-back cold file therefore
//! cannot be mistaken for the real one. The label differs from
//! `credmgr/v2/node-wrap/orphan`, so a cold blob never opens as a node wrap and
//! a node wrap never opens as a cold blob.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::keys::{generate_node_keypair, open_under_root, seal_under_root};

/// The first four bytes of a cold-key file.
pub const COLD_MAGIC: &[u8; 4] = b"CMCK";
/// The only format version this build reads or writes.
pub const COLD_VERSION: u8 = 1;
/// `kind`: the private half is sealed under a key derived from the root key.
pub const COLD_KIND_ROOT_DERIVED: u8 = 1;
/// The HKDF label of the sealing key — one label, one use (`keys::derive_subkey`).
pub const COLD_LABEL: &str = "credmgr/v2/orphan-cold/v1";

const HEADER_LEN: usize = 4 + 1 + 1 + 32;
const PRIVATE_LEN: usize = 32;
/// `nonce(12) ‖ ciphertext(32) ‖ tag(16)`.
const SEALED_LEN: usize = 12 + PRIVATE_LEN + 16;
/// The exact length of a cold-key file.
pub const COLD_FILE_LEN: usize = HEADER_LEN + SEALED_LEN;

/// What a cold-key file says about itself without decrypting anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdHeader {
    pub kind: u8,
    /// The orphan public key the file claims to hold the private half of.
    pub public: PublicKey,
}

/// A fresh orphan keypair, with its private half sealed under `root_key`.
/// Returns the public key (registry cleartext) and the file's exact bytes.
/// The private half exists unsealed only inside this call and is zeroised
/// before it returns.
pub fn generate_orphan_cold(root_key: &[u8; 32]) -> (PublicKey, Vec<u8>) {
    let pair = generate_node_keypair();
    let mut private = pair.private.to_bytes();
    let file = build_file(root_key, &pair.public, &private);
    private.zeroize();
    (pair.public, file)
}

fn build_file(root_key: &[u8; 32], public: &PublicKey, private: &[u8; 32]) -> Vec<u8> {
    let sealed = seal_under_root(root_key, COLD_LABEL, private);
    debug_assert_eq!(sealed.len(), SEALED_LEN);
    let mut out = Vec::with_capacity(COLD_FILE_LEN);
    out.extend_from_slice(COLD_MAGIC);
    out.push(COLD_VERSION);
    out.push(COLD_KIND_ROOT_DERIVED);
    out.extend_from_slice(public.as_bytes());
    out.extend_from_slice(&sealed);
    out
}

/// Read a cold-key file's header — magic, version, kind, claimed public key —
/// with no key at all. The load path uses it to compare against the registry
/// without decrypting anything; a mismatch is a `maintenance.verify` finding,
/// never an unlock failure.
pub fn parse_header(bytes: &[u8]) -> Result<ColdHeader, CryptoError> {
    if bytes.len() != COLD_FILE_LEN {
        return Err(CryptoError::Truncated);
    }
    if &bytes[..4] != COLD_MAGIC {
        return Err(CryptoError::BadMagic);
    }
    if bytes[4] != COLD_VERSION {
        return Err(CryptoError::UnsupportedVersion(bytes[4]));
    }
    if bytes[5] != COLD_KIND_ROOT_DERIVED {
        return Err(CryptoError::UnsupportedSuite(bytes[5]));
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&bytes[6..HEADER_LEN]);
    Ok(ColdHeader {
        kind: bytes[5],
        public: PublicKey::from(public),
    })
}

/// Open the private half. Fails — leaving nothing behind — on a wrong root key,
/// a wrong label, any tampering, or a derived public key that is not the one
/// the header names (and `expected_public`, when the caller has the registry's).
///
/// The returned [`StaticSecret`] zeroises on drop; a caller uses it once.
pub fn open_orphan_cold(
    root_key: &[u8; 32],
    bytes: &[u8],
    expected_public: Option<&PublicKey>,
) -> Result<StaticSecret, CryptoError> {
    let header = parse_header(bytes)?;
    let mut private = open_under_root(root_key, COLD_LABEL, &bytes[HEADER_LEN..])?;
    if private.len() != PRIVATE_LEN {
        private.zeroize();
        return Err(CryptoError::Truncated);
    }
    let mut arr = [0u8; PRIVATE_LEN];
    arr.copy_from_slice(&private);
    private.zeroize();
    let secret = StaticSecret::from(arr);
    arr.zeroize();
    let derived = PublicKey::from(&secret);
    if derived != header.public || expected_public.is_some_and(|p| *p != derived) {
        return Err(CryptoError::ColdKeyMismatch);
    }
    Ok(secret)
}

/// Re-seal the cold key from `old_root` to `new_root` — the one step a
/// root-key rotation (ADR-076) owes this file. The keypair is **unchanged**
/// (so every orphan envelope still opens); only the blob that protects the
/// private half is replaced. Opens under `old_root` first, so a file that does
/// not verify is refused rather than re-stamped. The result carries a fresh
/// nonce, so its bytes always differ from the input's.
pub fn reseal_orphan_cold(
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let secret = open_orphan_cold(old_root, bytes, None)?;
    let public = PublicKey::from(&secret);
    let mut private = secret.to_bytes();
    let file = build_file(new_root, &public, &private);
    private.zeroize();
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{unwrap_node_key, wrap_node_key, WrappedNodeKey};
    use crate::registry::ORPHAN_ID;

    const RK: [u8; 32] = [7u8; 32];

    /// `Result::unwrap_err` needs `T: Debug`, which a `StaticSecret` deliberately is not.
    fn refused(result: Result<StaticSecret, CryptoError>) -> CryptoError {
        result.map(|_| ()).unwrap_err()
    }

    #[test]
    fn a_generated_file_is_98_bytes_and_opens_to_the_key_its_header_names() {
        let (public, file) = generate_orphan_cold(&RK);
        assert_eq!(file.len(), COLD_FILE_LEN);
        assert_eq!(COLD_FILE_LEN, 98);
        assert_eq!(&file[..4], b"CMCK");
        assert_eq!(file[4], 1);
        assert_eq!(file[5], 1);
        assert_eq!(&file[6..38], public.as_bytes());

        let header = parse_header(&file).unwrap();
        assert_eq!(header.public, public);
        assert_eq!(header.kind, COLD_KIND_ROOT_DERIVED);

        let secret = open_orphan_cold(&RK, &file, Some(&public)).unwrap();
        assert_eq!(PublicKey::from(&secret), public);
    }

    #[test]
    fn the_private_half_is_not_in_the_file_in_the_clear() {
        let (public, file) = generate_orphan_cold(&RK);
        let secret = open_orphan_cold(&RK, &file, Some(&public)).unwrap();
        let private = secret.to_bytes();
        assert!(
            !file.windows(32).any(|w| w == private),
            "the private key must not appear in the file"
        );
    }

    #[test]
    fn a_wrong_root_key_is_refused() {
        let (_, file) = generate_orphan_cold(&RK);
        assert_eq!(
            refused(open_orphan_cold(&[8u8; 32], &file, None)),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn a_header_public_key_that_is_not_the_derived_one_is_refused() {
        let (_, mut file) = generate_orphan_cold(&RK);
        // Another keypair's public key in the header, the real sealed blob behind it.
        let other = generate_node_keypair().public;
        file[6..38].copy_from_slice(other.as_bytes());
        assert_eq!(
            refused(open_orphan_cold(&RK, &file, None)),
            CryptoError::ColdKeyMismatch
        );
    }

    #[test]
    fn a_registry_public_key_that_is_not_the_files_is_refused() {
        let (_, file) = generate_orphan_cold(&RK);
        let registry_says = generate_node_keypair().public;
        assert_eq!(
            refused(open_orphan_cold(&RK, &file, Some(&registry_says))),
            CryptoError::ColdKeyMismatch
        );
    }

    #[test]
    fn a_swapped_in_file_from_another_vault_is_refused_for_the_registry_it_is_checked_against() {
        // Same root key, a different orphan keypair: authenticates, but is not this vault's.
        let (real_public, _) = generate_orphan_cold(&RK);
        let (_, other_file) = generate_orphan_cold(&RK);
        assert_eq!(
            refused(open_orphan_cold(&RK, &other_file, Some(&real_public))),
            CryptoError::ColdKeyMismatch
        );
    }

    #[test]
    fn every_header_and_body_tamper_is_refused() {
        let (public, file) = generate_orphan_cold(&RK);
        for i in 0..file.len() {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            assert!(
                open_orphan_cold(&RK, &bad, Some(&public)).is_err(),
                "flipping byte {i} must not open"
            );
        }
    }

    #[test]
    fn a_truncated_or_extended_file_is_refused() {
        let (public, file) = generate_orphan_cold(&RK);
        assert_eq!(parse_header(&[]).unwrap_err(), CryptoError::Truncated);
        assert_eq!(
            parse_header(&file[..file.len() - 1]).unwrap_err(),
            CryptoError::Truncated
        );
        let mut longer = file.clone();
        longer.push(0);
        assert_eq!(parse_header(&longer).unwrap_err(), CryptoError::Truncated);
        assert!(open_orphan_cold(&RK, &file[..40], Some(&public)).is_err());
    }

    #[test]
    fn an_unknown_version_or_kind_is_named() {
        let (_, file) = generate_orphan_cold(&RK);
        let mut v = file.clone();
        v[4] = 2;
        assert_eq!(
            parse_header(&v).unwrap_err(),
            CryptoError::UnsupportedVersion(2)
        );
        let mut k = file.clone();
        k[5] = 2;
        assert_eq!(
            parse_header(&k).unwrap_err(),
            CryptoError::UnsupportedSuite(2)
        );
        let mut m = file;
        m[0] = b'X';
        assert_eq!(parse_header(&m).unwrap_err(), CryptoError::BadMagic);
    }

    /// The label is what keeps the two uses of "a private key sealed under the
    /// root" from standing in for one another.
    #[test]
    fn a_cold_blob_does_not_open_as_a_node_wrap_and_a_node_wrap_does_not_open_as_a_cold_blob() {
        let (_, file) = generate_orphan_cold(&RK);
        let as_wrap = WrappedNodeKey::from_bytes(&file[HEADER_LEN..]).unwrap();
        assert!(unwrap_node_key(&RK, ORPHAN_ID, &as_wrap).is_err());

        let pair = generate_node_keypair();
        let wrap = wrap_node_key(&RK, ORPHAN_ID, &pair.private).to_bytes();
        let mut forged = file[..HEADER_LEN].to_vec();
        forged[6..38].copy_from_slice(pair.public.as_bytes());
        forged.extend_from_slice(&wrap);
        assert!(open_orphan_cold(&RK, &forged, None).is_err());
    }

    #[test]
    fn generation_is_nondeterministic() {
        let (p1, f1) = generate_orphan_cold(&RK);
        let (p2, f2) = generate_orphan_cold(&RK);
        assert_ne!(p1, p2);
        assert_ne!(f1, f2);
    }

    /// ADR-076: a rotation re-seals, it does not re-key.
    #[test]
    fn a_reseal_keeps_the_keypair_and_moves_the_file_to_the_new_root_only() {
        let new_rk = [9u8; 32];
        let (public, file) = generate_orphan_cold(&RK);
        let before = open_orphan_cold(&RK, &file, None).unwrap().to_bytes();

        let moved = reseal_orphan_cold(&RK, &new_rk, &file).unwrap();
        assert_eq!(moved.len(), COLD_FILE_LEN);
        assert_ne!(moved, file);
        assert_eq!(parse_header(&moved).unwrap().public, public);

        let after = open_orphan_cold(&new_rk, &moved, Some(&public)).unwrap();
        assert_eq!(after.to_bytes(), before, "the same orphan private key");
        assert!(open_orphan_cold(&RK, &moved, None).is_err());
        assert!(open_orphan_cold(&new_rk, &file, None).is_err());
    }

    #[test]
    fn a_reseal_of_a_file_that_does_not_open_under_the_old_root_is_refused() {
        let (_, file) = generate_orphan_cold(&RK);
        assert!(reseal_orphan_cold(&[1u8; 32], &[2u8; 32], &file).is_err());
        let mut torn = file;
        let last = torn.len() - 1;
        torn[last] ^= 1;
        assert!(reseal_orphan_cold(&RK, &[2u8; 32], &torn).is_err());
    }
}
