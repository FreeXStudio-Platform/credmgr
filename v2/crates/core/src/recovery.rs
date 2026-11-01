//! The root recovery code and its wrap of the root key — `docs/04_CRYPTO_AND_KEYS.md
//! §2, §7`, ADR-045.
//!
//! **Why this is pure `crates/core` compute, not a `PlatformKeystore` concern.**
//! The other two root wraps (`root.wrap.se`, `root.wrap.pass`) exist to turn a
//! *weak* secret (a fingerprint enrolment, an operator passphrase) into a key —
//! that stretching is what needs a hardware tier or Argon2id. The recovery code
//! is generated with 256 bits of entropy in the first place (`04 §2`: "256-bit,
//! printed once"), so there is nothing to stretch: deriving a wrap key from it is
//! the same one-shot `HKDF-SHA512(ikm, info=label)` this crate already uses for
//! `keys::wrap_node_key`, and unwrapping needs no presence, no hardware, and no
//! platform trait. It is exactly as much "pure compute" as node-key wrapping is.
//!
//! **Encoding.** Hex, not a word list or base32: the failure mode this format
//! must resist is a human re-typing 64 characters onto another machine during a
//! disaster, possibly years later, with only whatever's built into that
//! machine's runtime to check their work — hex has no ambiguous glyphs (no
//! `0`/`O`, `1`/`l`/`I` confusion the way base32 or a word list can), and both a
//! Rust `u8::from_str_radix` and a four-line JS loop decode it identically with
//! zero risk of an alphabet table drifting between the two. Grouped in 4-char
//! blocks purely for human readability when transcribing; the grouping carries
//! no meaning and parsing accepts it with or without separators.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::CryptoError;

pub const RECOVERY_CODE_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ROOT_KEY_LEN: usize = 32;

const ROOT_WRAP_RECOVERY_INFO: &[u8] = b"credmgr/v2/root-wrap-recovery";

/// A fresh 256-bit recovery code. CSPRNG, never derived from anything else.
pub fn generate_recovery_code() -> [u8; RECOVERY_CODE_LEN] {
    let mut code = [0u8; RECOVERY_CODE_LEN];
    OsRng.fill_bytes(&mut code);
    code
}

/// Upper-case hex, grouped in 4-character blocks separated by `-`
/// (e.g. `A1B2-C3D4-...`), for one-time display and transcription.
pub fn format_recovery_code(code: &[u8; RECOVERY_CODE_LEN]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(RECOVERY_CODE_LEN * 2);
    for b in code {
        write!(hex, "{b:02X}").expect("writing to a String cannot fail");
    }
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex digits are ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Reverse of [`format_recovery_code`] — also accepts ungrouped or
/// lower-case hex, since a human retyping it may not preserve either.
/// Anything that is not exactly 64 hex digits once separators are stripped
/// is [`CryptoError::InvalidRecoveryCode`], never a panic.
pub fn parse_recovery_code(input: &str) -> Result<[u8; RECOVERY_CODE_LEN], CryptoError> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if cleaned.len() != RECOVERY_CODE_LEN * 2 {
        return Err(CryptoError::InvalidRecoveryCode);
    }
    let mut code = [0u8; RECOVERY_CODE_LEN];
    for (i, byte) in code.iter_mut().enumerate() {
        let hex_byte = &cleaned[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(hex_byte, 16).map_err(|_| CryptoError::InvalidRecoveryCode)?;
    }
    Ok(code)
}

/// `root.wrap.recovery`'s on-disk contents. Wire format (also what
/// [`RootRecoveryWrap::to_bytes`] produces): `nonce (12) || ciphertext‖tag (48)`
/// — 60 bytes, no length prefix needed since every field is fixed-size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecoveryWrap {
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by the 16-byte AEAD tag.
    pub ciphertext: Vec<u8>,
}

impl RootRecoveryWrap {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < NONCE_LEN + ROOT_KEY_LEN + TAG_LEN {
            return Err(CryptoError::Truncated);
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce);
        Ok(RootRecoveryWrap {
            nonce: nonce_arr,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// `HKDF-SHA512(ikm = recovery_code, info = "credmgr/v2/root-wrap-recovery")` —
/// no salt (the code is already 256 bits of entropy, matching `keys::derive_subkey`'s
/// no-salt convention for other already-high-entropy inputs).
fn derive_wrap_key(code: &[u8; RECOVERY_CODE_LEN]) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(None, code);
    let mut key = [0u8; 32];
    hk.expand(ROOT_WRAP_RECOVERY_INFO, &mut key)
        .expect("32-byte output is within HKDF-SHA512's max length");
    key
}

/// Wrap the (already-generated) root key under a fresh recovery code. Empty
/// AAD, matching `keys::wrap_node_key`'s convention for a wrap keyed by
/// already-high-entropy material — there is no relocation risk to bind
/// against, unlike an entry envelope that lives at a path-derived location.
pub fn wrap_root_with_recovery_code(
    code: &[u8; RECOVERY_CODE_LEN],
    root: &[u8; ROOT_KEY_LEN],
) -> RootRecoveryWrap {
    let mut key_bytes = derive_wrap_key(code);
    let key = Key::from_slice(&key_bytes);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    let mut buffer = root.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut buffer)
        .expect("ChaCha20Poly1305 encryption of a 32-byte key cannot fail");
    buffer.extend_from_slice(&tag);

    key_bytes.zeroize();
    RootRecoveryWrap {
        nonce: nonce_bytes,
        ciphertext: buffer,
    }
}

/// Reverse of [`wrap_root_with_recovery_code`]. Fails if `code` is wrong or
/// `wrap` was tampered with — the same undifferentiated `AuthenticationFailed`
/// every other AEAD open in this crate returns.
pub fn unwrap_root_with_recovery_code(
    code: &[u8; RECOVERY_CODE_LEN],
    wrap: &RootRecoveryWrap,
) -> Result<[u8; ROOT_KEY_LEN], CryptoError> {
    if wrap.ciphertext.len() < ROOT_KEY_LEN + TAG_LEN {
        return Err(CryptoError::Truncated);
    }
    let mut key_bytes = derive_wrap_key(code);
    let key = Key::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&wrap.nonce);

    let (ct, tag) = wrap.ciphertext.split_at(wrap.ciphertext.len() - TAG_LEN);
    let mut buffer = ct.to_vec();
    let tag_array = chacha20poly1305::Tag::from_slice(tag);

    let cipher = ChaCha20Poly1305::new(key);
    let result = cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, tag_array);
    key_bytes.zeroize();
    result.map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut arr = [0u8; ROOT_KEY_LEN];
    arr.copy_from_slice(&buffer);
    buffer.zeroize();
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let code = generate_recovery_code();
        let root = [7u8; ROOT_KEY_LEN];
        let wrap = wrap_root_with_recovery_code(&code, &root);
        let unwrapped = unwrap_root_with_recovery_code(&code, &wrap).unwrap();
        assert_eq!(unwrapped, root);
    }

    #[test]
    fn wrong_code_fails() {
        let code = generate_recovery_code();
        let other = generate_recovery_code();
        let root = [7u8; ROOT_KEY_LEN];
        let wrap = wrap_root_with_recovery_code(&code, &root);
        let err = unwrap_root_with_recovery_code(&other, &wrap).unwrap_err();
        assert_eq!(err, CryptoError::AuthenticationFailed);
    }

    #[test]
    fn tampered_wrap_fails() {
        let code = generate_recovery_code();
        let root = [7u8; ROOT_KEY_LEN];
        let mut wrap = wrap_root_with_recovery_code(&code, &root);
        let last = wrap.ciphertext.len() - 1;
        wrap.ciphertext[last] ^= 0xFF;
        let err = unwrap_root_with_recovery_code(&code, &wrap).unwrap_err();
        assert_eq!(err, CryptoError::AuthenticationFailed);
    }

    #[test]
    fn wrapping_is_nondeterministic() {
        let code = generate_recovery_code();
        let root = [7u8; ROOT_KEY_LEN];
        let w1 = wrap_root_with_recovery_code(&code, &root);
        let w2 = wrap_root_with_recovery_code(&code, &root);
        assert_ne!(w1, w2);
    }

    #[test]
    fn bytes_round_trip() {
        let code = generate_recovery_code();
        let root = [7u8; ROOT_KEY_LEN];
        let wrap = wrap_root_with_recovery_code(&code, &root);
        let bytes = wrap.to_bytes();
        let parsed = RootRecoveryWrap::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, wrap);
        let unwrapped = unwrap_root_with_recovery_code(&code, &parsed).unwrap();
        assert_eq!(unwrapped, root);
    }

    #[test]
    fn truncated_bytes_are_rejected() {
        let err = RootRecoveryWrap::from_bytes(&[0u8; 4]).unwrap_err();
        assert_eq!(err, CryptoError::Truncated);
    }

    #[test]
    fn format_parse_round_trip() {
        let code = generate_recovery_code();
        let formatted = format_recovery_code(&code);
        assert_eq!(
            formatted.len(),
            RECOVERY_CODE_LEN * 2 + 15,
            "16 groups of 4, 15 hyphens"
        );
        let parsed = parse_recovery_code(&formatted).unwrap();
        assert_eq!(parsed, code);
    }

    #[test]
    fn parse_accepts_lowercase_and_no_separators() {
        use std::fmt::Write;
        let code = generate_recovery_code();
        let mut hex_lower = String::with_capacity(RECOVERY_CODE_LEN * 2);
        for b in &code {
            write!(hex_lower, "{b:02x}").unwrap();
        }
        let parsed = parse_recovery_code(&hex_lower).unwrap();
        assert_eq!(parsed, code);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let err = parse_recovery_code("A1B2").unwrap_err();
        assert_eq!(err, CryptoError::InvalidRecoveryCode);
    }

    #[test]
    fn parse_rejects_non_hex() {
        let bad = "ZZ".repeat(RECOVERY_CODE_LEN);
        let err = parse_recovery_code(&bad).unwrap_err();
        assert_eq!(err, CryptoError::InvalidRecoveryCode);
    }
}
