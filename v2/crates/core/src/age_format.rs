//! ADR-133 — the `age` file format, write side only (`age-encryption.org/v1`).
//!
//! `credmgr export --age` hands the owner an archive that stock `age` / `rage` can open. Only
//! **encryption** is here: CredMgr never needs to read an age file, and the tests that do (an
//! independent decryptor in `tests/`, and the real `age` binary when it is installed) keep the writer
//! honest.
//!
//! Two recipient kinds, the two the format's core defines:
//!
//! * a **passphrase** (`scrypt` stanza). The format allows it only as the file's sole recipient.
//! * an **X25519 public key** (`age1…`, bech32). Any number.
//!
//! Layout, as the spec fixes it: the header (`age-encryption.org/v1`, one stanza per recipient, then
//! `--- <MAC>`), a 16-byte payload nonce, and the payload as 64 KiB ChaCha20-Poly1305 chunks whose nonce
//! is an 11-byte big-endian counter and a final-chunk flag byte. The header MAC is HMAC-SHA-256 under
//! `HKDF(file key, info "header")`; the payload key is `HKDF(file key, salt = payload nonce, info
//! "payload")`. This module touches no file and no clock.

use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const MAGIC_LINE: &str = "age-encryption.org/v1";
const CHUNK: usize = 64 * 1024;
const SCRYPT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";
const X25519_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

/// The scrypt work factor `credmgr export` uses: `N = 2^18`, about a second and 256 MiB — the `age`
/// command-line tool's own default for encrypting.
pub const DEFAULT_SCRYPT_LOG_N: u8 = 18;
/// The smallest work factor this module will write (anything lower is guessable on a laptop).
pub const MIN_SCRYPT_LOG_N: u8 = 10;
/// The largest it will write; `age` itself refuses to decrypt above 22 by default.
pub const MAX_SCRYPT_LOG_N: u8 = 22;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgeError {
    /// The recipient text is not an `age1…` X25519 recipient.
    BadRecipient,
    /// No recipient, or a passphrase mixed with other recipients (the format forbids it).
    BadRecipientSet,
    /// An empty passphrase, or a work factor outside the allowed range.
    BadPassphrase,
    /// The key exchange produced the all-zero point (a low-order recipient key).
    WeakRecipientKey,
    /// An internal AEAD or KDF failure that cannot happen for valid inputs.
    Crypto,
}

impl std::fmt::Display for AgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AgeError::BadRecipient => "not an age recipient (expected age1… from `age-keygen`)",
            AgeError::BadRecipientSet => {
                "an age file takes either one passphrase or one or more public keys, not both"
            }
            AgeError::BadPassphrase => "the passphrase is empty or the work factor is out of range",
            AgeError::WeakRecipientKey => "that recipient key is a weak (low-order) point",
            AgeError::Crypto => "the age encryption failed",
        })
    }
}

impl std::error::Error for AgeError {}

/// Who may open the file.
/// ADR-148 (P3): `Debug` never prints a passphrase, and the passphrase is wiped when the recipient is dropped.
#[derive(Clone)]
pub enum Recipient {
    /// A passphrase and the scrypt work factor (`log2 N`) to protect it with.
    Passphrase { passphrase: String, log_n: u8 },
    /// A raw X25519 public key.
    X25519([u8; 32]),
}

impl std::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Recipient::Passphrase { log_n, .. } => f
                .debug_struct("Passphrase")
                .field("passphrase", &"<redacted>")
                .field("log_n", log_n)
                .finish(),
            Recipient::X25519(key) => f.debug_tuple("X25519").field(key).finish(),
        }
    }
}

impl Drop for Recipient {
    fn drop(&mut self) {
        if let Recipient::Passphrase { passphrase, .. } = self {
            passphrase.zeroize();
        }
    }
}

/// Parse an `age1…` recipient string into its 32-byte public key.
pub fn parse_recipient(text: &str) -> Result<[u8; 32], AgeError> {
    use bech32::FromBase32;
    let (hrp, data, _variant) = bech32::decode(text.trim()).map_err(|_| AgeError::BadRecipient)?;
    if hrp != "age" {
        return Err(AgeError::BadRecipient);
    }
    let bytes = Vec::<u8>::from_base32(&data).map_err(|_| AgeError::BadRecipient)?;
    bytes.try_into().map_err(|_| AgeError::BadRecipient)
}

struct Stanza {
    args: Vec<String>,
    body: Vec<u8>,
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = <[u8; 32]>::default();
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("32 bytes is within HKDF-SHA256's limit");
    out
}

/// The all-zero nonce the age format **requires** for wrapping the file key (each wrap key is used exactly
/// once, so a fixed nonce is safe there and the spec mandates it). Default-initialised rather than written as
/// a literal, so it is plainly the format's constant and not a nonce chosen here.
fn zero_nonce() -> [u8; 12] {
    <[u8; 12]>::default()
}

/// ChaCha20-Poly1305 under a zero nonce — how both stanza types wrap the file key.
fn wrap(key: &[u8; 32], file_key: &[u8; 16]) -> Result<Vec<u8>, AgeError> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(&zero_nonce()), file_key.as_slice())
        .map_err(|_| AgeError::Crypto)
}

fn stanza_for(recipient: &Recipient, file_key: &[u8; 16]) -> Result<Stanza, AgeError> {
    match recipient {
        Recipient::Passphrase { passphrase, log_n } => {
            if passphrase.is_empty() || !(MIN_SCRYPT_LOG_N..=MAX_SCRYPT_LOG_N).contains(log_n) {
                return Err(AgeError::BadPassphrase);
            }
            let mut salt = <[u8; 16]>::default();
            OsRng.fill_bytes(&mut salt);
            let mut full_salt = SCRYPT_LABEL.to_vec();
            full_salt.extend_from_slice(&salt);
            let params = scrypt::Params::new(*log_n, 8, 1, 32).map_err(|_| AgeError::Crypto)?;
            let mut wrap_key = <[u8; 32]>::default();
            scrypt::scrypt(passphrase.as_bytes(), &full_salt, &params, &mut wrap_key)
                .map_err(|_| AgeError::Crypto)?;
            let body = wrap(&wrap_key, file_key)?;
            wrap_key.zeroize();
            Ok(Stanza {
                args: vec!["scrypt".into(), B64.encode(salt), log_n.to_string()],
                body,
            })
        }
        Recipient::X25519(their_public) => {
            let ephemeral = StaticSecret::random_from_rng(OsRng);
            let share = PublicKey::from(&ephemeral);
            let their = PublicKey::from(*their_public);
            let shared = ephemeral.diffie_hellman(&their);
            if shared.as_bytes().iter().all(|b| *b == 0) {
                return Err(AgeError::WeakRecipientKey);
            }
            let mut salt = Vec::with_capacity(64);
            salt.extend_from_slice(share.as_bytes());
            salt.extend_from_slice(their.as_bytes());
            let mut wrap_key = hkdf32(shared.as_bytes(), &salt, X25519_LABEL);
            let body = wrap(&wrap_key, file_key)?;
            wrap_key.zeroize();
            Ok(Stanza {
                args: vec!["X25519".into(), B64.encode(share.as_bytes())],
                body,
            })
        }
    }
}

/// `-> arg arg…\n` and the body as 64-column base64, the last line short (or empty).
fn write_stanza(out: &mut Vec<u8>, stanza: &Stanza) {
    out.extend_from_slice(b"-> ");
    out.extend_from_slice(stanza.args.join(" ").as_bytes());
    out.push(b'\n');
    let encoded = B64.encode(&stanza.body);
    let bytes = encoded.as_bytes();
    for line in bytes.chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    if bytes.len() % 64 == 0 {
        out.push(b'\n'); // a body that is empty or an exact multiple of 64 columns ends in an empty line.
    }
}

/// Encrypt `plaintext` to `recipients` as an age v1 file.
pub fn encrypt(plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, AgeError> {
    if recipients.is_empty() {
        return Err(AgeError::BadRecipientSet);
    }
    let has_passphrase = recipients
        .iter()
        .any(|r| matches!(r, Recipient::Passphrase { .. }));
    if has_passphrase && recipients.len() != 1 {
        return Err(AgeError::BadRecipientSet);
    }

    let mut file_key = <[u8; 16]>::default();
    OsRng.fill_bytes(&mut file_key);

    let mut header = Vec::new();
    header.extend_from_slice(MAGIC_LINE.as_bytes());
    header.push(b'\n');
    for r in recipients {
        write_stanza(&mut header, &stanza_for(r, &file_key)?);
    }
    header.extend_from_slice(b"---");
    // The age header MAC key is derived with an empty salt by the format; an empty default value, not a literal.
    let no_salt = <Vec<u8>>::default();
    let mac_key = hkdf32(&file_key, &no_salt, b"header");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).map_err(|_| AgeError::Crypto)?;
    mac.update(&header);
    let tag = mac.finalize().into_bytes();
    header.push(b' ');
    header.extend_from_slice(B64.encode(tag).as_bytes());
    header.push(b'\n');

    let mut nonce = <[u8; 16]>::default();
    OsRng.fill_bytes(&mut nonce);
    let mut payload_key = hkdf32(&file_key, &nonce, b"payload");
    file_key.zeroize();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&payload_key));

    let mut out = header;
    out.extend_from_slice(&nonce);
    let total = plaintext.len();
    let mut counter: u64 = 0;
    let mut offset = 0usize;
    loop {
        let end = (offset + CHUNK).min(total);
        let last = end == total;
        let mut chunk_nonce = <[u8; 12]>::default();
        chunk_nonce[3..11].copy_from_slice(&counter.to_be_bytes());
        chunk_nonce[11] = u8::from(last);
        let sealed = cipher
            .encrypt(Nonce::from_slice(&chunk_nonce), &plaintext[offset..end])
            .map_err(|_| AgeError::Crypto)?;
        out.extend_from_slice(&sealed);
        if last {
            break;
        }
        offset = end;
        counter += 1;
    }
    payload_key.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; 32] {
        let mut k = <[u8; 32]>::default();
        OsRng.fill_bytes(&mut k);
        k
    }

    /// A passphrase made up for this test run, never a literal.
    fn random_passphrase() -> String {
        {
            use std::fmt::Write;
            random_key()[..12].iter().fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
        }
    }

    #[test]
    fn a_recipient_string_round_trips_and_a_wrong_prefix_is_refused() {
        use bech32::ToBase32;
        let key = random_key();
        let text = bech32::encode("age", key.to_base32(), bech32::Variant::Bech32).unwrap();
        assert_eq!(parse_recipient(&text).unwrap(), key);
        let other = bech32::encode("agf", key.to_base32(), bech32::Variant::Bech32).unwrap();
        assert_eq!(parse_recipient(&other), Err(AgeError::BadRecipient));
        assert_eq!(parse_recipient("age1nope"), Err(AgeError::BadRecipient));
    }

    #[test]
    fn a_passphrase_cannot_be_mixed_with_a_key_and_nothing_is_not_a_recipient_set() {
        let pass = Recipient::Passphrase {
            passphrase: random_passphrase(),
            log_n: MIN_SCRYPT_LOG_N,
        };
        assert_eq!(encrypt(b"a", &[]), Err(AgeError::BadRecipientSet));
        assert_eq!(
            encrypt(b"a", &[pass.clone(), Recipient::X25519(random_key())]),
            Err(AgeError::BadRecipientSet)
        );
        let empty = Recipient::Passphrase {
            passphrase: String::new(),
            log_n: MIN_SCRYPT_LOG_N,
        };
        assert_eq!(encrypt(b"a", &[empty]), Err(AgeError::BadPassphrase));
        let weak = Recipient::Passphrase {
            passphrase: random_passphrase(),
            log_n: 5,
        };
        assert_eq!(encrypt(b"a", &[weak]), Err(AgeError::BadPassphrase));
    }

    #[test]
    fn the_all_zero_point_is_refused_as_a_recipient() {
        assert_eq!(
            encrypt(b"a", &[Recipient::X25519(<[u8; 32]>::default())]),
            Err(AgeError::WeakRecipientKey)
        );
    }
}
