//! The CMV2 on-disk envelope format and the sealed-box construction that fills
//! it. See `docs/03_DATA_MODEL.md §7` (byte layout) and
//! `docs/04_CRYPTO_AND_KEYS.md §3` (key derivation).
//!
//! ```text
//! magic      "CMV2"      4 bytes
//! version    uint8       1 byte   (1 = the plaintext is one raw value,
//!                                  2 = the plaintext is a field document)
//! suite      uint8       1 byte   (1 = X25519-HKDF-SHA512-ChaCha20Poly1305)
//! nodeId     16 bytes    the owning node, in cleartext (informational — see below)
//! epk        32 bytes    ephemeral X25519 public key
//! nonce      12 bytes
//! ciphertext var
//! tag        16 bytes
//! ```
//!
//! **What actually binds an envelope to its node and entry.** The doc states
//! "the AAD covers magic ‖ version ‖ suite ‖ nodeId ‖ entryId" without saying
//! whether that `nodeId` is the byte-for-byte header field or the caller's
//! asserted context. This implementation uses the caller's asserted
//! `node_id`/`entry_id` (the values the storage layer derives from *where the
//! file lives*) for both the header field written at seal time and the AAD at
//! both seal and open time. That is the only reading under which relocating an
//! envelope into a different node's directory is guaranteed to fail (P-3): the
//! ECDH already uses a different node key, and now the AAD the receiver
//! reconstructs from its own path-derived context disagrees with the AAD that
//! authenticated the ciphertext. The header field is then a redundant,
//! unauthenticated hint (`03 §2`'s "which key do I need without decrypting"); a
//! stored value that disagrees with the caller's asserted node id is rejected
//! before the AEAD call runs, for a clearer error, but the tag is what actually
//! enforces it.
//!
//! **The version byte is the payload discriminator (ADR-078).** Version 1 means
//! the plaintext is one raw value — what every entry written up to
//! `2.0.0-alpha.6` holds. Version 2 means the plaintext is a canonical-JSON
//! field document (`crate::fields`). Nothing else differs: the suite, the key
//! derivation, the header layout and the AAD construction are identical, and the
//! version byte is already one of the bytes the AAD covers, so *which kind of
//! payload an envelope carries is authenticated* — flipping the byte fails the
//! tag instead of making the reader mis-parse a raw value as a document (or the
//! reverse). Nothing ever sniffs the plaintext to decide, and the manifest holds
//! no "kind" flag that could drift from the ciphertext after an interrupted
//! write: the discriminator travels inside the ciphertext's own header into
//! `pending/`, `history/`, the removal archive, the seal archive and backups.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use secrecy::SecretBox;
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::CryptoError;

pub const MAGIC: [u8; 4] = *b"CMV2";
/// Envelope version 1: the plaintext is one raw value. Kept under this name
/// because every existing caller means "the raw-value version" by it.
pub const VERSION: u8 = 1;
/// Envelope version 2 (ADR-078): the plaintext is a field document.
pub const VERSION_FIELD_DOCUMENT: u8 = 2;
pub const SUITE_X25519_HKDF_SHA512_CHACHA20POLY1305: u8 = 1;

/// What an envelope's plaintext *is*. Determined by the authenticated version
/// byte and by nothing else (see the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadKind {
    /// Version 1 — the plaintext is one raw value (an alpha.6 entry, a node's
    /// `notes.env`).
    RawValue,
    /// Version 2 — the plaintext is a canonical-JSON field document.
    FieldDocument,
}

impl PayloadKind {
    /// The envelope version byte that carries this kind.
    pub const fn version(self) -> u8 {
        match self {
            PayloadKind::RawValue => VERSION,
            PayloadKind::FieldDocument => VERSION_FIELD_DOCUMENT,
        }
    }

    /// The kind a version byte denotes, `None` for a version this build does not
    /// implement.
    pub const fn from_version(version: u8) -> Option<PayloadKind> {
        match version {
            VERSION => Some(PayloadKind::RawValue),
            VERSION_FIELD_DOCUMENT => Some(PayloadKind::FieldDocument),
            _ => None,
        }
    }
}

const NODE_ID_FIELD_LEN: usize = 16;
const EPK_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = MAGIC.len() + 1 + 1 + NODE_ID_FIELD_LEN + EPK_LEN + NONCE_LEN;
const MIN_ENVELOPE_LEN: usize = HEADER_LEN + TAG_LEN;

const ENTRY_KEY_INFO: &[u8] = b"credmgr/v2/entry";

/// Encode a node id (`"global"` / `"orphan"` / `"n_" + 8 hex`) as a fixed
/// 16-byte, zero-padded UTF-8 field. Every id in `03_DATA_MODEL.md §1` is
/// ≤ 10 bytes, so this never truncates real data — it exists so the on-disk
/// header has a fixed, self-describing width.
fn encode_node_id(id: &str) -> Result<[u8; NODE_ID_FIELD_LEN], CryptoError> {
    let bytes = id.as_bytes();
    if bytes.len() > NODE_ID_FIELD_LEN {
        return Err(CryptoError::NodeIdTooLong);
    }
    let mut field = [0u8; NODE_ID_FIELD_LEN];
    field[..bytes.len()].copy_from_slice(bytes);
    Ok(field)
}

/// The AAD for an envelope **of the given version** — the version byte is part
/// of what the tag authenticates, which is what makes the payload kind
/// tamper-evident (a flipped byte reconstructs a different AAD and the tag
/// fails). Version 1's AAD is byte-for-byte what it has always been.
fn build_aad(version: u8, node_id_field: &[u8; NODE_ID_FIELD_LEN], entry_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + 1 + 1 + NODE_ID_FIELD_LEN + entry_id.len());
    aad.extend_from_slice(&MAGIC);
    aad.push(version);
    aad.push(SUITE_X25519_HKDF_SHA512_CHACHA20POLY1305);
    aad.extend_from_slice(node_id_field);
    aad.extend_from_slice(entry_id.as_bytes());
    aad
}

/// `HKDF-SHA512(ikm = shared, salt = ephemeral.pub ‖ node.pub, info =
/// "credmgr/v2/entry", len = 32)` — `04_CRYPTO_AND_KEYS.md §3`.
fn derive_entry_key(shared: &[u8], ephemeral_pub: &[u8; 32], node_pub: &[u8; 32]) -> [u8; 32] {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_pub);
    salt[32..].copy_from_slice(node_pub);
    let hk = Hkdf::<Sha512>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hk.expand(ENTRY_KEY_INFO, &mut key)
        .expect("32-byte output is within HKDF-SHA512's max length");
    key
}

/// Encrypt `plaintext` to `node_pub` under a fresh ephemeral keypair, bound to
/// `node_id` and `entry_id` (P-1, P-3, P-4, P-5) — as a **version-1 raw-value**
/// envelope. This is `seal_as(PayloadKind::RawValue, …)`; it is what a node's
/// `notes.env` still uses and what fixtures standing in for alpha.6 entries use.
/// Entries are sealed with [`seal_as`] and [`PayloadKind::FieldDocument`].
pub fn seal(
    plaintext: &[u8],
    node_pub: &PublicKey,
    node_id: &str,
    entry_id: &str,
) -> Result<Vec<u8>, CryptoError> {
    seal_as(
        PayloadKind::RawValue,
        plaintext,
        node_pub,
        node_id,
        entry_id,
    )
}

/// [`seal`] with the payload kind chosen: the version byte written into the
/// header (and into the AAD) is the kind's — 1 for a raw value, 2 for a field
/// document. Everything else is identical for both kinds.
pub fn seal_as(
    kind: PayloadKind,
    plaintext: &[u8],
    node_pub: &PublicKey,
    node_id: &str,
    entry_id: &str,
) -> Result<Vec<u8>, CryptoError> {
    let version = kind.version();
    let node_id_field = encode_node_id(node_id)?;

    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(node_pub);

    let key_bytes = derive_entry_key(
        shared.as_bytes(),
        ephemeral_pub.as_bytes(),
        node_pub.as_bytes(),
    );
    let key = Key::from_slice(&key_bytes);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(version, &node_id_field, entry_id);

    let cipher = ChaCha20Poly1305::new(key);
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut buffer)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut out = Vec::with_capacity(HEADER_LEN + buffer.len() + TAG_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(version);
    out.push(SUITE_X25519_HKDF_SHA512_CHACHA20POLY1305);
    out.extend_from_slice(&node_id_field);
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt an envelope with `node_priv`, asserting it belongs to `node_id`
/// and `entry_id` — the caller's context, derived from where the envelope was
/// found (its directory and filename), not trusted from the envelope's own
/// bytes. Returns the plaintext wrapped so it zeroises on drop.
///
/// **Version 1 only.** A version-2 (field-document) envelope is refused with
/// `UnsupportedVersion(2)`: this entry point exists for callers whose payload is
/// a raw value by definition — a node's `notes.env` — and it must not hand them
/// a JSON document as if it were their value. Entry readers use [`open_any`].
pub fn open(
    envelope: &[u8],
    node_priv: &StaticSecret,
    node_id: &str,
    entry_id: &str,
) -> Result<SecretBox<Vec<u8>>, CryptoError> {
    open_inner(envelope, node_priv, node_id, entry_id, |v| {
        (v == VERSION).then_some(PayloadKind::RawValue)
    })
    .map(|(_, plaintext)| plaintext)
}

/// [`open`] for a reader that accepts either payload kind: returns which kind
/// the envelope carries — read from the version byte the tag authenticates, so
/// it cannot be flipped in transit — together with the plaintext. The caller
/// interprets the plaintext by that kind: a raw value for
/// [`PayloadKind::RawValue`], a field document (`crate::fields::decode`) for
/// [`PayloadKind::FieldDocument`].
pub fn open_any(
    envelope: &[u8],
    node_priv: &StaticSecret,
    node_id: &str,
    entry_id: &str,
) -> Result<(PayloadKind, SecretBox<Vec<u8>>), CryptoError> {
    open_inner(
        envelope,
        node_priv,
        node_id,
        entry_id,
        PayloadKind::from_version,
    )
}

fn open_inner(
    envelope: &[u8],
    node_priv: &StaticSecret,
    node_id: &str,
    entry_id: &str,
    accept: impl Fn(u8) -> Option<PayloadKind>,
) -> Result<(PayloadKind, SecretBox<Vec<u8>>), CryptoError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(CryptoError::Truncated);
    }

    let (magic, rest) = envelope.split_at(MAGIC.len());
    if magic != MAGIC {
        return Err(CryptoError::BadMagic);
    }
    let (version, rest) = rest.split_at(1);
    let version = version[0];
    let Some(kind) = accept(version) else {
        return Err(CryptoError::UnsupportedVersion(version));
    };
    let (suite, rest) = rest.split_at(1);
    if suite[0] != SUITE_X25519_HKDF_SHA512_CHACHA20POLY1305 {
        return Err(CryptoError::UnsupportedSuite(suite[0]));
    }
    let (stored_node_id_field, rest) = rest.split_at(NODE_ID_FIELD_LEN);
    let (epk_bytes, rest) = rest.split_at(EPK_LEN);
    let (nonce_bytes, rest) = rest.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);

    let expected_node_id_field = encode_node_id(node_id)?;
    if stored_node_id_field != expected_node_id_field {
        return Err(CryptoError::NodeIdMismatch);
    }

    let mut epk_arr = [0u8; EPK_LEN];
    epk_arr.copy_from_slice(epk_bytes);
    let epk = PublicKey::from(epk_arr);

    let shared = node_priv.diffie_hellman(&epk);
    let node_pub = PublicKey::from(node_priv);
    let key_bytes = derive_entry_key(shared.as_bytes(), epk.as_bytes(), node_pub.as_bytes());
    let key = Key::from_slice(&key_bytes);

    let nonce = Nonce::from_slice(nonce_bytes);
    let aad = build_aad(version, &expected_node_id_field, entry_id);

    let cipher = ChaCha20Poly1305::new(key);
    let mut buffer = ciphertext.to_vec();
    let tag_array = chacha20poly1305::Tag::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce, &aad, &mut buffer, tag_array)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok((kind, SecretBox::new(Box::new(buffer))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn keypair() -> (StaticSecret, PublicKey) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    #[test]
    fn round_trip_basic() {
        let (priv_a, pub_a) = keypair();
        let plaintext = b"hunter2-not-really";
        let env = seal(plaintext, &pub_a, "n_1a2b3c4d", "e_deadbeef0001").unwrap();
        let opened = open(&env, &priv_a, "n_1a2b3c4d", "e_deadbeef0001").unwrap();
        assert_eq!(opened.expose_secret().as_slice(), plaintext);
    }

    #[test]
    fn round_trip_empty_and_large() {
        let (priv_a, pub_a) = keypair();
        for len in [0usize, 1, 1024, 1024 * 1024] {
            let plaintext = vec![0xab; len];
            let env = seal(&plaintext, &pub_a, "global", "e_000000000001").unwrap();
            let opened = open(&env, &priv_a, "global", "e_000000000001").unwrap();
            assert_eq!(opened.expose_secret(), &plaintext, "len={len}");
        }
    }

    #[test]
    fn cross_node_decrypt_fails() {
        let (_priv_a, pub_a) = keypair();
        let (priv_b, _pub_b) = keypair();
        let env = seal(b"secret", &pub_a, "n_aaaaaaaa", "e_1").unwrap();
        let err = open(&env, &priv_b, "n_aaaaaaaa", "e_1").unwrap_err();
        assert_eq!(err, CryptoError::AuthenticationFailed);
    }

    #[test]
    fn relocated_envelope_fails() {
        let (priv_a, pub_a) = keypair();
        let env = seal(b"secret", &pub_a, "n_aaaaaaaa", "e_1").unwrap();
        // Opened as if it lived in a different node's directory: wrong node id
        // asserted, and (realistically) the wrong node's private key too. Here
        // we isolate the AAD-binding failure specifically by using the SAME
        // key but asserting the wrong node id, proving the AAD alone rejects
        // it even when the ECDH would otherwise have "worked" is not
        // representable (ECDH needs the matching private key) — so this
        // checks the header/AAD mismatch is caught before any key confusion.
        let err = open(&env, &priv_a, "n_bbbbbbbb", "e_1").unwrap_err();
        assert_eq!(err, CryptoError::NodeIdMismatch);
    }

    #[test]
    fn swapped_entry_id_fails() {
        let (priv_a, pub_a) = keypair();
        let env = seal(b"secret", &pub_a, "n_aaaaaaaa", "e_1").unwrap();
        let err = open(&env, &priv_a, "n_aaaaaaaa", "e_2").unwrap_err();
        assert_eq!(err, CryptoError::AuthenticationFailed);
    }

    #[test]
    fn seal_is_nondeterministic() {
        let (_priv_a, pub_a) = keypair();
        let env1 = seal(b"same plaintext", &pub_a, "global", "e_1").unwrap();
        let env2 = seal(b"same plaintext", &pub_a, "global", "e_1").unwrap();
        assert_ne!(env1, env2);
    }

    #[test]
    fn node_id_too_long_is_rejected() {
        let (_priv_a, pub_a) = keypair();
        let err = seal(b"x", &pub_a, "this-node-id-is-far-too-long", "e_1").unwrap_err();
        assert_eq!(err, CryptoError::NodeIdTooLong);
    }

    #[test]
    fn truncated_envelope_is_rejected() {
        let (priv_a, _pub_a) = keypair();
        let err = open(&[0u8; 4], &priv_a, "global", "e_1").unwrap_err();
        assert_eq!(err, CryptoError::Truncated);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let (priv_a, pub_a) = keypair();
        let mut env = seal(b"x", &pub_a, "global", "e_1").unwrap();
        env[0] = b'X';
        let err = open(&env, &priv_a, "global", "e_1").unwrap_err();
        assert_eq!(err, CryptoError::BadMagic);
    }

    // ---- ADR-078: the payload kind rides in the authenticated version byte ----

    /// A real version-1 envelope exactly as the unmodified alpha.6 `seal`
    /// produced it (node secret `[7; 32]`, node `n_aaaaaaaa`, entry
    /// `e_bbbbbbbbbbbb`, plaintext `golden-alpha6-value`). Captured from the
    /// code **before** `seal_as` existed and pinned verbatim — the proof that an
    /// envelope an existing vault already holds still opens, as raw bytes, with
    /// no migration step.
    const ALPHA6_V1_ENVELOPE_HEX: &str = "434d563201016e5f61616161616161610000000000009ebfb2d1b75bfece9d44e93f0987d5bdee32351da73fadd09bc05fd514af523e5ae9ab036f8f3c8cb28be2f94b6d36e5f91214569f3293de18f6044860fc593216adf953e3e932af6c2ef66f1dcb73";
    const GOLDEN_NODE: &str = "n_aaaaaaaa";
    const GOLDEN_ENTRY: &str = "e_bbbbbbbbbbbb";

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn an_alpha6_version_1_envelope_still_opens_byte_for_byte() {
        let env = from_hex(ALPHA6_V1_ENVELOPE_HEX);
        assert_eq!(env[4], 1, "the golden vector is a version-1 envelope");
        let node_priv = StaticSecret::from([7u8; 32]);

        // The v1-only entry point (what `notes.env` uses) …
        let opened = open(&env, &node_priv, GOLDEN_NODE, GOLDEN_ENTRY).unwrap();
        assert_eq!(opened.expose_secret().as_slice(), b"golden-alpha6-value");

        // … and the entry reader, which must report it as a raw value.
        let (kind, opened) = open_any(&env, &node_priv, GOLDEN_NODE, GOLDEN_ENTRY).unwrap();
        assert_eq!(kind, PayloadKind::RawValue);
        assert_eq!(opened.expose_secret().as_slice(), b"golden-alpha6-value");
    }

    #[test]
    fn seal_is_exactly_seal_as_raw_value() {
        let (priv_a, pub_a) = keypair();
        let env = seal(b"v", &pub_a, "global", "e_1").unwrap();
        assert_eq!(env[4], VERSION);
        let (kind, _) = open_any(&env, &priv_a, "global", "e_1").unwrap();
        assert_eq!(kind, PayloadKind::RawValue);
    }

    #[test]
    fn a_field_document_envelope_is_version_2_and_open_any_reports_it() {
        let (priv_a, pub_a) = keypair();
        let doc = br#"{"v":1,"fields":[]}"#; // payload content is not this layer's concern
        let env = seal_as(
            PayloadKind::FieldDocument,
            doc,
            &pub_a,
            "n_1a2b3c4d",
            "e_deadbeef0001",
        )
        .unwrap();
        assert_eq!(env[4], VERSION_FIELD_DOCUMENT);
        let (kind, opened) = open_any(&env, &priv_a, "n_1a2b3c4d", "e_deadbeef0001").unwrap();
        assert_eq!(kind, PayloadKind::FieldDocument);
        assert_eq!(opened.expose_secret().as_slice(), doc);
    }

    #[test]
    fn the_raw_value_reader_refuses_a_field_document_instead_of_returning_json_as_a_value() {
        let (priv_a, pub_a) = keypair();
        let env = seal_as(PayloadKind::FieldDocument, b"{}", &pub_a, "global", "notes").unwrap();
        let err = open(&env, &priv_a, "global", "notes").unwrap_err();
        assert_eq!(err, CryptoError::UnsupportedVersion(2));
    }

    #[test]
    fn flipping_the_version_byte_fails_the_tag_in_both_directions() {
        let (priv_a, pub_a) = keypair();
        for (from, to) in [
            (PayloadKind::RawValue, VERSION_FIELD_DOCUMENT),
            (PayloadKind::FieldDocument, VERSION),
        ] {
            let mut env = seal_as(from, b"payload", &pub_a, "n_aaaaaaaa", "e_1").unwrap();
            env[4] = to;
            let err = open_any(&env, &priv_a, "n_aaaaaaaa", "e_1").unwrap_err();
            assert_eq!(
                err,
                CryptoError::AuthenticationFailed,
                "{from:?} relabelled as version {to} must fail authentication, not be \
                 handed to the wrong parser"
            );
        }
    }

    #[test]
    fn a_version_this_build_does_not_implement_is_named_not_attempted() {
        let (priv_a, pub_a) = keypair();
        for bad in [0u8, 3, 255] {
            let mut env = seal(b"x", &pub_a, "global", "e_1").unwrap();
            env[4] = bad;
            assert_eq!(
                open_any(&env, &priv_a, "global", "e_1").unwrap_err(),
                CryptoError::UnsupportedVersion(bad)
            );
        }
    }

    #[test]
    fn a_field_document_envelope_is_bound_to_its_node_and_entry_like_version_1() {
        let (priv_a, pub_a) = keypair();
        let env = seal_as(
            PayloadKind::FieldDocument,
            b"x",
            &pub_a,
            "n_aaaaaaaa",
            "e_1",
        )
        .unwrap();
        // Wrong entry id: the AAD differs, the tag fails.
        assert_eq!(
            open_any(&env, &priv_a, "n_aaaaaaaa", "e_2").unwrap_err(),
            CryptoError::AuthenticationFailed
        );
        // Wrong node id: refused before the AEAD call.
        assert_eq!(
            open_any(&env, &priv_a, "n_bbbbbbbb", "e_1").unwrap_err(),
            CryptoError::NodeIdMismatch
        );
        // Wrong key.
        let (priv_b, _) = keypair();
        assert_eq!(
            open_any(&env, &priv_b, "n_aaaaaaaa", "e_1").unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn payload_kind_and_version_byte_are_each_others_inverse() {
        for kind in [PayloadKind::RawValue, PayloadKind::FieldDocument] {
            assert_eq!(PayloadKind::from_version(kind.version()), Some(kind));
        }
        assert_eq!(PayloadKind::from_version(0), None);
        assert_eq!(PayloadKind::from_version(3), None);
    }
}

/// Fixed test vectors, independently verified against a from-scratch
/// `node:crypto` re-implementation (`crypto.diffieHellman` with JWK-imported
/// X25519 keys, `crypto.hkdfSync`, `crypto.createCipheriv('chacha20-poly1305',
/// ...)`) — every hex constant below was computed by Node, not just Rust,
/// before this test was written. This is the ADR-045/`scripts/
/// emergency-decrypt.mjs` interop risk pinned down at the primitive level:
/// if `derive_entry_key`, `build_aad`, or the AEAD call ever drift, this
/// fails here, in Rust, rather than surfacing as an inexplicable auth
/// failure in `emergency_decrypt.rs`'s end-to-end fixture test.
#[cfg(test)]
mod node_interop_vectors {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn x25519_hkdf_and_aead_match_an_independent_node_crypto_computation() {
        let node_priv = StaticSecret::from([3u8; 32]);
        let node_pub = PublicKey::from(&node_priv);
        let ephem_priv = StaticSecret::from([5u8; 32]);
        let ephem_pub = PublicKey::from(&ephem_priv);
        let shared = ephem_priv.diffie_hellman(&node_pub);

        let hex = |b: &[u8]| -> String {
            use std::fmt::Write;
            b.iter().fold(String::new(), |mut s, x| {
                write!(s, "{x:02x}").unwrap();
                s
            })
        };

        assert_eq!(
            hex(shared.as_bytes()),
            "8a7eddf1d2e69d6c895a5e969092dd6be0caa725d435c0244fe33fc2259aa847"
        );

        let key_bytes =
            derive_entry_key(shared.as_bytes(), ephem_pub.as_bytes(), node_pub.as_bytes());
        assert_eq!(
            hex(&key_bytes),
            "5ab7bf6da80a22096db141f45e960a984ad534584643c57257c1ca722a09780e"
        );

        let node_id_field = encode_node_id("n_aaaaaaaa").unwrap();
        let aad = build_aad(VERSION, &node_id_field, "e_1");
        assert_eq!(
            hex(&aad),
            "434d563201016e5f6161616161616161000000000000655f31"
        );

        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        let key = Key::from_slice(&key_bytes);
        let nonce_bytes = [9u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        let mut buffer = b"hello world".to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &aad, &mut buffer)
            .unwrap();
        assert_eq!(hex(&buffer), "89061f70f79ce63f391e4b");
        assert_eq!(hex(&tag), "89599015e831f0ff4a8eface87410c0c");
    }

    /// ADR-078: the version-2 AAD differs from version 1's in exactly one byte
    /// (the version), the ciphertext is the same keystream, and the tag differs
    /// — the whole mechanism by which the payload kind is authenticated. The
    /// constants were computed by `node:crypto` (same key and nonce as the
    /// version-1 vector above, only the AAD's version byte changed), not by this
    /// crate.
    #[test]
    fn the_version_2_aad_and_tag_match_an_independent_node_crypto_computation() {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        let hex = |b: &[u8]| -> String {
            use std::fmt::Write;
            b.iter().fold(String::new(), |mut s, x| {
                write!(s, "{x:02x}").unwrap();
                s
            })
        };

        let node_priv = StaticSecret::from([3u8; 32]);
        let node_pub = PublicKey::from(&node_priv);
        let ephem_priv = StaticSecret::from([5u8; 32]);
        let ephem_pub = PublicKey::from(&ephem_priv);
        let shared = ephem_priv.diffie_hellman(&node_pub);
        let key_bytes =
            derive_entry_key(shared.as_bytes(), ephem_pub.as_bytes(), node_pub.as_bytes());

        let node_id_field = encode_node_id("n_aaaaaaaa").unwrap();
        let aad = build_aad(VERSION_FIELD_DOCUMENT, &node_id_field, "e_1");
        assert_eq!(
            hex(&aad),
            "434d563202016e5f6161616161616161000000000000655f31"
        );

        let key = Key::from_slice(&key_bytes);
        let nonce_bytes = [9u8; 12];
        let cipher = ChaCha20Poly1305::new(key);
        let mut buffer = b"hello world".to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &aad, &mut buffer)
            .unwrap();
        assert_eq!(hex(&buffer), "89061f70f79ce63f391e4b");
        assert_eq!(hex(&tag), "51b8e2e525336dc5a140d24fca88b09a");
    }
}
