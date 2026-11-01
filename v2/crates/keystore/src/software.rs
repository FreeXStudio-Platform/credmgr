//! `SoftwareKeystore` — Argon2id over an operator passphrase. `16 §4.4`:
//! "Always present on every platform" as the escrow wrap, not one of the
//! three hardware tiers (see `lib.rs` module doc, ADR-041).
//!
//! One primitive backs both jobs this type does (wrapping the root key, and
//! sealing counter values): derive a 32-byte key from the passphrase with a
//! freshly-generated salt via Argon2id, then ChaCha20-Poly1305-seal the
//! payload with that key, storing the salt next to the ciphertext. Tampering
//! with either the payload or its salt fails the same AEAD tag check —
//! there is nothing to distinguish "wrong passphrase" from "corrupted blob",
//! consistent with `credmgr_core`'s "deliberately undifferentiated" AEAD
//! error convention.

use std::env;
use std::path::PathBuf;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{KeystoreError, Result};
use crate::{Capabilities, KeystoreId, PlatformKeystore, PresenceProof, Tier, WrappedKey};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// `16 §4.4`: "Argon2id (m=256 MiB, t=3, p=4)".
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

/// `salt || nonce || ciphertext‖tag`, sealed under `derive_key(passphrase, salt)`.
fn seal(passphrase: &SecretBox<String>, plaintext: &[u8]) -> Vec<u8> {
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
        .expect("ChaCha20Poly1305 encryption of a small fixed-size payload cannot fail");
    buffer.extend_from_slice(&tag);
    key_bytes.zeroize();

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + buffer.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buffer);
    out
}

fn open(passphrase: &SecretBox<String>, blob: &[u8]) -> Result<Vec<u8>> {
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

/// The passphrase-only keystore. Holds the passphrase for the lifetime of
/// one unlock attempt — the broker constructs one when the operator supplies
/// a passphrase and drops it on lock, exactly like the hot node-key set.
pub struct SoftwareKeystore {
    passphrase: SecretBox<String>,
    state_dir: PathBuf,
}

impl SoftwareKeystore {
    pub fn new(passphrase: SecretBox<String>, state_dir: PathBuf) -> Self {
        SoftwareKeystore {
            passphrase,
            state_dir,
        }
    }

    /// Same env-var-driven resolution as `credmgr_store::paths` (ADR-039),
    /// duplicated rather than depended on: `crates/keystore` must not gain a
    /// dependency on `crates/store` for ~15 lines a sibling crate also
    /// needs, and this crate's counters live in their own `keystore/`
    /// subdirectory so the two crates' files can never collide even if
    /// `CREDMGR_STATE_DIR` is overridden to the same root for both.
    pub fn default_state_dir() -> PathBuf {
        default_state_dir_root().join("keystore")
    }

    fn counter_path(&self, name: &str) -> PathBuf {
        self.state_dir.join(format!("{name}.swcounter"))
    }
}

#[derive(Serialize, Deserialize)]
struct CounterFile {
    /// Base64-free: the sealed blob is bytes, stored as a JSON array of u8
    /// rather than pulling in a base64 dependency for one field.
    sealed: Vec<u8>,
}

impl PlatformKeystore for SoftwareKeystore {
    fn id(&self) -> KeystoreId {
        KeystoreId::Software
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: false,
            user_presence: false,
            anti_hammering: false,
            survives_reboot: true,
            tier: Tier::Software,
        }
    }

    fn wrap_root(&self, root: &SecretBox<[u8; 32]>) -> Result<WrappedKey> {
        let bytes = seal(&self.passphrase, root.expose_secret());
        Ok(WrappedKey {
            keystore: KeystoreId::Software,
            bytes,
        })
    }

    fn unwrap_root(&self, wrapped: &WrappedKey, _reason: &str) -> Result<SecretBox<[u8; 32]>> {
        let mut plaintext = open(&self.passphrase, &wrapped.bytes)?;
        if plaintext.len() != 32 {
            plaintext.zeroize();
            return Err(KeystoreError::Truncated);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(SecretBox::new(Box::new(arr)))
    }

    fn verify_presence(&self, _reason: &str) -> Result<PresenceProof> {
        // `capabilities().user_presence == false` — see ADR-041 and the
        // trait doc comment. Never silently succeed here: a caller that
        // skips the capability check and relies on this for an orphan
        // reveal or a grant must get a hard error, not a free pass.
        Err(KeystoreError::PresenceUnavailable)
    }

    fn read_counter(&self, name: &str) -> Result<u64> {
        let path = self.counter_path(name);
        if !path.exists() {
            return Ok(0);
        }
        let bytes = std::fs::read(&path).map_err(|e| KeystoreError::Io {
            path: path.clone(),
            source: e,
        })?;
        let doc: CounterFile = serde_json::from_slice(&bytes).map_err(|e| KeystoreError::Json {
            path: path.clone(),
            source: e,
        })?;
        let plaintext = open(&self.passphrase, &doc.sealed)?;
        if plaintext.len() != 8 {
            return Err(KeystoreError::Truncated);
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&plaintext);
        Ok(u64::from_be_bytes(arr))
    }

    fn write_counter(&self, name: &str, value: u64) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir).map_err(|e| KeystoreError::Io {
            path: self.state_dir.clone(),
            source: e,
        })?;
        let sealed = seal(&self.passphrase, &value.to_be_bytes());
        let doc = CounterFile { sealed };
        let path = self.counter_path(name);
        let bytes = serde_json::to_vec(&doc).map_err(|e| KeystoreError::Json {
            path: path.clone(),
            source: e,
        })?;
        std::fs::write(&path, bytes).map_err(|e| KeystoreError::Io { path, source: e })
    }
}

fn default_state_dir_root() -> PathBuf {
    if let Some(over) = env::var_os("CREDMGR_STATE_DIR") {
        return PathBuf::from(over);
    }
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .join("Library")
            .join("Application Support")
            .join("credmgr-state")
    }
    #[cfg(target_os = "windows")]
    {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home_dir)
            .join("credmgr")
            .join("state")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".local").join("state"))
            .join("credmgr")
    }
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
fn home_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .expect("USERPROFILE must be set on Windows")
    }
    #[cfg(not(target_os = "windows"))]
    {
        env::var_os("HOME")
            .map(PathBuf::from)
            .expect("HOME must be set")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn keystore(dir: &Path, pass: &str) -> SoftwareKeystore {
        SoftwareKeystore::new(
            SecretBox::new(Box::new(pass.to_string())),
            dir.to_path_buf(),
        )
    }

    #[test]
    fn wrap_unwrap_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let ks = keystore(dir.path(), "correct horse battery staple");
        let root = SecretBox::new(Box::new([42u8; 32]));
        let wrapped = ks.wrap_root(&root).unwrap();
        let unwrapped = ks.unwrap_root(&wrapped, "test unlock").unwrap();
        assert_eq!(unwrapped.expose_secret(), root.expose_secret());
    }

    #[test]
    fn wrong_passphrase_fails_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let ks = keystore(dir.path(), "correct horse battery staple");
        let root = SecretBox::new(Box::new([42u8; 32]));
        let wrapped = ks.wrap_root(&root).unwrap();

        let wrong = keystore(dir.path(), "a different passphrase entirely");
        let err = wrong.unwrap_root(&wrapped, "test unlock").unwrap_err();
        assert!(matches!(err, KeystoreError::AuthenticationFailed));
    }

    #[test]
    fn tampered_wrapped_blob_fails_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let ks = keystore(dir.path(), "correct horse battery staple");
        let root = SecretBox::new(Box::new([42u8; 32]));
        let mut wrapped = ks.wrap_root(&root).unwrap();
        let last = wrapped.bytes.len() - 1;
        wrapped.bytes[last] ^= 0xFF;

        let err = ks.unwrap_root(&wrapped, "test unlock").unwrap_err();
        assert!(matches!(err, KeystoreError::AuthenticationFailed));
    }

    #[test]
    fn wrapping_is_nondeterministic() {
        let dir = tempfile::tempdir().unwrap();
        let ks = keystore(dir.path(), "correct horse battery staple");
        let root = SecretBox::new(Box::new([42u8; 32]));
        let w1 = ks.wrap_root(&root).unwrap();
        let w2 = ks.wrap_root(&root).unwrap();
        assert_ne!(w1.bytes, w2.bytes);
    }

    #[test]
    fn capabilities_are_honest_about_the_software_tier() {
        let dir = tempfile::tempdir().unwrap();
        let ks = keystore(dir.path(), "pw");
        let caps = ks.capabilities();
        assert!(!caps.hardware_backed);
        assert!(!caps.user_presence);
        assert!(!caps.anti_hammering);
        assert_eq!(caps.tier, Tier::Software);
    }

    #[test]
    fn verify_presence_is_refused_not_faked() {
        let dir = tempfile::tempdir().unwrap();
        let ks = keystore(dir.path(), "pw");
        let err = ks.verify_presence("orphan reveal").unwrap_err();
        assert!(matches!(err, KeystoreError::PresenceUnavailable));
    }

    #[test]
    fn fresh_counter_reads_as_zero() {
        let dir = tempfile::tempdir().unwrap();
        let ks = keystore(dir.path(), "pw");
        assert_eq!(ks.read_counter("vaultGeneration").unwrap(), 0);
    }

    #[test]
    fn counter_write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let ks = keystore(dir.path(), "pw");
        ks.write_counter("vaultGeneration", 42).unwrap();
        assert_eq!(ks.read_counter("vaultGeneration").unwrap(), 42);
    }

    #[test]
    fn counter_persists_across_a_fresh_instance_over_the_same_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        keystore(dir.path(), "pw")
            .write_counter("vaultGeneration", 7)
            .unwrap();
        let reopened = keystore(dir.path(), "pw");
        assert_eq!(reopened.read_counter("vaultGeneration").unwrap(), 7);
    }

    #[test]
    fn tampered_counter_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ks = keystore(dir.path(), "pw");
        ks.write_counter("vaultGeneration", 42).unwrap();

        let path = dir.path().join("vaultGeneration.swcounter");
        let mut doc: CounterFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let last = doc.sealed.len() - 1;
        doc.sealed[last] ^= 0xFF;
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();

        let err = ks.read_counter("vaultGeneration").unwrap_err();
        assert!(matches!(err, KeystoreError::AuthenticationFailed));
    }

    #[test]
    fn wrong_passphrase_cannot_read_the_counter() {
        let dir = tempfile::tempdir().unwrap();
        keystore(dir.path(), "pw")
            .write_counter("vaultGeneration", 42)
            .unwrap();
        let wrong = keystore(dir.path(), "not the passphrase");
        let err = wrong.read_counter("vaultGeneration").unwrap_err();
        assert!(matches!(err, KeystoreError::AuthenticationFailed));
    }

    #[test]
    fn default_state_dir_is_a_keystore_subdirectory_and_never_the_vault_dir() {
        let prev_state = env::var_os("CREDMGR_STATE_DIR");
        let prev_vault = env::var_os("CREDMGR_VAULT_DIR");
        env::remove_var("CREDMGR_STATE_DIR");
        env::remove_var("CREDMGR_VAULT_DIR");

        let dir = SoftwareKeystore::default_state_dir();
        assert!(dir.ends_with("keystore"));

        if let Some(v) = prev_state {
            env::set_var("CREDMGR_STATE_DIR", v);
        }
        if let Some(v) = prev_vault {
            env::set_var("CREDMGR_VAULT_DIR", v);
        }
    }
}
