//! The two vault files the macOS Secure Enclave tier adds (ADR-098).
//!
//! * `keys/presence.enroll` — the **public** keys whose signatures count as "the user was here"
//!   (`credmgr_core::presence`). Integrity-protected with the same root-derived HMAC as the registry, so a
//!   process that can write the vault directory but does not hold the root key cannot swap in a key of its
//!   own. A missing file means nothing is enrolled; a present file that fails its tag is an integrity
//!   error, never "nothing enrolled" (a tamper must not quietly turn a gate into a different gate).
//! * `keys/root.wrap.se` — the root key sealed to a Secure Enclave key (the Touch ID unlock). Its `sealed`
//!   field is an AEAD blob, but the rest of the file is **not** protected by it: `wrapPublic` is the point a
//!   root-key rotation re-seals the *new* root key to, without a prompt. An unauthenticated `wrapPublic` let a
//!   process that can write the vault directory plant its own point and receive the next root key
//!   (ADR-148 §P1-1). So the file carries `tag`, an HMAC under the root-derived key over
//!   `(v, keystore, wrapBlob, wrapPublic, createdAt)`; a rotation re-seals only to a wrap whose tag verifies
//!   under the old root key, and re-signs it under the new one. A wrap written before ADR-148 has no tag:
//!   it still opens the vault (the Secure Enclave and the registry HMAC decide that), but a rotation refuses
//!   it until Touch ID unlock is turned off and on again.
//!
//! `root.wrap.se` is never in a backup (`backup.rs` removes it); `presence.enroll` is (it holds public keys
//! only). Both are meaningful only on the Mac that holds the Secure Enclave key.

use serde::{Deserialize, Serialize};

use credmgr_core::signing;

use crate::atomic;
use crate::error::{Result, StoreError};
use crate::hexutil;
use crate::paths::VaultPaths;

const ENROLL_LABEL: &str = "presence-enroll";
/// ADR-148: the HMAC label of the device wrap's tag.
const WRAP_LABEL: &str = "device-wrap";
const ENROLL_VERSION: u8 = 1;
const WRAP_VERSION: u8 = 1;

/// One enrolled presence key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceKeyRecord {
    /// Short stable id (first 8 bytes of SHA-256 of the public key, hex).
    pub id: String,
    /// The 65-byte uncompressed P-256 point, hex.
    pub public: String,
    pub label: String,
    /// Epoch seconds.
    pub created_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollDoc {
    v: u8,
    keys: Vec<PresenceKeyRecord>,
    tag: String,
}

fn body_bytes(keys: &[PresenceKeyRecord]) -> Vec<u8> {
    let value = serde_json::to_value(keys).expect("records serialise");
    credmgr_core::presence::canonical_json(&value)
}

fn io_corrupt(path: std::path::PathBuf, why: &str) -> StoreError {
    StoreError::Io {
        path,
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string()),
    }
}

fn corrupt(paths: &VaultPaths, why: &str) -> StoreError {
    io_corrupt(paths.presence_enroll(), why)
}

/// The enrolled keys, verified under `root`. Absent file → empty.
pub fn load_presence(paths: &VaultPaths, root: &[u8; 32]) -> Result<Vec<PresenceKeyRecord>> {
    let path = paths.presence_enroll();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = atomic::read(&path)?;
    let doc: EnrollDoc = serde_json::from_slice(&bytes)
        .map_err(|_| corrupt(paths, "the presence enrolment file is not valid JSON"))?;
    if doc.v != ENROLL_VERSION {
        return Err(corrupt(
            paths,
            "the presence enrolment file has an unknown version",
        ));
    }
    let tag = hexutil::decode_32(&doc.tag)
        .ok_or_else(|| corrupt(paths, "the presence enrolment tag is malformed"))?;
    if !signing::verify(root, ENROLL_LABEL, &body_bytes(&doc.keys), &tag) {
        return Err(corrupt(
            paths,
            "the presence enrolment file failed its integrity check",
        ));
    }
    Ok(doc.keys)
}

/// The bytes `save_presence` would write, signed under `root` — also what a rotation re-signs.
pub fn presence_bytes(keys: &[PresenceKeyRecord], root: &[u8; 32]) -> Vec<u8> {
    let tag = signing::sign(root, ENROLL_LABEL, &body_bytes(keys));
    let doc = EnrollDoc {
        v: ENROLL_VERSION,
        keys: keys.to_vec(),
        tag: hexutil::encode(&tag),
    };
    serde_json::to_vec_pretty(&doc).expect("an enrolment document serialises")
}

/// Write the enrolment file (removing it when `keys` is empty).
pub fn save_presence(
    paths: &VaultPaths,
    root: &[u8; 32],
    keys: &[PresenceKeyRecord],
) -> Result<()> {
    if keys.is_empty() {
        if paths.presence_enroll().exists() {
            atomic::remove_durable(&paths.presence_enroll())?;
        }
        return Ok(());
    }
    atomic::write(&paths.presence_enroll(), &presence_bytes(keys, root))
}

/// Re-sign an existing enrolment file for a new root key (rotation). `None` when nothing is enrolled.
pub fn resigned_presence(
    paths: &VaultPaths,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    if !paths.presence_enroll().exists() {
        return Ok(None);
    }
    let keys = load_presence(paths, old_root)?;
    Ok(Some(presence_bytes(&keys, new_root)))
}

/// The Touch ID unlock wrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceWrap {
    pub v: u8,
    pub keystore: String,
    /// The Secure Enclave wrap key's opaque blob, hex.
    pub wrap_blob: String,
    /// The wrap key's public point, hex.
    pub wrap_public: String,
    /// The root key sealed to `wrap_public` (`credmgr_core::presence::seal_root_to_public`), hex.
    pub sealed: String,
    pub created_at: i64,
    /// ADR-148: HMAC under the root key over `(v, keystore, wrapBlob, wrapPublic, createdAt)`, hex. Absent in
    /// a wrap written before ADR-148 (which a rotation refuses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// Whether a device wrap's tag verifies (ADR-148).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapAuth {
    /// The tag verifies under the root key.
    Valid,
    /// No tag: written before ADR-148.
    Untagged,
    /// A tag that does not verify (tampered, or written under another root key).
    Invalid,
}

impl DeviceWrap {
    pub fn new(wrap_blob: &[u8], wrap_public: &[u8], sealed: &[u8], created_at: i64) -> Self {
        DeviceWrap {
            v: WRAP_VERSION,
            keystore: "macos-secure-enclave".to_string(),
            wrap_blob: hex(wrap_blob),
            wrap_public: hex(wrap_public),
            sealed: hex(sealed),
            created_at,
            tag: None,
        }
    }

    /// The bytes the tag covers: everything that decides where a rotation seals the root key.
    fn tag_body(&self) -> Vec<u8> {
        let value = serde_json::json!({
            "v": self.v,
            "keystore": self.keystore,
            "wrapBlob": self.wrap_blob,
            "wrapPublic": self.wrap_public,
            "createdAt": self.created_at,
        });
        credmgr_core::presence::canonical_json(&value)
    }

    /// Sign the wrap under `root` (ADR-148), replacing any tag it had.
    pub fn signed(mut self, root: &[u8; 32]) -> Self {
        let tag = signing::sign(root, WRAP_LABEL, &self.tag_body());
        self.tag = Some(hexutil::encode(&tag));
        self
    }

    /// Check the tag under `root`.
    pub fn authenticate(&self, root: &[u8; 32]) -> WrapAuth {
        let Some(tag) = self.tag.as_deref() else {
            return WrapAuth::Untagged;
        };
        match hexutil::decode_32(tag) {
            Some(tag) if signing::verify(root, WRAP_LABEL, &self.tag_body(), &tag) => {
                WrapAuth::Valid
            }
            _ => WrapAuth::Invalid,
        }
    }

    pub fn wrap_blob_bytes(&self) -> Option<Vec<u8>> {
        unhex(&self.wrap_blob)
    }

    pub fn wrap_public_bytes(&self) -> Option<Vec<u8>> {
        unhex(&self.wrap_public)
    }

    pub fn sealed_bytes(&self) -> Option<Vec<u8>> {
        unhex(&self.sealed)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("a device wrap serialises")
    }
}

fn hex(b: &[u8]) -> String {
    hexutil::encode(b)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| {
            let hi = (c[0] as char).to_digit(16)?;
            let lo = (c[1] as char).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}

/// Read `keys/root.wrap.se`. `Ok(None)` when no Touch ID unlock is set up.
pub fn load_device_wrap(paths: &VaultPaths) -> Result<Option<DeviceWrap>> {
    let path = paths.root_wrap_se();
    if !path.exists() {
        return Ok(None);
    }
    let bytes = atomic::read(&path)?;
    let wrap: DeviceWrap = serde_json::from_slice(&bytes)
        .map_err(|_| io_corrupt(path.clone(), "the Touch ID unlock wrap is not valid JSON"))?;
    if wrap.v != WRAP_VERSION {
        return Err(io_corrupt(
            path,
            "the Touch ID unlock wrap has an unknown version",
        ));
    }
    Ok(Some(wrap))
}

pub fn save_device_wrap(paths: &VaultPaths, wrap: &DeviceWrap) -> Result<()> {
    atomic::write(&paths.root_wrap_se(), &wrap.to_bytes())
}

pub fn remove_device_wrap(paths: &VaultPaths) -> Result<()> {
    if paths.root_wrap_se().exists() {
        atomic::remove_durable(&paths.root_wrap_se())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(n: u8) -> PresenceKeyRecord {
        PresenceKeyRecord {
            id: format!("{n:016x}"),
            public: hexutil::encode(&[n; 32]),
            label: "This Mac".into(),
            created_at: 1_700_000_000,
        }
    }

    fn vault() -> (tempfile::TempDir, VaultPaths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        atomic::ensure_dir(&paths.keys_dir()).unwrap();
        (dir, paths)
    }

    #[test]
    fn enrolment_round_trips_and_absent_means_empty() {
        let (_d, paths) = vault();
        let root = [1u8; 32];
        assert!(load_presence(&paths, &root).unwrap().is_empty());
        save_presence(&paths, &root, &[rec(1), rec(2)]).unwrap();
        assert_eq!(load_presence(&paths, &root).unwrap(), vec![rec(1), rec(2)]);
        save_presence(&paths, &root, &[]).unwrap();
        assert!(!paths.presence_enroll().exists());
    }

    #[test]
    fn a_wrong_root_or_an_edit_is_an_integrity_error_not_an_empty_list() {
        let (_d, paths) = vault();
        save_presence(&paths, &[1u8; 32], &[rec(1)]).unwrap();
        assert!(load_presence(&paths, &[2u8; 32]).is_err());
        let text = std::fs::read_to_string(paths.presence_enroll()).unwrap();
        std::fs::write(
            paths.presence_enroll(),
            text.replace("This Mac", "Evil Mac"),
        )
        .unwrap();
        assert!(load_presence(&paths, &[1u8; 32]).is_err());
    }

    #[test]
    fn rotation_resigns_under_the_new_root() {
        let (_d, paths) = vault();
        save_presence(&paths, &[1u8; 32], &[rec(7)]).unwrap();
        let bytes = resigned_presence(&paths, &[1u8; 32], &[2u8; 32])
            .unwrap()
            .unwrap();
        atomic::write(&paths.presence_enroll(), &bytes).unwrap();
        assert!(load_presence(&paths, &[1u8; 32]).is_err());
        assert_eq!(load_presence(&paths, &[2u8; 32]).unwrap(), vec![rec(7)]);
    }

    #[test]
    fn the_device_wrap_round_trips() {
        let (_d, paths) = vault();
        assert!(load_device_wrap(&paths).unwrap().is_none());
        let w = DeviceWrap::new(&[1, 2, 3], &[4; 65], &[5; 130], 42);
        save_device_wrap(&paths, &w).unwrap();
        let back = load_device_wrap(&paths).unwrap().unwrap();
        assert_eq!(back, w);
        assert_eq!(back.wrap_blob_bytes().unwrap(), vec![1, 2, 3]);
        remove_device_wrap(&paths).unwrap();
        assert!(load_device_wrap(&paths).unwrap().is_none());
    }

    #[test]
    fn the_device_wrap_tag_binds_the_public_point_to_the_root_key() {
        let w = DeviceWrap::new(&[1, 2, 3], &[4; 65], &[5; 130], 42);
        assert_eq!(w.authenticate(&[1u8; 32]), WrapAuth::Untagged);
        let signed = w.signed(&[1u8; 32]);
        assert_eq!(signed.authenticate(&[1u8; 32]), WrapAuth::Valid);
        assert_eq!(signed.authenticate(&[2u8; 32]), WrapAuth::Invalid);
        let mut planted = signed.clone();
        planted.wrap_public = hex(&[9; 65]);
        assert_eq!(planted.authenticate(&[1u8; 32]), WrapAuth::Invalid);
        // The sealed blob is outside the tag (it changes on every rotation and is an AEAD blob itself).
        let mut resealed = signed;
        resealed.sealed = hex(&[6; 130]);
        assert_eq!(resealed.authenticate(&[1u8; 32]), WrapAuth::Valid);
    }
}
