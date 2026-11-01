//! The external `vaultGeneration` counter — ADR-024, ADR-039. Freshness,
//! not just authorship: an HMAC on `registry.json` proves who wrote it,
//! never *when*, so a validly-signed but rolled-back file must be caught
//! some other way.
//!
//! `GenerationCounter` is a minimal trait ([`read`](GenerationCounter::read)/
//! [`write`](GenerationCounter::write)) that `crates/keystore`'s Phase-5
//! `PlatformKeystore` implementations will also satisfy — see ADR-039 for why
//! this crate doesn't depend on `credmgr-keystore` to get one now.
//! [`FileGenerationCounter`] is the one concrete implementation Phase 2
//! ships: a `0600` HMAC'd file, which is `16_CROSS_PLATFORM.md §4.3`'s own
//! documented Linux no-TPM fallback, generalised to every platform.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::error::{Result, StoreError};
use crate::hexutil;
use crate::paths::default_state_dir;

/// The counter name this crate's registry freshness check uses.
pub const VAULT_GENERATION: &str = "vaultGeneration";

pub trait GenerationCounter {
    /// `Ok(None)` means the counter has never been written — a fresh vault,
    /// not a failure.
    fn read(&self, root_key: &[u8; 32], name: &str) -> Result<Option<u64>>;
    fn write(&self, root_key: &[u8; 32], name: &str, value: u64) -> Result<()>;
}

fn label(name: &str) -> String {
    format!("generation-counter/{name}")
}

#[derive(Debug, Serialize, Deserialize)]
struct CounterDoc {
    value: u64,
    /// Hex-encoded 32-byte HMAC tag over `value`'s big-endian bytes.
    hmac: String,
}

/// `04_CRYPTO_AND_KEYS.md §6a`: "outside the vault directory". Backed by
/// [`crate::paths::default_state_dir`], a sibling location to the vault
/// itself — restoring an old copy of the *vault* directory does not restore
/// this file, which is the whole point.
pub struct FileGenerationCounter {
    dir: PathBuf,
}

impl FileGenerationCounter {
    pub fn new(dir: PathBuf) -> Self {
        FileGenerationCounter { dir }
    }

    pub fn default_location() -> Self {
        FileGenerationCounter::new(default_state_dir())
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.counter"))
    }

    /// Where counter `name` lives — public so root-key rotation (ADR-076)
    /// can stage a replacement for exactly this file.
    pub fn file_path(&self, name: &str) -> PathBuf {
        self.path(name)
    }
}

/// The bytes [`FileGenerationCounter::write`] would put on disk for
/// `value`, signed under `root_key`, without writing them (ADR-076).
pub fn signed_counter_bytes(root_key: &[u8; 32], name: &str, value: u64) -> Result<Vec<u8>> {
    let data = value.to_be_bytes();
    let tag = credmgr_core::signing::sign(root_key, &label(name), &data);
    let doc = CounterDoc {
        value,
        hmac: hexutil::encode(&tag),
    };
    serde_json::to_vec(&doc).map_err(|e| StoreError::Json {
        path: PathBuf::from(format!("{name}.counter")),
        source: e,
    })
}

impl GenerationCounter for FileGenerationCounter {
    fn read(&self, root_key: &[u8; 32], name: &str) -> Result<Option<u64>> {
        let path = self.path(name);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = atomic::read(&path)?;
        let doc: CounterDoc = serde_json::from_slice(&bytes).map_err(|e| StoreError::Json {
            path: path.clone(),
            source: e,
        })?;
        let tag = hexutil::decode_32(&doc.hmac)
            .ok_or_else(|| StoreError::GenerationCounterTampered { path: path.clone() })?;
        let data = doc.value.to_be_bytes();
        if !credmgr_core::signing::verify(root_key, &label(name), &data, &tag) {
            return Err(StoreError::GenerationCounterTampered { path });
        }
        Ok(Some(doc.value))
    }

    fn write(&self, root_key: &[u8; 32], name: &str, value: u64) -> Result<()> {
        let bytes = signed_counter_bytes(root_key, name, value)?;
        atomic::write(&self.path(name), &bytes)
    }
}

/// The broker-start check (`04 §6a`): compare `registry.json`'s own
/// `vaultGeneration` against the external counter. Lower ⇒ refuse. Equal ⇒
/// fine, nothing to do. Higher ⇒ a normal forward write since the counter
/// was last recorded — advance the external counter to match, so the next
/// check has a fresh baseline.
pub fn check_and_advance(
    root_key: &[u8; 32],
    counter: &dyn GenerationCounter,
    on_disk_generation: u64,
) -> Result<()> {
    let external = counter.read(root_key, VAULT_GENERATION)?.unwrap_or(0);
    if on_disk_generation < external {
        return Err(StoreError::GenerationRolledBack {
            on_disk: on_disk_generation,
            external,
        });
    }
    if on_disk_generation > external {
        counter.write(root_key, VAULT_GENERATION, on_disk_generation)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_counter_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let c = FileGenerationCounter::new(dir.path().to_path_buf());
        assert_eq!(c.read(&[1u8; 32], VAULT_GENERATION).unwrap(), None);
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let c = FileGenerationCounter::new(dir.path().to_path_buf());
        c.write(&[1u8; 32], VAULT_GENERATION, 42).unwrap();
        assert_eq!(c.read(&[1u8; 32], VAULT_GENERATION).unwrap(), Some(42));
    }

    #[test]
    fn tampered_counter_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let c = FileGenerationCounter::new(dir.path().to_path_buf());
        c.write(&[1u8; 32], VAULT_GENERATION, 42).unwrap();

        let path = dir.path().join("vaultGeneration.counter");
        let mut doc: CounterDoc = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        doc.value = 1; // attacker rolls the visible counter back too
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();

        let err = c.read(&[1u8; 32], VAULT_GENERATION).unwrap_err();
        assert!(matches!(err, StoreError::GenerationCounterTampered { .. }));
    }

    #[test]
    fn wrong_root_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let c = FileGenerationCounter::new(dir.path().to_path_buf());
        c.write(&[1u8; 32], VAULT_GENERATION, 42).unwrap();
        let err = c.read(&[2u8; 32], VAULT_GENERATION).unwrap_err();
        assert!(matches!(err, StoreError::GenerationCounterTampered { .. }));
    }

    #[test]
    fn on_disk_behind_external_is_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let c = FileGenerationCounter::new(dir.path().to_path_buf());
        let rk = [1u8; 32];
        c.write(&rk, VAULT_GENERATION, 5).unwrap();
        let err = check_and_advance(&rk, &c, 3).unwrap_err();
        assert!(matches!(
            err,
            StoreError::GenerationRolledBack {
                on_disk: 3,
                external: 5
            }
        ));
    }

    #[test]
    fn on_disk_ahead_advances_the_external_counter() {
        let dir = tempfile::tempdir().unwrap();
        let c = FileGenerationCounter::new(dir.path().to_path_buf());
        let rk = [1u8; 32];
        c.write(&rk, VAULT_GENERATION, 5).unwrap();
        check_and_advance(&rk, &c, 9).unwrap();
        assert_eq!(c.read(&rk, VAULT_GENERATION).unwrap(), Some(9));
    }

    #[test]
    fn equal_generation_is_fine_and_does_not_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let c = FileGenerationCounter::new(dir.path().to_path_buf());
        let rk = [1u8; 32];
        c.write(&rk, VAULT_GENERATION, 5).unwrap();
        check_and_advance(&rk, &c, 5).unwrap();
        assert_eq!(c.read(&rk, VAULT_GENERATION).unwrap(), Some(5));
    }

    #[test]
    fn state_dir_default_location_differs_from_vault_default_location() {
        // Guards against a future edit accidentally pointing the counter's
        // default at the vault directory, which would defeat the entire
        // point of ADR-024/039 (see paths::tests for the same assertion at
        // the path-resolution layer).
        assert_ne!(
            FileGenerationCounter::default_location().dir,
            crate::paths::default_vault_dir()
        );
    }
}
