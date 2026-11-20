//! The restore-scoped "accept a missing rollback counter" marker — ADR-148 amendment (K-23 (e)).
//!
//! The external generation counter (`generation.rs`, ADR-063/ADR-039) lives outside the vault directory so that
//! restoring an old copy of the vault does not restore it, and a **missing** counter is refused (review H1(a)):
//! deleting it must not let an older, validly signed registry load as current. A restore onto a new Mac (or into
//! a fresh state directory) has, by construction, no counter. Archives used to carry the counter for that reason,
//! which made every archive a matched old pair. This module replaces that with a narrower, one-shot acceptance:
//!
//! 1. **The ticket.** `maintenance.backup` (which holds the root key) puts `_state/restore.ticket` in the archive
//!    instead of the counter: `{v, registrySha256, generation, issuedAt, hmac}`, the hmac under the root key over
//!    the exact `registry.json` bytes the archive carries and that registry's `vaultGeneration`. It is not a
//!    counter and cannot be used as one.
//! 2. **The marker.** `credmgr restore` (which has no root key) writes the ticket, with the folder it restored into
//!    and the time, as `restore-accept.marker` in the state directory, and only when that directory has no counter
//!    (an existing counter is kept and decides, as before).
//! 3. **The first unlock.** With no counter, the broker accepts the registry only if the marker's ticket verifies
//!    under this vault's root key and names the exact `registry.json` bytes on disk and their generation; it then
//!    writes the counter at that generation and deletes the marker. Anything else (no marker, a marker for another
//!    vault or another registry, a tampered one) is refused as before. The folder the marker names is a record for
//!    a person, not a check: it is not signed (the restore has no root key), and a restored vault may be moved
//!    into place before its first unlock.
//!
//! Pure functions over bytes and paths; the callers do the I/O.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hexutil;

/// The ticket's name under the archive's `_state/` prefix.
pub const TICKET_STATE_FILE: &str = "restore.ticket";
/// The marker's name in the state directory, beside `vaultGeneration.counter`.
pub const MARKER_FILE: &str = "restore-accept.marker";
const TICKET_VERSION: u32 = 1;
const MARKER_VERSION: u32 = 1;
const MARKER_KIND: &str = "credmgr-restore-accept";
const TICKET_LABEL: &str = "restore-ticket/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ticket {
    pub v: u32,
    /// SHA-256 of the archived `registry.json`, lower-case hex.
    pub registry_sha256: String,
    /// That registry's `vaultGeneration`.
    pub generation: u64,
    /// When the backup was cut (unix seconds).
    pub issued_at: i64,
    /// HMAC-SHA256 under the root key over the three fields above, hex.
    pub hmac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Marker {
    pub v: u32,
    pub kind: String,
    /// The vault folder the restore wrote, canonical when it could be resolved. A record, not a check.
    pub target: String,
    /// When the restore ran (unix seconds).
    pub restored_at: i64,
    pub ticket: Ticket,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hexutil::encode(&Sha256::digest(bytes))
}

fn signed_data(registry_sha256: &str, generation: u64, issued_at: i64) -> Vec<u8> {
    format!("{registry_sha256}\n{generation}\n{issued_at}").into_bytes()
}

/// The `vaultGeneration` a `registry.json` carries, read without verifying it (the ticket's hmac and the
/// broker's own registry check do that).
pub fn registry_generation(registry_json: &[u8]) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(registry_json)
        .ok()?
        .get("vaultGeneration")?
        .as_u64()
}

/// The ticket `maintenance.backup` puts in an archive for these `registry.json` bytes.
pub fn ticket_bytes(root_key: &[u8; 32], registry_json: &[u8], issued_at: i64) -> Option<Vec<u8>> {
    let generation = registry_generation(registry_json)?;
    let registry_sha256 = sha256_hex(registry_json);
    let tag = credmgr_core::signing::sign(
        root_key,
        TICKET_LABEL,
        &signed_data(&registry_sha256, generation, issued_at),
    );
    let ticket = Ticket {
        v: TICKET_VERSION,
        registry_sha256,
        generation,
        issued_at,
        hmac: hexutil::encode(&tag),
    };
    serde_json::to_vec(&ticket).ok()
}

/// Parse a ticket's bytes (from an archive). Structure only; the hmac is checked at the first unlock.
pub fn parse_ticket(bytes: &[u8]) -> Option<Ticket> {
    let t: Ticket = serde_json::from_slice(bytes).ok()?;
    (t.v == TICKET_VERSION
        && t.registry_sha256.len() == 64
        && hexutil::decode_32(&t.hmac).is_some())
    .then_some(t)
}

/// The folder as the marker names it: canonical when it resolves, else as given.
pub fn folder_name(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

/// The marker `credmgr restore` writes for a restore into `target`.
pub fn marker_bytes(ticket: Ticket, target: &Path, restored_at: i64) -> Option<Vec<u8>> {
    let marker = Marker {
        v: MARKER_VERSION,
        kind: MARKER_KIND.to_string(),
        target: folder_name(target),
        restored_at,
        ticket,
    };
    serde_json::to_vec(&marker).ok()
}

pub fn marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MARKER_FILE)
}

/// Why a marker was not accepted. Each is a refusal; none says anything secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerRefusal {
    Unreadable,
    BadTag,
    OtherRegistry,
    OtherGeneration,
}

impl MarkerRefusal {
    pub fn reason(&self) -> &'static str {
        match self {
            MarkerRefusal::Unreadable => "the restore marker does not parse",
            MarkerRefusal::BadTag => "the restore marker was not made by this vault's key",
            MarkerRefusal::OtherRegistry => {
                "the restore marker names another registry than the one on disk"
            }
            MarkerRefusal::OtherGeneration => {
                "the restore marker names another generation than the registry on disk"
            }
        }
    }
}

/// The first unlock's check: the marker's ticket was made under this root key, and it names exactly the
/// `registry.json` bytes on disk and the generation the (verified) registry carries. Returns the generation to
/// write the counter at.
pub fn check_marker(
    root_key: &[u8; 32],
    marker: &[u8],
    registry_json: &[u8],
    registry_generation: u64,
) -> Result<u64, MarkerRefusal> {
    let m: Marker = serde_json::from_slice(marker).map_err(|_| MarkerRefusal::Unreadable)?;
    if m.v != MARKER_VERSION || m.kind != MARKER_KIND || m.ticket.v != TICKET_VERSION {
        return Err(MarkerRefusal::Unreadable);
    }
    let tag = hexutil::decode_32(&m.ticket.hmac).ok_or(MarkerRefusal::Unreadable)?;
    let data = signed_data(
        &m.ticket.registry_sha256,
        m.ticket.generation,
        m.ticket.issued_at,
    );
    if !credmgr_core::signing::verify(root_key, TICKET_LABEL, &data, &tag) {
        return Err(MarkerRefusal::BadTag);
    }
    if m.ticket.registry_sha256 != sha256_hex(registry_json) {
        return Err(MarkerRefusal::OtherRegistry);
    }
    if m.ticket.generation != registry_generation {
        return Err(MarkerRefusal::OtherGeneration);
    }
    Ok(m.ticket.generation)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RK: [u8; 32] = [9u8; 32];

    fn registry(generation: u64) -> Vec<u8> {
        format!(r#"{{"format":2,"vaultGeneration":{generation},"nodes":{{}}}}"#).into_bytes()
    }

    #[test]
    fn a_marker_from_a_ticket_is_accepted_for_its_key_registry_and_generation_only() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(7);
        let ticket = parse_ticket(&ticket_bytes(&RK, &reg, 100).unwrap()).unwrap();
        assert_eq!(ticket.generation, 7);
        let marker = marker_bytes(ticket, dir.path(), 200).unwrap();
        assert_eq!(check_marker(&RK, &marker, &reg, 7), Ok(7));
        // Another root key (another vault), another registry, another generation.
        assert_eq!(
            check_marker(&[1u8; 32], &marker, &reg, 7),
            Err(MarkerRefusal::BadTag)
        );
        assert_eq!(
            check_marker(&RK, &marker, &registry(8), 8),
            Err(MarkerRefusal::OtherRegistry)
        );
        assert_eq!(
            check_marker(&RK, &marker, &reg, 6),
            Err(MarkerRefusal::OtherGeneration)
        );
        assert_eq!(
            check_marker(&RK, b"{}", &reg, 7),
            Err(MarkerRefusal::Unreadable)
        );
    }

    #[test]
    fn a_forged_ticket_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(3);
        let mut ticket = parse_ticket(&ticket_bytes(&RK, &reg, 1).unwrap()).unwrap();
        // Re-point a valid ticket at another generation: the tag no longer covers it.
        ticket.generation = 2;
        let marker = marker_bytes(ticket, dir.path(), 2).unwrap();
        assert_eq!(
            check_marker(&RK, &marker, &reg, 2),
            Err(MarkerRefusal::BadTag)
        );
        assert!(parse_ticket(b"not json").is_none());
        assert!(
            ticket_bytes(&RK, b"{}", 1).is_none(),
            "no generation, no ticket"
        );
    }
}
