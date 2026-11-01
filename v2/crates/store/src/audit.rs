//! `audit/YYYY-MM.log` — append-only, `0600`, one JSON object per line,
//! hash-chained. See `docs/03_DATA_MODEL.md §9`.
//!
//! **Never recorded:** any value, any field label, any note content. A
//! record names the entry and the decision, never the secret — callers of
//! [`append`] are trusted not to pass a secret into `detail`; this module
//! has no way to check that mechanically, so it isn't the enforcement
//! point, just the thing whose contract that trust exists for.
//!
//! Each line's `prev` is the sha256 of the previous line's raw bytes — a
//! removed or edited line changes the hash the *next* line's `prev` must
//! equal, so an edit anywhere but the final line is caught by
//! [`verify`]'s chain walk alone. Catching truncation (or editing) of the
//! *last* line needs something outside the file to anchor against: an
//! HMAC'd `<year-month>.tip` sidecar recording the expected line count and
//! final hash, updated on every [`append`] — the same "unencrypted must not
//! mean unprotected" pattern as the registry/manifest pair (`04 §6a`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atomic;
use crate::error::{Result, StoreError};
use crate::hexutil;
use crate::paths::VaultPaths;

/// `prev` for the first record in a chain — 64 hex chars, the same length
/// as a real sha256 digest, but deliberately not the hash of anything.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const _: () = assert!(
    GENESIS_PREV.len() == 64,
    "GENESIS_PREV must be 64 hex chars, matching a real sha256 digest's encoded length"
);

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hexutil::encode(&hasher.finalize())
}

/// `now` (Unix epoch seconds) → the `"YYYY-MM"` this record belongs in, in
/// UTC — the `year_month` [`crate::paths::VaultPaths::audit_log`] needs to
/// pick which monthly log a caller appends to. Pure integer arithmetic
/// (Howard Hinnant's `civil_from_days`, public domain —
/// <http://howardhinnant.github.io/date_algorithms.html>) rather than a
/// `chrono`/`time` dependency: this workspace's dependency set is pinned
/// deliberately narrow (see `crates/core/Cargo.toml`'s own comments on the
/// edition2024/MSRV wall), and one caller needing "which month is this"
/// doesn't justify pulling one in.
pub fn year_month_for(now: i64) -> String {
    let days = now.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    /// `a_<12 hex chars>` — derived from `(year_month, position, prev)`
    /// rather than drawn from an RNG, so this crate does not need to depend
    /// on one just for this (the same "one caller doesn't justify a new
    /// dependency" reasoning `year_month_for`'s own doc comment gives for
    /// `chrono`). Unique in practice because `prev` already chains in every
    /// byte of everything appended before it.
    pub id: String,
    /// Unix epoch seconds — ADR-040.
    pub timestamp: i64,
    pub actor: String,
    pub action: String,
    pub node_id: Option<String>,
    /// ADR-055 — from `params.entry`, the same generic extraction
    /// `record_decision` already does for `node_id`/`params.node`.
    /// `#[serde(default)]` so a record written before this field existed
    /// (none ship in any vault, but the format must not assume that)
    /// deserialises as `None` rather than failing to parse.
    #[serde(default)]
    pub entry_id: Option<String>,
    pub decision: Option<String>,
    pub detail: Option<String>,
    /// ADR-055 — the op's own new manifest generation, copied from its
    /// success response (`result["generation"]`) when present. Purely
    /// additive: an op whose response has no `generation` leaves this
    /// `None`. `entry.undo` uses it to resolve which pre-rotate snapshot
    /// (`rotation_history`) an `entry.rotate` record's undo reads from.
    #[serde(default)]
    pub generation: Option<u64>,
    pub prev: String,
}

/// The fields a caller supplies; [`append`] fills in `timestamp` and `prev`.
#[derive(Debug, Clone, Default)]
pub struct NewEvent {
    pub actor: String,
    pub action: String,
    pub node_id: Option<String>,
    pub entry_id: Option<String>,
    pub decision: Option<String>,
    pub detail: Option<String>,
    pub generation: Option<u64>,
}

fn tip_path(log_path: &Path) -> PathBuf {
    log_path.with_extension("tip")
}

fn tip_label(year_month: &str) -> String {
    format!("audit-tip/{year_month}")
}

#[derive(Debug, Serialize, Deserialize)]
struct TipDoc {
    line_count: u64,
    last_hash: String,
    hmac: String,
}

fn json_err(path: &Path, source: serde_json::Error) -> StoreError {
    StoreError::Json {
        path: path.to_path_buf(),
        source,
    }
}

fn read_lines(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = atomic::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(text.lines().map(|l| l.to_string()).collect())
}

/// Append one record to `audit/<year_month>.log`, chaining it to the
/// current last line, then update and re-sign the `.tip` sidecar.
pub fn append(
    paths: &VaultPaths,
    root_key: &[u8; 32],
    year_month: &str,
    event: NewEvent,
    now: i64,
) -> Result<AuditRecord> {
    let path = paths.audit_log(year_month);
    let mut lines = read_lines(&path)?;

    let prev = match lines.last() {
        Some(last) => sha256_hex(last.as_bytes()),
        None => GENESIS_PREV.to_string(),
    };
    let id = format!(
        "a_{}",
        &sha256_hex(format!("{year_month}|{}|{prev}", lines.len()).as_bytes())[..12]
    );

    let record = AuditRecord {
        id,
        timestamp: now,
        actor: event.actor,
        action: event.action,
        node_id: event.node_id,
        entry_id: event.entry_id,
        decision: event.decision,
        detail: event.detail,
        generation: event.generation,
        prev,
    };
    let line = serde_json::to_string(&record).map_err(|e| json_err(&path, e))?;
    let line_hash = sha256_hex(line.as_bytes());
    lines.push(line);

    let mut contents = lines.join("\n");
    contents.push('\n');
    atomic::write(&path, contents.as_bytes())?;

    let tip = signed_tip(root_key, year_month, lines.len() as u64, line_hash);
    let tip_bytes = serde_json::to_vec(&tip).map_err(|e| json_err(&tip_path(&path), e))?;
    atomic::write(&tip_path(&path), &tip_bytes)?;

    Ok(record)
}

/// A tip sidecar for `line_count`/`last_hash`, signed under `root_key`.
fn signed_tip(root_key: &[u8; 32], year_month: &str, line_count: u64, last_hash: String) -> TipDoc {
    let signed_bytes = format!("{line_count}|{last_hash}");
    let tag =
        credmgr_core::signing::sign(root_key, &tip_label(year_month), signed_bytes.as_bytes());
    TipDoc {
        line_count,
        last_hash,
        hmac: hexutil::encode(&tag),
    }
}

/// Where `year_month`'s tip sidecar lives (ADR-076: root-key rotation stages
/// a re-signed copy at exactly this path).
pub fn tip_file(paths: &VaultPaths, year_month: &str) -> PathBuf {
    tip_path(&paths.audit_log(year_month))
}

/// Every month that has an audit log, oldest first.
pub fn year_months(paths: &VaultPaths) -> Result<Vec<String>> {
    let mut months = year_months_descending(paths)?;
    months.reverse();
    Ok(months)
}

/// The tip sidecar for `year_month` re-signed under `new_root`, **only if the
/// whole month verifies under `old_root` first** — the hash chain, the tip's
/// HMAC, and the tip's agreement with the log. Re-signing a log that already
/// fails verification would stamp a truncation or an edit as authentic, so a
/// month that does not verify is an `Err` and is left exactly as it is, so
/// *the rotation* does not hide the damage. (It keeps failing verification only
/// while nothing is appended to it: [`append`] signs a month's tip over
/// whatever lines the log holds and never verifies first, so the next record
/// written to that month — the rotation's own, if it lands there — makes it
/// verify again. That is `append`'s behaviour for every request, not a
/// rotation's.) Returns the bytes to write; touches nothing (ADR-076).
pub fn resigned_tip(
    paths: &VaultPaths,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    year_month: &str,
) -> Result<Vec<u8>> {
    verify(paths, old_root, year_month)?;
    let path = paths.audit_log(year_month);
    let tip_file = tip_path(&path);
    // `verify` returns Ok for a log with no lines without reading the tip;
    // there is nothing to re-sign then, and reading it below says so.
    let tip: TipDoc =
        serde_json::from_slice(&atomic::read(&tip_file)?).map_err(|e| json_err(&tip_file, e))?;
    let resigned = signed_tip(new_root, year_month, tip.line_count, tip.last_hash);
    serde_json::to_vec(&resigned).map_err(|e| json_err(&tip_file, e))
}

/// Walk the chain from the first line to the last, verifying every `prev`
/// link, then check the result against the signed `.tip` sidecar to catch
/// truncation (or a tampered-and-not-re-signed final line) that an
/// internally-consistent-but-short chain wouldn't otherwise reveal.
pub fn verify(paths: &VaultPaths, root_key: &[u8; 32], year_month: &str) -> Result<()> {
    let path = paths.audit_log(year_month);
    let lines = read_lines(&path)?;
    if lines.is_empty() {
        return Ok(());
    }

    let mut expected_prev = GENESIS_PREV.to_string();
    let mut last_hash = String::new();
    for (i, line) in lines.iter().enumerate() {
        let record: AuditRecord = serde_json::from_str(line).map_err(|e| json_err(&path, e))?;
        if record.prev != expected_prev {
            return Err(StoreError::AuditChainBroken {
                path: path.clone(),
                at_line: i,
            });
        }
        last_hash = sha256_hex(line.as_bytes());
        expected_prev.clone_from(&last_hash);
    }

    let tip_bytes = atomic::read(&tip_path(&path))?;
    let tip: TipDoc =
        serde_json::from_slice(&tip_bytes).map_err(|e| json_err(&tip_path(&path), e))?;
    let tag = hexutil::decode_32(&tip.hmac).ok_or_else(|| StoreError::AuditChainBroken {
        path: tip_path(&path),
        at_line: lines.len(),
    })?;
    let signed_bytes = format!("{}|{}", tip.line_count, tip.last_hash);
    if !credmgr_core::signing::verify(
        root_key,
        &tip_label(year_month),
        signed_bytes.as_bytes(),
        &tag,
    ) {
        return Err(StoreError::AuditChainBroken {
            path: tip_path(&path),
            at_line: lines.len(),
        });
    }

    if tip.line_count != lines.len() as u64 || tip.last_hash != last_hash {
        return Err(StoreError::AuditChainBroken {
            path,
            at_line: lines.len(),
        });
    }

    Ok(())
}

/// `audit/*.log`'s year-month filenames sorted descending — lexicographic
/// order on `YYYY-MM` is chronological order, so this is "most recent month
/// first" with no date parsing needed.
fn year_months_descending(paths: &VaultPaths) -> Result<Vec<String>> {
    let dir = paths.audit_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut months: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| StoreError::Io {
            path: dir.clone(),
            source: e,
        })?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".log"))
                .map(|s| s.to_string())
        })
        .collect();
    months.sort();
    months.reverse();
    Ok(months)
}

/// The last `limit` records across every monthly log, newest first —
/// walks months backwards so a caller near a month boundary still sees
/// contiguous history instead of an empty tail. Plaintext, like
/// `registry.json`: no `root_key` needed, so this reads correctly while the
/// vault is locked (`10_API_AND_MCP.md`'s "List / read metadata" row).
pub fn tail(paths: &VaultPaths, limit: usize) -> Result<Vec<AuditRecord>> {
    let mut out = Vec::new();
    for year_month in year_months_descending(paths)? {
        let path = paths.audit_log(&year_month);
        for line in read_lines(&path)?.iter().rev() {
            let record: AuditRecord = serde_json::from_str(line).map_err(|e| json_err(&path, e))?;
            out.push(record);
            if out.len() >= limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

/// A single record by id, or `None` if no monthly log holds it. Linear scan
/// — there is no index, and a vault's own audit history is not large enough
/// to need one (`13_TEST_PLAN.md` scales this build against one owner's
/// vault, not a multi-tenant log store).
pub fn get(paths: &VaultPaths, id: &str) -> Result<Option<AuditRecord>> {
    for year_month in year_months_descending(paths)? {
        let path = paths.audit_log(&year_month);
        for line in read_lines(&path)? {
            let record: AuditRecord =
                serde_json::from_str(&line).map_err(|e| json_err(&path, e))?;
            if record.id == id {
                return Ok(Some(record));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(action: &str) -> NewEvent {
        NewEvent {
            actor: "cli".to_string(),
            action: action.to_string(),
            node_id: Some("a".to_string()),
            entry_id: None,
            decision: Some("allow".to_string()),
            detail: None,
            generation: None,
        }
    }

    #[test]
    fn chain_of_several_records_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [5u8; 32];
        for i in 0..5 {
            append(
                &paths,
                &rk,
                "2026-08",
                ev("entry.reveal"),
                1_700_000_000 + i,
            )
            .unwrap();
        }
        verify(&paths, &rk, "2026-08").unwrap();
    }

    #[test]
    fn empty_log_verifies_trivially() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        verify(&paths, &[5u8; 32], "2026-08").unwrap();
    }

    #[test]
    fn editing_a_middle_line_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [5u8; 32];
        for i in 0..4 {
            append(
                &paths,
                &rk,
                "2026-08",
                ev("entry.reveal"),
                1_700_000_000 + i,
            )
            .unwrap();
        }
        let path = paths.audit_log("2026-08");
        let mut lines = read_lines(&path).unwrap();
        let mut rec: AuditRecord = serde_json::from_str(&lines[1]).unwrap();
        rec.decision = Some("deny".to_string()); // tamper, prev unchanged
        lines[1] = serde_json::to_string(&rec).unwrap();
        let mut contents = lines.join("\n");
        contents.push('\n');
        atomic::write(&path, contents.as_bytes()).unwrap();

        let err = verify(&paths, &rk, "2026-08").unwrap_err();
        assert!(matches!(
            err,
            StoreError::AuditChainBroken { at_line: 2, .. }
        ));
    }

    #[test]
    fn truncating_the_tail_is_caught_by_the_tip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [5u8; 32];
        for i in 0..4 {
            append(
                &paths,
                &rk,
                "2026-08",
                ev("entry.reveal"),
                1_700_000_000 + i,
            )
            .unwrap();
        }
        let path = paths.audit_log("2026-08");
        let lines = read_lines(&path).unwrap();
        let truncated = lines[..2].join("\n") + "\n"; // drop the last two lines
        atomic::write(&path, truncated.as_bytes()).unwrap();

        // Internally consistent as a 2-line chain — only the tip catches this.
        let err = verify(&paths, &rk, "2026-08").unwrap_err();
        assert!(matches!(err, StoreError::AuditChainBroken { .. }));
    }

    #[test]
    fn tampered_tip_hmac_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [5u8; 32];
        append(&paths, &rk, "2026-08", ev("unlock"), 1_700_000_000).unwrap();

        let tip = tip_path(&paths.audit_log("2026-08"));
        let mut doc: TipDoc = serde_json::from_slice(&atomic::read(&tip).unwrap()).unwrap();
        doc.line_count = 99;
        atomic::write(&tip, &serde_json::to_vec(&doc).unwrap()).unwrap();

        let err = verify(&paths, &rk, "2026-08").unwrap_err();
        assert!(matches!(err, StoreError::AuditChainBroken { .. }));
    }

    #[test]
    fn year_month_for_matches_known_utc_dates() {
        // Ground truth from `date -u -r <epoch> +%Y-%m-%d`, not memory.
        for (epoch, expected) in [
            (0, "1970-01"),
            (946_684_800, "2000-01"),   // 2000-01-01
            (1_609_459_200, "2021-01"), // 2021-01-01
            (1_800_000_000, "2027-01"), // 2027-01-15
            (1_735_689_600, "2025-01"), // 2025-01-01
            (1_743_465_600, "2025-04"), // 2025-04-01
        ] {
            assert_eq!(year_month_for(epoch), expected, "epoch {epoch}");
        }
    }

    #[test]
    fn never_records_a_value_field_by_construction() {
        // `AuditRecord` has no field capable of holding a secret value —
        // `detail` is free text but this test documents the contract at
        // the type level: there is no `value`/`secret`/`fieldLabel` field
        // to accidentally populate.
        let rec = AuditRecord {
            id: "a_000000000000".into(),
            timestamp: 0,
            actor: "x".into(),
            action: "y".into(),
            node_id: None,
            entry_id: None,
            decision: None,
            detail: None,
            generation: None,
            prev: GENESIS_PREV.to_string(),
        };
        let v = serde_json::to_value(rec).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        assert_eq!(
            keys.iter().collect::<std::collections::HashSet<_>>(),
            [
                "id",
                "timestamp",
                "actor",
                "action",
                "nodeId",
                "entryId",
                "decision",
                "detail",
                "generation",
                "prev"
            ]
            .iter()
            .collect()
        );
    }

    #[test]
    fn appended_records_get_unique_non_empty_ids() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [5u8; 32];
        let mut ids = std::collections::HashSet::new();
        for i in 0..5 {
            let rec = append(
                &paths,
                &rk,
                "2026-08",
                ev("entry.reveal"),
                1_700_000_000 + i,
            )
            .unwrap();
            assert!(rec.id.starts_with("a_"));
            assert!(ids.insert(rec.id), "ids must be unique");
        }
    }

    #[test]
    fn tail_returns_newest_first_and_respects_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [5u8; 32];
        let mut appended = Vec::new();
        for i in 0..5 {
            appended.push(
                append(
                    &paths,
                    &rk,
                    "2026-08",
                    ev("entry.reveal"),
                    1_700_000_000 + i,
                )
                .unwrap(),
            );
        }
        let last_three = tail(&paths, 3).unwrap();
        assert_eq!(last_three.len(), 3);
        assert_eq!(
            last_three.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
            vec![
                appended[4].id.clone(),
                appended[3].id.clone(),
                appended[2].id.clone(),
            ],
            "newest first"
        );
    }

    #[test]
    fn tail_walks_backwards_across_a_month_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [5u8; 32];
        let july = append(&paths, &rk, "2026-07", ev("vault.unlock"), 1_700_000_000).unwrap();
        let august = append(&paths, &rk, "2026-08", ev("entry.reveal"), 1_700_100_000).unwrap();
        let both = tail(&paths, 10).unwrap();
        assert_eq!(
            both.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
            vec![august.id, july.id],
            "August (later month) must come before July even though each log has only one line"
        );
    }

    #[test]
    fn tail_on_an_empty_vault_is_an_empty_list_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        assert_eq!(tail(&paths, 10).unwrap(), Vec::new());
    }

    #[test]
    fn get_finds_a_record_by_id_and_none_for_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        let rk = [5u8; 32];
        let rec = append(&paths, &rk, "2026-08", ev("entry.reveal"), 1_700_000_000).unwrap();
        let found = get(&paths, &rec.id).unwrap().expect("must find it");
        assert_eq!(found, rec);
        assert!(get(&paths, "a_does_not_exist").unwrap().is_none());
    }
}
