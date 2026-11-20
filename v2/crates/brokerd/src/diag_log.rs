//! ADR-159: the diagnostic log — a local, size-capped, rotating file that says what the broker did and
//! how it went, written so a person can paste it into a bug report without leaking anything.
//!
//! **What a line can hold.** A UTC timestamp, the process id, an event kind, and fields whose values are
//! either a `&'static str` or a number ([`Value`]). There is no variant for a runtime string, so an entry
//! name, a node name, an alias, a value, a note, a path, a token or a request body cannot be written here
//! by mistake: the compiler refuses it. Op names reach the log only through [`op_label`], which answers
//! one of the broker's own dispatch labels ([`KNOWN_OPS`], held to `ops.rs` by a test) or `"unlisted"` —
//! the `op` field of a request is the caller's text, and a caller can put anything in it. Error codes are
//! the static wire vocabulary (`server::error_tag`), never an error's message, which can quote a name. The
//! one narrow exception is a panic's source file: [`source_file`] keeps the bare `*.rs` file name and only
//! if it is made of lowercase letters, digits and `_`, and is the only place a non-static string enters.
//!
//! **Off by default.** The broker writes nothing unless `CREDMGR_DIAG_LOG=1` is in its environment
//! ([`enabled_by_env`]). Even name-free, a line per request is a timeline of when the vault was used,
//! kept outside the encrypted vault in a folder that OS diagnostic bundles collect; the more private
//! default is to keep it off until someone is chasing a problem.
//!
//! **Where and how big.** `credmgr_store::paths::default_log_dir()` (`CREDMGR_LOG_DIR` overrides), file
//! `credmgrd.log`, at most [`MAX_FILE_BYTES`] per file and [`KEEP_FILES`] files (`credmgrd.log`,
//! `.1`, `.2`) — 3 MiB at most. The directory is `0700` and each file `0600`. Writing never fails a
//! request: an I/O error on the log is dropped. No network: this is a file in a local directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The switch. `1`, `true` or `on` turns the log on; anything else, or unset, leaves it off.
pub const ENV_SWITCH: &str = "CREDMGR_DIAG_LOG";
/// The current file's name inside the log directory; rotated copies add `.1`, `.2`.
pub const FILE_NAME: &str = "credmgrd.log";
/// The most bytes one file holds before it is rotated.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// How many files are kept, the current one included.
pub const KEEP_FILES: usize = 3;

/// One field's value. Deliberately no `String` variant (see the module doc).
#[derive(Debug, Clone, Copy)]
pub enum Value {
    Str(&'static str),
    Num(u64),
}

/// Whether the environment asks for the log.
pub fn enabled_by_env() -> bool {
    std::env::var(ENV_SWITCH)
        .map(|v| matches!(v.trim(), "1" | "true" | "on"))
        .unwrap_or(false)
}

/// The rotating writer. Public so the rotation can be tested on a small cap; the broker uses one
/// process-wide instance through [`install`] and [`event`].
pub struct Writer {
    dir: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: Option<File>,
    size: u64,
}

impl Writer {
    pub fn open(dir: &Path, max_bytes: u64, keep: usize) -> io::Result<Writer> {
        credmgr_store::atomic::ensure_dir(dir).map_err(|e| io::Error::other(e.to_string()))?;
        let mut w = Writer {
            dir: dir.to_path_buf(),
            max_bytes,
            keep: keep.max(1),
            file: None,
            size: 0,
        };
        w.reopen()?;
        Ok(w)
    }

    fn path(&self, n: usize) -> PathBuf {
        if n == 0 {
            self.dir.join(FILE_NAME)
        } else {
            self.dir.join(format!("{FILE_NAME}.{n}"))
        }
    }

    fn reopen(&mut self) -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(self.path(0))?;
        self.size = file.metadata().map(|m| m.len()).unwrap_or(0);
        self.file = Some(file);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;
        let _ = fs::remove_file(self.path(self.keep - 1));
        for n in (0..self.keep - 1).rev() {
            let from = self.path(n);
            if from.exists() {
                fs::rename(&from, self.path(n + 1))?;
            }
        }
        if self.keep == 1 {
            let _ = fs::remove_file(self.path(0));
        }
        self.reopen()
    }

    /// Append one line (a `\n` is added), rotating first when it would not fit.
    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        let len = line.len() as u64 + 1;
        if self.size > 0 && self.size + len > self.max_bytes {
            self.rotate()?;
        }
        let file = match self.file.as_mut() {
            Some(f) => f,
            None => {
                self.reopen()?;
                self.file.as_mut().expect("reopened")
            }
        };
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        self.size += len;
        Ok(())
    }
}

static LOG: OnceLock<Mutex<Writer>> = OnceLock::new();

/// Turn the process-wide log on, writing to `dir`, and record panics' locations in it. Idempotent: a
/// second call keeps the first directory. Returns `Err` only when the directory or file cannot be
/// made; the broker then runs without a log.
pub fn install(dir: &Path) -> io::Result<()> {
    if LOG.get().is_some() {
        return Ok(());
    }
    let writer = Writer::open(dir, MAX_FILE_BYTES, KEEP_FILES)?;
    if LOG.set(Mutex::new(writer)).is_ok() {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            match info.location() {
                Some(at) => panic_event(at.file(), at.line()),
                None => event("panic", &[]),
            }
            previous(info);
        }));
    }
    Ok(())
}

/// Whether [`install`] has run in this process.
pub fn is_on() -> bool {
    LOG.get().is_some()
}

/// Write one event line, if the log is on. Never fails the caller.
pub fn event(kind: &'static str, fields: &[(&'static str, Value)]) {
    let Some(lock) = LOG.get() else { return };
    let line = format_line(now_epoch(), std::process::id(), kind, fields);
    if let Ok(mut w) = lock.lock() {
        let _ = w.write_line(&line);
    }
}

fn panic_event(file: &str, line: u32) {
    let Some(lock) = LOG.get() else { return };
    let mut text = format_line(
        now_epoch(),
        std::process::id(),
        "panic",
        &[("line", Value::Num(u64::from(line)))],
    );
    text.push_str(" file=");
    text.push_str(source_file(file));
    // A panic inside a request may hold the log's lock already (it never panics while writing, but a
    // poisoned lock is still usable for one last line).
    let mut w = match lock.lock() {
        Ok(w) => w,
        Err(poisoned) => poisoned.into_inner(),
    };
    let _ = w.write_line(&text);
}

/// The bare file name of a panic location, if it looks like one of this workspace's source files
/// (`[a-z0-9_]+\.rs`); `"?"` otherwise. A full path would carry the build machine's home directory.
pub fn source_file(path: &str) -> &str {
    let base = path.rsplit(['/', '\\']).next().unwrap_or("");
    let ok = base
        .strip_suffix(".rs")
        .map(|stem| {
            !stem.is_empty()
                && stem
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
        .unwrap_or(false);
    if ok {
        base
    } else {
        "?"
    }
}

/// One request's line: the op (through [`op_label`]), `ok` or the static error code, and how long it
/// took. A token-less `vault.status` / `vault.approval_get` that succeeded is skipped — the Lock screen
/// asks every five seconds, and those lines would push everything useful out of 3 MiB within a day.
pub fn request(op: &str, result: Result<(), &'static str>, took: Duration, passive: bool) {
    if !is_on() || (passive && result.is_ok()) {
        return;
    }
    event(
        "request",
        &[
            ("op", Value::Str(op_label(op))),
            ("result", Value::Str(result.err().unwrap_or("ok"))),
            (
                "ms",
                Value::Num(took.as_millis().min(u128::from(u64::MAX)) as u64),
            ),
        ],
    );
}

/// The broker's own label for `op`, or `"unlisted"`. Never echoes the caller's text.
pub fn op_label(op: &str) -> &'static str {
    KNOWN_OPS
        .iter()
        .find(|known| **known == op)
        .copied()
        .unwrap_or("unlisted")
}

/// Every top-level arm of `ops::dispatch_op`. `tests::known_ops_match_the_dispatch_table` reads
/// `src/ops.rs` and fails when an op is added or removed without updating this list; an op missing
/// here is logged as `unlisted`, never by its name.
pub const KNOWN_OPS: &[&str] = &[
    "agent.token_issue",
    "agent.token_revoke",
    "agent.token_rotate",
    "agent.token_status",
    "audit.get",
    "audit.report",
    "audit.tail",
    "device.enrol",
    "device.remove",
    "entry.alias",
    "entry.create",
    "entry.create_batch",
    "entry.expiring",
    "entry.get",
    "entry.get_by_ref",
    "entry.history",
    "entry.import_env",
    "entry.list",
    "entry.move",
    "entry.remove",
    "entry.restore",
    "entry.reveal",
    "entry.rotate",
    "entry.search",
    "entry.set_expiry",
    "entry.similar",
    "entry.tag_set",
    "entry.undo",
    "entry.update",
    "field.add",
    "field.remove",
    "field.reorder",
    "field.update",
    "grant.create",
    "grant.list",
    "grant.revoke",
    "graph.snapshot",
    "keystore.bind",
    "keystore.status",
    "keystore.unbind",
    "maintenance.backup",
    "maintenance.doctor",
    "maintenance.rotate_root",
    "maintenance.verify",
    "merge.apply",
    "merge.auto",
    "merge.auto_all",
    "merge.dismiss",
    "merge.dismissed_list",
    "merge.restore_all",
    "merge.suggestions",
    "merge.undismiss",
    "node.create",
    "node.export",
    "node.gate_enroll_begin",
    "node.gate_enroll_confirm",
    "node.gate_remove",
    "node.gate_verify",
    "node.list",
    "node.policy",
    "node.rekey",
    "node.reparent",
    "node.restore",
    "node.seal",
    "node.set_workdirs",
    "node.update",
    "notes.read",
    "notes.write",
    "orphan.destroy",
    "orphan.list",
    "orphan.reveal",
    "presence.challenge",
    "presence.enrol",
    "presence.status",
    "presence.unenrol",
    "search",
    "search.content",
    "session.confirm",
    "settings.get",
    "settings.kb",
    "settings.list",
    "settings.request_decide",
    "settings.request_get",
    "settings.request_list",
    "settings.revert",
    "settings.set",
    "totp.code",
    "totp.seed",
    "util.generate",
    "vault.anomalies_ack",
    "vault.approval_decide",
    "vault.approval_get",
    "vault.doctor_apply",
    "vault.doctor_scan",
    "vault.gate_enroll_begin",
    "vault.gate_enroll_confirm",
    "vault.gate_recover",
    "vault.gate_verify",
    "vault.init_begin",
    "vault.init_confirm",
    "vault.lock",
    "vault.node_lock",
    "vault.node_unlock",
    "vault.pending_accept",
    "vault.pending_discard",
    "vault.pending_list",
    "vault.recover",
    "vault.set_passphrase",
    "vault.status",
    "vault.unlock",
    "whoami",
];

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `2026-11-14T09:30:05Z pid=4242 event=request op=entry.reveal result=ok ms=3`. `pub` for the tests.
pub fn format_line(
    now: i64,
    pid: u32,
    kind: &'static str,
    fields: &[(&'static str, Value)],
) -> String {
    let mut line = format!("{} pid={pid} event={kind}", utc_timestamp(now));
    for (key, value) in fields {
        match value {
            Value::Str(s) => line.push_str(&format!(" {key}={s}")),
            Value::Num(n) => line.push_str(&format!(" {key}={n}")),
        }
    }
    line
}

/// `YYYY-MM-DDTHH:MM:SSZ` from Unix seconds (Howard Hinnant's `civil_from_days`, public domain — the
/// same arithmetic as `credmgr_store::audit::year_month_for`, no date crate).
pub fn utc_timestamp(now: i64) -> String {
    let days = now.div_euclid(86_400);
    let secs = now.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_utc_and_right() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_timestamp(1_800_000_000), "2027-01-15T08:00:00Z");
        assert_eq!(utc_timestamp(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn a_line_holds_only_static_text_and_numbers() {
        let line = format_line(
            0,
            7,
            "request",
            &[("op", Value::Str("entry.reveal")), ("ms", Value::Num(12))],
        );
        assert_eq!(
            line,
            "1970-01-01T00:00:00Z pid=7 event=request op=entry.reveal ms=12"
        );
    }

    #[test]
    fn an_unknown_op_is_never_echoed() {
        assert_eq!(op_label("entry.reveal"), "entry.reveal");
        assert_eq!(op_label("my-secret-password"), "unlisted");
        assert_eq!(op_label("entry.reveal "), "unlisted");
        assert_eq!(op_label(""), "unlisted");
    }

    #[test]
    fn a_panic_location_keeps_only_a_plain_file_name() {
        assert_eq!(source_file("crates/brokerd/src/ops.rs"), "ops.rs");
        assert_eq!(
            source_file("/home/alice/.cargo/registry/src/x/serde_json-1.0/src/de.rs"),
            "de.rs"
        );
        assert_eq!(source_file("C:\\Users\\alice\\src\\lib.rs"), "lib.rs");
        assert_eq!(source_file("/home/alice/My Vault.rs"), "?");
        assert_eq!(source_file("/home/alice/notes.txt"), "?");
        assert_eq!(source_file(""), "?");
    }

    #[test]
    fn the_writer_rotates_at_the_cap_and_keeps_at_most_n_files() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        let mut w = Writer::open(&logs, 100, 3).unwrap();
        for i in 0..40 {
            w.write_line(&format!("line {i:03} ............")).unwrap();
        }
        let mut names: Vec<String> = fs::read_dir(&logs)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["credmgrd.log", "credmgrd.log.1", "credmgrd.log.2"]
        );
        for name in &names {
            let len = fs::metadata(logs.join(name)).unwrap().len();
            assert!(len <= 100, "{name} is {len} bytes, over the cap");
        }
        // The newest line is in the current file; the oldest ones are gone.
        let current = fs::read_to_string(logs.join("credmgrd.log")).unwrap();
        assert!(current.contains("line 039"));
        let all: String = names
            .iter()
            .map(|n| fs::read_to_string(logs.join(n)).unwrap())
            .collect();
        assert!(!all.contains("line 000"));
        // Reopening appends to the current file instead of truncating it.
        drop(w);
        let mut w = Writer::open(&logs, 100, 3).unwrap();
        w.write_line("after").unwrap();
        let current_after = fs::read_to_string(logs.join("credmgrd.log")).unwrap();
        assert!(current_after.contains("after"));
    }

    #[cfg(unix)]
    #[test]
    fn the_directory_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        let mut w = Writer::open(&logs, 1024, 3).unwrap();
        w.write_line("x").unwrap();
        let dmode = fs::metadata(&logs).unwrap().permissions().mode() & 0o777;
        let fmode = fs::metadata(logs.join(FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dmode, 0o700);
        assert_eq!(fmode, 0o600);
    }

    #[test]
    fn known_ops_match_the_dispatch_table() {
        let source = include_str!("ops.rs");
        let body = source
            .split("\nfn dispatch_op(")
            .nth(1)
            .expect("ops.rs still defines dispatch_op");
        let body = &body[..body
            .find("unknown op")
            .expect("dispatch_op's catch-all arm")];
        let mut arms: Vec<&str> = body
            .lines()
            .filter_map(|l| l.strip_prefix("        \""))
            .filter_map(|rest| {
                let close = rest.find('"')?;
                rest[close + 1..]
                    .trim_start()
                    .starts_with("=>")
                    .then(|| &rest[..close])
            })
            .collect();
        arms.sort_unstable();
        let mut ours = KNOWN_OPS.to_vec();
        ours.sort_unstable();
        assert!(arms.len() > 80, "parsed only {} arms", arms.len());
        assert_eq!(
            ours, arms,
            "diag_log::KNOWN_OPS must list exactly the broker's dispatch arms; an op missing here \
             is logged as `unlisted`"
        );
    }
}
