//! ADR-159: the desktop shell's half of the diagnostic log — `desktop.log` beside the broker's
//! `credmgrd.log`, in the directory [`crate::vault_paths::resolve_log_dir`] mirrors from
//! `crates/store`. Same rules as the broker's (`crates/brokerd/src/diag_log.rs`): off unless
//! `CREDMGR_DIAG_LOG=1`, 3 files of at most 1 MiB, `0600` files in a `0700` directory, and a line holds
//! only static labels and numbers — there is no way to pass a runtime string to [`event`]. A broker
//! call is logged by its op's label from the bridge's own table ([`op_label`]) and its error code from
//! the broker's static vocabulary ([`code_label`]), never by params, values or messages. Local only.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{BridgeError, ErrorSource, BROKER_ERROR_CODES};

pub const ENV_SWITCH: &str = "CREDMGR_DIAG_LOG";
pub const FILE_NAME: &str = "desktop.log";
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const KEEP_FILES: usize = 3;

/// One field's value; deliberately no `String` variant.
#[derive(Debug, Clone, Copy)]
pub enum Value {
    Str(&'static str),
    Num(u64),
}

pub fn enabled_by_env() -> bool {
    std::env::var(ENV_SWITCH)
        .map(|v| matches!(v.trim(), "1" | "true" | "on"))
        .unwrap_or(false)
}

/// The size-capped, rotating file.
pub struct Writer {
    dir: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: Option<File>,
    size: u64,
}

impl Writer {
    pub fn open(dir: &Path, max_bytes: u64, keep: usize) -> io::Result<Writer> {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
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

    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        let len = line.len() as u64 + 1;
        if self.size > 0 && self.size + len > self.max_bytes {
            self.rotate()?;
        }
        if self.file.is_none() {
            self.reopen()?;
        }
        let file = self.file.as_mut().expect("opened above");
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        self.size += len;
        Ok(())
    }
}

static LOG: OnceLock<Mutex<Writer>> = OnceLock::new();

/// Turn the log on in this process when the switch is set and a directory resolves. Called once from
/// [`crate::run`]; a failure leaves the app running without a log.
pub fn install_from_env() {
    if !enabled_by_env() {
        return;
    }
    if let Some(dir) = crate::vault_paths::resolve_log_dir() {
        let _ = install(&dir);
    }
}

pub fn install(dir: &Path) -> io::Result<()> {
    if LOG.get().is_some() {
        return Ok(());
    }
    let writer = Writer::open(dir, MAX_FILE_BYTES, KEEP_FILES)?;
    let _ = LOG.set(Mutex::new(writer));
    event(
        "start",
        &[
            ("version", Value::Str(env!("CARGO_PKG_VERSION"))),
            ("os", Value::Str(std::env::consts::OS)),
            ("arch", Value::Str(std::env::consts::ARCH)),
        ],
    );
    Ok(())
}

pub fn event(kind: &'static str, fields: &[(&'static str, Value)]) {
    let Some(lock) = LOG.get() else { return };
    let line = format_line(now_epoch(), std::process::id(), kind, fields);
    if let Ok(mut w) = lock.lock() {
        let _ = w.write_line(&line);
    }
}

/// One broker call from the shell: the op's bridge label, `ok` or a static code, and the time.
pub fn call(op: &str, result: Result<(), &BridgeError>, took: Duration) {
    if LOG.get().is_none() {
        return;
    }
    event(
        "call",
        &[
            ("op", Value::Str(op_label(op))),
            (
                "result",
                Value::Str(result.err().map(code_label).unwrap_or("ok")),
            ),
            (
                "ms",
                Value::Num(took.as_millis().min(u128::from(u64::MAX)) as u64),
            ),
        ],
    );
}

/// The bridge table's own spelling of `op`, or `"unlisted"`.
pub fn op_label(op: &str) -> &'static str {
    crate::commands::bridged()
        .find(|b| b.op == op)
        .map(|b| b.op)
        .unwrap_or("unlisted")
}

/// A static label for a failure: the broker's code from [`BROKER_ERROR_CODES`], or the error's source.
pub fn code_label(err: &BridgeError) -> &'static str {
    match err.source {
        ErrorSource::Broker => BROKER_ERROR_CODES
            .iter()
            .find(|c| **c == err.code)
            .copied()
            .unwrap_or("broker_other"),
        ErrorSource::Transport => "broker_unreachable",
        ErrorSource::Protocol => "protocol",
        ErrorSource::Bridge => "bridge",
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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

/// `YYYY-MM-DDTHH:MM:SSZ` (Howard Hinnant's `civil_from_days`, public domain).
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
    fn labels_never_echo_the_callers_text() {
        assert_eq!(op_label("entry.reveal"), "entry.reveal");
        assert_eq!(op_label("SECRET_NAME"), "unlisted");
        let broker = BridgeError {
            source: ErrorSource::Broker,
            code: "entry_exists".into(),
            message: "an entry named SECRET_NAME already exists".into(),
            detail: None,
        };
        assert_eq!(code_label(&broker), "entry_exists");
        let odd = BridgeError {
            source: ErrorSource::Broker,
            code: "SECRET_VALUE".into(),
            message: String::new(),
            detail: None,
        };
        assert_eq!(code_label(&odd), "broker_other");
        assert_eq!(
            code_label(&BridgeError::transport("no socket at /home/alice/vault")),
            "broker_unreachable"
        );
    }

    #[test]
    fn timestamps_and_lines() {
        assert_eq!(utc_timestamp(1_800_000_000), "2027-01-15T08:00:00Z");
        assert_eq!(
            format_line(
                0,
                9,
                "call",
                &[("op", Value::Str("entry.list")), ("ms", Value::Num(4))]
            ),
            "1970-01-01T00:00:00Z pid=9 event=call op=entry.list ms=4"
        );
    }

    #[test]
    fn the_writer_rotates_and_keeps_three_files_under_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        let mut w = Writer::open(&logs, 80, 3).unwrap();
        for i in 0..30 {
            w.write_line(&format!("line {i:03} ..........")).unwrap();
        }
        let mut names: Vec<String> = fs::read_dir(&logs)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["desktop.log", "desktop.log.1", "desktop.log.2"]);
        for n in &names {
            assert!(fs::metadata(logs.join(n)).unwrap().len() <= 80);
        }
    }
}
