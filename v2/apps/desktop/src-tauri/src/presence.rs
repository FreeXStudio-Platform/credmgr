//! Presence for the desktop shell (ADR-098): Touch ID, through the Secure Enclave helper.
//!
//! The broker decides who counts as present; this module only *asks the chip*. When a request comes back
//! `presence_required`, [`prove`] asks the broker for a challenge, has the Mac's Secure Enclave key sign
//! it — the system shows Touch ID (or the device-password fallback) — and returns the request with the
//! proof attached. The webview never sees a nonce, a digest or a signature, and neither does it hold the
//! session token; it is told only that the user was asked and what they answered.
//!
//! **Why this is self-contained and does not depend on `credmgr-keystore`.** The shell holds no key and
//! decrypts nothing (ADR-001), and ADR-035 keeps its dependency tree away from the security crates. The
//! helper protocol is three JSON lines; `tests/drift_guards.rs` pins the file layout this reads
//! (`<state>/se/presence.key.json`) to `crates/keystore/src/presence_client.rs`.
//!
//! Off macOS every entry point reports `platform_unsupported`; the shell still builds and says why.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use crate::error::BridgeError;

/// Env override for the helper, shared with the CLI and the broker.
pub const HELPER_ENV: &str = "CREDMGR_PRESENCE_HELPER";
const HELPER_NAME: &str = "credmgr-presence";
const HELPER_TIMEOUT: Duration = Duration::from_secs(180);

fn unsupported() -> BridgeError {
    failed(
        "platform_unsupported",
        "Touch ID needs a Mac with a Secure Enclave and the credmgr-presence helper",
    )
}

/// A bridge-local error with a code from `error::BRIDGE_LOCAL_CODES`. Built directly rather than through
/// `BridgeError::bridge`, whose literal-code scan (`tests/ts_client.rs`) cannot follow a variable.
fn failed(code: &str, detail: impl Into<String>) -> BridgeError {
    BridgeError {
        source: crate::error::ErrorSource::Bridge,
        code: code.to_string(),
        message: detail.into(),
        detail: None,
    }
}

/// Where the helper is: the env override (debug builds only), else beside this executable
/// (`Contents/MacOS/` in the app, the same directory as `credmgr` in a tarball), else `../Resources`.
///
/// K-23 (a), ADR-156, the same rule as `credmgr_keystore::secure_enclave::Helper::locate` (ADR-148 P3):
/// a release build ignores `CREDMGR_PRESENCE_HELPER`, because an environment variable is not a place a
/// release takes its root of trust from, and refuses a helper whose probe does not name the production
/// variant (the unattended TEST helper signs without asking anyone).
pub fn locate_helper() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os(HELPER_ENV) {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    if !cfg!(target_os = "macos") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let found = [
        dir.join(HELPER_NAME),
        dir.join("../libexec").join(HELPER_NAME),
        dir.join("../Resources").join(HELPER_NAME),
    ]
    .into_iter()
    .find(|p| p.is_file())?;
    #[cfg(not(debug_assertions))]
    {
        let probe = run_helper(&found, json!({ "cmd": "probe" })).ok()?;
        if !is_production_variant(&probe) {
            return None;
        }
    }
    Some(found)
}

/// The variant string the production helper's probe carries (`native/macos/presence/main.swift`).
const PRODUCTION_VARIANT: &str = "credmgr-presence-variant:production";

/// Whether a probe answer names the production helper. Kept apart so a debug test can hold it.
pub fn is_production_variant(probe: &Value) -> bool {
    probe["variant"].as_str() == Some(PRODUCTION_VARIANT)
}

/// `crates/store/src/paths.rs::default_state_dir`, for the platform this feature exists on.
pub fn state_dir() -> Option<PathBuf> {
    if let Some(over) = std::env::var_os("CREDMGR_STATE_DIR") {
        return Some(PathBuf::from(over));
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")?;
        Some(
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("credmgr-state"),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// `<state>/se/presence.key.json`.
pub fn key_path(state: &Path) -> PathBuf {
    state.join("se").join("presence.key.json")
}

struct KeyFile {
    blob: Vec<u8>,
    public: Vec<u8>,
}

fn load_key(state: &Path) -> Option<KeyFile> {
    let bytes = std::fs::read(key_path(state)).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    Some(KeyFile {
        blob: B64.decode(v["blob"].as_str()?).ok()?,
        public: B64.decode(v["public"].as_str()?).ok()?,
    })
}

fn run_helper(helper: &Path, request: Value) -> Result<Value, BridgeError> {
    let mut child = Command::new(helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| failed("presence_unavailable", format!("{}: {e}", helper.display())))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let body = serde_json::to_vec(&request).expect("a JSON value serialises");
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&body);
    });
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        out
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() > HELPER_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(failed("presence_error", "the Touch ID prompt timed out"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(failed("presence_unavailable", e.to_string())),
        }
    }
    let _ = writer.join();
    let reply: Value = serde_json::from_slice(&reader.join().unwrap_or_default())
        .map_err(|_| failed("presence_error", "the Secure Enclave helper gave no answer"))?;
    if reply["ok"].as_bool() == Some(true) {
        return Ok(reply);
    }
    let detail = reply["detail"].as_str().unwrap_or("").to_string();
    Err(match reply["error"].as_str().unwrap_or("failed") {
        // The user dismissed the prompt: not an error to shout about, and a code the screens know.
        "cancelled" => failed("presence_cancelled", "the Touch ID prompt was dismissed"),
        "locked_out" => failed(
            "presence_locked_out",
            "Touch ID is locked out; unlock the Mac with its password first",
        ),
        "unavailable" => failed("presence_unavailable", detail),
        _ => failed("presence_error", detail),
    })
}

/// Whether this Mac can answer a challenge right now: the helper is here and a presence key exists.
/// When it cannot, a `presence_required` answer is handed to the screen as it is, and the screen offers
/// to set Touch ID up - the shell does not invent a prompt it cannot show.
pub fn ready() -> bool {
    locate_helper().is_some() && state_dir().and_then(|s| load_key(&s)).is_some()
}

/// What this Mac can do, for the Settings screen. Never prompts.
pub fn probe() -> Result<Value, BridgeError> {
    let helper = locate_helper().ok_or_else(unsupported)?;
    let r = run_helper(&helper, json!({ "cmd": "probe" }))?;
    let state = state_dir();
    Ok(json!({
        "secureEnclave": r["secureEnclave"], "biometry": r["biometry"], "passcode": r["passcode"],
        "keyOnThisMac": state.as_deref().and_then(load_key).is_some(),
    }))
}

/// Create this Mac's presence key if there is none (never prompts) and return its public half (base64),
/// for `presence.enrol`.
pub fn ensure_key() -> Result<String, BridgeError> {
    let helper = locate_helper().ok_or_else(unsupported)?;
    let state = state_dir().ok_or_else(unsupported)?;
    if let Some(k) = load_key(&state) {
        return Ok(B64.encode(k.public));
    }
    let r = run_helper(&helper, json!({ "cmd": "enroll", "purpose": "presence" }))?;
    let (Some(blob), Some(public)) = (r["blob"].as_str(), r["public"].as_str()) else {
        return Err(failed("presence_error", "the helper returned no key"));
    };
    let file = serde_json::to_vec_pretty(&json!({ "v": 1, "blob": blob, "public": public }))
        .expect("a key file serialises");
    let path = key_path(&state);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| failed("presence_error", e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(&path)
        .and_then(|mut f| f.write_all(&file))
        .map_err(|e| failed("presence_error", e.to_string()))?;
    Ok(public.to_string())
}

/// Forget the device-local key file (the vault's enrolment is removed with `presence.unenrol`).
pub fn forget_key() {
    if let Some(state) = state_dir() {
        let _ = std::fs::remove_file(key_path(&state));
    }
}

/// ADR-148 §P2-4: sign a possession challenge with this Mac's key and return `params` with `possession` added.
pub fn attach_possession(challenge: &Value, params: &Value) -> Result<Value, BridgeError> {
    let mut out = attach_proof(challenge, params)?;
    if let Some(map) = out.as_object_mut() {
        if let Some(proof) = map.remove("presence") {
            map.insert("possession".to_string(), proof);
        }
    }
    Ok(out)
}

/// Sign the broker's `challenge` (`presence.challenge`'s value) with this Mac's key — Touch ID appears —
/// and return `params` with `presence` added.
pub fn attach_proof(challenge: &Value, params: &Value) -> Result<Value, BridgeError> {
    let helper = locate_helper().ok_or_else(unsupported)?;
    let state = state_dir().ok_or_else(unsupported)?;
    let key = load_key(&state).ok_or_else(|| {
        failed(
            "presence_not_enrolled",
            "this Mac has no presence key yet; set up Touch ID in Settings",
        )
    })?;
    let digest = challenge["digest"]
        .as_str()
        .ok_or_else(|| failed("presence_error", "the broker's challenge had no digest"))?;
    let nonce = challenge["nonce"]
        .as_str()
        .ok_or_else(|| failed("presence_error", "the broker's challenge had no nonce"))?;
    let reason = challenge["reason"].as_str().unwrap_or("Confirm it is you");
    let r = run_helper(
        &helper,
        json!({ "cmd": "sign", "blob": B64.encode(&key.blob), "message": digest, "reason": reason }),
    )?;
    let signature = r["signature"]
        .as_str()
        .ok_or_else(|| failed("presence_error", "the helper returned no signature"))?;
    let mut out = if params.is_object() {
        params.clone()
    } else {
        json!({})
    };
    out["presence"] = json!({ "nonce": nonce, "signature": signature });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_production_variant_is_accepted_and_the_test_helper_is_not() {
        assert!(is_production_variant(
            &json!({ "variant": "credmgr-presence-variant:production" })
        ));
        for other in [
            json!({ "variant": "credmgr-presence-variant:unattended-test" }),
            json!({}),
            json!({ "variant": 1 }),
        ] {
            assert!(!is_production_variant(&other), "{other}");
        }
    }

    #[test]
    fn the_release_build_reads_no_helper_override_from_the_environment() {
        // The source is the contract here: the env read sits behind `debug_assertions`.
        let src = include_str!("presence.rs");
        let at = src
            .find("std::env::var_os(HELPER_ENV)")
            .expect("the override is read once");
        let before = &src[..at];
        let gate = before.rfind("#[cfg(debug_assertions)]").expect("gated");
        assert!(
            at - gate < 120,
            "the env read must be the first thing under the debug gate"
        );
    }
}
