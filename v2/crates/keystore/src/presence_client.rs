//! The client half of presence (ADR-098): what the CLI and the desktop shell do to turn "this op needs a
//! presence proof" into a request that carries one.
//!
//! The Secure Enclave presence key lives on this Mac only. Its opaque blob is kept in the state directory
//! (`<state>/se/presence.key.json`, mode 0600) — outside the vault, never backed up — and its public half
//! is enrolled in the vault (`presence.enrol`). Using the key is what prompts Touch ID: this module never
//! decides whether the user is present, the chip does.
//!
//! The flow for one gated request is [`prove`]: `presence.challenge` (the broker names the nonce and the
//! digest), the Secure Enclave signs the digest, and the caller sends the original op again with
//! `params.presence = {nonce, signature}` added.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use crate::error::{KeystoreError, Result};
use crate::secure_enclave::{Enrolled, Helper, PresenceKeyFile, Purpose};

/// `<state>/se/presence.key.json`.
pub fn key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("se").join("presence.key.json")
}

/// The device-local presence key, if one was created on this Mac.
pub fn load_key(state_dir: &Path) -> Result<Option<PresenceKeyFile>> {
    let path = key_path(state_dir);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|source| KeystoreError::Json { path, source }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(KeystoreError::Io { path, source }),
    }
}

/// Create this Mac's presence key in the Secure Enclave and remember its blob. Never prompts. Replaces
/// nothing: an existing key file is returned unchanged (re-enrolling a *new* key means deleting the old
/// one deliberately).
pub fn create_key(helper: &Helper, state_dir: &Path) -> Result<PresenceKeyFile> {
    if let Some(existing) = load_key(state_dir)? {
        return Ok(existing);
    }
    let enrolled: Enrolled = helper.enroll(Purpose::Presence)?;
    let file = PresenceKeyFile::new(&enrolled);
    let path = key_path(state_dir);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|source| KeystoreError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let bytes = serde_json::to_vec_pretty(&file).expect("a key file serialises");
    write_private(&path, &bytes)?;
    Ok(file)
}

/// Forget the device-local key (the vault's enrolment is removed separately, with `presence.unenrol`).
pub fn delete_key(state_dir: &Path) -> Result<()> {
    match std::fs::remove_file(key_path(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(KeystoreError::Io {
            path: key_path(state_dir),
            source,
        }),
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path).map_err(|source| KeystoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    f.write_all(bytes).map_err(|source| KeystoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// What the broker's `presence.challenge` answered.
#[derive(Debug, Clone)]
pub struct Challenge {
    pub nonce_b64: String,
    pub digest: Vec<u8>,
    /// The sentence for the Touch ID dialog.
    pub reason: String,
}

impl Challenge {
    /// Read the broker's `presence.challenge` value.
    pub fn from_value(v: &Value) -> Option<Challenge> {
        Some(Challenge {
            nonce_b64: v["nonce"].as_str()?.to_string(),
            digest: B64.decode(v["digest"].as_str()?).ok()?,
            reason: v["reason"]
                .as_str()
                .unwrap_or("Confirm it is you")
                .to_string(),
        })
    }
}

/// Sign a challenge with this Mac's presence key (prompts) and return `params` with `presence` added.
pub fn attach_proof(
    helper: &Helper,
    state_dir: &Path,
    challenge: &Challenge,
    params: &Value,
) -> Result<Value> {
    let key = load_key(state_dir)?.ok_or(KeystoreError::PresenceUnavailable)?;
    let signature = helper.sign(&key.blob()?, &challenge.digest, &challenge.reason)?;
    let mut out = params.clone();
    if !out.is_object() {
        out = json!({});
    }
    out["presence"] = json!({ "nonce": challenge.nonce_b64, "signature": B64.encode(signature) });
    Ok(out)
}

/// ADR-148 §P2-4: sign a **possession** challenge (`presence.challenge` with `possession: true`) with this
/// Mac's presence key (prompts) and return `params` with `possession` added — what `presence.enrol` needs to
/// believe the key being enrolled is held here.
pub fn attach_possession(
    helper: &Helper,
    state_dir: &Path,
    challenge: &Challenge,
    params: &Value,
) -> Result<Value> {
    let key = load_key(state_dir)?.ok_or(KeystoreError::PresenceUnavailable)?;
    let signature = helper.sign(&key.blob()?, &challenge.digest, &challenge.reason)?;
    let mut out = params.clone();
    if !out.is_object() {
        out = json!({});
    }
    out["possession"] = json!({ "nonce": challenge.nonce_b64, "signature": B64.encode(signature) });
    Ok(out)
}

/// The whole client flow around one gated request. `ask(op, params)` is the caller's way to reach the
/// broker (the CLI's socket call, the shell's bridge) and returns the broker's `value` or its error text.
///
/// 1. `ask(op, params)`; if it works, done (a vault with no presence gate on this op, or an old broker).
/// 2. On a `presence_required` answer: `ask("presence.challenge", {op, params})`, sign, `ask(op, params')`.
///
/// The error type is the caller's own; `needs_presence` says whether an error means "send a proof".
pub fn prove<E>(
    helper: &Helper,
    state_dir: &Path,
    op: &str,
    params: Value,
    mut ask: impl FnMut(&str, Value) -> std::result::Result<Value, E>,
    needs_presence: impl Fn(&E) -> bool,
    from_keystore: impl Fn(KeystoreError) -> E,
) -> std::result::Result<Value, E> {
    match ask(op, params.clone()) {
        Err(e) if needs_presence(&e) => {
            let challenge_value = ask("presence.challenge", json!({ "op": op, "params": params }))?;
            let challenge = Challenge::from_value(&challenge_value).ok_or_else(|| {
                from_keystore(KeystoreError::Helper {
                    code: "failed".into(),
                    detail: "the broker's challenge was malformed".into(),
                })
            })?;
            let proved =
                attach_proof(helper, state_dir, &challenge, &params).map_err(&from_keystore)?;
            ask(op, proved)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_file_is_created_once_and_loaded_back() {
        let Some(helper) = test_helper() else { return };
        let dir = tempfile::tempdir().unwrap();
        assert!(load_key(dir.path()).unwrap().is_none());
        let first = create_key(&helper, dir.path()).unwrap();
        let second = create_key(&helper, dir.path()).unwrap();
        assert_eq!(first, second, "an existing key is never replaced silently");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(key_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        delete_key(dir.path()).unwrap();
        assert!(load_key(dir.path()).unwrap().is_none());
    }

    #[test]
    fn prove_asks_once_when_no_proof_is_needed_and_signs_when_it_is() {
        let Some(helper) = test_helper() else { return };
        let dir = tempfile::tempdir().unwrap();
        let key = create_key(&helper, dir.path()).unwrap();
        // A fake broker: the op wants presence until params.presence is present.
        let nonce = crate::secure_enclave::random_nonce();
        let digest = credmgr_core::presence::digest(&nonce, "x.op", &json!({"a": 1}));
        let mut calls: Vec<String> = Vec::new();
        let result: std::result::Result<Value, String> = prove(
            &helper,
            dir.path(),
            "x.op",
            json!({"a": 1}),
            |op, params| {
                calls.push(op.to_string());
                match op {
                    "presence.challenge" => Ok(json!({
                        "nonce": B64.encode(nonce), "digest": B64.encode(digest), "reason": "test",
                    })),
                    _ if params.get("presence").is_some() => {
                        // The signature must verify against the key's public half.
                        let sig = B64
                            .decode(params["presence"]["signature"].as_str().unwrap())
                            .unwrap();
                        assert!(credmgr_core::presence::verify(
                            &key.public().unwrap(),
                            &digest,
                            &sig
                        )
                        .is_ok());
                        Ok(json!({"ok": true}))
                    }
                    _ => Err("presence_required".to_string()),
                }
            },
            |e| e.starts_with("presence_required"),
            |e| e.to_string(),
        );
        assert_eq!(result.unwrap(), json!({"ok": true}));
        assert_eq!(calls, vec!["x.op", "presence.challenge", "x.op"]);
    }

    fn test_helper() -> Option<Helper> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let guess =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/native/credmgr-presence-test");
        let h = Helper::at(guess.is_file().then_some(guess)?);
        h.probe().ok()?.secure_enclave.then_some(h)
    }
}
