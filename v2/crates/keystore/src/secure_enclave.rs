//! The macOS Secure Enclave tier (ADR-098).
//!
//! Two jobs, both through the `credmgr-presence` helper (`v2/native/macos/presence`, Swift/CryptoKit):
//!
//! * **Device wrap of the root key.** [`SecureEnclaveKeystore`] seals the 32-byte root key to a Secure
//!   Enclave P-256 key with an ECIES construction (ephemeral ECDH → HKDF-SHA256 → ChaCha20-Poly1305).
//!   Sealing needs only the public key, so it never prompts and rotation can redo it silently. Opening
//!   needs the Secure Enclave, which asks for Touch ID or the device password **every time** and only
//!   works on the Mac that made the key. The passphrase and recovery wraps stay beside it: this is a
//!   second door, not a replacement.
//! * **Presence signing.** [`Helper::sign`] asks a second Secure Enclave key to sign a broker digest
//!   (`credmgr_core::presence`); the broker checks it. That is the proof behind every presence-gated op.
//!
//! The helper is a separate process because the workspace forbids `unsafe` and CryptoKit's Secure Enclave
//! types are Swift-only. It speaks one JSON line in, one JSON line out, holds nothing, and its binary is
//! pinned in the release checksums.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroize;

use credmgr_core::presence::{NONCE_LEN, PUBLIC_LEN};

use crate::error::{KeystoreError, Result};
use crate::{Capabilities, KeystoreId, PlatformKeystore, PresenceProof, Tier, WrappedKey};

/// How long a helper call may take before it is killed. Long on purpose: the user may be looking for
/// their finger. The system prompt has its own cancel.
const HELPER_TIMEOUT: Duration = Duration::from_secs(180);
const NAME: &str = "credmgr-presence";
/// The error code a helper call that ran past its timeout fails with (ADR-148 addendum).
pub const TIMED_OUT: &str = "timed_out";
/// What the production helper's `probe` answers as its `variant` (`native/macos/presence/main.swift`).
#[cfg_attr(debug_assertions, allow(dead_code))]
const PRODUCTION_VARIANT: &str = "credmgr-presence-variant:production";

/// The helper's answer to `probe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub secure_enclave: bool,
    /// `touchid`, `faceid`, `other` or `none`.
    pub biometry: String,
    /// A device password is set, so `userPresence` can fall back to it.
    pub passcode: bool,
}

/// A freshly created Secure Enclave key: the opaque persistable blob and its public point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    pub blob: Vec<u8>,
    pub public: Vec<u8>,
}

/// Which kind of Secure Enclave key to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// An ECDSA signing key (presence proofs).
    Presence,
    /// An ECDH key (the root-key wrap).
    Wrap,
}

/// A handle on the helper binary.
#[derive(Debug, Clone)]
pub struct Helper {
    path: PathBuf,
    /// How long one call may take ([`HELPER_TIMEOUT`] unless a test shortened it).
    timeout: Duration,
}

impl Helper {
    /// Use the helper at `path`.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Helper {
            path: path.into(),
            timeout: HELPER_TIMEOUT,
        }
    }

    /// The same helper with a shorter call timeout (a test seam: a real prompt gets [`HELPER_TIMEOUT`]).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Find the helper: `CREDMGR_PRESENCE_HELPER` (debug builds only), then next to the running executable
    /// (`credmgr`, `credmgrd` and the app's main binary all ship beside it), then `../Resources`
    /// inside an app bundle. Returns `None` off macOS or when it is absent: callers then stay on the
    /// software tier and say so.
    ///
    /// ADR-148 (P3): a release build ignores `CREDMGR_PRESENCE_HELPER` (an environment variable is not a
    /// place a release takes its root of trust from) and refuses a helper whose probe does not name the
    /// production variant — the unattended TEST helper signs without asking anyone.
    pub fn locate() -> Option<Helper> {
        #[cfg(debug_assertions)]
        if let Some(p) = std::env::var_os("CREDMGR_PRESENCE_HELPER") {
            let p = PathBuf::from(p);
            return p.is_file().then(|| Helper::at(p));
        }
        if !cfg!(target_os = "macos") {
            return None;
        }
        let found = Self::beside_executable()?;
        #[cfg(not(debug_assertions))]
        {
            let probe = found.call(json!({ "cmd": "probe" })).ok()?;
            if probe["variant"].as_str() != Some(PRODUCTION_VARIANT) {
                return None;
            }
        }
        Some(found)
    }

    fn beside_executable() -> Option<Helper> {
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        [
            dir.join(NAME),
            dir.join("../libexec").join(NAME),
            dir.join("../Resources").join(NAME),
        ]
        .into_iter()
        .find(|p| p.is_file())
        .map(Helper::at)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn call(&self, request: Value) -> Result<Value> {
        let mut child = Command::new(&self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| KeystoreError::HelperMissing(format!("{}: {e}", self.path.display())))?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = child.stdout.take().expect("piped stdout");
        let body = serde_json::to_vec(&request).expect("a JSON value serialises");
        // Written from a thread so a helper that never reads cannot wedge us before the timeout.
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
                Ok(None) if started.elapsed() > self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    // ADR-148 addendum: its own code, so a Touch ID prompt left to time out is counted like a
                    // dismissal (the broker's backoff), not reported as the helper being unavailable.
                    return Err(KeystoreError::Helper {
                        code: TIMED_OUT.into(),
                        detail: "the helper did not answer in time".into(),
                    });
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => {
                    return Err(KeystoreError::HelperMissing(e.to_string()));
                }
            }
        }
        let _ = writer.join();
        let out = reader.join().unwrap_or_default();
        let reply: Value = serde_json::from_slice(&out).map_err(|_| KeystoreError::Helper {
            code: "failed".into(),
            detail: "the helper's answer was not JSON".into(),
        })?;
        if reply["ok"].as_bool() == Some(true) {
            Ok(reply)
        } else {
            Err(KeystoreError::Helper {
                code: reply["error"].as_str().unwrap_or("failed").to_string(),
                detail: reply["detail"].as_str().unwrap_or("").to_string(),
            })
        }
    }

    fn field(reply: &Value, key: &str) -> Result<Vec<u8>> {
        reply[key]
            .as_str()
            .and_then(|s| B64.decode(s).ok())
            .ok_or_else(|| KeystoreError::Helper {
                code: "failed".into(),
                detail: format!("the helper's answer has no usable {key}"),
            })
    }

    /// A throwaway key does ECDH against `peer` (an uncompressed point) and is dropped. Returns its public
    /// point and the raw shared secret. No prompt, no key material survives the call.
    pub fn ephemeral(&self, peer: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let r = self.call(json!({ "cmd": "ephemeral", "peer": B64.encode(peer) }))?;
        Ok((Self::field(&r, "public")?, Self::field(&r, "secret")?))
    }

    pub fn probe(&self) -> Result<Probe> {
        let r = self.call(json!({ "cmd": "probe" }))?;
        Ok(Probe {
            secure_enclave: r["secureEnclave"].as_bool().unwrap_or(false),
            biometry: r["biometry"].as_str().unwrap_or("none").to_string(),
            passcode: r["passcode"].as_bool().unwrap_or(false),
        })
    }

    /// Create a Secure Enclave key. Never prompts.
    pub fn enroll(&self, purpose: Purpose) -> Result<Enrolled> {
        let purpose = match purpose {
            Purpose::Presence => "presence",
            Purpose::Wrap => "wrap",
        };
        let r = self.call(json!({ "cmd": "enroll", "purpose": purpose }))?;
        let public = Self::field(&r, "public")?;
        if public.len() != PUBLIC_LEN {
            return Err(KeystoreError::Helper {
                code: "failed".into(),
                detail: "the helper returned a public key of the wrong length".into(),
            });
        }
        Ok(Enrolled {
            blob: Self::field(&r, "blob")?,
            public,
        })
    }

    /// Sign `message` with the presence key in `blob`. Prompts (Touch ID or device password).
    pub fn sign(&self, blob: &[u8], message: &[u8], reason: &str) -> Result<Vec<u8>> {
        let r = self.call(json!({
            "cmd": "sign", "blob": B64.encode(blob), "message": B64.encode(message), "reason": reason,
        }))?;
        Self::field(&r, "signature")
    }

    /// ECDH against `peer` (an uncompressed point) with the wrap key in `blob`. Prompts.
    pub fn ecdh(&self, blob: &[u8], peer: &[u8], reason: &str) -> Result<Vec<u8>> {
        let r = self.call(json!({
            "cmd": "ecdh", "blob": B64.encode(blob), "peer": B64.encode(peer), "reason": reason,
        }))?;
        Self::field(&r, "secret")
    }
}

/// Seal `root` to the Secure Enclave public key `se_public`. No prompt: the helper's throwaway key does the
/// ECDH and only the public half of the Enclave key is used.
///
/// ADR-148 (P3), stated rather than changed: the helper is **trusted** for this ephemeral ECDH. A helper that
/// lied (returned a shared secret it kept) would learn the root key it is asked to seal. That is why the
/// helper is located only beside the signed binaries (never from the environment in a release), its
/// variant is checked, and its bytes are pinned in the release checksums; moving the ephemeral half into
/// Rust would remove this trust and is tracked as a follow-up.
pub fn seal_to_public(helper: &Helper, se_public: &[u8], root: &[u8; 32]) -> Result<Vec<u8>> {
    let (eph_public, shared) = helper.ephemeral(se_public)?;
    let sealed = credmgr_core::presence::seal_root_with_shared(&eph_public, &shared, root);
    let mut shared = shared;
    shared.zeroize();
    sealed.map_err(|_| KeystoreError::Helper {
        code: "failed".into(),
        detail: "the Secure Enclave helper returned an unusable ephemeral key".into(),
    })
}

/// Open a [`seal_to_public`] blob with the Secure Enclave key in `se_blob`. Prompts.
pub fn open_with_helper(
    helper: &Helper,
    se_blob: &[u8],
    sealed: &[u8],
    reason: &str,
) -> Result<SecretBox<[u8; 32]>> {
    let peer =
        credmgr_core::presence::sealed_root_peer(sealed).map_err(|_| KeystoreError::Truncated)?;
    let mut shared = helper.ecdh(se_blob, peer, reason)?;
    let opened = credmgr_core::presence::open_sealed_root(sealed, &shared);
    shared.zeroize();
    let mut arr = opened.ok_or(KeystoreError::AuthenticationFailed)?;
    let boxed = SecretBox::new(Box::new(arr));
    arr.zeroize();
    Ok(boxed)
}

/// The device-local record of the presence key: the Secure Enclave blob plus its public point. Lives in
/// the state directory (outside the vault, never backed up) because it is only meaningful on this Mac.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PresenceKeyFile {
    pub v: u8,
    pub blob: String,
    pub public: String,
}

impl PresenceKeyFile {
    pub fn new(e: &Enrolled) -> Self {
        PresenceKeyFile {
            v: 1,
            blob: B64.encode(&e.blob),
            public: B64.encode(&e.public),
        }
    }

    pub fn blob(&self) -> Result<Vec<u8>> {
        B64.decode(&self.blob)
            .map_err(|_| KeystoreError::AuthenticationFailed)
    }

    pub fn public(&self) -> Result<Vec<u8>> {
        B64.decode(&self.public)
            .map_err(|_| KeystoreError::AuthenticationFailed)
    }
}

/// A random broker-style nonce, for callers that need a local presence check with no broker (tests,
/// the doctor).
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = <[u8; NONCE_LEN]>::default();
    OsRng.fill_bytes(&mut n);
    n
}

/// The Secure Enclave keystore: wraps and opens the root key, and can attest presence.
pub struct SecureEnclaveKeystore {
    helper: Helper,
    /// The wrap key's Secure Enclave blob.
    wrap_blob: Vec<u8>,
    /// The wrap key's public point.
    wrap_public: Vec<u8>,
    /// The presence key's blob and public point, when one is enrolled on this Mac.
    presence: Option<(Vec<u8>, Vec<u8>)>,
    state_dir: PathBuf,
}

impl SecureEnclaveKeystore {
    pub fn new(
        helper: Helper,
        wrap_blob: Vec<u8>,
        wrap_public: Vec<u8>,
        presence: Option<(Vec<u8>, Vec<u8>)>,
        state_dir: PathBuf,
    ) -> Self {
        SecureEnclaveKeystore {
            helper,
            wrap_blob,
            wrap_public,
            presence,
            state_dir,
        }
    }

    fn counter_path(&self, name: &str) -> PathBuf {
        self.state_dir.join(format!("{name}.secounter"))
    }
}

impl PlatformKeystore for SecureEnclaveKeystore {
    fn id(&self) -> KeystoreId {
        KeystoreId::MacosSecureEnclave
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: true,
            user_presence: self.presence.is_some(),
            anti_hammering: true,
            survives_reboot: true,
            tier: Tier::Hardware,
        }
    }

    fn wrap_root(&self, root: &SecretBox<[u8; 32]>) -> Result<WrappedKey> {
        Ok(WrappedKey {
            keystore: KeystoreId::MacosSecureEnclave,
            bytes: seal_to_public(&self.helper, &self.wrap_public, root.expose_secret())?,
        })
    }

    fn unwrap_root(&self, wrapped: &WrappedKey, reason: &str) -> Result<SecretBox<[u8; 32]>> {
        open_with_helper(&self.helper, &self.wrap_blob, &wrapped.bytes, reason)
    }

    fn verify_presence(&self, reason: &str) -> Result<PresenceProof> {
        let (blob, public) = self
            .presence
            .as_ref()
            .ok_or(KeystoreError::PresenceUnavailable)?;
        let digest =
            credmgr_core::presence::digest(&random_nonce(), "keystore.verify", &Value::Null);
        let sig = self.helper.sign(blob, &digest, reason)?;
        credmgr_core::presence::verify(public, &digest, &sig)
            .map_err(|_| KeystoreError::AuthenticationFailed)?;
        Ok(PresenceProof {
            keystore: KeystoreId::MacosSecureEnclave,
        })
    }

    /// Counters are plain, non-secret high-water marks; the vault already HMACs what they protect
    /// (`FileGenerationCounter`). This implementation keeps them in the state directory unsealed.
    fn read_counter(&self, name: &str) -> Result<u64> {
        let path = self.counter_path(name);
        match std::fs::read_to_string(&path) {
            Ok(s) => s.trim().parse().map_err(|_| KeystoreError::Truncated),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(source) => Err(KeystoreError::Io { path, source }),
        }
    }

    fn write_counter(&self, name: &str, value: u64) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir).map_err(|source| KeystoreError::Io {
            path: self.state_dir.clone(),
            source,
        })?;
        let path = self.counter_path(name);
        std::fs::write(&path, value.to_string())
            .map_err(|source| KeystoreError::Io { path, source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    #[test]
    fn the_key_file_round_trips() {
        let e = Enrolled {
            blob: vec![1, 2, 3],
            public: vec![4; 65],
        };
        let f = PresenceKeyFile::new(&e);
        let again: PresenceKeyFile =
            serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(again.blob().unwrap(), e.blob);
        assert_eq!(again.public().unwrap(), e.public);
    }

    #[test]
    fn a_missing_helper_is_reported_not_faked() {
        let h = Helper::at("/nonexistent/credmgr-presence");
        assert!(matches!(h.probe(), Err(KeystoreError::HelperMissing(_))));
    }

    /// Software signing key used only to confirm the digest/verify pairing the helper must match.
    #[test]
    fn a_software_signature_over_the_digest_verifies() {
        let sk = SigningKey::random(&mut OsRng);
        let public = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let d = credmgr_core::presence::digest(&random_nonce(), "x", &Value::Null);
        let sig: Signature = sk.sign(&d);
        assert!(credmgr_core::presence::verify(&public, &d, &sig.to_bytes()).is_ok());
    }

    // ---- against the real helper, when it has been built (v2/native/macos/presence/build.sh) ----
    // The TEST variant creates keys without a user-presence prompt so these run unattended. They
    // exercise the real Secure Enclave and the real CryptoKit signature format.
    fn test_helper() -> Option<Helper> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let p = std::env::var_os("CREDMGR_PRESENCE_TEST_HELPER")
            .map(PathBuf::from)
            .or_else(|| {
                let guess = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../target/native/credmgr-presence-test");
                guess.is_file().then_some(guess)
            })?;
        Some(Helper::at(p))
    }

    #[test]
    fn real_secure_enclave_signature_verifies_in_rust() {
        let Some(h) = test_helper() else { return };
        let probe = h.probe().unwrap();
        if !probe.secure_enclave {
            return;
        }
        let key = h.enroll(Purpose::Presence).unwrap();
        let n8 = random_nonce();
        let d = credmgr_core::presence::digest(&n8, "grant.create", &json!({"to": "acme"}));
        let sig = h.sign(&key.blob, &d, "test").unwrap();
        assert_eq!(
            credmgr_core::presence::verify(&key.public, &d, &sig),
            Ok(())
        );
        let other = credmgr_core::presence::digest(&n8, "grant.create", &json!({"to": "evil"}));
        assert!(credmgr_core::presence::verify(&key.public, &other, &sig).is_err());
    }

    #[test]
    fn real_secure_enclave_wrap_round_trips_the_root_key() {
        let Some(h) = test_helper() else { return };
        if !h.probe().unwrap().secure_enclave {
            return;
        }
        let key = h.enroll(Purpose::Wrap).unwrap();
        let ks = SecureEnclaveKeystore::new(
            h,
            key.blob.clone(),
            key.public.clone(),
            None,
            std::env::temp_dir().join("credmgr-se-test"),
        );
        let root = SecretBox::new(Box::new([0x5au8; 32]));
        let wrapped = ks.wrap_root(&root).unwrap();
        let back = ks.unwrap_root(&wrapped, "test").unwrap();
        assert_eq!(back.expose_secret(), root.expose_secret());
        assert!(ks.capabilities().hardware_backed);
        assert!(matches!(
            ks.verify_presence("x"),
            Err(KeystoreError::PresenceUnavailable)
        ));
    }
}
