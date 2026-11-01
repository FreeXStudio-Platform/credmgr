//! Failures from every [`crate::PlatformKeystore`] implementation.

use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum KeystoreError {
    /// AEAD tag verification failed on a wrapped root key or a counter
    /// blob: wrong passphrase, wrong platform secret, or tampering.
    /// Deliberately undifferentiated — same rationale as
    /// `credmgr_core::error::CryptoError::AuthenticationFailed`.
    AuthenticationFailed,
    /// A stored blob is shorter than its fixed header + minimum tag length.
    Truncated,
    /// This implementation's `Capabilities::user_presence` is `false` — see
    /// ADR-041. Callers must check `capabilities()` before calling
    /// `verify_presence`; this is the honest failure when they don't.
    PresenceUnavailable,
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeystoreError::AuthenticationFailed => {
                write!(f, "keystore: authentication failed")
            }
            KeystoreError::Truncated => write!(f, "keystore: truncated blob"),
            KeystoreError::PresenceUnavailable => write!(
                f,
                "keystore: this tier cannot verify presence — check capabilities() first"
            ),
            KeystoreError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            KeystoreError::Json { path, source } => {
                write!(f, "{}: malformed JSON: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for KeystoreError {}

pub type Result<T> = std::result::Result<T, KeystoreError>;
