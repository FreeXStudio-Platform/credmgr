//! Error types for `credmgr-core`. Everything here is a pure computation failure —
//! a malformed envelope, a broken invariant, an oversized id. No I/O error ever
//! originates in this crate.

use core::fmt;

/// Failures from [`crate::envelope`] and [`crate::keys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The first four bytes were not `CMV2`.
    BadMagic,
    /// The envelope declares a version this build does not implement.
    UnsupportedVersion(u8),
    /// The envelope declares a cipher suite this build does not implement.
    UnsupportedSuite(u8),
    /// The byte slice is shorter than the fixed header + minimum tag length.
    Truncated,
    /// A node id's UTF-8 encoding does not fit the fixed 16-byte envelope field.
    NodeIdTooLong,
    /// The envelope's stored node-id field does not decode to valid UTF-8 —
    /// or does not match the caller's expected node id (checked before any
    /// AEAD call, for a clearer error; the AEAD tag is what actually enforces
    /// this, see `04_CRYPTO_AND_KEYS.md §3`).
    NodeIdMismatch,
    /// AEAD tag verification failed: wrong key, wrong AAD (node/entry id
    /// binding), or corrupted ciphertext. Deliberately undifferentiated —
    /// telling an attacker *which* check failed is a side channel.
    AuthenticationFailed,
    /// A recovery code string did not decode to exactly
    /// [`crate::recovery::RECOVERY_CODE_LEN`] bytes of hex (`04 §2`,
    /// ADR-045). Distinct from `AuthenticationFailed`: this is a transcription
    /// error caught before any key derivation is attempted, not a wrong-key
    /// AEAD failure.
    InvalidRecoveryCode,
    /// A gate recovery code string did not decode to exactly
    /// [`crate::totp::GATE_RECOVERY_CODE_LEN`] bytes of hex (`07 §4`).
    /// Deliberately a separate variant from `InvalidRecoveryCode`: the two
    /// are different codes of different lengths protecting different things
    /// (the root key vs. a TOTP gate challenge) — `07 §1`'s "gate and totp
    /// never share a word" discipline extended to this pair too.
    InvalidGateRecoveryCode,
    /// A stored TOTP item's secret field did not decode as RFC 4648 base32
    /// (`07 §6`) — a transcription/corruption error, distinct from both
    /// recovery-code variants above (different encoding, different thing
    /// being decoded).
    InvalidTotpSecret,
    /// ADR-077 (MX-1): a stored TOTP secret decoded fine but is shorter than
    /// [`crate::totp::MIN_TOTP_SECRET_LEN`] (80 bits — a recorded deviation from
    /// the 128 bits RFC 4226 §4 asks of a shared secret, explained there). A
    /// value this short is a truncated paste or a typo: no real service issues
    /// less, and a code derived from it would never match. It lands here as a
    /// typed refusal instead of crashing the caller.
    TotpSecretTooShort {
        /// The decoded secret's length, in bits.
        bits: usize,
    },
    /// ADR-077 (MX-1): TOTP parameters outside what the engine accepts —
    /// digits other than 6–8, or a period of zero seconds.
    InvalidTotpParameters,
    /// ADR-079: an orphan cold-key file opened, but the public key derived
    /// from the private half it held is not the one its own header — or the
    /// registry — names. A swapped, rolled-back or transplanted file: it must
    /// never be used to seal or to open anything.
    ColdKeyMismatch,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::BadMagic => write!(f, "envelope: bad magic bytes"),
            CryptoError::UnsupportedVersion(v) => write!(f, "envelope: unsupported version {v}"),
            CryptoError::UnsupportedSuite(s) => write!(f, "envelope: unsupported suite {s}"),
            CryptoError::Truncated => write!(f, "envelope: truncated"),
            CryptoError::NodeIdTooLong => write!(f, "node id exceeds 16 bytes as UTF-8"),
            CryptoError::NodeIdMismatch => write!(f, "envelope: node id does not match"),
            CryptoError::AuthenticationFailed => write!(f, "envelope: authentication failed"),
            CryptoError::InvalidRecoveryCode => {
                write!(f, "recovery code: does not decode to 32 bytes of hex")
            }
            CryptoError::InvalidGateRecoveryCode => {
                write!(f, "gate recovery code: does not decode to 16 bytes of hex")
            }
            CryptoError::InvalidTotpSecret => {
                write!(f, "totp secret: does not decode as base32")
            }
            CryptoError::TotpSecretTooShort { bits } => write!(
                f,
                "totp secret: {bits} bits is shorter than the 80-bit minimum"
            ),
            CryptoError::InvalidTotpParameters => {
                write!(
                    f,
                    "totp parameters: digits must be 6-8 and the period at least 1 second"
                )
            }
            CryptoError::ColdKeyMismatch => {
                write!(f, "orphan cold key: the public key does not match")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
