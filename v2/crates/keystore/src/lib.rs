//! `credmgr-keystore` — the `PlatformKeystore` trait and its implementations
//! (macOS Secure Enclave, Windows Hello/TPM+DPAPI, Linux TPM2/secret-service,
//! and the Argon2id software fallback). See `docs/16_CROSS_PLATFORM.md §3-4`.
//!
//! **Phase 3 status (ADR-041):** the trait, `Capabilities`/`Tier`, and
//! [`software::SoftwareKeystore`] are built and tested now — `16 §4.4`
//! documents `Software` as the escrow wrap present on every platform
//! unconditionally, not one of the three hardware tiers. The macOS Secure
//! Enclave, Windows Hello/TPM+DPAPI, and Linux TPM2/secret-service
//! implementations are Phase 5 work (`docs/12_BUILD_PLAN.md` Phase 5),
//! landing behind this same trait.
//!
//! Platform FFI is the one place this workspace's crates may need `unsafe`
//! (Secure Enclave / CNG / TPM2 bindings). None exists yet — `SoftwareKeystore`
//! is pure Rust — so the blanket forbid stays on; a future platform module
//! that genuinely needs `unsafe` must scope it with `#[allow(unsafe_code)]`
//! on that module alone, justified in a comment.
#![forbid(unsafe_code)]

pub mod backup_passphrase;
pub mod error;
pub mod software;

pub use error::{KeystoreError, Result};

use secrecy::SecretBox;

/// Which concrete implementation is backing the trait. Not every variant is
/// implemented yet (ADR-041) — the enum is complete because `Capabilities`
/// and broker match arms need to name a tier before Phase 5 builds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeystoreId {
    MacosSecureEnclave,
    WindowsHello,
    WindowsDpapi,
    LinuxTpm,
    LinuxSecretService,
    Software,
}

/// `16_CROSS_PLATFORM.md §3` — hardware-backed, OS-protected, or
/// passphrase-only, in descending order of what a stolen disk image costs
/// an attacker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    Hardware,
    OsProtected,
    Software,
}

/// What this implementation actually delivers, stated so the UI can say so
/// in plain words rather than showing a lock icon that means less than the
/// user thinks (`16 §3`, `02 §6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capabilities {
    /// Key material cannot be exported from the device.
    pub hardware_backed: bool,
    /// A biometric/PIN/touch prompt is available for `verify_presence`.
    pub user_presence: bool,
    /// The platform itself rate-limits wrong-guess attempts.
    pub anti_hammering: bool,
    /// The wrap survives a reboot without re-enrolment.
    pub survives_reboot: bool,
    pub tier: Tier,
}

/// The root key, wrapped for storage. Implementation-specific in content
/// (a software blob here, a Secure Enclave reference in Phase 5) but always
/// serializable, since it lives on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    pub keystore: KeystoreId,
    pub bytes: Vec<u8>,
}

/// Proof that [`PlatformKeystore::verify_presence`] succeeded. Short-lived,
/// carries no key material — the broker decides how long it stays valid
/// (`02_ARCHITECTURE.md §6`: "a short-lived attestation, never a key").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceProof {
    pub keystore: KeystoreId,
}

/// Hardware-or-OS-backed protection for the root key. Deliberately never
/// exposes the wrapping key itself — only wrap/unwrap operations — so a weak
/// platform cannot silently hand out something a strong one would not
/// (`16_CROSS_PLATFORM.md §3`, verbatim contract).
pub trait PlatformKeystore: Send + Sync {
    fn id(&self) -> KeystoreId;
    fn capabilities(&self) -> Capabilities;

    /// Wrap the root key. May prompt (biometric enrolment) on hardware tiers.
    fn wrap_root(&self, root: &SecretBox<[u8; 32]>) -> Result<WrappedKey>;

    /// Unwrap. MUST require user presence when `capabilities().user_presence`.
    fn unwrap_root(&self, wrapped: &WrappedKey, reason: &str) -> Result<SecretBox<[u8; 32]>>;

    /// A single presence check, for grants / orphan reveal / approval-on-demand.
    /// Returns [`KeystoreError::PresenceUnavailable`] when
    /// `capabilities().user_presence` is `false` — callers must check first.
    fn verify_presence(&self, reason: &str) -> Result<PresenceProof>;

    /// Monotonic counter storage, OUTSIDE the vault directory (`04 §6a`, F-3).
    /// `Ok(0)` means the counter has never been written.
    fn read_counter(&self, name: &str) -> Result<u64>;
    fn write_counter(&self, name: &str, value: u64) -> Result<()>;
}
