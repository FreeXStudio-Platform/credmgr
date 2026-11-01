//! RFC 6238 TOTP — gate 2FA challenges and TOTP items (`docs/07_TWO_FACTOR.md`).
//! Time is always an explicit parameter here, matching this crate's I/O-free
//! contract (`lib.rs`): nothing in this module reads the system clock, the
//! same discipline `envelope.rs`/`keys.rs` already apply to CSPRNG generation
//! (an `OsRng` call is not a clock/file/socket/env read).
//!
//! **Two different codes, never confused (`07 §1`, `07 §4` vs. this module's
//! gate-recovery codes).** The *root* recovery code (`crate::recovery`,
//! ADR-045) rewraps the root key and is generated once, at vault creation.
//! The *gate* recovery codes here satisfy one TOTP gate challenge each and
//! are reissued every time a gate is (re-)enrolled — they never touch key
//! material at all, only a broker-side "was this used" check, so they carry
//! no HKDF/AEAD wrap of their own, unlike the root recovery code.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, TOTP as RawTotp};

use crate::error::CryptoError;

/// `07 §4`: "Generate a 160-bit secret ... base32-encoded."
pub const GATE_SECRET_LEN: usize = 20;
/// `07 §5`: "Period 30s".
pub const DEFAULT_PERIOD: u64 = 30;
/// `07 §5`: "Digits 6".
pub const DEFAULT_DIGITS: usize = 6;
/// `07 §5`: "Clock skew ±1 step accepted (90s total window)".
pub const DEFAULT_SKEW: u8 = 1;

/// `07 §4`: "Issue 10 single-use recovery codes."
pub const GATE_RECOVERY_CODE_COUNT: usize = 10;
/// 128 bits — enough to make guessing infeasible for a code that is only
/// ever compared, never used to derive a key (contrast the root recovery
/// code's 256 bits, which doubles as HKDF input material, `crate::recovery`).
pub const GATE_RECOVERY_CODE_LEN: usize = 16;

/// A fresh gate TOTP secret. CSPRNG, never derived from anything else.
pub fn generate_gate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; GATE_SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    secret
}

/// RFC 4648 base32, the reverse of [`Totp::secret_base32`] — used wherever a
/// stored secret (a TOTP item's field value, `07 §6`) needs to become a
/// [`Totp`] again via [`Totp::from_stored_secret`].
///
/// Tolerant of how real sites print a seed, because a stored seed is whatever
/// was pasted: lower case, spaces or dashes in groups of four, and `=` padding
/// are all accepted (ADR-077 — a correctly padded 128-bit seed used to be
/// refused as "not valid base32"). Anything outside the base32 alphabet after
/// that is still an error.
pub fn decode_gate_secret_base32(s: &str) -> Result<Vec<u8>, CryptoError> {
    let canonical: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let unpadded = canonical.trim_end_matches('=');
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, unpadded)
        .filter(|bytes| !bytes.is_empty())
        .ok_or(CryptoError::InvalidTotpSecret)
}

/// The shortest seed this crate computes a code from: 80 bits (10 bytes, 16
/// base32 characters).
///
/// **A recorded deviation from RFC 4226 §4 (R6)**, which says a shared secret
/// MUST be at least 128 bits (and RECOMMENDS 160). Why it is safe and why it is
/// needed (ADR-077, orchestrator decision 2026-10-02):
///
/// * The RFC floor protects the strength of a secret *the verifier chose*. A
///   stored seed is the opposite case: some other service chose it, issued it to
///   the user, and is the party that verifies codes. This vault is the prover; it
///   cannot make that service's seed any stronger or weaker, and refusing to use
///   it only locks the user out of a code their own authenticator app would show.
/// * Many real services still issue 80-bit seeds (16 base32 characters — the
///   original Google Authenticator key format), so a 128-bit floor made "store
///   my seed, get my code" fail for ordinary accounts.
/// * Every secret this crate *generates* — the 2FA gate's — is 160 bits
///   ([`GATE_SECRET_LEN`]); the lower floor applies only to a stored seed's
///   *decode*, never to what the vault issues.
///
/// Below 80 bits is still refused with a typed error: no real service issues
/// less, so such a value is a truncated paste or a typo, and a code derived from
/// it would silently never match.
pub const MIN_TOTP_SECRET_LEN: usize = 10;

/// `07 §5`: "SHA-256/512 supported for items" (the gate itself always uses
/// the RFC 6238 default, SHA-1 — `Totp::new_gate` bakes that in).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<TotpAlgorithm> for Algorithm {
    fn from(a: TotpAlgorithm) -> Algorithm {
        match a {
            TotpAlgorithm::Sha1 => Algorithm::SHA1,
            TotpAlgorithm::Sha256 => Algorithm::SHA256,
            TotpAlgorithm::Sha512 => Algorithm::SHA512,
        }
    }
}

/// A configured TOTP generator/verifier — one per gate scope or per stored
/// TOTP item. Wraps `totp_rs::TOTP` rather than hand-rolling HMAC-truncation
/// (`16_CROSS_PLATFORM.md §2`'s crate table names `totp-rs` explicitly), but
/// never with its `otpauth` feature — see `Cargo.toml`'s comment on why, and
/// [`Totp::otpauth_uri`] for the hand-built replacement.
#[derive(Clone)]
pub struct Totp(RawTotp);

impl Totp {
    /// `07 §4`/`§5`'s gate defaults: SHA-1, 6 digits, 30s period, ±1 skew.
    pub fn new_gate(secret: Vec<u8>) -> Self {
        Self::new(secret, TotpAlgorithm::Sha1, DEFAULT_DIGITS, DEFAULT_PERIOD)
    }

    /// `07 §6`: TOTP items may choose 6 or 8 digits and SHA-256/512.
    ///
    /// **Panics** unless the arguments are valid (digits 6–8, a period of at
    /// least one second, a secret of at least [`MIN_TOTP_SECRET_LEN`] bytes).
    /// That is fine for the gate, whose secret this crate generates itself
    /// ([`Totp::new_gate`]); it is *not* fine for anything that came from
    /// storage or a caller — those go through [`Totp::try_new`] or
    /// [`Totp::from_stored_secret`], which answer an error instead (ADR-077:
    /// this `expect` was reachable from `totp.code` with a short stored seed
    /// and killed the connection thread).
    pub fn new(secret: Vec<u8>, algorithm: TotpAlgorithm, digits: usize, period: u64) -> Self {
        Self::try_new(secret, algorithm, digits, period)
            .expect("callers of Totp::new guarantee valid parameters; use Totp::try_new otherwise")
    }

    /// The checked constructor: every invalid argument is an `Err`, never a
    /// panic, whatever the input. Validity is decided *here*, in terms this
    /// crate documents ([`MIN_TOTP_SECRET_LEN`] — 80 bits, a recorded deviation
    /// from the RFC's 128, see that constant — digits 6–8, a period of at least
    /// one second); the wrapped engine's own stricter 128-bit check is bypassed
    /// on purpose via its `new_unchecked`, so nothing below this function can
    /// refuse or panic on a value this function accepted: the engine divides by
    /// the period (hence the zero check), raises ten to `digits` (hence the
    /// range), and feeds the secret to HMAC, which takes a key of any length.
    pub fn try_new(
        mut secret: Vec<u8>,
        algorithm: TotpAlgorithm,
        digits: usize,
        period: u64,
    ) -> Result<Self, CryptoError> {
        // A refused secret is still a secret: wipe it rather than just drop it.
        if !(6..=8).contains(&digits) || period == 0 {
            zeroize::Zeroize::zeroize(&mut secret);
            return Err(CryptoError::InvalidTotpParameters);
        }
        if secret.len() < MIN_TOTP_SECRET_LEN {
            let bits = secret.len() * 8;
            zeroize::Zeroize::zeroize(&mut secret);
            return Err(CryptoError::TotpSecretTooShort { bits });
        }
        Ok(Totp(RawTotp::new_unchecked(
            algorithm.into(),
            digits,
            DEFAULT_SKEW,
            period,
            secret,
        )))
    }

    /// The current code at `unix_time`, with no skew applied — what a real
    /// authenticator app would show at that instant.
    pub fn code(&self, unix_time: u64) -> String {
        self.0.generate(unix_time)
    }

    /// `07 §5`: "Replay — every accepted `(scope, counterStep)` is recorded
    /// and refused again." Returns the matched RFC 6238 counter step (not
    /// just a bool) so the caller can key its replay ledger on it. Mirrors
    /// `totp_rs::TOTP::check`'s own skew window (`basestep = time/step -
    /// skew`) so acceptance matches the RFC exactly; unlike `check`, this
    /// never throws away *which* step matched.
    pub fn verify(&self, code: &str, unix_time: u64) -> Option<u64> {
        let step = self.0.step;
        let skew = u64::from(self.0.skew);
        let current_step = unix_time / step;
        let basestep = current_step.saturating_sub(skew);
        for offset in 0..=(skew * 2) {
            // Saturating, so a timestamp (or a period) near `u64::MAX` can never
            // overflow-panic here: at that extreme the window is meaningless, and
            // "no panic" is the property that matters.
            let counter = basestep.saturating_add(offset);
            let candidate = self.0.generate(counter.saturating_mul(step));
            if constant_time_eq_str(&candidate, code) {
                return Some(counter);
            }
        }
        None
    }

    pub fn secret_base32(&self) -> String {
        self.0.get_secret_base32()
    }

    /// Rebuilds a `Totp` for an already-enrolled TOTP item (`07 §6`) from
    /// its stored base32 secret and configured parameters — the reverse of
    /// generating a fresh one via [`Totp::new`]/[`Totp::new_gate`].
    pub fn from_stored_secret(
        secret_base32: &str,
        algorithm: TotpAlgorithm,
        digits: usize,
        period: u64,
    ) -> Result<Self, CryptoError> {
        let secret = decode_gate_secret_base32(secret_base32)?;
        Self::try_new(secret, algorithm, digits, period)
    }

    /// `07 §4`'s `otpauth://totp/CredMgr:<label>?secret=...&issuer=CredMgr&
    /// period=30&digits=6` URI, built by hand rather than via `totp_rs`'s own
    /// `get_url()` — that needs the `otpauth` feature, which pulls `url` ->
    /// `idna_adapter`, requiring Cargo's `edition2024` (unavailable under
    /// this workspace's 1.78 MSRV; see `Cargo.toml`). `issuer`/`label` here
    /// are always operator-controlled short strings (`CredMgr`, a vault or
    /// node id) with no `otpauth://` URI ever leaving the machine
    /// (`07 §4`: "rendered in-process; no image ever leaves the machine"),
    /// so a minimal percent-encoder is sufficient and correct.
    pub fn otpauth_uri(&self, issuer: &str, label: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&period={}&digits={}",
            percent_encode(issuer),
            percent_encode(label),
            self.secret_base32(),
            percent_encode(issuer),
            self.0.step,
            self.0.digits,
        )
    }
}

/// RFC 3986 "unreserved" characters pass through; everything else is
/// percent-encoded. No claim of full RFC 3986 coverage — see the doc comment
/// on [`Totp::otpauth_uri`] for why that is enough here.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `07 §5`: "Comparison: `crypto.timingSafeEqual`." Both inputs are ASCII
/// digit strings of the configured `digits` length; a length mismatch is
/// itself a legitimate rejection, not a shortcut worth hiding — no
/// meaningful validity information leaks by comparing wrong-length input
/// early, since submitting a code of the wrong length is not a distinct
/// attack step to hide.
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// --- Gate recovery codes (`07 §4`) --------------------------------------

/// `07 §4`: "Issue 10 single-use recovery codes, shown once." CSPRNG, never
/// derived from the TOTP secret or from each other.
pub fn generate_gate_recovery_codes() -> Vec<[u8; GATE_RECOVERY_CODE_LEN]> {
    (0..GATE_RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut code = [0u8; GATE_RECOVERY_CODE_LEN];
            OsRng.fill_bytes(&mut code);
            code
        })
        .collect()
}

/// Upper-case hex, grouped in 4-character blocks — same presentation as
/// `crate::recovery::format_recovery_code`, deliberately duplicated rather
/// than shared (different length, different type, and — per this module's
/// header comment — a caller must never be able to pass one kind of code
/// through the other kind's formatter by generic-parameter accident).
pub fn format_gate_recovery_code(code: &[u8; GATE_RECOVERY_CODE_LEN]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(GATE_RECOVERY_CODE_LEN * 2);
    for b in code {
        write!(hex, "{b:02X}").expect("writing to a String cannot fail");
    }
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex digits are ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Reverse of [`format_gate_recovery_code`]; also accepts ungrouped or
/// lower-case hex, matching `crate::recovery::parse_recovery_code`'s
/// leniency for the same reason (a human retyping it may not preserve
/// either).
pub fn parse_gate_recovery_code(input: &str) -> Result<[u8; GATE_RECOVERY_CODE_LEN], CryptoError> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if cleaned.len() != GATE_RECOVERY_CODE_LEN * 2 {
        return Err(CryptoError::InvalidGateRecoveryCode);
    }
    let mut code = [0u8; GATE_RECOVERY_CODE_LEN];
    for (i, byte) in code.iter_mut().enumerate() {
        let hex_byte = &cleaned[i * 2..i * 2 + 2];
        *byte =
            u8::from_str_radix(hex_byte, 16).map_err(|_| CryptoError::InvalidGateRecoveryCode)?;
    }
    Ok(code)
}

/// SHA-256 of a gate recovery code, for storage: the plaintext code is shown
/// exactly once at issuance (`07 §4`) and never persisted — the broker keeps
/// only this hash, one per code, and marks it consumed on first match.
pub fn hash_gate_recovery_code(code: &[u8; GATE_RECOVERY_CODE_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(code);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000; // arbitrary fixed epoch second, mid-2023

    #[test]
    fn code_at_the_same_step_is_deterministic() {
        let totp = Totp::new_gate(vec![1u8; GATE_SECRET_LEN]);
        assert_eq!(totp.code(T0), totp.code(T0));
    }

    #[test]
    fn code_is_six_digits_by_default() {
        let totp = Totp::new_gate(vec![1u8; GATE_SECRET_LEN]);
        assert_eq!(totp.code(T0).len(), 6);
        assert!(totp.code(T0).chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn a_code_from_a_different_secret_is_very_likely_different() {
        let a = Totp::new_gate(vec![1u8; GATE_SECRET_LEN]);
        let b = Totp::new_gate(vec![2u8; GATE_SECRET_LEN]);
        assert_ne!(a.code(T0), b.code(T0));
    }

    #[test]
    fn verify_accepts_the_current_code_and_returns_its_step() {
        let totp = Totp::new_gate(vec![9u8; GATE_SECRET_LEN]);
        let code = totp.code(T0);
        assert_eq!(totp.verify(&code, T0), Some(T0 / DEFAULT_PERIOD));
    }

    #[test]
    fn verify_accepts_one_step_of_skew_either_direction() {
        let totp = Totp::new_gate(vec![9u8; GATE_SECRET_LEN]);
        let code = totp.code(T0);
        assert!(totp.verify(&code, T0 + DEFAULT_PERIOD).is_some());
        assert!(totp.verify(&code, T0 - DEFAULT_PERIOD).is_some());
    }

    #[test]
    fn verify_rejects_two_steps_of_skew() {
        let totp = Totp::new_gate(vec![9u8; GATE_SECRET_LEN]);
        let code = totp.code(T0);
        assert_eq!(totp.verify(&code, T0 + 2 * DEFAULT_PERIOD), None);
        assert_eq!(totp.verify(&code, T0 - 2 * DEFAULT_PERIOD), None);
    }

    #[test]
    fn verify_rejects_a_wrong_code() {
        let totp = Totp::new_gate(vec![9u8; GATE_SECRET_LEN]);
        assert_eq!(totp.verify("000000", T0), None);
    }

    #[test]
    fn verify_rejects_a_code_from_a_different_secret() {
        let a = Totp::new_gate(vec![1u8; GATE_SECRET_LEN]);
        let b = Totp::new_gate(vec![2u8; GATE_SECRET_LEN]);
        let code = b.code(T0);
        assert_eq!(a.verify(&code, T0), None);
    }

    #[test]
    fn otpauth_uri_carries_the_secret_and_params() {
        let totp = Totp::new_gate(vec![9u8; GATE_SECRET_LEN]);
        let uri = totp.otpauth_uri("CredMgr", "global");
        assert!(uri.starts_with("otpauth://totp/CredMgr:global?"));
        assert!(uri.contains(&format!("secret={}", totp.secret_base32())));
        assert!(uri.contains("issuer=CredMgr"));
        assert!(uri.contains("period=30"));
        assert!(uri.contains("digits=6"));
    }

    #[test]
    fn items_may_use_eight_digits_and_a_stronger_algorithm() {
        let totp = Totp::new(vec![9u8; GATE_SECRET_LEN], TotpAlgorithm::Sha256, 8, 30);
        assert_eq!(totp.code(T0).len(), 8);
    }

    #[test]
    fn a_stored_item_secret_round_trips_through_base32_and_still_verifies() {
        let original = Totp::new(vec![3u8; GATE_SECRET_LEN], TotpAlgorithm::Sha1, 6, 30);
        let stored = original.secret_base32();
        let reloaded =
            Totp::from_stored_secret(&stored, TotpAlgorithm::Sha1, 6, 30).expect("decodes");
        assert_eq!(original.code(T0), reloaded.code(T0));
    }

    #[test]
    fn decoding_garbage_as_a_totp_secret_is_a_named_error_not_a_panic() {
        // Deliberately not `.unwrap_err()` — `Totp` holds a secret and does
        // not implement `Debug`, so it can never be accidentally formatted
        // into a log line; `matches!` needs no `Debug` bound.
        let result = Totp::from_stored_secret("not valid base32!!!", TotpAlgorithm::Sha1, 6, 30);
        assert!(matches!(result, Err(CryptoError::InvalidTotpSecret)));
    }

    /// ADR-077 (MX-1): the panic the endpoint matrix found. An 80-bit seed (16
    /// base32 characters) decodes fine and the engine this crate wraps refuses
    /// it; that refusal used to be an `expect` on the connection thread. The
    /// orchestrator's decision: an 80-bit seed is *accepted* (it is what many real
    /// services issue), anything below 80 bits is a typed refusal.
    #[test]
    fn an_80_bit_seed_is_accepted_and_fewer_bits_are_a_named_refusal() {
        let enc = |len: usize| {
            base32::encode(
                base32::Alphabet::Rfc4648 { padding: false },
                &vec![7u8; len],
            )
        };
        let eighty_bit = enc(10);
        assert_eq!(eighty_bit.len(), 16);
        let totp = Totp::from_stored_secret(&eighty_bit, TotpAlgorithm::Sha1, 6, 30)
            .unwrap_or_else(|_| panic!("an 80-bit seed must be usable"));
        let code = totp.code(T0);
        assert_eq!(code.len(), 6);
        assert_eq!(totp.verify(&code, T0), Some(T0 / DEFAULT_PERIOD));
        // 120 bits and the RFC's 128-bit floor work too.
        for len in [15, 16, 20, 32] {
            assert!(
                Totp::from_stored_secret(&enc(len), TotpAlgorithm::Sha1, 6, 30).is_ok(),
                "{len} bytes"
            );
        }
        // One byte under the floor, and the extremes, are typed refusals naming
        // the length.
        for (len, bits) in [(9, 72), (5, 40), (1, 8)] {
            let result = Totp::from_stored_secret(&enc(len), TotpAlgorithm::Sha1, 6, 30);
            assert!(
                matches!(result, Err(CryptoError::TotpSecretTooShort { bits: b }) if b == bits),
                "{len} bytes -> {bits} bits"
            );
        }
        // Known answer: the RFC 6238 SHA-1 test seed is 20 bytes, so the lower
        // floor changed nothing about how a code is derived. RFC 6238 Appendix B,
        // T = 59 s -> 94287082 (8 digits).
        let rfc = Totp::try_new(b"12345678901234567890".to_vec(), TotpAlgorithm::Sha1, 8, 30)
            .unwrap_or_else(|_| panic!("rfc seed"));
        assert_eq!(rfc.code(59), "94287082");
    }

    /// The whole input space `from_stored_secret` and `try_new` accept, swept: no
    /// combination panics, and `Ok` is returned exactly when the documented
    /// limits hold (6–8 digits, a period of at least a second, >= 80 bits).
    #[test]
    fn no_secret_length_digit_count_or_period_can_make_the_checked_constructors_panic() {
        for len in 0..40usize {
            for digits in 0..12usize {
                for period in [0u64, 1, 2, 30, 31, u64::MAX / 2, u64::MAX] {
                    let secret = vec![0x5Au8; len];
                    let should_work =
                        (6..=8).contains(&digits) && period >= 1 && len >= MIN_TOTP_SECRET_LEN;
                    let built = Totp::try_new(secret.clone(), TotpAlgorithm::Sha1, digits, period);
                    assert_eq!(
                        built.is_ok(),
                        should_work,
                        "len {len} digits {digits} period {period}"
                    );
                    if let Ok(totp) = built {
                        // And a built one never panics generating or verifying -
                        // not even at the edges of the clock.
                        for time in [0u64, T0, u64::MAX - 1, u64::MAX] {
                            let code = totp.code(time);
                            assert_eq!(code.len(), digits);
                            let _ = totp.verify(&code, time);
                            let _ = totp.verify("", time);
                            let _ = totp.verify("not a code", time);
                        }
                        let code = totp.code(T0);
                        assert!(totp.verify(&code, T0).is_some());
                        let _ = totp.otpauth_uri("CredMgr", "global");
                    }
                    let encoded =
                        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret);
                    let via_stored =
                        Totp::from_stored_secret(&encoded, TotpAlgorithm::Sha256, digits, period);
                    assert_eq!(via_stored.is_ok(), should_work && len > 0);
                }
            }
        }
        // Empty, whitespace-only, padding-only and non-ASCII stored values are an
        // invalid-secret error (or a too-short refusal), never a panic.
        for junk in [
            "",
            " ",
            "====",
            "\n\t",
            "-",
            "\u{0}",
            "é",
            "日本語",
            "A",
            "AA======",
        ] {
            let result = Totp::from_stored_secret(junk, TotpAlgorithm::Sha1, 6, 30);
            assert!(
                matches!(
                    result,
                    Err(CryptoError::InvalidTotpSecret | CryptoError::TotpSecretTooShort { .. })
                ),
                "{junk:?}"
            );
        }
        // A very long stored value is fine too (HMAC takes any key length).
        let long = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &[3u8; 4096]);
        assert!(Totp::from_stored_secret(&long, TotpAlgorithm::Sha512, 8, 30).is_ok());
    }

    /// A seed is whatever was pasted: padded, lower case, grouped by spaces or
    /// dashes — all decode to the same bytes as the bare form.
    #[test]
    fn a_stored_seed_may_be_padded_lower_case_or_grouped() {
        let bytes: Vec<u8> = (1..=16).collect();
        let bare = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes);
        let padded = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &bytes);
        assert!(padded.ends_with('='), "the control: 16 bytes need padding");
        let grouped: String = bare
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let dashed = grouped.replace(' ', "-");
        for form in [
            bare.clone(),
            padded,
            bare.to_lowercase(),
            grouped,
            dashed,
            format!("  {bare}\n"),
        ] {
            assert_eq!(decode_gate_secret_base32(&form).unwrap(), bytes, "{form:?}");
        }
        // Characters outside the alphabet are still an error.
        for bad in ["JBSWY3DP1", "JBSWY3DP!", "JBSW Y3D*", "0189"] {
            assert!(
                matches!(
                    decode_gate_secret_base32(bad),
                    Err(CryptoError::InvalidTotpSecret)
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn gate_recovery_codes_are_ten_and_distinct() {
        let codes = generate_gate_recovery_codes();
        assert_eq!(codes.len(), GATE_RECOVERY_CODE_COUNT);
        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), GATE_RECOVERY_CODE_COUNT, "no duplicate codes");
    }

    #[test]
    fn gate_recovery_code_format_parse_round_trip() {
        let codes = generate_gate_recovery_codes();
        let code = codes[0];
        let formatted = format_gate_recovery_code(&code);
        assert_eq!(parse_gate_recovery_code(&formatted).unwrap(), code);
    }

    #[test]
    fn gate_recovery_code_parse_accepts_lowercase_and_no_separators() {
        use std::fmt::Write;
        let code = generate_gate_recovery_codes()[0];
        let mut hex_lower = String::with_capacity(GATE_RECOVERY_CODE_LEN * 2);
        for b in &code {
            write!(hex_lower, "{b:02x}").unwrap();
        }
        assert_eq!(parse_gate_recovery_code(&hex_lower).unwrap(), code);
    }

    #[test]
    fn gate_recovery_code_parse_rejects_wrong_length() {
        let err = parse_gate_recovery_code("A1B2").unwrap_err();
        assert_eq!(err, CryptoError::InvalidGateRecoveryCode);
    }

    #[test]
    fn hashing_a_gate_recovery_code_is_deterministic_and_distinguishing() {
        let codes = generate_gate_recovery_codes();
        assert_eq!(
            hash_gate_recovery_code(&codes[0]),
            hash_gate_recovery_code(&codes[0])
        );
        assert_ne!(
            hash_gate_recovery_code(&codes[0]),
            hash_gate_recovery_code(&codes[1])
        );
    }
}
