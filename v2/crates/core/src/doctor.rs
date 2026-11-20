//! ADR-161 — the pure checks behind the doctor's tidy-up scan (`vault.doctor_scan`, doc 25, research memo 03
//! §3). Everything here works on a value the broker has already opened and **returns only a verdict**: a
//! digest under a key that lives for one scan, a reason code, a timestamp. Nothing here does I/O, keeps a
//! value, or touches the network; the broker decides what of a verdict may leave it.
//!
//! - [`ScanKey`] — HMAC-SHA256 under a key drawn from the OS for one scan and zeroised when dropped, so a
//!   digest means nothing after the scan and two scans' digests of one value differ.
//! - [`normalised`] — the "probable duplicate" form: trimmed, trailing newline dropped, a URL's scheme and
//!   host lowercased and its default port removed.
//! - [`skip_for_duplicates`] — values under 8 characters and well-known placeholders are not compared.
//! - [`weak_password`] — length, character kinds and common patterns, from a short built-in list (no
//!   wordlist download, no network).
//! - [`jwt_expiry`] — a JWT's `exp` claim, decoded offline.
//! - [`is_otpauth_uri`], [`key_environment`], [`name_environment`] — the "mistyped value" checks.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use base64::Engine as _;

/// A per-scan HMAC key. Drawn from the OS when the scan starts, zeroised when the scan drops it.
pub struct ScanKey {
    key: Zeroizing<[u8; 32]>,
}

impl ScanKey {
    /// A fresh key from the OS random source.
    #[must_use]
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        ScanKey { key }
    }

    /// HMAC-SHA256 of `bytes` under this scan's key.
    #[must_use]
    pub fn digest(&self, bytes: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.key.as_ref())
            .expect("HMAC accepts any key length");
        mac.update(bytes);
        mac.finalize().into_bytes().into()
    }
}

impl std::fmt::Debug for ScanKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScanKey(..)")
    }
}

/// The shortest value compared for duplicates (doc 25: shorter values collide by chance).
pub const DUPLICATE_MIN_CHARS: usize = 8;

/// Values that are placeholders, not secrets — never a duplicate finding.
const PLACEHOLDERS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "replaceme",
    "replace-me",
    "replace_me",
    "placeholder",
    "your-api-key",
    "your_api_key",
    "yourapikey",
    "your-key-here",
    "xxxxxxxx",
    "todo",
    "tbd",
    "none",
    "null",
    "undefined",
    "example",
    "password",
    "secret",
];

/// Whether `value` is left out of the duplicate check: shorter than [`DUPLICATE_MIN_CHARS`] once trimmed,
/// a known placeholder, or one character repeated (`xxxxxxxx`, `********`).
#[must_use]
pub fn skip_for_duplicates(value: &str) -> bool {
    let t = value.trim();
    if t.chars().count() < DUPLICATE_MIN_CHARS {
        return true;
    }
    let lower = t.to_lowercase();
    if PLACEHOLDERS.contains(&lower.as_str()) {
        return true;
    }
    let mut chars = t.chars();
    let first = chars.next();
    first.is_some_and(|c| chars.all(|d| d == c))
}

/// The "probable duplicate" form of a value: surrounding whitespace and a trailing newline dropped; for a
/// `scheme://host...` URL, the scheme and host lowercased and the scheme's default port (`:80` for http,
/// `:443` for https) removed. `None` when that is the value itself, so the caller compares it once.
#[must_use]
pub fn normalised(value: &str) -> Option<String> {
    let t = value.trim();
    let out = match url_parts(t) {
        Some((scheme, host, port, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            let host = host.to_lowercase();
            let default = matches!(
                (scheme.as_str(), port),
                ("http", Some("80")) | ("https", Some("443"))
            );
            match port {
                Some(p) if !default => format!("{scheme}://{host}:{p}{rest}"),
                _ => format!("{scheme}://{host}{rest}"),
            }
        }
        None => t.to_string(),
    };
    (out != value).then_some(out)
}

/// `(scheme, host, port, rest)` of a `scheme://[userinfo@]host[:port]rest` value; `None` for anything else.
fn url_parts(t: &str) -> Option<(&str, &str, Option<&str>, &str)> {
    let (scheme, after) = t.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        return None;
    }
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(end);
    // userinfo is part of the secret, so a URL with one is compared as written.
    if authority.contains('@') || authority.is_empty() || authority.starts_with('[') {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            Some((scheme, host, Some(port), rest))
        }
        Some(_) => None,
        None => Some((scheme, authority, None, rest)),
    }
}

/// Why a password is weak. The reason is a property of the value, never a part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeakReason {
    /// Fewer than [`WEAK_MIN_LEN`] characters.
    Short,
    /// Fewer than three of lower case, upper case, digits and symbols, and shorter than 16 characters.
    FewKinds,
    /// A common word, a keyboard or alphabet run, or one character repeated.
    CommonPattern,
}

impl WeakReason {
    /// The word the wire carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WeakReason::Short => "short",
            WeakReason::FewKinds => "few_character_kinds",
            WeakReason::CommonPattern => "common_pattern",
        }
    }
}

/// A password shorter than this is weak whatever it contains.
pub const WEAK_MIN_LEN: usize = 12;

/// Short, built-in: the most common password stems. Not a wordlist; nothing is downloaded.
const COMMON_WORDS: &[&str] = &[
    "password", "passwort", "passw0rd", "p@ssw0rd", "letmein", "welcome", "admin", "qwerty",
    "azerty", "iloveyou", "monkey", "dragon", "master", "sunshine", "princess", "football",
    "baseball", "shadow", "superman", "trustno1", "changeme", "secret", "login", "abc123",
    "111111", "123123", "000000",
];

/// Keyboard and alphabet rows a run is looked for in.
const RUNS: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "azertyuiop",
    "qwertzuiop",
];

/// The run length that counts as a pattern.
const RUN_LEN: usize = 4;

/// The reasons `value`, read as a password, is weak — empty when none applies. Heuristic: length, character
/// kinds, and common patterns (a common word, a run of four along a keyboard or alphabet row in either
/// direction, one character four times in a row). An empty value is not judged.
#[must_use]
pub fn weak_password(value: &str) -> Vec<WeakReason> {
    let len = value.chars().count();
    if len == 0 {
        return Vec::new();
    }
    let mut reasons = Vec::new();
    if len < WEAK_MIN_LEN {
        reasons.push(WeakReason::Short);
    }
    let kinds = [
        value.chars().any(|c| c.is_lowercase()),
        value.chars().any(|c| c.is_uppercase()),
        value.chars().any(|c| c.is_ascii_digit()),
        value.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|k| **k)
    .count();
    if kinds < 3 && len < 16 {
        reasons.push(WeakReason::FewKinds);
    }
    if has_common_pattern(value) {
        reasons.push(WeakReason::CommonPattern);
    }
    reasons
}

fn has_common_pattern(value: &str) -> bool {
    let lower: Zeroizing<String> = Zeroizing::new(value.to_lowercase());
    if COMMON_WORDS.iter().any(|w| lower.contains(w)) {
        return true;
    }
    let chars: Zeroizing<Vec<char>> = Zeroizing::new(lower.chars().collect());
    if chars.windows(RUN_LEN).any(|w| w.iter().all(|c| *c == w[0])) {
        return true;
    }
    chars.windows(RUN_LEN).any(|w| {
        let fwd: String = w.iter().collect();
        let rev: String = w.iter().rev().collect();
        let hit = RUNS
            .iter()
            .any(|row| row.contains(fwd.as_str()) || row.contains(rev.as_str()));
        let mut fwd = fwd;
        let mut rev = rev;
        zeroize::Zeroize::zeroize(&mut fwd);
        zeroize::Zeroize::zeroize(&mut rev);
        hit
    })
}

/// The `exp` claim of `value` read as a compact JWT (`header.payload.signature`, base64url), decoded
/// offline: the header must be a JSON object with an `alg`, the payload a JSON object whose `exp` is a
/// whole number of seconds. Anything else is `None`. The signature is not checked — the scan only asks
/// when the token says it stops working.
#[must_use]
pub fn jwt_expiry(value: &str) -> Option<i64> {
    let t = value.trim();
    if t.len() > 16 * 1024 {
        return None;
    }
    let mut parts = t.split('.');
    let (header, payload, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || header.is_empty() || payload.is_empty() {
        return None;
    }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = Zeroizing::new(engine.decode(header.trim_end_matches('=')).ok()?);
    let header: serde_json::Value = serde_json::from_slice(&header).ok()?;
    header.as_object()?.get("alg")?.as_str()?;
    let payload = Zeroizing::new(engine.decode(payload.trim_end_matches('=')).ok()?);
    let payload: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let exp = payload.as_object()?.get("exp")?;
    exp.as_i64().or_else(|| {
        exp.as_f64()
            .filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() < 1e15)
            .map(|f| f as i64)
    })
}

/// Whether `value` is a raw `otpauth://` URI (a 2FA seed with its issuer and settings, pasted whole).
#[must_use]
pub fn is_otpauth_uri(value: &str) -> bool {
    let t = value.trim_start();
    t.len() >= 10 && t[..10].eq_ignore_ascii_case("otpauth://")
}

/// Whether a key is a live one or a test one, by the prefix its issuer gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEnvironment {
    Live,
    Test,
}

/// Secret-key prefixes that say which environment a key belongs to (Stripe's secret and restricted keys,
/// the documented pair in memo 03 §3.1). A publishable key is not a secret and is not judged.
const LIVE_PREFIXES: &[&str] = &["sk_live_", "rk_live_"];
const TEST_PREFIXES: &[&str] = &["sk_test_", "rk_test_"];

/// The environment `value`'s prefix names, if it carries one of the known prefixes.
#[must_use]
pub fn key_environment(value: &str) -> Option<KeyEnvironment> {
    let t = value.trim_start();
    if LIVE_PREFIXES.iter().any(|p| t.starts_with(p)) {
        Some(KeyEnvironment::Live)
    } else if TEST_PREFIXES.iter().any(|p| t.starts_with(p)) {
        Some(KeyEnvironment::Test)
    } else {
        None
    }
}

/// The environment a node or entry name says it is for, by a whole word in it (`test`, `testing`,
/// `sandbox` → test; `prod`, `production`, `live` → live). `None` when it says neither, or both.
#[must_use]
pub fn name_environment(name: &str) -> Option<KeyEnvironment> {
    let lower = name.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let test = words
        .iter()
        .any(|w| matches!(*w, "test" | "testing" | "sandbox"));
    let live = words
        .iter()
        .any(|w| matches!(*w, "prod" | "production" | "live"));
    match (test, live) {
        (true, false) => Some(KeyEnvironment::Test),
        (false, true) => Some(KeyEnvironment::Live),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.c2ln",
            e.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
            e.encode(payload.as_bytes())
        )
    }

    #[test]
    fn two_keys_digest_one_value_differently_and_one_key_is_stable() {
        let (a, b) = (ScanKey::generate(), ScanKey::generate());
        assert_eq!(a.digest(b"value-1234"), a.digest(b"value-1234"));
        assert_ne!(a.digest(b"value-1234"), b.digest(b"value-1234"));
        assert_ne!(a.digest(b"value-1234"), a.digest(b"value-1235"));
        assert_eq!(format!("{a:?}"), "ScanKey(..)");
    }

    #[test]
    fn short_values_and_placeholders_are_not_compared() {
        assert!(skip_for_duplicates("short"));
        assert!(skip_for_duplicates("  changeme  "));
        assert!(skip_for_duplicates("xxxxxxxxxxxx"));
        assert!(skip_for_duplicates("PLACEHOLDER"));
        assert!(!skip_for_duplicates("a-real-looking-secret"));
    }

    #[test]
    fn normalising_trims_and_lowercases_a_urls_host_and_drops_its_default_port() {
        assert_eq!(normalised("abc\n").as_deref(), Some("abc"));
        assert_eq!(normalised("abc"), None);
        assert_eq!(
            normalised("HTTPS://Example.COM:443/Path?Q=1").as_deref(),
            Some("https://example.com/Path?Q=1")
        );
        assert_eq!(
            normalised("http://Host:8080/x").as_deref(),
            Some("http://host:8080/x")
        );
        // userinfo is part of the secret: left as written.
        assert_eq!(normalised(concat!("https://User", ":Pw@Host/")), None);
    }

    #[test]
    fn weak_passwords_are_judged_by_length_kinds_and_patterns() {
        assert!(weak_password("Xk7#pQ2!mZ9@vL4$").is_empty());
        let r = weak_password("abc");
        assert!(r.contains(&WeakReason::Short) && r.contains(&WeakReason::FewKinds));
        assert!(weak_password("MyPassword!2024xyz").contains(&WeakReason::CommonPattern));
        assert!(weak_password("Zz9!qwerXk7#pQ2").contains(&WeakReason::CommonPattern));
        assert!(weak_password("Zz9!aaaaXk7#pQ2").contains(&WeakReason::CommonPattern));
        assert!(weak_password("Zz9!4321Xk7#pQ2").contains(&WeakReason::CommonPattern));
        assert!(weak_password("").is_empty());
    }

    #[test]
    fn a_jwt_exp_is_read_and_anything_else_is_not() {
        assert_eq!(
            jwt_expiry(&jwt(r#"{"sub":"x","exp":1700000000}"#)),
            Some(1_700_000_000)
        );
        assert_eq!(jwt_expiry(&jwt(r#"{"sub":"x"}"#)), None);
        assert_eq!(jwt_expiry(&jwt(r#"{"exp":"soon"}"#)), None);
        assert_eq!(jwt_expiry("not.a.jwt"), None);
        assert_eq!(jwt_expiry("a.b"), None);
        assert_eq!(jwt_expiry("plain-secret"), None);
    }

    #[test]
    fn mistyped_values_are_recognised() {
        assert!(is_otpauth_uri("OTPAUTH://totp/x?secret=ABC"));
        assert!(!is_otpauth_uri("JBSWY3DPEHPK3PXP"));
        assert_eq!(key_environment("sk_live_abc"), Some(KeyEnvironment::Live));
        assert_eq!(key_environment("rk_test_abc"), Some(KeyEnvironment::Test));
        assert_eq!(key_environment("pk_live_abc"), None);
        assert_eq!(name_environment("stripe-test"), Some(KeyEnvironment::Test));
        assert_eq!(name_environment("Prod API"), Some(KeyEnvironment::Live));
        assert_eq!(name_environment("contest"), None);
        assert_eq!(name_environment("test-to-prod"), None);
    }
}
