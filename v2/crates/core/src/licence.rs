//! Offline licence certificates and the tier → entitlement table (ADR-153, `docs/26_PRODUCT_PLAN_2X.md §5`).
//!
//! A licence is a small JSON payload signed offline with an ECDSA P-256 key the publisher keeps off every
//! networked machine. The app carries only the public keys. Checking a licence needs no network, no
//! account and no server: [`verify`] takes the token, the key ring, the clock, this device's fingerprint
//! and the build date of the running app, and returns a [`LicenceState`].
//!
//! **A licence never touches the vault (ADR-095 item 4, ADR-096 item 3).** Every state that is not
//! [`LicenceState::Licensed`] maps to the [`Tier::Free`] entitlements, and the Free tier is the whole vault:
//! unlock, read, write, every security control, the CLI, the local MCP server, export and backup. A tier
//! only adds conveniences (see [`entitlements`]). Nothing in this module can lock, refuse or degrade
//! access to a user's own data, and no caller may use a [`LicenceState`] to do so.
//!
//! **One-time payment.** A licence has no expiry by default. It carries `updatesUntil`: the licence keeps
//! working forever for every build released on or before that date. A build released later reports
//! [`LicenceState::UpgradeRequired`] (Free entitlements) until the holder buys an upgrade; the older
//! build they already have keeps working.
//!
//! **App Store builds** do not use this token: Apple's StoreKit verifies the purchase on the device, and
//! the shell maps the product id to a tier with [`tier_for_store_product`]. Both paths end in the same
//! [`entitlements`] table, so the two builds can never disagree about what a tier includes.
//!
//! Pure compute like the rest of `credmgr-core`: byte formats, a verifier and the table. Reading the token
//! from disk, reading the platform's machine id and showing the state are the shell's job (ADR-095 item 6:
//! the check lives in the shell, never in the page or the broker).

use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The token's first dot-separated part. A later format gets a new prefix; this verifier refuses it.
pub const TOKEN_PREFIX: &str = "CMLIC1";
/// Domain separation: no other signature the publisher's key makes is valid as a licence.
pub const DOMAIN: &[u8] = b"credmgr/v2/licence/v1\0";
/// Domain separation for the device fingerprint.
pub const FINGERPRINT_DOMAIN: &[u8] = b"credmgr/v2/device-fingerprint/v1\0";
/// The only payload version this verifier reads.
pub const PAYLOAD_VERSION: u32 = 1;
/// Largest token accepted, so a hostile file cannot make the verifier allocate without bound.
pub const MAX_TOKEN_LEN: usize = 8 * 1024;
/// Tolerated clock skew for `issuedAt` in the future (a licence issued "tomorrow" by a fast clock).
pub const CLOCK_SKEW_SECS: u64 = 24 * 60 * 60;
/// Most personal devices a [`Tier::Plus`] licence may name. "All your devices", with a ceiling that
/// stops one licence from being shared across an office.
pub const PLUS_DEVICE_LIMIT: u32 = 10;

/// App Store product ids (non-consumable in-app purchases), one per paid tier.
pub const STORE_PRODUCT_SOLO: &str = "com.credmgr.desktop.licence.solo";
pub const STORE_PRODUCT_PLUS: &str = "com.credmgr.desktop.licence.plus";
pub const STORE_PRODUCT_TEAM: &str = "com.credmgr.desktop.licence.team";

/// The four tiers. `Free` is the whole vault; each paid tier adds conveniences to the one before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// No licence. The complete vault on any number of machines, each its own vault.
    Free,
    /// One-time licence for one device.
    Solo,
    /// One-time licence for all of one person's devices (up to [`PLUS_DEVICE_LIMIT`]).
    Plus,
    /// One-time licence per seat for a team sharing nodes.
    Team,
}

impl Tier {
    /// The word a person reads.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Tier::Free => "Free",
            Tier::Solo => "Solo",
            Tier::Plus => "Plus",
            Tier::Team => "Team",
        }
    }
}

/// A convenience a paid tier adds. There is deliberately no entitlement for unlocking, reading, writing,
/// exporting, backing up or any security control: those are never sold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Entitlement {
    /// The doctor applies its tidy-up plans in one step (merge, move, alias, share). The scan and its
    /// report are free.
    DoctorApply,
    /// The opt-in offline/k-anonymous breached-password check.
    BreachCheck,
    /// Scheduled encrypted backups to a folder the user picks (a one-off backup is always free).
    ScheduledBackup,
    /// The supporter extras: app icons, accent colours, themes (ADR-082).
    Extras,
    /// End-to-end-encrypted sync between the holder's own devices.
    Sync,
    /// The optional connector that lets cloud assistants use credentials without receiving them.
    RemoteAgents,
    /// The phone companion (approve requests, read entries).
    MobileCompanion,
    /// Shared team nodes with member roles.
    TeamVault,
    /// Team audit export and policy templates.
    TeamAdmin,
}

/// What each tier includes. Cumulative: each tier holds everything the one below it holds.
#[must_use]
pub fn entitlements(tier: Tier) -> BTreeSet<Entitlement> {
    use Entitlement::*;
    let solo = [DoctorApply, BreachCheck, ScheduledBackup, Extras];
    let plus = [Sync, RemoteAgents, MobileCompanion];
    let team = [TeamVault, TeamAdmin];
    let mut set = BTreeSet::new();
    if tier >= Tier::Solo {
        set.extend(solo);
    }
    if tier >= Tier::Plus {
        set.extend(plus);
    }
    if tier >= Tier::Team {
        set.extend(team);
    }
    set
}

/// The tier an App Store product id buys, or `None` for an id this build does not know.
#[must_use]
pub fn tier_for_store_product(product_id: &str) -> Option<Tier> {
    match product_id {
        STORE_PRODUCT_SOLO => Some(Tier::Solo),
        STORE_PRODUCT_PLUS => Some(Tier::Plus),
        STORE_PRODUCT_TEAM => Some(Tier::Team),
        _ => None,
    }
}

/// The signed part of a licence. Field names are the wire names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LicencePayload {
    /// Always [`PAYLOAD_VERSION`].
    pub v: u32,
    /// The publisher's licence id (for support and revocation lists).
    pub id: String,
    /// The tier bought.
    pub tier: Tier,
    /// Who it was sold to, for display only ("Licensed to …"). Never used as authority.
    pub holder: String,
    /// Seats (Team) — 1 for Solo and Plus.
    pub seats: u32,
    /// Device fingerprints ([`device_fingerprint`]) this licence is bound to. Solo: exactly one. Plus: up
    /// to [`PLUS_DEVICE_LIMIT`]. Team: empty (seats are counted by the team vault, not per machine).
    #[serde(default)]
    pub devices: Vec<String>,
    /// The vault's licence identity (hex SEC1 public key) this licence is bound to, so it follows the
    /// person through sync, backup and restore instead of naming machines. `None` for a device-bound
    /// licence. A copied token fails in anyone else's vault.
    #[serde(default)]
    pub holder_key: Option<String>,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds: builds released on or before this date are covered forever.
    pub updates_until: u64,
    /// Unix seconds, or `None` for a perpetual (one-time) licence.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Which publisher key signed it (key rotation without breaking old licences).
    pub key_id: String,
}

/// Why a token was refused. A refused token is the Free tier, nothing worse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidReason {
    /// Not `CMLIC1.<payload>.<signature>`, bad base64, too long, or not the expected JSON.
    Malformed,
    /// A payload version or tier shape this build does not read.
    Unsupported,
    /// `keyId` is not in this build's key ring.
    UnknownKey,
    /// The signature does not verify.
    BadSignature,
    /// The payload contradicts itself (a Solo licence naming two devices, zero seats …).
    Inconsistent,
    /// Issued in the future beyond [`CLOCK_SKEW_SECS`] — a clock set back, or a forged date.
    NotYetValid,
}

/// The result of checking a licence on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenceState {
    /// No licence installed.
    Unlicensed,
    /// Valid here.
    Licensed(LicencePayload),
    /// Valid signature, but this build was released after `updatesUntil`.
    UpgradeRequired(LicencePayload),
    /// Valid signature, but past `expiresAt`.
    Expired(LicencePayload),
    /// Valid signature, but this device is not one of the licence's devices.
    WrongDevice(LicencePayload),
    /// Valid signature, but bound to another vault's licence identity.
    WrongHolder(LicencePayload),
    /// The token was refused.
    Invalid(InvalidReason),
}

impl LicenceState {
    /// The tier in force. Anything but `Licensed` is Free.
    #[must_use]
    pub fn effective_tier(&self) -> Tier {
        match self {
            LicenceState::Licensed(p) => p.tier,
            _ => Tier::Free,
        }
    }

    /// The entitlements in force.
    #[must_use]
    pub fn entitlements(&self) -> BTreeSet<Entitlement> {
        entitlements(self.effective_tier())
    }

    /// A stable word for the shell and the page (`"licensed"`, `"upgradeRequired"` …).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            LicenceState::Unlicensed => "unlicensed",
            LicenceState::Licensed(_) => "licensed",
            LicenceState::UpgradeRequired(_) => "upgradeRequired",
            LicenceState::Expired(_) => "expired",
            LicenceState::WrongDevice(_) => "wrongDevice",
            LicenceState::WrongHolder(_) => "wrongHolder",
            LicenceState::Invalid(_) => "invalid",
        }
    }
}

/// `hex(SHA-256(FINGERPRINT_DOMAIN ‖ platform_id))`. The platform id (macOS `IOPlatformUUID`, Windows
/// `MachineGuid`, Linux `/etc/machine-id`) never leaves the device in the clear; the licence names only
/// this hash.
#[must_use]
pub fn device_fingerprint(platform_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(FINGERPRINT_DOMAIN);
    h.update(platform_id.trim().as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn signed_message(payload_bytes: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + payload_bytes.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(payload_bytes);
    m
}

fn consistent(p: &LicencePayload) -> bool {
    if p.v != PAYLOAD_VERSION || p.id.is_empty() || p.key_id.is_empty() {
        return false;
    }
    let devices_ok = p
        .devices
        .iter()
        .all(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()));
    if !devices_ok {
        return false;
    }
    match p.tier {
        Tier::Free => false,
        Tier::Solo => p.seats == 1 && p.devices.len() == 1,
        Tier::Plus => {
            p.seats == 1
                && (p.holder_key.is_some() || !p.devices.is_empty())
                && p.devices.len() as u64 <= u64::from(PLUS_DEVICE_LIMIT)
        }
        Tier::Team => p.seats >= 1 && p.devices.is_empty(),
    }
}

/// Sign a payload into a token. Used by the publisher's offline issuer and by tests; the app never holds
/// a signing key.
///
/// # Errors
/// Returns [`InvalidReason::Inconsistent`] for a payload [`verify`] would refuse anyway.
pub fn issue(signing_key: &SigningKey, payload: &LicencePayload) -> Result<String, InvalidReason> {
    if !consistent(payload) {
        return Err(InvalidReason::Inconsistent);
    }
    let bytes = serde_json::to_vec(payload).map_err(|_| InvalidReason::Malformed)?;
    let sig: Signature = signing_key.sign(&signed_message(&bytes));
    Ok(format!(
        "{TOKEN_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(&bytes),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    ))
}

/// Check a licence token on this device.
///
/// * `keys` — the publisher key ring: `(keyId, SEC1 public key bytes)`.
/// * `now` — unix seconds from the device clock.
/// * `this_device` — [`device_fingerprint`] of this device.
/// * `this_holder` — this vault's licence identity (hex), when it has one.
/// * `build_date` — unix seconds when the running build was released (baked in at build time).
///
/// `None` for `token` is [`LicenceState::Unlicensed`]. Never panics on hostile input.
#[must_use]
pub fn verify(
    token: Option<&str>,
    keys: &[(&str, &[u8])],
    now: u64,
    this_device: &str,
    this_holder: Option<&str>,
    build_date: u64,
) -> LicenceState {
    let Some(token) = token.map(str::trim) else {
        return LicenceState::Unlicensed;
    };
    if token.is_empty() {
        return LicenceState::Unlicensed;
    }
    let payload = match check_signature(token, keys) {
        Ok(p) => p,
        Err(r) => return LicenceState::Invalid(r),
    };
    if payload.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
        return LicenceState::Invalid(InvalidReason::NotYetValid);
    }
    if payload.expires_at.is_some_and(|e| now > e) {
        return LicenceState::Expired(payload);
    }
    if !payload.devices.is_empty()
        && !payload
            .devices
            .iter()
            .any(|d| d.eq_ignore_ascii_case(this_device))
    {
        return LicenceState::WrongDevice(payload);
    }
    if let Some(bound) = payload.holder_key.as_deref() {
        if !this_holder.is_some_and(|h| h.eq_ignore_ascii_case(bound)) {
            return LicenceState::WrongHolder(payload);
        }
    }
    if build_date > payload.updates_until {
        return LicenceState::UpgradeRequired(payload);
    }
    LicenceState::Licensed(payload)
}

fn check_signature(token: &str, keys: &[(&str, &[u8])]) -> Result<LicencePayload, InvalidReason> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(InvalidReason::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(prefix), Some(body), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(InvalidReason::Malformed);
    };
    if prefix != TOKEN_PREFIX {
        return Err(InvalidReason::Unsupported);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| InvalidReason::Malformed)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| InvalidReason::Malformed)?;
    // Read the key id before trusting anything else, so an unknown key is reported as such.
    let raw: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| InvalidReason::Malformed)?;
    if raw.get("v").and_then(serde_json::Value::as_u64) != Some(u64::from(PAYLOAD_VERSION)) {
        return Err(InvalidReason::Unsupported);
    }
    let key_id = raw
        .get("keyId")
        .and_then(serde_json::Value::as_str)
        .ok_or(InvalidReason::Malformed)?;
    let key_bytes = keys
        .iter()
        .find(|(id, _)| *id == key_id)
        .map(|(_, k)| *k)
        .ok_or(InvalidReason::UnknownKey)?;
    let key = VerifyingKey::from_sec1_bytes(key_bytes).map_err(|_| InvalidReason::UnknownKey)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| InvalidReason::BadSignature)?;
    key.verify(&signed_message(&bytes), &signature)
        .map_err(|_| InvalidReason::BadSignature)?;
    // Only a signed payload is parsed strictly.
    let payload: LicencePayload =
        serde_json::from_slice(&bytes).map_err(|_| InvalidReason::Unsupported)?;
    if !consistent(&payload) {
        return Err(InvalidReason::Inconsistent);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_793_000_000;

    fn key() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        (sk, pk)
    }

    fn payload(tier: Tier, devices: Vec<String>) -> LicencePayload {
        LicencePayload {
            v: 1,
            id: "L-0001".into(),
            tier,
            holder: "test holder".into(),
            seats: 1,
            devices,
            holder_key: None,
            issued_at: NOW - DAY,
            updates_until: NOW + 365 * DAY,
            expires_at: None,
            key_id: "k1".into(),
        }
    }

    fn here() -> String {
        device_fingerprint("TEST-PLATFORM-UUID-A")
    }

    #[test]
    fn free_is_empty_and_tiers_are_cumulative() {
        assert!(entitlements(Tier::Free).is_empty());
        let s = entitlements(Tier::Solo);
        let p = entitlements(Tier::Plus);
        let t = entitlements(Tier::Team);
        assert!(s.is_subset(&p) && p.is_subset(&t));
        assert!(s.contains(&Entitlement::DoctorApply) && !s.contains(&Entitlement::Sync));
        assert!(p.contains(&Entitlement::Sync) && !p.contains(&Entitlement::TeamVault));
        assert!(t.contains(&Entitlement::TeamVault));
    }

    #[test]
    fn a_valid_solo_licence_on_its_device_is_licensed() {
        let (sk, pk) = key();
        let tok = issue(&sk, &payload(Tier::Solo, vec![here()])).unwrap();
        let st = verify(Some(&tok), &[("k1", &pk)], NOW, &here(), None, NOW);
        assert_eq!(st.code(), "licensed");
        assert_eq!(st.effective_tier(), Tier::Solo);
    }

    #[test]
    fn every_failure_is_the_free_tier() {
        let (sk, pk) = key();
        let (_, other_pk) = key();
        let tok = issue(&sk, &payload(Tier::Plus, vec![here()])).unwrap();
        let keys: &[(&str, &[u8])] = &[("k1", &pk)];
        let cases = [
            verify(None, keys, NOW, &here(), None, NOW),
            verify(Some(&tok), &[("k1", &other_pk)], NOW, &here(), None, NOW),
            verify(Some(&tok), &[("k2", &pk)], NOW, &here(), None, NOW),
            verify(
                Some(&tok),
                keys,
                NOW,
                &device_fingerprint("ANOTHER-MAC"),
                None,
                NOW,
            ),
            verify(Some(&tok), keys, NOW, &here(), None, NOW + 2 * 365 * DAY),
            verify(Some("CMLIC1.garbage"), keys, NOW, &here(), None, NOW),
            verify(
                Some(&"x".repeat(MAX_TOKEN_LEN + 1)),
                keys,
                NOW,
                &here(),
                None,
                NOW,
            ),
        ];
        for st in &cases {
            assert_eq!(st.effective_tier(), Tier::Free, "{st:?}");
            assert!(st.entitlements().is_empty());
        }
        assert_eq!(cases[0], LicenceState::Unlicensed);
        assert_eq!(cases[1], LicenceState::Invalid(InvalidReason::BadSignature));
        assert_eq!(cases[2], LicenceState::Invalid(InvalidReason::UnknownKey));
        assert_eq!(cases[3].code(), "wrongDevice");
        assert_eq!(cases[4].code(), "upgradeRequired");
    }

    #[test]
    fn a_tampered_payload_fails_the_signature() {
        let (sk, pk) = key();
        let tok = issue(&sk, &payload(Tier::Solo, vec![here()])).unwrap();
        let parts: Vec<&str> = tok.split('.').collect();
        let mut p: LicencePayload =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        p.tier = Tier::Team;
        p.devices.clear();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&p).unwrap()),
            parts[2]
        );
        assert_eq!(
            verify(Some(&forged), &[("k1", &pk)], NOW, &here(), None, NOW),
            LicenceState::Invalid(InvalidReason::BadSignature)
        );
    }

    #[test]
    fn the_signature_is_domain_separated() {
        let (sk, pk) = key();
        let p = payload(Tier::Solo, vec![here()]);
        let bytes = serde_json::to_vec(&p).unwrap();
        // A signature over the bare payload (no domain) must not verify.
        let sig: Signature = sk.sign(&bytes);
        let tok = format!(
            "{TOKEN_PREFIX}.{}.{}",
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );
        assert_eq!(
            verify(Some(&tok), &[("k1", &pk)], NOW, &here(), None, NOW),
            LicenceState::Invalid(InvalidReason::BadSignature)
        );
    }

    #[test]
    fn an_old_build_keeps_working_after_the_update_window() {
        let (sk, pk) = key();
        let tok = issue(&sk, &payload(Tier::Solo, vec![here()])).unwrap();
        // Ten years later, the build they bought still works …
        let st = verify(
            Some(&tok),
            &[("k1", &pk)],
            NOW + 3650 * DAY,
            &here(),
            None,
            NOW,
        );
        assert_eq!(st.code(), "licensed");
        // … a build released after `updatesUntil` asks for an upgrade.
        let st = verify(
            Some(&tok),
            &[("k1", &pk)],
            NOW + 3650 * DAY,
            &here(),
            None,
            NOW + 400 * DAY,
        );
        assert_eq!(st.code(), "upgradeRequired");
    }

    #[test]
    fn expiry_and_future_issue_are_enforced() {
        let (sk, pk) = key();
        let mut p = payload(Tier::Team, vec![]);
        p.seats = 5;
        p.expires_at = Some(NOW + DAY);
        let tok = issue(&sk, &p).unwrap();
        assert_eq!(
            verify(Some(&tok), &[("k1", &pk)], NOW, "", None, NOW).code(),
            "licensed"
        );
        assert_eq!(
            verify(Some(&tok), &[("k1", &pk)], NOW + 2 * DAY, "", None, NOW).code(),
            "expired"
        );
        p.expires_at = None;
        p.issued_at = NOW + 3 * DAY;
        let tok = issue(&sk, &p).unwrap();
        assert_eq!(
            verify(Some(&tok), &[("k1", &pk)], NOW, "", None, NOW),
            LicenceState::Invalid(InvalidReason::NotYetValid)
        );
    }

    #[test]
    fn inconsistent_payloads_cannot_be_issued() {
        let (sk, _) = key();
        let two = vec![here(), device_fingerprint("B")];
        assert!(issue(&sk, &payload(Tier::Solo, two)).is_err());
        assert!(issue(&sk, &payload(Tier::Free, vec![here()])).is_err());
        assert!(issue(&sk, &payload(Tier::Team, vec![here()])).is_err());
        let many = (0..=PLUS_DEVICE_LIMIT)
            .map(|i| device_fingerprint(&i.to_string()))
            .collect();
        assert!(issue(&sk, &payload(Tier::Plus, many)).is_err());
        assert!(issue(&sk, &payload(Tier::Plus, vec!["not-hex".into()])).is_err());
    }

    #[test]
    fn a_holder_bound_plus_licence_follows_the_vault_not_the_machine() {
        let (sk, pk) = key();
        let mut p = payload(Tier::Plus, vec![]);
        p.holder_key = Some("ab".repeat(33));
        let tok = issue(&sk, &p).unwrap();
        let keys: &[(&str, &[u8])] = &[("k1", &pk)];
        let mine = "AB".repeat(33);
        // Any machine, the same vault identity: licensed.
        let st = verify(
            Some(&tok),
            keys,
            NOW,
            &device_fingerprint("ANY-MAC"),
            Some(&mine),
            NOW,
        );
        assert_eq!(st.code(), "licensed");
        // Someone else's vault, or no identity: free.
        assert_eq!(
            verify(Some(&tok), keys, NOW, &here(), Some(&"cd".repeat(33)), NOW).code(),
            "wrongHolder"
        );
        assert_eq!(
            verify(Some(&tok), keys, NOW, &here(), None, NOW).effective_tier(),
            Tier::Free
        );
    }

    #[test]
    fn store_products_map_to_tiers() {
        assert_eq!(tier_for_store_product(STORE_PRODUCT_SOLO), Some(Tier::Solo));
        assert_eq!(tier_for_store_product(STORE_PRODUCT_PLUS), Some(Tier::Plus));
        assert_eq!(tier_for_store_product(STORE_PRODUCT_TEAM), Some(Tier::Team));
        assert_eq!(tier_for_store_product("com.example.other"), None);
    }

    #[test]
    fn fingerprint_is_stable_hex_and_trims() {
        let a = device_fingerprint("ABC");
        assert_eq!(a.len(), 64);
        assert_eq!(a, device_fingerprint("  ABC\n"));
        assert_ne!(a, device_fingerprint("ABD"));
    }

    #[test]
    fn wire_names_are_camel_case() {
        let json = serde_json::to_string(&payload(Tier::Plus, vec![here()])).unwrap();
        for k in [
            "\"issuedAt\"",
            "\"updatesUntil\"",
            "\"keyId\"",
            "\"tier\":\"plus\"",
        ] {
            assert!(json.contains(k), "{k} missing in {json}");
        }
    }
}
