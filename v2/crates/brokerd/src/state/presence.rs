//! ADR-098 — presence attestation and the Touch ID unlock, on the broker side.
//!
//! **Presence.** A presence-gated op is asked in two steps. The client calls `presence.challenge` naming
//! the op and its exact params; the broker answers with a single-use nonce and the digest to sign
//! (`credmgr_core::presence::digest`). The client has the user's Secure Enclave key sign that digest —
//! which only happens after Touch ID or the device password — and repeats the request with
//! `params.presence = {nonce, signature}`. [`BrokerState::presence_attest`] re-derives the digest from
//! the request it actually received, finds the nonce, checks it is unexpired and was issued for this op
//! and this session, verifies the signature against an enrolled key, and burns the nonce. Nothing the
//! client says about itself is believed: not "I touched the sensor", not "this is the same request".
//!
//! **Touch ID unlock.** `keys/root.wrap.se` holds the root key sealed to a Secure Enclave key. Opening it
//! is `credmgr_keystore::secure_enclave::open_with_helper`, which makes the user authenticate. The result
//! is a root key like any other and goes through the same [`BrokerState::complete_unlock`] as the
//! passphrase path, so the registry HMAC, the rollback counter and the second-factor gate all still apply.

use secrecy::ExposeSecret;
use serde_json::Value;
use sha2::{Digest, Sha256};

use credmgr_core::presence as core_presence;
use credmgr_keystore::secure_enclave::{self, Helper, Purpose};
use credmgr_keystore::KeystoreError;
use credmgr_store::presence_file::{self, DeviceWrap, PresenceKeyRecord};

use super::durable::UnlockError;
use super::BrokerState;

/// How long a challenge lives. The user has to find a finger, not write a letter.
pub const CHALLENGE_TTL_SECONDS: i64 = 60;
/// Challenges outstanding at once, so a client that never answers cannot grow the table without bound.
const CHALLENGE_CAP: usize = 64;
const KEY_CAP: usize = 8;

/// An issued, not yet used challenge.
#[derive(Debug, Clone)]
pub struct PresenceChallenge {
    op: String,
    /// The session it was issued to (the token's public id); a proof cannot be moved between sessions.
    session: String,
    expires_at: i64,
}

/// Why presence could not be checked. Maps onto the wire's `presence_failed` reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceDenied {
    /// No presence key is enrolled on this vault.
    NotEnrolled,
    /// No `presence` object in the params.
    Missing,
    /// Unknown, expired, already used, or issued for another op or session.
    Expired,
    /// The signature does not verify against any enrolled key.
    Invalid,
}

impl PresenceDenied {
    pub fn reason(self) -> &'static str {
        match self {
            PresenceDenied::NotEnrolled => "not_enrolled",
            PresenceDenied::Missing => "missing",
            PresenceDenied::Expired => "expired",
            PresenceDenied::Invalid => "invalid",
        }
    }
}

/// What the broker tells a client that asked for a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    pub nonce: [u8; core_presence::NONCE_LEN],
    pub digest: [u8; 32],
    pub expires_in: i64,
}

/// Remove `presence` from a params object, returning the rest — what the digest is computed over.
pub fn without_presence(params: &Value) -> Value {
    match params {
        Value::Object(map) => {
            let mut rest = map.clone();
            rest.remove("presence");
            Value::Object(rest)
        }
        other => other.clone(),
    }
}

/// ADR-148 §P2-4: the op a proof-of-possession challenge is issued for. Not a broker op (nothing dispatches
/// it), so a possession proof can never be replayed as a presence proof for `presence.enrol` or anything else.
pub const POSSESSION_OP: &str = "presence.enrol#possession";

/// Remove both proofs from a params object: what a proof of possession is computed over.
pub fn without_proofs(params: &Value) -> Value {
    match without_presence(params) {
        Value::Object(mut map) => {
            map.remove("possession");
            Value::Object(map)
        }
        other => other,
    }
}

fn decode_proof(proof: &Value) -> Option<([u8; core_presence::NONCE_LEN], Vec<u8>)> {
    let nonce = proof
        .get("nonce")
        .and_then(Value::as_str)
        .and_then(|s| base64::Engine::decode(&b64(), s).ok())
        .and_then(|v| <[u8; core_presence::NONCE_LEN]>::try_from(v).ok())?;
    let signature = proof
        .get("signature")
        .and_then(Value::as_str)
        .and_then(|s| base64::Engine::decode(&b64(), s).ok())?;
    Some((nonce, signature))
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn key_id(public: &[u8]) -> String {
    let h = Sha256::digest(public);
    super::hex_encode(&h[..8])
}

impl BrokerState {
    /// The enrolled presence keys (public, non-secret).
    pub fn presence_keys(&self) -> Vec<PresenceKeyRecord> {
        self.presence_keys
            .read()
            .expect("presence keys poisoned")
            .clone()
    }

    /// Replace the in-memory list (the loader, after it verified the file).
    pub(super) fn set_presence_keys(&self, keys: Vec<PresenceKeyRecord>) {
        *self.presence_keys.write().expect("presence keys poisoned") = keys;
    }

    /// Write `keys/presence.enroll` (kept for an older daemon and for the rotation that re-signs it). The list
    /// that counts is the one in the signed registry (ADR-148 §P2-4): `presence.enrol` / `presence.unenrol`
    /// are persisted ops, so the registry write that follows them carries the new list.
    fn save_presence_keys(&self, keys: &[PresenceKeyRecord]) -> Result<(), String> {
        if !self.is_durable() {
            return Ok(());
        }
        let root = self.session_root.read().expect("session root poisoned");
        let root = root
            .as_ref()
            .ok_or_else(|| "the vault is locked".to_string())?;
        presence_file::save_presence(&self.paths, root.expose_secret(), keys)
            .map_err(|e| e.to_string())
    }

    /// Enrol a presence public key (an uncompressed P-256 point). The caller has already checked who is
    /// asking; this checks the key is a real point and the list stays small.
    pub fn presence_enrol(
        &self,
        public: &[u8],
        label: &str,
        now: i64,
    ) -> Result<PresenceKeyRecord, String> {
        if public.len() != core_presence::PUBLIC_LEN {
            return Err("a presence key is a 65-byte uncompressed P-256 point".into());
        }
        // A key that is not a point on the curve could never verify anything; refuse it now.
        core_presence::verify(public, &[0u8; 32], &[0u8; 64])
            .err()
            .filter(|e| *e == core_presence::PresenceError::BadKey)
            .map_or(Ok(()), |_| {
                Err("that is not a valid P-256 point".to_string())
            })?;
        let mut keys = self.presence_keys();
        let id = key_id(public);
        if keys.iter().any(|k| k.id == id) {
            return Err("that key is already enrolled".into());
        }
        if keys.len() >= KEY_CAP {
            return Err(format!("at most {KEY_CAP} presence keys can be enrolled"));
        }
        let record = PresenceKeyRecord {
            id,
            public: super::hex_encode(public),
            label: label.trim().chars().take(60).collect(),
            created_at: now,
        };
        keys.push(record.clone());
        self.save_presence_keys(&keys)?;
        self.set_presence_keys(keys);
        Ok(record)
    }

    /// Remove an enrolled key. Returns whether one was removed.
    ///
    /// ADR-148 addendum: the signed registry — the list that counts — is written **first**, carrying the
    /// shorter list; only then do memory and `keys/presence.enroll` follow. A failed or interrupted write
    /// therefore leaves the key enrolled everywhere (and the caller is told), never removed in this process
    /// while the registry would bring it back at the next start.
    pub fn presence_unenrol(&self, id: &str, now: i64) -> Result<bool, String> {
        let mut keys = self.presence_keys();
        let before = keys.len();
        keys.retain(|k| k.id != id);
        if keys.len() == before {
            return Ok(false);
        }
        let in_registry = keys.clone();
        self.persist_registry_edit(now, &mut |doc| {
            doc.presence_keys = Some(in_registry.clone());
        })?;
        self.set_presence_keys(keys.clone());
        self.save_presence_keys(&keys)?;
        Ok(true)
    }

    /// Write the registry through with `edit` applied to the document just before it is signed (a durable,
    /// unlocked vault; a no-op otherwise). The edit is what lands on disk even before memory changes.
    fn persist_registry_edit(
        &self,
        now: i64,
        edit: &mut dyn FnMut(&mut credmgr_store::registry_file::RegistryDocument),
    ) -> Result<(), String> {
        if !self.is_durable() {
            return Ok(());
        }
        let root = {
            let guard = self.session_root.read().expect("session root poisoned");
            let root = guard
                .as_ref()
                .ok_or_else(|| "the vault is locked".to_string())?;
            secrecy::SecretBox::new(Box::new(*root.expose_secret()))
        };
        self.persist_with_root_edit(root.expose_secret(), now, edit)
            .map_err(|e| format!("the vault could not be saved to disk: {e}"))
    }

    /// Issue a challenge for `op` with exactly these `params`, to the session `session`.
    pub fn presence_challenge(
        &self,
        session: &str,
        op: &str,
        params: &Value,
        now: i64,
    ) -> Result<IssuedChallenge, PresenceDenied> {
        if self.presence_keys().is_empty() {
            return Err(PresenceDenied::NotEnrolled);
        }
        Ok(self.issue_challenge(session, op, &without_presence(params), now))
    }

    /// ADR-148 §P2-4: a challenge the key being enrolled signs, proving the enrolling client holds its private
    /// half. Issued whether or not anything is enrolled yet (the first key needs one too). `params` are the
    /// `presence.enrol` params the client will send, without either proof.
    pub fn possession_challenge(&self, session: &str, params: &Value, now: i64) -> IssuedChallenge {
        self.issue_challenge(session, POSSESSION_OP, &without_proofs(params), now)
    }

    /// Check `params.possession` is `public`'s signature over a possession challenge issued to `session`
    /// for exactly these enrol params. Burns the nonce either way.
    pub fn possession_attest(
        &self,
        session: &str,
        public: &[u8],
        params: &Value,
        now: i64,
    ) -> Result<(), PresenceDenied> {
        let proof = params.get("possession").ok_or(PresenceDenied::Missing)?;
        let (nonce, signature) = decode_proof(proof).ok_or(PresenceDenied::Invalid)?;
        let challenge = self
            .presence_challenges
            .lock()
            .expect("presence challenges poisoned")
            .remove(&nonce)
            .ok_or(PresenceDenied::Expired)?;
        if challenge.expires_at <= now
            || challenge.op != POSSESSION_OP
            || challenge.session != session
        {
            return Err(PresenceDenied::Expired);
        }
        let digest = core_presence::digest(&nonce, POSSESSION_OP, &without_proofs(params));
        core_presence::verify(public, &digest, &signature).map_err(|_| PresenceDenied::Invalid)
    }

    fn issue_challenge(
        &self,
        session: &str,
        op: &str,
        signed_params: &Value,
        now: i64,
    ) -> IssuedChallenge {
        let mut nonce = <[u8; core_presence::NONCE_LEN]>::default();
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let digest = core_presence::digest(&nonce, op, signed_params);
        let mut table = self
            .presence_challenges
            .lock()
            .expect("presence challenges poisoned");
        table.retain(|_, c| c.expires_at > now);
        if table.len() >= CHALLENGE_CAP {
            // Drop the oldest rather than refuse: a stuck client must not lock the owner out.
            if let Some(oldest) = table
                .iter()
                .min_by_key(|(_, c)| c.expires_at)
                .map(|(k, _)| *k)
            {
                table.remove(&oldest);
            }
        }
        table.insert(
            nonce,
            PresenceChallenge {
                op: op.to_string(),
                session: session.to_string(),
                expires_at: now + CHALLENGE_TTL_SECONDS,
            },
        );
        IssuedChallenge {
            nonce,
            digest,
            expires_in: CHALLENGE_TTL_SECONDS,
        }
    }

    /// Whether this request carries a valid, unused presence proof for exactly this op and params, from
    /// this session. The nonce is burned whether or not the signature verifies: a guess costs a fresh
    /// biometric.
    pub fn presence_attest(
        &self,
        session: &str,
        op: &str,
        params: &Value,
        now: i64,
    ) -> Result<(), PresenceDenied> {
        let keys = self.presence_keys();
        if keys.is_empty() {
            return Err(PresenceDenied::NotEnrolled);
        }
        let proof = params.get("presence").ok_or(PresenceDenied::Missing)?;
        let (nonce, signature) = decode_proof(proof).ok_or(PresenceDenied::Invalid)?;

        let challenge = self
            .presence_challenges
            .lock()
            .expect("presence challenges poisoned")
            .remove(&nonce)
            .ok_or(PresenceDenied::Expired)?;
        if challenge.expires_at <= now || challenge.op != op || challenge.session != session {
            return Err(PresenceDenied::Expired);
        }
        let digest = core_presence::digest(&nonce, op, &without_presence(params));
        for key in &keys {
            let Some(public) = unhex(&key.public) else {
                continue;
            };
            if core_presence::verify(&public, &digest, &signature).is_ok() {
                return Ok(());
            }
        }
        Err(PresenceDenied::Invalid)
    }

    /// The Secure Enclave helper: the test seam if set, else the one that ships beside this daemon.
    pub fn presence_helper(&self) -> Option<Helper> {
        self.presence_helper
            .read()
            .expect("presence helper poisoned")
            .clone()
            .or_else(Helper::locate)
    }

    /// Use this helper instead of searching for one (tests).
    pub fn set_presence_helper_for_test(&self, helper: Option<Helper>) {
        *self
            .presence_helper
            .write()
            .expect("presence helper poisoned") = helper;
    }

    /// Drop every outstanding challenge (the vault locked).
    pub(super) fn clear_presence_challenges(&self) {
        self.presence_challenges
            .lock()
            .expect("presence challenges poisoned")
            .clear();
    }

    // ---- the Touch ID unlock ----------------------------------------------------------------------

    /// The Touch ID unlock wrap file, whether or not the registry names it.
    pub fn device_wrap(&self) -> Option<DeviceWrap> {
        presence_file::load_device_wrap(&self.paths).ok().flatten()
    }

    /// Whether a Touch ID unlock is set up for this vault: a wrap file the registry names.
    pub fn touch_id_unlock_on(&self) -> bool {
        self.device_wrap().is_some_and(|w| self.wrap_is_named(&w))
    }

    /// The Touch ID unlock wraps the signed registry names (ADR-148 addendum).
    pub(super) fn device_wraps(&self) -> Option<Vec<String>> {
        self.device_wraps
            .read()
            .expect("device wraps poisoned")
            .clone()
    }

    pub(super) fn set_device_wraps(&self, wraps: Option<Vec<String>>) {
        *self.device_wraps.write().expect("device wraps poisoned") = wraps;
    }

    /// ADR-148 addendum, migration: what a registry written before the addendum carries forward on its next
    /// write — the wrap on disk now, unless its tag fails under `root` (a tampered or foreign file).
    pub(super) fn device_wraps_to_carry(&self, root: &[u8; 32]) -> Vec<String> {
        match self.device_wrap() {
            Some(w) if w.authenticate(root) != presence_file::WrapAuth::Invalid => {
                wrap_id(&w).into_iter().collect()
            }
            _ => Vec::new(),
        }
    }

    /// Whether the registry names `wrap`. Once a vault has loaded, the verified list in memory answers; before
    /// that (a fresh daemon, still locked) the registry on disk is read **unverified** — only to avoid showing
    /// a prompt that could not succeed: after the Enclave opens the root key, [`Self::unlock_with_device`]
    /// checks again against the verified list. A registry that names none (written before the addendum) or
    /// cannot be read names every wrap.
    fn wrap_is_named(&self, wrap: &DeviceWrap) -> bool {
        let Some(id) = wrap_id(wrap) else {
            return false;
        };
        let named = self.device_wraps().or_else(|| {
            credmgr_store::atomic::read(&self.paths.registry())
                .ok()
                .and_then(|bytes| {
                    serde_json::from_slice::<credmgr_store::registry_file::RegistryDocument>(&bytes)
                        .ok()
                })
                .and_then(|doc| doc.device_wraps)
        });
        named.map_or(true, |list| list.contains(&id))
    }

    /// Set up the Touch ID unlock: create a Secure Enclave wrap key, seal the resident root key to it, and
    /// write `keys/root.wrap.se`. Needs the vault unlocked (the root key must be resident). `helper`
    /// is injected so tests can use the unattended variant.
    pub fn device_enrol(&self, helper: &Helper, now: i64) -> Result<(), String> {
        if !self.is_durable() {
            return Err("this vault is not backed by disk".into());
        }
        let key = helper.enroll(Purpose::Wrap).map_err(|e| e.to_string())?;
        let wrap = {
            let root = self.session_root.read().expect("session root poisoned");
            let root = root
                .as_ref()
                .ok_or_else(|| "the vault is locked".to_string())?;
            let sealed = secure_enclave::seal_to_public(helper, &key.public, root.expose_secret())
                .map_err(|e| e.to_string())?;
            // ADR-148 §P1-1: the tag binds the wrap's public point to this vault's root key.
            DeviceWrap::new(&key.blob, &key.public, &sealed, now).signed(root.expose_secret())
        };
        presence_file::save_device_wrap(&self.paths, &wrap).map_err(|e| e.to_string())?;
        // ADR-148 addendum: the signed registry names the wrap (and only this one). Until that write lands the
        // file on disk is inert, so a failure here leaves Touch ID unlock off, never half on.
        let named = vec![super::hex_encode(&key.public)];
        let in_registry = named.clone();
        self.persist_registry_edit(now, &mut |doc| {
            doc.device_wraps = Some(in_registry.clone());
        })?;
        self.set_device_wraps(Some(named));
        Ok(())
    }

    /// The Touch ID unlock wrap re-sealed to `new_root` (the same Secure Enclave key, no prompt), as the
    /// bytes a root-key rotation stages. `Ok(None)` when Touch ID unlock is not set up.
    ///
    /// ADR-148 §P1-1: the wrap's public point is where the new root key goes, so the wrap must carry a tag
    /// that verifies under `old_root` — checked **before** anything else, so a planted wrap is refused the
    /// same way with or without the helper. An untagged wrap (set up before ADR-148) is refused too: nothing
    /// proves its point is the one this vault enrolled. The result is re-signed under `new_root`.
    pub fn resealed_device_wrap(
        &self,
        old_root: &[u8; 32],
        new_root: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, String> {
        let Some(wrap) = presence_file::load_device_wrap(&self.paths).map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        // ADR-148 addendum: a wrap the registry does not name (one put back after `device.remove`) is not set
        // up; it is left as it is and never receives the new root key.
        if !self.wrap_is_named(&wrap) {
            return Ok(None);
        }
        match wrap.authenticate(old_root) {
            presence_file::WrapAuth::Valid => {}
            presence_file::WrapAuth::Untagged => {
                return Err(DEVICE_WRAP_UNTAGGED.to_string());
            }
            presence_file::WrapAuth::Invalid => {
                return Err(DEVICE_WRAP_INVALID.to_string());
            }
        }
        let helper = self.presence_helper().ok_or_else(|| {
            "Touch ID unlock is on but the Secure Enclave helper is not available here; turn Touch ID off, \
             or rotate on the Mac that holds the key"
                .to_string()
        })?;
        let public = wrap
            .wrap_public_bytes()
            .ok_or_else(|| "the Touch ID unlock wrap is damaged".to_string())?;
        let sealed = secure_enclave::seal_to_public(&helper, &public, new_root)
            .map_err(|e| e.to_string())?;
        let new = DeviceWrap::new(
            &wrap.wrap_blob_bytes().unwrap_or_default(),
            &public,
            &sealed,
            wrap.created_at,
        )
        .signed(new_root);
        Ok(Some(new.to_bytes()))
    }

    /// Remove the Touch ID unlock. ADR-148 addendum: the signed registry stops naming the wrap **first**, so
    /// the file — whether this removal deletes it or a backup puts it back later — no longer unlocks.
    pub fn device_remove(&self, now: i64) -> Result<(), String> {
        self.persist_registry_edit(now, &mut |doc| doc.device_wraps = Some(Vec::new()))?;
        if self.is_durable() {
            self.set_device_wraps(Some(Vec::new()));
        }
        presence_file::remove_device_wrap(&self.paths).map_err(|e| e.to_string())
    }

    /// `vault.unlock` with `method: "device"`: open `keys/root.wrap.se` through the Secure Enclave (the
    /// user authenticates), then finish exactly as a passphrase unlock does. The helper call runs before
    /// any lock is taken, so a user who walks away from the prompt does not stall every other request.
    ///
    /// `reason` is the sentence the system shows in the Touch ID dialog. ADR-148 §P1-5: the broker names the
    /// process that asked in it, so a person can tell their own `credmgr unlock --touch-id` from an agent's.
    pub fn unlock_with_device(
        &self,
        helper: &Helper,
        now: i64,
        reason: &str,
    ) -> Result<bool, DeviceUnlockError> {
        let wrap = presence_file::load_device_wrap(&self.paths)
            .map_err(|e| DeviceUnlockError::Unlock(UnlockError::Integrity(e)))?
            .ok_or(DeviceUnlockError::NotSetUp)?;
        // ADR-148 addendum: a wrap the registry does not name is not set up — refused before any prompt.
        if !self.wrap_is_named(&wrap) {
            return Err(DeviceUnlockError::NotSetUp);
        }
        let (blob, sealed) = wrap
            .wrap_blob_bytes()
            .zip(wrap.sealed_bytes())
            .ok_or(DeviceUnlockError::NotSetUp)?;
        let root = secure_enclave::open_with_helper(helper, &blob, &sealed, reason)
            .map_err(DeviceUnlockError::from_keystore)?;
        let pending_gate = self
            .unlock_with_root(root, now)
            .map_err(DeviceUnlockError::Unlock)?;
        // The check above read the registry unverified when nothing was loaded yet; now it has verified.
        if let (Some(id), Some(named)) = (wrap_id(&wrap), self.device_wraps()) {
            if !named.contains(&id) {
                self.lock();
                return Err(DeviceUnlockError::NotSetUp);
            }
        }
        Ok(pending_gate)
    }
}

/// ADR-148 §P1-1: why a rotation refuses an untagged Touch ID unlock wrap.
pub const DEVICE_WRAP_UNTAGGED: &str = "the Touch ID unlock was set up by an earlier version and its file is not \
     authenticated, so the new root key will not be sealed to it; turn Touch ID unlock off and on again \
     (`credmgr touch-id disable` then `credmgr touch-id enable`) and rotate again";
/// ADR-148 §P1-1: why a rotation refuses a Touch ID unlock wrap whose tag does not verify.
pub const DEVICE_WRAP_INVALID: &str = "the Touch ID unlock file failed its integrity check (keys/root.wrap.se \
     was changed outside CredMgr); the root key was not rotated. Turn Touch ID unlock off and on again \
     before rotating";

/// Why a Touch ID unlock did not open the vault.
#[derive(Debug)]
pub enum DeviceUnlockError {
    /// No `keys/root.wrap.se`.
    NotSetUp,
    /// The user dismissed the prompt.
    Cancelled,
    /// Too many failed attempts; the Mac asks for the password first.
    LockedOut,
    /// The helper is missing, or this Mac has no Secure Enclave.
    Unavailable(String),
    /// The Secure Enclave opened something that is not this vault's root key (a stale wrap).
    WrongKey,
    /// The key opened but the vault failed its own checks.
    Unlock(UnlockError),
}

impl DeviceUnlockError {
    fn from_keystore(e: KeystoreError) -> Self {
        match e {
            KeystoreError::Helper { code, detail } => match code.as_str() {
                "cancelled" => DeviceUnlockError::Cancelled,
                // ADR-148 addendum: a prompt left to the helper's timeout is a dismissal for the backoff — a
                // caller must not get a free retry by leaving the dialog up until it closes itself.
                secure_enclave::TIMED_OUT => DeviceUnlockError::Cancelled,
                "locked_out" => DeviceUnlockError::LockedOut,
                "unavailable" => DeviceUnlockError::Unavailable(detail),
                _ => DeviceUnlockError::Unavailable(format!("{code}: {detail}")),
            },
            KeystoreError::HelperMissing(why) => DeviceUnlockError::Unavailable(why),
            KeystoreError::AuthenticationFailed | KeystoreError::Truncated => {
                DeviceUnlockError::WrongKey
            }
            other => DeviceUnlockError::Unavailable(other.to_string()),
        }
    }
}

/// How the registry names a Touch ID unlock wrap: its public point, lower-case hex.
fn wrap_id(wrap: &DeviceWrap) -> Option<String> {
    wrap.wrap_public_bytes().map(|p| super::hex_encode(&p))
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| {
            let hi = (c[0] as char).to_digit(16)?;
            let lo = (c[1] as char).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}
