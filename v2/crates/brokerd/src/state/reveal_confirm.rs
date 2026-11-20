//! ADR-150 — the broker's half of "confirm before showing secrets": the vault policy as the registry holds it,
//! the per-session confirmations, and the passphrase check `session.confirm` makes. The rules themselves (what
//! a value needs, what weakens the policy, whether a confirmation meets a need) are pure and live in
//! `credmgr_core::reveal_confirm`.

use secrecy::{ExposeSecret, SecretBox};

use credmgr_core::inference::Sensitivity;
use credmgr_core::registry::GLOBAL_ID;
use credmgr_core::reveal_confirm::{self, Confirmation, Need, RevealConfirm};

use super::BrokerState;

/// Why a passphrase confirmation failed. Which part failed is never said to the caller.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmPassphraseError {
    WrongPassphrase,
    /// ADR-165: the passphrase wrap is bound to a device key this Mac does not hold (or is damaged).
    MachineLock(credmgr_keystore::machine_lock::MachineLockError),
}

impl BrokerState {
    /// The vault's policy: the `global` node's `revealConfirm`, off when absent.
    pub fn reveal_confirm_policy(&self) -> RevealConfirm {
        self.registry
            .read()
            .expect("registry poisoned")
            .nodes
            .get(GLOBAL_ID)
            .map(|n| n.policy.reveal_confirm)
            .unwrap_or_default()
    }

    /// Records that the person behind `session` (a login's public id) just confirmed it was them.
    pub fn record_confirmation(&self, session: &str, now: i64) {
        self.reveal_confirmations
            .write()
            .expect("reveal confirmations poisoned")
            .insert(
                session.to_string(),
                Confirmation {
                    at: now,
                    spent: false,
                },
            );
    }

    /// Whether `session` holds a confirmation that meets `need` at `now`; a need for a fresh one uses it up.
    /// Checked and spent under one write lock, so two requests cannot share one "every time" confirmation.
    pub fn take_confirmation(&self, session: Option<&str>, need: Need, now: i64) -> bool {
        if need == Need::None {
            return true;
        }
        let Some(session) = session else {
            return false;
        };
        let mut held = self
            .reveal_confirmations
            .write()
            .expect("reveal confirmations poisoned");
        let (ok, consume) = reveal_confirm::satisfied(need, held.get(session).copied(), now);
        if ok && consume {
            if let Some(c) = held.get_mut(session) {
                c.spent = true;
            }
        }
        ok
    }

    /// What showing a value of `sensitivity` needs right now.
    pub fn reveal_need(&self, sensitivity: Sensitivity) -> Need {
        self.reveal_confirm_policy().need(sensitivity)
    }

    pub(super) fn clear_reveal_confirmations(&self) {
        self.reveal_confirmations
            .write()
            .expect("reveal confirmations poisoned")
            .clear();
    }

    /// `session.confirm` with the passphrase: the passphrase must open this vault's passphrase wrap, and the root
    /// key it yields must be the one this unlocked vault is running on (a wrap file swapped in from another vault
    /// opens, but to a different key). Nothing is kept: the root key is compared and dropped (zeroised).
    /// Serialised with every other authentication step.
    pub fn confirm_passphrase(
        &self,
        passphrase: SecretBox<String>,
    ) -> Result<(), ConfirmPassphraseError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        let root = self
            .root_from_passphrase(passphrase, "confirm before showing secrets")
            .map_err(|e| match e {
                super::durable::PassRootError::MachineLock(m) => {
                    ConfirmPassphraseError::MachineLock(m)
                }
                super::durable::PassRootError::Wrong => ConfirmPassphraseError::WrongPassphrase,
            })?;
        let resident = self.session_root.read().expect("session root poisoned");
        let Some(resident) = resident.as_ref() else {
            return Err(ConfirmPassphraseError::WrongPassphrase);
        };
        // Constant time: the comparison does not stop at the first differing byte.
        let diff = root
            .expose_secret()
            .iter()
            .zip(resident.expose_secret().iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff == 0 {
            Ok(())
        } else {
            Err(ConfirmPassphraseError::WrongPassphrase)
        }
    }
}
