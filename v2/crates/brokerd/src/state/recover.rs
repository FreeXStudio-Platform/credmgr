//! ADR-163 — opening the vault with the recovery code alone, when the passphrase is forgotten.
//!
//! The recovery code is the second way to the root key: `root.wrap.recovery` holds the root key wrapped
//! under `HKDF-SHA512(recovery code)` (ADR-045), written by `vault.init_confirm` and rewritten by every root
//! rotation (ADR-076) and passphrase change (ADR-156). Until ADR-163 the broker used it only to reset a lost
//! second factor, and only together with the passphrase (`vault.gate_recover`, ADR-064).
//!
//! [`BrokerState::recover_with_code`] is a **one-way door**. It never leaves the vault open under the code
//! that opened it: the same call re-keys the vault through the root rotation of ADR-076
//! ([`BrokerState::rotate_root_locked`], the code path `vault.set_passphrase` uses), so it
//!
//! * makes a new root key, a new `root.wrap.pass` from the new passphrase, and a new `root.wrap.recovery`
//!   under a **new** recovery code, staged and committed together — the used code's wrap is overwritten in
//!   the same commit, and it wrapped the old root key, which nothing on disk accepts any more;
//! * crash-safety is the rotation's: before the commit record the old passphrase and the old code still
//!   open the vault; after it, the new passphrase and the new code; never neither;
//! * the vault is unlocked only once the rotation has committed and its files are in place. A refusal at
//!   any step leaves the vault locked and every file as it was.
//!
//! Who may call it — never an agent, never over MCP, behind the per-uid unlock backoff — is decided by
//! `ops.rs` (`vault.recover`) and `server.rs`. This file is the mechanism, and the in-memory list of
//! refused attempts made while the vault was locked, which the next unlock writes to the audit trail.

use std::collections::VecDeque;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::{Zeroize, Zeroizing};

use credmgr_core::recovery::{
    parse_recovery_code, unwrap_root_with_recovery_code, RootRecoveryWrap,
};
use credmgr_store::atomic;
use credmgr_store::error::StoreError;

use super::rotate::{RotateRootError, RotationAudit, RotationOutcome};
use super::{BrokerState, GATE_SCOPE_VAULT};

/// How many refused recovery attempts made while the vault was locked are kept in memory until the next
/// unlock can sign them into the audit trail. Past this, the oldest are counted, not itemised.
pub const REFUSED_RECOVERY_QUEUE: usize = 64;

/// One recovery attempt that could not be audited when it happened (the vault was locked, so there was no
/// root key to sign a record with). No secret: the time, who asked (the same actor string every audit
/// record uses) and the answer's error tag or outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnauditedRecovery {
    pub at: i64,
    pub actor: String,
    /// `"deny"`, or `"allow"` for a recovery whose rotation committed but whose file moves the next unlock
    /// finishes (its own audit record could not be written either).
    pub decision: &'static str,
    pub reason: &'static str,
}

/// The attempts waiting for a root key, and how many fell off the front of a full queue.
#[derive(Debug, Default)]
pub(super) struct UnauditedRecoveries {
    pub(super) queue: VecDeque<UnauditedRecovery>,
    pub(super) dropped: u64,
}

/// What a recovery that got past its rotation's commit point did.
#[derive(Debug)]
pub struct RecoverOutcome {
    /// The rotation's own outcome (the new recovery code, the files moved, whether the move is pending).
    pub rotation: RotationOutcome,
    /// Whether the vault is open under the new root key. `false` when the rotation committed but could not
    /// finish moving its files (`rotation.completion_pending`), **and** when the files are in place but this
    /// process could not open the node keys under the new root key, so it locked the vault again (review
    /// P2-a). Either way the vault is locked, every session token was revoked by that lock, and the next
    /// unlock with the new passphrase opens it from disk. The caller must not hand out a login then.
    pub opened: bool,
}

/// Why [`BrokerState::recover_with_code`] refused. **Every variant leaves the vault locked and every file
/// exactly as it was** (a rotation that got past its commit point does not fail; it returns an outcome).
#[derive(Debug)]
pub enum RecoverError {
    /// The caller is an agent: an agent token, or no token from inside a registered project folder. Found
    /// only once the vault is loaded on a broker that had not loaded it yet (review P1-1); the same refusal
    /// `ops.rs` gives before any code is read when the registry is already in memory.
    Agent,
    /// The vault is already open: there is nothing to recover, and a passphrase change from the open vault
    /// (`vault.set_passphrase`) is the way to replace a passphrase that is known.
    AlreadyUnlocked,
    /// No vault here, or the vault has no `root.wrap.recovery` (one made before recovery wraps existed, or
    /// whose wrap was removed). It appears with the next root rotation or passphrase change.
    Unavailable,
    /// The code is not a recovery code, or not this vault's. Counted by the unlock backoff.
    WrongCode,
    /// A second factor is enrolled and none was given. The code was right; the counter is not touched,
    /// exactly as `vault.unlock` answers `two_factor_required` after a right passphrase.
    SecondFactorRequired,
    /// A second factor is enrolled and the one given is wrong or replayed. Counted by the backoff.
    WrongSecondFactor,
    /// The code opened the wrap, but the vault on disk did not verify under the key it yielded (a wrap
    /// rolled back from before a rotation, a tampered registry). Nothing was opened.
    Integrity(StoreError),
    /// The rotation refused before its commit point. Nothing was changed.
    Rotate(RotateRootError),
}

impl std::fmt::Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoverError::Agent => write!(f, "an agent cannot recover the vault"),
            RecoverError::AlreadyUnlocked => write!(f, "the vault is already unlocked"),
            RecoverError::Unavailable => write!(f, "this vault has no recovery-code unlock"),
            RecoverError::WrongCode => write!(f, "the recovery code does not open this vault"),
            RecoverError::SecondFactorRequired => write!(f, "a second factor is required"),
            RecoverError::WrongSecondFactor => write!(f, "the second factor was not accepted"),
            RecoverError::Integrity(e) => {
                write!(f, "the vault on disk failed its integrity check: {e}")
            }
            RecoverError::Rotate(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RecoverError {}

impl BrokerState {
    /// Whether this vault can be opened with its recovery code: a public fact, the wrap file exists (the
    /// same kind of fact `vault.status` already reports for Touch ID). It says nothing about which code.
    pub fn recovery_unlock_available(&self) -> bool {
        self.paths.root_wrap_recovery().is_file()
    }

    /// ADR-163: open a locked vault with the recovery code, and in the same call replace the passphrase and
    /// the recovery code. See the module docs. In order:
    ///
    /// 1. an open vault is refused (nothing to recover);
    /// 2. an interrupted rotation is finished or dropped before any root wrap is read (ADR-076);
    /// 3. no `root.wrap.recovery` is refused as [`RecoverError::Unavailable`];
    /// 4. the code must open the wrap — a malformed and a wrong code are the same answer;
    /// 5. the vault on disk must verify under the root key the code yielded (registry HMAC, rollback
    ///    counter, every manifest), exactly as an unlock checks it;
    /// 5a. the caller must not be an agent, asked again now that the registry is in memory: on a broker
    ///    that had not loaded the vault, `scope`'s working directory could not be matched against the
    ///    project folders before this point (review P1-1);
    /// 6. an enrolled second factor must be given and must verify (a TOTP code, or one of the gate's own
    ///    single-use backup codes);
    /// 7. the root rotation, with the new passphrase making the new passphrase wrap;
    /// 8. the vault is unlocked under the new root key — unless the rotation committed but could not
    ///    finish moving its files, in which case it stays locked and the next unlock (with the NEW
    ///    passphrase) finishes the move, as for any rotation.
    pub fn recover_with_code(
        &self,
        scope: &crate::scope::BrokerScope,
        recovery_code: &str,
        new_passphrase: SecretBox<String>,
        second_factor: Option<&str>,
        now: i64,
    ) -> Result<RecoverOutcome, RecoverError> {
        let _auth = self.auth_lock.lock().expect("auth lock poisoned");
        if !self.is_locked() {
            return Err(RecoverError::AlreadyUnlocked);
        }
        self.recover_interrupted_rotation()
            .map_err(RecoverError::Integrity)?;

        let wrap_path = self.paths.root_wrap_recovery();
        if !wrap_path.is_file() || !self.paths.registry().exists() {
            return Err(RecoverError::Unavailable);
        }
        let wrap = atomic::read(&wrap_path)
            .ok()
            .and_then(|bytes| RootRecoveryWrap::from_bytes(&bytes).ok())
            .ok_or_else(|| {
                RecoverError::Integrity(super::durable::corrupt(
                    wrap_path.clone(),
                    "the recovery-code wrap is damaged",
                ))
            })?;

        let root = {
            let Ok(code) = parse_recovery_code(recovery_code) else {
                return Err(RecoverError::WrongCode);
            };
            let code = Zeroizing::new(code);
            let Ok(mut opened) = unwrap_root_with_recovery_code(&code, &wrap) else {
                return Err(RecoverError::WrongCode);
            };
            let root: SecretBox<[u8; 32]> = SecretBox::new(Box::new(opened));
            opened.zeroize();
            root
        };

        // The code opened its wrap. That proves the code matches the wrap file, not that the wrap file
        // belongs to this vault as it stands: a copy put back from before a rotation opens with the code
        // that was printed then. Everything signed must verify under the key it yields before anything is
        // trusted — on a fresh broker by loading the vault, on one that already holds it by verifying the
        // files again.
        if self.is_durable() {
            self.verify_vault_on_disk(root.expose_secret())
                .map_err(RecoverError::Integrity)?;
        } else {
            self.load_from_disk(root.expose_secret())
                .map_err(RecoverError::Integrity)?;
        }

        // Never an agent (review P1-1). `ops.rs` asked before any code was read, but on a broker that had not
        // loaded the vault the registry was empty then, so a token-less agent inside a project folder looked
        // like a person's terminal. The registry is in memory now; ask again before the second factor and
        // before anything is rotated. The vault stays locked: the load opened nothing (no session root, no
        // node key in the hot set).
        if self.is_identified_agent(scope) {
            return Err(RecoverError::Agent);
        }

        // The second factor, when the owner enrolled one: the recovery code replaces the passphrase, not the
        // authenticator. A gate backup code is accepted (it is what the owner printed for a lost
        // authenticator); a TOTP step is recorded against replay. Both are written by the rotation's registry
        // write below.
        if self.is_gate_confirmed(GATE_SCOPE_VAULT) {
            let Some(code) = second_factor else {
                return Err(RecoverError::SecondFactorRequired);
            };
            if !self.consume_gate_code(GATE_SCOPE_VAULT, code.trim(), now, true) {
                return Err(RecoverError::WrongSecondFactor);
            }
        }

        let outcome = self
            .rotate_root_locked(
                &root,
                RotationAudit::RECOVERY,
                super::rotate::MachineLockIntent::Keep {
                    wrap_passphrase: &new_passphrase,
                },
                // ADR-165 N5: a recovery re-keys every live node, so an old copy of the folder plus the used
                // code (or the forgotten passphrase) opens nothing written after it.
                super::rotate::NodeKeys::Replace,
                now,
            )
            .map_err(RecoverError::Rotate)?;
        drop(root);

        let mut opened = false;
        if !outcome.completion_pending {
            // The rotation put the new root key in `session_root`; open the vault under it, as an unlock's
            // tail does. The node keys were re-wrapped from the ones that just verified, so they open.
            let new_root = self
                .session_root
                .read()
                .expect("session root poisoned")
                .as_ref()
                .map(|r| SecretBox::new(Box::new(*r.expose_secret())));
            opened = !self.recover_open_fault_fires()
                && new_root
                    .as_ref()
                    .is_some_and(|r| self.install_hot_keys_from_root(r.expose_secret()).is_ok());
            if !opened {
                // Committed, and the files are in place, but this process could not open the node keys: lock
                // rather than run half-open. The next unlock with the new passphrase opens it from disk.
                self.lock_inner();
            }
        }
        Ok(RecoverOutcome {
            rotation: outcome,
            opened,
        })
    }

    /// Review P2-a's seam: the next recovery fails to open the node keys after its rotation committed.
    #[cfg(feature = "test-utils")]
    pub fn set_recover_open_fault_for_test(&self, fail: bool) {
        self.recover_open_fault
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "test-utils")]
    fn recover_open_fault_fires(&self) -> bool {
        self.recover_open_fault
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(not(feature = "test-utils"))]
    fn recover_open_fault_fires(&self) -> bool {
        false
    }

    /// Remember a recovery attempt that could not be audited when it was made (the vault was locked).
    pub fn note_unaudited_recovery(&self, attempt: UnauditedRecovery) {
        let mut pending = self
            .unaudited_recoveries
            .lock()
            .expect("unaudited recoveries poisoned");
        if pending.queue.len() >= REFUSED_RECOVERY_QUEUE {
            pending.queue.pop_front();
            pending.dropped += 1;
        }
        pending.queue.push_back(attempt);
    }

    /// Hand over, and forget, every recovery attempt waiting to be audited, with the count of those that
    /// did not fit. Called by the server's audit writer once it holds a root key.
    pub fn take_unaudited_recoveries(&self) -> (Vec<UnauditedRecovery>, u64) {
        let mut pending = self
            .unaudited_recoveries
            .lock()
            .expect("unaudited recoveries poisoned");
        let dropped = std::mem::take(&mut pending.dropped);
        (pending.queue.drain(..).collect(), dropped)
    }
}
