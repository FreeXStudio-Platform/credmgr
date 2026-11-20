//! ADR-135 — a node's own second factor: the bodies of `node.gate_enroll_begin`, `node.gate_enroll_confirm`,
//! `node.gate_verify` and `node.gate_remove`, and the "fresh factors" check the sensitive 2.0.0 ops share.
//! A child module of `ops`, like `stable_ops`, so the dispatcher's private helpers are in reach.

use serde_json::{json, Value};

use credmgr_core::registry::{GLOBAL_ID, ORPHAN_ID};

use super::{human_admin_on, owner_session, require_fresh_second_factor, require_presence};
use crate::protocol::OpError;
use crate::scope::BrokerScope;
use crate::state::BrokerState;

/// What every `node.gate_*` op checks first: the owner's login, a real project node (the vault's own gate
/// has the `vault.gate_*` ops; the orphan node has no gate), and `Admin` on it.
fn gate_target(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    now: i64,
) -> Result<(), OpError> {
    owner_session(state, scope)?;
    if target_node == GLOBAL_ID {
        return Err(OpError::Malformed(
            "the vault's own second factor is set with the vault.gate_* ops; node.gate_* is for a project's own".into(),
        ));
    }
    if target_node == ORPHAN_ID {
        return Err(OpError::Malformed(
            "the orphan node has no second factor of its own".into(),
        ));
    }
    if !state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .contains_key(target_node)
    {
        return Err(OpError::NotFound(format!("no node {target_node}")));
    }
    human_admin_on(state, scope, target_node, now)
}

/// Replacing or removing a gate in force needs that same gate's code, fresh (ADR-064's rule, per scope).
fn own_gate_fresh_if_in_force(
    state: &BrokerState,
    target_node: &str,
    now: i64,
) -> Result<(), OpError> {
    if state.node_has_own_gate(target_node) && !state.is_elevated(target_node, now) {
        return Err(OpError::TwoFactorRequired {
            challenge: "totp".to_string(),
            scope: target_node.to_string(),
            expires_in: 0,
        });
    }
    Ok(())
}

pub(super) fn enroll_begin(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    now: i64,
) -> Result<Value, OpError> {
    gate_target(state, scope, target_node, now)?;
    own_gate_fresh_if_in_force(state, target_node, now)?;
    Ok(json!({ "node": target_node, "otpauthUri": state.gate_enroll_begin(target_node) }))
}

pub(super) fn enroll_confirm(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    code: &str,
    now: i64,
) -> Result<Value, OpError> {
    use crate::state::GateEnrollError;
    gate_target(state, scope, target_node, now)?;
    own_gate_fresh_if_in_force(state, target_node, now)?;
    match state.gate_enroll_confirm(target_node, code, now) {
        Ok(codes) => Ok(json!({ "node": target_node, "recoveryCodes": codes })),
        Err(GateEnrollError::NotEnrolling) => Err(OpError::GateNotEnrolling),
        Err(GateEnrollError::WrongCode) => Err(OpError::GateVerificationFailed),
    }
}

/// A step-up for one node: its own code, fresh for the window, opening that node and no other.
pub(super) fn verify(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    code: &str,
    now: i64,
) -> Result<Value, OpError> {
    use crate::state::GateVerifyError;
    gate_target(state, scope, target_node, now)?;
    match state.gate_step_up(target_node, code, now) {
        Ok(()) => Ok(json!({
            "node": target_node, "elevated": true, "expiresIn": state.elevation_seconds(),
        })),
        Err(GateVerifyError::NoChallengePending) => Err(OpError::Malformed(format!(
            "node {target_node} has no second factor of its own - the vault's applies"
        ))),
        Err(GateVerifyError::WrongCode) => Err(OpError::GateVerificationFailed),
    }
}

/// Remove a node's own second factor: with its fresh code and a presence proof, or — the last door, when
/// the authenticator is lost — the vault passphrase and the printed root recovery code together
/// (ADR-064's rule).
pub(super) fn remove(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    passphrase: Option<&str>,
    recovery_code: Option<&str>,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    use crate::state::GateRecoverError;
    gate_target(state, scope, target_node, now)?;
    if !state.node_has_own_gate(target_node) {
        return Err(OpError::Malformed(format!(
            "node {target_node} has no second factor of its own to remove"
        )));
    }
    let had = match (passphrase, recovery_code) {
        (Some(pass), Some(code)) => state
            .gate_recover_scope(
                secrecy::SecretBox::new(Box::new(pass.to_string())),
                code,
                target_node,
                now,
            )
            .map_err(|e| match e {
                GateRecoverError::WrongFactors => OpError::WrongPassphrase,
                GateRecoverError::MachineLock(m) => crate::ops::machine_lock_refused(&m),
                GateRecoverError::Store(e) => {
                    OpError::Internal(format!("the node's second factor could not be reset: {e}"))
                }
            })?,
        (None, None) => {
            own_gate_fresh_if_in_force(state, target_node, now)?;
            require_presence(state, scope, "node.gate_remove", params, now)?;
            state.gate_drop(target_node, now).map_err(|e| {
                OpError::Internal(format!("the second factor could not be removed: {e}"))
            })?
        }
        _ => {
            return Err(OpError::Malformed(
                "give both params.passphrase and params.recoveryCode, or neither".into(),
            ))
        }
    };
    state.drop_elevations();
    Ok(json!({ "node": target_node, "removed": had }))
}

/// The second factors a sensitive op on `target_node` costs, fresh: the vault's when one is enrolled, **and**
/// the node's own when it has one (ADR-135). The first that is missing is the one the answer names.
pub(super) fn require_fresh_factors_for(
    state: &BrokerState,
    target_node: &str,
    now: i64,
) -> Result<(), OpError> {
    require_fresh_second_factor(state, now)?;
    own_gate_fresh_if_in_force(state, target_node, now)
}
