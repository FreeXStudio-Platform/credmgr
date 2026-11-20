//! ADR-135 — a node's own second factor (issue #16, ADR-093's known risk).
//!
//! What it proves, each by trying to break it:
//! * a node with a gate of its own asks for **its** code, the owner included, while every other node
//!   keeps the vault's rule (the owner exempt) — and the vault's gate is untouched by all of it;
//! * a code opens one node: the vault's code does not open a gated node, a node's code does not open
//!   another node or the vault's, and a code is spent once;
//! * the gate survives a restart; removing it takes its fresh code and a presence proof, or the last door;
//! * a gated node is neither sealed nor released by a locked-vault approval; a rekey or an export of it
//!   costs its code in addition to the vault's.

mod f1_support;

use serde_json::json;

use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::Capability;
use credmgr_core::totp::{decode_gate_secret_base32, Totp};

use f1_support::*;

fn agent_on(node: &str) -> BrokerScope {
    BrokerScope {
        node_id: node.to_string(),
        capabilities: vec![Capability::List, Capability::Read, Capability::Reveal],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

fn totp_of(uri: &str) -> Totp {
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    Totp::new_gate(decode_gate_secret_base32(b32).unwrap())
}

/// Give `node` a second factor of its own. Returns the authenticator and the ten recovery codes.
fn enrol_node_gate(state: &BrokerState, owner: &BrokerScope, node: &str) -> (Totp, Vec<String>) {
    let begin = call(
        state,
        owner,
        NOW,
        "node.gate_enroll_begin",
        json!({ "node": node }),
    )
    .expect("begin");
    let totp = totp_of(begin["otpauthUri"].as_str().unwrap());
    let done = call(
        state,
        owner,
        NOW,
        "node.gate_enroll_confirm",
        json!({ "node": node, "code": totp.code(NOW as u64) }),
    )
    .expect("confirm");
    let codes: Vec<String> = done["recoveryCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        codes.len(),
        10,
        "a node gate has its own ten recovery codes"
    );
    (totp, codes)
}

fn reveal_as(
    state: &BrokerState,
    who: &BrokerScope,
    at: i64,
    node: &str,
    entry: &str,
) -> Result<String, OpError> {
    call(
        state,
        who,
        at,
        "entry.reveal",
        json!({ "node": node, "entry": entry }),
    )
    .map(|v| v["value"].as_str().unwrap().to_string())
}

/// A login on a vault whose gate is on: the passphrase, then the vault's code.
fn login_through_the_vault_gate(state: &BrokerState, vault_totp: &Totp, at: i64) -> BrokerScope {
    let first = call(
        state,
        &anyone(),
        at,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    );
    assert!(
        matches!(first, Err(OpError::TwoFactorRequired { .. })),
        "{first:?}"
    );
    let token = call(
        state,
        &anyone(),
        at,
        "vault.gate_verify",
        json!({ "code": vault_totp.code(at as u64) }),
    )
    .expect("the vault's code completes the login")["token"]
        .as_str()
        .unwrap()
        .to_string();
    scope_of(state, &token)
}

fn scope_of_refusal<T: std::fmt::Debug>(r: &Result<T, OpError>) -> String {
    match r {
        Err(OpError::TwoFactorRequired { scope, .. }) => scope.clone(),
        other => panic!("expected two_factor_required, got {other:?}"),
    }
}

#[test]
fn a_node_with_a_gate_of_its_own_asks_even_the_owner_and_its_code_opens_that_node_only() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    create_node(&state, &owner, "beta");
    let a = create_entry(&state, &owner, "acme", "db", "acme-secret");
    let b = create_entry(&state, &owner, "beta", "db", "beta-secret");
    let vault_totp = enrol_gate(&state, &owner);
    let (acme_totp, _codes) = enrol_node_gate(&state, &owner, "acme");
    let agent_a = agent_on("acme");
    let agent_b = agent_on("beta");

    // The owner is exempt from the VAULT's gate (their login passed it) and not from acme's own.
    assert_eq!(
        reveal_as(&state, &owner, LATER, "beta", &b).unwrap(),
        "beta-secret"
    );
    let r = reveal_as(&state, &owner, LATER, "acme", &a);
    assert_eq!(
        scope_of_refusal(&r),
        "acme",
        "the owner is asked for acme's code"
    );
    // An agent is asked for whichever gate the node answers to.
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &agent_b, LATER, "beta", &b)),
        "global"
    );
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &agent_a, LATER, "acme", &a)),
        "acme"
    );

    // The vault's code opens the vault-gated node for the agent and does NOT open acme.
    step_up(&state, &owner, &vault_totp, LATER);
    assert_eq!(
        reveal_as(&state, &agent_b, LATER, "beta", &b).unwrap(),
        "beta-secret"
    );
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &agent_a, LATER, "acme", &a)),
        "acme"
    );
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &owner, LATER, "acme", &a)),
        "acme"
    );

    // acme's own code opens acme, for the owner and for an agent, and nothing else.
    let ok = call(
        &state,
        &owner,
        LATER + 100,
        "node.gate_verify",
        json!({ "node": "acme", "code": acme_totp.code((LATER + 100) as u64) }),
    )
    .expect("node step-up");
    assert_eq!(
        (ok["node"].as_str(), ok["elevated"].as_bool()),
        (Some("acme"), Some(true))
    );
    assert_eq!(
        reveal_as(&state, &owner, LATER + 101, "acme", &a).unwrap(),
        "acme-secret"
    );
    assert_eq!(
        reveal_as(&state, &agent_a, LATER + 101, "acme", &a).unwrap(),
        "acme-secret"
    );
    // …but its window is its own: 300 seconds, then it asks again.
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &owner, LATER + 100 + 301, "acme", &a)),
        "acme"
    );

    // A code is spent once, and a wrong one is refused.
    let again = call(
        &state,
        &owner,
        LATER + 100,
        "node.gate_verify",
        json!({ "node": "acme", "code": acme_totp.code((LATER + 100) as u64) }),
    );
    assert!(
        matches!(again, Err(OpError::GateVerificationFailed)),
        "{again:?}"
    );
    let wrong = call(
        &state,
        &owner,
        LATER + 500,
        "node.gate_verify",
        json!({ "node": "acme", "code": "000000" }),
    );
    assert!(
        matches!(wrong, Err(OpError::GateVerificationFailed)),
        "{wrong:?}"
    );

    // beta's rule is as it was: the vault's code, fresh, the owner exempt.
    assert_eq!(
        reveal_as(&state, &owner, LATER + 600, "beta", &b).unwrap(),
        "beta-secret"
    );
}

#[test]
fn the_node_gate_ops_are_the_owners_for_a_real_project_and_say_so_when_there_is_nothing_to_verify()
{
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    // (Built field by field: `BrokerScope` wipes its bearer on drop, so struct-update syntax cannot move out of one.)
    let mut agent = agent_on("acme");
    agent.capabilities = vec![Capability::List, Capability::Admin];
    for op in [
        "node.gate_enroll_begin",
        "node.gate_verify",
        "node.gate_remove",
    ] {
        assert!(
            call(
                &state,
                &agent,
                NOW,
                op,
                json!({ "node": "acme", "code": "000000" })
            )
            .is_err(),
            "{op}: an agent"
        );
        for bad in ["global", "orphan"] {
            let r = call(
                &state,
                &owner,
                NOW,
                op,
                json!({ "node": bad, "code": "000000" }),
            );
            assert!(
                matches!(r, Err(OpError::Malformed(_))),
                "{op} on {bad}: {r:?}"
            );
        }
        let r = call(
            &state,
            &owner,
            NOW,
            op,
            json!({ "node": "nowhere", "code": "000000" }),
        );
        assert!(matches!(r, Err(OpError::NotFound(_))), "{op}: {r:?}");
    }
    // A node with no gate of its own has nothing to verify or remove: the vault's applies.
    let r = call(
        &state,
        &owner,
        NOW,
        "node.gate_verify",
        json!({ "node": "acme", "code": "000000" }),
    );
    assert!(
        matches!(&r, Err(OpError::Malformed(m)) if m.contains("vault's applies")),
        "{r:?}"
    );
    let r = call(
        &state,
        &owner,
        NOW,
        "node.gate_remove",
        json!({ "node": "acme" }),
    );
    assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
    // Confirming without beginning, or with a wrong code, enrols nothing.
    let r = call(
        &state,
        &owner,
        NOW,
        "node.gate_enroll_confirm",
        json!({ "node": "acme", "code": "123456" }),
    );
    assert!(matches!(r, Err(OpError::GateNotEnrolling)), "{r:?}");
    call(
        &state,
        &owner,
        NOW,
        "node.gate_enroll_begin",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let r = call(
        &state,
        &owner,
        NOW,
        "node.gate_enroll_confirm",
        json!({ "node": "acme", "code": "000000" }),
    );
    assert!(matches!(r, Err(OpError::GateVerificationFailed)), "{r:?}");
    assert!(!state.node_has_own_gate("acme"));
}

#[test]
fn the_gate_survives_a_restart_and_the_last_door_removes_it_without_touching_the_vaults() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let a = create_entry(&state, &owner, "acme", "db", "acme-secret");
    let vault_totp = enrol_gate(&state, &owner);
    let (_acme_totp, _codes) = enrol_node_gate(&state, &owner, "acme");

    // Restart: the node's gate is still there, and so is the vault's (which now gates the login itself).
    drop(owner);
    drop(state);
    let state = v.broker(None);
    let owner = login_through_the_vault_gate(&state, &vault_totp, LATER);
    assert!(
        state.node_has_own_gate("acme"),
        "the node's second factor was persisted"
    );
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &owner, LATER, "acme", &a)),
        "acme"
    );

    // Wrong factors: nothing is removed. Right ones: the node's gate goes, the vault's stays.
    let bad = call(
        &state,
        &owner,
        NOW,
        "node.gate_remove",
        json!({ "node": "acme", "passphrase": PASSPHRASE, "recoveryCode": "AAAA-AAAA-AAAA-AAAA" }),
    );
    assert!(matches!(bad, Err(OpError::WrongPassphrase)), "{bad:?}");
    assert!(state.node_has_own_gate("acme"));
    let half = call(
        &state,
        &owner,
        NOW,
        "node.gate_remove",
        json!({ "node": "acme", "passphrase": PASSPHRASE }),
    );
    assert!(matches!(half, Err(OpError::Malformed(_))), "{half:?}");

    let recovery = v.recovery_code.borrow().clone();
    let done = call(
        &state,
        &owner,
        NOW,
        "node.gate_remove",
        json!({ "node": "acme", "passphrase": PASSPHRASE, "recoveryCode": recovery }),
    )
    .expect("the last door");
    assert_eq!(done["removed"], true);
    assert!(!state.node_has_own_gate("acme"));
    assert!(
        state.is_gate_confirmed("global"),
        "the vault's own gate is untouched"
    );
    assert_eq!(
        reveal_as(&state, &owner, LATER, "acme", &a).unwrap(),
        "acme-secret",
        "back to the vault's rule: the owner exempt"
    );

    // And that, too, is persisted.
    drop(owner);
    drop(state);
    let state = v.broker(None);
    let owner = login_through_the_vault_gate(&state, &vault_totp, LATER + 600);
    assert!(!state.node_has_own_gate("acme"));
    assert!(state.is_gate_confirmed("global"));
    assert_eq!(
        reveal_as(&state, &owner, LATER + 601, "acme", &a).unwrap(),
        "acme-secret"
    );
}

#[test]
fn a_gated_node_is_not_sealed_not_released_by_a_locked_approval_and_costs_its_code_to_rekey() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let a = create_entry(&state, &owner, "acme", "db", "acme-secret");
    let (acme_totp, _) = enrol_node_gate(&state, &owner, "acme");

    // Not sealed while it has a factor of its own.
    let r = call(&state, &owner, NOW, "node.seal", json!({ "node": "acme" }));
    assert!(
        matches!(&r, Err(OpError::Malformed(m)) if m.contains("second factor of its own")),
        "{r:?}"
    );

    // A rekey asks for the node's code before anything else (the vault has no gate here).
    let r = call(
        &state,
        &owner,
        LATER,
        "node.rekey",
        json!({ "node": "acme" }),
    );
    assert_eq!(scope_of_refusal(&r), "acme");
    call(
        &state,
        &owner,
        LATER,
        "node.gate_verify",
        json!({ "node": "acme", "code": acme_totp.code(LATER as u64) }),
    )
    .unwrap();
    let r = call(
        &state,
        &owner,
        LATER,
        "node.rekey",
        json!({ "node": "acme" }),
    );
    assert!(
        matches!(r, Err(OpError::PresenceRequired { .. })),
        "with the node's code fresh the next thing asked is presence: {r:?}"
    );

    // A locked vault gives an agent no approval path to a gated node's value.
    state.lock();
    let r = call(
        &state,
        &agent_on("acme"),
        LATER,
        "entry.reveal",
        json!({ "node": "acme", "entry": a }),
    );
    assert!(
        matches!(r, Err(OpError::VaultLocked)),
        "no approval is opened for a gated node: {r:?}"
    );
}

#[test]
fn a_root_key_rotation_carries_a_nodes_own_gate_to_the_new_root() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let a = create_entry(&state, &owner, "acme", "db", "acme-secret");
    let (totp, _) = enrol_node_gate(&state, &owner, "acme");

    // The gate's secret is sealed under a key derived from the root key; a rotation must re-seal it.
    credmgr_brokerd::ops::rotate_root_response(&state, PASSPHRASE, NOW + 10).expect("rotation");
    drop(owner);
    drop(state);
    let state = v.broker(None);
    let owner = login(&state);
    assert!(
        state.node_has_own_gate("acme"),
        "the gate survived the rotation"
    );
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &owner, LATER, "acme", &a)),
        "acme"
    );
    call(
        &state,
        &owner,
        LATER,
        "node.gate_verify",
        json!({ "node": "acme", "code": totp.code(LATER as u64) }),
    )
    .expect("the same authenticator still works under the new root key");
    assert_eq!(
        reveal_as(&state, &owner, LATER + 1, "acme", &a).unwrap(),
        "acme-secret"
    );
}

#[test]
fn removing_a_gate_with_its_own_code_takes_a_fresh_code_and_a_presence_proof() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    create_node(&state, &owner, "acme");
    let (totp, _) = enrol_node_gate(&state, &owner, "acme");
    let ask = json!({ "node": "acme" });

    let r = call(&state, &owner, LATER, "node.gate_remove", ask.clone());
    assert_eq!(scope_of_refusal(&r), "acme", "its fresh code first");
    call(
        &state,
        &owner,
        LATER,
        "node.gate_verify",
        json!({ "node": "acme", "code": totp.code(LATER as u64) }),
    )
    .unwrap();
    let r = call(&state, &owner, LATER, "node.gate_remove", ask.clone());
    assert!(
        matches!(r, Err(OpError::PresenceRequired { .. })),
        "then presence: {r:?}"
    );
    let proved = with_proof(&state, &owner, &key, LATER, "node.gate_remove", ask);
    let done = call(&state, &owner, LATER, "node.gate_remove", proved)
        .expect("with the code and the proof");
    assert_eq!(done["removed"], true);
    assert!(!state.node_has_own_gate("acme"));
}

// ---- ADR-148: the pre-stable security fixes -------------------------------------------------------------

#[test]
fn p1_2_turning_require_two_factor_off_does_not_skip_a_nodes_own_gate() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let a = create_entry(&state, &owner, "acme", "db", "acme-secret");
    let _vault_totp = enrol_gate(&state, &owner);
    let (acme_totp, _codes) = enrol_node_gate(&state, &owner, "acme");

    // An owner session (the admin gate, nothing more) sets `requireTwoFactor: never` on the gated node.
    call(
        &state,
        &owner,
        LATER,
        "node.policy",
        json!({ "node": "acme", "policy": { "requireTwoFactor": "never" }, "reason": "test" }),
    )
    .expect("the policy change itself is the admin's");

    // The node's own code is still asked before a reveal — of the owner and of an agent.
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &owner, LATER, "acme", &a)),
        "acme"
    );
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &agent_on("acme"), LATER, "acme", &a)),
        "acme"
    );
    // …and still opens it.
    call(
        &state,
        &owner,
        LATER + 30,
        "node.gate_verify",
        json!({ "node": "acme", "code": acme_totp.code((LATER + 30) as u64) }),
    )
    .expect("node step-up");
    assert_eq!(
        reveal_as(&state, &owner, LATER + 31, "acme", &a).unwrap(),
        "acme-secret"
    );
}

#[test]
fn p2_2_a_spent_node_code_stays_spent_across_a_restart() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let a = create_entry(&state, &owner, "acme", "db", "acme-secret");
    let vault_totp = enrol_gate(&state, &owner);
    let (acme_totp, codes) = enrol_node_gate(&state, &owner, "acme");
    let at = LATER + 100;
    let totp_code = acme_totp.code(at as u64);
    for code in [totp_code.as_str(), codes[0].as_str()] {
        call(
            &state,
            &owner,
            at,
            "node.gate_verify",
            json!({ "node": "acme", "code": code }),
        )
        .expect("first use");
    }

    // Restart: the TOTP replay floor and the spent recovery code were written through.
    drop(owner);
    drop(state);
    let state = v.broker(None);
    let owner = login_through_the_vault_gate(&state, &vault_totp, at + 10);
    for code in [totp_code.as_str(), codes[0].as_str()] {
        let again = call(
            &state,
            &owner,
            at,
            "node.gate_verify",
            json!({ "node": "acme", "code": code }),
        );
        assert!(
            matches!(again, Err(OpError::GateVerificationFailed)),
            "a spent code is refused after a restart: {again:?}"
        );
    }
    assert_eq!(
        scope_of_refusal(&reveal_as(&state, &owner, at + 20, "acme", &a)),
        "acme"
    );
}
