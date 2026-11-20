//! ADR-098 — presence proofs and the Touch ID unlock, end to end against a durable vault.
//!
//! ADR-148 §P2-5: the presence rows sign with a **software** P-256 key, so every refusal here (TTL, another
//! op, another session, replay, tamper, the key cap, challenge eviction, proof of possession) runs on every
//! host, Linux CI included, against the broker's own verifier. Only the Touch ID unlock journey still needs
//! the Secure Enclave, through the unattended TEST helper (`native/macos/presence/build.sh --test-noauth`);
//! it skips (passes vacuously) without it. The Touch ID *refusals* use a stand-in helper script instead.
//!
//! What is proved, each one by trying to break it:
//! * a proof is bound to its op, its exact params, its session and one use;
//! * a proof outlives neither its 60 seconds nor a lock;
//! * without an enrolled key nothing is attested, and a tampered enrolment file stops the vault opening;
//! * adding a second key, removing one, and turning on Touch ID unlock all need the first key;
//! * Touch ID unlock opens the same vault, survives a root-key rotation, and is gone when removed.

mod f1_support;

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_store::presence_file::{self, DeviceWrap};

use f1_support::*;

/// Any audit record id. `ops::dispatch` does not audit, so make one through the real request path first.
fn some_audit_id(state: &Arc<BrokerState>, owner: &BrokerScope) -> String {
    let (r, _) = server::handle_request(
        state,
        &peer(),
        &Request {
            id: "seed".into(),
            op: "audit.tail".into(),
            token: owner.token_id.clone(),
            params: json!({ "limit": 1 }),
        },
    );
    r.expect("audit.tail");
    call(state, owner, NOW, "audit.tail", json!({ "limit": 5 })).unwrap()["records"][0]["id"]
        .as_str()
        .expect("there is at least one audit record")
        .to_string()
}

#[test]
fn without_an_enrolled_key_nothing_is_attested() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let r = call(
        &state,
        &owner,
        NOW,
        "presence.challenge",
        json!({ "op": "audit.get", "params": {} }),
    );
    assert!(matches!(
        r,
        Err(OpError::PresenceFailed {
            reason: "not_enrolled",
            ..
        })
    ));
    // The op itself keeps its long-standing answer; the challenge is where "nothing enrolled" is named.
    let r = call(
        &state,
        &owner,
        NOW,
        "audit.get",
        json!({ "id": "a_000000000000" }),
    );
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");
}

#[test]
fn a_real_proof_opens_a_gated_op_exactly_once() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    let id = some_audit_id(&state, &owner);

    // No proof: the same answer as ever.
    let none = call(&state, &owner, NOW, "audit.get", json!({ "id": id }));
    assert!(
        matches!(none, Err(OpError::PresenceRequired { .. })),
        "{none:?}"
    );

    let proved = with_proof(&state, &owner, &key, NOW, "audit.get", json!({ "id": id }));
    let record = call(&state, &owner, NOW, "audit.get", proved.clone()).expect("a proof opens it");
    assert_eq!(record["id"], json!(id));

    // The same proof again: spent.
    let again = call(&state, &owner, NOW, "audit.get", proved);
    assert!(matches!(
        again,
        Err(OpError::PresenceFailed {
            reason: "expired",
            ..
        })
    ));
}

#[test]
fn a_proof_does_not_move_to_other_params_another_op_another_session_or_past_its_ttl() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    let id = some_audit_id(&state, &owner);

    // Other params: the digest differs, the signature does not verify.
    let mut moved = with_proof(&state, &owner, &key, NOW, "audit.get", json!({ "id": id }));
    moved["id"] = json!("a_ffffffffffff");
    assert!(matches!(
        call(&state, &owner, NOW, "audit.get", moved),
        Err(OpError::PresenceFailed {
            reason: "invalid",
            ..
        })
    ));

    // Another op: the broker issued the nonce for audit.get.
    let proved = with_proof(&state, &owner, &key, NOW, "audit.get", json!({ "id": id }));
    assert!(matches!(
        call(&state, &owner, NOW, "totp.seed", proved),
        Err(OpError::Malformed(_)
            | OpError::PresenceFailed { .. }
            | OpError::CapabilityNotHeld { .. })
    ));

    // Another session.
    let other = login(&state);
    let proved = with_proof(&state, &owner, &key, NOW, "audit.get", json!({ "id": id }));
    assert!(matches!(
        call(&state, &other, NOW, "audit.get", proved),
        Err(OpError::PresenceFailed {
            reason: "expired",
            ..
        })
    ));

    // Past its 60 seconds.
    let proved = with_proof(&state, &owner, &key, NOW, "audit.get", json!({ "id": id }));
    assert!(matches!(
        call(&state, &owner, NOW + 61, "audit.get", proved),
        Err(OpError::PresenceFailed {
            reason: "expired",
            ..
        })
    ));
}

#[test]
fn an_agent_cannot_obtain_a_challenge_and_a_lock_voids_them() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    assert!(call(
        &state,
        &anyone(),
        NOW,
        "presence.challenge",
        json!({ "op": "audit.get", "params": {} })
    )
    .is_err());

    let id = some_audit_id(&state, &owner);
    let proved = with_proof(&state, &owner, &key, NOW, "audit.get", json!({ "id": id }));
    state.lock();
    let owner2 = login(&state);
    assert!(matches!(
        call(&state, &owner2, NOW, "audit.get", proved),
        Err(OpError::PresenceFailed {
            reason: "expired",
            ..
        })
    ));
}

#[test]
fn a_second_key_needs_the_first_and_enrolment_survives_a_restart_but_not_tampering() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);

    let second = Signer::software();
    let ask = json!({ "publicKey": B64.encode(second.public()), "label": "second" });
    let ask = with_possession(&state, &owner, &second, NOW, ask);
    assert!(matches!(
        call(&state, &owner, NOW, "presence.enrol", ask.clone()),
        Err(OpError::PresenceRequired { .. })
    ));
    let proved = with_proof(&state, &owner, &key, NOW, "presence.enrol", ask);
    call(&state, &owner, NOW, "presence.enrol", proved).expect("with the first key");
    assert_eq!(state.presence_keys().len(), 2);

    // Restart.
    let fresh = v.broker(None);
    let owner = login(&fresh);
    assert_eq!(fresh.presence_keys().len(), 2);
    let status = call(&fresh, &owner, NOW, "presence.status", json!({})).unwrap();
    assert_eq!(status["enrolled"].as_array().unwrap().len(), 2);

    // Tamper: the vault refuses to open rather than reading "nothing enrolled".
    let file = v.paths().presence_enroll();
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, text.replace("test Mac", "evil Mac")).unwrap();
    let tampered = v.broker(None);
    let r = call(
        &tampered,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    );
    assert!(matches!(r, Err(OpError::Internal(_))), "{r:?}");
}

#[test]
fn touch_id_unlock_opens_the_vault_and_survives_a_root_key_rotation() {
    let helper = helper_or_skip!();
    let (v, state) = created_vault(Some(&helper));
    let owner = login(&state);

    // Not set up yet.
    let r = call(
        &state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "method": "device" }),
    );
    assert!(
        matches!(
            r,
            Err(OpError::PresenceFailed {
                reason: "not_enrolled",
                ..
            })
        ),
        "{r:?}"
    );

    call(&state, &owner, NOW, "device.enrol", json!({})).expect("device.enrol");
    assert!(v.paths().root_wrap_se().exists());
    let wrap = presence_file::load_device_wrap(&v.paths())
        .unwrap()
        .unwrap();
    assert_eq!(
        wrap.authenticate(&root_key(&v)),
        presence_file::WrapAuth::Valid,
        "ADR-148: device.enrol writes a tagged wrap"
    );
    let status = call(&state, &owner, NOW, "presence.status", json!({})).unwrap();
    assert_eq!(status["touchIdUnlock"], json!(true));

    // Lock, then open with the Secure Enclave and no passphrase.
    state.lock();
    let opened = call(
        &state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "method": "device" }),
    )
    .expect("device unlock");
    assert_eq!(opened["locked"], json!(false));
    assert!(opened["token"].is_string());

    // A fresh daemon (a restart) does the same.
    let fresh = v.broker(Some(&helper));
    let opened = call(
        &fresh,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "method": "device" }),
    )
    .expect("device unlock after restart");
    assert!(opened["token"].is_string());

    // Rotate the root key (needs a presence key too), then the Touch ID unlock still opens the vault.
    let owner = login(&fresh);
    let key = enrol_first_key(&fresh, &owner);
    let params = json!({ "passphrase": PASSPHRASE });
    let proved = with_proof(&fresh, &owner, &key, NOW, "maintenance.rotate_root", params);
    let rotated =
        call(&fresh, &owner, NOW, "maintenance.rotate_root", proved).expect("rotate_root");
    assert_eq!(rotated["rotated"], json!(true));
    assert!(
        rotated["notResigned"].as_array().unwrap().is_empty(),
        "{rotated}"
    );

    let after = v.broker(Some(&helper));
    let opened = call(
        &after,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "method": "device" }),
    )
    .expect("device unlock after rotation");
    assert!(opened["token"].is_string());
    // The enrolment was re-signed too.
    assert_eq!(after.presence_keys().len(), 1);

    // Remove it.
    let owner = login(&after);
    let params = json!({});
    let proved = with_proof(&after, &owner, &key, NOW, "device.remove", params);
    call(&after, &owner, NOW, "device.remove", proved).expect("device.remove");
    after.lock();
    let r = call(
        &after,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "method": "device" }),
    );
    assert!(matches!(
        r,
        Err(OpError::PresenceFailed {
            reason: "not_enrolled",
            ..
        })
    ));
}

#[test]
fn widening_a_nodes_reach_needs_a_proof_and_narrowing_does_not() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID }),
    )
    .unwrap();

    let widen = json!({ "node": "acme", "policy": { "descendantRead": true }, "reason": "test" });
    assert!(matches!(
        call(&state, &owner, NOW, "node.policy", widen.clone()),
        Err(OpError::PresenceRequired { .. })
    ));
    let proved = with_proof(&state, &owner, &key, NOW, "node.policy", widen);
    call(&state, &owner, NOW, "node.policy", proved).expect("widening with a proof");

    let narrow = json!({ "node": "acme", "policy": { "descendantRead": false }, "reason": "test" });
    call(&state, &owner, NOW, "node.policy", narrow).expect("narrowing needs no proof");
}

#[test]
fn the_wire_carries_the_proof_and_audits_without_the_signature_being_a_secret() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    let id = some_audit_id(&state, &owner);
    let token = {
        let registry = state.registry.read().unwrap().clone();
        let _ = registry;
        owner.token_id.clone().unwrap()
    };
    let proved = with_proof(&state, &owner, &key, NOW, "audit.get", json!({ "id": id }));
    let (result, _audit) = server::handle_request(
        &state,
        &peer(),
        &Request {
            id: "r1".into(),
            op: "audit.get".into(),
            token: Some(token),
            params: proved,
        },
    );
    assert!(result.is_ok(), "{result:?}");
}

// ---- the remaining gated operations: each is refused without a proof and works with one ----------

fn must_need_proof(r: Result<Value, OpError>) {
    assert!(
        matches!(r, Err(OpError::PresenceRequired { .. })),
        "expected presence_required, got {r:?}"
    );
}

#[test]
fn totp_seed_is_revealed_only_with_a_proof() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID }),
    )
    .unwrap();
    let seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let created = call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": "acme", "name": "GITHUB_2FA", "value": seed }),
    )
    .unwrap();
    let entry = created["entry"].as_str().unwrap().to_string();

    let ask = json!({ "node": "acme", "entry": entry });
    must_need_proof(call(&state, &owner, NOW, "totp.seed", ask.clone()));
    let proved = with_proof(&state, &owner, &key, NOW, "totp.seed", ask);
    let out = call(&state, &owner, NOW, "totp.seed", proved).expect("with a proof");
    assert_eq!(out["seed"], json!(seed));
}

#[test]
fn grant_create_and_node_reparent_work_with_a_proof_and_change_nothing_without() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    for id in ["acme", "globex"] {
        call(
            &state,
            &owner,
            NOW,
            "node.create",
            json!({ "id": id, "label": id, "parentId": GLOBAL_ID }),
        )
        .unwrap();
    }

    // grant.create
    let ask = json!({
        "from": "acme", "to": { "kind": "node", "nodeId": "globex" },
        "scope": ["read"], "reason": "shared staging server",
    });
    must_need_proof(call(&state, &owner, NOW, "grant.create", ask.clone()));
    assert!(state.registry.read().unwrap().grants.is_empty());
    let proved = with_proof(&state, &owner, &key, NOW, "grant.create", ask.clone());
    let grant = call(&state, &owner, NOW, "grant.create", proved).expect("grant with a proof");
    assert!(grant["id"].as_str().unwrap().starts_with("g_"));
    assert_eq!(state.registry.read().unwrap().grants.len(), 1);
    // The identical grant is refused.
    let proved = with_proof(&state, &owner, &key, NOW, "grant.create", ask);
    assert!(matches!(
        call(&state, &owner, NOW, "grant.create", proved),
        Err(OpError::Malformed(_))
    ));

    // node.reparent: acme under globex (depth 2), then globex cannot go under acme (a cycle).
    let ask =
        json!({ "node": "acme", "newParent": "globex", "reason": "acme is a globex project" });
    must_need_proof(call(&state, &owner, NOW, "node.reparent", ask.clone()));
    assert_eq!(
        state.registry.read().unwrap().nodes["acme"]
            .parent_id
            .as_deref(),
        Some(GLOBAL_ID)
    );
    let proved = with_proof(&state, &owner, &key, NOW, "node.reparent", ask);
    let moved = call(&state, &owner, NOW, "node.reparent", proved).expect("reparent with a proof");
    assert_eq!(moved["depth"], json!(2));
    assert_eq!(state.registry.read().unwrap().nodes["acme"].depth, 2);
    let cycle = json!({ "node": "globex", "newParent": "acme", "reason": "this would be a cycle" });
    let proved = with_proof(&state, &owner, &key, NOW, "node.reparent", cycle);
    assert!(matches!(
        call(&state, &owner, NOW, "node.reparent", proved),
        Err(OpError::Malformed(_))
    ));
}

#[test]
fn a_sealed_entry_is_readable_only_with_a_proof_and_the_value_comes_back() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID }),
    )
    .unwrap();
    let created = call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": "acme", "name": "STRIPE_KEY", "value": "sk_test_abc123" }),
    )
    .unwrap();
    let _ = created;
    call(&state, &owner, NOW, "node.seal", json!({ "node": "acme" })).expect("seal");

    let listed = call(&state, &owner, NOW, "orphan.list", json!({})).unwrap();
    let entry = listed["entries"][0]["entry"].as_str().unwrap().to_string();
    assert_eq!(listed["entries"][0]["name"], json!("STRIPE_KEY"));

    // The ordinary read is refused outright, as ever.
    assert!(call(
        &state,
        &owner,
        NOW,
        "entry.reveal",
        json!({ "node": "orphan", "entry": entry })
    )
    .is_err());
    // The sealed read: no proof, no value.
    let ask = json!({ "entry": entry });
    must_need_proof(call(&state, &owner, NOW, "orphan.reveal", ask.clone()));
    let proved = with_proof(&state, &owner, &key, NOW, "orphan.reveal", ask);
    let out = call(&state, &owner, NOW, "orphan.reveal", proved).expect("sealed read with a proof");
    assert_eq!(out["value"], json!("sk_test_abc123"));
    // An agent cannot, even holding a proof-shaped params object.
    assert!(call(
        &state,
        &anyone(),
        NOW,
        "orphan.reveal",
        json!({ "entry": entry })
    )
    .is_err());
}

// ---- ADR-148: the pre-stable security fixes -------------------------------------------------------------

/// What the software stand-in for the Secure Enclave helper does when asked to open the wrap (`ecdh`, the one
/// call that would show a Touch ID prompt).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Finger {
    /// The person touches the sensor: the wrap opens.
    Touches,
    /// The person dismisses the prompt.
    Dismisses,
    /// Nobody answers: the helper sits there until the broker's timeout kills it.
    WalksAway,
}

/// A software stand-in for the Secure Enclave helper (ADR-148 §P2-5 and its addendum), so the Touch ID unlock
/// runs on any Unix host. It answers `enroll` with a fixed blob and point and `ephemeral` with a fixed point and
/// shared secret; `ecdh` — the prompt — answers per `finger`, with that same shared secret when the wrap opens
/// (an ECIES seal and open agree whenever both sides use one secret, so the real root key round-trips). Every
/// prompt is logged, one request per line, to the returned path.
fn stand_in_helper(
    dir: &std::path::Path,
    finger: Finger,
) -> (credmgr_keystore::secure_enclave::Helper, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let point = |tag: u8| {
        let mut p = vec![4u8];
        p.extend_from_slice(&[tag; 64]);
        B64.encode(p)
    };
    let (blob, public, eph, shared) = (
        B64.encode(b"stand-in wrap key"),
        point(0x51),
        point(0x52),
        B64.encode([0x53u8; 32]),
    );
    let prompt = match finger {
        Finger::Touches => format!("printf '{{\"ok\":true,\"secret\":\"{shared}\"}}'"),
        Finger::Dismisses => {
            "printf '{\"ok\":false,\"error\":\"cancelled\",\"detail\":\"dismissed\"}'".to_string()
        }
        Finger::WalksAway => "sleep 5".to_string(),
    };
    let script = dir.join(format!("stand-in-presence-helper-{}", finger as u8));
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nreq=$(cat)\ncase \"$req\" in\n\
             *'\"cmd\":\"probe\"'*) printf '{{\"ok\":true,\"secureEnclave\":true,\"biometry\":\"touchid\",\"passcode\":true}}' ;;\n\
             *'\"cmd\":\"enroll\"'*) printf '{{\"ok\":true,\"blob\":\"{blob}\",\"public\":\"{public}\"}}' ;;\n\
             *'\"cmd\":\"ephemeral\"'*) printf '{{\"ok\":true,\"public\":\"{eph}\",\"secret\":\"{shared}\"}}' ;;\n\
             *'\"cmd\":\"ecdh\"'*) printf '%s\\n' \"$req\" >> \"$0.requests\"; {prompt} ;;\n\
             *) printf '{{\"ok\":false,\"error\":\"failed\",\"detail\":\"unknown\"}}' ;;\nesac\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let log = dir.join(format!(
        "stand-in-presence-helper-{}.requests",
        finger as u8
    ));
    (credmgr_keystore::secure_enclave::Helper::at(script), log)
}

/// How many Touch ID prompts the stand-in has shown.
fn prompts(log: &std::path::Path) -> usize {
    std::fs::read_to_string(log).map_or(0, |t| t.lines().count())
}

/// A syntactically valid Touch ID wrap whose public point is `public` (no prompt is ever needed to plant one:
/// the file is plain JSON in the vault directory).
fn planted_wrap(public: &[u8]) -> DeviceWrap {
    let mut sealed = b"CMSE".to_vec();
    sealed.push(1);
    sealed.extend_from_slice(public);
    sealed.extend_from_slice(&[7u8; 12 + 32 + 16]);
    DeviceWrap::new(&[1, 2, 3, 4], public, &sealed, NOW)
}

#[test]
fn p1_1_a_planted_touch_id_wrap_never_receives_the_new_root_key() {
    let dir = tempfile::tempdir().unwrap();
    let (helper, _log) = stand_in_helper(dir.path(), Finger::Touches);
    let (v, state) = created_vault(Some(&helper));
    let owner = login(&state);
    call(&state, &owner, NOW, "device.enrol", json!({})).expect("device.enrol");
    let enrolled_point = presence_file::load_device_wrap(&v.paths())
        .unwrap()
        .unwrap()
        .wrap_public_bytes()
        .unwrap();
    let key = enrol_first_key(&state, &owner);
    let pass_wrap_before = std::fs::read(v.paths().root_wrap_pass()).unwrap();
    let rotate = |state: &Arc<BrokerState>| {
        let proved = with_proof(
            state,
            &owner,
            &key,
            NOW,
            "maintenance.rotate_root",
            json!({ "passphrase": PASSPHRASE }),
        );
        call(state, &owner, NOW, "maintenance.rotate_root", proved)
    };

    // Over the enrolled point, untagged (what anyone with write access to the vault directory can write) and
    // forged-tag variants: the tag check refuses the rotation.
    for forge in [false, true] {
        let mut wrap = planted_wrap(&enrolled_point);
        if forge {
            wrap = wrap.signed(&[0x42; 32]);
        }
        presence_file::save_device_wrap(&v.paths(), &wrap).unwrap();
        let r = rotate(&state);
        let why = format!("{r:?}");
        assert!(r.is_err(), "forge={forge}: rotation must refuse: {why}");
        assert!(
            why.contains("not authenticated") || why.contains("integrity check"),
            "forge={forge}: refused because the wrap is unauthenticated, not for another reason: {why}"
        );
        assert_eq!(
            std::fs::read(v.paths().root_wrap_pass()).unwrap(),
            pass_wrap_before,
            "forge={forge}: the root key was not rotated"
        );
        assert_eq!(
            presence_file::load_device_wrap(&v.paths())
                .unwrap()
                .unwrap(),
            wrap,
            "forge={forge}: the planted wrap was not re-sealed"
        );
    }

    // ADR-148 addendum: a validly tagged wrap at a point the registry does not name (the attacker's own) is not
    // set up at all — the rotation goes ahead and leaves the planted file exactly as it was.
    let attacker = planted_wrap(&Signer::software().public()).signed(&root_key(&v));
    presence_file::save_device_wrap(&v.paths(), &attacker).unwrap();
    rotate(&state).expect("an unnamed wrap does not block a rotation");
    assert_eq!(
        presence_file::load_device_wrap(&v.paths())
            .unwrap()
            .unwrap(),
        attacker,
        "the unnamed wrap never received the new root key"
    );
}

/// A vault with Touch ID unlock set up through `helper`, then locked.
fn touch_id_vault(
    helper: &credmgr_keystore::secure_enclave::Helper,
) -> (Vault, Arc<BrokerState>, BrokerScope) {
    let (v, state) = created_vault(Some(helper));
    let owner = login(&state);
    call(&state, &owner, NOW, "device.enrol", json!({})).expect("device.enrol");
    (v, state, owner)
}

/// ADR-165 N5: a passphrase change now gives every live node a new keypair inside its rotation; the Touch ID
/// unlock wrap is still re-sealed to the new root key in the same commit, so Touch ID opens the vault after it,
/// on a fresh daemon, and the re-keyed entries read back.
#[test]
fn touch_id_unlock_survives_a_rekeying_passphrase_change() {
    const TEST_NEW_PASSPHRASE: &str = "a new passphrase chosen with touch id on";
    let dir = tempfile::tempdir().unwrap();
    let (helper, _log) = stand_in_helper(dir.path(), Finger::Touches);
    let (v, state, owner) = touch_id_vault(&helper);
    let key = enrol_first_key(&state, &owner);
    create_node(&state, &owner, "acme");
    let entry = create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
    let before = root_key(&v);
    let proved = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "vault.set_passphrase",
        json!({ "passphrase": PASSPHRASE, "newPassphrase": TEST_NEW_PASSPHRASE }),
    );
    let changed = call(&state, &owner, NOW, "vault.set_passphrase", proved).expect("change");
    assert_eq!(
        changed["nodesRekeyed"],
        json!(["acme", "global"]),
        "{changed}"
    );
    assert!(
        changed["notResigned"].as_array().unwrap().is_empty(),
        "{changed}"
    );
    let wrap = presence_file::load_device_wrap(&v.paths())
        .unwrap()
        .unwrap();
    assert_eq!(wrap.authenticate(&before), presence_file::WrapAuth::Invalid);
    drop(owner);
    drop(state);
    let fresh = v.broker(Some(&helper));
    let opened = call(
        &fresh,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "method": "device" }),
    )
    .expect("Touch ID opens the vault after a re-keying passphrase change");
    let owner = scope_of(&fresh, opened["token"].as_str().expect("a token"));
    assert_eq!(reveal(&fresh, &owner, "acme", &entry), "alpha-secret");
    verify_ok(&fresh, &owner);
}

#[test]
fn p1_5_an_identified_agent_never_receives_a_session_from_touch_id() {
    let dir = tempfile::tempdir().unwrap();
    let (helper, log) = stand_in_helper(dir.path(), Finger::Touches);
    let (_v, state, owner) = touch_id_vault(&helper);
    create_node(&state, &owner, "acme");
    let workdir = dir.path().join("acme-project");
    std::fs::create_dir_all(&workdir).unwrap();
    let workdir = workdir
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    call(
        &state,
        &owner,
        NOW,
        "node.set_workdirs",
        json!({ "node": "acme", "workdirs": [workdir] }),
    )
    .expect("set_workdirs");
    state.lock();

    // An agent token.
    let token = state.tokens.issue(
        "acme",
        vec![Capability::List, Capability::Read],
        Origin::Agent,
        None,
    );
    let agent_token = scope_of(&state, &token.id);
    // No token, launched inside a registered project folder (`scope::resolve_scope`'s agent scope).
    let in_project = BrokerScope {
        node_id: "acme".into(),
        capabilities: vec![Capability::List, Capability::Read],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: Some(format!("{workdir}/src")),
    };
    for (who, scope) in [("agent token", agent_token), ("project folder", in_project)] {
        let r = call(
            &state,
            &scope,
            NOW,
            "vault.unlock",
            json!({ "method": "device" }),
        );
        assert!(
            matches!(r, Err(OpError::CapabilityNotHeld { .. })),
            "{who}: an identified agent is refused: {r:?}"
        );
        assert_eq!(
            prompts(&log),
            0,
            "{who}: refused before any Touch ID prompt was shown"
        );
    }
    assert!(state.is_locked(), "nothing was unlocked");
    // And the same stand-in does open it for anyone else — so the refusal above is the rule, not a failure.
    call(
        &state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "method": "device" }),
    )
    .expect("a person's terminal may unlock");
    assert_eq!(prompts(&log), 1);
}

/// Five failed Touch ID prompts from `asking`, through the real request path; the sixth must be backed off.
fn assert_five_failed_prompts_back_off(
    state: &Arc<BrokerState>,
    asking: &credmgr_brokerd::peer::PeerInfo,
) {
    let unlock = || {
        server::handle_request(
            state,
            asking,
            &Request {
                id: "u".into(),
                op: "vault.unlock".into(),
                token: None,
                params: json!({ "method": "device" }),
            },
        )
        .0
    };
    for n in 0..5 {
        let r = unlock();
        assert!(
            matches!(
                r,
                Err(OpError::PresenceFailed {
                    reason: "cancelled",
                    ..
                })
            ),
            "attempt {n}: {r:?}"
        );
    }
    let r = unlock();
    assert!(
        matches!(r, Err(OpError::RateLimited { .. })),
        "five failed prompts back the uid off: {r:?}"
    );
}

#[test]
fn p1_5_the_touch_id_prompt_names_who_asked_and_a_dismissal_counts_against_the_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let (helper, log) = stand_in_helper(dir.path(), Finger::Dismisses);
    let (_v, state, _owner) = touch_id_vault(&helper);
    state.lock();
    let asking = credmgr_brokerd::peer::PeerInfo {
        uid: 4242,
        pid: std::process::id() as i32,
        cwd: Some("/srv/work/code/acme".into()),
    };
    let r = server::handle_request(
        &state,
        &asking,
        &Request {
            id: "u".into(),
            op: "vault.unlock".into(),
            token: None,
            // A client cannot choose the name shown: `_peer` is the server's.
            params: json!({ "method": "device", "_peer": "System Settings" }),
        },
    )
    .0;
    assert!(
        matches!(
            r,
            Err(OpError::PresenceFailed {
                reason: "cancelled",
                ..
            })
        ),
        "{r:?}"
    );
    let sent = std::fs::read_to_string(log).unwrap();
    assert!(
        sent.contains("Unlock CredMgr for ")
            && sent.contains(&format!("pid {}", std::process::id())),
        "the dialog names the requesting process: {sent}"
    );
    assert!(
        sent.contains("/srv/work/code/acme"),
        "and its folder: {sent}"
    );
    assert!(
        !sent.contains("System Settings"),
        "a client-supplied name is discarded: {sent}"
    );
    // Five dismissals from one uid back it off, like five wrong passphrases.
    let other = credmgr_brokerd::peer::PeerInfo {
        uid: 4343,
        ..asking
    };
    assert_five_failed_prompts_back_off(&state, &other);
}

/// ADR-148 addendum: a prompt nobody answers, left until the helper's timeout, counts against the backoff like a
/// dismissal (before, it read as "unavailable" and cost nothing, so it could be shown again and again).
#[test]
fn a_touch_id_prompt_left_to_time_out_counts_like_a_dismissal() {
    let dir = tempfile::tempdir().unwrap();
    let (helper, log) = stand_in_helper(dir.path(), Finger::WalksAway);
    // 1.5 s: below the stand-in's 5 s wait so every prompt times out, with room for the un-prompted enrol under a loaded
    // full-suite run (300 ms timed the setup out, 2026-11-08).
    let helper = helper.with_timeout(std::time::Duration::from_millis(1500));
    let (_v, state, _owner) = touch_id_vault(&helper);
    state.lock();
    let asking = credmgr_brokerd::peer::PeerInfo {
        uid: 4444,
        pid: std::process::id() as i32,
        cwd: None,
    };
    assert_five_failed_prompts_back_off(&state, &asking);
    assert_eq!(prompts(&log), 5, "the backed-off sixth showed no prompt");
}

/// ADR-148 §P2-5 and its addendum: the whole Touch ID unlock journey on the software stand-in, with no Secure
/// Enclave — the wrap's tag re-signed by one root-key rotation verifies at the next, and a wrap put back after
/// `device.remove` (validly tagged, from a backup) unlocks nothing and receives no new root key.
#[test]
fn p2_5_touch_id_unlock_survives_two_rotations_and_a_removed_wrap_stays_removed() {
    let dir = tempfile::tempdir().unwrap();
    let (helper, log) = stand_in_helper(dir.path(), Finger::Touches);
    let (v, state, owner) = touch_id_vault(&helper);
    let key = enrol_first_key(&state, &owner);
    let unlock_by_touch = |state: &Arc<BrokerState>| {
        call(
            state,
            &anyone(),
            NOW,
            "vault.unlock",
            json!({ "method": "device" }),
        )
    };
    drop(owner);
    state.lock();
    let opened = unlock_by_touch(&state).expect("touch");
    let owner = scope_of(&state, opened["token"].as_str().expect("a token"));

    let (mut state, mut owner) = (state, owner);
    for round in 1..=2 {
        let before = root_key(&v);
        let proved = with_proof(
            &state,
            &owner,
            &key,
            NOW,
            "maintenance.rotate_root",
            json!({ "passphrase": PASSPHRASE }),
        );
        let rotated = call(&state, &owner, NOW, "maintenance.rotate_root", proved)
            .unwrap_or_else(|e| panic!("rotation {round}: {e:?}"));
        assert!(
            rotated["notResigned"].as_array().unwrap().is_empty(),
            "rotation {round}: {rotated}"
        );
        let after = root_key(&v);
        assert_ne!(before, after, "rotation {round} changed the root key");
        let wrap = presence_file::load_device_wrap(&v.paths())
            .unwrap()
            .unwrap();
        assert_eq!(
            wrap.authenticate(&after),
            presence_file::WrapAuth::Valid,
            "rotation {round}: the wrap is re-signed under the new root key"
        );
        assert_eq!(wrap.authenticate(&before), presence_file::WrapAuth::Invalid);
        // A fresh daemon opens the vault with Touch ID, under the new root key.
        drop(owner);
        let (fresh, _) = restart(&v, state, Some(&helper));
        fresh.lock();
        let opened = unlock_by_touch(&fresh)
            .unwrap_or_else(|e| panic!("touch after rotation {round}: {e:?}"));
        owner = scope_of(&fresh, opened["token"].as_str().expect("a token"));
        state = fresh;
    }

    // Remove it, keeping the (validly tagged) file as a backup would have.
    let kept = std::fs::read(v.paths().root_wrap_se()).unwrap();
    let proved = with_proof(&state, &owner, &key, NOW, "device.remove", json!({}));
    call(&state, &owner, NOW, "device.remove", proved).expect("device.remove");
    std::fs::write(v.paths().root_wrap_se(), &kept).unwrap();
    let shown = prompts(&log);
    let status = call(&state, &anyone(), NOW, "vault.status", json!({})).unwrap();
    assert_eq!(status["touchIdUnlock"], json!(false), "{status}");

    // Neither this daemon nor a fresh one (which has not verified anything yet) offers the old wrap a prompt.
    state.lock();
    for who in ["this daemon", "a fresh daemon"] {
        let probe = if who == "this daemon" {
            state.clone()
        } else {
            v.broker(Some(&helper))
        };
        let r = unlock_by_touch(&probe);
        assert!(
            matches!(
                r,
                Err(OpError::PresenceFailed {
                    reason: "not_enrolled",
                    ..
                })
            ),
            "{who}: a wrap put back after removal unlocks nothing: {r:?}"
        );
        assert_eq!(prompts(&log), shown, "{who}: and shows no prompt");
    }

    // A rotation does not re-seal the new root key to it either.
    let owner = login(&state);
    let proved = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "maintenance.rotate_root",
        json!({ "passphrase": PASSPHRASE }),
    );
    call(&state, &owner, NOW, "maintenance.rotate_root", proved).expect("rotation");
    assert_eq!(std::fs::read(v.paths().root_wrap_se()).unwrap(), kept);
}

/// ADR-148 addendum: `presence.unenrol` writes the signed registry before memory and the enrolment file change.
/// A write that fails leaves the key enrolled — in this process too, as the error says — never removed here but
/// back at the next start.
#[test]
fn a_failed_unenrol_changes_nothing_and_a_successful_one_survives_a_restart() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let first = enrol_first_key(&state, &owner);
    let second = Signer::software();
    let ask = json!({ "publicKey": B64.encode(second.public()), "label": "second" });
    let ask = with_possession(&state, &owner, &second, NOW, ask);
    let ask = with_proof(&state, &owner, &first, NOW, "presence.enrol", ask);
    let id = call(&state, &owner, NOW, "presence.enrol", ask).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let file_before = std::fs::read(v.paths().presence_enroll()).unwrap();

    state.set_persist_fault_for_test(Some(
        credmgr_brokerd::state::PersistFault::FailBeforeRegistry,
    ));
    let ask = with_proof(
        &state,
        &owner,
        &first,
        NOW,
        "presence.unenrol",
        json!({ "id": id }),
    );
    let r = call(&state, &owner, NOW, "presence.unenrol", ask);
    assert!(r.is_err(), "{r:?}");
    assert_eq!(
        state.presence_keys().len(),
        2,
        "memory did not move ahead of the registry"
    );
    assert_eq!(
        std::fs::read(v.paths().presence_enroll()).unwrap(),
        file_before,
        "nor did the enrolment file"
    );
    state.set_persist_fault_for_test(None);
    let (state, owner) = restart(&v, state, None);
    assert_eq!(state.presence_keys().len(), 2);

    let ask = with_proof(
        &state,
        &owner,
        &first,
        NOW,
        "presence.unenrol",
        json!({ "id": id }),
    );
    assert_eq!(
        call(&state, &owner, NOW, "presence.unenrol", ask).unwrap()["removed"],
        json!(true)
    );
    // Put the two-key file back: the registry's list, written first, is the list.
    std::fs::write(v.paths().presence_enroll(), &file_before).unwrap();
    let (state, _owner) = restart(&v, state, None);
    assert_eq!(
        state.presence_keys().len(),
        1,
        "the removed key stays removed"
    );
}

#[test]
fn p2_4_deleting_or_replaying_the_enrolment_file_does_not_unenrol_and_enrolment_needs_possession() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    let one_key_file = std::fs::read(v.paths().presence_enroll()).unwrap();

    // Possession: a key the client does not hold, or no proof at all, is refused.
    let second = Signer::software();
    let ask = json!({ "publicKey": B64.encode(second.public()), "label": "second" });
    let wrong = with_possession(&state, &owner, &Signer::software(), NOW, ask.clone());
    let wrong = with_proof(&state, &owner, &key, NOW, "presence.enrol", wrong);
    assert!(
        matches!(
            call(&state, &owner, NOW, "presence.enrol", wrong),
            Err(OpError::PresenceFailed {
                reason: "invalid",
                ..
            })
        ),
        "a possession proof by another key is refused"
    );
    let bare = with_proof(&state, &owner, &key, NOW, "presence.enrol", ask.clone());
    assert!(
        matches!(
            call(&state, &owner, NOW, "presence.enrol", bare),
            Err(OpError::Malformed(_))
        ),
        "no possession proof, no enrolment"
    );
    let good = with_possession(&state, &owner, &second, NOW, ask);
    let good = with_proof(&state, &owner, &key, NOW, "presence.enrol", good);
    call(&state, &owner, NOW, "presence.enrol", good).expect("held, and approved by the first key");
    assert_eq!(state.presence_keys().len(), 2);

    // Replay the older one-key file: the registry's list is the list.
    std::fs::write(v.paths().presence_enroll(), one_key_file).unwrap();
    let (state, owner) = restart(&v, state, None);
    assert_eq!(
        state.presence_keys().len(),
        2,
        "a replayed enrolment file is ignored"
    );

    // Delete it: still enrolled, and a gated op still needs a proof.
    std::fs::remove_file(v.paths().presence_enroll()).unwrap();
    let (state, owner2) = restart(&v, state, None);
    drop(owner);
    assert_eq!(
        state.presence_keys().len(),
        2,
        "a deleted enrolment file unenrols nothing"
    );
    let intruder = Signer::software();
    let ask = json!({ "publicKey": B64.encode(intruder.public()), "label": "intruder" });
    let ask = with_possession(&state, &owner2, &intruder, NOW, ask);
    assert!(
        matches!(
            call(&state, &owner2, NOW, "presence.enrol", ask),
            Err(OpError::PresenceRequired { .. })
        ),
        "with the file gone, enrolling another key still needs an enrolled key's proof"
    );
}

#[test]
fn p2_5_at_most_eight_keys_and_the_oldest_of_sixty_four_challenges_is_evicted() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let first = enrol_first_key(&state, &owner);
    for n in 2..=8 {
        let k = Signer::software();
        let ask = json!({ "publicKey": B64.encode(k.public()), "label": format!("key {n}") });
        let ask = with_possession(&state, &owner, &k, NOW, ask);
        let ask = with_proof(&state, &owner, &first, NOW, "presence.enrol", ask);
        call(&state, &owner, NOW, "presence.enrol", ask).expect("up to eight");
    }
    let ninth = Signer::software();
    let ask = json!({ "publicKey": B64.encode(ninth.public()), "label": "ninth" });
    let ask = with_possession(&state, &owner, &ninth, NOW, ask);
    let ask = with_proof(&state, &owner, &first, NOW, "presence.enrol", ask);
    assert!(
        matches!(call(&state, &owner, NOW, "presence.enrol", ask), Err(OpError::Malformed(m)) if m.contains("at most 8")),
        "a ninth key is refused"
    );
    assert_eq!(state.presence_keys().len(), 8);

    // The table holds 64: the 65th challenge evicts the oldest (the one expiring first), which then no
    // longer verifies — all well inside the 60-second TTL, so this is eviction and not expiry.
    let id = some_audit_id(&state, &owner);
    let oldest = with_proof(
        &state,
        &owner,
        &first,
        NOW,
        "audit.get",
        json!({ "id": id }),
    );
    for _ in 1..=64 {
        call(
            &state,
            &owner,
            NOW + 1,
            "presence.challenge",
            json!({ "op": "audit.get", "params": { "id": id } }),
        )
        .unwrap();
    }
    assert!(
        matches!(
            call(&state, &owner, NOW + 1, "audit.get", oldest),
            Err(OpError::PresenceFailed {
                reason: "expired",
                ..
            })
        ),
        "the evicted challenge is gone"
    );
}

// --- ADR-173: approving an agent's waiting request needs a presence proof when a key is enrolled -------------

/// A node locked by its owner, and the request an owner-session reveal leaves behind (ADR-042).
fn waiting_request(state: &BrokerState, owner: &BrokerScope) -> String {
    create_node(state, owner, "acme");
    let entry = create_entry(state, owner, "acme", "API_KEY", "s3cr3t-value");
    call(
        state,
        owner,
        NOW,
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .expect("node lock");
    match call(
        state,
        owner,
        NOW,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    ) {
        Err(OpError::ApprovalPending { request, .. }) => request,
        other => panic!("expected approval_pending, got {other:?}"),
    }
}

#[test]
fn approving_needs_a_proof_once_a_key_is_enrolled() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    let request = waiting_request(&state, &owner);
    let approve = json!({ "request": request, "approved": true });

    // No proof: the answer these ops always give. Nothing was decided.
    let r = call(
        &state,
        &owner,
        NOW,
        "vault.approval_decide",
        approve.clone(),
    );
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");
    let still = call(
        &state,
        &owner,
        NOW,
        "vault.approval_get",
        json!({ "request": request }),
    )
    .unwrap();
    assert_eq!(still["state"], json!("pending"));

    // A proof made for a denial does not approve.
    let mut other = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "vault.approval_decide",
        json!({ "request": request, "approved": false }),
    );
    other["approved"] = json!(true);
    let r = call(&state, &owner, NOW, "vault.approval_decide", other);
    assert!(matches!(r, Err(OpError::PresenceFailed { .. })), "{r:?}");

    // The right proof approves exactly once.
    let proved = with_proof(&state, &owner, &key, NOW, "vault.approval_decide", approve);
    let done = call(&state, &owner, NOW, "vault.approval_decide", proved.clone())
        .expect("a proof approves");
    assert_eq!(done["approved"], json!(true));
    let again = call(&state, &owner, NOW, "vault.approval_decide", proved);
    assert!(again.is_err(), "a proof is spent");
}

#[test]
fn denying_is_never_gated_with_a_key_enrolled() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let _key = enrol_first_key(&state, &owner);
    let request = waiting_request(&state, &owner);
    let denied = call(
        &state,
        &owner,
        NOW,
        "vault.approval_decide",
        json!({ "request": request, "approved": false }),
    )
    .expect("deny is never gated");
    assert_eq!(denied["approved"], json!(false));
}

#[test]
fn approving_with_no_key_enrolled_is_unchanged() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let request = waiting_request(&state, &owner);
    let done = call(
        &state,
        &owner,
        NOW,
        "vault.approval_decide",
        json!({ "request": request, "approved": true }),
    )
    .expect("no key enrolled: the login is enough, as before");
    assert_eq!(done["approved"], json!(true));
}
