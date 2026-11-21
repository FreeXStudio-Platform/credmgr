//! ADR-164 — node-scoped agent tokens, end to end on a durable vault (`f1_support`): the owner's issue path
//! with its second factor and Touch ID proof (a software P-256 key, so it runs on every host), and every
//! request made with a token through the real server wiring (`server::handle_request_at`).
//!
//! What is proved, each one by trying to break it:
//! * only the owner's login issues or rotates, after a fresh second factor (where enrolled) and a proof for
//!   that exact request; every check that needs no finger comes first;
//! * an agent — a token-less caller, an agent token, a fixture token — reaches none of the four ops;
//! * the capabilities asked for can never exceed what the node gives agents, and the expiry is mandatory;
//! * the bearer is in the issue answer only: never in the status answer, the audit trail or any file;
//! * rotation kills the old bearer at once, revocation the token, expiry the token at its second, and a
//!   broker restart every token.

mod f1_support;

use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::Capability;

use f1_support::*;

const ALL: [&str; 5] = ["list", "read", "reveal", "create", "update"];

fn with_token(
    state: &Arc<BrokerState>,
    token: &str,
    now: i64,
    op: &str,
    params: Value,
) -> Result<Value, OpError> {
    let request = Request {
        id: "r".to_string(),
        op: op.to_string(),
        token: Some(token.to_string()),
        params,
    };
    server::handle_request_at(state, &peer(), &request, now, Instant::now()).0
}

/// A vault with the owner logged in, a presence key, and two projects with one entry each.
fn setup() -> (Vault, Arc<BrokerState>, BrokerScope, Signer, String) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    create_node(&state, &owner, "acme");
    create_node(&state, &owner, "beta");
    let entry = create_entry(&state, &owner, "acme", "API_KEY", "acme-value-1");
    create_entry(&state, &owner, "beta", "BETA_KEY", "beta-value-1");
    (v, state, owner, key, entry)
}

fn issue_params(node: &str, caps: &[&str]) -> Value {
    json!({ "node": node, "label": "ci runner", "capabilities": caps })
}

fn issue(state: &BrokerState, owner: &BrokerScope, key: &Signer, params: Value) -> Value {
    let proved = with_proof(state, owner, key, NOW, "agent.token_issue", params);
    call(state, owner, NOW, "agent.token_issue", proved).expect("issue with a proof")
}

fn bearer(v: &Value) -> String {
    v["token"]
        .as_str()
        .expect("the issue answer carries the token")
        .to_string()
}

fn every_file_under(dir: &std::path::Path, out: &mut Vec<u8>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                every_file_under(&p, out);
            } else if let Ok(bytes) = std::fs::read(&p) {
                out.extend_from_slice(&bytes);
                out.push(b'\n');
            }
        }
    }
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn issuing_needs_the_owners_login_a_fresh_second_factor_and_a_proof() {
    let (_v, state, owner, key, _e) = setup();
    let ask = issue_params("acme", &["list", "read"]);
    // No proof: presence_required, and nothing is issued.
    assert!(matches!(
        call(&state, &owner, NOW, "agent.token_issue", ask.clone()),
        Err(OpError::PresenceRequired { .. })
    ));
    assert!(state.tokens.agent_tokens(NOW).is_empty());
    // A proof for other params does not move.
    let other = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "agent.token_issue",
        issue_params("acme", ALL.as_slice()),
    );
    let mut moved = ask.clone();
    moved["presence"] = other["presence"].clone();
    assert!(call(&state, &owner, NOW, "agent.token_issue", moved).is_err());
    assert!(state.tokens.agent_tokens(NOW).is_empty());

    // With the second factor enrolled, a proof alone is not enough: it must be fresh.
    let totp = enrol_gate(&state, &owner);
    let proved = with_proof(
        &state,
        &owner,
        &key,
        LATER,
        "agent.token_issue",
        ask.clone(),
    );
    assert!(matches!(
        call(&state, &owner, LATER, "agent.token_issue", proved),
        Err(OpError::TwoFactorRequired { .. })
    ));
    step_up(&state, &owner, &totp, LATER);
    let proved = with_proof(
        &state,
        &owner,
        &key,
        LATER,
        "agent.token_issue",
        ask.clone(),
    );
    let v = call(&state, &owner, LATER, "agent.token_issue", proved).expect("fresh factor + proof");
    assert!(bearer(&v).starts_with("cma_"));
    assert_eq!(v["node"], "acme");
    assert_eq!(v["capabilities"], json!(["list", "read"]));
    assert_eq!(v["expiresAt"], json!(LATER + 86_400), "one day by default");
    assert_eq!(v["shownOnce"], true);

    // No agent reaches the op, and none is ever asked for a finger: a token-less caller, a fixture token.
    let fixture = state
        .tokens
        .issue("acme", vec![Capability::Admin], Origin::Cli, None);
    let fixture_scope = scope_of(&state, &fixture.id);
    for scope in [anyone(), fixture_scope] {
        assert!(matches!(
            call(&state, &scope, LATER, "agent.token_issue", ask.clone()),
            Err(OpError::CapabilityNotHeld { .. })
        ));
    }
}

#[test]
fn everything_that_needs_no_finger_is_checked_before_the_prompt() {
    let (_v, state, owner, _key, _e) = setup();
    let malformed = [
        json!({ "node": "acme", "label": "x", "capabilities": ["admin"] }),
        json!({ "node": "acme", "label": "x", "capabilities": ["notes"] }),
        json!({ "node": "acme", "label": "x", "capabilities": [] }),
        json!({ "node": "acme", "label": "x", "capabilities": ["sudo"] }),
        json!({ "node": "acme", "label": "x", "capabilities": "list" }),
        json!({ "node": "acme", "label": "", "capabilities": ["list"] }),
        json!({ "node": "acme", "label": "a\nb", "capabilities": ["list"] }),
        json!({ "node": "acme", "label": "x".repeat(65), "capabilities": ["list"] }),
        json!({ "node": "acme", "label": "x", "capabilities": ["list"], "expiresIn": 0 }),
        json!({ "node": "acme", "label": "x", "capabilities": ["list"], "expiresIn": 59 }),
        json!({ "node": "acme", "label": "x", "capabilities": ["list"], "expiresIn": 604_801 }),
        json!({ "node": "acme", "label": "x", "capabilities": ["list"], "expiresIn": "1d" }),
        json!({ "node": "orphan", "label": "x", "capabilities": ["list"] }),
        json!({ "label": "x", "capabilities": ["list"] }),
        json!({ "node": "acme", "capabilities": ["list"] }),
        json!({ "node": "acme", "label": "x" }),
    ];
    for params in malformed {
        let r = call(&state, &owner, NOW, "agent.token_issue", params.clone());
        assert!(matches!(r, Err(OpError::Malformed(_))), "{params}: {r:?}");
    }
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "agent.token_issue",
            issue_params("nowhere", &["list"])
        ),
        Err(OpError::NotFound(_))
    ));
    // The node's agent access is the ceiling: a read-only node gives no create or update.
    call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "beta", "reason": "read-only for agents", "policy": { "agentAccess": "read-only" } }),
    )
    .expect("narrowing needs no proof");
    for cap in ["create", "update"] {
        let r = call(
            &state,
            &owner,
            NOW,
            "agent.token_issue",
            issue_params("beta", &["list", cap]),
        );
        assert!(
            matches!(r, Err(OpError::Malformed(ref m)) if m.contains(cap)),
            "{cap}: {r:?}"
        );
    }
    assert!(state.tokens.agent_tokens(NOW).is_empty());
}

#[test]
fn the_secret_is_shown_once_and_never_listed_logged_or_audited() {
    let (v, state, owner, key, entry) = setup();
    let issued = issue(
        &state,
        &owner,
        &key,
        issue_params("acme", &["list", "read", "reveal"]),
    );
    let token = bearer(&issued);
    let id = issued["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("a_"));

    // Used: the value comes back (a medium value on a Guarded node).
    let got = with_token(
        &state,
        &token,
        NOW,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert_eq!(got["value"], "acme-value-1");

    // The status answer is metadata: the id, never the bearer, and the use is recorded.
    let status = call(&state, &owner, NOW, "agent.token_status", json!({})).unwrap();
    let text = status.to_string();
    assert!(!text.contains(&token), "{text}");
    assert!(
        !text.contains(&token[4..20]),
        "no fragment of the bearer either"
    );
    let row = &status["tokens"][0];
    assert_eq!(row["id"], json!(id));
    assert_eq!(row["lastUsedAt"], json!(NOW));
    assert!(row.get("token").is_none());
    assert_eq!(status["max"], 32);

    // A refusal does not echo it.
    let refused = with_token(
        &state,
        &token,
        NOW,
        "entry.reveal",
        json!({ "node": "beta", "entry": "e_x" }),
    )
    .unwrap_err();
    assert!(!format!("{refused:?}").contains(&token));
    assert!(!credmgr_brokerd::protocol::to_wire("r", &Err(refused))
        .to_string()
        .contains(&token));

    // No file in the vault or state directory holds the bearer; the trail names the token by its id.
    let mut bytes = Vec::new();
    every_file_under(&v.vault_dir, &mut bytes);
    every_file_under(&v.state_dir, &mut bytes);
    assert!(!contains(&bytes, &token));
    assert!(!contains(&bytes, &token[4..]));
    assert!(
        contains(&bytes, &format!("Agent:{id}")),
        "every request is audited under the token's id"
    );
    // Nor does any printable form of the store.
    assert!(!format!("{:?}", state.tokens).contains(&token));
}

#[test]
fn an_agent_cannot_mint_widen_rotate_list_or_revoke_a_token_its_own_included() {
    let (_v, state, owner, key, _e) = setup();
    let issued = issue(&state, &owner, &key, issue_params("acme", ALL.as_slice()));
    let token = bearer(&issued);
    let id = issued["id"].as_str().unwrap().to_string();
    for (op, params) in [
        // narrower than its own: still no
        ("agent.token_issue", issue_params("acme", &["list"])),
        ("agent.token_issue", issue_params("beta", &["list"])),
        ("agent.token_rotate", json!({ "id": id })),
        ("agent.token_status", json!({})),
        ("agent.token_revoke", json!({ "id": id })),
    ] {
        let r = with_token(&state, &token, NOW, op, params);
        assert!(
            matches!(r, Err(OpError::CapabilityNotHeld { .. })),
            "{op}: {r:?}"
        );
    }
    // It cannot get the challenge an issue would need, so it cannot even put a prompt in front of the owner.
    assert!(with_token(
        &state,
        &token,
        NOW,
        "presence.challenge",
        json!({ "op": "agent.token_issue", "params": issue_params("acme", &["list"]) })
    )
    .is_err());
    assert_eq!(state.tokens.agent_tokens(NOW).len(), 1);
    // The token is untouched by the attempts.
    assert!(with_token(&state, &token, NOW, "whoami", json!({})).is_ok());
}

#[test]
fn rotation_replaces_the_secret_revocation_ends_the_token_and_expiry_ends_it_on_time() {
    let (_v, state, owner, key, _e) = setup();
    let issued = issue(&state, &owner, &key, issue_params("acme", &["list"]));
    let old = bearer(&issued);
    let id = issued["id"].as_str().unwrap().to_string();
    let list = json!({ "node": "acme" });

    // Rotation needs the same gate as issuing.
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "agent.token_rotate",
            json!({ "id": id })
        ),
        Err(OpError::PresenceRequired { .. })
    ));
    let ask = json!({ "id": id, "expiresIn": 3600 });
    let proved = with_proof(&state, &owner, &key, NOW, "agent.token_rotate", ask);
    let rotated =
        call(&state, &owner, NOW, "agent.token_rotate", proved).expect("rotate with a proof");
    let new = bearer(&rotated);
    assert_ne!(new, old);
    assert_eq!(rotated["id"], json!(id), "the token keeps its id");
    assert_eq!(rotated["expiresAt"], json!(NOW + 3600));
    assert!(matches!(
        with_token(&state, &old, NOW, "entry.list", list.clone()),
        Err(OpError::SessionExpired)
    ));
    assert!(with_token(&state, &new, NOW, "entry.list", list.clone()).is_ok());

    // Revocation is safety: no proof, and it holds from the next request.
    let r = call(
        &state,
        &owner,
        NOW,
        "agent.token_revoke",
        json!({ "id": id }),
    )
    .expect("revoke");
    assert_eq!(r["revoked"], true);
    assert!(matches!(
        with_token(&state, &new, NOW, "entry.list", list.clone()),
        Err(OpError::SessionExpired)
    ));
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "agent.token_revoke",
            json!({ "id": id })
        ),
        Err(OpError::NotFound(_))
    ));
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "agent.token_rotate",
            json!({ "id": id })
        ),
        Err(OpError::NotFound(_))
    ));

    // The longest expiry is seven days, and it ends at its second.
    let week =
        json!({ "node": "acme", "label": "week", "capabilities": ["list"], "expiresIn": 604_800 });
    let w = bearer(&issue(&state, &owner, &key, week));
    assert!(with_token(&state, &w, NOW + 604_799, "entry.list", list.clone()).is_ok());
    assert!(matches!(
        with_token(&state, &w, NOW + 604_800, "entry.list", list.clone()),
        Err(OpError::SessionExpired)
    ));
    let status = call(
        &state,
        &owner,
        NOW + 604_800,
        "agent.token_status",
        json!({}),
    )
    .unwrap();
    assert_eq!(status["tokens"], json!([]));
}

#[test]
fn a_restart_revokes_every_agent_token_and_narrowing_a_node_narrows_its_tokens() {
    let (v, state, owner, key, _e) = setup();
    let token = bearer(&issue(
        &state,
        &owner,
        &key,
        issue_params("acme", ALL.as_slice()),
    ));
    let who = with_token(&state, &token, NOW, "whoami", json!({})).unwrap();
    assert_eq!(who["node"], "acme");
    assert_eq!(who["reachable"], json!(["acme"]));
    assert_eq!(who["capabilities"].as_array().unwrap().len(), 5);
    // The owner makes acme read-only for agents: the token loses create and update on its next request.
    call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "acme", "reason": "read-only for agents", "policy": { "agentAccess": "read-only" } }),
    )
    .unwrap();
    let who = with_token(&state, &token, NOW, "whoami", json!({})).unwrap();
    assert_eq!(who["capabilities"], json!(["list", "read", "reveal"]));
    assert!(matches!(
        with_token(
            &state,
            &token,
            NOW,
            "entry.create",
            json!({ "node": "acme", "name": "N", "value": "v" })
        ),
        Err(OpError::CapabilityNotHeld {
            capability: Capability::Create
        })
    ));
    // Nothing about a token is on disk, so a restarted broker holds none.
    let (state, _owner) = restart(&v, state, None);
    assert!(state.tokens.agent_tokens(NOW).is_empty());
    assert!(matches!(
        with_token(&state, &token, NOW, "whoami", json!({})),
        Err(OpError::SessionExpired)
    ));
}

/// Review P1-1, durable vault: sealing a node ends its tokens, and restoring it does not bring them back.
#[test]
fn a_sealed_nodes_tokens_end_with_it_and_a_restore_does_not_revive_them() {
    let (_v, state, owner, key, _e) = setup();
    let issued = issue(&state, &owner, &key, issue_params("acme", &["list"]));
    let token = bearer(&issued);
    let id = issued["id"].as_str().unwrap().to_string();
    let other = bearer(&issue(
        &state,
        &owner,
        &key,
        issue_params("beta", &["list"]),
    ));
    assert!(with_token(&state, &token, NOW, "entry.list", json!({ "node": "acme" })).is_ok());

    call(&state, &owner, NOW, "node.seal", json!({ "node": "acme" })).expect("seal acme");
    // Re-review N-1: no request presents the token between the seal and the restore, so only the seal itself can
    // have ended it (the missing-node check in scope resolution never runs). Checked in the store first, then after
    // the restore.
    assert_eq!(
        state.tokens.dead_agent_public_id(&token),
        Some((
            id.clone(),
            credmgr_brokerd::token::AgentTokenDeath::NodeGone
        ))
    );
    let live: Vec<String> = state
        .tokens
        .agent_tokens(NOW)
        .into_iter()
        .map(|t| t.node_id)
        .collect();
    assert_eq!(live, ["beta"], "only the sealed node's tokens end");

    call(
        &state,
        &owner,
        NOW + 60,
        "node.restore",
        json!({ "node": "acme" }),
    )
    .expect("restore acme");
    for op in ["whoami", "entry.list"] {
        assert!(
            matches!(
                with_token(&state, &token, NOW + 60, op, json!({ "node": "acme" })),
                Err(OpError::SessionExpired)
            ),
            "{op}: a restore never revives a token"
        );
    }
    assert!(with_token(
        &state,
        &other,
        NOW + 60,
        "entry.list",
        json!({ "node": "beta" })
    )
    .is_ok());
}

/// Review P1-1: a token whose node is not in the registry, however it left, is dead on its next request and stays
/// dead when a node with the same id appears again.
#[test]
fn a_token_whose_node_left_the_registry_is_dead_even_when_the_id_comes_back() {
    let (_v, state, owner, key, _e) = setup();
    let token = bearer(&issue(
        &state,
        &owner,
        &key,
        issue_params("acme", &["list"]),
    ));
    let node = state
        .registry
        .write()
        .unwrap()
        .nodes
        .remove("acme")
        .expect("acme is in the registry");
    assert!(matches!(
        with_token(&state, &token, NOW, "whoami", json!({})),
        Err(OpError::SessionExpired)
    ));
    assert!(
        state.tokens.agent_tokens(NOW).is_empty(),
        "it is revoked, not dormant"
    );
    state
        .registry
        .write()
        .unwrap()
        .nodes
        .insert("acme".into(), node);
    assert!(matches!(
        with_token(&state, &token, NOW, "entry.list", json!({ "node": "acme" })),
        Err(OpError::SessionExpired)
    ));
}

/// Review P1-2: an approval or a setting request made with an agent token names the token, by public id and label,
/// to the owner and to no one else; a rotation keeps the request the same token's.
#[test]
fn the_owner_sees_which_agent_token_asked_for_an_approval_or_a_setting_change() {
    let (_v, state, owner, key, entry) = setup();
    // `update`: the switchboard lets an agent change only settings of its own node, holding `update` there (Q-1).
    let issued = issue(
        &state,
        &owner,
        &key,
        issue_params("acme", &["list", "read", "reveal", "update"]),
    );
    let token = bearer(&issued);
    let id = issued["id"].as_str().unwrap().to_string();
    state
        .registry
        .write()
        .unwrap()
        .nodes
        .get_mut("acme")
        .unwrap()
        .policy
        .security_level = credmgr_core::registry::SecurityLevel::Sealed;
    let ask = json!({ "node": "acme", "entry": entry });
    let request = match with_token(&state, &token, NOW, "entry.reveal", ask.clone()) {
        Err(OpError::ApprovalPending { request, .. }) => request,
        other => panic!("a Sealed (Strict) node waits for the owner: {other:?}"),
    };
    let seen = call(
        &state,
        &owner,
        NOW,
        "vault.approval_get",
        json!({ "request": request }),
    )
    .unwrap();
    assert_eq!(
        seen["agentToken"],
        json!({ "id": id, "label": "ci runner" })
    );
    let listed = call(&state, &owner, NOW, "vault.approval_get", json!({})).unwrap();
    assert_eq!(listed["pending"][0]["agentToken"]["id"], json!(id));
    // The token itself cannot read the approvals.
    assert!(with_token(&state, &token, NOW, "vault.approval_get", json!({})).is_err());

    // Rotated, the same token asking again is the same request, not a new anonymous one.
    let proved = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "agent.token_rotate",
        json!({ "id": id }),
    );
    let rotated = call(&state, &owner, NOW, "agent.token_rotate", proved).unwrap();
    match with_token(&state, &bearer(&rotated), NOW, "entry.reveal", ask) {
        Err(OpError::ApprovalPending { request: again, .. }) => assert_eq!(again, request),
        other => panic!("{other:?}"),
    }

    // A vault setting is Global's: a token confined to acme may not change it (ADR-155 amendment, Q-1).
    assert!(matches!(
        with_token(
            &state,
            &bearer(&rotated),
            NOW,
            "settings.set",
            json!({ "id": "app.autoLockMins", "value": 0, "reason": "trust me" }),
        ),
        Err(OpError::CapabilityNotHeld { .. })
    ));
    // A weakening change to its own node's setting waits for the owner, who sees the token's name.
    let r = with_token(
        &state,
        &bearer(&rotated),
        NOW,
        "settings.set",
        json!({ "id": "node.requireTwoFactor", "node": "acme", "value": "never", "reason": "trust me" }),
    )
    .unwrap();
    assert_eq!(r["state"], "pending");
    let sr = r["request"].as_str().unwrap().to_string();
    let owner_view = call(
        &state,
        &owner,
        NOW,
        "settings.request_get",
        json!({ "request": sr }),
    )
    .unwrap();
    assert_eq!(
        owner_view["agentToken"],
        json!({ "id": id, "label": "ci runner" })
    );
    let own_view = with_token(
        &state,
        &bearer(&rotated),
        NOW,
        "settings.request_get",
        json!({ "request": sr }),
    )
    .unwrap();
    assert!(
        own_view.get("agentToken").is_none(),
        "the requester is not shown its own token's name"
    );
}

/// Review P2-1 and P2-2: the Touch ID sentence says what the proof is for, and the audit trail names the token each
/// owner action touched.
#[test]
fn the_touch_id_sentence_and_the_audit_trail_name_the_token() {
    let (_v, state, owner, key, _e) = setup();
    let mut ask = issue_params("acme", &["reveal", "list"]);
    ask["expiresIn"] = json!(7 * 86_400);
    let challenge = call(
        &state,
        &owner,
        NOW,
        "presence.challenge",
        json!({ "op": "agent.token_issue", "params": ask }),
    )
    .unwrap();
    let reason = challenge["reason"].as_str().unwrap();
    assert!(reason.contains("7-day"), "{reason}");
    assert!(reason.contains("project acme"), "{reason}");
    assert!(reason.contains("list, reveal"), "{reason}");
    assert!(reason.contains("ci runner"), "{reason}");

    let owner_bearer = owner.token_id.clone().expect("the owner's login");
    let proved = with_proof(&state, &owner, &key, NOW, "agent.token_issue", ask);
    let issued = with_token(&state, &owner_bearer, NOW, "agent.token_issue", proved).unwrap();
    let id = issued["id"].as_str().unwrap().to_string();
    with_token(
        &state,
        &owner_bearer,
        NOW,
        "agent.token_revoke",
        json!({ "id": id }),
    )
    .unwrap();
    // A refused revoke still names the token it was about.
    let _ = with_token(
        &state,
        &owner_bearer,
        NOW,
        "agent.token_revoke",
        json!({ "id": id }),
    );

    let tail = with_token(
        &state,
        &owner_bearer,
        NOW,
        "audit.tail",
        json!({ "limit": 50 }),
    )
    .unwrap();
    let rows: Vec<&Value> = tail["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            r["action"]
                .as_str()
                .is_some_and(|a| a.starts_with("agent.token_"))
        })
        .collect();
    let find = |action: &str, decision: &str| {
        rows.iter()
            .find(|r| r["action"] == action && r["decision"] == decision)
            .unwrap_or_else(|| panic!("{action} {decision}: {rows:?}"))
    };
    let issue_row = find("agent.token_issue", "allow");
    let detail = issue_row["detail"].as_str().unwrap();
    assert!(
        detail.starts_with(&format!(
            "token {id}; node acme; caps list,reveal; expires "
        )),
        "{detail}"
    );
    let revoke_row = find("agent.token_revoke", "allow");
    assert_eq!(
        revoke_row["node"], "acme",
        "filed under the token's own node"
    );
    assert!(revoke_row["detail"].as_str().unwrap().contains(&id));
    let refused = find("agent.token_revoke", "deny");
    assert!(refused["detail"]
        .as_str()
        .unwrap()
        .ends_with(&format!("; token {id}")));
    assert!(!tail.to_string().contains(issued["token"].as_str().unwrap()));
}

/// Review P2-7: Global is never an agent token's node.
#[test]
fn no_agent_token_is_issued_for_global() {
    let (_v, state, owner, _key, _e) = setup();
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "agent.token_issue",
            issue_params("global", &["list"])
        ),
        Err(OpError::Malformed(_))
    ));
    assert!(state.tokens.agent_tokens(NOW).is_empty());
}

/// Re-review N-2: an agent's scope is one node, and the list of pending approvals spans every node, so no identified
/// agent reads it, locked or not. An agent token and an agent in a registered folder are both refused while the vault
/// is locked; the token-less Lock screen still reads the list, but without any token's id or label.
#[test]
fn no_agent_reads_the_pending_approvals_of_other_nodes_even_while_the_vault_is_locked() {
    let (_v, state, owner, key, entry) = setup();
    let beta = bearer(&issue(
        &state,
        &owner,
        &key,
        issue_params("beta", &["list"]),
    ));
    let acme = bearer(&issue(
        &state,
        &owner,
        &key,
        issue_params("acme", &["list", "read", "reveal"]),
    ));
    {
        let mut reg = state.registry.write().unwrap();
        let n = reg.nodes.get_mut("acme").unwrap();
        n.policy.security_level = credmgr_core::registry::SecurityLevel::Sealed;
        reg.nodes
            .get_mut("beta")
            .unwrap()
            .workdirs
            .push("/projects/beta".into());
    }
    assert!(matches!(
        with_token(
            &state,
            &acme,
            NOW,
            "entry.reveal",
            json!({ "node": "acme", "entry": entry })
        ),
        Err(OpError::ApprovalPending { .. })
    ));
    let in_beta_folder = |token: Option<&str>| {
        let request = Request {
            id: "r".to_string(),
            op: "vault.approval_get".to_string(),
            token: token.map(str::to_string),
            params: json!({}),
        };
        let peer = credmgr_brokerd::peer::PeerInfo {
            uid: 501,
            pid: 1,
            cwd: Some("/projects/beta".into()),
        };
        server::handle_request_at(&state, &peer, &request, NOW, Instant::now()).0
    };
    let refused = |r: Result<Value, OpError>| matches!(r, Err(OpError::CapabilityNotHeld { .. }));

    for locked in [false, true] {
        if locked {
            state.lock();
            assert!(state.is_locked());
        }
        // Another node's token, the requesting token itself, and a folder agent: all refused.
        assert!(
            refused(with_token(
                &state,
                &beta,
                NOW,
                "vault.approval_get",
                json!({})
            )),
            "locked={locked}"
        );
        assert!(
            refused(with_token(
                &state,
                &acme,
                NOW,
                "vault.approval_get",
                json!({})
            )),
            "locked={locked}"
        );
        assert!(refused(in_beta_folder(None)), "locked={locked}");
    }
    // The Lock screen (no token, no registered folder) still sees what waits, but not which token asked.
    let list = with_token_less(&state);
    let pending = list["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1, "{list}");
    assert!(pending[0].get("agentToken").is_none(), "{list}");
    assert!(pending[0].get("cwd").is_none(), "{list}");
    assert!(!list.to_string().contains("ci runner"), "{list}");
}

fn with_token_less(state: &Arc<BrokerState>) -> Value {
    let request = Request {
        id: "r".to_string(),
        op: "vault.approval_get".to_string(),
        token: None,
        params: json!({}),
    };
    server::handle_request_at(state, &peer(), &request, NOW, Instant::now())
        .0
        .expect("the Lock screen reads the list while locked")
}

/// Re-review N-3: a label is shown in the Touch ID sentence and beside every request the token makes, so a character
/// that reverses or hides the text around it is refused at issue, before any prompt. Ordinary letters, accents,
/// symbols and emoji are fine.
#[test]
fn a_label_with_direction_changing_or_invisible_characters_is_refused() {
    let (_v, state, owner, key, _e) = setup();
    for bad in [
        "ci \u{202E}nur",       // right-to-left override
        "ci \u{2066}x\u{2069}", // left-to-right isolate
        "ci\u{200B}runner",     // zero-width space
        "ci\u{200D}runner",     // zero-width joiner
        "\u{FEFF}ci",           // byte-order mark
        "ci\u{2060}runner",     // word joiner
        "ci\u{E0041}",          // a tag character
        "ci\u{00AD}runner",     // soft hyphen
        "ci\u{2028}runner",     // line separator
        "ci\u{0007}",           // a control character, as before
    ] {
        let params = json!({ "node": "acme", "label": bad, "capabilities": ["list"] });
        let r = call(&state, &owner, NOW, "agent.token_issue", params.clone());
        assert!(matches!(r, Err(OpError::Malformed(_))), "{bad:?}: {r:?}");
        let proved = with_proof(&state, &owner, &key, NOW, "agent.token_issue", params);
        let r = call(&state, &owner, NOW, "agent.token_issue", proved);
        assert!(
            matches!(r, Err(OpError::Malformed(_))),
            "{bad:?} with a proof: {r:?}"
        );
    }
    assert!(state.tokens.agent_tokens(NOW).is_empty());
    let fine = issue(
        &state,
        &owner,
        &key,
        json!({ "node": "acme", "label": "Zoë’s agent ✓ 🤖", "capabilities": ["list"] }),
    );
    assert_eq!(fine["label"], "Zoë’s agent ✓ 🤖");
}
