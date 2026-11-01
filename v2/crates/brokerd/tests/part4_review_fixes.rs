//! Defects found by the independent review of the 2026-10-24 wave (each test fails
//! without its fix): a private node's entry name through `entry.undo` / `entry.restore`,
//! invisible characters in a look-alike name, an unbounded approvals table on a locked
//! vault, and a step-up with no gate counting as a login failure.

mod common;

use common::*;
use credmgr_brokerd::protocol::OpError;
use serde_json::json;

#[test]
fn undoing_or_restoring_an_entry_in_a_private_node_does_not_tell_the_agent_its_name() {
    let (f, owner, _api) = with_acme();
    send(
        &f,
        None,
        Some(&owner),
        "node.policy",
        json!({ "node": "acme", "reason": "hide names", "policy": { "privateNames": true } }),
    )
    .unwrap();
    let secret = "wallet-zebra-name";
    let id = create_as_owner(&f, &owner, secret);
    let generation = |f: &Fixture| -> u64 {
        send(
            f,
            None,
            Some(&owner),
            "entry.list",
            json!({ "node": "acme" }),
        )
        .unwrap()["generation"]
            .as_u64()
            .unwrap()
    };
    let request = credmgr_brokerd::protocol::Request {
        id: "r".into(),
        op: "entry.remove".into(),
        token: Some(owner.clone()),
        params: json!({ "node": "acme", "entry": id, "generation": generation(&f) }),
    };
    let (res, audit) = credmgr_brokerd::server::handle_request_at(
        &f.state,
        &peer(None),
        &request,
        NOW,
        std::time::Instant::now(),
    );
    res.expect("remove");
    let audit = audit.unwrap();

    // The agent finds the record in its (redacted) feed and undoes it: no name comes back.
    let g = as_agent(&f, "entry.list", json!({ "node": "acme" })).unwrap()["generation"]
        .as_u64()
        .unwrap();
    let undone = as_agent(
        &f,
        "entry.undo",
        json!({ "node": "acme", "id": audit, "generation": g }),
    )
    .expect("undo");
    assert!(!undone.to_string().contains(secret), "{undone}");
    assert!(
        undone["restoredName"].is_null() && undone["restored"]["name"].is_null(),
        "{undone}"
    );

    // A replace-mode restore that collides does not echo the name either.
    let id2 = create_as_owner(&f, &owner, "second-private-name");
    let g = generation(&f);
    send(
        &f,
        None,
        Some(&owner),
        "entry.remove",
        json!({ "node": "acme", "entry": id2, "generation": g }),
    )
    .unwrap();
    create_as_owner(&f, &owner, "second-private-name");
    let g = as_agent(&f, "entry.list", json!({ "node": "acme" })).unwrap()["generation"]
        .as_u64()
        .unwrap();
    let r = as_agent(
        &f,
        "entry.restore",
        json!({ "node": "acme", "entry": id2, "generation": g }),
    );
    match r {
        Err(OpError::EntryExists { name, .. }) => assert_eq!(name, ""),
        other => panic!("{other:?}"),
    }
    // The owner still sees the name.
    let g = generation(&f);
    let kept = send(
        &f,
        None,
        Some(&owner),
        "entry.restore",
        json!({ "node": "acme", "entry": id2, "generation": g, "mode": "keep-both" }),
    )
    .unwrap();
    assert_eq!(kept["restoredName"], "second-private-name old");
}

#[test]
fn an_invisible_character_does_not_make_a_name_new() {
    let (f, owner, _) = with_acme();
    create_as_owner(&f, &owner, "payroll");
    for twin in [
        "payroll\u{FE0F}",
        "pay\u{034F}roll",
        "pay\u{3164}roll",
        "payroll\u{E0041}",
        "pay\u{180B}roll",
    ] {
        let r = send(
            &f,
            None,
            Some(&owner),
            "entry.create",
            json!({ "node": "acme", "name": twin, "value": "x" }),
        );
        assert!(
            matches!(r, Err(OpError::EntryExists { .. })),
            "{twin:?}: {r:?}"
        );
    }
}

#[test]
fn an_agent_cannot_grow_the_approvals_table_by_inventing_entry_ids_on_a_locked_vault() {
    let (f, owner, entry) = with_acme();
    send(&f, None, Some(&owner), "vault.lock", json!({})).unwrap();
    for i in 0..50 {
        let r = as_agent(
            &f,
            "entry.reveal",
            json!({ "node": "acme", "entry": format!("e_invented{i:04}") }),
        );
        assert!(matches!(r, Err(OpError::NotFound(_))), "{r:?}");
    }
    assert_eq!(
        f.state.approval_count_for_test(),
        0,
        "invented ids opened no request"
    );
    // A real entry still opens exactly one, however often it is asked.
    for _ in 0..3 {
        assert!(matches!(
            as_agent(
                &f,
                "entry.reveal",
                json!({ "node": "acme", "entry": entry })
            ),
            Err(OpError::ApprovalPending { .. })
        ));
    }
    assert_eq!(f.state.approval_count_for_test(), 1);
}

#[test]
fn a_step_up_with_no_gate_is_a_malformed_ask_and_never_feeds_the_unlock_backoff() {
    let (f, owner, _) = with_acme();
    for _ in 0..8 {
        let r = send(
            &f,
            None,
            Some(&owner),
            "vault.gate_verify",
            json!({ "code": "123456" }),
        );
        assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
    }
    // The same uid can still unlock: nothing counted as a failed login.
    let r = send(
        &f,
        None,
        None,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    );
    assert!(r.is_ok(), "{r:?}");
}
