//! ADR-174 (3), closing PHASE8 K-6: a login handed to a caller inside a project's folder (where `credmgr unlock`
//! prints the `export CREDMGR_TOKEN=...` an agent in that shell inherits) is a **project login**. It reaches
//! that project only and is honoured only from that project's registered folders; the owner's own login (an
//! unlock from outside every project folder: a terminal in `~`, the desktop app) is unaffected.

mod common;

use common::*;
use serde_json::{json, Value};

use credmgr_brokerd::protocol::OpError;

struct Two {
    f: Fixture,
    acme_cwd: String,
    beta_cwd: String,
    beta_entry: String,
    acme_entry: String,
}

/// acme and beta, each with its own folder and one entry; the vault left LOCKED so the next unlock is the one
/// under test.
fn two_projects() -> Two {
    let (f, owner, acme_entry) = with_acme();
    let beta_dir = f._dir.path().join("work").join("beta");
    std::fs::create_dir_all(beta_dir.join("src")).unwrap();
    let beta_dir = std::fs::canonicalize(&beta_dir).unwrap();
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "beta", "label": "Beta", "parentId": "global",
                "workdirs": [beta_dir.to_string_lossy()] }),
    )
    .expect("node.create beta");
    let beta_entry = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "beta", "name": "BETA_KEY", "value": "beta-only-value" }),
    )
    .expect("entry.create beta")["entry"]
        .as_str()
        .unwrap()
        .to_string();
    send(&f, None, Some(&owner), "vault.lock", json!({})).expect("lock");
    let acme_cwd = f.acme_workdir.to_string_lossy().into_owned();
    Two {
        beta_cwd: beta_dir.to_string_lossy().into_owned(),
        acme_cwd,
        f,
        beta_entry,
        acme_entry,
    }
}

fn unlock_in(f: &Fixture, cwd: Option<&str>) -> String {
    send(
        f,
        cwd,
        None,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("unlock")["token"]
        .as_str()
        .unwrap()
        .to_string()
}

fn is_session_expired(r: &Result<Value, OpError>) -> bool {
    matches!(r, Err(OpError::SessionExpired))
}

#[test]
fn a_login_from_inside_a_project_folder_reaches_that_project_only() {
    let t = two_projects();
    let inside = format!("{}/src", t.acme_cwd);
    let token = unlock_in(&t.f, Some(&inside));

    // From the folder (the folder itself, or beneath it): its own project works.
    for cwd in [t.acme_cwd.as_str(), inside.as_str()] {
        let list = send(
            &t.f,
            Some(cwd),
            Some(&token),
            "entry.list",
            json!({ "node": "acme" }),
        )
        .unwrap();
        assert_eq!(list["names"], json!(["API_KEY"]), "{cwd}");
        let value = send(
            &t.f,
            Some(cwd),
            Some(&token),
            "entry.reveal",
            json!({ "node": "acme", "entry": t.acme_entry }),
        )
        .unwrap();
        assert!(value.to_string().contains("v-1"), "{value}");
    }

    // Another project: nothing, and nothing of it named.
    let beta = send(
        &t.f,
        Some(&inside),
        Some(&token),
        "entry.list",
        json!({ "node": "beta" }),
    );
    let err = beta.expect_err("a project login does not reach a sibling project");
    assert!(!format!("{err:?}").contains("BETA_KEY"), "{err:?}");
    let reveal = send(
        &t.f,
        Some(&inside),
        Some(&token),
        "entry.reveal",
        json!({ "node": "beta", "entry": t.beta_entry }),
    );
    let err = reveal.expect_err("nor reveal one of its entries");
    assert!(!format!("{err:?}").contains("beta-only-value"), "{err:?}");

    // And none of the owner's powers: a project login is not an owner session.
    let create = send(
        &t.f,
        Some(&inside),
        Some(&token),
        "node.create",
        json!({ "id": "gamma", "label": "Gamma", "parentId": "global" }),
    );
    assert!(create.is_err(), "{create:?}");
}

#[test]
fn a_project_login_is_refused_from_any_other_folder() {
    let t = two_projects();
    let inside = format!("{}/src", t.acme_cwd);
    let token = unlock_in(&t.f, Some(&inside));
    let beta_src = format!("{}/src", t.beta_cwd);
    let elsewhere = "/tmp";
    // The look-alike prefix is not "inside": `<acme>-evil` is a different folder.
    let lookalike = format!("{}-evil", t.acme_cwd);
    for cwd in [
        Some(t.beta_cwd.as_str()),
        Some(beta_src.as_str()),
        Some(elsewhere),
        Some(lookalike.as_str()),
        None,
    ] {
        let r = send(
            &t.f,
            cwd,
            Some(&token),
            "entry.list",
            json!({ "node": "acme" }),
        );
        assert!(is_session_expired(&r), "{cwd:?}: {r:?}");
    }
    // The refusal is recorded without naming the project or the folder.
    let owner = unlock_in(&t.f, None);
    let tail = send(
        &t.f,
        None,
        Some(&owner),
        "audit.tail",
        json!({ "limit": 50 }),
    )
    .unwrap();
    let text = tail.to_string();
    assert!(
        text.contains("anomaly.project_login_wrong_folder"),
        "{text}"
    );
    assert!(
        !text.contains(&t.acme_cwd) && !text.contains(&t.beta_cwd),
        "{text}"
    );
    // Coming back to its own folder works again: a refusal does not burn the login.
    // (The vault was re-unlocked above, which killed the first login with the lock, so mint a fresh one.)
    send(&t.f, None, Some(&owner), "vault.lock", json!({})).unwrap();
    let again = unlock_in(&t.f, Some(&inside));
    let ok = send(
        &t.f,
        Some(&inside),
        Some(&again),
        "entry.list",
        json!({ "node": "acme" }),
    );
    assert!(ok.is_ok(), "{ok:?}");
}

#[test]
fn the_owners_login_from_outside_every_project_folder_is_unaffected() {
    let t = two_projects();
    // No cwd, and a folder that belongs to no project, are the same: the owner's whole-vault login.
    for cwd in [None, Some("/tmp")] {
        let owner = unlock_in(&t.f, cwd);
        for node in ["acme", "beta"] {
            let list = send(
                &t.f,
                None,
                Some(&owner),
                "entry.list",
                json!({ "node": node }),
            )
            .unwrap();
            assert_eq!(list["ids"].as_array().unwrap().len(), 1, "{node}");
        }
        // Presented from inside a project folder it still works: it never carried a folder.
        let from_project = send(
            &t.f,
            Some(&t.acme_cwd),
            Some(&owner),
            "entry.list",
            json!({ "node": "beta" }),
        );
        assert!(from_project.is_ok(), "{from_project:?}");
        send(&t.f, None, Some(&owner), "vault.lock", json!({})).unwrap();
    }
}

#[test]
fn a_project_login_dies_at_lock() {
    let t = two_projects();
    let inside = format!("{}/src", t.acme_cwd);
    let token = unlock_in(&t.f, Some(&inside));
    send(&t.f, Some(&inside), Some(&token), "vault.lock", json!({})).expect("lock");
    let owner_again = unlock_in(&t.f, None);
    let r = send(
        &t.f,
        Some(&inside),
        Some(&token),
        "entry.list",
        json!({ "node": "acme" }),
    );
    assert!(is_session_expired(&r), "{r:?}");
    drop(owner_again);
}
