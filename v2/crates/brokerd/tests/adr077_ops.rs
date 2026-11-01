//! ADR-077 — four small, wire-visible repairs, each proven against the real
//! server wiring (`server::handle_request_at`) on a vault `vault.init_*` created:
//!
//! * **MX-1** `totp.code` on a stored seed the engine used to refuse answers a code
//!   for any seed of 80 bits or more (padded, lower case or grouped forms
//!   included) and a typed refusal below that - it used to panic the connection
//!   thread and leave the client with a closed socket.
//! * **G3** a locked *node* on an unlocked vault answers `node_locked` (with the
//!   node), never `vault_locked`: the desktop bridge ends the session on
//!   `vault_locked`, so the old answer logged the owner out for locking one node.
//! * **G1** `entry.list` additively carries the manifest metadata the UI needs -
//!   to human sessions only; an agent caller keeps the pre-ADR-077 response.
//! * **G2** `vault.status` additively says whether a vault exists at all.

use std::sync::Arc;
use std::time::Instant;

use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{to_wire, OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;

const NOW: i64 = 1_800_000_000;
const PASSPHRASE: &str = "correct horse battery staple";

struct Fixture {
    state: Arc<BrokerState>,
    acme_workdir: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

/// A broker over a directory with no vault in it (nothing initialised yet).
fn empty_broker() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let acme_workdir = dir.path().join("work").join("acme");
    std::fs::create_dir_all(acme_workdir.join("src")).unwrap();
    // The broker stores and compares real paths; on macOS the temp directory is
    // a symlink (`/var` -> `/private/var`), so resolve it up front.
    let acme_workdir = std::fs::canonicalize(&acme_workdir).unwrap();
    let keystore = SoftwareKeystore::new(
        SecretBox::new(Box::default()),
        state_dir.join("placeholder-keystore"),
    );
    let state = Arc::new(BrokerState::new(
        Box::new(keystore),
        credmgr_store::paths::VaultPaths::new(vault_dir),
    ));
    state.set_state_dir_for_test(state_dir);
    Fixture {
        state,
        acme_workdir,
        _dir: dir,
    }
}

fn anyone() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

/// `credmgr init` for real; returns the broker still running (and unlocked by
/// the init itself being followed by a login in `login`).
fn created_vault() -> Fixture {
    let f = empty_broker();
    let begin = credmgr_brokerd::ops::dispatch(
        &f.state,
        &anyone(),
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin");
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    credmgr_brokerd::ops::dispatch(
        &f.state,
        &anyone(),
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": code }),
    )
    .expect("init_confirm");
    f
}

fn peer(cwd: Option<&str>) -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: cwd.map(str::to_string),
    }
}

fn send(
    f: &Fixture,
    cwd: Option<&str>,
    token: Option<&str>,
    op: &str,
    params: Value,
) -> Result<Value, OpError> {
    let request = Request {
        id: "r".to_string(),
        op: op.to_string(),
        token: token.map(str::to_string),
        params,
    };
    server::handle_request_at(&f.state, &peer(cwd), &request, NOW, Instant::now()).0
}

fn login(f: &Fixture) -> String {
    send(
        f,
        None,
        None,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("unlock")["token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A logged-in broker with `acme` (bound to a real workdir) and one entry in it.
fn with_acme() -> (Fixture, String, String) {
    let f = created_vault();
    let owner = login(&f);
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": "global",
                "workdirs": [f.acme_workdir.to_string_lossy()] }),
    )
    .expect("node.create");
    let entry = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "API_KEY", "value": "v-1" }),
    )
    .expect("entry.create")["entry"]
        .as_str()
        .unwrap()
        .to_string();
    (f, owner, entry)
}

fn wire(err: OpError) -> Value {
    to_wire("r", &Err(err))
}

// ------------------------------------------------------------------------------------------
// MX-1
// ------------------------------------------------------------------------------------------

/// RFC 4648 base32 encode (upper case), local so this test needs no extra
/// dependency.
fn b32(bytes: &[u8], padding: bool) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    for chunk in bytes.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..8 {
            if i < chars {
                out.push(ALPHABET[((bits >> (35 - 5 * i)) & 31) as usize] as char);
            } else if padding {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn totp_code_on_an_unusable_seed_is_a_typed_refusal_never_a_dropped_connection() {
    let (f, owner, _) = with_acme();
    let store = |name: &str, seed: &str| -> String {
        send(
            &f,
            None,
            Some(&owner),
            "entry.create",
            // typed as a seed by its owner: the class a code is computed from is the class a reveal withholds
            json!({ "node": "acme", "name": name,
                    "fields": [{ "label": "2fa", "value": seed, "type": "totp-seed" }] }),
        )
        .expect("store the seed")["entry"]
            .as_str()
            .unwrap()
            .to_string()
    };
    // Below the 80-bit floor: a typed refusal, whatever the length.
    let seventy_two = store("OTP_72", &b32(&[7u8; 9], false));
    let forty = store("OTP_40", &b32(&[7u8; 5], false));
    let junk = store("OTP_JUNK", "this is not base32 !!");
    // At or above it: a code. 80 bits (16 base32 characters) is what many real
    // services issue; the RFC 4226 floor of 128 bits is a recorded deviation.
    let eighty_bit = store("OTP_80", &b32(&[7u8; 10], false));
    let one_twenty = store("OTP_120", &b32(&[7u8; 15], false));
    let good_160 = store("OTP_160", &b32(&[9u8; 20], false));
    // 128 bits, correctly padded and in lower case: a form real sites print.
    let padded_128 = store("OTP_128_PADDED", &b32(&[5u8; 16], true).to_lowercase());
    // 80 bits the way a site shows it: grouped, lower case.
    let grouped_80 = store(
        "OTP_80_GROUPED",
        &b32(&[11u8; 10], false)
            .to_lowercase()
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" "),
    );

    let code = |entry: &str| {
        send(
            &f,
            None,
            Some(&owner),
            "totp.code",
            json!({ "node": "acme", "entry": entry }),
        )
    };

    for (what, entry, bits, seed) in [
        ("72-bit", &seventy_two, 72, b32(&[7u8; 9], false)),
        ("40-bit", &forty, 40, b32(&[7u8; 5], false)),
    ] {
        match code(entry) {
            Err(OpError::Malformed(message)) => {
                assert!(
                    message.contains(&format!("{bits} bits")) && message.contains("80"),
                    "{what}: {message}"
                );
                // The refusal names the problem, never the seed.
                assert!(!message.contains(&seed), "{message}");
                let body = wire(OpError::Malformed(message));
                assert_eq!(body["error"], "malformed_request");
            }
            other => panic!("{what}: expected a malformed_request refusal, got {other:?}"),
        }
    }
    assert!(
        matches!(code(&junk), Err(OpError::Malformed(m)) if m.contains("not a base32")),
        "junk is a refusal that says so"
    );
    // Every seed at or above the floor yields six digits and nothing but
    // node/entry/code - never the seed.
    for (what, entry) in [
        ("80-bit", &eighty_bit),
        ("120-bit", &one_twenty),
        ("160-bit", &good_160),
        ("padded lower-case 128-bit", &padded_128),
        ("grouped lower-case 80-bit", &grouped_80),
    ] {
        let ok =
            code(entry).unwrap_or_else(|e| panic!("{what}: a usable seed gives a code: {e:?}"));
        let digits = ok["code"].as_str().unwrap();
        assert!(
            digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()),
            "{what}"
        );
        assert_eq!(
            ok.as_object().unwrap().len(),
            3,
            "{what}: exactly node, entry, code - never the seed"
        );
    }
    // The daemon is fine afterwards, and every refused request was audited.
    assert_eq!(
        send(&f, None, None, "vault.status", json!({})).unwrap()["locked"],
        false
    );
    let feed = send(
        &f,
        None,
        Some(&owner),
        "audit.tail",
        json!({ "limit": 500 }),
    )
    .unwrap();
    let denied = feed["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["action"] == "totp.code" && r["decision"] == "deny")
        .count();
    assert_eq!(denied, 3, "{feed}");
}

// ------------------------------------------------------------------------------------------
// G3
// ------------------------------------------------------------------------------------------

#[test]
fn a_locked_node_answers_node_locked_with_the_node_and_never_vault_locked() {
    let (f, owner, entry) = with_acme();
    // A write into the tray while the node is locked, so there is something to accept.
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .expect("lock acme");
    let pending = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "TRAYED", "value": "v-2" }),
    )
    .expect("a locked node takes the write into its tray");
    assert_eq!(pending["pending"], true);
    let pending_entry = pending["entry"].as_str().unwrap().to_string();

    let n = |op: &str, params: Value| (op.to_string(), params);
    let calls = [
        n(
            "entry.update",
            json!({ "node": "acme", "entry": entry, "value": "x", "generation": 1 }),
        ),
        n(
            "entry.rotate",
            json!({ "node": "acme", "entry": entry, "value": "x", "generation": 1 }),
        ),
        n(
            "entry.remove",
            json!({ "node": "acme", "entry": entry, "generation": 1 }),
        ),
        n(
            "entry.restore",
            json!({ "node": "acme", "entry": entry, "generation": 1 }),
        ),
        n(
            "entry.undo",
            json!({ "node": "acme", "id": "a_000000000000", "generation": 1 }),
        ),
        n("notes.read", json!({ "node": "acme" })),
        n(
            "notes.write",
            json!({ "node": "acme", "markdown": "m", "generation": 1 }),
        ),
        n(
            "vault.pending_accept",
            json!({ "node": "acme", "entry": pending_entry }),
        ),
        n("node.seal", json!({ "node": "acme" })),
    ];
    for (op, params) in &calls {
        match send(&f, None, Some(&owner), op, params.clone()) {
            Err(OpError::NodeLocked { node }) => {
                assert_eq!(node, "acme", "{op}");
                let body = wire(OpError::NodeLocked { node });
                assert_eq!(body["error"], "node_locked", "{op}");
                assert_eq!(body["node"], "acme", "{op}");
                assert!(
                    body["message"].as_str().unwrap().contains("acme")
                        && body["remedy"]
                            .as_str()
                            .unwrap()
                            .contains("vault.node_unlock"),
                    "{op}: {body}"
                );
            }
            other => panic!("{op} on a locked node: expected node_locked, got {other:?}"),
        }
    }

    // Reveal and TOTP on a locked node keep their documented answers (an
    // approval request; an access denial) — and, above all, are not `vault_locked`.
    for (op, params) in [
        ("entry.reveal", json!({ "node": "acme", "entry": entry })),
        ("totp.code", json!({ "node": "acme", "entry": entry })),
    ] {
        let answer = send(&f, None, Some(&owner), op, params);
        assert!(
            !matches!(answer, Err(OpError::VaultLocked)),
            "{op} on a locked node must not end the session: {answer:?}"
        );
    }

    // The login is still good: it reads the vault's status and a sibling's data.
    assert_eq!(
        send(&f, None, None, "vault.status", json!({})).unwrap()["locked"],
        false
    );
    send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .expect("the session survived the node lock");

    // Unlock the node: the very same call now works.
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_unlock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    send(
        &f,
        None,
        Some(&owner),
        "notes.read",
        json!({ "node": "acme" }),
    )
    .expect("notes.read after unlocking the node");
}

/// The other half: when the *whole vault* is locked the answer is still
/// `vault_locked` — that is the code that tells a client its login is over.
#[test]
fn a_locked_vault_still_answers_vault_locked() {
    let (f, owner, entry) = with_acme();
    // Leave a node lock in place as well: the vault-level answer wins.
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    send(&f, None, Some(&owner), "vault.lock", json!({})).expect("lock the vault");
    // The owner's token died with the lock; an agent in acme's workdir (read-write
    // on its own node) hits the same refusal path.
    let agent_cwd = format!("{}/src", f.acme_workdir.to_string_lossy());
    let answer = send(
        &f,
        Some(&agent_cwd),
        None,
        "entry.update",
        json!({ "node": "acme", "entry": entry, "value": "x", "generation": 1 }),
    );
    assert!(matches!(answer, Err(OpError::VaultLocked)), "{answer:?}");
    assert_eq!(wire(OpError::VaultLocked)["error"], "vault_locked");
}

// ------------------------------------------------------------------------------------------
// G1
// ------------------------------------------------------------------------------------------

#[test]
fn entry_list_carries_the_manifest_metadata_beside_ids_and_names() {
    let (f, owner, entry) = with_acme();
    let listed = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    // The existing shape is untouched...
    assert_eq!(listed["ids"], json!([entry]));
    assert_eq!(listed["names"], json!(["API_KEY"]));
    assert!(listed["generation"].as_u64().unwrap() >= 1);
    // ...and `entries` adds exactly the nine manifest fields, nothing else
    // (`hasTotp` joined in C1 / ADR-080).
    let rows = listed["entries"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let row = rows[0].as_object().unwrap();
    let mut keys: Vec<&str> = row.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "expiresAt",
            "fieldCount",
            "hasTotp",
            "id",
            "modified",
            "name",
            "rotatedAt",
            "sensitivity",
            "type"
        ]
    );
    assert_eq!(row["id"], json!(entry));
    assert_eq!(row["name"], "API_KEY");
    assert_eq!(row["fieldCount"], 1);
    assert_eq!(row["modified"], json!(NOW));
    assert_eq!(
        row["hasTotp"],
        json!(false),
        "a plain entry has no second-factor seed"
    );
    assert!(row["rotatedAt"].is_null() && row["expiresAt"].is_null());
    assert!(row["type"].is_string() && row["sensitivity"].is_string());
    // Never a value, a hash, a label or a ref.
    for forbidden in ["value", "sha256", "label", "ref", "hash"] {
        assert!(!row.contains_key(forbidden), "{forbidden}");
    }

    // A rotation shows up as `rotatedAt`.
    let generation = listed["generation"].as_u64().unwrap();
    send(
        &f,
        None,
        Some(&owner),
        "entry.rotate",
        json!({ "node": "acme", "entry": entry, "value": "v-2", "generation": generation }),
    )
    .expect("rotate");
    let after = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(after["entries"][0]["rotatedAt"], json!(NOW));
}

/// C1 / ADR-080: the list row says whether the entry carries a TOTP seed, so an
/// app can mark it without opening it. Human sessions only, like the rest of `entries`.
#[test]
fn entry_list_marks_an_entry_that_carries_a_totp_seed() {
    let (f, owner, _plain) = with_acme();
    let with_seed = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "SERVER", "fields": [
            { "label": "host", "value": "db.example.test" },
            { "label": "otp", "value": b32(&[0x3b; 20], false) }
        ] }),
    )
    .expect("entry.create with a seed")["entry"]
        .as_str()
        .unwrap()
        .to_string();
    let listed = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let rows = listed["entries"].as_array().unwrap();
    let flag = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap()["hasTotp"].clone();
    assert_eq!(
        flag(&with_seed),
        json!(true),
        "the seed-bearing entry is marked"
    );
    assert_eq!(
        rows.iter().filter(|r| r["hasTotp"] == json!(true)).count(),
        1,
        "and only that one"
    );
    // The agent surface keeps exactly its pre-ADR-077 response.
    let agent = send(
        &f,
        Some(&f.acme_workdir.to_string_lossy()),
        None,
        "entry.list",
        json!({ "node": "acme" }),
    );
    if let Ok(body) = agent {
        assert!(body.get("entries").is_none(), "no metadata for an agent");
    }
}

/// Same visibility as `ids`/`names`: a caller that cannot list a node gets the
/// same refusal, and for the human sessions that do get `entries` it lists
/// exactly the entries `ids` does.
#[test]
fn entry_list_metadata_obeys_the_same_gate_and_filter_as_the_ids() {
    let (f, owner, _entry) = with_acme();
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "beta", "label": "Beta", "parentId": "global" }),
    )
    .expect("node.create beta");
    // An agent inside acme's workdir cannot list sibling beta (R8) - no `entries` leak.
    let agent_cwd = format!("{}/src", f.acme_workdir.to_string_lossy());
    let denied = send(
        &f,
        Some(&agent_cwd),
        None,
        "entry.list",
        json!({ "node": "beta" }),
    );
    assert!(
        matches!(denied, Err(OpError::NodeAccessDenied { .. })),
        "{denied:?}"
    );
    // An unscoped process (global, list-only) is refused acme as well.
    let unscoped = send(
        &f,
        Some("/tmp"),
        None,
        "entry.list",
        json!({ "node": "acme" }),
    );
    assert!(
        matches!(unscoped, Err(OpError::NodeAccessDenied { .. })),
        "{unscoped:?}"
    );
    // A human session holding `list` on acme only (a CLI login narrowed to the
    // node): ids and entries agree one-for-one, and the sibling stays refused.
    let cli = f.state.tokens.issue(
        "acme",
        vec![Capability::List],
        Origin::Cli,
        Some(f.acme_workdir.to_string_lossy().into_owned()),
    );
    let own = send(
        &f,
        Some(&f.acme_workdir.to_string_lossy()),
        Some(&cli.id),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let ids: Vec<&Value> = own["ids"].as_array().unwrap().iter().collect();
    let from_entries: Vec<&Value> = own["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["id"])
        .collect();
    assert_eq!(ids, from_entries);
    let sibling = send(
        &f,
        Some(&f.acme_workdir.to_string_lossy()),
        Some(&cli.id),
        "entry.list",
        json!({ "node": "beta" }),
    );
    assert!(
        matches!(sibling, Err(OpError::NodeAccessDenied { .. })),
        "{sibling:?}"
    );
}

/// Orchestrator decision for 2.0.0-beta.1: `entries` is for the person at the
/// keyboard. An `Origin::Agent` caller - the MCP surface, every tokenless
/// cwd-scoped process, any explicitly issued agent token - keeps exactly the
/// response it had before ADR-077: the key is ABSENT (not empty, not null).
#[test]
fn entry_list_metadata_is_returned_to_human_sessions_only() {
    let (f, owner, entry) = with_acme();
    let agent_cwd = format!("{}/src", f.acme_workdir.to_string_lossy());

    let keys = |v: &Value| -> Vec<String> {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort_unstable();
        k
    };

    // The three agent shapes: tokenless inside the workdir (read-write agent
    // policy, so it holds `list`), tokenless elsewhere is refused above, and an
    // explicit agent-origin session token.
    let agent_token = f.state.tokens.issue(
        "acme",
        vec![Capability::List, Capability::Read],
        Origin::Agent,
        None,
    );
    let tokenless = send(
        &f,
        Some(&agent_cwd),
        None,
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let with_token = send(
        &f,
        None,
        Some(&agent_token.id),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    for (what, body) in [
        ("tokenless agent", &tokenless),
        ("agent token", &with_token),
    ] {
        assert_eq!(
            keys(body),
            ["generation", "ids", "names", "node"],
            "{what}: the pre-ADR-077 response, byte for byte in shape"
        );
        assert!(body.get("entries").is_none(), "{what} must not see entries");
        assert_eq!(body["ids"], json!([entry]), "{what}");
        assert_eq!(body["names"], json!(["API_KEY"]), "{what}");
    }

    // The human origins (the owner's login is HumanUi; a CLI and a native
    // session are issued the same way) all get the metadata beside the same
    // ids/names/generation.
    for origin in [Origin::Cli, Origin::Native, Origin::HumanUi] {
        let token = f
            .state
            .tokens
            .issue("acme", vec![Capability::List], origin, None);
        let body = send(
            &f,
            None,
            Some(&token.id),
            "entry.list",
            json!({ "node": "acme" }),
        )
        .unwrap();
        assert_eq!(
            keys(&body),
            ["entries", "generation", "ids", "names", "node"],
            "{origin:?}"
        );
        assert_eq!(body["entries"][0]["name"], "API_KEY", "{origin:?}");
        assert_eq!(body["ids"], json!([entry]), "{origin:?}");
    }
    let as_owner = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(as_owner["entries"][0]["id"], json!(entry));
}

// ------------------------------------------------------------------------------------------
// G2
// ------------------------------------------------------------------------------------------

#[test]
fn vault_status_says_whether_a_vault_exists() {
    let f = empty_broker();
    // Nothing initialised: locked, and not initialised - the first-run signal.
    let status = send(&f, None, None, "vault.status", json!({})).unwrap();
    assert_eq!(status["locked"], true);
    assert_eq!(status["initialized"], false);

    // An init in flight is still "no vault" - nothing is on disk until it is confirmed.
    let begin = send(
        &f,
        None,
        None,
        "vault.init_begin",
        json!({ "passphrase": PASSPHRASE }),
    )
    .unwrap();
    assert_eq!(
        send(&f, None, None, "vault.status", json!({})).unwrap()["initialized"],
        false
    );
    send(
        &f,
        None,
        None,
        "vault.init_confirm",
        json!({ "recoveryCode": begin["recoveryCode"] }),
    )
    .unwrap();
    let after = send(&f, None, None, "vault.status", json!({})).unwrap();
    assert_eq!(after["initialized"], true);

    // And it survives a restart: a fresh broker over the same vault directory,
    // still locked and not yet loaded, still reports a vault.
    let g_dir = tempfile::tempdir().unwrap();
    let keystore = SoftwareKeystore::new(
        SecretBox::new(Box::default()),
        g_dir.path().join("placeholder-keystore"),
    );
    let g = Fixture {
        state: Arc::new(BrokerState::new(
            Box::new(keystore),
            credmgr_store::paths::VaultPaths::new(f.state.paths.root().to_path_buf()),
        )),
        acme_workdir: f.acme_workdir.clone(),
        _dir: g_dir,
    };
    let status = send(&g, None, None, "vault.status", json!({})).unwrap();
    assert_eq!(status["locked"], true);
    assert_eq!(status["initialized"], true);
}
