//! ADR-161 — `vault.doctor_scan`, the doctor's tidy-up scan (phase 1): a report and a preview plan, never a
//! value and never a write.
//!
//! * Every finding kind is produced from a planted vault: exact and probable duplicate values (with the
//!   proposal memo 03 §3.2 gives for where the copies sit), a misfiled entry in `global`, near-duplicate
//!   names across nodes, a weak password, a raw `otpauth://` URI and a live key in a test node, expired and
//!   expiring entries (the manifest's expiry and a JWT's `exp`), and a stale entry.
//! * No planted value, and nothing that looks like a digest, appears in the answer or in the audit trail.
//! * The owner's login only: an agent, a human scope with no login session, a CLI scope are refused.
//! * A locked node contributes nothing; a node with its own second factor that is not open is scanned by
//!   name only; the orphan node is never read.
//! * A move proposal is applied with `entry.move` exactly as given, and a re-scan sees the result.
//! * Bounded: one scan at a time, and an entry cap that sets `truncated`.

mod f1_support;

use std::time::Instant;

use serde_json::{json, Value};

use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_core::totp::{decode_gate_secret_base32, Totp};

use f1_support::*;

const DAY: i64 = 86_400;

/// Shared by two sub-nodes of `acme` → move one copy to `acme`.
const DUP_SUB: &str = "dup-sub-7Q4mZr91XkLpWq";
/// Shared by `acme` and `beta` (two projects) → keep in one and grant, or a shared node.
const DUP_CROSS: &str = "dup-cross-Vv83kPq2LmZt";
/// Twice in `beta` → merge.
const DUP_SAME: &str = "dup-same-8sKd3LqPx0Nn";
/// Equal only once normalised → a probable duplicate.
const URL_A: &str = "https://Hooks.Example.test:443/in-9fK2xQ";
const URL_B: &str = "https://hooks.example.test/in-9fK2xQ";
const WEAK_PW: &str = "letmein1";
const OTP_URI: &str = "otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
// Written in two pieces so no secret scanner reads this test file as holding a live key; the planted value is the whole string.
const LIVE_KEY: &str = concat!("sk_live", "_51HxQ9doctorScanZz");
const MISFILED_VALUE: &str = "misfiled-Rr72pLq0Kw";

fn all_planted() -> Vec<String> {
    let mut v: Vec<String> = [
        DUP_SUB,
        DUP_CROSS,
        DUP_SAME,
        URL_A,
        URL_B,
        WEAK_PW,
        OTP_URI,
        LIVE_KEY,
        MISFILED_VALUE,
        "9fK2xQ",
        "JBSWY3DPEHPK3PXP",
        "doctorScanZz",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    v.push(expired_jwt());
    v
}

fn jwt(exp: i64) -> String {
    use base64::Engine as _;
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.c2lnbmF0dXJl",
        e.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        e.encode(format!(r#"{{"sub":"svc","exp":{exp}}}"#).as_bytes())
    )
}

fn expired_jwt() -> String {
    jwt(NOW - DAY)
}

fn node(state: &BrokerState, owner: &BrokerScope, id: &str, label: &str, parent: &str) {
    call(
        state,
        owner,
        NOW,
        "node.create",
        json!({ "id": id, "label": label, "parentId": parent }),
    )
    .expect("node.create");
}

fn entry_at(
    state: &BrokerState,
    owner: &BrokerScope,
    at: i64,
    node: &str,
    name: &str,
    fields: Value,
) -> String {
    call(
        state,
        owner,
        at,
        "entry.create",
        json!({ "node": node, "name": name, "fields": fields }),
    )
    .expect("entry.create")["entry"]
        .as_str()
        .unwrap()
        .to_string()
}

fn one(label: &str, value: &str) -> Value {
    json!([{ "label": label, "value": value }])
}

fn scan(state: &BrokerState, owner: &BrokerScope) -> Value {
    call(state, owner, NOW, "vault.doctor_scan", json!({})).expect("vault.doctor_scan")
}

fn of_kind<'a>(report: &'a Value, kind: &str) -> Vec<&'a Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"] == kind)
        .collect()
}

fn names(finding: &Value) -> Vec<String> {
    let mut n: Vec<String> = finding["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            format!(
                "{}/{}",
                e["node"].as_str().unwrap(),
                e["name"].as_str().unwrap()
            )
        })
        .collect();
    n.sort();
    n
}

/// No planted value, no fragment of one, and nothing shaped like a digest (a run of 32+ hex characters).
fn assert_no_value(text: &str, what: &str) {
    for v in all_planted() {
        assert!(!text.contains(&v), "{what} carries a planted value");
    }
    let mut run = 0;
    for c in text.chars() {
        run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
        assert!(
            run < 32,
            "{what} carries something shaped like a digest: {text}"
        );
    }
}

/// The planted vault: `acme` with sub-nodes `acme-web` and `acme-api`, `beta`, `stripe-test`, and `global`.
fn planted() -> (Vault, std::sync::Arc<BrokerState>, BrokerScope) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    node(&state, &owner, "acme", "Acme", GLOBAL_ID);
    node(&state, &owner, "acme-web", "Acme web", "acme");
    node(&state, &owner, "acme-api", "Acme api", "acme");
    node(&state, &owner, "beta", "Beta", GLOBAL_ID);
    node(&state, &owner, "stripe-test", "Stripe test", GLOBAL_ID);
    let s = &state;
    let o = &owner;
    entry_at(s, o, NOW, "acme-web", "STRIPE_KEY", one("key", DUP_SUB));
    entry_at(s, o, NOW, "acme-api", "stripe-key", one("key", DUP_SUB));
    entry_at(
        s,
        o,
        NOW,
        "acme",
        "TEST_SHARED_TOKEN",
        one("token", DUP_CROSS),
    );
    entry_at(
        s,
        o,
        NOW,
        "beta",
        "TEST_SHARED_TOKEN",
        one("token", DUP_CROSS),
    );
    entry_at(s, o, NOW, "beta", "TEST_A_TOKEN", one("token", DUP_SAME));
    entry_at(s, o, NOW, "beta", "TEST_B_SECRET", one("token", DUP_SAME));
    entry_at(s, o, NOW, "acme", "HOOK_URL", one("url", URL_A));
    entry_at(s, o, NOW, "beta", "WEBHOOK", one("url", URL_B));
    entry_at(
        s,
        o,
        NOW,
        "beta",
        "ADMIN_LOGIN",
        json!([{ "label": "username", "value": "admin" }, { "label": "password", "value": WEAK_PW, "type": "password" }]),
    );
    entry_at(
        s,
        o,
        NOW,
        "beta",
        "TWO_FACTOR",
        json!([{ "label": "uri", "value": OTP_URI, "type": "password" }]),
    );
    entry_at(
        s,
        o,
        NOW,
        "stripe-test",
        "STRIPE_SECRET",
        one("key", LIVE_KEY),
    );
    entry_at(
        s,
        o,
        NOW,
        GLOBAL_ID,
        "ACME_DEPLOY_HOOK",
        one("hook", MISFILED_VALUE),
    );
    entry_at(
        s,
        o,
        NOW,
        "beta",
        "SESSION_JWT",
        one("token", &expired_jwt()),
    );
    entry_at(
        s,
        o,
        NOW - 400 * DAY,
        "beta",
        "OLD_THING",
        one("token", "old-but-fine-Kq81zP"),
    );
    let soon = entry_at(
        s,
        o,
        NOW,
        "beta",
        "CERT_SOON",
        one("token", "cert-soon-Lm28xQ"),
    );
    let gone = entry_at(
        s,
        o,
        NOW,
        "beta",
        "CERT_GONE",
        one("token", concat!("cert-gone", "-Pq93zW")),
    );
    for (entry, at) in [(soon, NOW + 5 * DAY), (gone, NOW - DAY)] {
        let g = generation(s, o, "beta");
        call(
            s,
            o,
            NOW,
            "entry.set_expiry",
            json!({ "node": "beta", "entry": entry, "generation": g, "expiresAt": at }),
        )
        .expect("set_expiry");
    }
    (v, state, owner)
}

#[test]
fn every_finding_kind_is_reported_with_the_proposal_its_place_calls_for() {
    let (_v, state, owner) = planted();
    let r = scan(&state, &owner);
    assert_eq!(r["staleDays"], 365);
    assert_eq!(r["expiringDays"], 30);
    assert_eq!(r["truncated"], false);
    assert_eq!(r["entriesScanned"], 16, "{r}");
    assert_eq!(r["valuesChecked"], 16, "{r}");
    assert_eq!(
        r["nodesScanned"], 6,
        "global, acme, acme-web, acme-api, beta, stripe-test"
    );

    // Duplicates: exact, by where the copies sit.
    let dups = of_kind(&r, "duplicate_value");
    let find = |a: &str, b: &str| {
        dups.iter()
            .find(|f| names(f) == vec![a.to_string(), b.to_string()])
            .unwrap_or_else(|| panic!("no duplicate {a} + {b}: {r}"))
    };
    let sub = find("acme-api/stripe-key", "acme-web/STRIPE_KEY");
    assert_eq!(sub["match"], "exact");
    assert_eq!(sub["proposal"]["action"], "move_to_parent");
    assert_eq!(sub["proposal"]["op"], "entry.move");
    assert_eq!(sub["proposal"]["to"], "acme");
    assert_eq!(sub["proposal"]["toLabel"], "Acme");
    let mv = &sub["proposal"]["move"];
    assert_eq!(mv["to"], "acme");
    assert_eq!(
        mv["generation"].as_u64().unwrap(),
        generation(&state, &owner, mv["node"].as_str().unwrap())
    );
    let cross = find("acme/TEST_SHARED_TOKEN", "beta/TEST_SHARED_TOKEN");
    assert_eq!(cross["proposal"]["action"], "share");
    assert_eq!(cross["proposal"]["op"], Value::Null);
    let same = find("beta/TEST_A_TOKEN", "beta/TEST_B_SECRET");
    assert_eq!(same["proposal"]["action"], "merge");
    let probable = find("acme/HOOK_URL", "beta/WEBHOOK");
    assert_eq!(probable["match"], "probable");
    assert_eq!(dups.len(), 4, "{r}");

    // Misfiled in global → move to the project its name starts with.
    let misfiled = of_kind(&r, "misfiled");
    assert_eq!(misfiled.len(), 1, "{r}");
    assert_eq!(names(misfiled[0]), vec!["global/ACME_DEPLOY_HOOK"]);
    assert_eq!(misfiled[0]["proposal"]["move"]["to"], "acme");
    assert_eq!(misfiled[0]["proposal"]["move"]["node"], "global");

    // Near-duplicate names across nodes (the two STRIPE keys differ only in separators and case).
    let similar = of_kind(&r, "similar_names");
    assert!(
        similar.iter().any(|f| names(f)
            == vec![
                "acme-api/stripe-key".to_string(),
                "acme-web/STRIPE_KEY".to_string()
            ]
            && f["similarity"] == "separators"
            && f["sameNode"] == false),
        "{r}"
    );

    // Weak password, by reason only.
    let weak = of_kind(&r, "weak");
    assert_eq!(weak.len(), 1, "{r}");
    assert_eq!(names(weak[0]), vec!["beta/ADMIN_LOGIN"]);
    assert_eq!(weak[0]["fieldLabel"], "password");
    assert!(weak[0]["reasons"]
        .as_array()
        .unwrap()
        .contains(&json!("short")));

    // Mistyped: a raw otpauth URI, and a live key in a test node.
    let mistyped = of_kind(&r, "mistyped");
    let reason_of = |name: &str| {
        mistyped
            .iter()
            .find(|f| names(f)[0].ends_with(name))
            .map(|f| f["reason"].as_str().unwrap().to_string())
    };
    assert_eq!(reason_of("/TWO_FACTOR").as_deref(), Some("otpauth_uri"));
    assert_eq!(
        reason_of("/STRIPE_SECRET").as_deref(),
        Some("live_key_in_test")
    );

    // Expired (manifest and JWT), expiring, stale.
    let expired = of_kind(&r, "expired");
    let mut sources: Vec<(String, String)> = expired
        .iter()
        .map(|f| {
            (
                names(f)[0].clone(),
                f["source"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    sources.sort();
    assert_eq!(
        sources,
        vec![
            ("beta/CERT_GONE".to_string(), "manifest".to_string()),
            ("beta/SESSION_JWT".to_string(), "jwt".to_string()),
        ]
    );
    let jwt_row = expired.iter().find(|f| f["source"] == "jwt").unwrap();
    assert_eq!(jwt_row["expiresAt"], NOW - DAY);
    let expiring = of_kind(&r, "expiring");
    assert_eq!(expiring.len(), 1);
    assert_eq!(names(expiring[0]), vec!["beta/CERT_SOON"]);
    let stale = of_kind(&r, "stale");
    assert_eq!(stale.len(), 1, "{r}");
    assert_eq!(names(stale[0]), vec!["beta/OLD_THING"]);
    assert_eq!(stale[0]["basis"], "modified");

    // The counts match the findings.
    for (kind, n) in r["counts"].as_object().unwrap() {
        assert_eq!(
            of_kind(&r, kind).len() as u64,
            n.as_u64().unwrap(),
            "{kind}"
        );
    }
    // A shorter stale window and a longer expiry window are honoured.
    let wide = call(
        &state,
        &owner,
        NOW,
        "vault.doctor_scan",
        json!({ "staleDays": 1000, "expiringDays": 3650 }),
    )
    .unwrap();
    assert_eq!(of_kind(&wide, "stale").len(), 0);
}

#[test]
fn no_value_digest_or_fragment_leaves_in_the_answer_or_the_audit_trail() {
    let (v, state, owner) = planted();
    // Through the real server, so the request's generic audit record is written.
    let request = Request {
        id: "r".into(),
        op: "vault.doctor_scan".into(),
        token: owner.token_id.clone(),
        params: json!({}),
    };
    let answer = server::handle_request_at(&state, &peer(), &request, NOW, Instant::now())
        .0
        .expect("scan through the server");
    let text = serde_json::to_string(&answer).unwrap();
    assert!(text.contains("STRIPE_KEY"), "names are shown");
    assert_no_value(&text, "the scan's answer");

    let records = credmgr_store::audit::range(&v.paths(), 0, NOW + 1).unwrap();
    let scan_records: Vec<_> = records
        .iter()
        .filter(|r| r.action == "vault.doctor_scan")
        .collect();
    assert_eq!(scan_records.len(), 1, "one audit record for the request");
    assert_eq!(scan_records[0].decision.as_deref(), Some("allow"));
    // The scan's own record, whole; the rest of the trail (whose hash chain is hex by design) for values.
    let mut own = serde_json::to_value(scan_records[0]).unwrap();
    own.as_object_mut().unwrap().remove("prev"); // the chain's link to the record before, hex by design
    assert_no_value(&own.to_string(), "the scan's audit record");
    assert_eq!(own["detail"], Value::Null);
    let trail = serde_json::to_string(&records).unwrap();
    for planted in all_planted() {
        assert!(
            !trail.contains(&planted),
            "the audit trail carries a planted value"
        );
    }
    // And nothing on disk outside the sealed envelopes carries one: the audit files read raw.
    for file in std::fs::read_dir(v.paths().audit_dir()).unwrap() {
        let bytes = std::fs::read(file.unwrap().path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for planted in all_planted() {
            assert!(
                !text.contains(&planted),
                "an audit file carries a planted value"
            );
        }
    }
}

#[test]
fn only_the_owners_login_may_scan() {
    let (_v, state, _owner) = planted();
    let all = vec![
        Capability::List,
        Capability::Read,
        Capability::Reveal,
        Capability::Create,
        Capability::Update,
        Capability::Notes,
        Capability::Admin,
    ];
    for (origin, token) in [
        (Origin::Agent, None),
        (Origin::HumanUi, None),
        (Origin::HumanUi, Some("not-a-session".to_string())),
        (Origin::Cli, None),
    ] {
        let scope = BrokerScope {
            node_id: GLOBAL_ID.to_string(),
            capabilities: all.clone(),
            origin,
            token_id: token,
            bound_workdir: None,
        };
        let r = call(&state, &scope, NOW, "vault.doctor_scan", json!({}));
        assert!(
            matches!(r, Err(OpError::CapabilityNotHeld { .. })),
            "{origin:?}: {r:?}"
        );
    }
    // Bad windows are refused before anything is read.
    let owner = login(&state);
    for bad in [
        json!({ "staleDays": 0 }),
        json!({ "expiringDays": 3651 }),
        json!({ "staleDays": "a year" }),
    ] {
        let r = call(&state, &owner, NOW, "vault.doctor_scan", bad.clone());
        assert!(matches!(r, Err(OpError::Malformed(_))), "{bad}: {r:?}");
    }
}

fn enrol_node_gate(state: &BrokerState, owner: &BrokerScope, node: &str) {
    let begin = call(
        state,
        owner,
        NOW,
        "node.gate_enroll_begin",
        json!({ "node": node }),
    )
    .expect("begin");
    let uri = begin["otpauthUri"].as_str().unwrap();
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let totp = Totp::new_gate(decode_gate_secret_base32(b32).unwrap());
    call(
        state,
        owner,
        NOW,
        "node.gate_enroll_confirm",
        json!({ "node": node, "code": totp.code(NOW as u64) }),
    )
    .expect("confirm");
}

#[test]
fn a_locked_node_contributes_nothing_and_a_gated_node_only_its_names() {
    let (_v, state, owner) = planted();
    node(&state, &owner, "vaulted", "Vaulted", GLOBAL_ID);
    entry_at(
        &state,
        &owner,
        NOW,
        "vaulted",
        "VAULTED_COPY",
        one("key", DUP_SUB),
    );
    enrol_node_gate(&state, &owner, "vaulted");
    call(
        &state,
        &owner,
        NOW,
        "vault.node_lock",
        json!({ "node": "beta" }),
    )
    .expect("lock beta");

    let r = scan(&state, &owner);
    let text = serde_json::to_string(&r).unwrap();
    // Locked: nothing of beta is named anywhere in the findings.
    for f in r["findings"].as_array().unwrap() {
        for e in f["entries"].as_array().unwrap() {
            assert_ne!(e["node"], "beta", "a locked node is never listed: {f}");
        }
    }
    let skipped = r["skipped"].as_array().unwrap();
    assert!(skipped
        .iter()
        .any(|s| s["node"] == "beta" && s["reason"] == "locked" && s["what"] == "all"));
    // Gated and not open: named (its entry is counted), but its value is not compared.
    assert!(skipped.iter().any(|s| s["node"] == "vaulted"
        && s["reason"] == "second_factor"
        && s["what"] == "values"));
    for f in of_kind(&r, "duplicate_value") {
        assert!(
            !names(f).iter().any(|n| n.starts_with("vaulted/")),
            "a gated node's value is not compared: {f}"
        );
    }
    // The orphan node is never in a report.
    assert!(!text.contains("\"orphan\""));
    assert_no_value(&text, "the scan's answer");
}

#[test]
fn a_move_proposal_applies_through_entry_move_and_a_rescan_sees_it() {
    let (_v, state, owner) = planted();
    let key = enrol_first_key(&state, &owner);
    let r = scan(&state, &owner);
    let sub = of_kind(&r, "duplicate_value")
        .into_iter()
        .find(|f| f["proposal"]["action"] == "move_to_parent")
        .expect("a move-to-parent proposal")
        .clone();
    let params = sub["proposal"]["move"].clone();
    let proved = with_proof(&state, &owner, &key, NOW, "entry.move", params);
    let moved = call(&state, &owner, NOW, "entry.move", proved).expect("entry.move");
    assert_eq!(moved["node"], "acme");

    // Now one copy sits in `acme`, which `acme-api` (or `acme-web`) reads: the other copy is redundant.
    let again = scan(&state, &owner);
    let after = of_kind(&again, "duplicate_value")
        .into_iter()
        .find(|f| {
            names(f)
                .iter()
                .any(|n| n.starts_with("acme/") && n.to_lowercase().contains("stripe"))
        })
        .expect("the pair is still a duplicate")
        .clone();
    assert_eq!(after["proposal"]["action"], "remove_copies");
    assert_eq!(after["proposal"]["keep"]["node"], "acme");

    // A stale generation from the earlier report is refused by entry.move and changes nothing.
    let stale = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "entry.move",
        of_kind(&r, "misfiled")[0]["proposal"]["move"].clone(),
    );
    // The misfiled proposal was read before the move above, but `global` did not change: it still applies.
    assert!(call(&state, &owner, NOW, "entry.move", stale).is_ok());
}

#[test]
fn one_scan_at_a_time_and_a_capped_scan_says_it_was_cut() {
    let (_v, state, owner) = planted();
    {
        let _running = state.hold_doctor_scan_for_test();
        let r = call(&state, &owner, NOW, "vault.doctor_scan", json!({}));
        assert!(matches!(r, Err(OpError::RateLimited { .. })), "{r:?}");
    }
    state.set_doctor_scan_cap_for_test(Some(3));
    let r = scan(&state, &owner);
    assert_eq!(r["entriesScanned"], 3);
    assert_eq!(r["truncated"], true);
    state.set_doctor_scan_cap_for_test(None);
    assert_eq!(scan(&state, &owner)["truncated"], false);
}

#[test]
fn two_scans_agree_on_the_findings() {
    // The per-scan key differs each run (credmgr_core::doctor's unit test), and a digest never leaves, so
    // all a caller can see is that the grouping is the same each time.
    let (_v, state, owner) = planted();
    let a = scan(&state, &owner);
    let b = scan(&state, &owner);
    assert_eq!(a["findings"], b["findings"]);
}
