//! Issue #36 / ADR-112 - `maintenance.backup` makes a COMPLETE archive and a restore
//! rebuilds the same vault from it.
//!
//! The method: a real vault (`vault.init_*`) is filled with everything the archive
//! used to leave out - a sealed note, a sealed node (`archive/<id>/`), a removed
//! entry, rotation history, the audit log - and backed up through the real op. The
//! archive is decrypted with its passphrase and restored into a FRESH vault directory
//! and a FRESH state directory with `credmgr_store::backup::restore_bundle` (what
//! `credmgr restore` runs). Then:
//!
//! * the restored vault directory is byte-identical to the source, file for file;
//! * a new broker over it unlocks with the vault passphrase and `maintenance.verify`
//!   passes;
//! * every entry reveals the same value, the note reads back, the sealed node
//!   restores from its archive, the removed entry restores, the rotation is undone from
//!   its history, and the audit chain verifies;
//! * the archive carries no generation counter but a restore ticket (ADR-148 amendment): the restore
//!   writes a one-shot marker, the first unlock consumes it and writes the counter, which is the source's.
//!
//! Then the refusals: a wrong passphrase, a damaged archive, a target that is not
//! empty, a stale archive restored beside a newer counter (refused as rolled back), a missing
//! counter with no marker, a marker for another vault or a forged one, and a consumed marker
//! planted again after the vault moved on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_keystore::backup_passphrase::decrypt_with_passphrase;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::backup::{restore_bundle, CounterOutcome};
use credmgr_store::paths::VaultPaths;

const NOW: i64 = 1_800_000_000;
const MARKER: &str = "restore-accept.marker";
const PASSPHRASE: &str = "correct horse battery staple";
fn archive_passphrase() -> &'static str {
    "a different passphrase for the archive"
}

struct Env {
    vault_dir: PathBuf,
    state_dir: PathBuf,
    _dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = dir.path().join("vault");
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&vault_dir).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        Env {
            vault_dir,
            state_dir,
            _dir: dir,
        }
    }

    fn paths(&self) -> VaultPaths {
        VaultPaths::new(self.vault_dir.clone())
    }

    /// A broker as a freshly started daemon would be: nothing in memory.
    fn broker(&self) -> Arc<BrokerState> {
        let keystore = SoftwareKeystore::new(
            SecretBox::new(Box::default()),
            self.state_dir.join("placeholder-keystore"),
        );
        let state = Arc::new(BrokerState::new(Box::new(keystore), self.paths()));
        state.set_state_dir_for_test(self.state_dir.clone());
        state
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

fn peer() -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    }
}

/// A request through the real server wiring (so the audit log is written), with the
/// audit id the broker answered with.
fn send(
    state: &Arc<BrokerState>,
    token: Option<&str>,
    op: &str,
    params: Value,
) -> (Result<Value, OpError>, Option<String>) {
    let request = Request {
        id: "r".to_string(),
        op: op.to_string(),
        token: token.map(str::to_string),
        params,
    };
    server::handle_request_at(state, &peer(), &request, NOW, Instant::now())
}

fn ok(state: &Arc<BrokerState>, token: &str, op: &str, params: Value) -> Value {
    send(state, Some(token), op, params)
        .0
        .unwrap_or_else(|e| panic!("{op} failed: {e:?}"))
}

fn init(env: &Env, state: &Arc<BrokerState>) {
    let begin = credmgr_brokerd::ops::dispatch(
        state,
        &anyone(),
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin");
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    credmgr_brokerd::ops::dispatch(
        state,
        &anyone(),
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": code }),
    )
    .expect("init_confirm");
    let _ = env;
}

fn login(state: &Arc<BrokerState>) -> Result<String, OpError> {
    send(
        state,
        None,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .0
    .map(|v| {
        v["token"]
            .as_str()
            .expect("a login mints a token")
            .to_string()
    })
}

fn reveal(state: &Arc<BrokerState>, token: &str, node: &str, entry: &str) -> String {
    ok(
        state,
        token,
        "entry.reveal",
        json!({ "node": node, "entry": entry }),
    )["value"]
        .as_str()
        .unwrap()
        .to_string()
}

fn generation(state: &Arc<BrokerState>, token: &str, node: &str) -> u64 {
    ok(state, token, "entry.list", json!({ "node": node }))["generation"]
        .as_u64()
        .unwrap()
}

/// Every file under `root` except what an archive is documented to leave out, as
/// `relative path -> bytes`.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out.retain(|rel, _| {
        !(rel.starts_with("backups/")
            || rel.starts_with("run/")
            || rel.starts_with("rotation-pending/")
            || rel == "keys/root.wrap.se"
            || rel.rsplit('/').next().is_some_and(|n| n.starts_with('.')))
    });
    out
}

struct Source {
    env: Env,
    state: Arc<BrokerState>,
    owner: String,
    one: String,
    two: String,
    gone: String,
    rotate_audit: String,
    beta_entry: String,
}

/// A vault holding one of everything the old archive omitted.
fn rich_vault() -> Source {
    let env = Env::new();
    let state = env.broker();
    init(&env, &state);
    let owner = login(&state).expect("unlock");

    let create_node = |id: &str| {
        ok(
            &state,
            &owner,
            "node.create",
            json!({ "id": id, "label": id, "parentId": "global" }),
        );
    };
    create_node("acme");
    create_node("beta");

    let new_entry = |node: &str, name: &str, value: &str| -> String {
        ok(
            &state,
            &owner,
            "entry.create",
            json!({ "node": node, "name": name, "value": value }),
        )["entry"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let one = new_entry("acme", "ONE", "value-one");
    let two = new_entry("acme", "TWO", "value-two");
    let gone = new_entry("acme", "GONE", "value-gone");
    let beta_entry = new_entry("beta", "BETA", "value-beta");

    // A multi-field entry, so field ids and labels travel too.
    ok(
        &state,
        &owner,
        "entry.create",
        json!({ "node": "acme", "name": "LOGIN", "fields": [
            { "label": "host", "value": "db.internal" },
            { "label": "password", "value": "pw-restore-test" },
        ] }),
    );

    // A sealed note.
    let g = generation(&state, &owner, "acme");
    ok(
        &state,
        &owner,
        "notes.write",
        json!({ "node": "acme", "markdown": "# runbook\nrestart the thing", "generation": g }),
    );

    // Rotation history: ONE is rotated; the audit id lets the test undo it later.
    let g = generation(&state, &owner, "acme");
    let (rotated, audit) = send(
        &state,
        Some(&owner),
        "entry.rotate",
        json!({ "node": "acme", "entry": one, "value": "value-one-rotated", "generation": g }),
    );
    rotated.expect("entry.rotate");
    let rotate_audit = audit.expect("a rotation is audited");

    // A removed entry (archive/removed-entries/).
    let g = generation(&state, &owner, "acme");
    ok(
        &state,
        &owner,
        "entry.remove",
        json!({ "node": "acme", "entry": gone, "generation": g }),
    );

    // A sealed node (archive/<id>/ + the orphan copies).
    ok(&state, &owner, "node.seal", json!({ "node": "beta" }));

    Source {
        env,
        state,
        owner,
        one,
        two,
        gone,
        rotate_audit,
        beta_entry,
    }
}

fn backup(src: &Source, passphrase: &str) -> Vec<u8> {
    let v = ok(
        &src.state,
        &src.owner,
        "maintenance.backup",
        json!({ "passphrase": passphrase }),
    );
    assert_eq!(v["complete"], true, "{v}");
    let blob = std::fs::read(v["path"].as_str().unwrap()).unwrap();
    decrypt_with_passphrase(&SecretBox::new(Box::new(passphrase.to_string())), &blob)
        .expect("the archive opens with its passphrase")
}

#[test]
fn a_backup_restores_into_a_fresh_directory_as_the_same_vault() {
    let source = rich_vault();
    let counter_file = "vaultGeneration.counter";
    let archive = backup(&source, archive_passphrase());
    let source_counter = std::fs::read(source.env.state_dir.join(counter_file))
        .expect("the source has a generation counter");

    // ---- restore into a fresh vault directory and a fresh state directory ----
    let fresh = Env::new();
    let target = fresh._dir.path().join("restored").join("vault");
    let report = restore_bundle(&archive, &target, &fresh.state_dir).expect("restore");
    assert!(report.complete);
    // ADR-148 amendment: the counter is not in the archive; a restore ticket is, and the
    // restore turned it into the one-shot marker the first unlock consumes.
    assert_eq!(report.counter, CounterOutcome::AcceptMarker);
    let entries = credmgr_store::backup::unpack(&archive).unwrap();
    assert!(
        !entries
            .iter()
            .any(|e| e.relative_path.ends_with(counter_file)),
        "the generation counter stays on this machine"
    );
    assert!(entries
        .iter()
        .any(|e| e.relative_path == "_state/restore.ticket"));
    assert!(!fresh.state_dir.join(counter_file).exists());
    assert!(fresh.state_dir.join(MARKER).exists());

    // 1. Byte-identical vault directory.
    let want = tree(&source.env.vault_dir);
    let got = tree(&target);
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        want.keys().collect::<Vec<_>>(),
        "same file set"
    );
    for (rel, bytes) in &want {
        if rel.starts_with("audit/") {
            // `maintenance.backup` itself is audited after the archive is cut, so the live
            // log is the archived one plus the backup's own record: the archive is a prefix,
            // and the chain tip beside it (the hash of that last record) has moved on.
            assert!(!got[rel].is_empty(), "{rel} is not empty");
            if !rel.ends_with(".tip") {
                assert!(
                    bytes.starts_with(&got[rel]),
                    "{rel}: the archived log is a prefix"
                );
            }
        } else {
            assert_eq!(&got[rel], bytes, "{rel} differs");
        }
    }
    // The pieces the old archive omitted are among them.
    for needle in [
        "nodes/acme/notes.env",
        "archive/beta/node.key",
        "archive/beta/meta.json",
        "keys/cold/orphan.key",
    ] {
        assert!(
            got.contains_key(needle),
            "{needle} is in the restored vault"
        );
    }
    assert!(
        got.keys()
            .any(|k| k.starts_with("archive/removed-entries/")),
        "a removed entry's archive"
    );
    assert!(
        got.keys().any(|k| k.starts_with("archive/entry-history/")),
        "rotation history"
    );
    assert!(got.keys().any(|k| k.starts_with("audit/")), "the audit log");

    // ---- open the restored vault with a new broker ----
    let restored = Env {
        vault_dir: target.clone(),
        state_dir: fresh.state_dir.clone(),
        _dir: tempfile::tempdir().unwrap(),
    };
    let state = restored.broker();
    let token = login(&state).expect("the restored vault unlocks with the vault passphrase");

    // 2. The first unlock consumed the marker and wrote the counter, which is the source's.
    assert!(
        !fresh.state_dir.join(MARKER).exists(),
        "the marker is consumed"
    );
    assert_eq!(
        std::fs::read(fresh.state_dir.join(counter_file)).unwrap(),
        source_counter
    );

    let verify = ok(&state, &token, "maintenance.verify", json!({}));
    assert_eq!(verify["ok"], true, "maintenance.verify: {verify}");

    // 3. Entries.
    assert_eq!(
        reveal(&state, &token, "acme", &source.one),
        "value-one-rotated"
    );
    assert_eq!(reveal(&state, &token, "acme", &source.two), "value-two");
    let login_entry = ok(&state, &token, "entry.list", json!({ "node": "acme" }));
    assert!(
        login_entry["names"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == "LOGIN"),
        "{login_entry}"
    );

    // 4. The note.
    let note = ok(&state, &token, "notes.read", json!({ "node": "acme" }));
    assert!(
        note.to_string().contains("restart the thing"),
        "the sealed note came back: {note}"
    );

    // 5. Rotation history: the rotation is undone from the restored history.
    let g = generation(&state, &token, "acme");
    ok(
        &state,
        &token,
        "entry.undo",
        json!({ "node": "acme", "id": source.rotate_audit, "generation": g }),
    );
    assert_eq!(reveal(&state, &token, "acme", &source.one), "value-one");

    // 6. The removed entry comes back from its archive.
    let g = generation(&state, &token, "acme");
    ok(
        &state,
        &token,
        "entry.restore",
        json!({ "node": "acme", "entry": source.gone, "generation": g }),
    );
    assert_eq!(reveal(&state, &token, "acme", &source.gone), "value-gone");

    // 7. The sealed node is restorable from its archive.
    ok(&state, &token, "node.restore", json!({ "node": "beta" }));
    assert_eq!(
        reveal(&state, &token, "beta", &source.beta_entry),
        "value-beta"
    );

    // 8. The audit chain verifies (maintenance.verify walks it).
    let verify = ok(&state, &token, "maintenance.verify", json!({}));
    assert_eq!(
        verify["ok"], true,
        "after the undo, restore and node restore: {verify}"
    );
}

#[test]
fn a_wrong_passphrase_a_damaged_archive_and_a_used_target_restore_nothing() {
    let src = rich_vault();
    let archive = backup(&src, archive_passphrase());

    // Wrong passphrase: the archive does not open at all.
    let v = ok(
        &src.state,
        &src.owner,
        "maintenance.backup",
        json!({ "passphrase": archive_passphrase() }),
    );
    let blob = std::fs::read(v["path"].as_str().unwrap()).unwrap();
    assert!(
        decrypt_with_passphrase(&SecretBox::new(Box::new("not it".to_string())), &blob).is_err()
    );

    // A damaged (truncated) archive is refused and writes nothing.
    let fresh = Env::new();
    let target = fresh._dir.path().join("restored");
    let err = restore_bundle(&archive[..archive.len() - 5], &target, &fresh.state_dir).unwrap_err();
    assert!(err.to_string().contains("truncated"), "{err}");
    assert!(!target.exists());
    assert!(!fresh.state_dir.join("vaultGeneration.counter").exists());

    // A target that already holds a vault is not touched.
    let err = restore_bundle(&archive, &src.env.vault_dir, &fresh.state_dir).unwrap_err();
    assert!(err.to_string().contains("not empty"), "{err}");
}

#[test]
fn an_old_archive_restored_beside_a_newer_counter_is_refused_as_rolled_back() {
    let old = rich_vault();
    let old_archive = backup(&old, archive_passphrase());
    let counter_at_backup =
        std::fs::read(old.env.state_dir.join("vaultGeneration.counter")).unwrap();

    // The vault moves on after the backup.
    ok(
        &old.state,
        &old.owner,
        "entry.create",
        json!({ "node": "acme", "name": "LATER", "value": "later-value" }),
    );
    let counter_now = std::fs::read(old.env.state_dir.join("vaultGeneration.counter")).unwrap();
    assert_ne!(
        counter_now, counter_at_backup,
        "the later write moved the counter (otherwise this test proves nothing)"
    );

    // Restore the OLD archive into a new vault directory but beside the LIVE state
    // directory: the counter there is kept, and the stale registry is refused.
    let target = old.env._dir.path().join("restored-old");
    let report = restore_bundle(&old_archive, &target, &old.env.state_dir).unwrap();
    assert_eq!(report.counter, CounterOutcome::KeptExisting);
    assert_eq!(
        std::fs::read(old.env.state_dir.join("vaultGeneration.counter")).unwrap(),
        counter_now,
        "the newer counter was not lowered"
    );
    let stale = Env {
        vault_dir: target,
        state_dir: old.env.state_dir.clone(),
        _dir: tempfile::tempdir().unwrap(),
    };
    let state = stale.broker();
    let refused = login(&state);
    assert!(
        refused.is_err(),
        "a rolled-back registry must not open: {refused:?}"
    );
}

/// ADR-148 amendment (K-23 (e)): restore the archive of `src` into a fresh vault folder and a fresh state
/// directory; the restored vault's environment (not yet opened).
fn restored_from(archive: &[u8]) -> Env {
    let fresh = Env::new();
    let target = fresh._dir.path().join("restored");
    let report = restore_bundle(archive, &target, &fresh.state_dir).expect("restore");
    assert_eq!(report.counter, CounterOutcome::AcceptMarker);
    Env {
        vault_dir: target,
        state_dir: fresh.state_dir.clone(),
        _dir: fresh._dir,
    }
}

#[test]
fn a_missing_counter_without_the_restore_marker_is_still_refused() {
    let src = rich_vault();
    let archive = backup(&src, archive_passphrase());
    let restored = restored_from(&archive);
    std::fs::remove_file(restored.state_dir.join(MARKER)).unwrap();
    let refused = login(&restored.broker());
    assert!(refused.is_err(), "no counter and no marker: {refused:?}");
    assert!(!restored.state_dir.join("vaultGeneration.counter").exists());

    // And on the live vault: deleting its counter is refused as before (review H1(a)).
    std::fs::remove_file(src.env.state_dir.join("vaultGeneration.counter")).unwrap();
    assert!(login(&src.env.broker()).is_err());
}

#[test]
fn a_restore_marker_for_another_vault_or_a_forged_one_is_refused() {
    let a = rich_vault();
    let b = rich_vault();
    let restored_a = restored_from(&backup(&a, archive_passphrase()));
    let restored_b = restored_from(&backup(&b, archive_passphrase()));
    let marker_a = std::fs::read(restored_a.state_dir.join(MARKER)).unwrap();
    let marker_b = std::fs::read(restored_b.state_dir.join(MARKER)).unwrap();

    // A's marker beside B's restored vault: signed under another root key, naming another registry.
    std::fs::write(restored_b.state_dir.join(MARKER), marker_a).unwrap();
    let refused = login(&restored_b.broker());
    assert!(refused.is_err(), "another vault's marker: {refused:?}");
    assert!(!restored_b
        .state_dir
        .join("vaultGeneration.counter")
        .exists());

    // B's own marker with its generation edited: the tag no longer covers it.
    let mut forged: Value = serde_json::from_slice(&marker_b).unwrap();
    let g = forged["ticket"]["generation"].as_u64().unwrap();
    forged["ticket"]["generation"] = json!(g + 1);
    std::fs::write(
        restored_b.state_dir.join(MARKER),
        serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    assert!(login(&restored_b.broker()).is_err(), "a forged generation");
    // B's own marker with its tag replaced: refused.
    let mut forged: Value = serde_json::from_slice(&marker_b).unwrap();
    forged["ticket"]["hmac"] = json!("00".repeat(32));
    std::fs::write(
        restored_b.state_dir.join(MARKER),
        serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    assert!(login(&restored_b.broker()).is_err(), "a forged tag");

    // B's own marker, as written: accepted once, then the counter decides.
    std::fs::write(restored_b.state_dir.join(MARKER), &marker_b).unwrap();
    let token = login(&restored_b.broker()).expect("its own marker opens it");
    let _ = token;
    assert!(restored_b
        .state_dir
        .join("vaultGeneration.counter")
        .exists());
    assert!(!restored_b.state_dir.join(MARKER).exists());
}

#[test]
fn a_consumed_marker_planted_again_after_the_vault_moved_on_is_refused() {
    let src = rich_vault();
    let restored = restored_from(&backup(&src, archive_passphrase()));
    let marker = std::fs::read(restored.state_dir.join(MARKER)).unwrap();
    let state = restored.broker();
    let token = login(&state).expect("the first unlock consumes the marker");
    // The vault moves on: the registry is rewritten at a higher generation.
    ok(
        &state,
        &token,
        "node.create",
        json!({ "id": "later", "label": "later", "parentId": GLOBAL_ID }),
    );
    drop(state);
    // Someone deletes the counter and puts the old marker back: it names the old registry, refused.
    std::fs::remove_file(restored.state_dir.join("vaultGeneration.counter")).unwrap();
    std::fs::write(restored.state_dir.join(MARKER), marker).unwrap();
    let refused = login(&restored.broker());
    assert!(refused.is_err(), "a replayed marker: {refused:?}");
}
