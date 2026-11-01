//! Phase 4 exit gate: "every command works against the broker; none
//! decrypts directly." This drives the *real* compiled `credmgr` binary
//! (via `CARGO_BIN_EXE_credmgr`) as a subprocess against a *real*
//! `credmgrd` — an actual `BrokerState` seeded with a fixture vault and
//! served on a real, temporary UDS socket by `server::run` — never a mock,
//! never an in-process function call standing in for the wire protocol.
//!
//! Also the top-level build prompt's own named demonstration: "`credmgr
//! whoami` from a directory registered to a node returns that node and
//! refuses another — demonstrated, not asserted." `whoami_*` below is that
//! demonstration, driven through real `LOCAL_PEERCRED`/cwd resolution
//! (`peer.rs`), not a stub.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use secrecy::SecretBox;

use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::envelope;
use credmgr_core::keys::generate_node_keypair;
use credmgr_core::registry::{
    Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID, ORPHAN_ID,
};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{ManifestBody, ManifestEntry, Sensitivity};
use credmgr_store::paths::VaultPaths;

const PASSPHRASE: &str = "correct horse battery staple";

/// A running fixture broker plus everything a test needs to point the real
/// `credmgr` binary at it: the vault directory (for `CREDMGR_VAULT_DIR`) and
/// the directory registered as the `acme` node's `workdirs[0]` (for the
/// subprocess's `current_dir`, which is what `peer.rs`'s real
/// `proc_pidinfo(PROC_PIDVNODEPATHINFO)` lookup reports back to the broker).
struct Fixture {
    vault_dir: PathBuf,
    acme_workdir: PathBuf,
    /// Kept so a test can mint a token directly against the same running
    /// broker (`state.tokens.issue`). `vault.unlock`/`vault.gate_verify` are
    /// now a real, wire-level login path (ADR-056) — but they only ever mint
    /// a token scoped to `GLOBAL_ID`; this fixture helper remains the only
    /// way to present an `Origin::HumanUi`+`Admin` token scoped to a
    /// *specific* project (e.g. `"acme"`), which every test below that seals,
    /// grants against, or otherwise administers `acme` specifically needs.
    state: Arc<BrokerState>,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    /// Mint a token with the given capabilities/origin directly against the
    /// live broker and return its id, ready to pass via `CREDMGR_TOKEN`.
    fn issue_token(&self, node_id: &str, capabilities: Vec<Capability>, origin: Origin) -> String {
        self.state
            .tokens
            .issue(node_id, capabilities, origin, None)
            .id
    }
}

fn start_fixture_broker() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_dir = tmp.path().join("vault");
    let state_dir = tmp.path().join("keystore-state");
    let acme_workdir = tmp.path().join("acme-project");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::create_dir_all(&acme_workdir).unwrap();
    // macOS's temp root is itself a symlink (`/tmp` → `/private/tmp`), and
    // `peer.rs`'s real `proc_pidinfo(PROC_PIDVNODEPATHINFO)` reports the
    // resolved path — canonicalize before registering it as a `workdirs[]`
    // entry, or an exact-string match against the live, resolved cwd never
    // fires.
    let acme_workdir = acme_workdir.canonicalize().unwrap();

    let paths = VaultPaths::new(vault_dir.clone());
    std::fs::create_dir_all(paths.run_dir()).unwrap();
    std::fs::set_permissions(paths.run_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let keystore =
        SoftwareKeystore::new(SecretBox::new(Box::new(PASSPHRASE.to_string())), state_dir);
    let state = Arc::new(BrokerState::new(Box::new(keystore), paths.clone()));

    let root_key = SecretBox::new(Box::new([42u8; 32]));
    state.seed_root_key(&root_key);

    let mut registry = Registry::new();
    registry.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    registry.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());
    registry.nodes.insert(
        "acme".to_string(),
        Node {
            id: "acme".to_string(),
            label: "Acme".to_string(),
            kind: NodeKind::Project,
            depth: 1,
            parent_id: Some(GLOBAL_ID.to_string()),
            workdirs: vec![acme_workdir.to_string_lossy().into_owned()],
            policy: NodePolicy::default(),
        },
    );
    state.set_registry(registry);

    let orphan_pair = generate_node_keypair();
    // ORPHAN's own key is never seeded into the hot set via `seed_node_key`
    // (that would put its private half in the broker's hot set, which
    // `04_CRYPTO_AND_KEYS.md §5` says must never happen) — only its public
    // key is registered, exactly what `node.seal`'s real dispatch path
    // needs (`state.node_public_key(ORPHAN_ID)`) and nothing more.
    state.seed_public_key_only(ORPHAN_ID, orphan_pair.public);

    let acme_pub = state.seed_node_key(&root_key, "acme");

    let entry_id = "e_test0001";
    let plaintext = b"s3cr3t-deploy-token";
    // Not the real hash of `plaintext` — this field is informational
    // manifest metadata, never re-derived or checked by anything these
    // tests exercise, so a fixed placeholder is honest and simpler than
    // pulling in a hashing dependency just for a fixture.
    let sha256 = "0".repeat(64);
    let mut manifest = ManifestBody::new("acme");
    manifest.entries.push(ManifestEntry {
        id: entry_id.to_string(),
        name: "DEPLOY_TOKEN".to_string(),
        r#ref: 1000,
        entry_type: credmgr_core::inference::EntryType::Token,
        sensitivity: Sensitivity::High,
        field_count: 1,
        sha256,
        modified: 0,
        expires_at: None,
        rotated_at: None,
        has_totp: false,
    });
    state.set_manifest("acme", manifest);

    let sealed = envelope::seal(plaintext, &acme_pub, "acme", entry_id).unwrap();
    credmgr_store::atomic::write(&paths.entry_env("acme", entry_id), &sealed).unwrap();

    state
        .unlock(0)
        .expect("fixture keystore's own passphrase must unlock its own wrap");

    let state_handle = Arc::clone(&state);
    let socket_path = paths.run_socket();
    std::thread::spawn(move || {
        credmgr_brokerd::server::run(state, &socket_path).expect("fixture broker crashed");
    });
    // No fixed sleep: poll until the socket is connectable, bounded so a
    // genuine startup failure fails the test instead of hanging it.
    wait_for_socket(&paths.run_socket());

    Fixture {
        vault_dir,
        acme_workdir,
        state: state_handle,
        _tmp: tmp,
    }
}

fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("credmgrd fixture never opened its socket at {path:?}");
}

fn credmgr(fixture: &Fixture, cwd: &Path, args: &[&str]) -> (bool, String, String) {
    credmgr_with_token(fixture, cwd, args, None)
}

fn credmgr_with_token(
    fixture: &Fixture,
    cwd: &Path,
    args: &[&str],
    token: Option<&str>,
) -> (bool, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_credmgr"));
    command
        .args(args)
        .current_dir(cwd)
        .env("CREDMGR_VAULT_DIR", &fixture.vault_dir);
    if let Some(token) = token {
        command.env("CREDMGR_TOKEN", token);
    }
    let output = command
        .output()
        .expect("failed to launch the credmgr binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn whoami_from_a_registered_dir_returns_that_node_and_refuses_another() {
    let fixture = start_fixture_broker();

    let (ok, stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["whoami"]);
    assert!(ok, "whoami from the registered dir failed: {stderr}");
    assert!(
        stdout.contains("node: acme"),
        "expected the acme node, got: {stdout}"
    );

    let elsewhere = fixture._tmp.path().join("nowhere-in-particular");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let (ok, stdout, stderr) = credmgr(&fixture, &elsewhere, &["whoami"]);
    assert!(ok, "whoami from an unregistered dir failed: {stderr}");
    assert!(
        !stdout.contains("node: acme"),
        "an unregistered directory must never resolve to acme's scope, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!("node: {GLOBAL_ID}")),
        "an unregistered directory falls back to global/list-only, got: {stdout}"
    );
}

#[test]
fn status_reports_unlocked() {
    let fixture = start_fixture_broker();
    let (ok, stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["status"]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout.trim(), "locked: false");
}

#[test]
fn list_and_search_and_get_round_trip_a_real_value() {
    let fixture = start_fixture_broker();

    let (ok, stdout, stderr) =
        credmgr(&fixture, &fixture.acme_workdir, &["list", "--node", "acme"]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout.trim(), "DEPLOY_TOKEN");

    let (ok, stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["search", "DEPLOY"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("acme") && stdout.contains("DEPLOY_TOKEN"),
        "{stdout}"
    );

    let (ok, stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["get", "DEPLOY_TOKEN"]);
    assert!(ok, "get failed: {stderr}");
    assert_eq!(stdout.trim(), "s3cr3t-deploy-token");

    // Explicit --node takes the same path and must agree.
    let (ok, stdout, stderr) = credmgr(
        &fixture,
        &fixture.acme_workdir,
        &["get", "DEPLOY_TOKEN", "--node", "acme"],
    );
    assert!(ok, "{stderr}");
    assert_eq!(stdout.trim(), "s3cr3t-deploy-token");
}

#[test]
fn set_creates_then_updates_the_same_name() {
    let fixture = start_fixture_broker();

    let created = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(["set", "NEW_SECRET", "--node", "acme"])
        .current_dir(&fixture.acme_workdir)
        .env("CREDMGR_VAULT_DIR", &fixture.vault_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    write_stdin_and_wait(created, "first-value");

    let (ok, stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["get", "NEW_SECRET"]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout.trim(), "first-value");

    let updated = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(["set", "NEW_SECRET", "--node", "acme"])
        .current_dir(&fixture.acme_workdir)
        .env("CREDMGR_VAULT_DIR", &fixture.vault_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    write_stdin_and_wait(updated, "second-value");

    let (ok, stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["get", "NEW_SECRET"]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout.trim(), "second-value");
}

fn write_stdin_and_wait(mut child: std::process::Child, value: &str) {
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "credmgr set exited non-zero");
}

#[test]
fn node_seal_then_restore_round_trips() {
    let fixture = start_fixture_broker();
    // `node.seal`/`node.restore` are `Capability::Admin`-gated (ADR's own
    // "Phase 3 substitutes Admin for the missing 2FA factor" note in
    // `ops.rs`) — a cwd-resolved agent scope never carries `Admin`
    // (`scope.rs::capabilities_for_agent_access`), so this is the one place
    // in this file that needs a real token, minted directly against the
    // fixture's own `TokenStore` (see `Fixture::issue_token`'s doc).
    let admin_token = fixture.issue_token("acme", vec![Capability::Admin], Origin::HumanUi);

    let (ok, stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["node", "seal", "acme"],
        Some(&admin_token),
    );
    assert!(ok, "seal failed: {stderr}");
    assert!(stdout.contains("acme"), "{stdout}");

    // Sealed: acme no longer lists as a node at all.
    let (ok, stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["node", "ls"]);
    assert!(ok, "{stderr}");
    assert!(
        !stdout.contains("acme"),
        "acme should be gone after seal: {stdout}"
    );

    let (ok, stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["node", "restore", "acme"],
        Some(&admin_token),
    );
    assert!(ok, "restore failed: {stderr}");
    assert!(stdout.contains("acme"), "{stdout}");

    let (ok, stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["node", "ls"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("acme"),
        "acme should be back after restore: {stdout}"
    );
}

#[test]
fn rotate_replaces_the_value_and_keeps_the_name_reachable() {
    let fixture = start_fixture_broker();

    let rotated = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(["rotate", "DEPLOY_TOKEN", "--node", "acme"])
        .current_dir(&fixture.acme_workdir)
        .env("CREDMGR_VAULT_DIR", &fixture.vault_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    write_stdin_and_wait(rotated, "rotated-deploy-token");

    let (ok, stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["get", "DEPLOY_TOKEN"]);
    assert!(ok, "get after rotate failed: {stderr}");
    assert_eq!(stdout.trim(), "rotated-deploy-token");
}

#[test]
fn rm_soft_deletes_so_a_later_get_is_not_found() {
    let fixture = start_fixture_broker();

    let (ok, stdout, stderr) = credmgr(
        &fixture,
        &fixture.acme_workdir,
        &["rm", "DEPLOY_TOKEN", "--node", "acme"],
    );
    assert!(ok, "rm failed: {stderr}");
    assert!(stdout.contains("DEPLOY_TOKEN"), "{stdout}");

    let (ok, _stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["get", "DEPLOY_TOKEN"]);
    assert!(!ok, "removed entry should no longer be gettable");
    assert!(
        stderr.contains("no entry named"),
        "expected a not-found style error, got: {stderr}"
    );

    let (ok, stdout, stderr) =
        credmgr(&fixture, &fixture.acme_workdir, &["list", "--node", "acme"]);
    assert!(ok, "{stderr}");
    assert!(
        !stdout.contains("DEPLOY_TOKEN"),
        "removed entry must not still be listed: {stdout}"
    );
}

#[test]
fn audit_shows_a_just_made_change_and_json_mode_round_trips() {
    let fixture = start_fixture_broker();

    let (ok, _stdout, stderr) = credmgr(&fixture, &fixture.acme_workdir, &["get", "DEPLOY_TOKEN"]);
    assert!(ok, "get failed: {stderr}");

    let (ok, stdout, stderr) = credmgr(
        &fixture,
        &fixture.acme_workdir,
        &["audit", "--limit", "5", "--json"],
    );
    assert!(ok, "audit failed: {stderr}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let records = value["records"].as_array().expect("records array");
    assert!(
        !records.is_empty(),
        "the get call just above must itself be in the log: {stdout}"
    );
    // A real CLI invocation resolves via cwd (`06 §4` case 2) to
    // `Origin::Agent`, same as the MCP surface — redacted by construction.
    assert!(
        records[0].get("node").is_none(),
        "a CLI call with no token is Origin::Agent — redacted, got {:?}",
        records[0]
    );
}

#[test]
fn grant_ls_and_revoke_round_trip_a_real_grant() {
    let fixture = start_fixture_broker();
    // Same reasoning as `node_seal_then_restore_round_trips`: a cwd-resolved
    // agent scope never carries `Admin`, so a real token is required.
    let admin_token = fixture.issue_token("acme", vec![Capability::Admin], Origin::HumanUi);

    // `grant.create`'s own positive path is presence-gated and cannot
    // complete on this build (proven separately below) — seeding the grant
    // directly into the running broker's registry is the only way to get a
    // real one in front of `grant.list`/`grant.revoke`.
    fixture
        .state
        .registry
        .write()
        .expect("registry poisoned")
        .grants
        .push(credmgr_core::registry::Grant {
            id: "g_test_cli".to_string(),
            from: "elsewhere".to_string(),
            to: credmgr_core::registry::GrantTarget::Node {
                node_id: "acme".to_string(),
            },
            direction: credmgr_core::registry::Direction::OneWay,
            scope: vec![Capability::Read],
            expires_at: None,
            reason: "cli integration test fixture grant".to_string(),
        });

    let (ok, stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["grant", "ls", "--json"],
        Some(&admin_token),
    );
    assert!(ok, "grant ls failed: {stderr}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let grants = value["grants"].as_array().expect("grants array");
    assert!(
        grants.iter().any(|g| g["id"] == "g_test_cli"),
        "seeded grant must be listed: {stdout}"
    );

    let (ok, stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["grant", "revoke", "g_test_cli"],
        Some(&admin_token),
    );
    assert!(ok, "grant revoke failed: {stderr}");
    assert!(stdout.contains("g_test_cli"), "{stdout}");

    let (ok, stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["grant", "ls", "--json"],
        Some(&admin_token),
    );
    assert!(ok, "{stderr}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        value["grants"].as_array().unwrap().is_empty(),
        "the revoked grant must actually be gone, not merely reported as revoked: {stdout}"
    );
}

#[test]
fn grant_create_is_presence_required_end_to_end() {
    let fixture = start_fixture_broker();
    let admin_token = fixture.issue_token("acme", vec![Capability::Admin], Origin::HumanUi);

    let (ok, _stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &[
            "grant",
            "elsewhere",
            "--to",
            "acme",
            "--scope",
            "read",
            "--reason",
            "cli integration test reason",
        ],
        Some(&admin_token),
    );
    assert!(
        !ok,
        "grant create must fail today — no native presence attestation exists until Phase 5"
    );
    assert!(
        stderr.contains("presence_required"),
        "must fail specifically on presence, not on some other validation error: {stderr}"
    );
}

/// ADR-056: `credmgr unlock`, through the real compiled binary against a
/// real broker, is the "real, non-fixture client" the mechanism's own exit
/// criteria name — proving the whole chain end to end: passphrase in over
/// stdin, `export CREDMGR_TOKEN=` out over stdout, that same token back in
/// via the env var on a second, independent invocation, unredacted audit out.
#[test]
fn unlock_through_the_real_binary_prints_a_token_that_reads_unredacted_audit() {
    let fixture = start_fixture_broker();
    // `start_fixture_broker` pre-unlocks for every *other* test's
    // convenience — re-lock so this test starts genuinely locked, exactly
    // what a freshly-started `credmgrd` would be.
    fixture.state.lock();

    // Unlocked from an *unregistered* directory, deliberately — not
    // `acme_workdir`. `vault.unlock`'s own audit record is stamped with the
    // *caller's pre-unlock* scope's node (no `params.node` of its own), and
    // a cwd match would stamp it against "acme", not "global" — invisible
    // to the very session token this unlock is about to mint (the named
    // limitation ADR-056 documents: a `global`-scoped token cannot read
    // "acme"'s audit trail). An unregistered cwd resolves to `global`
    // (`06 §4` case 3), so the unlock's own record lands where this test's
    // token can actually see it.
    let unlock = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(["unlock"])
        .current_dir(fixture._tmp.path())
        .env("CREDMGR_VAULT_DIR", &fixture.vault_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to launch the credmgr binary");
    let stdout = write_stdin_and_capture_stdout(unlock, PASSPHRASE);

    assert!(stdout.contains("locked: false"), "{stdout}");
    let token = stdout
        .lines()
        .find_map(|l| l.strip_prefix("export CREDMGR_TOKEN="))
        .unwrap_or_else(|| panic!("expected an `export CREDMGR_TOKEN=` line in: {stdout}"))
        .to_string();
    assert!(
        token.starts_with("cmt_"),
        "expected a real token id, got: {token}"
    );

    let (ok, stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["audit", "--json"],
        Some(&token),
    );
    assert!(ok, "audit failed: {stderr}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let records = value["records"].as_array().cloned().unwrap_or_default();
    assert!(
        !records.is_empty(),
        "the unlock that minted this very token must itself be audited: {stdout}"
    );
    assert!(
        records.iter().any(|r| r.get("decision").is_some()),
        "a real login token is Origin::HumanUi — unredacted, got: {stdout}"
    );
}

fn write_stdin_and_capture_stdout(mut child: std::process::Child, value: &str) -> String {
    use std::io::{Read, Write};
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "credmgr unlock exited non-zero; stdout so far: {stdout}"
    );
    stdout
}

/// ADR-069: `credmgr set` against a locked vault says the write is waiting in
/// the review tray, and `credmgr pending` is where a human reviews it — list,
/// then accept. Until 2026-09-24 the CLI printed "pending review at next
/// unlock" and had no command that could perform that review.
#[test]
fn a_locked_write_is_reviewed_and_accepted_through_credmgr_pending() {
    let fixture = start_fixture_broker();
    fixture.state.lock();

    let deposited = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(["set", "LOCKED_WRITE", "--node", "acme"])
        .current_dir(&fixture.acme_workdir)
        .env("CREDMGR_VAULT_DIR", &fixture.vault_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = write_stdin_and_capture_stdout(deposited, "tray-value");
    assert!(
        stdout.contains("credmgr pending"),
        "the CLI points at the review command: {stdout}"
    );

    fixture.state.unlock(0).expect("fixture re-unlock");
    let owner = fixture.issue_token(
        "acme",
        vec![
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Create,
        ],
        Origin::HumanUi,
    );

    let (ok, stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["pending", "--node", "acme", "--json"],
        Some(&owner),
    );
    assert!(ok, "{stderr}");
    let listed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let items = listed["pending"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{stdout}");
    assert_eq!(items[0]["name"], "LOCKED_WRITE");
    let entry = items[0]["entry"].as_str().unwrap().to_string();

    let (ok, _, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["pending", "accept", &entry, "--node", "acme"],
        Some(&owner),
    );
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["get", "LOCKED_WRITE", "--node", "acme"],
        Some(&owner),
    );
    assert!(ok, "{stderr}");
    assert_eq!(stdout.trim(), "tray-value");

    let (ok, stdout, _) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["pending", "--node", "acme"],
        Some(&owner),
    );
    assert!(ok);
    assert!(stdout.contains("nothing pending"), "{stdout}");
}
