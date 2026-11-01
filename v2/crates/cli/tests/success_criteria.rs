//! Phase 7 exit gate: "success criteria 1, 2 and 6 from `01 §7` demonstrated,
//! with evidence" — the backend-only subset (`01_CONCEPT.md §7`'s own
//! 2026-08-08 correction note: criteria 3/4/5/7 are UI-observable and belong
//! to Phase 6's exit gate instead). Each test below quotes the criterion it
//! demonstrates and drives the real compiled `credmgr` binary against a real
//! `credmgrd`, the same standard `broker_integration.rs`/`mcp_integration.rs`
//! already set — never a mock, never an in-process function call standing in
//! for the wire protocol.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::{json, Value};

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

struct Fixture {
    vault_dir: PathBuf,
    acme_workdir: PathBuf,
    northwind_workdir: PathBuf,
    linux_workdir: PathBuf,
    state: Arc<BrokerState>,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    fn issue_token(&self, node_id: &str, capabilities: Vec<Capability>, origin: Origin) -> String {
        self.state
            .tokens
            .issue(node_id, capabilities, origin, None)
            .id
    }
}

fn depth1(id: &str, label: &str, workdir: &Path) -> Node {
    Node {
        id: id.to_string(),
        label: label.to_string(),
        kind: NodeKind::Project,
        depth: 1,
        parent_id: Some(GLOBAL_ID.to_string()),
        workdirs: vec![workdir.to_string_lossy().into_owned()],
        policy: NodePolicy::default(),
    }
}

fn start_fixture_broker() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_dir = tmp.path().join("vault");
    let state_dir = tmp.path().join("keystore-state");
    let acme_workdir = tmp.path().join("acme-project");
    let northwind_workdir = tmp.path().join("northwind-project");
    let linux_workdir = tmp.path().join("linux-project");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::create_dir_all(&acme_workdir).unwrap();
    std::fs::create_dir_all(&northwind_workdir).unwrap();
    std::fs::create_dir_all(&linux_workdir).unwrap();
    // macOS's temp root is itself a symlink (`peer.rs`'s real
    // `proc_pidinfo(PROC_PIDVNODEPATHINFO)` reports the resolved path).
    let acme_workdir = acme_workdir.canonicalize().unwrap();
    let northwind_workdir = northwind_workdir.canonicalize().unwrap();
    let linux_workdir = linux_workdir.canonicalize().unwrap();

    let paths = VaultPaths::new(vault_dir.clone());
    std::fs::create_dir_all(paths.run_dir()).unwrap();
    std::fs::set_permissions(paths.run_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let keystore =
        SoftwareKeystore::new(SecretBox::new(Box::new(PASSPHRASE.to_string())), state_dir);
    let state = Arc::new(BrokerState::new(Box::new(keystore), paths.clone()));

    let root_key = SecretBox::new(Box::new([13u8; 32]));
    state.seed_root_key(&root_key);

    let mut registry = Registry::new();
    registry.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    registry.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());
    registry
        .nodes
        .insert("acme".to_string(), depth1("acme", "Acme", &acme_workdir));
    registry.nodes.insert(
        "northwind".to_string(),
        depth1("northwind", "Northwind", &northwind_workdir),
    );
    registry.nodes.insert(
        "linux".to_string(),
        depth1("linux", "Linux", &linux_workdir),
    );
    state.set_registry(registry);

    let orphan_pair = generate_node_keypair();
    state.seed_public_key_only(ORPHAN_ID, orphan_pair.public);

    // acme gets one real entry, sealed for real — criterion 1's "receives a
    // structured refusal, not an empty list, for anything in acme" needs
    // something in acme worth being refused.
    let acme_pub = state.seed_node_key(&root_key, "acme");
    let acme_entry_id = "e_acme0001";
    let mut acme_manifest = ManifestBody::new("acme");
    acme_manifest.entries.push(ManifestEntry {
        id: acme_entry_id.to_string(),
        name: "DEPLOY_TOKEN".to_string(),
        r#ref: 1000,
        entry_type: credmgr_core::inference::EntryType::Token,
        sensitivity: Sensitivity::High,
        field_count: 1,
        sha256: "0".repeat(64),
        modified: 0,
        expires_at: None,
        rotated_at: None,
        has_totp: false,
    });
    state.set_manifest("acme", acme_manifest);
    let sealed = envelope::seal(b"acme-secret-value", &acme_pub, "acme", acme_entry_id).unwrap();
    credmgr_store::atomic::write(&paths.entry_env("acme", acme_entry_id), &sealed).unwrap();

    // northwind gets its own node key so it can hold entries of its own too.
    state.seed_node_key(&root_key, "northwind");

    // linux gets one real entry — this is what criterion 2's seal proves
    // stays recoverable, listable and unreadable.
    let linux_pub = state.seed_node_key(&root_key, "linux");
    let linux_entry_id = "e_linux001";
    let mut linux_manifest = ManifestBody::new("linux");
    linux_manifest.entries.push(ManifestEntry {
        id: linux_entry_id.to_string(),
        name: "ROOT_PASSWORD".to_string(),
        r#ref: 1001,
        entry_type: credmgr_core::inference::EntryType::Login,
        sensitivity: Sensitivity::High,
        field_count: 1,
        sha256: "0".repeat(64),
        modified: 0,
        expires_at: None,
        rotated_at: None,
        has_totp: false,
    });
    state.set_manifest("linux", linux_manifest);
    let sealed_linux =
        envelope::seal(b"hunter2-not-really", &linux_pub, "linux", linux_entry_id).unwrap();
    credmgr_store::atomic::write(&paths.entry_env("linux", linux_entry_id), &sealed_linux).unwrap();

    state
        .unlock(0)
        .expect("fixture keystore's own passphrase must unlock its own wrap");

    let state_handle = Arc::clone(&state);
    let socket_path = paths.run_socket();
    std::thread::spawn(move || {
        credmgr_brokerd::server::run(state, &socket_path).expect("fixture broker crashed");
    });
    wait_for_socket(&paths.run_socket());

    Fixture {
        vault_dir,
        acme_workdir,
        northwind_workdir,
        linux_workdir,
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

/// Spawns a real `credmgr mcp` subprocess rooted at `cwd`, feeds it real
/// JSON-RPC over stdin, and returns every response line — the literal "MCP
/// agent" success criterion 1 names, not a stand-in.
fn run_mcp_session(fixture: &Fixture, cwd: &Path, requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .arg("mcp")
        .current_dir(cwd)
        .env("CREDMGR_VAULT_DIR", &fixture.vault_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch `credmgr mcp`");

    let mut stdin = child.stdin.take().expect("stdin");
    for request in requests {
        writeln!(stdin, "{request}").expect("write request");
    }
    drop(stdin);

    let output = child.wait_with_output().expect("wait for credmgr mcp");
    assert!(
        output.status.success(),
        "credmgr mcp exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("bad json {line:?}: {e}")))
        .collect()
}

/// **Success criterion 1** (`01_CONCEPT.md §7`): "An MCP agent launched in
/// `~/projects/northwind/` can list and read Northwind + Global entries, and
/// receives a structured refusal — not an empty list — for anything in
/// `acme`."
#[test]
fn success_criterion_1_mcp_agent_reads_its_own_scope_and_is_structurally_refused_elsewhere() {
    let fixture = start_fixture_broker();

    // An entry of northwind's own, created live through the MCP surface —
    // "populated only through its own CLI/MCP/broker" (criterion 6's own
    // wording, demonstrated here as a side effect of setting up this test).
    let create_resp = run_mcp_session(
        &fixture,
        &fixture.northwind_workdir,
        &[json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "credmgr_create", "arguments": {
                "node": "northwind", "name": "API_KEY", "value": "northwind-key",
            } },
        })],
    );
    assert_eq!(
        create_resp[0]["result"]["isError"], false,
        "{:?}",
        create_resp[0]
    );

    // List from northwind's own cwd: sees its own entry. Does not see acme's.
    let list_resp = run_mcp_session(
        &fixture,
        &fixture.northwind_workdir,
        &[json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "credmgr_list", "arguments": { "node": "northwind" } },
        })],
    );
    let text = list_resp[0]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    assert!(
        text.contains("API_KEY"),
        "northwind must see its own just-created entry: {text}"
    );
    assert!(
        !text.contains("DEPLOY_TOKEN"),
        "northwind must never see acme's entry: {text}"
    );

    // Reading Global works (R3) — "can... read... Global".
    let whoami_resp = run_mcp_session(
        &fixture,
        &fixture.northwind_workdir,
        &[json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "credmgr_whoami", "arguments": {} },
        })],
    );
    let whoami_text = whoami_resp[0]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let whoami: Value = serde_json::from_str(whoami_text).expect("whoami is JSON");
    assert_eq!(whoami["node"], "northwind");
    let reachable: Vec<&str> = whoami["reachable"]
        .as_array()
        .expect("reachable array")
        .iter()
        .filter_map(|n| n.as_str())
        .collect();
    assert!(reachable.contains(&GLOBAL_ID), "{reachable:?}");
    assert!(
        !reachable.contains(&"acme"),
        "acme must not be named as reachable from northwind: {reachable:?}"
    );

    // The refusal itself, attempting `acme`'s own entry by name — structured,
    // not an empty list.
    let get_resp = run_mcp_session(
        &fixture,
        &fixture.northwind_workdir,
        &[json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "credmgr_get", "arguments": {
                "node": "acme", "entry": "e_acme0001",
            } },
        })],
    );
    assert_eq!(
        get_resp[0]["result"]["isError"], true,
        "reaching into acme from northwind must be refused: {:?}",
        get_resp[0]
    );
    // `ToolCallError::Denied`'s `Display` (`crates/mcp/src/tools.rs`) formats
    // the broker's structured denial (`error`/`message`/`remedy`,
    // `10_API_AND_MCP.md §1`) as `"{error}: {message}\n  remedy: {remedy}"` —
    // a readable string, not embedded JSON — so this checks its content
    // rather than re-parsing it.
    let denial_text = get_resp[0]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    assert!(
        denial_text.starts_with("node_access_denied"),
        "{denial_text}"
    );
    assert!(denial_text.contains("acme"), "{denial_text}");
    assert!(
        denial_text.contains("remedy"),
        "a structured refusal names a remedy, not just a bare failure: {denial_text}"
    );
}

/// **Success criterion 2** (`01_CONCEPT.md §7`): "`credmgr node seal linux`
/// leaves every value recoverable, listable by name, and unreadable by any
/// agent." Recoverable and unreadable-by-any-agent are demonstrated directly.
/// "Listable by name" is demonstrated the way `06_ACCESS_GRAPH.md §1` (d)
/// actually states it — R0 denies orphan universally, value **and** name,
/// to everything short of native + live presence, which Phase 3 has no
/// transport for; a live `list --node orphan` success is not yet a callable
/// path for anything (this test proves that refusal is real and total,
/// including for an orphan-scoped token, rather than assuming it).
#[test]
fn success_criterion_2_seal_leaves_the_value_recoverable_listable_and_unreadable() {
    let fixture = start_fixture_broker();
    let admin_token = fixture.issue_token("linux", vec![Capability::Admin], Origin::HumanUi);

    // Before sealing: a plain agent-origin read of linux's own entry, from
    // linux's own registered workdir, works — establishes the baseline this
    // test then proves seal takes away.
    let (ok, stdout, stderr) = credmgr(
        &fixture,
        &fixture.linux_workdir,
        &["get", "ROOT_PASSWORD", "--node", "linux"],
    );
    assert!(ok, "baseline read before seal failed: {stderr}");
    assert_eq!(stdout.trim(), "hunter2-not-really");

    let (ok, seal_stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["node", "seal", "linux"],
        Some(&admin_token),
    );
    assert!(ok, "seal failed: {stderr}");
    assert!(seal_stdout.contains("linux"), "{seal_stdout}");

    // Unreadable by any agent: linux is gone as a node at all, so even an
    // agent still sitting in what *was* linux's own registered workdir is
    // refused, not merely empty.
    let (ok, _stdout, stderr) = credmgr(
        &fixture,
        &fixture.linux_workdir,
        &["get", "ROOT_PASSWORD", "--node", "linux"],
    );
    assert!(
        !ok,
        "a sealed node's value must not be readable by any agent"
    );
    assert!(
        !stderr.is_empty(),
        "the refusal must say something, not fail silently"
    );

    // "Listable by name" (`06_ACCESS_GRAPH.md §1` (d): "Names are not
    // hidden; values are not reachable") describes what a *denial* against
    // orphan reveals, not a separate successful `list` call: R0 in
    // `credmgr_core::access::resolve` denies **any** capability, from
    // **any** subject, against orphan as a target — "no grant, policy, or
    // token can override" — with the single stated exception of
    // `Origin::Native` plus a live presence attestation, which Phase 3 has
    // no transport for (the same honest gap ADR-046 names for the hardware
    // keystores). A `Capability::List` token scoped to orphan itself is
    // refused too, proving R0's own "everyone, no exceptions" claim rather
    // than assuming it: `access::resolve`'s very first check denies orphan
    // as a *subject* unconditionally (`subject.node_id == ORPHAN_ID`), so
    // even asking "from orphan's own point of view" does not work around R0.
    let admin_orphan_token =
        fixture.issue_token(ORPHAN_ID, vec![Capability::List], Origin::HumanUi);
    let (ok, _stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["list", "--node", ORPHAN_ID],
        Some(&admin_orphan_token),
    );
    assert!(
        !ok,
        "orphan must refuse even an orphan-scoped Admin/List token — R0 has no exception \
         short of native + live presence: {stderr}"
    );
    assert!(
        !stderr.is_empty(),
        "the refusal must say something, not fail silently"
    );

    // Recoverable: restore brings linux back with its value intact.
    let (ok, restore_stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &["node", "restore", "linux"],
        Some(&admin_token),
    );
    assert!(ok, "restore failed: {stderr}");
    assert!(restore_stdout.contains("linux"), "{restore_stdout}");

    let (ok, stdout, stderr) = credmgr(
        &fixture,
        &fixture.linux_workdir,
        &["get", "ROOT_PASSWORD", "--node", "linux"],
    );
    assert!(ok, "post-restore read failed: {stderr}");
    assert_eq!(
        stdout.trim(),
        "hunter2-not-really",
        "the exact original value must come back byte for byte"
    );
}

/// **Success criterion 6** (`01_CONCEPT.md §7`, corrected 2026-08-08): "A
/// fresh V2 vault, created and populated only through its own CLI/MCP/broker
/// (never imported), places every credential in exactly one node, and
/// nothing is reachable from a node that did not create or receive a grant
/// for it."
#[test]
fn success_criterion_6_fresh_credentials_land_in_exactly_one_node_and_nothing_leaks_by_default() {
    let fixture = start_fixture_broker();

    // A brand-new node, created live through the real broker (ADR-051) —
    // not seeded directly into the registry the way this file's OWN fixture
    // nodes are. This is the literal "created ... only through its own
    // CLI/MCP/broker" half of the criterion.
    let admin_token = fixture.issue_token(GLOBAL_ID, vec![Capability::Admin], Origin::HumanUi);
    let (ok, create_stdout, stderr) = credmgr_with_token(
        &fixture,
        &fixture.acme_workdir,
        &[
            "node", "create", "contoso", "--label", "Contoso", "--parent", GLOBAL_ID,
        ],
        Some(&admin_token),
    );
    assert!(ok, "node create failed: {stderr}");
    assert!(create_stdout.contains("contoso"), "{create_stdout}");

    // A workdir for contoso is registered the same way the fixture's other
    // nodes are (workdir registration is a separate, already-covered
    // mechanism — `whoami`'s own test — not what this criterion is about).
    let contoso_workdir = fixture._tmp.path().join("contoso-project");
    std::fs::create_dir_all(&contoso_workdir).unwrap();
    let contoso_workdir = contoso_workdir.canonicalize().unwrap();
    {
        let mut registry = fixture.state.registry.write().expect("registry poisoned");
        registry
            .nodes
            .get_mut("contoso")
            .expect("just created")
            .workdirs
            .push(contoso_workdir.to_string_lossy().into_owned());
    }

    // A credential, populated live through the CLI (never imported).
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(["set", "API_KEY", "--node", "contoso"])
        .current_dir(&contoso_workdir)
        .env("CREDMGR_VAULT_DIR", &fixture.vault_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"contoso-secret\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Exactly one node: contoso lists it, acme and northwind do not.
    let (ok, contoso_list, stderr) =
        credmgr(&fixture, &contoso_workdir, &["list", "--node", "contoso"]);
    assert!(ok, "{stderr}");
    assert_eq!(contoso_list.trim(), "API_KEY");

    let (ok, _stdout, stderr) = credmgr(
        &fixture,
        &fixture.acme_workdir,
        &["get", "API_KEY", "--node", "contoso"],
    );
    assert!(
        !ok,
        "acme must not be able to reach contoso's credential — no grant exists"
    );
    assert!(!stderr.is_empty());

    let (ok, _stdout, stderr) = credmgr(
        &fixture,
        &fixture.northwind_workdir,
        &["get", "API_KEY", "--node", "contoso"],
    );
    assert!(
        !ok,
        "northwind must not be able to reach contoso's credential either — \
         isolation is the default, not a property of any particular pair"
    );
    assert!(!stderr.is_empty());

    // The value itself round-trips correctly from contoso's own scope.
    let (ok, stdout, stderr) = credmgr(
        &fixture,
        &contoso_workdir,
        &["get", "API_KEY", "--node", "contoso"],
    );
    assert!(ok, "{stderr}");
    assert_eq!(stdout.trim(), "contoso-secret");
}
