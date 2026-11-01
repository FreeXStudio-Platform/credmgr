//! End-to-end proof that `credmgr mcp` is real, not just a registry that
//! looks right in isolation: spawns the actual compiled `credmgr mcp`
//! subprocess, feeds it real JSON-RPC over stdin, and checks its stdout —
//! against a real, running `credmgrd` fixture, the same shape
//! `broker_integration.rs` already established for the human-facing
//! commands. `credmgr_mcp::tests::i13_tool_registry` covers the forbidden-
//! list guarantee in isolation; this file covers "the wiring actually
//! works" — a registry entry with no real transport behind it would pass
//! I-13 and fail here.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::state::BrokerState;
use credmgr_core::registry::{Node, NodeKind, NodePolicy, Registry, GLOBAL_ID, ORPHAN_ID};
use credmgr_core::totp::Totp;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{Counts, ManifestBody, ManifestEntry, Sensitivity};
use credmgr_store::paths::VaultPaths;

const PASSPHRASE: &str = "correct horse battery staple";

struct Fixture {
    vault_dir: PathBuf,
    acme_workdir: PathBuf,
    _state: Arc<BrokerState>,
    _tmp: tempfile::TempDir,
}

fn start_fixture_broker() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_dir = tmp.path().join("vault");
    let state_dir = tmp.path().join("keystore-state");
    let acme_workdir = tmp.path().join("acme-project");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::create_dir_all(&acme_workdir).unwrap();
    let acme_workdir = acme_workdir.canonicalize().unwrap();

    let paths = VaultPaths::new(vault_dir.clone());
    std::fs::create_dir_all(paths.run_dir()).unwrap();
    std::fs::set_permissions(
        paths.run_dir(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();

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

    let acme_pub = state.seed_node_key(&root_key, "acme");

    let sealed = credmgr_core::envelope::seal(b"s3cr3t-deploy-token", &acme_pub, "acme", "e1")
        .expect("seal");
    credmgr_store::atomic::write(&paths.entry_env("acme", "e1"), &sealed).unwrap();

    let totp = Totp::new_gate(vec![5u8; 20]);
    let seed_base32 = totp.secret_base32();
    let totp_sealed = credmgr_core::envelope::seal(seed_base32.as_bytes(), &acme_pub, "acme", "e2")
        .expect("seal");
    credmgr_store::atomic::write(&paths.entry_env("acme", "e2"), &totp_sealed).unwrap();

    let mut manifest = ManifestBody::new("acme");
    manifest.entries.push(ManifestEntry {
        id: "e1".to_string(),
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
    manifest.entries.push(ManifestEntry {
        id: "e2".to_string(),
        name: "DEPLOY_2FA".to_string(),
        r#ref: 1001,
        entry_type: credmgr_core::inference::EntryType::Totp,
        sensitivity: Sensitivity::High,
        field_count: 1,
        sha256: "0".repeat(64),
        modified: 0,
        expires_at: None,
        rotated_at: None,
        has_totp: false,
    });
    manifest.counts = Counts {
        entries: 2,
        totp: 1,
    };
    state.set_manifest("acme", manifest);

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
        _state: state_handle,
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

/// Spawns `credmgr mcp` for the fixture, sends every line in `requests`
/// (each pre-serialized), and returns every response line the process
/// wrote before it was told to stop (EOF on its stdin, via dropping the
/// child's stdin handle).
fn run_mcp_session(fixture: &Fixture, requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .arg("mcp")
        .current_dir(&fixture.acme_workdir)
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
    drop(stdin); // EOF — the server loop returns once it has answered everything above.

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

#[test]
fn initialize_then_tools_list_matches_the_real_registry() {
    let fixture = start_fixture_broker();
    let responses = run_mcp_session(
        &fixture,
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        ],
    );
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["result"]["protocolVersion"], "2024-11-05");

    let listed_names: Vec<String> = responses[1]["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    let registry_names: Vec<&str> = credmgr_mcp::tools::registry()
        .iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(
        listed_names, registry_names,
        "the live tools/list must match the compiled-in registry exactly"
    );
    assert!(listed_names.contains(&"credmgr_totp_code".to_string()));
    assert!(!listed_names.iter().any(|n| n.contains("seed")));
}

#[test]
fn tools_call_credmgr_get_round_trips_a_real_value_through_the_real_broker() {
    let fixture = start_fixture_broker();
    let responses = run_mcp_session(
        &fixture,
        &[json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "credmgr_get", "arguments": { "node": "acme", "entry": "e1" } },
        })],
    );
    assert_eq!(responses.len(), 1);
    let content_text = responses[0]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let inner: Value = serde_json::from_str(content_text).expect("tool result is itself JSON");
    assert_eq!(inner["value"], "s3cr3t-deploy-token");
    assert_eq!(responses[0]["result"]["isError"], false);
}

#[test]
fn tools_call_credmgr_totp_code_never_returns_the_raw_seed() {
    let fixture = start_fixture_broker();
    let responses = run_mcp_session(
        &fixture,
        &[json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "credmgr_totp_code", "arguments": { "node": "acme", "entry": "e2" } },
        })],
    );
    let content_text = responses[0]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let inner: Value = serde_json::from_str(content_text).expect("tool result is itself JSON");
    let code = inner["code"].as_str().expect("code field");
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert!(
        inner.get("seed").is_none() && inner.get("value").is_none(),
        "totp.code's response must carry only the code, never the seed: {inner}"
    );
}

#[test]
fn tools_call_credmgr_rotate_replaces_the_value_through_the_real_broker() {
    let fixture = start_fixture_broker();
    let responses = run_mcp_session(
        &fixture,
        &[
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "credmgr_rotate", "arguments": {
                    "node": "acme", "entry": "e1", "value": "rotated-deploy-token", "generation": 0,
                } },
            }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "credmgr_get", "arguments": { "node": "acme", "entry": "e1" } },
            }),
        ],
    );
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["result"]["isError"], false);

    let get_text = responses[1]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let inner: Value = serde_json::from_str(get_text).expect("tool result is itself JSON");
    assert_eq!(inner["value"], "rotated-deploy-token");
}

#[test]
fn tools_call_credmgr_remove_soft_deletes_through_the_real_broker() {
    let fixture = start_fixture_broker();
    let responses = run_mcp_session(
        &fixture,
        &[
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "credmgr_remove", "arguments": {
                    "node": "acme", "entry": "e1", "generation": 0,
                } },
            }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "credmgr_get", "arguments": { "node": "acme", "entry": "e1" } },
            }),
        ],
    );
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["result"]["isError"], false);
    // Removed — a later reveal of the same entry id must now be denied,
    // never silently serve the archived value.
    assert_eq!(
        responses[1]["result"]["isError"], true,
        "a removed entry must not still be revealable: {:?}",
        responses[1]
    );
}

#[test]
fn tools_call_credmgr_recent_changes_is_redacted_through_the_real_broker() {
    let fixture = start_fixture_broker();
    let responses = run_mcp_session(
        &fixture,
        &[
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "credmgr_list", "arguments": { "node": "acme" } },
            }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "credmgr_recent_changes", "arguments": { "limit": 5 } },
            }),
        ],
    );
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["result"]["isError"], false);
    assert_eq!(responses[1]["result"]["isError"], false);

    let text = responses[1]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let inner: Value = serde_json::from_str(text).expect("tool result is itself JSON");
    let records = inner["records"].as_array().expect("records array");
    assert!(
        !records.is_empty(),
        "the credmgr_list call just before this must itself be in the log: {inner:?}"
    );
    let keys: std::collections::BTreeSet<&str> = records[0]
        .as_object()
        .expect("record is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        ["id", "timestamp", "actor", "action"].into_iter().collect(),
        "a real MCP session resolves to Origin::Agent by construction (cwd-based, `06 §4` case \
         2) — redacted because the op itself is Origin-aware, not because this tool asked for \
         redaction: {:?}",
        records[0]
    );
}

#[test]
fn tools_call_a_cross_node_entry_is_denied_end_to_end() {
    let fixture = start_fixture_broker();
    let responses = run_mcp_session(
        &fixture,
        &[json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            // "acme"'s own MCP session (cwd-scoped) has no way to reach a
            // node id it invents — global is the only thing outside its own
            // scope it can read at all.
            "params": { "name": "credmgr_get", "arguments": { "node": "some-other-project", "entry": "e1" } },
        })],
    );
    assert_eq!(responses[0]["result"]["isError"], true);
}
