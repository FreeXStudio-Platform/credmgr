//! ADR-130…134 on the command line: `search --deep`, `export --age`, `orphan destroy`,
//! `audit report`, `node rekey` — the REAL compiled `credmgr` binary against a REAL broker served on a
//! temporary socket, the way `cli_parity.rs` does it.
//!
//! What it pins: `search --deep` prints node and name and never a value; every refusal that the
//! command line can make on its own (no `--age`, stdout, an existing file, two different passphrases, a
//! missing `--count` or confirmation word, a bad date) happens **before** the broker is asked and writes
//! nothing. The ops that need the owner's finger, a fresh code and a Secure Enclave are proved in
//! `crates/brokerd/tests/{rekey,f1_ops}.rs`; here the fixture token is deliberately not a login session.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
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
const ENTRY_ID: &str = "e_content01";
const ENTRY_VALUE: &str = "db password zebra-plum-7731 for the svc user";

struct Fixture {
    vault_dir: PathBuf,
    workdir: PathBuf,
    state: Arc<BrokerState>,
    _tmp: tempfile::TempDir,
}

fn start() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_dir = tmp.path().join("vault");
    let state_dir = tmp.path().join("keystore-state");
    let workdir = tmp.path().join("acme-project");
    for d in [&vault_dir, &state_dir, &workdir] {
        std::fs::create_dir_all(d).unwrap();
    }
    let workdir = workdir.canonicalize().unwrap();
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
            workdirs: vec![workdir.to_string_lossy().into_owned()],
            policy: NodePolicy::default(),
        },
    );
    state.set_registry(registry);
    state.seed_public_key_only(ORPHAN_ID, generate_node_keypair().public);
    let acme_pub = state.seed_node_key(&root_key, "acme");
    let sealed = envelope::seal(ENTRY_VALUE.as_bytes(), &acme_pub, "acme", ENTRY_ID).unwrap();
    credmgr_store::atomic::write(&paths.entry_env("acme", ENTRY_ID), &sealed).unwrap();
    let mut manifest = ManifestBody::new("acme");
    manifest.entries.push(ManifestEntry {
        id: ENTRY_ID.to_string(),
        name: "DATABASE_URL".to_string(),
        r#ref: 1000,
        entry_type: credmgr_core::inference::EntryType::Token,
        sensitivity: Sensitivity::High,
        field_count: 1,
        sha256: "0".repeat(64),
        modified: 0,
        expires_at: None,
        rotated_at: None,
        has_totp: false,
        aliases: Vec::new(),
        tags: Vec::new(),
    });
    state.set_manifest("acme", manifest);
    state.unlock(0).expect("fixture keystore unlocks itself");

    let handle = Arc::clone(&state);
    let socket = paths.run_socket();
    std::thread::spawn(move || {
        credmgr_brokerd::server::run(state, &socket).expect("fixture broker crashed");
    });
    for _ in 0..200 {
        if std::os::unix::net::UnixStream::connect(paths.run_socket()).is_ok() {
            return Fixture {
                vault_dir,
                workdir,
                state: handle,
                _tmp: tmp,
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("credmgrd fixture never opened its socket");
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Out {
    fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

fn token(fx: &Fixture) -> String {
    fx.state
        .tokens
        .issue(
            "acme",
            vec![Capability::List, Capability::Read, Capability::Reveal],
            Origin::HumanUi,
            None,
        )
        .id
}

fn run(fx: &Fixture, args: &[&str], stdin: Option<&str>) -> Out {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(args)
        .current_dir(&fx.workdir)
        .env("CREDMGR_VAULT_DIR", &fx.vault_dir)
        .env("CREDMGR_TOKEN", token(fx))
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch credmgr");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        let _ = pipe.write_all(text.as_bytes());
    }
    let o = child.wait_with_output().unwrap();
    Out {
        ok: o.status.success(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

#[test]
fn search_content_prints_node_and_name_and_never_a_value() {
    let fx = start();
    let out = run(&fx, &["search", "ZEBRA-plum", "--deep"], None);
    assert!(out.ok, "{}", out.stderr);
    assert_eq!(out.stdout.trim(), "acme\tDATABASE_URL");
    assert!(!out.all().contains("zebra-plum-7731") && !out.all().contains("db password"));

    let json = run(
        &fx,
        &["search", "zebra", "--deep", "--node", "acme", "--json"],
        None,
    );
    assert!(json.ok, "{}", json.stderr);
    let v: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(v["results"][0]["id"], ENTRY_ID);
    assert!(!json.all().contains("7731"));

    let none = run(&fx, &["search", "nothing-like-it", "--deep"], None);
    assert!(none.ok && none.stdout.trim().is_empty());
    // Too short a term is the broker's refusal, shown as is.
    let short = run(&fx, &["search", "zz", "--deep"], None);
    assert!(
        !short.ok && short.stderr.contains("3 to 200"),
        "{}",
        short.stderr
    );
    // ADR-156: `--node` on a name search asks that one node (`entry.search`): names only, never a value, so a term
    // that is only in a value finds nothing there and a term in a name finds it.
    let by_name = run(&fx, &["search", "zebra", "--node", "acme"], None);
    assert!(by_name.ok, "{}", by_name.stderr);
    assert!(by_name.stdout.trim().is_empty() && !by_name.all().contains("7731"));
    let named = run(&fx, &["search", "database", "--node", "acme"], None);
    assert!(named.ok, "{}", named.stderr);
    assert!(named.stdout.contains("DATABASE_URL") && !named.all().contains("7731"));
}

#[test]
fn export_refuses_what_the_command_line_can_refuse_before_it_asks_the_broker() {
    let fx = start();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("out.age");
    let file_s = file.to_str().unwrap();

    let no_age = run(&fx, &["export", "--node", "acme", "--out", file_s], None);
    assert!(
        !no_age.ok && no_age.stderr.contains("--age"),
        "{}",
        no_age.stderr
    );
    for bad in ["-", "/dev/stdout"] {
        let r = run(
            &fx,
            &["export", "--node", "acme", "--out", bad, "--age"],
            Some("x\nx\n"),
        );
        assert!(
            !r.ok && r.stderr.contains("never written to stdout"),
            "{bad}: {}",
            r.stderr
        );
    }
    std::fs::write(&file, b"keep me").unwrap();
    let exists = run(
        &fx,
        &["export", "--node", "acme", "--out", file_s, "--age"],
        Some("a\na\n"),
    );
    assert!(!exists.ok && exists.stderr.contains("already exists"));
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"keep me",
        "an existing file is not touched"
    );
    std::fs::remove_file(&file).unwrap();

    let differ = run(
        &fx,
        &["export", "--node", "acme", "--out", file_s, "--age"],
        Some("one long passphrase here\nanother one entirely\n"),
    );
    assert!(
        !differ.ok && differ.stderr.contains("differ"),
        "{}",
        differ.stderr
    );
    assert!(!file.exists(), "nothing was written");

    // The broker's own refusal (the fixture token is not the owner's login) leaves no file either, and
    // the passphrase never appears in anything printed.
    let denied = run(
        &fx,
        &["export", "--node", "acme", "--out", file_s, "--age"],
        Some("a long export passphrase\na long export passphrase\n"),
    );
    assert!(!denied.ok);
    assert!(!file.exists() && !denied.all().contains("a long export passphrase"));
    // A passphrase is never an argv flag.
    let argv = run(
        &fx,
        &[
            "export",
            "--node",
            "acme",
            "--out",
            file_s,
            "--age",
            "--passphrase",
            "x",
        ],
        None,
    );
    assert!(!argv.ok && !file.exists());
}

#[test]
fn orphan_destroy_wants_the_count_and_the_word_before_anything_is_sent() {
    let fx = start();
    let no_count = run(
        &fx,
        &[
            "orphan",
            "destroy",
            "--all",
            "--confirm",
            "destroy-sealed-entries",
        ],
        None,
    );
    assert!(
        !no_count.ok && no_count.stderr.contains("--count"),
        "{}",
        no_count.stderr
    );
    let no_word = run(&fx, &["orphan", "destroy", "--all", "--count", "2"], None);
    assert!(
        !no_word.ok && no_word.stderr.contains("--confirm"),
        "{}",
        no_word.stderr
    );
    let both = run(
        &fx,
        &[
            "orphan",
            "destroy",
            "--all",
            "e_aaaaaaaaaaaa",
            "--count",
            "1",
            "--confirm",
            "destroy-sealed-entries",
        ],
        None,
    );
    assert!(
        !both.ok && both.stderr.contains("not both"),
        "{}",
        both.stderr
    );
    let neither = run(
        &fx,
        &[
            "orphan",
            "destroy",
            "--count",
            "1",
            "--confirm",
            "destroy-sealed-entries",
        ],
        None,
    );
    assert!(
        !neither.ok && neither.stderr.contains("not neither"),
        "{}",
        neither.stderr
    );
    // Typed but wrong: the broker's refusal, nothing destroyed (there is nothing sealed to destroy here).
    let wrong = run(
        &fx,
        &[
            "orphan",
            "destroy",
            "--all",
            "--count",
            "0",
            "--confirm",
            "yes",
        ],
        None,
    );
    assert!(!wrong.ok, "{}", wrong.all());
}

#[test]
fn the_node_gate_commands_check_their_arguments_and_reach_the_broker() {
    let fx = start();
    for args in [
        vec!["gate", "verify", "--node", "acme"],
        vec!["gate", "verify", "1", "2", "--node", "acme"],
        vec!["gate", "verify", "000000", "--node", "acme"], // a bare code on argv is refused (ADR-113)
        vec!["gate", "enroll", "--node", "acme", "extra"],
        vec!["gate", "remove", "--node", "acme", "--bogus"],
        vec!["gate", "frobnicate", "--node", "acme"],
    ] {
        let r = run(&fx, &args, None);
        assert!(!r.ok, "{args:?} should be refused: {}", r.all());
    }
    // Well-formed: the broker answers (the fixture token is not the owner's login session).
    let r = run(&fx, &["gate", "verify", "--node", "acme"], Some("000000\n"));
    assert!(
        !r.ok && r.stderr.contains("capability_not_held"),
        "{}",
        r.stderr
    );
    let argv = run(
        &fx,
        &[
            "gate",
            "verify",
            "--node",
            "acme",
            "--code-on-argv",
            "000000",
        ],
        None,
    );
    assert!(
        !argv.ok && argv.stderr.contains("capability_not_held"),
        "{}",
        argv.stderr
    );
    // Without --node the vault's own `gate verify` is what runs - a different op, untouched.
    let vault = run(&fx, &["gate", "verify", "000000"], None);
    assert!(
        !vault.ok && !vault.stderr.contains("node.gate"),
        "{}",
        vault.stderr
    );
}

#[test]
fn audit_report_and_rekey_check_their_arguments() {
    let fx = start();
    for args in [
        vec!["audit", "report"],
        vec!["audit", "report", "--days", "0"],
        vec!["audit", "report", "--days", "400"],
        vec!["audit", "report", "--from", "2026-11-01"],
        vec![
            "audit",
            "report",
            "--from",
            "2026-13-01",
            "--to",
            "2026-12-01",
        ],
        vec![
            "audit",
            "report",
            "--days",
            "3",
            "--from",
            "2026-11-01",
            "--to",
            "2026-12-01",
        ],
    ] {
        let r = run(&fx, &args, None);
        assert!(!r.ok, "{args:?} should be refused: {}", r.all());
    }
    // A well-formed request reaches the broker, which refuses a caller that is not a login session.
    let denied = run(&fx, &["audit", "report", "--days", "7"], None);
    assert!(
        !denied.ok && denied.stderr.contains("capability_not_held"),
        "{}",
        denied.stderr
    );

    assert!(!run(&fx, &["node", "rekey"], None).ok);
    assert!(!run(&fx, &["node", "rekey", "a", "b"], None).ok);
    let denied = run(&fx, &["node", "rekey", "acme"], None);
    assert!(
        !denied.ok && denied.stderr.contains("capability_not_held"),
        "{}",
        denied.stderr
    );
}
