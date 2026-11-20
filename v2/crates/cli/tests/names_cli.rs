//! `credmgr alias`, `credmgr similar` and `credmgr import-env` (ADR-121, ADR-122).
//!
//! Same shape as `cli_parity.rs`: the REAL compiled `credmgr` binary as a subprocess against a
//! REAL `credmgrd` served on a temporary socket. Every secret-shaped value is a generated
//! placeholder, and every test also asserts that none of them was printed.

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
const V_ONE: &str = "val-one-zq-1111";
const V_TWO: &str = "val-two-zq-2222";
const V_DEPLOY: &str = "s3cr3t-deploy-token";

struct Fixture {
    vault_dir: PathBuf,
    acme_workdir: PathBuf,
    state: Arc<BrokerState>,
    tmp: tempfile::TempDir,
}

impl Fixture {
    fn owner(&self) -> String {
        self.state
            .tokens
            .issue(
                "acme",
                vec![
                    Capability::List,
                    Capability::Read,
                    Capability::Reveal,
                    Capability::Create,
                    Capability::Update,
                    Capability::Notes,
                    Capability::Admin,
                ],
                Origin::HumanUi,
                None,
            )
            .id
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.tmp.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
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
    state.seed_public_key_only(ORPHAN_ID, generate_node_keypair().public);
    let acme_pub = state.seed_node_key(&root_key, "acme");

    let entry_id = "e_test0001";
    let mut manifest = ManifestBody::new("acme");
    manifest.entries.push(ManifestEntry {
        id: entry_id.to_string(),
        name: "deploy-token".to_string(),
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
    let sealed = envelope::seal(V_DEPLOY.as_bytes(), &acme_pub, "acme", entry_id).unwrap();
    credmgr_store::atomic::write(&paths.entry_env("acme", entry_id), &sealed).unwrap();
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
                acme_workdir,
                state: handle,
                tmp,
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

fn run(fx: &Fixture, args: &[&str], token: Option<&str>, stdin: Option<&[u8]>) -> Out {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_credmgr"));
    cmd.args(args)
        .current_dir(&fx.acme_workdir)
        .env("CREDMGR_VAULT_DIR", &fx.vault_dir)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match token {
        Some(t) => cmd.env("CREDMGR_TOKEN", t),
        None => cmd.env_remove("CREDMGR_TOKEN"),
    };
    let mut child = cmd.spawn().expect("launch credmgr");
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        let _ = pipe.write_all(bytes);
    }
    let output = child.wait_with_output().unwrap();
    Out {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn names(fx: &Fixture, token: &str) -> Vec<String> {
    let out = run(fx, &["list", "--node", "acme"], Some(token), None);
    assert!(out.ok, "list failed: {}", out.stderr);
    out.stdout.lines().map(str::to_string).collect()
}

// ---- alias --------------------------------------------------------------

#[test]
fn an_alias_is_added_listed_used_to_get_the_entry_and_removed() {
    let fx = start_fixture_broker();
    let owner = fx.owner();

    let out = run(
        &fx,
        &["alias", "deploy-token", "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("has no aliases"), "{}", out.stdout);

    let out = run(
        &fx,
        &[
            "alias",
            "deploy-token",
            "--node",
            "acme",
            "--add",
            "ship-it",
            "--add",
            "Release Key",
        ],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stdout.contains("answers to: ship-it, Release Key"),
        "{}",
        out.stdout
    );

    let out = run(
        &fx,
        &["alias", "deploy-token", "--node", "acme"],
        Some(&owner),
        None,
    );
    assert_eq!(
        out.stdout.lines().collect::<Vec<_>>(),
        ["ship-it", "Release Key"]
    );

    // the alias finds the entry: by node, and without one
    for args in [
        vec!["get", "ship-it", "--node", "acme"],
        vec!["get", "Release Key"],
    ] {
        let out = run(&fx, &args, Some(&owner), None);
        assert!(out.ok, "{args:?}: {}", out.stderr);
        assert_eq!(out.stdout.trim_end(), V_DEPLOY, "{args:?}");
    }
    // `list` is still the names
    assert_eq!(names(&fx, &owner), ["deploy-token"]);

    let out = run(
        &fx,
        &[
            "alias",
            "ship-it",
            "--node",
            "acme",
            "--remove",
            "release key",
        ],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("answers to: ship-it"), "{}", out.stdout);
    assert!(!out.stdout.contains("Release Key"));

    let out = run(
        &fx,
        &[
            "alias",
            "deploy-token",
            "--node",
            "acme",
            "--remove",
            "never-was",
        ],
        Some(&owner),
        None,
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("has no alias"), "{}", out.stderr);

    let out = run(
        &fx,
        &[
            "alias",
            "deploy-token",
            "--node",
            "acme",
            "--clear",
            "--json",
        ],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(out.stdout.trim()).unwrap();
    assert_eq!(v["aliases"], serde_json::json!([]));
}

#[test]
fn an_alias_that_is_already_a_name_is_refused_and_one_that_resembles_a_name_is_said() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let file = fx.write("a.env", &format!("stripe-key={V_ONE}\n"));
    assert!(
        run(
            &fx,
            &["import-env", file.to_str().unwrap(), "--node", "acme"],
            Some(&owner),
            None
        )
        .ok
    );

    let out = run(
        &fx,
        &[
            "alias",
            "deploy-token",
            "--node",
            "acme",
            "--add",
            "STRIPE-KEY",
        ],
        Some(&owner),
        None,
    );
    assert!(!out.ok);
    assert!(
        out.stderr.to_lowercase().contains("exist"),
        "{}",
        out.stderr
    );

    let out = run(
        &fx,
        &[
            "alias",
            "deploy-token",
            "--node",
            "acme",
            "--add",
            "Stripe_Key",
        ],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stderr.contains("resembles: stripe-key"),
        "the near-duplicate is said on stderr: {}",
        out.stderr
    );
}

#[test]
fn changing_aliases_needs_a_login() {
    let fx = start_fixture_broker();
    let out = run(
        &fx,
        &[
            "alias",
            "deploy-token",
            "--node",
            "acme",
            "--add",
            "x-alias",
        ],
        None,
        None,
    );
    assert!(!out.ok, "{}", out.all());
}

// ---- similar ------------------------------------------------------------

#[test]
fn similar_lists_the_names_that_look_alike_and_writes_nothing() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let out = run(
        &fx,
        &["similar", "deploy_token", "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stdout
            .contains("resembles: deploy-token (same letters, other separators or case)"),
        "{}",
        out.stdout
    );
    let out = run(
        &fx,
        &["similar", "deploy-token", "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.stdout.contains("is already taken"), "{}", out.stdout);
    let out = run(
        &fx,
        &["similar", "wholly-different", "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.stdout.contains("no near-duplicate"), "{}", out.stdout);
    let out = run(&fx, &["similar", "x"], Some(&owner), None);
    assert!(!out.ok);
    assert_eq!(names(&fx, &owner), ["deploy-token"]);
}

// ---- import-env ---------------------------------------------------------

fn env_text() -> String {
    format!("TEST_ONE_TOKEN={V_ONE}\nTEST_TWO_TOKEN={V_TWO}\nEMPTY_ONE=\n")
}

#[test]
fn a_dry_run_names_every_pair_and_writes_nothing() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let file = fx.write(
        "a.env",
        &format!("{}deploy_token=zz-three-3333\n", env_text()),
    );
    let out = run(
        &fx,
        &[
            "import-env",
            file.to_str().unwrap(),
            "--node",
            "acme",
            "--dry-run",
        ],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stdout.contains("new       TEST_ONE_TOKEN"),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("new       deploy_token"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("empty     EMPTY_ONE"), "{}", out.stdout);
    assert!(out.stdout.contains("3 new"), "{}", out.stdout);
    assert!(
        out.all().contains("resembles: deploy-token"),
        "{}",
        out.all()
    );
    for v in [V_ONE, V_TWO, "zz-three-3333"] {
        assert!(!out.all().contains(v), "a value was printed: {}", out.all());
    }
    assert_eq!(names(&fx, &owner), ["deploy-token"]);
}

#[test]
fn a_clean_file_is_imported_and_a_conflict_writes_nothing_unless_told_to_skip() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let file = fx.write("a.env", &env_text());
    let out = run(
        &fx,
        &["import-env", file.to_str().unwrap(), "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stdout.contains("created  TEST_ONE_TOKEN"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("imported 2 of 2"), "{}", out.stdout);
    for v in [V_ONE, V_TWO] {
        assert!(!out.all().contains(v), "a value was printed: {}", out.all());
    }
    assert_eq!(
        names(&fx, &owner),
        ["deploy-token", "TEST_ONE_TOKEN", "TEST_TWO_TOKEN"]
    );
    let got = run(
        &fx,
        &["get", "TEST_TWO_TOKEN", "--node", "acme"],
        Some(&owner),
        None,
    );
    assert_eq!(got.stdout.trim_end(), V_TWO);

    // the same file again: every pair conflicts, so nothing is written and the names are listed
    let out = run(
        &fx,
        &["import-env", file.to_str().unwrap(), "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(!out.ok);
    assert!(
        out.stderr
            .contains("2 name(s) conflict, so nothing was written: TEST_ONE_TOKEN, TEST_TWO_TOKEN"),
        "{}",
        out.stderr
    );

    // one new pair beside the conflicts: refused as a whole, then accepted with skip
    let mixed = fx.write("b.env", &format!("{}TEST_THREE_TOKEN=zz-3\n", env_text()));
    let out = run(
        &fx,
        &["import-env", mixed.to_str().unwrap(), "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(!out.ok);
    assert_eq!(names(&fx, &owner).len(), 3, "nothing was written");
    let out = run(
        &fx,
        &[
            "import-env",
            mixed.to_str().unwrap(),
            "--node",
            "acme",
            "--on-conflict",
            "skip",
        ],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stdout.contains("created  TEST_THREE_TOKEN"),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("skipped  TEST_ONE_TOKEN (exists)"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("imported 1 of 3"), "{}", out.stdout);
    assert_eq!(names(&fx, &owner).len(), 4);
}

#[test]
fn import_env_reads_stdin_refuses_bad_options_and_never_echoes_a_bad_line() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let out = run(
        &fx,
        &["import-env", "-", "--node", "acme", "--json"],
        Some(&owner),
        Some(env_text().as_bytes()),
    );
    assert!(out.ok, "{}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(out.stdout.trim()).unwrap();
    assert_eq!(v["complete"], true);
    assert_eq!(v["created"].as_array().unwrap().len(), 2);
    assert!(!out.all().contains(V_ONE));

    for (args, expect) in [
        (vec!["import-env"], "usage: credmgr import-env"),
        (vec!["import-env", "x.env"], "usage: credmgr import-env"),
        (
            vec![
                "import-env",
                "x.env",
                "--node",
                "acme",
                "--on-conflict",
                "overwrite",
            ],
            "--on-conflict takes refuse or skip",
        ),
    ] {
        let out = run(&fx, &args, Some(&owner), None);
        assert!(!out.ok, "{args:?}");
        assert!(out.stderr.contains(expect), "{args:?}: {}", out.stderr);
    }
    let bad = fx.write("bad.env", "OK_ONE=fine\nsk-bare-token-shaped-zz-9999\n");
    let out = run(
        &fx,
        &["import-env", bad.to_str().unwrap(), "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("line 2"), "{}", out.stderr);
    assert!(!out.all().contains("bare-token-shaped"), "{}", out.all());
}
