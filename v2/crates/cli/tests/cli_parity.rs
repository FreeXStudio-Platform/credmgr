//! CLI parity for four ops the broker already had and the CLI did not reach:
//! `credmgr import` (`entry.create_batch`, ADR-073), `credmgr node rename`
//! (`node.update`, ADR-071), `credmgr node policy` (`node.policy`, ADR-071) and
//! `credmgr notes show|set` (`notes.read`/`notes.write`, ADR-072).
//!
//! Same shape as `broker_integration.rs`, on purpose: the REAL compiled
//! `credmgr` binary as a subprocess against a REAL `credmgrd` — a
//! `BrokerState` served on a real temporary socket by `server::run`. Every
//! "it changed" assertion reads the broker's own state (registry, manifest
//! generation, the sealed note file on disk) or reads back through the binary;
//! none of them trusts the command's own success message. Every secret-shaped
//! fixture value below is a generated placeholder.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use secrecy::SecretBox;

use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::envelope;
use credmgr_core::keys::generate_node_keypair;
use credmgr_core::registry::{
    AgentAccess, Capability, Node, NodeKind, NodePolicy, Registry, SiblingVisibility,
    TwoFactorRequirement, GLOBAL_ID, ORPHAN_ID,
};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{ManifestBody, ManifestEntry, Sensitivity};
use credmgr_store::paths::VaultPaths;
use serde_json::Value;

const PASSPHRASE: &str = "correct horse battery staple";

struct Fixture {
    vault_dir: PathBuf,
    acme_workdir: PathBuf,
    state: Arc<BrokerState>,
    tmp: tempfile::TempDir,
}

impl Fixture {
    fn issue_token(&self, node_id: &str, capabilities: Vec<Capability>, origin: Origin) -> String {
        self.state
            .tokens
            .issue(node_id, capabilities, origin, None)
            .id
    }

    /// A human with every capability the commands under test can need on `acme`.
    fn owner(&self) -> String {
        self.issue_token(
            "acme",
            vec![
                Capability::List,
                Capability::Read,
                Capability::Reveal,
                Capability::Create,
                Capability::Notes,
                Capability::Admin,
            ],
            Origin::HumanUi,
        )
    }

    fn policy(&self, node: &str) -> NodePolicy {
        self.state.registry.read().unwrap().nodes[node]
            .policy
            .clone()
    }

    fn label(&self, node: &str) -> String {
        self.state.registry.read().unwrap().nodes[node]
            .label
            .clone()
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
    // macOS's temp root is a symlink; the broker compares against the resolved cwd.
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
    state.set_manifest("acme", manifest);
    let sealed = envelope::seal(b"s3cr3t-deploy-token", &acme_pub, "acme", entry_id).unwrap();
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

/// Runs the real binary. `stdin: None` is `/dev/null` (an empty read), not a
/// terminal.
fn run(fx: &Fixture, cwd: &Path, args: &[&str], token: Option<&str>, stdin: Option<&[u8]>) -> Out {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_credmgr"));
    cmd.args(args)
        .current_dir(cwd)
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
        // A command that refuses before reading stdin may close the pipe first.
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

fn list_names(fx: &Fixture, token: &str) -> Vec<String> {
    let out = run(
        fx,
        &fx.acme_workdir,
        &["list", "--node", "acme"],
        Some(token),
        None,
    );
    assert!(out.ok, "list failed: {}", out.stderr);
    out.stdout.lines().map(str::to_string).collect()
}

fn get(fx: &Fixture, token: &str, name: &str) -> String {
    let out = run(
        fx,
        &fx.acme_workdir,
        &["get", name, "--node", "acme"],
        Some(token),
        None,
    );
    assert!(out.ok, "get {name} failed: {}", out.stderr);
    out.stdout
        .strip_suffix('\n')
        .unwrap_or(&out.stdout)
        .to_string()
}

// ---- credmgr import -------------------------------------------------------

const V_TOKEN: &str = "tok-svc-aaa-1111";
const V_DB: &str = "postgres://db.internal:5432/app?sslmode=require";
const V_SINGLE: &str = r"lit $x \n # kept";
const V_SPACED: &str = "spaced-ccc-3333";
const V_PEM: &str = "-----BEGIN TEST-----\nline-ddd-4444\n-----END TEST-----";

fn env_file() -> String {
    [
        "# service credentials — a comment, then a blank line".to_string(),
        String::new(),
        format!("export SERVICE_TOKEN={V_TOKEN}"),
        format!("DB_URL=\"{V_DB}\""),
        format!("SINGLE_QUOTED='{V_SINGLE}'"),
        format!("SPACED = {V_SPACED}   # a trailing note"),
        "PLACEHOLDER=".to_string(),
        format!("PEM_BLOCK=\"{V_PEM}\""),
    ]
    .join("\n")
}

#[test]
fn import_creates_every_entry_in_one_call_and_never_prints_a_value() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let file = fx.write("service.env", &env_file());

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", file.to_str().unwrap(), "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "import failed: {}", out.stderr);
    for name in [
        "SERVICE_TOKEN",
        "DB_URL",
        "SINGLE_QUOTED",
        "SPACED",
        "PEM_BLOCK",
    ] {
        assert!(
            out.stdout.contains(&format!("created  {name}")),
            "{name} should be reported created: {}",
            out.stdout
        );
    }
    assert!(
        out.stdout.contains("imported 5 of 5 entries into acme"),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout
            .contains("skipped 1 empty value(s), not imported: PLACEHOLDER"),
        "an empty placeholder is reported by name, not silently dropped: {}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("created  PLACEHOLDER"),
        "{}",
        out.stdout
    );
    // The point of the command: no value ever reaches the terminal.
    for secret in [
        V_TOKEN,
        V_SPACED,
        "line-ddd-4444",
        "sslmode=require",
        "lit $x",
    ] {
        assert!(
            !out.all().contains(secret),
            "import printed a value ({secret}): {}",
            out.all()
        );
    }

    // And what landed is exactly what the file said, read back through the binary.
    assert_eq!(get(&fx, &owner, "SERVICE_TOKEN"), V_TOKEN);
    assert_eq!(get(&fx, &owner, "DB_URL"), V_DB);
    assert_eq!(get(&fx, &owner, "SINGLE_QUOTED"), V_SINGLE);
    assert_eq!(get(&fx, &owner, "SPACED"), V_SPACED);
    assert_eq!(get(&fx, &owner, "PEM_BLOCK"), V_PEM);
    let names = list_names(&fx, &owner);
    assert!(!names.contains(&"PLACEHOLDER".to_string()), "{names:?}");
    assert_eq!(
        names.len(),
        6,
        "DEPLOY_TOKEN plus the five imported: {names:?}"
    );

    // --json is the broker's answer plus what the CLI skipped, still value-free.
    let more = fx.write("more.env", "JSON_ONE=json-eee-5555\nJSON_EMPTY=\n");
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", more.to_str().unwrap(), "--node", "acme", "--json"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    let json: Value = serde_json::from_str(out.stdout.trim()).expect("one JSON document");
    assert_eq!(json["complete"], true);
    assert_eq!(json["created"][0]["name"], "JSON_ONE");
    assert_eq!(json["skippedEmpty"][0], "JSON_EMPTY");
    assert!(!out.all().contains("json-eee-5555"), "{}", out.all());
}

#[test]
fn a_name_already_on_the_node_refuses_the_whole_batch_and_names_the_blocker() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let file = fx.write(
        "clash.env",
        "FRESH_ONE=fresh-eee-5555\nFRESH_TWO=fresh-fff-6666\nDEPLOY_TOKEN=clash-ggg-7777\n",
    );

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", file.to_str().unwrap(), "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(!out.ok, "a clashing name must fail the import");
    assert!(out.stderr.contains("entry_exists"), "{}", out.stderr);
    assert!(
        out.stderr
            .contains("'DEPLOY_TOKEN' already exists on node 'acme'"),
        "the blocking name must be in the message: {}",
        out.stderr
    );
    for secret in ["fresh-eee-5555", "clash-ggg-7777"] {
        assert!(!out.all().contains(secret), "{}", out.all());
    }
    // All-or-nothing: the two valid entries ahead of the clash were NOT written.
    assert_eq!(list_names(&fx, &owner), vec!["DEPLOY_TOKEN"]);
    assert_eq!(get(&fx, &owner, "DEPLOY_TOKEN"), "s3cr3t-deploy-token");
}

#[test]
fn a_file_that_cannot_be_imported_cleanly_is_refused_before_anything_is_written() {
    let fx = start_fixture_broker();
    let owner = fx.owner();

    for (what, text, expect, leaked) in [
        (
            "a duplicate key",
            "ALPHA=one-hhh-8888\nBETA=two-iii-9999\nALPHA=three-jjj-0000\n",
            "line 3: ALPHA appears again (first on line 1)",
            "one-hhh-8888",
        ),
        (
            "a line with no NAME=",
            "OK_ONE=fine-kkk-1212\nsk-bare-token-shaped-lll-3434\n",
            "line 2: expected NAME=value",
            "bare-token-shaped",
        ),
        (
            "a name with a space in it",
            "bad name=tok-mmm-5656\n",
            "line 1: not a valid name",
            "tok-mmm-5656",
        ),
        (
            "a quote that never closes",
            "OPEN=\"never-closed-nnn-7878\nmore\n",
            "line 1: a quoted value is never closed",
            "never-closed",
        ),
        (
            // The forgotten closing quote that every dotenv reader would
            // answer by silently folding the next assignment into this value.
            "an unbalanced quote that would swallow the next assignment",
            "FIRST_OK=ok-sss-1111\nSECRET_PW=\"never-closed-ttt-2222\nNEXT_KEY=next-uuu-3333\"\n",
            "line 2: a quoted value is not closed before line 3",
            "never-closed-ttt-2222",
        ),
        (
            "only comments and empties",
            "# nothing here\nEMPTY_ONE=\n",
            "nothing to import",
            "",
        ),
    ] {
        let file = fx.write("bad.env", text);
        let out = run(
            &fx,
            &fx.acme_workdir,
            &["import", file.to_str().unwrap(), "--node", "acme"],
            Some(&owner),
            None,
        );
        assert!(!out.ok, "{what} must be refused");
        assert!(out.stderr.contains(expect), "{what}: {}", out.stderr);
        if !leaked.is_empty() {
            assert!(
                !out.all().contains(leaked),
                "{what}: the diagnostic echoed file content: {}",
                out.all()
            );
        }
        assert_eq!(
            list_names(&fx, &owner),
            vec!["DEPLOY_TOKEN"],
            "{what}: nothing may have been written"
        );
    }

    // The batch ceiling is the broker's (500); 501 is refused here with advice,
    // 500 goes through.
    let many = |n: usize| -> String {
        let mut text = String::new();
        for i in 0..n {
            text.push_str(&format!("BULK_{i:04}=bulk-value-{i}\n"));
        }
        text
    };
    let file = fx.write("many.env", &many(501));
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", file.to_str().unwrap(), "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(!out.ok);
    assert!(
        out.stderr.contains("at most 500") && out.stderr.contains("501"),
        "{}",
        out.stderr
    );
    assert_eq!(list_names(&fx, &owner), vec!["DEPLOY_TOKEN"]);

    let file = fx.write("exact.env", &many(500));
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", file.to_str().unwrap(), "--node", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stdout.contains("imported 500 of 500 entries into acme"),
        "{}",
        out.stdout.lines().last().unwrap_or("")
    );
    assert_eq!(list_names(&fx, &owner).len(), 501);
    assert_eq!(get(&fx, &owner, "BULK_0499"), "bulk-value-499");
}

#[test]
fn import_reads_stdin_for_a_dash_and_refuses_what_it_cannot_authorise_or_parse_as_a_command() {
    let fx = start_fixture_broker();
    let owner = fx.owner();

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", "-", "--node", "acme"],
        Some(&owner),
        Some(b"VIA_STDIN=stdin-ooo-9090\n"),
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("created  VIA_STDIN"), "{}", out.stdout);
    assert!(!out.all().contains("stdin-ooo-9090"));
    assert!(
        !out.stderr.contains("still holds the plaintext"),
        "no source file to warn about when reading stdin: {}",
        out.stderr
    );
    assert_eq!(get(&fx, &owner, "VIA_STDIN"), "stdin-ooo-9090");

    let file = fx.write("one.env", "ONE=one-ppp-1313\n");
    let path = file.to_str().unwrap();
    for (args, expect) in [
        (vec!["import"], "usage: credmgr import"),
        (vec!["import", path], "usage: credmgr import"),
        (
            vec!["import", path, "--nod", "acme"],
            "usage: credmgr import",
        ),
        (
            vec!["import", path, "extra", "--node", "acme"],
            "usage: credmgr import",
        ),
        (
            vec!["import", "/no/such/dir/x.env", "--node", "acme"],
            "could not open",
        ),
    ] {
        let out = run(&fx, &fx.acme_workdir, &args, Some(&owner), None);
        assert!(!out.ok, "{args:?} must fail");
        assert!(out.stderr.contains(expect), "{args:?}: {}", out.stderr);
    }

    // A node that does not exist, and a caller without `create`: refused by the
    // broker, nothing written.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", path, "--node", "nope"],
        Some(&owner),
        None,
    );
    assert!(!out.ok, "{}", out.all());
    let reader = fx.issue_token(
        "acme",
        vec![Capability::List, Capability::Read, Capability::Reveal],
        Origin::HumanUi,
    );
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", path, "--node", "acme"],
        Some(&reader),
        None,
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("capability_not_held"), "{}", out.stderr);
    assert!(!list_names(&fx, &owner).contains(&"ONE".to_string()));
}

#[test]
fn an_import_that_stops_part_way_exits_non_zero_and_says_what_was_saved() {
    let fx = start_fixture_broker();
    // A node the registry knows — so the caller may create in it and the
    // broker's up-front validation passes — whose keypair was never seeded. The
    // first `entry.create` in the batch then fails (`NotFound`), and the broker
    // answers `complete: false` with `failed.index == 0` instead of an error.
    fx.state.registry.write().unwrap().nodes.insert(
        "ghost".to_string(),
        Node {
            id: "ghost".to_string(),
            label: "Ghost".to_string(),
            kind: NodeKind::Project,
            depth: 1,
            parent_id: Some(GLOBAL_ID.to_string()),
            workdirs: vec![],
            policy: NodePolicy::default(),
        },
    );
    let ghost = fx.issue_token(
        "ghost",
        vec![
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Create,
        ],
        Origin::HumanUi,
    );
    let file = fx.write(
        "ghost.env",
        "GHOST_ONE=ghost-vvv-1010\nGHOST_TWO=ghost-www-2020\n",
    );

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", file.to_str().unwrap(), "--node", "ghost"],
        Some(&ghost),
        None,
    );
    assert!(
        !out.ok,
        "a batch that did not complete must not exit 0: {}",
        out.all()
    );
    assert!(
        out.stderr
            .contains("the import failed on entry 1 (GHOST_ONE)")
            && out.stderr.contains("nothing was saved"),
        "{}",
        out.stderr
    );
    assert!(
        out.stdout.contains("imported 0 of 2 entries into ghost"),
        "what WAS saved is still reported: {}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("created  GHOST_"),
        "no entry may be reported created: {}",
        out.stdout
    );
    for secret in ["ghost-vvv-1010", "ghost-www-2020"] {
        assert!(!out.all().contains(secret), "{}", out.all());
    }

    // --json carries the same verdict: the document says `complete: false`, and
    // the exit status still says so too.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &[
            "import",
            file.to_str().unwrap(),
            "--node",
            "ghost",
            "--json",
        ],
        Some(&ghost),
        None,
    );
    assert!(!out.ok, "{}", out.all());
    let json: Value = serde_json::from_str(out.stdout.trim()).expect("one JSON document");
    assert_eq!(json["complete"], false);
    assert_eq!(json["failed"]["index"], 0);
    assert_eq!(json["failed"]["name"], "GHOST_ONE");
    assert!(!out.all().contains("ghost-vvv-1010"), "{}", out.all());
}

#[test]
fn an_import_into_a_locked_vault_is_held_for_review_not_lost() {
    let fx = start_fixture_broker();
    fx.state.lock();
    let file = fx.write("locked.env", "LOCK_ONE=lock-qqq-1\nLOCK_TWO=lock-rrr-2\n");

    // Locked, the only caller is an agent scoped to the project by its cwd.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["import", file.to_str().unwrap(), "--node", "acme"],
        None,
        None,
    );
    assert!(
        out.ok,
        "a locked create is permitted and held: {}",
        out.stderr
    );
    assert!(out.stdout.contains("held     LOCK_ONE"), "{}", out.stdout);
    assert!(
        out.stdout.contains("2 entries wait in the review tray")
            && out.stdout.contains("credmgr pending"),
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains("created  LOCK_ONE"), "{}", out.stdout);

    fx.state.unlock(0).expect("re-unlock");
    let owner = fx.owner();
    let pending = run(
        &fx,
        &fx.acme_workdir,
        &["pending", "--node", "acme", "--json"],
        Some(&owner),
        None,
    );
    assert!(pending.ok, "{}", pending.stderr);
    let json: Value = serde_json::from_str(pending.stdout.trim()).unwrap();
    let mut names: Vec<&str> = json["pending"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["LOCK_ONE", "LOCK_TWO"]);
    assert_eq!(
        list_names(&fx, &owner),
        vec!["DEPLOY_TOKEN"],
        "held entries are not live until accepted"
    );
}

// ---- credmgr node rename --------------------------------------------------

#[test]
fn node_rename_changes_the_label_and_never_the_id() {
    let fx = start_fixture_broker();
    let admin = fx.issue_token("acme", vec![Capability::Admin], Origin::HumanUi);
    assert_eq!(fx.label("acme"), "Acme");

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["node", "rename", "acme", "Acme Corporation"],
        Some(&admin),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stdout.contains("label is now 'Acme Corporation'"),
        "{}",
        out.stdout
    );
    assert_eq!(
        fx.label("acme"),
        "Acme Corporation",
        "the broker's registry changed"
    );
    let ls = run(
        &fx,
        &fx.acme_workdir,
        &["node", "ls"],
        Some(&fx.owner()),
        None,
    );
    assert!(
        ls.stdout.lines().any(|l| l == "acme"),
        "the id is untouched: {}",
        ls.stdout
    );

    // The broker trims; --json is its answer verbatim.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["node", "rename", "acme", "  Padded  ", "--json"],
        Some(&admin),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    let json: Value = serde_json::from_str(out.stdout.trim()).unwrap();
    assert_eq!(json["label"], "Padded");
    assert_eq!(fx.label("acme"), "Padded");

    // Refusals, each leaving the label alone: Global and Orphan are the
    // broker's own, surfaced as it said them.
    for (args, expect) in [
        (
            vec!["node", "rename", "global", "Everything"],
            "cannot be renamed",
        ),
        (
            vec!["node", "rename", "orphan", "Mine"],
            "cannot be renamed",
        ),
        (vec!["node", "rename", "acme", "   "], "label must be 1"),
        // A node that does not exist is refused (as not_found or as access
        // denied — the broker picks); the empty needle asserts only failure.
        (vec!["node", "rename", "nope", "X"], ""),
        (vec!["node", "rename", "acme"], "usage: credmgr node rename"),
        (
            vec!["node", "rename", "acme", "Two", "Words"],
            "usage: credmgr node rename",
        ),
        (
            vec!["node", "rename", "acme", "X", "--bogus"],
            "unknown option",
        ),
    ] {
        let out = run(&fx, &fx.acme_workdir, &args, Some(&admin), None);
        assert!(!out.ok, "{args:?} must fail");
        assert!(out.stderr.contains(expect), "{args:?}: {}", out.stderr);
    }
    assert_eq!(fx.label("acme"), "Padded");
    assert_eq!(fx.label(GLOBAL_ID), Node::global().label);

    // An agent (no token, scoped by cwd) is never an administrator.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["node", "rename", "acme", "Hijacked"],
        None,
        None,
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("capability_not_held"), "{}", out.stderr);
    assert_eq!(fx.label("acme"), "Padded");
}

// ---- credmgr node policy --------------------------------------------------

#[test]
fn node_policy_applies_a_partial_patch_and_reports_what_is_not_enforced() {
    let fx = start_fixture_broker();
    let admin = fx.issue_token("acme", vec![Capability::Admin], Origin::HumanUi);
    assert_eq!(fx.policy("acme"), NodePolicy::default());

    let out = run(
        &fx,
        &fx.acme_workdir,
        &[
            "node",
            "policy",
            "acme",
            "--reason",
            "tighten after the audit",
            "--agent-access",
            "read-only",
            "--lock-after-seconds",
            "300",
            "--private-names",
        ],
        Some(&admin),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    let p = fx.policy("acme");
    assert_eq!(p.agent_access, AgentAccess::ReadOnly);
    assert_eq!(p.lock_after_seconds, Some(300));
    assert!(p.private_names);
    assert_eq!(
        p.sibling_visibility,
        NodePolicy::default().sibling_visibility,
        "a field not in the patch is untouched"
    );
    assert!(
        out.stdout.contains(
            "policy updated on acme (changed: lockAfterSeconds, privateNames, agentAccess)"
        ),
        "the report names what the broker says changed: {}",
        out.stdout
    );
    // One "field value" row per policy field, untouched ones included.
    let row = |field: &str, value: &str| {
        out.stdout
            .lines()
            .any(|l| l.split_whitespace().eq([field, value]))
    };
    assert!(
        row("agentAccess", "read-only")
            && row("lockAfterSeconds", "300")
            && row("privateNames", "true")
            && row("siblingVisibility", "shared")
            && row("descendantRead", "false")
            && row("requireTwoFactor", "reveal"),
        "the report shows the resulting policy, untouched fields included: {}",
        out.stdout
    );
    assert!(
        out.stdout
            .contains("reason recorded: tighten after the audit"),
        "{}",
        out.stdout
    );
    // ADR-083 / ADR-085: every policy field is enforced now, so nothing is reported
    // as "stored but not acted on" and no change draws the old warning.
    assert!(
        !out.stdout.contains("not enforced yet"),
        "nothing is un-enforced any more: {}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("does not protect anything yet"),
        "{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("warning: agentAccess"),
        "an enforced field draws no warning: {}",
        out.stdout
    );

    // `none` clears the per-node timer; the rest of the patch is independent.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &[
            "node",
            "policy",
            "acme",
            "--reason",
            "no auto-lock",
            "--lock-after-seconds",
            "none",
            "--no-private-names",
            "--json",
        ],
        Some(&admin),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    let json: Value = serde_json::from_str(out.stdout.trim()).unwrap();
    assert_eq!(json["policy"]["lockAfterSeconds"], Value::Null);
    assert_eq!(json["notEnforced"], serde_json::json!([]));
    let p = fx.policy("acme");
    assert_eq!(p.lock_after_seconds, None);
    assert!(!p.private_names);
    assert_eq!(
        p.agent_access,
        AgentAccess::ReadOnly,
        "earlier change stands"
    );

    // requireTwoFactor is stored and enforced: no "does not protect" warning.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &[
            "node",
            "policy",
            "acme",
            "--reason",
            "ask for the second factor",
            "--require-two-factor",
            "always",
        ],
        Some(&admin),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        !out.stdout.contains("does not protect anything yet"),
        "{}",
        out.stdout
    );
    assert_eq!(
        fx.policy("acme").require_two_factor,
        TwoFactorRequirement::Always
    );
}

#[test]
fn a_widening_policy_change_is_refused_honestly_and_applies_none_of_the_patch() {
    let fx = start_fixture_broker();
    let admin = fx.issue_token("acme", vec![Capability::Admin], Origin::HumanUi);

    // Narrowing first (siblings isolated) so that sharing again is a widening.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &[
            "node",
            "policy",
            "acme",
            "--reason",
            "isolate siblings",
            "--sibling-visibility",
            "isolated",
        ],
        Some(&admin),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert_eq!(
        fx.policy("acme").sibling_visibility,
        SiblingVisibility::Isolated
    );
    let before = fx.policy("acme");

    for flags in [
        // descendant-read on widens, even next to a perfectly good narrowing…
        vec!["--descendant-read", "--agent-access", "none"],
        // …and so does sharing siblings again.
        vec!["--sibling-visibility", "shared"],
    ] {
        let mut args = vec!["node", "policy", "acme", "--reason", "open it up"];
        args.extend(&flags);
        let out = run(&fx, &fx.acme_workdir, &args, Some(&admin), None);
        assert!(!out.ok, "{flags:?} needs presence and must be refused");
        assert!(out.stderr.contains("presence_required"), "{}", out.stderr);
        assert!(
            out.stderr.contains("Nothing in this change was applied"),
            "the refusal says plainly that nothing happened: {}",
            out.stderr
        );
        assert_eq!(
            fx.policy("acme"),
            before,
            "{flags:?}: all-or-nothing — not even the narrowing half may land"
        );
    }

    // Switching OFF what is already off is not a widening.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &[
            "node",
            "policy",
            "acme",
            "--reason",
            "belt and braces",
            "--no-descendant-read",
        ],
        Some(&admin),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
}

#[test]
fn node_policy_refuses_bad_input_before_or_at_the_broker_and_changes_nothing() {
    let fx = start_fixture_broker();
    let admin = fx.issue_token("acme", vec![Capability::Admin], Origin::HumanUi);

    for (args, expect) in [
        (
            vec!["node", "policy", "acme", "--agent-access", "read-only"],
            "--reason is required",
        ),
        (
            vec![
                "node",
                "policy",
                "acme",
                "--reason",
                "   ",
                "--private-names",
            ],
            "--reason is required",
        ),
        (
            vec!["node", "policy", "acme", "--reason", "why"],
            "no policy flag given",
        ),
        (
            vec![
                "node",
                "policy",
                "acme",
                "--reason",
                "why",
                "--agent-access",
                "readwrite",
            ],
            "read-write|read-only|none",
        ),
        (
            vec![
                "node",
                "policy",
                "acme",
                "--reason",
                "why",
                "--require-two-factor",
                "sometimes",
            ],
            "never|reveal|always",
        ),
        (
            vec![
                "node",
                "policy",
                "acme",
                "--reason",
                "why",
                "--sibling-visibility",
                "open",
            ],
            "shared|isolated",
        ),
        (
            vec![
                "node",
                "policy",
                "acme",
                "--reason",
                "why",
                "--private-names",
                "--no-private-names",
            ],
            "contradict",
        ),
        (
            vec![
                "node",
                "policy",
                "acme",
                "--reason",
                "why",
                "--lock-after-seconds",
                "soon",
            ],
            "number of seconds",
        ),
        (
            vec![
                "node",
                "policy",
                "acme",
                "--reason",
                "why",
                "--lock-after-seconds",
                "-5",
            ],
            "number of seconds",
        ),
        (
            vec!["node", "policy", "acme", "--private-names", "--reason"],
            "missing its value",
        ),
        (
            vec!["node", "policy", "--reason", "why", "--private-names"],
            "usage: credmgr node policy",
        ),
        (
            vec![
                "node",
                "policy",
                "acme",
                "other",
                "--reason",
                "why",
                "--private-names",
            ],
            "usage: credmgr node policy",
        ),
        // The broker's own refusals, surfaced as it said them.
        (
            vec![
                "node",
                "policy",
                "orphan",
                "--reason",
                "why",
                "--private-names",
            ],
            "fixed by design",
        ),
        (
            vec![
                "node",
                "policy",
                "nope",
                "--reason",
                "why",
                "--private-names",
            ],
            "",
        ),
    ] {
        let out = run(&fx, &fx.acme_workdir, &args, Some(&admin), None);
        assert!(!out.ok, "{args:?} must fail");
        assert!(out.stderr.contains(expect), "{args:?}: {}", out.stderr);
    }

    // An agent is never an administrator.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &[
            "node",
            "policy",
            "acme",
            "--reason",
            "why",
            "--private-names",
        ],
        None,
        None,
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("capability_not_held"), "{}", out.stderr);

    assert_eq!(
        fx.policy("acme"),
        NodePolicy::default(),
        "no refusal changed anything"
    );
}

#[test]
fn a_reason_flag_never_takes_the_next_option_as_its_text() {
    let fx = start_fixture_broker();
    let owner = fx.owner();

    // `--reason` with another option where its text belongs. Taken as the text,
    // `--descendant-read` would be recorded in the audit log as the reason AND
    // dropped from the patch — a different change from the one asked for.
    for args in [
        vec![
            "node",
            "policy",
            "acme",
            "--private-names",
            "--reason",
            "--descendant-read",
        ],
        vec!["node", "policy", "acme", "--reason", "--private-names"],
    ] {
        let out = run(&fx, &fx.acme_workdir, &args, Some(&owner), None);
        assert!(!out.ok, "{args:?} must be refused: {}", out.all());
        assert!(
            out.stderr.contains("--reason needs its text"),
            "{args:?}: {}",
            out.stderr
        );
        assert_eq!(
            fx.policy("acme"),
            NodePolicy::default(),
            "{args:?}: a refusal applies nothing, not even the flags that were fine"
        );
    }

    // `grant` records a reason too. Refused before the broker is asked, so the
    // answer is the flag error, not the presence gate that would otherwise come.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["grant", "acme", "--to", "global", "--reason", "--scope"],
        Some(&owner),
        None,
    );
    assert!(!out.ok, "{}", out.all());
    assert!(
        out.stderr.contains("--reason needs its text"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("presence_required"), "{}", out.stderr);

    // Real text still goes through.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &[
            "node",
            "policy",
            "acme",
            "--private-names",
            "--reason",
            "hide names from siblings",
        ],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(fx.policy("acme").private_names);
    assert!(
        out.stdout
            .contains("reason recorded: hide names from siblings"),
        "{}",
        out.stdout
    );
}

// ---- credmgr notes --------------------------------------------------------

const NOTE: &str = "# Acme runbook\n\nDeploys on Tuesdays; vendor contact: note-body-sss-4040\n";

#[test]
fn a_note_round_trips_byte_for_byte_and_is_sealed_on_disk() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let note_file = VaultPaths::new(fx.vault_dir.clone()).notes_env("acme");

    // The manifest generation must be non-zero for this to prove anything: a
    // client that sent a hard-coded 0 would be refused as a `conflict`.
    let file = fx.write("seed.env", "SEED_ONE=seed-ttt-1\nSEED_TWO=seed-uuu-2\n");
    assert!(
        run(
            &fx,
            &fx.acme_workdir,
            &["import", file.to_str().unwrap(), "--node", "acme"],
            Some(&owner),
            None,
        )
        .ok
    );
    let before = fx.state.manifest_generation("acme").unwrap();
    assert!(
        before >= 1,
        "the fixture manifest must have moved off generation 0"
    );

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stdout.is_empty(),
        "no note, nothing on stdout: {:?}",
        out.stdout
    );
    assert!(out.stderr.contains("no note on acme"), "{}", out.stderr);

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&owner),
        Some(NOTE.as_bytes()),
    );
    assert!(out.ok, "{}", out.stderr);
    let after = fx.state.manifest_generation("acme").unwrap();
    assert_eq!(
        after,
        before + 1,
        "the write bumped the generation it was based on"
    );
    assert!(
        out.stdout
            .contains(&format!("note saved on acme (generation {after})")),
        "{}",
        out.stdout
    );

    // Exactly what went in comes out — trailing newline and all.
    let shown = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme"],
        Some(&owner),
        None,
    );
    assert!(shown.ok, "{}", shown.stderr);
    assert_eq!(shown.stdout, NOTE);
    let json = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme", "--json"],
        Some(&owner),
        None,
    );
    let json: Value = serde_json::from_str(json.stdout.trim()).unwrap();
    assert_eq!(json["markdown"], NOTE);
    assert!(json["modified"].is_number(), "{json}");

    // Sealed under the node key: the plaintext is nowhere in the file.
    let on_disk = std::fs::read(&note_file).expect("the sealed note file exists");
    assert!(!on_disk.is_empty());
    assert!(
        !String::from_utf8_lossy(&on_disk).contains("note-body-sss-4040")
            && !on_disk.windows(10).any(|w| w == b"Deploys on"),
        "the note must not be stored in plaintext"
    );

    // `--file` replaces it.
    let replacement = fx.write("note.md", "second version\n");
    let out = run(
        &fx,
        &fx.acme_workdir,
        &[
            "notes",
            "set",
            "acme",
            "--file",
            replacement.to_str().unwrap(),
        ],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    let shown = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme"],
        Some(&owner),
        None,
    );
    assert_eq!(shown.stdout, "second version\n");

    // Empty input is REFUSED, never read as a delete: a failed upstream pipe
    // (`failing-cmd | credmgr notes set acme`) must not destroy a sealed note.
    let before_empty = fx.state.manifest_generation("acme").unwrap();
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&owner),
        Some(b""),
    );
    assert!(!out.ok, "empty input must be refused: {}", out.all());
    assert!(
        out.stderr.contains("credmgr notes clear acme"),
        "the refusal names the way to delete: {}",
        out.stderr
    );
    assert!(
        note_file.exists(),
        "an empty `notes set` must not delete the sealed note"
    );
    assert_eq!(
        fx.state.manifest_generation("acme").unwrap(),
        before_empty,
        "nothing reached the broker's write path"
    );
    let shown = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme"],
        Some(&owner),
        None,
    );
    assert_eq!(shown.stdout, "second version\n");

    // `notes clear` is the deliberate way — the file as well as the manifest's claim.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "clear", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(
        out.stdout.contains("cleared the note on acme"),
        "{}",
        out.stdout
    );
    assert!(!note_file.exists(), "clearing removes the sealed file");
    assert_eq!(
        fx.state.manifest_generation("acme").unwrap(),
        before_empty + 1,
        "a real clear is one write"
    );
    let shown = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme"],
        Some(&owner),
        None,
    );
    assert!(shown.ok && shown.stdout.is_empty(), "{}", shown.all());
    assert!(shown.stderr.contains("no note on acme"));
}

/// One way input can come up empty: what it is, the command line, and stdin.
type EmptyInputCase<'a> = (&'a str, Vec<&'a str>, Option<&'a [u8]>);

#[test]
fn notes_set_never_deletes_whatever_the_empty_input_looks_like_and_clear_is_exact() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let note_file = VaultPaths::new(fx.vault_dir.clone()).notes_env("acme");

    // Clearing a note that is not there says so and writes nothing — the node's
    // generation is not bumped for a no-op.
    let g0 = fx.state.manifest_generation("acme").unwrap();
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "clear", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.all());
    assert!(
        out.stderr.contains("no note on acme") && out.stderr.contains("nothing to clear"),
        "{}",
        out.stderr
    );
    assert!(!out.stdout.contains("cleared"), "{}", out.stdout);
    assert_eq!(fx.state.manifest_generation("acme").unwrap(), g0);

    // A note worth protecting.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&owner),
        Some(NOTE.as_bytes()),
    );
    assert!(out.ok, "{}", out.stderr);
    let saved = fx.state.manifest_generation("acme").unwrap();
    assert!(note_file.exists());

    // Every way input can come up empty: a closed pipe, /dev/null, only
    // whitespace, an empty `--file`. None of them may touch the note.
    let empty_file = fx.write("empty.md", "");
    let blank_file = fx.write("blank.md", "\n  \n");
    let cases: Vec<EmptyInputCase> = vec![
        (
            "an empty pipe",
            vec!["notes", "set", "acme"],
            Some(&b""[..]),
        ),
        ("/dev/null", vec!["notes", "set", "acme"], None),
        (
            "a lone newline",
            vec!["notes", "set", "acme"],
            Some(&b"\n"[..]),
        ),
        (
            "only whitespace",
            vec!["notes", "set", "acme"],
            Some(&b" \t\r\n\n"[..]),
        ),
        (
            "an empty --file",
            vec![
                "notes",
                "set",
                "acme",
                "--file",
                empty_file.to_str().unwrap(),
            ],
            None,
        ),
        (
            "a blank --file",
            vec![
                "notes",
                "set",
                "acme",
                "--file",
                blank_file.to_str().unwrap(),
            ],
            None,
        ),
    ];
    for (what, args, stdin) in cases {
        let out = run(&fx, &fx.acme_workdir, &args, Some(&owner), stdin);
        assert!(
            !out.ok,
            "{what}: empty input must be refused: {}",
            out.all()
        );
        assert!(
            out.stderr.contains("notes set") && out.stderr.contains("notes clear acme"),
            "{what}: {}",
            out.stderr
        );
        assert!(!out.stdout.contains("cleared"), "{what}: {}", out.stdout);
        assert!(note_file.exists(), "{what}: the note must survive");
        assert_eq!(
            fx.state.manifest_generation("acme").unwrap(),
            saved,
            "{what}: the manifest must not have moved"
        );
    }
    let shown = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme"],
        Some(&owner),
        None,
    );
    assert_eq!(shown.stdout, NOTE, "the note is byte-for-byte what it was");

    // `clear` takes exactly one node: no text, no flags, no stray arguments.
    for args in [
        vec!["notes", "clear"],
        vec!["notes", "clear", "acme", "extra"],
        vec!["notes", "clear", "acme", "--file", "x.md"],
        vec!["notes", "clear", "--force", "acme"],
    ] {
        let out = run(&fx, &fx.acme_workdir, &args, Some(&owner), Some(b"x"));
        assert!(!out.ok, "{args:?} must fail");
        assert!(
            out.stderr.contains("usage: credmgr notes") || out.stderr.contains("missing its value"),
            "{args:?}: {}",
            out.stderr
        );
        assert!(note_file.exists(), "{args:?}: the note must survive");
    }

    // It needs the same separate capability as the rest of the notes commands.
    let reader = fx.issue_token(
        "acme",
        vec![Capability::List, Capability::Read, Capability::Reveal],
        Origin::HumanUi,
    );
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "clear", "acme"],
        Some(&reader),
        None,
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("capability_not_held"), "{}", out.stderr);
    assert!(note_file.exists());

    // And then it really deletes, once, exactly.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "clear", "acme"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(!note_file.exists());
    assert_eq!(fx.state.manifest_generation("acme").unwrap(), saved + 1);
}

#[test]
fn notes_need_their_own_capability_and_never_take_text_from_argv_or_unbounded_input() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let note_file = VaultPaths::new(fx.vault_dir.clone()).notes_env("acme");

    // `notes` is never implied by `read`/`reveal`.
    let reader = fx.issue_token(
        "acme",
        vec![Capability::List, Capability::Read, Capability::Reveal],
        Origin::HumanUi,
    );
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme"],
        Some(&reader),
        None,
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("capability_not_held"), "{}", out.stderr);
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&reader),
        Some(b"sneaky"),
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("capability_not_held"), "{}", out.stderr);
    assert!(!note_file.exists(), "a refused write leaves nothing behind");

    // The text is never an argument: a positional after the node is a usage error.
    for args in [
        vec!["notes", "set", "acme", "inline note text"],
        vec!["notes", "set", "acme", "--file"],
        vec!["notes", "set"],
        vec!["notes", "show"],
        vec!["notes"],
        vec!["notes", "frob", "acme"],
    ] {
        let out = run(&fx, &fx.acme_workdir, &args, Some(&owner), Some(b"x"));
        assert!(!out.ok, "{args:?} must fail");
        assert!(
            out.stderr.contains("usage: credmgr notes") || out.stderr.contains("missing its value"),
            "{args:?}: {}",
            out.stderr
        );
    }
    assert!(!note_file.exists());

    // The broker's 64 KiB cap, enforced here first; exactly at the cap is fine.
    let over = vec![b'a'; 64 * 1024 + 1];
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&owner),
        Some(&over),
    );
    assert!(!out.ok);
    assert!(
        out.stderr.contains("limited to 65536 bytes"),
        "{}",
        out.stderr
    );
    assert!(!note_file.exists());
    let exact = vec![b'a'; 64 * 1024];
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&owner),
        Some(&exact),
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(note_file.exists());

    // Bytes that are not text are refused rather than mangled into a note.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&owner),
        Some(&[0xff, 0xfe, 0x00]),
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("not valid UTF-8"), "{}", out.stderr);
    let shown = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme", "--json"],
        Some(&owner),
        None,
    );
    let json: Value = serde_json::from_str(shown.stdout.trim()).unwrap();
    assert_eq!(
        json["markdown"].as_str().map(str::len),
        Some(64 * 1024),
        "the refused write did not disturb the saved note"
    );

    // A node that does not exist.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "nope"],
        Some(&owner),
        Some(b"x"),
    );
    assert!(!out.ok, "{}", out.all());
}

/// ADR-077: `notes.read` returns the manifest generation, and the CLI's
/// `notes set` / `notes clear` take it from there - so a grantee holding `notes`
/// alone (no `list`, the capability `entry.list`, their old source of the
/// generation, is gated on) is no longer refused.
#[test]
fn a_notes_only_grantee_can_set_show_and_clear_without_the_list_capability() {
    let fx = start_fixture_broker();
    let note_file = VaultPaths::new(fx.vault_dir.clone()).notes_env("acme");
    let notes_only = fx.issue_token("acme", vec![Capability::Notes], Origin::HumanUi);

    // The control: this token really cannot list (so the old route would have failed).
    let probe = run(
        &fx,
        &fx.acme_workdir,
        &["list", "--node", "acme"],
        Some(&notes_only),
        None,
    );
    assert!(
        !probe.ok && probe.all().contains("capability_not_held"),
        "the control: a notes-only token must not hold list: {}",
        probe.all()
    );

    // And the broker hands it the generation on `notes.read`, which the CLI shows
    // under --json.
    let generation = fx.state.manifest_generation("acme").unwrap();
    let shown = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme", "--json"],
        Some(&notes_only),
        None,
    );
    assert!(shown.ok, "{}", shown.all());
    let json: Value = serde_json::from_str(shown.stdout.trim()).unwrap();
    assert_eq!(json["generation"], generation, "{json}");
    assert_eq!(json["markdown"], "");

    // set
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&notes_only),
        Some(NOTE.as_bytes()),
    );
    assert!(out.ok, "notes set without list: {}", out.all());
    let saved = fx.state.manifest_generation("acme").unwrap();
    assert_eq!(saved, generation + 1);
    assert!(
        out.stdout
            .contains(&format!("note saved on acme (generation {saved})")),
        "{}",
        out.stdout
    );
    assert!(note_file.exists());
    let shown = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme", "--json"],
        Some(&notes_only),
        None,
    );
    let json: Value = serde_json::from_str(shown.stdout.trim()).unwrap();
    assert_eq!(json["generation"], saved, "read-your-write: {json}");
    assert_eq!(json["markdown"], NOTE);

    // clear
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "clear", "acme"],
        Some(&notes_only),
        None,
    );
    assert!(out.ok, "notes clear without list: {}", out.all());
    assert!(!note_file.exists());
    assert_eq!(fx.state.manifest_generation("acme").unwrap(), saved + 1);

    // Clearing what is not there still touches nothing.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "clear", "acme"],
        Some(&notes_only),
        None,
    );
    assert!(out.ok, "{}", out.all());
    assert!(out.stderr.contains("nothing to clear"), "{}", out.stderr);
    assert_eq!(fx.state.manifest_generation("acme").unwrap(), saved + 1);

    // The `notes` capability is still the gate: no `notes`, no read, no write.
    let list_only = fx.issue_token("acme", vec![Capability::List], Origin::HumanUi);
    for args in [
        vec!["notes", "show", "acme"],
        vec!["notes", "set", "acme"],
        vec!["notes", "clear", "acme"],
    ] {
        let out = run(
            &fx,
            &fx.acme_workdir,
            &args,
            Some(&list_only),
            Some(b"text"),
        );
        assert!(!out.ok, "{args:?}");
        assert!(
            out.stderr.contains("capability_not_held"),
            "{args:?}: {}",
            out.stderr
        );
    }
}

/// `notes.write` never reads the old note, so writing is how a damaged note is
/// repaired. `notes.read` fails on one (its file is gone while the manifest
/// still records it), so the CLI must not let that failure stop `notes set` for a
/// caller that can still get the generation from `entry.list`.
#[test]
fn notes_set_still_repairs_a_damaged_note() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let note_file = VaultPaths::new(fx.vault_dir.clone()).notes_env("acme");
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&owner),
        Some(NOTE.as_bytes()),
    );
    assert!(out.ok, "{}", out.all());

    // Damage: the file disappears, the manifest still records its digest.
    std::fs::remove_file(&note_file).unwrap();
    let broken = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme"],
        Some(&owner),
        None,
    );
    assert!(!broken.ok, "the control: reading a damaged note fails");
    assert!(broken.stderr.contains("internal"), "{}", broken.stderr);

    // A notes-only grantee cannot repair it (no list for the fallback) and is told
    // why, with the original error - not a bare capability refusal.
    let notes_only = fx.issue_token("acme", vec![Capability::Notes], Origin::HumanUi);
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&notes_only),
        Some(b"fresh"),
    );
    assert!(!out.ok);
    assert!(out.stderr.contains("internal"), "{}", out.stderr);
    assert!(!note_file.exists());

    // An owner (list + notes) repairs it by writing.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "set", "acme"],
        Some(&owner),
        Some(b"fresh start\n"),
    );
    assert!(out.ok, "{}", out.all());
    assert!(note_file.exists());
    let shown = run(
        &fx,
        &fx.acme_workdir,
        &["notes", "show", "acme"],
        Some(&owner),
        None,
    );
    assert_eq!(shown.stdout, "fresh start\n");
}

// ---- help -----------------------------------------------------------------

#[test]
fn help_documents_every_new_command_and_policy_flag() {
    let out = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .arg("help")
        .output()
        .expect("launch credmgr");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "credmgr import <file|-> --node <id>",
        "credmgr node rename <id> <label>",
        "credmgr node policy <id> --reason",
        "--agent-access read-write|read-only|none",
        "--require-two-factor never|reveal|always",
        "--lock-after-seconds <n>|none",
        "--private-names|--no-private-names",
        "--sibling-visibility shared|isolated",
        "--descendant-read|--no-descendant-read",
        "credmgr notes show <id>",
        "credmgr notes set <id> [--file <path>]",
        "credmgr notes clear <id>",
        "credmgr generate [--length <n>] [--no-symbols] [--pronounceable] [--json]",
        "credmgr approve <request> [--deny] [--code <n>]",
        "credmgr approvals [<request>] [--json]",
        "--purge-expired-seals",
        "values are never printed",
        "empty input is",
        "`set` never deletes",
    ] {
        assert!(help.contains(needle), "`credmgr help` is missing: {needle}");
    }
}

// ---- Part 4 parity: generate, approve, doctor --purge-expired-seals, name warnings -----

#[test]
fn generate_prints_only_the_password_on_stdout_and_the_strength_on_stderr() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let out = run(&fx, &fx.acme_workdir, &["generate"], Some(&owner), None);
    assert!(out.ok, "{}", out.stderr);
    let value = out.stdout.strip_suffix('\n').expect("one line");
    assert_eq!(value.len(), 20, "{value}");
    assert!(!value.contains(char::is_whitespace));
    assert!(
        out.stderr
            .contains("20 characters, about 124 bits of entropy"),
        "{}",
        out.stderr
    );
    assert!(
        !out.stderr.contains(value),
        "the value is printed once, on stdout"
    );

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["generate", "--length", "32", "--no-symbols", "--json"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.stderr);
    let json: Value = serde_json::from_str(out.stdout.trim()).unwrap();
    assert_eq!(json["length"], 32);
    assert_eq!(json["symbols"], false);
    assert!(json["value"]
        .as_str()
        .unwrap()
        .bytes()
        .all(|b| b.is_ascii_alphanumeric()));

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["generate", "--pronounceable", "--length", "20"],
        Some(&owner),
        None,
    );
    assert!(
        out.ok && out.stdout.trim_end().matches('-').count() == 4,
        "{}",
        out.stdout
    );
}

#[test]
fn generate_refuses_a_bad_length_and_a_stray_argument_without_calling_for_a_value() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    for args in [
        &["generate", "--length", "7"][..],
        &["generate", "--length", "129"],
        &["generate", "--length", "many"],
    ] {
        let out = run(&fx, &fx.acme_workdir, args, Some(&owner), None);
        assert!(!out.ok, "{args:?}");
        assert!(
            out.stdout.is_empty(),
            "no value on a refusal: {}",
            out.stdout
        );
        assert!(
            out.stderr.contains('8') && out.stderr.contains("128"),
            "{}",
            out.stderr
        );
    }
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["generate", "extra"],
        Some(&owner),
        None,
    );
    assert!(
        !out.ok && out.stderr.contains("usage: credmgr generate"),
        "{}",
        out.stderr
    );
}

#[test]
fn a_look_alike_of_an_existing_name_is_refused_and_a_mixed_script_name_is_warned_about() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    // DEPLOY_TOKEN with a Cyrillic O (U+041E) is a twin of the existing entry.
    let twin = "DEPLOY_TOKEN".replace('O', "\u{041E}");
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["set", &twin, "--node", "acme"],
        Some(&owner),
        Some(b"x"),
    );
    assert!(!out.ok, "{}", out.all());
    assert!(out.stderr.contains("entry_exists"), "{}", out.stderr);
    // A mixed-script name that is NOT a twin is accepted, with a warning on stderr.
    let mixed = "p\u{0430}yroll";
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["set", mixed, "--node", "acme"],
        Some(&owner),
        Some(b"x"),
    );
    assert!(out.ok, "{}", out.all());
    assert!(out.stdout.contains("saved"), "{}", out.stdout);
    assert!(
        out.stderr
            .contains("warning: that name mixes Latin letters with Greek or Cyrillic"),
        "{}",
        out.stderr
    );
    // A plain name draws no warning.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["set", "PLAIN_NAME", "--node", "acme"],
        Some(&owner),
        Some(b"x"),
    );
    assert!(out.ok && !out.stderr.contains("warning"), "{}", out.all());
}

#[test]
fn approve_reads_the_passphrase_from_stdin_never_sends_the_token_and_explains_its_refusals() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    // No request given: usage.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["approve"],
        Some(&owner),
        Some(b"pw\n"),
    );
    assert!(
        !out.ok && out.stderr.contains("usage: credmgr approve"),
        "{}",
        out.stderr
    );
    // The fixture vault is not a locked disk vault: the broker says the factor path is for a locked vault.
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["approve", "rq_nothing", "--code", "000000"],
        Some(&owner),
        Some(format!("{PASSPHRASE}\n").as_bytes()),
    );
    assert!(!out.ok, "{}", out.all());
    assert!(out.stderr.contains("locked"), "{}", out.stderr);
    assert!(
        !out.all().contains(PASSPHRASE),
        "the passphrase is never echoed"
    );
}

#[test]
fn doctor_takes_the_purge_flag_and_help_lists_it() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["doctor", "--dry-run", "--purge-expired-seals", "--json"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.all());
    let json: Value = serde_json::from_str(out.stdout.trim()).unwrap();
    assert_eq!(json["applied"], false);
}

#[test]
fn a_waiting_request_prints_the_id_credmgr_approve_takes() {
    let fx = start_fixture_broker();
    fx.state.lock_node("acme");
    let out = run(
        &fx,
        &fx.acme_workdir,
        &["get", "DEPLOY_TOKEN", "--node", "acme"],
        None,
        None,
    );
    assert!(!out.ok, "{}", out.all());
    assert!(out.stderr.contains("approval_pending"), "{}", out.stderr);
    let id = out
        .stderr
        .split("request: ")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .expect("a request id");
    assert!(id.starts_with("rq_") && id.len() == 35, "{id}");
    assert!(
        out.stderr.contains(&format!("credmgr approve {id}")),
        "{}",
        out.stderr
    );
}

#[test]
fn approvals_lists_what_is_waiting_for_the_owner_and_status_counts_it() {
    let fx = start_fixture_broker();
    let owner = fx.owner();
    // The owner's login is a real session (the fixture token is registered as one).
    fx.state.register_session_token(&owner, 1_800_000_000);
    fx.state.lock_node("acme");
    let asked = run(
        &fx,
        &fx.acme_workdir,
        &["get", "DEPLOY_TOKEN", "--node", "acme"],
        None,
        None,
    );
    let id = asked
        .stderr
        .split("request: ")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .expect("a request id")
        .to_string();

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["approvals", "--json"],
        Some(&owner),
        None,
    );
    assert!(out.ok, "{}", out.all());
    let json: Value = serde_json::from_str(out.stdout.trim()).unwrap();
    assert_eq!(json["pending"][0]["request"], id.as_str());
    assert_eq!(json["pending"][0]["node"], "acme");
    assert_eq!(json["pending"][0]["command"], "entry.reveal");

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["approvals", &id],
        Some(&owner),
        None,
    );
    assert!(
        out.ok && out.stdout.contains(&id) && out.stdout.contains("node"),
        "{}",
        out.all()
    );

    // A token-less caller is not the owner while the vault is unlocked.
    let out = run(&fx, &fx.acme_workdir, &["approvals"], None, None);
    assert!(!out.ok, "{}", out.all());

    let out = run(&fx, &fx.acme_workdir, &["status"], None, None);
    assert!(
        out.ok && out.stdout.contains("approvals waiting: 1"),
        "{}",
        out.all()
    );

    let out = run(
        &fx,
        &fx.acme_workdir,
        &["approvals", "a", "b"],
        Some(&owner),
        None,
    );
    assert!(
        !out.ok && out.stderr.contains("usage: credmgr approvals"),
        "{}",
        out.all()
    );
}
