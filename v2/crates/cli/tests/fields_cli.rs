//! The multi-field CLI and the MCP tools that go with it (ADR-078, work package
//! C2a): `credmgr set --bulk`, `get --field/--all/--json`, `rotate --field`,
//! `credmgr field ls|add|set|rm|mv`, and `credmgr_create` / `credmgr_get_metadata`
//! / `credmgr_get` / `credmgr_field_*` / `credmgr_totp_code` over the real
//! `credmgr mcp` subprocess.
//!
//! Same shape as `cli_parity.rs` on purpose: the REAL compiled `credmgr` binary
//! as a subprocess against a REAL broker (`BrokerState` served on a real
//! temporary socket by `server::run`). Every "it changed" assertion reads back
//! through the binary; none trusts a command's own success message. Every
//! secret-shaped fixture value below is a generated placeholder.
//!
//! What this file pins, beyond "the commands work":
//! - **a value never travels in argv** - every argv shape that could carry one
//!   (`--value`, a stray positional, on every command that writes) is refused
//!   and changes nothing (`no_secret_in_argv.rs` is the structural half);
//! - **nothing prints a value it was not asked to** - `field ls`, the refusal of
//!   an unaddressed `get`, and `set --bulk` never put a value on the terminal;
//! - **an alpha.6 entry reads unchanged and the first field edit upgrades it**.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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
/// An entry written the way alpha.6 wrote every entry: a version-1 envelope
/// holding one raw value, and no label anywhere.
const LEGACY_ID: &str = "e_legacy01";
const LEGACY_VALUE: &str = "s3cr3t-deploy-token";

const V_HOST: &str = "db-7f3a.fields.test";
const V_USER: &str = "svc_91c2";
const V_PASS: &str = "pw-b04e77d1";
const V_NOTE: &str = "note 5d21 with spaces";
const VALUES: [&str; 4] = [V_HOST, V_USER, V_PASS, V_NOTE];

fn bulk_text() -> String {
    format!("host: {V_HOST}\nusername: {V_USER}\npassword: {V_PASS}\nnotes: {V_NOTE}\n")
}

struct Fixture {
    vault_dir: PathBuf,
    acme_workdir: PathBuf,
    state: Arc<BrokerState>,
    paths: VaultPaths,
    _tmp: tempfile::TempDir,
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
                    Capability::Admin,
                ],
                Origin::HumanUi,
                None,
            )
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

    let sealed = envelope::seal(LEGACY_VALUE.as_bytes(), &acme_pub, "acme", LEGACY_ID).unwrap();
    credmgr_store::atomic::write(&paths.entry_env("acme", LEGACY_ID), &sealed).unwrap();
    let mut manifest = ManifestBody::new("acme");
    manifest.entries.push(ManifestEntry {
        id: LEGACY_ID.to_string(),
        name: "OLD_PASS".to_string(),
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
                paths,
                _tmp: tmp,
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("credmgrd fixture never opened its socket");
}

struct Out {
    ok: bool,
    /// The process exit status (`None` if it was killed by a signal).
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Out {
    fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
    fn leaks(&self, values: &[&str]) -> bool {
        let all = self.all();
        values.iter().any(|v| all.contains(v))
    }
}

/// Runs the real binary. `stdin: None` is `/dev/null` (an empty read).
fn run(fx: &Fixture, token: &str, args: &[&str], stdin: Option<&str>) -> Out {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_credmgr"));
    cmd.args(args)
        .current_dir(&fx.acme_workdir)
        .env("CREDMGR_VAULT_DIR", &fx.vault_dir)
        .env("CREDMGR_TOKEN", token)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("launch credmgr");
    if let Some(text) = stdin {
        // A command that refuses before reading stdin may close the pipe first.
        let mut pipe = child.stdin.take().unwrap();
        let _ = pipe.write_all(text.as_bytes());
    }
    let output = child.wait_with_output().unwrap();
    Out {
        ok: output.status.success(),
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn ok(fx: &Fixture, token: &str, args: &[&str], stdin: Option<&str>) -> Out {
    let out = run(fx, token, args, stdin);
    assert!(
        out.ok,
        "`credmgr {}` failed: {}",
        args.join(" "),
        out.stderr
    );
    out
}

/// `field ls --json`: the entry's metadata. Never carries a value.
fn meta(fx: &Fixture, token: &str, name: &str) -> Value {
    let out = ok(
        fx,
        token,
        &["field", "ls", name, "--node", "acme", "--json"],
        None,
    );
    serde_json::from_str(&out.stdout).unwrap_or_else(|e| panic!("bad json {:?}: {e}", out.stdout))
}

fn labels(meta: &Value) -> Vec<String> {
    meta["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["label"].as_str().unwrap().to_string())
        .collect()
}

fn id_of(meta: &Value, label: &str) -> String {
    meta["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .unwrap_or_else(|| panic!("no field {label:?} in {meta}"))["id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn get_field(fx: &Fixture, token: &str, name: &str, label: &str) -> String {
    let out = ok(
        fx,
        token,
        &["get", name, "--node", "acme", "--field", label],
        None,
    );
    out.stdout
        .strip_suffix('\n')
        .unwrap_or(&out.stdout)
        .to_string()
}

fn make_prod_db(fx: &Fixture, token: &str) {
    let out = ok(
        fx,
        token,
        &["set", "PROD_DB", "--node", "acme", "--bulk"],
        Some(&bulk_text()),
    );
    assert!(out.stdout.contains("saved (4 fields)"), "{}", out.stdout);
    assert!(
        !out.leaks(&VALUES),
        "set --bulk printed a value: {}",
        out.all()
    );
}

fn envelope_version(fx: &Fixture, entry_id: &str) -> u8 {
    std::fs::read(fx.paths.entry_env("acme", entry_id)).unwrap()[4]
}

fn names(fx: &Fixture, token: &str) -> Vec<String> {
    ok(fx, token, &["list", "--node", "acme"], None)
        .stdout
        .lines()
        .map(str::to_string)
        .collect()
}

// ---- one bulk paste is one entry; every read path agrees ------------------

#[test]
fn a_bulk_paste_is_one_entry_and_every_read_path_agrees() {
    let fx = start_fixture_broker();
    let t = fx.owner();
    make_prod_db(&fx, &t);

    let listed = names(&fx, &t);
    assert_eq!(
        listed.iter().filter(|n| *n == "PROD_DB").count(),
        1,
        "{listed:?}"
    );

    // `field ls` shows the labels in the order pasted - and never a value.
    let m = meta(&fx, &t, "PROD_DB");
    assert_eq!(labels(&m), ["host", "username", "password", "notes"]);
    assert_eq!(m["fieldCount"], 4);
    for f in m["fields"].as_array().unwrap() {
        let id = f["id"].as_str().unwrap();
        assert!(
            id.len() == 10
                && id.starts_with("f_")
                && id[2..].chars().all(|c| c.is_ascii_hexdigit()),
            "a field id looks like f_ and 8 hex digits: {id}"
        );
    }
    let text = ok(&fx, &t, &["field", "ls", "PROD_DB", "--node", "acme"], None);
    assert!(
        text.stdout.contains("4 fields") && text.stdout.contains("password"),
        "{}",
        text.stdout
    );
    assert!(
        !text.leaks(&VALUES),
        "field ls printed a value: {}",
        text.all()
    );
    assert!(
        !serde_json::to_string(&m).unwrap().contains(V_PASS),
        "entry.get carries no value"
    );

    // One field by label, case-insensitively, and by id.
    assert_eq!(get_field(&fx, &t, "PROD_DB", "password"), V_PASS);
    assert_eq!(get_field(&fx, &t, "PROD_DB", "PASSWORD"), V_PASS);
    let id = id_of(&m, "username");
    let by_id = ok(
        &fx,
        &t,
        &["get", "PROD_DB", "--node", "acme", "--field-id", &id],
        None,
    );
    assert_eq!(by_id.stdout, format!("{V_USER}\n"));

    // No selector on a four-field entry: refused, naming the labels, printing nothing.
    let bare = run(&fx, &t, &["get", "PROD_DB", "--node", "acme"], None);
    assert!(!bare.ok);
    assert_eq!(
        bare.code,
        Some(2),
        "'name the field' exits 2, not the 1 of 'the vault said no'"
    );
    assert!(
        bare.stderr.contains("4 fields")
            && bare.stderr.contains("host, username, password, notes")
            && bare.stderr.contains("--field"),
        "{}",
        bare.stderr
    );
    assert!(
        !bare.leaks(&VALUES),
        "the refusal printed a value: {}",
        bare.all()
    );

    // --all is the paste form back, exactly; --json is the exact form.
    let all = ok(
        &fx,
        &t,
        &["get", "PROD_DB", "--node", "acme", "--all"],
        None,
    );
    assert_eq!(all.stdout, bulk_text());
    let json = ok(
        &fx,
        &t,
        &["get", "PROD_DB", "--node", "acme", "--json"],
        None,
    );
    let rows: Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 4);
    assert_eq!(rows[2]["label"], "password");
    assert_eq!(rows[2]["value"], V_PASS);
    assert_eq!(rows[2]["type"], "password");
    assert_eq!(rows[2]["masked"], true);

    // Combinations that cannot be meant are refused, an unknown label lists the real ones.
    let both = run(
        &fx,
        &t,
        &[
            "get", "PROD_DB", "--node", "acme", "--all", "--field", "host",
        ],
        None,
    );
    assert!(
        !both.ok && both.stderr.contains("cannot be combined"),
        "{}",
        both.stderr
    );
    let unknown = run(
        &fx,
        &t,
        &["get", "PROD_DB", "--node", "acme", "--field", "nope"],
        None,
    );
    assert!(!unknown.ok);
    assert_eq!(
        unknown.code,
        Some(2),
        "a label that matches nothing is the same kind of refusal"
    );
    assert!(
        unknown.stderr.contains("no field labelled 'nope'")
            && unknown.stderr.contains("host, username, password, notes"),
        "{}",
        unknown.stderr
    );
}

// ---- changing one field, rotating one field, replacing all of them --------

#[test]
fn set_and_rotate_address_one_field_and_a_bare_set_on_several_fields_is_refused() {
    let fx = start_fixture_broker();
    let t = fx.owner();
    make_prod_db(&fx, &t);

    // A plain `set` on a four-field entry would have to guess which one.
    let bare = run(&fx, &t, &["set", "PROD_DB", "--node", "acme"], Some("x"));
    assert!(!bare.ok);
    assert_eq!(
        bare.code,
        Some(1),
        "the broker's refusal is an ordinary failure"
    );
    assert!(
        bare.stderr.contains("4 fields")
            && bare.stderr.contains("--field <label>")
            && bare.stderr.contains("credmgr field ls PROD_DB"),
        "{}",
        bare.stderr
    );
    let bare = run(&fx, &t, &["rotate", "PROD_DB", "--node", "acme"], Some("x"));
    assert!(
        !bare.ok && bare.stderr.contains("--field <label>"),
        "{}",
        bare.stderr
    );
    assert_eq!(
        ok(
            &fx,
            &t,
            &["get", "PROD_DB", "--node", "acme", "--all"],
            None
        )
        .stdout,
        bulk_text(),
        "a refused write changed nothing"
    );

    // set --field changes one value and keeps every other field.
    ok(
        &fx,
        &t,
        &["set", "PROD_DB", "--node", "acme", "--field", "password"],
        Some("pw-second-1111"),
    );
    assert_eq!(get_field(&fx, &t, "PROD_DB", "password"), "pw-second-1111");
    assert_eq!(get_field(&fx, &t, "PROD_DB", "host"), V_HOST);
    assert_eq!(get_field(&fx, &t, "PROD_DB", "notes"), V_NOTE);
    assert_eq!(
        labels(&meta(&fx, &t, "PROD_DB")),
        ["host", "username", "password", "notes"],
        "the field list and its order are untouched"
    );

    // rotate --field changes one value, and says so.
    let rotated = ok(
        &fx,
        &t,
        &["rotate", "PROD_DB", "--node", "acme", "--field", "username"],
        Some("svc_rotated_2"),
    );
    assert!(rotated.stdout.starts_with("rotated"), "{}", rotated.stdout);
    assert_eq!(get_field(&fx, &t, "PROD_DB", "username"), "svc_rotated_2");
    assert_eq!(get_field(&fx, &t, "PROD_DB", "password"), "pw-second-1111");

    // set --field on a name that does not exist does not create it.
    let missing = run(
        &fx,
        &t,
        &["set", "NO_SUCH", "--node", "acme", "--field", "x"],
        Some("v"),
    );
    assert!(
        !missing.ok && missing.stderr.contains("no entry named 'NO_SUCH'"),
        "{}",
        missing.stderr
    );
    assert!(!names(&fx, &t).contains(&"NO_SUCH".to_string()));

    // --bulk on an existing name replaces the whole field list.
    ok(
        &fx,
        &t,
        &["set", "PROD_DB", "--node", "acme", "--bulk"],
        Some("region: eu-central-1\n"),
    );
    assert_eq!(labels(&meta(&fx, &t, "PROD_DB")), ["region"]);

    // --bulk takes its labels from the text; a selector or --label beside it is a contradiction.
    for extra in [["--field", "region"], ["--label", "region"]] {
        let mut args = vec!["set", "PROD_DB", "--node", "acme", "--bulk"];
        args.extend(extra);
        let out = run(&fx, &t, &args, Some("a: b\n"));
        assert!(
            !out.ok && out.stderr.contains("cannot be combined"),
            "{}",
            out.stderr
        );
    }
    // ...and an input with no fields at all stores nothing.
    let empty = run(
        &fx,
        &t,
        &["set", "EMPTY_ONE", "--node", "acme", "--bulk"],
        Some("\n\n"),
    );
    assert!(
        !empty.ok && empty.stderr.contains("no fields"),
        "{}",
        empty.stderr
    );
    assert!(!names(&fx, &t).contains(&"EMPTY_ONE".to_string()));
}

#[test]
fn a_plain_set_keeps_its_label_and_a_one_field_entry_prints_its_value() {
    let fx = start_fixture_broker();
    let t = fx.owner();
    let created = ok(
        &fx,
        &t,
        &["set", "API_TOKEN", "--node", "acme", "--label", "token"],
        Some("tok-one-aaaa"),
    );
    assert!(created.stdout.trim() == "saved", "{}", created.stdout);
    assert_eq!(
        labels(&meta(&fx, &t, "API_TOKEN")),
        ["token"],
        "the label is stored now"
    );
    // A one-field entry needs no selector: `get` prints the value, as it always did.
    let got = ok(&fx, &t, &["get", "API_TOKEN", "--node", "acme"], None);
    assert_eq!(got.stdout, "tok-one-aaaa\n");
    // Updating it keeps the field; --label renames it.
    ok(
        &fx,
        &t,
        &["set", "API_TOKEN", "--node", "acme", "--label", "key"],
        Some("tok-two-bbbb"),
    );
    assert_eq!(labels(&meta(&fx, &t, "API_TOKEN")), ["key"]);
    assert_eq!(
        ok(&fx, &t, &["get", "API_TOKEN", "--node", "acme"], None).stdout,
        "tok-two-bbbb\n"
    );
}

// ---- field add / set / mv / rm, and undo ----------------------------------

#[test]
fn field_add_set_mv_rm_and_undo_round_trip() {
    let fx = start_fixture_broker();
    let t = fx.owner();
    make_prod_db(&fx, &t);

    // add one at position 0
    let added = ok(
        &fx,
        &t,
        &[
            "field", "add", "PROD_DB", "--node", "acme", "--label", "region", "--at", "0",
        ],
        Some("eu-west-1"),
    );
    assert!(added.stdout.contains("added 1 field"), "{}", added.stdout);
    assert_eq!(
        labels(&meta(&fx, &t, "PROD_DB")),
        ["region", "host", "username", "password", "notes"]
    );
    assert_eq!(get_field(&fx, &t, "PROD_DB", "region"), "eu-west-1");

    // add several, appended, from the paste form
    let bulk = ok(
        &fx,
        &t,
        &["field", "add", "PROD_DB", "--node", "acme", "--bulk"],
        Some("k1: v-one\nk2: v-two\n"),
    );
    assert!(bulk.stdout.contains("added 2 fields"), "{}", bulk.stdout);
    let m = meta(&fx, &t, "PROD_DB");
    assert_eq!(m["fieldCount"], 7);
    assert_eq!(labels(&m)[5..], ["k1", "k2"]);

    // mv
    ok(
        &fx,
        &t,
        &[
            "field", "mv", "PROD_DB", "--node", "acme", "--field", "region", "--to", "3",
        ],
        None,
    );
    assert_eq!(labels(&meta(&fx, &t, "PROD_DB"))[3], "region");
    let far = run(
        &fx,
        &t,
        &[
            "field", "mv", "PROD_DB", "--node", "acme", "--field", "region", "--to", "99",
        ],
        None,
    );
    assert!(
        !far.ok && far.stderr.contains("out of range"),
        "{}",
        far.stderr
    );

    // set: rename, retype, mask - and "auto" goes back to inferring
    ok(
        &fx,
        &t,
        &[
            "field", "set", "PROD_DB", "--node", "acme", "--field", "region", "--label", "zone",
            "--type", "text", "--mask", "on",
        ],
        None,
    );
    let m = meta(&fx, &t, "PROD_DB");
    let zone = m["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "zone")
        .unwrap()
        .clone();
    assert_eq!(zone["type"], "text");
    assert_eq!(zone["masked"], true);
    assert_eq!(zone["typeOverridden"], true);
    assert_eq!(zone["maskedOverridden"], true);
    assert_eq!(
        get_field(&fx, &t, "PROD_DB", "zone"),
        "eu-west-1",
        "the value did not move"
    );
    ok(
        &fx,
        &t,
        &[
            "field",
            "set",
            "PROD_DB",
            "--node",
            "acme",
            "--field-id",
            zone["id"].as_str().unwrap(),
            "--type",
            "auto",
            "--mask",
            "auto",
        ],
        None,
    );
    let m = meta(&fx, &t, "PROD_DB");
    let zone = m["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "zone")
        .unwrap();
    assert_eq!(zone["typeOverridden"], false);
    assert_eq!(zone["maskedOverridden"], false);

    // field set never takes a value, and a patch with nothing in it is refused
    let nothing = run(
        &fx,
        &t,
        &[
            "field", "set", "PROD_DB", "--node", "acme", "--field", "zone",
        ],
        None,
    );
    assert!(
        !nothing.ok && nothing.stderr.contains("nothing to change"),
        "{}",
        nothing.stderr
    );
    let bad_type = run(
        &fx,
        &t,
        &[
            "field", "set", "PROD_DB", "--node", "acme", "--field", "zone", "--type", "bogus",
        ],
        None,
    );
    assert!(
        !bad_type.ok && bad_type.stderr.contains("--type takes"),
        "{}",
        bad_type.stderr
    );

    // rm prints the audit id; undo puts the field back with its value
    let removed = ok(
        &fx,
        &t,
        &[
            "field", "rm", "PROD_DB", "--node", "acme", "--field", "username",
        ],
        None,
    );
    assert!(
        removed.stdout.contains("it now has 6 fields"),
        "{}",
        removed.stdout
    );
    assert!(
        !removed.leaks(&VALUES),
        "field rm printed a value: {}",
        removed.all()
    );
    let audit = removed
        .stdout
        .split_whitespace()
        .find(|w| w.len() == 14 && w.starts_with("a_"))
        .unwrap_or_else(|| panic!("no audit id in {:?}", removed.stdout))
        .to_string();
    assert!(removed
        .stdout
        .contains(&format!("credmgr undo {audit} --node acme")));
    assert!(!labels(&meta(&fx, &t, "PROD_DB")).contains(&"username".to_string()));
    ok(&fx, &t, &["undo", &audit, "--node", "acme"], None);
    assert_eq!(get_field(&fx, &t, "PROD_DB", "username"), V_USER);
    assert_eq!(meta(&fx, &t, "PROD_DB")["fieldCount"], 7);

    // an entry keeps at least one field
    ok(
        &fx,
        &t,
        &["set", "ONE", "--node", "acme", "--label", "only"],
        Some("v"),
    );
    let last = run(
        &fx,
        &t,
        &["field", "rm", "ONE", "--node", "acme", "--field", "only"],
        None,
    );
    assert!(
        !last.ok && last.stderr.contains("at least one field"),
        "{}",
        last.stderr
    );
}

#[test]
fn two_fields_with_one_label_are_told_apart_by_id_never_guessed() {
    let fx = start_fixture_broker();
    let t = fx.owner();
    ok(
        &fx,
        &t,
        &["set", "DUP", "--node", "acme", "--bulk"],
        Some("note: first-aaa\nnote: second-bbb\n"),
    );
    let m = meta(&fx, &t, "DUP");
    assert_eq!(labels(&m), ["note", "note"]);
    let ids: Vec<String> = m["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();
    assert_ne!(ids[0], ids[1]);

    let by_label = run(
        &fx,
        &t,
        &["get", "DUP", "--node", "acme", "--field", "note"],
        None,
    );
    assert!(!by_label.ok);
    assert_eq!(
        by_label.code,
        Some(2),
        "an ambiguous label is a selection refusal"
    );
    assert!(
        by_label.stderr.contains("2 fields labelled 'note'")
            && by_label.stderr.contains("--field-id")
            && by_label.stderr.contains(&ids[0])
            && by_label.stderr.contains(&ids[1]),
        "{}",
        by_label.stderr
    );
    assert!(!by_label.leaks(&["first-aaa", "second-bbb"]));
    for (id, expected) in ids.iter().zip(["first-aaa", "second-bbb"]) {
        let out = ok(
            &fx,
            &t,
            &["get", "DUP", "--node", "acme", "--field-id", id],
            None,
        );
        assert_eq!(out.stdout, format!("{expected}\n"));
    }
    // a write by the ambiguous label is refused too
    let write = run(
        &fx,
        &t,
        &["field", "rm", "DUP", "--node", "acme", "--field", "note"],
        None,
    );
    assert!(
        !write.ok && write.stderr.contains("--field-id"),
        "{}",
        write.stderr
    );
    assert_eq!(meta(&fx, &t, "DUP")["fieldCount"], 2);
}

// ---- an alpha.6 entry ------------------------------------------------------

#[test]
fn an_alpha6_entry_reads_unchanged_and_the_first_field_edit_upgrades_it() {
    let fx = start_fixture_broker();
    let t = fx.owner();
    assert_eq!(
        envelope_version(&fx, LEGACY_ID),
        envelope::VERSION,
        "the fixture entry is a version-1 envelope, as alpha.6 wrote it"
    );

    // Read in place: the same value, one field, no label, nothing rewritten.
    assert_eq!(
        ok(&fx, &t, &["get", "OLD_PASS", "--node", "acme"], None).stdout,
        format!("{LEGACY_VALUE}\n")
    );
    let m = meta(&fx, &t, "OLD_PASS");
    assert_eq!(labels(&m), [""], "alpha.6 kept no label");
    assert_eq!(
        m["sensitivity"], "high",
        "what the manifest showed, it still shows"
    );
    assert_eq!(m["type"], "token");
    assert_eq!(
        m["fields"][0]["masked"], true,
        "an old high-sensitivity value stays masked"
    );
    let text = ok(
        &fx,
        &t,
        &["field", "ls", "OLD_PASS", "--node", "acme"],
        None,
    );
    assert!(text.stdout.contains("(no label)"), "{}", text.stdout);
    assert_eq!(
        ok(
            &fx,
            &t,
            &["get", "OLD_PASS", "--node", "acme", "--all"],
            None
        )
        .stdout,
        format!("{LEGACY_VALUE}\n"),
        "an unlabelled value prints as itself"
    );
    assert_eq!(
        envelope_version(&fx, LEGACY_ID),
        envelope::VERSION,
        "reading rewrites nothing"
    );

    // The first edit re-seals it as a field document; the old value survives it.
    ok(
        &fx,
        &t,
        &[
            "field", "add", "OLD_PASS", "--node", "acme", "--label", "backup",
        ],
        Some("more-1234"),
    );
    assert_eq!(
        envelope_version(&fx, LEGACY_ID),
        envelope::VERSION_FIELD_DOCUMENT
    );
    let all = ok(
        &fx,
        &t,
        &["get", "OLD_PASS", "--node", "acme", "--all"],
        None,
    );
    assert!(
        all.stdout.contains(LEGACY_VALUE) && all.stdout.contains("backup: more-1234"),
        "{}",
        all.stdout
    );
    let m = meta(&fx, &t, "OLD_PASS");
    assert_eq!(m["sensitivity"], "high");
    assert_eq!(m["type"], "token");
    assert_eq!(m["fieldCount"], 2);
}

// ---- a value never travels in argv -----------------------------------------

#[test]
fn no_argv_shape_carries_a_value_and_a_refused_one_changes_nothing() {
    let fx = start_fixture_broker();
    let t = fx.owner();
    make_prod_db(&fx, &t);
    const S: &str = "argv-sentinel-4d2f";

    // Every command that writes, with the sentinel where a value could go:
    // after a `--value` flag, and as a stray positional. None may be accepted.
    let shapes: Vec<Vec<&str>> = vec![
        vec!["set", "PROD_DB", "--node", "acme", "--value", S],
        vec!["set", "PROD_DB", "--node", "acme", S],
        vec![
            "set", "PROD_DB", "--node", "acme", "--field", "host", "--value", S,
        ],
        vec!["set", "PROD_DB", "--node", "acme", "--bulk", S],
        vec![
            "rotate", "PROD_DB", "--node", "acme", "--field", "host", "--value", S,
        ],
        vec!["rotate", "PROD_DB", "--node", "acme", "--field", "host", S],
        vec![
            "field", "add", "PROD_DB", "--node", "acme", "--label", "extra", "--value", S,
        ],
        vec![
            "field", "add", "PROD_DB", "--node", "acme", "--label", "extra", S,
        ],
        vec!["field", "add", "PROD_DB", "--node", "acme", "--bulk", S],
        vec![
            "field", "set", "PROD_DB", "--node", "acme", "--field", "host", "--value", S,
        ],
        vec![
            "field", "set", "PROD_DB", "--node", "acme", "--field", "host", S,
        ],
        vec![
            "field", "set", "PROD_DB", "--node", "acme", "--field", "host", "--secret", S,
        ],
        vec![
            "field", "rm", "PROD_DB", "--node", "acme", "--field", "host", S,
        ],
        vec![
            "field", "mv", "PROD_DB", "--node", "acme", "--field", "host", "--to", "1", S,
        ],
        vec!["field", "ls", "PROD_DB", "--node", "acme", S],
        vec!["get", "PROD_DB", "--node", "acme", "--field", "host", S],
    ];
    for args in &shapes {
        let out = run(&fx, &t, args, None);
        assert!(
            !out.ok,
            "`credmgr {}` was accepted - a value must come from stdin only",
            args.join(" ")
        );
        assert!(
            !out.stdout.contains(S),
            "`credmgr {}` echoed the argv value to stdout",
            args.join(" ")
        );
    }
    assert_eq!(
        ok(
            &fx,
            &t,
            &["get", "PROD_DB", "--node", "acme", "--all"],
            None
        )
        .stdout,
        bulk_text(),
        "no refused command changed the entry"
    );
    assert_eq!(
        names(&fx, &t).len(),
        2,
        "...or created another: {:?}",
        names(&fx, &t)
    );
    assert_eq!(meta(&fx, &t, "PROD_DB")["fieldCount"], 4);
}

// ---- a locked bulk write ----------------------------------------------------

#[test]
fn a_locked_bulk_write_lands_in_the_tray_with_its_field_count_and_accepting_keeps_every_field() {
    let fx = start_fixture_broker();
    let t = fx.owner();
    fx.state.lock();

    let held = ok(
        &fx,
        &t,
        &["set", "TRAY_DB", "--node", "acme", "--bulk"],
        Some(&bulk_text()),
    );
    assert!(held.stdout.contains("(4 fields)"), "{}", held.stdout);
    assert!(held.stdout.contains("credmgr pending"), "{}", held.stdout);
    assert!(!held.leaks(&VALUES));

    fx.state.unlock(0).expect("fixture re-unlock");
    let t = fx.owner();
    let tray = ok(&fx, &t, &["pending", "--node", "acme"], None);
    let line = tray
        .stdout
        .lines()
        .find(|l| l.contains("TRAY_DB"))
        .unwrap_or_else(|| panic!("TRAY_DB is not in the tray: {}", tray.stdout));
    assert!(line.contains("(4 fields)"), "{line}");
    assert!(
        !tray.leaks(&VALUES),
        "the tray listing printed a value: {}",
        tray.all()
    );
    let entry = line.split_whitespace().nth(1).unwrap().to_string();

    ok(
        &fx,
        &t,
        &["pending", "accept", &entry, "--node", "acme"],
        None,
    );
    assert_eq!(get_field(&fx, &t, "TRAY_DB", "password"), V_PASS);
    let m = meta(&fx, &t, "TRAY_DB");
    assert_eq!(labels(&m), ["host", "username", "password", "notes"]);
    assert_eq!(m["fieldCount"], 4);
}

// ---- MCP: the tools an agent gets -------------------------------------------

/// Spawns `credmgr mcp` (scoped to the fixture's project by its working
/// directory, like an agent), sends one `tools/call`, and returns `(isError,
/// the tool's JSON answer or its error text)`.
fn mcp(fx: &Fixture, tool: &str, arguments: Value) -> (bool, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .arg("mcp")
        .current_dir(&fx.acme_workdir)
        .env("CREDMGR_VAULT_DIR", &fx.vault_dir)
        .env_remove("CREDMGR_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch credmgr mcp");
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": tool, "arguments": arguments },
    });
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{request}").unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap()
        .to_string();
    let response: Value = serde_json::from_str(&line).unwrap();
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    let is_error = response["result"]["isError"].as_bool().unwrap();
    if is_error {
        (true, Value::String(text))
    } else {
        (false, serde_json::from_str(&text).unwrap())
    }
}

fn mcp_ok(fx: &Fixture, tool: &str, arguments: Value) -> Value {
    let (is_error, value) = mcp(fx, tool, arguments);
    assert!(!is_error, "{tool} failed: {value}");
    value
}

fn mcp_generation(fx: &Fixture) -> u64 {
    mcp_ok(fx, "credmgr_list", json!({ "node": "acme" }))["generation"]
        .as_u64()
        .unwrap()
}

#[test]
fn an_agent_creates_reads_and_edits_a_multi_field_entry_through_the_mcp_tools() {
    let fx = start_fixture_broker();

    // credmgr_create with `fields`: structure, not the paste grammar.
    let created = mcp_ok(
        &fx,
        "credmgr_create",
        json!({
            "node": "acme", "name": "AGENT_DB",
            "fields": [
                { "label": "host", "value": V_HOST },
                { "label": "password", "value": V_PASS },
            ],
        }),
    );
    assert_eq!(created["fieldCount"], 2);
    let entry = created["entry"].as_str().unwrap().to_string();
    let ids: Vec<String> = created["fieldIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 2);

    // value AND fields, or neither, is refused - the broker never guesses.
    let (err, text) = mcp(
        &fx,
        "credmgr_create",
        json!({ "node": "acme", "name": "BOTH", "value": "v", "fields": [{ "label": "a", "value": "b" }] }),
    );
    assert!(err, "{text}");
    let (err, _) = mcp(
        &fx,
        "credmgr_create",
        json!({ "node": "acme", "name": "NEITHER" }),
    );
    assert!(err);

    // credmgr_get_metadata: ids, labels, types, masking - never a value.
    let md = mcp_ok(
        &fx,
        "credmgr_get_metadata",
        json!({ "node": "acme", "entry": entry }),
    );
    assert_eq!(md["fieldCount"], 2);
    assert_eq!(md["fields"][1]["label"], "password");
    assert_eq!(md["fields"][1]["masked"], true);
    let md_text = md.to_string();
    assert!(
        !md_text.contains(V_PASS) && !md_text.contains(V_HOST),
        "credmgr_get_metadata carried a value: {md_text}"
    );

    // credmgr_get narrows to `fieldIds`; `value` is present exactly when one field comes back.
    let one = mcp_ok(
        &fx,
        "credmgr_get",
        json!({ "node": "acme", "entry": entry, "fieldIds": [ids[1]] }),
    );
    assert_eq!(one["fields"].as_array().unwrap().len(), 1);
    assert_eq!(one["value"], V_PASS);
    let both = mcp_ok(
        &fx,
        "credmgr_get",
        json!({ "node": "acme", "entry": entry }),
    );
    assert_eq!(both["fields"].as_array().unwrap().len(), 2);
    assert!(
        both.get("value").is_none(),
        "two fields: no single `value`: {both}"
    );
    let (err, _) = mcp(
        &fx,
        "credmgr_get",
        json!({ "node": "acme", "entry": entry, "fieldIds": ["f_deadbeef"] }),
    );
    assert!(
        err,
        "an unknown field id is refused, with no partial answer"
    );

    // credmgr_field_update / _add / _remove, generation-checked.
    let updated = mcp_ok(
        &fx,
        "credmgr_field_update",
        json!({
            "node": "acme", "entry": entry, "generation": mcp_generation(&fx),
            "field": ids[0], "patch": { "label": "hostname", "type": "host" },
        }),
    );
    assert_eq!(updated["fieldCount"], 2);
    let md = mcp_ok(
        &fx,
        "credmgr_get_metadata",
        json!({ "node": "acme", "entry": entry }),
    );
    assert_eq!(md["fields"][0]["label"], "hostname");
    assert_eq!(md["fields"][0]["typeOverridden"], true);

    let added = mcp_ok(
        &fx,
        "credmgr_field_add",
        json!({
            "node": "acme", "entry": entry, "generation": mcp_generation(&fx),
            "fields": [{ "label": "port", "value": "5432" }], "position": 1,
        }),
    );
    assert_eq!(added["fieldCount"], 3);
    assert_eq!(added["added"].as_array().unwrap().len(), 1);
    let md = mcp_ok(
        &fx,
        "credmgr_get_metadata",
        json!({ "node": "acme", "entry": entry }),
    );
    assert_eq!(
        md["fields"][1]["label"], "port",
        "inserted at the position asked"
    );

    let removed = mcp_ok(
        &fx,
        "credmgr_field_remove",
        json!({
            "node": "acme", "entry": entry, "generation": mcp_generation(&fx),
            "field": added["added"][0],
        }),
    );
    assert_eq!(removed["fieldCount"], 2);

    // A stale generation is a conflict, not an overwrite.
    let (err, text) = mcp(
        &fx,
        "credmgr_field_remove",
        json!({ "node": "acme", "entry": entry, "generation": 0, "field": ids[1] }),
    );
    assert!(err && text.as_str().unwrap().contains("conflict"), "{text}");

    // credmgr_update takes `fields` too (the whole list), and an override.
    mcp_ok(
        &fx,
        "credmgr_update",
        json!({
            "node": "acme", "entry": entry, "generation": mcp_generation(&fx),
            "fields": [{ "id": ids[1], "label": "password", "value": "pw-replaced-9" }],
            "entryType": "login",
        }),
    );
    let after = mcp_ok(
        &fx,
        "credmgr_get",
        json!({ "node": "acme", "entry": entry }),
    );
    assert_eq!(
        after["value"], "pw-replaced-9",
        "one field left: its value is `value`"
    );

    // field.reorder is not an agent tool.
    let (err, text) = mcp(&fx, "credmgr_field_reorder", json!({}));
    assert!(
        err && text.as_str().unwrap().contains("unknown tool"),
        "{text}"
    );
}

#[test]
fn credmgr_totp_code_takes_a_field_and_refuses_an_ambiguous_entry() {
    let fx = start_fixture_broker();
    const SEED_A: &str = "JBSWY3DPEHPK3PXP";
    const SEED_B: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    // One seed among other fields: found without being named.
    let one = mcp_ok(
        &fx,
        "credmgr_create",
        json!({
            "node": "acme", "name": "TOTP_ONE",
            "fields": [
                { "label": "user", "value": "svc" },
                { "label": "authenticator", "value": SEED_A, "type": "totp-seed" },
            ],
        }),
    );
    let entry = one["entry"].as_str().unwrap();
    let code = mcp_ok(
        &fx,
        "credmgr_totp_code",
        json!({ "node": "acme", "entry": entry }),
    );
    let code_text = code["code"].as_str().unwrap();
    assert!(code_text.len() == 6 && code_text.chars().all(|c| c.is_ascii_digit()));
    assert!(code.get("seed").is_none() && !code.to_string().contains(SEED_A));

    // Two seeds: ambiguous without `field`, answered with it.
    let two = mcp_ok(
        &fx,
        "credmgr_create",
        json!({
            "node": "acme", "name": "TOTP_TWO",
            "fields": [
                { "label": "first", "value": SEED_A, "type": "totp-seed" },
                { "label": "second", "value": SEED_B, "type": "totp-seed" },
            ],
        }),
    );
    let entry = two["entry"].as_str().unwrap();
    let (err, text) = mcp(
        &fx,
        "credmgr_totp_code",
        json!({ "node": "acme", "entry": entry }),
    );
    assert!(
        err && text.as_str().unwrap().contains("pass params.field"),
        "{text}"
    );
    let named = mcp_ok(
        &fx,
        "credmgr_totp_code",
        json!({ "node": "acme", "entry": entry, "field": two["fieldIds"][1] }),
    );
    assert_eq!(named["code"].as_str().unwrap().len(), 6);
    assert!(!named.to_string().contains(SEED_B));
}
