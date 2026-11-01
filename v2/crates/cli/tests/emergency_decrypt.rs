//! Phase 4 exit gate: "`emergency-decrypt.mjs` recovers a value with only
//! the recovery code, and is tested" (`04_CRYPTO_AND_KEYS.md §7`, ADR-045).
//!
//! Builds a real fixture vault on disk using the actual Rust crypto
//! (`recovery::wrap_root_with_recovery_code`, `keys::wrap_node_key`,
//! `envelope::seal`) — not a hand-crafted byte string standing in for what
//! those functions produce — then shells out to the real
//! `scripts/emergency-decrypt.mjs` and asserts the recovered plaintext is
//! byte-identical. This is the proof that Rust-written and JS-read wrap/
//! envelope formats actually agree, not just that each side's own unit
//! tests pass in isolation.

use std::path::PathBuf;
use std::process::Command;

use credmgr_core::envelope;
use credmgr_core::keys::{generate_node_keypair, wrap_node_key};
use credmgr_core::recovery::{
    format_recovery_code, generate_recovery_code, wrap_root_with_recovery_code,
};
use credmgr_store::paths::VaultPaths;

/// `str::trim`-equivalent for a byte slice, without the 1.80+ `trim_ascii_end`
/// this workspace's 1.78 MSRV pin (ADR-035/036) doesn't yet have.
fn trim_trailing_newline(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1] == b'\n' || bytes[end - 1] == b'\r') {
        end -= 1;
    }
    &bytes[..end]
}

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/emergency-decrypt.mjs")
        .canonicalize()
        .expect("scripts/emergency-decrypt.mjs must exist")
}

/// Builds a fixture vault, returns `(vault_dir, recovery_code_bytes,
/// node_id, entry_id, plaintext)` plus the owning tempdir (kept alive by
/// the caller).
fn build_fixture_vault() -> (
    tempfile::TempDir,
    [u8; 32],
    &'static str,
    &'static str,
    &'static [u8],
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let paths = VaultPaths::new(tmp.path().to_path_buf());

    let root_key = [11u8; 32];
    let recovery_code = generate_recovery_code();
    let recovery_wrap = wrap_root_with_recovery_code(&recovery_code, &root_key);
    credmgr_store::atomic::write(&paths.root_wrap_recovery(), &recovery_wrap.to_bytes())
        .expect("writing root.wrap.recovery");

    let node_id = "acme";
    let pair = generate_node_keypair();
    let wrapped_node_key = wrap_node_key(&root_key, node_id, &pair.private);
    credmgr_store::atomic::write(&paths.node_key(node_id), &wrapped_node_key.to_bytes())
        .expect("writing node key");

    let entry_id = "e_test0001";
    let plaintext: &'static [u8] = b"emergency-recovered-value";
    let sealed = envelope::seal(plaintext, &pair.public, node_id, entry_id)
        .expect("sealing the fixture entry");
    credmgr_store::atomic::write(&paths.entry_env(node_id, entry_id), &sealed)
        .expect("writing entry envelope");

    (tmp, recovery_code, node_id, entry_id, plaintext)
}

fn run_script(
    vault: &std::path::Path,
    node: &str,
    entry: &str,
    recovery_code: &str,
) -> std::process::Output {
    run_script_with(vault, node, entry, recovery_code, &[])
}

fn run_script_with(
    vault: &std::path::Path,
    node: &str,
    entry: &str,
    recovery_code: &str,
    extra_args: &[&str],
) -> std::process::Output {
    Command::new("node")
        .arg(script_path())
        .args([
            "--vault",
            &vault.to_string_lossy(),
            "--node",
            node,
            "--entry",
            entry,
        ])
        .args(extra_args)
        .env("CREDMGR_RECOVERY_CODE", recovery_code)
        .output()
        .expect("failed to launch node")
}

#[test]
fn recovers_a_real_value_with_only_the_recovery_code() {
    let (tmp, recovery_code, node_id, entry_id, plaintext) = build_fixture_vault();
    // Hyphenated, upper-case display form — proves the script's own parser
    // (not just raw hex) round-trips, matching what an operator would
    // actually retype from a printed card.
    let formatted = format_recovery_code(&recovery_code);

    let output = run_script(tmp.path(), node_id, entry_id, &formatted);
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        trim_trailing_newline(&output.stdout),
        plaintext,
        "recovered value did not match what was sealed"
    );
}

#[test]
fn wrong_recovery_code_is_refused_not_silently_wrong() {
    let (tmp, _recovery_code, node_id, entry_id, _plaintext) = build_fixture_vault();
    let wrong_code = format_recovery_code(&generate_recovery_code());

    let output = run_script(tmp.path(), node_id, entry_id, &wrong_code);
    assert!(
        !output.status.success(),
        "a wrong recovery code must fail, not succeed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("authentication failed"),
        "expected an authentication-failed error, got: {stderr}"
    );
    assert!(
        !stderr.contains("root-key rotation"),
        "an ordinary vault is not described as mid-rotation: {stderr}"
    );
}

#[test]
fn lowercase_and_unformatted_hex_also_works() {
    let (tmp, recovery_code, node_id, entry_id, plaintext) = build_fixture_vault();
    let raw_hex = {
        use std::fmt::Write;
        recovery_code.iter().fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        })
    };

    let output = run_script(tmp.path(), node_id, entry_id, &raw_hex);
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(trim_trailing_newline(&output.stdout), plaintext);
}

// ---------------------------------------------------------------------------
// Envelope versions 1 and 2 (ADR-078)
// ---------------------------------------------------------------------------

use credmgr_core::envelope::PayloadKind;
use credmgr_core::fields::{self, FieldInput, Override};
use credmgr_core::keys::NodeKeyPair;

/// A one-node vault with its root and node key wraps on disk and **no entry
/// yet**: the caller seals whatever it likes to the returned node keypair and
/// writes it under `paths.entry_env(node, entry)`.
fn vault_with_node(node_id: &str) -> (tempfile::TempDir, VaultPaths, NodeKeyPair, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let paths = VaultPaths::new(tmp.path().to_path_buf());
    let root_key = [11u8; 32];
    let recovery_code = generate_recovery_code();
    credmgr_store::atomic::write(
        &paths.root_wrap_recovery(),
        &wrap_root_with_recovery_code(&recovery_code, &root_key).to_bytes(),
    )
    .unwrap();
    let pair = generate_node_keypair();
    credmgr_store::atomic::write(
        &paths.node_key(node_id),
        &wrap_node_key(&root_key, node_id, &pair.private).to_bytes(),
    )
    .unwrap();
    (tmp, paths, pair, format_recovery_code(&recovery_code))
}

fn field(label: &str, value: &str) -> FieldInput {
    FieldInput {
        label: label.to_string(),
        value: value.to_string(),
        field_type: None,
        masked: None,
    }
}

/// A multi-line key, a CJK label, a value with CRLF and quotes, an empty label:
/// everything a JSON document has to carry without loss.
fn awkward_document() -> fields::EntryDoc {
    // Assembled from fragments so no source line holds a contiguous key header.
    let pem = format!(
        "-----BEGIN {k}-----\nQUJDREVGRw==\n-----END {k}-----",
        k = "OPENSSH PRIVATE KEY"
    );
    fields::create(
        vec![
            field("host", "db.internal"),
            field("private key", &pem),
            field("密码", "line one\r\nline \"two\" \\ three"),
            field("", "unlabelled"),
        ],
        Override::Keep,
        Override::Keep,
    )
    .expect("a valid document")
}

/// A vault holding `doc` as a version-2 entry `e_test0002` of node `acme`.
fn vault_with_document(doc: &fields::EntryDoc) -> (tempfile::TempDir, String) {
    let (tmp, paths, pair, code) = vault_with_node("acme");
    let sealed = envelope::seal_as(
        PayloadKind::FieldDocument,
        &fields::encode(doc).unwrap(),
        &pair.public,
        "acme",
        "e_test0002",
    )
    .unwrap();
    credmgr_store::atomic::write(&paths.entry_env("acme", "e_test0002"), &sealed).unwrap();
    (tmp, code)
}

#[test]
fn recovers_a_version_2_field_document_as_its_json_byte_for_byte() {
    let doc = awkward_document();
    let canonical = fields::encode(&doc).unwrap();
    let (tmp, code) = vault_with_document(&doc);

    let output = run_script(tmp.path(), "acme", "e_test0002", &code);
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        trim_trailing_newline(&output.stdout),
        canonical.as_slice(),
        "a version-2 entry is printed as its canonical JSON document, untouched"
    );
    // And what it printed is a document the Rust side decodes back to the input.
    assert_eq!(
        fields::decode(trim_trailing_newline(&output.stdout)).unwrap(),
        doc
    );
}

#[test]
fn pretty_indents_a_version_2_document_without_changing_its_content() {
    let doc = awkward_document();
    let canonical = fields::encode(&doc).unwrap();
    let (tmp, code) = vault_with_document(&doc);

    let output = run_script_with(tmp.path(), "acme", "e_test0002", &code, &["--pretty"]);
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("\n  \"fields\": ["),
        "indented for a human: {text}"
    );
    // Re-parsing the indented text and re-encoding it gives the canonical bytes:
    // nothing was lost or reordered.
    let reparsed: fields::EntryDoc = serde_json::from_str(&text).unwrap();
    assert_eq!(reparsed, doc);
    assert_eq!(fields::encode(&reparsed).unwrap(), canonical);
}

#[test]
fn pretty_leaves_a_version_1_raw_value_alone() {
    let (tmp, recovery_code, node_id, entry_id, plaintext) = build_fixture_vault();
    let output = run_script_with(
        tmp.path(),
        node_id,
        entry_id,
        &format_recovery_code(&recovery_code),
        &["--pretty"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(trim_trailing_newline(&output.stdout), plaintext);
}

#[test]
fn a_relabelled_version_byte_fails_authentication_in_both_directions() {
    for (kind, flipped_to, label) in [
        (
            PayloadKind::RawValue,
            2u8,
            "a raw value relabelled as a document",
        ),
        (
            PayloadKind::FieldDocument,
            1u8,
            "a document relabelled as a raw value",
        ),
    ] {
        let (tmp, paths, pair, code) = vault_with_node("acme");
        let mut sealed = envelope::seal_as(
            kind,
            b"{\"v\":1,\"fields\":[]}",
            &pair.public,
            "acme",
            "e_test0003",
        )
        .unwrap();
        sealed[4] = flipped_to;
        credmgr_store::atomic::write(&paths.entry_env("acme", "e_test0003"), &sealed).unwrap();

        let output = run_script(tmp.path(), "acme", "e_test0003", &code);
        assert!(!output.status.success(), "{label} must be refused");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("authentication failed"),
            "{label}: {stderr}"
        );
        assert!(output.stdout.is_empty(), "{label}: nothing reached stdout");
    }
}

#[test]
fn an_envelope_version_this_script_does_not_know_is_named() {
    let (tmp, paths, pair, code) = vault_with_node("acme");
    let mut sealed = envelope::seal(b"x", &pair.public, "acme", "e_test0004").unwrap();
    sealed[4] = 3;
    credmgr_store::atomic::write(&paths.entry_env("acme", "e_test0004"), &sealed).unwrap();

    let output = run_script(tmp.path(), "acme", "e_test0004", &code);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported version 3"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// A vault caught in the middle of a root-key rotation (ADR-076)
// ---------------------------------------------------------------------------

/// A vault whose root-key rotation committed and was then cut off while moving
/// its files into place: `keys/nodes/acme.key` and `keys/root.wrap.recovery`
/// each exist twice — the old wrap live, the new one staged under
/// `rotation-pending/` — and `COMMIT` says the staged ones win.
struct MidRotation {
    tmp: tempfile::TempDir,
    paths: VaultPaths,
    old_code: [u8; 32],
    new_code: [u8; 32],
}

const NODE: &str = "acme";
const ENTRY: &str = "e_test0001";
const VALUE: &[u8] = b"value-from-a-rotating-vault";

fn build_mid_rotation() -> MidRotation {
    use credmgr_store::rotation::RotationStage;
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let paths = VaultPaths::new(tmp.path().join("vault"));
    std::fs::create_dir_all(paths.root()).unwrap();

    let (old_root, new_root) = ([11u8; 32], [22u8; 32]);
    let (old_code, new_code) = (generate_recovery_code(), generate_recovery_code());
    let pair = generate_node_keypair();
    credmgr_store::atomic::write(
        &paths.root_wrap_recovery(),
        &wrap_root_with_recovery_code(&old_code, &old_root).to_bytes(),
    )
    .unwrap();
    credmgr_store::atomic::write(
        &paths.node_key(NODE),
        &wrap_node_key(&old_root, NODE, &pair.private).to_bytes(),
    )
    .unwrap();
    credmgr_store::atomic::write(
        &paths.entry_env(NODE, ENTRY),
        &envelope::seal(VALUE, &pair.public, NODE, ENTRY).unwrap(),
    )
    .unwrap();

    // The rotation: stage the new wraps (the node key first, the recovery wrap
    // last — the order the broker uses), then the commit record.
    let mut stage = RotationStage::begin(&paths, &state).unwrap();
    stage
        .stage_vault_file(
            &paths.node_key(NODE),
            &wrap_node_key(&new_root, NODE, &pair.private).to_bytes(),
        )
        .unwrap();
    stage
        .stage_vault_file(
            &paths.root_wrap_recovery(),
            &wrap_root_with_recovery_code(&new_code, &new_root).to_bytes(),
        )
        .unwrap();
    stage.commit().unwrap();
    MidRotation {
        tmp,
        paths,
        old_code,
        new_code,
    }
}

impl MidRotation {
    /// Move one staged file into place, as the roll-forward does.
    fn move_into_place(&self, relative: &[&str], live: PathBuf) {
        let mut staged = self.paths.rotation_stage().join("vault");
        for part in relative {
            staged = staged.join(part);
        }
        std::fs::rename(staged, live).expect("move a staged file into place");
    }

    fn run(&self, code: &[u8; 32]) -> std::process::Output {
        run_script(
            self.tmp.path().join("vault").as_path(),
            NODE,
            ENTRY,
            &format_recovery_code(code),
        )
    }
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Committed, nothing moved yet: the NEW code opens the vault through the staged
/// files, and — the live files all being old — so does the OLD one.
#[test]
fn a_vault_committed_but_not_yet_moved_opens_with_either_code_and_says_it_is_mid_rotation() {
    let v = build_mid_rotation();
    for (which, code) in [("new", &v.new_code), ("old", &v.old_code)] {
        let output = v.run(code);
        assert!(
            output.status.success(),
            "the {which} code: {}",
            stderr_of(&output)
        );
        assert_eq!(trim_trailing_newline(&output.stdout), VALUE, "{which}");
        assert!(
            stderr_of(&output).contains("middle of a root-key rotation"),
            "the {which} code succeeded but must say the vault is mid-rotation: {}",
            stderr_of(&output)
        );
    }
}

/// The window the review named. The node key has moved (new wrap live), the
/// recovery wrap is still staged (old wrap live). Read as the live vault stands
/// it is a mixture no code opens — the old "authentication failed". Now: the new
/// code opens it through the staged recovery wrap, and the old code is told
/// what is going on instead of "wrong recovery code".
#[test]
fn a_vault_caught_mid_roll_forward_opens_with_the_new_code_and_explains_itself_to_the_old() {
    let v = build_mid_rotation();
    v.move_into_place(&["keys", "nodes", "acme.key"], v.paths.node_key(NODE));
    assert!(v.paths.rotation_stage().join("COMMIT").exists());

    let output = v.run(&v.new_code);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(trim_trailing_newline(&output.stdout), VALUE);
    assert!(stderr_of(&output).contains("start credmgrd or unlock"));

    let output = v.run(&v.old_code);
    assert!(
        !output.status.success(),
        "the old code opens neither combination"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("middle of a root-key rotation"),
        "it says why instead of blaming the code: {stderr}"
    );
    assert!(
        stderr.contains("NEW recovery code") && stderr.contains("unlock the vault once"),
        "it says what to do: {stderr}"
    );
    assert!(
        stderr.contains("rotate the root key again"),
        "including when the new code was never shown: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "nothing but the value ever goes to stdout"
    );
}

/// Every file moved, the commit record not yet retired: the live vault is
/// entirely the new one and `COMMIT` is the only trace of the rotation.
#[test]
fn a_vault_whose_files_all_moved_but_whose_commit_record_remains_still_opens_with_the_new_code() {
    let v = build_mid_rotation();
    v.move_into_place(&["keys", "nodes", "acme.key"], v.paths.node_key(NODE));
    v.move_into_place(
        &["keys", "root.wrap.recovery"],
        v.paths.root_wrap_recovery(),
    );
    let output = v.run(&v.new_code);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(trim_trailing_newline(&output.stdout), VALUE);
    assert!(stderr_of(&output).contains("middle of a root-key rotation"));

    let output = v.run(&v.old_code);
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("NEW recovery code"));
}

/// Once the rotation is finished (no `COMMIT`) the vault is an ordinary one:
/// the new code opens it, and a wrong or old code gets the ordinary error — the
/// mid-rotation text must not appear where it would mislead.
#[test]
fn once_the_rotation_has_finished_the_ordinary_messages_return() {
    let v = build_mid_rotation();
    v.move_into_place(&["keys", "nodes", "acme.key"], v.paths.node_key(NODE));
    v.move_into_place(
        &["keys", "root.wrap.recovery"],
        v.paths.root_wrap_recovery(),
    );
    credmgr_store::atomic::remove_durable(&v.paths.rotation_stage().join("COMMIT")).unwrap();
    std::fs::remove_dir_all(v.paths.rotation_stage()).unwrap();

    let output = v.run(&v.new_code);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        !stderr_of(&output).contains("rotation"),
        "nothing to say: {}",
        stderr_of(&output)
    );

    let output = v.run(&v.old_code);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("authentication failed"), "{stderr}");
    assert!(!stderr.contains("rotation"), "{stderr}");
}
