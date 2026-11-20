//! ADR-156 on the command line: `credmgr passphrase`, `expire`, `expiring`, `history`, `ref` and
//! `search --node` — the REAL compiled `credmgr` binary against a REAL broker on a temporary socket,
//! starting from `credmgr init` so the passphrase change is a real root rotation of a real vault.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use secrecy::SecretBox;

use credmgr_brokerd::state::BrokerState;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::paths::VaultPaths;

const PASSPHRASE: &str = "correct horse battery staple";

struct Fixture {
    vault_dir: PathBuf,
    _tmp: tempfile::TempDir,
}

fn start_fixture_broker_on_empty_vault() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_dir = tmp.path().join("vault");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();

    let paths = VaultPaths::new(vault_dir.clone());
    std::fs::create_dir_all(paths.run_dir()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(paths.run_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Placeholder, matching `credmgrd::main`'s own real startup keystore —
    // never read by `vault.init_begin`'s own throwaway keystore (ADR-061).
    let keystore = SoftwareKeystore::new(SecretBox::new(Box::default()), state_dir.clone());
    let state = Arc::new(BrokerState::new(Box::new(keystore), paths.clone()));
    state.set_state_dir_for_test(state_dir);

    let socket_path = paths.run_socket();
    std::thread::spawn(move || {
        credmgr_brokerd::server::run(state, &socket_path).expect("fixture broker crashed");
    });
    wait_for_socket(&paths.run_socket());

    Fixture {
        vault_dir,
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

/// Drives `credmgr init` interactively: writes the passphrase line, reads
/// stdout until the `RECOVERY_CODE=` marker line `cmd_init` prints, writes
/// the confirmation line back (either the real code or a deliberately wrong
/// one), then collects the rest of stdout/stderr and the exit status.
/// Necessarily more involved than `broker_integration.rs`'s single
/// `Command::output()` call — this command is the only one in the binary
/// that needs two round trips of interactive input, which is the whole
/// reason ADR-061 exists in two ops rather than one.
struct InitRun {
    ok: bool,
    stdout: String,
    stderr: String,
    recovery_code: String,
}

fn run_credmgr_init(
    vault_dir: &Path,
    passphrase: &str,
    confirm_with: impl FnOnce(&str) -> String,
) -> InitRun {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .arg("init")
        .env("CREDMGR_VAULT_DIR", vault_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch credmgr init");

    let mut stdin = child.stdin.take().expect("child stdin");
    writeln!(stdin, "{passphrase}").expect("writing the passphrase line");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut collected_stdout = String::new();
    let mut recovery_code = None;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .expect("reading a line from the child's stdout");
        if n == 0 {
            break; // EOF before the marker — an error path, handled below.
        }
        collected_stdout.push_str(&line);
        if let Some(code) = line.trim().strip_prefix("RECOVERY_CODE=") {
            recovery_code = Some(code.to_string());
            break;
        }
    }

    if let Some(code) = &recovery_code {
        let confirmation = confirm_with(code);
        writeln!(stdin, "{confirmation}").expect("writing the confirmation line");
    }
    drop(stdin); // EOF on stdin — nothing else this process reads afterward.

    // Drain whatever's left of stdout (the "vault created at ..." line, or
    // nothing on an error path).
    use std::io::Read;
    let mut rest = String::new();
    reader
        .read_to_string(&mut rest)
        .expect("reading the rest of the child's stdout");
    collected_stdout.push_str(&rest);

    let output = child.wait_with_output().expect("waiting for credmgr init");
    InitRun {
        ok: output.status.success(),
        stdout: collected_stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        recovery_code: recovery_code.unwrap_or_default(),
    }
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn cli(vault_dir: &Path, token: Option<&str>, args: &[&str], stdin: &str) -> Out {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_credmgr"));
    cmd.args(args)
        .env("CREDMGR_VAULT_DIR", vault_dir)
        .env_remove("CREDMGR_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(t) = token {
        cmd.env("CREDMGR_TOKEN", t);
    }
    let mut child = cmd.spawn().expect("launch credmgr");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    Out {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `credmgr keystore bind` driven like a person (review N1): the passphrase and the current code, then, once
/// the new code is printed, the lines `retype` makes of it (one per try; an empty line cancels).
fn run_keystore_bind(
    vault_dir: &Path,
    token: &str,
    passphrase: &str,
    current_code: &str,
    retype: impl FnOnce(&str) -> Vec<String>,
) -> InitRun {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(["keystore", "bind"])
        .env("CREDMGR_VAULT_DIR", vault_dir)
        .env("CREDMGR_TOKEN", token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch credmgr keystore bind");
    let mut stdin = child.stdin.take().expect("child stdin");
    writeln!(stdin, "{passphrase}\n{current_code}").expect("writing the first two lines");
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut collected = String::new();
    let mut shown = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).expect("reading stdout") == 0 {
            break;
        }
        collected.push_str(&line);
        if let Some(code) = line.trim().strip_prefix("RECOVERY_CODE=") {
            shown = Some(code.to_string());
            break;
        }
    }
    if let Some(code) = &shown {
        for l in retype(code) {
            // The process may have finished already (a cancel); a closed pipe is fine.
            let _ = writeln!(stdin, "{l}");
        }
    }
    drop(stdin);
    use std::io::Read;
    let mut rest = String::new();
    reader
        .read_to_string(&mut rest)
        .expect("reading the rest of stdout");
    collected.push_str(&rest);
    let output = child
        .wait_with_output()
        .expect("waiting for credmgr keystore bind");
    InitRun {
        ok: output.status.success(),
        stdout: collected,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        recovery_code: shown.unwrap_or_default(),
    }
}

fn unlock(vault_dir: &Path, passphrase: &str) -> Result<String, String> {
    let out = cli(vault_dir, None, &["unlock"], &format!("{passphrase}\n"));
    if !out.ok {
        return Err(out.stderr);
    }
    out.stdout
        .lines()
        .find_map(|l| l.strip_prefix("export CREDMGR_TOKEN="))
        .map(str::to_string)
        .ok_or(out.stdout)
}

const NEW_PASSPHRASE: &str = "a brand new passphrase 2027";

#[test]
fn passphrase_changes_the_unlock_and_prints_a_new_recovery_code_once() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("first unlock");

    // A wrong current passphrase changes nothing.
    let wrong = cli(
        &fixture.vault_dir,
        Some(&token),
        &["passphrase"],
        &format!("not the passphrase\n{NEW_PASSPHRASE}\n"),
    );
    assert!(!wrong.ok);
    assert!(
        wrong.stderr.contains("wrong_passphrase"),
        "{}",
        wrong.stderr
    );
    // A missing new passphrase is refused before the broker is asked.
    let missing = cli(
        &fixture.vault_dir,
        Some(&token),
        &["passphrase"],
        &format!("{PASSPHRASE}\n"),
    );
    assert!(!missing.ok);
    assert!(
        missing.stderr.contains("new passphrase is required"),
        "{}",
        missing.stderr
    );

    let changed = cli(
        &fixture.vault_dir,
        Some(&token),
        &["passphrase"],
        &format!("{PASSPHRASE}\n{NEW_PASSPHRASE}\n"),
    );
    assert!(
        changed.ok,
        "passphrase: {} {}",
        changed.stdout, changed.stderr
    );
    assert!(changed.stdout.contains("passphrase changed"));
    let code = changed
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("RECOVERY_CODE="))
        .expect("a new recovery code is printed");
    assert_ne!(
        code, init.recovery_code,
        "the rotation issues a new recovery code"
    );
    assert!(!changed.stdout.contains(NEW_PASSPHRASE) && !changed.stderr.contains(NEW_PASSPHRASE));

    let _ = cli(&fixture.vault_dir, Some(&token), &["lock"], "");
    assert!(
        unlock(&fixture.vault_dir, PASSPHRASE).is_err(),
        "the old passphrase no longer opens it"
    );
    unlock(&fixture.vault_dir, NEW_PASSPHRASE).expect("the new passphrase opens it");
}

#[test]
fn expire_expiring_history_ref_and_node_search_round_trip_without_a_value() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("unlock");
    let v = |args: &[&str], stdin: &str| cli(&fixture.vault_dir, Some(&token), args, stdin);

    let set = v(
        &["set", "STRIPE_KEY", "--node", "global"],
        "sk-value-marker-4410\n",
    );
    assert!(set.ok, "set: {}", set.stderr);

    let none = v(&["expiring"], "");
    assert!(none.ok, "{}", none.stderr);
    assert!(none.stdout.contains("nothing expires"), "{}", none.stdout);

    let exp = v(&["expire", "STRIPE_KEY", "--in", "10"], "");
    assert!(exp.ok, "expire: {}", exp.stderr);
    assert!(exp.stdout.contains("STRIPE_KEY expires"), "{}", exp.stdout);
    let soon = v(&["expiring", "--days", "30"], "");
    assert!(
        soon.stdout.contains("global\tSTRIPE_KEY"),
        "{}",
        soon.stdout
    );
    let not_yet = v(&["expiring", "--days", "5"], "");
    assert!(
        not_yet.stdout.contains("nothing expires"),
        "{}",
        not_yet.stdout
    );
    let bad = v(&["expire", "STRIPE_KEY", "--at", "2027-02-30"], "");
    assert!(
        !bad.ok && bad.stderr.contains("--at takes"),
        "{}",
        bad.stderr
    );
    let cleared = v(&["expire", "STRIPE_KEY", "--clear"], "");
    assert!(
        cleared.stdout.contains("no longer has an expiry"),
        "{}",
        cleared.stdout
    );

    let hist = v(&["history", "STRIPE_KEY"], "");
    assert!(hist.ok, "history: {}", hist.stderr);
    assert!(hist.stdout.contains("entry.create"), "{}", hist.stdout);
    assert!(hist.stdout.contains("entry.set_expiry"), "{}", hist.stdout);

    let json = v(&["history", "STRIPE_KEY", "--json"], "");
    let value: serde_json::Value = serde_json::from_str(json.stdout.trim()).unwrap();
    let r = value["ref"].as_u64().expect("history carries the ref");
    let by_ref = v(&["ref", &r.to_string()], "");
    assert_eq!(by_ref.stdout.trim(), "global\tSTRIPE_KEY");
    let missing_ref = v(&["ref", "999999"], "");
    assert!(!missing_ref.ok);

    let found = v(&["search", "stripe", "--node", "global"], "");
    assert_eq!(found.stdout.trim(), "global\tSTRIPE_KEY");

    for out in [&none, &exp, &soon, &hist, &json, &by_ref, &found] {
        assert!(
            !out.stdout.contains("sk-value-marker"),
            "a value leaked: {}",
            out.stdout
        );
    }
}

/// ADR-158: `credmgr move` resolves the name, refuses its own mistakes before the broker is asked, and is
/// refused by the broker without a presence proof (no presence key can be enrolled from this test, so the
/// success path is the broker's own suite, `crates/brokerd/tests/entry_move.rs`). Nothing moves.
#[test]
fn move_refuses_usage_mistakes_and_without_presence_moves_nothing() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("unlock");
    let v = |args: &[&str], stdin: &str| cli(&fixture.vault_dir, Some(&token), args, stdin);

    let node = v(
        &[
            "node", "create", "acme", "--parent", "global", "--label", "Acme",
        ],
        "",
    );
    assert!(node.ok, "node add: {}{}", node.stdout, node.stderr);
    let set = v(
        &["set", "STRIPE_KEY", "--node", "global"],
        "sk-value-marker-5520\n",
    );
    assert!(set.ok, "set: {}", set.stderr);

    let no_to = v(&["move", "STRIPE_KEY"], "");
    assert!(
        !no_to.ok && no_to.stderr.contains("usage: credmgr move"),
        "{}",
        no_to.stderr
    );
    let same = v(&["move", "STRIPE_KEY", "--to", "global"], "");
    assert!(
        !same.ok && same.stderr.contains("already in"),
        "{}",
        same.stderr
    );
    let missing = v(&["move", "NO_SUCH", "--node", "global", "--to", "acme"], "");
    assert!(!missing.ok, "{}", missing.stdout);

    let refused = v(
        &["move", "STRIPE_KEY", "--to", "acme", "--reason", "misfiled"],
        "",
    );
    assert!(!refused.ok, "{}", refused.stdout);
    assert!(
        refused.stderr.contains("presence_required"),
        "{}",
        refused.stderr
    );
    let still = v(&["search", "STRIPE_KEY", "--node", "global"], "");
    assert_eq!(still.stdout.trim(), "global\tSTRIPE_KEY", "nothing moved");
    for out in [&no_to, &same, &missing, &refused, &still] {
        assert!(!out.stdout.contains("sk-value-marker") && !out.stderr.contains("sk-value-marker"));
    }
}

/// ADR-161: `credmgr doctor --scan` prints the tidy-up report — a shared value with the `credmgr move`
/// command that applies its proposal, a misfiled entry — and never a value, in text or JSON. Usage mistakes
/// are refused before the broker is asked; a plain `credmgr doctor` is still the repair.
#[test]
fn doctor_scan_reports_findings_and_the_move_that_applies_them_without_a_value() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("unlock");
    let v = |args: &[&str], stdin: &str| cli(&fixture.vault_dir, Some(&token), args, stdin);

    for (id, parent) in [
        ("acme", "global"),
        ("acme-web", "acme"),
        ("acme-api", "acme"),
    ] {
        let node = v(
            &["node", "create", id, "--parent", parent, "--label", id],
            "",
        );
        assert!(node.ok, "node create {id}: {}{}", node.stdout, node.stderr);
    }
    for (name, node) in [("WEB_KEY", "acme-web"), ("API_KEY", "acme-api")] {
        let set = v(&["set", name, "--node", node], "shared-marker-value-6631\n");
        assert!(set.ok, "set {name}: {}", set.stderr);
    }
    let set = v(
        &["set", "ACME_TOKEN", "--node", "global"],
        "misfiled-marker-value-6632\n",
    );
    assert!(set.ok, "set: {}", set.stderr);

    let text = v(&["doctor", "--scan"], "");
    assert!(text.ok, "{}{}", text.stdout, text.stderr);
    assert!(text.stdout.contains("share a value"), "{}", text.stdout);
    assert!(
        text.stdout.contains("--to acme"),
        "the move that applies the proposal is printed: {}",
        text.stdout
    );
    assert!(
        text.stdout.contains("global/ACME_TOKEN sits in global"),
        "{}",
        text.stdout
    );
    let json = v(&["doctor", "--scan", "--json", "--stale-days", "30"], "");
    assert!(json.ok, "{}", json.stderr);
    let report: serde_json::Value = serde_json::from_str(json.stdout.trim()).expect("json");
    assert_eq!(report["staleDays"], 30);
    assert_eq!(report["counts"]["duplicate_value"], 1);
    assert_eq!(report["counts"]["misfiled"], 1);

    let bad = v(&["doctor", "--scan", "--stale-days", "soon"], "");
    assert!(
        !bad.ok && bad.stderr.contains("whole number"),
        "{}",
        bad.stderr
    );
    let stray = v(&["doctor", "--scan", "extra"], "");
    assert!(
        !stray.ok && stray.stderr.contains("usage: credmgr doctor --scan"),
        "{}",
        stray.stderr
    );
    for out in [&text, &json, &bad, &stray] {
        assert!(!out.stdout.contains("marker-value") && !out.stderr.contains("marker-value"));
    }
}

/// ADR-169: `credmgr doctor --scan --apply` lists every move of the plan before anything moves, asks first
/// (no terminal and no `--yes`: nothing moves), and with `--yes` sends the whole plan, which the broker refuses
/// here without a presence key — again moving nothing. `--yes` without `--apply` is a usage mistake. No value.
#[test]
fn doctor_apply_previews_the_plan_asks_first_and_moves_nothing_without_presence() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("unlock");
    let v = |args: &[&str], stdin: &str| cli(&fixture.vault_dir, Some(&token), args, stdin);

    let nothing = v(&["doctor", "--scan", "--apply"], "");
    assert!(nothing.ok, "{}{}", nothing.stdout, nothing.stderr);
    assert!(
        nothing.stdout.contains("nothing to apply"),
        "{}",
        nothing.stdout
    );

    for (id, parent) in [("acme", "global"), ("demo", "global")] {
        let node = v(
            &["node", "create", id, "--parent", parent, "--label", id],
            "",
        );
        assert!(node.ok, "node create {id}: {}{}", node.stdout, node.stderr);
    }
    let markers = ["TEST_apply-marker-7710\n", "TEST_apply-marker-7711\n"];
    for (name, marker) in ["ACME_TOKEN", "DEMO_TOKEN"].into_iter().zip(markers) {
        let set = v(&["set", name, "--node", "global"], marker);
        assert!(set.ok, "set {name}: {}", set.stderr);
    }

    let asked = v(&["doctor", "--scan", "--apply"], "");
    assert!(!asked.ok, "{}", asked.stdout);
    assert!(
        asked.stdout.contains("the plan: 2 moves"),
        "{}",
        asked.stdout
    );
    assert!(
        asked.stdout.contains("1. ACME_TOKEN: global -> acme"),
        "{}",
        asked.stdout
    );
    assert!(
        asked.stdout.contains("2. DEMO_TOKEN: global -> demo"),
        "{}",
        asked.stdout
    );
    assert!(asked.stderr.contains("nothing moved"), "{}", asked.stderr);

    let sent = v(&["doctor", "--scan", "--apply", "--yes"], "");
    assert!(!sent.ok, "{}", sent.stdout);
    assert!(sent.stderr.contains("presence_required"), "{}", sent.stderr);
    let still = v(&["search", "TOKEN", "--node", "global"], "");
    assert!(
        still.stdout.contains("ACME_TOKEN") && still.stdout.contains("DEMO_TOKEN"),
        "nothing moved: {}",
        still.stdout
    );

    let json = v(&["doctor", "--scan", "--apply", "--json"], "");
    assert!(!json.ok);
    assert!(json.stderr.contains("the plan: 2 moves"), "{}", json.stderr);

    let usage = v(&["doctor", "--scan", "--yes"], "");
    assert!(
        !usage.ok && usage.stderr.contains("usage: credmgr doctor --scan"),
        "{}",
        usage.stderr
    );
    for out in [&nothing, &asked, &sent, &still, &json, &usage] {
        assert!(!out.stdout.contains("apply-marker") && !out.stderr.contains("apply-marker"));
    }
}

/// rc.2 §3 item 3: `credmgr edit` against the real broker, with `EDITOR` pointing at a script that rewrites the
/// document. Only the changed keys are applied; no value is shown; the temp file is gone afterwards.
#[test]
fn edit_applies_only_changed_metadata_through_the_editor_without_a_value() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("unlock");
    let v = |args: &[&str], stdin: &str| cli(&fixture.vault_dir, Some(&token), args, stdin);
    let set = v(
        &["set", "STRIPE_KEY", "--node", "global"],
        "sk-value-marker-7731\n",
    );
    assert!(set.ok, "set: {}", set.stderr);

    let script = fixture.vault_dir.parent().unwrap().join("ed.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nsed -i.bak -e 's/^aliases:.*/aliases: pay, billing/' -e 's/^expires:.*/expires: 2031-05-06/' -e 's/^field\\.\\(f_[0-9a-f]*\\)\\.label: .*/field.\\1.label: api secret/' \"$1\"\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let edit = |extra: &[&str]| {
        let mut args = vec!["edit", "STRIPE_KEY", "--node", "global"];
        args.extend_from_slice(extra);
        let out = Command::new(env!("CARGO_BIN_EXE_credmgr"))
            .args(&args)
            .env("CREDMGR_VAULT_DIR", &fixture.vault_dir)
            .env("CREDMGR_TOKEN", &token)
            .env_remove("VISUAL")
            .env("EDITOR", &script)
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    let (ok, so, se) = edit(&["--dry-run"]);
    assert!(ok, "dry-run: {se}");
    assert!(
        so.contains("none applied") && so.contains("entry.alias"),
        "{so}"
    );
    let still = v(&["search", "billing", "--node", "global"], "");
    assert!(
        !still.stdout.contains("STRIPE_KEY"),
        "dry-run applied: {}",
        still.stdout
    );

    let (ok, so, se) = edit(&[]);
    assert!(ok, "edit: {so}{se}");
    assert!(so.contains("updated"), "{so}");
    let found = v(&["search", "billing", "--node", "global"], "");
    assert_eq!(found.stdout.trim(), "global\tSTRIPE_KEY");
    let list = v(&["expiring", "--days", "3650"], "");
    assert!(list.stdout.contains("STRIPE_KEY"), "{}", list.stdout);
    let field = v(
        &[
            "get",
            "STRIPE_KEY",
            "--node",
            "global",
            "--field",
            "api secret",
        ],
        "",
    );
    assert!(
        field.ok && field.stdout.contains("sk-value-marker-7731"),
        "{}{}",
        field.stdout,
        field.stderr
    );

    for s in [&so, &se] {
        assert!(!s.contains("sk-value-marker"), "a value leaked: {s}");
    }
    let leftovers = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("credmgr-edit-"))
        .count();
    assert_eq!(leftovers, 0, "temp edit dirs left behind");
}

/// ADR-163: `credmgr recover` — the recovery code and the new passphrase come from stdin, never argv; a wrong
/// code changes nothing; the right one sets the new passphrase, prints a NEW recovery code once and a login,
/// and the used code and the old passphrase stop working.
#[test]
fn recover_opens_the_vault_with_the_code_sets_the_new_passphrase_and_retires_the_code() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("first unlock");

    // An open vault: nothing to recover.
    let open = cli(
        &fixture.vault_dir,
        Some(&token),
        &["recover"],
        &format!("{}\n{NEW_PASSPHRASE}\n", init.recovery_code),
    );
    assert!(!open.ok);
    assert!(
        open.stderr.contains("credmgr passphrase"),
        "{}",
        open.stderr
    );
    let _ = cli(&fixture.vault_dir, Some(&token), &["lock"], "");

    // No secret is accepted on the command line.
    let argv = cli(
        &fixture.vault_dir,
        None,
        &["recover", &init.recovery_code],
        "",
    );
    assert!(!argv.ok);
    assert!(
        argv.stderr.contains("usage: credmgr recover"),
        "{}",
        argv.stderr
    );

    // A wrong code changes nothing.
    let wrong = cli(
        &fixture.vault_dir,
        None,
        &["recover"],
        &format!("{}\n{NEW_PASSPHRASE}\n", "00".repeat(32)),
    );
    assert!(!wrong.ok);
    assert!(
        wrong.stderr.contains("recovery_code_mismatch"),
        "{}",
        wrong.stderr
    );
    // A missing new passphrase is refused before the broker is asked.
    let missing = cli(
        &fixture.vault_dir,
        None,
        &["recover"],
        &format!("{}\n", init.recovery_code),
    );
    assert!(!missing.ok);
    assert!(
        missing.stderr.contains("new passphrase is required"),
        "{}",
        missing.stderr
    );
    let token =
        unlock(&fixture.vault_dir, PASSPHRASE).expect("nothing above changed the passphrase");
    let _ = cli(&fixture.vault_dir, Some(&token), &["lock"], "");

    let recovered = cli(
        &fixture.vault_dir,
        None,
        &["recover"],
        &format!("{}\n{NEW_PASSPHRASE}\n", init.recovery_code),
    );
    assert!(
        recovered.ok,
        "recover: {} {}",
        recovered.stdout, recovered.stderr
    );
    assert!(recovered.stdout.contains("vault recovered"));
    let code = recovered
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("RECOVERY_CODE="))
        .expect("a new recovery code is printed");
    assert_ne!(code, init.recovery_code);
    let token = recovered
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("export CREDMGR_TOKEN="))
        .expect("the vault is open and a login is printed")
        .to_string();
    for text in [&recovered.stdout, &recovered.stderr] {
        assert!(!text.contains(NEW_PASSPHRASE) && !text.contains(&init.recovery_code));
    }

    let _ = cli(&fixture.vault_dir, Some(&token), &["lock"], "");
    assert!(
        unlock(&fixture.vault_dir, PASSPHRASE).is_err(),
        "the old passphrase is retired"
    );
    let used = cli(
        &fixture.vault_dir,
        None,
        &["recover"],
        &format!("{}\nyet another passphrase\n", init.recovery_code),
    );
    assert!(
        !used.ok && used.stderr.contains("recovery_code_mismatch"),
        "{}",
        used.stderr
    );
    unlock(&fixture.vault_dir, NEW_PASSPHRASE).expect("the new passphrase opens it");
}

/// ADR-165: `credmgr keystore status | bind | unbind` against a real broker on a real vault. The fixture's
/// state directory sits beside the vault folder, as the default one does.
#[test]
fn keystore_status_bind_and_unbind_round_trip_and_the_vault_still_opens() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("unlock");

    let usage = cli(&fixture.vault_dir, Some(&token), &["keystore"], "");
    assert!(!usage.ok);
    assert!(
        usage.stderr.contains("usage: credmgr keystore"),
        "{}",
        usage.stderr
    );

    let st = cli(
        &fixture.vault_dir,
        Some(&token),
        &["keystore", "status"],
        "",
    );
    assert!(st.ok, "{}", st.stderr);
    assert!(st.stdout.contains("machine lock: off"), "{}", st.stdout);

    // ADR-165 review P1-1: bind takes the passphrase and the CURRENT recovery code from stdin; a wrong code
    // changes nothing.
    let wrong = cli(
        &fixture.vault_dir,
        Some(&token),
        &["keystore", "bind"],
        &format!("{PASSPHRASE}\n{}\n", "00".repeat(32)),
    );
    assert!(!wrong.ok);
    assert!(
        wrong.stderr.contains("recovery_code_mismatch") && wrong.stderr.contains("CURRENT code"),
        "{}",
        wrong.stderr
    );
    let missing = cli(
        &fixture.vault_dir,
        Some(&token),
        &["keystore", "bind"],
        &format!("{PASSPHRASE}\n"),
    );
    assert!(!missing.ok && missing.stderr.contains("recovery code is required"));

    // Review N1: the new code is printed before anything changes, and the lock goes on only once it is typed
    // back. An empty line cancels: nothing changed, and the code typed first still works.
    let cancelled = run_keystore_bind(
        &fixture.vault_dir,
        &token,
        PASSPHRASE,
        &init.recovery_code,
        |_| vec![String::new()],
    );
    assert!(!cancelled.ok);
    assert!(
        cancelled.stdout.contains("Nothing has changed yet") && !cancelled.recovery_code.is_empty(),
        "{}",
        cancelled.stdout
    );
    assert!(
        cancelled.stderr.contains("nothing changed"),
        "{}",
        cancelled.stderr
    );
    let st = cli(
        &fixture.vault_dir,
        Some(&token),
        &["keystore", "status"],
        "",
    );
    assert!(st.stdout.contains("machine lock: off"), "{}", st.stdout);
    // Three wrong retypings: nothing changed either.
    let wrong_thrice = run_keystore_bind(
        &fixture.vault_dir,
        &token,
        PASSPHRASE,
        &init.recovery_code,
        |_| vec![init.recovery_code.clone(); 3],
    );
    assert!(!wrong_thrice.ok);
    assert!(
        wrong_thrice.stderr.contains("did not match three times"),
        "{}",
        wrong_thrice.stderr
    );
    // A wrong retyping, then the right one.
    let bound = run_keystore_bind(
        &fixture.vault_dir,
        &token,
        PASSPHRASE,
        &init.recovery_code,
        |code| vec!["not it".to_string(), code.to_string()],
    );
    assert!(bound.ok, "{}", bound.stderr);
    assert!(
        bound.stderr.contains("not the code shown above"),
        "{}",
        bound.stderr
    );
    assert!(
        bound.stdout.contains("machine lock is on"),
        "{}",
        bound.stdout
    );
    assert!(bound.stdout.contains("BEFORE now"), "{}", bound.stdout);
    assert!(bound.stdout.contains("not sealed in the Secure Enclave"));
    assert!(
        bound.stdout.contains("now the vault's recovery code"),
        "{}",
        bound.stdout
    );
    let new_code = bound.recovery_code.clone();
    assert_eq!(
        bound.stdout.matches("RECOVERY_CODE=").count(),
        1,
        "the new code is printed once: {}",
        bound.stdout
    );
    assert_ne!(new_code, init.recovery_code, "bind is a root rotation");
    assert!(!bound.stdout.contains(PASSPHRASE) && !bound.stderr.contains(PASSPHRASE));

    let js = cli(
        &fixture.vault_dir,
        Some(&token),
        &["keystore", "status", "--json"],
        "",
    );
    let v: serde_json::Value = serde_json::from_str(js.stdout.trim()).expect("json");
    assert_eq!(v["bound"], true);
    assert_eq!(v["tier"], "file");

    // Lock, and the passphrase still opens it on this "Mac".
    let _ = cli(&fixture.vault_dir, Some(&token), &["lock"], "");
    unlock(&fixture.vault_dir, PASSPHRASE).expect("a bound vault opens here");
    let _ = cli(&fixture.vault_dir, None, &["lock"], "");

    // Review P1-4: a recovery says what it did to the machine lock.
    let recovered = cli(
        &fixture.vault_dir,
        None,
        &["recover"],
        &format!("{new_code}\n{NEW_PASSPHRASE}\n"),
    );
    assert!(recovered.ok, "{}", recovered.stderr);
    assert!(
        recovered.stdout.contains("machine lock: still on"),
        "{}",
        recovered.stdout
    );
    let token = unlock(&fixture.vault_dir, NEW_PASSPHRASE).expect("the new passphrase opens it");

    let unbound = cli(
        &fixture.vault_dir,
        Some(&token),
        &["keystore", "unbind"],
        &format!("{NEW_PASSPHRASE}\n"),
    );
    assert!(unbound.ok, "{}", unbound.stderr);
    assert!(
        unbound.stdout.contains("machine lock is off"),
        "{}",
        unbound.stdout
    );

    // Nothing typed: the CLI asks for the passphrase and sends nothing.
    let empty = cli(&fixture.vault_dir, None, &["keystore", "bind"], "");
    assert!(!empty.ok);
    assert!(
        empty.stderr.contains("passphrase is required"),
        "{}",
        empty.stderr
    );
    // Without a login: refused by the broker, nothing printed but the error.
    let anon = cli(
        &fixture.vault_dir,
        None,
        &["keystore", "bind"],
        &format!(
            "{NEW_PASSPHRASE}
{new_code}
"
        ),
    );
    assert!(!anon.ok);
    assert!(
        anon.stderr.contains("capability_not_held"),
        "{}",
        anon.stderr
    );
}

/// ADR-167: `credmgr tag` adds, removes and clears (normalised), and `credmgr list --tag` filters one node.
#[test]
fn tag_adds_removes_clears_and_list_filters_by_tag() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("unlock");
    let v = |args: &[&str], stdin: &str| cli(&fixture.vault_dir, Some(&token), args, stdin);

    let node = v(
        &[
            "node", "create", "acme", "--parent", "global", "--label", "acme",
        ],
        "",
    );
    assert!(node.ok, "{}", node.stderr);
    for name in ["DB_URL", "API_KEY"] {
        let set = v(&["set", name, "--node", "acme"], "tag-marker-value-7741\n");
        assert!(set.ok, "set {name}: {}", set.stderr);
    }
    let add = v(
        &[
            "tag",
            "DB_URL",
            "--node",
            "acme",
            "--add",
            "Prod",
            "--add",
            "staging db",
        ],
        "",
    );
    assert!(add.ok, "{}{}", add.stdout, add.stderr);
    assert!(add.stdout.contains("prod, staging-db"), "{}", add.stdout);
    let show = v(&["tag", "DB_URL", "--node", "acme"], "");
    assert_eq!(
        show.stdout.lines().collect::<Vec<_>>(),
        vec!["prod", "staging-db"]
    );
    let listed = v(&["list", "--node", "acme", "--tag", "PROD"], "");
    assert!(listed.ok, "{}", listed.stderr);
    assert_eq!(listed.stdout.trim(), "DB_URL");
    let removed = v(&["tag", "DB_URL", "--node", "acme", "--remove", "prod"], "");
    assert!(
        removed.stdout.contains("staging-db") && !removed.stdout.contains("prod,"),
        "{}",
        removed.stdout
    );
    let cleared = v(&["tag", "DB_URL", "--node", "acme", "--clear"], "");
    assert!(cleared.stdout.contains("has no tags"), "{}", cleared.stdout);
    let none = v(&["list", "--node", "acme", "--tag", "prod"], "");
    assert!(none.ok && none.stdout.trim().is_empty(), "{}", none.stdout);

    let bad = v(
        &["tag", "DB_URL", "--node", "acme", "--add", "no,commas"],
        "",
    );
    assert!(
        !bad.ok && bad.stderr.contains("may hold only"),
        "{}",
        bad.stderr
    );
    let nodeless = v(&["list", "--tag", "prod"], "");
    assert!(
        !nodeless.ok && nodeless.stderr.contains("filters one node"),
        "{}",
        nodeless.stderr
    );
    for out in [&add, &show, &listed, &removed, &cleared, &none, &bad] {
        assert!(!out.stdout.contains("marker-value") && !out.stderr.contains("marker-value"));
    }
}

/// ADR-168: `credmgr merge` suggests, dismisses, runs auto-all as a dry run, and applies with --apply.
#[test]
fn merge_suggests_dismisses_and_auto_all_is_a_dry_run_until_apply() {
    let fixture = start_fixture_broker_on_empty_vault();
    let init = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |c| c.to_string());
    assert!(init.ok, "init: {}{}", init.stdout, init.stderr);
    let token = unlock(&fixture.vault_dir, PASSPHRASE).expect("unlock");
    let v = |args: &[&str], stdin: &str| cli(&fixture.vault_dir, Some(&token), args, stdin);

    let node = v(
        &[
            "node", "create", "acme", "--parent", "global", "--label", "acme",
        ],
        "",
    );
    assert!(node.ok, "{}", node.stderr);
    for name in ["STRIPE_KEY", "STRIPE_COPY"] {
        let set = v(
            &["set", name, "--node", "acme"],
            "merge-marker-value-5520\n",
        );
        assert!(set.ok, "set {name}: {}", set.stderr);
    }
    let suggest = v(&["merge", "suggest", "--node", "acme"], "");
    assert!(suggest.ok, "{}{}", suggest.stdout, suggest.stderr);
    assert!(
        suggest.stdout.contains("identical values: "),
        "{}",
        suggest.stdout
    );
    let json = v(&["merge", "suggest", "--node", "acme", "--json"], "");
    let r: serde_json::Value = serde_json::from_str(json.stdout.trim()).expect("json");
    let key = r["suggestions"][0]["key"].as_str().unwrap().to_string();

    let dry = v(&["merge", "auto-all", "--node", "acme"], "");
    assert!(
        dry.ok && dry.stdout.contains("dry run: nothing was changed"),
        "{}{}",
        dry.stdout,
        dry.stderr
    );
    let list = v(&["list", "--node", "acme"], "");
    assert_eq!(list.stdout.lines().count(), 2, "{}", list.stdout);

    let dismissed = v(&["merge", "dismiss", "--node", "acme", "--group", &key], "");
    assert!(dismissed.ok, "{}", dismissed.stderr);
    let again = v(&["merge", "suggest", "--node", "acme"], "");
    assert!(
        again.stdout.contains("no merge suggestions"),
        "{}",
        again.stdout
    );
    let shown = v(&["merge", "dismissed", "--node", "acme"], "");
    assert!(
        shown.stdout.contains("STRIPE_KEY") && shown.stdout.contains(&key),
        "{}",
        shown.stdout
    );
    let back = v(&["merge", "restore-all", "--node", "acme"], "");
    assert!(back.stdout.contains("1 dismissed"), "{}", back.stdout);

    let applied = v(&["merge", "auto-all", "--node", "acme", "--apply"], "");
    assert!(applied.ok, "{}{}", applied.stdout, applied.stderr);
    assert!(
        applied.stdout.contains("merged STRIPE_COPY into"),
        "{}",
        applied.stdout
    );
    let list = v(&["list", "--node", "acme"], "");
    assert_eq!(list.stdout.trim(), "STRIPE_KEY");

    let usage = v(
        &["merge", "apply", "--node", "acme", "--keep", "STRIPE_KEY"],
        "",
    );
    assert!(
        !usage.ok && usage.stderr.contains("usage: credmgr merge"),
        "{}",
        usage.stderr
    );
    for out in [
        &suggest, &json, &dry, &dismissed, &again, &shown, &back, &applied, &usage,
    ] {
        assert!(!out.stdout.contains("marker-value") && !out.stderr.contains("marker-value"));
    }
}
