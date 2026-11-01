//! `credmgr` — the single-binary CLI. Talks to `credmgrd` over the local
//! socket/pipe; never decrypts directly (`v2/docs/12_BUILD_PLAN.md` Phase 4
//! exit gate: "no command accepts a secret in argv", "none decrypts
//! directly"). `credmgr mcp` is this same binary's MCP stdio server
//! subcommand ("one artefact to sign, one to trust",
//! `16_CROSS_PLATFORM.md §2`) — `credmgr_mcp::server::run` over real
//! stdin/stdout, talking to the same `credmgrd` over the same socket this
//! binary's own commands use.
//!
//! **Argv safety, by construction, not by convention.** No subcommand below
//! defines a flag or positional that carries a secret value — `set`'s new
//! value and `unlock`'s passphrase are read from stdin only
//! ([`read_stdin_value`]), matching `10_API_AND_MCP.md §2`: "value from
//! stdin; never from argv." `tests/no_secret_in_argv.rs` asserts this
//! structurally.
#![forbid(unsafe_code)]

mod dotenv;
mod fields;
mod transport;

use std::io::Read;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU8, Ordering};

use serde_json::{json, Value};

use transport::TransportError;

/// The status the process exits with when a command fails. `1` unless the failing
/// command asked for another through [`selection_error`].
static EXIT_STATUS: AtomicU8 = AtomicU8::new(1);

/// Exit status for "the command line did not say which one" (ADR-078): an entry with
/// several fields and no `--field`, a label that matches two fields or none. The
/// conventional status for a command that was understood but not complete, and the one
/// `docs/10_API_AND_MCP.md` gives a script to tell "name the field" from "the vault said
/// no" (status 1).
const EXIT_SELECTION: u8 = 2;

/// A refusal because a field was not named (or not uniquely) - [`EXIT_SELECTION`].
fn selection_error(message: impl Into<String>) -> String {
    EXIT_STATUS.store(EXIT_SELECTION, Ordering::Relaxed);
    message.into()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("credmgr: {msg}");
            ExitCode::from(EXIT_STATUS.load(Ordering::Relaxed))
        }
    }
}

/// `21_RELEASE_AND_INTEGRITY.md §1.3`'s build stamp, minimum form: the
/// crate version, the commit `scripts/release.sh` built from, and whether that
/// tree was dirty. `option_env!`, not a build script — rustc records the
/// variables it reads, so cargo rebuilds when the release script changes them.
/// Inert data (§1.3 rule 4): nothing trusts it; it lets an honest build say
/// which build it is.
fn version_line(bin: &str) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let platform = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    match option_env!("CREDMGR_BUILD_COMMIT") {
        Some(commit) if !commit.is_empty() => {
            let short = &commit[..commit.len().min(12)];
            let dirty = if option_env!("CREDMGR_BUILD_DIRTY") == Some("1") {
                ", dirty"
            } else {
                ""
            };
            format!("{bin} {version} (commit {short}{dirty}, {platform})")
        }
        _ => format!("{bin} {version} (development build, no commit stamp, {platform})"),
    }
}

fn run(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "init" => cmd_init(),
        "status" => cmd_status(),
        "unlock" => cmd_unlock(),
        "lock" => cmd_lock(),
        "gate" => cmd_gate(args),
        "whoami" => cmd_whoami(args),
        "list" => cmd_list(args),
        "get" => cmd_get(args),
        "field" => fields::cmd_field(args),
        "search" => cmd_search(args),
        "set" => cmd_set(args),
        "rotate" => cmd_rotate(args),
        "rm" => cmd_rm(args),
        "undo" => cmd_undo(args),
        "audit" => cmd_audit(args),
        "verify" => cmd_verify(args),
        "pending" => cmd_pending(args),
        "doctor" => cmd_doctor(args),
        "generate" => cmd_generate(args),
        "approve" => cmd_approve(args),
        "approvals" => cmd_approvals(args),
        "backup" => cmd_backup(args),
        "node" => cmd_node(args),
        "grant" => cmd_grant(args),
        "import" => cmd_import(args),
        "notes" => cmd_notes(args),
        "mcp" => cmd_mcp(),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "--version" | "-V" | "version" => {
            println!("{}", version_line("credmgr"));
            Ok(())
        }
        other => Err(format!(
            "unknown command '{other}' — run `credmgr help` for the command list"
        )),
    }
}

fn print_usage() {
    println!(
        "credmgr — local credential vault CLI\n\
         \n\
         Usage:\n\
         \x20 credmgr init                           (creates a new vault; passphrase from\n\
         \x20                                      stdin, then confirm the printed recovery\n\
         \x20                                      code by retyping it — needs credmgrd\n\
         \x20                                      running against an empty vault directory)\n\
         \x20 credmgr status\n\
         \x20 credmgr unlock                        (passphrase from stdin; a real login —\n\
         \x20                                      prints `export CREDMGR_TOKEN=...` on\n\
         \x20                                      success. Capture it with:\n\
         \x20                                      eval \"$(credmgr unlock <<< \"$pw\")\")\n\
         \x20 credmgr gate verify <code>             (completes unlock when 2FA is enrolled;\n\
         \x20                                      prints the token the same way. With a login\n\
         \x20                                      already in CREDMGR_TOKEN it is a step-up: it\n\
         \x20                                      proves the second factor for five minutes, for\n\
         \x20                                      nodes whose policy asks for it)\n\
         \x20 credmgr gate enroll                   (turns on two-factor; needs an unlocked login)\n\
         \x20 credmgr gate recover                  (lost authenticator: passphrase + root recovery\n\
         \x20                                      code from stdin reset the gate)\n\
         \x20 credmgr lock\n\
         \x20 credmgr whoami [--json]\n\
         \x20 credmgr list [--node <id>] [--json]\n\
         \x20 credmgr get <name> [--node <id>] [--field <label> | --field-id <id> | --all] [--json]\n\
         \x20                                      (a one-field entry prints its value; with several\n\
         \x20                                      fields name one, or use --all / --json for every one)\n\
         \x20 credmgr search <term> [--json]\n\
         \x20 credmgr set <name> --node <id> [--label <l>]   (value from stdin)\n\
         \x20 credmgr set <name> --node <id> --bulk          (`label: value` lines from stdin become the\n\
         \x20                                      entry's fields; a `///` line separates blocks)\n\
         \x20 credmgr set <name> --node <id> (--field <label> | --field-id <id>) [--label <new>]\n\
         \x20                                      (change one field's value; the value is read from stdin)\n\
         \x20 credmgr rotate <name> [--node <id>] [--field <label> | --field-id <id>]\n\
         \x20                                      (new value from stdin, keeps history)\n\
         \x20 credmgr field ls <name> [--node <id>] [--json]   (labels, types and ids - never values)\n\
         \x20 credmgr field add <name> (--label <l> | --bulk) [--at <n>]   (value(s) from stdin)\n\
         \x20 credmgr field set <name> (--field <l> | --field-id <id>) [--label <new>]\n\
         \x20                                      [--type <t>|auto] [--mask on|off|auto]\n\
         \x20 credmgr field rm <name> (--field <l> | --field-id <id>)   (undo with `credmgr undo`)\n\
         \x20 credmgr field mv <name> (--field <l> | --field-id <id>) --to <n>   (positions count from 0)\n\
         \x20 credmgr rm <name> [--node <id>]       (soft, 7-day recovery)\n\
         \x20 credmgr undo <id> --node <id> [--mode replace|keep-both]\n\
         \x20                                      (undo a rotate, a field change or a remove by its audit id)\n\
         \x20 credmgr audit [--limit N] [--json]    (recent decisions; redacted for agent tokens)\n\
         \x20 credmgr verify [--json]                (checks manifest/registry integrity, needs unlock)\n\
         \x20 credmgr pending [--node <id>] [--json] (writes made while locked, awaiting review)\n\
         \x20 credmgr pending accept|discard <entry> --node <id>\n\
         \x20 credmgr doctor [--dry-run] [--purge-expired-seals]\n\
         \x20                                      (fixes safe drift; needs unlock, Admin. With\n\
         \x20                                      --purge-expired-seals it also destroys the retained\n\
         \x20                                      originals of nodes sealed more than seven days ago;\n\
         \x20                                      --dry-run only lists them)\n\
         \x20 credmgr generate [--length <n>] [--no-symbols] [--pronounceable] [--json]\n\
         \x20                                      (a password made by the broker, 8-128 characters,\n\
         \x20                                      printed to stdout; its strength goes to stderr)\n\
         \x20 credmgr approve <request> [--deny] [--code <n>]\n\
         \x20                                      (decide an agent's waiting request while the vault\n\
         \x20                                      stays locked: passphrase from stdin, plus your\n\
         \x20                                      authenticator code when two-factor is on)\n\
         \x20 credmgr approvals [<request>] [--json]\n\
         \x20                                      (what the waiting agent requests ask for, so you can\n\
         \x20                                      decide them with `credmgr approve`; works while locked)\n\
         \x20 credmgr doctor --rebuild-registry --confirm --known-revoked <id>[,<id>...]\n\
         \x20                                      (needs presence — native shell only, Phase 5; passphrase from stdin)\n\
         \x20 credmgr backup [--retain N]            (encrypted snapshot; passphrase from stdin)\n\
         \x20 credmgr import <file|-> --node <id> [--json]\n\
         \x20                                      (a .env-style file — NAME=value, # comments, export,\n\
         \x20                                      quotes — becomes entries in ONE all-or-nothing call;\n\
         \x20                                      `-` reads stdin; values are never printed)\n\
         \x20 credmgr notes show <id> [--json]       (the node's markdown note)\n\
         \x20 credmgr notes set <id> [--file <path>] (note text from the file or stdin; empty input is\n\
         \x20                                      refused — `set` never deletes)\n\
         \x20 credmgr notes clear <id>               (deletes the node's note; the only way to)\n\
         \x20 credmgr node ls [--json]\n\
         \x20 credmgr node create <id> --parent <id> [--label <l>] [--workdir <dir>]...\n\
         \x20 credmgr node workdir <id> [<dir>...]  (bind dirs: an agent run inside is scoped to <id>)\n\
         \x20 credmgr node rename <id> <label>      (the display name only; the id never changes)\n\
         \x20 credmgr node policy <id> --reason \"...\" [--agent-access read-write|read-only|none]\n\
         \x20                                      [--require-two-factor never|reveal|always]\n\
         \x20                                      [--lock-after-seconds <n>|none] [--json]\n\
         \x20                                      [--private-names|--no-private-names]\n\
         \x20                                      [--sibling-visibility shared|isolated]\n\
         \x20                                      [--descendant-read|--no-descendant-read]\n\
         \x20                                      (a partial patch, all-or-nothing; widening who can\n\
         \x20                                      read — descendant-read on, siblings shared — needs\n\
         \x20                                      presence, so it is refused here)\n\
         \x20 credmgr node seal <name>\n\
         \x20 credmgr node restore <name>\n\
         \x20 credmgr grant <from> --to <node> --scope read --reason \"...\"\n\
         \x20                                      (needs presence — native shell only, Phase 5)\n\
         \x20 credmgr grant ls [--json]\n\
         \x20 credmgr grant revoke <id>\n\
         \x20 credmgr mcp                          (MCP stdio server; for agent config, not humans)\n\
         \x20 credmgr --version"
    );
}

// ---- argument parsing ---------------------------------------------------
//
// Hand-rolled rather than a crate dependency: the command surface is small
// and flat, and a security-sensitive CLI gains nothing from an extra
// supply-chain dependency for `--flag value` extraction (same reasoning
// `docs/14_DECISIONS.md` ADR-039 already applied to path resolution).

fn take_flag_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let idx = args.iter().position(|a| a == flag)?;
    if idx + 1 >= args.len() {
        return None;
    }
    args.remove(idx); // the flag itself
    Some(args.remove(idx)) // its value, now at the same index
}

/// `take_flag_value` for free text that is RECORDED (a grant's or a policy
/// change's `--reason` goes into the audit log). A value that is itself a
/// `--flag` means the real text was left out; taking it would swallow that flag
/// — silently dropping what it asked for — and write its name into the audit
/// record as if it were the reason. Refused instead, naming both.
fn take_text_flag(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, String> {
    if let Some(idx) = args.iter().position(|a| a == flag) {
        if let Some(next) = args.get(idx + 1) {
            if next.starts_with("--") {
                return Err(format!(
                    "{flag} needs its text, but the next argument is the option '{next}' — \
                     put the text right after {flag}, as one quoted argument \
                     (it cannot itself start with '--')"
                ));
            }
        }
    }
    Ok(take_flag_value(args, flag))
}

fn take_bool_flag(args: &mut Vec<String>, flag: &str) -> bool {
    match args.iter().position(|a| a == flag) {
        Some(idx) => {
            args.remove(idx);
            true
        }
        None => false,
    }
}

/// Reads a secret value (a new/updated entry, a passphrase) from stdin —
/// never a CLI argument. Strips exactly one trailing `\n` (and a preceding
/// `\r`), the way a shell pipe/heredoc/`echo` always adds one, so a value
/// that deliberately ends in a blank line is preserved rather than
/// double-stripped.
fn read_stdin_value() -> Result<String, String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("could not read a value from stdin: {e}"))?;
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(buf)
}

/// One line from stdin, trailing `\n`/`\r\n` stripped — `credmgr init`
/// (ADR-061) needs two sequential secret-shaped reads (the passphrase, then
/// the recovery-code confirmation), which [`read_stdin_value`]'s
/// read-to-EOF shape can't give; every other command in this binary reads
/// exactly one value per invocation, so this stays local to `cmd_init`
/// rather than becoming a second general-purpose stdin reader.
fn read_stdin_line() -> Result<String, String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_line(&mut buf)
        .map_err(|e| format!("could not read a line from stdin: {e}"))?;
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(buf)
}

// ---- talking to the broker ----------------------------------------------

/// ADR-084: the broker accepts a name that mixes Latin with Greek or Cyrillic
/// letters and says so in `warnings`. It is the shape of a look-alike spoof, so
/// it is shown, once, on stderr — the command still succeeded.
fn print_name_warnings(value: &Value) {
    let flagged = value["warnings"]
        .as_array()
        .is_some_and(|w| w.iter().any(|x| x == "mixed_script_name"));
    if flagged {
        eprintln!(
            "warning: that name mixes Latin letters with Greek or Cyrillic ones - it can look \
             like another name. Check it is the one you meant"
        );
    }
}

/// Every response is `{ok: true, value: ...}` or `{ok: false, error: ...}`
/// (`10_API_AND_MCP.md §1`) — centralised here so every command surfaces a
/// denial identically, `remedy` included whenever the broker sent one.
fn unwrap_ok(response: Value) -> Result<Value, String> {
    if response["ok"].as_bool() == Some(true) {
        return Ok(response["value"].clone());
    }
    let error = response["error"].as_str().unwrap_or("unknown_error");
    let mut msg = error.to_string();
    if let Some(m) = response["message"].as_str() {
        msg.push_str(": ");
        msg.push_str(m);
    }
    // Two denials carry their detail in fields rather than a `message`; without
    // it `credmgr import` could not say WHICH name stopped a whole batch.
    if let (Some(name), Some(node)) = (response["name"].as_str(), response["node"].as_str()) {
        if error == "entry_exists" {
            msg.push_str(&format!(": '{name}' already exists on node '{node}'"));
        }
    }
    if error == "conflict" {
        if let (Some(expected), Some(current)) = (
            response["expectedGeneration"].as_u64(),
            response["currentGeneration"].as_u64(),
        ) {
            msg.push_str(&format!(
                ": the node is at generation {current}, not {expected} — it changed underneath this write"
            ));
        }
    }
    // ADR-088: the request id is what `credmgr approve` takes, and it is not in the message.
    if error == "approval_pending" {
        if let Some(request) = response["request"].as_str() {
            msg.push_str(&format!(
                "\n  request: {request}   (decide it with: credmgr approve {request})"
            ));
        }
    }
    if let Some(remedy) = response["remedy"].as_str() {
        msg.push_str("\n  remedy: ");
        msg.push_str(remedy);
    }
    Err(msg)
}

/// `CREDMGR_TOKEN`, when set, is presented on every request — an env var,
/// never a CLI flag, for the same reason a value is never a CLI flag: a
/// bearer token in argv lands in shell history and `ps` output exactly like
/// a password would (`10_API_AND_MCP.md §2`'s own reasoning, applied to the
/// one other bearer secret this binary ever handles). There is no `credmgr
/// login` yet — issuing a token is still test/fixture-only plumbing
/// (`crates/brokerd/src/token.rs`); this is the client-side half of
/// whatever Phase 5's session flow ends up writing to this env var.
fn call(op: &str, params: Value) -> Result<Value, String> {
    call_audited(op, params).map(|(value, _audit)| value)
}

/// [`call`], also returning the audit record id the broker answered with
/// (`10_API_AND_MCP.md §1`: "returns its id, so a caller can cite exactly what it
/// did"). `credmgr field rm` prints it, because it is what `credmgr undo` takes.
/// `None` when the broker sent none - best effort on its side.
fn call_audited(op: &str, params: Value) -> Result<(Value, Option<String>), String> {
    let token = std::env::var("CREDMGR_TOKEN").ok();
    let response =
        transport::call(op, token.as_deref(), params).map_err(|e: TransportError| e.to_string())?;
    let audit = response["audit"].as_str().map(str::to_string);
    unwrap_ok(response).map(|value| (value, audit))
}

// ---- commands ------------------------------------------------------------

/// ADR-061: vault bootstrap. Two round trips (`vault.init_begin` /
/// `vault.init_confirm`) rather than one — `04_CRYPTO_AND_KEYS.md §2.3`
/// requires the recovery code be shown once and the operator required to
/// re-enter it *before* setup completes, which a single synchronous op
/// can't do without either blocking the broker on interactive input or
/// writing the vault before the operator has proven they saved the code.
/// The passphrase and the retyped recovery code are both read one line at a
/// time from stdin, never argv — same invariant every other secret-taking
/// command in this binary already holds, just two reads instead of one.
fn cmd_init() -> Result<(), String> {
    let vault_dir = credmgr_store::paths::VaultPaths::default_location();
    // Courtesy client-side check — a fast refusal with no broker round
    // trip. The authoritative check lives in `BrokerState::begin_init`;
    // both call the same `credmgr_store::paths::is_inside_git_working_tree`
    // so the two can't quietly disagree (ADR-061).
    if credmgr_store::paths::is_inside_git_working_tree(vault_dir.root()) {
        return Err(format!(
            "refusing to create a vault inside a git working tree ({})",
            vault_dir.root().display()
        ));
    }

    println!("Choose a vault passphrase (from stdin, one line):");
    // Flushed before every stdin read below: stdout is fully buffered
    // (not line-buffered) whenever it isn't a real terminal — a driving
    // script piping stdin/reading stdout interactively (the integration
    // test) would otherwise deadlock, waiting on output still sitting in
    // this process's own buffer while this process waits on input the
    // script hasn't sent yet because it hasn't seen the prompt.
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let passphrase = read_stdin_line()?;
    if passphrase.is_empty() {
        return Err("a passphrase is required".to_string());
    }

    let begin = call("vault.init_begin", json!({ "passphrase": passphrase }))?;
    let recovery_code = begin["recoveryCode"]
        .as_str()
        .ok_or("credmgrd did not return a recovery code")?
        .to_string();

    println!();
    println!("Vault recovery code — write this down now, it will not be shown again:");
    println!();
    // `RECOVERY_CODE=` line, same "greppable KEY=value alongside the
    // human-readable framing" convention `print_unlock_result`'s
    // `export CREDMGR_TOKEN=...` already uses.
    println!("RECOVERY_CODE={recovery_code}");
    println!();
    println!("Retype it to confirm you've saved it (from stdin, one line):");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let confirmation = read_stdin_line()?;

    call(
        "vault.init_confirm",
        json!({ "recoveryCode": confirmation }),
    )?;
    println!("vault created at {}", vault_dir.root().display());
    Ok(())
}

fn cmd_status() -> Result<(), String> {
    let value = call("vault.status", json!({}))?;
    println!("locked: {}", value["locked"].as_bool().unwrap_or(true));
    // ADR-090: a count only; `credmgr approvals` says what they are.
    let waiting = value["pendingApprovals"].as_u64().unwrap_or(0);
    if waiting > 0 {
        println!("approvals waiting: {waiting}   (see them with: credmgr approvals)");
    }
    Ok(())
}

/// `ADR-056`: a real `vault.unlock`/`vault.gate_verify` success is a real
/// login and mints a real token — printed as `export CREDMGR_TOKEN=<id>` so
/// `eval "$(credmgr unlock <<< "$pw")"` captures it into the caller's shell,
/// the same idiom `ssh-agent -s`/`gpg-agent` use for "a subprocess
/// authenticated, hand the result to my shell." `locked: <bool>` is printed
/// either way, unconditionally, exactly as before this ADR — a response with
/// no `token` (e.g. `vault.status`, which never has one) leaves this a no-op
/// beyond the status line.
fn print_unlock_result(value: &Value) {
    println!("locked: {}", value["locked"].as_bool().unwrap_or(true));
    // ADR-085: a step-up mints no token — it opens a window.
    if value["elevated"].as_bool() == Some(true) {
        println!(
            "second factor accepted for {} seconds",
            value["expiresIn"].as_u64().unwrap_or(0)
        );
    }
    if let Some(token) = value["token"].as_str() {
        println!("export CREDMGR_TOKEN={token}");
        // ADR-065: this is the vault owner's login — it reaches every
        // project until the vault locks. A `#` line, so `eval` ignores it.
        println!(
            "# CREDMGR_TOKEN opens every project in this vault until it locks — \
             keep it out of any shell an AI agent runs in"
        );
    }
}

fn cmd_unlock() -> Result<(), String> {
    let passphrase = read_stdin_value()?;
    // ADR-063: the broker builds its keystore from this passphrase per
    // request, proves it against `root.wrap.pass`, and loads the vault from
    // disk on the first unlock after a restart.
    let value = call("vault.unlock", json!({ "passphrase": passphrase }))?;
    print_unlock_result(&value);
    Ok(())
}

fn cmd_lock() -> Result<(), String> {
    let value = call("vault.lock", json!({}))?;
    println!("locked: {}", value["locked"].as_bool().unwrap_or(true));
    Ok(())
}

/// `credmgr gate verify <code>` — completes `07_TWO_FACTOR.md §3`'s second
/// factor after a `vault.unlock` that returned `two_factor_required`. `code`
/// is a 6-digit TOTP, not a secret in the `passphrase`/`set`-value sense (it
/// is worthless after ~90s, `07 §5`), so it is an ordinary positional
/// argument rather than stdin — unlike every other secret this binary
/// handles, argv exposure here costs an attacker nothing they couldn't get
/// by shoulder-surfing the same 6 digits directly.
fn cmd_gate(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr gate verify <code> | gate enroll | gate recover";
    if args.is_empty() {
        return Err(USAGE.to_string());
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "verify" => {
            let code = args
                .first()
                .cloned()
                .ok_or("usage: credmgr gate verify <code>")?;
            let value = call("vault.gate_verify", json!({ "code": code }))?;
            print_unlock_result(&value);
            Ok(())
        }
        // `07_TWO_FACTOR.md §4`'s CLI enrolment path. Needs an unlocked
        // login (`CREDMGR_TOKEN`). Prints the otpauth URI for an
        // authenticator app, reads one current code from stdin, and prints
        // the ten gate recovery codes — once, never again.
        "enroll" => {
            let begin = call("vault.gate_enroll_begin", json!({})).map_err(|e| {
                if e.starts_with("two_factor_required") {
                    "two_factor_required — replacing an enrolled gate needs its second factor, \
                     fresh: `credmgr lock`, unlock again, `credmgr gate verify <code>`, then run \
                     `credmgr gate enroll` within five minutes"
                        .to_string()
                } else {
                    e
                }
            })?;
            let uri = begin["otpauthUri"]
                .as_str()
                .ok_or("credmgrd did not return an otpauth URI")?;
            println!(
                "Add this to your authenticator app (it is the gate's secret — do not share it):"
            );
            println!();
            println!("OTPAUTH_URI={uri}");
            println!();
            println!("Then type the 6-digit code it shows (from stdin, one line):");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let code = read_stdin_line()?;
            let confirm = call("vault.gate_enroll_confirm", json!({ "code": code.trim() }))?;
            println!();
            println!("Two-factor is on. Recovery codes — each works once; store them offline now,");
            println!("they will not be shown again:");
            println!();
            for c in confirm["recoveryCodes"].as_array().into_iter().flatten() {
                if let Some(c) = c.as_str() {
                    println!("GATE_RECOVERY_CODE={c}");
                }
            }
            Ok(())
        }
        // ADR-064, the last door: authenticator lost and every gate recovery
        // code spent. The vault passphrase and the printed *root* recovery
        // code (the one `credmgr init` showed) together reset the gate; then
        // `credmgr unlock` works on the passphrase alone and `gate enroll`
        // sets up a new authenticator. Both secrets from stdin, one line each.
        "recover" => {
            println!("Vault passphrase (from stdin, one line):");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let passphrase = read_stdin_line()?;
            println!("Root recovery code — the one `credmgr init` printed (from stdin, one line):");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let code = read_stdin_line()?;
            let value = call(
                "vault.gate_recover",
                json!({ "passphrase": passphrase, "recoveryCode": code }),
            )?;
            if value["gateReset"].as_bool() == Some(true) {
                println!(
                    "gate reset — unlock with your passphrase, then run `credmgr gate enroll`"
                );
            } else {
                println!("no two-factor gate was enrolled — nothing to reset");
            }
            Ok(())
        }
        other => Err(format!("unknown 'gate' subcommand: {other}\n{USAGE}")),
    }
}

/// ADR-066: workdir arguments are sent absolute — a relative one is taken
/// against this process's own cwd, which is what a person typing `.` means.
/// The broker canonicalises and validates them; this only resolves `.`.
fn absolute_dirs(dirs: Vec<String>) -> Result<Vec<String>, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot read the current directory: {e}"))?;
    Ok(dirs
        .into_iter()
        .map(|d| {
            let p = std::path::Path::new(&d);
            if p.is_absolute() {
                d
            } else {
                cwd.join(p).to_string_lossy().into_owned()
            }
        })
        .collect())
}

/// `credmgr mcp` — the MCP stdio server. Blocks on stdin until EOF (the
/// client process closing the pipe), the same lifecycle every stdio-based
/// MCP server has. Each `tools/call` reaches `credmgrd` over
/// `credmgr_mcp::transport`'s own socket connection — this subcommand never
/// touches the broker directly.
fn cmd_mcp() -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    credmgr_mcp::server::run(stdin.lock(), stdout.lock())
        .map_err(|e| format!("mcp server i/o error: {e}"))
}

fn cmd_whoami(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let value = call("whoami", json!({}))?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    println!("node: {}", value["node"].as_str().unwrap_or("?"));
    if let Some(caps) = value["capabilities"].as_array() {
        let names: Vec<&str> = caps.iter().filter_map(Value::as_str).collect();
        println!("capabilities: {}", names.join(", "));
    }
    if let Some(reachable) = value["reachable"].as_array() {
        let names: Vec<&str> = reachable.iter().filter_map(Value::as_str).collect();
        println!("reachable: {}", names.join(", "));
    }
    Ok(())
}

fn cmd_list(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    let value = match node {
        Some(node) => call("entry.list", json!({ "node": node }))?,
        None => call("node.list", json!({}))?,
    };
    if as_json {
        println!("{value}");
        return Ok(());
    }
    let key = if value.get("names").is_some() {
        "names"
    } else {
        "nodes"
    };
    if let Some(items) = value[key].as_array() {
        for item in items {
            if let Some(s) = item.as_str() {
                println!("{s}");
            }
        }
    }
    Ok(())
}

fn cmd_search(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let term = args
        .first()
        .cloned()
        .ok_or("usage: credmgr search <term>")?;
    let value = call("search", json!({ "term": term }))?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    if let Some(results) = value["results"].as_array() {
        for r in results {
            println!(
                "{}\t{}",
                r["node"].as_str().unwrap_or("?"),
                r["name"].as_str().unwrap_or("?")
            );
        }
    }
    Ok(())
}

/// Resolves a bare entry name to `(node, entry_id)` — every user-facing
/// command takes a name, never the broker's internal entry id
/// (`10_API_AND_MCP.md §2`: `credmgr get <name>`).
fn resolve_name(name: &str, node: Option<&str>) -> Result<(String, String), String> {
    if let Some(node) = node {
        let value = call("entry.list", json!({ "node": node }))?;
        let ids = value["ids"].as_array().cloned().unwrap_or_default();
        let names = value["names"].as_array().cloned().unwrap_or_default();
        for (id, n) in ids.iter().zip(names.iter()) {
            if n.as_str() == Some(name) {
                return Ok((
                    node.to_string(),
                    id.as_str().unwrap_or_default().to_string(),
                ));
            }
        }
        return Err(format!("no entry named '{name}' on node '{node}'"));
    }
    let value = call("search", json!({ "term": name }))?;
    let results = value["results"].as_array().cloned().unwrap_or_default();
    let matches: Vec<&Value> = results
        .iter()
        .filter(|r| r["name"].as_str() == Some(name))
        .collect();
    match matches.len() {
        0 => Err(format!("no entry named '{name}' found in scope")),
        1 => Ok((
            matches[0]["node"].as_str().unwrap_or_default().to_string(),
            matches[0]["id"].as_str().unwrap_or_default().to_string(),
        )),
        _ => {
            let nodes: Vec<&str> = matches.iter().filter_map(|r| r["node"].as_str()).collect();
            Err(format!(
                "'{name}' exists on more than one node ({}) — specify --node",
                nodes.join(", ")
            ))
        }
    }
}

/// `credmgr get <name> [--node] [--field <label> | --field-id <id> | --all] [--json]`.
///
/// A one-field entry prints its value, exactly as before. An entry with several
/// fields is **refused without a selector** — printing "the" value of a
/// four-field entry would be a guess — with the labels in the refusal so the next
/// command is obvious. `--field` finds the field's id through `entry.get` (which
/// carries labels, never a value) and then reveals only that field; `--all` and
/// `--json` reveal every field. With no selector the first call is the reveal
/// itself, so a locked vault still gets the one-tap approval path (ADR-042).
fn cmd_get(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr get <name> [--node <id>] \
         [--field <label> | --field-id <id> | --all] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let all = take_bool_flag(&mut args, "--all");
    let node = take_flag_value(&mut args, "--node");
    let selector = fields::Selector::take(&mut args)?;
    reject_flags(&args, USAGE)?;
    let [name] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    if all && selector.is_some() {
        return Err(
            "--all shows every field; it cannot be combined with --field or --field-id".to_string(),
        );
    }
    let (node, entry) = resolve_name(name, node.as_deref())?;

    let mut params = json!({ "node": node, "entry": entry });
    if selector.is_some() {
        let id = match &selector.id {
            Some(id) => id.clone(),
            None => fields::pick(&fields::entry_meta(&node, &entry)?, name, &selector)?,
        };
        params["fieldIds"] = json!([id]);
    }
    let answer = call("entry.reveal", params)?;
    let shown = fields::revealed(&answer);

    if as_json {
        println!("{}", Value::Array(shown));
        return Ok(());
    }
    if all {
        print!("{}", fields::render_all(&fields::pairs(&shown)));
        return Ok(());
    }
    match shown.as_slice() {
        [only] => {
            println!("{}", only["value"].as_str().unwrap_or(""));
            Ok(())
        }
        _ => Err(selection_error(format!(
            "entry '{name}' has {} fields ({}) — pass --field <label>, --field-id <id>, --all or --json",
            shown.len(),
            fields::label_list(&shown),
        ))),
    }
}

/// `credmgr set <name> --node <id>` and its multi-field forms. The value (or the
/// bulk text) is read from stdin, never argv.
///
/// - plain: the value of a new entry, or of an existing one-field entry;
///   `--label` names the field of a new entry (or renames it on an update);
/// - `--bulk`: `label: value` lines from stdin become the entry's fields — a new
///   entry, or the full replacement of an existing one's field list;
/// - `--field` / `--field-id`: change one field of an existing entry.
fn cmd_set(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr set <name> --node <id> \
         [--bulk | --field <label> | --field-id <id>] [--label <l>]   (value from stdin)";
    let bulk = take_bool_flag(&mut args, "--bulk");
    let node = take_flag_value(&mut args, "--node").ok_or(USAGE)?;
    let selector = fields::Selector::take(&mut args)?;
    let label = take_text_flag(&mut args, "--label")?;
    reject_flags(&args, USAGE)?;
    let [name] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    if bulk && (selector.is_some() || label.is_some()) {
        return Err(
            "--bulk takes its labels from the text on stdin; it cannot be combined with --field, --field-id or --label"
                .to_string(),
        );
    }
    let name = name.clone();

    enum Payload {
        Value(String),
        Fields(Vec<Value>),
    }
    let payload = if bulk {
        Payload::Fields(fields::read_bulk_stdin()?)
    } else {
        Payload::Value(read_stdin_value()?)
    };

    // An existing name goes through `entry.update` (needs its id and the
    // manifest's current generation, F-9's optimistic-concurrency check); a
    // brand-new name goes through `entry.create`, which also works on a
    // locked vault (`04 §3`) while `update` does not.
    let list = call("entry.list", json!({ "node": node }))?;
    let ids = list["ids"].as_array().cloned().unwrap_or_default();
    let names = list["names"].as_array().cloned().unwrap_or_default();
    let existing = ids
        .iter()
        .zip(names.iter())
        .find(|(_, n)| n.as_str() == Some(name.as_str()))
        .map(|(id, _)| id.as_str().unwrap_or_default().to_string());

    let value = match existing {
        Some(entry_id) => {
            let generation = list["generation"].as_u64().unwrap_or(0);
            let mut params = json!({ "node": node, "entry": entry_id, "generation": generation });
            match payload {
                Payload::Fields(f) => params["fields"] = json!(f),
                Payload::Value(v) => {
                    params["value"] = json!(v);
                    if let Some(l) = &label {
                        params["label"] = json!(l);
                    }
                    if selector.is_some() {
                        let meta = fields::entry_meta(&node, &entry_id)?;
                        params["field"] = json!(fields::pick(&meta, &name, &selector)?);
                    }
                }
            }
            call("entry.update", params).map_err(|e| fields::with_field_hint(e, &name))?
        }
        None => {
            if selector.is_some() {
                return Err(format!(
                    "no entry named '{name}' on node '{node}' to change a field of — \
                     `credmgr set {name} --node {node}` creates it"
                ));
            }
            let mut params = json!({ "node": node, "name": name });
            match payload {
                Payload::Fields(f) => params["fields"] = json!(f),
                Payload::Value(v) => {
                    params["value"] = json!(v);
                    if let Some(l) = &label {
                        params["label"] = json!(l);
                    }
                }
            }
            call("entry.create", params)?
        }
    };
    print_name_warnings(&value);
    let count = value["fieldCount"].as_u64().unwrap_or(1);
    let many = if count > 1 {
        format!(" ({count} fields)")
    } else {
        String::new()
    };
    if value["pending"].as_bool() == Some(true) {
        println!(
            "saved{many} — vault is locked; after unlocking, review it with `credmgr pending`"
        );
    } else {
        println!("saved{many}");
    }
    Ok(())
}

/// The manifest's current generation for `node` — F-9's optimistic-
/// concurrency check, same requirement `cmd_set`'s `entry.update` path
/// already has. A second `entry.list` round trip beyond whatever
/// `resolve_name` already made when `--node` was given: correctness over
/// shaving one call, and `search`'s response (used when `--node` is
/// omitted) never carries a generation at all (`10_API_AND_MCP.md §1`'s
/// `entry.list` response is the only source of it).
fn entry_generation(node: &str) -> Result<u64, String> {
    let list = call("entry.list", json!({ "node": node }))?;
    Ok(list["generation"].as_u64().unwrap_or(0))
}

/// `credmgr rotate <name> [--node] [--field <label> | --field-id <id>]` - the new
/// value is read from stdin. On an entry with several fields it names the field
/// being rotated; the broker keeps the previous envelope as history.
fn cmd_rotate(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr rotate <name> [--node <id>] \
         [--field <label> | --field-id <id>]   (new value from stdin)";
    let node = take_flag_value(&mut args, "--node");
    let selector = fields::Selector::take(&mut args)?;
    reject_flags(&args, USAGE)?;
    let [name] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let (node, entry) = resolve_name(name, node.as_deref())?;
    let (generation, field) = if selector.is_some() {
        let meta = fields::entry_meta(&node, &entry)?;
        let id = fields::pick(&meta, name, &selector)?;
        (meta["generation"].as_u64().unwrap_or(0), Some(id))
    } else {
        (entry_generation(&node)?, None)
    };
    let new_value = read_stdin_value()?;
    let mut params =
        json!({ "node": node, "entry": entry, "value": new_value, "generation": generation });
    if let Some(field) = field {
        params["field"] = json!(field);
    }
    let value = call("entry.rotate", params).map_err(|e| fields::with_field_hint(e, name))?;
    println!(
        "rotated — generation {}",
        value["generation"].as_u64().unwrap_or(generation)
    );
    Ok(())
}

fn cmd_rm(mut args: Vec<String>) -> Result<(), String> {
    let node = take_flag_value(&mut args, "--node");
    let name = args
        .first()
        .cloned()
        .ok_or("usage: credmgr rm <name> [--node <id>]")?;
    let (node, entry) = resolve_name(&name, node.as_deref())?;
    let generation = entry_generation(&node)?;
    call(
        "entry.remove",
        json!({ "node": node, "entry": entry, "generation": generation }),
    )?;
    println!("removed '{name}' — recoverable for 7 days");
    Ok(())
}

fn cmd_undo(mut args: Vec<String>) -> Result<(), String> {
    let node = take_flag_value(&mut args, "--node")
        .ok_or("usage: credmgr undo <id> --node <id> [--mode replace|keep-both]")?;
    let mode = take_flag_value(&mut args, "--mode");
    let id = args
        .first()
        .cloned()
        .ok_or("usage: credmgr undo <id> --node <id> [--mode replace|keep-both]")?;
    let generation = entry_generation(&node)?;
    let mut params = json!({ "node": node, "id": id, "generation": generation });
    if let Some(mode) = mode {
        params["mode"] = json!(mode);
    }
    let value = call("entry.undo", params)?;
    println!("{value}");
    Ok(())
}

fn cmd_audit(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let limit: u64 = take_flag_value(&mut args, "--limit")
        .map(|s| {
            s.parse()
                .map_err(|_| format!("--limit must be a number, got '{s}'"))
        })
        .transpose()?
        .unwrap_or(50);
    let value = call("audit.tail", json!({ "limit": limit }))?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    if let Some(records) = value["records"].as_array() {
        for r in records {
            println!(
                "{}\t{}\t{}\t{}",
                r["timestamp"].as_i64().unwrap_or(0),
                r["action"].as_str().unwrap_or("?"),
                r["node"].as_str().unwrap_or("-"),
                r["decision"].as_str().unwrap_or("-"),
            );
        }
    }
    Ok(())
}

fn cmd_verify(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let value = call("maintenance.verify", json!({}))?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    let ok = value["ok"].as_bool().unwrap_or(false);
    println!(
        "nodes checked: {}\nok: {ok}",
        value["nodesChecked"].as_u64().unwrap_or(0)
    );
    if let Some(errors) = value["errors"].as_array() {
        for e in errors {
            println!(
                "ERROR  {}: {}",
                e["node"],
                e["detail"].as_str().unwrap_or("?")
            );
        }
    }
    if let Some(warnings) = value["warnings"].as_array() {
        for w in warnings {
            println!(
                "warn   {}: {}",
                w["node"],
                w["detail"].as_str().unwrap_or("?")
            );
        }
    }
    Ok(())
}

/// The locked-write review tray (F-1, ADR-023, ADR-069). `set` against a
/// locked vault prints "pending review at next unlock"; this is where that
/// review happens. With no `--node`, lists the tray of every node the
/// caller can see.
fn cmd_pending(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    let sub = if args.is_empty() {
        "list".to_string()
    } else {
        args.remove(0)
    };
    match sub.as_str() {
        "list" => {
            let nodes: Vec<String> = match node {
                Some(n) => vec![n],
                None => call("node.list", json!({}))?["nodes"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            let mut all = Vec::new();
            for n in &nodes {
                let value = call("vault.pending_list", json!({ "node": n }))?;
                if let Some(items) = value["pending"].as_array() {
                    for item in items {
                        let mut item = item.clone();
                        item["node"] = json!(n);
                        all.push(item);
                    }
                }
            }
            if as_json {
                println!("{}", json!({ "pending": all }));
            } else if all.is_empty() {
                println!("nothing pending");
            } else {
                for item in &all {
                    // ADR-078: a held multi-field entry says how many fields it
                    // holds (the count only - the tray never shows a label or a value).
                    let fields = match item["fieldCount"].as_u64() {
                        Some(n) if n > 1 => format!("  ({n} fields)"),
                        _ => String::new(),
                    };
                    println!(
                        "{}  {}  {}{fields}  (accept: credmgr pending accept {} --node {})",
                        item["node"].as_str().unwrap_or("?"),
                        item["entry"].as_str().unwrap_or("?"),
                        item["name"].as_str().unwrap_or("?"),
                        item["entry"].as_str().unwrap_or("?"),
                        item["node"].as_str().unwrap_or("?"),
                    );
                }
            }
            Ok(())
        }
        "accept" | "discard" => {
            let entry = args
                .first()
                .ok_or_else(|| format!("usage: credmgr pending {sub} <entry> --node <id>"))?;
            let node = node.ok_or_else(|| format!("credmgr pending {sub} needs --node <id>"))?;
            let op = if sub == "accept" {
                "vault.pending_accept"
            } else {
                "vault.pending_discard"
            };
            call(op, json!({ "node": node, "entry": entry }))?;
            println!(
                "{} {entry} on {node}",
                if sub == "accept" {
                    "accepted"
                } else {
                    "discarded"
                }
            );
            Ok(())
        }
        other => Err(format!(
            "unknown pending subcommand '{other}' — use list, accept or discard"
        )),
    }
}

fn cmd_doctor(mut args: Vec<String>) -> Result<(), String> {
    let dry_run = take_bool_flag(&mut args, "--dry-run");
    let purge_expired = take_bool_flag(&mut args, "--purge-expired-seals");
    let rebuild = take_bool_flag(&mut args, "--rebuild-registry");
    let as_json = take_bool_flag(&mut args, "--json");

    if rebuild {
        let confirm = take_bool_flag(&mut args, "--confirm");
        let known_revoked: Vec<String> = take_flag_value(&mut args, "--known-revoked")
            .map(|s| s.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        let passphrase = read_stdin_value()?;
        let value = call(
            "maintenance.doctor",
            json!({
                "rebuildRegistry": true,
                "confirm": confirm,
                "knownRevokedGrantIds": known_revoked,
                "passphrase": passphrase,
            }),
        )?;
        println!("{value}");
        return Ok(());
    }

    let mut params = json!({ "apply": !dry_run });
    if purge_expired {
        params["purgeExpiredSeals"] = json!(true);
    }
    let value = call("maintenance.doctor", params)?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    println!(
        "applied: {}\nfixes: {}",
        value["applied"].as_bool().unwrap_or(false),
        value["fixCount"].as_u64().unwrap_or(0)
    );
    if let Some(fixes) = value["fixes"].as_array() {
        for f in fixes {
            println!(
                "fixed  {}: {}",
                f["node"],
                f["type"].as_str().unwrap_or("?")
            );
        }
    }
    if let Some(unfixable) = value["unfixable"].as_array() {
        for u in unfixable {
            println!(
                "STUCK  {}: {}",
                u["node"],
                u["detail"].as_str().unwrap_or("?")
            );
        }
    }
    Ok(())
}

/// `credmgr generate` (ADR-087) - the password is made by the broker, not here, and
/// goes to stdout alone so it pipes (`credmgr generate | credmgr set NAME --node n`);
/// the strength goes to stderr. It is never put in argv by this command.
fn cmd_generate(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr generate [--length <8-128>] [--no-symbols] [--pronounceable] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let no_symbols = take_bool_flag(&mut args, "--no-symbols");
    let pronounceable = take_bool_flag(&mut args, "--pronounceable");
    let length = take_flag_value(&mut args, "--length");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    let mut params = json!({});
    if let Some(l) = length {
        params["length"] = json!(l
            .parse::<u64>()
            .map_err(|_| format!("--length takes a number from 8 to 128 - got '{l}'"))?);
    }
    if no_symbols {
        params["symbols"] = json!(false);
    }
    if pronounceable {
        params["pronounceable"] = json!(true);
    }
    let value = call("util.generate", params)?;
    if as_json {
        println!("{value}");
    } else {
        println!("{}", value["value"].as_str().unwrap_or_default());
        eprintln!(
            "{} characters, about {} bits of entropy",
            value["length"].as_u64().unwrap_or(0),
            value["entropyBits"].as_u64().unwrap_or(0)
        );
    }
    Ok(())
}

/// `credmgr approve <request> [--deny] [--code <n>]` (ADR-088, 4b) - decides one
/// agent request while the vault stays locked. The passphrase is read from stdin
/// (never argv); the authenticator code, when two-factor is on, is `--code` (it is
/// worthless after about ninety seconds, like `gate verify <code>`). The login in
/// `CREDMGR_TOKEN`, if any, is deliberately not sent: the factors are the
/// authority here, and a token from before the lock is dead anyway.
fn cmd_approve(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr approve <request> [--deny] [--code <authenticator code>]  (passphrase from stdin)";
    let deny = take_bool_flag(&mut args, "--deny");
    let code = take_flag_value(&mut args, "--code");
    reject_flags(&args, USAGE)?;
    let [request] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let passphrase = read_stdin_value()?;
    let mut params = json!({ "request": request, "approved": !deny, "passphrase": passphrase });
    if let Some(code) = code {
        params["code"] = json!(code);
    }
    let response = transport::call("vault.approval_decide", None, params)
        .map_err(|e: TransportError| e.to_string())?;
    let value = unwrap_ok(response).map_err(|e| {
        if e.starts_with("two_factor_required") {
            "two_factor_required - two-factor is on: add --code <your authenticator code> \
             (a recovery code is not accepted here)"
                .to_string()
        } else {
            e
        }
    })?;
    println!(
        "{} request {} (node {}, entry {}) - the vault stayed locked",
        if deny { "denied" } else { "approved" },
        value["request"].as_str().unwrap_or(request),
        value["node"].as_str().unwrap_or("?"),
        value["entry"].as_str().unwrap_or("?"),
    );
    Ok(())
}

/// `credmgr approvals [<request>] [--json]` (ADR-090) - what the waiting agent
/// requests ask for. Read-only and works while the vault is locked; the decision
/// itself is `credmgr approve`. The login in `CREDMGR_TOKEN` is sent when there is
/// one (an unlocked vault answers only the owner's session) and left out when
/// the broker says it has expired (a locked vault has no sessions).
fn cmd_approvals(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr approvals [<request>] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    reject_flags(&args, USAGE)?;
    let params = match args.as_slice() {
        [] => json!({}),
        [request] => json!({ "request": request }),
        _ => return Err(USAGE.to_string()),
    };
    let value = match call("vault.approval_get", params.clone()) {
        Err(e) if e.starts_with("session_expired") => {
            let response = transport::call("vault.approval_get", None, params)
                .map_err(|e: TransportError| e.to_string())?;
            unwrap_ok(response)?
        }
        other => other?,
    };
    if as_json {
        println!("{value}");
        return Ok(());
    }
    let items: Vec<&Value> = match value["pending"].as_array() {
        Some(list) => list.iter().collect(),
        None => vec![&value],
    };
    if items.is_empty() {
        println!("no requests are waiting");
    }
    for a in items {
        let node = match a["nodeLabel"].as_str() {
            Some(label) => format!("{label} ({})", a["node"].as_str().unwrap_or("?")),
            None => a["node"].as_str().unwrap_or("?").to_string(),
        };
        let entry = match a["entryName"].as_str() {
            Some(name) => format!("{name} ({})", a["entry"].as_str().unwrap_or("?")),
            None => a["entry"].as_str().unwrap_or("?").to_string(),
        };
        println!(
            "{}  {}  node {node}  entry {entry}  {} s left{}",
            a["request"].as_str().unwrap_or("?"),
            a["state"].as_str().unwrap_or("pending"),
            a["expiresIn"].as_u64().unwrap_or(0),
            if a["nameHidden"].as_bool() == Some(true) {
                "  (names hidden)"
            } else {
                ""
            },
        );
    }
    Ok(())
}

fn cmd_backup(mut args: Vec<String>) -> Result<(), String> {
    let retain: u64 = take_flag_value(&mut args, "--retain")
        .map(|s| {
            s.parse()
                .map_err(|_| format!("--retain must be a number, got '{s}'"))
        })
        .transpose()?
        .unwrap_or(14);
    let passphrase = read_stdin_value()?;
    if passphrase.is_empty() {
        return Err("a backup passphrase is required on stdin".to_string());
    }
    let value = call(
        "maintenance.backup",
        json!({ "passphrase": passphrase, "retain": retain }),
    )?;
    println!("backup written: {}", value["path"].as_str().unwrap_or("?"));
    if let Some(pruned) = value["pruned"].as_array() {
        if !pruned.is_empty() {
            println!("pruned {} old backup(s)", pruned.len());
        }
    }
    Ok(())
}

fn cmd_node(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: credmgr node ls|create <id> --label <label> --parent <id> [--workdir <dir>]...|workdir <id> [<dir>...]|rename <id> <label>|policy <id> --reason \"...\" [flags]|seal <name>|restore <name>"
                .to_string(),
        );
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "create" => {
            let id = args
                .first()
                .cloned()
                .ok_or("usage: credmgr node create <id> --label <label> --parent <id>")?;
            let mut rest = args[1..].to_vec();
            let label = take_flag_value(&mut rest, "--label").unwrap_or_else(|| id.clone());
            let parent = take_flag_value(&mut rest, "--parent")
                .ok_or("usage: credmgr node create <id> --label <label> --parent <id>")?;
            let mut workdirs = Vec::new();
            while let Some(dir) = take_flag_value(&mut rest, "--workdir") {
                workdirs.push(dir);
            }
            let mut params = json!({ "id": id, "label": label, "parentId": parent });
            if !workdirs.is_empty() {
                params["workdirs"] = json!(absolute_dirs(workdirs)?);
            }
            let value = call("node.create", params)?;
            print_name_warnings(&value);
            println!("{value}");
            Ok(())
        }
        // ADR-066: bind directories to a node so an agent launched inside
        // one is scoped to it. Replaces the node's list; no dirs clears it.
        "workdir" => {
            let id = args
                .first()
                .cloned()
                .ok_or("usage: credmgr node workdir <id> [<dir>...]")?;
            let dirs = absolute_dirs(args[1..].to_vec())?;
            let value = call("node.set_workdirs", json!({ "node": id, "workdirs": dirs }))?;
            println!("{value}");
            Ok(())
        }
        // ADR-071: a rename changes the label a human reads; the id — what
        // grants, workdirs and every agent's scope refer to — never moves.
        // Global and Orphan refuse; that refusal is the broker's, surfaced as is.
        "rename" => {
            const USAGE: &str =
                "usage: credmgr node rename <id> <label>  (quote a label that has spaces)";
            let as_json = take_bool_flag(&mut args, "--json");
            reject_flags(&args, USAGE)?;
            let [node, label] = args.as_slice() else {
                return Err(USAGE.to_string());
            };
            let value = call("node.update", json!({ "node": node, "label": label }))?;
            print_name_warnings(&value);
            if as_json {
                println!("{value}");
            } else {
                println!(
                    "renamed {} (label is now '{}')",
                    value["node"].as_str().unwrap_or(node),
                    value["label"].as_str().unwrap_or(label)
                );
            }
            Ok(())
        }
        "policy" => cmd_node_policy(args),
        "ls" => {
            let as_json = take_bool_flag(&mut args, "--json");
            let value = call("node.list", json!({}))?;
            if as_json {
                println!("{value}");
                return Ok(());
            }
            if let Some(nodes) = value["nodes"].as_array() {
                for n in nodes {
                    if let Some(s) = n.as_str() {
                        println!("{s}");
                    }
                }
            }
            Ok(())
        }
        "seal" => {
            let name = args
                .first()
                .cloned()
                .ok_or("usage: credmgr node seal <name>")?;
            let value = call("node.seal", json!({ "node": name }))?;
            println!("{value}");
            Ok(())
        }
        "restore" => {
            let name = args
                .first()
                .cloned()
                .ok_or("usage: credmgr node restore <name>")?;
            let value = call("node.restore", json!({ "node": name }))?;
            println!("{value}");
            Ok(())
        }
        other => Err(format!("unknown 'node' subcommand: {other}")),
    }
}

/// `10_API_AND_MCP.md §2`: `credmgr grant <from> --to <to> --scope read
/// --reason "…"` · `credmgr grant ls | revoke <id>`. `grant.create`'s
/// positive path is unconditionally `presence_required` until Phase 5's
/// native shell exists (`ops.rs`'s own doc on `grant.create`) — this command
/// is wired now anyway, since the CLI surface itself, and every validation
/// short of presence, are real today; only the final step is not.
fn cmd_grant(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: credmgr grant <from> --to <node> --scope read --reason \"...\" \
             | credmgr grant ls [--json] | credmgr grant revoke <id>"
                .to_string(),
        );
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "ls" => {
            let as_json = take_bool_flag(&mut args, "--json");
            let value = call("grant.list", json!({}))?;
            if as_json {
                println!("{value}");
                return Ok(());
            }
            if let Some(grants) = value["grants"].as_array() {
                for g in grants {
                    println!(
                        "{}\t{}\t{}\t{}",
                        g["id"].as_str().unwrap_or("?"),
                        g["from"].as_str().unwrap_or("?"),
                        g["to"]["nodeId"].as_str().unwrap_or("?"),
                        g["reason"].as_str().unwrap_or(""),
                    );
                }
            }
            Ok(())
        }
        "revoke" => {
            let id = args
                .first()
                .cloned()
                .ok_or("usage: credmgr grant revoke <id>")?;
            call("grant.revoke", json!({ "id": id }))?;
            println!("revoked '{id}'");
            Ok(())
        }
        from => {
            let mut args = args;
            let to = take_flag_value(&mut args, "--to")
                .ok_or("usage: credmgr grant <from> --to <node> --scope read --reason \"...\"")?;
            let scope_str =
                take_flag_value(&mut args, "--scope").unwrap_or_else(|| "read".to_string());
            let reason = take_text_flag(&mut args, "--reason")?
                .ok_or("--reason is required (min 8 characters)")?;
            let scope: Vec<&str> = scope_str.split(',').map(str::trim).collect();
            call(
                "grant.create",
                json!({
                    "from": from,
                    "to": { "kind": "node", "nodeId": to },
                    "scope": scope,
                    "reason": reason,
                }),
            )?;
            println!("grant created");
            Ok(())
        }
    }
}

// ---- import, node policy, notes (ADR-071 … ADR-073) ------------------------

/// A leftover `--…` once every known flag has been taken is a typo, or a flag
/// that was missing its value — say so instead of treating it as a positional.
fn reject_flags(args: &[String], usage: &str) -> Result<(), String> {
    match args.iter().find(|a| a.starts_with("--")) {
        Some(flag) => Err(format!(
            "unknown option, or '{flag}' is missing its value\n{usage}"
        )),
        None => Ok(()),
    }
}

/// Reads text from `reader`, refusing more than `max` bytes (rather than
/// truncating — a cut-off `.env` or note is worse than an error) and anything
/// that is not UTF-8.
fn read_capped(reader: impl Read, max: usize, what: &str) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read {what}: {e}"))?;
    if bytes.len() > max {
        return Err(format!("{what} is larger than {max} bytes"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{what} is not valid UTF-8 text"))
}

/// A `.env` file is a few KiB; 4 MiB is generous and bounds the read.
const IMPORT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// `entry.create_batch`'s own ceiling (ADR-073) — checked here as well so an
/// oversized file is refused before anything is sent, with advice the broker's
/// terse refusal does not carry.
const IMPORT_MAX_ENTRIES: usize = 500;

/// ADR-073: `credmgr import <file|-> --node <id>` — an `.env`-shaped file into
/// ONE node, as ONE `entry.create_batch` call. The broker validates every name
/// before the first write, so a refused batch (a name already on the node, a
/// duplicate, a capability the caller lacks) creates nothing at all — not even
/// its valid half. The file is read here and the values go straight into the
/// request; nothing in this function prints one. Errors name a line number and
/// never its text (`dotenv.rs`).
fn cmd_import(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr import <file|-> --node <id> [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node").ok_or(USAGE)?;
    reject_flags(&args, USAGE)?;
    let [source] = args.as_slice() else {
        return Err(USAGE.to_string());
    };

    let label = if source == "-" { "stdin" } else { source };
    let text = if source == "-" {
        read_capped(std::io::stdin().lock(), IMPORT_MAX_BYTES, "the input")?
    } else {
        let file =
            std::fs::File::open(source).map_err(|e| format!("could not open '{source}': {e}"))?;
        read_capped(file, IMPORT_MAX_BYTES, &format!("'{source}'"))?
    };
    let parsed = dotenv::parse(&text).map_err(|e| format!("{label}: {e}"))?;

    if parsed.entries.is_empty() {
        let skipped = if parsed.skipped_empty.is_empty() {
            String::new()
        } else {
            format!(
                " ({} had an empty value: {})",
                parsed.skipped_empty.len(),
                parsed.skipped_empty.join(", ")
            )
        };
        return Err(format!(
            "nothing to import from {label}: no NAME=value line with a value{skipped}"
        ));
    }
    if parsed.entries.len() > IMPORT_MAX_ENTRIES {
        return Err(format!(
            "{label} holds {} entries; one import takes at most {IMPORT_MAX_ENTRIES} — \
             split the file and import the parts one after another",
            parsed.entries.len()
        ));
    }

    let entries: Vec<Value> = parsed
        .entries
        .iter()
        .map(|e| json!({ "name": e.name, "value": e.value }))
        .collect();
    let mut value = call(
        "entry.create_batch",
        json!({ "node": node, "entries": entries }),
    )?;
    value["skippedEmpty"] = json!(parsed.skipped_empty);
    print_name_warnings(&value);

    let created = value["created"].as_array().cloned().unwrap_or_default();
    let complete = value["complete"].as_bool() == Some(true);
    let held = created
        .iter()
        .filter(|c| c["pending"].as_bool() == Some(true))
        .count();
    if as_json {
        println!("{value}");
    } else {
        for c in &created {
            let name = c["name"].as_str().unwrap_or("?");
            if c["pending"].as_bool() == Some(true) {
                println!("held     {name}");
            } else {
                println!("created  {name}");
            }
        }
        println!(
            "imported {} of {} entries into {node}",
            created.len(),
            value["total"]
                .as_u64()
                .unwrap_or(parsed.entries.len() as u64)
        );
        if !parsed.skipped_empty.is_empty() {
            println!(
                "skipped {} empty value(s), not imported: {}",
                parsed.skipped_empty.len(),
                parsed.skipped_empty.join(", ")
            );
        }
        if held > 0 {
            println!(
                "the vault is locked — {held} {} in the review tray; \
                 after unlocking, review them with `credmgr pending`",
                if held == 1 {
                    "entry waits"
                } else {
                    "entries wait"
                }
            );
        }
    }
    if !complete {
        return Err(partial_import_error(created.len(), &value["failed"]));
    }
    if source != "-" {
        eprintln!(
            "note: {source} still holds the plaintext values — delete it once you have checked the import"
        );
    }
    Ok(())
}

/// What `entry.create_batch` answers when it stopped part-way (`complete:
/// false`): which entry failed, and exactly how much was saved before it. The
/// broker's `failed.error` carries a name and a reason, never a value.
fn partial_import_error(saved: usize, failed: &Value) -> String {
    let Some(index) = failed["index"].as_u64().map(|i| i + 1) else {
        // Fail closed: an answer that is neither complete nor says what failed
        // is not reported as a success.
        return format!(
            "the import did not complete and the broker did not say which entry failed; \
             {saved} entries are listed above as saved — check with `credmgr list`"
        );
    };
    let name = failed["name"].as_str().unwrap_or("?");
    let error = failed["error"].as_str().unwrap_or("unknown error");
    if saved == 0 {
        format!("the import failed on entry {index} ({name}) — {error}; nothing was saved")
    } else {
        format!(
            "the import stopped part-way: entry {index} ({name}) failed — {error}; \
             the {saved} entries above were saved, the rest were not attempted"
        )
    }
}

/// The six fields `node.policy` accepts, as the CLI spells them. Enum values are
/// checked here so a typo is refused before a round trip; the broker's own
/// parse is still the authority.
const AGENT_ACCESS: &[&str] = &["read-write", "read-only", "none"];
const TWO_FACTOR: &[&str] = &["never", "reveal", "always"];
const SIBLING_VISIBILITY: &[&str] = &["shared", "isolated"];

/// `--on` / `--no-on` pairs: neither → unchanged, one → that value, both →
/// a contradiction worth refusing rather than guessing at.
fn take_bool_pair(args: &mut Vec<String>, on: &str, off: &str) -> Result<Option<bool>, String> {
    match (take_bool_flag(args, on), take_bool_flag(args, off)) {
        (true, true) => Err(format!("{on} and {off} contradict each other")),
        (true, false) => Ok(Some(true)),
        (false, true) => Ok(Some(false)),
        (false, false) => Ok(None),
    }
}

fn take_choice(
    args: &mut Vec<String>,
    flag: &str,
    allowed: &[&str],
) -> Result<Option<String>, String> {
    let Some(v) = take_flag_value(args, flag) else {
        return Ok(None);
    };
    if allowed.contains(&v.as_str()) {
        Ok(Some(v))
    } else {
        Err(format!("{flag} takes {} — got '{v}'", allowed.join("|")))
    }
}

/// How one policy value reads in the report.
fn show_policy_value(v: &Value) -> String {
    match v {
        Value::Null => "none".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// ADR-071: `credmgr node policy <id> --reason "…" [flags]` — a partial patch;
/// the broker applies all of it or none of it. Narrowing or neutral changes
/// need only the admin gate. Turning on `descendantRead` or sharing siblings
/// WIDENS who can read what, which needs presence — and presence is not
/// attestable from a CLI, so the broker answers `presence_required` and
/// nothing is applied. That is reported as exactly that, not as a failure of
/// the command.
fn cmd_node_policy(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr node policy <id> --reason \"...\" \
         [--agent-access read-write|read-only|none] [--require-two-factor never|reveal|always] \
         [--lock-after-seconds <n>|none] [--private-names|--no-private-names] \
         [--sibling-visibility shared|isolated] [--descendant-read|--no-descendant-read] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let reason = take_text_flag(&mut args, "--reason")?;
    let agent_access = take_choice(&mut args, "--agent-access", AGENT_ACCESS)?;
    let two_factor = take_choice(&mut args, "--require-two-factor", TWO_FACTOR)?;
    let sibling = take_choice(&mut args, "--sibling-visibility", SIBLING_VISIBILITY)?;
    let lock_after = take_flag_value(&mut args, "--lock-after-seconds");
    let private_names = take_bool_pair(&mut args, "--private-names", "--no-private-names")?;
    let descendant_read = take_bool_pair(&mut args, "--descendant-read", "--no-descendant-read")?;
    reject_flags(&args, USAGE)?;
    let [node] = args.as_slice() else {
        return Err(USAGE.to_string());
    };

    let mut policy = serde_json::Map::new();
    if let Some(v) = agent_access {
        policy.insert("agentAccess".into(), json!(v));
    }
    if let Some(v) = two_factor {
        policy.insert("requireTwoFactor".into(), json!(v));
    }
    if let Some(v) = sibling {
        policy.insert("siblingVisibility".into(), json!(v));
    }
    if let Some(v) = private_names {
        policy.insert("privateNames".into(), json!(v));
    }
    if let Some(v) = descendant_read {
        policy.insert("descendantRead".into(), json!(v));
    }
    if let Some(v) = lock_after {
        let seconds = if v == "none" {
            Value::Null // clears the per-node timer
        } else {
            json!(v.parse::<u32>().map_err(|_| format!(
                "--lock-after-seconds takes a number of seconds or 'none' — got '{v}'"
            ))?)
        };
        policy.insert("lockAfterSeconds".into(), seconds);
    }
    if policy.is_empty() {
        return Err(format!("no policy flag given — nothing to change\n{USAGE}"));
    }
    let reason = reason
        .filter(|r| !r.trim().is_empty())
        .ok_or("--reason is required — a policy change records why (up to 500 characters)")?;

    let value = call(
        "node.policy",
        json!({ "node": node, "reason": reason, "policy": Value::Object(policy) }),
    )
    .map_err(|e| {
        if e.starts_with("presence_required") {
            "presence_required — turning descendant-read on, or setting siblings to shared, \
             widens who can read what, so it needs native presence (the desktop app's Touch ID); \
             a command line cannot attest it. Nothing in this change was applied — narrowing \
             changes are not affected"
                .to_string()
        } else {
            e
        }
    })?;

    if as_json {
        println!("{value}");
        return Ok(());
    }
    let changed: Vec<&str> = value["changed"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    println!(
        "policy updated on {} (changed: {})",
        value["node"].as_str().unwrap_or(node),
        changed.join(", ")
    );
    for field in [
        "agentAccess",
        "requireTwoFactor",
        "lockAfterSeconds",
        "privateNames",
        "siblingVisibility",
        "descendantRead",
    ] {
        println!(
            "  {field:<19}{}",
            show_policy_value(&value["policy"][field])
        );
    }
    println!(
        "reason recorded: {}",
        value["reason"].as_str().unwrap_or("")
    );
    let not_enforced: Vec<&str> = value["notEnforced"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !not_enforced.is_empty() {
        println!(
            "not enforced yet (stored and reported, nothing acts on them): {}",
            not_enforced.join(", ")
        );
        for f in changed.iter().filter(|f| not_enforced.contains(f)) {
            println!("warning: {f} was changed, but changing it does not protect anything yet");
        }
    }
    Ok(())
}

/// `notes.write`'s `conflict` — the manifest moved between reading its
/// generation and the write landing.
fn explain_notes_error(e: String) -> String {
    if e.starts_with("conflict") {
        format!(
            "{e}\n  nothing was saved — another write to this node landed first; run the command again"
        )
    } else {
        e
    }
}

/// The manifest generation a note write is based on (F-9), taken from
/// `notes.read` — which returns it since ADR-077 — so a caller holding `notes`
/// but not `list` can still write a note. It used to come from `entry.list`,
/// whose capability is `list`: a grantee with `notes` alone was refused.
///
/// Two fallbacks, both to `entry.list` (the old source), both narrow:
/// * the broker's answer has no `generation` (an older daemon);
/// * `notes.read` itself failed with `internal` — the note on disk is damaged
///   (its file is missing, or does not match the digest the manifest records).
///   `notes.write` never reads the old note, so a write is exactly how such a
///   note is repaired, and refusing to start one because the *read* half is
///   broken would make the damage permanent. If the fallback is refused as well
///   the original error is the one reported.
///
/// Any other `notes.read` refusal (no `notes` capability, a locked node, an
/// unknown node) is the real answer and passes straight through.
fn note_generation(node: &str) -> Result<u64, String> {
    match call("notes.read", json!({ "node": node })) {
        Ok(read) => match read["generation"].as_u64() {
            Some(generation) => Ok(generation),
            None => entry_generation(node),
        },
        Err(e) if e.starts_with("internal") => entry_generation(node).map_err(|_| e),
        Err(e) => Err(e),
    }
}

/// `notes.write`, with the F-9 handshake: the broker wants the manifest
/// generation the caller based the write on. It is read here, right before the
/// write and after the text is in hand, so a slow editor session cannot go
/// stale on a change that has nothing to do with the note — unless the caller
/// already holds a generation from a read it made just before (`known`; `notes
/// clear` reads the note to see whether there is one, and writes on that same
/// read). A mismatch is the broker's `conflict`, reported as such. An empty
/// `markdown` removes the note — which is why only `notes clear` ever passes one.
fn write_note(node: &str, markdown: &str, known: Option<u64>) -> Result<(u64, Value), String> {
    let generation = match known {
        Some(generation) => generation,
        None => note_generation(node)?,
    };
    let value = call(
        "notes.write",
        json!({ "node": node, "markdown": markdown, "generation": generation }),
    )
    .map_err(explain_notes_error)?;
    Ok((generation, value))
}

/// ADR-072: `credmgr notes show <id>`, `credmgr notes set <id> [--file <path>]`
/// and `credmgr notes clear <id>`. A note is context, not a secret value, but it
/// is sealed like one and can hold sensitive detail — so, like a value, its text
/// never travels in argv: it comes from `--file` or stdin. Needs the separate
/// `notes` capability.
///
/// Deleting a note takes its own command. The broker treats an empty
/// `markdown` as a delete, and a CLI that forwarded empty input as one would
/// let a failed upstream pipe (`failing-cmd | credmgr notes set x`), a closed
/// stdin, or an empty file destroy a sealed note with nothing to say it was
/// not meant. So `notes set` refuses empty input and `notes clear` is the one
/// deliberate way to delete.
fn cmd_notes(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr notes show <id> [--json] | \
         credmgr notes set <id> [--file <path>]  (text from the file, or stdin; empty input is refused) | \
         credmgr notes clear <id>  (deletes the note)";
    /// The broker's own cap (`NOTE_MAX_BYTES`); checked here to refuse early.
    const NOTE_MAX_BYTES: usize = 64 * 1024;
    if args.is_empty() {
        return Err(USAGE.to_string());
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "show" => {
            let as_json = take_bool_flag(&mut args, "--json");
            reject_flags(&args, USAGE)?;
            let [node] = args.as_slice() else {
                return Err(USAGE.to_string());
            };
            let value = call("notes.read", json!({ "node": node }))?;
            if as_json {
                println!("{value}");
                return Ok(());
            }
            let markdown = value["markdown"].as_str().unwrap_or("");
            if markdown.is_empty() {
                eprintln!("no note on {node}");
                return Ok(());
            }
            // Byte-for-byte, so `notes show x > n.md` then `notes set x --file n.md`
            // round-trips exactly; a terminal still gets its final newline.
            let mut out = std::io::stdout().lock();
            std::io::Write::write_all(&mut out, markdown.as_bytes())
                .map_err(|e| format!("could not write the note: {e}"))?;
            if !markdown.ends_with('\n') && std::io::IsTerminal::is_terminal(&out) {
                std::io::Write::write_all(&mut out, b"\n")
                    .map_err(|e| format!("could not write the note: {e}"))?;
            }
            Ok(())
        }
        "set" => {
            let file = take_flag_value(&mut args, "--file");
            reject_flags(&args, USAGE)?;
            let [node] = args.as_slice() else {
                return Err(USAGE.to_string());
            };
            let too_big = || format!("a note is limited to {NOTE_MAX_BYTES} bytes");
            let markdown = match file {
                Some(path) => {
                    let f = std::fs::File::open(&path)
                        .map_err(|e| format!("could not open '{path}': {e}"))?;
                    read_capped(f, NOTE_MAX_BYTES, &format!("'{path}'")).map_err(|e| {
                        if e.contains("larger than") {
                            too_big()
                        } else {
                            e
                        }
                    })?
                }
                None => {
                    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                        eprintln!("reading the note from stdin — finish with Ctrl-D");
                    }
                    read_capped(std::io::stdin().lock(), NOTE_MAX_BYTES, "the note").map_err(
                        |e| {
                            if e.contains("larger than") {
                                too_big()
                            } else {
                                e
                            }
                        },
                    )?
                }
            };
            // Refused BEFORE any broker call, so nothing is touched. Whitespace
            // alone counts: overwriting a real note with blank lines is a delete
            // by another name.
            if markdown.trim().is_empty() {
                return Err(format!(
                    "the input is empty, so nothing was changed — `notes set` never deletes. \
                     To remove the note on {node}, run: credmgr notes clear {node}"
                ));
            }
            let (generation, value) = write_note(node, &markdown, None)?;
            println!(
                "note saved on {node} (generation {})",
                value["generation"].as_u64().unwrap_or(generation)
            );
            Ok(())
        }
        "clear" => {
            reject_flags(&args, USAGE)?;
            let [node] = args.as_slice() else {
                return Err(USAGE.to_string());
            };
            // Nothing there: say so and leave the manifest alone. A clear that
            // always wrote would bump the node's generation for no change.
            let current = call("notes.read", json!({ "node": node }))?;
            if current["markdown"].as_str().unwrap_or("").is_empty() {
                eprintln!("no note on {node} — nothing to clear");
                return Ok(());
            }
            // The generation comes from the very read that showed there is a
            // note to clear (absent only from an older daemon, which `write_note`
            // then asks `entry.list` for).
            write_note(node, "", current["generation"].as_u64())?;
            println!("cleared the note on {node}");
            Ok(())
        }
        other => Err(format!("unknown 'notes' subcommand: {other}\n{USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_conflict_is_explained_and_anything_else_passes_through() {
        let c = explain_notes_error(
            "conflict: the node is at generation 5, not 4 — it changed underneath this write"
                .to_string(),
        );
        assert!(
            c.contains("nothing was saved") && c.contains("run the command again"),
            "{c}"
        );
        assert_eq!(
            explain_notes_error("capability_not_held".to_string()),
            "capability_not_held"
        );
    }

    #[test]
    fn unwrap_ok_names_the_entry_that_blocked_a_batch_and_the_conflicting_generations() {
        let exists = unwrap_ok(json!({
            "ok": false, "error": "entry_exists", "node": "acme", "name": "DB_URL"
        }))
        .unwrap_err();
        assert!(
            exists.contains("'DB_URL' already exists on node 'acme'"),
            "{exists}"
        );
        let conflict = unwrap_ok(json!({
            "ok": false, "error": "conflict", "node": "acme",
            "expectedGeneration": 4, "currentGeneration": 5
        }))
        .unwrap_err();
        assert!(conflict.contains("generation 5, not 4"), "{conflict}");
        // Untouched shapes stay as they were.
        assert_eq!(
            unwrap_ok(json!({ "ok": false, "error": "vault_locked", "message": "m" })).unwrap_err(),
            "vault_locked: m"
        );
    }

    /// ADR-077 (G3): a locked node on an unlocked vault is its own refusal, and
    /// the CLI prints what the broker says - the node, and how to fix it - so the
    /// person at the keyboard does not mistake it for "unlock the vault".
    #[test]
    fn node_locked_says_which_node_and_how_to_unlock_it() {
        let shown = unwrap_ok(json!({
            "ok": false, "error": "node_locked", "node": "acme",
            "message": "node acme is locked; the vault itself is unlocked",
            "remedy": "unlock this node (vault.node_unlock) and retry - the login is still valid",
        }))
        .unwrap_err();
        assert!(
            shown.starts_with("node_locked: node acme is locked"),
            "{shown}"
        );
        assert!(
            shown.contains("remedy: unlock this node (vault.node_unlock)"),
            "{shown}"
        );
        assert!(!shown.contains("vault_locked"), "{shown}");
    }

    #[test]
    fn flag_pairs_and_choices_refuse_what_cannot_be_meant() {
        let mut a = vec![
            "--private-names".to_string(),
            "--no-private-names".to_string(),
        ];
        assert!(take_bool_pair(&mut a, "--private-names", "--no-private-names").is_err());
        let mut a = vec!["--no-descendant-read".to_string()];
        assert_eq!(
            take_bool_pair(&mut a, "--descendant-read", "--no-descendant-read"),
            Ok(Some(false))
        );
        let mut a = vec!["--agent-access".to_string(), "readwrite".to_string()];
        let e = take_choice(&mut a, "--agent-access", AGENT_ACCESS).unwrap_err();
        assert!(
            e.contains("read-write|read-only|none") && e.contains("readwrite"),
            "{e}"
        );
    }

    #[test]
    fn a_text_flag_never_swallows_the_next_option_as_its_text() {
        // The text is taken when it is there...
        let mut a = vec![
            "acme".to_string(),
            "--reason".to_string(),
            "rotate the CI token".to_string(),
        ];
        assert_eq!(
            take_text_flag(&mut a, "--reason"),
            Ok(Some("rotate the CI token".to_string()))
        );
        assert_eq!(a, vec!["acme".to_string()]);
        // ...absent is absent...
        let mut a = vec!["acme".to_string()];
        assert_eq!(take_text_flag(&mut a, "--reason"), Ok(None));
        // ...and a flag with nothing after it is left for the caller to report.
        let mut a = vec!["acme".to_string(), "--reason".to_string()];
        assert_eq!(take_text_flag(&mut a, "--reason"), Ok(None));
        assert!(a.contains(&"--reason".to_string()));
        // An option where the text belongs is refused, and nothing is consumed.
        let mut a = vec![
            "--private-names".to_string(),
            "--reason".to_string(),
            "--descendant-read".to_string(),
        ];
        let e = take_text_flag(&mut a, "--reason").unwrap_err();
        assert!(
            e.contains("--reason needs its text") && e.contains("--descendant-read"),
            "{e}"
        );
        assert_eq!(a.len(), 3, "a refusal consumes nothing");
    }

    #[test]
    fn a_partial_import_says_what_failed_and_how_much_was_saved() {
        let failed = json!({ "index": 2, "name": "THIRD", "error": "NotFound(\"no key\")" });
        let some = partial_import_error(2, &failed);
        assert!(
            some.contains("entry 3 (THIRD) failed")
                && some.contains("the 2 entries above were saved")
                && some.contains("the rest were not attempted"),
            "{some}"
        );
        let none = partial_import_error(0, &json!({ "index": 0, "name": "FIRST", "error": "e" }));
        assert!(
            none.contains("entry 1 (FIRST)") && none.contains("nothing was saved"),
            "{none}"
        );
        // An answer that is neither complete nor says what failed is not a success.
        let unknown = partial_import_error(1, &Value::Null);
        assert!(
            unknown.contains("did not complete") && unknown.contains("credmgr list"),
            "{unknown}"
        );
    }

    #[test]
    fn read_capped_refuses_oversize_and_non_utf8_rather_than_truncating() {
        assert_eq!(read_capped(&b"abc"[..], 3, "x").unwrap(), "abc");
        assert!(read_capped(&b"abcd"[..], 3, "x")
            .unwrap_err()
            .contains("larger than 3"));
        assert!(read_capped(&[0xff, 0xfe][..], 8, "x")
            .unwrap_err()
            .contains("UTF-8"));
    }
}
