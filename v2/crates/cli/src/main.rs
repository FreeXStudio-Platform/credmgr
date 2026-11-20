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

mod agent;
mod agent_tokens;
mod clip;
mod edit_cmd;
mod fields;
mod import_json;
mod merge_cmds;
mod names_cmds;
mod quick_cmds;
mod settings_cmd;
mod stable;
mod transport;

use std::io::{IsTerminal, Read};
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
    // `black_box`: the optimiser must keep the stamp whole in the binary (the
    // release verifier greps for it), not fold it into the pieces parsed below.
    match parse_build_stamp(std::hint::black_box(BUILD_STAMP)) {
        Some((commit, dirty)) => {
            let short = &commit[..commit.len().min(12)];
            let dirty = if dirty { ", dirty" } else { "" };
            format!("{bin} {version} (commit {short}{dirty}, {platform})")
        }
        None => format!("{bin} {version} (development build, no commit stamp, {platform})"),
    }
}

/// The build stamp `build.rs` writes from the release script's environment
/// (`credmgr-build-stamp:v1:commit=<hex>:dirty=<0|1>`). It is a constant of the
/// binary on purpose: `scripts/release.sh --verify` finds it in the bytes (issue
/// #38) without running the program, and `--version` is read from the same string.
const BUILD_STAMP: &str = env!("CREDMGR_BUILD_STAMP");

/// `(commit, dirty)` out of a stamp; `None` for a build with no commit.
fn parse_build_stamp(stamp: &str) -> Option<(&str, bool)> {
    let rest = stamp.strip_prefix("credmgr-build-stamp:v1:commit=")?;
    let (commit, dirty) = rest.split_once(":dirty=")?;
    if commit == "none" || commit.is_empty() {
        return None;
    }
    Some((commit, dirty == "1"))
}

fn run(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    let cmd = args.remove(0);
    // ADR-162: the App Store edition's CLI runs in its own sandbox and cannot open a path outside its
    // container. Say so, with the way round, before anything is asked or sent.
    if credmgr_store::paths::FLAVOUR == credmgr_store::paths::Flavour::Mas {
        if let Some(refusal) = mas_limit(&cmd, &args) {
            return Err(refusal);
        }
    }
    match cmd.as_str() {
        "init" => cmd_init(),
        "status" => cmd_status(args),
        "unlock" => cmd_unlock(args),
        "presence" => cmd_presence(args),
        "touch-id" => cmd_touch_id(args),
        // ADR-165: the machine lock.
        "keystore" => cmd_keystore(args),
        "lock" => cmd_lock(),
        // ADR-156: the post-launch quick wins.
        "passphrase" => quick_cmds::cmd_passphrase(args),
        // ADR-163: the passphrase is forgotten; the recovery code opens the vault and a new passphrase is set.
        "recover" => quick_cmds::cmd_recover(args),
        "expire" => quick_cmds::cmd_expire(args),
        "edit" => edit_cmd::cmd_edit(args),
        // ADR-158: an entry to another node, re-encrypted to its key.
        "move" => quick_cmds::cmd_move(args),
        "expiring" => quick_cmds::cmd_expiring(args),
        "history" => quick_cmds::cmd_history(args),
        "ref" => quick_cmds::cmd_ref(args),
        "confirm" => cmd_confirm(args),
        "gate" => cmd_gate(args),
        "whoami" => cmd_whoami(args),
        "list" => cmd_list(args),
        "get" => cmd_get(args),
        "totp" => cmd_totp(args),
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
        // Hidden: the detached clearer `--copy` starts (see `clip.rs`). Not in the help text.
        clip::CLEAR_COMMAND => clip::run_clear(&args),
        "approve" => cmd_approve(args),
        "approvals" => cmd_approvals(args),
        "backup" => cmd_backup(args),
        "restore" => cmd_restore(args),
        "node" => cmd_node(args),
        "grant" => cmd_grant(args),
        "import" => cmd_import(args),
        "import-env" => names_cmds::cmd_import_env(args),
        "alias" => names_cmds::cmd_alias(args),
        // ADR-167: an entry's tags. ADR-168: merge suggestions and merges inside one node.
        "tag" => names_cmds::cmd_tag(args),
        "merge" => merge_cmds::cmd_merge(args),
        "similar" => names_cmds::cmd_similar(args),
        "notes" => cmd_notes(args),
        "orphan" => stable::cmd_orphan(args),
        "export" => stable::cmd_export(args),
        "mcp" => cmd_mcp(args),
        "agent" => agent::cmd_agent(args),
        "prompt" => agent::cmd_prompt(args),
        // ADR-155: the switchboard and the LLM knowledge base.
        "settings" => settings_cmd::cmd_settings(args),
        "kb" => settings_cmd::cmd_kb(args),
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

/// ADR-162: the commands the Mac App Store edition's bundled CLI cannot do, and what to use instead.
/// A sandboxed command-line tool sees only its own container and the app-group container: a file named
/// on the command line (other than `-`, stdin) and other apps' configuration files are out of reach, and
/// the sandbox would refuse the open with a bare "Operation not permitted". `None` = allowed. Pure and
/// always compiled, so its table is tested in the default build; `run` consults it only in the `mas` flavour.
fn mas_limit(cmd: &str, args: &[String]) -> Option<String> {
    const WAY_ROUND: &str =
        "The CredMgr app can do this, and so can the full CLI (the free separate \
                             download, which reaches the same vault).";
    let positional: Vec<String> = {
        // Drop each flag and the value it takes, so `--node <id>` is not mistaken for a file.
        let mut out = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if a.starts_with("--") {
                if matches!(
                    a.as_str(),
                    "--node"
                        | "--on-conflict"
                        | "--out"
                        | "--age-recipient"
                        | "--to"
                        | "--state-dir"
                        | "--file"
                        | "--dir"
                        | "--binary"
                ) {
                    it.next();
                }
                continue;
            }
            out.push(a.clone());
        }
        out
    };
    match cmd {
        "import" | "import-env" => match positional.first().map(String::as_str) {
            Some(f) if f != "-" => Some(format!(
                "the App Store edition's CLI cannot open '{f}': it runs in the macOS sandbox. Pipe it \
                 instead: credmgr {cmd} - --node <id> < {f}\n{WAY_ROUND}"
            )),
            _ => None,
        },
        "export" => Some(format!(
            "the App Store edition's CLI cannot write an export file: it runs in the macOS sandbox.\n{WAY_ROUND}"
        )),
        "restore" => Some(format!(
            "the App Store edition's CLI cannot read a backup archive from a path you name: it runs in the \
             macOS sandbox.\n{WAY_ROUND}"
        )),
        "agent" => Some(format!(
            "the App Store edition's CLI cannot read or write other apps' configuration files: it runs in \
             the macOS sandbox. Print the configuration and paste it yourself: credmgr mcp --print-config \
             <client>\n{WAY_ROUND}"
        )),
        "notes" if args.iter().any(|a| a == "--file") => Some(format!(
            "the App Store edition's CLI cannot open a --file: it runs in the macOS sandbox. Pipe the note \
             on stdin instead.\n{WAY_ROUND}"
        )),
        _ => None,
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
         \x20 credmgr status [--ack | --log]       (--ack: you have seen the security alarm; --log: where the diagnostic log is)\n\
         \x20 credmgr unlock                        (passphrase from stdin; a real login —\n\
         \x20                                      prints `export CREDMGR_TOKEN=...` on\n\
         \x20                                      success. Capture it with:\n\
         \x20                                      eval \"$(credmgr unlock <<< \"$pw\")\")\n\
         \x20 credmgr gate verify [--code-on-argv <n>]\n\
         \x20                                      (completes unlock when 2FA is enrolled; the code is\n\
         \x20                                      typed at a prompt or read from stdin, never put in\n\
         \x20                                      the command line, where `ps` shows it for as long\n\
         \x20                                      as the command runs - --code-on-argv does that on\n\
         \x20                                      purpose. Prints the token the same way. With a login\n\
         \x20                                      already in CREDMGR_TOKEN it is a step-up: it\n\
         \x20                                      proves the second factor for five minutes, for\n\
         \x20                                      nodes whose policy asks for it)\n\
         \x20 credmgr gate enroll                   (turns on two-factor; needs an unlocked login)\n\
         \x20 credmgr gate enroll|verify|remove [--last-door] --node <id>\n\
         \x20                                      (verify asks for the code or reads stdin; --code-on-argv <n>)\n\
         \x20                                      (a project's OWN second factor: its code is asked even of you, opens\n\
         \x20                                      that project only, and the vault's code never opens it. remove needs\n\
         \x20                                      its fresh code and Touch ID; --last-door instead takes the vault\n\
         \x20                                      passphrase and the root recovery code from stdin)\n\
         \x20 credmgr gate recover                  (lost authenticator: passphrase + root recovery\n\
         \x20                                      code from stdin reset the gate)\n\
         \x20 credmgr presence status|enrol|unenrol   (Touch ID presence key for this Mac)\n\
         \x20 credmgr touch-id enable|disable        (unlock this vault with Touch ID)\n\
         \x20 credmgr keystore status|bind|unbind [--json]\n\
         \x20                                      (the machine lock: bind seals the passphrase unlock to a\n\
         \x20                                      device key on this Mac, so a copy of the vault folder does\n\
         \x20                                      not open with the passphrase elsewhere; the recovery code\n\
         \x20                                      still does, on any Mac. unbind needs Touch ID and the\n\
         \x20                                      second factor where they are set up)\n\
         \x20 credmgr unlock --touch-id\n\
         \x20 credmgr lock\n\
         \x20 credmgr passphrase [--json]           (change the vault passphrase: the current one, then the\n\
         \x20                                      new one, from stdin - asked twice at a terminal. Prints\n\
         \x20                                      a NEW recovery code once; the old code stops working)\n\
         \x20 credmgr recover [--json]              (forgot the passphrase: the recovery code, then a new\n\
         \x20                                      passphrase, from stdin - asked twice at a terminal; a\n\
         \x20                                      second-factor code too if one is enrolled. Sets the new\n\
         \x20                                      passphrase, prints a NEW recovery code once and retires\n\
         \x20                                      the used one)\n\
         \x20 credmgr confirm [--touch-id]          (confirm it is you before secrets are shown, when the\n\
         \x20                                      vault asks for it: Touch ID, or the passphrase from\n\
         \x20                                      stdin. `get` asks by itself at a terminal)\n\
         \x20 credmgr whoami [--json]\n\
         \x20 credmgr list [--node <id> [--tag <tag>]] [--json]\n\
         \x20 credmgr get <name> [--node <id>] [--field <label> | --field-id <id> | --all] [--json]\n\
         \x20                                      (a one-field entry prints its value; with several\n\
         \x20                                      fields name one, or use --all / --json for every one;\n\
         \x20                                      `get ... --copy` puts one value on the macOS clipboard\n\
         \x20                                      instead of stdout, cleared after 30 s if unchanged)\n\
         \x20 credmgr totp <name> [--node <id>] [--field <label> | --field-id <id>] [--copy | --json]\n\
         \x20                                      (the current one-time code from a stored seed, and how\n\
         \x20                                      long it stays valid; the seed itself is never shown.\n\
         \x20                                      --copy: macOS clipboard, cleared after 30 s if unchanged)\n\
         \x20 credmgr search <term> [--node <id>] [--json]\n\
         \x20                                      (names and aliases; --node asks one node only)\n\
         \x20 credmgr ref <number> [--json]         (which entry a short reference names)\n\
         \x20 credmgr expire <name> [--node <id>] (--at <YYYY-MM-DD|unix seconds> | --in <days> | --clear)\n\
         \x20 credmgr edit <name> --node <id> [--dry-run]\n\
         \x20                                      (an entry's metadata in $VISUAL / $EDITOR / vi: aliases, expiry,\n\
         \x20                                      sensitivity, type, tags, field labels/types/masking; never a\n\
         \x20                                      value; only the changed keys are applied)\n\
         \x20 credmgr move <name> [--node <id>] --to <id> [--reason <text>] [--json]\n\
         \x20                                      (moves an entry to another project, re-encrypted to its key;\n\
         \x20                                      grants that named it are revoked; needs a fresh authenticator\n\
         \x20                                      code and Touch ID, every time)\n\
         \x20 credmgr expiring [--days N] [--node <id>] [--json]\n\
         \x20                                      (entries expiring within N days, 30 by default; expired too)\n\
         \x20 credmgr history <name> [--node <id>] [--limit N] [--json]\n\
         \x20                                      (what happened to an entry: actions and times, never a value)\n\
         \x20 credmgr search <term> --deep [--node <id>] [--json]\n\
         \x20                                      (looks inside field VALUES; prints node and name only, never a\n\
         \x20                                      value; needs reveal; at most 12 searches a minute)\n\
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
         \x20 credmgr doctor --scan [--stale-days N] [--expiring-days N] [--json]\n\
         \x20                                      (the tidy-up scan: shared values, near-identical names,\n\
         \x20                                      misfiled, weak, mistyped, expired and stale entries,\n\
         \x20                                      each with what to do; changes nothing, shows no value)\n\
         \x20 credmgr doctor --scan --apply [--yes] [--json]\n\
         \x20                                      (the scan, then every move it proposes in one step:\n\
         \x20                                      lists each move and asks first (--yes: do not ask);\n\
         \x20                                      one code and one Touch ID for the whole plan; stops\n\
         \x20                                      at the first move that fails and says what moved)\n\
         \x20 credmgr generate [--length <n>] [--no-symbols] [--pronounceable | --hex] [--copy | --json]\n\
         \x20                                      (a password made by the broker, 8-128 characters,\n\
         \x20                                      printed to stdout; its strength goes to stderr.\n\
         \x20                                      --hex: lower-case hex only. --copy: macOS clipboard\n\
         \x20                                      instead of stdout, cleared after 30 s if unchanged)\n\
         \x20 credmgr approve <request> [--deny] [--code-on-argv <n>]\n\
         \x20                                      (decide an agent's waiting request while the vault\n\
         \x20                                      stays locked: the passphrase is the first stdin line;\n\
         \x20                                      with two-factor on, the authenticator code is the\n\
         \x20                                      second line or, at a terminal, asked for when needed.\n\
         \x20                                      --code-on-argv puts it in the command line, visible\n\
         \x20                                      to `ps`: use it only where a prompt is impossible)\n\
         \x20 credmgr approvals [<request>] [--json]\n\
         \x20 credmgr settings list|get|set|toggle|revert|requests|approve|deny   (the switchboard)\n\
         \x20 credmgr kb                             (the knowledge base for language models)\n\
         \x20                                      (what the waiting agent requests ask for, so you can\n\
         \x20                                      decide them with `credmgr approve`; works while locked)\n\
         \x20 credmgr doctor --rebuild-registry --confirm --known-revoked <id>[,<id>...]\n\
         \x20                                      (needs presence — native shell only, Phase 5; passphrase from stdin)\n\
         \x20 credmgr backup [--retain N]            (a complete encrypted archive of the vault -\n\
         \x20                                      entries, notes, sealed nodes, removed and rotated\n\
         \x20                                      history, the audit log and the generation counter;\n\
         \x20                                      backup passphrase from stdin)\n\
         \x20 credmgr restore <archive> [--to <empty dir>] [--state-dir <dir>]\n\
         \x20                                      (rebuilds a vault from a backup archive, backup\n\
         \x20                                      passphrase from stdin; --to defaults to the vault\n\
         \x20                                      directory and must be empty or absent; refuses to\n\
         \x20                                      overwrite or merge; then `credmgr unlock` with the\n\
         \x20                                      vault passphrase)\n\
         \x20 credmgr import <file|-> --node <id> [--format json|env] [--json]\n\
         \x20                                      (a .env-style file — NAME=value, # comments, export,\n\
         \x20                                      quotes — becomes entries in ONE all-or-nothing call;\n\
         \x20                                      `-` reads stdin; values are never printed. A .json file\n\
         \x20                                      (or --format json) is an array of\n\
         \x20                                      name+value entries or name+fields (label, value, type))\n\
         \x20 credmgr import-env <file|-> --node <id> [--dry-run] [--on-conflict refuse|skip] [--json]\n\
         \x20                                      (like `import`, but it previews every name first: new,\n\
         \x20                                      already there, repeated, empty, resembling another. Each\n\
         \x20                                      entry is written on its own with its own audit record;\n\
         \x20                                      a conflict writes nothing unless you say `skip`)\n\
         \x20 credmgr alias <name> [--node <id>] [--add <alias>]... [--remove <alias>]... [--clear] [--json]\n\
         \x20                                      (other names an entry answers to; lists them when no\n\
         \x20                                      change is asked; needs a login, `credmgr unlock`)\n\
         \x20 credmgr tag <name> [--node <id>] [--add <tag>]... [--remove <tag>]... [--clear] [--json]\n\
         \x20                                      (an entry's tags: lower-cased labels, at most 16; lists\n\
         \x20                                      them when no change is asked; needs a login)\n\
         \x20 credmgr merge suggest|dismissed|restore-all --node <id> [--json]\n\
         \x20 credmgr merge apply --node <id> --keep <name> --drop <name>... [--json]\n\
         \x20 credmgr merge dismiss|undismiss|auto --node <id> --group <key> [--json]\n\
         \x20 credmgr merge auto-all --node <id> [--apply] [--json]\n\
         \x20                                      (duplicates inside one node: the kept entry takes the\n\
         \x20                                      other names as aliases, the rest are removed and can be\n\
         \x20                                      undone for 7 days; auto-all is a dry run unless --apply)\n\
         \x20 credmgr similar <name> --node <id> [--json]\n\
         \x20                                      (which names on the node look like <name>; writes nothing)\n\
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
         \x20                                      [--security-level open|guarded|strict]\n\
         \x20                                      (a partial patch, all-or-nothing; widening who can\n\
         \x20                                      read — descendant-read on, siblings shared, or a LOWER\n\
         \x20                                      security level — needs presence: Touch ID, proved\n\
         \x20                                      automatically when enrolled)\n\
         \x20 credmgr node rekey <id>               (a new key for the node, every file re-sealed to it; needs a\n\
         \x20                                      fresh authenticator code and Touch ID, every time)\n\
         \x20 credmgr orphan ls [--json]            (sealed entries: names only)\n\
         \x20 credmgr orphan destroy (--all | <entry-id>...) --count <n> --confirm destroy-sealed-entries\n\
         \x20                                      (deletes sealed entries and their archives for good; needs a fresh\n\
         \x20                                      authenticator code and Touch ID; cannot be undone)\n\
         \x20 credmgr export --node <id> --out <file> --age [--age-recipient <age1...>]... [--force]\n\
         \x20                                      (an age-encrypted archive of a node, written to a file only; the\n\
         \x20                                      passphrase comes from stdin twice, or use --age-recipient; 2FA seeds\n\
         \x20                                      are left out; needs a fresh authenticator code and Touch ID)\n\
         \x20 credmgr audit report (--days <n> | --from YYYY-MM-DD --to YYYY-MM-DD) [--node <id>] [--json]\n\
         \x20                                      (counts by action, actor and node, denials, presence uses; no values)\n\
         \x20 credmgr node seal <name>\n\
         \x20 credmgr node restore <name>\n\
         \x20 credmgr grant <from> --to <node> --scope read --reason \"...\"\n\
         \x20                                      (needs presence — native shell only, Phase 5)\n\
         \x20 credmgr grant ls [--json]\n\
         \x20 credmgr grant revoke <id>\n\
         \x20 credmgr mcp                          (MCP stdio server; for agent config, not humans)\n\
         \x20 credmgr mcp --print-config [<client>]  (the exact MCP config for claude-code, claude-desktop,\n\
         \x20                                      cursor, vscode or windsurf; no client = generic JSON)\n\
         \x20 credmgr agent detect [--json]          (which clients are on this Mac and whether they are wired)\n\
         \x20 credmgr agent connect|disconnect <client> [--yes]\n\
         \x20                                      (shows the diff, backs the file up, then writes only the\n\
         \x20                                      credmgr entry; never Claude Code's state file)\n\
         \x20 credmgr agent init [--node <id>] [--dir <path>] [--yes]\n\
         \x20                                      (writes CREDMGR.md - node names and rules, no secret)\n\
         \x20 credmgr agent token issue <node> --label <text> --cap <list,read,...> [--expires 8h]\n\
         \x20                                      (a node-scoped agent token, printed once; owner login,\n\
         \x20                                      second factor and Touch ID; one day by default, 7 at most)\n\
         \x20 credmgr agent token ls|rotate <id>|revoke <id>\n\
         \x20 credmgr prompt [--node <id>] [--json]  (the Vault Protocol prompt for an agent, from the live\n\
         \x20                                      vault: names and structure, never a value)\n\
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

/// The first line of `text` (without its `\r\n` / `\n`) and everything after it.
fn split_first_line(text: &str) -> (&str, &str) {
    match text.split_once('\n') {
        Some((first, rest)) => (first.strip_suffix('\r').unwrap_or(first), rest),
        None => (text, ""),
    }
}

/// An authenticator code, never from argv (issue #39): at a terminal it is
/// asked for on stderr (stdout stays the machine-readable answer); piped, it is
/// the next line of stdin. Surrounding spaces are dropped; empty input is an
/// error, not a request to the broker.
pub(crate) fn read_authenticator_code() -> Result<String, String> {
    if std::io::stdin().is_terminal() {
        eprint!("Authenticator code: ");
        std::io::Write::flush(&mut std::io::stderr()).ok();
    }
    let code = read_stdin_line()?.trim().to_string();
    if code.is_empty() {
        return Err(
            "no authenticator code was given (type it at the prompt, or pipe it in as one line)"
                .to_string(),
        );
    }
    Ok(code)
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

/// Issue #40 / ADR-111: the broker lists, in `possibleSeedFields`, the fields of the
/// entry it just wrote that could be a TOTP seed but are not typed as one. As text they
/// stay readable to anything that may reveal the entry, and `totp.code` refuses them.
/// Says so once on stderr, names the command that types them, and - when a person is at
/// a terminal (never in a pipe or a script) - offers to do it now. The offer reads the
/// terminal itself because the value came in on stdin.
fn offer_seed_typing(node: &str, name: &str, value: &Value) {
    let ids: Vec<String> = value["possibleSeedFields"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if ids.is_empty() {
        return;
    }
    let entry = value["entry"].as_str().unwrap_or_default();
    let held = value["pending"].as_bool() == Some(true);
    for id in &ids {
        eprintln!(
            "warning: field {id} of '{name}' looks as though it could be a 2FA seed, but it is not typed as one. \
             Stored as text, anything that may reveal this entry can read it, and `credmgr totp` cannot make codes from it."
        );
        eprintln!("  type it as a seed:  credmgr field set {name} --field-id {id} --type totp-seed --node {node}");
        if held || entry.is_empty() || !ask_at_terminal("Type it as a 2FA seed now? [y/N] ") {
            continue;
        }
        let typed = fields::entry_meta(node, entry).and_then(|meta| {
            call(
                "field.update",
                json!({
                    "node": node, "entry": entry,
                    "generation": meta["generation"].as_u64().unwrap_or(0),
                    "field": id, "patch": { "type": "totp-seed" },
                }),
            )
        });
        match typed {
            Ok(_) => eprintln!("field {id} is now typed totp-seed"),
            Err(e) => eprintln!("could not type field {id}: {e}"),
        }
    }
}

/// A yes/no question put to the person at the keyboard: only when stderr is a terminal and
/// `/dev/tty` opens (stdin may already be the pipe the value came in on), and never when
/// `CREDMGR_NO_PROMPT` is set. Anything but `y`/`yes` is no.
fn ask_at_terminal(question: &str) -> bool {
    if !std::io::stderr().is_terminal() || std::env::var_os("CREDMGR_NO_PROMPT").is_some() {
        return false;
    }
    let Ok(tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        return false;
    };
    let mut out = match tty.try_clone() {
        Ok(f) => f,
        Err(_) => return false,
    };
    if std::io::Write::write_all(&mut out, question.as_bytes()).is_err() {
        return false;
    }
    let mut line = String::new();
    if std::io::BufRead::read_line(&mut std::io::BufReader::new(tty), &mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
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
    let send = |op: &str, params: Value| -> Result<(Value, Option<String>), String> {
        let response = transport::call(op, token.as_deref(), params)
            .map_err(|e: TransportError| e.to_string())?;
        let audit = response["audit"].as_str().map(str::to_string);
        unwrap_ok(response).map(|value| (value, audit))
    };
    let first = send(op, params.clone());
    // ADR-150: the vault asks the owner's login to confirm it is still them before a secret is shown (or before
    // that rule is weakened). Confirm — Touch ID when this Mac has a presence key, else the passphrase typed at
    // the terminal — and send the request once more. Never from a pipe: a script runs `credmgr confirm` first.
    let first = match first {
        Err(e) if e.starts_with("confirmation_required") && op != "session.confirm" => {
            confirm_interactively(&e)?;
            send(op, params.clone())
        }
        other => other,
    };
    match first {
        // ADR-098: an op that needs the user's finger. When this Mac has a presence key, ask the broker
        // for a challenge, let the Secure Enclave sign it (Touch ID or the device password), and send the
        // request again with the proof. Without one, say how to get one.
        Err(e) if e.starts_with("presence_required") && op != "presence.challenge" => {
            let Some(helper) = credmgr_keystore::secure_enclave::Helper::locate() else {
                return Err(format!(
                    "{e}\n(this build has no Secure Enclave helper; presence needs the macOS app or the macOS tarball)"
                ));
            };
            let state_dir = credmgr_store::paths::default_state_dir();
            if credmgr_keystore::presence_client::load_key(&state_dir)
                .ok()
                .flatten()
                .is_none()
            {
                return Err(format!(
                    "{e}\nthis Mac has no presence key yet - run `credmgr presence enrol` (unlocked, as the owner)"
                ));
            }
            let challenge = send("presence.challenge", json!({ "op": op, "params": params }))?.0;
            let challenge = credmgr_keystore::presence_client::Challenge::from_value(&challenge)
                .ok_or("the broker's presence challenge was malformed")?;
            eprintln!(
                "{}: touch the sensor (or use your Mac password)...",
                challenge.reason
            );
            let proved = credmgr_keystore::presence_client::attach_proof(
                &helper, &state_dir, &challenge, &params,
            )
            .map_err(|e| presence_error(&e))?;
            send(op, proved)
        }
        other => other,
    }
}

/// Whether this Mac can answer a Touch ID check for this vault: the Secure Enclave helper is here and a
/// presence key was created on this Mac.
fn touch_id_ready() -> bool {
    credmgr_keystore::secure_enclave::Helper::locate().is_some()
        && credmgr_keystore::presence_client::load_key(&credmgr_store::paths::default_state_dir())
            .ok()
            .flatten()
            .is_some()
}

/// ADR-150: answer `confirmation_required` for the person at the terminal. Touch ID first when it is set up on
/// this Mac (a dismissed prompt falls back to the passphrase); else the passphrase, typed at a prompt on stderr.
/// The passphrase is never read from argv, and never from a pipe here (stdin may be the command's own input).
fn confirm_interactively(refusal: &str) -> Result<(), String> {
    let no_prompt = std::env::var_os("CREDMGR_NO_PROMPT").is_some();
    if !no_prompt && touch_id_ready() {
        eprintln!("This vault asks you to confirm it is you before showing secrets.");
        match call("session.confirm", json!({})) {
            Ok(_) => return Ok(()),
            Err(e) => eprintln!("Touch ID did not confirm ({e}); using the passphrase instead."),
        }
    }
    if no_prompt || !std::io::stdin().is_terminal() {
        return Err(format!(
            "{refusal}\nrun `credmgr confirm` first (Touch ID, or the passphrase on stdin), then repeat this command"
        ));
    }
    // The typed line echoes, as `credmgr unlock`'s does: this binary forbids unsafe code and carries no no-echo
    // prompt helper. The buffer is zeroised when it drops.
    eprint!("This vault asks you to confirm it is you. Vault passphrase: ");
    std::io::Write::flush(&mut std::io::stderr()).ok();
    let passphrase = secrecy::zeroize::Zeroizing::new(read_stdin_line()?);
    call(
        "session.confirm",
        json!({ "passphrase": passphrase.as_str() }),
    )
    .map(|_| ())
}

/// `credmgr confirm [--touch-id]` (ADR-150): confirm it is you, so the vault's "confirm before showing secrets"
/// policy lets this login see secrets for its trust window (or for the next one, in "every time" mode). The
/// passphrase is the first line of stdin, never argv.
fn cmd_confirm(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr confirm [--touch-id]   (passphrase from stdin without --touch-id)";
    let touch = take_bool_flag(&mut args, "--touch-id");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    let value = if touch {
        call("session.confirm", json!({}))?
    } else {
        if std::io::stdin().is_terminal() {
            eprint!("Vault passphrase: ");
            std::io::Write::flush(&mut std::io::stderr()).ok();
        }
        // Zeroised when it drops; echoes like `credmgr unlock` (no no-echo helper in this binary).
        let passphrase = secrecy::zeroize::Zeroizing::new(read_stdin_line()?);
        if passphrase.is_empty() {
            return Err(
                "no passphrase was given (type it at the prompt, or pipe it in as one line)".into(),
            );
        }
        call(
            "session.confirm",
            json!({ "passphrase": passphrase.as_str() }),
        )?
    };
    println!(
        "confirmed - secrets can be shown for {} seconds",
        value["expiresIn"].as_u64().unwrap_or(0)
    );
    Ok(())
}

/// A keystore failure in the words a person needs.
fn presence_error(e: &credmgr_keystore::KeystoreError) -> String {
    use credmgr_keystore::KeystoreError as K;
    match e {
        K::Helper { code, .. } if code == "cancelled" => {
            "cancelled - the Touch ID prompt was dismissed".to_string()
        }
        K::Helper { code, detail } if code == "locked_out" => {
            format!("Touch ID is locked out ({detail}); unlock the Mac with its password first")
        }
        K::HelperMissing(why) => format!("the Secure Enclave helper is not available: {why}"),
        other => other.to_string(),
    }
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

/// ADR-159: where `credmgrd`'s diagnostic log is, and whether one has been written. Read from the
/// filesystem, not the broker, so it works when the broker will not start — the case the log exists for.
/// The directory is this process's `default_log_dir()`; a broker started with a different
/// `CREDMGR_LOG_DIR` writes elsewhere.
fn diag_log_line() -> String {
    let file = credmgr_store::paths::default_log_dir().join("credmgrd.log");
    match std::fs::metadata(&file) {
        Ok(m) => format!(
            "diagnostic log: {} ({} KiB; no names or values in it)",
            file.display(),
            m.len().div_ceil(1024)
        ),
        Err(_) => format!(
            "diagnostic log: {} (none written; off by default, start credmgrd with CREDMGR_DIAG_LOG=1 to turn it on)",
            file.display()
        ),
    }
}

fn cmd_status(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr status [--ack | --log]";
    // ADR-156: `--ack` says the owner has seen the cross-node alarm.
    let ack = take_bool_flag(&mut args, "--ack");
    // ADR-159: `--log` prints only the diagnostic log's place, without asking the broker.
    let log_only = take_bool_flag(&mut args, "--log");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() || (ack && log_only) {
        return Err(USAGE.to_string());
    }
    if log_only {
        println!("{}", diag_log_line());
        return Ok(());
    }
    if ack {
        let value = call("vault.anomalies_ack", json!({}))?;
        println!(
            "alarm acknowledged ({} trip(s))",
            value["acknowledged"].as_u64().unwrap_or(0)
        );
        return Ok(());
    }
    let value = call("vault.status", json!({}))?;
    println!("locked: {}", value["locked"].as_bool().unwrap_or(true));
    // ADR-156: only the owner's login is told (the key is absent otherwise).
    let alarms = value["anomaliesUnseen"].as_u64().unwrap_or(0);
    if alarms > 0 {
        println!(
            "security alarm: {alarms} burst(s) of five refused cross-project requests in ten minutes \
             (see `credmgr audit`; clear with `credmgr status --ack`)"
        );
    }
    // ADR-165 M5: this Mac's machine-lock record names this folder under another vault id (owner only).
    let detached = value["warnings"]
        .as_array()
        .is_some_and(|w| w.iter().any(|w| w == "machine_lock_record_detached"));
    if detached {
        println!(
            "machine lock warning: this Mac's machine-lock record for this vault folder names a different vault \
             id than the folder's vault.id (edited, removed, or the folder was put back to an older copy); \
             nothing was repaired (see `credmgr keystore status`)"
        );
    }
    // ADR-090: a count only; `credmgr approvals` says what they are.
    let waiting = value["pendingApprovals"].as_u64().unwrap_or(0);
    if waiting > 0 {
        println!("approvals waiting: {waiting}   (see them with: credmgr approvals)");
    }
    println!("{}", diag_log_line());
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

fn cmd_unlock(mut args: Vec<String>) -> Result<(), String> {
    // ADR-098: `--touch-id` opens the vault with the Secure Enclave instead of the passphrase. The
    // broker asks the system for Touch ID (or the Mac password) itself; nothing is read from stdin.
    if take_bool_flag(&mut args, "--touch-id") {
        reject_flags(&args, "usage: credmgr unlock [--touch-id]")?;
        let value = call("vault.unlock", json!({ "method": "device" }))
            .map_err(explain_touch_id_unlock_error)?;
        print_unlock_result(&value);
        return Ok(());
    }
    reject_flags(&args, "usage: credmgr unlock [--touch-id]")?;
    let passphrase = read_stdin_value()?;
    // ADR-063: the broker builds its keystore from this passphrase per
    // request, proves it against `root.wrap.pass`, and loads the vault from
    // disk on the first unlock after a restart.
    let value = call("vault.unlock", json!({ "passphrase": passphrase }))?;
    print_unlock_result(&value);
    Ok(())
}

/// `credmgr presence status | enrol [--label <text>] | unenrol <id>` (ADR-098).
fn cmd_presence(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr presence status [--json] | enrol [--label <text>] | unenrol <id>";
    if args.is_empty() {
        return Err(USAGE.to_string());
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "status" => {
            let as_json = take_bool_flag(&mut args, "--json");
            let value = call("presence.status", json!({}))?;
            if as_json {
                println!("{value}");
                return Ok(());
            }
            println!(
                "secure enclave: {}   biometry: {}   device password: {}",
                value["secureEnclave"].as_bool().unwrap_or(false),
                value["biometry"].as_str().unwrap_or("none"),
                value["passcode"].as_bool().unwrap_or(false),
            );
            let keys = value["enrolled"].as_array().cloned().unwrap_or_default();
            if keys.is_empty() {
                println!("presence keys: none - run `credmgr presence enrol`");
            }
            for k in keys {
                println!(
                    "presence key {}  {}",
                    k["id"].as_str().unwrap_or("?"),
                    k["label"].as_str().unwrap_or("")
                );
            }
            println!(
                "touch id unlock: {}",
                value["touchIdUnlock"].as_bool().unwrap_or(false)
            );
            Ok(())
        }
        "enrol" | "enroll" => {
            let label =
                take_text_flag(&mut args, "--label")?.unwrap_or_else(|| "This Mac".to_string());
            reject_flags(&args, USAGE)?;
            let helper = credmgr_keystore::secure_enclave::Helper::locate()
                .ok_or("this build has no Secure Enclave helper (macOS only)")?;
            let state_dir = credmgr_store::paths::default_state_dir();
            let key = credmgr_keystore::presence_client::create_key(&helper, &state_dir)
                .map_err(|e| presence_error(&e))?;
            let public = key.public().map_err(|e| presence_error(&e))?;
            let params = json!({
                "publicKey": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public),
                "label": label,
            });
            // ADR-148 §P2-4: prove this Mac holds the new key — it signs a broker nonce (Touch ID appears).
            let challenge = call(
                "presence.challenge",
                json!({ "op": "presence.enrol", "params": params, "possession": true }),
            )?;
            let challenge = credmgr_keystore::presence_client::Challenge::from_value(&challenge)
                .ok_or("the broker's possession challenge was malformed")?;
            eprintln!(
                "{}: touch the sensor (or use your Mac password)...",
                challenge.reason
            );
            let params = credmgr_keystore::presence_client::attach_possession(
                &helper, &state_dir, &challenge, &params,
            )
            .map_err(|e| presence_error(&e))?;
            let value = call("presence.enrol", params)?;
            println!(
                "enrolled presence key {} ({})",
                value["id"].as_str().unwrap_or("?"),
                label
            );
            Ok(())
        }
        "unenrol" | "unenroll" => {
            let [id] = args.as_slice() else {
                return Err(USAGE.to_string());
            };
            call("presence.unenrol", json!({ "id": id }))?;
            println!("removed presence key {id}");
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

/// `credmgr touch-id enable | disable` - unlock this vault with Touch ID (ADR-098).
fn cmd_touch_id(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr touch-id enable | disable";
    let sub = if args.is_empty() {
        return Err(USAGE.to_string());
    } else {
        args.remove(0)
    };
    reject_flags(&args, USAGE)?;
    match sub.as_str() {
        "enable" => {
            call("device.enrol", json!({}))?;
            println!("Touch ID unlock is on. Lock the vault and try `credmgr unlock --touch-id`.");
            Ok(())
        }
        "disable" => {
            call("device.remove", json!({}))?;
            println!("Touch ID unlock is off.");
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

/// `credmgr keystore status | bind | unbind [--json]` - the machine lock (ADR-165).
fn cmd_keystore(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr keystore status | bind | unbind [--json]   (bind: the passphrase, then \
                         the current recovery code, then the NEW recovery code typed back, one stdin line \
                         each; unbind: the passphrase)";
    let json_out = take_bool_flag(&mut args, "--json");
    let sub = if args.is_empty() {
        return Err(USAGE.to_string());
    } else {
        args.remove(0)
    };
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    // ADR-165 (review P1-1, P2-4): the secrets come from stdin, never the command line.
    let (op, params) = match sub.as_str() {
        "status" => ("keystore.status", json!({})),
        "bind" => {
            let value = keystore_bind_two_phase(json_out)?;
            if !json_out {
                print!("{}", keystore_text(&sub, &value));
            }
            return Ok(());
        }
        "unbind" => {
            let passphrase = quick_cmds::ask_secret("Passphrase")?;
            if passphrase.is_empty() {
                ("keystore.unbind", json!({}))
            } else {
                (
                    "keystore.unbind",
                    json!({ "passphrase": passphrase.as_str() }),
                )
            }
        }
        _ => return Err(USAGE.to_string()),
    };
    let mut params = params;
    let answer = call(op, params.clone());
    quick_cmds::wipe_strings(&mut params);
    let value = answer.map_err(|e| keystore_error_hint(&sub, e))?;
    if json_out {
        println!("{value}");
        return Ok(());
    }
    print!("{}", keystore_text(&sub, &value));
    Ok(())
}

/// `credmgr keystore bind` (review N1): `prepare` with the passphrase and the current recovery code (which
/// changes nothing and answers the new code), the new code printed once, then `commit` with it typed back.
/// Up to three tries at the retyping; anything else (an empty line, the end of stdin) cancels, and nothing
/// has changed. Answers the commit's body.
fn keystore_bind_two_phase(json_out: bool) -> Result<Value, String> {
    let passphrase = quick_cmds::ask_secret("Passphrase")?;
    if passphrase.is_empty() {
        return Err("the passphrase is required (first stdin line)".to_string());
    }
    let code = quick_cmds::ask_secret("Current recovery code")?;
    if code.trim().is_empty() {
        return Err(
            "the current recovery code is required (second stdin line): it is proven before the \
             lock is turned on, so a lost device key can never lock you out"
                .to_string(),
        );
    }
    let mut params = json!({
        "phase": "prepare",
        "passphrase": passphrase.as_str(),
        "recoveryCode": code.trim(),
    });
    let answer = call("keystore.bind", params.clone());
    quick_cmds::wipe_strings(&mut params);
    drop(passphrase);
    drop(code);
    let prepared = answer.map_err(|e| keystore_error_hint("bind", e))?;
    if json_out {
        println!("{prepared}");
    }
    if prepared["already"] == json!(true) {
        // Bound already: no new code; the commit re-keys any project whose key dates from before the bind.
        let value = call("keystore.bind", json!({ "phase": "commit" }))
            .map_err(|e| keystore_error_hint("bind", e))?;
        if json_out {
            println!("{value}");
        }
        return Ok(value);
    }
    let new_code = prepared["newRecoveryCode"]
        .as_str()
        .ok_or("credmgrd did not return the new recovery code")?
        .to_string();
    if !json_out {
        println!(
            "Ready to turn the machine lock on. Nothing has changed yet.\n\n\
             New vault recovery code - write this down now, it will not be shown again:\n\
             (once the lock is on, the recovery code you typed stops working and only this one opens the\n\
             vault on another Mac or after this Mac's device key is lost)\n\n\
             RECOVERY_CODE={new_code}\n\n\
             Retype it to turn the lock on (from stdin, one line; an empty line cancels and changes nothing):"
        );
    }
    std::io::Write::flush(&mut std::io::stdout()).ok();
    for attempt in 1..=3 {
        let typed = quick_cmds::ask_secret("New recovery code").unwrap_or_default();
        if typed.trim().is_empty() {
            let _ = call("keystore.bind", json!({ "phase": "cancel" }));
            return Err(
                "cancelled - the machine lock was not turned on and nothing changed; the recovery code you \
                 typed first still works"
                    .to_string(),
            );
        }
        let mut params = json!({ "phase": "commit", "recoveryCode": typed.trim() });
        let answer = call("keystore.bind", params.clone());
        quick_cmds::wipe_strings(&mut params);
        match answer {
            Ok(value) => {
                if json_out {
                    println!("{value}");
                }
                return Ok(value);
            }
            Err(e) if e.starts_with("recovery_code_mismatch") && attempt < 3 => {
                eprintln!("That is not the code shown above. Nothing changed; type it again:");
            }
            Err(e) if e.starts_with("recovery_code_mismatch") => {
                let _ = call("keystore.bind", json!({ "phase": "cancel" }));
                return Err(
                    "recovery_code_mismatch: the retyped code did not match three times - the machine lock was \
                     not turned on and nothing changed; the recovery code you typed first still works. Run \
                     `credmgr keystore bind` again"
                        .to_string(),
                );
            }
            Err(e) => return Err(keystore_error_hint("bind", e)),
        }
    }
    unreachable!("the loop returns on its third try")
}

/// The words `credmgr keystore` prints for an answer (status, bind or unbind).
fn keystore_text(sub: &str, v: &Value) -> String {
    let mut out = String::new();
    let bound = v["bound"].as_bool().unwrap_or(false);
    match sub {
        "bind" if v["changed"] == json!(false) => {
            out.push_str("The machine lock was already on. No new root key, no new recovery code.\n")
        }
        "bind" => out.push_str(
            "The machine lock is on: the root key was replaced and every project re-keyed, and the\n\
             passphrase now opens this vault only on this Mac. Another Mac using this folder needs the\n\
             recovery code. A copy of the folder made BEFORE now still opens with the passphrase and\n\
             shows what it held then; nothing written from now on.\n",
        ),
        "unbind" if v["changed"] == json!(false) => {
            out.push_str("The machine lock was already off. Nothing changed.\n")
        }
        "unbind" => out.push_str(
            "The machine lock is off: the passphrase opens a copy of this vault folder on any computer again.\n",
        ),
        _ => {}
    }
    if sub == "bind" && v["changed"] == json!(true) {
        out.push_str(
            "The recovery code you retyped is now the vault's recovery code; the one you typed first no \
             longer works.\n",
        );
    }
    if let Some(failed) = v["rekeyFailed"].as_array().filter(|a| !a.is_empty()) {
        for f in failed {
            out.push_str(&format!(
                "warning: project {} was not given a new key ({}); run `credmgr keystore bind` again\n",
                f["node"].as_str().unwrap_or("?"),
                f["reason"].as_str().unwrap_or("")
            ));
        }
    }
    // ADR-165 review M1: archives from before the bind leave the vault folder.
    if let Some(n) = v["archivesMoved"].as_u64().filter(|n| *n > 0) {
        out.push_str(&format!(
            "Moved {n} backup archive{} from the vault folder's backups/ to CredMgr's state folder.\n",
            if n == 1 { "" } else { "s" }
        ));
    }
    if let Some(failed) = v["archivesNotMoved"].as_array().filter(|a| !a.is_empty()) {
        for f in failed {
            out.push_str(&format!(
                "warning: backup archive {} is still in the vault folder ({}); every copy of the folder \
                 carries it; run `credmgr keystore bind` again to move it\n",
                f["file"].as_str().unwrap_or("?"),
                f["reason"].as_str().unwrap_or("")
            ));
        }
    }
    if v["completionPending"].as_bool() == Some(true) {
        out.push_str(
            "note: the change is committed and the vault locked itself; unlock with your passphrase, then run \
             `credmgr keystore bind` again to finish\n",
        );
    }
    let tier = if bound {
        "on (device key file on this Mac; not sealed in the Secure Enclave)"
    } else {
        "off"
    };
    out.push_str(&format!("machine lock: {tier}\n"));
    if bound && v["opensHere"] == json!(false) {
        out.push_str(
            "warning: this Mac cannot open the passphrase file with its device key; unlock with\n\
             `credmgr recover` (the recovery code) instead\n",
        );
    }
    if let Some(w) = v["warning"].as_str() {
        out.push_str(&format!("warning: {w}\n"));
    }
    if let Some(p) = v["protects"].as_str() {
        out.push_str(&format!("protects: {p}\n"));
    }
    if let Some(p) = v["doesNotProtect"].as_str() {
        out.push_str(&format!("does not protect: {p}\n"));
    }
    out.push_str(&format!(
        "recovery code unlock: {}\n",
        if v["recoveryUnlock"].as_bool().unwrap_or(false) {
            "available (works without the device key)"
        } else {
            "not set up yet (change the passphrase to issue a recovery code; bind needs one)"
        }
    ));
    out
}

fn keystore_error_hint(sub: &str, e: String) -> String {
    if e.starts_with("two_factor_required") && sub == "unbind" {
        return format!("{e}\n(turning the machine lock off needs a fresh second factor: run `credmgr gate verify` first)");
    }
    if e.starts_with("recovery_code_mismatch") && sub == "bind" {
        return "recovery_code_mismatch: that recovery code does not open this vault - nothing was changed. \
                Turning the machine lock on needs the CURRENT code (the last one CredMgr printed); without it, \
                change the passphrase (`credmgr passphrase`) to be shown a new one first. Wrong guesses are \
                rate-limited, like wrong passphrases"
            .to_string();
    }
    e
}

fn cmd_lock() -> Result<(), String> {
    let value = call("vault.lock", json!({}))?;
    println!("locked: {}", value["locked"].as_bool().unwrap_or(true));
    Ok(())
}

/// `credmgr gate verify` — completes `07_TWO_FACTOR.md §3`'s second factor
/// after a `vault.unlock` that returned `two_factor_required`. The code is a
/// single-use TOTP, worthless after ~90 s (`07 §5`) and useless without the
/// passphrase, but SECURITY.md counts a secret in argv as in scope (a same-user
/// process sees it in `ps` while the command runs), so it is typed at a prompt or
/// read from stdin (issue #39). `--code-on-argv <n>` keeps the old argv form for
/// the places that cannot prompt, and says what it costs.
fn cmd_gate(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr gate verify | gate enroll | gate recover";
    if args.is_empty() {
        return Err(USAGE.to_string());
    }
    let sub = args.remove(0);
    // ADR-135: `--node <id>` makes the same subcommands about one project's own second factor.
    if let Some(node) = take_flag_value(&mut args, "--node") {
        return stable::cmd_node_gate(&sub, &node, args);
    }
    match sub.as_str() {
        "verify" => {
            const VERIFY_USAGE: &str = "usage: credmgr gate verify  (the code is read from a prompt or stdin; --code-on-argv <n> puts it in the command line, visible to `ps`)";
            let on_argv = take_flag_value(&mut args, "--code-on-argv");
            reject_flags(&args, VERIFY_USAGE)?;
            if !args.is_empty() {
                // The old spelling, `gate verify 123456`: refused with the way out, never accepted quietly.
                return Err(format!(
                    "the code is no longer a command-line argument (a process list shows it while the command runs).\n{VERIFY_USAGE}"
                ));
            }
            let code = match on_argv {
                Some(code) => code,
                None => read_authenticator_code()?,
            };
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
                     fresh: `credmgr lock`, unlock again, `credmgr gate verify`, then run \
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
fn cmd_mcp(mut args: Vec<String>) -> Result<(), String> {
    // ADR-141: `credmgr mcp --print-config [<client>]` prints the client's configuration and exits;
    // it touches no file and starts no server.
    if take_bool_flag(&mut args, "--print-config") {
        return agent::print_config(args);
    }
    if !args.is_empty() {
        return Err(
            "usage: credmgr mcp   (the stdio server)  |  credmgr mcp --print-config [<client>]"
                .to_string(),
        );
    }
    // ADR-164: an agent token in CREDMGR_AGENT_TOKEN scopes the session to its node; anything else there (a
    // login above all) stops the server before it answers a single call.
    credmgr_mcp::transport::agent_token_from_env()?;
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
    if let Some(level) = value["level"].as_str() {
        println!(
            "security level: {}",
            credmgr_core::registry::SecurityLevel::parse(level).map_or(level, |l| l.label())
        );
    }
    Ok(())
}

fn cmd_list(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    // ADR-167: a tag narrows one node's list; it is never a query across nodes.
    let tag = take_flag_value(&mut args, "--tag");
    let value = match (node, tag) {
        (Some(node), Some(tag)) => call("entry.list", json!({ "node": node, "tag": tag }))?,
        (Some(node), None) => call("entry.list", json!({ "node": node }))?,
        (None, Some(_)) => {
            return Err(
                "usage: credmgr list --node <id> --tag <tag> (a tag filters one node)".into(),
            )
        }
        (None, None) => call("node.list", json!({}))?,
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
    // ADR-132: `--deep` looks inside field values (names and ids come back, never a value).
    let deep = take_bool_flag(&mut args, "--deep");
    let node = take_flag_value(&mut args, "--node");
    let term = args
        .first()
        .cloned()
        .ok_or("usage: credmgr search <term> [--node <id>] [--deep] [--json]")?;
    if deep {
        return stable::cmd_search_content(&term, node, as_json);
    }
    // ADR-156: `--node` on a name search asks that one node (`entry.search`).
    let value = match &node {
        Some(node) => call("entry.search", json!({ "node": node, "term": term }))?,
        None => call("search", json!({ "term": term }))?,
    };
    if as_json {
        println!("{value}");
        return Ok(());
    }
    if let Some(results) = value["results"].as_array() {
        for r in results {
            println!(
                "{}\t{}",
                r["node"].as_str().or(node.as_deref()).unwrap_or("?"),
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
        // ADR-121: an alias names the entry too. `search` carries it for every caller (the list's
        // per-entry metadata does not reach an agent).
        let found = call("search", json!({ "term": name }))?;
        if let Some(hit) = found["results"].as_array().and_then(|rows| {
            rows.iter()
                .find(|r| r["node"].as_str() == Some(node) && r["alias"].as_str() == Some(name))
        }) {
            return Ok((
                node.to_string(),
                hit["id"].as_str().unwrap_or_default().to_string(),
            ));
        }
        return Err(format!("no entry named '{name}' on node '{node}'"));
    }
    let value = call("search", json!({ "term": name }))?;
    let results = value["results"].as_array().cloned().unwrap_or_default();
    let matches: Vec<&Value> = results
        .iter()
        .filter(|r| r["name"].as_str() == Some(name) || r["alias"].as_str() == Some(name))
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
         [--field <label> | --field-id <id> | --all] [--json | --copy]";
    let as_json = take_bool_flag(&mut args, "--json");
    let copy = take_bool_flag(&mut args, "--copy");
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
    if copy && (as_json || all) {
        return Err("--copy copies one field's value and prints nothing; it cannot be combined with --json or --all".to_string());
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

    if copy {
        return match shown.as_slice() {
            [only] => {
                clip::copy_secret(only["value"].as_str().unwrap_or(""))?;
                eprintln!(
                    "copied; the clipboard clears in {} seconds if still unchanged",
                    clip::CLEAR_AFTER_SECS
                );
                Ok(())
            }
            _ => Err(selection_error(format!(
                "entry '{name}' has {} fields ({}) — pass --field <label> or --field-id <id> to say which one to copy",
                shown.len(),
                fields::label_list(&shown),
            ))),
        };
    }

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

/// `credmgr totp <name> [--node <id>] [--field <label> | --field-id <id>] [--json]` — the current one-time
/// code of a stored seed (`totp.code`). The seed never leaves the broker; only the six digits do, and they go to
/// stdout alone so they pipe. The seconds the code stays valid go to stderr. Like `get`, the broker's "confirm
/// before showing secrets" rule is answered at a terminal by `call`.
fn cmd_totp(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr totp <name> [--node <id>] [--field <label> | --field-id <id>] [--copy | --json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let copy = take_bool_flag(&mut args, "--copy");
    let node = take_flag_value(&mut args, "--node");
    let selector = fields::Selector::take(&mut args)?;
    reject_flags(&args, USAGE)?;
    let [name] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    if copy && as_json {
        return Err("--copy puts the code on the clipboard and prints nothing; it cannot be combined with --json".to_string());
    }
    let (node, entry) = resolve_name(name, node.as_deref())?;
    let mut params = json!({ "node": node, "entry": entry });
    if selector.is_some() {
        let id = match &selector.id {
            Some(id) => id.clone(),
            None => fields::pick(&fields::entry_meta(&node, &entry)?, name, &selector)?,
        };
        params["field"] = json!(id);
    }
    let answer = call("totp.code", params)?;
    let code = answer["code"]
        .as_str()
        .ok_or("the broker answered without a code")?;
    if copy {
        clip::copy_secret(code)?;
        eprintln!(
            "copied the code{}; the clipboard clears in {} seconds if still unchanged",
            answer["validForSeconds"]
                .as_u64()
                .map(|s| format!(" (valid for {s} more seconds)"))
                .unwrap_or_default(),
            clip::CLEAR_AFTER_SECS
        );
    } else if as_json {
        let mut out = json!({ "code": code });
        if let Some(s) = answer["validForSeconds"].as_u64() {
            out["validForSeconds"] = json!(s);
        }
        println!("{out}");
    } else {
        println!("{code}");
        if let Some(s) = answer["validForSeconds"].as_u64() {
            eprintln!("valid for {s} more seconds");
        }
    }
    Ok(())
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
         [--bulk | --field <label> | --field-id <id>] [--label <l>] \
         [--sensitivity low|medium|high|critical|auto]   (value from stdin)";
    let bulk = take_bool_flag(&mut args, "--bulk");
    let sensitivity = take_choice(
        &mut args,
        "--sensitivity",
        &["low", "medium", "high", "critical", "auto"],
    )?;
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
            if let Some(sv) = &sensitivity {
                params["sensitivity"] = json!(sv);
            }
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
            if let Some(sv) = &sensitivity {
                params["sensitivity"] = json!(sv);
            }
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
    offer_seed_typing(&node, &name, &value);
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
    offer_seed_typing(&node, name, &value);
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
    // ADR-134: `credmgr audit report ...` - a summary for a period instead of the recent records.
    if args.first().map(String::as_str) == Some("report") {
        args.remove(0);
        return stable::cmd_audit_report(args);
    }
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
    // ADR-161: the tidy-up scan is read-only and a different op; it shares the command, not its flags.
    if take_bool_flag(&mut args, "--scan") {
        return quick_cmds::cmd_doctor_scan(args);
    }
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
    const USAGE: &str = "usage: credmgr generate [--length <8-128>] [--no-symbols] [--pronounceable | --hex] [--copy | --json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let copy = take_bool_flag(&mut args, "--copy");
    let no_symbols = take_bool_flag(&mut args, "--no-symbols");
    let pronounceable = take_bool_flag(&mut args, "--pronounceable");
    let hex = take_bool_flag(&mut args, "--hex");
    let length = take_flag_value(&mut args, "--length");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    if hex && pronounceable {
        return Err("--hex and --pronounceable are different alphabets; give one".to_string());
    }
    if copy && as_json {
        return Err("--copy puts the value on the clipboard and prints nothing; it cannot be combined with --json".to_string());
    }
    let mut params = json!({});
    if hex {
        params["hex"] = json!(true);
    }
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
    if copy {
        clip::copy_secret(value["value"].as_str().unwrap_or_default())?;
        eprintln!(
            "copied {} characters (about {} bits of entropy); the clipboard clears in {} seconds if still unchanged",
            value["length"].as_u64().unwrap_or(0),
            value["entropyBits"].as_u64().unwrap_or(0),
            clip::CLEAR_AFTER_SECS
        );
    } else if as_json {
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

/// `credmgr approve <request> [--deny] [--code-on-argv <n>]` (ADR-088, 4b) - decides
/// one agent request while the vault stays locked. The passphrase is the first
/// line of stdin (never argv); the authenticator code, when two-factor is on, is
/// the second line, or - at a terminal - asked for after the broker says it is
/// needed (issue #39: a code in argv is visible to `ps`; `--code-on-argv` keeps
/// that form on purpose). The login in `CREDMGR_TOKEN`, if any, is deliberately
/// not sent: the factors are the authority here, and a token from before the lock
/// is dead anyway.
fn cmd_approve(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr approve <request> [--deny] [--code-on-argv <n>]  (passphrase = first stdin line; the authenticator code = second line, or asked for at a terminal)";
    let deny = take_bool_flag(&mut args, "--deny");
    let mut code = take_flag_value(&mut args, "--code-on-argv");
    reject_flags(&args, USAGE)?;
    let [request] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let interactive = std::io::stdin().is_terminal();
    let passphrase = if interactive {
        eprint!("Vault passphrase: ");
        std::io::Write::flush(&mut std::io::stderr()).ok();
        read_stdin_line()?
    } else {
        let mut all = String::new();
        std::io::stdin()
            .read_to_string(&mut all)
            .map_err(|e| format!("could not read the passphrase from stdin: {e}"))?;
        let (first, rest) = split_first_line(&all);
        if code.is_none() && !rest.trim().is_empty() {
            code = Some(rest.trim().to_string());
        }
        first.to_string()
    };
    let decide = |code: Option<&str>| -> Result<Value, String> {
        let mut params = json!({ "request": request, "approved": !deny, "passphrase": passphrase });
        if let Some(code) = code {
            params["code"] = json!(code);
        }
        let response = transport::call("vault.approval_decide", None, params)
            .map_err(|e: TransportError| e.to_string())?;
        unwrap_ok(response)
    };
    let value = match decide(code.as_deref()) {
        Err(e) if e.starts_with("two_factor_required") && code.is_none() && interactive => {
            // Two-factor is on and no code came with the passphrase: ask for it now.
            let typed = read_authenticator_code()?;
            decide(Some(&typed))?
        }
        Err(e) if e.starts_with("two_factor_required") => {
            return Err(
                "two_factor_required - two-factor is on: give the authenticator code as the \
                 second line of stdin (or run this at a terminal and type it when asked). \
                 A recovery code is not accepted here"
                    .to_string(),
            );
        }
        other => other?,
    };
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
            "{}  {}  node {node}  entry {entry}  {} s left{}{}",
            a["request"].as_str().unwrap_or("?"),
            a["state"].as_str().unwrap_or("pending"),
            a["expiresIn"].as_u64().unwrap_or(0),
            if a["nameHidden"].as_bool() == Some(true) {
                "  (names hidden)"
            } else {
                ""
            },
            agent_tokens::asked_by(a),
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
    if passphrase.contains('\n') {
        return Err("the backup passphrase is one line; stdin held more than one".to_string());
    }
    let value = call(
        "maintenance.backup",
        json!({ "passphrase": passphrase, "retain": retain }),
    )?;
    println!("backup written: {}", value["path"].as_str().unwrap_or("?"));
    println!(
        "  a complete archive: restore it into an empty directory with `credmgr restore <file>` \
         (the backup passphrase, then your vault passphrase)"
    );
    // ADR-165 (review N2): a machine-locked vault's archive holds the passphrase file unsealed, so it is kept
    // outside the vault folder, where no copy of the folder carries it.
    if value["outsideVaultFolder"] == json!(true) {
        println!(
            "  the machine lock is on, so this archive is kept outside the vault folder (in CredMgr's state \
             folder, beside this Mac's device key) and no copy of the vault folder carries it. It opens with \
             the backup passphrase and the vault passphrase alone, without the device key: keep any copy of \
             it as safe as the vault"
        );
    }
    if let Some(pruned) = value["pruned"].as_array() {
        if !pruned.is_empty() {
            println!("pruned {} old backup(s)", pruned.len());
        }
    }
    Ok(())
}

/// `credmgr restore <archive> [--to <dir>] [--state-dir <dir>]` (issue #36, ADR-112) -
/// rebuilds a vault from a backup archive. Offline: it needs no broker and talks to
/// none (the target must not hold a vault). The backup passphrase is read from stdin,
/// never argv. The archive is decrypted in memory, validated whole, and written into
/// the target all at once or not at all; a vault is never merged into or overwritten.
fn cmd_restore(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr restore <archive file> [--to <empty directory>] [--state-dir <directory>] [--json]  (backup passphrase from stdin)";
    let to = take_flag_value(&mut args, "--to");
    let state_dir = take_flag_value(&mut args, "--state-dir");
    // ADR-166: the desktop app's Settings > Backup > Restore runs this command with `--json`,
    // so the app and the terminal share one restore and one set of refusals.
    let as_json = take_bool_flag(&mut args, "--json");
    let fail = |code: &str, message: String| -> String {
        if as_json {
            println!("{}", json!({ "error": code, "message": message }));
        }
        message
    };
    if let Err(e) = reject_flags(&args, USAGE) {
        return Err(fail("restore_failed", e));
    }
    let [archive] = args.as_slice() else {
        return Err(fail("restore_failed", USAGE.to_string()));
    };
    let target = match to {
        Some(dir) => std::path::PathBuf::from(dir),
        None => credmgr_store::paths::VaultPaths::default_location()
            .root()
            .to_path_buf(),
    };
    let state_dir = match state_dir {
        Some(dir) => std::path::PathBuf::from(dir),
        None => credmgr_store::paths::default_state_dir(),
    };
    // Say where it will land before asking for a secret, and refuse early, before the
    // slow key derivation, a target that cannot be used or a broker that is running.
    let sockets = [
        transport::socket_path(),
        credmgr_store::paths::VaultPaths::new(target.clone()).run_socket(),
    ];
    if let Some(refusal) = restore_refusal(&target, &sockets) {
        return Err(fail(refusal.code(), refusal.message()));
    }
    let passphrase = read_stdin_value()?;
    if passphrase.is_empty() {
        return Err(fail(
            "restore_failed",
            "the backup passphrase is required on stdin".to_string(),
        ));
    }
    let blob = std::fs::read(archive)
        .map_err(|e| fail("restore_failed", format!("cannot read {archive}: {e}")))?;
    let plaintext = credmgr_keystore::backup_passphrase::decrypt_with_passphrase(
        &secrecy::SecretBox::new(Box::new(passphrase)),
        &blob,
    )
    .map_err(|_| {
        fail(
            "restore_failed",
            "could not decrypt the archive - wrong backup passphrase, or the file is damaged"
                .to_string(),
        )
    })?;
    let report = credmgr_store::backup::restore_bundle(&plaintext, &target, &state_dir)
        .map_err(|e| fail("restore_failed", e.to_string()))?;
    if as_json {
        let counter = match report.counter {
            credmgr_store::backup::CounterOutcome::Restored => "restored",
            credmgr_store::backup::CounterOutcome::KeptExisting => "keptExisting",
            credmgr_store::backup::CounterOutcome::NotInArchive => "notInArchive",
            // ADR-148 amendment: the one-shot marker the first unlock of the target consumes.
            credmgr_store::backup::CounterOutcome::AcceptMarker => "acceptMarker",
        };
        println!(
            "{}",
            json!({
                "restored": true,
                "target": target.display().to_string(),
                "stateDir": state_dir.display().to_string(),
                "files": report.files,
                "bytes": report.bytes,
                "counter": counter,
                "complete": report.complete,
            })
        );
        return Ok(());
    }
    println!(
        "restored {} files ({} bytes) into {}",
        report.files,
        report.bytes,
        target.display()
    );
    match report.counter {
        credmgr_store::backup::CounterOutcome::Restored => {
            println!("generation counter restored into {}", state_dir.display());
        }
        credmgr_store::backup::CounterOutcome::KeptExisting => println!(
            "generation counter: {} already holds one and it was kept. If it is ahead of this \
             archive the vault will refuse to open as rolled back - that is the counter doing \
             its job; restore into a new --state-dir to start from the archive's",
            state_dir.display()
        ),
        credmgr_store::backup::CounterOutcome::NotInArchive => println!(
            "the archive carries neither a generation counter nor a restore ticket: with no counter in {} \
             the vault opens only when credmgrd is started once with CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1",
            state_dir.display()
        ),
        credmgr_store::backup::CounterOutcome::AcceptMarker => println!(
            "generation counter: none in {}; a one-time restore marker there lets the first unlock of \
             this folder set it (for this restored vault only)",
            state_dir.display()
        ),
    }
    if !report.complete {
        println!(
            "note: this archive predates the complete format - it holds entries, manifests, the \
             registry and keys only, so sealed-node and removed-entry archives, rotation history \
             and notes are not in it"
        );
    }
    println!("next: `credmgr unlock` with the vault passphrase, then `credmgr verify`");
    Ok(())
}

/// Why a restore is refused before the passphrase is read or a byte is written.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RestoreRefusal {
    /// The target holds something: a restore never merges into, or overwrites, a vault.
    TargetNotEmpty(std::path::PathBuf),
    /// A broker answers on this socket (K-23 (d), ADR-156; ADR-166).
    BrokerRunning(std::path::PathBuf),
}

impl RestoreRefusal {
    /// The code `--json` prints, which the desktop app passes on as its error code.
    fn code(&self) -> &'static str {
        match self {
            RestoreRefusal::TargetNotEmpty(_) => "restore_target_not_empty",
            RestoreRefusal::BrokerRunning(_) => "broker_running",
        }
    }

    fn message(&self) -> String {
        match self {
            RestoreRefusal::TargetNotEmpty(target) => format!(
                "{} is not an empty directory: a restore never merges into, or overwrites, a vault. \
                 Give --to <an empty or new directory>",
                target.display()
            ),
            RestoreRefusal::BrokerRunning(socket) => format!(
                "credmgrd is running (it answers on {}): quit CredMgr or stop credmgrd before \
                 restoring, so the restored vault and its generation counter are not written beside \
                 a live broker",
                socket.display()
            ),
        }
    }
}

/// The one check every restore makes first, the terminal's and the app's alike (ADR-166): the
/// target must be empty or new, and no broker may answer on any of `sockets` (the vault's own and
/// the target's). A live connection is a running broker; a socket file nobody listens on (a broker
/// that died) does not block.
fn restore_refusal(
    target: &std::path::Path,
    sockets: &[std::path::PathBuf],
) -> Option<RestoreRefusal> {
    if target.exists() && target.read_dir().map_or(true, |mut d| d.next().is_some()) {
        return Some(RestoreRefusal::TargetNotEmpty(target.to_path_buf()));
    }
    sockets
        .iter()
        .find(|socket| std::os::unix::net::UnixStream::connect(socket).is_ok())
        .map(|socket| RestoreRefusal::BrokerRunning(socket.clone()))
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
        // ADR-130: `credmgr node rekey <id>` - a new key for the node, every file re-sealed to it.
        "rekey" => stable::cmd_node_rekey(args),
        // ADR-098: `credmgr node reparent <id> --to <parent> --reason "..."` - needs Touch ID.
        "reparent" => {
            const USAGE: &str = "usage: credmgr node reparent <id> --to <parent> --reason \"...\"";
            let to = take_flag_value(&mut args, "--to").ok_or(USAGE)?;
            let reason = take_text_flag(&mut args, "--reason")?.ok_or(USAGE)?;
            reject_flags(&args, USAGE)?;
            let [id] = args.as_slice() else {
                return Err(USAGE.to_string());
            };
            let value = call(
                "node.reparent",
                json!({ "node": id, "newParent": to, "reason": reason }),
            )?;
            println!("moved '{id}' under '{to}' (depth {})", value["depth"]);
            Ok(())
        }
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
    const USAGE: &str = "usage: credmgr import <file|-> --node <id> [--format json|env] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node").ok_or(USAGE)?;
    let forced_format = take_flag_value(&mut args, "--format");
    reject_flags(&args, USAGE)?;
    let [source] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let format = import_json::Format::choose(forced_format.as_deref(), source)?;

    let label = if source == "-" { "stdin" } else { source };
    let text = if source == "-" {
        read_capped(std::io::stdin().lock(), IMPORT_MAX_BYTES, "the input")?
    } else {
        let file =
            std::fs::File::open(source).map_err(|e| format!("could not open '{source}': {e}"))?;
        read_capped(file, IMPORT_MAX_BYTES, &format!("'{source}'"))?
    };
    // Both formats end in the same three things: the batch items, the names skipped for an empty value, and the
    // `.env` lines that were refused (always none for JSON).
    let (entries, skipped_empty, refused_lines, what_was_expected): (
        Vec<Value>,
        Vec<String>,
        Value,
        &str,
    ) = match format {
        import_json::Format::Json => {
            let parsed = import_json::parse(&text).map_err(|e| format!("{label}: {e}"))?;
            (
                parsed.entries,
                parsed.skipped_empty,
                json!([]),
                "no entry with a value",
            )
        }
        import_json::Format::Env => {
            let parsed = credmgr_core::dotenv::parse(&text).map_err(|e| format!("{label}: {e}"))?;
            warn_refused_env_lines(label, &parsed.refused_lines);
            (
                parsed
                    .entries
                    .iter()
                    .map(|e| json!({ "name": e.name, "value": e.value }))
                    .collect(),
                parsed.skipped_empty,
                json!(parsed.refused_lines),
                "no NAME=value line with a value",
            )
        }
    };

    if entries.is_empty() {
        let skipped = if skipped_empty.is_empty() {
            String::new()
        } else {
            format!(
                " ({} had an empty value: {})",
                skipped_empty.len(),
                skipped_empty.join(", ")
            )
        };
        return Err(format!(
            "nothing to import from {label}: {what_was_expected}{skipped}"
        ));
    }
    if entries.len() > IMPORT_MAX_ENTRIES {
        return Err(format!(
            "{label} holds {} entries; one import takes at most {IMPORT_MAX_ENTRIES} — \
             split the file and import the parts one after another",
            entries.len()
        ));
    }
    let total_entries = entries.len();
    let mut value = call(
        "entry.create_batch",
        json!({ "node": node, "entries": entries }),
    )?;
    value["skippedEmpty"] = json!(skipped_empty);
    value["refusedLines"] = refused_lines;
    print_name_warnings(&value);
    for c in value["created"].as_array().into_iter().flatten() {
        if c.get("possibleSeedFields").is_some() {
            eprintln!(
                "warning: '{}' has a value that looks as though it could be a 2FA seed; as text it stays readable to anything \
                 that may reveal it. Type it: credmgr field ls '{}' --node {node}, then credmgr field set ... --type totp-seed",
                c["name"].as_str().unwrap_or("?"),
                c["name"].as_str().unwrap_or("?"),
            );
        }
    }

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
            value["total"].as_u64().unwrap_or(total_entries as u64)
        );
        if !skipped_empty.is_empty() {
            println!(
                "skipped {} empty value(s), not imported: {}",
                skipped_empty.len(),
                skipped_empty.join(", ")
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
const SECURITY_LEVEL: &[&str] = &["open", "guarded", "strict", "sealed"];

/// ADR-152: `--security-level strict` is the name for people; the stored and wire value stays `sealed`.
fn security_level_wire(v: &str) -> &str {
    credmgr_core::registry::SecurityLevel::parse_input(v).map_or(v, |l| l.as_str())
}

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
         [--sibling-visibility shared|isolated] [--descendant-read|--no-descendant-read] \
         [--security-level open|guarded|strict] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let reason = take_text_flag(&mut args, "--reason")?;
    let agent_access = take_choice(&mut args, "--agent-access", AGENT_ACCESS)?;
    let two_factor = take_choice(&mut args, "--require-two-factor", TWO_FACTOR)?;
    let sibling = take_choice(&mut args, "--sibling-visibility", SIBLING_VISIBILITY)?;
    let security_level = take_choice(&mut args, "--security-level", SECURITY_LEVEL)?;
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
    if let Some(v) = security_level {
        policy.insert("securityLevel".into(), json!(security_level_wire(&v)));
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
        "securityLevel",
    ] {
        let shown = show_policy_value(&value["policy"][field]);
        let shown = if field == "securityLevel" {
            credmgr_core::registry::SecurityLevel::parse(&shown)
                .map_or(shown.clone(), |l| l.label().to_string())
        } else {
            shown
        };
        println!("  {field:<19}{shown}");
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
/// ADR-148 addendum: say why `credmgr unlock --touch-id` was refused, in words a person can act on. The broker
/// refuses the Touch ID unlock to a caller it identifies as an agent — an agent token, or no token from inside
/// a registered project folder — with a bare `capability_not_held`.
fn explain_touch_id_unlock_error(e: String) -> String {
    if e.starts_with("capability_not_held") {
        format!(
            "{e}\n(Touch ID unlock is refused to anything that looks like an AI agent: a CREDMGR_TOKEN that is an \
             agent token, or a command run from inside a registered project folder. Run it outside your project \
             folders without an agent token, or unlock with your passphrase: `credmgr unlock`)"
        )
    } else if e.starts_with("presence_failed") && e.contains("no presence key is enrolled") {
        format!("{e}\n(set it up first with `credmgr touch-id enable`, while unlocked)")
    } else {
        e
    }
}

/// ADR-148 addendum: name (by number only, never their text) the `.env` lines that were refused because they
/// are only the padded end of a base64 value. The rest of the file still imports.
pub(crate) fn warn_refused_env_lines(label: &str, lines: &[usize]) {
    if lines.is_empty() {
        return;
    }
    let list: Vec<String> = lines.iter().map(usize::to_string).collect();
    eprintln!(
        "warning: {label}: skipped line(s) {} - only the padded end of a base64 value, not NAME=value; \
         quote the whole value on one line to import it",
        list.join(", ")
    );
}

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

    // ---- ADR-162: what the App Store edition's sandboxed CLI refuses -----------------------------

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn the_mas_cli_refuses_a_named_file_and_keeps_stdin() {
        let e = mas_limit("import-env", &v(&[".env", "--node", "n_aaaaaaaa"])).unwrap();
        assert!(
            e.contains("cannot open '.env'")
                && e.contains("credmgr import-env - --node <id> < .env"),
            "{e}"
        );
        assert!(mas_limit("import-env", &v(&["-", "--node", "n_aaaaaaaa"])).is_none());
        assert!(
            mas_limit("import-env", &v(&["--node", "n_aaaaaaaa", "-"])).is_none(),
            "a flag value is not the file"
        );
        assert!(mas_limit("import", &v(&["secrets.txt", "--node", "n_a"])).is_some());
        assert!(mas_limit("import", &v(&["-", "--node", "n_a"])).is_none());
        assert!(mas_limit("notes", &v(&["set", "n_a", "--file", "x.md"])).is_some());
        assert!(mas_limit("notes", &v(&["set", "n_a"])).is_none());
    }

    #[test]
    fn the_mas_cli_refuses_exports_restores_and_agent_config_writes_with_the_way_round() {
        for (cmd, args) in [
            ("export", v(&["--node", "n_a", "--out", "x.age", "--age"])),
            ("restore", v(&["backup.enc"])),
            ("agent", v(&["connect", "claude-code", "--yes"])),
            ("agent", v(&["detect"])),
        ] {
            let e = mas_limit(cmd, &args).unwrap_or_else(|| panic!("{cmd} must be refused"));
            assert!(
                e.contains("macOS sandbox") && e.contains("full CLI"),
                "{cmd}: {e}"
            );
        }
        assert!(mas_limit("agent", &v(&["connect", "x"]))
            .unwrap()
            .contains("mcp --print-config"));
    }

    #[test]
    fn the_mas_cli_leaves_every_vault_command_alone() {
        // The broker does the work for these, inside the group container: nothing to refuse.
        for cmd in [
            "get", "list", "set", "unlock", "lock", "status", "mcp", "backup", "prompt", "search",
            "doctor",
        ] {
            assert!(mas_limit(cmd, &v(&["--node", "n_a"])).is_none(), "{cmd}");
        }
        // The default build never consults the table.
        assert_eq!(
            credmgr_store::paths::FLAVOUR == credmgr_store::paths::Flavour::Mas,
            cfg!(feature = "mas")
        );
    }

    #[test]
    fn a_restore_is_refused_for_a_used_target_or_a_live_broker_and_not_for_a_dead_socket() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("new");
        let dead = dir.path().join("dead.sock");
        // A socket file nobody listens on: the broker that made it is gone.
        drop(std::os::unix::net::UnixListener::bind(&dead).unwrap());
        assert_eq!(restore_refusal(&empty, std::slice::from_ref(&dead)), None);

        let live = dir.path().join("live.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&live).unwrap();
        let refused = restore_refusal(&empty, &[dead.clone(), live.clone()]).unwrap();
        assert_eq!(refused, RestoreRefusal::BrokerRunning(live.clone()));
        assert_eq!(refused.code(), "broker_running");

        let used = dir.path().join("used");
        std::fs::create_dir_all(&used).unwrap();
        std::fs::write(used.join("registry.json"), b"x").unwrap();
        let refused = restore_refusal(&used, &[live]).unwrap();
        assert_eq!(refused.code(), "restore_target_not_empty");
        assert!(refused.message().contains("not an empty directory"));
    }

    #[test]
    fn a_refused_touch_id_unlock_says_why_and_what_to_do() {
        let agent = explain_touch_id_unlock_error("capability_not_held".to_string());
        assert!(
            agent.contains("registered project folder") && agent.contains("credmgr unlock`"),
            "{agent}"
        );
        let unset = explain_touch_id_unlock_error(
            "presence_failed: no presence key is enrolled on this vault".to_string(),
        );
        assert!(unset.contains("credmgr touch-id enable"), "{unset}");
        let dismissed = explain_touch_id_unlock_error(
            "presence_failed: the Touch ID prompt was dismissed or timed out".to_string(),
        );
        assert!(!dismissed.contains("touch-id enable"), "{dismissed}");
    }

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

    #[test]
    fn security_level_strict_is_an_alias_for_the_stored_sealed() {
        let mut args = vec!["--security-level".to_string(), "strict".to_string()];
        let v = take_choice(&mut args, "--security-level", SECURITY_LEVEL)
            .unwrap()
            .unwrap();
        assert_eq!(v, "strict");
        assert_eq!(
            security_level_wire(&v),
            "sealed",
            "the wire value stays sealed"
        );
        // the stored spelling and the others still parse, unchanged
        for (given, wire) in [
            ("sealed", "sealed"),
            ("open", "open"),
            ("guarded", "guarded"),
        ] {
            let mut a = vec!["--security-level".to_string(), given.to_string()];
            let v = take_choice(&mut a, "--security-level", SECURITY_LEVEL)
                .unwrap()
                .unwrap();
            assert_eq!(security_level_wire(&v), wire);
        }
        let mut bad = vec!["--security-level".to_string(), "locked".to_string()];
        assert!(take_choice(&mut bad, "--security-level", SECURITY_LEVEL).is_err());
    }
}
