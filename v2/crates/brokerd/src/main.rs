//! `credmgrd` — the broker daemon. The single enforcement point (ADR-001):
//! every client (CLI, MCP, the Tauri app) is a socket peer, none holds a
//! node key directly.
//!
//! **ADR-061: this binary now actually runs.** Until 2026-08-31 `main`
//! printed a status line and exited — there was no code path, anywhere,
//! that ran the broker as a real process outside a test harness. It now
//! resolves the vault path (`CREDMGR_VAULT_DIR` or the OS default), loads
//! whatever already exists on disk (nothing, for a not-yet-initialized
//! vault — `scope::resolve_scope` already degrades to a harmless
//! `List`-only scope against an empty registry, so this is not a special
//! "unbootstrapped mode", just the normal empty case), and serves the
//! socket.
//!
//! **The start-up keystore is an inert placeholder, on purpose** (built from
//! an empty passphrase). Nothing here knows the passphrase at start, and
//! nothing needs to: `vault.unlock {passphrase}` builds the real keystore
//! per request, proves it against `keys/root.wrap.pass`, loads and verifies
//! the vault from disk, and keeps only the unwrapped root key, resident until
//! `vault.lock` (ADR-063 as amended — the passphrase keystore itself is
//! dropped at once, and never replaces this placeholder). Until 2026-09-24
//! the unlock path used this placeholder directly and refused every real
//! passphrase. `packaging/com.credmgr.brokerd.plist` is the launchd unit.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;

use secrecy::SecretBox;

use credmgr_brokerd::diag_log::{self, Value as Diag};
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::paths::VaultPaths;

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

/// Same stamp as `credmgr --version` (see that function): version, commit,
/// dirty flag — inert data an honest build uses to identify itself.
fn version_line() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let platform = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    // `black_box`: the optimiser must keep the stamp whole in the binary (the
    // release verifier greps for it), not fold it into the pieces parsed below.
    match parse_build_stamp(std::hint::black_box(BUILD_STAMP)) {
        Some((commit, dirty)) => {
            let short = &commit[..commit.len().min(12)];
            let dirty = if dirty { ", dirty" } else { "" };
            format!("credmgrd {version} (commit {short}{dirty}, {platform})")
        }
        None => format!("credmgrd {version} (development build, no commit stamp, {platform})"),
    }
}

/// A name-free description of an I/O failure for the start-up messages: the error's kind, never
/// its text, because an `io::Error` built by this crate or by `std` can quote a path (ADR-159
/// amendment: the daemon's own output carries no home directory and so no user name).
fn kind_label(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::AddrInUse => "another broker is already serving this vault",
        std::io::ErrorKind::PermissionDenied => "permission denied",
        std::io::ErrorKind::NotFound => "not found",
        _ => "i/o error",
    }
}

/// Whether something is answering on `socket` — the same test `server::run`
/// uses (Review M4) to decide that a broker already serves this vault.
fn broker_is_serving(socket: &std::path::Path) -> bool {
    socket.exists() && std::os::unix::net::UnixStream::connect(socket).is_ok()
}

fn main() -> ExitCode {
    if matches!(std::env::args().nth(1).as_deref(), Some("--version" | "-V")) {
        println!("{}", version_line());
        return ExitCode::SUCCESS;
    }
    let paths = VaultPaths::default_location();

    // ADR-159: the diagnostic log, off unless `CREDMGR_DIAG_LOG=1`. Nothing below writes a path, a
    // name or a value to it — only static labels and numbers (`diag_log`'s module doc).
    if diag_log::enabled_by_env() {
        let dir = credmgr_store::paths::default_log_dir();
        if let Err(e) = diag_log::install(&dir) {
            eprintln!(
                "credmgrd: could not open the diagnostic log in the log folder ({}) — running without it",
                kind_label(&e)
            );
        }
    }
    let (commit, dirty) = parse_build_stamp(BUILD_STAMP).unwrap_or(("none", false));
    diag_log::event(
        "start",
        &[
            ("version", Diag::Str(env!("CARGO_PKG_VERSION"))),
            ("commit", Diag::Str(&commit[..commit.len().min(12)])),
            ("dirty", Diag::Str(if dirty { "yes" } else { "no" })),
            ("os", Diag::Str(std::env::consts::OS)),
            ("arch", Diag::Str(std::env::consts::ARCH)),
            (
                "vault_dir",
                Diag::Str(if std::env::var_os("CREDMGR_VAULT_DIR").is_some() {
                    "override"
                } else {
                    "default"
                }),
            ),
            (
                "vault",
                Diag::Str(if paths.registry().exists() {
                    "present"
                } else {
                    "absent"
                }),
            ),
        ],
    );

    // Directory layout only — `run/` (`0700`) must exist before the socket
    // can bind; every other subdirectory is created lazily by whichever
    // write first needs it (`atomic::write`'s own behavior, unchanged here).
    if let Err(e) = credmgr_store::atomic::ensure_dir(&paths.run_dir()) {
        diag_log::event("exit", &[("reason", Diag::Str("run_dir"))]);
        let _ = e; // not printed: its text can quote the run folder's path
        eprintln!("credmgrd: could not create the vault's run folder");
        return ExitCode::FAILURE;
    }

    // ADR-076: a root-key rotation a crash interrupted is finished — or, if it
    // never reached its commit record, dropped — before anything reads a root
    // wrap. Key-free (it only renames files), so it needs no passphrase; every
    // unlock runs it again, so a failure here is reported but does not stop the
    // daemon from serving `vault.status` and the rest.
    //
    // Two guards keep this from hurting a rotation that is still running. A
    // broker already serving this vault owns recovery — a second daemon must
    // not touch the vault at all; `server::run` is about to refuse it (Review
    // M4). And the recovery itself runs under the per-vault lock, so even a
    // daemon that starts in the instant before the first one binds its socket
    // waits for a rotation in progress instead of deleting its half-written
    // stage as a crash leftover (the ADR-076 review's P2).
    let state_dir = credmgr_store::paths::default_state_dir();
    if broker_is_serving(&paths.run_socket()) {
        diag_log::event(
            "recovery",
            &[("result", Diag::Str("left_to_running_broker"))],
        );
        eprintln!(
            "credmgrd: a broker is already serving this vault — leaving rotation recovery to it."
        );
    } else {
        let recovery = BrokerState::recover_interrupted_rotation_at(&paths, &state_dir);
        let label = match &recovery {
            Ok(credmgr_store::rotation::Recovery::Nothing) => "nothing",
            Ok(credmgr_store::rotation::Recovery::DiscardedStage) => "discarded_stage",
            Ok(credmgr_store::rotation::Recovery::RolledForward { .. }) => "rolled_forward",
            Err(_) => "error",
        };
        diag_log::event("recovery", &[("result", Diag::Str(label))]);
        match recovery {
            Ok(credmgr_store::rotation::Recovery::Nothing) => {}
            // What was left behind cannot say whether the rotation had finished,
            // so neither can this line (see `Recovery::DiscardedStage`).
            Ok(credmgr_store::rotation::Recovery::DiscardedStage) => eprintln!(
                "credmgrd: removed leftover staging files of a root-key rotation that was cut off. \
                 This changes nothing in the vault: it opens with whichever root key your passphrase \
                 yields. If you were rotating the root key and never saw the new recovery code, \
                 rotate again to get one you hold."
            ),
            Ok(credmgr_store::rotation::Recovery::RolledForward { files }) => eprintln!(
                "credmgrd: finished an interrupted root-key rotation ({files} files) — the new root key is in force. \
                 If the new recovery code was never shown to you, rotate again to get one you hold: \
                 the old recovery code no longer opens anything."
            ),
            // The error is not printed: some of its texts quote a file path, and so the user name.
            // `vault.unlock` reports the same failure to the person, in the app or the CLI.
            Err(_) => eprintln!(
                "credmgrd: could not recover an interrupted root-key rotation — unlock will report the same until it is resolved."
            ),
        }
    }

    // Placeholder — see the module doc above for exactly what this does and
    // does not cover. `default_state_dir()` matches what
    // `BrokerState::begin_init`'s own throwaway keystore uses, so the two
    // never disagree about where the software counter files live.
    let placeholder_keystore = SoftwareKeystore::new(
        SecretBox::new(Box::default()),
        credmgr_store::paths::default_state_dir(),
    );
    let state = Arc::new(BrokerState::new(
        Box::new(placeholder_keystore),
        paths.clone(),
    ));

    // No start-up load of an existing vault: `verify_and_load_vault` needs
    // the root key to check the registry's HMAC, and the first
    // `vault.unlock {passphrase}` is where that key first exists (ADR-063).
    // An unverified registry is never loaded, so until that unlock the
    // graph is empty and every op but `vault.status`/`vault.unlock`/
    // `vault.gate_recover`/`vault.init_*` has nothing to act on.
    if !paths.registry().exists() {
        eprintln!(
            "credmgrd: no vault in the vault folder yet — run `credmgr init` from another terminal to create one; this process keeps serving vault.init_begin/vault.init_confirm in the meantime."
        );
    }

    println!("credmgrd: listening on the broker socket");
    diag_log::event("listening", &[]);
    match server::run(state, &paths.run_socket()) {
        Ok(()) => {
            diag_log::event("exit", &[("reason", Diag::Str("listener_closed"))]);
            ExitCode::SUCCESS
        }
        Err(e) => {
            let reason = match e.kind() {
                std::io::ErrorKind::AddrInUse => "another_broker_serving",
                std::io::ErrorKind::PermissionDenied => "permission_denied",
                std::io::ErrorKind::NotFound => "not_found",
                _ => "io_error",
            };
            diag_log::event("exit", &[("reason", Diag::Str(reason))]);
            eprintln!("credmgrd: server error ({reason})");
            ExitCode::FAILURE
        }
    }
}
