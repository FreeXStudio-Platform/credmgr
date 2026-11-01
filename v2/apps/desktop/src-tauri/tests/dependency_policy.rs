//! C14 — "the app links no network stack", checked rather than claimed.
//!
//! `PRIVACY.md` and the About screen say the app makes no network requests. That
//! sentence is only as true as the dependency tree behind it, and a tree changes
//! whenever somebody adds a crate or a transitive dependency grows a feature.
//! This test runs `cargo tree` over the **normal** (linked) edges for the
//! targets the app ships on and fails if any HTTP client, HTTP server or TLS
//! binding is among them. `deny.toml` bans the same crates in CI, over the same
//! targets; this test is the one a developer hits before pushing.
//!
//! ## What "the targets the app ships on" means, and why not `--target all`
//!
//! Tauri 2's own manifest depends on `reqwest` for **Android and iOS only**
//! (`tauri/Cargo.toml`: `[target.'cfg(any(target_os = "android", all(target_vendor
//! = "apple", not(target_os = "macos")))'.dependencies.reqwest]`, used by its
//! mobile plugin bridge). `cargo tree --target all` therefore lists `reqwest`
//! and `hyper`; neither is compiled or linked for macOS or Linux. The beta ships
//! on macOS, so the macOS triples are what is asserted. If a desktop target is
//! added to the product, add it to [`SHIPPED_TARGETS`] and to `deny.toml`'s
//! `[graph] targets` together.
//!
//! Build-time edges (`tauri-build`, `tauri-codegen`) run on the developer's
//! machine and are not part of the binary, so they are not asserted here.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// The platforms the desktop app is built for.
const SHIPPED_TARGETS: &[&str] = &["aarch64-apple-darwin", "x86_64-apple-darwin"];

/// Crates that would mean the app can open a network connection or listen on a
/// port. Mirrors `v2/deny.toml` `[bans]` (A-1: no outbound connection; A-2: no
/// listening port) and adds the TLS bindings an HTTP client would bring.
const BANNED: &[&str] = &[
    "reqwest",
    "hyper",
    "hyper-util",
    "ureq",
    "isahc",
    "curl",
    "curl-sys",
    "surf",
    "attohttpc",
    "axum",
    "actix-web",
    "warp",
    "tiny_http",
    "openssl",
    "openssl-sys",
    "native-tls",
    "rustls",
];

/// Names in a `cargo tree --prefix none --format "{p}"` listing: the first word
/// of each line.
fn crate_names(listing: &str) -> BTreeSet<String> {
    listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

fn banned_in(listing: &str) -> Vec<String> {
    let names = crate_names(listing);
    BANNED
        .iter()
        .filter(|b| names.contains(**b))
        .map(|b| b.to_string())
        .collect()
}

fn cargo_tree(extra: &[&str]) -> Result<String, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let run = |offline: bool| {
        let mut command = Command::new(&cargo);
        command
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")))
            .args(["tree", "--locked", "-e", "normal", "--prefix", "none"])
            .args(["--format", "{p}"])
            .args(extra);
        if offline {
            command.arg("--offline");
        }
        command
            .output()
            .map_err(|e| format!("could not run cargo: {e}"))
    };
    // Offline first: `cargo test` has already fetched everything this needs, and
    // a policy test should not depend on the network. A cache that lacks a
    // target-specific crate (an `x86_64` crate on an `aarch64` host) is the one
    // case that needs it, so fall back once.
    let mut output = run(true)?;
    if !output.status.success() {
        output = run(false)?;
    }
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
fn no_http_client_server_or_tls_binding_is_linked_on_a_shipped_target() {
    for target in SHIPPED_TARGETS {
        let listing = cargo_tree(&["--target", target])
            .unwrap_or_else(|e| panic!("cargo tree --target {target} failed:\n{e}"));
        let names = crate_names(&listing);

        // The listing must be a real tree, or an empty one would pass forever.
        for expected in ["desktop", "tauri", "serde_json", "zeroize"] {
            assert!(
                names.contains(expected),
                "{target}: `cargo tree` did not list {expected} — the check is blind"
            );
        }
        assert!(
            names.len() > 100,
            "{target}: only {} crates listed; Tauri's tree is far larger",
            names.len()
        );

        let found = banned_in(&listing);
        assert!(
            found.is_empty(),
            "{target}: the app now links {found:?}. The product's privacy statement says it makes no \
             network requests (17_AIRLOCK_AND_LLM.md A-1/A-2). Find which dependency pulled it in \
             with `cargo tree -e normal --target {target} -i {}`, and remove it or the feature that \
             enables it.",
            found[0]
        );
    }
}

#[test]
fn the_macos_appkit_crates_are_what_was_added_for_c1_and_c2() {
    // Not a ban, a record: the platform bindings this shell reaches AppKit with,
    // so a reviewer sees any change to that surface in a test diff.
    let listing = cargo_tree(&["--target", "aarch64-apple-darwin"]).expect("cargo tree");
    let names = crate_names(&listing);
    for direct in ["objc2", "objc2-app-kit", "objc2-foundation", "block2"] {
        assert!(
            names.contains(direct),
            "{direct} is missing from the macOS tree"
        );
    }
}

#[test]
fn the_check_can_fail() {
    // A guard that cannot fail proves nothing. Feed it the shape of listing a
    // real violation would produce.
    let violation = "desktop v0.1.0 (/x)\ntauri v2.12.1\nreqwest v0.13.5\nhyper v1.11.1\n";
    assert_eq!(banned_in(violation), vec!["reqwest", "hyper"]);
    // Names are matched whole: `hyperlink` is not `hyper`, and a `(*)` marker on
    // a repeated line does not hide a crate.
    assert!(banned_in("hyperlink v1.0.0\nreqwest-middleware-ish v1.0.0\n").is_empty());
    assert_eq!(banned_in("ureq v3.0.0 (*)\n"), vec!["ureq"]);
}

#[test]
fn the_ci_policy_bans_the_same_crates() {
    // `deny.toml` is what CI runs; this test is what a developer runs. If they
    // disagree about what is banned, one of them is lying.
    let deny = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("deny.toml"))
        .expect("src-tauri/deny.toml");
    for banned in BANNED
        .iter()
        .filter(|b| !b.ends_with("-sys") && **b != "hyper-util")
    {
        assert!(
            deny.contains(&format!("crate = \"{banned}\"")),
            "deny.toml does not ban {banned}, which dependency_policy.rs does"
        );
    }
    // `deny.toml` checks the platforms this test checks, and no others.
    for target in SHIPPED_TARGETS {
        assert!(
            deny.contains(&format!("triple = \"{target}\"")),
            "deny.toml's [graph] targets lack {target}"
        );
    }
}
