//! ADR-162: the Mac App Store edition's packaging, read off disk like `shell_config.rs` reads
//! `tauri.conf.json`.
//!
//! Every file here is an input to `scripts/release-app.sh --mas` and `sign-notarise.sh --mas`, and none of
//! them can be exercised on this host the way a Mac would (no codesign, no sandbox, no App Store Connect).
//! What can be held is their content: each executable's entitlements are exactly the keys ADR-162 names,
//! the broker never has a network entitlement, the identifiers live in one file, and the privacy manifest
//! says what the code does. `release-selftest.sh --mas` holds the rendered, assembled bundle to the same rules.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn v2() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("src-tauri is three levels below v2/")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = v2().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The text with XML comments removed (they explain the files and may name keys).
fn uncommented(xml: &str) -> String {
    let mut out = String::new();
    let mut rest = xml;
    while let Some(at) = rest.find("<!--") {
        out.push_str(&rest[..at]);
        let end = rest[at..].find("-->").expect("a closed comment");
        rest = &rest[at + end + 3..];
    }
    out.push_str(rest);
    out
}

/// The top-level `<key>`s of a flat plist dict (entitlements are flat).
fn keys(xml: &str) -> BTreeSet<String> {
    let body = uncommented(xml);
    body.split("<key>")
        .skip(1)
        .map(|s| s[..s.find("</key>").expect("closed key")].to_string())
        .collect()
}

/// The text right after `<key>k</key>`, up to the next `<key>` or the end of the dict.
fn value_after(xml: &str, key: &str) -> String {
    let body = uncommented(xml);
    let tag = format!("<key>{key}</key>");
    let at = body.find(&tag).unwrap_or_else(|| panic!("no {key}"));
    let rest = &body[at + tag.len()..];
    let end = [rest.find("<key>"), rest.find("</dict>")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(rest.len());
    rest[..end].split_whitespace().collect::<Vec<_>>().join(" ")
}

const SANDBOX: &str = "com.apple.security.app-sandbox";
const GROUPS: &str = "com.apple.security.application-groups";
const INHERIT: &str = "com.apple.security.inherit";
const APP_ID: &str = "com.apple.application-identifier";
const TEAM_ID: &str = "com.apple.developer.team-identifier";

fn entitlements(name: &str) -> String {
    read(&format!("packaging/mas/entitlements/{name}.entitlements"))
}

#[test]
fn each_executable_carries_exactly_the_entitlements_adr_162_names() {
    let set = |k: &[&str]| k.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
    assert_eq!(
        keys(&entitlements("app")),
        set(&[SANDBOX, GROUPS, APP_ID, TEAM_ID])
    );
    assert_eq!(keys(&entitlements("credmgrd")), set(&[SANDBOX, GROUPS]));
    assert_eq!(keys(&entitlements("credmgr")), set(&[SANDBOX, GROUPS]));
    assert_eq!(
        keys(&entitlements("credmgr-presence")),
        set(&[SANDBOX, INHERIT]),
        "an inherit helper may carry exactly app-sandbox and inherit: macOS refuses to start it otherwise"
    );
    for name in ["app", "credmgrd", "credmgr", "credmgr-presence"] {
        let text = entitlements(name);
        assert_eq!(
            value_after(&text, SANDBOX),
            "<true/>",
            "{name} is sandboxed"
        );
        for k in keys(&text) {
            assert!(
                !k.contains("network")
                    && !k.contains("files.")
                    && !k.contains("temporary-exception")
                    && !k.contains("cs.")
                    && !k.contains("keychain"),
                "{name} carries {k}: no network, file-access, exception, runtime-relaxing or keychain \
                 entitlement without an ADR (ADR-001, ADR-098, ADR-162)"
            );
        }
    }
    assert_eq!(
        value_after(&entitlements("credmgr-presence"), INHERIT),
        "<true/>"
    );
}

#[test]
fn the_ids_are_written_in_identity_conf_only() {
    // Each template names the group and the team by token; release-app.sh renders them from identity.conf.
    for name in ["app", "credmgrd", "credmgr"] {
        assert_eq!(
            value_after(&entitlements(name), GROUPS),
            "<array> <string>@MAS_APP_GROUP@</string> </array>",
            "{name}: exactly one app group, by token"
        );
    }
    let app = entitlements("app");
    assert_eq!(
        value_after(&app, APP_ID),
        "<string>@MAS_TEAM_ID@.@MAS_BUNDLE_ID@</string>"
    );
    assert_eq!(value_after(&app, TEAM_ID), "<string>@MAS_TEAM_ID@</string>");
    let identity = read("packaging/mas/identity.conf");
    let value =
        |k: &str| desktop_lib::vault_paths::mas_identity_value(&identity, k).map(str::to_string);
    let team = value("MAS_TEAM_ID").expect("MAS_TEAM_ID");
    let bundle = value("MAS_BUNDLE_ID").expect("MAS_BUNDLE_ID");
    assert!(value("MAS_APP_GROUP_NAME").is_some() && value("MAS_IDS_FINAL").is_some());
    let mut templates = vec![
        "packaging/mas/entitlements/app.entitlements".to_string(),
        "packaging/mas/entitlements/credmgrd.entitlements".to_string(),
        "packaging/mas/entitlements/credmgr.entitlements".to_string(),
        "packaging/mas/entitlements/credmgr-presence.entitlements".to_string(),
        "packaging/mas/embedded/credmgrd-Info.plist".to_string(),
        "packaging/mas/embedded/credmgr-Info.plist".to_string(),
        "packaging/mas/LaunchAgents/com.credmgr.brokerd.plist".to_string(),
        "apps/desktop/src-tauri/tauri.mas.conf.json".to_string(),
    ];
    for t in templates.drain(..) {
        let text = uncommented(&read(&t));
        assert!(!text.contains(&team), "{t} writes the team id literally");
        assert!(
            !text.contains(&bundle),
            "{t} writes the bundle id literally"
        );
        // Every token is one the renderer (release-lib.sh rl_mas_render) knows.
        for piece in text.split('@').skip(1).step_by(2) {
            assert!(
                ["MAS_APP_GROUP", "MAS_TEAM_ID", "MAS_BUNDLE_ID", "VERSION"].contains(&piece),
                "{t}: unknown token @{piece}@"
            );
        }
    }
    let overlay: Value =
        serde_json::from_str(&read("apps/desktop/src-tauri/tauri.mas.conf.json")).unwrap();
    assert!(
        overlay.get("identifier").is_none(),
        "the overlay must not name the bundle id: release-app.sh injects it"
    );
}

#[test]
fn the_overlay_bundles_the_mas_binaries_the_agent_plist_and_the_privacy_manifest() {
    let shell = Path::new(env!("CARGO_MANIFEST_DIR"));
    let overlay: Value =
        serde_json::from_str(&read("apps/desktop/src-tauri/tauri.mas.conf.json")).unwrap();
    let files = overlay["bundle"]["macOS"]["files"]
        .as_object()
        .expect("bundle.macOS.files");
    let resolved = |k: &str| {
        desktop_lib::login_agent::normalize(&shell.join(files[k].as_str().expect("a path")))
    };
    let workspace = desktop_lib::login_agent::normalize(&shell.join("../../.."));
    // The MAS-flavour broker and CLI, never the Developer ID build in target/release.
    assert_eq!(
        resolved("MacOS/credmgrd"),
        workspace.join("target/mas/release/credmgrd")
    );
    assert_eq!(
        resolved("MacOS/credmgr"),
        workspace.join("target/mas/release/credmgr")
    );
    // The agent plist where SMAppService looks, named as login_agent.rs registers it.
    let agent_key = format!(
        "Library/LaunchAgents/{}",
        desktop_lib::login_agent::MAS_AGENT_PLIST
    );
    assert!(resolved(&agent_key).is_file(), "{agent_key}");
    assert!(resolved("Resources/PrivacyInfo.xcprivacy").is_file());
    // The Touch ID helper comes from the base config (Tauri merges the overlay into it).
    assert!(
        !files.contains_key("MacOS/credmgr-presence"),
        "the base config bundles the helper; the overlay must not fork it"
    );
    let base: Value =
        serde_json::from_str(&read("apps/desktop/src-tauri/tauri.conf.json")).unwrap();
    assert!(base["bundle"]["macOS"]["files"]["MacOS/credmgr-presence"].is_string());
    // The agent's BundleProgram is the file the overlay puts at Contents/MacOS/credmgrd.
    assert_eq!(
        desktop_lib::login_agent::MAS_BUNDLE_PROGRAM,
        format!(
            "Contents/{}",
            files.keys().find(|k| k.ends_with("/credmgrd")).unwrap()
        )
    );
    assert_eq!(overlay["bundle"]["category"], "DeveloperTool");
    let min = overlay["bundle"]["macOS"]["minimumSystemVersion"]
        .as_str()
        .unwrap();
    let major: u32 = min.split('.').next().unwrap().parse().unwrap();
    assert!(major >= 13, "SMAppService needs macOS 13");
}

#[test]
fn the_privacy_manifest_declares_no_tracking_no_collection_and_only_the_apis_the_code_uses() {
    let pm = read("packaging/mas/PrivacyInfo.xcprivacy");
    assert_eq!(value_after(&pm, "NSPrivacyTracking"), "<false/>");
    assert_eq!(value_after(&pm, "NSPrivacyTrackingDomains"), "<array/>");
    assert_eq!(value_after(&pm, "NSPrivacyCollectedDataTypes"), "<array/>");
    let body = uncommented(&pm);
    let cats: Vec<&str> = body
        .split("<string>NSPrivacyAccessedAPICategory")
        .skip(1)
        .map(|s| &s[..s.find('<').unwrap()])
        .collect();
    assert_eq!(cats, ["FileTimestamp", "SystemBootTime"]);
    assert!(body.contains("<string>C617.1</string>") && body.contains("<string>35F9.1</string>"));
}

#[test]
fn the_developer_id_build_is_unchanged() {
    // The default (direct) build keeps its empty hardened-runtime entitlements and its own identifier.
    let direct = read("apps/desktop/src-tauri/entitlements.plist");
    assert!(
        keys(&direct).is_empty(),
        "entitlements.plist must stay empty of exceptions"
    );
    let base: Value =
        serde_json::from_str(&read("apps/desktop/src-tauri/tauri.conf.json")).unwrap();
    assert_eq!(base["identifier"], "com.credmgr.desktop");
    assert_eq!(
        base["bundle"]["macOS"]["files"]["MacOS/credmgrd"],
        "../../../target/release/credmgrd"
    );
    // ADR-166 (Restore from the app) bundles the command line in the Developer ID build too, from the default
    // target; the MAS build bundles its own `mas`-feature binary (`tauri.mas.conf.json`), never this one.
    assert_eq!(
        base["bundle"]["macOS"]["files"]["MacOS/credmgr"],
        "../../../target/release/credmgr"
    );
}
