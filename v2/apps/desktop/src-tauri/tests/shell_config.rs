//! The window's Content Security Policy, read from `tauri.conf.json` on disk.
//!
//! `05_THREAT_MODEL.md` and `02_ARCHITECTURE.md §5.3` make a restrictive CSP a
//! release gate, "asserted by a test that reads `tauri.conf.json` and fails
//! closed on `null`". The reason is concrete: `entry_reveal` hands the
//! webview a plaintext secret, and A-1's no-outbound-network property protects
//! the *broker* process, not the renderer. A vault window that may load a
//! remote script, or post to a remote origin, can exfiltrate what it was just
//! shown. The scaffold shipped `"csp": null` until 2026-09-24.
//!
//! What is asserted is the *production* policy (`app.security.csp`). The
//! development policy (`devCsp`) is allowed the local Vite server and nothing
//! else — never a remote origin — and is checked for exactly that.

use std::path::Path;

use serde_json::Value;

fn config() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json");
    let text = std::fs::read_to_string(&path).expect("read tauri.conf.json");
    serde_json::from_str(&text).expect("tauri.conf.json is JSON")
}

/// Every source expression across every directive, as `(directive, source)`.
fn sources(policy: &Value) -> Vec<(String, String)> {
    let object = policy
        .as_object()
        .expect("a CSP is an object of directives here, never a bare string or null");
    object
        .iter()
        .flat_map(|(directive, value)| {
            let text = match value {
                Value::String(s) => s.clone(),
                Value::Array(items) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" "),
                other => panic!("{directive}: unexpected CSP value {other}"),
            };
            text.split_whitespace()
                .map(|s| (directive.clone(), s.to_string()))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Tauri's own IPC endpoints — the only non-`'self'` origin production allows.
const TAURI_IPC: &[&str] = &["ipc:", "http://ipc.localhost"];

#[test]
fn the_production_csp_exists_and_admits_no_remote_origin() {
    let csp = &config()["app"]["security"]["csp"];
    assert!(
        !csp.is_null(),
        "app.security.csp is null — the vault window would load anything (release gate, \
         05_THREAT_MODEL.md)"
    );
    assert_eq!(
        csp["default-src"], "'self'",
        "default-src must be exactly 'self'"
    );
    assert_eq!(csp["object-src"], "'none'");
    assert_eq!(csp["base-uri"], "'none'");

    for (directive, source) in sources(csp) {
        assert!(
            !source.starts_with("'unsafe-"),
            "{directive} allows {source} — no unsafe-inline/unsafe-eval in production"
        );
        assert_ne!(source, "*", "{directive} allows any origin");
        let is_origin = source.contains("://") || source.ends_with(':');
        let allowed = TAURI_IPC.contains(&source.as_str()) || source == "data:";
        assert!(
            !is_origin || allowed,
            "{directive} admits {source} — production may reach no origin but Tauri's own IPC"
        );
        if source == "data:" {
            assert_eq!(
                directive, "img-src",
                "data: is allowed for images (QR codes) only"
            );
        }
    }
}

#[test]
fn the_development_csp_admits_the_local_dev_server_and_nothing_remote() {
    let dev = &config()["app"]["security"]["devCsp"];
    assert!(
        !dev.is_null(),
        "devCsp unset would fall back to the production policy and break `tauri dev`"
    );
    for (directive, source) in sources(dev) {
        if source.contains("://") {
            let host = source.split("://").nth(1).unwrap_or_default();
            assert!(
                TAURI_IPC.contains(&source.as_str()) || host.starts_with("localhost:"),
                "devCsp {directive} admits {source} — development may reach localhost only"
            );
        }
        assert_ne!(source, "*", "devCsp {directive} allows any origin");
    }
}

// ---------------------------------------------------------------------------
// The rest of the shell's configuration
// ---------------------------------------------------------------------------

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(manifest_dir().join(relative))
        .unwrap_or_else(|e| panic!("cannot read {relative}: {e}"))
}

#[test]
fn the_opener_plugin_and_the_scaffolds_greet_are_gone() {
    // C13: nothing in the app opens an external URL, so no plugin that can is
    // linked or permitted; `greet` was the create-tauri-app hello-world.
    let cargo = read("Cargo.toml");
    assert!(
        !cargo.contains("tauri-plugin-opener") && !cargo.contains("tauri_plugin_opener"),
        "the opener plugin is back in Cargo.toml"
    );
    let lock = read("Cargo.lock");
    assert!(
        !lock.contains("name = \"tauri-plugin-opener\""),
        "the opener plugin is still locked in Cargo.lock"
    );

    for entry in std::fs::read_dir(manifest_dir().join("capabilities")).expect("capabilities/") {
        let path = entry.expect("entry").path();
        let text = std::fs::read_to_string(&path).expect("read capability");
        assert!(
            !text.contains("opener"),
            "{} grants an opener permission",
            path.display()
        );
    }

    for entry in std::fs::read_dir(manifest_dir().join("src")).expect("src/") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        assert!(
            !text.contains("tauri_plugin_opener") && !text.contains("fn greet"),
            "{} still carries the scaffold's opener or greet",
            path.display()
        );
    }
}

#[test]
fn the_window_gets_core_default_and_nothing_else() {
    // Widening this is a security decision, so it fails a test and gets read.
    let dir = manifest_dir().join("capabilities");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("capabilities/") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        seen += 1;
        let capability: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).expect("JSON");
        assert_eq!(capability["windows"], serde_json::json!(["main"]));
        assert_eq!(
            capability["permissions"],
            serde_json::json!(["core:default"]),
            "{}: the permission set changed",
            path.display()
        );
        assert!(
            capability.get("remote").is_none() && capability.get("webviews").is_none(),
            "{}: a capability for remote content or extra webviews",
            path.display()
        );
    }
    assert_eq!(seen, 1, "expected exactly one capability file");
}

#[test]
fn the_crate_carries_the_product_licence_file_like_the_rest_of_the_product() {
    let cargo = read("Cargo.toml");
    assert!(
        cargo
            .lines()
            .any(|l| l.trim() == "license-file = \"../../../LICENSE\""),
        "Cargo.toml must declare license-file = \"../../../LICENSE\" (v2/LICENSE)"
    );
}

#[test]
fn every_bundled_icon_exists_and_the_mark_it_came_from_is_in_the_tree() {
    let config = config();
    let icons = config["bundle"]["icon"].as_array().expect("bundle.icon");
    assert!(!icons.is_empty());
    for icon in icons {
        let relative = icon.as_str().expect("icon path");
        let path = manifest_dir().join(relative);
        assert!(
            path.is_file(),
            "bundle.icon lists {relative}, which is missing"
        );
    }
    // The icon set is generated (`npx tauri icon`) from one committed source.
    let mark = manifest_dir().join("../../../design/marks/keep.svg");
    assert!(
        mark.is_file(),
        "v2/design/marks/keep.svg is the icon's source"
    );
}

#[test]
fn the_tauri_crate_and_the_tauri_npm_packages_agree_on_major_and_minor() {
    // `tauri info` refuses to build on a mismatch ("version mismatched Tauri
    // packages"); this fails first, with the reason, and without Node.
    fn major_minor(version: &str) -> (u64, u64) {
        let mut parts = version
            .trim_start_matches(['^', '~', '='])
            .split('.')
            .map(|p| p.parse::<u64>().expect("numeric version part"));
        (parts.next().unwrap(), parts.next().unwrap())
    }

    let lock = read("Cargo.lock");
    let crate_version = lock
        .split("[[package]]")
        .find(|block| block.lines().nth(1) == Some("name = \"tauri\""))
        .and_then(|block| block.lines().find_map(|l| l.strip_prefix("version = \"")))
        .and_then(|v| v.strip_suffix('"'))
        .expect("tauri is locked");

    let package: Value =
        serde_json::from_str(&read("../package.json")).expect("package.json is JSON");
    for (section, name) in [
        ("dependencies", "@tauri-apps/api"),
        ("devDependencies", "@tauri-apps/cli"),
    ] {
        let npm_version = package[section][name]
            .as_str()
            .unwrap_or_else(|| panic!("package.json lacks {name}"));
        assert_eq!(
            major_minor(crate_version),
            major_minor(npm_version),
            "tauri crate {crate_version} vs {name} {npm_version}: run `cargo update -p tauri` \
             (or move the npm pin) so `npx tauri info` reports no mismatch"
        );
    }
}

#[test]
fn the_window_is_one_window_with_the_products_name() {
    let config = config();
    assert_eq!(config["productName"], "CredMgr");
    assert_eq!(config["app"]["withGlobalTauri"], false);
    let windows = config["app"]["windows"].as_array().expect("windows");
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0]["label"], "main");
}

#[test]
fn the_main_window_is_created_content_protected() {
    // Threat T10: a screen recording or a screen share must show the window blank. It starts on for every install and start;
    // turning it off is the user's Settings choice (applied by `capture_protection_set` after the page boots) or the
    // developer environment variable (`shell::ENV_CONTENT_PROTECTION`), never a config default.
    let windows = config()["app"]["windows"].clone();
    let main = windows
        .as_array()
        .and_then(|w| w.iter().find(|w| w["label"] == "main"))
        .expect("a window labelled main")
        .clone();
    assert_eq!(
        main["contentProtected"],
        Value::Bool(true),
        "the main window must set contentProtected: true"
    );
}
