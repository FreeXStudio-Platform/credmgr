//! The shell's Touch ID helper path against the real Secure Enclave through the unattended test helper.
//! Skips when the helper has not been built (native/macos/presence/build.sh --test-noauth).
#![cfg(target_os = "macos")]

use std::path::Path;

#[test]
fn probe_and_key_creation_work_against_the_real_helper() {
    let helper =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../target/native/credmgr-presence-test");
    if !helper.is_file() {
        eprintln!("skipped: test helper not built");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // One test in this process sets these; they are read by the module under test.
    std::env::set_var(desktop_lib::presence::HELPER_ENV, &helper);
    std::env::set_var("CREDMGR_STATE_DIR", dir.path());
    let probe = desktop_lib::presence::probe().expect("probe");
    assert_eq!(probe["secureEnclave"], true, "{probe}");
    assert_eq!(probe["keyOnThisMac"], false);
    assert!(!desktop_lib::presence::ready());
    let public = desktop_lib::presence::ensure_key().expect("a key is created");
    assert!(!public.is_empty());
    assert!(desktop_lib::presence::ready());
    assert_eq!(
        desktop_lib::presence::ensure_key().unwrap(),
        public,
        "an existing key is kept"
    );
    assert_eq!(
        desktop_lib::presence::probe().unwrap()["keyOnThisMac"],
        true
    );
}
