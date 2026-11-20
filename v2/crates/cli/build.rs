//! The build stamp, as one marker string (issue #38).
//!
//! `scripts/release.sh` passes `CREDMGR_BUILD_COMMIT` and `CREDMGR_BUILD_DIRTY`.
//! This turns them into a single self-describing constant, `CREDMGR_BUILD_STAMP`,
//! so `scripts/release.sh --verify` can read the stamp straight out of the
//! binary's bytes without running it (a verifier must not execute what it has not
//! vouched for). `--version` is built from the same constant, so the two cannot
//! disagree. Inert data: nothing trusts it (21_RELEASE_AND_INTEGRITY.md 1.3 rule 4).
//! Keep this file identical to `crates/brokerd/build.rs`.
fn main() {
    println!("cargo:rerun-if-env-changed=CREDMGR_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=CREDMGR_BUILD_DIRTY");
    let commit = std::env::var("CREDMGR_BUILD_COMMIT").unwrap_or_default();
    let valid = (12..=64).contains(&commit.len())
        && commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let commit = if valid { commit.as_str() } else { "none" };
    let dirty = if std::env::var("CREDMGR_BUILD_DIRTY").as_deref() == Ok("1") {
        "1"
    } else {
        "0"
    };
    println!(
        "cargo:rustc-env=CREDMGR_BUILD_STAMP=credmgr-build-stamp:v1:commit={commit}:dirty={dirty}"
    );
}
