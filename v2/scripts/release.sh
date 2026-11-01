#!/usr/bin/env bash
# CredMgr V2 - release build of the CLI and the broker: tarball + SBOMs + SHA256SUMS (M3, K-5).
#
#   scripts/release.sh                 build from a clean tree; refuses a dirty one
#   scripts/release.sh --dev           same, but allows a dirty tree and stamps the build "dirty"
#   scripts/release.sh --verify [DIR]  re-check an existing dist/ (default: v2/dist); builds nothing.
#                                      Add --run-binaries to also execute the binaries (--version); off by default
#                                      so a verifier never runs what it has not yet vouched for.
#     --allow-dev-build                  (verify) accept a "dirty" stamp - never publish such a build
#     --allow-version-skew               (verify) accept assets of mixed versions - never publish them
#
# What a build does, in order, and nothing else:
#   1. refuses a dirty working tree (21_RELEASE_AND_INTEGRITY.md 1.3 rule 1 - a binary that cannot
#      say which commit it is must not ship);
#   2. builds `credmgr` and `credmgrd` with `cargo build --release --locked`, stamping each with the
#      commit and target (`credmgr --version`), and with the build machine's home, cargo and checkout
#      paths remapped away so that no login name is embedded in a shipped binary;
#   3. writes a CycloneDX SBOM for each shipped binary and for the desktop shell
#      (apps/desktop/src-tauri, its own workspace), sanitised of local paths; installs
#      `cargo-cyclonedx` with `cargo install` when it is missing;
#   4. empties dist/ of the previous release's files (one dist/ is one release), stages
#      credmgr-<version>-<target>/ - bin/, packaging/, sbom/, docs and its own SHA256SUMS - and writes
#      it as a deterministic tarball (sorted, fixed time, owner 0:0 with no names);
#   5. writes dist/SHA256SUMS over every file in dist/;
#   6. runs --verify on what it just produced.
#
# What it deliberately does NOT do (K-4, K-5): sign, notarise, upload, tag or publish anything.
# Provenance is SHA256SUMS only. The desktop app is built by scripts/release-app.sh, which adds its
# files to this same dist/. The version is read from [workspace.package] in Cargo.toml; nothing here
# ever edits it.
set -euo pipefail

RL_NAME=release
V2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-lib.sh
. "$V2/scripts/release-lib.sh"
cd "$V2"
DIST="$V2/dist"

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'; }

MODE=build
DEV=0
VERIFY_DIR=""
VERIFY_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev) DEV=1 ;;
    --verify) MODE=verify
              if [[ $# -gt 1 && "$2" != --* ]]; then VERIFY_DIR="$2"; shift; fi ;;
    --allow-dev-build|--allow-version-skew|--require-app|--run-binaries) VERIFY_ARGS+=("$1") ;;
    -h|--help) usage; exit 0 ;;
    *) rl_die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

# ---- verify only --------------------------------------------------------------------------------
if [[ "$MODE" == verify ]]; then
  rl_need python3 shasum
  rl_verify "${VERIFY_DIR:-$DIST}" --require-cli ${VERIFY_ARGS[@]+"${VERIFY_ARGS[@]}"}
  exit $?
fi

# ---- build --------------------------------------------------------------------------------------
rl_need git cargo rustc python3 shasum
VERSION=$(rl_cargo_version Cargo.toml workspace.package)
[[ -n "$VERSION" ]] || rl_die "cannot read the [workspace.package] version from Cargo.toml"
rl_valid_version "$VERSION" || rl_die "version '$VERSION' is not MAJOR.MINOR.PATCH[-prerelease] (one pre-release segment, no further hyphen)"

DIRTY=0
if [[ -n "$(git status --porcelain -- .)" ]]; then
  if [[ $DEV -eq 0 ]]; then
    echo "release: REFUSED - the working tree under v2/ is dirty. Commit first, or pass --dev for a" >&2
    echo "         development build that will be stamped dirty (never publish one)." >&2
    exit 1
  fi
  DIRTY=1
fi

COMMIT=$(git rev-parse HEAD)
TARGET=$(rustc -vV | sed -n 's/^host: //p')
[[ -n "$TARGET" ]] || rl_die "cannot read the host target from 'rustc -vV'"
export CREDMGR_BUILD_COMMIT="$COMMIT"
export CREDMGR_BUILD_DIRTY="$DIRTY"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export CARGO_INCREMENTAL=0

# Without this, rustc writes the build machine's paths into panic locations: the first version of
# this script shipped "/Users/<login>/.cargo/registry/src/..." in both binaries. rustc applies the
# LAST matching mapping, so the broad prefix goes first and the specific ones after it.
CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
for p in "$HOME" "$CARGO_HOME_DIR" "$V2"; do
  [[ "$p" == *[[:space:]]* ]] && rl_die "a path containing whitespace cannot be passed through RUSTFLAGS: $p"
done
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/build/home --remap-path-prefix=$CARGO_HOME_DIR=/build/cargo --remap-path-prefix=$V2=/build/v2"
# Reproducibility, as MEASURED (2026-10-03, rustc 1.78, Apple ld 27037): the same commit in the same
# checkout rebuilds byte-identically even from an empty target/ (58 crates recompiled); in a second
# checkout at another path the SBOMs are still identical and the binaries differ in 47-48 bytes - the
# Mach-O LC_UUID and the ad-hoc code-signature hash that covers it - and nowhere else. Neither
# `-Wl,-reproducible` nor a shared CARGO_TARGET_DIR changed that, so neither is passed. The published
# SHA256SUMS, not a rebuild, is the reference.

rl_info "building credmgr $VERSION at ${COMMIT:0:12} for $TARGET (dirty=$DIRTY)"
# Without this the linker stamps the build host's macOS version as the minimum (a 27.2 host produced "minos 27.2",
# found by the beta.1 claim check): the binaries must run wherever the app does (tauri.conf.json minimumSystemVersion).
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.1}"
cargo build --release --locked -p credmgr-cli -p credmgr-brokerd

# ---- SBOMs --------------------------------------------------------------------------------------
CYCLONEDX_ARGS=(--format json --spec-version 1.5)
ensure_cyclonedx() {
  cargo cyclonedx --version >/dev/null 2>&1 && return 0
  [[ "${CREDMGR_RELEASE_NO_INSTALL:-0}" == 1 ]] && rl_die "cargo-cyclonedx is not installed (cargo +stable install --locked cargo-cyclonedx)"
  rl_info "cargo-cyclonedx is missing - installing it with the stable toolchain (CREDMGR_RELEASE_NO_INSTALL=1 forbids this)"
  # From a neutral directory with +stable: this tree pins rustc 1.78, which is too old to build it.
  ( cd "${TMPDIR:-/tmp}" && cargo +stable install --locked cargo-cyclonedx ) || rl_die "could not install cargo-cyclonedx"
  cargo cyclonedx --version >/dev/null 2>&1 || rl_die "cargo-cyclonedx installed but 'cargo cyclonedx' still does not run"
}
ensure_cyclonedx

WORK=$(mktemp -d "${TMPDIR:-/tmp}/credmgr-release.XXXXXX")
RAW_SBOMS=( "$V2/crates/cli/credmgr_bin.cdx.json" "$V2/crates/brokerd/credmgrd_bin.cdx.json"
            "$V2/apps/desktop/src-tauri/desktop.cdx.json" )
cleanup() {   # the generator writes next to each Cargo.toml; never leave its output in the tree
  rm -f "${RAW_SBOMS[@]}" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
rm -f "${RAW_SBOMS[@]}"

rl_info "writing SBOMs"
( cd "$V2" && cargo cyclonedx "${CYCLONEDX_ARGS[@]}" --describe binaries -q )
# The desktop shell is its own workspace pinned to its own toolchain (ADR-035), so it has to be
# resolved from inside its directory.
( cd "$V2/apps/desktop/src-tauri" && cargo cyclonedx "${CYCLONEDX_ARGS[@]}" --describe crate -q )
for f in "${RAW_SBOMS[@]}"; do [[ -s "$f" ]] || rl_die "cargo-cyclonedx did not produce ${f#"$V2"/}"; done

# ---- stage and package --------------------------------------------------------------------------
NAME="credmgr-$VERSION-$TARGET"
rl_info "emptying dist/ of any previous release"
mkdir -p "$DIST"
find "$DIST" -mindepth 1 -maxdepth 1 \( -name 'credmgr-*' -o -name 'CredMgr.app' -o -name 'SHA256SUMS*' \) -exec rm -rf {} +

STAGE="$WORK/stage/$NAME"
mkdir -p "$STAGE/bin" "$STAGE/packaging" "$STAGE/sbom"
cp target/release/credmgr target/release/credmgrd "$STAGE/bin/"
cp packaging/com.credmgr.brokerd.plist "$STAGE/packaging/"
cp RELEASE.md CHANGELOG.md SECURITY.md LICENSE "$STAGE/"

sbom_name() { printf 'credmgr-%s-sbom-%s.cdx.json' "$VERSION" "$1"; }
rl_sbom_sanitise "$V2/crates/cli/credmgr_bin.cdx.json"         "$DIST/$(sbom_name credmgr)"  "$V2" "$SOURCE_DATE_EPOCH" "$COMMIT" credmgr
rl_sbom_sanitise "$V2/crates/brokerd/credmgrd_bin.cdx.json"    "$DIST/$(sbom_name credmgrd)" "$V2" "$SOURCE_DATE_EPOCH" "$COMMIT" credmgrd
rl_sbom_sanitise "$V2/apps/desktop/src-tauri/desktop.cdx.json" "$DIST/$(sbom_name desktop)"  "$V2" "$SOURCE_DATE_EPOCH" "$COMMIT" desktop
cp "$DIST/$(sbom_name credmgr)" "$DIST/$(sbom_name credmgrd)" "$STAGE/sbom/"

# The tarball's own manifest: every packaged file but itself, so an unpacked tree can be re-checked.
( cd "$STAGE" && export LC_ALL=C
  # The list is built before the redirect target exists, so the manifest cannot list itself.
  FILES=$(find . -type f | sed 's|^\./||' | sort)
  printf '%s\n' "$FILES" | while IFS= read -r f; do shasum -a 256 -- "$f"; done > SHA256SUMS )

rl_make_tarball "$WORK/stage" "$NAME" "$DIST/$NAME.tar.gz" "$SOURCE_DATE_EPOCH"
rl_sums_write "$DIST"

# ---- check what was just produced ----------------------------------------------------------------
rl_info "verifying dist/"
VERIFY_NOW=( --require-cli --run-binaries --expect-version "$VERSION" --expect-commit "$COMMIT" )
[[ $DIRTY -eq 1 ]] && VERIFY_NOW+=( --allow-dev-build )
rl_verify "$DIST" "${VERIFY_NOW[@]}"

echo
rl_info "done - UNSIGNED (see RELEASE.md and K-5)"
( cd "$DIST" && ls -l | awk 'NR>1 {printf "  %10d  %s\n", $5, $NF}' && echo && cat SHA256SUMS )
