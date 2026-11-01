#!/usr/bin/env bash
# CredMgr V2 - release build of the DESKTOP APP: CredMgr.app + .dmg, added to the same dist/ as
# scripts/release.sh (M3, K-5). macOS only. UNSIGNED: sealed ad-hoc, never identity-signed or notarised.
#
#   scripts/release-app.sh                   build from a clean tree; refuses a dirty one
#   scripts/release-app.sh --dev             allow a dirty tree (never publish such a build)
#   scripts/release-app.sh --allow-version-skew   build although the manifests disagree on the version
#   scripts/release-app.sh --no-launch-check      do not start the built app (headless machines)
#   scripts/release-app.sh --skip-npm-ci          reuse node_modules (a dev loop; a release runs `npm ci`)
#   scripts/release-app.sh --verify [DIR]    re-check an existing dist/, app included; builds nothing
#
# What it does, in order:
#   1. refuses a dirty tree, and refuses to build when the four manifests that carry a version
#      (workspace Cargo.toml, tauri.conf.json, package.json, src-tauri/Cargo.toml) disagree;
#   2. `npm ci` (exact lockfile versions), then the frontend build and its release gate;
#   3. compiles the shell with `cargo build --locked`, then bundles with `tauri bundle` - NOT with
#      `npm run tauri build`. See "Why not `tauri build`" below;
#   4. seals the bundle ad-hoc (identity "-": it binds Info.plist and resources so the bundle is
#      internally consistent; it is NOT a Developer ID signature and Gatekeeper still refuses it);
#   5. copies CredMgr.app into dist/ and writes credmgr-desktop-<version>-<target>.dmg and
#      ...app.zip beside the CLI tarball, then rewrites dist/SHA256SUMS over everything there;
#   6. runs the same verifier as `release.sh --verify` (dmg verifies and mounts, the unpacked app's
#      seal verifies, no build-machine path in the executable);
#   7. STARTS the built app against a throwaway vault directory and requires a real on-screen
#      window, then stops it. A bundle that builds and verifies but cannot open is not a release.
#
# Why not `tauri build`: its CLI exports MACOSX_DEPLOYMENT_TARGET=13.1 (from minimumSystemVersion)
# to every crate. With the macOS 27 command-line-tools linker (ld 27037.1) that makes some
# proc-macro dylibs malformed - dyld refuses them ("mis-aligned LINKEDIT string pool") and rustc
# reports "can't find crate for `zerofrom_derive`" - so the documented one-command build fails here,
# before and independently of anything in this repository. The CLI overwrites a value set in the
# environment, so it cannot be worked around from outside. The steps below are what `tauri build`
# runs (frontend, `cargo build --bins --features tauri/custom-protocol --release`, bundle), minus
# that global export; tauri-build still pins the final executable itself to 13.1.
#
# Nothing here signs with an identity, notarises, uploads or publishes (K-5). It deliberately
# unsets every APPLE_* signing variable so a stray one in the environment cannot change that.
set -euo pipefail

RL_NAME=release-app
V2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-lib.sh
. "$V2/scripts/release-lib.sh"
cd "$V2"
DESK="$V2/apps/desktop"
SHELL_DIR="$DESK/src-tauri"
DIST="$V2/dist"

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'; }

DEV=0; SKEW=0; LAUNCH=1; NPM_CI=1; MODE=build; VERIFY_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev) DEV=1 ;;
    --allow-version-skew) SKEW=1 ;;
    --no-launch-check) LAUNCH=0 ;;
    --skip-npm-ci) NPM_CI=0 ;;
    --verify) MODE=verify
              if [[ $# -gt 1 && "$2" != --* ]]; then VERIFY_DIR="$2"; shift; fi ;;
    -h|--help) usage; exit 0 ;;
    *) rl_die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

if [[ "$MODE" == verify ]]; then
  rl_need python3 shasum
  V=(); [[ $SKEW -eq 1 ]] && V+=(--allow-version-skew)
  rl_verify "${VERIFY_DIR:-$DIST}" --require-app ${V[@]+"${V[@]}"}
  exit $?
fi

# ---- preconditions ------------------------------------------------------------------------------
[[ "$(uname -s)" == Darwin ]] || rl_die "the desktop app is built on macOS only"
rl_need git node npm cargo rustc python3 shasum hdiutil ditto codesign

NODE_V=$(node -p 'process.versions.node')
"$RL_PY" - "$NODE_V" <<'PY' || rl_die "Node 22.12 or newer is required (apps/desktop/package.json engines); found $NODE_V"
import sys
v = tuple(int(x) for x in sys.argv[1].split(".")[:3])
sys.exit(0 if v >= (22, 12, 0) else 1)
PY

DIRTY=0
if [[ -n "$(git status --porcelain -- .)" ]]; then
  if [[ $DEV -eq 0 ]]; then
    echo "release-app: REFUSED - the working tree under v2/ is dirty. Commit first, or pass --dev for a" >&2
    echo "             development build (never publish one)." >&2
    exit 1
  fi
  DIRTY=1
fi

WS_V=$(rl_cargo_version Cargo.toml workspace.package)
APP_V=$(rl_json_field "$SHELL_DIR/tauri.conf.json" version)
PKG_V=$(rl_json_field "$DESK/package.json" version)
SHELL_V=$(rl_cargo_version "$SHELL_DIR/Cargo.toml" package)
rl_valid_version "$APP_V" || rl_die "tauri.conf.json version '$APP_V' is not MAJOR.MINOR.PATCH[-prerelease]"
rl_info "versions: workspace=$WS_V  tauri.conf.json=$APP_V  package.json=$PKG_V  src-tauri/Cargo.toml=$SHELL_V"
if [[ "$WS_V" != "$APP_V" || "$PKG_V" != "$APP_V" || "$SHELL_V" != "$APP_V" ]]; then
  if [[ $SKEW -eq 0 ]]; then
    echo "release-app: REFUSED - the manifests disagree on the version (above). A release is one version:" >&2
    echo "             bump them together, or pass --allow-version-skew for a build you will not publish." >&2
    exit 1
  fi
  rl_warn "version skew allowed: the bundle is versioned by tauri.conf.json ($APP_V); do NOT publish this build"
fi

COMMIT=$(git rev-parse HEAD)
TARGET=$( cd "$SHELL_DIR" && rustc -vV | sed -n 's/^host: //p' )
[[ -n "$TARGET" ]] || rl_die "cannot read the host target from 'rustc -vV'"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export CARGO_INCREMENTAL=0

# Never let the environment turn this into a signed or notarised build, and never inherit a
# deployment target: the CLI-free steps below must see the linker's default (see the header).
# Every variable the Tauri bundler reads for signing or notarising carries the APPLE_ prefix, so they
# are dropped by prefix rather than by a list that would need to know their names.
unset MACOSX_DEPLOYMENT_TARGET
for _v in $(compgen -e); do
  case "$_v" in APPLE_*) unset "$_v" ;; esac
done
unset _v
# Same path hygiene as release.sh: no login name inside the shipped executable.
CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
for p in "$HOME" "$CARGO_HOME_DIR" "$V2"; do
  [[ "$p" == *[[:space:]]* ]] && rl_die "a path containing whitespace cannot be passed through RUSTFLAGS: $p"
done
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/build/home --remap-path-prefix=$CARGO_HOME_DIR=/build/cargo --remap-path-prefix=$V2=/build/v2"

# ---- build ---------------------------------------------------------------------------------------
if [[ $NPM_CI -eq 1 ]]; then
  rl_info "npm ci"
  ( cd "$DESK" && npm ci )
fi
[[ -d "$DESK/node_modules" ]] || rl_die "apps/desktop/node_modules is missing - run without --skip-npm-ci"

BEFORE_BUILD=$(rl_json_field "$SHELL_DIR/tauri.conf.json" build.beforeBuildCommand)
rl_info "frontend: $BEFORE_BUILD"
( cd "$DESK" && sh -c "$BEFORE_BUILD" )

rl_info "compiling the shell (cargo build --locked, toolchain pinned by src-tauri/rust-toolchain.toml)"
( cd "$SHELL_DIR" && cargo build --locked --bins --features tauri/custom-protocol --release )

rl_info "bundling (app + dmg), sealed ad-hoc"
rm -rf "$SHELL_DIR/target/release/bundle"
# CI=true: the DMG step's Finder AppleScript (window layout) is skipped - it would raise a
# "wants to control Finder" prompt on the build machine and needs a logged-in GUI.
( cd "$DESK" && CI=true APPLE_SIGNING_IDENTITY=- npm run tauri bundle -- --bundles app,dmg )

APP_SRC="$SHELL_DIR/target/release/bundle/macos/CredMgr.app"
DMG_SRC=$(find "$SHELL_DIR/target/release/bundle/dmg" -maxdepth 1 -name '*.dmg' | head -1)
[[ -d "$APP_SRC" ]] || rl_die "the bundler did not produce $APP_SRC"
[[ -f "$DMG_SRC" ]] || rl_die "the bundler did not produce a .dmg"

# ---- into dist/ ------------------------------------------------------------------------------------
NAME="credmgr-desktop-$APP_V-$TARGET"
mkdir -p "$DIST"
find "$DIST" -mindepth 1 -maxdepth 1 \( -name 'credmgr-desktop-*' -o -name 'CredMgr.app' \) -exec rm -rf {} +
ditto "$APP_SRC" "$DIST/CredMgr.app"
# --norsrc/--noextattr/--noqtn/--noacl: no AppleDouble members, no quarantine or provenance xattrs.
ditto -c -k --keepParent --norsrc --noextattr --noqtn --noacl "$APP_SRC" "$DIST/$NAME.app.zip"
cp "$DMG_SRC" "$DIST/$NAME.dmg"
rl_sums_write "$DIST"

rl_info "verifying dist/"
V=( --require-app )
[[ $SKEW -eq 1 ]] && V+=( --allow-version-skew )
# A --dev run accepts a dirty-stamped CLI build already in dist/; a release run must not.
[[ $DEV -eq 1 ]] && V+=( --allow-dev-build )
rl_verify "$DIST" "${V[@]}"

# ---- does it open? -------------------------------------------------------------------------------
APP_PID=""; LAUNCH_TMP=""
stop_app() {
  if [[ -n "$APP_PID" ]] && kill -0 "$APP_PID" 2>/dev/null; then
    kill "$APP_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do kill -0 "$APP_PID" 2>/dev/null || break; sleep 1; done
    kill -9 "$APP_PID" 2>/dev/null || true
  fi
  if [[ -n "$APP_PID" ]]; then wait "$APP_PID" 2>/dev/null || true; fi
  APP_PID=""
  if [[ -n "$LAUNCH_TMP" ]]; then rm -rf "$LAUNCH_TMP"; fi
  LAUNCH_TMP=""
  return 0
}
trap stop_app EXIT

# Counts on-screen top-level windows of a process that are at least 600x400 (the app opens 1280x820).
# Needs the Swift interpreter that ships with the command-line tools; without it the check falls
# back to "alive for 8 seconds" and says so.
count_windows() {   # <pid> -> prints a number, or 'unavailable'
  local src; src=$(mktemp "${TMPDIR:-/tmp}/cmwin.XXXXXX")
  cat > "$src" <<'SWIFT'
import CoreGraphics
import Foundation
let pid = Int(CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "0") ?? 0
guard let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] else { print("unavailable"); exit(0) }
var n = 0
for w in list where (w[kCGWindowOwnerPID as String] as? Int) == pid && (w[kCGWindowLayer as String] as? Int) == 0 {
    let b = w[kCGWindowBounds as String] as? [String: Any] ?? [:]
    if ((b["Width"] as? Double) ?? 0) >= 600 && ((b["Height"] as? Double) ?? 0) >= 400 { n += 1 }
}
print(n)
SWIFT
  swift "$src" "$1" 2>/dev/null || echo unavailable
  rm -f "$src"
}

launch_check() {   # <CredMgr.app>
  local app=$1 exe i n seen=0 alive=0 have_swift=1
  if [[ "$(launchctl managername 2>/dev/null)" != Aqua ]]; then
    rl_warn "launch check SKIPPED - there is no logged-in GUI session on this machine; run it on one before publishing"
    return 0
  fi
  exe="$app/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")"
  LAUNCH_TMP=$(mktemp -d /tmp/cmapp.XXXXXX)   # short: a Unix socket path must stay under ~104 bytes
  [[ "$(count_windows 1)" == unavailable ]] && have_swift=0
  rl_info "launching $(basename "$app") against a throwaway vault directory (no daemon, so it shows 'broker unreachable')"
  CREDMGR_VAULT_DIR="$LAUNCH_TMP/v" CREDMGR_STATE_DIR="$LAUNCH_TMP/s" "$exe" >"$LAUNCH_TMP/out.log" 2>&1 &
  APP_PID=$!
  for i in $(seq 1 25); do
    sleep 1
    if ! kill -0 "$APP_PID" 2>/dev/null; then
      local rc=0
      wait "$APP_PID" 2>/dev/null || rc=$?
      echo "  FAIL  the app exited by itself after ${i}s (exit $rc):" >&2
      sed 's/^/        /' "$LAUNCH_TMP/out.log" >&2
      stop_app; return 1
    fi
    if [[ $have_swift -eq 1 ]]; then
      n=$(count_windows "$APP_PID")
      if [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 && $i -ge 6 ]]; then seen=1; break; fi
    elif [[ $i -ge 8 ]]; then alive=1; break; fi
  done
  if [[ $seen -eq 1 ]]; then
    echo "  PASS  the app is running and has $n on-screen window(s) of at least 600x400 after ${i}s"
  elif [[ $alive -eq 1 ]]; then
    echo "  PASS  the app is running after ${i}s (window check unavailable: no Swift interpreter)"
  else
    echo "  FAIL  the app stayed up but opened no window of at least 600x400 within 25s" >&2
    stop_app; return 1
  fi
  if grep -qi 'panicked' "$LAUNCH_TMP/out.log" 2>/dev/null; then
    echo "  FAIL  the app logged a panic:" >&2; sed 's/^/        /' "$LAUNCH_TMP/out.log" >&2; stop_app; return 1
  fi
  stop_app
  echo "  PASS  and it stopped cleanly"
}

if [[ $LAUNCH -eq 1 ]]; then
  echo "== launch check"
  launch_check "$DIST/CredMgr.app" || rl_die "the built app does not open - do not publish it"
else
  rl_warn "launch check skipped by --no-launch-check - a bundle that was never opened is not a release"
fi

# ---- summary ---------------------------------------------------------------------------------------
echo
rl_info "done - UNSIGNED (ad-hoc sealed only), dirty=$DIRTY, commit ${COMMIT:0:12}"
( cd "$DIST" && for f in "$NAME.dmg" "$NAME.app.zip"; do printf '  %10d  %s\n' "$(wc -c < "$f")" "$f"; done; echo; cat SHA256SUMS )
cat <<'NOTE'

GATEKEEPER (K-5). This app is sealed ad-hoc, not signed with a Developer ID and not notarised. A copy
that arrives through a browser, AirDrop or a message carries a quarantine flag, and macOS will refuse to
open it ("is damaged", or "Apple could not verify it is free of malware"). Once you have checked it
against the published SHA256SUMS you can allow it:

    xattr -dr com.apple.quarantine /Applications/CredMgr.app

or try to open it once, then System Settings > Privacy & Security > "Open Anyway". The app is only a
front end: it needs credmgrd running (RELEASE.md, "Start the broker"), otherwise it says 'broker unreachable'.
NOTE
