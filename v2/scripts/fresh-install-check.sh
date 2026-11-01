#!/usr/bin/env bash
# CredMgr V2 - does a FRESH INSTALL of the release tarball actually work?
#
#   scripts/fresh-install-check.sh                   check v2/dist, including the full journey (a few minutes)
#   scripts/fresh-install-check.sh --quick           skip the full journey; keep the smoke test
#   scripts/fresh-install-check.sh --dist DIR        check another dist/
#   scripts/fresh-install-check.sh --allow-dev-build accept a "dirty" version stamp (a --dev build)
#
# It behaves like a person who downloaded two files and nothing else:
#   1. copies ONLY the tarball and SHA256SUMS into an empty "download" folder and runs the documented
#      `shasum -a 256 -c --ignore-missing SHA256SUMS` there, and requires the tarball's own line to say OK
#      (--ignore-missing passes silently when nothing matched, which is why the OK line is demanded);
#   2. unpacks it into a throwaway prefix, re-checks the tarball's own manifest, runs the documented
#      quarantine-clearing step against the real files, and checks that the binaries link only against
#      system libraries;
#   3. runs `credmgr --version` and `credmgrd --version` in a stripped environment (no cargo, no
#      Homebrew, no checkout on PATH) and requires the stamp to name the tarball's version;
#   4. starts the unpacked `credmgrd` on a throwaway vault, runs `credmgr init`, `unlock`, `set`, `get`,
#      `lock` and checks the locked login is refused;
#   5. runs scripts/e2e-journey.sh against the UNPACKED binaries (init, restart, locked write, two-factor,
#      second daemon, no plaintext on disk).
#
# It never touches a real vault: every step sets CREDMGR_VAULT_DIR, CREDMGR_STATE_DIR and HOME to
# directories under one temp prefix (`credmgrd` started without them would use ~/Library/Application
# Support/credmgr), and the passphrase is generated for the run and never printed. Needs the Unix-socket
# sandbox off. Builds nothing and publishes nothing.
set -uo pipefail

RL_NAME=fresh-install
V2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-lib.sh
. "$V2/scripts/release-lib.sh"

DIST="$V2/dist"; QUICK=0; ALLOW_DEV=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist) DIST="${2:?--dist needs a directory}"; shift ;;
    --quick) QUICK=1 ;;
    --allow-dev-build) ALLOW_DEV=1 ;;
    -h|--help) sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    *) rl_die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done
rl_need python3 shasum tar
DIST=$(cd "$DIST" 2>/dev/null && pwd) || rl_die "no such directory: $DIST"

FAIL=0
ok()  { echo "  PASS  $*"; }
bad() { echo "  FAIL  $*"; FAIL=1; }
expect() { local what=$1; shift; if eval "$@"; then ok "$what"; else bad "$what"; fi; }

# Short prefix: a Unix socket path must stay under ~104 bytes.
P=$(mktemp -d /tmp/cmfi.XXXXXX)
DPID=""
cleanup() {
  if [[ -n "$DPID" ]]; then kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; fi
  rm -rf "$P"
}
trap cleanup EXIT

TARBALL=$(find "$DIST" -maxdepth 1 -name 'credmgr-*-*.tar.gz' | head -1)
[[ -n "$TARBALL" && -f "$DIST/SHA256SUMS" ]] || rl_die "need a credmgr-<version>-<target>.tar.gz and SHA256SUMS in $DIST (run scripts/release.sh)"
TB=$(basename "$TARBALL"); TOP=${TB%.tar.gz}

echo "== 1. a download folder holding only the tarball and SHA256SUMS"
mkdir -p "$P/download"
cp "$TARBALL" "$DIST/SHA256SUMS" "$P/download/"
( cd "$P/download" && shasum -a 256 -c --ignore-missing SHA256SUMS > "$P/sums.out" 2>&1 ); RC=$?
expect "the documented checksum command exits 0" '[ $RC -eq 0 ]'
expect "and says OK for the tarball itself (not silently for nothing)" 'grep -qxF "$TB: OK" "$P/sums.out"'
( cd "$P/download" && printf 'x' >> "$TB" && shasum -a 256 -c --ignore-missing SHA256SUMS > /dev/null 2>&1 ); RC=$?
expect "a tarball with one byte added is refused by the same command" '[ $RC -ne 0 ]'
cp "$TARBALL" "$P/download/$TB"

echo "== 2. unpack into a throwaway prefix"
mkdir -p "$P/prefix"
tar -xzf "$P/download/$TB" -C "$P/prefix"; RC=$?
expect "tar -xzf succeeds" '[ $RC -eq 0 ]'
R="$P/prefix/$TOP"
expect "the tarball unpacks to $TOP/" '[ -d "$R/bin" ]'
( cd "$R" && shasum -a 256 -c SHA256SUMS > "$P/inner.out" 2>&1 ); RC=$?
expect "the tarball's own manifest passes ($(grep -c ': OK$' "$P/inner.out") files)" '[ $RC -eq 0 ]'
# RELEASE.md step 2: unsigned downloads arrive quarantined and the doc says to clear it. Set the flag the
# way a browser does, run the documented command, require it gone and the binaries still intact. The
# binaries are NOT run while the flag is set: Gatekeeper would raise a dialog on the desktop.
if [[ "$(uname -s)" == Darwin ]]; then
  for b in credmgr credmgrd; do xattr -w com.apple.quarantine "0083;5f000000;Safari;00000000-0000-0000-0000-000000000000" "$R/bin/$b"; done
  for b in credmgr credmgrd; do xattr -d com.apple.quarantine "$R/bin/$b" 2>/dev/null || true; done
  # (No `| grep -q` anywhere in this file: under pipefail, grep exiting at its first match can SIGPIPE
  # the producer and turn a true match into a failed pipeline. Capture first, then match.)
  XA=$(xattr "$R/bin/credmgr" "$R/bin/credmgrd" 2>&1)
  expect "the documented 'xattr -d com.apple.quarantine' clears it" '[[ "$XA" != *quarantine* ]]'
  ( cd "$R" && shasum -a 256 -c SHA256SUMS > /dev/null 2>&1 ); RC=$?
  expect "and the binaries are byte-for-byte unchanged by it" '[ $RC -eq 0 ]'
  LIBS=$(for b in credmgr credmgrd; do otool -L "$R/bin/$b" | tail -n +2 | awk '{print $1}'; done | sort -u)
  expect "both link only system libraries ($(echo "$LIBS" | wc -l | tr -d ' ') distinct)" \
    '! grep -qvE "^(/usr/lib/|/System/)" <<<"$LIBS"'
  for b in credmgr credmgrd; do
    SIG=$(codesign -dv "$R/bin/$b" 2>&1)
    expect "bin/$b is code-signed at least ad-hoc (required for arm64 to run it)" '[[ "$SIG" == *"Signature=adhoc"* ]]'
  done
fi
mkdir -p "$P/bin"; cp "$R/bin/credmgr" "$R/bin/credmgrd" "$P/bin/"   # RELEASE.md: cp bin/credmgr bin/credmgrd /usr/local/bin/

echo "== 3. --version, in a stripped environment"
mkdir -p "$P/v" "$P/s" "$P/h"
CLEAN=( env -i PATH=/usr/bin:/bin HOME="$P/h" CREDMGR_VAULT_DIR="$P/v" CREDMGR_STATE_DIR="$P/s" )
WANT_VER=${TOP#credmgr-}; WANT_VER=${WANT_VER%%-aarch64-*}; WANT_VER=${WANT_VER%%-x86_64-*}
for b in credmgr credmgrd; do
  LINE=$("${CLEAN[@]}" "$P/bin/$b" --version 2>&1)
  expect "$b --version: $LINE" 'grep -Eq "^$b [0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)? \(commit [0-9a-f]{12}(, dirty)?, " <<<"$LINE"'
  expect "$b names version $WANT_VER, the tarball's" '[[ "$LINE" == "$b $WANT_VER "* ]]'
  if [[ "$LINE" == *", dirty"* ]]; then
    if [[ $ALLOW_DEV -eq 1 ]]; then echo "  NOTE  $b is a dirty-tree development build"; else bad "$b is a dirty-tree development build (pass --allow-dev-build to accept one)"; fi
  fi
done

echo "== 4. init, unlock, set, get, lock - a throwaway vault, the unpacked binaries"
PW="fresh-$("$RL_PY" -c 'import secrets; print(secrets.token_hex(12))')"
"${CLEAN[@]}" "$P/bin/credmgrd" > "$P/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 50); do [[ -S "$P/v/run/broker.sock" ]] && break; sleep 0.2; done
expect "the unpacked credmgrd came up and is serving a socket under the throwaway vault" '[ -S "$P/v/run/broker.sock" ] && kill -0 "$DPID" 2>/dev/null'
if [[ -S "$P/v/run/broker.sock" ]]; then
  # init reads the passphrase, prints a one-time recovery code and needs it typed back: drive both ends.
  INIT_OUT=$("$RL_PY" - "$P/bin/credmgr" "$PW" "$P" <<'PY'
import os, subprocess, sys
exe, pw, prefix = sys.argv[1:4]
env = {"PATH": "/usr/bin:/bin", "HOME": prefix + "/h", "CREDMGR_VAULT_DIR": prefix + "/v", "CREDMGR_STATE_DIR": prefix + "/s"}
p = subprocess.Popen([exe, "init"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
p.stdin.write(pw + "\n"); p.stdin.flush()
code_seen = False
for line in p.stdout:
    if line.startswith("RECOVERY_CODE="):
        code_seen = True
        p.stdin.write(line.split("=", 1)[1].strip() + "\n"); p.stdin.flush()
p.stdin.close()
rc = p.wait()
print("CODE_SEEN=%s" % ("yes" if code_seen else "no")); print("RC=%d" % rc)
PY
  )
  expect "credmgr init printed a recovery code and accepted its retyping" 'grep -q "CODE_SEEN=yes" <<<"$INIT_OUT" && grep -q "RC=0" <<<"$INIT_OUT"'
  OUT=$(echo "$PW" | "${CLEAN[@]}" "$P/bin/credmgr" unlock 2>&1)
  TOKEN=$(echo "$OUT" | sed -n 's/^export CREDMGR_TOKEN=//p')
  expect "credmgr unlock with the init passphrase returns a login" '[ -n "$TOKEN" ]'
  printf 'fresh-install-value' | "${CLEAN[@]}" CREDMGR_TOKEN="$TOKEN" "$P/bin/credmgr" set FRESH_CHECK --node global > /dev/null 2>&1
  expect "credmgr set stores a value" '[ $? -eq 0 ]'
  GOT=$("${CLEAN[@]}" CREDMGR_TOKEN="$TOKEN" "$P/bin/credmgr" get FRESH_CHECK --node global 2>&1)
  expect "credmgr get reads it back" '[ "$GOT" = "fresh-install-value" ]'
  "${CLEAN[@]}" CREDMGR_TOKEN="$TOKEN" "$P/bin/credmgr" lock > /dev/null 2>&1
  OUT=$("${CLEAN[@]}" CREDMGR_TOKEN="$TOKEN" "$P/bin/credmgr" get FRESH_CHECK --node global 2>&1); RC=$?
  expect "after lock the same login is refused (session_expired)" '[ $RC -ne 0 ] && grep -q session_expired <<<"$OUT"'
  N=$(grep -rl --exclude=broker.sock -e 'fresh-install-value' -e "$PW" "$P/v" "$P/s" 2>/dev/null | wc -l | tr -d ' ')
  expect "neither the value nor the passphrase appears in any file under the vault (found in $N)" '[ "$N" = 0 ]'
else
  echo "  daemon log:"; sed 's/^/    /' "$P/daemon.log"
fi
kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; DPID=""

if [[ $QUICK -eq 1 ]]; then
  echo "== 5. the full journey: SKIPPED by --quick (a release is not checked until it has run)"
else
  echo "== 5. the full real-binary journey against the unpacked binaries"
  JBASH=bash
  if (( ${BASH_VERSINFO[0]} < 4 )); then
    for cand in /opt/homebrew/bin/bash /usr/local/bin/bash; do [[ -x "$cand" ]] && { JBASH=$cand; break; }; done
    "$JBASH" -c '(( BASH_VERSINFO[0] >= 4 ))' || { bad "e2e-journey.sh needs bash 4+ (coproc); this machine's bash is $BASH_VERSION and no newer one was found"; JBASH=""; }
  fi
  if [[ -n "$JBASH" ]]; then
    BIN="$R/bin" "$JBASH" "$V2/scripts/e2e-journey.sh" > "$P/journey.out" 2>&1; RC=$?
    grep -E "PASS|FAIL|E2E|^==" "$P/journey.out" | sed 's/^/    journey: /'
    expect "e2e-journey.sh: every check passed against the unpacked binaries (exit $RC)" '[ $RC -eq 0 ] && grep -q "E2E: ALL PASSED" "$P/journey.out"'
  fi
fi

echo
if [[ $FAIL -eq 0 ]]; then echo "FRESH INSTALL: ALL PASSED  ($TB)"; else echo "FRESH INSTALL: FAILURES ABOVE"; fi
exit $FAIL
