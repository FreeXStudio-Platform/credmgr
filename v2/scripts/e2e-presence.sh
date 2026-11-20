#!/usr/bin/env bash
# CredMgr V2 — the real-binary presence journey (ADR-098). Runs the REAL `credmgrd` and `credmgr` against a
# throwaway vault and the real Secure Enclave through the unattended TEST helper
# (`native/macos/presence/build.sh --test-noauth`): enrol this Mac, run the presence-gated ops from the CLI
# (which asks for the proof itself), turn on Touch ID unlock, lock, unlock with it, restart, unlock again.
#
#   scripts/e2e-presence.sh            uses target/debug (run `cargo build --workspace` first)
#
# macOS only (skips elsewhere). Test passphrase and values are generated fixtures. Needs the Unix-socket
# sandbox off.
set -u
V2="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(uname)" = Darwin ] || { echo "skipped: macOS only"; exit 0; }
BIN=${BIN:-$V2/target/debug}
case "$BIN" in /*) ;; *) BIN="$V2/$BIN" ;; esac
"$V2/native/macos/presence/build.sh" --test-noauth "$V2/target/native" >/dev/null || { echo "could not build the test helper"; exit 1; }
HELPER="$V2/target/native/credmgr-presence-test"
E=$(mktemp -d /tmp/cmpre.XXXXXX)
PW='correct horse battery staple'
mkdir -p "$E/v" "$E/s" "$E/h"
export CREDMGR_VAULT_DIR=$E/v CREDMGR_STATE_DIR=$E/s HOME=$E/h CREDMGR_PRESENCE_HELPER=$HELPER
unset CREDMGR_TOKEN
FAIL=0
ok()   { echo "  PASS  $*"; }
bad()  { echo "  FAIL  $*"; FAIL=1; }
expect() { local what=$1; shift; if eval "$@"; then ok "$what"; else bad "$what"; fi; }
start() { "$BIN/credmgrd" >"$E/$1.log" 2>&1 & DPID=$!; sleep 2; }
stop()  { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
login() { local out; out=$(echo "$PW" | "$BIN/credmgr" unlock 2>&1); TOKEN=$(echo "$out" | sed -n 's/^export CREDMGR_TOKEN=//p'); }
touch_login() { local out; out=$("$BIN/credmgr" unlock --touch-id 2>&1); TOKEN=$(echo "$out" | sed -n 's/^export CREDMGR_TOKEN=//p'); LAST=$out; }
trap 'stop; rm -rf "$E"' EXIT
cm() { CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" "$@"; }

echo "== 1. init, unlock, two projects"
start d1
coproc INIT { "$BIN/credmgr" init 2>&1; }
exec {INIT_OUT}<&"${INIT[0]}" {INIT_IN}>&"${INIT[1]}"
echo "$PW" >&"$INIT_IN"
while IFS= read -r line <&"$INIT_OUT"; do
  case "$line" in RECOVERY_CODE=*) echo "${line#RECOVERY_CODE=}" >&"$INIT_IN";; esac
done
exec {INIT_OUT}<&- {INIT_IN}>&-
login; expect "unlock with the passphrase" '[ -n "$TOKEN" ]'
cm node create acme --parent global --label Acme >/dev/null 2>&1
cm node create globex --parent global --label Globex >/dev/null 2>&1

echo "== 2. before enrolment the gated ops refuse, and say what to do"
OUT=$(cm grant acme --to globex --scope read --reason "shared staging server" 2>&1)
expect "grant without a presence key names the fix" 'echo "$OUT" | grep -q "presence enrol"'
expect "presence status shows the Secure Enclave" 'cm presence status 2>&1 | grep -q "secure enclave: true"'

echo "== 3. enrol this Mac; the CLI proves presence by itself"
expect "presence enrol" 'cm presence enrol --label "e2e Mac" 2>&1 | grep -q "enrolled presence key"'
expect "grant create succeeds with a proof" 'cm grant acme --to globex --scope read --reason "shared staging server" >/dev/null 2>&1'
expect "the grant is listed" 'cm grant ls 2>&1 | grep -q "shared staging server"'
expect "node reparent succeeds with a proof" 'cm node reparent acme --to globex --reason "acme belongs to globex" 2>&1 | grep -q "depth 2"'
OUT=$(cd "$E" && "$BIN/credmgr" grant acme --to globex --scope reveal --reason "an agent tries this" 2>&1)
expect "a process with no login cannot create a grant" '! echo "$OUT" | grep -q "^g_"'

echo "== 4. Touch ID unlock"
expect "touch-id enable" 'cm touch-id enable 2>&1 | grep -q "Touch ID unlock is on"'
cm lock >/dev/null 2>&1
touch_login; expect "unlock --touch-id opens the vault" '[ -n "$TOKEN" ]'
expect "the Touch ID session can read the graph" 'cm node ls >/dev/null 2>&1'
stop; start d2
touch_login; expect "unlock --touch-id after a daemon restart" '[ -n "$TOKEN" ]'
expect "the enrolment survived the restart" 'cm presence status 2>&1 | grep -q "e2e Mac"'
cm touch-id disable >/dev/null 2>&1; cm lock >/dev/null 2>&1
touch_login; expect "after disable, --touch-id is refused" '[ -z "$TOKEN" ] && echo "$LAST" | grep -q "presence_failed"'
login; expect "the passphrase still unlocks" '[ -n "$TOKEN" ]'

echo
[ "$FAIL" = 0 ] && echo "ALL PASSED" || echo "FAILED"
exit $FAIL
