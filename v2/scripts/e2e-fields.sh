#!/usr/bin/env bash
# CredMgr V2 — the multi-field journey (ADR-078). Runs the REAL `credmgrd` and `credmgr` against a
# throwaway vault and checks the path a user takes with an entry that holds several fields:
#
#   1. a bulk paste becomes ONE entry with four fields (labels and order kept)
#   2. read one field, list the labels (never a value), add / move / remove a field
#   3. undo the removal, restart the daemon, everything is still there
#   4. a locked bulk write lands in the tray; accepting it keeps all four fields
#   4c. seal the project holding those entries (ADR-079), restart, restore it: every envelope comes back
#      byte-identical, every field reads back, and the orphan copies were field documents all along
#   5. LEGACY: a vault written by 2.0.0-alpha.6 opens unchanged with these binaries, every value
#      reads back, `verify` is clean, and the first field edit upgrades one entry without losing it
#
#   scripts/e2e-fields.sh                     uses target/debug (run `cargo build --workspace` first)
#   BIN=target/release scripts/e2e-fields.sh
#   LEGACY_BIN_DIR=/path/to/alpha6/bin scripts/e2e-fields.sh
#   STAGES="beta"   scripts/e2e-fields.sh     run only the multi-field segments (default: "beta legacy")
#   STAGES="legacy" scripts/e2e-fields.sh     run only the alpha.6 compatibility segment
#
# The legacy segment needs the alpha.6 `credmgr` + `credmgrd` binaries. It looks in $LEGACY_BIN_DIR, then
# in dist/credmgr-2.0.0-alpha.6-*/bin under this tree. If it finds neither it says so and counts as a
# FAILURE — a compatibility claim nobody ran is not a pass. (Local only: dist/ is gitignored.)
#
# Why this exists (BUILD_LOG Session 27): 406 green tests hid that the shipped daemon could not open a
# vault it had created. Run this before calling a field-model release real. Needs the macOS/Linux
# Unix-socket sandbox off. Every passphrase and value is a generated fixture, never a real secret.
# Exits non-zero if any expectation failed.
set -u
V2="$(cd "$(dirname "$0")/.." && pwd)"
BIN=${BIN:-$V2/target/debug}
case "$BIN" in /*) ;; *) BIN="$V2/$BIN" ;; esac
STAGES=${STAGES:-"beta legacy"}
E=$(mktemp -d /tmp/cmfld.XXXXXX)   # short: a Unix socket path must stay under ~104 bytes
PW="fixture-pass-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export CREDMGR_VAULT_DIR=$E/v CREDMGR_STATE_DIR=$E/s HOME=$E/h
mkdir -p "$E/v" "$E/s" "$E/h" "$E/work/fld/src"
unset CREDMGR_TOKEN
FAIL=0
ok()   { echo "  PASS  $*"; }
bad()  { echo "  FAIL  $*"; FAIL=1; }
expect() { local what=$1; shift; if eval "$@"; then ok "$what"; else bad "$what"; fi; }
rand() { head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

DPID=""
CUR_BIN="$BIN"   # the binaries the running daemon and the CLI calls below belong to
start() { "$CUR_BIN/credmgrd" >"$E/$1.log" 2>&1 & DPID=$!; sleep 2; }
stop()  { [ -n "$DPID" ] && kill "$DPID" 2>/dev/null; [ -n "$DPID" ] && wait "$DPID" 2>/dev/null; DPID=""; }
login() { local out; out=$(echo "$PW" | "$CUR_BIN/credmgr" unlock 2>&1); TOKEN=$(echo "$out" | sed -n 's/^export CREDMGR_TOKEN=//p'); LAST_UNLOCK=$out; }
cm()    { CREDMGR_TOKEN=$TOKEN "$CUR_BIN/credmgr" "$@"; }
trap 'stop; rm -rf "$E"' EXIT

# init a vault with whichever binaries CUR_BIN names; leaves the daemon running and RC set.
init_vault() {
  start "$1"
  coproc INIT { "$CUR_BIN/credmgr" init 2>&1; }
  exec {INIT_OUT}<&"${INIT[0]}" {INIT_IN}>&"${INIT[1]}"
  echo "$PW" >&"$INIT_IN"; RC=""
  while IFS= read -r line <&"$INIT_OUT"; do
    case "$line" in RECOVERY_CODE=*) RC=${line#RECOVERY_CODE=}; echo "$RC" >&"$INIT_IN";; esac
  done
  exec {INIT_OUT}<&- {INIT_IN}>&-
}

# Four fields with generated values. Labels are free text — these are just four a person might type.
V_HOST="db-$(rand).fields.test"
V_USER="svc_$(rand)"
V_PASS="pw-$(rand)"
V_NOTE="note $(rand) with spaces"
bulk_text() { printf 'host: %s\nusername: %s\npassword: %s\nnotes: %s\n' "$V_HOST" "$V_USER" "$V_PASS" "$V_NOTE"; }

case " $STAGES " in *" beta "*)
echo "== versions"; "$BIN/credmgr" --version; "$BIN/credmgrd" --version

echo "== 1. one bulk paste is one entry with four fields"
CUR_BIN="$BIN"
init_vault d1
expect "init printed a root recovery code" '[ ${#RC} -gt 20 ]'
login; expect "unlock with the init passphrase" '[ -n "$TOKEN" ]'
cm node create fld --parent global --label Fields --workdir "$E/work/fld" >/dev/null 2>&1
expect "node create" '[ $? -eq 0 ]'
OUT=$(bulk_text | cm set PROD_DB --node fld --bulk 2>&1); RC1=$?
expect "set --bulk creates one entry" '[ $RC1 -eq 0 ]'
expect "set --bulk never prints a value" '! echo "$OUT" | grep -qF -e "$V_PASS" -e "$V_HOST" -e "$V_USER"'
OUT=$(cm list --node fld 2>&1)
expect "the node lists exactly one entry, PROD_DB" '[ "$(echo "$OUT" | grep -c PROD_DB)" = 1 ]'

echo "== 2. read one field; list the labels without values; add, move, remove"
OUT=$(cm field ls PROD_DB --node fld --json 2>&1)
expect "field ls --json shows the four labels in order" '[ "$(echo "$OUT" | python3 -c "import sys,json; print(\",\".join(f[\"label\"] for f in json.load(sys.stdin)[\"fields\"]))")" = "host,username,password,notes" ]'
expect "field ls never carries a value" '! echo "$OUT" | grep -qF -e "$V_PASS" -e "$V_HOST" -e "$V_USER" -e "$V_NOTE"'
expect "get --field password prints exactly the pasted password" '[ "$(cm get PROD_DB --node fld --field password 2>&1)" = "$V_PASS" ]'
OUT=$(cm get PROD_DB --node fld 2>&1); RC1=$?
expect "get with no selector on a four-field entry is refused, listing the labels" '[ $RC1 -ne 0 ] && echo "$OUT" | grep -q "4 fields" && echo "$OUT" | grep -q password'
expect "the refusal never prints a value" '! echo "$OUT" | grep -qF -e "$V_PASS" -e "$V_HOST"'
V_EXTRA="extra-$(rand)"
printf '%s' "$V_EXTRA" | cm field add PROD_DB --node fld --label region >/dev/null 2>&1
expect "field add appends a fifth field" '[ "$(cm get PROD_DB --node fld --field region 2>&1)" = "$V_EXTRA" ]'
cm field mv PROD_DB --node fld --field region --to 0 >/dev/null 2>&1
expect "field mv puts it first" '[ "$(cm field ls PROD_DB --node fld --json 2>&1 | python3 -c "import sys,json; print(json.load(sys.stdin)[\"fields\"][0][\"label\"])")" = region ]'
OUT=$(cm field rm PROD_DB --node fld --field username 2>&1); RC1=$?
expect "field rm removes one field" '[ $RC1 -eq 0 ] && ! cm get PROD_DB --node fld --field username >/dev/null 2>&1'
UNDO_ID=$(echo "$OUT" | grep -oE 'a_[0-9a-f]+' | head -1)
expect "field rm prints the audit id to undo it with" '[ -n "$UNDO_ID" ]'

echo "== 3. undo the removal, restart, nothing lost"
OUT=$(cm undo "$UNDO_ID" --node fld 2>&1); RC1=$?
expect "undo of the field removal succeeds" '[ $RC1 -eq 0 ]'
expect "the removed field is back with its value" '[ "$(cm get PROD_DB --node fld --field username 2>&1)" = "$V_USER" ]'
stop; start d2
login; expect "unlock after restart" '[ -n "$TOKEN" ]'
ALL=$(cm get PROD_DB --node fld --all 2>&1)
expect "after the restart every value is still there (--all)" 'for v in "$V_HOST" "$V_USER" "$V_PASS" "$V_EXTRA"; do echo "$ALL" | grep -qF -- "$v" || exit 1; done'
expect "verify is clean after every field operation" 'cm verify 2>&1 | grep -q "ok: true"'

echo "== 4. a locked bulk write lands in the tray; accepting keeps all four fields"
cm lock >/dev/null 2>&1
OUT=$(cd "$E/work/fld/src" && bulk_text | "$CUR_BIN/credmgr" set TRAY_DB --node fld --bulk 2>&1)
expect "a locked bulk write goes to the tray" 'echo "$OUT" | grep -q "credmgr pending"'
stop; start d2b; login
OUT=$(cm pending 2>&1)
expect "after a restart the tray still holds it" 'echo "$OUT" | grep -q TRAY_DB'
expect "the tray shows four fields and no value" 'echo "$OUT" | grep TRAY_DB | grep -q "4" && ! echo "$OUT" | grep -qF -e "$V_PASS" -e "$V_HOST"'
ENTRY=$(echo "$OUT" | grep TRAY_DB | awk '{print $2}')
cm pending accept "$ENTRY" --node fld >/dev/null 2>&1
expect "accepted, the password reads back" '[ "$(cm get TRAY_DB --node fld --field password 2>&1)" = "$V_PASS" ]'
expect "accepted, it still has four fields" '[ "$(cm field ls TRAY_DB --node fld --json 2>&1 | python3 -c "import sys,json; print(len(json.load(sys.stdin)[\"fields\"]))")" = 4 ]'

echo "== 4b. no label and no value in clear anywhere under the vault directory"
N=$(grep -rl --exclude=broker.sock -e "$V_PASS" -e "$V_HOST" -e "$V_USER" -e "$V_NOTE" -e "$V_EXTRA" "$E/v" 2>/dev/null | wc -l | tr -d ' ')
expect "no value appears in clear in any file (found in $N)" '[ "$N" = 0 ]'
# Labels are encrypted with the value (ADR-078): none of these is allowed in the manifest or the audit log.
# The node registry legitimately holds a `"label"` key - a NODE's display name ("Fields" above) - so that one
# key is searched everywhere except registry.json*; the field labels themselves are searched everywhere.
FILES=$({ grep -rlE --exclude=broker.sock '"username"|"password"|"notes"|"region"' "$E/v"
          grep -rlE --exclude=broker.sock --exclude='registry.json*' '"label"' "$E/v"; } 2>/dev/null | sort -u | sed "s|^$E/v/||")
N=$(echo -n "$FILES" | grep -c . || true)
[ "$N" != 0 ] && echo "$FILES" | sed 's/^/        in: /'
expect "no field document key or label appears in clear under the vault directory (found in $N)" '[ "$N" = 0 ]'

echo "== 4c. seal the project that holds multi-field entries, restart, restore (ADR-079 x ADR-078)"
ENVDIR="$E/v/nodes/fld/entries"
SUMS_BEFORE=$(cd "$ENVDIR" && shasum -a 256 -- *.env | sort)
ALL_BEFORE=$(cm get PROD_DB --node fld --all 2>&1)
LS_BEFORE=$(cm field ls PROD_DB --node fld --json 2>&1)
TRAY_ALL_BEFORE=$(cm get TRAY_DB --node fld --all 2>&1)
TRAY_LS_BEFORE=$(cm field ls TRAY_DB --node fld --json 2>&1)
expect "the project holds two multi-field entries before the seal" '[ "$(ls "$ENVDIR" | wc -l | tr -d " ")" = 2 ]'
OUT=$(cm node seal fld 2>&1)
expect "node seal works on a project holding multi-field entries" 'echo "$OUT" | grep -q "\"sealed\":true"'
expect "the sealed project left the graph" '! cm node ls 2>&1 | grep -qx fld'
expect "its fields are not readable through the product" '! cm get PROD_DB --node fld --field password >/dev/null 2>&1 && ! cm get TRAY_DB --node fld --all >/dev/null 2>&1'
# The orphan copies are re-encrypted, never re-written: a field document stays a field document (envelope
# version byte 2) - the version-1-only reseal that used to be here would have refused these two outright.
expect "the orphan holds two copies, both field documents (version 2)" '[ "$(ls "$E/v/nodes/orphan/entries" | wc -l | tr -d " ")" = 2 ] && for f in "$E"/v/nodes/orphan/entries/*.env; do [ "$(od -An -tu1 -j4 -N1 "$f" | tr -d " ")" = 2 ] || exit 1; done'
expect "verify is clean while the project is sealed (the orphan digests are true)" 'cm verify 2>&1 | grep -q "ok: true"'
N=$(grep -rl --exclude=broker.sock -e "$V_PASS" -e "$V_HOST" -e "$V_USER" -e "$V_NOTE" -e "$V_EXTRA" "$E/v" 2>/dev/null | wc -l | tr -d ' ')
expect "no value appears in clear anywhere under the vault while sealed (found in $N)" '[ "$N" = 0 ]'
stop; start d2c; login
expect "the seal survived a restart" '! cm node ls 2>&1 | grep -qx fld'
OUT=$(cm node restore fld 2>&1)
expect "node restore brings it back" 'echo "$OUT" | grep -q "\"restored\":true"'
expect "restored, every envelope file is byte-identical to the one that was sealed" '[ "$(cd "$ENVDIR" && shasum -a 256 -- *.env | sort)" = "$SUMS_BEFORE" ]'
expect "restored, every field of the bulk-pasted entry reads back (--all)" '[ "$(cm get PROD_DB --node fld --all 2>&1)" = "$ALL_BEFORE" ]'
expect "restored, its field list (ids, labels, order) is identical" '[ "$(cm field ls PROD_DB --node fld --json 2>&1)" = "$LS_BEFORE" ]'
expect "restored, the tray-accepted entry is whole too" '[ "$(cm get TRAY_DB --node fld --all 2>&1)" = "$TRAY_ALL_BEFORE" ] && [ "$(cm field ls TRAY_DB --node fld --json 2>&1)" = "$TRAY_LS_BEFORE" ]'
expect "restored, the password still reads back from its field" '[ "$(cm get PROD_DB --node fld --field password 2>&1)" = "$V_PASS" ]'
expect "verify is clean after the restore" 'cm verify 2>&1 | grep -q "ok: true"'
stop; start d2d; login
expect "restored, then restarted: the fields are still there" '[ "$(cm get PROD_DB --node fld --all 2>&1)" = "$ALL_BEFORE" ] && [ "$(cd "$ENVDIR" && shasum -a 256 -- *.env | sort)" = "$SUMS_BEFORE" ]'
expect "restored, then restarted: verify is still clean" 'cm verify 2>&1 | grep -q "ok: true"'
stop
;; esac

case " $STAGES " in *" legacy "*)
echo "== 5. LEGACY: a vault written by 2.0.0-alpha.6 opens unchanged"
LEGACY_BIN=${LEGACY_BIN_DIR:-}
if [ -z "$LEGACY_BIN" ]; then
  for d in "$V2"/dist/credmgr-2.0.0-alpha.6-*/bin; do [ -x "$d/credmgrd" ] && LEGACY_BIN=$d; done
fi
if [ -z "$LEGACY_BIN" ]; then
  # A linked worktree has no dist/ of its own (it is gitignored, so it is never checked out): look in the
  # main checkout, found through git. Read-only - nothing is copied or run from anywhere but there.
  MAIN_ROOT=$(cd "$(git -C "$V2" rev-parse --git-common-dir 2>/dev/null)/.." 2>/dev/null && pwd)
  if [ -n "$MAIN_ROOT" ]; then
    for d in "$MAIN_ROOT"/v2/dist/credmgr-2.0.0-alpha.6-*/bin; do [ -x "$d/credmgrd" ] && LEGACY_BIN=$d; done
  fi
fi
if [ -z "$LEGACY_BIN" ] || [ ! -x "$LEGACY_BIN/credmgrd" ] || [ ! -x "$LEGACY_BIN/credmgr" ]; then
  bad "the alpha.6 binaries were not found - set LEGACY_BIN_DIR (the compatibility claim is not proven without them)"
else
  # a fresh vault, written entirely by alpha.6
  rm -rf "$E/v" "$E/s"; mkdir -p "$E/v" "$E/s"
  CUR_BIN="$LEGACY_BIN"
  expect "the legacy binaries are alpha.6" '"$LEGACY_BIN/credmgr" --version 2>&1 | grep -q "alpha.6"'
  init_vault l1
  login; expect "alpha.6 unlock" '[ -n "$TOKEN" ]'
  cm node create old --parent global --label Old >/dev/null 2>&1
  L_PW="legacy-$(rand)"; L_TOTP="JBSWY3DPEHPK3PXP"; L_TEXT="a plain note $(rand)"
  printf '%s' "$L_PW" | cm set OLD_PASS --node old >/dev/null 2>&1
  printf '%s' "$L_TOTP" | cm set OLD_TOTP --node old >/dev/null 2>&1
  printf '%s' "$L_TEXT" | cm set OLD_TEXT --node old >/dev/null 2>&1
  expect "alpha.6 reads its own value back" '[ "$(cm get OLD_PASS --node old 2>&1)" = "$L_PW" ]'
  stop

  # the same vault, opened by THIS build
  CUR_BIN="$BIN"
  start l2
  login; expect "this build unlocks a vault alpha.6 created" '[ -n "$TOKEN" ]'
  expect "a password reads back unchanged" '[ "$(cm get OLD_PASS --node old 2>&1)" = "$L_PW" ]'
  # ADR-094: a reveal never returns a stored seed; the entry is still there, typed as a seed, and `get` does not print it
  expect "a TOTP seed is kept and typed, and get never prints it" 'cm field ls OLD_TOTP --node old 2>&1 | grep -q "totp-seed" && ! cm get OLD_TOTP --node old 2>&1 | grep -qF -- "$L_TOTP"'
  expect "a text value reads back unchanged" '[ "$(cm get OLD_TEXT --node old 2>&1)" = "$L_TEXT" ]'
  expect "verify is clean on the alpha.6 vault" 'cm verify 2>&1 | grep -q "ok: true"'
  OUT=$(cm field ls OLD_PASS --node old --json 2>&1)
  expect "a legacy entry is one field with no label" '[ "$(echo "$OUT" | python3 -c "import sys,json; f=json.load(sys.stdin)[\"fields\"]; print(len(f), repr(f[0][\"label\"]))")" = "1 '"''"'" ]'
  L_MORE="more-$(rand)"
  printf '%s' "$L_MORE" | cm field add OLD_PASS --node old --label backup >/dev/null 2>&1
  expect "the first field edit upgrades the entry, adding a second field" '[ "$(cm get OLD_PASS --node old --field backup 2>&1)" = "$L_MORE" ]'
  expect "and the original value is untouched" 'cm get OLD_PASS --node old --all 2>&1 | grep -qF -- "$L_PW"'
  expect "an entry that was not edited still reads back unchanged" '[ "$(cm get OLD_TEXT --node old 2>&1)" = "$L_TEXT" ]'
  stop; start l3; login
  expect "after a restart the upgraded entry is intact" 'cm get OLD_PASS --node old --all 2>&1 | grep -qF -e "$L_PW" && cm get OLD_PASS --node old --all 2>&1 | grep -qF -e "$L_MORE"'
  expect "after a restart the untouched legacy entries are intact" 'cm field ls OLD_TOTP --node old 2>&1 | grep -q "totp-seed" && [ "$(cm get OLD_TEXT --node old 2>&1)" = "$L_TEXT" ]'
  expect "verify is still clean" 'cm verify 2>&1 | grep -q "ok: true"'
  stop
fi
;; esac

echo; [ $FAIL -eq 0 ] && echo "E2E-FIELDS: ALL PASSED" || echo "E2E-FIELDS: FAILURES ABOVE"
exit $FAIL
