#!/usr/bin/env bash
# CredMgr V2 — the real-binary journey. Runs the REAL `credmgrd` and `credmgr` against a throwaway
# vault and checks the path a user takes: init → unlock → projects and workdirs → restart → a locked
# write that survives a restart → seal, restart, restore (ADR-079) → two-factor → the last door → a
# second daemon → no plaintext on disk.
#
#   scripts/e2e-journey.sh            uses target/debug (run `cargo build --workspace` first)
#   BIN=target/release scripts/e2e-journey.sh
#
# Why this exists (BUILD_LOG Session 27): 406 green tests hid that the shipped daemon could not open
# a vault it had created — every test built its own keyed state. Run this before calling a release
# real. Needs the macOS/Linux Unix-socket sandbox off. Test passphrase and values are generated
# fixtures, never real secrets. Exits non-zero on the first failed expectation's run.
set -u
V2="$(cd "$(dirname "$0")/.." && pwd)"
BIN=${BIN:-$V2/target/debug}
case "$BIN" in /*) ;; *) BIN="$V2/$BIN" ;; esac
E=$(mktemp -d /tmp/cme2e.XXXXXX)   # short: a Unix socket path must stay under ~104 bytes
PW='correct horse battery staple'
mkdir -p "$E/v" "$E/s" "$E/h" "$E/work/acme/src"
export CREDMGR_VAULT_DIR=$E/v CREDMGR_STATE_DIR=$E/s HOME=$E/h
unset CREDMGR_TOKEN
FAIL=0
ok()   { echo "  PASS  $*"; }
bad()  { echo "  FAIL  $*"; FAIL=1; }
expect() { local what=$1; shift; if eval "$@"; then ok "$what"; else bad "$what"; fi; }
start() { "$BIN/credmgrd" >"$E/$1.log" 2>&1 & DPID=$!; sleep 2; }
stop()  { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
login() { local out; out=$(echo "$PW" | "$BIN/credmgr" unlock 2>&1); TOKEN=$(echo "$out" | sed -n 's/^export CREDMGR_TOKEN=//p'); LAST_UNLOCK=$out; }
totp()  { python3 - "$1" "${2:-0}" <<'PY'
import sys,base64,hmac,hashlib,struct,time,urllib.parse
uri=sys.argv[1]; off=int(sys.argv[2])
secret=urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)['secret'][0]
key=base64.b32decode(secret+'='*(-len(secret)%8))
c=int(time.time()//30)+off
h=hmac.new(key,struct.pack('>Q',c),hashlib.sha1).digest()
o=h[-1]&15; print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000))
PY
}
trap 'stop; rm -rf "$E"' EXIT

echo "== versions"
"$BIN/credmgr" --version; "$BIN/credmgrd" --version

echo "== 1. init + unlock on the same daemon"
start d1
coproc INIT { "$BIN/credmgr" init 2>&1; }
exec {INIT_OUT}<&"${INIT[0]}" {INIT_IN}>&"${INIT[1]}"
echo "$PW" >&"$INIT_IN"; RC=""
while IFS= read -r line <&"$INIT_OUT"; do
  case "$line" in RECOVERY_CODE=*) RC=${line#RECOVERY_CODE=}; echo "$RC" >&"$INIT_IN";; esac
done
exec {INIT_OUT}<&- {INIT_IN}>&-
expect "init printed a root recovery code" '[ ${#RC} -gt 20 ]'
login; expect "unlock with the init passphrase" '[ -n "$TOKEN" ]'
expect "unlock prints the owner-token warning" 'echo "$LAST_UNLOCK" | grep -q "keep it out of any shell an AI agent runs in"'

echo "== 2. a project bound to a directory; a global secret and a project secret"
CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node create acme --parent global --label Acme --workdir "$E/work/acme" >/dev/null 2>&1
expect "node create with --workdir" '[ $? -eq 0 ]'
printf 'global-value' | CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" set SHARED --node global >/dev/null 2>&1
printf 'acme-deploy-value' | CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" set DEPLOY --node acme >/dev/null 2>&1
expect "the owner reads the project secret" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get DEPLOY --node acme 2>&1)" = "acme-deploy-value" ]'
AGENT_WHO=$(cd "$E/work/acme/src" && "$BIN/credmgr" whoami 2>&1 | head -1)
expect "a tokenless process inside the workdir is scoped to acme ($AGENT_WHO)" 'echo "$AGENT_WHO" | grep -q "acme"'
stop

echo "== 3. restart: everything survives"
start d2
expect "status reports locked after restart" '"$BIN/credmgr" status 2>&1 | grep -q "locked: true"'
expect "a passphrase-less unlock is refused" '! "$BIN/credmgr" unlock </dev/null >/dev/null 2>&1'
login; expect "unlock after restart" '[ -n "$TOKEN" ]'
expect "project secret survived the restart" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get DEPLOY --node acme 2>&1)" = "acme-deploy-value" ]'
expect "global secret survived the restart" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get SHARED --node global 2>&1)" = "global-value" ]'

echo "== 3b. an agent writes while locked; the write survives a restart and is accepted (ADR-069)"
CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" lock >/dev/null 2>&1
OUT=$(cd "$E/work/acme/src" && printf 'agent-value' | "$BIN/credmgr" set AGENT_KEY --node acme 2>&1)
expect "a locked write from inside the workdir goes to the tray" 'echo "$OUT" | grep -q "credmgr pending"'
stop; start d2b
login
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" pending 2>&1)
expect "after a restart the tray still holds it" 'echo "$OUT" | grep -q AGENT_KEY'
ENTRY=$(echo "$OUT" | grep AGENT_KEY | awk '{print $2}')
CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" pending accept "$ENTRY" --node acme >/dev/null 2>&1
expect "accepted, it reads back" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get AGENT_KEY --node acme 2>&1)" = "agent-value" ]'
expect "verify is clean — every envelope matches its digest (ADR-067)" 'CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" verify 2>&1 | grep -q "ok: true"'

echo "== 3c. import, rename, policy and notes through the CLI (ADR-071, ADR-072, ADR-073)"
printf '%s\n' '# journey env' 'export IMP_ONE=imp-one-value' 'IMP_TWO="imp two value"' 'IMP_EMPTY=' >"$E/import.env"
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" import "$E/import.env" --node acme 2>&1)
expect "import creates the entries and says so" 'echo "$OUT" | grep -q "imported 2 of 2 entries into acme"'
expect "import never prints a value" '! echo "$OUT" | grep -qE "imp-one-value|imp two value"'
expect "an imported value reads back" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get IMP_TWO --node acme 2>&1)" = "imp two value" ]'
expect "importing the same names again is refused" '! CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" import "$E/import.env" --node acme >/dev/null 2>&1'
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node rename acme "Acme Inc" 2>&1)
expect "node rename changes the label" 'echo "$OUT" | grep -q "label is now .Acme Inc."'
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node policy acme --reason "journey" --private-names 2>&1)
expect "node policy applies a patch; nothing is left un-enforced (ADR-083, ADR-085)" 'echo "$OUT" | grep -q "policy updated on acme" && ! echo "$OUT" | grep -q "not enforced yet"'
# ADR-083: with privateNames on, a process inside the workdir is not the owner - it sees a count, never a name.
OUT=$(cd "$E/work/acme/src" && "$BIN/credmgr" get DEPLOY --node acme 2>&1)
expect "privateNames: an agent inside the workdir cannot find an entry by name" 'echo "$OUT" | grep -q "no entry named"'
expect "privateNames: and the owner still can" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get DEPLOY --node acme 2>&1)" = "acme-deploy-value" ]'
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node policy acme --reason "journey" --descendant-read 2>&1)
expect "widening reach is refused for want of presence" 'echo "$OUT" | grep -q presence_required'
printf '# acme notes\nrunbook line\n' | CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" notes set acme >/dev/null 2>&1
expect "a note round-trips" 'CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" notes show acme 2>&1 | grep -q "runbook line"'
# A failed upstream pipe hands `notes set` an empty stdin. It must refuse, not delete.
OUT=$(printf '' | CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" notes set acme 2>&1); RC3=$?
expect "notes set with empty input is refused, naming notes clear" '[ $RC3 -ne 0 ] && echo "$OUT" | grep -q "notes clear acme"'
expect "the refused empty set left the note intact" 'CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" notes show acme 2>&1 | grep -q "runbook line"'
# A flag where the reason belongs would be recorded as the reason and dropped from the patch.
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node policy acme --no-private-names --reason --descendant-read 2>&1); RC3=$?
expect "a --reason with no text is refused rather than swallowing the next option" '[ $RC3 -ne 0 ] && echo "$OUT" | grep -q "needs its text"'
# A forgotten closing quote must not fold the next assignment into the value.
printf '%s\n' 'FIRST_OK=first-ok' 'UNCLOSED="never-closed' 'AFTER=after"' >"$E/unbalanced.env"
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" import "$E/unbalanced.env" --node acme 2>&1); RC3=$?
expect "an unbalanced quote is refused with line numbers" '[ $RC3 -ne 0 ] && echo "$OUT" | grep -q "line 2" && echo "$OUT" | grep -q "line 3"'
expect "the refused file created nothing" '! CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get FIRST_OK --node acme >/dev/null 2>&1'

echo "== 3d. seal a project, restart, restore it (ADR-079, K-7: sealing now works in a vault init made)"
CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node create beta --parent global --label Beta >/dev/null 2>&1
printf 'beta-sealed-value' | CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" set SEALME --node beta >/dev/null 2>&1
expect "the project secret reads back before the seal" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get SEALME --node beta 2>&1)" = "beta-sealed-value" ]'
BETA_ENV=$(ls "$E/v/nodes/beta/entries/" 2>/dev/null | head -1)
BETA_SUM=$(shasum -a 256 "$E/v/nodes/beta/entries/$BETA_ENV" 2>/dev/null | awk '{print $1}')
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node seal beta 2>&1)
expect "node seal works in a vault credmgr init made" 'echo "$OUT" | grep -q "\"sealed\":true"'
expect "the sealed project left the graph" '! CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node ls 2>&1 | grep -qx beta'
expect "its value is not readable through the product" '! CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get SEALME --node beta >/dev/null 2>&1'
expect "the orphan cold key exists, owner-only" '[ -f "$E/v/keys/cold/orphan.key" ] && [ "$(stat -f %Lp "$E/v/keys/cold/orphan.key" 2>/dev/null || stat -c %a "$E/v/keys/cold/orphan.key")" = 600 ]'
expect "no orphan private key was written under keys/nodes" '[ ! -e "$E/v/keys/nodes/orphan.key" ]'
expect "the sealed node's files moved into the archive" '[ ! -e "$E/v/nodes/beta" ] && [ -f "$E/v/archive/beta/node.key" ]'
stop; start d2c
login
expect "the seal survived a daemon restart" '! CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node ls 2>&1 | grep -qx beta'
expect "verify is clean while a node is sealed" 'CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" verify 2>&1 | grep -q "ok: true"'
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node restore beta 2>&1)
expect "node restore brings it back after the restart" 'echo "$OUT" | grep -q "\"restored\":true"'
expect "the restored value reads back byte-identical" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get SEALME --node beta 2>&1)" = "beta-sealed-value" ]'
expect "the restored envelope file is byte-identical to the one that was sealed" '[ "$(shasum -a 256 "$E/v/nodes/beta/entries/$BETA_ENV" | awk "{print \$1}")" = "$BETA_SUM" ]'
expect "verify is clean after the restore" 'CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" verify 2>&1 | grep -q "ok: true"'
expect "a second restore finds nothing sealed" '! CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node restore beta >/dev/null 2>&1'
stop; start d2d
login
expect "restored, then restarted again: still there" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get SEALME --node beta 2>&1)" = "beta-sealed-value" ]'
expect "and the archive is gone" '[ ! -e "$E/v/archive/beta" ]'

echo "== 4. two-factor: enrol, lock, unlock needs the code"
coproc ENR { CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" gate enroll 2>&1; }
# Copy the pipe ends at once: bash unsets the coproc array the moment the process exits.
exec {ENR_OUT}<&"${ENR[0]}" {ENR_IN}>&"${ENR[1]}"
URI=""; GCODES=0
while IFS= read -r line <&"$ENR_OUT"; do
  echo "$line" >>"$E/enroll.log"
  case "$line" in
    OTPAUTH_URI=*) URI=${line#OTPAUTH_URI=}; totp "$URI" >&"$ENR_IN";;
    GATE_RECOVERY_CODE=*) GCODES=$((GCODES+1));;
  esac
done
exec {ENR_OUT}<&- {ENR_IN}>&-
[ $GCODES -eq 10 ] || { echo "  gate enroll said:"; sed 's/^/    /' "$E/enroll.log" 2>/dev/null; }
expect "gate enroll issued 10 recovery codes" '[ $GCODES -eq 10 ]'
CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" lock >/dev/null 2>&1
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get DEPLOY --node acme 2>&1)
expect "the login locked away is refused as session_expired (ADR-068)" 'echo "$OUT" | grep -q session_expired'
OUT=$(echo "$PW" | "$BIN/credmgr" unlock 2>&1)
expect "unlock now answers two_factor_required" 'echo "$OUT" | grep -q two_factor_required'
sleep 31   # the enrolment consumed this TOTP step; use the next one
OUT=$("$BIN/credmgr" gate verify "$(totp "$URI")" 2>&1); TOKEN=$(echo "$OUT" | sed -n 's/^export CREDMGR_TOKEN=//p')
expect "gate verify completes the login" '[ -n "$TOKEN" ]'
stop

echo "== 5. restart: the gate is still in force; the last door resets it"
start d3
OUT=$(echo "$PW" | "$BIN/credmgr" unlock 2>&1)
expect "after restart the gate still gates" 'echo "$OUT" | grep -q two_factor_required'
OUT=$(printf '%s\n%s\n' "$PW" "0000-0000" | "$BIN/credmgr" gate recover 2>&1)
expect "gate recover with a wrong root code is refused" 'echo "$OUT" | grep -q wrong_passphrase'
OUT=$(printf '%s\n%s\n' "$PW" "$RC" | "$BIN/credmgr" gate recover 2>&1)
expect "gate recover with passphrase + root recovery code resets the gate" 'echo "$OUT" | grep -q "gate reset"'
login; expect "the passphrase alone unlocks after the reset" '[ -n "$TOKEN" ]'
expect "an imported value survived the restarts (ADR-063 write-through)" '[ "$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" get IMP_ONE --node acme 2>&1)" = "imp-one-value" ]'
expect "the sealed note survived the restarts" 'CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" notes show acme 2>&1 | grep -q "runbook line"'
echo "== 5b. generate, and an agent's waiting request decided with the passphrase while the vault stays locked (ADR-087, ADR-088)"
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" node policy acme --reason "journey: names visible again" --no-private-names 2>&1)
expect "names are made visible to agents again for this stage" 'echo "$OUT" | grep -q "policy updated on acme"'
GEN=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" generate 2>/dev/null)
expect "generate prints a 20-character password" '[ ${#GEN} -eq 20 ]'
GEN2=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" generate --length 32 --no-symbols 2>/dev/null)
expect "generate honours --length and --no-symbols" '[ ${#GEN2} -eq 32 ] && ! echo "$GEN2" | grep -q "[^A-Za-z0-9]"'
CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" lock >/dev/null 2>&1
OUT=$(cd "$E/work/acme/src" && "$BIN/credmgr" get DEPLOY --node acme 2>&1)
expect "a reveal on the wholly locked vault waits for a person (approval_pending)" 'echo "$OUT" | grep -q approval_pending'
REQ=$(echo "$OUT" | sed -n 's/.*request: \(rq_[0-9a-f]*\).*/\1/p' | head -1)
expect "the waiting request has an id to decide" '[ ${#REQ} -eq 35 ]'
OUT=$(echo "not the passphrase" | "$BIN/credmgr" approve "$REQ" 2>&1)
expect "approve with the wrong passphrase decides nothing" 'echo "$OUT" | grep -q wrong_passphrase'
OUT=$(echo "$PW" | "$BIN/credmgr" approve "$REQ" 2>&1)
expect "approve with the passphrase releases that one request" 'echo "$OUT" | grep -q "approved request"'
expect "the vault is still locked afterwards" '"$BIN/credmgr" status 2>&1 | grep -q "locked: true"'
OUT=$(cd "$E/work/acme/src" && "$BIN/credmgr" get DEPLOY --node acme 2>&1)
expect "the agent reads exactly the approved value" '[ "$OUT" = "acme-deploy-value" ]'
OUT=$(cd "$E/work/acme/src" && "$BIN/credmgr" get DEPLOY --node acme 2>&1)
expect "and asking again is a new request, not a second release" 'echo "$OUT" | grep -q approval_pending'
login; expect "the owner logs in again" '[ -n "$TOKEN" ]'
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" notes clear acme 2>&1)
expect "notes clear is the one way to delete it" 'echo "$OUT" | grep -q "cleared the note on acme"'
expect "after the clear there is no note" '! CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" notes show acme 2>/dev/null | grep -q .'
OUT=$(CREDMGR_TOKEN=$TOKEN "$BIN/credmgr" notes clear acme 2>&1)
expect "clearing again says there is nothing to clear" 'echo "$OUT" | grep -q "nothing to clear"'
stop

echo "== 6. a second daemon refuses a live socket"
start d4
"$BIN/credmgrd" >"$E/d5.log" 2>&1; RC2=$?
expect "second credmgrd exits non-zero" '[ $RC2 -ne 0 ]'
expect "and says why" 'grep -q "another credmgrd is already serving" "$E/d5.log"'
stop

echo "== 7. no plaintext value anywhere under the vault directory"
N=$(grep -rl --exclude=broker.sock -e 'acme-deploy-value' -e 'global-value' -e 'agent-value' -e 'imp-one-value' -e 'imp two value' -e 'runbook line' -e 'beta-sealed-value' "$E/v" 2>/dev/null | wc -l | tr -d ' ')
expect "plaintext appears in 0 files (found $N)" '[ "$N" = 0 ]'
# ADR-077: a session token is a bearer secret. It used to be written, as the audit record's actor, into
# the plaintext audit log. Shape-based, so it covers every login this journey made, not just the last.
N=$(grep -rlE --exclude=broker.sock 'cmt_[0-9a-fA-F]{8,}' "$E/v" 2>/dev/null | wc -l | tr -d ' ')
expect "no session token (cmt_...) is written anywhere under the vault directory (found in $N files)" '[ "$N" = 0 ]'

echo; [ $FAIL -eq 0 ] && echo "E2E: ALL PASSED" || echo "E2E: FAILURES ABOVE"
exit $FAIL
