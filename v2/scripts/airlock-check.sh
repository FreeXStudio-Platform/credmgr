#!/usr/bin/env bash
# Airlock check (17_AIRLOCK_AND_LLM.md §1, A-1 and A-2; ADR-156 quick win 9).
#
#   scripts/airlock-check.sh [path/to/credmgrd]     (default: target/debug/credmgrd, built if missing)
#
# A-2, "nothing listens on a network interface": starts the REAL credmgrd on a throwaway vault in a
# private temp directory, creates and unlocks a vault over its Unix socket, and fails if the process
# holds ANY internet socket (TCP, UDP or raw, v4 or v6) at two moments: just started, and after init,
# unlock and an entry written and read back. lsof when present (AIRLOCK_NO_LSOF=1 forces the other
# path); otherwise, on Linux, every socket fd of the process is matched against
# /proc/<pid>/net/{tcp,tcp6,udp,udp6,raw,raw6}. Before trusting either path, the script points it at
# a throwaway process that DOES listen on 127.0.0.1 and fails unless it is seen: a detector that
# sees nothing proves nothing.
#
# A-1, "no outbound network connection, ever": fails if the binary's symbols name a TCP/UDP socket
# type or an HTTP/TLS stack, or if it links a TLS or HTTP library dynamically (ldd / otool -L).
#
# Stdlib only (bash, python3, nm, and lsof or /proc). Exits 0 when every check holds.
set -euo pipefail

V2="$(cd "$(dirname "$0")/.." && pwd)"
DAEMON="${1:-$V2/target/debug/credmgrd}"
if [ ! -x "$DAEMON" ]; then
  (cd "$V2" && cargo build -p credmgr-brokerd --bin credmgrd --locked)
fi
DAEMON="$(cd "$(dirname "$DAEMON")" && pwd)/$(basename "$DAEMON")"

fail() { echo "airlock-check: FAIL: $*" >&2; exit 1; }
say() { echo "airlock-check: $*"; }

# ---- A-1: what the binary carries ------------------------------------------------------------
SYMBOLS_RE='TcpListener|TcpStream|UdpSocket|hyper::|reqwest|rustls|openssl|native_tls|ureq::|libcurl|tungstenite|h2::client|h2::server|SSL_connect|SSL_CTX_new'
if ! command -v nm >/dev/null; then fail "nm is not installed"; fi
if nm_out="$(nm -C "$DAEMON" 2>/dev/null || nm "$DAEMON" 2>/dev/null)"; then
  [ -n "$nm_out" ] || fail "nm read no symbols from $DAEMON (stripped?) - the scan would prove nothing"
  hits="$(printf '%s\n' "$nm_out" | grep -E "$SYMBOLS_RE" | head -5 || true)"
  [ -z "$hits" ] || fail "credmgrd links network or TLS code:
$hits"
else
  fail "nm could not read $DAEMON"
fi
LIBS_RE='libssl|libcrypto|libcurl|libgnutls|libnghttp|Network\.framework|CFNetwork'
if command -v ldd >/dev/null && [ "$(uname)" = "Linux" ]; then
  libs="$(ldd "$DAEMON" 2>/dev/null || true)"
elif command -v otool >/dev/null; then
  libs="$(otool -L "$DAEMON" 2>/dev/null || true)"
else
  libs=""
fi
bad_libs="$(printf '%s\n' "$libs" | grep -E "$LIBS_RE" || true)"
[ -z "$bad_libs" ] || fail "credmgrd links a network or TLS library dynamically:
$bad_libs"
say "A-1 binary scan: no socket types, HTTP or TLS code in $(basename "$DAEMON")"

# ---- A-2: what the running broker holds --------------------------------------------------------
BOX="$(mktemp -d "${TMPDIR:-/tmp}/airlock.XXXXXX")"
PID=""
cleanup() {
  if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$BOX"
}
trap cleanup EXIT
mkdir -p "$BOX/vault" "$BOX/state" "$BOX/home"
chmod 700 "$BOX"
SOCK="$BOX/vault/run/broker.sock"

env -i PATH="/usr/bin:/bin:/usr/sbin:/sbin" HOME="$BOX/home" \
  CREDMGR_VAULT_DIR="$BOX/vault" CREDMGR_STATE_DIR="$BOX/state" \
  "$DAEMON" </dev/null >"$BOX/daemon.log" 2>&1 &
PID=$!

for _ in $(seq 1 300); do
  [ -S "$SOCK" ] && break
  kill -0 "$PID" 2>/dev/null || { cat "$BOX/daemon.log" >&2; fail "credmgrd exited before serving its socket"; }
  sleep 0.1
done
[ -S "$SOCK" ] || fail "credmgrd did not create its socket within 30 s"

internet_sockets() {
  if [ "${AIRLOCK_NO_LSOF:-0}" != "1" ] && command -v lsof >/dev/null; then
    # -a: AND the selections; -i: every internet socket, any protocol, v4 and v6.
    lsof -nP -a -p "$PID" -i 2>/dev/null | tail -n +2 || true
    return
  fi
  if [ -d "/proc/$PID/fd" ]; then
    python3 - "$PID" <<'PY'
import os, sys
pid = sys.argv[1]
inodes = set()
for fd in os.listdir(f"/proc/{pid}/fd"):
    try:
        target = os.readlink(f"/proc/{pid}/fd/{fd}")
    except OSError:
        continue
    if target.startswith("socket:["):
        inodes.add(target[8:-1])
for table in ("tcp", "tcp6", "udp", "udp6", "raw", "raw6"):
    try:
        rows = open(f"/proc/{pid}/net/{table}").read().splitlines()[1:]
    except OSError:
        continue
    for row in rows:
        cols = row.split()
        if len(cols) > 9 and cols[9] in inodes:
            print(f"{table} {cols[1]} -> {cols[2]} inode {cols[9]}")
PY
    return
  fi
  fail "neither lsof nor /proc is available to list the broker's sockets"
}

# The detector must see a socket that is there, or its silence below means nothing.
REAL_PID="$PID"
python3 -c 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(1); time.sleep(30)' &
PROBE_PID=$!
for _ in $(seq 1 50); do
  PID="$PROBE_PID"; seen="$(internet_sockets)"; PID="$REAL_PID"
  [ -n "$seen" ] && break
  sleep 0.1
done
kill "$PROBE_PID" 2>/dev/null || true; wait "$PROBE_PID" 2>/dev/null || true
[ -n "$seen" ] || fail "the socket detector did not see a known 127.0.0.1 listener - it would prove nothing"
say "detector self-test: a known TCP listener is seen"

check_moment() {
  local found
  found="$(internet_sockets)"
  [ -z "$found" ] || fail "credmgrd holds an internet socket ($1):
$found"
  say "A-2 $1: no internet socket"
}

check_moment "just started"

# Drive the broker through init, unlock, a write and a read, over its Unix socket (stdlib only).
python3 - "$SOCK" <<'PY'
import json, secrets, socket, sys
path = sys.argv[1]
token = None
def call(op, params=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(120)
    s.connect(path)
    s.sendall((json.dumps({"id": "1", "op": op, "token": token, "params": params or {}}) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    answer = json.loads(buf)
    if not answer.get("ok"):
        raise SystemExit(f"airlock-check: {op} refused: {answer.get('error')}")
    return answer.get("value") or {}
pw = "airlock-" + secrets.token_hex(12)
begun = call("vault.init_begin", {"passphrase": pw})
code = begun.get("recoveryCode")
call("vault.init_confirm", {"recoveryCode": code})
token = call("vault.unlock", {"passphrase": pw}).get("token")
value = "airlock-" + secrets.token_hex(8)
created = call("entry.create", {"node": "global", "name": "AIRLOCK_PROBE", "value": value})
read = call("entry.reveal", {"node": "global", "entry": created.get("entry")})
if read.get("value") != value:
    raise SystemExit("airlock-check: the probe value did not read back")
PY
check_moment "initialised, unlocked, an entry written and read back"

say "PASS (A-1 and A-2 hold for $(basename "$DAEMON"))"
