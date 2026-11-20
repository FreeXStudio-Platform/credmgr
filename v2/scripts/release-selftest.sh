#!/usr/bin/env bash
# CredMgr V2 - proves the release verifier (scripts/release.sh --verify) can FAIL.
#
#   scripts/release-selftest.sh [DIST]     DIST defaults to v2/dist and must hold a release.sh build
#   scripts/release-selftest.sh --mas      only the Mac App Store inspection cases (ADR-162); needs no dist/ and
#                                          no Mac: it assembles a stand-in MAS bundle from the real packaging/mas/
#                                          files and breaks it one way at a time (they also run after a full run)
#
# A green verifier proves only what it checks, and a check that has never been seen to fail is a
# check nobody knows works. This takes a copy of a real dist/ and breaks it one way at a time -
# a flipped byte, a stray file, a login name in a tar header, a home path in a binary or an SBOM,
# a dangling dependency edge, mixed versions, a tarball that escapes its directory - and requires
# the verifier to refuse each one and to say WHY (it matches the failure text, not just the exit
# code). The first case is the control: the unbroken copy must pass.
#
# Builds nothing, touches nothing outside a temp directory, needs no network.
set -uo pipefail

RL_NAME=release-selftest
V2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-lib.sh
. "$V2/scripts/release-lib.sh"

# ---- ADR-162: the Mac App Store inspection (rl_mas_inspect) must refuse each of these ------------------------
# The stand-in bundle is built from the REAL templates, rendered by the real renderer, with the real agent plist
# and privacy manifest and the real Info.plist step - so the control case also proves those files agree with
# the inspection. Only the executables are stand-ins: bytes with the markers a real MAS build carries.
mas_cases() {
  local SCR MG=0 MB=0 M="" MAS_FAKE_HOME="/Use""rs/someone"
  SCR=$(mktemp -d "${TMPDIR:-/tmp}/rmas.XXXXXX")
  mas_fresh() {
    M=$(mktemp -d "$SCR/m.XXXXXX")
    rl_mas_render_all "$V2" "$M/cfg" 9.9.9 >/dev/null || return 1
    cp -R "$M/cfg/entitlements" "$M/entitlements" && cp "$M/cfg/identity.conf" "$M/identity.conf" && rm -rf "$M/cfg" || return 1
    local C="$M/CredMgr.app/Contents"
    mkdir -p "$C/MacOS" "$C/Resources" "$C/Library/LaunchAgents" || return 1
    python3 - "$C/Info.plist" "$(rl_mas_identity "$M/identity.conf" MAS_BUNDLE_ID)" <<'PY2' || return 1
import plistlib, sys
plistlib.dump({"CFBundleIdentifier": sys.argv[2], "CFBundleExecutable": "CredMgr", "CFBundleShortVersionString": "9.9.9",
               "LSMinimumSystemVersion": "13.1"}, open(sys.argv[1], "wb"))
PY2
    local n
    for n in CredMgr credmgrd credmgr; do
      printf 'stand-in\0MAS_APP_GROUP_NAME=credmgr\0credmgr-build-stamp:v1:commit=%s:dirty=0\0' "0123456789abcdef0123456789abcdef01234567" > "$C/MacOS/$n"
    done
    printf 'stand-in\0credmgr-presence-variant:production\0' > "$C/MacOS/credmgr-presence"
    chmod +x "$C/MacOS/"*
    cp "$V2/packaging/mas/LaunchAgents/com.credmgr.brokerd.plist" "$C/Library/LaunchAgents/" || return 1
    cp "$V2/packaging/mas/PrivacyInfo.xcprivacy" "$C/Resources/" || return 1
    rl_mas_assemble "$M/CredMgr.app"
  }
  plset() {   # <plist> <python statement on d>
    python3 - "$1" "$2" <<'PY2'
import plistlib, sys
p = sys.argv[1]; d = plistlib.load(open(p, "rb")); exec(sys.argv[2]); plistlib.dump(d, open(p, "wb"))
PY2
  }
  mas_case() {   # <name> <expected text or ''> <fn> [inspect args]
    local name=$1 expect=$2 fn=$3 out rc; shift 3
    mas_fresh || { echo "  ERROR  $name: could not build the stand-in bundle"; MB=$((MB+1)); return; }
    "$fn" || { echo "  ERROR  $name: could not break the stand-in bundle"; MB=$((MB+1)); return; }
    out=$(rl_mas_inspect "$M" "$@" 2>&1); rc=$?
    if grep -qF 'Traceback (most recent call last)' <<<"$out"; then
      echo "  FAIL  $name: the inspection CRASHED"; grep -A6 Traceback <<<"$out" | head -8; MB=$((MB+1))
    elif [[ -z "$expect" ]]; then
      if [[ $rc -eq 0 ]]; then echo "  PASS  $name (accepted, as it must be)"; MG=$((MG+1))
      else echo "  FAIL  $name: the inspection rejected a good bundle"; grep FAIL <<<"$out" | head -5; MB=$((MB+1)); fi
    elif [[ $rc -ne 0 ]] && grep -qF -- "$expect" <<<"$out"; then
      echo "  PASS  $name (refused: ...${expect}...)"; MG=$((MG+1))
    else
      echo "  FAIL  $name: expected a refusal mentioning '$expect' (exit $rc)"; grep FAIL <<<"$out" | head -5; MB=$((MB+1))
    fi
  }
  m_control()        { :; }
  m_no_agent()       { rm -f "$M/CredMgr.app/Contents/Library/LaunchAgents/com.credmgr.brokerd.plist"; }
  m_agent_abs()      { plset "$M/CredMgr.app/Contents/Library/LaunchAgents/com.credmgr.brokerd.plist" 'd["BundleProgram"] = "/usr/local/bin/credmgrd"'; }
  m_agent_user()     { plset "$M/CredMgr.app/Contents/Library/LaunchAgents/com.credmgr.brokerd.plist" 'd["UserName"] = "root"'; }
  m_broker_net()     { plset "$M/entitlements/credmgrd.entitlements" 'd["com.apple.security.network.client"] = True'; }
  m_presence_extra() { plset "$M/entitlements/credmgr-presence.entitlements" 'd["com.apple.security.application-groups"] = ["X.y"]'; }
  m_app_unsandboxed(){ plset "$M/entitlements/app.entitlements" 'd["com.apple.security.app-sandbox"] = False'; }
  m_wrong_group()    { plset "$M/entitlements/credmgr.entitlements" 'd["com.apple.security.application-groups"] = ["ZZZZZZZZZZ.other"]'; }
  m_unrendered()     { cp "$V2/packaging/mas/entitlements/credmgrd.entitlements" "$M/entitlements/credmgrd.entitlements"; }
  m_pm_tracking()    { plset "$M/CredMgr.app/Contents/Resources/PrivacyInfo.xcprivacy" 'd["NSPrivacyTracking"] = True'; }
  m_pm_collected()   { plset "$M/CredMgr.app/Contents/Resources/PrivacyInfo.xcprivacy" 'd["NSPrivacyCollectedDataTypes"] = [{"NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeEmailAddress"}]'; }
  m_pm_reason()      { plset "$M/CredMgr.app/Contents/Resources/PrivacyInfo.xcprivacy" 'd["NSPrivacyAccessedAPITypes"].append({"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults", "NSPrivacyAccessedAPITypeReasons": ["XXXX.1"]})'; }
  m_no_pm()          { rm -f "$M/CredMgr.app/Contents/Resources/PrivacyInfo.xcprivacy"; }
  m_no_export()      { plset "$M/CredMgr.app/Contents/Info.plist" 'del d["ITSAppUsesNonExemptEncryption"]'; }
  m_export_false()   { plset "$M/CredMgr.app/Contents/Info.plist" 'd["ITSAppUsesNonExemptEncryption"] = False'; }
  m_bundle_id()      { plset "$M/CredMgr.app/Contents/Info.plist" 'd["CFBundleIdentifier"] = "com.example.other"'; }
  m_updater()        { plset "$M/CredMgr.app/Contents/Info.plist" 'd["SUFeedURL"] = "x"'; }
  m_old_macos()      { plset "$M/CredMgr.app/Contents/Info.plist" 'd["LSMinimumSystemVersion"] = "12.0"'; }
  m_direct_broker()  { printf 'stand-in\0credmgr-build-stamp:v1:commit=0123456789abcdef0123456789abcdef01234567:dirty=0\0' > "$M/CredMgr.app/Contents/MacOS/credmgrd"; }
  m_cli_leak()       { printf '%s/.cargo/registry/src/x/y.rs\0' "$MAS_FAKE_HOME" >> "$M/CredMgr.app/Contents/MacOS/credmgr"; }
  m_dirty()          { python3 - "$M/CredMgr.app/Contents/MacOS/credmgrd" <<'PY2'
import sys
p = sys.argv[1]; b = open(p, "rb").read(); open(p, "wb").write(b.replace(b":dirty=0", b":dirty=1"))
PY2
  }
  m_stray_exe()      { printf 'x' > "$M/CredMgr.app/Contents/MacOS/helper"; chmod +x "$M/CredMgr.app/Contents/MacOS/helper"; }
  m_long_group()     { python3 - "$M/identity.conf" <<'PY2'
import sys
p = sys.argv[1]; s = open(p).read().replace("MAS_APP_GROUP_NAME=credmgr", "MAS_APP_GROUP_NAME=" + "credential-manager-shared-group-container-long"); open(p, "w").write(s)
PY2
  }
  m_dmg()            { : > "$M/credmgr-desktop-9.9.9.dmg"; }
  echo "== ADR-162: the Mac App Store inspection must refuse each of these (stand-in bundle, any host)"
  mas_case mas-control            ""                                                   m_control
  mas_case mas-control-version    ""                                                   m_control --expect-version 9.9.9
  mas_case mas-wrong-version      "expected 0.0.1"                                     m_control --expect-version 0.0.1
  if [[ "$(rl_mas_identity "$V2/packaging/mas/identity.conf" MAS_IDS_FINAL)" == yes ]]; then
    mas_case mas-strict-no-profile "embedded.provisionprofile"                       m_control --strict
  else
    mas_case mas-strict-placeholder "PLACEHOLDERS"                                     m_control --strict
  fi
  mas_case mas-no-agent           "LaunchAgents/com.credmgr.brokerd.plist is missing"  m_no_agent
  mas_case mas-agent-outside      "not the bundled broker"                             m_agent_abs
  mas_case mas-agent-root         "the agent plist carries"                            m_agent_user
  mas_case mas-broker-network     "carries a network entitlement"                      m_broker_net
  mas_case mas-presence-extra-key "expected exactly"                                   m_presence_extra
  mas_case mas-app-unsandboxed    "does not set app-sandbox to true"                   m_app_unsandboxed
  mas_case mas-wrong-group        "names app groups"                                   m_wrong_group
  mas_case mas-unrendered         "still holds an @TOKEN@"                             m_unrendered
  mas_case mas-privacy-tracking   "declares tracking"                                  m_pm_tracking
  mas_case mas-privacy-collected  "declares collected data types"                      m_pm_collected
  mas_case mas-privacy-reason     "is not a category and reason Apple defines"         m_pm_reason
  mas_case mas-no-privacy         "PrivacyInfo.xcprivacy is missing"                   m_no_pm
  mas_case mas-no-export-answer   "ITSAppUsesNonExemptEncryption"                      m_no_export
  mas_case mas-export-exempt-claim "ITSAppUsesNonExemptEncryption to true"             m_export_false
  mas_case mas-bundle-id          "the bundle identifier is"                           m_bundle_id
  mas_case mas-updater            "updater keys"                                       m_updater
  mas_case mas-old-macos          "where SMAppService does not exist"                  m_old_macos
  mas_case mas-direct-broker      "was not built with the mas feature"                 m_direct_broker
  mas_case mas-cli-path-leak      "embeds a build-machine path"                        m_cli_leak
  mas_case mas-dirty-build        "is a development build"                             m_dirty
  mas_case mas-dirty-allowed      ""                                                   m_dirty --allow-dev-build
  mas_case mas-stray-exe          "Contents/MacOS holds"                               m_stray_exe
  mas_case mas-socket-too-long    "makes the socket path"                              m_long_group
  mas_case mas-dmg                "a .dmg is in the MAS dist"                          m_dmg
  # The renderer refuses a token it does not know rather than shipping it literally.
  printf '<string>@MAS_NOPE@</string>\n' > "$SCR/bad.tpl"
  if out=$(rl_mas_render "$SCR/bad.tpl" "$SCR/bad.out" "$V2/packaging/mas/identity.conf" 9.9.9 2>&1); then
    echo "  FAIL  mas-render-unknown-token: rendered a template with an unknown token"; MB=$((MB+1))
  elif grep -qF "unknown token" <<<"$out" && [[ ! -e "$SCR/bad.out" ]]; then
    echo "  PASS  mas-render-unknown-token (refused, nothing written)"; MG=$((MG+1))
  else
    echo "  FAIL  mas-render-unknown-token: refused without saying why, or wrote a file: $out"; MB=$((MB+1))
  fi
  rm -rf "$SCR"
  GOOD=$((GOOD+MG)); BAD=$((BAD+MB))
}

GOOD=0; BAD=0
if [[ "${1:-}" == --mas ]]; then
  rl_need python3
  mas_cases
  echo
  echo "release-selftest --mas: $GOOD behaved correctly, $BAD did not"
  [[ $BAD -eq 0 ]]
  exit $?
fi

BASE="${1:-$V2/dist}"
rl_need python3 shasum tar
[[ -d "$BASE" ]] || rl_die "no such directory: $BASE"
TARBALL=$(find "$BASE" -maxdepth 1 -name 'credmgr-*.tar.gz' | head -1)
[[ -n "$TARBALL" ]] || rl_die "no credmgr-*.tar.gz in $BASE - run scripts/release.sh first"
TNAME=$(basename "$TARBALL" .tar.gz)   # also the tarball's top-level directory
SB=$(basename "$(find "$BASE" -maxdepth 1 -name 'credmgr-*-sbom-credmgr.cdx.json' | head -1)")
[[ "$SB" == credmgr-*-sbom-credmgr.cdx.json ]] || rl_die "no credmgr-<version>-sbom-credmgr.cdx.json in $BASE"
VER=${SB#credmgr-}; VER=${VER%-sbom-credmgr.cdx.json}
EPOCH=1700000000
# A deliberately fake build-machine home, assembled at run time so this file itself carries no
# home-directory literal for the personal-data guard (or a reader) to mistake for a real one.
FAKE_HOME="/Use""rs/someone"

# Until the manifests are bumped together, the dist under test may legitimately mix versions (the
# CLI at the workspace version, the app at tauri.conf.json's). Then every case runs with the skew
# allowance, so that each case isolates its OWN defect, and the one case that needs skew refused is skipped.
BASE_SKEW=$(python3 - "$BASE" <<'PY'
import os, re, sys
V = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?"
vs = {m.group(1) for n in os.listdir(sys.argv[1]) for m in [re.match(r"^credmgr-(?:desktop-)?(%s)-" % V, n)] if m}
print(1 if len(vs) > 1 else 0)
PY
)
DEFAULT_ARGS=()
if [[ "$BASE_SKEW" == 1 ]]; then DEFAULT_ARGS=(--allow-version-skew); echo "NOTE: $BASE mixes versions; every case runs with --allow-version-skew"; fi

SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/rsel.XXXXXX")
trap 'rm -rf "$SCRATCH"' EXIT
RUNFLAG=(--run-binaries)   # the static cases (issue #38) clear this: the verifier must refuse WITHOUT executing anything

# ---- helpers: every mutation works on $T (a copy of dist/); tarball surgery goes through $W -------
T=""; W=""
fresh() {                       # a new copy of the dist/ under test
  T=$(mktemp -d "$SCRATCH/t.XXXXXX"); W=""
  find "$BASE" -maxdepth 1 -type f ! -name '.*' -exec cp {} "$T/" \;
  if [[ -d "$BASE/CredMgr.app" ]]; then ditto "$BASE/CredMgr.app" "$T/CredMgr.app"; fi
}
app_exe() { printf '%s/CredMgr.app/Contents/MacOS/%s' "$T" "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$T/CredMgr.app/Contents/Info.plist")"; }
unpack() { W=$(mktemp -d "$SCRATCH/w.XXXXXX"); tar -xzf "$T/$TNAME.tar.gz" -C "$W"; }
inner_sums() {                  # rewrite the tarball's own manifest so only the intended defect remains
  ( cd "$W/$TNAME" && FILES=$(find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort) \
    && printf '%s\n' "$FILES" | while IFS= read -r f; do shasum -a 256 -- "$f"; done > SHA256SUMS )
}
repack()    { rl_make_tarball "$W" "$TNAME" "$T/$TNAME.tar.gz" "$EPOCH" && rl_sums_write "$T"; }
repack_bsd(){ rm -f "$T/$TNAME.tar.gz"; ( cd "$W" && COPYFILE_DISABLE=1 tar -czf "$T/$TNAME.tar.gz" "$TNAME" ) && rl_sums_write "$T"; }
sbom_file() { printf '%s/credmgr-%s-sbom-%s.cdx.json' "$T" "$VER" "$1"; }

run_case() {                    # <name> <expected failure text, or '' for "must pass"> <fn> [verify args...]
  local name=$1 expect=$2 fn=$3 out rc
  shift 3
  fresh
  "$fn" || { echo "  ERROR  $name: could not build the broken copy"; BAD=$((BAD+1)); return; }
  out=$(rl_verify "$T" --require-cli ${RUNFLAG[@]+"${RUNFLAG[@]}"} --allow-dev-build ${DEFAULT_ARGS[@]+"${DEFAULT_ARGS[@]}"} "$@" 2>&1); rc=$?
  # (here-strings, never `| grep -q`: under pipefail grep exiting at its first match can SIGPIPE the producer)
  if grep -qF 'Traceback (most recent call last)' <<<"$out"; then
    # A verifier that crashes is not refusing for the right reason, whatever its exit code says.
    echo "  FAIL  $name: the verifier CRASHED instead of reporting"; echo "$out" | grep -A6 Traceback | head -8; BAD=$((BAD+1)); return
  fi
  if [[ -z "$expect" ]]; then
    if [[ $rc -eq 0 ]]; then echo "  PASS  $name (accepted, as it must be)"; GOOD=$((GOOD+1))
    else echo "  FAIL  $name: the verifier rejected a good dist/"; echo "$out" | grep FAIL | head -5; BAD=$((BAD+1)); fi
  else
    if [[ $rc -ne 0 ]] && grep -qF -- "$expect" <<<"$out"; then
      echo "  PASS  $name (refused: ...${expect}...)"; GOOD=$((GOOD+1))
    else
      echo "  FAIL  $name: expected a refusal mentioning '$expect' (exit $rc)"; echo "$out" | grep -E 'FAIL|Traceback' | head -5; BAD=$((BAD+1))
    fi
  fi
}

# ---- the cases ------------------------------------------------------------------------------------
c_control()        { :; }
c_flip_byte()      { python3 - "$T/$TNAME.tar.gz" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 0xFF; open(p, "wb").write(bytes(b))
PY
}
c_stray_file()     { echo "not a release asset" > "$T/stray.txt"; }
c_missing_listed() { rm -f "$(sbom_file desktop)"; }
c_edited_hash()    { python3 - "$T/SHA256SUMS" <<'PY'
import sys
p = sys.argv[1]; L = open(p).read().splitlines(); L[0] = ("0" if L[0][0] != "0" else "1") + L[0][1:]; open(p, "w").write("\n".join(L) + "\n")
PY
}
c_garbage_line()   { echo "this is not a checksum line" >> "$T/SHA256SUMS"; }
c_home_in_binary() { unpack; printf '%s/.cargo/registry/src/x/y.rs\0' "$FAKE_HOME" >> "$W/$TNAME/bin/credmgrd"; inner_sums; repack; }
c_home_in_sbom()   { python3 - "$(sbom_file credmgr)" "$FAKE_HOME" <<'PY'
import sys
p, home = sys.argv[1], sys.argv[2]
s = open(p).read(); s = s.replace('"path+file://./crates', '"path+file://%s/proj/crates' % home, 1); open(p, "w").write(s)
PY
rl_sums_write "$T"; }
c_owner_named()    { unpack; repack_bsd; }
c_appledouble()    { unpack; : > "$W/$TNAME/bin/._credmgr"; inner_sums; repack; }
c_inner_lie()      { unpack; echo "tampered after the manifest was written" >> "$W/$TNAME/RELEASE.md"; repack; }
c_symlink()        { unpack; ln -s /etc/passwd "$W/$TNAME/bin/link"; inner_sums; repack_bsd; }
c_traversal()      { python3 - "$T/$TNAME.tar.gz" "$TNAME" <<'PY'
import gzip, io, sys, tarfile
out, top = sys.argv[1], sys.argv[2]
with tarfile.open(out, "w:gz") as tf:
    for name in (top + "/../../escaped.txt", "/abs/escaped.txt"):
        ti = tarfile.TarInfo(name); ti.size = 3; tf.addfile(ti, io.BytesIO(b"bad"))
PY
rl_sums_write "$T"; }
CANARY="${TMPDIR:-/tmp}/cmv-canary.txt"
c_hostile_extract() { rm -f "$CANARY"; python3 - "$T/$TNAME.tar.gz" "$TNAME" "$CANARY" <<'PY'
import io, sys, tarfile
out, top, canary = sys.argv[1:4]
with tarfile.open(out, "w:gz") as tf:
    # lands in $TMPDIR (one level above the verifier's work dir) if anything extracts it
    ti = tarfile.TarInfo(top + "/../../" + canary.rsplit("/", 1)[1]); ti.size = 3; tf.addfile(ti, io.BytesIO(b"bad"))
PY
rl_sums_write "$T"; }
c_dangling_edge()  { python3 - "$(sbom_file credmgrd)" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["dependencies"][0].setdefault("dependsOn", []).append("pkg:cargo/nonexistent@0.0.0"); open(p, "w").write(json.dumps(d, indent=2) + "\n")
PY
rl_sums_write "$T"; }
c_mixed_versions() { mv "$(sbom_file desktop)" "$T/credmgr-9.9.9-sbom-desktop.cdx.json"; rl_sums_write "$T"; }
c_duplicate_sbom() { cp "$(sbom_file desktop)" "$T/credmgr-9.9.9-sbom-desktop.cdx.json"; rl_sums_write "$T"; }
c_unknown_asset()  { echo "release notes" > "$T/credmgr-notes.txt"; rl_sums_write "$T"; }
c_no_tarball()     { rm -f "$T/$TNAME.tar.gz"; rl_sums_write "$T"; }
c_truncated_gz()   { head -c 1500 "$T/$TNAME.tar.gz" > "$T/cut" && mv "$T/cut" "$T/$TNAME.tar.gz"; rl_sums_write "$T"; }
c_missing_sbom_t() { rm -f "$(sbom_file desktop)"; rl_sums_write "$T"; }
# --- desktop-app cases (macOS; only when the dist under test holds an app) ---
c_app_unsealed()   { codesign --remove-signature "$T/CredMgr.app" 2>/dev/null; }
c_app_leak()       { printf '%s/.cargo/registry/src/x/y.rs\0' "$FAKE_HOME" >> "$(app_exe)"; }
c_app_diverges()   { printf 'x' >> "$(app_exe)"; }
c_app_no_daemon()  { rm -f "$T/CredMgr.app/Contents/MacOS/credmgrd"; }
c_dmg_corrupt()    { python3 - "$(ls "$T"/credmgr-desktop-*.dmg)" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 3] ^= 0xFF; open(p, "wb").write(bytes(b))
PY
rl_sums_write "$T"; }
c_zip_wrong()      { local z; z=$(ls "$T"/credmgr-desktop-*.app.zip); rm -f "$z"; mkdir "$T/_x" && echo hi > "$T/_x/readme.txt" \
                       && ditto -c -k --keepParent "$T/_x" "$z" && rm -rf "$T/_x"; rl_sums_write "$T"; }


# --- issue #38: what the verifier must find in the bytes, without --run-binaries ---
c_stamp_removed()  { unpack; python3 - "$W/$TNAME/bin/credmgrd" <<'PY'
import sys
p = sys.argv[1]; b = open(p, "rb").read(); k = b"credmgr-build-stamp:v1:"
assert k in b, "no stamp in the binary under test"
open(p, "wb").write(b.replace(k, b"credmgr-build-gone!!:v1:"))
PY
inner_sums; repack; }
c_minos_high()     { unpack; python3 - "$W/$TNAME/bin/credmgr" <<'PY'
import struct, sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read())
off = 0
if struct.unpack(">I", b[:4])[0] in (0xCAFEBABE, 0xCAFEBABF):
    off = struct.unpack(">5I", b[8:28])[2]
assert struct.unpack("<I", b[off:off + 4])[0] == 0xFEEDFACF, "not a thin 64-bit Mach-O slice"
ncmds = struct.unpack("<I", b[off + 16:off + 20])[0]; q = off + 32; hit = False
for _ in range(ncmds):
    cmd, size = struct.unpack("<II", b[q:q + 8])
    if cmd == 0x32:
        b[q + 12:q + 16] = struct.pack("<I", (27 << 16) | (2 << 8)); hit = True
    q += size
assert hit, "no LC_BUILD_VERSION to patch"
open(p, "wb").write(bytes(b))
PY
inner_sums; repack; }
c_doc_changed()    { unpack; echo "The CLI needs macOS 27.2." >> "$W/$TNAME/RELEASE.md"; inner_sums; repack; }
BASE_DIRTY=$(tar -xzOf "$TARBALL" "$TNAME/bin/credmgr" | python3 -c 'import re,sys; m = re.search(rb"credmgr-build-stamp:v1:commit=[0-9a-f]+:dirty=([01])", sys.stdin.buffer.read()); print(m.group(1).decode() if m else "x")')
echo "== the release verifier must refuse each of these (base: $BASE)"
run_case control            ""                                                 c_control
run_case flipped-byte       "sha256 MISMATCH"                                  c_flip_byte
run_case stray-file         "unexpected file in dist/"                         c_stray_file
run_case listed-but-missing "SHA256SUMS and dist/ disagree"                    c_missing_listed
run_case edited-hash-line   "sha256 MISMATCH"                                  c_edited_hash
run_case malformed-line     "is not '<sha256>  <plain file name>'"             c_garbage_line
run_case home-path-binary   "embeds a build-machine path"                      c_home_in_binary
run_case home-path-sbom     "embeds a build-machine path"                      c_home_in_sbom
run_case owner-names        "tar headers name an owner"                        c_owner_named
run_case appledouble        "AppleDouble"                                      c_appledouble
run_case manifest-mismatch  "does not match the tarball's SHA256SUMS"          c_inner_lie
run_case symlink-member     "tarball holds a link or special file"             c_symlink
run_case path-traversal     "a member escapes"                                 c_traversal
run_case hostile-no-extract "nothing was extracted"                             c_hostile_extract
if [[ -e "$CANARY" ]]; then echo "  FAIL  hostile-no-extract: a hostile member was written to $CANARY"; rm -f "$CANARY"; BAD=$((BAD+1)); else echo "  PASS  hostile-no-extract (no file escaped the work directory)"; GOOD=$((GOOD+1)); fi
run_case dangling-edge      "dangling dependency refs"                         c_dangling_edge
if [[ "$BASE_SKEW" == 1 ]]; then
  echo "  SKIP  mixed-versions (the base already mixes versions; the case needs them refused)"
else
  run_case mixed-versions   "assets carry different versions"                  c_mixed_versions
fi
run_case duplicate-sbom     "more than one desktop SBOM"                       c_duplicate_sbom
run_case unknown-asset      "unexpected file in dist/"                         c_unknown_asset
run_case no-tarball         "expected one credmgr-<version>-<target>.tar.gz"   c_no_tarball
run_case truncated-gzip     "the tarball cannot be read"                       c_truncated_gz
run_case missing-sbom       "missing SBOM(s)"                                  c_missing_sbom_t
run_case wrong-version      "expected version 0.0.1"                           c_control --expect-version 0.0.1
echo "== issue #38: the same, WITHOUT --run-binaries (nothing is executed)"
RUNFLAG=()
run_case static-control     ""                                                 c_control
run_case stamp-removed      "carries no build stamp"                           c_stamp_removed
run_case minos-too-high     "needs macOS 27.2 but the limit is"                c_minos_high
run_case stamp-wrong-commit ", expected 000000000000"                                   c_control --expect-commit 0000000000000000000000000000000000000000
if [[ "$BASE_DIRTY" == 0 ]]; then
  run_case doc-not-at-commit "differs from the file at the stamped commit"     c_doc_changed
else
  echo "  SKIP  doc-not-at-commit (the base dist is a dirty --dev build or unstamped: its documents are not expected to match a commit)"
fi
RUNFLAG=(--run-binaries)
if compgen -G "$BASE/credmgr-desktop-*.dmg" >/dev/null && [[ "$(uname -s)" == Darwin ]]; then
  echo "== the same for the desktop app"
  run_case app-unsealed     "signature does not verify"                        c_app_unsealed --allow-version-skew
  run_case app-path-leak    "executable embeds a build-machine path"           c_app_leak --allow-version-skew
  run_case app-copies-differ "the app copies differ"                           c_app_diverges --allow-version-skew
  run_case app-no-daemon    "has no bundled credmgrd"                          c_app_no_daemon --allow-version-skew
  run_case dmg-corrupt      "fails hdiutil verify"                             c_dmg_corrupt --allow-version-skew
  run_case zip-wrong        "does not unpack to a single CredMgr.app"          c_zip_wrong --allow-version-skew
else
  echo "== desktop-app cases SKIPPED (no credmgr-desktop-*.dmg in $BASE, or not macOS)"
fi
run_fresh() {                   # <name> <expected failure text> <fn>: scripts/fresh-install-check.sh must refuse
  local name=$1 expect=$2 fn=$3 out rc
  fresh
  "$fn" || { echo "  ERROR  $name: could not build the broken copy"; BAD=$((BAD+1)); return; }
  out=$("$V2/scripts/fresh-install-check.sh" --dist "$T" --quick --allow-dev-build 2>&1); rc=$?
  if [[ $rc -ne 0 ]] && grep -qF -- "$expect" <<<"$out"; then
    echo "  PASS  $name (refused: ...${expect}...)"; GOOD=$((GOOD+1))
  else
    echo "  FAIL  $name: expected a refusal mentioning '$expect' (exit $rc)"; grep 'FAIL' <<<"$out" | head -4; BAD=$((BAD+1))
  fi
}
c_fresh_corrupt()  { python3 - "$T/$TNAME.tar.gz" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 0xFF; open(p, "wb").write(bytes(b))
PY
}
c_fresh_dead()     { unpack; printf '#!/bin/sh\nexit 3\n' > "$W/$TNAME/bin/credmgrd"; chmod +x "$W/$TNAME/bin/credmgrd"; inner_sums; repack; }
echo "== scripts/fresh-install-check.sh must refuse these too"
run_fresh fresh-corrupt-download "and says OK for the tarball itself"         c_fresh_corrupt
run_fresh fresh-broker-wont-start "came up and is serving a socket"           c_fresh_dead
run_fill() {                    # <name> <expected failure text, or ''> <sums-file content> [extra fill-formula args]
  local name=$1 expect=$2 content=$3 out rc f; shift 3
  f=$(mktemp "$SCRATCH/sums.XXXXXX"); printf '%b' "$content" > "$f"
  out=$("$V2/packaging/homebrew/fill-formula.sh" --sums "$f" "$@" 2>&1); rc=$?
  if [[ -z "$expect" ]]; then
    if [[ $rc -eq 0 ]] && grep -qF 'sha256 "1111111111111111111111111111111111111111111111111111111111111111"' <<<"$out" \
       && grep -qF 'download/v9.8.7-rc.1/credmgr-9.8.7-rc.1-aarch64-apple-darwin.tar.gz' <<<"$out"; then
      echo "  PASS  $name (filled: version and hash landed)"; GOOD=$((GOOD+1))
    else echo "  FAIL  $name: a good SHA256SUMS was not filled correctly (exit $rc)"; echo "$out" | head -3; BAD=$((BAD+1)); fi
  elif [[ $rc -ne 0 ]] && grep -qF -- "$expect" <<<"$out"; then
    echo "  PASS  $name (refused: ...${expect}...)"; GOOD=$((GOOD+1))
  else echo "  FAIL  $name: expected a refusal mentioning '$expect' (exit $rc)"; echo "$out" | head -3; BAD=$((BAD+1)); fi
}
H1=1111111111111111111111111111111111111111111111111111111111111111
Z0=0000000000000000000000000000000000000000000000000000000000000000
LINE="$H1  credmgr-9.8.7-rc.1-aarch64-apple-darwin.tar.gz\n"
echo "== the Homebrew fill script must refuse a bad SHA256SUMS and fill a good one"
run_fill fill-good          ""                                "$LINE"
run_fill fill-no-line       "found 0"                         "$H1  credmgr-9.8.7-rc.1-sbom-credmgr.cdx.json\n"
run_fill fill-two-lines     "found 2"                         "$LINE$H1  credmgr-9.8.8-aarch64-apple-darwin.tar.gz\n"
run_fill fill-zero-hash     "refusing an all-zero hash"       "$Z0  credmgr-9.8.7-rc.1-aarch64-apple-darwin.tar.gz\n"
run_fill fill-short-hash    "found 0"                         "abc123  credmgr-9.8.7-rc.1-aarch64-apple-darwin.tar.gz\n"
run_fill fill-wrong-target  "found 0"                         "$H1  credmgr-9.8.7-rc.1-x86_64-apple-darwin.tar.gz\n"
run_fill fill-bad-repo      "must look like OWNER/REPO"       "$LINE" --repo "not a repo"
# Aimed at a SCRATCH COPY of the script and template, so a broken guard cannot damage the real template.
SB=$(mktemp -d "$SCRATCH/hb.XXXXXX"); cp "$V2/packaging/homebrew/credmgr.rb" "$V2/packaging/homebrew/fill-formula.sh" "$SB/"
printf '%b' "$LINE" > "$SB/sums"; BEFORE=$(shasum -a 256 < "$SB/credmgr.rb")
OUT=$("$SB/fill-formula.sh" --sums "$SB/sums" --out "$SB/credmgr.rb" 2>&1); RC=$?; AFTER=$(shasum -a 256 < "$SB/credmgr.rb")
if [[ $RC -ne 0 ]] && grep -qF "refusing to overwrite the template" <<<"$OUT" && [[ "$BEFORE" == "$AFTER" ]]; then
  echo "  PASS  fill-over-template (refused, and the template is byte-for-byte unchanged)"; GOOD=$((GOOD+1))
else echo "  FAIL  fill-over-template: exit $RC, template changed: $([[ "$BEFORE" == "$AFTER" ]] && echo no || echo YES)"; BAD=$((BAD+1)); fi
echo "== and these must still be accepted"
run_case skew-allowed      ""                                                 c_mixed_versions --allow-version-skew
if compgen -G "$BASE/credmgr-desktop-*.dmg" >/dev/null && [[ "$(uname -s)" == Darwin ]]; then
  run_case app-control      ""                                                 c_control --allow-version-skew
fi

mas_cases

echo
echo "release-selftest: $GOOD behaved correctly, $BAD did not"
[[ $BAD -eq 0 ]]
