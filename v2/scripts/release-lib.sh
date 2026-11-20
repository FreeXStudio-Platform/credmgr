#!/usr/bin/env bash
# shellcheck shell=bash
# CredMgr V2 - shared plumbing for scripts/release.sh, scripts/release-app.sh and
# scripts/fresh-install-check.sh. SOURCED, never executed.
#
# It holds the three things the release scripts must agree on, so they cannot drift apart:
#   * how a version is read from a manifest (one place, one grammar);
#   * how a tarball is written (deterministic: sorted, fixed mtime, owner 0/0 and NO user name -
#     the first version of this tooling shipped the builder's login name in every tar header);
#   * how a dist/ directory is verified (SHA256SUMS completeness and content, the tarball, the
#     SBOMs, the app bundle, and a scan of every shipped binary and SBOM for build-machine paths).
#
# Compatible with the bash 3.2 that macOS ships: no associative arrays, no mapfile, no ${x,,}.

RL_PY=${RL_PY:-python3}

rl_die()  { printf '%s: %s\n' "${RL_NAME:-release}" "$*" >&2; exit 1; }
rl_warn() { printf '%s: WARNING: %s\n' "${RL_NAME:-release}" "$*" >&2; }
rl_info() { printf '%s: %s\n' "${RL_NAME:-release}" "$*"; }
rl_need() {
  local t
  for t in "$@"; do command -v "$t" >/dev/null 2>&1 || rl_die "needs '$t' on PATH"; done
}

# ---------------------------------------------------------------------------------------------
# Versions. Filenames, the Homebrew URL and the verifier all parse the same grammar:
# MAJOR.MINOR.PATCH with an optional single pre-release segment (2.0.0-beta.1). A pre-release with
# its own hyphen is refused because "credmgr-<version>-<target>" would become ambiguous to read back.
RL_VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'

rl_valid_version() { [[ "$1" =~ $RL_VERSION_RE ]]; }

# The version of a Cargo manifest's [workspace.package] (or, with $2=package, its [package]).
rl_cargo_version() {   # <Cargo.toml> [workspace.package|package]
  local section=${2:-workspace.package}
  awk -v want="[$section]" '
    /^\[/ { insec = ($0 == want) }
    insec && /^version[[:space:]]*=/ { n = split($0, a, "\""); if (n >= 2) { print a[2]; exit } }
  ' "$1"
}

rl_json_field() {      # <file.json> <key or dotted path, e.g. build.beforeBuildCommand>
  "$RL_PY" -c '
import json, sys
v = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    v = v[k]
print(v)' "$1" "$2"
}

# ---------------------------------------------------------------------------------------------
# SHA256SUMS. One line per top-level regular file in dist/, sorted bytewise, the file's plain name
# (no directory part), so `shasum -a 256 -c SHA256SUMS` run next to a download just works - and
# `--ignore-missing` covers someone who fetched only the tarball. Rewritten from scratch every time
# a script adds an asset, so it can never list a file that is not there or omit one that is.
rl_sums_write() {      # <dist>
  ( cd "$1" || exit 1
    export LC_ALL=C
    list=$(find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name '.*' | sed 's|^\./||' | sort)
    [ -n "$list" ] || exit 1
    : > SHA256SUMS.new
    printf '%s\n' "$list" | while IFS= read -r f; do shasum -a 256 -- "$f" >> SHA256SUMS.new; done
    mv SHA256SUMS.new SHA256SUMS ) || rl_die "could not write SHA256SUMS in $1"
}

# ---------------------------------------------------------------------------------------------
# A deterministic tar.gz: members sorted, mtime fixed to the epoch, owner 0:0 with NO names,
# modes normalised (0755 for anything executable, else 0644), gzip header without a name or time.
# The same inputs on the same machine give the same bytes; across machines a different zlib may
# compress differently, which is why the *published* SHA256SUMS - not a rebuild - is the reference.
rl_make_tarball() {    # <parent dir> <top-level dir name> <out.tar.gz> <epoch>
  "$RL_PY" - "$@" <<'PYEOF'
import gzip, os, sys, tarfile
parent, top, out, epoch = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
root = os.path.join(parent, top)
entries = [top]
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort()
    rel = os.path.relpath(dirpath, parent)
    for d in dirnames:
        entries.append(os.path.join(rel, d))
    for f in sorted(filenames):
        entries.append(os.path.join(rel, f))
entries = sorted(set(entries))
tmp = out + ".new"
with open(tmp, "wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
            for rel in entries:
                full = os.path.join(parent, rel)
                if os.path.islink(full):
                    sys.exit("refusing to archive a symlink: " + rel)
                ti = tarfile.TarInfo(rel.replace(os.sep, "/"))
                ti.mtime = epoch
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                if os.path.isdir(full):
                    ti.type = tarfile.DIRTYPE
                    ti.mode = 0o755
                    tf.addfile(ti)
                else:
                    ti.type = tarfile.REGTYPE
                    ti.mode = 0o755 if os.access(full, os.X_OK) else 0o644
                    ti.size = os.path.getsize(full)
                    with open(full, "rb") as fh:
                        tf.addfile(ti, fh)
os.replace(tmp, out)
PYEOF
}

# ---------------------------------------------------------------------------------------------
# An SBOM that is safe to publish. cargo-cyclonedx writes the absolute path of the checkout into
# every component's bom-ref (path+file:///<home>/.../v2/crates/cli#...), a random serial number and
# the wall-clock time. This rewrites the paths to a relative form, derives the serial from the
# content so a rebuild of the same commit gives the same document, pins the timestamp to the
# build's epoch, and sorts components and dependencies. It then REFUSES to emit a file that still
# contains a local path, rather than trusting the substitution to have caught everything.
rl_sbom_sanitise() {   # <in.json> <out.json> <v2 dir> <epoch> <commit> <kind>
  "$RL_PY" - "$@" <<'PYEOF'
import datetime, json, os, re, sys, uuid
src, dst, v2, epoch, commit, kind = sys.argv[1:7]
text = open(src, encoding="utf-8").read()
roots = {v2, os.path.realpath(v2)}
for r in sorted(roots, key=len, reverse=True):
    text = text.replace("file://" + r, "file://.")
    text = text.replace(r, ".")
doc = json.loads(text)
if doc.get("bomFormat") != "CycloneDX":
    sys.exit("not a CycloneDX document: " + src)
root = doc["metadata"]["component"]
doc["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(
    uuid.NAMESPACE_URL, "credmgr-sbom:%s:%s:%s:%s" % (kind, root.get("name"), root.get("version"), commit)))
doc["metadata"]["timestamp"] = datetime.datetime.fromtimestamp(
    int(epoch), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
doc["components"] = sorted(doc.get("components", []), key=lambda c: c.get("bom-ref", ""))
deps = []
for d in doc.get("dependencies", []):
    d = dict(d)
    if "dependsOn" in d:
        d["dependsOn"] = sorted(d["dependsOn"])
    deps.append(d)
doc["dependencies"] = sorted(deps, key=lambda d: d.get("ref", ""))
out = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
home = os.path.expanduser("~")
leaks = [p for p in (v2, os.path.realpath(v2), home) if p and p != "/" and p in out]
leaks += re.findall(r"/Users/[^/\"\s]+|/home/[a-z_][a-z0-9_-]*/|/private/var/folders", out)
if leaks:
    sys.exit("SBOM still names a local path after sanitising (%s): %s" % (src, sorted(set(leaks))[:3]))
open(dst, "w", encoding="utf-8").write(out)
PYEOF
}

# ---------------------------------------------------------------------------------------------
# The verifier. Re-checks a produced dist/ without building anything:
#   rl_verify <dist> [--expect-version V] [--expect-commit SHA] [--allow-dev-build]
#                    [--allow-version-skew] [--require-cli] [--require-app] [--run-binaries]
#                    [--max-minos X.Y] [--repo-dir DIR]
# The verifier never executes what it checks unless --run-binaries is given; without it the
# binaries are inspected as bytes only and the --version check is skipped. Issue #38: even then it
# reads the build stamp (commit, dirty) out of each binary's bytes, reads the Mach-O minimum macOS
# version (LC_BUILD_VERSION) and refuses one above --max-minos (default RL_MAX_MINOS), and compares
# the documents packaged in the tarball with the same files at the stamped commit (git, in
# --repo-dir, default $V2 when the caller has one).
# Exit 0 only when every check passed. Output is one PASS/FAIL line per fact, like e2e-journey.sh.
RL_MAX_MINOS=${RL_MAX_MINOS:-13.1}   # = apps/desktop/src-tauri/tauri.conf.json minimumSystemVersion

rl_verify() {
  "$RL_PY" - --repo-dir "${V2:-}" --max-minos "$RL_MAX_MINOS" "$@" <<'PYEOF'
import argparse, gzip, hashlib, json, os, platform, re, shutil, subprocess, sys, tarfile, tempfile

ap = argparse.ArgumentParser()
ap.add_argument("dist")
ap.add_argument("--expect-version")
ap.add_argument("--expect-commit")
ap.add_argument("--allow-dev-build", action="store_true")
ap.add_argument("--allow-version-skew", action="store_true")
ap.add_argument("--require-cli", action="store_true")
ap.add_argument("--require-app", action="store_true")
ap.add_argument("--run-binaries", action="store_true")
ap.add_argument("--max-minos", default="13.1")
ap.add_argument("--repo-dir", default="")
a = ap.parse_args()
dist = os.path.abspath(a.dist)

FAILED = []
def ok(m): print("  PASS  " + m)
def bad(m): FAILED.append(m); print("  FAIL  " + m)
def note(m): print("  NOTE  " + m)
def check(cond, good, fail):
    (ok if cond else bad)(good if cond else fail)
    return bool(cond)

VER = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?"
TGT = r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_.]+){2,3}"
RE_TAR  = re.compile(r"^credmgr-(?P<ver>%s)-(?P<tgt>%s)\.tar\.gz$" % (VER, TGT))
RE_SBOM = re.compile(r"^credmgr-(?P<ver>%s)-sbom-(?P<which>credmgr|credmgrd|desktop)\.cdx\.json$" % VER)
RE_DMG  = re.compile(r"^credmgr-desktop-(?P<ver>%s)-(?P<tgt>%s)\.dmg$" % (VER, TGT))
RE_APPZ = re.compile(r"^credmgr-desktop-(?P<ver>%s)-(?P<tgt>%s)\.app\.zip$" % (VER, TGT))
RE_BINLINE = re.compile(r"^(?P<bin>credmgrd?) (?P<ver>%s) \(commit (?P<commit>[0-9a-f]{12})(?P<dirty>, dirty)?, (?P<plat>[^)]+)\)$" % VER)

HOME = os.path.expanduser("~")
LEAK_RE = re.compile(rb"/Users/[^/\0\s\"']+/|/home/[a-z_][a-z0-9_-]*/|/private/var/folders/")
def leaks_in(data, label):
    found = sorted({m.group(0).decode("utf-8", "replace") for m in LEAK_RE.finditer(data)})
    if HOME and HOME != "/" and HOME.encode() in data:
        found.append("(this machine's home directory)")
    return found

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# The build stamp, as build.rs writes it into a binary (see crates/cli/build.rs).
STAMP_RE = re.compile(rb"credmgr-build-stamp:v1:commit=([0-9a-f]{12,64}|none):dirty=([01])")

def build_stamps(data):
    return sorted({(m.group(1).decode(), m.group(2) == b"1") for m in STAMP_RE.finditer(data)})

def macho_minos(data):
    """Minimum OS version of every slice of a Mach-O file, as [(platform id, (major, minor, patch))].
    [] when the file has no such load command; None when it is not Mach-O at all. Pure Python, so it
    works on any host (a Linux CI box verifying a macOS tarball)."""
    import struct
    if len(data) < 8:
        return None
    be = struct.unpack(">I", data[:4])[0]
    slices = []
    if be in (0xCAFEBABE, 0xCAFEBABF):
        n = struct.unpack(">I", data[4:8])[0]
        if n > 16:
            return None
        for i in range(n):
            if be == 0xCAFEBABE:
                _, _, off, size, _ = struct.unpack(">5I", data[8 + 20 * i: 28 + 20 * i])
            else:
                _, _, off, size, _, _ = struct.unpack(">IIQQII", data[8 + 32 * i: 40 + 32 * i])
            slices.append((off, size))
    else:
        slices.append((0, len(data)))
    found = []
    for off, size in slices:
        head = data[off: off + 32]
        if len(head) < 28:
            return None
        magic = struct.unpack("<I", head[:4])[0]
        if magic == 0xFEEDFACF:
            hdr = 32
        elif magic == 0xFEEDFACE:
            hdr = 28
        else:
            return None
        ncmds = struct.unpack("<I", head[16:20])[0]
        p = off + hdr
        for _ in range(min(ncmds, 4096)):
            if p + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack("<II", data[p: p + 8])
            if cmdsize < 8:
                break
            if cmd == 0x32 and p + 24 <= len(data):        # LC_BUILD_VERSION: platform, minos, sdk, ntools
                plat, minos = struct.unpack("<II", data[p + 8: p + 16])
                found.append((plat, (minos >> 16, (minos >> 8) & 0xFF, minos & 0xFF)))
            elif cmd == 0x24 and p + 16 <= len(data):      # LC_VERSION_MIN_MACOSX: version, sdk
                v = struct.unpack("<I", data[p + 8: p + 12])[0]
                found.append((1, (v >> 16, (v >> 8) & 0xFF, v & 0xFF)))
            p += cmdsize
    return found

def parse_ver(s):
    parts = [int(x) for x in s.split(".")]
    return tuple((parts + [0, 0, 0])[:3])

def git_blob(repo_dir, commit, rel):
    """Bytes of <rel> (relative to repo_dir) at <commit>, or None when git or the commit is not there."""
    try:
        r = subprocess.run(["git", "-C", repo_dir, "show", "%s:./%s" % (commit, rel)], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None

def git_has_commit(repo_dir, commit):
    try:
        r = subprocess.run(["git", "-C", repo_dir, "cat-file", "-e", commit + "^{commit}"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0

def host_matches(target):
    arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}.get(platform.machine().lower())
    sysname = platform.system()
    if sysname == "Darwin":
        return target == "%s-apple-darwin" % arch
    if sysname == "Linux":
        return target.startswith(arch + "-") and "linux" in target
    return False

print("== verify %s" % dist)
check(os.path.isdir(dist), "dist directory exists", "no such directory: " + dist)
if not os.path.isdir(dist):
    sys.exit(1)

# ---- A. SHA256SUMS: complete, exact, and nothing unlisted ---------------------------------------
sums_path = os.path.join(dist, "SHA256SUMS")
listed = {}
if check(os.path.isfile(sums_path), "SHA256SUMS present", "SHA256SUMS missing"):
    for n, line in enumerate(open(sums_path, encoding="utf-8").read().splitlines(), 1):
        m = re.match(r"^([0-9a-f]{64})  ([^/\s][^/]*)$", line)
        if not m:
            bad("SHA256SUMS line %d is not '<sha256>  <plain file name>'" % n)
            continue
        if m.group(2) in listed:
            bad("SHA256SUMS lists %s twice" % m.group(2))
        listed[m.group(2)] = m.group(1)
present = sorted(f for f in os.listdir(dist)
                 if f != "SHA256SUMS" and not f.startswith(".") and os.path.isfile(os.path.join(dist, f)))
check(sorted(listed) == present, "SHA256SUMS lists exactly the %d assets in dist/" % len(present),
      "SHA256SUMS and dist/ disagree: only listed %s, only present %s" % (
          sorted(set(listed) - set(present)), sorted(set(present) - set(listed))))
for name in present:
    if name in listed:
        check(sha256(os.path.join(dist, name)) == listed[name], "sha256 matches: " + name, "sha256 MISMATCH: " + name)

# ---- B. classify the assets and compare versions -----------------------------------------------
tarballs = [n for n in present if RE_TAR.match(n)]
sbom_all = [n for n in present if RE_SBOM.match(n)]
sboms    = {}
for n in sbom_all:
    which = RE_SBOM.match(n).group("which")
    if which in sboms:
        bad("more than one %s SBOM in dist/: %s and %s" % (which, sboms[which], n))
    sboms[which] = n
dmgs     = [n for n in present if RE_DMG.match(n)]
appzips  = [n for n in present if RE_APPZ.match(n)]
known = set(tarballs) | set(sbom_all) | set(dmgs) | set(appzips)
for n in present:
    if n not in known:
        bad("unexpected file in dist/: " + n)
versions = {}
for n in sorted(known):
    for rx in (RE_TAR, RE_SBOM, RE_DMG, RE_APPZ):
        m = rx.match(n)
        if m:
            versions[n] = m.group("ver")
distinct = sorted(set(versions.values()))
if len(distinct) > 1:
    if a.allow_version_skew:
        note("assets carry different versions %s (allowed by --allow-version-skew; never publish this)" % distinct)
    else:
        bad("assets carry different versions %s - one release is one version" % distinct)
elif distinct:
    ok("every asset carries the same version, " + distinct[0])
if a.expect_version:
    check(distinct == [a.expect_version] or (a.allow_version_skew and a.expect_version in distinct),
          "version is %s" % a.expect_version, "expected version %s, found %s" % (a.expect_version, distinct))

# ---- C. the CLI tarball -------------------------------------------------------------------------
if a.require_cli or tarballs:
    check(len(tarballs) == 1, "exactly one CLI tarball", "expected one credmgr-<version>-<target>.tar.gz, found %d" % len(tarballs))
if len(tarballs) == 1:
    tname = tarballs[0]
    tm = RE_TAR.match(tname)
    ver, tgt = tm.group("ver"), tm.group("tgt")
    top = "credmgr-%s-%s" % (ver, tgt)
    tpath = os.path.join(dist, tname)
    work = tempfile.mkdtemp(prefix="cmv.")
    try:
        members = []
        with tarfile.open(tpath, "r:gz") as tf:
            members = tf.getmembers()
            names = [m.name for m in members]
            member_ok = True
            member_ok &= check(all(n == top or n.startswith(top + "/") for n in names), "every member is under %s/" % top,
                  "a member escapes %s/" % top)
            member_ok &= check(not any(n.startswith("/") or ".." in n.split("/") for n in names), "no absolute or '..' member paths", "absolute or '..' member path")
            member_ok &= check(all(m.isfile() or m.isdir() for m in members), "only regular files and directories (no links, no devices)", "tarball holds a link or special file")
            check(not any(os.path.basename(n).startswith("._") or os.path.basename(n) == ".DS_Store" for n in names), "no AppleDouble or .DS_Store members", "AppleDouble/.DS_Store member in tarball")
            owners = {(m.uid, m.gid, m.uname, m.gname) for m in members}
            check(owners <= {(0, 0, "", "")} or owners <= {(0, 0, "root", "wheel")} or owners <= {(0, 0, "root", "root")},
                  "owner is 0:0 with no user name (no login name leaked into the archive)", "tar headers name an owner: %s" % sorted(owners)[:3])
            if not member_ok:
                bad("the tarball failed its member checks; nothing was extracted")
                raise ValueError("unsafe members")
            work_real = os.path.realpath(work)
            try:
                tf.extractall(work, filter="data")
            except TypeError:
                # no tarfile filter on this Python: validate each member, then extract it by itself
                for m in members:
                    dest = os.path.realpath(os.path.join(work, m.name))
                    if not (dest == work_real or dest.startswith(work_real + os.sep)):
                        bad("refusing to extract %s: it resolves outside the work directory" % m.name)
                        raise ValueError("unsafe member path")
                    tf.extract(m, work)
        root = os.path.join(work, top)
        need = ["bin/credmgr", "bin/credmgrd", "bin/credmgr-presence", "packaging/com.credmgr.brokerd.plist", "RELEASE.md", "CHANGELOG.md",
                "SECURITY.md", "LICENSE", "SHA256SUMS", "sbom/credmgr-%s-sbom-credmgr.cdx.json" % ver,
                "sbom/credmgr-%s-sbom-credmgrd.cdx.json" % ver]
        for rel in need:
            check(os.path.isfile(os.path.join(root, rel)), "tarball holds " + rel, "tarball is missing " + rel)
        for rel in ("bin/credmgr", "bin/credmgrd", "bin/credmgr-presence"):
            p = os.path.join(root, rel)
            if os.path.isfile(p):
                check(os.access(p, os.X_OK), rel + " is executable", rel + " is not executable")
        # ADR-098: the unattended TEST variant of the Touch ID helper creates keys with no prompt. It must never ship.
        check(not os.path.exists(os.path.join(root, "bin", "credmgr-presence-test")),
              "the unattended test helper is not packaged", "bin/credmgr-presence-test is in the tarball")
        pp = os.path.join(root, "bin", "credmgr-presence")
        if os.path.isfile(pp):
            with open(pp, "rb") as fh:
                blob = fh.read()
                check(b"credmgr-presence-variant:production" in blob and b"unattended-test" not in blob,
                      "the packaged helper is the production build (asks for user presence)",
                      "bin/credmgr-presence is not the production build (unattended test variant or unmarked)")
        # inner manifest: covers every file but itself, and every hash matches
        inner = os.path.join(root, "SHA256SUMS")
        if os.path.isfile(inner):
            inner_listed = {}
            for line in open(inner, encoding="utf-8").read().splitlines():
                m = re.match(r"^([0-9a-f]{64})  (.+)$", line)
                if m:
                    inner_listed[m.group(2)] = m.group(1)
            actual = sorted(os.path.relpath(os.path.join(dp, f), root) for dp, _, fs in os.walk(root) for f in fs
                            if os.path.relpath(os.path.join(dp, f), root) != "SHA256SUMS")
            check(sorted(inner_listed) == actual, "the tarball's own SHA256SUMS covers all %d packaged files" % len(actual),
                  "the tarball's SHA256SUMS and its contents disagree")
            check(all(os.path.isfile(os.path.join(root, f)) and sha256(os.path.join(root, f)) == h for f, h in inner_listed.items()),
                  "every packaged file matches the tarball's own SHA256SUMS", "a packaged file does not match the tarball's SHA256SUMS")
        # the binaries: stamp, architecture, no build-machine paths
        stamped = {}
        dirty_any = False
        for b in ("credmgr", "credmgrd"):
            p = os.path.join(root, "bin", b)
            if not os.path.isfile(p):
                continue
            data = open(p, "rb").read()
            found = leaks_in(data, b)
            check(not found, "bin/%s names no build-machine path" % b, "bin/%s embeds a build-machine path: %s" % (b, found[:3]))
            # Issue #38: the stamp is read out of the bytes, so it is checked even without --run-binaries.
            stamps = build_stamps(data)
            if not check(len(stamps) == 1, "bin/%s carries one build stamp in its bytes" % b,
                         "bin/%s carries no build stamp (or several): %s - rebuild it with scripts/release.sh" % (b, stamps or "none")):
                pass
            elif stamps[0][0] == "none":
                bad("bin/%s was built without a commit (a development build) - a binary that cannot say which commit it is must not ship" % b)
            else:
                s_commit, s_dirty = stamps[0]
                stamped[b] = s_commit
                ok("bin/%s is stamped with commit %s" % (b, s_commit[:12]))
                if a.expect_commit:
                    check(a.expect_commit.startswith(s_commit) or s_commit.startswith(a.expect_commit),
                          "bin/%s stamp matches the expected commit" % b,
                          "bin/%s is stamped %s, expected %s" % (b, s_commit[:12], a.expect_commit[:12]))
                if s_dirty:
                    dirty_any = True
                    (note if a.allow_dev_build else bad)("bin/%s was built from a DIRTY tree (read from its stamp) - a development build, never to be published" % b)
                else:
                    ok("bin/%s stamp says a clean tree" % b)
            # Issue #38: the minimum macOS version a binary demands is what the user's Mac must have. A build host
            # that stamps its own version (27.2 once did) makes the shipped binary refuse to start on the Macs we promise.
            if "apple-darwin" in tgt:
                mins = macho_minos(data)
                if mins is None:
                    bad("bin/%s is not a Mach-O file but the target is %s" % (b, tgt))
                elif not mins:
                    bad("bin/%s carries no minimum macOS version (no LC_BUILD_VERSION)" % b)
                else:
                    want = parse_ver(a.max_minos)
                    for plat, ver3 in sorted(set(mins)):
                        txt = "%d.%d%s" % (ver3[0], ver3[1], ("." + str(ver3[2])) if ver3[2] else "")
                        check(plat == 1 and ver3 <= want, "bin/%s needs macOS %s or later (limit %s)" % (b, txt, a.max_minos),
                              "bin/%s needs macOS %s but the limit is %s (platform %d) - the build host's version leaked in; set MACOSX_DEPLOYMENT_TARGET" % (b, txt, a.max_minos, plat))
            if platform.system() == "Darwin":
                desc = subprocess.run(["file", "-b", p], capture_output=True, text=True).stdout.strip()
                want = "arm64" if tgt.startswith("aarch64") else tgt.split("-")[0]
                check(want in desc, "bin/%s is built for %s" % (b, want), "bin/%s is not built for %s: %s" % (b, want, desc))
            if host_matches(tgt) and not a.run_binaries:
                note("%s was not executed (pass --run-binaries to run the --version check)" % b)
            elif host_matches(tgt):
                r = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=60,
                                   env={"PATH": "/usr/bin:/bin"})
                line = (r.stdout or "").strip()
                m = RE_BINLINE.match(line)
                if not check(r.returncode == 0 and m, "%s --version: %s" % (b, line), "%s --version gave an unreadable stamp: %r (exit %s)" % (b, line, r.returncode)):
                    continue
                check(m.group("bin") == b and m.group("ver") == ver, "%s reports version %s" % (b, ver),
                      "%s reports %s, the file name says %s" % (b, m.group("ver"), ver))
                if a.expect_commit:
                    check(a.expect_commit.startswith(m.group("commit")), "%s names commit %s" % (b, m.group("commit")),
                          "%s names commit %s, expected %s" % (b, m.group("commit"), a.expect_commit[:12]))
                if m.group("dirty"):
                    (note if a.allow_dev_build else bad)("%s was built from a DIRTY tree - a development build, never to be published" % b)
                else:
                    ok("%s was built from a clean tree" % b)
            else:
                note("target %s is not this machine; %s was not executed" % (tgt, b))
        # Issue #38: both binaries come from one commit, and the documents packaged beside them are the ones at that commit.
        if len(set(stamped.values())) > 1:
            bad("credmgr and credmgrd are stamped with different commits: %s" % {k: v[:12] for k, v in sorted(stamped.items())})
        if stamped:
            commit = sorted(stamped.values())[0]
            repo = a.repo_dir or os.getcwd()
            if not git_has_commit(repo, commit):
                note("commit %s is not in the repository at %s: the packaged documents were not compared with it" % (commit[:12], repo if a.repo_dir else "the current directory"))
            else:
                for doc in ("RELEASE.md", "CHANGELOG.md", "SECURITY.md", "LICENSE"):
                    inside = os.path.join(root, doc)
                    blob = git_blob(repo, commit, doc)
                    if blob is None or not os.path.isfile(inside):
                        continue   # a missing packaged file is already reported above
                    same = hashlib.sha256(open(inside, "rb").read()).hexdigest() == hashlib.sha256(blob).hexdigest()
                    if dirty_any and a.allow_dev_build and not same:
                        note("packaged %s differs from commit %s (a dirty development build, allowed)" % (doc, commit[:12]))
                        continue
                    check(same, "packaged %s is the file at commit %s" % (doc, commit[:12]),
                          "packaged %s differs from the file at the stamped commit %s - the documents do not belong to these binaries" % (doc, commit[:12]))
        # the SBOMs shipped inside must be the same bytes as the loose ones
        for which in ("credmgr", "credmgrd"):
            loose = sboms.get(which)
            inside = os.path.join(root, "sbom", "credmgr-%s-sbom-%s.cdx.json" % (ver, which))
            if loose and os.path.isfile(inside):
                check(sha256(os.path.join(dist, loose)) == sha256(inside), "%s SBOM inside the tarball is the published one" % which,
                      "%s SBOM inside the tarball differs from the published file" % which)
    except (tarfile.TarError, EOFError, OSError, ValueError) as e:
        bad("the tarball cannot be read: %s: %s" % (type(e).__name__, e))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if a.expect_version:
        check(ver == a.expect_version, "tarball version is %s" % a.expect_version, "tarball says %s, expected %s" % (ver, a.expect_version))

# ---- D. the SBOMs -------------------------------------------------------------------------------
for which, name in sorted(sboms.items()):
    path = os.path.join(dist, name)
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        bad("%s is not valid JSON: %s" % (name, e))
        continue
    root = doc.get("metadata", {}).get("component", {})
    check(doc.get("bomFormat") == "CycloneDX" and doc.get("specVersion") == "1.5",
          "%s is CycloneDX 1.5" % name, "%s is not a CycloneDX 1.5 document" % name)
    check(bool(re.match(r"^urn:uuid:[0-9a-f-]{36}$", doc.get("serialNumber", ""))), "%s has a serial number" % name, "%s has no valid serial number" % name)
    comps = doc.get("components", [])
    check(len(comps) >= 10, "%s lists %d components" % (name, len(comps)), "%s lists suspiciously few components (%d)" % (name, len(comps)))
    refs = {c.get("bom-ref") for c in comps} | {root.get("bom-ref")}
    dangling = {d["ref"] for d in doc.get("dependencies", []) if d["ref"] not in refs}
    dangling |= {x for d in doc.get("dependencies", []) for x in d.get("dependsOn", []) if x not in refs}
    check(not dangling, "%s: every dependency edge resolves" % name, "%s: dangling dependency refs %s" % (name, sorted(dangling)[:3]))
    if which in ("credmgr", "credmgrd") and versions.get(name):
        check(root.get("name") == which and root.get("version") == versions[name],
              "%s describes %s %s" % (name, which, versions[name]),
              "%s describes %s %s, expected %s %s" % (name, root.get("name"), root.get("version"), which, versions[name]))
    raw = open(path, "rb").read()
    found = leaks_in(raw, name)
    check(not found, "%s names no build-machine path" % name, "%s embeds a build-machine path: %s" % (name, found[:3]))

if a.require_cli:
    check(set(sboms) >= {"credmgr", "credmgrd", "desktop"}, "all three SBOMs (credmgr, credmgrd, desktop) are present",
          "missing SBOM(s): %s" % sorted({"credmgr", "credmgrd", "desktop"} - set(sboms)))

# ---- E. the desktop app (only when present; macOS only) ------------------------------------------
if a.require_app or dmgs or appzips:
    check(len(dmgs) == 1 and len(appzips) == 1, "one .dmg and one .app.zip",
          "expected one .dmg and one .app.zip, found %d and %d" % (len(dmgs), len(appzips)))
    if platform.system() != "Darwin":
        bad("app assets can only be verified on macOS")
    else:
        exe_hashes = {}
        def inspect_app(app, label, want_ver):
            try:
                _inspect_app(app, label, want_ver)
            except Exception as e:      # a damaged image can fail half-way through a read
                bad("%s could not be inspected: %s: %s" % (label, type(e).__name__, str(e)[:160]))
        def _inspect_app(app, label, want_ver):
            plist = os.path.join(app, "Contents", "Info.plist")
            if not check(os.path.isfile(plist), label + " has an Info.plist", label + " has no Info.plist"):
                return
            def pl(key):
                return subprocess.run(["/usr/libexec/PlistBuddy", "-c", "Print :" + key, plist], capture_output=True, text=True).stdout.strip()
            check(pl("CFBundleShortVersionString") == want_ver, "%s is version %s" % (label, want_ver),
                  "%s says version %s, the file name says %s" % (label, pl("CFBundleShortVersionString"), want_ver))
            check(pl("CFBundleIdentifier") == "com.credmgr.desktop", label + " identifier is com.credmgr.desktop", label + " has the wrong bundle identifier: " + pl("CFBundleIdentifier"))
            r = subprocess.run(["codesign", "--verify", "--deep", "--strict", app], capture_output=True, text=True)
            check(r.returncode == 0, label + " code signature verifies (ad-hoc: integrity only, NOT an identity)", label + " signature does not verify: " + r.stderr.strip()[:200])
            exe = os.path.join(app, "Contents", "MacOS", pl("CFBundleExecutable"))
            exe_hashes[label] = sha256(exe)
            found = leaks_in(open(exe, "rb").read(), label)
            check(not found, label + " executable names no build-machine path", label + " executable embeds a build-machine path: %s" % found[:3])
            # ADR-148 (P3): the Touch ID helper inside the app is the production build too (the unattended TEST
            # variant signs without asking anyone), checked the same way as the tarball's.
            # ADR-157: the app carries its own broker for Start at login. It is held to the tarball's rules: present
            # and executable, no build-machine path, one build stamp naming a commit (the expected one when given),
            # a clean tree unless this is a --dev check, and a minimum macOS no higher than the limit.
            daemon = os.path.join(app, "Contents", "MacOS", "credmgrd")
            if check(os.path.isfile(daemon) and os.access(daemon, os.X_OK), label + " carries an executable credmgrd (Contents/MacOS)",
                     label + " has no bundled credmgrd in Contents/MacOS (Start at login needs it)"):
                db = open(daemon, "rb").read()
                found = leaks_in(db, label + " credmgrd")
                check(not found, label + " credmgrd names no build-machine path", label + " credmgrd embeds a build-machine path: %s" % found[:3])
                dstamps = build_stamps(db)
                if not check(len(dstamps) == 1, label + " credmgrd carries one build stamp",
                             label + " credmgrd carries no build stamp (or several): %s" % (dstamps or "none")):
                    pass
                elif dstamps[0][0] == "none":
                    bad(label + " credmgrd was built without a commit (a development build)")
                else:
                    d_commit, d_dirty = dstamps[0]
                    ok("%s credmgrd is stamped with commit %s" % (label, d_commit[:12]))
                    if a.expect_commit:
                        check(a.expect_commit.startswith(d_commit) or d_commit.startswith(a.expect_commit),
                              label + " credmgrd stamp matches the expected commit",
                              "%s credmgrd is stamped %s, expected %s" % (label, d_commit[:12], a.expect_commit[:12]))
                    if d_dirty:
                        (note if a.allow_dev_build else bad)(label + " credmgrd was built from a DIRTY tree - a development build, never to be published")
                dmins = macho_minos(db)
                if dmins:
                    want = parse_ver(a.max_minos)
                    check(all(plat == 1 and ver3 <= want for plat, ver3 in dmins),
                          label + " credmgrd needs macOS %s or earlier" % a.max_minos,
                          label + " credmgrd needs a newer macOS than %s - set MACOSX_DEPLOYMENT_TARGET" % a.max_minos)
                else:
                    bad(label + " credmgrd is not a Mach-O file with a minimum macOS version")
            for helper in (os.path.join(app, "Contents", "MacOS", "credmgr-presence"),
                           os.path.join(app, "Contents", "Resources", "credmgr-presence")):
                if os.path.isfile(helper):
                    hb = open(helper, "rb").read()
                    check(b"credmgr-presence-variant:production" in hb and b"unattended-test" not in hb,
                          label + " carries the production Touch ID helper",
                          label + " carries a Touch ID helper that is not the production build")
        for z in appzips:
            tmp = tempfile.mkdtemp(prefix="cmz.")
            try:
                r = subprocess.run(["ditto", "-x", "-k", os.path.join(dist, z), tmp], capture_output=True, text=True)
                apps = [d for d in os.listdir(tmp) if d.endswith(".app")]
                if check(r.returncode == 0 and apps == ["CredMgr.app"], z + " unpacks to CredMgr.app", z + " does not unpack to a single CredMgr.app: " + r.stderr.strip()[:200]):
                    inspect_app(os.path.join(tmp, "CredMgr.app"), z, RE_APPZ.match(z).group("ver"))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        loose_app = os.path.join(dist, "CredMgr.app")
        if os.path.isdir(loose_app):
            vers = {RE_APPZ.match(z).group("ver") for z in appzips} | {RE_DMG.match(d).group("ver") for d in dmgs}
            inspect_app(loose_app, "dist/CredMgr.app", sorted(vers)[0] if len(vers) == 1 else "")
        for d in dmgs:
            r = subprocess.run(["hdiutil", "verify", os.path.join(dist, d)], capture_output=True, text=True)
            check(r.returncode == 0, d + " passes hdiutil verify", d + " fails hdiutil verify: " + (r.stdout + r.stderr).strip()[-200:])
            mnt = tempfile.mkdtemp(prefix="cmd.")
            attached = False
            try:
                r = subprocess.run(["hdiutil", "attach", "-nobrowse", "-readonly", "-noverify", "-mountpoint", mnt, os.path.join(dist, d)],
                                   capture_output=True, text=True)
                attached = r.returncode == 0
                if check(attached, d + " mounts read-only", d + " does not mount: " + r.stderr.strip()[:200]):
                    check(os.path.isdir(os.path.join(mnt, "CredMgr.app")), d + " contains CredMgr.app", d + " does not contain CredMgr.app")
                    if os.path.isdir(os.path.join(mnt, "CredMgr.app")):
                        inspect_app(os.path.join(mnt, "CredMgr.app"), d, RE_DMG.match(d).group("ver"))
            finally:
                if attached:
                    subprocess.run(["hdiutil", "detach", "-quiet", mnt], capture_output=True)
                shutil.rmtree(mnt, ignore_errors=True)
        if len(exe_hashes) > 1:
            check(len(set(exe_hashes.values())) == 1,
                  "every copy of the app (%s) holds the same executable" % ", ".join(sorted(exe_hashes)),
                  "the app copies differ: %s" % {k: v[:12] for k, v in sorted(exe_hashes.items())})

print()
if FAILED:
    print("VERIFY: %d FAILURE(S)" % len(FAILED))
    sys.exit(1)
print("VERIFY: ALL PASSED")
PYEOF
}

# ---------------------------------------------------------------------------------------------
# ADR-162: the Mac App Store edition. Everything below works on any host with python3 (the inspection is
# pure Python over plists and bytes), so release-selftest.sh --mas proves it on Linux; only building the
# bundle needs a Mac. The identifiers come from one file, packaging/mas/identity.conf.
RL_MAS_DIR_REL=packaging/mas
RL_MAS_ENTITLED="app credmgrd credmgr credmgr-presence"   # one .entitlements template each

rl_mas_identity() {    # <identity.conf> <KEY> -> prints the value (empty when absent)
  awk -F= -v k="$2" '/^[[:space:]]*#/ { next } $1 == k { sub(/^[^=]*=/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }' "$1"
}

rl_mas_render() {      # <template> <out> <identity.conf> <version>: fill @MAS_*@ and @VERSION@, refuse leftovers
  "$RL_PY" - "$@" <<'PY'
import re, sys
tpl, out, ident, version = sys.argv[1:5]
kv = {}
for line in open(ident):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1); kv[k.strip()] = v.strip()
for k in ("MAS_TEAM_ID", "MAS_BUNDLE_ID", "MAS_APP_GROUP_NAME"):
    if not kv.get(k):
        sys.exit("identity.conf has no %s" % k)
kv["MAS_APP_GROUP"] = kv["MAS_TEAM_ID"] + "." + kv["MAS_APP_GROUP_NAME"]
kv["VERSION"] = version
text = open(tpl).read()
text = re.sub(r"@([A-Z_]+)@", lambda m: kv.get(m.group(1), m.group(0)), text)
left = sorted(set(re.findall(r"@[A-Z_]+@", text)))
if left:
    sys.exit("%s: unknown token(s) left after rendering: %s" % (tpl, left))
open(out, "w").write(text)
PY
}

rl_mas_render_all() {  # <v2 dir> <out dir> <version>: entitlements, embedded Info.plists and the Tauri overlay
  local v2=$1 out=$2 version=$3 ident n
  ident="$v2/$RL_MAS_DIR_REL/identity.conf"
  mkdir -p "$out/entitlements" "$out/embedded" || return 1
  for n in $RL_MAS_ENTITLED; do
    rl_mas_render "$v2/$RL_MAS_DIR_REL/entitlements/$n.entitlements" "$out/entitlements/$n.entitlements" "$ident" "$version" || return 1
  done
  for n in credmgrd credmgr; do
    rl_mas_render "$v2/$RL_MAS_DIR_REL/embedded/$n-Info.plist" "$out/embedded/$n-Info.plist" "$ident" "$version" || return 1
  done
  cp "$ident" "$out/identity.conf" || return 1
  # The overlay holds no identifier of its own (identity.conf is the one place): it is injected here, with the
  # rendered app entitlements, and the base config's bundled files are kept by Tauri's JSON merge.
  "$RL_PY" - "$v2/apps/desktop/src-tauri/tauri.mas.conf.json" "$out/tauri.mas.conf.json" \
      "$(rl_mas_identity "$ident" MAS_BUNDLE_ID)" "$out/entitlements/app.entitlements" <<'PY'
import json, sys
src, dst, bundle_id, ent = sys.argv[1:5]
c = json.load(open(src))
c["identifier"] = bundle_id
c.setdefault("bundle", {}).setdefault("macOS", {})["entitlements"] = ent
json.dump(c, open(dst, "w"), indent=2)
PY
}

rl_mas_assemble() {    # <CredMgr.app>: the Info.plist keys App Store Connect reads that Tauri does not write
  "$RL_PY" - "$1" <<'PY'
import plistlib, sys
p = sys.argv[1] + "/Contents/Info.plist"
d = plistlib.load(open(p, "rb"))
# Export compliance (docs/27_APP_STORE.md section 7): CredMgr implements standard algorithms itself (XChaCha20-
# Poly1305, X25519, Argon2id, HMAC-SHA256, P-256) instead of calling Apple's, which Apple does not treat as exempt
# (documentation: the French declaration where sold in France). The answer is recorded in the bundle so every
# upload says the same; ITSEncryptionExportComplianceCode is added once Apple issues one.
d["ITSAppUsesNonExemptEncryption"] = True
d.setdefault("LSApplicationCategoryType", "public.app-category.developer-tools")
plistlib.dump(d, open(p, "wb"))
PY
}

# Inspects an assembled MAS distribution directory (CredMgr.app, entitlements/, identity.conf) - the release
# verifier's rules, adapted: no signature to check yet (signing waits on the operator's certificates), and the
# sandbox-specific facts instead. --strict is the submission gate: placeholder ids and a missing provisioning
# profile become failures. --expect-version V, --allow-dev-build as for rl_verify.
rl_mas_inspect() {
  "$RL_PY" - "$@" <<'PYEOF'
import argparse, os, plistlib, re, sys

ap = argparse.ArgumentParser()
ap.add_argument("dist")
ap.add_argument("--strict", action="store_true")
ap.add_argument("--expect-version")
ap.add_argument("--allow-dev-build", action="store_true")
a = ap.parse_args()
dist = os.path.abspath(a.dist)

FAILED = []
def ok(m): print("  PASS  " + m)
def bad(m): FAILED.append(m); print("  FAIL  " + m)
def note(m): print("  NOTE  " + m)
def check(cond, good, fail):
    (ok if cond else bad)(good if cond else fail)
    return bool(cond)
def load(path, what):
    try:
        return plistlib.load(open(path, "rb"))
    except Exception as e:
        bad("%s is not a readable property list: %s" % (what, str(e)[:120]))
        return None

ident = {}
ipath = os.path.join(dist, "identity.conf")
if check(os.path.isfile(ipath), "identity.conf (the ids this build used) is beside the app", "identity.conf is missing from the MAS dist"):
    for line in open(ipath):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1); ident[k.strip()] = v.strip()
TEAM, BUNDLE, NAME = ident.get("MAS_TEAM_ID", ""), ident.get("MAS_BUNDLE_ID", ""), ident.get("MAS_APP_GROUP_NAME", "")
GROUP = TEAM + "." + NAME
check(re.fullmatch(r"[A-Z0-9]{10}", TEAM or ""), "the team id has the shape of a Team ID", "MAS_TEAM_ID %r is not ten upper-case letters or digits" % TEAM)
check(re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", BUNDLE or ""), "the bundle id is reverse-DNS", "MAS_BUNDLE_ID %r is not a reverse-DNS id" % BUNDLE)
placeholder = TEAM == "XXXXXXXXXX" or ident.get("MAS_IDS_FINAL") != "yes"
if placeholder:
    (bad if a.strict else note)("the ids are PLACEHOLDERS (identity.conf, MAS_IDS_FINAL=%s): this bundle cannot be signed or submitted until the operator chooses them" % ident.get("MAS_IDS_FINAL"))
else:
    ok("identity.conf is marked final")

# The 104-byte sun_path limit (crates/store paths.rs SOCKET_PATH_MAX), for a 30-character user name.
sock = "/Users/" + "a" * 30 + "/Library/Group Containers/" + GROUP + "/vault/run/broker.sock"
check(len(sock) <= 103, "the broker socket path fits the 104-byte limit (%d bytes for a 30-character user name)" % len(sock),
      "the app-group id %r makes the socket path %d bytes for a 30-character user name; the limit is 103 - shorten MAS_APP_GROUP_NAME" % (GROUP, len(sock)))

# ---- entitlements: exactly these keys, per executable --------------------------------------------------
WANT = {
    "app": {"com.apple.security.app-sandbox", "com.apple.security.application-groups",
            "com.apple.application-identifier", "com.apple.developer.team-identifier"},
    "credmgrd": {"com.apple.security.app-sandbox", "com.apple.security.application-groups"},
    "credmgr": {"com.apple.security.app-sandbox", "com.apple.security.application-groups"},
    "credmgr-presence": {"com.apple.security.app-sandbox", "com.apple.security.inherit"},
}
for n, want in sorted(WANT.items()):
    p = os.path.join(dist, "entitlements", n + ".entitlements")
    if not check(os.path.isfile(p), "%s.entitlements is present" % n, "%s.entitlements is missing" % n):
        continue
    raw = open(p).read()
    if not check("@" not in re.sub(r"<!--.*?-->", "", raw, flags=re.S), "%s.entitlements is fully rendered" % n, "%s.entitlements still holds an @TOKEN@" % n):
        continue
    d = load(p, n + ".entitlements")
    if d is None:
        continue
    keys = set(d)
    check(keys == want, "%s.entitlements carries exactly %s" % (n, sorted(k.rsplit(".", 1)[-1] for k in want)),
          "%s.entitlements carries %s; expected exactly %s" % (n, sorted(keys), sorted(want)))
    net = sorted(k for k in keys if "network" in k)
    check(not net, "%s has no network entitlement" % n, "%s carries a network entitlement %s (ADR-001: none, ever, on the broker)" % (n, net))
    check(d.get("com.apple.security.app-sandbox") is True, "%s is sandboxed" % n, "%s does not set app-sandbox to true" % n)
    if "com.apple.security.application-groups" in want:
        check(d.get("com.apple.security.application-groups") == [GROUP], "%s names the one app group %s" % (n, GROUP),
              "%s names app groups %r, expected [%r]" % (n, d.get("com.apple.security.application-groups"), GROUP))
    if n == "credmgr-presence":
        check(d.get("com.apple.security.inherit") is True, "credmgr-presence inherits its parent's sandbox", "credmgr-presence does not set inherit to true")
    if n == "app":
        check(d.get("com.apple.application-identifier") == TEAM + "." + BUNDLE and d.get("com.apple.developer.team-identifier") == TEAM,
              "the app's identity keys name %s.%s" % (TEAM, BUNDLE), "the app's identity keys do not match identity.conf")

# ---- the bundle ------------------------------------------------------------------------------------------
app = os.path.join(dist, "CredMgr.app")
if not check(os.path.isdir(app), "CredMgr.app is present", "CredMgr.app is missing from the MAS dist"):
    print(); print("MAS INSPECT: %d FAILURE(S)" % len(FAILED)); sys.exit(1)
C = os.path.join(app, "Contents")
info = load(os.path.join(C, "Info.plist"), "Info.plist") if os.path.isfile(os.path.join(C, "Info.plist")) else None
if info is None:
    bad("CredMgr.app has no readable Info.plist"); info = {}
check(info.get("CFBundleIdentifier") == BUNDLE, "the bundle identifier is %s" % BUNDLE, "the bundle identifier is %r, identity.conf says %r" % (info.get("CFBundleIdentifier"), BUNDLE))
if a.expect_version:
    check(info.get("CFBundleShortVersionString") == a.expect_version, "the app is version %s" % a.expect_version,
          "the app says version %r, expected %s" % (info.get("CFBundleShortVersionString"), a.expect_version))
check(str(info.get("LSApplicationCategoryType", "")).startswith("public.app-category."), "Info.plist names an App Store category",
      "Info.plist has no LSApplicationCategoryType (App Store Connect refuses the upload)")
check(info.get("ITSAppUsesNonExemptEncryption") is True, "Info.plist answers export compliance (ITSAppUsesNonExemptEncryption = true: own standard crypto)",
      "Info.plist does not set ITSAppUsesNonExemptEncryption to true (CredMgr implements its own standard crypto: docs/27_APP_STORE.md section 7)")
def ver(s):
    try: return tuple(int(x) for x in str(s).split("."))
    except ValueError: return (0,)
check(ver(info.get("LSMinimumSystemVersion", "0")) >= (13, 0), "the minimum macOS is 13 or later (SMAppService)",
      "LSMinimumSystemVersion %r is below 13.0, where SMAppService does not exist" % info.get("LSMinimumSystemVersion"))
upd = sorted(k for k in info if k.startswith("SU"))
check(not upd, "no self-updater keys (2.4.5(vii): updates come from the Mac App Store)", "Info.plist carries updater keys %s" % upd)

exe_name = info.get("CFBundleExecutable", "")
macos = os.path.join(C, "MacOS")
want_exes = {exe_name, "credmgrd", "credmgr", "credmgr-presence"}
have = set(os.listdir(macos)) if os.path.isdir(macos) else set()
check(have == want_exes, "Contents/MacOS holds exactly the app, credmgrd, credmgr and credmgr-presence",
      "Contents/MacOS holds %s; expected %s" % (sorted(have), sorted(want_exes)))

LEAK_RE = re.compile(rb"/Users/[^/\0\s\"']+/|/home/[a-z_][a-z0-9_-]*/|/private/var/folders/")
STAMP_RE = re.compile(rb"credmgr-build-stamp:v1:commit=([0-9a-f]{12,64}|none):dirty=([01])")
for n in sorted(want_exes):
    p = os.path.join(macos, n)
    if not os.path.isfile(p):
        continue
    b = open(p, "rb").read()
    check(os.access(p, os.X_OK), "%s is executable" % n, "%s is not executable" % n)
    found = sorted({m.group(0).decode("utf-8", "replace") for m in LEAK_RE.finditer(b)})
    check(not found, "%s names no build-machine path" % n, "%s embeds a build-machine path: %s" % (n, found[:3]))
    if n == "credmgr-presence":
        check(b"credmgr-presence-variant:production" in b and b"unattended-test" not in b,
              "credmgr-presence is the production Touch ID helper", "credmgr-presence is not the production build")
        continue
    # A binary built with the `mas` feature reads packaging/mas/identity.conf at run time, so its text is in
    # the bytes; a Developer ID build (the wrong flavour: it would look for the vault outside the sandbox) has none.
    check(b"MAS_APP_GROUP_NAME=" in b, "%s was built as the MAS flavour (it carries identity.conf)" % n,
          "%s was not built with the mas feature: it would look for the vault outside the sandbox" % n)
    if n in ("credmgrd", "credmgr"):
        st = sorted({(m.group(1).decode(), m.group(2) == b"1") for m in STAMP_RE.finditer(b)})
        if check(len(st) == 1, "%s carries one build stamp" % n, "%s carries no build stamp (or several)" % n):
            if st[0][0] == "none" or st[0][1]:
                (note if a.allow_dev_build else bad)("%s is a development build (no commit, or a dirty tree)" % n)

agent = os.path.join(C, "Library", "LaunchAgents", "com.credmgr.brokerd.plist")
if check(os.path.isfile(agent), "the SMAppService agent plist is in Contents/Library/LaunchAgents", "Contents/Library/LaunchAgents/com.credmgr.brokerd.plist is missing (Start at login cannot register)"):
    d = load(agent, "the agent plist") or {}
    check(d.get("Label") == "com.credmgr.brokerd", "the agent's Label is com.credmgr.brokerd", "the agent's Label is %r" % d.get("Label"))
    bp = d.get("BundleProgram", "")
    check(bp == "Contents/MacOS/credmgrd" and os.path.isfile(os.path.join(app, bp)),
          "the agent's BundleProgram is the bundled Contents/MacOS/credmgrd", "the agent's BundleProgram is %r, not the bundled broker" % bp)
    extra = sorted(set(d) & {"Program", "ProgramArguments", "UserName", "GroupName", "StandardOutPath", "StandardErrorPath", "RootDirectory"})
    check(not extra, "the agent names nothing outside the bundle and never a user", "the agent plist carries %s" % extra)

pm = os.path.join(C, "Resources", "PrivacyInfo.xcprivacy")
REASONS = {
    "NSPrivacyAccessedAPICategoryFileTimestamp": {"DDA9.1", "C617.1", "3B52.1", "0A2A.1"},
    "NSPrivacyAccessedAPICategorySystemBootTime": {"35F9.1", "8FFB.1", "3D61.1"},
    "NSPrivacyAccessedAPICategoryDiskSpace": {"85F4.1", "E174.1", "7D9E.1", "B728.1"},
    "NSPrivacyAccessedAPICategoryUserDefaults": {"CA92.1", "1C8F.1", "C56D.1", "AC6B.1"},
    "NSPrivacyAccessedAPICategoryActiveKeyboards": {"3EC4.1", "54BD.1"},
}
if check(os.path.isfile(pm), "the privacy manifest is in Contents/Resources", "Contents/Resources/PrivacyInfo.xcprivacy is missing"):
    d = load(pm, "the privacy manifest") or {}
    check(d.get("NSPrivacyTracking") is False and d.get("NSPrivacyTrackingDomains") == [], "the privacy manifest declares no tracking",
          "the privacy manifest declares tracking or tracking domains")
    check(d.get("NSPrivacyCollectedDataTypes") == [], "the privacy manifest declares no collected data", "the privacy manifest declares collected data types")
    for e in d.get("NSPrivacyAccessedAPITypes", []):
        cat, rs = e.get("NSPrivacyAccessedAPIType"), e.get("NSPrivacyAccessedAPITypeReasons", [])
        check(cat in REASONS and rs and set(rs) <= REASONS[cat], "required-reason API %s declared with %s" % (str(cat).replace("NSPrivacyAccessedAPICategory", ""), rs),
              "required-reason API entry %r / %r is not a category and reason Apple defines" % (cat, rs))

prof = os.path.join(C, "embedded.provisionprofile")
if os.path.isfile(prof):
    ok("a provisioning profile is embedded")
else:
    (bad if a.strict else note)("no Contents/embedded.provisionprofile: the operator's Mac App Store profile goes in at signing (sign-notarise.sh --mas)")
check(not [f for f in os.listdir(dist) if f.endswith(".dmg")], "no .dmg in the MAS dist (the store takes a signed .pkg)", "a .dmg is in the MAS dist")

print()
if FAILED:
    print("MAS INSPECT: %d FAILURE(S)" % len(FAILED)); sys.exit(1)
print("MAS INSPECT: ALL PASSED")
PYEOF
}
