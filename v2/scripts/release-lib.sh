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
# The verifier never executes what it checks unless --run-binaries is given; without it the
# binaries are inspected as bytes only (stamp, architecture, paths) and the --version check is skipped.
# Exit 0 only when every check passed. Output is one PASS/FAIL line per fact, like e2e-journey.sh.
rl_verify() {
  "$RL_PY" - "$@" <<'PYEOF'
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
        need = ["bin/credmgr", "bin/credmgrd", "packaging/com.credmgr.brokerd.plist", "RELEASE.md", "CHANGELOG.md",
                "SECURITY.md", "LICENSE", "SHA256SUMS", "sbom/credmgr-%s-sbom-credmgr.cdx.json" % ver,
                "sbom/credmgr-%s-sbom-credmgrd.cdx.json" % ver]
        for rel in need:
            check(os.path.isfile(os.path.join(root, rel)), "tarball holds " + rel, "tarball is missing " + rel)
        for rel in ("bin/credmgr", "bin/credmgrd"):
            p = os.path.join(root, rel)
            if os.path.isfile(p):
                check(os.access(p, os.X_OK), rel + " is executable", rel + " is not executable")
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
        for b in ("credmgr", "credmgrd"):
            p = os.path.join(root, "bin", b)
            if not os.path.isfile(p):
                continue
            data = open(p, "rb").read()
            found = leaks_in(data, b)
            check(not found, "bin/%s names no build-machine path" % b, "bin/%s embeds a build-machine path: %s" % (b, found[:3]))
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
