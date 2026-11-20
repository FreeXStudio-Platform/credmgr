#!/usr/bin/env bash
# Visual capture of Settings › Agents › "Requests from agents" and the "Confirm it is you" dialog (RELEASE_VERIFICATION §16a).
# No page.screenshot: in WebKit it injects a <style>, which the app's CSP refuses (the harness fails on any CSP report).
# Playwright's video screencast records without touching the DOM; tests/e2e/visual-capture-switchboard.spec.ts notes the
# time of each capture point and ffmpeg pulls those frames. Usage: scripts/visual-capture.sh <out-dir>   (needs ffmpeg)
set -euo pipefail
out=${1:?usage: scripts/visual-capture.sh <out-dir>}
mkdir -p "$out"
cd "$(dirname "$0")/.."
npm run build:test >/dev/null
for size in 1440 narrow; do
  CREDMGR_SHOTS="$out" CREDMGR_SHOTS_SIZE="$size" npx playwright test tests/e2e/visual-capture-switchboard.spec.ts --project=webkit --workers=1
done
python3 - "$out" <<'PY'
import glob, json, subprocess, sys
out = sys.argv[1]
for f in sorted(glob.glob(f"{out}/*.json")):
    d = json.load(open(f))
    for name, t in d["marks"].items():
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-ss", str(t), "-i", d["video"], "-frames:v", "1", f"{out}/{name}.png"], check=True)
        print(f"{out}/{name}.png")
PY
