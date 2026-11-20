#!/usr/bin/env bash
# Build credmgr-presence (ADR-098). Usage: build.sh [--test-noauth] [OUT_DIR]
#   default OUT_DIR = v2/target/native; the binary is OUT_DIR/credmgr-presence.
#   --test-noauth  builds the TEST variant (keys without a user-presence prompt) as credmgr-presence-test,
#                  for automated tests only. It is never packaged (release.sh refuses to ship it).
# Needs Xcode's swiftc. Targets macOS 13.1 on Apple Silicon, ad-hoc signed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME=credmgr-presence; EXTRA=()
if [[ "${1:-}" == "--test-noauth" ]]; then NAME=credmgr-presence-test; EXTRA=(-D TESTNOAUTH); shift; fi
OUT="${1:-$HERE/../../../target/native}"; mkdir -p "$OUT"
swiftc -O -target arm64-apple-macos13.1 "${EXTRA[@]}" "$HERE/main.swift" -o "$OUT/$NAME"
codesign --force --sign - "$OUT/$NAME" >/dev/null 2>&1 || true
echo "$OUT/$NAME"
