#!/usr/bin/env bash
# Sign, notarise and staple a CredMgr macOS release (operator-run; needs an Apple Developer account).
#
#   scripts/sign-notarise.sh --identity "Developer ID Application: Name (TEAMID)" --profile credmgr-notary [--dry-run]
#
# What it does, in order, on the artefacts `release.sh` and `release-app.sh` left in dist/:
#   1. signs every executable with the hardened runtime and a secure timestamp: bin/credmgr, bin/credmgrd,
#      bin/credmgr-presence in the tarball staging tree, then the Touch ID helper and the bundled broker
#      (credmgrd, ADR-157) inside CredMgr.app, then the app itself (inside-out, never --deep for signing);
#   2. verifies the signatures (codesign --verify --strict, spctl);
#   3. submits the app (zipped) and the tarball's binaries (zipped) to Apple's notary service and waits;
#   4. staples the ticket to CredMgr.app, rebuilds and signs the DMG, notarises and staples it;
#   5. re-writes dist/SHA256SUMS.
#
# It never reads a credential from a file or prints one. The notary login is a keychain profile you created
# once with:  xcrun notarytool store-credentials credmgr-notary --apple-id <id> --team-id <TEAMID>
# (it asks for an app-specific password and stores it in your login keychain; credmgr is a fine place to
# keep the original). Nothing here changes the source tree; the unsigned artefacts stay reproducible.
#
# Prerequisites the script checks: Xcode command-line tools, a "Developer ID Application" identity in the
# keychain, the notary profile, and a dist/ built by release.sh and release-app.sh at the same commit.
# Without an Apple Developer account none of this can run; that is by design, not an omission.
#
# --mas (ADR-162): the Mac App Store path, DOCUMENTED AND NOT ENABLED. It runs only with --dry-run, which prints
# every step against dist-mas/ (from `release-app.sh --mas`); a real run refuses until the operator has the
# certificates, the provisioning profile and final ids (docs/27_APP_STORE.md, operator checklist), and then the
# guard below is removed in the same change that is first pressed on a Mac. The steps, in order:
#   scripts/sign-notarise.sh --mas --identity "Apple Distribution: Name (TEAMID)" \
#       --installer-identity "3rd Party Mac Developer Installer: Name (TEAMID)" \
#       --profile-file CredMgr_MAS.provisionprofile --dry-run
#   1. refuses unless `release-app.sh --mas --verify --strict` passes (final ids, no placeholders);
#   2. embeds the provisioning profile as Contents/embedded.provisionprofile;
#   3. signs inside-out, never --deep, each executable with ITS OWN rendered entitlements and identifier:
#      credmgr-presence (sandbox + inherit), credmgrd and credmgr (own sandbox + app group; identifiers
#      <bundle id>.brokerd / .cli, the same strings as their linked Info.plist), then the app itself;
#      no --options runtime is needed for the store, and no notarisation: App Store Connect processes the upload;
#   4. verifies (codesign --verify --strict, and prints each executable's entitlements back);
#   5. builds the installer package: productbuild --component CredMgr.app /Applications --sign <installer identity>;
#   6. uploads nothing: the operator uploads the .pkg with Transporter (or `xcrun altool --upload-app`) themselves.
set -euo pipefail
V2="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$V2/dist"
IDENTITY="" PROFILE="" DRY=0 MAS=0 INSTALLER="" PROFILE_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity) IDENTITY="$2"; shift 2 ;;
    --profile)  PROFILE="$2"; shift 2 ;;
    --dry-run)  DRY=1; shift ;;
    --mas)      MAS=1; shift ;;
    --installer-identity) INSTALLER="$2"; shift 2 ;;
    --profile-file) PROFILE_FILE="$2"; shift 2 ;;
    -h|--help)  sed -n '2,42p' "$0"; exit 0 ;;
    *) echo "sign-notarise: unknown argument $1" >&2; exit 2 ;;
  esac
done
if [[ $MAS -eq 1 ]]; then
  # ---- ADR-162: the Mac App Store path. Documented, dry-run only (see the header). ----------------------
  [[ $DRY -eq 1 ]] || { echo "sign-notarise: --mas is documented, not enabled: it runs only with --dry-run until the operator's MAS certificates, provisioning profile and final ids exist (docs/27_APP_STORE.md)" >&2; exit 1; }
  [[ -n "$IDENTITY" && -n "$INSTALLER" && -n "$PROFILE_FILE" ]] || { echo "usage: sign-notarise.sh --mas --identity <Apple Distribution: ...> --installer-identity <3rd Party Mac Developer Installer: ...> --profile-file <file.provisionprofile> --dry-run" >&2; exit 2; }
  DM="$V2/dist-mas"; APP="$DM/CredMgr.app"; ENTS="$DM/entitlements"
  [[ -d "$APP" && -d "$ENTS" ]] || { echo "sign-notarise: $DM is incomplete; run scripts/release-app.sh --mas first" >&2; exit 1; }
  BUNDLE_ID=$(awk -F= '$1 == "MAS_BUNDLE_ID" { print $2 }' "$DM/identity.conf")
  p() { printf '+'; printf ' %q' "$@"; echo; }
  echo "== 1. the submission gate";  p "$V2/scripts/release-app.sh" --mas --verify "$DM" --strict
  echo "== 2. provisioning profile"; p cp "$PROFILE_FILE" "$APP/Contents/embedded.provisionprofile"
  echo "== 3. sign inside-out, each with its own entitlements"
  p codesign --force --timestamp --sign "$IDENTITY" --entitlements "$ENTS/credmgr-presence.entitlements" "$APP/Contents/MacOS/credmgr-presence"
  p codesign --force --timestamp --sign "$IDENTITY" --identifier "$BUNDLE_ID.brokerd" --entitlements "$ENTS/credmgrd.entitlements" "$APP/Contents/MacOS/credmgrd"
  p codesign --force --timestamp --sign "$IDENTITY" --identifier "$BUNDLE_ID.cli" --entitlements "$ENTS/credmgr.entitlements" "$APP/Contents/MacOS/credmgr"
  p codesign --force --timestamp --sign "$IDENTITY" --entitlements "$ENTS/app.entitlements" "$APP"
  echo "== 4. verify";               p codesign --verify --strict --verbose=2 "$APP"
  for exe in credmgr-presence credmgrd credmgr; do p codesign -d --entitlements - "$APP/Contents/MacOS/$exe"; done
  echo "== 5. installer package";    p productbuild --component "$APP" /Applications --sign "$INSTALLER" "$DM/CredMgr.pkg"
  echo "== 6. upload: by the operator, with Transporter (nothing is uploaded from here)"
  exit 0
fi

[[ -n "$IDENTITY" && -n "$PROFILE" ]] || { echo "usage: sign-notarise.sh --identity <Developer ID Application: ...> --profile <notarytool keychain profile> [--dry-run]" >&2; exit 2; }

run() { if [[ $DRY -eq 1 ]]; then printf '+ %q' "$@"; echo; else "$@"; fi; }
die() { echo "sign-notarise: $*" >&2; exit 1; }

[[ "$(uname)" = Darwin ]] || die "macOS only"
command -v codesign >/dev/null && command -v xcrun >/dev/null || die "Xcode command-line tools are required"
if [[ $DRY -eq 0 ]]; then
  security find-identity -v -p codesigning | grep -F "$IDENTITY" >/dev/null || die "no code-signing identity named '$IDENTITY' in the keychain"
  xcrun notarytool history --keychain-profile "$PROFILE" >/dev/null 2>&1 || die "the notary keychain profile '$PROFILE' does not work (xcrun notarytool store-credentials ...)"
fi

APP="$DIST/CredMgr.app"
[[ -d "$APP" ]] || die "$APP is missing; run scripts/release-app.sh first"
TAR=$(ls "$DIST"/credmgr-*-aarch64-apple-darwin.tar.gz 2>/dev/null | head -1 || true)
[[ -n "$TAR" ]] || die "the CLI tarball is missing in dist/; run scripts/release.sh first"
ENT="$V2/apps/desktop/src-tauri/entitlements.plist"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/credmgr-sign.XXXXXX"); trap 'rm -rf "$WORK"' EXIT

SIGN=(codesign --force --options runtime --timestamp --sign "$IDENTITY")

echo "== 1. sign the app, inside-out"
for exe in "$APP/Contents/MacOS/credmgr-presence" "$APP/Contents/MacOS/credmgrd"; do
  [[ -f "$exe" ]] && run "${SIGN[@]}" "$exe"
done
MAIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist")"
run "${SIGN[@]}" --entitlements "$ENT" "$MAIN"
run "${SIGN[@]}" --entitlements "$ENT" "$APP"

echo "== 1b. sign the CLI tarball's binaries"
tar -xzf "$TAR" -C "$WORK"
TREE=$(find "$WORK" -maxdepth 1 -mindepth 1 -type d | head -1)
for b in credmgr credmgrd credmgr-presence; do
  [[ -f "$TREE/bin/$b" ]] && run "${SIGN[@]}" "$TREE/bin/$b"
done
# ADR-148 (P3): signing changed the binaries' bytes, so the tarball's own SHA256SUMS is rewritten (same rule
# as release.sh: every file but itself, sorted bytewise) - otherwise the shipped tree fails its own check.
if [[ $DRY -eq 1 ]]; then
  echo "+ (rewrite $TREE/SHA256SUMS over the re-signed tree)"
else
  ( cd "$TREE" && export LC_ALL=C && rm -f SHA256SUMS
    FILES=$(find . -type f | sed 's|^\./||' | sort)
    printf '%s\n' "$FILES" | while IFS= read -r f; do shasum -a 256 -- "$f"; done > SHA256SUMS ) \
    || die "could not rewrite the tarball's SHA256SUMS"
fi

echo "== 2. verify"
run codesign --verify --deep --strict --verbose=2 "$APP"
run spctl --assess --type execute --verbose=2 "$APP"

echo "== 3. notarise (the app, then the binaries)"
run ditto -c -k --keepParent "$APP" "$WORK/app.zip"
run xcrun notarytool submit "$WORK/app.zip" --keychain-profile "$PROFILE" --wait
run ditto -c -k --keepParent "$TREE/bin" "$WORK/bin.zip"
run xcrun notarytool submit "$WORK/bin.zip" --keychain-profile "$PROFILE" --wait

echo "== 4. staple, repackage"
run xcrun stapler staple "$APP"
VER=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")
DMG="$DIST/credmgr-desktop-$VER-aarch64-apple-darwin.dmg"
run rm -f "$DMG"
run hdiutil create -volname "CredMgr" -srcfolder "$APP" -ov -format UDZO "$DMG"
run codesign --force --timestamp --sign "$IDENTITY" "$DMG"
run xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait
run xcrun stapler staple "$DMG"
run ditto -c -k --keepParent --norsrc --noextattr --noqtn --noacl "$APP" "$DIST/credmgr-desktop-$VER-aarch64-apple-darwin.app.zip"
# Repack the signed CLI tree over the original tarball name.
run tar -czf "$TAR" -C "$WORK" "$(basename "$TREE")"

echo "== 5. checksums"
# ADR-148 (P3): a failure here is a failure (it used to be swallowed by `|| true`).
( cd "$DIST" && run shasum -a 256 credmgr-* > SHA256SUMS ) || die "could not write dist/SHA256SUMS"
echo "done. Publish the notarised files from dist/; the unsigned originals are the ones in the previous release."
