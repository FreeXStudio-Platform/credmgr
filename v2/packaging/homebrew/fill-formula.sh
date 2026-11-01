#!/usr/bin/env bash
# Fill the Homebrew formula template from a release's SHA256SUMS.
#
#   packaging/homebrew/fill-formula.sh [--sums FILE] [--repo OWNER/REPO] [--out FILE]
#
#   --sums   the SHA256SUMS that scripts/release.sh wrote (default: ../../dist/SHA256SUMS)
#   --repo   the GitHub repository whose Releases hold the tarball (default: FreeXStudio-Platform/credmgr)
#   --out    where to write the filled formula (default: standard output)
#
# Reads the line for credmgr-<version>-aarch64-apple-darwin.tar.gz, writes a copy of credmgr.rb with
# {{VERSION}} and the all-zero sha256 replaced, and checks the result: no {{PLACEHOLDER}} left, a
# 64-hex hash, and `ruby -c` accepts it. It NEVER edits the template, and it publishes nothing - the
# filled file is what a maintainer commits to the tap repository as Formula/credmgr.rb.
#
# The hash must come from the SHA256SUMS that is PUBLISHED with the release, not from a build the
# maintainer just made on their own machine: Homebrew users download the uploaded file, and a rebuild
# may differ in bytes (compression, signing) from the one that was checked.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/credmgr.rb"
SUMS="$HERE/../../dist/SHA256SUMS"
REPO="FreeXStudio-Platform/credmgr"
OUT=""
die() { echo "fill-formula: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sums) SUMS="${2:?--sums needs a file}"; shift ;;
    --repo) REPO="${2:?--repo needs OWNER/REPO}"; shift ;;
    --out)  OUT="${2:?--out needs a file}"; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

[[ -f "$TEMPLATE" ]] || die "template not found: $TEMPLATE"
[[ -f "$SUMS" ]] || die "no SHA256SUMS at $SUMS (pass --sums, or run scripts/release.sh first)"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repo must look like OWNER/REPO, got '$REPO'"
if [[ -n "$OUT" ]]; then
  [[ "$(cd "$(dirname "$OUT")" 2>/dev/null && pwd)/$(basename "$OUT")" != "$TEMPLATE" ]] || die "refusing to overwrite the template"
fi

LINES=$(grep -E '^[0-9a-f]{64}  credmgr-[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?-aarch64-apple-darwin\.tar\.gz$' "$SUMS" || true)
COUNT=$(printf '%s' "$LINES" | grep -c . || true)
[[ "$COUNT" -eq 1 ]] || die "expected exactly one credmgr-<version>-aarch64-apple-darwin.tar.gz line in $SUMS, found $COUNT"
SHA=${LINES%%  *}
FILE=${LINES#*  }
VERSION=${FILE#credmgr-}; VERSION=${VERSION%-aarch64-apple-darwin.tar.gz}
[[ "$SHA" =~ ^[0-9a-f]{64}$ ]] || die "not a sha256: $SHA"
[[ "$SHA" != 0000000000000000000000000000000000000000000000000000000000000000 ]] || die "refusing an all-zero hash"

# The template's own header ("TEMPLATE. Prepared, not published...") is replaced by a note that is true
# of the filled file, so the tap does not carry a header that talks about a file it is not.
NOTE1="# Generated from v2/packaging/homebrew/credmgr.rb by fill-formula.sh for credmgr $VERSION."
NOTE2="# Installs the prebuilt, UNSIGNED release tarball; it builds nothing. Do not edit by hand - regenerate."
BODY=""; skip=0
while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    "# --- template note"*)     BODY+="$NOTE1"$'\n'"$NOTE2"$'\n'; skip=1; continue ;;
    "# --- end template note"*) skip=0; continue ;;
  esac
  if [[ $skip -eq 0 ]]; then BODY+="$line"$'\n'; fi
done < "$TEMPLATE"
FILLED=$(printf '%s' "$BODY" | sed -e "s|{{VERSION}}|$VERSION|g" \
                                   -e "s|sha256 \"0\{64\}\"|sha256 \"$SHA\"|" \
                                   -e "s|FreeXStudio-Platform/credmgr|$REPO|g")

# (here-strings, never `| grep -q`: under pipefail grep exiting at its first match can SIGPIPE the producer)
if grep -qE '[{][{][A-Z0-9_]+[}][}]' <<<"$FILLED"; then
  die "a placeholder is still unreplaced: $(grep -oE '[{][{][A-Z0-9_]+[}][}]' <<<"$FILLED" | sort -u | tr '\n' ' ')"
fi
if grep -qE '"0{64}"' <<<"$FILLED"; then die "the all-zero placeholder hash is still in the formula"; fi
grep -qF "sha256 \"$SHA\"" <<<"$FILLED" || die "the hash did not land in the formula"
grep -qF "download/v$VERSION/credmgr-$VERSION-aarch64-apple-darwin.tar.gz" <<<"$FILLED" || die "the URL did not take the version"
if command -v ruby >/dev/null 2>&1; then
  printf '%s\n' "$FILLED" | ruby -c >/dev/null || die "the filled formula is not valid Ruby"
fi

if [[ -n "$OUT" ]]; then
  printf '%s\n' "$FILLED" > "$OUT"
  echo "fill-formula: wrote $OUT  (credmgr $VERSION, sha256 ${SHA:0:12}..., repo $REPO)" >&2
else
  printf '%s\n' "$FILLED"
fi
