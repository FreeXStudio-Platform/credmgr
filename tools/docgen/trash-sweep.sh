#!/bin/sh
# trash-sweep.sh — gated permanent removal of aged doc-trash folders.
# Policy (docs/DOC_MASTER_CHECKLIST.md §4): "delete" NEVER means rm at archive time.
# Duplicates/wrong docs move to docs/archives/_trash/<YYYY-MM-DD>/ with a WHY.md;
# this sweep permanently removes only _trash date-folders OLDER THAN 7 DAYS,
# and only when run manually (or by an operator-scheduled task). Never automatic
# on the same day — the 7-day window is the cooling-off period for restores.
#
# Usage:  sh tools/docgen/trash-sweep.sh          # dry-run (default): list what would be removed
#         sh tools/docgen/trash-sweep.sh --apply  # actually remove aged folders
set -eu

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
TRASH_DIR="$REPO_ROOT/docs/archives/_trash"
RETENTION_DAYS=7
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

[ -d "$TRASH_DIR" ] || { echo "trash-sweep: nothing to sweep ($TRASH_DIR absent)"; exit 0; }

NOW_EPOCH=$(date +%s)
SWEPT=0
for d in "$TRASH_DIR"/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    # folder names are YYYY-MM-DD; skip anything else
    case "$name" in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
        *) echo "trash-sweep: SKIP non-date folder: $name"; continue ;;
    esac
    # BSD (macOS) date first, GNU date fallback
    folder_epoch=$(date -j -f "%Y-%m-%d" "$name" +%s 2>/dev/null || date -d "$name" +%s 2>/dev/null) || {
        echo "trash-sweep: SKIP unparseable date: $name"; continue; }
    age_days=$(( (NOW_EPOCH - folder_epoch) / 86400 ))
    if [ "$age_days" -gt "$RETENTION_DAYS" ]; then
        if [ "$APPLY" -eq 1 ]; then
            rm -rf "$d"
            echo "trash-sweep: REMOVED $name (age ${age_days}d > ${RETENTION_DAYS}d)"
        else
            echo "trash-sweep: would remove $name (age ${age_days}d > ${RETENTION_DAYS}d) — rerun with --apply"
        fi
        SWEPT=$((SWEPT + 1))
    else
        echo "trash-sweep: KEEP $name (age ${age_days}d <= ${RETENTION_DAYS}d retention)"
    fi
done
[ "$SWEPT" -eq 0 ] && echo "trash-sweep: nothing aged out."
exit 0
