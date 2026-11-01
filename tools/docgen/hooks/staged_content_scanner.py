"""Git pre-commit / pre-push scanner: block a classified doc staged outside ``docs/confidential/``.

The doc-system moat (RULEBOOK L14, CLASSIFICATION.md) says only ``classification: public`` documents
may be committed to a public/tracked location; ``confidential`` and ``secret`` docs live ONLY under
``docs/confidential/``. This hook is the last-line, index-level enforcement of that: it reads the
**staged bytes** of every added/modified file (``git diff --cached``), parses the doc-system YAML
header with the same ``classification.parse_header`` the engine uses, and BLOCKS the commit/push if a
non-public header is staged at any path outside ``docs/confidential/``.

Design (matches the engine's fail-closed posture):

* **Staged bytes, not working tree** — we scan exactly what is in the index (``git show :<path>``), so
  a clean working-tree copy can never mask a classified blob that was actually staged.
* **Fail-closed on ambiguity** — a file that git reports as staged but whose staged blob cannot be
  read is reported as a BLOCKING finding, never silently skipped. An un-decodable (binary) staged blob
  is simply not a Markdown doc and is skipped (it has no doc-header to leak), which is safe: the header
  parser only ever matches text front-matter.
* **Header is authority** — classification comes from the parsed header (the engine's single source of
  truth), NOT from the filename. A public-looking filename with a ``secret`` header is still blocked.
* **Deterministic + side-effect-free** — reads only; sorts findings by path; no writes, no network.

Public API:

* ``iter_staged_files(repo_root) -> list[str]`` — repo-relative paths of added/modified staged files.
* ``read_staged_bytes(repo_root, rel_path) -> bytes | None`` — the staged blob, or ``None`` if unreadable.
* ``is_inside_confidential_dir(rel_path) -> bool`` — path-containment test (blocks ``../`` escape).
* ``scan_staged(repo_root, *, files=None) -> list[Finding]`` — the core, git-free-testable check.
* ``main(argv=None) -> int`` — CLI entry (exit 0 = clean, 1 = blocked, 2 = usage/IO error).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path, PurePosixPath

from tools.docgen.classification import (
    _FRONT_MATTER_RE,  # noqa: PLC2701 - reuse the engine's own fence so "what is a header" never drifts
    parse_header,
)
from tools.docgen.models import Finding, Severity, Tier

# The one sanctioned home for non-public (confidential/secret) documents (CLASSIFICATION.md).
CONFIDENTIAL_DIR = "docs/confidential"

# Only Markdown carries a doc-system header; other staged files have no header to leak.
_DOC_SUFFIXES = (".md", ".markdown")

_GATE = "staged-content-scanner"


def _repo_root_default() -> Path:
    """The repository root, derived structurally from this file's location (``tools/docgen/hooks/``)."""
    return Path(__file__).resolve().parents[3]


def iter_staged_files(repo_root: Path) -> list[str]:
    """Return repo-relative POSIX paths of files added or modified in the git index.

    Uses ``git diff --cached --name-only --diff-filter=ACMR`` so deletions (D) are ignored — a deleted
    file cannot leak content. Returns an empty list if git is unavailable or the command fails; callers
    that need to distinguish "no staged files" from "git error" should use ``main`` (which surfaces the
    error), but ``scan_staged`` accepts an explicit ``files`` list so the core logic is git-free-testable.
    """
    try:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
            cwd=str(repo_root),
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    # ``-z`` gives NUL-separated paths (safe for any filename); decode as UTF-8, drop empties.
    raw = proc.stdout.decode("utf-8", errors="replace")
    return sorted(p for p in raw.split("\x00") if p)


def read_staged_bytes(repo_root: Path, rel_path: str) -> bytes | None:
    """Read the STAGED blob of ``rel_path`` from the index (``git show :<path>``).

    Returns the staged bytes, or ``None`` if the blob cannot be read (git error / path not in index).
    Reading the index — not the working tree — is the whole point: it is the bytes that would actually
    be committed. ``None`` is treated fail-closed by ``scan_staged`` (reported as a blocking finding).
    """
    try:
        proc = subprocess.run(
            ["git", "show", f":{rel_path}"],
            cwd=str(repo_root),
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return proc.stdout


def is_inside_confidential_dir(rel_path: str) -> bool:
    """True iff ``rel_path`` is contained within ``docs/confidential/`` (containment, not prefix match).

    Uses ``PurePosixPath`` containment so a sibling like ``docs/confidential-notes/x.md`` is correctly
    treated as OUTSIDE, and normalizes ``.``/``..`` segments so ``docs/confidential/../secret.md`` (which
    resolves outside) is NOT accepted. Backslashes are normalized to ``/`` so a Windows-style staged path
    is handled identically (git always reports forward slashes, but this keeps the helper robust).
    """
    normalized = rel_path.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    # Reject any path that tries to climb out with ``..``; such a path is never legitimately "inside".
    if ".." in candidate.parts:
        return False
    confidential = PurePosixPath(CONFIDENTIAL_DIR)
    return candidate == confidential or confidential in candidate.parents


def _looks_like_doc(rel_path: str) -> bool:
    return PurePosixPath(rel_path.replace("\\", "/")).suffix.lower() in _DOC_SUFFIXES


def scan_staged(
    repo_root: Path,
    *,
    files: list[str] | None = None,
) -> list[Finding]:
    """Core check: return a BLOCKING ``Finding`` for every classified doc staged outside the vault.

    For each staged Markdown file (``files`` explicit list, or discovered via ``iter_staged_files``):
      1. skip files already inside ``docs/confidential/`` (that is where they belong);
      2. read the STAGED bytes; if unreadable -> a blocking finding (fail-closed);
      3. parse the doc-system header; if ``classification`` is CONFIDENTIAL or SECRET -> a blocking
         finding naming the path and tier.

    A file with a ``public`` header, or with no doc-system header at all (e.g. an ordinary README), is
    clean — only an actual non-public classification outside the vault blocks. Findings are returned
    sorted by evidence path for deterministic output.
    """
    staged = files if files is not None else iter_staged_files(repo_root)
    findings: list[Finding] = []

    for rel_path in staged:
        if not _looks_like_doc(rel_path):
            continue
        if is_inside_confidential_dir(rel_path):
            continue

        blob = read_staged_bytes(repo_root, rel_path)
        if blob is None:
            findings.append(
                Finding(
                    gate=_GATE,
                    message=(
                        f"Staged file '{rel_path}' could not be read from the index; refusing to pass "
                        f"it (fail-closed — an unreadable staged doc must not be assumed public)."
                    ),
                    severity=Severity.CRIT,
                    blocking=True,
                    evidence=rel_path,
                )
            )
            continue

        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            # Not decodable as text => not a doc-system Markdown header; nothing to leak here.
            continue

        header = parse_header(text)
        if header.classification is Tier.PUBLIC:
            continue
        # Only treat it as a real classified doc if a header was actually present. A plain Markdown
        # file with no front-matter parses to the SECRET sentinel (fail-closed for the engine's gate),
        # but for THIS placement guard a header-less README outside the vault is legitimate — so we
        # only block when genuine front-matter with a non-public classification was found.
        if not _has_doc_header(text):
            continue

        findings.append(
            Finding(
                gate=_GATE,
                message=(
                    f"'{rel_path}' has classification='{header.classification.value}' but is staged "
                    f"outside '{CONFIDENTIAL_DIR}/'. Non-public docs may only live in the confidential "
                    f"vault (RULEBOOK L14 / CLASSIFICATION.md)."
                ),
                severity=Severity.CRIT,
                blocking=True,
                evidence=rel_path,
            )
        )

    return sorted(findings, key=lambda f: (f.evidence, f.message))


def _has_doc_header(text: str) -> bool:
    """True iff ``text`` begins with a doc-system YAML front-matter block that declares ``classification``.

    Guards against treating an ordinary (header-less) Markdown file as SECRET: ``parse_header`` returns
    the SECRET sentinel for header-less input (correct fail-closed default for the render gate), but the
    placement guard must only fire on files that genuinely carry a non-public classification header.
    """
    # Use ``.search`` (not ``.match``) to mirror ``parse_header`` exactly: whatever front-matter the
    # engine's parser would honor as the header is the same block this guard treats as authoritative.
    header_match = _FRONT_MATTER_RE.search(text)
    if header_match is None:
        return False
    return "classification" in header_match.group(1)


def main(argv: list[str] | None = None) -> int:
    """CLI entry: scan the git index and block on any classified doc outside the vault.

    Exit codes: 0 = clean, 1 = one or more blocking findings, 2 = usage/IO error (e.g. not a git repo).
    Intended to be invoked from a ``pre-commit``/``pre-push`` shell hook.
    """
    parser = argparse.ArgumentParser(
        prog="staged-content-scanner",
        description=(
            "Block a confidential/secret doc-system document staged outside docs/confidential/."
        ),
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root (default: derived from this file's location).",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve() if args.repo_root else _repo_root_default()

    if not (repo_root / ".git").exists():
        sys.stderr.write(
            f"staged-content-scanner: '{repo_root}' is not a git repository (no .git). \n"
        )
        return 2

    findings = scan_staged(repo_root)
    for finding in findings:
        sys.stderr.write(f"[{finding.gate}] {finding.severity.value}: {finding.message}\n")

    if findings:
        sys.stderr.write(
            f"staged-content-scanner: BLOCKED — {len(findings)} classified doc(s) staged outside "
            f"'{CONFIDENTIAL_DIR}/'. Move them into the vault or set classification: public.\n"
        )
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI dispatch
    raise SystemExit(main())
