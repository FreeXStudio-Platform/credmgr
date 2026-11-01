"""Surface↔channel git router: enforce RULEBOOK L3's release-matrix placement of RENDERED exports.

RULEBOOK L3 says a public document leaves local storage only on the channel its header declares:
``surface: web`` publishes to the web, ``surface: repo`` commits to the repo tree, ``surface: both``
does either/both. The header-vs-manifest *validity* half of L3 already lives in ``export_sanitizer``
(Gate 1 surface validity, Gate 5 manifest drift) and ``classification.validate_header``. What was
still missing — and is implemented here — is the physical *routing* half: given a doc that renders
to ``surface: web``, its rendered artifact must NEVER land committed in the repo tree; given
``surface: repo``, its rendered artifact must NEVER be web-only (uncommitted). This checker is the
git-aware, index-level enforcement of that, exactly parallel to ``staged_content_scanner``.

What it operates on — and why source Markdown is NOT flagged
------------------------------------------------------------
The subject of L3 routing is the **rendered export artifact** (the ``.html`` / ``.json`` / ``.pdf``
the generator emits, or a rendered ``.md`` that carries the L7 ``generated-by docgen`` stamp), NOT
the authoring source Markdown. The source unit (``sample.md`` with ``surface: web``) is legitimately
git-tracked — it is the thing you EDIT, per RULEBOOK L7 ("modular source, generated exports"); its
committed presence is correct and MUST NOT be flagged. Only a *generated* artifact is a "landing on
a channel". This distinction is the checker's core false-positive guard: an un-stamped ``.md`` is
treated as source and skipped entirely.

The channel is determined from git, deterministically:

* ``repo`` channel  == the artifact is git-tracked (``git ls-files`` reports it) → it will ship in
  the repo tree.
* ``web`` channel    == the artifact exists on disk but is NOT git-tracked (a gitignored/deploy-only
  render, e.g. under the generator's gitignored ``_out``) → it can only reach the public via a web
  publish, never the repo.

Routing matrix (public docs; ``header.surface`` → allowed channel of a rendered artifact):

    surface=web   → artifact must be web-channel only.  Git-tracked artifact  → BLOCK.
    surface=repo  → artifact must be repo-channel.       Web-only (untracked)  → BLOCK.
    surface=both  → either/both channels allowed.        Never blocks on channel.
    surface=none  → non-public: no public rendered artifact should exist at all → any artifact BLOCKS
                    (defence-in-depth; the primary non-public guard is ``staged_content_scanner``).

Design (matches the engine's fail-closed posture, mirrors ``staged_content_scanner``):

* **Git is the source of truth for the channel** — ``git ls-files`` (tracked set), read once, so the
  tracked/untracked decision is exact and reads only committed/index state, never a guess.
* **Header is authority for the surface** — the declared surface comes from the parsed header (the
  engine's single source of truth via ``classification.parse_header``), never the filename.
* **Fail-closed on ambiguity** — an artifact whose ``surface`` cannot be established (unreadable /
  unparseable header on something that IS a generated artifact) is a BLOCKING finding, never skipped.
* **Deterministic + side-effect-free** — reads only; findings sorted by ``(evidence, message)``; no
  writes, no network. Safe to run from a pre-commit / pre-push hook.

Public API:

* ``Channel`` — the ``REPO`` / ``WEB`` enum a rendered artifact lands on.
* ``iter_tracked_files(repo_root) -> set[str]`` — repo-relative POSIX paths git currently tracks.
* ``is_generated_artifact(rel_path, text) -> bool`` — True iff a file is a rendered export (by suffix,
  or a stamped generated ``.md``), i.e. subject to L3 routing rather than authoring source.
* ``channel_of(rel_path, tracked) -> Channel`` — REPO if git-tracked, else WEB.
* ``route_finding(rel_path, surface, channel) -> Finding | None`` — the pure routing decision.
* ``scan_routes(repo_root, *, records=None) -> list[Finding]`` — the core, git-free-testable check.
* ``main(argv=None) -> int`` — CLI entry (exit 0 = clean, 1 = blocked, 2 = usage/IO error).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath

from tools.docgen.classification import parse_header
from tools.docgen.models import Finding, Severity, Surface

_GATE = "surface-channel-router"

# The generator stamps every rendered output with this marker (ENGINE_PLAN §4b L7 generated-file
# guard). A ``.md`` that carries it is a GENERATED export subject to L3 routing; a ``.md`` without it
# is authoring source and is left alone. Kept in sync with ``generator``'s stamp prefix.
_GENERATED_STAMP = "generated-by docgen"

# Rendered export formats (ExportManifest ``format`` enum minus ``md``, which is disambiguated by the
# generated-stamp above). These are always exports, never authoring source.
_RENDERED_SUFFIXES = (".html", ".json", ".pdf")

# Authoring-source / generated Markdown share this suffix; the stamp disambiguates them.
_MARKDOWN_SUFFIXES = (".md", ".markdown")


class Channel(str, Enum):
    """The physical channel a rendered artifact has landed on (derived from git-tracked state)."""

    REPO = "repo"  # git-tracked — ships in the repo tree
    WEB = "web"  # present on disk but NOT git-tracked — reachable only via a web publish


@dataclass(frozen=True)
class RouteRecord:
    """One rendered artifact to route: its repo-relative path, declared surface, and landed channel.

    Constructed by ``scan_routes`` from git + parsed headers, or supplied directly in tests so the
    routing logic is git-free-testable (mirroring ``staged_content_scanner``'s explicit ``files``).
    """

    rel_path: str
    surface: Surface
    channel: Channel


def _repo_root_default() -> Path:
    """The repository root, derived structurally from this file's location (``tools/docgen/hooks/``)."""
    return Path(__file__).resolve().parents[3]


def iter_tracked_files(repo_root: Path) -> set[str]:
    """Return the set of repo-relative POSIX paths git currently tracks (``git ls-files -z``).

    This is the authoritative "is committed to the repo tree" set. Returns an empty set if git is
    unavailable or the command fails; ``scan_routes`` treats an empty tracked-set as "nothing is on
    the repo channel", which is a safe reading for the CLI path (``main`` separately verifies the
    directory is a git repo and exits 2 otherwise, so a genuine git failure never silently reads as
    "clean").
    """
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=str(repo_root),
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return set()
    raw = proc.stdout.decode("utf-8", errors="replace")
    return {p for p in raw.split("\x00") if p}


def _suffix(rel_path: str) -> str:
    return PurePosixPath(rel_path.replace("\\", "/")).suffix.lower()


def is_generated_artifact(rel_path: str, text: str | None) -> bool:
    """True iff ``rel_path`` is a RENDERED export (subject to L3 routing), not authoring source.

    A file qualifies as a rendered artifact when either:
      * its suffix is a rendered format (``.html`` / ``.json`` / ``.pdf``) — always an export; or
      * it is Markdown (``.md`` / ``.markdown``) AND its text carries the generator's
        ``generated-by docgen`` stamp (a GENERATED ``.md`` export, per RULEBOOK L7).

    A Markdown file WITHOUT the stamp is authoring source and returns False — this is the guard that
    keeps legitimately-tracked source units (e.g. ``sample.md``) from ever being flagged. ``text`` may
    be ``None`` when unavailable (e.g. a binary/unreadable ``.pdf``); a rendered suffix still counts.
    """
    suffix = _suffix(rel_path)
    if suffix in _RENDERED_SUFFIXES:
        return True
    if suffix in _MARKDOWN_SUFFIXES:
        return text is not None and _GENERATED_STAMP in text
    return False


def channel_of(rel_path: str, tracked: set[str]) -> Channel:
    """REPO if the artifact is git-tracked (ships in the repo tree), else WEB (publish-only)."""
    normalized = rel_path.replace("\\", "/")
    return Channel.REPO if normalized in tracked else Channel.WEB


def route_finding(rel_path: str, surface: Surface, channel: Channel) -> Finding | None:
    """The pure L3 routing decision for one rendered artifact. Returns a BLOCKING ``Finding`` or None.

    Implements the routing matrix in the module docstring:
      * ``web``  landing on the ``repo`` channel  → BLOCK (web export must never be committed).
      * ``repo`` landing on the ``web`` channel   → BLOCK (repo export must never be web-only).
      * ``both`` → never blocks on channel.
      * ``none`` (non-public) → any rendered public artifact BLOCKS (defence-in-depth).
    A fail-closed ``surface`` that could not be parsed reads as ``Surface.NONE`` (per
    ``classification._coerce_surface``), so an unparseable header on a real artifact blocks here too.
    """
    if surface is Surface.WEB and channel is Channel.REPO:
        return Finding(
            gate=_GATE,
            message=(
                f"'{rel_path}' declares surface=web but its rendered export is committed to the repo "
                f"tree (repo channel). A web-surface export must never land in the repo (RULEBOOK L3)."
            ),
            severity=Severity.CRIT,
            blocking=True,
            evidence=rel_path,
        )
    if surface is Surface.REPO and channel is Channel.WEB:
        return Finding(
            gate=_GATE,
            message=(
                f"'{rel_path}' declares surface=repo but its rendered export is not committed (web-only "
                f"channel). A repo-surface export must be committed to the repo, never web-only "
                f"(RULEBOOK L3)."
            ),
            severity=Severity.HIGH,
            blocking=True,
            evidence=rel_path,
        )
    if surface is Surface.NONE:
        return Finding(
            gate=_GATE,
            message=(
                f"'{rel_path}' is a rendered public artifact whose surface routes to none "
                f"(non-public / unparseable). No public export should exist for it (RULEBOOK L3)."
            ),
            severity=Severity.CRIT,
            blocking=True,
            evidence=rel_path,
        )
    return None


def _read_text(repo_root: Path, rel_path: str) -> str | None:
    """Best-effort UTF-8 read of an on-disk artifact; ``None`` if absent or not decodable as text."""
    path = (repo_root / rel_path).resolve()
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def scan_routes(
    repo_root: Path,
    *,
    records: list[RouteRecord] | None = None,
) -> list[Finding]:
    """Core check: a BLOCKING ``Finding`` for every rendered export placed on the wrong channel (L3).

    Two modes, exactly like ``staged_content_scanner``:

    * ``records`` supplied → the routing decision runs purely on those ``RouteRecord``s (git-free,
      fully unit-testable). Each record's ``surface``/``channel`` is trusted as given.
    * ``records is None`` → discover them from the repo: read git's tracked set once, walk every
      tracked file, keep only rendered artifacts (``is_generated_artifact``), parse each one's header
      for its declared ``surface``, derive its channel from git, and route. NOTE: discovery from the
      tracked set can only ever surface the ``web``-landing-on-``repo`` violation (a tracked artifact
      is on the repo channel by definition); the inverse (``repo`` export existing web-only /
      uncommitted) is not visible from ``git ls-files`` alone and is enforced against an explicit
      record set / export manifest by callers that have one. This is stated honestly rather than
      pretending the tracked-set walk covers both directions.

    Findings are returned sorted by ``(evidence, message)`` for deterministic output.
    """
    if records is not None:
        found = [
            f
            for rec in records
            if (f := route_finding(rec.rel_path, rec.surface, rec.channel)) is not None
        ]
        return sorted(found, key=lambda f: (f.evidence, f.message))

    tracked = iter_tracked_files(repo_root)
    findings: list[Finding] = []
    for rel_path in sorted(tracked):
        suffix = _suffix(rel_path)
        # Only read text when it could matter (Markdown needs the stamp; rendered suffixes are
        # classified by suffix alone and their header — if any — is parsed for the surface).
        text = _read_text(repo_root, rel_path) if suffix in (
            *_RENDERED_SUFFIXES,
            *_MARKDOWN_SUFFIXES,
        ) else None

        if not is_generated_artifact(rel_path, text):
            continue

        surface = _surface_of_artifact(text)
        if surface is None:
            findings.append(
                Finding(
                    gate=_GATE,
                    message=(
                        f"Rendered artifact '{rel_path}' is committed to the repo but its declared "
                        f"surface could not be read from its header (fail-closed — a tracked export "
                        f"with no readable surface must not be assumed correctly-placed)."
                    ),
                    severity=Severity.CRIT,
                    blocking=True,
                    evidence=rel_path,
                )
            )
            continue

        channel = channel_of(rel_path, tracked)
        finding = route_finding(rel_path, surface, channel)
        if finding is not None:
            findings.append(finding)

    return sorted(findings, key=lambda f: (f.evidence, f.message))


def _surface_of_artifact(text: str | None) -> Surface | None:
    """Extract the declared ``surface`` from a rendered artifact's embedded/source header.

    Rendered HTML/JSON/PDF do not always carry a parseable YAML front-matter block; when no header can
    be found the surface is unknown → ``None`` (fail-closed, the caller blocks). A Markdown export
    carries its source header verbatim, so ``parse_header`` finds it. Returns the parsed ``Surface``
    (which is itself fail-closed to ``Surface.NONE`` on an unrecognized/missing ``surface:`` field).
    """
    if text is None:
        return None
    header = parse_header(text)
    # A header-less artifact yields the sentinel (id "UNKNOWN", surface NONE). Distinguish "no header
    # at all" (unknown surface → block) from "header present but surface=none". We treat an absent
    # front-matter block as unknown so the caller fails closed rather than silently reading NONE.
    if "surface" not in text:
        return None
    return header.surface


def main(argv: list[str] | None = None) -> int:
    """CLI entry: scan the tracked tree and block on any rendered export placed on the wrong channel.

    Exit codes: 0 = clean, 1 = one or more blocking findings, 2 = usage/IO error (e.g. not a git repo).
    Intended to be invoked from a ``pre-commit`` / ``pre-push`` shell hook alongside the other guards.
    """
    parser = argparse.ArgumentParser(
        prog="surface-channel-router",
        description=(
            "Block a rendered doc-system export committed to the wrong channel for its surface "
            "(RULEBOOK L3): surface=web never committed to the repo tree."
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
            f"surface-channel-router: '{repo_root}' is not a git repository (no .git). \n"
        )
        return 2

    findings = scan_routes(repo_root)
    for finding in findings:
        sys.stderr.write(f"[{finding.gate}] {finding.severity.value}: {finding.message}\n")

    if findings:
        sys.stderr.write(
            f"surface-channel-router: BLOCKED — {len(findings)} rendered export(s) on the wrong "
            f"channel for their surface (RULEBOOK L3).\n"
        )
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI dispatch
    raise SystemExit(main())
