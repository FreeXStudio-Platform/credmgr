"""Docs index / gallery generator (Bundle 3 — ENGINE_PLAN.md / DOC_SYSTEM_COMPLETION_PROGRAM.md §2).

Scans a directory of already-built docgen JSON sidecars (written by
``generator.build(..., formats=("html", "json"))``) for PUBLIC documents, groups them by
their ``DOC_MANIFEST.md`` type, and emits one self-contained, browsable HTML index linking
to each document's rendered HTML.

Fail-closed on tier: a confidential/secret document's JSON sidecar is silently EXCLUDED from
the index — never listed, never named, never counted by title (L14 — the index itself is a
PUBLIC artifact, so it must carry zero non-public content, not even a title). A malformed or
unreadable sidecar is skipped (this is a discovery scan, not a gate — a bad file simply isn't
indexed; it never crashes the whole build).

Stdlib only. mypy --strict clean. Deterministic (sorted grouping/ordering; no timestamps in
the index content itself).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any

from tools.docgen import components, tokens
from tools.docgen.classification import _extract_prefix, parse_header
from tools.docgen.models import ManifestRow, Tier

_UNLISTED = "(unlisted)"

# Schema id for the machine-readable CONTENT_INDEX.json (see schemas/content_index.schema.json).
_CONTENT_INDEX_SCHEMA = "credmgr.doc-system.content-index/v1"


@dataclass(frozen=True)
class IndexedDoc:
    """One PUBLIC document discovered for the index."""

    id: str
    title: str
    html_path: Path


def scan_public_doc_jsons(build_dir: Path) -> list[IndexedDoc]:
    """Recursively scan ``build_dir`` for docgen JSON sidecars, returning only PUBLIC docs.

    Fail-closed on tier: any sidecar whose ``header.classification`` is not exactly
    ``"public"`` is skipped entirely, regardless of any other field.
    """
    docs: list[IndexedDoc] = []
    for json_path in sorted(build_dir.rglob("*.json")):
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            header = payload["header"]
            if header.get("classification") != Tier.PUBLIC.value:
                continue
            doc_id = str(header["id"])
            title = str(header["title"])
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            continue
        html_path = json_path.with_suffix(".html")
        if not html_path.is_file():
            continue
        docs.append(IndexedDoc(id=doc_id, title=title, html_path=html_path))
    return docs


def group_by_manifest_type(
    docs: list[IndexedDoc], manifest_rows: list[ManifestRow]
) -> dict[str, list[IndexedDoc]]:
    """Group discovered docs by their DOC_MANIFEST.md type-prefix row.

    A doc whose id-prefix matches no manifest row lands under the ``(unlisted)`` sentinel
    rather than being dropped — an indexed doc is never silently lost, even if the manifest
    itself is stale.
    """
    known_prefixes = {row.id for row in manifest_rows}
    grouped: dict[str, list[IndexedDoc]] = {}
    for doc in docs:
        prefix = _extract_prefix(doc.id) or _UNLISTED
        key = prefix if prefix in known_prefixes else _UNLISTED
        grouped.setdefault(key, []).append(doc)
    for items in grouped.values():
        items.sort(key=lambda d: d.id)
    return grouped


def render_index(
    grouped: dict[str, list[IndexedDoc]],
    manifest_rows: list[ManifestRow],
    *,
    index_dir: Path,
) -> str:
    """Render the self-contained HTML index page."""
    by_prefix = {row.id: row for row in manifest_rows}
    sections: list[str] = []
    for prefix in sorted(grouped):
        docs = grouped[prefix]
        row = by_prefix.get(prefix)
        section_title = row.title if row is not None else "Unlisted / not in DOC_MANIFEST.md"
        rows = [
            [
                # os.path.relpath (not Path.relative_to) since the index and a given doc
                # can live in sibling/unrelated directories, not just nested ones.
                f'<a href="{escape(os.path.relpath(d.html_path, index_dir))}">{escape(d.title)}</a>',
                escape(d.id),
            ]
            for d in docs
        ]
        sections.append(
            components.section(
                f"{prefix} · {section_title}", components.data_table(["Title", "ID"], rows)
            )
        )
    css = tokens.build_css()
    body = (
        "\n".join(sections)
        if sections
        else '<p class="t-body">No public documents indexed yet.</p>'
    )
    return f"""\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CredMgr Docs Index</title>
<style>
{css}
</style>
</head>
<body data-theme="dark">
<div class="doc-root">
<h1 class="t-h1">CredMgr Docs Index</h1>
<p class="t-lede">Every published PUBLIC document, grouped by type.</p>
<main>
{body}
</main>
</div>
</body>
</html>
"""


def build_index(build_dir: Path, manifest_rows: list[ManifestRow], out_path: Path) -> Path:
    """Scan, group, render, and write the index. Returns the written path."""
    docs = scan_public_doc_jsons(build_dir)
    grouped = group_by_manifest_type(docs, manifest_rows)
    html = render_index(grouped, manifest_rows, index_dir=out_path.parent)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# CONTENT_INDEX.json — the machine-readable organization / retrieval layer over
# the CURRENTLY-AVAILABLE (authored) docs. A future graphify pass or the app
# docs page consumes this JSON instead of re-parsing every Markdown source.
#
# Built from the authored .md sources (their YAML headers) cross-referenced
# against DOC_MANIFEST.md's type rows. Leak-safe by construction (RULEBOOK L14):
# CONTENT_INDEX.json is a COMMITTED artifact, so it lists only classification:
# public documents by id/title/path. A confidential/secret authored doc is
# counted in an aggregate (`non_public_excluded`) but is NEVER named — same
# fail-closed stance as scan_public_doc_jsons() above.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContentEntry:
    """One authored PUBLIC document, as listed in CONTENT_INDEX.json."""

    id: str
    title: str
    type_prefix: str
    surface: str
    path: str  # repo-relative path of the authored .md source
    status: str

    def to_dict(self) -> dict[str, str]:
        """Serialize to the CONTENT_INDEX entry shape (tier is always ``public``)."""
        return {
            "id": self.id,
            "title": self.title,
            "tier": Tier.PUBLIC.value,
            "type_prefix": self.type_prefix,
            "surface": self.surface,
            "path": self.path,
            "status": self.status,
        }


def scan_authored_docs(
    docs_root: Path, manifest_rows: list[ManifestRow], *, repo_root: Path
) -> tuple[list[ContentEntry], int]:
    """Scan ``docs_root`` recursively for authored ``.md`` sources.

    Returns ``(public_entries, non_public_excluded_count)``. Fail-closed on tier: a doc whose
    parsed header ``classification`` is not exactly PUBLIC is counted in the exclusion tally but
    never returned (so its id/title/path never enter a committed artifact — RULEBOOK L14).

    A doc with no extractable id-prefix, or a prefix absent from ``manifest_rows``, is still
    listed (never silently dropped) under the ``(unlisted)`` sentinel — mirroring
    ``group_by_manifest_type`` — so a real public doc is never lost to a stale manifest.

    ``.md`` sources whose name signals a derived/sidecar artifact (``*.video-script.md``) are
    skipped: they are generated companions of a real doc, not documents in their own right.
    A file that can't be read is skipped (discovery scan, not a gate).
    """
    known_prefixes = {row.id for row in manifest_rows}
    entries: list[ContentEntry] = []
    non_public = 0
    for md_path in sorted(docs_root.rglob("*.md")):
        name = md_path.name
        if name.endswith(".video-script.md"):
            continue
        try:
            text = md_path.read_text(encoding="utf-8")
        except OSError:
            continue
        header = parse_header(text)
        if header.classification is not Tier.PUBLIC:
            non_public += 1
            continue
        prefix = _extract_prefix(header.id)
        type_prefix = prefix if (prefix is not None and prefix in known_prefixes) else _UNLISTED
        rel_path = _repo_relative(md_path, repo_root)
        entries.append(
            ContentEntry(
                id=header.id,
                title=header.title,
                type_prefix=type_prefix,
                surface=header.surface.value,
                path=rel_path,
                status=header.status,
            )
        )
    entries.sort(key=lambda e: e.id)
    return entries, non_public


def build_content_index(
    docs_root: Path,
    manifest_rows: list[ManifestRow],
    *,
    repo_root: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    """Build the CONTENT_INDEX payload (a plain dict, ready for ``json.dumps``).

    Deterministic: entries are sorted by id; paths are repo-relative POSIX strings; no timestamps
    or other run-varying data are embedded, so build-twice is byte-identical.
    """
    entries, non_public = scan_authored_docs(docs_root, manifest_rows, repo_root=repo_root)
    return {
        "schema": _CONTENT_INDEX_SCHEMA,
        "generated_from": {
            "manifest": _repo_relative(manifest_path, repo_root),
            "docs_root": _repo_relative(docs_root, repo_root),
        },
        "counts": {
            "public": len(entries),
            "non_public_excluded": non_public,
            "manifest_rows": len(manifest_rows),
        },
        "entries": [e.to_dict() for e in entries],
    }


def write_content_index(
    docs_root: Path,
    manifest_rows: list[ManifestRow],
    out_path: Path,
    *,
    repo_root: Path,
    manifest_path: Path,
) -> Path:
    """Build and write CONTENT_INDEX.json. Returns the written path.

    Emits a trailing newline and ``sort_keys=True`` so the file is stable across builds and
    diffs cleanly. Returns ``out_path``.
    """
    payload = build_content_index(
        docs_root, manifest_rows, repo_root=repo_root, manifest_path=manifest_path
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return out_path


def _repo_relative(path: Path, repo_root: Path) -> str:
    """Return ``path`` relative to ``repo_root`` as a POSIX string (stable across platforms).

    Falls back to ``os.path.relpath`` when ``path`` is not under ``repo_root`` (e.g. a tmp-dir
    test fixture), so the function never raises on an unexpected layout.
    """
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return Path(os.path.relpath(path, repo_root)).as_posix()
