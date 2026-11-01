"""DOC_MANIFEST.md reader (RULEBOOK L10/L18; DOC_MANIFEST.md).

Parses the manifest's Markdown table into ``ManifestRow`` objects. Tolerant of the header/rule prose
sitting above and below the table (the file has narrative text before the table, a "## Rule" section,
and a "*Change history*" table after it — only the first well-formed pipe-table whose header row
contains ``id`` and ``variants`` is treated as the manifest table).

Cell parsing is deliberately tolerant of the manifest's real prose style: backtick-wrapped id patterns
(``` `DET-3NN` ```), parenthetical asides (``(template public — see ...)``), and multi-clause surface
cells (``none (secret instances) / repo (public sibling)``) — the reader extracts the *first* clause of
such compound cells as the row's primary tier/surface signal, since the manifest's authoritative single
value for validation purposes is that first clause (the compound detail is documentation, not a second
machine-checked field). This mirrors CLASSIFICATION.md's tier vocabulary: manifest cells write the
commercial-facing name ("commercial") for what CLASSIFICATION.md's header schema calls tier
``public`` — the mapping is applied here so downstream code speaks one vocabulary (``Tier``/``Surface``).
"""

from __future__ import annotations

import re
from pathlib import Path

from tools.docgen.models import ManifestRow, Surface, Tier

# Manifest prose uses "commercial" for what the document-header schema (CLASSIFICATION.md) calls the
# `public` tier — both mean "may leave local storage, sanitizer required". Confidential/secret map 1:1.
_VARIANT_WORD_TO_TIER: dict[str, Tier] = {
    "commercial": Tier.PUBLIC,
    "public": Tier.PUBLIC,
    "confidential": Tier.CONFIDENTIAL,
    "secret": Tier.SECRET,
}

_SURFACE_WORDS: dict[str, Surface] = {
    "web": Surface.WEB,
    "repo": Surface.REPO,
    "both": Surface.BOTH,
    "none": Surface.NONE,
}

_TABLE_ROW_RE = re.compile(r"^\|(.+)\|\s*$")
_SEPARATOR_ROW_RE = re.compile(r"^\|[\s:|-]+\|\s*$")


def read_manifest(path: Path) -> list[ManifestRow]:
    """Parse DOC_MANIFEST.md's table into a list of ``ManifestRow``.

    Fail-closed on the caller's behalf in spirit (returns an empty list rather than raising) when the
    file is unreadable or no manifest table can be located — callers that need "the manifest must
    exist" as a hard gate should treat an empty return as a blocking condition themselves (this reader
    is a pure parser, not a gate).
    """
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    return parse_manifest_text(text)


def parse_manifest_text(text: str) -> list[ManifestRow]:
    lines = text.splitlines()
    header_idx = _find_manifest_header(lines)
    if header_idx is None:
        return []

    header_cells = _split_row(lines[header_idx])
    col_index = _column_index(header_cells)
    if col_index is None:
        return []

    rows: list[ManifestRow] = []
    i = header_idx + 1
    if i < len(lines) and _SEPARATOR_ROW_RE.match(lines[i].strip()):
        i += 1

    while i < len(lines):
        line = lines[i].rstrip()
        if not line.strip():
            break
        if not _TABLE_ROW_RE.match(line.strip()):
            break
        cells = _split_row(line)
        row = _row_from_cells(cells, col_index)
        if row is not None:
            rows.append(row)
        i += 1

    return rows


def _find_manifest_header(lines: list[str]) -> int | None:
    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not _TABLE_ROW_RE.match(line):
            continue
        cells = [c.strip().lower() for c in _split_row(line)]
        if any(_strip_markup(c) == "id" for c in cells) and any(
            "variants" in _strip_markup(c) for c in cells
        ):
            return idx
    return None


def _column_index(header_cells: list[str]) -> dict[str, int] | None:
    normalized = [_strip_markup(c).strip().lower() for c in header_cells]
    index: dict[str, int] = {}
    for i, name in enumerate(normalized):
        if name == "id":
            index["id"] = i
        elif name == "title":
            index["title"] = i
        elif name.startswith("type"):
            index["type"] = i
        elif name.startswith("variants"):
            index["variants"] = i
        elif name == "content_role":
            index["content_role"] = i
        elif name == "surface":
            index["surface"] = i
        elif name == "status":
            index["status"] = i
    required = {"id", "title", "type", "variants", "content_role", "surface", "status"}
    if not required.issubset(index.keys()):
        return None
    return index


def _split_row(line: str) -> list[str]:
    """Split a Markdown table row on unescaped ``|`` (an escaped ``\\|`` inside a cell, e.g. the
    manifest's ``variants: [commercial\\|confidential\\|secret]`` header cell, must not split)."""
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    raw_cells = re.split(r"(?<!\\)\|", stripped)
    return [cell.strip().replace("\\|", "|") for cell in raw_cells]


def _strip_markup(cell: str) -> str:
    """Strip backticks/markdown emphasis so header/word matching is robust to formatting."""
    cell = cell.replace("`", "")
    cell = re.sub(r"\*+", "", cell)
    return cell.strip()


def _row_from_cells(cells: list[str], col_index: dict[str, int]) -> ManifestRow | None:
    max_idx = max(col_index.values())
    if len(cells) <= max_idx:
        return None

    doc_id = _strip_markup(cells[col_index["id"]]).strip()
    if not doc_id:
        return None

    title = _strip_markup(cells[col_index["title"]]).strip()
    type_cell = _strip_markup(cells[col_index["type"]]).strip()
    variants_cell = cells[col_index["variants"]]
    content_role = _strip_markup(cells[col_index["content_role"]]).strip()
    surface_cell = cells[col_index["surface"]]
    status = _strip_markup(cells[col_index["status"]]).strip()

    variants = _parse_variants(variants_cell)
    surface = _parse_surface(surface_cell)

    return ManifestRow(
        id=doc_id,
        title=title or type_cell,
        type=type_cell,
        variants=variants,
        content_role=content_role,
        surface=surface,
        status=status,
    )


def _parse_variants(cell: str) -> list[Tier]:
    """Extract every tier word mentioned in a (possibly compound) variants cell.

    e.g. "commercial + confidential + secret (3 variants, never cross)" -> [PUBLIC, CONFIDENTIAL, SECRET];
    "confidential + secret (template public — see ...)" -> [CONFIDENTIAL, SECRET, PUBLIC] (the
    parenthetical "template public" clause still names a real tier this doc type is authored at).
    """
    plain = _strip_markup(cell).lower()
    found: list[Tier] = []
    seen: set[Tier] = set()
    for word, tier in _VARIANT_WORD_TO_TIER.items():
        if re.search(rf"\b{re.escape(word)}\b", plain) and tier not in seen:
            found.append(tier)
            seen.add(tier)
    return found


def _parse_surface(cell: str) -> Surface:
    """Take the FIRST clause of a (possibly compound) surface cell as the row's primary surface.

    e.g. "web (commercial) / none (confidential+secret)" -> Surface.WEB (the manifest's own convention
    is that the first-listed surface corresponds to the row's primary/commercial variant).
    """
    plain = _strip_markup(cell).lower()
    first_clause = re.split(r"[/(]", plain, maxsplit=1)[0].strip()
    for word, surface in _SURFACE_WORDS.items():
        if re.search(rf"\b{re.escape(word)}\b", first_clause):
            return surface
    # Fall back to scanning the whole cell for any known surface word (fail-closed to NONE if none found).
    for word, surface in _SURFACE_WORDS.items():
        if re.search(rf"\b{re.escape(word)}\b", plain):
            return surface
    return Surface.NONE
