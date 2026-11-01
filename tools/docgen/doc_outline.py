"""Structural outline extraction — what makes a document's JSON sibling machine-readable.

``generator._render_json`` originally emitted the parsed header and the gate result and nothing
else: a 408-byte file with zero document content. That is a build receipt, not a machine-readable
document, and it cannot support the thing the corpus needs it for — answering "which documents
does this one depend on, which ADRs does it rest on, and which blueprint figures belong to which
section" without re-parsing prose.

This module derives that structure from the Markdown body, deterministically:

* **sections** — one per ``##`` heading, in document order, each with its own subheadings, the
  figure ids it embeds, and the outbound references made inside it. A stable ``id`` is derived by
  slugging the heading, so a section can be linked to and diffed across rebuilds.
* **references** — three kinds, extracted separately because they resolve differently:
  ``doc`` (``06_ACCESS_GRAPH.md``, optionally with a ``§`` locator), ``adr`` (``ADR-056``) and
  ``code`` (a repo path like ``crates/brokerd/src/ops.rs``). A verification pass can walk these
  and prove every one resolves; that is the guard the corpus has never had.
* **counts** — tables, code blocks, figures. Cheap drift detection: a doc that loses its figures
  in a refactor shows up as a number change, not as a silent rendering difference.

Ordering is document order with duplicates removed, never set iteration, so two builds of the same
source produce byte-identical JSON (the engine's determinism contract).
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["extract"]

_H2_RE = re.compile(r"^##\s+(?!#)(.*)$")
_HN_RE = re.compile(r"^(#{3,6})\s+(.*)$")
_FIGURE_RE = re.compile(r"<!--\s*figure:([A-Za-z0-9_-]+)\s*-->")
_FENCE_RE = re.compile(r"^\s*(?:```|~~~)")
_TABLE_DIVIDER_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")

# A corpus document reference, with an optional section locator: `06_ACCESS_GRAPH.md §4.2`.
_DOC_REF_RE = re.compile(r"\b(\d{2}_[A-Z0-9_]+\.md)(?:\s*§\s*([0-9]+(?:\.[0-9a-z]+)*))?")
_ADR_REF_RE = re.compile(r"\bADR-(\d{3})\b")
# A repo-relative source path. Anchored on the directories this project actually has, so prose
# like "the store" never reads as a path and a real path is never missed.
_CODE_REF_RE = re.compile(
    r"\b((?:crates|apps|scripts|tools|docs)/[A-Za-z0-9_./-]+\.(?:rs|py|mjs|js|ts|json|toml|md|svelte))"
)


def _slug(text: str) -> str:
    """A stable, lowercase, hyphenated anchor for a heading. Deterministic and idempotent."""
    cleaned = re.sub(r"[`*_]", "", text).strip().lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", cleaned)
    return cleaned.strip("-") or "section"


def _dedupe(items: list[str]) -> list[str]:
    """Document order, duplicates removed. Never a set — set order is not reproducible."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _references(text: str) -> dict[str, list[Any]]:
    docs: list[dict[str, str]] = []
    seen_docs: set[tuple[str, str]] = set()
    for match in _DOC_REF_RE.finditer(text):
        key = (match.group(1), match.group(2) or "")
        if key in seen_docs:
            continue
        seen_docs.add(key)
        ref: dict[str, str] = {"doc": match.group(1)}
        if match.group(2):
            ref["section"] = match.group(2)
        docs.append(ref)
    adrs = _dedupe([f"ADR-{m.group(1)}" for m in _ADR_REF_RE.finditer(text)])
    code = _dedupe([m.group(1) for m in _CODE_REF_RE.finditer(text)])
    return {"documents": docs, "adrs": adrs, "code": code}


def extract(md_body: str) -> dict[str, Any]:
    """Return the structural outline of a document body (front matter already stripped)."""
    lines = md_body.splitlines()

    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    prose: list[str] = []          # everything outside fences, for reference extraction
    section_prose: list[str] = []
    in_fence = False
    tables = 0
    code_blocks = 0
    all_figures: list[str] = []

    def _close() -> None:
        nonlocal current, section_prose
        if current is not None:
            current["references"] = _references("\n".join(section_prose))
            sections.append(current)
        section_prose = []

    for idx, line in enumerate(lines):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            if in_fence:
                code_blocks += 1
            continue
        if in_fence:
            continue

        h2 = _H2_RE.match(line)
        if h2:
            _close()
            title = h2.group(1).strip()
            current = {
                "id": _slug(title),
                "title": title,
                "level": 2,
                "headings": [],
                "figures": [],
            }
            continue

        hn = _HN_RE.match(line)
        if hn and current is not None:
            current["headings"].append(
                {"level": len(hn.group(1)), "title": hn.group(2).strip(), "id": _slug(hn.group(2))}
            )

        for fig in _FIGURE_RE.finditer(line):
            all_figures.append(fig.group(1))
            if current is not None:
                current["figures"].append(fig.group(1))

        if _TABLE_DIVIDER_RE.match(line) and idx > 0 and lines[idx - 1].strip().startswith("|"):
            tables += 1

        prose.append(line)
        section_prose.append(line)

    _close()

    return {
        "sections": sections,
        "figures": _dedupe(all_figures),
        "references": _references("\n".join(prose)),
        "counts": {
            "sections": len(sections),
            "tables": tables,
            "code_blocks": code_blocks,
            "figures": len(_dedupe(all_figures)),
        },
    }
