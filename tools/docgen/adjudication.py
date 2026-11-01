"""Active L10/L11 adjudication — CONSULT the governance matrices, don't just check they exist.

Until now the engine only verified that ``CONTRADICTION.md`` (RULEBOOK L11 tie-breaker table)
and ``update_impact_map.json`` (RULEBOOK L10 change-type -> dependent-docs + sanitization) EXIST
and PARSE. This module upgrades that to **active consultation** (the ENGINE_PLAN §4b item deferred
to ``docs/pm/POOL.md``):

* ``load_contradictions`` / ``annotate_with_contradictions`` — when a gate finding fires, look the
  relevant tie-breaker up in ``CONTRADICTION.md`` and attach its recorded resolution as an
  **advisory (non-blocking) INFO finding**, so an operator sees *how the rulebook already resolved
  this recurring conflict* instead of re-deriving it ad hoc. This is purely additive: it never
  changes ``GateResult.ok`` (no advisory INFO is ``blocking``), never drops or mutates an existing
  finding, and never relaxes a hard block. The precedence spine (``export_sanitizer.adjudicate``)
  still governs the hard ordering; this layer explains, it does not override.

* ``load_impact_map`` / ``compute_change_impact`` — given a change type
  (``DETECTOR_CHANGE`` / ``VISUAL_STYLE_CHANGE`` / ``USER_POLICY_CHANGE`` /
  ``ARCHITECTURE_CHANGE`` / ``RULE_CHANGE``), consult ``update_impact_map.json`` and return the
  dependent doc-id prefixes that must be reviewed plus the public-sanitization rule to apply —
  the actual L10 blast-radius answer, read from the map rather than treated as a mere file that
  exists.

**Fail-open by contract** (these are advisory governance aids layered on top of the hard gates —
they must NEVER be able to *block* a build that the leak-gate itself passed, nor *pass* one it
blocked). A missing/unreadable/malformed matrix degrades gracefully: the consultation returns an
empty result and logs a WARNING via ``logging`` — it is never faked and never silently swallowed
into a false "consulted OK". The hard blocking moat lives entirely in ``export_sanitizer`` and is
unaffected by anything here.

Stdlib only. mypy --strict clean.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from tools.docgen.models import Finding, Severity

_LOG = logging.getLogger("tools.docgen.adjudication")

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOC_SYSTEM_DIR = _REPO_ROOT / "docs" / "design" / "doc-system"
_DEFAULT_CONTRADICTION_PATH = _DOC_SYSTEM_DIR / "CONTRADICTION.md"
_DEFAULT_IMPACT_MAP_PATH = _DOC_SYSTEM_DIR / "update_impact_map.json"


# ======================================================================================
# L11 — Contradiction matrix (CONTRADICTION.md)
# ======================================================================================


@dataclass(frozen=True)
class ContradictionRule:
    """One row of the L11 tie-breaker table (``CONTRADICTION.md``).

    ``rule_tags`` is the normalized set of rule/gate tokens cited in the row's ``Rule(s)``
    column — e.g. ``{"l1", "l4", "l14"}`` and gate names like ``{"gate 9"}`` — used to match a
    fired gate finding back to the tie-breaker that already governs its conflict class.
    """

    index: int
    conflict: str
    resolution: str
    rule_tags: frozenset[str]


# A gate's internal name (``Finding.gate``) -> the CONTRADICTION.md tokens that name the same
# concern. A finding matches a contradiction row when the row cites ANY of the gate's tokens.
# Kept deliberately conservative: only gates that have a recurring documented tie-breaker map to
# a token; an unmapped gate simply gets no advisory (never an error).
_GATE_TO_CONTRADICTION_TOKENS: dict[str, frozenset[str]] = {
    "tier": frozenset({"gate 1", "l1", "l14"}),
    "secret_value": frozenset({"gate 3", "l4"}),
    "pii_path_internal": frozenset({"gate 3b", "l4"}),
    "variant_overlap": frozenset({"gate 9", "l18"}),
    "manifest_drift": frozenset({"l5"}),
    "implementation_internal": frozenset({"l4", "l6"}),
    "hash_gate": frozenset({"l9"}),
}

# Tokens we extract from a ``Rule(s)`` cell. ``L<n>`` rule ids and ``Gate <n[letter]>`` names.
_L_RULE_RE = re.compile(r"\bL(\d+)\b", re.IGNORECASE)
_GATE_RE = re.compile(r"\bGate\s+(\d+[a-z]?)\b", re.IGNORECASE)
_TABLE_ROW_RE = re.compile(r"^\|(.+)\|\s*$")
_SEPARATOR_ROW_RE = re.compile(r"^\|[\s:|-]+\|\s*$")


def _extract_rule_tags(rules_cell: str) -> frozenset[str]:
    """Normalize a ``Rule(s)`` cell into its set of rule/gate tokens.

    ``"L1, L4, L14"`` -> ``{"l1", "l4", "l14"}``; ``"L18, CLASSIFICATION.md Gate 9"`` ->
    ``{"l18", "gate 9"}``. Free-form prose (file names, section refs) that is neither an ``L<n>``
    id nor a ``Gate <n>`` name is ignored — matching is by explicit rule/gate token only.
    """
    tags: set[str] = set()
    for m in _L_RULE_RE.finditer(rules_cell):
        tags.add(f"l{m.group(1)}")
    for m in _GATE_RE.finditer(rules_cell):
        tags.add(f"gate {m.group(1).lower()}")
    return frozenset(tags)


def _split_row(line: str) -> list[str]:
    inner = line.strip().strip("|")
    return [cell.strip() for cell in inner.split("|")]


def load_contradictions(path: Path | None = None) -> list[ContradictionRule]:
    """Parse ``CONTRADICTION.md`` into ``ContradictionRule`` rows (the L11 tie-breaker table).

    Locates the first well-formed pipe table whose header row contains ``conflict`` and
    ``resolution`` (tolerant of the narrative prose before it and the ``## Rule`` / change-history
    sections after it — the same tolerance ``doc_manifest.read_manifest`` uses).

    Fail-open (this is an advisory governance aid, never a gate): a missing/unreadable/malformed
    file returns ``[]`` and logs a WARNING. It can never block a build; the hard moat is
    ``export_sanitizer``.
    """
    resolved = path or _DEFAULT_CONTRADICTION_PATH
    if not resolved.is_file():
        _LOG.warning("L11 contradiction matrix absent at %s — skipping active consultation", resolved)
        return []
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - unreadable file is environment-specific
        _LOG.warning("L11 contradiction matrix unreadable at %s: %s", resolved, exc)
        return []
    return _parse_contradiction_text(text)


def _parse_contradiction_text(text: str) -> list[ContradictionRule]:
    lines = text.splitlines()
    header_idx, cols = _find_contradiction_header(lines)
    if header_idx is None or cols is None:
        _LOG.warning("L11 contradiction matrix has no recognizable conflict/resolution table")
        return []

    conflict_col, resolution_col, rules_col = cols
    rows: list[ContradictionRule] = []
    i = header_idx + 1
    if i < len(lines) and _SEPARATOR_ROW_RE.match(lines[i].strip()):
        i += 1

    row_index = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped or not _TABLE_ROW_RE.match(stripped):
            break
        cells = _split_row(stripped)
        max_needed = max(conflict_col, resolution_col, rules_col)
        if len(cells) <= max_needed:
            i += 1
            continue
        conflict = cells[conflict_col]
        resolution = cells[resolution_col]
        rules_cell = cells[rules_col]
        rows.append(
            ContradictionRule(
                index=row_index,
                conflict=conflict,
                resolution=resolution,
                rule_tags=_extract_rule_tags(rules_cell),
            )
        )
        row_index += 1
        i += 1
    return rows


def _find_contradiction_header(
    lines: list[str],
) -> tuple[int | None, tuple[int, int, int] | None]:
    """Find the tie-breaker table header row and the (conflict, resolution, rules) column indices."""
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not _TABLE_ROW_RE.match(stripped):
            continue
        cells = [c.lower() for c in _split_row(stripped)]
        conflict_col = _first_index_containing(cells, "conflict")
        resolution_col = _first_index_containing(cells, "resolution")
        rules_col = _first_index_containing(cells, "rule")
        if conflict_col is not None and resolution_col is not None and rules_col is not None:
            return idx, (conflict_col, resolution_col, rules_col)
    return None, None


def _first_index_containing(cells: list[str], needle: str) -> int | None:
    for i, cell in enumerate(cells):
        if needle in cell:
            return i
    return None


def _rows_matching_gate(gate: str, rules: list[ContradictionRule]) -> list[ContradictionRule]:
    tokens = _GATE_TO_CONTRADICTION_TOKENS.get(gate)
    if not tokens:
        return []
    return [rule for rule in rules if rule.rule_tags & tokens]


def annotate_with_contradictions(
    findings: list[Finding],
    *,
    contradiction_path: Path | None = None,
    rules: list[ContradictionRule] | None = None,
) -> list[Finding]:
    """Return ``findings`` plus one advisory INFO per fired gate that a tie-breaker governs.

    For each *blocking* finding whose gate maps to a documented L11 conflict class, the recorded
    tie-breaker resolution is attached as a non-blocking ``Severity.INFO`` finding on the synthetic
    gate ``"l11_contradiction"``. Deterministic: the input order of ``findings`` is preserved and
    the matched contradiction rows are consulted in their table order; each (finding, rule) pair
    yields at most one advisory, de-duplicated by ``(finding.gate, rule.index)`` so re-running is
    idempotent.

    Purely additive — never drops, reorders, or unblocks an existing finding, and every appended
    finding is ``blocking=False`` (INFO), so ``GateResult.ok`` is unchanged. Fail-open: if the
    matrix is absent/empty, the input list is returned unchanged.
    """
    matrix = rules if rules is not None else load_contradictions(contradiction_path)
    if not matrix:
        return list(findings)

    annotated: list[Finding] = list(findings)
    # Idempotence: an advisory is uniquely identified by its (message, evidence). Pre-seed the
    # de-dup set with any advisories ALREADY present in the input so re-running over an
    # already-annotated list adds nothing (the original blocking findings are still present and
    # would otherwise re-match on every pass).
    seen: set[tuple[str, str]] = {
        (f.message, f.evidence) for f in findings if f.gate == "l11_contradiction"
    }
    for finding in findings:
        if not finding.blocking:
            continue
        for rule in _rows_matching_gate(finding.gate, matrix):
            message = f"L11 tie-breaker for '{finding.gate}': {rule.resolution}"
            evidence = f"CONTRADICTION.md#{rule.index}"
            key = (message, evidence)
            if key in seen:
                continue
            seen.add(key)
            annotated.append(
                Finding(
                    gate="l11_contradiction",
                    message=message,
                    severity=Severity.INFO,
                    blocking=False,
                    evidence=evidence,
                )
            )
    return annotated


# ======================================================================================
# L10 — Update-impact map (update_impact_map.json)
# ======================================================================================


@dataclass(frozen=True)
class ChangeImpact:
    """The L10 blast-radius answer for one change type (read from ``update_impact_map.json``)."""

    change_type: str
    known: bool  # True iff the change type resolved to a real map entry
    description: str = ""
    dependent_doc_ids: tuple[str, ...] = ()
    public_sanitization_rule: str = ""
    findings: list[Finding] = field(default_factory=list)


def load_impact_map(path: Path | None = None) -> dict[str, dict[str, object]]:
    """Parse ``update_impact_map.json`` into its ``change_types`` mapping.

    Fail-open (advisory governance aid): a missing/unreadable/malformed file returns ``{}`` and
    logs a WARNING. Callers treat an empty map as "no impact information available", never as a
    block.
    """
    resolved = path or _DEFAULT_IMPACT_MAP_PATH
    if not resolved.is_file():
        _LOG.warning("L10 update-impact map absent at %s — skipping active consultation", resolved)
        return {}
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning("L10 update-impact map unreadable/invalid at %s: %s", resolved, exc)
        return {}
    if not isinstance(raw, dict):
        _LOG.warning("L10 update-impact map top level is not a JSON object at %s", resolved)
        return {}
    change_types = raw.get("change_types")
    if not isinstance(change_types, dict):
        _LOG.warning("L10 update-impact map has no 'change_types' object at %s", resolved)
        return {}
    result: dict[str, dict[str, object]] = {}
    for key, entry in change_types.items():
        if isinstance(key, str) and isinstance(entry, dict):
            result[key] = entry
    return result


def compute_change_impact(
    change_type: str,
    *,
    impact_map_path: Path | None = None,
    change_map: dict[str, dict[str, object]] | None = None,
) -> ChangeImpact:
    """Consult the L10 map and return the dependent docs + sanitization rule for ``change_type``.

    This is the ACTIVE consultation the engine previously deferred: rather than only checking the
    map file exists, it reads the actual entry for a change type and returns its
    ``dependent_doc_ids`` (the doc-type prefixes that must be reviewed) and
    ``public_sanitization_rule`` (the blast-radius governance answer, RULEBOOK L10).

    A recognized change type yields ``known=True`` and an advisory INFO ``Finding`` naming the
    dependent docs. An UNKNOWN change type yields ``known=False`` and, in this consultation, a
    non-blocking advisory ``Finding`` (``Severity.MED``) so the operator sees the type wasn't in
    the map — still fail-open (never blocking): a caller that wants a hard gate on unknown change
    types can inspect ``ChangeImpact.known`` itself.

    Deterministic: ``dependent_doc_ids`` preserves the map's declared order.
    """
    the_map = change_map if change_map is not None else load_impact_map(impact_map_path)
    entry = the_map.get(change_type)
    if entry is None:
        _LOG.warning("L10 change type %r not present in update-impact map", change_type)
        return ChangeImpact(
            change_type=change_type,
            known=False,
            findings=[
                Finding(
                    gate="l10_impact",
                    message=(
                        f"change type {change_type!r} not found in update_impact_map.json — "
                        "no L10 blast-radius information available (advisory)"
                    ),
                    severity=Severity.MED,
                    blocking=False,
                    evidence="update_impact_map.json",
                )
            ],
        )

    raw_ids = entry.get("dependent_doc_ids")
    dependent_ids: tuple[str, ...] = (
        tuple(str(x) for x in raw_ids) if isinstance(raw_ids, list) else ()
    )
    description = str(entry.get("description", ""))
    sanitization = str(entry.get("public_sanitization_rule", ""))
    return ChangeImpact(
        change_type=change_type,
        known=True,
        description=description,
        dependent_doc_ids=dependent_ids,
        public_sanitization_rule=sanitization,
        findings=[
            Finding(
                gate="l10_impact",
                message=(
                    f"L10 change {change_type}: review dependent docs "
                    f"[{', '.join(dependent_ids)}] — {sanitization}"
                ),
                severity=Severity.INFO,
                blocking=False,
                evidence="update_impact_map.json",
            )
        ],
    )
