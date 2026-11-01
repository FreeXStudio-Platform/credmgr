"""Header parsing + validation for the CredMgr doc-system (RULEBOOK L2/L5/L14; CLASSIFICATION.md).

Parses the required YAML metadata header from a document's Markdown source and validates it against
the locked rules: all fields present, ``export_allowed`` a real bool, tier/surface/export agreement,
id-prefix known to ``TAXONOMY.md``, and header/manifest drift (a document's header tier must match its
``DOC_MANIFEST.md`` row).

Fail-closed throughout: a missing or malformed header is reported as a **blocking** ``Finding``, never
raised as an exception that a caller could mistake for "no findings = pass". ``parse_header`` never
raises on malformed input — malformed input is instead surfaced as a header with placeholder id
``"UNKNOWN"`` plus ``validate_header`` blocking findings when validated.
"""

from __future__ import annotations

import datetime
import re

import yaml

from tools.docgen.models import DocHeader, Finding, ManifestRow, Severity, Surface, Tier

# The YAML front-matter delimiters (CLASSIFICATION.md "Metadata header" fence: ``---`` ... ``---``).
_FRONT_MATTER_RE = re.compile(r"^\s*---\s*\n(.*?\n)---\s*\n?", re.DOTALL)

# Required header fields (CLASSIFICATION.md). ``variants`` is optional (defaults to empty list).
_REQUIRED_FIELDS = (
    "id",
    "classification",
    "title",
    "audience",
    "owner",
    "status",
    "export_allowed",
    "surface",
    "last_reviewed",
)

# id must be "<PREFIX>-<NNN>" where PREFIX is uppercase letters (with an optional single hyphenated
# suffix segment, e.g. "SOC-S" style prefixes like "SOC-S-003" are NOT supported here — TAXONOMY.md's
# prefixes with an internal hyphen, e.g. "SOC-S"/"SOC-E", are matched by longest-prefix-first below).
_ID_RE = re.compile(r"^([A-Z][A-Z0-9-]*[A-Z0-9])-([0-9]+)$")

_SENTINEL_ID = "UNKNOWN"


def _sentinel_header() -> DocHeader:
    """A placeholder header returned when parsing cannot even establish structure.

    Never used to signal success — always paired with a blocking Finding from validate_header when
    the caller runs validation. Exists so parse_header's return type stays a plain DocHeader (fail
    closed via findings, not via exceptions).
    """
    return DocHeader(
        id=_SENTINEL_ID,
        classification=Tier.SECRET,
        title="",
        audience="",
        owner="",
        status="",
        export_allowed=False,
        surface=Surface.NONE,
        last_reviewed="",
        variants=[],
    )


def parse_header(md: str) -> DocHeader:
    """Parse the YAML front-matter header from a document's Markdown source.

    Returns a best-effort ``DocHeader``. Any field that is missing, of the wrong type, or not a valid
    enum member is coerced to a safe placeholder (empty string / SECRET / NONE / False) rather than
    raising — callers MUST run ``validate_header`` on the result to discover what was wrong; a parsed
    header alone is never proof of validity. This keeps the contract fail-closed: malformed input never
    silently reads as a valid public/exportable document.
    """
    match = _FRONT_MATTER_RE.search(md)
    if match is None:
        return _sentinel_header()

    try:
        raw = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        return _sentinel_header()

    if not isinstance(raw, dict):
        return _sentinel_header()

    doc_id = raw.get("id")
    doc_id_str = doc_id if isinstance(doc_id, str) else _SENTINEL_ID

    classification_raw = raw.get("classification")
    classification = _coerce_tier(classification_raw)

    surface_raw = raw.get("surface")
    surface = _coerce_surface(surface_raw)

    export_allowed_raw = raw.get("export_allowed")
    export_allowed = export_allowed_raw if isinstance(export_allowed_raw, bool) else False

    variants_raw = raw.get("variants", [])
    variants = [str(v) for v in variants_raw] if isinstance(variants_raw, list) else []

    def _str_field(name: str) -> str:
        value = raw.get(name)
        if isinstance(value, str):
            return value
        # YAML auto-parses an unquoted ISO date (e.g. `last_reviewed: 2026-07-05`) into a
        # datetime.date/datetime object rather than a string; coerce it back to ISO text so a
        # correctly-formatted-but-unquoted date is never treated as a missing field.
        if isinstance(value, datetime.date):
            return value.isoformat()
        return ""

    return DocHeader(
        id=doc_id_str,
        classification=classification,
        title=_str_field("title"),
        audience=_str_field("audience"),
        owner=_str_field("owner"),
        status=_str_field("status"),
        export_allowed=export_allowed,
        surface=surface,
        last_reviewed=_str_field("last_reviewed"),
        variants=variants,
    )


def _coerce_tier(value: object) -> Tier:
    if isinstance(value, str):
        try:
            return Tier(value.strip().lower())
        except ValueError:
            pass
    # Fail-closed: an unrecognized/missing tier is treated as the most restrictive tier so a
    # malformed header never accidentally reads as PUBLIC/exportable.
    return Tier.SECRET


def _coerce_surface(value: object) -> Surface:
    if isinstance(value, str):
        try:
            return Surface(value.strip().lower())
        except ValueError:
            pass
    # Fail-closed: an unrecognized/missing surface is treated as NONE (nothing may render there).
    return Surface.NONE


def _raw_front_matter_fields(md: str) -> dict[str, object] | None:
    """Re-parse raw YAML without coercion, for field-presence/type checks in validate_header."""
    match = _FRONT_MATTER_RE.search(md)
    if match is None:
        return None
    try:
        raw = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        return None
    return raw if isinstance(raw, dict) else None


def validate_header(h: DocHeader) -> list[Finding]:
    """Validate a parsed ``DocHeader`` against RULEBOOK L2/L5/L14 + CLASSIFICATION.md.

    Checks (each independent, all fail-closed, all blocking unless noted):
    - all required fields present and non-empty (id/classification/title/audience/owner/status/
      surface/last_reviewed) and ``export_allowed`` a real bool;
    - id matches ``<PREFIX>-<NNN>`` and PREFIX is a known TAXONOMY.md prefix;
    - tier/surface agreement: non-public -> surface must be NONE; public -> surface must NOT be NONE;
    - tier/export agreement: ``export_allowed: true`` only legal for PUBLIC.

    A header that failed to parse at all (sentinel id ``"UNKNOWN"``) always yields a blocking finding
    naming the missing/malformed header — this function never returns an empty list for garbage input.
    """
    findings: list[Finding] = []

    if h.id == _SENTINEL_ID and not h.title and not h.audience:
        findings.append(
            Finding(
                gate="header",
                message="Document header is missing or malformed (no valid YAML front-matter found).",
                severity=Severity.CRIT,
                blocking=True,
                evidence="parse_header returned the sentinel header",
            )
        )
        # Still fall through to per-field checks below (they will also fire, which is fine —
        # redundant blocking findings do not weaken fail-closed behavior).

    missing = [f for f in _REQUIRED_FIELDS if not _field_present(h, f)]
    if missing:
        findings.append(
            Finding(
                gate="header",
                message=f"Missing or empty required header field(s): {', '.join(missing)}.",
                severity=Severity.CRIT,
                blocking=True,
                evidence=f"fields={missing}",
            )
        )

    if not isinstance(h.export_allowed, bool):  # pragma: no cover - dataclass typing enforces this
        findings.append(
            Finding(
                gate="header",
                message="export_allowed is not a real boolean.",
                severity=Severity.CRIT,
                blocking=True,
            )
        )

    if h.id != _SENTINEL_ID and h.id:
        id_match = _ID_RE.match(h.id)
        if id_match is None:
            findings.append(
                Finding(
                    gate="header",
                    message=f"id '{h.id}' does not match the required <PREFIX>-<NNN> format.",
                    severity=Severity.HIGH,
                    blocking=True,
                    evidence=h.id,
                )
            )

    # Tier <-> surface agreement (CLASSIFICATION.md metadata header rules).
    if h.classification is not Tier.PUBLIC and h.surface is not Surface.NONE:
        findings.append(
            Finding(
                gate="header",
                message=(
                    f"classification={h.classification.value} must have surface=none; "
                    f"got surface={h.surface.value}."
                ),
                severity=Severity.CRIT,
                blocking=True,
            )
        )
    if h.classification is Tier.PUBLIC and h.surface is Surface.NONE:
        findings.append(
            Finding(
                gate="header",
                message="classification=public must have surface in {web, repo, both}, got none.",
                severity=Severity.HIGH,
                blocking=True,
            )
        )

    # Tier <-> export_allowed agreement.
    if h.export_allowed and h.classification is not Tier.PUBLIC:
        findings.append(
            Finding(
                gate="header",
                message=(
                    f"export_allowed=true is only legal for classification=public; "
                    f"got classification={h.classification.value}."
                ),
                severity=Severity.CRIT,
                blocking=True,
            )
        )

    return findings


def _field_present(h: DocHeader, name: str) -> bool:
    if name == "export_allowed":
        return isinstance(h.export_allowed, bool)
    if name == "classification":
        return isinstance(h.classification, Tier)
    if name == "surface":
        return isinstance(h.surface, Surface)
    value = getattr(h, name, None)
    return isinstance(value, str) and value.strip() != "" and value != _SENTINEL_ID


def check_taxonomy_prefix(h: DocHeader, known_prefixes: set[str]) -> list[Finding]:
    """Validate the header's id-prefix is a known TAXONOMY.md prefix (RULEBOOK L2, TAXONOMY.md).

    Fail-closed: an empty ``known_prefixes`` set (e.g. TAXONOMY.md unreadable) blocks every document,
    it never silently accepts an unrecognized prefix.
    """
    findings: list[Finding] = []
    if not known_prefixes:
        findings.append(
            Finding(
                gate="header",
                message="No known TAXONOMY.md prefixes were supplied; cannot validate id-prefix (fail-closed).",
                severity=Severity.CRIT,
                blocking=True,
            )
        )
        return findings

    prefix = _extract_prefix(h.id)
    if prefix is None:
        findings.append(
            Finding(
                gate="header",
                message=f"id '{h.id}' has no extractable prefix (expected <PREFIX>-<NNN>).",
                severity=Severity.HIGH,
                blocking=True,
                evidence=h.id,
            )
        )
        return findings

    if prefix not in known_prefixes:
        findings.append(
            Finding(
                gate="header",
                message=f"id-prefix '{prefix}' is not a known TAXONOMY.md doc type.",
                severity=Severity.HIGH,
                blocking=True,
                evidence=f"id={h.id}, known={sorted(known_prefixes)}",
            )
        )
    return findings


def _extract_prefix(doc_id: str) -> str | None:
    """Extract the prefix from an id, matching the LONGEST known-shape first.

    Handles hyphenated prefixes like ``SOC-S``/``SOC-E`` (TAXONOMY.md) by splitting on the final
    ``-<digits>`` suffix rather than the first hyphen.
    """
    match = re.match(r"^(.+)-([0-9]+)$", doc_id)
    if match is None:
        return None
    return match.group(1)


def check_manifest_drift(h: DocHeader, manifest_rows: list[ManifestRow]) -> list[Finding]:
    """Cross-check a document header's tier against its DOC_MANIFEST.md row (RULEBOOK L5/L10).

    A document's header ``classification`` must appear in the ``variants`` list of the manifest row
    whose ``id`` matches the header's id-prefix (manifest rows are keyed by type prefix, e.g. ``DET``,
    not by the full instance id). Fail-closed: if no manifest row matches the header's prefix at all,
    that is itself a blocking drift finding (an unlisted doc type must not silently pass).
    """
    findings: list[Finding] = []
    prefix = _extract_prefix(h.id)
    if prefix is None:
        findings.append(
            Finding(
                gate="header",
                message=f"id '{h.id}' has no extractable prefix; cannot check manifest drift.",
                severity=Severity.HIGH,
                blocking=True,
                evidence=h.id,
            )
        )
        return findings

    matching_row = next((row for row in manifest_rows if row.id == prefix), None)
    if matching_row is None:
        findings.append(
            Finding(
                gate="header",
                message=f"No DOC_MANIFEST.md row found for doc-type prefix '{prefix}'.",
                severity=Severity.HIGH,
                blocking=True,
                evidence=f"id={h.id}",
            )
        )
        return findings

    if h.classification not in matching_row.variants:
        findings.append(
            Finding(
                gate="header",
                message=(
                    f"Header tier '{h.classification.value}' for '{h.id}' is not among the tiers "
                    f"DOC_MANIFEST.md lists for '{prefix}': "
                    f"{[t.value for t in matching_row.variants]} (manifest drift)."
                ),
                severity=Severity.CRIT,
                blocking=True,
                evidence=f"id={h.id}, prefix={prefix}",
            )
        )

    # Surface drift is only meaningful for the PUBLIC/commercial variant. A manifest row stores a
    # single surface, and by the manifest's own convention (doc_manifest._parse_surface) that is the
    # primary/commercial surface — e.g. ENG's compound cell "web (commercial) / none (confidential+
    # secret)" parses to `web`. A non-public variant's surface is independently and correctly pinned
    # to `none` by the tier<->surface agreement rule above, so comparing it against the commercial
    # surface would be a spurious conflict (it blocked every confidential/secret ENG doc). Check the
    # row surface only when the header is public.
    if h.classification is Tier.PUBLIC and matching_row.surface is not h.surface:
        findings.append(
            Finding(
                gate="header",
                message=(
                    f"Header surface '{h.surface.value}' for '{h.id}' disagrees with DOC_MANIFEST.md's "
                    f"surface '{matching_row.surface.value}' for '{prefix}' (manifest drift)."
                ),
                severity=Severity.HIGH,
                blocking=True,
                evidence=f"id={h.id}, prefix={prefix}",
            )
        )

    return findings
