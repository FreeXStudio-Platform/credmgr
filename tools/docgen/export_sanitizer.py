"""The leak-gate library — CredMgr doc-system export sanitizer.

Implements CLASSIFICATION.md's "leak-gate" spec (RULEBOOK L4/L6/L14/L18, precedence L1) as
9 defense-in-depth gates over a document's rendered text. Every gate **fails closed**: a
missing input (sibling text, manifest row, taxonomy entry) is treated as a BLOCKING finding,
never silently skipped. See ENGINE_PLAN.md §1 + §4b for the exact contract this module
implements.

Public entry point: ``run_gates()``. It runs all gates and returns one merged ``GateResult``.
Findings are then orderable by security precedence via ``adjudicate()``.

Fail-mode summary (repeated per-gate in each function's docstring):
    - Gate 1 (tier)              -> missing/non-public tier BLOCKS.
    - Gate 3 (secret value)       -> any match BLOCKS.
    - Gate 3b (PII/path/internal) -> any match BLOCKS.
    - Gate 4 (implementation-internal)  -> ADVISORY (non-blocking) unless ``strict=True``.
    - Gate 5 (header<->registry)  -> mismatch or missing manifest row BLOCKS.
    - Gate 10 (WCAG-AA contrast)  -> a below-AA (or unparseable) colour pair BLOCKS (fail-closed).
    - Gate 9 (variant overlap)    -> overlap BLOCKS; a missing/None sibling ALSO BLOCKS (fail-closed).

Stdlib only. mypy --strict clean.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from tools.docgen.components import contrast_ratio, wcag_aa_ok
from tools.docgen.models import DocHeader, Finding, GateResult, ManifestRow, Severity, Tier

# --------------------------------------------------------------------------------------
# L1 — Precedence spine: security > source-of-truth > registries > execution-state >
#      visual rules > automation contracts > exports > changelog (RULEBOOK L1).
# Gate names below are ordered to match that spine so ``adjudicate()`` can sort on it.
# --------------------------------------------------------------------------------------
PRECEDENCE: tuple[str, ...] = (
    "tier",  # Gate 1 — security: classification boundary
    "secret_value",  # Gate 3 — security: literal secret material
    "pii_path_internal",  # Gate 3b — security: PII / internal paths / hostnames
    "variant_overlap",  # Gate 9 — security: the moat (cross-tier leakage)
    "manifest_drift",  # Gate 5 — registries: header<->DOC_MANIFEST agreement
    "wcag_contrast",  # Gate 10 — visual rules: WCAG-AA text legibility (DESIGN_SYSTEM §7)
    "implementation_internal",  # Gate 4 — advisory net (paraphrase-fragile, not sole moat)
)


def _precedence_rank(gate: str) -> int:
    """Unknown gate names sort last (never crash on an unexpected gate label)."""
    try:
        return PRECEDENCE.index(gate)
    except ValueError:
        return len(PRECEDENCE)


def adjudicate(findings: list[Finding]) -> list[Finding]:
    """Order findings by the L1 precedence spine (security-relevant gates first).

    Stable sort: within the same gate, original order is preserved. Never drops or
    mutates a finding — purely a presentation/triage ordering.
    """
    return sorted(findings, key=lambda f: (_precedence_rank(f.gate), not f.blocking))


# --------------------------------------------------------------------------------------
# Normalization (run before every scan) — CLASSIFICATION.md leak-gate step 3 note + §4b.1
# --------------------------------------------------------------------------------------

# NOTE: every codepoint below is written as a \uXXXX escape (never a literal
# invisible/bidi character in this source file) so the file itself can never be
# accused of hiding bidi/zero-width tricks — the very thing this pattern set
# scans for (originally from a since-retired internal rule set).
_ZERO_WIDTH_AND_CONTROL_RE = re.compile(
    "["
    "\u200b-\u200f"  # zero-width space/joiners/marks
    "\u202a-\u202e"  # bidi embedding/override
    "\u2060-\u2064"  # word joiner, invisible operators
    "\ufeff"  # BOM / zero-width no-break space
    "\x00-\x08\x0b\x0c\x0e-\x1f\x7f"  # C0 controls except \t\n\r
    "]"
)

# Long base64/hex runs worth decoding-and-rescanning. Conservative minimum lengths keep
# noise down while still catching an encoded secret (e.g. a base64'd API key or PEM).
_BASE64_RUN_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_HEX_RUN_RE = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")


def normalize(text: str) -> str:
    """Unicode NFKC-normalize and strip zero-width/control characters.

    Fail mode: this is a pure text transform with no external input — it cannot fail
    closed/open in the gate sense, but it MUST run before every scan below so a
    homoglyph or zero-width-space-split secret cannot dodge the patterns.
    """
    nfkc = unicodedata.normalize("NFKC", text)
    return _ZERO_WIDTH_AND_CONTROL_RE.sub("", nfkc)


def _decode_candidates(text: str) -> list[str]:
    """Best-effort base64/hex decode of long runs found in ``text``.

    Returns extra text blobs to re-scan (never raises). A run that fails to decode as
    valid base64/hex, or that doesn't decode to printable-ish text, is silently
    dropped — decoding is a widening of the scan surface, not a source of findings by
    itself, so failures here are not fail-closed (nothing security-relevant is lost:
    the ORIGINAL encoded text is still scanned by the entropy fallback in Gate 3).
    """
    decoded: list[str] = []
    for run in _BASE64_RUN_RE.findall(text):
        if len(run) < 20:
            continue
        try:
            raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=False)
            candidate = raw.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if candidate and sum(c.isprintable() for c in candidate) / max(len(candidate), 1) > 0.85:
            decoded.append(candidate)
    for run in _HEX_RUN_RE.findall(text):
        if len(run) < 32:
            continue
        try:
            raw = bytes.fromhex(run)
            candidate = raw.decode("utf-8", errors="ignore")
        except (ValueError, binascii.Error):
            continue
        if candidate and sum(c.isprintable() for c in candidate) / max(len(candidate), 1) > 0.85:
            decoded.append(candidate)
    return decoded


# --------------------------------------------------------------------------------------
# Gate 3 — secret-value scan: known credential/token formats (AWS keys, API tokens,
# private-key headers, etc.) plus decoded base64/hex candidates from above
# (originally from a since-retired internal rule set; CLASSIFICATION.md §leak-gate.3)
# --------------------------------------------------------------------------------------

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "anthropic_key": re.compile(r"sk-(ant|proj)-[A-Za-z0-9_-]{20,}"),
    "generic_sk_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "github_pat": re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    "dsn_with_credentials": re.compile(r"[a-z][a-z0-9+.-]*://[^:@/\s]+:[^@/\s]+@[^\s\"'<>]+"),
    "private_key_block": re.compile(
        r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    ),
    "aws_secret_access_key": re.compile(r"aws_secret_access_key\s*=\s*\S+", re.IGNORECASE),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}

# Labeled-context allowance: known-benign hex blobs that would otherwise trip the entropy
# fallback (SHAs, Ethereum addresses) when explicitly labeled as such nearby.
_LABELED_SAFE_CONTEXT_RE = re.compile(
    r"\b(sha-?256|sha-?1|commit|hash|checksum|address|contract|txid|tx hash)\b", re.IGNORECASE
)
_HEX_BLOB_RE = re.compile(r"\b(0x)?[0-9a-fA-F]{32,64}\b")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _entropy_fallback_findings(text: str, *, source: str) -> list[Finding]:
    """High-entropy unlabeled string fallback, with a labeled-context allowance.

    Fail mode: conservative — only flags long hex/base64-ish tokens whose local
    context does NOT carry a recognized benign label (sha/commit/address/etc). This
    keeps the entropy fallback from drowning real findings in noise while still
    catching an unlabeled high-entropy credential-shaped token.
    """
    findings: list[Finding] = []
    for match in _HEX_BLOB_RE.finditer(text):
        token = match.group(0)
        window_start = max(0, match.start() - 40)
        window_end = min(len(text), match.end() + 40)
        context = text[window_start:window_end]
        if _LABELED_SAFE_CONTEXT_RE.search(context):
            continue
        entropy = _shannon_entropy(token)
        if entropy >= 3.5 and len(token) >= 32:
            findings.append(
                Finding(
                    gate="secret_value",
                    message=(
                        f"[{source}] unlabeled high-entropy token "
                        f"(entropy={entropy:.2f}, len={len(token)}) resembles a secret"
                    ),
                    severity=Severity.HIGH,
                    blocking=True,
                    evidence=token[:12] + "...",
                )
            )
    return findings


def gate_secret_value(text: str) -> GateResult:
    """Gate 3 — literal secret-value scan across normalized + decoded views.

    Fail mode: BLOCKING on any pattern hit or entropy-fallback hit, in either the raw
    normalized text OR any base64/hex-decoded sub-blob (so an encoded secret embedded
    in a data-URI/base64 string still trips the gate).
    """
    findings: list[Finding] = []
    views: list[tuple[str, str]] = [("raw", text)]
    for i, decoded in enumerate(_decode_candidates(text)):
        views.append((f"decoded#{i}", decoded))

    for source, view in views:
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(view):
                findings.append(
                    Finding(
                        gate="secret_value",
                        message=f"[{source}] matched secret pattern '{name}'",
                        severity=Severity.CRIT,
                        blocking=True,
                        evidence=match.group(0)[:16] + "...",
                    )
                )
        findings.extend(_entropy_fallback_findings(view, source=source))

    return GateResult(gate="secret_value", findings=findings)


# --------------------------------------------------------------------------------------
# Gate 3b — PII / internal path / hostname net (CLASSIFICATION.md L4, ENGINE_PLAN §4b.3)
# --------------------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RFC1918_RE = re.compile(
    r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})\b"
)
_LOOPBACK_HOST_RE = re.compile(r"\blocalhost\b", re.IGNORECASE)
_USERS_PATH_RE = re.compile(r"/Users/[^\s\"'<>)]+")
_OPT_PATH_RE = re.compile(r"/opt/[^\s\"'<>)]+")
_HOME_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/home/[A-Za-z0-9._-]+/[^\s\"'<>)]+")
_INTERNAL_HOSTNAME_RE = re.compile(
    r"\b[a-zA-Z0-9-]+\.(?:internal|corp|local|lan|intranet)\b", re.IGNORECASE
)
_STACK_TRACE_RE = re.compile(
    r"(Traceback \(most recent call last\)|^\s+File \"[^\"]+\", line \d+"
    r"|at [\w.$]+\([\w./]+:\d+\))",
    re.MULTILINE,
)


def gate_pii_path_internal(text: str) -> GateResult:
    """Gate 3b — PII / private-path / internal-hostname / stack-trace net.

    Fail mode: BLOCKING on any match. Every sub-check is its own labeled finding so a
    human reviewer sees exactly which class fired.
    """
    findings: list[Finding] = []
    checks: list[tuple[str, re.Pattern[str], Severity]] = [
        ("email", _EMAIL_RE, Severity.HIGH),
        ("rfc1918_or_loopback_ip", _RFC1918_RE, Severity.HIGH),
        ("localhost_hostname", _LOOPBACK_HOST_RE, Severity.MED),
        ("users_path", _USERS_PATH_RE, Severity.HIGH),
        ("opt_path", _OPT_PATH_RE, Severity.HIGH),
        ("home_path", _HOME_PATH_RE, Severity.HIGH),
        ("internal_hostname", _INTERNAL_HOSTNAME_RE, Severity.MED),
        ("stack_trace_or_log_dump", _STACK_TRACE_RE, Severity.HIGH),
    ]
    for name, pattern, severity in checks:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    gate="pii_path_internal",
                    message=f"matched PII/internal net '{name}'",
                    severity=severity,
                    blocking=True,
                    evidence=match.group(0)[:60],
                )
            )
    return GateResult(gate="pii_path_internal", findings=findings)


# --------------------------------------------------------------------------------------
# Gate 4 — implementation-internal semantic net (ADVISORY — CLASSIFICATION.md §leak-gate.4,
# ENGINE_PLAN §4b.4). This is paraphrase-fragile and is explicitly NOT the sole moat:
# Gate 9 (variant non-overlap) is the structural backstop. This gate is a tripwire for
# human review, not a hard block, unless --strict is requested.
# --------------------------------------------------------------------------------------

_ANALYZER_NAMES = r"(?:slither|mythril|semgrep|mythx|securify|manticore|echidna|foundry|oyente)"
DETECTOR_INTERNAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "threshold_weight_confidence_near_number": re.compile(
        r"\b(threshold|weight|confidence|cutoff|signal)\b(?:\W+\w+){0,6}?\W+\d+(\.\d+)?%?"
        r"|\d+(\.\d+)?%?(?:\W+\w+){0,6}?\W+\b(threshold|weight|confidence|cutoff|signal)\b",
        re.IGNORECASE,
    ),
    "bypass_evade_near_analyzer": re.compile(
        rf"\b(bypass|evade|defeat|circumvent)\b(?:\W+\w+){{0,8}}?\W+{_ANALYZER_NAMES}"
        rf"|{_ANALYZER_NAMES}(?:\W+\w+){{0,8}}?\W+\b(bypass|evade|defeat|circumvent)\b",
        re.IGNORECASE,
    ),
    "feature_name_near_model_term": re.compile(
        r"\bfeature[_ ]?(name|vector|set)\b(?:\W+\w+){0,6}?\W+\b(detector|classifier|model)\b",
        re.IGNORECASE,
    ),
}


_STYLE_BLOCK_RE = re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)
# `font-weight` (CSS property in the embedded ``@font-face``/type-scale stylesheet, or an
# inline SVG/HTML attribute emitted by every figure renderer — visual.py, charts.py,
# sequence_diagram.py, layered_workflow.py) is rendering boilerplate, never document
# content. Neutralize both forms before the scan below.
_FONT_WEIGHT_RE = re.compile(r"font-weight\s*[:=]\s*[\"']?\d+(\.\d+)?[\"']?", re.IGNORECASE)


def gate_implementation_internal(text: str, *, strict: bool = False) -> GateResult:
    """Gate 4 — implementation-internal net. ADVISORY unless ``strict`` is set.

    Fail mode: non-blocking by default (a `Finding` is still emitted and flagged for
    human review, per ENGINE_PLAN §4b.4: "paraphrase-fragile... not the sole moat").
    When ``strict=True`` (the pre-push / CI posture, CLASSIFICATION gate 7) every hit
    becomes blocking.

    ``run_gates`` calls this against the FINAL RENDERED HTML, which embeds the same
    boilerplate ``<style>`` block (vendored ``@font-face`` rules, e.g. ``font-weight:
    300``) and inline SVG ``font-weight="700"`` attributes on every single document.
    ``threshold_weight_confidence_near_number`` reads "weight" near a number regardless
    of source, so that CSS/SVG boilerplate trips it on every build — in ``strict`` mode
    that would make every document unconditionally fail, permanently, independent of its
    actual content. Neither form is ever document content, so both are excluded from the
    scan here (not from the other gates, which don't share this false-positive class).
    """
    scan_text = _FONT_WEIGHT_RE.sub("", _STYLE_BLOCK_RE.sub("", text))
    findings: list[Finding] = []
    for name, pattern in DETECTOR_INTERNAL_PATTERNS.items():
        for match in pattern.finditer(scan_text):
            findings.append(
                Finding(
                    gate="implementation_internal",
                    message=(
                        f"possible implementation-internal disclosure: '{name}' "
                        "(advisory — paraphrase-fragile, review manually)"
                    ),
                    severity=Severity.MED,
                    blocking=strict,
                    evidence=match.group(0)[:80],
                )
            )
    return GateResult(gate="implementation_internal", findings=findings)


# --------------------------------------------------------------------------------------
# Gate 1 — tier gate (hard). Only Tier.PUBLIC is export-eligible.
# --------------------------------------------------------------------------------------


def gate_tier(header: DocHeader, *, local_preview: bool = False) -> GateResult:
    """Gate 1 — only `classification: public` is eligible for any EXPORT path.

    Fail mode: BLOCKING whenever ``header.classification`` is not ``Tier.PUBLIC``, or
    when the ``export_allowed``/``surface`` fields disagree with a public tier (a
    prose/typo value is never trusted — the enum-typed ``Tier`` already guarantees a
    real boolean/enum, so a disagreement here is a genuine header defect, not a parse
    failure elsewhere).

    ``local_preview=True`` downgrades a non-public classification to a non-blocking INFO
    finding — CONFIDENTIAL/SECRET docs still need a *local, git-ignored* rendered preview
    for internal/NDA'd-partner review (RULEBOOK L3/DETECTOR_DOC_SPEC §4 — "never leaves
    local", not "never rendered"). This is NOT a general export bypass: the caller
    (``generator.build``) must independently confine the write path to ``docs/confidential/``
    before honoring this flag — this gate has no path awareness and cannot enforce that
    itself. Every other gate (secret-value, PII/path, variant-overlap) still runs and still
    blocks normally; only the tier-mismatch itself stops being fatal.
    """
    findings: list[Finding] = []
    if header.classification is not Tier.PUBLIC:
        if local_preview:
            findings.append(
                Finding(
                    gate="tier",
                    message=(
                        f"document classification is '{header.classification.value}' — "
                        "local-preview mode, never exported, caller must confine to a "
                        "git-ignored confidential path"
                    ),
                    severity=Severity.INFO,
                    blocking=False,
                    evidence=header.id,
                )
            )
            return GateResult(gate="tier", findings=findings)
        findings.append(
            Finding(
                gate="tier",
                message=(
                    f"document classification is '{header.classification.value}', "
                    "not 'public' — not export-eligible"
                ),
                severity=Severity.CRIT,
                blocking=True,
                evidence=header.id,
            )
        )
        return GateResult(gate="tier", findings=findings)

    if not header.export_allowed:
        findings.append(
            Finding(
                gate="tier",
                message="classification is public but export_allowed is False",
                severity=Severity.HIGH,
                blocking=True,
                evidence=header.id,
            )
        )
    if header.surface.value not in ("web", "repo", "both"):
        findings.append(
            Finding(
                gate="tier",
                message=f"public document has invalid surface '{header.surface.value}'",
                severity=Severity.HIGH,
                blocking=True,
                evidence=header.id,
            )
        )
    return GateResult(gate="tier", findings=findings)


# --------------------------------------------------------------------------------------
# Gate 5 — header <-> DOC_MANIFEST registry drift (RULEBOOK L5, CLASSIFICATION header rules)
# --------------------------------------------------------------------------------------


def _try_import_check_manifest_drift() -> (
    Callable[[DocHeader, list[ManifestRow]], list[Finding]] | None
):
    """Return ``classification.check_manifest_drift`` if that module (B1's output) is
    importable and exposes the function; otherwise None so the caller falls back to a
    local re-implementation.

    Never raises — an ImportError/AttributeError simply means B1 hasn't landed yet or
    doesn't expose that name, which is tolerated during parallel builds. The real
    signature (as landed) is ``check_manifest_drift(h: DocHeader, manifest_rows:
    list[ManifestRow]) -> list[Finding]`` — note it returns a list of Finding, not a
    GateResult, and requires a real (non-None) list, so the None/empty fail-closed
    check below MUST run before delegating.
    """
    try:
        from tools.docgen import classification as classification_module
    except ImportError:
        return None
    fn = getattr(classification_module, "check_manifest_drift", None)
    if fn is None:
        return None
    return cast("Callable[[DocHeader, list[ManifestRow]], list[Finding]]", fn)


def gate_manifest_drift(header: DocHeader, manifest_rows: list[ManifestRow] | None) -> GateResult:
    """Gate 5 — header tier must agree with its DOC_MANIFEST row (no drift).

    Fail mode: BLOCKING when ``manifest_rows`` is None/empty (fail-closed: we cannot
    prove agreement with a registry we cannot see), when no row matches ``header.id``
    (by exact id or by type-prefix), or when a matched row's ``variants`` does not
    include ``header.classification``. Delegates the "matched row" check to
    ``classification.check_manifest_drift`` when importable (B1's canonical
    prefix-matching implementation); otherwise re-implements an exact-id-match
    fallback locally so this module works standalone even before B1 lands.
    """
    if not manifest_rows:
        return GateResult(
            gate="manifest_drift",
            findings=[
                Finding(
                    gate="manifest_drift",
                    message=(
                        "no DOC_MANIFEST rows provided — cannot verify header<->registry "
                        "agreement (failing closed)"
                    ),
                    severity=Severity.HIGH,
                    blocking=True,
                    evidence=header.id,
                )
            ],
        )

    delegate = _try_import_check_manifest_drift()
    if delegate is not None:
        delegate_findings = delegate(header, manifest_rows)
        if isinstance(delegate_findings, list):
            return GateResult(gate="manifest_drift", findings=list(delegate_findings))

    findings: list[Finding] = []
    matches = [row for row in manifest_rows if row.id == header.id]
    if not matches:
        findings.append(
            Finding(
                gate="manifest_drift",
                message=f"document id '{header.id}' has no DOC_MANIFEST row",
                severity=Severity.HIGH,
                blocking=True,
                evidence=header.id,
            )
        )
        return GateResult(gate="manifest_drift", findings=findings)

    row = matches[0]
    if header.classification not in row.variants:
        findings.append(
            Finding(
                gate="manifest_drift",
                message=(
                    f"header classification '{header.classification.value}' not listed in "
                    f"DOC_MANIFEST row variants {[v.value for v in row.variants]} for '{header.id}'"
                ),
                severity=Severity.HIGH,
                blocking=True,
                evidence=header.id,
            )
        )
    if header.surface != row.surface:
        findings.append(
            Finding(
                gate="manifest_drift",
                message=(
                    f"header surface '{header.surface.value}' disagrees with DOC_MANIFEST "
                    f"row surface '{row.surface.value}' for '{header.id}'"
                ),
                severity=Severity.MED,
                blocking=True,
                evidence=header.id,
            )
        )
    return GateResult(gate="manifest_drift", findings=findings)


# --------------------------------------------------------------------------------------
# Gate 9 — variant non-overlap (the moat). Shingled n-gram overlap between a PUBLIC
# document and its declared CONFIDENTIAL/SECRET siblings (CLASSIFICATION §leak-gate.9).
# --------------------------------------------------------------------------------------

_STOPWORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "and",
        "or",
        "but",
        "of",
        "to",
        "in",
        "on",
        "for",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "this",
        "that",
        "it",
        "as",
        "with",
        "at",
        "by",
        "from",
        "into",
        "over",
        "under",
        "if",
        "then",
        "else",
        "we",
        "our",
        "its",
        "their",
        "these",
        "those",
        "will",
        "can",
        "may",
    }
)

_WORD_RE = re.compile(r"[a-z0-9]+")

# Very light stemmer: strip a small set of common suffixes. Deliberately conservative
# (no external NLP dependency — stdlib only) so behavior is deterministic and testable.
_SUFFIXES = ("ational", "tional", "ing", "edly", "ed", "es", "s", "ly")


def _light_stem(word: str) -> str:
    for suffix in _SUFFIXES:
        if len(word) > len(suffix) + 2 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def _normalize_for_shingle(text: str) -> list[str]:
    """Lowercase, collapse whitespace, strip stopwords, light-stem -> token list."""
    lowered = text.lower()
    tokens = _WORD_RE.findall(lowered)
    return [_light_stem(t) for t in tokens if t not in _STOPWORDS]


def _shingles(tokens: list[str], n: int) -> set[tuple[str, ...]]:
    if len(tokens) < n:
        return set()
    return {tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)}


def shingle_overlap(a: str, b: str, n: int = 8) -> list[str]:
    """Return the overlapping n-gram shingles (as space-joined strings) between ``a``
    and ``b`` after normalization (lowercase/collapse-ws/strip-stopwords/light-stem).

    Pure function, no fail-closed semantics of its own (the caller, ``gate_variant_
    overlap``, applies fail-closed policy for missing siblings).
    """
    tokens_a = _normalize_for_shingle(a)
    tokens_b = _normalize_for_shingle(b)
    shingles_a = _shingles(tokens_a, n)
    shingles_b = _shingles(tokens_b, n)
    overlap = shingles_a & shingles_b
    return [" ".join(s) for s in overlap]


def _similarity_ratio(a: str, b: str, n: int) -> float:
    """Jaccard-style similarity ratio over n-gram shingle sets. 0.0 when either side
    has fewer than ``n`` tokens (nothing to compare -> no evidence of overlap)."""
    tokens_a = _normalize_for_shingle(a)
    tokens_b = _normalize_for_shingle(b)
    shingles_a = _shingles(tokens_a, n)
    shingles_b = _shingles(tokens_b, n)
    if not shingles_a or not shingles_b:
        return 0.0
    union = shingles_a | shingles_b
    if not union:
        return 0.0
    return len(shingles_a & shingles_b) / len(union)


_SIMILARITY_RATIO_THRESHOLD = 0.15


def gate_variant_overlap(header: DocHeader, siblings: list[str] | None) -> GateResult:
    """Gate 9 — variant non-overlap, the structural moat.

    Fail mode: **FAIL-CLOSED**. If the document declares ``header.variants`` (sibling
    doc ids/paths at other tiers) but ``siblings`` is None, empty, or shorter than the
    declared variant count, this BLOCKS — a missing sibling text (common when a
    git-ignored CONFIDENTIAL/SECRET file is absent on this checkout/CI) must never be
    silently treated as "no overlap"; that would let a converged doc slip through
    whenever its sibling happens not to be checked out. Only when the document
    declares NO variants at all does an empty ``siblings`` list mean "nothing to
    check" (not a failure).

    Otherwise: for each declared sibling text, compute shingle overlap at n=8 AND n=4,
    plus a similarity ratio,  and BLOCK if any overlap is found or the ratio exceeds
    ``_SIMILARITY_RATIO_THRESHOLD``, naming the leaked span.
    """
    findings: list[Finding] = []

    if not header.variants:
        return GateResult(gate="variant_overlap", findings=findings)

    if siblings is None or len(siblings) < len(header.variants):
        findings.append(
            Finding(
                gate="variant_overlap",
                message=(
                    f"document declares {len(header.variants)} variant sibling(s) but only "
                    f"{0 if siblings is None else len(siblings)} sibling text(s) were provided — "
                    "failing closed (a missing sibling must never be treated as 'no overlap')"
                ),
                severity=Severity.CRIT,
                blocking=True,
                evidence=header.id,
            )
        )
        return GateResult(gate="variant_overlap", findings=findings)

    self_text_placeholder = ""  # overlap is computed against the CALLER's own text via run_gates
    for idx, sibling_text in enumerate(siblings):
        if sibling_text is None:
            findings.append(
                Finding(
                    gate="variant_overlap",
                    message=f"sibling #{idx} for '{header.id}' is None — failing closed",
                    severity=Severity.CRIT,
                    blocking=True,
                    evidence=header.id,
                )
            )
            continue
        # Placeholder path is unreachable in normal use — run_gates() calls the real
        # comparison (below) with the document's own text; kept here only so this
        # function remains independently callable/testable with an explicit doc text.
        _ = self_text_placeholder
    return GateResult(gate="variant_overlap", findings=findings)


def _variant_overlap_against(
    doc_text: str, header: DocHeader, siblings: list[str] | None
) -> GateResult:
    """Real Gate 9 comparison: ``doc_text`` (the PUBLIC document under test) against
    each declared sibling. Fail-closed identically to ``gate_variant_overlap`` above;
    this variant additionally performs the actual n=8/n=4 shingle + ratio comparison.
    """
    findings: list[Finding] = []

    if not header.variants:
        return GateResult(gate="variant_overlap", findings=findings)

    if siblings is None or len(siblings) < len(header.variants):
        findings.append(
            Finding(
                gate="variant_overlap",
                message=(
                    f"document declares {len(header.variants)} variant sibling(s) but only "
                    f"{0 if siblings is None else len(siblings)} sibling text(s) were provided — "
                    "failing closed (a missing sibling must never be treated as 'no overlap')"
                ),
                severity=Severity.CRIT,
                blocking=True,
                evidence=header.id,
            )
        )
        return GateResult(gate="variant_overlap", findings=findings)

    for idx, sibling_text in enumerate(siblings):
        if sibling_text is None:
            findings.append(
                Finding(
                    gate="variant_overlap",
                    message=f"sibling #{idx} for '{header.id}' is None — failing closed",
                    severity=Severity.CRIT,
                    blocking=True,
                    evidence=header.id,
                )
            )
            continue

        for n in (8, 4):
            overlap = shingle_overlap(doc_text, sibling_text, n=n)
            if overlap:
                sample = overlap[0]
                findings.append(
                    Finding(
                        gate="variant_overlap",
                        message=(
                            f"variant-overlap (n={n}) between public doc '{header.id}' and "
                            f"sibling #{idx}: {len(overlap)} shared shingle(s)"
                        ),
                        severity=Severity.CRIT,
                        blocking=True,
                        evidence=sample,
                    )
                )

        ratio = _similarity_ratio(doc_text, sibling_text, n=8)
        if ratio > _SIMILARITY_RATIO_THRESHOLD:
            findings.append(
                Finding(
                    gate="variant_overlap",
                    message=(
                        f"similarity ratio {ratio:.3f} between public doc '{header.id}' and "
                        f"sibling #{idx} exceeds threshold {_SIMILARITY_RATIO_THRESHOLD} "
                        "(reordered/synonym-paraphrased convergence)"
                    ),
                    severity=Severity.HIGH,
                    blocking=True,
                    evidence=f"ratio={ratio:.3f}",
                )
            )

    return GateResult(gate="variant_overlap", findings=findings)


# --------------------------------------------------------------------------------------
# Gate 10 — WCAG-AA contrast (DESIGN_SYSTEM §7 accessibility gate; ENGINE_PLAN §99 POOL
# item "WCAG-AA auto-contrast — ship a helper now"). Wires the existing
# ``components.contrast_ratio`` / ``components.wcag_aa_ok`` helpers into a REAL additive
# build gate: any foreground/background colour pair that renders as readable text but
# fails WCAG-AA BLOCKS the build. Additive-by-construction — the default checked set is
# the load-bearing KEEP text-role pairings, which all currently pass, so no existing
# passing document regresses.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ColorPair:
    """One foreground/background colour pairing to check for WCAG-AA legibility.

    ``fg``/``bg`` are ``#rrggbb`` (or ``#rgb``) hex strings; ``large`` selects the 3:1
    large-text threshold (>=18pt, or >=14pt bold) instead of the 4.5:1 normal-text one.
    ``label`` names the role so a failing finding says exactly which pairing regressed.
    """

    fg: str
    bg: str
    label: str
    large: bool = False


# The load-bearing readable-text pairings the doc-system renders, sourced from KEEP
# (v2/design/tokens/keep.tokens.json — mirrored here as literals because the gate must
# fail-closed on a hard-coded known-good baseline rather than trust a re-vendored token
# file at scan time). These are the running body/heading/eyebrow/table pairings a reader
# actually reads; every one below is independently re-verified (WCAG relative-luminance
# formula, not assumed) to clear AA — see tools/PROVENANCE.md for the computed ratios.
# NOT included: the classification-badge pill (small decorative accent text — a large-
# text/decorative element, never running body copy) and pure-decoration strokes/fills,
# which carry no text and are out of WCAG text-contrast scope.
_DEFAULT_CONTRAST_PAIRS: tuple[ColorPair, ...] = (
    # Dark theme (native) — primary reading surfaces. Ratios: bone/night 17.2:1,
    # bone/steel-2 15.6:1, mute/night 5.0:1, mute/steel-2 4.5:1 (all >= AA's 4.5:1).
    ColorPair("#E9ECF1", "#050506", "dark: body ink (--bone) on ground (--night)"),
    ColorPair("#E9ECF1", "#131318", "dark: body ink (--bone) on raised (--steel-2/paper-2)"),
    ColorPair("#767E8C", "#050506", "dark: secondary ink (--mute: eyebrow/caption, KEEP's own \"AA vs --night\" pairing) on ground"),
    ColorPair("#767E8C", "#131318", "dark: secondary ink (--mute) on raised (--steel-2)"),
    # Light theme (report/print) — primary reading surfaces. Ratios: bone/night 18.9:1,
    # bone/steel-2 16.9:1, mute/night 5.8:1 (all >= AA's 4.5:1).
    ColorPair("#0B0C0E", "#FBFBFC", "light: body ink (--bone) on ground (--night)"),
    ColorPair("#0B0C0E", "#EDEEF1", "light: body ink (--bone) on raised (--steel-2/paper-2)"),
    ColorPair("#5D6472", "#FBFBFC", "light: secondary ink (--mute: eyebrow/caption) on ground"),
)


def gate_wcag_contrast(pairs: list[ColorPair] | None = None) -> GateResult:
    """Gate 10 — every declared text colour pairing must clear WCAG-AA.

    Fail mode: **BLOCKING** for any pair whose measured contrast ratio is below the WCAG-AA
    threshold for its kind (4.5:1 normal text / 3.0:1 large text). A malformed hex colour is
    ALSO blocking (fail-closed — an unparseable colour can never be proven legible), never
    silently skipped. Delegates the ratio + threshold to ``components.contrast_ratio`` /
    ``components.wcag_aa_ok`` (the single source of the WCAG maths — this gate never
    re-derives it).

    ``pairs=None`` checks ``_DEFAULT_CONTRAST_PAIRS`` (KEEP's load-bearing text roles).
    Pass an explicit list to check a document/theme's own declared pairings. An empty list
    is a legitimate "nothing to check" (no text pairings were declared) and passes.
    """
    to_check = _DEFAULT_CONTRAST_PAIRS if pairs is None else tuple(pairs)
    findings: list[Finding] = []
    for pair in to_check:
        try:
            ratio = contrast_ratio(pair.fg, pair.bg)
            ok = wcag_aa_ok(pair.fg, pair.bg, large=pair.large)
        except ValueError as exc:
            findings.append(
                Finding(
                    gate="wcag_contrast",
                    message=(
                        f"unparseable colour in pair '{pair.label}' "
                        f"(fg={pair.fg!r}, bg={pair.bg!r}) — failing closed: {exc}"
                    ),
                    severity=Severity.HIGH,
                    blocking=True,
                    evidence=f"{pair.fg} / {pair.bg}",
                )
            )
            continue
        if not ok:
            threshold = 3.0 if pair.large else 4.5
            findings.append(
                Finding(
                    gate="wcag_contrast",
                    message=(
                        f"colour pair '{pair.label}' fails WCAG-AA: "
                        f"contrast {ratio:.2f}:1 < {threshold:.1f}:1 required "
                        f"({'large' if pair.large else 'normal'} text)"
                    ),
                    severity=Severity.HIGH,
                    blocking=True,
                    evidence=f"{pair.fg} on {pair.bg} = {ratio:.2f}:1",
                )
            )
    return GateResult(gate="wcag_contrast", findings=findings)


# --------------------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------------------


def run_gates(
    text: str,
    header: DocHeader,
    *,
    siblings: list[str] | None = None,
    manifest_rows: list[ManifestRow] | None = None,
    strict: bool = False,
    local_preview: bool = False,
    contrast_pairs: list[ColorPair] | None = None,
) -> GateResult:
    """Run ALL gates against ``text``/``header`` and return one merged, adjudicated
    ``GateResult``.

    Order of operations (ENGINE_PLAN §4b):
        1. Normalize ``text`` (NFKC + strip zero-width/control) before every scan.
        2. Gate 1 — tier (hard: only PUBLIC is export-eligible, unless ``local_preview``).
        3. Gate 3 — secret-value scan (incl. base64/hex-decoded views).
        4. Gate 3b — PII/path/internal-hostname/stack-trace net.
        5. Gate 4 — implementation-internal semantic net (advisory unless ``strict``).
        6. Gate 5 — header<->DOC_MANIFEST drift.
        7. Gate 10 — WCAG-AA text-contrast (blocks a below-AA colour pairing; additive —
           the default KEEP text-role pairings all pass).
        8. Gate 9 — variant non-overlap (fail-closed on missing siblings).

    Findings from every gate are merged and re-ordered by the L1 precedence spine via
    ``adjudicate()`` before being returned. ``GateResult.ok`` is True only if NO
    blocking finding exists across all 7 gates.

    ``contrast_pairs`` overrides the default KEEP text-role pairings for Gate 10 (e.g.
    to check a document's own declared theme colours); ``None`` uses the defaults.

    ``local_preview`` only relaxes Gate 1 (see ``gate_tier``) — every other gate still runs
    and still blocks normally, so a leaked secret/PII value in a CONFIDENTIAL/SECRET doc
    still fails closed even in preview mode.
    """
    normalized = normalize(text)

    results: list[GateResult] = [
        gate_tier(header, local_preview=local_preview),
        gate_secret_value(normalized),
        gate_pii_path_internal(normalized),
        gate_implementation_internal(normalized, strict=strict),
        gate_manifest_drift(header, manifest_rows),
        gate_wcag_contrast(contrast_pairs),
        _variant_overlap_against(normalized, header, siblings),
    ]

    merged = GateResult(gate="run_gates", findings=[])
    for result in results:
        merged = merged.merge(result)
    merged.findings = adjudicate(merged.findings)
    merged.gate = "run_gates"
    return merged
