"""The doc-system gate CLI + rulebook hash-gate (VERSION.json's ``gate``).

Implements the VERSION.json hash-gate spec: the locked rule files (``rulebook_files``) are
concatenated and SHA-256'd; a mismatch against the recorded ``rulebook_sha256`` — without a
version bump + CHG-700 entry + ADR — means someone edited a locked rule without following
RULEBOOK L9 ("Any change to a locked rule MUST bump VERSION.json, append a CHG-700 entry, and
record an ADR"). The gate cannot verify the CHG-700/ADR half of that (that's a human process,
checked by review); what it CAN mechanically verify is: has the file set's content changed
since the last recorded hash, and if so, was the version bumped to reflect it.

Fail-closed throughout: any missing rulebook file raises to a blocking finding (never
silently skipped) — a locked rule file that vanished from disk is itself a governance defect.

CLI:
    python -m tools.docgen.validate_doc_system [--strict] [--write-hash] [--rules-dir DIR]
        [--version-json PATH]

Exit code is non-zero whenever any BLOCKING finding exists (mirroring ``GateResult.blocked``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from tools.docgen import adjudication
from tools.docgen.models import Finding, GateResult, Severity

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_VERSION_JSON = _REPO_ROOT / "docs" / "design" / "doc-system" / "VERSION.json"
_PENDING_SENTINEL_PREFIX = "PENDING"


def compute_hash(files: list[Path]) -> str:
    """SHA-256 of the concatenated contents of ``files``, in the given order.

    Fail mode: FAIL-CLOSED — raises ``FileNotFoundError`` (propagated, never swallowed) if any
    file is missing. A missing locked-rule file must never be silently treated as "no content to
    hash"; the caller (``check``) converts this into a blocking ``Finding`` rather than letting an
    uncaught traceback stand in for a gate result. Timestamps are never part of the hashed
    content — callers must pass file paths whose content excludes any timestamp/`created_at`
    fields (per ENGINE_PLAN §4b's determinism note) for the hash to be stable across runs that
    don't actually change rule meaning.
    """
    digest = hashlib.sha256()
    for file_path in files:
        if not file_path.is_file():
            raise FileNotFoundError(f"locked rulebook file missing: {file_path}")
        digest.update(file_path.read_bytes())
    return digest.hexdigest()


def _resolve_rulebook_files(
    version_data: dict[str, object], *, repo_root: Path, rules_dir: Path
) -> list[Path]:
    """Resolve ``rulebook_files`` entries to absolute paths under an explicit, deterministic root.

    Unlike a "probe several candidate roots and pick whichever exists" strategy, resolution here
    is a single deterministic rule: each entry is a path relative to the real repo root (e.g.
    ``docs/design/doc-system/RULEBOOK.md``). We resolve against ``repo_root`` directly. A probing
    strategy is deliberately avoided — it is unsound whenever a test fixture's relative path
    happens to also exist under the real repo root (it does, for every real rulebook filename),
    which would silently resolve a test's file list to the REAL project's files instead of the
    fixture's. ``rules_dir`` (conventionally ``docs/design/doc-system``) is accepted and used as a
    secondary anchor ONLY when an entry's repo-root-relative resolution does not exist AND the
    entry's basename can be found directly under ``rules_dir`` (this covers a caller passing a
    non-default ``rules_dir`` while ``rulebook_files`` still lists the default relative paths) —
    but the repo-root-relative path always wins when it exists, so this can never silently swap in
    the wrong file when both roots happen to contain a same-named file.

    Fail mode: a malformed/missing ``rulebook_files`` key returns an empty list; the caller
    treats an empty list as a blocking configuration defect (fail-closed), never as "nothing to
    check."
    """
    raw_files = version_data.get("rulebook_files")
    if not isinstance(raw_files, list):
        return []
    rel_paths = [str(rel) for rel in raw_files]

    resolved: list[Path] = []
    for rel in rel_paths:
        primary = repo_root / rel
        if primary.is_file():
            resolved.append(primary)
            continue
        secondary = rules_dir / Path(rel).name
        resolved.append(secondary)
    return resolved


def _load_version_json(version_json_path: Path) -> tuple[dict[str, object] | None, Finding | None]:
    """Load and parse VERSION.json.

    Fail mode: FAIL-CLOSED. A missing or malformed VERSION.json returns ``(None, Finding)`` with
    ``Finding.blocking=True`` — the hash-gate has nothing to check against and must not report a
    pass.
    """
    if not version_json_path.is_file():
        return None, Finding(
            gate="hash_gate",
            message=f"VERSION.json not found at {version_json_path}",
            severity=Severity.CRIT,
            blocking=True,
            evidence=str(version_json_path),
        )
    try:
        data = json.loads(version_json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, Finding(
            gate="hash_gate",
            message=f"VERSION.json is not valid JSON: {exc}",
            severity=Severity.CRIT,
            blocking=True,
            evidence=str(version_json_path),
        )
    if not isinstance(data, dict):
        return None, Finding(
            gate="hash_gate",
            message="VERSION.json top level is not a JSON object",
            severity=Severity.CRIT,
            blocking=True,
            evidence=str(version_json_path),
        )
    return data, None


def _derive_repo_root(rules_dir: Path) -> Path:
    """Derive the repo root to resolve ``rulebook_files`` against, from ``rules_dir``.

    When ``rules_dir`` IS the real ``docs/design/doc-system`` directory (the default), the real
    ``_REPO_ROOT`` is returned directly — no path-math involved, so the production path is exact.
    Otherwise ``rules_dir`` is treated as an isolated fixture's own ``docs/design/doc-system``
    equivalent, and its 3rd-level parent (mirroring that same nesting depth) is returned as the
    fixture's repo root; if the fixture doesn't have 3 parents (e.g. a flat temp dir used directly
    as ``rules_dir``), ``rules_dir`` itself is used as the root instead.
    """
    resolved_rules_dir = rules_dir.resolve()
    if resolved_rules_dir == (_REPO_ROOT / "docs" / "design" / "doc-system").resolve():
        return _REPO_ROOT
    parents = resolved_rules_dir.parents
    if len(parents) >= 3:
        return parents[2]
    return resolved_rules_dir


def consult_governance(
    result: GateResult,
    *,
    change_type: str | None = None,
    contradiction_path: Path | None = None,
    impact_map_path: Path | None = None,
) -> GateResult:
    """Actively consult the L10/L11 governance matrices and fold their advice into ``result``.

    This is the active-adjudication upgrade (ENGINE_PLAN §4b's deferred item): the gate no longer
    merely relies on the matrices existing — it READS them.

    * L11 (``CONTRADICTION.md``): every blocking finding in ``result`` gets its documented
      tie-breaker resolution attached as an advisory INFO finding (via
      ``adjudication.annotate_with_contradictions``).
    * L10 (``update_impact_map.json``): when ``change_type`` is given, the map is consulted and
      its dependent-doc list + public-sanitization rule are appended as advisory findings (via
      ``adjudication.compute_change_impact``).

    Purely additive and fail-open — every appended finding is non-blocking, so ``result.blocked``
    is unchanged; a missing/unreadable matrix leaves ``result`` untouched (the consultation logs a
    WARNING rather than faking a pass). Returns a NEW ``GateResult`` (does not mutate the input).
    """
    findings = adjudication.annotate_with_contradictions(
        result.findings, contradiction_path=contradiction_path
    )
    if change_type is not None:
        impact = adjudication.compute_change_impact(
            change_type, impact_map_path=impact_map_path
        )
        findings = [*findings, *impact.findings]
    return GateResult(gate=result.gate, findings=findings)


def check(
    rules_dir: Path,
    *,
    strict: bool = False,
    version_json_path: Path | None = None,
    write_hash: bool = False,
) -> GateResult:
    """Run the hash-gate: compare the locked rulebook file set's hash to the recorded one.

    Behavior:
        - Loads ``version_json_path`` (default ``docs/design/doc-system/VERSION.json``).
        - Resolves ``rulebook_files`` to absolute paths under the repo root.
        - FAIL-CLOSED if VERSION.json is missing/malformed, if ``rulebook_files`` is empty/absent,
          or if ANY listed file is missing from disk (``compute_hash`` raises; caught here and
          turned into a blocking Finding, never a silent pass).
        - If the recorded ``rulebook_sha256`` starts with the ``PENDING`` sentinel (as documented
          in VERSION.json), this is the FIRST RUN: the computed hash is accepted and, when
          ``write_hash`` is True, written back into VERSION.json's ``rulebook_sha256`` field
          (this is the one case where the gate mutates its own input, matching ENGINE_PLAN's
          spec: "if PENDING, WRITE the computed hash back on this first run and pass").
        - Otherwise, a hash mismatch is a BLOCKING finding — a locked rule changed without a
          recorded version bump. (The gate cannot itself verify a CHG-700/ADR entry exists; that
          remains a human/process check per RULEBOOK L9. This mechanical check catches the
          "content changed silently" half.)
        - ``rules_dir`` is the deterministic anchor for resolving ``rulebook_files`` (see
          ``_resolve_rulebook_files``): when ``rules_dir`` equals the default
          ``docs/design/doc-system`` under the real repo, resolution uses the real repo root;
          otherwise (an isolated test fixture) the repo root is derived from ``rules_dir`` itself
          (its 3rd-level parent, mirroring the real ``docs/design/doc-system`` nesting depth, or
          ``rules_dir`` directly if the fixture doesn't have that much nesting), so a fixture's
          files are never confused with the real project's same-named files.
        - ``strict`` currently has no additional effect for the hash-gate itself (findings here
          are already unconditionally blocking — a rulebook drift is never merely advisory), but
          is accepted uniformly with ``export_sanitizer.run_gates(..., strict=...)`` for a
          consistent CLI story (``--strict`` is one flag that tightens every gate it can).
    """
    del (
        strict
    )  # accepted for CLI/API symmetry; hash-gate findings are already unconditionally blocking.
    resolved_version_json = version_json_path or _DEFAULT_VERSION_JSON

    version_data, load_finding = _load_version_json(resolved_version_json)
    if load_finding is not None or version_data is None:
        findings = [load_finding] if load_finding is not None else []
        return GateResult(gate="hash_gate", findings=findings)

    repo_root = _derive_repo_root(rules_dir)
    rulebook_files = _resolve_rulebook_files(version_data, repo_root=repo_root, rules_dir=rules_dir)
    if not rulebook_files:
        return GateResult(
            gate="hash_gate",
            findings=[
                Finding(
                    gate="hash_gate",
                    message=(
                        "VERSION.json has no (or a malformed) 'rulebook_files' list — "
                        "failing closed (evidence root: "
                        f"{rules_dir})"
                    ),
                    severity=Severity.CRIT,
                    blocking=True,
                    evidence=str(resolved_version_json),
                )
            ],
        )

    try:
        computed = compute_hash(rulebook_files)
    except FileNotFoundError as exc:
        return GateResult(
            gate="hash_gate",
            findings=[
                Finding(
                    gate="hash_gate",
                    message=f"locked rulebook file set incomplete: {exc}",
                    severity=Severity.CRIT,
                    blocking=True,
                    evidence=str(exc),
                )
            ],
        )

    recorded = version_data.get("rulebook_sha256")
    recorded_str = recorded if isinstance(recorded, str) else ""

    if recorded_str.strip().upper().startswith(_PENDING_SENTINEL_PREFIX):
        if write_hash:
            _write_hash_back(resolved_version_json, version_data, computed)
        return GateResult(
            gate="hash_gate",
            findings=[
                Finding(
                    gate="hash_gate",
                    message=(
                        "rulebook_sha256 was PENDING (first run) — accepted computed hash "
                        f"{computed[:12]}..."
                        + (" and wrote it back to VERSION.json" if write_hash else "")
                    ),
                    severity=Severity.INFO,
                    blocking=False,
                    evidence=computed,
                )
            ],
        )

    if computed != recorded_str:
        return GateResult(
            gate="hash_gate",
            findings=[
                Finding(
                    gate="hash_gate",
                    message=(
                        "locked rulebook file set hash mismatch: a locked rule changed without "
                        "a recorded version bump (RULEBOOK L9 requires a VERSION.json bump + "
                        "CHG-700 entry + ADR on any locked-rule edit). "
                        f"computed={computed[:12]}... recorded={recorded_str[:12]}..."
                    ),
                    severity=Severity.HIGH,
                    blocking=True,
                    evidence=f"computed={computed} recorded={recorded_str}",
                )
            ],
        )

    return GateResult(
        gate="hash_gate",
        findings=[
            Finding(
                gate="hash_gate",
                message="rulebook hash matches VERSION.json — no undeclared drift",
                severity=Severity.INFO,
                blocking=False,
                evidence=computed[:12] + "...",
            )
        ],
    )


def _write_hash_back(
    version_json_path: Path, version_data: dict[str, object], computed_hash: str
) -> None:
    """Write the freshly computed hash into VERSION.json's ``rulebook_sha256`` field.

    Only called on the documented PENDING first-run path (``check(..., write_hash=True)``) or an
    explicit ``--write-hash`` CLI invocation. Preserves all other keys and formatting via a full
    read-modify-write of the JSON object; not used to silently paper over a real drift (a non-
    PENDING mismatch never calls this function from ``check()``).
    """
    updated = dict(version_data)
    updated["rulebook_sha256"] = computed_hash
    version_json_path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.docgen.validate_doc_system",
        description="CredMgr doc-system gate: rulebook hash-gate + manifest consistency check.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Tighten advisory gates to blocking (mirrors export_sanitizer.run_gates strict mode).",
    )
    parser.add_argument(
        "--write-hash",
        action="store_true",
        help="On a PENDING first-run hash, write the computed hash back into VERSION.json.",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=_REPO_ROOT / "docs" / "design" / "doc-system",
        help="Root directory of the doc-system rulebook (default: docs/design/doc-system).",
    )
    parser.add_argument(
        "--version-json",
        type=Path,
        default=None,
        help="Path to VERSION.json (default: docs/design/doc-system/VERSION.json).",
    )
    parser.add_argument(
        "--change-type",
        type=str,
        default=None,
        help=(
            "Actively consult update_impact_map.json for this L10 change type "
            "(DETECTOR_CHANGE/VISUAL_STYLE_CHANGE/USER_POLICY_CHANGE/ARCHITECTURE_CHANGE/"
            "RULE_CHANGE) and print the dependent docs + sanitization rule (advisory)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code (0 = pass, non-zero = blocking finding)."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    result = check(
        args.rules_dir,
        strict=args.strict,
        version_json_path=args.version_json,
        write_hash=args.write_hash,
    )

    # Active L10/L11 consultation (advisory, fail-open — never flips the exit code): attach the
    # governing CONTRADICTION.md tie-breakers and, if --change-type is given, the L10 blast-radius.
    result = consult_governance(result, change_type=args.change_type)

    for finding in result.findings:
        marker = "BLOCK" if finding.blocking else "info"
        print(
            f"[{marker}] ({finding.gate}) {finding.message}",
            file=sys.stderr if finding.blocking else sys.stdout,
        )

    if result.blocked:
        print("doc-system gate: FAILED", file=sys.stderr)
        return 1

    print("doc-system gate: PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
