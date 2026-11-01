"""CI cost-control wiring + verifier for the doc-system gate.

Portfolio standard (``~/.claude/rules/ci-cost-control.md`` + ``docs/ci/``): GitHub-hosted
Actions minutes are spent **only when an operator triggers a run and is watching it**. The
doc-system gate (``validate_doc_system`` / ``cli check``) therefore runs in exactly two
places:

* **Locally**, as a ``pre-push`` git hook — free, fast, on every push (Stage 0).
* **On GitHub**, as a ``workflow_dispatch``-only workflow — never on ``push``/``pull_request``
  (Stage 1/3, operator-driven).

This module is the *verifier* that PROVES that wiring: it statically analyzes a GitHub
Actions workflow file and reports any cost-control violation (a forbidden ``push:`` /
``pull_request:`` trigger, a missing ``workflow_dispatch``, a missing ``concurrency`` /
``timeout-minutes`` / least-privilege ``permissions`` block, or ``write-all`` permissions).
It also verifies that the local pre-push hook actually invokes the gate.

It is ADDITIVE and read-only: no network, no writes, deterministic (findings sorted). It
imports the engine's shared ``Finding`` / ``GateResult`` / ``Severity`` types — no redefinition.

Fail mode: **fail-closed** — an unreadable / unparseable workflow, or a missing hook, is a
blocking finding, never silently skipped (a gate you cannot verify is not a gate you can
trust). If PyYAML is absent the parser degrades to a conservative regex reader that is
*stricter* (it flags any bare ``push:`` / ``pull_request:`` top-level key) and records an
INFO finding noting the degraded mode — honest, never faked.

CLI::

    python -m tools.docgen.ci_cost_control [--workflow PATH ...] [--hook PATH] [--strict]

Exit code is non-zero whenever any BLOCKING finding exists (mirrors ``GateResult.blocked``).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from tools.docgen.models import Finding, GateResult, Severity

try:  # PyYAML is the accurate path; the regex fallback keeps the verifier honest without it.
    import yaml

    _HAVE_YAML = True
except ImportError:  # pragma: no cover - exercised only on a yaml-less host
    _HAVE_YAML = False

_REPO_ROOT = Path(__file__).resolve().parents[2]

# The doc-system gate's shipped wiring (relative to repo root).
DOCGEN_GATE_WORKFLOW = Path(".github/workflows/docgen-gate.yml")
DOCGEN_PREPUSH_HOOK = Path("tools/docgen/hooks/pre-push.sample")

# Triggers that must NEVER appear on a heavy/gate GitHub-hosted workflow (only the weekly
# security scan may use ``schedule``; the gate uses ``workflow_dispatch`` only).
_FORBIDDEN_TRIGGERS = ("push", "pull_request")

_GATE = "ci_cost_control"

# The gate invocation the local hook MUST contain (either the module entry or the CLI check).
_GATE_INVOCATION_PATTERNS = (
    re.compile(r"tools\.docgen\.validate_doc_system"),
    re.compile(r"tools\.docgen\.cli\b.*\bcheck\b"),
)


def _severity_for(blocking: bool) -> Severity:
    return Severity.HIGH if blocking else Severity.INFO


def _load_workflow(path: Path) -> tuple[dict[object, object] | None, str, Finding | None]:
    """Return ``(parsed_or_None, raw_text, io_finding_or_None)``.

    Fail-closed: a missing/unreadable file yields a blocking ``Finding`` (and ``None`` doc).
    A parse error likewise blocks. ``raw_text`` is always the file bytes decoded utf-8 (empty
    on IO failure) so the regex fallback / raw scans can run even when structured parse fails.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, "", Finding(
            gate=_GATE,
            message=f"workflow unreadable (fail-closed): {path}",
            severity=Severity.HIGH,
            blocking=True,
            evidence=str(exc),
        )
    if not _HAVE_YAML:
        return None, raw, None
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:  # pragma: no cover - malformed YAML is rare in-repo
        return None, raw, Finding(
            gate=_GATE,
            message=f"workflow YAML unparseable (fail-closed): {path}",
            severity=Severity.HIGH,
            blocking=True,
            evidence=str(exc),
        )
    if not isinstance(parsed, dict):
        return None, raw, Finding(
            gate=_GATE,
            message=f"workflow is not a mapping (fail-closed): {path}",
            severity=Severity.HIGH,
            blocking=True,
        )
    return parsed, raw, None


def _on_triggers(parsed: dict[object, object]) -> set[str]:
    """Extract the set of trigger keys from a parsed workflow ``on:`` block.

    ``on`` may be a string (``on: push``), a list (``on: [push, workflow_dispatch]``), or a
    mapping (``on: {workflow_dispatch: {}}``). PyYAML parses the bareword ``on`` key as the
    boolean ``True`` in YAML 1.1, so we look under both keys.
    """
    # PyYAML parses the bareword ``on`` key as the boolean ``True`` (YAML 1.1); check both.
    on_block: object = parsed.get("on", parsed.get(True))
    if isinstance(on_block, str):
        return {on_block}
    if isinstance(on_block, list):
        return {str(item) for item in on_block}
    if isinstance(on_block, dict):
        return {str(key) for key in on_block}
    return set()


def _regex_triggers(raw: str) -> set[str]:
    """Conservative fallback: any top-level (column-0) ``key:`` under an ``on:`` block.

    Stricter than the YAML path by design — flags a bare ``push:``/``pull_request:`` anywhere
    a trigger could plausibly be declared. Used only when PyYAML is unavailable.
    """
    triggers: set[str] = set()
    in_on = False
    for line in raw.splitlines():
        if re.match(r"^on\s*:", line) or re.match(r"^(True|true)\s*:", line):
            in_on = True
            # inline forms: ``on: [push, workflow_dispatch]`` / ``on: push``
            inline = line.split(":", 1)[1].strip().strip("[]")
            for tok in re.split(r"[,\s]+", inline):
                if tok:
                    triggers.add(tok)
            continue
        if in_on:
            if line and not line[0].isspace():  # dedent to column 0 ends the on: block
                in_on = False
                continue
            key_match = re.match(r"^\s{1,4}([A-Za-z_]+)\s*:", line)
            if key_match:
                triggers.add(key_match.group(1))
    return triggers


def check_workflow_cost_control(path: Path) -> list[Finding]:
    """Assert a GitHub Actions workflow obeys the CI cost-control standard.

    BLOCKS on: a forbidden ``push``/``pull_request`` trigger, a missing ``workflow_dispatch``,
    a missing ``concurrency`` block, ``write-all`` permissions, or any job missing
    ``timeout-minutes``. Read-only + deterministic (findings sorted by message).

    Fail-closed: unreadable/unparseable workflow → single blocking finding.
    """
    parsed, raw, io_finding = _load_workflow(path)
    if io_finding is not None:
        return [io_finding]

    findings: list[Finding] = []
    rel = _rel(path)

    if parsed is None:  # yaml absent → conservative regex mode
        findings.append(
            Finding(
                gate=_GATE,
                message="PyYAML absent — degraded regex trigger scan (conservative)",
                severity=Severity.INFO,
                blocking=False,
                evidence=rel,
            )
        )
        triggers = _regex_triggers(raw)
    else:
        triggers = _on_triggers(parsed)

    for forbidden in _FORBIDDEN_TRIGGERS:
        if forbidden in triggers:
            findings.append(
                Finding(
                    gate=_GATE,
                    message=f"forbidden auto-trigger '{forbidden}:' on {rel}",
                    severity=Severity.HIGH,
                    blocking=True,
                    evidence="CI cost-control: no push/PR triggers on gate workflows",
                )
            )

    if "workflow_dispatch" not in triggers:
        findings.append(
            Finding(
                gate=_GATE,
                message=f"missing 'workflow_dispatch' trigger on {rel}",
                severity=Severity.HIGH,
                blocking=True,
                evidence="gate workflows must be operator-dispatchable",
            )
        )

    # Structured hygiene checks only run when YAML gave us a real mapping.
    if parsed is not None:
        findings.extend(_check_hygiene(parsed, rel))

    findings.sort(key=lambda f: (not f.blocking, f.message))
    return findings


def _check_hygiene(parsed: dict[object, object], rel: str) -> list[Finding]:
    """Concurrency + least-privilege permissions + per-job timeouts."""
    findings: list[Finding] = []

    if "concurrency" not in parsed:
        findings.append(
            Finding(
                gate=_GATE,
                message=f"missing 'concurrency' block on {rel}",
                severity=Severity.MED,
                blocking=True,
                evidence="cost-control: cancel superseded runs",
            )
        )

    permissions = parsed.get("permissions")
    if permissions == "write-all" or (
        isinstance(permissions, dict)
        and any(str(v) == "write-all" for v in permissions.values())
    ):
        findings.append(
            Finding(
                gate=_GATE,
                message=f"'permissions: write-all' forbidden on {rel}",
                severity=Severity.HIGH,
                blocking=True,
            )
        )
    if permissions is None:
        findings.append(
            Finding(
                gate=_GATE,
                message=f"missing least-privilege 'permissions' block on {rel}",
                severity=Severity.MED,
                blocking=True,
                evidence="declare read-only permissions explicitly",
            )
        )

    jobs = parsed.get("jobs")
    if isinstance(jobs, dict):
        for job_name, job in sorted(jobs.items()):
            if isinstance(job, dict) and "timeout-minutes" not in job:
                findings.append(
                    Finding(
                        gate=_GATE,
                        message=f"job '{job_name}' missing 'timeout-minutes' on {rel}",
                        severity=Severity.MED,
                        blocking=True,
                    )
                )
    return findings


def check_prepush_hook(path: Path) -> list[Finding]:
    """Assert the local pre-push hook invokes the doc-system gate (Stage 0, free/local).

    Fail-closed: a missing/unreadable hook is a blocking finding — the whole point of the
    cost-control model is that the cheap check runs locally, so a hook that does not exist or
    does not call the gate is a real wiring defect.
    """
    rel = _rel(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [
            Finding(
                gate=_GATE,
                message=f"pre-push hook unreadable (fail-closed): {rel}",
                severity=Severity.HIGH,
                blocking=True,
                evidence=str(exc),
            )
        ]

    if any(pat.search(text) for pat in _GATE_INVOCATION_PATTERNS):
        return [
            Finding(
                gate=_GATE,
                message=f"pre-push hook invokes the doc-system gate ({rel})",
                severity=Severity.INFO,
                blocking=False,
            )
        ]
    return [
        Finding(
            gate=_GATE,
            message=f"pre-push hook does not invoke the doc-system gate ({rel})",
            severity=Severity.HIGH,
            blocking=True,
            evidence="expected 'tools.docgen.validate_doc_system' or 'cli … check'",
        )
    ]


def audit(
    *,
    workflows: list[Path] | None = None,
    hook: Path | None = None,
    repo_root: Path | None = None,
) -> GateResult:
    """Full cost-control audit of the doc-system gate wiring.

    Defaults to the shipped ``docgen-gate.yml`` workflow + ``pre-push.sample`` hook. Returns a
    ``GateResult`` whose ``ok`` is True only when no blocking finding exists.
    """
    root = repo_root or _REPO_ROOT
    wf_paths = workflows if workflows is not None else [root / DOCGEN_GATE_WORKFLOW]
    hook_path = hook if hook is not None else (root / DOCGEN_PREPUSH_HOOK)

    findings: list[Finding] = []
    for wf in wf_paths:
        findings.extend(check_workflow_cost_control(wf))
    findings.extend(check_prepush_hook(hook_path))
    findings.sort(key=lambda f: (not f.blocking, f.message))
    return GateResult(gate=_GATE, findings=findings)


def _rel(path: Path) -> str:
    """Repo-relative POSIX path when possible, else the basename (deterministic, no abs leak)."""
    try:
        return path.resolve().relative_to(_REPO_ROOT).as_posix()
    except ValueError:
        return path.name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.docgen.ci_cost_control",
        description="Verify the doc-system gate is wired per the CI cost-control standard.",
    )
    parser.add_argument(
        "--workflow",
        action="append",
        default=None,
        help="workflow YAML to check (repeatable); default: the shipped docgen-gate.yml",
    )
    parser.add_argument(
        "--hook",
        default=None,
        help="pre-push hook to check; default: tools/docgen/hooks/pre-push.sample",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat advisory (non-blocking) findings as failures too",
    )
    args = parser.parse_args(argv)

    workflows = [Path(w) for w in args.workflow] if args.workflow else None
    hook = Path(args.hook) if args.hook else None
    result = audit(workflows=workflows, hook=hook)

    for finding in sorted(result.findings, key=lambda f: (not f.blocking, f.message)):
        stream = sys.stderr if finding.blocking else sys.stdout
        stream.write(f"[{finding.gate}] {finding.severity.value}: {finding.message}\n")

    if result.blocked:
        sys.stderr.write("ci_cost_control: BLOCKED — see findings above\n")
        return 1
    if args.strict and any(not f.blocking and f.severity is not Severity.INFO for f in result.findings):
        sys.stderr.write("ci_cost_control: --strict and advisory findings exist\n")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
