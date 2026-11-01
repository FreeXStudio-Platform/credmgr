"""Release-verification drift check: is ``v2/docs/RELEASE_VERIFICATION.md`` still a list of the shipped controls?

Run: ``python3 -m tools.release_verification_check`` from the repo root.
Exit 0 clean, 1 findings, 2 usage error or an input that cannot be read.
``--self-test`` proves the check can fail (it mutates the document in memory and requires a finding for each mutation).

Why this exists. ``RELEASE_VERIFICATION.md`` has one row per control of the built app, derived from the shipped templates
(``v2/apps/desktop/src/design/screens/*.html`` and ``app.template.html``). The rows were produced by extraction scripts
that lived only in a session scratchpad, so the first template edit would have left the checklist describing a screen
that no longer exists, and nothing would have said so (the verifier of 2026-10-03 named this). This is the guard: it
re-extracts the controls from the templates on every run and compares them with the document.

What it checks, per template:

* a section ``### <Title> — `<template>` `` exists in §2 for every template, and for no template that does not exist;
* the number of table rows equals the number of controls the template draws (every element that carries an event
  binding, plus every ``input``, ``select``, ``textarea`` and ``a``; components named ``sc-*`` are layout, not controls);
* every handler a template binds appears in that section's *Event* column, and every handler named there is bound
  by the template;
* the ``**Size.**`` line states the true row total and the true number of screen templates.

What it does not check: that an *expected result* is right, or that a row's bridge command and broker op are the ones
the handler really sends. That is a human reading, and the *Result* column is a human's too. A green run here means
"the checklist covers exactly the controls that ship", never "the controls work".

Stdlib only, like the rest of ``tools/``. It is deliberately not part of ``corpus_check``'s default run: that run is
repeated in the published tree, where a front-end source path may not exist, and a gate that fails there for a missing
input would be removed rather than obeyed. Run it whenever a ``src/design`` template or the checklist changes (CONTRIBUTING).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DESIGN_DIR = REPO_ROOT / "v2" / "apps" / "desktop" / "src" / "design"
SCREENS_DIR = DESIGN_DIR / "screens"
SCAFFOLD = DESIGN_DIR / "app.template.html"
DOC = REPO_ROOT / "v2" / "docs" / "RELEASE_VERIFICATION.md"
SCAFFOLD_NAME = "app.template.html"

# An opening tag and its attributes. A component (`sc-*`) is layout; everything else counts when it is bound or is a form control or link.
_TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9-]*)(\s[^<>]*?)?/?>", re.S)
_EVENT_RE = re.compile(r'\bon([A-Z][A-Za-z]*)="\{\{([A-Za-z0-9_.]+)\}\}"')
_CONTROL_TAGS = ("input", "select", "textarea", "a")

_SECTION_RE = re.compile(r"^### .* — `([^`]+)`\s*$")
_HANDLER_RE = re.compile(r"→ `([A-Za-z0-9_.]+)`")
_SIZE_RE = re.compile(r"\*\*Size\.\*\*\s+(\d+)\s+control rows in\s+(\d+)\s+screen templates")


@dataclass(frozen=True)
class Finding:
    subject: str
    message: str


def extract_controls(text: str) -> list[tuple[str, list[str]]]:
    """Every control a template draws, as ``(tag, [handler, ...])``, in source order."""
    controls: list[tuple[str, list[str]]] = []
    for match in _TAG_RE.finditer(text):
        tag = match.group(1).lower()
        if tag.startswith("sc-"):
            continue
        events = _EVENT_RE.findall(match.group(2) or "")
        if events or tag in _CONTROL_TAGS:
            controls.append((tag, [handler for _, handler in events]))
    return controls


def read_templates() -> dict[str, str]:
    """``{template name: source}`` for every screen template and the page scaffolding."""
    if not SCREENS_DIR.is_dir() or not SCAFFOLD.is_file():
        raise FileNotFoundError(f"cannot find the front-end templates under {DESIGN_DIR}")
    templates = {path.stem: path.read_text(encoding="utf-8") for path in sorted(SCREENS_DIR.glob("*.html"))}
    templates[SCAFFOLD_NAME] = SCAFFOLD.read_text(encoding="utf-8")
    return templates


def parse_document(text: str) -> tuple[dict[str, list[str]], str]:
    """``({section name: [row line, ...]}, text of the document)`` for the screen sections of §2 only."""
    sections: dict[str, list[str]] = {}
    in_screens = False
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("## "):
            in_screens = line.startswith("## 2.")
            current = None
            continue
        if not in_screens:
            continue
        section = _SECTION_RE.match(line)
        if section:
            current = section.group(1)
            sections.setdefault(current, [])
            continue
        if current is not None and line.startswith("| ") and not line.startswith("| Control") and not line.startswith("|---"):
            sections[current].append(line)
    return sections, text


def event_handlers(row: str) -> set[str]:
    """The handlers named in a row's *Event* column (the second cell)."""
    cells = row.split("|")
    return set(_HANDLER_RE.findall(cells[2])) if len(cells) > 2 else set()


def check(templates: dict[str, str], doc_text: str) -> list[Finding]:
    sections, _ = parse_document(doc_text)
    findings: list[Finding] = []
    total_rows = 0
    for name, source in templates.items():
        controls = extract_controls(source)
        rows = sections.get(name)
        if rows is None:
            findings.append(Finding(name, f"no section for this template in §2 ({len(controls)} control(s) unlisted)"))
            continue
        total_rows += len(rows)
        if len(rows) != len(controls):
            findings.append(Finding(name, f"the template draws {len(controls)} control(s) and the checklist has {len(rows)} row(s)"))
        bound = {handler for _, handlers in controls for handler in handlers}
        listed: set[str] = set()
        for row in rows:
            listed |= event_handlers(row)
        for handler in sorted(bound - listed):
            findings.append(Finding(name, f"the template binds `{handler}` and no row names it"))
        for handler in sorted(listed - bound):
            findings.append(Finding(name, f"a row names `{handler}` and the template does not bind it"))
    for name in sorted(set(sections) - set(templates)):
        findings.append(Finding(name, "a section for a template that does not exist"))
    size = _SIZE_RE.search(doc_text)
    if size is None:
        findings.append(Finding("Size", "the document has no `**Size.** N control rows in M screen templates` line to hold to the truth"))
    else:
        stated_rows, stated_templates = int(size.group(1)), int(size.group(2))
        screens = len(templates) - 1
        if stated_rows != total_rows:
            findings.append(Finding("Size", f"the Size line says {stated_rows} control rows; the checklist has {total_rows}"))
        if stated_templates != screens:
            findings.append(Finding("Size", f"the Size line says {stated_templates} screen templates; there are {screens}"))
    return findings


def _self_test(templates: dict[str, str], doc_text: str) -> list[str]:
    """Each mutation must produce at least one finding; the unmutated pair must produce none. Returns the failures."""
    failures: list[str] = []
    if check(templates, doc_text):
        return ["the unmutated checklist already has findings; fix those first"]

    sections, _ = parse_document(doc_text)
    victim = next((name for name, rows in sections.items() if len(rows) > 1 and name in templates), None)
    if victim is None:
        # Without a section that has two or more rows and a matching template there is nothing to mutate, and a
        # self-test that cannot mutate proves nothing: report it as a failure rather than crash or pass.
        return ["the checklist has no section with more than one row and a matching template, so the self-test has nothing to mutate"]
    row = sections[victim][0]
    lines = doc_text.splitlines()

    def without_line(target: str) -> str:
        index = lines.index(target)
        return "\n".join(lines[:index] + lines[index + 1 :])

    mutations = {
        "a row removed from the checklist": (templates, without_line(row)),
        "a section removed from the checklist": (templates, doc_text.replace(f"— `{victim}`", "— `renamed-away`", 1)),
        "the Size line made false": (templates, _SIZE_RE.sub("**Size.** 1 control rows in 1 screen templates", doc_text, count=1)),
    }
    handler = next(iter(event_handlers(row)), None)
    if handler is not None:
        mutations["a handler renamed in the checklist"] = (templates, doc_text.replace(f"→ `{handler}`", "→ `nothingBindsThis`", 1))
    template_with_button = dict(templates)
    template_with_button[victim] = templates[victim] + '\n<button onClick="{{addedSinceTheChecklist}}">x</button>\n'
    mutations["a control added to a template"] = (template_with_button, doc_text)
    template_without_binding = dict(templates)
    bound_in_victim = next((h for _, hs in extract_controls(templates[victim]) for h in hs), None)
    if bound_in_victim is not None:
        template_without_binding[victim] = templates[victim].replace(f'"{{{{{bound_in_victim}}}}}"', '""', 1)
        mutations["a binding removed from a template"] = (template_without_binding, doc_text)

    for label, (tpl, doc) in mutations.items():
        if not check(tpl, doc):
            failures.append(f"the check did not notice: {label}")
    return failures


def main(argv: list[str]) -> int:
    unknown = [a for a in argv if a != "--self-test"]
    if unknown:
        sys.stderr.write(f"release_verification_check: unknown argument(s): {' '.join(unknown)}\n")
        sys.stderr.write("usage: python3 -m tools.release_verification_check [--self-test]\n")
        return 2
    try:
        templates = read_templates()
        doc_text = DOC.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as error:
        sys.stderr.write(f"release_verification_check: {error}\n")
        return 2

    if "--self-test" in argv:
        failures = _self_test(templates, doc_text)
        for failure in failures:
            print(f"  [FAIL] {failure}")
        print("release_verification_check: self-test " + ("FAILED" if failures else "passed (every mutation was noticed)"))
        return 1 if failures else 0

    findings = check(templates, doc_text)
    for finding in findings:
        print(f"  [BLOCK] {finding.subject} — {finding.message}")
    if findings:
        print(f"\nrelease_verification_check: {len(findings)} finding(s)")
        return 1
    sections, _ = parse_document(doc_text)
    rows = sum(len(r) for r in sections.values())
    print(f"release_verification_check: clean ({rows} rows in {len(templates)} templates, §2 of RELEASE_VERIFICATION.md)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
