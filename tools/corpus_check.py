"""Corpus integrity checks — the guards `v2/docs/` has never had.

Run: ``python3 -m tools.corpus_check`` from the repo root. Exit 0 clean, 1 findings, 2 usage error.

Public tree. ``--public-tree`` is for a tree produced by ``tools/public-export`` (a single-commit export with no
git history). It is selected by itself when there is no ``.git`` at all, and when the tree carries the generated
``.public-export`` marker (so it keeps working in the published repository after that repository gains commits).
It changes exactly one thing: in the ``stamps`` check, a stamp whose named commit cannot be resolved is checked for
structure only, because that commit lives in the private repository. A stamp whose commit does resolve is still
compared against it. ``endpoints`` and ``crossrefs`` run unchanged and at full strength. The private tree has
neither a marker nor a missing ``.git``, so history-drift detection is never weakened where history exists, and
the explicit flag is refused there.

Three checks, each closing a documented drift class this project has already paid for:

``endpoints``
    Every op named in ``18_ENDPOINT_INDEX.md`` must exist in ``crates/brokerd/src/ops.rs``, and
    every op in ``ops.rs`` must be named in the index. This is the check three documents claimed a
    test ``I-26`` performed, for months, when no such test had ever existed (``PROJECT_MAP.md``
    §5.11). It lives here rather than in the Rust suite because the thing being checked is a
    *document*, and because ``v2/crates/`` is owned by a parallel session; the guarantee is
    identical either way. Ops the index deliberately lists as not-yet-built must say so in their
    notes cell with the word ``planned`` — an unmarked name is read as a claim that it is built.

``crossrefs``
    Every ``NN_NAME.md §S`` reference in the corpus must resolve: the target document must exist
    and must actually have a section numbered ``S``. Cross-references rot silently and constantly;
    nothing has ever checked them.

``stamps``
    Every ``artifact-hardened`` stamp names a commit. If the document body changed after that
    commit, the stamp is invalid and the document is not source-of-truth (the three-pass contract).
    Comparison excludes the stamp line itself — a stamp can never appear in the revision it names
    (ADR-052, and ``PHASE8_AUDIT_REPORT.md`` §3 C-7 for why whole-file comparison is wrong).

Stdlib only, like the rest of ``tools/``.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "v2" / "docs"
PUBLIC_MARKER = REPO_ROOT / ".public-export"  # generated into a public export only; see tools/public-export
OPS_RS = REPO_ROOT / "v2" / "crates" / "brokerd" / "src" / "ops.rs"
ENDPOINT_INDEX = DOCS_DIR / "18_ENDPOINT_INDEX.md"

_OP_ARM_RE = re.compile(r'"([a-z_]+(?:\.[a-z_]+)?)"\s*=>')
_OP_MENTION_RE = re.compile(r"`([a-z]+\.[a-z_]+)`")
# An op name is `namespace.verb`, lowercase. A bare word (`keystore`), a Rust type
# (`PresenceProof`) or a fragment (`_write`) in the same cell is prose, not an op claim.
_OP_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
_MCP_TOOL_RE = re.compile(r"^credmgr_[a-z_]+$")
MCP_TOOLS_RS = REPO_ROOT / "v2" / "crates" / "mcp" / "src" / "tools.rs"
# The release-facing documents outside v2/docs: each carries a stamp like a corpus document, and the same rule applies
# (a stamp names a commit; the body must not have changed since).
RELEASE_FACING = (
    "README.md",
    "v2/README.md",
    "v2/RELEASE.md",
    "v2/SECURITY.md",
    "v2/PRIVACY.md",
    "v2/CHANGELOG.md",
)
_STAMP_RE = re.compile(r"<!--\s*artifact-hardened:.*?-->", re.DOTALL)
_FRONT_MATTER_RE = re.compile(r"\A---\s*\n.*?\n---\s*\n", re.DOTALL)
_STAMP_SHA_RE = re.compile(r"@\s*([0-9a-f]{7,40})\b")
_DOC_REF_RE = re.compile(r"\b(\d{2}_[A-Z0-9_]+\.md)\s*§\s*(\d+(?:\.\d+)*)")
_SECTION_RE = re.compile(r"^#{2,6}\s+(\d+(?:\.\d+)*)[.)]?\s", re.MULTILINE)
_FENCE_SPLIT_RE = re.compile(r"^\s*(?:```|~~~)", re.MULTILINE)


@dataclass(frozen=True)
class Finding:
    check: str
    subject: str
    message: str
    blocking: bool = True


def _strip_fences(text: str) -> str:
    """Drop fenced code blocks — an op name or a doc reference inside an example is not a claim."""
    out, inside = [], False
    for line in text.splitlines():
        if _FENCE_SPLIT_RE.match(line):
            inside = not inside
            continue
        if not inside:
            out.append(line)
    return "\n".join(out)


_SEPARATOR_ROW_RE = re.compile(r"^\|[\s:|-]+\|\s*$")


def _expand_op_cell(cell: str) -> list[str]:
    """Op names claimed by one "V2 op" table cell.

    Handles the index's own shorthand, where a namespace is written once and then elided: a cell
    reading "vault.node_lock / node_unlock" (each backticked) means two ops, not one op and one
    stray word. A bare token inherits the most recent namespace seen in the same cell.
    """
    names: list[str] = []
    namespace = ""
    for token in re.findall(r"`([A-Za-z_][A-Za-z0-9_.]*)`", cell):
        if _OP_NAME_RE.match(token):
            namespace = token.split(".", 1)[0]
            names.append(token)
        elif namespace and re.fullmatch(r"[a-z][a-z0-9_]*", token):
            names.append(f"{namespace}.{token}")
    return names


def broker_ops() -> set[str]:
    """Every op name dispatched by the broker. Dotted names only — bare arms are nested
    subcommands or unrelated string matches, and `search`/`whoami` are handled explicitly."""
    text = OPS_RS.read_text(encoding="utf-8")
    names = {m.group(1) for m in _OP_ARM_RE.finditer(text)}
    return {n for n in names if "." in n} | {n for n in names if n in {"search", "whoami"}}


def mcp_tool_names() -> set[str]:
    """Every tool the MCP server registers. A separate surface from the broker's ops."""
    if not MCP_TOOLS_RS.is_file():
        return set()
    return set(re.findall(r'name:\s*"(credmgr_[a-z_]+)"', MCP_TOOLS_RS.read_text(encoding="utf-8")))


def check_endpoints() -> list[Finding]:
    if not ENDPOINT_INDEX.is_file() or not OPS_RS.is_file():
        return [Finding("endpoints", "-", "endpoint index or ops.rs not found — failing closed")]

    real = broker_ops()
    text = ENDPOINT_INDEX.read_text(encoding="utf-8")
    body = _strip_fences(text)

    # A *claim* is an op named in a mapping table's "V2 op" column — not any backticked token
    # anywhere in the prose. Without that narrowing, naming-convention examples (`noun.verb`) and
    # illustrative asides read as assertions and bury the real findings, which is how a checker
    # earns the right to be ignored.
    mentioned: dict[str, list[str]] = {}
    for line in body.splitlines():
        if not line.strip().startswith("|") or _SEPARATOR_ROW_RE.match(line.strip()):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        for op in _expand_op_cell(cells[1]):
            mentioned.setdefault(op, []).append(line)

    mcp_tools = mcp_tool_names()
    findings: list[Finding] = []
    for op, lines in sorted(mentioned.items()):
        if op in real:
            continue
        # `credmgr_*` names are MCP tools, a different surface with its own registry — checking
        # them against the broker's dispatch table would report every one of them as missing.
        if _MCP_TOOL_RE.match(op):
            if op not in mcp_tools and not any("planned" in ln.lower() for ln in lines):
                findings.append(
                    Finding("endpoints", op, "named as an MCP tool but registered nowhere in crates/mcp/src/tools.rs")
                )
            continue
        if any("planned" in ln.lower() for ln in lines):
            continue
        findings.append(
            Finding(
                "endpoints",
                op,
                "named in 18_ENDPOINT_INDEX.md but dispatched nowhere in ops.rs "
                "(mark it `planned` in its notes cell if that is deliberate)",
            )
        )

    # The reverse direction is deliberately more forgiving: an op named ANYWHERE in the index
    # counts as accounted for. The question this half answers is "did an op ship without ever being
    # written down", and a mention in prose answers it.
    for op in sorted(real):
        if op in mentioned or re.search(rf"`{re.escape(op)}`|`{re.escape(op.split('.')[-1])}`", body):
            continue
        findings.append(
            Finding("endpoints", op, "dispatched by the broker but absent from 18_ENDPOINT_INDEX.md")
        )
    return findings


def _sections(text: str) -> set[str]:
    """Every section number a document actually defines, from its numbered headings."""
    return {m.group(1) for m in _SECTION_RE.finditer(text)}


def check_crossrefs() -> list[Finding]:
    docs = sorted(DOCS_DIR.glob("*.md"))
    if not docs:
        return [Finding("crossrefs", "-", f"no documents found under {DOCS_DIR} — failing closed")]

    sections: dict[str, set[str]] = {}
    for path in docs:
        sections[path.name] = _sections(path.read_text(encoding="utf-8"))

    findings: list[Finding] = []
    for path in docs:
        body = _strip_fences(path.read_text(encoding="utf-8"))
        seen: set[tuple[str, str]] = set()
        for match in _DOC_REF_RE.finditer(body):
            target, ref = match.group(1), match.group(2)
            if (target, ref) in seen:
                continue
            seen.add((target, ref))
            if target not in sections:
                findings.append(
                    Finding("crossrefs", f"{path.name} -> {target}", "target document does not exist")
                )
                continue
            if ref in sections[target]:
                continue
            # `§4.2` where the target only numbers to `## 4.` is an unconfirmable sub-reference,
            # not necessarily a broken one — advisory. A missing TOP-level section is a real break.
            top = ref.split(".")[0]
            if top not in sections[target]:
                findings.append(
                    Finding("crossrefs", f"{path.name} -> {target} §{ref}", f"{target} has no section {top}")
                )
            else:
                findings.append(
                    Finding(
                        "crossrefs",
                        f"{path.name} -> {target} §{ref}",
                        f"{target} defines §{top} but no heading numbered {ref}",
                        blocking=False,
                    )
                )
    return findings


def _hardened_body(text: str) -> str:
    """The part of a document a stamp actually attests to.

    Excludes the stamp itself — a stamp can never appear in the revision it names (ADR-052) — and
    the YAML front matter, which is machine metadata whose `status`/`last_reviewed` fields change
    as a matter of routine. Comparing either would report every document as drifted for reasons
    that have nothing to do with its content.
    """
    return _STAMP_RE.sub("", _FRONT_MATTER_RE.sub("", text)).strip()


def _git_show(sha: str, rel: str) -> str | None:
    try:
        return subprocess.run(
            ["git", "show", f"{sha}:{rel}"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, OSError):
        return None


def check_stamps(public_tree: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    structural = 0
    paths = sorted(DOCS_DIR.glob("*.md")) + [REPO_ROOT / r for r in RELEASE_FACING if (REPO_ROOT / r).exists()]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        label = path.name if path.parent == DOCS_DIR else str(path.relative_to(REPO_ROOT))
        stamp = _STAMP_RE.search(text)
        if stamp is None:
            findings.append(Finding("stamps", label, "no artifact-hardened stamp"))
            continue
        text_lower = stamp.group(0).lower()
        # A stamp that DECLARES itself unhardened is honest by construction — check that before
        # looking for a commit, because such a stamp routinely cites the commit whose stamp it is
        # replacing, and reading that citation as its own claim re-flags a document that just told
        # the truth about itself.
        if "not hardened" in text_lower or "needs re-hardening" in text_lower:
            continue
        sha_match = _STAMP_SHA_RE.search(stamp.group(0))
        if sha_match is None:
            findings.append(
                Finding("stamps", label, "stamp names no commit and does not declare itself unhardened")
            )
            continue
        sha = sha_match.group(1)
        rel = str(path.relative_to(REPO_ROOT))
        past = _git_show(sha, rel)
        if past is None:
            if public_tree:
                # The named commit lives in the private repository and cannot be resolved here, and failing
                # every document for that would only teach people to ignore the check. The structural
                # guarantees above (a stamp exists; it declares itself unhardened or names a commit) still
                # hold. Drift against history is checked in the private tree before export.
                structural += 1
                continue
            findings.append(Finding("stamps", label, f"stamp names commit {sha}, which does not resolve"))
            continue
        if _hardened_body(past) != _hardened_body(text):
            findings.append(
                Finding(
                    "stamps",
                    label,
                    f"body changed since {sha}: the stamp is invalid and this document is not "
                    "source-of-truth until it is re-hardened or explicitly marked NEEDS RE-HARDENING",
                )
            )
    if public_tree and structural:
        findings.append(
            Finding(
                "stamps",
                "-",
                f"public-tree mode: {structural} stamp(s) name a commit that does not resolve here and "
                "were checked for structure only; the history comparison needs the private repository",
                blocking=False,
            )
        )
    return findings


CHECKS = {"endpoints": check_endpoints, "crossrefs": check_crossrefs, "stamps": check_stamps}


def _has_history() -> bool:
    """True when REPO_ROOT is a git repository with more than one commit."""
    try:
        out = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
        return int(out) > 1
    except (subprocess.CalledProcessError, OSError, ValueError):
        return False


def _has_git_metadata() -> bool:
    return (REPO_ROOT / ".git").exists()


def main(argv: list[str]) -> int:
    flagged = "--public-tree" in argv
    public_tree = flagged
    if not public_tree and not _has_git_metadata():
        # An unpacked export (or any tarball of the tree) has no .git at all, so a stamp's commit can
        # never be looked up. Say so and run the structural form rather than failing every document.
        public_tree = True
        print("corpus_check: no .git here - running in public-tree mode (stamps checked for structure only)")
    if not public_tree and PUBLIC_MARKER.is_file():
        # The published repository: .git exists and may have many commits, but the stamps name commits of the
        # private repository. The marker is generated into the export and nowhere else.
        public_tree = True
        print("corpus_check: .public-export marker present - running in public-tree mode (unresolvable stamp commits checked for structure only)")
    if flagged and _has_history():
        # The explicit flag exists for a history-free export. Honouring it where history exists would let the
        # drift check be skipped on the one tree that can run it. (The marker is how the published repository
        # opts in once it has history; the private repository never carries one.)
        sys.stderr.write(
            "corpus_check: --public-tree is for a single-commit public export; this repository has "
            "history. Run without the flag.\n"
        )
        return 2
    requested = [a for a in argv if not a.startswith("-")] or list(CHECKS)
    unknown = [name for name in requested if name not in CHECKS]
    if unknown:
        sys.stderr.write(f"corpus_check: unknown check(s): {', '.join(unknown)}\n")
        sys.stderr.write(f"available: {', '.join(CHECKS)}\n")
        return 2

    findings: list[Finding] = []
    for name in requested:
        if name == "stamps":
            findings.extend(check_stamps(public_tree=public_tree))
        else:
            findings.extend(CHECKS[name]())

    blocking = [f for f in findings if f.blocking]
    for finding in findings:
        mark = "BLOCK" if finding.blocking else "note "
        print(f"  [{mark}] {finding.check}: {finding.subject} — {finding.message}")
    if not findings:
        print(f"corpus_check: clean ({', '.join(requested)})")
    else:
        print(f"\ncorpus_check: {len(blocking)} blocking, {len(findings) - len(blocking)} advisory")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
