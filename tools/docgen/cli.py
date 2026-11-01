"""``python -m tools.docgen.cli`` — argparse entry point for the doc-system engine.

Subcommands: ``build`` (Markdown -> HTML/JSON/PDF via ``generator.build``), ``render``
(a standalone ``VisualSpec`` JSON file -> SVG via ``visual.render``), ``manifest`` (print
``DOC_MANIFEST.md`` rows), and ``check`` (best-effort structural check: header validity +
manifest drift + gate re-run — the full hash-gate lives in ``validate_doc_system.py`` once
built; ``check`` here degrades honestly if that module is absent rather than pretending).

Exit codes: 0 = success, 1 = gate/validation failure, 2 = usage/IO error. ``--strict`` turns
advisory findings into hard failures (RULEBOOK L13/CLASSIFICATION.md gate spec).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from tools.docgen import build_cache, doc_manifest, generator, visual
from tools.docgen.classification import parse_header, validate_header
from tools.docgen.generator import (
    _visual_spec_from_dict,  # noqa: PLC2701 - CLI reuses the loader intentionally
)
from tools.docgen.models import BuildResult

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOC_SYSTEM_DIR = _REPO_ROOT / "docs" / "design" / "doc-system"
_DOC_MANIFEST_PATH = _DOC_SYSTEM_DIR / "DOC_MANIFEST.md"
_AUTHORED_DOCS_ROOT = _DOC_SYSTEM_DIR / "authored"
_CONTENT_INDEX_PATH = _DOC_SYSTEM_DIR / "CONTENT_INDEX.json"


def _emit_build_result(result: BuildResult, *, skipped: bool) -> None:
    """Print a single build's findings + written artifacts (shared by one-shot and watch)."""
    for finding in result.gate.findings:
        stream = sys.stderr if finding.blocking else sys.stdout
        stream.write(f"[{finding.gate}] {finding.severity.value}: {finding.message}\n")
    if skipped:
        sys.stdout.write(f"skipped (unchanged): {result.doc_id}\n")
        return
    for fmt, out_path in result.outputs.items():
        sys.stdout.write(f"wrote {fmt}: {out_path}\n")


def _build_once(
    md_path: Path,
    *,
    formats: tuple[str, ...],
    out_dir: Path | None,
    local_preview: bool,
    cache_path: Path | None,
) -> tuple[BuildResult, bool]:
    """Build a single document, optionally via the incremental cache. Returns (result, skipped).

    Fail-open: when ``cache_path`` is set the build goes through ``build_cache`` (unchanged docs
    are skipped); a corrupt/absent cache simply builds normally. The cache is loaded, updated,
    and persisted around this one build so ``--watch`` accumulates across ticks.
    """
    if cache_path is None:
        result = generator.build(
            md_path, formats=formats, out_dir=out_dir, local_preview=local_preview
        )
        return result, False

    cache = build_cache.load_cache(cache_path)
    fingerprint = build_cache._engine_fingerprint()  # noqa: SLF001 - intentional CLI reuse
    result, skipped = build_cache.build_cached(
        md_path,
        formats=formats,
        out_dir=out_dir,
        local_preview=local_preview,
        cache=cache,
        engine_fingerprint=fingerprint,
    )
    build_cache.save_cache(cache_path, cache)
    return result, skipped


def _cmd_build(args: argparse.Namespace) -> int:
    md_path = Path(args.input)
    formats = tuple(args.formats.split(",")) if args.formats else ("html",)
    out_dir = Path(args.out_dir) if args.out_dir else None
    cache_path = Path(args.cache) if args.cache else None

    if args.watch:
        return _run_watch(
            md_path,
            formats=formats,
            out_dir=out_dir,
            local_preview=args.local_preview,
            cache_path=cache_path,
            interval=args.watch_interval,
        )

    try:
        result, skipped = _build_once(
            md_path,
            formats=formats,
            out_dir=out_dir,
            local_preview=args.local_preview,
            cache_path=cache_path,
        )
    except generator.BuildBlockedError as exc:
        sys.stderr.write(f"docgen build: blocked: {exc}\n")
        return 2

    _emit_build_result(result, skipped=skipped)

    if not result.ok:
        sys.stderr.write(f"docgen build: BLOCKED (doc_id={result.doc_id}) — see findings above\n")
        return 1

    if args.strict and any(not f.blocking for f in result.gate.findings):
        sys.stderr.write("docgen build: --strict set and advisory findings exist\n")
        return 1

    return 0


def _run_watch(
    md_path: Path,
    *,
    formats: tuple[str, ...],
    out_dir: Path | None,
    local_preview: bool,
    cache_path: Path | None,
    interval: float,
) -> int:
    """Poll-based ``--watch`` rebuild loop: rebuild on each tick, skipping unchanged docs via cache.

    The cache makes an unchanged tick nearly free (a hash + an existence check, no render). This
    is a simple stdlib polling loop (no OS-specific fs-event dependency) so it degrades honestly
    everywhere. Runs until interrupted (Ctrl-C); returns 0 on clean exit. A blocked build in one
    tick is reported but does not stop the loop — the author fixes the doc and the next tick picks
    it up. When no cache is requested, ``--watch`` still works (every tick is a full rebuild).
    """
    effective_cache = cache_path
    if effective_cache is None and out_dir is not None:
        effective_cache = build_cache.default_cache_path(out_dir)
    sys.stdout.write(
        f"docgen build --watch: watching {md_path} (every {interval:g}s; Ctrl-C to stop)\n"
    )
    sys.stdout.flush()
    try:
        while True:
            try:
                result, skipped = _build_once(
                    md_path,
                    formats=formats,
                    out_dir=out_dir,
                    local_preview=local_preview,
                    cache_path=effective_cache,
                )
                _emit_build_result(result, skipped=skipped)
                if not result.ok:
                    sys.stderr.write(f"docgen build --watch: BLOCKED (doc_id={result.doc_id})\n")
            except generator.BuildBlockedError as exc:
                sys.stderr.write(f"docgen build --watch: blocked: {exc}\n")
            sys.stdout.flush()
            sys.stderr.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        sys.stdout.write("\ndocgen build --watch: stopped\n")
        return 0


def _cmd_render(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec)
    try:
        data = json.loads(spec_path.read_text(encoding="utf-8"))
        spec = _visual_spec_from_dict(data)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        sys.stderr.write(f"docgen render: failed to load spec {spec_path}: {exc}\n")
        return 2

    try:
        svg = visual.render(spec, theme=args.theme)
    except visual.CollisionError as exc:
        sys.stderr.write(f"docgen render: collision detected, refusing to emit SVG: {exc}\n")
        return 1

    if args.out:
        Path(args.out).write_text(svg, encoding="utf-8")
        sys.stdout.write(f"wrote {args.out}\n")
    else:
        sys.stdout.write(svg)
        sys.stdout.write("\n")
    return 0


def _cmd_manifest(_args: argparse.Namespace) -> int:
    rows = doc_manifest.read_manifest(_DOC_MANIFEST_PATH)
    if not rows:
        sys.stderr.write(f"docgen manifest: no rows found in {_DOC_MANIFEST_PATH}\n")
        return 1
    for row in rows:
        variants = "/".join(t.value for t in row.variants)
        sys.stdout.write(
            f"{row.id}\t{row.title}\t{row.type}\t{variants}\t{row.surface.value}\t{row.status}\n"
        )
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    """Best-effort structural check: header validity + manifest drift.

    Honest degradation: the full VERSION.json rule-hash-gate is owned by
    ``validate_doc_system.py`` (a separate module in this plan, not yet present at the time
    this CLI was authored). If that module exists, delegate to it; otherwise, run the
    checks this module CAN perform and say plainly that the hash-gate was skipped.
    """
    md_path = Path(args.input)
    text = md_path.read_text(encoding="utf-8")
    header = parse_header(text)
    findings = validate_header(header)

    manifest_rows = doc_manifest.read_manifest(_DOC_MANIFEST_PATH)
    if manifest_rows:
        from tools.docgen.classification import check_manifest_drift

        findings.extend(check_manifest_drift(header, manifest_rows))

    for finding in findings:
        stream = sys.stderr if finding.blocking else sys.stdout
        stream.write(f"[{finding.gate}] {finding.severity.value}: {finding.message}\n")

    try:
        from tools.docgen import validate_doc_system

        hash_result = validate_doc_system.check(
            rules_dir=_REPO_ROOT / "docs" / "design" / "doc-system",
            version_json_path=_REPO_ROOT / "docs" / "design" / "doc-system" / "VERSION.json",
        )
        if not hash_result.ok:
            for finding in hash_result.findings:
                sys.stderr.write(f"[{finding.gate}] {finding.severity.value}: {finding.message}\n")
            return 1
    except ImportError:
        sys.stdout.write(
            "docgen check: validate_doc_system.py not present yet — hash-gate skipped "
            "(header + manifest-drift checks only; not a full gate pass)\n"
        )

    return 1 if any(f.blocking for f in findings) else 0


def _cmd_index(args: argparse.Namespace) -> int:
    from tools.docgen import build_index

    manifest_rows = doc_manifest.read_manifest(_DOC_MANIFEST_PATH)
    if not manifest_rows:
        sys.stderr.write(f"docgen index: no DOC_MANIFEST.md rows found at {_DOC_MANIFEST_PATH}\n")
        return 1

    written = build_index.build_index(Path(args.build_dir), manifest_rows, Path(args.out))
    docs = build_index.scan_public_doc_jsons(Path(args.build_dir))
    sys.stdout.write(f"wrote index: {written} ({len(docs)} public document(s) indexed)\n")
    return 0


def _cmd_content_index(args: argparse.Namespace) -> int:
    """Emit the machine-readable CONTENT_INDEX.json over the authored PUBLIC docs.

    Source of truth = the authored ``.md`` sources' headers, cross-referenced against
    DOC_MANIFEST.md. Leak-safe (RULEBOOK L14): only ``classification: public`` docs are listed;
    non-public authored docs are counted in aggregate but never named.
    """
    from tools.docgen import build_index

    manifest_rows = doc_manifest.read_manifest(_DOC_MANIFEST_PATH)
    if not manifest_rows:
        sys.stderr.write(
            f"docgen content-index: no DOC_MANIFEST.md rows found at {_DOC_MANIFEST_PATH}\n"
        )
        return 1

    docs_root = Path(args.docs_root) if args.docs_root else _AUTHORED_DOCS_ROOT
    out_path = Path(args.out) if args.out else _CONTENT_INDEX_PATH
    if not docs_root.is_dir():
        sys.stderr.write(f"docgen content-index: docs root not found: {docs_root}\n")
        return 2

    written = build_index.write_content_index(
        docs_root,
        manifest_rows,
        out_path,
        repo_root=_REPO_ROOT,
        manifest_path=_DOC_MANIFEST_PATH,
    )
    entries, non_public = build_index.scan_authored_docs(
        docs_root, manifest_rows, repo_root=_REPO_ROOT
    )
    sys.stdout.write(
        f"wrote content-index: {written} "
        f"({len(entries)} public doc(s) listed, {non_public} non-public excluded)\n"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="docgen", description="CredMgr doc-system engine CLI")
    parser.add_argument("--strict", action="store_true", help="treat advisory findings as failures")
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="build a Markdown document into HTML/JSON/PDF")
    p_build.add_argument("input", help="path to the source .md file")
    p_build.add_argument("-o", "--out-dir", dest="out_dir", default=None, help="output directory")
    p_build.add_argument(
        "--formats", default="html", help="comma-separated formats: html,json,pdf (default: html)"
    )
    p_build.add_argument(
        "--local-preview",
        dest="local_preview",
        action="store_true",
        help=(
            "allow a CONFIDENTIAL/SECRET document to render for local review (Gate 1 "
            "relaxed to advisory); out-dir must resolve under docs/confidential/ or the "
            "build is blocked. Never affects a public document. Never makes a doc export-eligible."
        ),
    )
    p_build.add_argument(
        "--cache",
        default=None,
        help=(
            "path to an incremental build-cache JSON. When set, an unchanged document (same "
            "source, sibling spec, formats, flag, and engine) whose outputs still exist is "
            "skipped. Fail-open: a corrupt/absent cache just does a full build."
        ),
    )
    p_build.add_argument(
        "--watch",
        action="store_true",
        help=(
            "rebuild on a fixed interval until interrupted (poll-based, stdlib-only). Combine "
            "with --cache (or -o, which picks a default cache) so unchanged ticks are near-free."
        ),
    )
    p_build.add_argument(
        "--watch-interval",
        dest="watch_interval",
        type=float,
        default=1.0,
        help="seconds between --watch rebuild ticks (default: 1.0)",
    )
    p_build.set_defaults(func=_cmd_build)

    p_render = sub.add_parser("render", help="render a VisualSpec JSON file to SVG")
    p_render.add_argument("spec", help="path to a VisualSpec .json file")
    p_render.add_argument("-o", "--out", default=None, help="output .svg path (default: stdout)")
    p_render.add_argument("--theme", default="dark", choices=("dark", "light"))
    p_render.set_defaults(func=_cmd_render)

    p_manifest = sub.add_parser("manifest", help="print DOC_MANIFEST.md rows")
    p_manifest.set_defaults(func=_cmd_manifest)

    p_check = sub.add_parser("check", help="run the doc-system gate against a document")
    p_check.add_argument("input", help="path to the source .md file")
    p_check.set_defaults(func=_cmd_check)

    p_index = sub.add_parser(
        "index", help="scan built docgen JSON sidecars and emit a browsable PUBLIC docs index"
    )
    p_index.add_argument(
        "build_dir", help="directory to scan (recursively) for docgen JSON sidecars"
    )
    p_index.add_argument("-o", "--out", required=True, help="path to write the index HTML")
    p_index.set_defaults(func=_cmd_index)

    p_ci = sub.add_parser(
        "content-index",
        help=(
            "emit a machine-readable CONTENT_INDEX.json over the authored PUBLIC docs "
            "(for a graphify pass / the app docs page — no Markdown re-parsing)"
        ),
    )
    p_ci.add_argument(
        "--docs-root",
        dest="docs_root",
        default=None,
        help=(
            "root to scan (recursively) for authored .md sources "
            f"(default: {_AUTHORED_DOCS_ROOT})"
        ),
    )
    p_ci.add_argument(
        "-o",
        "--out",
        default=None,
        help=f"path to write CONTENT_INDEX.json (default: {_CONTENT_INDEX_PATH})",
    )
    p_ci.set_defaults(func=_cmd_content_index)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
