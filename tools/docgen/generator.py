"""Markdown -> HTML/JSON(/PDF) generator (RULEBOOK L7/L13/L14; ENGINE_PLAN.md §1/§4b).

``build()`` is the integration seam: it canonicalizes the input path (L12 isolation), parses
the document header, renders the Markdown body to a self-contained HTML document (inline CSS
from ``tokens.build_css()``, inline eye-mark, embedded rendered SVG figures), appends the
verified-stamp, stamps the output with a ``generated-by`` + content-sha256 comment (L7), and
— critically — re-runs the leak-gate on the FINAL RENDERED bytes of every output channel
before writing anything to disk. A public document that fails the gate is never written.

This module composes ``classification.py``, ``export_sanitizer.py``, and ``visual.py`` (all
already built by sibling Wave-1 modules) plus this builder's own ``tokens.py``/``components.py``.
PDF rendering is attempted via ``weasyprint`` if importable; otherwise the build degrades
gracefully and records ``pdf: skipped(weasyprint absent)`` rather than silently faking it.

Stdlib + PyYAML (already a project dependency via ``classification.py``) only for the core
path; ``weasyprint`` is optional. mypy --strict clean.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from html import escape
from pathlib import Path
from typing import Any

from tools.docgen import (
    adjudication,
    components,
    diagram_graphs,
    doc_manifest,
    doc_outline,
    echarts_bridge,
    export_sanitizer,
    geo_map,
    i18n,
    isometric3d,
    markdown_blocks,
    sankey,
    sequence_diagram,
    tokens,
    visual,
)
from tools.docgen.classification import parse_header, validate_header
from tools.docgen.echarts_bridge import EChartsFigureSpec
from tools.docgen.geo_map import GeoMapSpec
from tools.docgen.isometric3d import IsometricSpec
from tools.docgen.models import (
    BuildResult,
    DocHeader,
    Finding,
    GateResult,
    SequenceSpec,
    Severity,
    Tier,
    VisualSpec,
)
from tools.docgen.sankey import SankeySpec

# The union of every figure-spec type the generator can dispatch. Node/edge-graph kinds
# (flowchart/state/system_map/dependency_graph) share ``VisualSpec``; the others each own a
# distinct spec shape and render via ``isinstance`` narrowing (mypy --strict clean).
# ``echarts`` delegates data charts to the visual-engine (ENGINE_ROUTING_POLICY.json) —
# one engine per family, no second chart implementation here.
_FigureSpec = (
    VisualSpec | SequenceSpec | SankeySpec | GeoMapSpec | IsometricSpec | EChartsFigureSpec
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOC_MANIFEST_PATH = _REPO_ROOT / "docs" / "design" / "doc-system" / "DOC_MANIFEST.md"
_FIGURE_DIRECTIVE_RE = re.compile(r"<!--\s*figure:([A-Za-z0-9_-]+)\s*-->")


class BuildBlockedError(RuntimeError):
    """Raised when a build is blocked by the leak-gate (public doc must never be written)."""


def _canonicalize_inside_repo(path: Path, *, root: Path = _REPO_ROOT) -> Path:
    """Resolve ``path`` to an absolute, symlink-free path and assert it stays inside ``root``.

    Fail-closed (RULEBOOK L12 isolation): a path that escapes the repo root (via ``..`` or a
    symlink) raises rather than silently being read/written.
    """
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise BuildBlockedError(
            f"path {path} resolves outside the repo root ({root}): {resolved}"
        ) from exc
    return resolved


def _read_markdown(md_path: Path) -> str:
    return md_path.read_text(encoding="utf-8")


def _strip_front_matter(md: str) -> str:
    """Remove the YAML front-matter block (already parsed into a DocHeader) from the body."""
    match = re.match(r"^\s*---\s*\n.*?\n---\s*\n?", md, re.DOTALL)
    if match is None:
        return md
    return md[match.end() :]


_FIGURE_RENDERERS: dict[str, Callable[[VisualSpec], str]] = {
    "flowchart": visual.render,
    "state": diagram_graphs.render_state_diagram,
    "system_map": diagram_graphs.render_system_map,
    "dependency_graph": diagram_graphs.render_dependency_graph,
}


def _render_markdown_body(md_body: str, *, figures: dict[str, tuple[str, _FigureSpec]]) -> str:
    """Render the document body to HTML, one ``components.section`` per ``##`` heading.

    Sectioning lives here (``#`` is the masthead title and is skipped; each ``##`` opens a new
    section whose eyebrow is the heading text); everything *inside* a section is rendered by
    ``markdown_blocks.render_blocks`` — headings ``###``-``######``, ordered/unordered lists with
    nesting, fenced code, blockquotes, horizontal rules, pipe tables, ``<!-- figure:ID -->``
    directives and multi-line paragraphs with inline code/link/bold/emphasis.

    Widened 2026-08-18. Before that this renderer recognised four constructs and emitted every
    other line as escaped paragraph text — which silently mangled any real document while leaving
    every gate green (Session 19, trap 1). The fail-closed property that made the narrow version
    safe is unchanged and is now enforced in ``markdown_blocks``: document text is always escaped,
    raw HTML is never passed through, and link hrefs are allowlisted.
    """
    lines = md_body.splitlines()
    blocks: list[str] = []
    current_section: list[str] = []
    current_eyebrow = "overview"

    def _render_figure(fig_id: str) -> str | None:
        entry = figures.get(fig_id)
        if entry is None:
            return None
        _kind, spec = entry
        if isinstance(spec, EChartsFigureSpec):
            svg = echarts_bridge.render(spec)
        elif isinstance(spec, SankeySpec):
            svg = sankey.render_sankey(spec)
        elif isinstance(spec, GeoMapSpec):
            svg = geo_map.render_geo_map(spec)
        elif isinstance(spec, IsometricSpec):
            svg = isometric3d.render(spec)
        elif isinstance(spec, SequenceSpec):
            svg = sequence_diagram.render(spec)
        else:
            renderer = _FIGURE_RENDERERS.get(_kind, visual.render)
            svg = renderer(spec)
        # Not every spec type carries a ``legend`` field (SankeySpec/GeoMapSpec do not); guard
        # with getattr so the legend row is simply empty for those.
        legend_html = "".join(
            f'<span class="figure-legend-item">{escape(entry_.label)}</span>'
            for entry_ in getattr(spec, "legend", [])
        )
        return components.figure(svg, spec.caption, legend_html)

    def _render_table(table_lines: list[str]) -> str:
        headers, rows = _parse_pipe_table(table_lines)
        return components.data_table(headers, rows, render_cell=markdown_blocks.render_inline)

    def _flush_section() -> None:
        if current_section:
            rendered = markdown_blocks.render_blocks(
                current_section, on_figure=_render_figure, on_table=_render_table
            )
            if rendered:
                blocks.append(components.section(current_eyebrow, "".join(rendered)))
            current_section.clear()

    in_fence = False
    for line in lines:
        # Fence state is tracked HERE, not only inside markdown_blocks, because sectioning runs
        # first: without it a `# comment` line inside a ```bash block is deleted as an H1 and a
        # `## ` line inside one splits the section mid-fence, silently corrupting both the code
        # and the document structure. Found by review 2026-08-18; latent until fenced code was
        # supported at all.
        if markdown_blocks.is_fence_line(line):
            in_fence = not in_fence
            current_section.append(line)
            continue
        if not in_fence:
            if line.startswith("# "):
                # Document title is handled by the masthead; skip the H1 line itself.
                continue
            if line.startswith("## "):
                _flush_section()
                current_eyebrow = line[3:].strip()
                continue
        current_section.append(line)

    _flush_section()
    return "\n".join(blocks)


def _parse_pipe_table(table_lines: list[str]) -> tuple[list[str], list[list[str]]]:
    def _split(row: str) -> list[str]:
        stripped = row.strip().strip("|")
        return [cell.strip() for cell in stripped.split("|")]

    headers = _split(table_lines[0])
    rows = [_split(line) for line in table_lines[2:] if line.strip()]
    return headers, rows


def _content_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _stamp_generated(html_doc: str) -> str:
    """Append the L7 generated-file guard comment with the content hash of everything BEFORE it."""
    digest = _content_sha256(html_doc.encode("utf-8"))
    return f"{html_doc}\n<!-- generated-by docgen · content-sha256:{digest} -->\n"


_LOCALE_FIELD_RE = re.compile(r"^\s*locale\s*:\s*(?P<val>[^\r\n#]+)", re.MULTILINE)


def _extract_locale(md: str) -> str | None:
    """Read an OPTIONAL ``locale:`` front-matter field (i18n scaffold hook, ENGINE_PLAN §4b).

    Returns the raw declared locale string, or ``None`` when the document declares none.
    ``DocHeader`` is a frozen contract shared across the engine, so the scaffold reads this
    optional field directly from the raw markdown rather than widening that dataclass — a
    document without a ``locale:`` field is unaffected (``<html lang>`` stays ``en``, so
    existing builds remain byte-identical).
    """
    match = _LOCALE_FIELD_RE.search(md)
    if match is None:
        return None
    return match.group("val").strip().strip("'\"") or None


def _render_html(header: DocHeader, body_html: str, *, lang: str = i18n.DEFAULT_LOCALE) -> str:
    """Assemble the full self-contained HTML document: inline CSS + masthead + body + stamp.

    ``lang`` is the resolved ``<html lang="…">`` value (see ``i18n.resolve_lang``); it defaults
    to English so callers that do not opt into the i18n scaffold get identical output.
    """
    css = tokens.build_css()
    masthead_html = components.masthead(header)
    verified = components.verified_stamp(header.id)
    title = escape(header.title)
    lang_attr = escape(lang, quote=True)
    doc = f"""\
<!doctype html>
<html lang="{lang_attr}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
{css}
</style>
</head>
<body>
<div class="doc-root">
{masthead_html}
<main>
{body_html}
</main>
{verified}
</div>
</body>
</html>
"""
    return _stamp_generated(doc)


def _findings_to_json(gate: GateResult) -> dict[str, object]:
    return {
        "gate": gate.gate,
        "ok": gate.ok,
        "findings": [
            {
                "gate": f.gate,
                "message": f.message,
                "severity": f.severity.value,
                "blocking": f.blocking,
                "evidence": f.evidence,
            }
            for f in gate.findings
        ],
    }


def _render_json(
    header: DocHeader, gate: GateResult, *, outline: dict[str, Any] | None = None
) -> str:
    """Serialise the document's machine-readable sibling: header, gate result, and outline.

    ``outline`` (``doc_outline.extract``) is what makes this file a *document* rather than a
    build receipt — sections with stable ids, the figure ids each one embeds, and the outbound
    document/ADR/code references it makes. It is optional so any caller that only wants the
    receipt keeps the previous payload shape exactly.
    """
    payload: dict[str, Any] = {
        "header": {
            "id": header.id,
            "classification": header.classification.value,
            "title": header.title,
            "audience": header.audience,
            "owner": header.owner,
            "status": header.status,
            "export_allowed": header.export_allowed,
            "surface": header.surface.value,
            "last_reviewed": header.last_reviewed,
            "variants": header.variants,
        },
        "gate": _findings_to_json(gate),
    }
    if outline is not None:
        payload["document"] = outline
    return json.dumps(payload, indent=2, sort_keys=True)


def _try_render_pdf(html_doc: str) -> bytes | None:
    """Attempt PDF rendering via weasyprint. Returns None (never raises) if unavailable."""
    try:
        import weasyprint  # type: ignore[import-untyped]  # no stubs/py.typed upstream
    except ImportError:
        return None
    pdf_bytes: bytes = weasyprint.HTML(string=html_doc).write_pdf()
    return pdf_bytes


_CONFIDENTIAL_ROOT = _REPO_ROOT / "docs" / "confidential"


def build(
    md_path: Path,
    *,
    formats: tuple[str, ...] = ("html",),
    out_dir: Path | None = None,
    local_preview: bool = False,
) -> BuildResult:
    """Build ``md_path`` into the requested ``formats`` (subset of ``html``/``json``/``pdf``).

    Pipeline (RULEBOOK L7/L13/L14):
    1. Canonicalize ``md_path``; assert it resolves inside the repo (L12).
    2. Parse + validate the document header.
    3. Render the Markdown body to a self-contained HTML document.
    4. Re-run ``export_sanitizer.run_gates`` on the FINAL RENDERED bytes of each requested
       output channel (not just the source Markdown) — a public document that fails the
       gate is never written to disk (``BuildResult.ok`` is False and no ``outputs`` entry
       is produced for the blocked format).
    5. Write the passing outputs; PDF degrades to a recorded skip if weasyprint is absent.

    ``local_preview=True`` (RULEBOOK L3/DETECTOR_DOC_SPEC §4) lets a CONFIDENTIAL/SECRET
    document render for internal/NDA'd-partner review WITHOUT being export-eligible — Gate 1
    is relaxed (see ``export_sanitizer.gate_tier``) but every other gate (secret-value, PII,
    manifest-drift, variant-overlap) still runs and still blocks. This function additionally
    enforces the ONE safety backstop the gate itself cannot: a non-public document may only
    be written under the git-ignored ``docs/confidential/`` tree — fail-closed
    (``BuildBlockedError``) if ``local_preview`` is requested for a non-public document whose
    resolved output directory falls outside it, so a preview build can never leak a
    confidential/secret render into a public/committed path by accident. ``local_preview``
    has no effect on a ``classification: public`` document (Gate 1 already passes it).

    Deterministic: no wall-clock timestamps are embedded in the hashed HTML content (the
    content-sha256 stamp covers only the document body preceding it).
    """
    resolved_md = _canonicalize_inside_repo(md_path)
    md_text = _read_markdown(resolved_md)
    header = parse_header(md_text)
    header_findings = validate_header(header)

    manifest_rows = doc_manifest.read_manifest(_DOC_MANIFEST_PATH)

    figures = _load_sibling_figure(resolved_md)
    body_md = _strip_front_matter(md_text)
    outline = doc_outline.extract(body_md)
    body_html = _render_markdown_body(body_md, figures=figures)
    lang = i18n.resolve_lang(_extract_locale(md_text))
    html_doc = _render_html(header, body_html, lang=lang)

    out_directory = out_dir if out_dir is not None else resolved_md.parent
    out_directory = _canonicalize_inside_repo(out_directory)

    if local_preview and header.classification is not Tier.PUBLIC:
        try:
            out_directory.relative_to(_CONFIDENTIAL_ROOT)
        except ValueError as exc:
            raise BuildBlockedError(
                f"local_preview requested for a '{header.classification.value}' document "
                f"but out_dir {out_directory} is not under {_CONFIDENTIAL_ROOT} — refusing "
                "to risk a non-public render outside the git-ignored confidential tree"
            ) from exc

    outputs: dict[str, Path] = {}
    final_gate = GateResult(gate="build", findings=list(header_findings))

    # Scan the RAW Markdown for secret/PII content as well as the rendered output.
    #
    # The rendered HTML is not a superset of the source: `markdown_blocks` deliberately DROPS HTML
    # comments (they are metadata — the `artifact-hardened` stamp lives in one). Before that change
    # an unrecognised comment was escaped into the output and therefore scanned; afterwards it
    # would have vanished before any gate saw it, so a secret or a real hostname inside a comment
    # would have passed every gate by never being looked at. Anything the renderer drops must still
    # be scanned, so the two content gates run against the source directly.
    for raw_gate in (
        export_sanitizer.gate_secret_value(export_sanitizer.normalize(md_text)),
        export_sanitizer.gate_pii_path_internal(export_sanitizer.normalize(md_text)),
    ):
        final_gate = final_gate.merge(raw_gate)

    for fmt in formats:
        if fmt == "html":
            gate = export_sanitizer.run_gates(
                html_doc, header, manifest_rows=manifest_rows, local_preview=local_preview
            )
            final_gate = final_gate.merge(gate)
            if gate.ok:
                out_path = out_directory / f"{resolved_md.stem}.html"
                out_path.write_text(html_doc, encoding="utf-8")
                outputs["html"] = out_path
        elif fmt == "json":
            json_doc = _render_json(header, final_gate, outline=outline)
            gate = export_sanitizer.run_gates(
                json_doc, header, manifest_rows=manifest_rows, local_preview=local_preview
            )
            final_gate = final_gate.merge(gate)
            if gate.ok:
                out_path = out_directory / f"{resolved_md.stem}.json"
                out_path.write_text(json_doc, encoding="utf-8")
                outputs["json"] = out_path
        elif fmt == "pdf":
            gate = export_sanitizer.run_gates(
                html_doc, header, manifest_rows=manifest_rows, local_preview=local_preview
            )
            final_gate = final_gate.merge(gate)
            if gate.ok:
                pdf_bytes = _try_render_pdf(html_doc)
                if pdf_bytes is None:
                    final_gate.findings.append(
                        Finding(
                            gate="pdf",
                            message="pdf: skipped(weasyprint absent)",
                            severity=Severity.INFO,
                            blocking=False,
                        )
                    )
                else:
                    out_path = out_directory / f"{resolved_md.stem}.pdf"
                    out_path.write_bytes(pdf_bytes)
                    outputs["pdf"] = out_path
        else:
            final_gate.findings.append(
                Finding(
                    gate="build",
                    message=f"unknown format requested: {fmt!r}",
                    severity=Severity.HIGH,
                    blocking=True,
                )
            )

    # L11 active consultation (ENGINE_PLAN §4b deferred item, now implemented in
    # ``adjudication.py``): for any blocking gate finding, attach the CONTRADICTION.md
    # tie-breaker that already governs its conflict class as an advisory INFO note. Purely
    # additive and fail-open — every appended finding is non-blocking, so ``BuildResult.ok``
    # is unchanged, and a missing/unreadable matrix leaves the findings untouched.
    final_gate.findings = adjudication.annotate_with_contradictions(final_gate.findings)

    return BuildResult(doc_id=header.id, gate=final_gate, outputs=outputs)


def _load_sibling_figure(md_path: Path) -> dict[str, tuple[str, _FigureSpec]]:
    """Load the ``<stem>_spec.json`` figure spec(s) adjacent to ``md_path``, if present.

    Returns an empty mapping (never raises) when no sidecar spec file exists — a document
    with no ``<!-- figure:ID --> `` directives needs none. The sidecar is either a single
    figure object (the original, still-supported shape — every document authored before
    this could hold at most one figure) or a JSON array of figure objects, for documents
    that embed more than one (e.g. a workflow doc combining a flowchart, a sequence, and a
    state diagram). Each object's ``kind`` field selects its loader/renderer; it defaults to
    ``"flowchart"`` so a spec authored before the multi-convention renderers existed renders
    exactly as before. ``"sequence"`` is the one kind whose JSON shape differs (``actors``/
    ``messages``, not ``nodes``/``edges``) since it doesn't share ``VisualSpec``'s geometry,
    so it gets its own loader.
    """
    spec_path = md_path.parent / f"{md_path.stem}_spec.json"
    if not spec_path.is_file():
        return {}
    raw = json.loads(spec_path.read_text(encoding="utf-8"))
    entries = raw if isinstance(raw, list) else [raw]
    figures: dict[str, tuple[str, _FigureSpec]] = {}
    for data in entries:
        kind = data.get("kind", "flowchart")
        spec: _FigureSpec
        if kind == "sequence":
            spec = _sequence_spec_from_dict(data)
        elif kind == "echarts":
            spec = echarts_bridge.spec_from_dict(data)
        elif kind == "sankey":
            spec = _sankey_spec_from_dict(data)
        elif kind == "geo_map":
            spec = _geo_map_spec_from_dict(data)
        elif kind == "isometric3d":
            spec = _isometric_spec_from_dict(data)
        else:
            spec = _visual_spec_from_dict(data)
        figures[spec.id] = (kind, spec)
    return figures


def _sequence_spec_from_dict(data: dict[str, Any]) -> SequenceSpec:
    """Build a ``SequenceSpec`` (with nested ``Actor``/``Message``) from parsed JSON."""
    from tools.docgen.models import Actor, DataSource, LegendEntry, Message

    actors = [Actor(id=a["id"], label=a["label"]) for a in data["actors"]]
    messages = [
        Message(
            src=m["src"],
            dst=m["dst"],
            label=m.get("label", ""),
            order=int(m["order"]),
            style=m.get("style", "solid"),
        )
        for m in data["messages"]
    ]
    legend = [
        LegendEntry(kind=item["kind"], key=item["key"], label=item["label"])
        for item in data.get("legend", [])
    ]
    data_sources = [
        DataSource(
            kind=src["kind"],
            ref=src["ref"],
            retrieved=src.get("retrieved", ""),
            url=src.get("url", ""),
        )
        for src in data.get("data_sources", [])
    ]
    return SequenceSpec(
        id=data["id"],
        title=data["title"],
        caption=data["caption"],
        actors=actors,
        messages=messages,
        width=float(data.get("width", 720.0)),
        height=float(data.get("height", 420.0)),
        legend=legend,
        data_sources=data_sources,
    )


def _sankey_spec_from_dict(data: dict[str, Any]) -> SankeySpec:
    """Build a ``SankeySpec`` (nested ``SankeyNode``/``SankeyFlow``) from parsed JSON.

    A Sankey has no ``legend`` field (its bands ARE its legend); its distinct shape is
    ``nodes`` with a ``col`` index + ``flows`` with a positive ``value``. ``data_sources``
    are threaded through for the L16 source-attribution footer.
    """
    from tools.docgen.models import DataSource
    from tools.docgen.sankey import SankeyFlow, SankeyNode

    nodes = [SankeyNode(id=n["id"], label=n["label"], col=int(n["col"])) for n in data["nodes"]]
    flows = [
        SankeyFlow(
            src=f["src"],
            dst=f["dst"],
            value=float(f["value"]),
            label=f.get("label", ""),
            emphasis=bool(f.get("emphasis", False)),
        )
        for f in data["flows"]
    ]
    data_sources = [
        DataSource(
            kind=src["kind"],
            ref=src["ref"],
            retrieved=src.get("retrieved", ""),
            url=src.get("url", ""),
        )
        for src in data.get("data_sources", [])
    ]
    return SankeySpec(
        id=data["id"],
        title=data["title"],
        caption=data["caption"],
        nodes=nodes,
        flows=flows,
        unit=data.get("unit", ""),
        width=float(data.get("width", 720.0)),
        height=float(data.get("height", 420.0)),
        data_sources=data_sources,
    )


def _geo_map_spec_from_dict(data: dict[str, Any]) -> GeoMapSpec:
    """Build a ``GeoMapSpec`` (nested ``GeoPoint``/``GeoLink``) from parsed JSON.

    Distinct shape: ``points`` (``lon``/``lat`` degrees, optional sourced ``value``) +
    ``links`` (``src``/``dst``). No ``legend`` field. ``value`` stays ``None`` unless
    present so the L16 unsourced-value gate in the renderer keeps its meaning.
    """
    from tools.docgen.geo_map import GeoLink, GeoPoint
    from tools.docgen.models import DataSource

    points = [
        GeoPoint(
            id=p["id"],
            label=p["label"],
            lon=float(p["lon"]),
            lat=float(p["lat"]),
            hot=bool(p.get("hot", False)),
            value=None if p.get("value") is None else float(p["value"]),
            note=p.get("note", ""),
        )
        for p in data["points"]
    ]
    links = [
        GeoLink(
            src=link_["src"],
            dst=link_["dst"],
            label=link_.get("label", ""),
            style=link_.get("style", "solid"),
        )
        for link_ in data.get("links", [])
    ]
    data_sources = [
        DataSource(
            kind=src["kind"],
            ref=src["ref"],
            retrieved=src.get("retrieved", ""),
            url=src.get("url", ""),
        )
        for src in data.get("data_sources", [])
    ]
    return GeoMapSpec(
        id=data["id"],
        title=data["title"],
        caption=data["caption"],
        points=points,
        links=links,
        width=float(data.get("width", 900.0)),
        height=float(data.get("height", 500.0)),
        show_base=bool(data.get("show_base", True)),
        data_sources=data_sources,
    )


def _isometric_spec_from_dict(data: dict[str, Any]) -> IsometricSpec:
    """Build an ``IsometricSpec`` (nested ``IsoBox``/``IsoConnector``) from parsed JSON.

    Distinct shape: ``boxes`` (world-placed cuboids) + ``connectors`` + ``layer_labels``,
    not ``nodes``/``edges``. It DOES carry a ``legend`` (like ``VisualSpec``/``SequenceSpec``).
    """
    from tools.docgen.isometric3d import IsoBox, IsoConnector
    from tools.docgen.models import DataSource, LegendEntry

    boxes = [
        IsoBox(
            id=b["id"],
            label=b["label"],
            x=float(b["x"]),
            y=float(b["y"]),
            z=float(b["z"]),
            w=float(b.get("w", 96.0)),
            d=float(b.get("d", 96.0)),
            h=float(b.get("h", 44.0)),
            note=b.get("note", ""),
            highlight=bool(b.get("highlight", False)),
        )
        for b in data["boxes"]
    ]
    connectors = [
        IsoConnector(
            src=c["src"],
            dst=c["dst"],
            label=c.get("label", ""),
            style=c.get("style", "solid"),
        )
        for c in data.get("connectors", [])
    ]
    legend = [
        LegendEntry(kind=item["kind"], key=item["key"], label=item["label"])
        for item in data.get("legend", [])
    ]
    data_sources = [
        DataSource(
            kind=src["kind"],
            ref=src["ref"],
            retrieved=src.get("retrieved", ""),
            url=src.get("url", ""),
        )
        for src in data.get("data_sources", [])
    ]
    return IsometricSpec(
        id=data["id"],
        title=data["title"],
        caption=data["caption"],
        boxes=boxes,
        connectors=connectors,
        layer_labels=data.get("layer_labels", []),
        legend=legend,
        motion=bool(data.get("motion", True)),
        width=float(data.get("width", 720.0)),
        height=float(data.get("height", 480.0)),
        data_sources=data_sources,
    )


def _visual_spec_from_dict(data: dict[str, Any]) -> VisualSpec:
    """Build a ``VisualSpec`` (with nested ``Node``/``Edge``/``LegendEntry``) from parsed JSON."""
    from tools.docgen.models import DataSource, Edge, LegendEntry, Node, NodeType

    nodes = [
        Node(
            id=n["id"],
            type=NodeType(n["type"]),
            label=n["label"],
            x=float(n["x"]),
            y=float(n["y"]),
            w=float(n.get("w", 120.0)),
            h=float(n.get("h", 56.0)),
            note=n.get("note", ""),
            highlight=bool(n.get("highlight", False)),
            alive=bool(n.get("alive", False)),
        )
        for n in data["nodes"]
    ]
    edges = [
        Edge(
            src=e["src"],
            dst=e["dst"],
            label=e.get("label", ""),
            style=e.get("style", "solid"),
            condition=e.get("condition", ""),
            main=bool(e.get("main", False)),
        )
        for e in data["edges"]
    ]
    legend = [
        LegendEntry(kind=item["kind"], key=item["key"], label=item["label"])
        for item in data.get("legend", [])
    ]
    data_sources = [
        DataSource(
            kind=src["kind"],
            ref=src["ref"],
            retrieved=src.get("retrieved", ""),
            url=src.get("url", ""),
        )
        for src in data.get("data_sources", [])
    ]
    return VisualSpec(
        id=data["id"],
        title=data["title"],
        caption=data["caption"],
        nodes=nodes,
        edges=edges,
        legend=legend,
        motion=bool(data.get("motion", True)),
        width=float(data.get("width", 720.0)),
        height=float(data.get("height", 420.0)),
        data_sources=data_sources,
    )
