"""Bridge from docgen to the visual-engine ECharts adapter (tools/visual-engine).

Docgen remains the authority for document diagrams; this bridge adds the data-chart
families the generator's own docstring left unwired ("extend ``_FIGURE_RENDERERS``-style
dispatch") by delegating to the project's canonical chart engine instead of growing a
second chart implementation here. One engine per family (ENGINE_ROUTING_POLICY.json):
docgen renders diagrams natively; quantitative charts render through the engine's
deterministic SSR path and are embedded as inline SVG exactly like every other figure.

Invariants preserved:
- **Determinism** — the engine guarantees build-twice byte-identical SVG for a fixed
  job + pinned engine version (its own regression suite locks this), so docgen's
  hash-gate discipline is unchanged.
- **Fail-closed** — a validation-gate failure, a missing Node runtime, or missing
  engine dependencies raises ``EChartsRenderError``; the build fails honestly rather
  than emitting a document with a silently absent figure (T-R9).
- **Leak-gate coverage** — the returned SVG is embedded into the document body BEFORE
  the export sanitizer runs, so rendered chart bytes pass the same 9-gate scan as
  every other output channel.

stdlib only (subprocess/tempfile/json/pathlib). ``mypy --strict`` clean.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.docgen.models import LegendEntry

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ENGINE_ROOT = _REPO_ROOT / "tools" / "visual-engine"
_ENGINE_CLI = _ENGINE_ROOT / "adapters" / "echarts" / "cli.mjs"
_RENDER_TIMEOUT_S = 60


class EChartsRenderError(RuntimeError):
    """Raised when the visual-engine render fails or cannot run (fail-closed)."""


@dataclass(frozen=True)
class EChartsFigureSpec:
    """A docgen figure whose SVG comes from the visual-engine ECharts adapter.

    ``job`` is a normalized visual job packet (tools/visual-engine/schemas/
    visual-job.schema.json); the engine's own gates validate it — this class carries
    only what the generator's figure component needs (``id``, ``caption``, ``legend``).
    """

    id: str
    caption: str
    job: dict[str, Any]
    legend: list[LegendEntry] = field(default_factory=list)


def spec_from_dict(data: dict[str, Any]) -> EChartsFigureSpec:
    """Build an ``EChartsFigureSpec`` from a sidecar ``*_spec.json`` object."""
    job = data.get("job")
    if not isinstance(job, dict):
        raise EChartsRenderError(
            f'figure "{data.get("id", "?")}": kind "echarts" requires a "job" object '
            "(a visual-engine job packet)"
        )
    legend = [
        LegendEntry(
            kind=str(entry.get("kind", "swatch")),
            key=str(entry.get("key", "")),
            label=str(entry["label"]),
        )
        for entry in data.get("legend", [])
    ]
    return EChartsFigureSpec(
        id=str(data.get("id", str(job.get("visual_id", "echarts-figure")))),
        caption=str(data.get("caption", "")),
        job=job,
        legend=legend,
    )


def engine_available() -> tuple[bool, str]:
    """Report whether the engine can run here (Node on PATH + installed deps)."""
    if not _ENGINE_CLI.is_file():
        return False, f"engine CLI missing: {_ENGINE_CLI}"
    if not (_ENGINE_ROOT / "node_modules" / "echarts").is_dir():
        return False, f"engine deps not installed — run `npm ci` in {_ENGINE_ROOT}"
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False, "node not found on PATH"
    return True, "ok"


def render(spec: EChartsFigureSpec) -> str:
    """Render the figure's job through the engine's direct (non-MCP) CLI → SVG string.

    The engine writes ``<visual_id>.svg`` into a private temp dir; the bytes are read
    back and returned for inline embedding. Every engine gate failure surfaces with
    the gate id in the raised message.
    """
    available, why = engine_available()
    if not available:
        raise EChartsRenderError(
            f'figure "{spec.id}" cannot render: {why}. The visual-engine is the '
            "canonical chart renderer (CLAUDE.md ▸ VISUALIZATION ENGINE AUTHORITY); "
            "install it rather than hand-drawing the chart."
        )
    with tempfile.TemporaryDirectory(prefix="docgen-echarts-") as tmp:
        tmp_path = Path(tmp)
        job_path = tmp_path / "job.json"
        job_path.write_text(json.dumps(spec.job), encoding="utf-8")
        result = subprocess.run(
            [
                "node",
                str(_ENGINE_CLI),
                "render",
                str(job_path),
                "-o",
                str(tmp_path),
                "--formats",
                "svg",
            ],
            capture_output=True,
            text=True,
            timeout=_RENDER_TIMEOUT_S,
            cwd=str(_ENGINE_ROOT),
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()[:500]
            raise EChartsRenderError(f'figure "{spec.id}": visual-engine render failed — {detail}')
        visual_id = str(spec.job.get("visual_id", "visual"))
        safe_id = "".join(c if c.isalnum() or c in "._-" else "_" for c in visual_id)
        svg_path = tmp_path / f"{safe_id}.svg"
        if not svg_path.is_file():
            raise EChartsRenderError(
                f'figure "{spec.id}": engine reported success but wrote no SVG '
                f"(expected {svg_path.name}; NO_CHART jobs cannot be embedded as figures)"
            )
        return svg_path.read_text(encoding="utf-8")
