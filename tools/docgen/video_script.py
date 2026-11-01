"""Video-script storyboard exporter (RULEBOOK L19 / DOC_SYSTEM_COMPLETION_PROGRAM.md §2
Bundle 3). Not a video renderer — a small, reusable artifact: the narrative that goes with
a `content_role: article` document's already-built animation, written down NOW so it can
drive real video generation LATER. L19: "ARCHITECT writes the topic/outline, BUILDER writes
the deep explanation... the animation is built now while the video narrative/script is
written down separately."

Eligibility is `content_role == "article"` (checked against the doc's `ManifestRow`, per
the Bundle 3 build order) — a project-doc or asset never gets a video script.

Stdlib only; mypy --strict clean; deterministic (stable scene order, no timestamps).
"""

from __future__ import annotations

from pathlib import Path

from tools.docgen.models import ManifestRow, VideoScene, VideoScript

_ELIGIBLE_CONTENT_ROLE = "article"


def render_video_script(script: VideoScript) -> str:
    """Render ``script`` to a deterministic Markdown storyboard."""
    lines = [
        f"# Video script — {script.title}",
        "",
        f"`doc_id: {script.doc_id}`",
        "",
        "> Storyboard only — this drives future video generation, it is not a rendered video.",
        "> Each scene's `animation_ref` (when set) names an already-built VISUAL_LIBRARY §4 animation.",
        "",
    ]
    for i, scene in enumerate(script.scenes, start=1):
        lines.append(f"## Scene {i} — {scene.beat}")
        lines.append("")
        if scene.animation_ref:
            lines.append(f"**Animation:** `{scene.animation_ref}`")
            lines.append("")
        lines.append(f"**Narration:** {scene.narration}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_video_script(script: VideoScript, out_dir: Path) -> Path:
    """Render and write ``<doc_id>.video-script.md`` under ``out_dir``. Returns the path written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{script.doc_id}.video-script.md"
    out_path.write_text(render_video_script(script), encoding="utf-8")
    return out_path


def generate_for_manifest_row(
    row: ManifestRow, *, doc_id: str, title: str, scenes: list[VideoScene], out_dir: Path
) -> Path | None:
    """Write a video script for the specific document ``doc_id``/``title`` if its TYPE (``row``)
    is eligible (``content_role == "article"``).

    ``row`` is used ONLY for the eligibility check — the output file is always keyed by the
    document's own instance id, never ``row.id`` (the manifest row's bare TYPE PREFIX, e.g.
    ``"EDU"``). Multiple instances of the same article type (Bundle 5 authors 3 separate
    EDU-5NN articles under the one ``EDU`` manifest row) would otherwise all write to the same
    ``<row.id>.video-script.md`` and silently overwrite one another.

    Returns ``None`` (no-op, no file written) for any other content role — the eligibility
    gate the Bundle 3 build order names, made explicit rather than left to caller discipline.
    """
    if row.content_role != _ELIGIBLE_CONTENT_ROLE:
        return None
    script = VideoScript(doc_id=doc_id, title=title, scenes=scenes)
    return write_video_script(script, out_dir)
