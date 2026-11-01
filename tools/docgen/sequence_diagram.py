"""SequenceSpec -> SVG renderer (VISUAL_LIBRARY.md catalog: "who talks to whom, in what
order, over time"). A genuinely different visual convention from the flowchart family:
vertical actor lifelines + horizontal ordered messages, not a node/edge graph.

Static by design (no animated dot) — the numbered message badges already state the
travel order explicitly (VISUAL_LIBRARY §3: "the static state must already tell the
story"), matching the flowchart family's own reduced-motion fallback convention.

Reuses the flowchart family's generic geometry/text/escape helpers (``tools.docgen.visual``)
so collision math and formatting stay identical across every figure type in the engine.

Stdlib only; mypy --strict clean; deterministic (2dp-rounded floats, stable ordering).
"""

from __future__ import annotations

from tools.docgen.models import Finding, Message, SequenceSpec, Severity
from tools.docgen.visual import (
    BBox,
    _escape,
    _fmt,
    _gap,
    _intersects,
    _r,
    _text_box,
)

_LIFELINE_TOP = 56.0
_ROW_GAP_PX = 48.0
_ACTOR_BOX_W = 120.0
_ACTOR_BOX_H = 36.0
_LABEL_FONT_PX = 12.0
_ARROW_HEAD_LEN = 9.0
_CAPTION_RESERVE_PX = 40.0


class SequenceCollisionError(RuntimeError):
    """Raised by ``render`` when ``check_collisions`` finds a blocking overlap."""


def _actor_x_positions(spec: SequenceSpec) -> dict[str, float]:
    n = len(spec.actors)
    if n == 0:
        return {}
    step = spec.width / (n + 1)
    return {actor.id: _r(step * (i + 1)) for i, actor in enumerate(spec.actors)}


def _required_height(spec: SequenceSpec) -> float:
    rows = len(spec.messages)
    return _LIFELINE_TOP + _ACTOR_BOX_H + rows * _ROW_GAP_PX + _CAPTION_RESERVE_PX


def check_collisions(spec: SequenceSpec) -> list[Finding]:
    """Blocking findings: unknown actor refs, duplicate ``order`` values, actor-label
    overlap, and insufficient ``height`` for the message count (the vertical analogue
    of the flowchart family's overlap-can-never-ship rule).
    """
    findings: list[Finding] = []
    actor_ids = {a.id for a in spec.actors}

    for msg in spec.messages:
        if msg.src not in actor_ids:
            findings.append(
                Finding(
                    gate="sequence.collision",
                    message=f"Message references unknown src actor '{msg.src}'",
                    severity=Severity.CRIT,
                    blocking=True,
                )
            )
        if msg.dst not in actor_ids:
            findings.append(
                Finding(
                    gate="sequence.collision",
                    message=f"Message references unknown dst actor '{msg.dst}'",
                    severity=Severity.CRIT,
                    blocking=True,
                )
            )
        if msg.src == msg.dst:
            findings.append(
                Finding(
                    gate="sequence.collision",
                    message=f"Self-messages are not supported yet (src==dst=='{msg.src}')",
                    severity=Severity.CRIT,
                    blocking=True,
                )
            )

    orders = [m.order for m in spec.messages]
    seen: set[int] = set()
    for order in orders:
        if order in seen:
            findings.append(
                Finding(
                    gate="sequence.collision",
                    message=f"Duplicate message order={order} (ambiguous vertical position)",
                    severity=Severity.CRIT,
                    blocking=True,
                )
            )
        seen.add(order)

    required_h = _required_height(spec)
    if spec.height < required_h:
        findings.append(
            Finding(
                gate="sequence.collision",
                message=f"height={spec.height} is below the {required_h:.2f}px required for {len(spec.messages)} message(s)",
                severity=Severity.CRIT,
                blocking=True,
            )
        )

    xs = _actor_x_positions(spec)
    boxes: list[BBox] = []
    for actor in spec.actors:
        x = xs.get(actor.id, 0.0)
        box = _text_box(x, _LIFELINE_TOP - _ACTOR_BOX_H / 2, actor.label, _LABEL_FONT_PX)
        boxes.append(box)
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            if _intersects(boxes[i], boxes[j]):
                findings.append(
                    Finding(
                        gate="sequence.collision",
                        message=f"Actor label boxes {i} and {j} overlap",
                        severity=Severity.CRIT,
                        blocking=True,
                    )
                )
            elif _gap(boxes[i], boxes[j]) < 22.0:
                findings.append(
                    Finding(
                        gate="sequence.collision",
                        message=f"Actor label gap between boxes {i} and {j} below the 22px minimum",
                        severity=Severity.CRIT,
                        blocking=True,
                    )
                )

    return findings


def _defs_css() -> str:
    return (
        "<style><![CDATA["
        ".lifeline{stroke:currentColor;stroke-width:1;stroke-dasharray:4 4;opacity:0.5;}"
        ".actor-box{fill:none;stroke:currentColor;stroke-width:1.5;}"
        ".actor-label,.msg-label,.figure-caption{font-family:var(--f-body,Inter,system-ui,sans-serif);fill:currentColor;}"
        ".msg-line{stroke:currentColor;stroke-width:1.5;fill:none;}"
        ".msg-line-dashed{stroke-dasharray:6 4;}"
        ".msg-badge{fill:var(--paper-2,#141420);stroke:currentColor;stroke-width:1;}"
        "]]></style>"
    )


def render(spec: SequenceSpec, *, theme: str = "dark") -> str:
    """Render ``spec`` to a complete, self-contained ``<svg>``. Raises
    ``SequenceCollisionError`` on any blocking finding (never ships an overlap).
    Deterministic: identical input -> byte-identical output on every call.
    """
    collisions = check_collisions(spec)
    if collisions:
        messages = "; ".join(f.message for f in collisions)
        raise SequenceCollisionError(
            f"{spec.id}: {len(collisions)} blocking collision(s): {messages}"
        )

    xs = _actor_x_positions(spec)
    parts: list[str] = [_defs_css()]

    lifeline_bottom = spec.height - _CAPTION_RESERVE_PX
    for actor in spec.actors:
        x = xs[actor.id]
        parts.append(
            f'<line class="lifeline" x1="{_fmt(x)}" y1="{_fmt(_LIFELINE_TOP)}" '
            f'x2="{_fmt(x)}" y2="{_fmt(lifeline_bottom)}"/>'
        )

    for actor in spec.actors:
        x = xs[actor.id]
        box_x = _r(x - _ACTOR_BOX_W / 2)
        box_y = _r(_LIFELINE_TOP - _ACTOR_BOX_H)
        parts.append(
            f'<rect class="actor-box" x="{_fmt(box_x)}" y="{_fmt(box_y)}" '
            f'width="{_fmt(_ACTOR_BOX_W)}" height="{_fmt(_ACTOR_BOX_H)}" rx="6"/>'
            f'<text class="actor-label" x="{_fmt(x)}" y="{_fmt(_LIFELINE_TOP - _ACTOR_BOX_H / 2 + 4.0)}" '
            f'text-anchor="middle" font-size="{_LABEL_FONT_PX}">{_escape(actor.label)}</text>'
        )

    ordered_messages: list[Message] = sorted(spec.messages, key=lambda m: m.order)
    for idx, msg in enumerate(ordered_messages):
        y = _r(_LIFELINE_TOP + _ACTOR_BOX_H / 2 + (idx + 1) * _ROW_GAP_PX)
        x0, x1 = xs[msg.src], xs[msg.dst]
        direction = 1.0 if x1 >= x0 else -1.0
        arrow_x1 = _r(x1 - direction * _ARROW_HEAD_LEN)
        cls = "msg-line" + (" msg-line-dashed" if msg.style == "dashed" else "")
        parts.append(
            f'<line class="{cls}" x1="{_fmt(x0)}" y1="{_fmt(y)}" x2="{_fmt(arrow_x1)}" y2="{_fmt(y)}"/>'
        )
        head = _r(4.0) * direction
        parts.append(
            f'<polygon class="{cls}" fill="currentColor" points="'
            f"{_fmt(x1)},{_fmt(y)} {_fmt(x1 - direction * _ARROW_HEAD_LEN)},{_fmt(y - abs(head))} "
            f'{_fmt(x1 - direction * _ARROW_HEAD_LEN)},{_fmt(y + abs(head))}"/>'
        )
        label_x = _r((x0 + x1) / 2)
        if msg.label:
            parts.append(
                f'<text class="msg-label" x="{_fmt(label_x)}" y="{_fmt(y - 6.0)}" '
                f'text-anchor="middle" font-size="{_LABEL_FONT_PX}">{_escape(msg.label)}</text>'
            )
        badge_x = min(x0, x1) - 18.0
        parts.append(
            f'<circle class="msg-badge" cx="{_fmt(badge_x)}" cy="{_fmt(y)}" r="8"/>'
            f'<text x="{_fmt(badge_x)}" y="{_fmt(y + 3.5)}" text-anchor="middle" '
            f'font-size="9" fill="currentColor">{idx + 1}</text>'
        )

    if spec.title:
        parts.append(
            f'<text x="{_fmt(spec.width / 2)}" y="20" class="figure-title" '
            f'font-size="18" text-anchor="middle" font-weight="700" fill="currentColor">{_escape(spec.title)}</text>'
        )
    if spec.caption:
        parts.append(
            f'<text x="{_fmt(spec.width / 2)}" y="{_fmt(spec.height - 10.0)}" '
            f'class="figure-caption" font-size="12" text-anchor="middle">{_escape(spec.caption)}</text>'
        )

    body = "".join(parts)
    return (
        f'<svg viewBox="0 0 {_fmt(spec.width)} {_fmt(spec.height)}" '
        f'xmlns="http://www.w3.org/2000/svg" class="ah-figure ah-sequence" data-theme="{theme}" '
        f'role="img" aria-label="{_escape(spec.title or spec.id)}">{body}</svg>'
    )
