"""Shared data contracts for the CredMgr doc-system engine.

Every module in ``tools/docgen`` imports its types from here so interfaces never drift.
Stdlib only; mypy --strict clean. See ENGINE_PLAN.md for the module map.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Tier(str, Enum):
    """Classification tiers (RULEBOOK L2). Only PUBLIC may be committed/exported (L14)."""

    PUBLIC = "public"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class Surface(str, Enum):
    """Where a public doc may render (L3). Non-public tiers are always NONE."""

    WEB = "web"
    REPO = "repo"
    BOTH = "both"
    NONE = "none"


class Severity(str, Enum):
    CRIT = "crit"
    HIGH = "high"
    MED = "med"
    LOW = "low"
    INFO = "info"


class NodeType(str, Enum):
    """Glyph-per-node vocabulary (DESIGN_SYSTEM §4 / MOTION_SPEC)."""

    SOURCE = "source"  # rounded stadium
    PROCESS = "process"  # rectangle
    DECISION = "decision"  # diamond
    GATE = "gate"  # hexagon
    DATASTORE = "datastore"  # cylinder
    OUTPUT = "output"  # parallelogram
    FALLBACK = "fallback"  # dashed rounded rect
    ATTACKER = "attacker"  # danger-tinted rect
    JUNCTION = "junction"  # small filled circle (fork/merge)
    STATE = "state"  # rounded stadium (state-diagram node, reuses the SOURCE glyph shape)


class Theme(str, Enum):
    DARK = "dark"
    LIGHT = "light"


@dataclass(frozen=True)
class DocHeader:
    """The required metadata header (RULEBOOK L5)."""

    id: str
    classification: Tier
    title: str
    audience: str
    owner: str
    status: str
    export_allowed: bool
    surface: Surface
    last_reviewed: str
    variants: list[str] = field(default_factory=list)

    @property
    def is_public(self) -> bool:
        return self.classification is Tier.PUBLIC


@dataclass(frozen=True)
class Finding:
    """A single gate/validation result line. ``blocking`` decides export."""

    gate: str
    message: str
    severity: Severity = Severity.HIGH
    blocking: bool = True
    evidence: str = ""


@dataclass
class GateResult:
    """Outcome of a gate run. ``ok`` is True only when no blocking finding exists."""

    gate: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.blocking for f in self.findings)

    @property
    def blocked(self) -> bool:
        return not self.ok

    def merge(self, other: GateResult) -> GateResult:
        return GateResult(
            gate=f"{self.gate}+{other.gate}", findings=[*self.findings, *other.findings]
        )


@dataclass(frozen=True)
class Node:
    id: str
    type: NodeType
    label: str
    x: float
    y: float
    w: float = 120.0
    h: float = 56.0
    note: str = ""  # boxed, smaller-font description (DESIGN_SYSTEM §3)
    highlight: bool = False  # KEY node -> sig fill
    alive: bool = False  # compute node → ambient pulse (MOTION_SPEC §4)

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def cy(self) -> float:
        return self.y + self.h / 2

    def bbox(self) -> tuple[float, float, float, float]:
        return (self.x, self.y, self.x + self.w, self.y + self.h)


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    label: str = ""
    style: str = "solid"  # "solid" normal | "dashed" fallback/escalation
    condition: str = ""  # yes/no trigger that selects this branch (MOTION_SPEC §5)
    main: bool = False  # carries the primary flow-dot


@dataclass(frozen=True)
class LegendEntry:
    kind: str  # "node" | "line" | "swatch"
    key: str  # NodeType value, "solid"/"dashed", or a hex colour
    label: str


@dataclass(frozen=True)
class DataSource:
    """Provenance for every numeric datum in a figure (VISUAL_LIBRARY §5 / L16)."""

    kind: str  # "metric" | "scraped" | "cited"
    ref: str  # claim-ledger id, or file/commit
    retrieved: str = ""
    url: str = ""


@dataclass(frozen=True)
class VisualSpec:
    id: str
    title: str
    caption: str
    nodes: list[Node]
    edges: list[Edge]
    legend: list[LegendEntry] = field(default_factory=list)
    motion: bool = True
    width: float = 720.0
    height: float = 420.0
    data_sources: list[DataSource] = field(default_factory=list)


@dataclass(frozen=True)
class ManifestRow:
    """One row of DOC_MANIFEST.md (which doc exists at which tier[s])."""

    id: str
    title: str
    type: str
    variants: list[Tier]
    content_role: str  # "project-doc" | "article" | "asset"
    surface: Surface
    status: str


@dataclass(frozen=True)
class Fact:
    """A fetched public fact (fetch_public_fact.py), always cited."""

    url: str
    value: str
    retrieved: str
    kind: str = "scraped"


@dataclass
class BuildResult:
    doc_id: str
    gate: GateResult
    outputs: dict[str, Path] = field(default_factory=dict)  # format -> written path

    @property
    def ok(self) -> bool:
        return self.gate.ok


# ---------------------------------------------------------------------------
# Sequence diagram (VISUAL_LIBRARY.md #1 "who talks to whom, in what order") —
# a genuinely different shape from VisualSpec's node/edge graph: participants
# are vertical lifelines, messages are horizontal arrows ordered by time.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Actor:
    """A sequence-diagram participant (one vertical lifeline)."""

    id: str
    label: str


@dataclass(frozen=True)
class Message:
    """One arrow between two actors' lifelines, at a given vertical time-order."""

    src: str
    dst: str
    label: str
    order: int  # vertical position; lower = earlier (drawn top to bottom)
    style: str = "solid"  # "solid" call | "dashed" return/async


@dataclass(frozen=True)
class SequenceSpec:
    id: str
    title: str
    caption: str
    actors: list[Actor]
    messages: list[Message]
    width: float = 720.0
    height: float = 420.0
    legend: list[LegendEntry] = field(default_factory=list)
    data_sources: list[DataSource] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Data-series chart specs (VISUAL_LIBRARY.md — bar/heatmap/radar/pie/timeline
# are NOT node graphs; each gets its own small, purpose-shaped dataclass
# rather than being forced into VisualSpec's nodes+edges shape).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BarItem:
    label: str
    value: float
    note: str = ""


@dataclass(frozen=True)
class BarSpec:
    id: str
    title: str
    caption: str
    items: list[BarItem]
    unit: str = ""
    log_scale: bool = False  # log10 bar heights for wide-dynamic-range comparisons
    width: float = 720.0
    height: float = 420.0
    data_sources: list[DataSource] = field(default_factory=list)


@dataclass(frozen=True)
class RadarSeries:
    label: str
    values: list[float]  # aligned 1:1 with RadarSpec.axes


@dataclass(frozen=True)
class RadarSpec:
    id: str
    title: str
    caption: str
    axes: list[str]
    series: list[RadarSeries]
    max_value: float
    width: float = 480.0
    height: float = 480.0
    legend: list[LegendEntry] = field(default_factory=list)
    data_sources: list[DataSource] = field(default_factory=list)


@dataclass(frozen=True)
class PieSlice:
    label: str
    value: float


@dataclass(frozen=True)
class PieSpec:
    id: str
    title: str
    caption: str
    slices: list[PieSlice]
    donut: bool = True
    width: float = 480.0
    height: float = 480.0
    legend: list[LegendEntry] = field(default_factory=list)
    data_sources: list[DataSource] = field(default_factory=list)


@dataclass(frozen=True)
class TimelineEvent:
    label: str
    date_label: str  # human-readable date/period shown on the axis
    t: float  # normalized position along the axis, 0..1 (caller derives from real dates)
    note: str = ""


@dataclass(frozen=True)
class TimelineSpec:
    id: str
    title: str
    caption: str
    events: list[TimelineEvent]
    width: float = 900.0
    height: float = 260.0
    data_sources: list[DataSource] = field(default_factory=list)


@dataclass(frozen=True)
class HeatmapSpec:
    id: str
    title: str
    caption: str
    row_labels: list[str]
    col_labels: list[str]
    matrix: list[list[float]]  # row-major; len == (len(row_labels), len(col_labels))
    min_value: float
    max_value: float
    width: float = 720.0
    height: float = 420.0
    data_sources: list[DataSource] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 2.5D / layered workflow (VISUAL_LIBRARY.md §2 — "how work moves across LAYERS,
# up/down + left/right"). A third distinct shape: nodes belong to a numbered
# layer (depth) plus a column (horizontal position within that layer); a
# connector may cross layers. Not a VisualSpec graph (layer/column position
# replaces free x/y placement) and not a data-series chart.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LayerNode:
    id: str
    label: str
    layer: int  # 0 = top/front plane, increasing = deeper/lower
    col: int  # horizontal slot within its plane


@dataclass(frozen=True)
class LayerConnector:
    src: str
    dst: str
    label: str = ""


@dataclass(frozen=True)
class LayeredSpec:
    id: str
    title: str
    caption: str
    layer_labels: list[str]  # one per layer, top to bottom; len == number of layers
    nodes: list[LayerNode]
    connectors: list[LayerConnector]
    width: float = 720.0
    height: float = 480.0
    data_sources: list[DataSource] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Video-script storyboard (RULEBOOK L19 / Bundle 3 — a future-video-generation
# artifact, not a rendered video: the narrative is written down now, alongside
# the animation the doc already built, for a `content_role: article` doc.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VideoScene:
    beat: str  # short label for the story beat, e.g. "hook", "mechanism", "fix"
    narration: str  # the spoken narration line for this scene
    animation_ref: str = ""  # a VISUAL_LIBRARY §4 animation id, or "" if this beat has none


@dataclass(frozen=True)
class VideoScript:
    doc_id: str
    title: str
    scenes: list[VideoScene]
