"""One-off generator for the 6 reusable exploit-flow VisualSpec JSON files.

Not part of the runtime API -- run manually (``.venv/bin/python -m
tools.docgen.assets._build_animations``) to (re)produce
``tools/docgen/assets/animations/*.json``. Kept for reproducibility/audit; the
JSON files themselves are the shipped artifact.

Layout note: nodes are placed on a generous grid (>=200px pitch) so every
edge run has enough length to clear the 22px minimum-gap rule (MOTION_SPEC S7)
for its label AND its neighboring node boxes simultaneously. Each spec is
verified clean via ``check_collisions`` before being written -- a spec that
still collides is a bug in this generator, not an acceptable output.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

from tools.docgen.models import DataSource, Edge, LegendEntry, Node, NodeType, VisualSpec
from tools.docgen.visual import check_collisions

OUT_DIR = Path(__file__).parent / "animations"

_LEGEND_NODES = [
    LegendEntry(kind="node", key=NodeType.SOURCE.value, label="Source"),
    LegendEntry(kind="node", key=NodeType.PROCESS.value, label="Process"),
    LegendEntry(kind="node", key=NodeType.DECISION.value, label="Decision"),
    LegendEntry(kind="node", key=NodeType.GATE.value, label="Gate"),
    LegendEntry(kind="node", key=NodeType.ATTACKER.value, label="Attacker-controlled"),
    LegendEntry(kind="node", key=NodeType.OUTPUT.value, label="Output"),
]


def _spec_to_dict(spec: VisualSpec) -> dict[str, object]:
    return asdict(spec)


def _write(spec: VisualSpec) -> None:
    findings = check_collisions(spec)
    if findings:
        print(
            f"REFUSING to write {spec.id}: {len(findings)} collision finding(s):", file=sys.stderr
        )
        for f in findings:
            print(f"   {f.message}", file=sys.stderr)
        raise SystemExit(1)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{spec.id}.json"
    data = _spec_to_dict(spec)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path} (0 collisions)")


def bridge_drain() -> VisualSpec:
    # NOTE: check/drain/safe were originally packed at x=640/920 with only ~170px
    # of run between check's right edge (750) and drain/safe's left edge (920) --
    # too short for the edge-condition label (offset perpendicular 30-44px from
    # the arc midpoint) to clear check's own bbox on one end and drain/safe's on
    # the other simultaneously. Widened the check->drain/safe run to ~340px (check
    # right edge 780 -> drain/safe left edge 1120) so the condition label -- which
    # sits near the midpoint of that run -- has full 22px+ clearance from both
    # neighboring node boxes. Canvas widened to match (1140 -> 1360).
    nodes = [
        Node(id="user", type=NodeType.SOURCE, label="User Deposit", x=40, y=260, w=140, h=56),
        Node(id="attacker", type=NodeType.ATTACKER, label="Attacker Call", x=40, y=60, w=140, h=56),
        Node(
            id="bridge",
            type=NodeType.PROCESS,
            label="Bridge Vault",
            x=340,
            y=160,
            w=150,
            h=64,
            alive=True,
            highlight=True,
        ),
        Node(
            id="check", type=NodeType.DECISION, label="Balance\nCheck?", x=640, y=150, w=140, h=84
        ),
        Node(id="drain", type=NodeType.OUTPUT, label="Funds Drained", x=1120, y=60, w=150, h=56),
        Node(
            id="safe",
            type=NodeType.OUTPUT,
            label="Withdrawal OK",
            x=1120,
            y=340,
            w=150,
            h=56,
            note="Guarded path",
        ),
    ]
    edges = [
        Edge(src="user", dst="bridge", label="deposit", main=True),
        Edge(src="attacker", dst="bridge", label="reentrant call", condition="no reentrancy guard"),
        Edge(src="bridge", dst="check", label="withdraw()", main=True),
        Edge(
            src="check", dst="drain", label="", condition="checked after call → exploit", main=True
        ),
        Edge(
            src="check",
            dst="safe",
            label="",
            condition="checked before call → safe",
            style="dashed",
        ),
    ]
    return VisualSpec(
        id="anim-bridge-drain",
        title="Bridge Drain via Reentrancy",
        caption="Illustrative sequence: an attacker re-enters a withdrawal before state is updated, draining the vault.",
        nodes=nodes,
        edges=edges,
        legend=_LEGEND_NODES,
        width=1360,
        height=520,
        data_sources=[DataSource(kind="metric", ref="anim.bridge-drain.illustrative")],
    )


def brute_force() -> VisualSpec:
    # DEVIATION NOTE (see task constraints): this builder was ALREADY failing
    # check_collisions on the pre-edit baseline (verified via `git stash` diff --
    # oracle's bbox/label overlapped the oracle->success edge-condition label, and
    # oracle->fail's condition label overlapped the fail node), independent of the
    # bridge_drain fix above. Since the required verification step ("ALL 6 functions
    # must produce 0 collisions") cannot pass otherwise, applying the same minimal
    # spacing-only fix here: widened oracle->success/fail run so the condition label
    # near the arc midpoint clears both the oracle box and the success/fail boxes.
    nodes = [
        Node(id="attacker", type=NodeType.ATTACKER, label="Attacker", x=40, y=200, w=140, h=56),
        Node(
            id="guess",
            type=NodeType.PROCESS,
            label="Guess Nonce",
            x=340,
            y=200,
            w=150,
            h=56,
            alive=True,
        ),
        Node(
            id="oracle",
            type=NodeType.GATE,
            label="Signature\nCheck",
            x=640,
            y=190,
            w=130,
            h=84,
            highlight=True,
        ),
        Node(id="success", type=NodeType.OUTPUT, label="Forged Auth", x=1140, y=60, w=150, h=56),
        Node(id="fail", type=NodeType.FALLBACK, label="Rejected", x=1140, y=380, w=150, h=56),
    ]
    edges = [
        Edge(src="attacker", dst="guess", label="iterate space", main=True),
        Edge(src="guess", dst="oracle", label="submit", main=True),
        Edge(src="oracle", dst="success", condition="predictable ID matched → forged", main=True),
        Edge(src="oracle", dst="fail", condition="entropy sufficient → rejected", style="dashed"),
    ]
    return VisualSpec(
        id="anim-brute-force",
        title="Brute-Force / Predictable Nonce",
        caption=(
            "Illustrative sequence: an attacker iterates a small keyspace until a weak "
            "nonce/signature check accepts a forged value."
        ),
        nodes=nodes,
        edges=edges,
        legend=_LEGEND_NODES,
        width=1360,
        height=520,
        data_sources=[DataSource(kind="metric", ref="anim.brute-force.illustrative")],
    )


def sandwich() -> VisualSpec:
    # DEVIATION NOTE (see task constraints): pre-existing collision -- 'victim' at
    # y=340..396 sat directly under the legend row (which anchors at height-78, i.e.
    # y≈382..396 at the original height=460), overlapping 2 legend swatches and
    # falling short of the min gap to its own edge label. Fix: push 'victim' up
    # (y=340 unchanged is fine once canvas height grows) -- actually raised canvas
    # height so the legend row clears every node with margin, matching the other
    # builders' generous-canvas convention.
    nodes = [
        Node(id="attacker", type=NodeType.ATTACKER, label="Attacker Bot", x=40, y=60, w=150, h=56),
        Node(id="frontrun", type=NodeType.PROCESS, label="Front-run Tx", x=340, y=60, w=150, h=56),
        Node(
            id="pool",
            type=NodeType.DATASTORE,
            label="Liquidity Pool",
            x=640,
            y=200,
            w=150,
            h=84,
            alive=True,
            highlight=True,
        ),
        Node(id="victim", type=NodeType.SOURCE, label="Victim Tx", x=340, y=360, w=150, h=56),
        Node(id="backrun", type=NodeType.PROCESS, label="Back-run Tx", x=940, y=60, w=150, h=56),
        Node(id="profit", type=NodeType.OUTPUT, label="Attacker Profit", x=940, y=360, w=150, h=56),
    ]
    edges = [
        Edge(src="attacker", dst="frontrun", label="submit", main=True),
        Edge(src="frontrun", dst="pool", label="skew price", main=True),
        Edge(src="victim", dst="pool", label="swap at bad price", main=True),
        Edge(src="pool", dst="backrun", label="", main=True),
        Edge(src="backrun", dst="profit", label="realize spread", main=True),
    ]
    return VisualSpec(
        id="anim-sandwich",
        title="Sandwich / MEV Attack",
        caption=(
            "Illustrative sequence: an attacker front-runs then back-runs a victim swap "
            "around a manipulated pool price."
        ),
        nodes=nodes,
        edges=edges,
        legend=_LEGEND_NODES,
        width=1160,
        height=560,
        data_sources=[DataSource(kind="metric", ref="anim.sandwich.illustrative")],
    )


def contract_manipulation() -> VisualSpec:
    # DEVIATION NOTE (see task constraints): pre-existing collisions -- attacker->proxy
    # was too short a run for its label to clear both endpoint nodes; proxy->logic's
    # condition label sat inside proxy's own bbox; storage's note-adjacent caption gap
    # was under the 22px minimum. Widened proxy/logic/storage/hijack x-spacing and
    # canvas height so every label clears its neighboring boxes with margin.
    nodes = [
        Node(
            id="attacker", type=NodeType.ATTACKER, label="Attacker Input", x=40, y=200, w=150, h=56
        ),
        Node(
            id="proxy",
            type=NodeType.GATE,
            label="Proxy\nDelegatecall",
            x=400,
            y=190,
            w=140,
            h=84,
            alive=True,
        ),
        Node(
            id="logic",
            type=NodeType.PROCESS,
            label="Logic Contract",
            x=840,
            y=60,
            w=150,
            h=56,
            highlight=True,
        ),
        Node(
            id="storage", type=NodeType.DATASTORE, label="Storage Slots", x=760, y=340, w=150, h=84
        ),
        Node(
            id="hijack",
            type=NodeType.OUTPUT,
            label="Ownership Hijacked",
            x=1120,
            y=200,
            w=170,
            h=64,
        ),
    ]
    edges = [
        Edge(src="attacker", dst="proxy", label="crafted calldata", main=True),
        Edge(
            src="proxy",
            dst="logic",
            label="delegatecall",
            condition="unchecked implementation → exploit",
            main=True,
        ),
        Edge(src="proxy", dst="storage", label="writes collide", main=True),
        Edge(src="storage", dst="hijack", label="", main=True),
    ]
    return VisualSpec(
        id="anim-contract-manipulation",
        title="Contract Manipulation via Delegatecall",
        caption=(
            "Illustrative sequence: attacker-controlled calldata bends proxy logic, colliding "
            "storage slots to hijack ownership."
        ),
        nodes=nodes,
        edges=edges,
        legend=_LEGEND_NODES,
        width=1370,
        height=540,
        data_sources=[DataSource(kind="metric", ref="anim.contract-manipulation.illustrative")],
    )


def double_spend() -> VisualSpec:
    # DEVIATION NOTE (see task constraints): pre-existing collisions -- txb overlapped
    # 2 legend swatches (its box sat directly under the legend row) AND its own
    # outgoing edge-condition label (the run to ledger was too short/too close to
    # txb's own box). Pushed txb down + ledger/desync right and raised canvas height
    # so both the legend row and the condition label clear every node with margin.
    nodes = [
        Node(id="attacker", type=NodeType.ATTACKER, label="Attacker", x=40, y=200, w=140, h=56),
        Node(id="txa", type=NodeType.PROCESS, label="Tx A: Spend", x=340, y=60, w=150, h=56),
        Node(
            id="txb", type=NodeType.PROCESS, label="Tx B: Spend (replay)", x=340, y=440, w=190, h=56
        ),
        Node(
            id="ledger",
            type=NodeType.DATASTORE,
            label="Balance Ledger",
            x=760,
            y=200,
            w=160,
            h=84,
            alive=True,
            highlight=True,
        ),
        Node(id="desync", type=NodeType.OUTPUT, label="State Desync", x=1100, y=200, w=160, h=84),
    ]
    edges = [
        Edge(src="attacker", dst="txa", label="submit", main=True),
        Edge(src="attacker", dst="txb", label="submit (same value)", main=True),
        Edge(src="txa", dst="ledger", label="debit", main=True),
        Edge(
            src="txb",
            dst="ledger",
            label="debit again",
            condition="no consumed-flag check → double spend",
            main=True,
        ),
        Edge(src="ledger", dst="desync", label="", main=True),
    ]
    return VisualSpec(
        id="anim-double-spend",
        title="Double-Spend via Missing Consumed-Flag",
        caption="Illustrative sequence: the same value is debited twice because the ledger never marks it consumed.",
        nodes=nodes,
        edges=edges,
        legend=_LEGEND_NODES,
        width=1350,
        height=600,
        data_sources=[DataSource(kind="metric", ref="anim.double-spend.illustrative")],
    )


def reentrancy() -> VisualSpec:
    # DEVIATION NOTE (see task constraints): pre-existing collisions -- the
    # attacker->withdraw label sat marginally under the 22px minimum from both
    # endpoint nodes; callback->reenter's condition label overlapped callback's own
    # bbox; callback->update's condition label overlapped update's bbox; and the
    # callback->reenter condition label was too close to the reenter->drain label.
    # Re-spaced callback/reenter/update/drain (search-verified via check_collisions)
    # so every label clears its neighboring boxes with margin.
    nodes = [
        Node(
            id="attacker",
            type=NodeType.ATTACKER,
            label="Attacker Contract",
            x=40,
            y=200,
            w=160,
            h=56,
        ),
        Node(
            id="withdraw",
            type=NodeType.PROCESS,
            label="withdraw()",
            x=420,
            y=200,
            w=150,
            h=56,
            alive=True,
            highlight=True,
        ),
        Node(
            id="callback",
            type=NodeType.DECISION,
            label="External\nCall?",
            x=700,
            y=190,
            w=120,
            h=84,
        ),
        Node(id="reenter", type=NodeType.JUNCTION, label="", x=1220, y=60, w=24, h=24),
        Node(
            id="update", type=NodeType.PROCESS, label="Update Balance", x=1100, y=380, w=160, h=56
        ),
        Node(id="drain", type=NodeType.OUTPUT, label="Vault Drained", x=1320, y=200, w=150, h=64),
    ]
    edges = [
        Edge(src="attacker", dst="withdraw", label="call withdraw", main=True),
        Edge(src="withdraw", dst="callback", label="send funds", main=True),
        Edge(
            src="callback",
            dst="reenter",
            condition="callback before state update → reentrant",
            main=True,
        ),
        Edge(src="reenter", dst="withdraw", label="re-invoke", style="dashed"),
        Edge(src="callback", dst="update", condition="state updated first → safe", style="dashed"),
        Edge(src="reenter", dst="drain", label="repeat until drained", main=True),
    ]
    return VisualSpec(
        id="anim-reentrancy",
        title="Classic Reentrancy Drain",
        caption="Illustrative sequence: a callback re-enters withdraw() before the balance is updated, repeating the drain.",
        nodes=nodes,
        edges=edges,
        legend=_LEGEND_NODES,
        width=1570,
        height=580,
        data_sources=[DataSource(kind="metric", ref="anim.reentrancy.illustrative")],
    )


def main() -> None:
    for builder in (
        bridge_drain,
        brute_force,
        sandwich,
        contract_manipulation,
        double_spend,
        reentrancy,
    ):
        _write(builder())


if __name__ == "__main__":
    main()
