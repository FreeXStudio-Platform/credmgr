# Vault Graph — engine specification

`KEEP · CredMgr V2` · the Obsidian/Graphify-class node canvas
`verified: 2026-08-04` · §7 amended 2026-09-24 (entry-dots, operator sign-off 2026-09-07)

The graph is not a widget. It is **the primary navigation surface** of CredMgr V2 — it
replaces the flat credential list of V1. Everything below is a contract Sonnet 5 builds
against.

---

## 1. Engine choice

**Vendored `force-graph@1` (canvas 2D), driven by a custom renderer.**

Rationale, weighed against the alternatives:

| Option | Verdict |
|---|---|
| **force-graph (vendored)** | ✅ **Chosen.** Canvas, so 500+ nodes stay at 60fps. Battle-tested d3-force under the hood. Already vendored + checksum-verified in the portfolio. Exposes `nodeCanvasObject`, so KEEP draws every pixel itself — the library supplies physics and hit-testing, not styling. |
| Hand-rolled force sim | Rejected: reimplements Barnes–Hut and quadtree hit-testing for no gain. |
| Cytoscape.js | Rejected: 400KB+, opinionated styling, its own selector language to learn. |
| D3 + SVG | Rejected: one DOM node per graph node — dies past ~300 nodes, which a 20-project vault reaches. |
| React Flow | Rejected: needs React; V2's frontend is Svelte (see `docs/01_ARCHITECTURE.md`). Also optimised for orthogonal flowcharts, not force layouts. |

The library is used for exactly three things: the force simulation, pan/zoom transform,
and pointer hit-testing. **All drawing is ours** via `nodeCanvasObjectMode('replace')` and
`linkCanvasObjectMode('replace')`.

---

## 2. Data contract

The canvas is fed one object. It is derived from the node registry and the per-node entry
counts — **never from decrypted values**. The graph must render correctly while the vault
is fully locked.

```ts
type VaultGraph = {
  nodes: GraphNode[];
  links: GraphLink[];
  meta: { generatedAt: string; vaultLocked: boolean; };
};

type GraphNode = {
  id: string;                 // node id, e.g. "global" | "n_7f3a"
  label: string;              // display name, e.g. "Linux"
  kind: 'global' | 'project' | 'sub' | 'orphan';
  depth: 0 | 1 | 2;           // 0=global, 1=project, 2=sub. Hard cap at 2.
  parentId: string | null;    // null only for global and orphan
  counts: { entries: number; totp: number };   // the ONLY two numbers ever shown
  gate: { locked: boolean; twofa: 'none' | 'enrolled' | 'required' };
  health: 'ok' | 'warn' | 'danger' | null;     // null = nothing to say (the common case)
  pinned?: { x: number; y: number };            // user-dragged position, persisted
};

type GraphLink = {
  source: string; target: string;
  kind: 'structural' | 'grant';
  direction: 'down' | 'a->b' | 'b->a' | 'mutual';  // structural is always 'down'
  expiresAt?: string | null;                       // grants only
};
```

**Counts rule.** `counts.entries` is the number of credential entries **owned by that node
alone** — never including descendants, never including what it can read through
inheritance. `counts.totp` is the number of stored 2FA/TOTP items owned by that node.
These two numbers are the entire hover card. Adding a third number is a spec violation.

---

## 3. Visual language

Everything below is legible in pure greyscale. Shape and stroke carry meaning; colour
only ever carries *state*, and most nodes have no state to report.

### Nodes

| Kind | Radius | Fill | Stroke |
|---|---|---|---|
| `global` | 22 | `--bone` (solid) | none |
| `project` | 15 | none | `--bone`, 1.5px |
| `sub` | 10 | none | `--ash`, 1px |
| `orphan` | 15 | 45° hatch, `--hatch` | `--faint`, 1.5px **dashed 3 3** |

Overlays, drawn as small marks on the node ring — never as colour fills:

- **Locked** — a 5px keyhole glyph centred in the node.
- **2FA required** — a 2px notch at the 12-o'clock position on the ring.
- **2FA enrolled but unconfirmed** — the same notch, `--warn`.
- **Selected** — ring stroke → 2.5px, plus a 3px offset halo ring in `--bone` at 20% alpha.
- **Search hit** — ring stroke → 2.5px, everything else dimmed to 25% alpha.
- **health='danger'** — ring stroke recoloured `--danger`. This is the only node-level colour.

Node label: mono, `--fs-xs`, drawn **below** the node, only when `zoom ≥ 1.4`, clipped at
22 characters with an ellipsis. The global node's label always renders regardless of zoom.

### Edges

| Kind | Stroke | Width | Notes |
|---|---|---|---|
| `structural` | solid `--hair-strong` | 1 | Always parent → child. Never has an arrowhead: containment is not a direction. |
| `grant` | **dashed 4 3** `--ash` | 1 | Carries an arrowhead at the reading end. `mutual` gets one at both ends. |
| `grant` expiring < 7d | dashed 2 3 `--warn` | 1 | |
| any, when either endpoint is selected | as above, at full alpha; all others drop to 15% | | |

This is the operator's stated rule made exact: **straight solid = direct structural
connection, dashed = a human-granted interconnection.**

---

## 4. Layout

Force simulation, seeded deterministically so the graph looks the same every launch:

```
charge:            -260
linkDistance:      structural 110 · grant 190
alphaDecay:        0.035
velocityDecay:     0.4
centre:            global node pinned at canvas centre, fx/fy set, never free
radialConstraint:  depth 1 → r≈180 · depth 2 → r≈300 (soft radial force, strength 0.06)
collide:           node radius + 26 (the --g-gap-min token)
orphanNode:        pinned bottom-left, excluded from charge/link forces entirely
```

The radial constraint is what makes the topology *legible*: projects sit on a ring around
global, sub-nodes on an outer ring near their parent. Without it a force graph of a strict
tree looks like a hairball.

**Pinning.** Dragging a node sets `fx/fy` and persists `pinned` to the node registry. A
pinned node shows a 1px dot at its centre. `⌥`-drag releases the pin. "Re-flow" in the
canvas menu clears every pin.

**Orphan.** The orphan node never participates in the simulation. It is drawn in a fixed
bottom-left dock, with a hairline to nothing. It is *outside* the tree by definition —
making it float in the same field as real nodes would misrepresent the model.

---

## 5. Interaction

| Gesture | Result |
|---|---|
| **Click node** | Select. Inspector loads that node's own entries. URL/state → `node=<id>`. |
| **Double-click node** | Zoom-to-fit that node and its immediate structural children. |
| **Drag node** | Pin + move. Persists. |
| **⌥-drag node** | Unpin. |
| **Drag canvas** | Pan. |
| **Scroll / pinch** | Zoom, clamped `[0.3, 6]`. |
| **Hover node (180ms)** | Two-number card. Dismisses instantly on leave. |
| **Right-click node** | Context menu: Open · New entry · New sub-node · Grant access… · Rename · Lock now · Remove node… |
| **Drag node A → node B** | **Propose a grant.** Drops open the grant dialog pre-filled A→B. Never creates a grant silently. |
| **`F`** | Fit to view. |
| **`G`** | Jump to global. |
| **`/`** | Focus search. Enter → focus first hit. |
| **`T`** | Toggle graph ⇄ worktree-tree view. |
| **`Esc`** | Clear selection / close menu. |
| **Arrow keys** | Move focus between nodes along edges (keyboard graph traversal). |

**Accessibility.** A canvas is opaque to a screen reader, so the graph ships with a
**mirror**: a visually-hidden `<ul role="tree">` carrying the identical structure, kept in
sync, fully keyboard operable. The worktree view (`T`) is not a nicety — it is the
accessible equivalent of the canvas and must reach 100% feature parity, including grant
creation. Any feature reachable only by dragging on canvas is a bug.

---

## 6. Performance budget

| Metric | Budget |
|---|---|
| Cold render, 50 nodes | < 120ms to first paint |
| Simulation settle, 200 nodes | < 1.5s |
| Frame time while dragging, 500 nodes | < 16ms |
| Memory, 500 nodes | < 40MB canvas + data |

Above 400 nodes: freeze the simulation after settle and only re-run on topology change.
Above 800 nodes: collapse sub-nodes into their parent by default with a `+n` badge.

---

## 7. What the graph must never do

1. **Never render a credential value, name, or field label.** Only node labels and the two
   counts. A screenshot of the graph must leak nothing but topology.
2. **Never show inherited or descendant entries in the count.** Own entries only.
3. **Never create, delete, or modify a grant without an explicit confirmed dialog.**
4. **Never require the vault to be unlocked to draw.** Locked vault → full topology, real
   counts, every value gated. (Counts come from the unencrypted node registry; see
   `docs/03_DATA_MODEL.md` for why that is an accepted, bounded metadata leak.)
5. **Never animate as the sole carrier of meaning.** With `prefers-reduced-motion`, the
   simulation runs one settle pass with no transition and everything still reads.

**§7 (amended — signed off by the operator 2026-09-07 in the Claude Design project's
`BACKEND_HANDOFF_NOTES.md`; pasted upstream 2026-09-24).** Entries MAY be rendered as separate
nodes in the graph view. Default is ON for every node, togglable per session via the E key or the
graph-view chip (client-side only, not persisted server-side). Two mitigations are load-bearing and
must not regress: (1) an entry-dot's colour is a hash of its internal id only — never its name or
value; (2) hover/tooltip on an entry-dot reveals field type only — never name or value. This
narrows the original AR-1 boundary from "entries are invisible" to "entry name and value are
invisible"; entry existence and type may now be visually implied. Rule 1 above still holds for
every entry-dot: no value, name or field label is ever rendered.
