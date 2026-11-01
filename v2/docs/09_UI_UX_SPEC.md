---
id: V2-009
classification: public
title: UI / UX specification
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
variants: public
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18, after the freeze on this document was lifted. The previous stamp (Approved
     With Known Risks @ d15a5c7 on 2026-08-04, reconciled 2026-08-10 under ADR-052) attested to
     a body written almost entirely in the present tense, describing screens, a design system
     and a first-run flow as though rendered and reachable. This document was withheld from the
     2026-08-18 corpus rewrite on the belief that an external front-end team was building every
     screen from a byte-identical copy of it. **No such team exists and no copy was ever sent**
     (commit `ee59696`; see `HANDOVER_STATE.md`) — the freeze protected nobody, and the correct
     response to a false premise is to fix the document, not to leave it uncorrected. Every claim
     below was re-checked against live source in this pass: the desktop application does not
     exist (`v2/apps/desktop/src/routes/` holds one `+page.svelte`, the `create-tauri-app`
     hello-world); the Tauri bridge reaches 8 of the broker's 38 operations with no screen
     calling any of them (ADR-057, `19_FRONTEND_DELIVERY_SCOPE.md`); the KEEP design tokens and
     the vendored graph engine are real files, unchanged; and one genuine defect was found and
     fixed — §12's first-run flow claimed "V1 migration is offered" here, an operation
     `11_MIGRATION.md` retracted and explicitly flagged as residue still living in this document
     (`11_MIGRATION.md §3.2`). The corpus-wide hardening status is the operator's to assign after
     their own review, not this session's to self-award. Updated 2026-09-24 for ADR-062 (the
     bridge now reaches all 42 ops) — status callout and Source only; no screen spec changed.
     Updated 2026-09-24 for ADR-071…073 (the bridge at 47 ops) — status callout and Source only;
     no screen spec changed. Updated 2026-10-02 for ADR-075…077 (the design is hosted, the bridge
     reaches 48 ops) — status callout, §1, §2 and Source only; no screen spec changed. Updated 2026-10-03 for
     ADR-078/079 (every screen wired, the bridge at 53 ops; the status callout lists the differences from this
     specification) — status callout and Source only; no screen spec changed. The
     statements above about `routes/` holding one `+page.svelte` and the bridge reaching 8 of 38
     operations record what the 2026-08-18 pass found and are superseded by the status callout. -->
# UI / UX specification

`CredMgr V2` · every screen the desktop delivery must render, specified in full — Pass 1 content,
Pass 2 reviewed, corrected to ultimate-destination state · `2026-08-18`
Design system: **KEEP** (`design/tokens/keep.tokens.json`, `keep.css`, `keep-components.css`) —
the tokens are real and built, and the hosted design loads `keep.css` (generated from them).
Graph engine: `design/graph-engine/VAULT_GRAPH_SPEC.md` — the spec and the vendored
`force-graph@1` engine are real and built; **the hosted app does not load that engine**: its graph is
the design's own hand-written canvas (`apps/desktop/src/design/logic/graph.js`, `ADR-075`).

> **Status.** **The screens this document describes are designed, hosted and wired to the vault.**
> `v2/apps/desktop/` hosts the finished app design — the KEEP design, precompiled at build time and served
> under the strict CSP (`ADR-075`) — and every screen reads from the broker and every change goes to it,
> through one model (`apps/desktop/src/vault/`): first run, the Lock screen with the second factor, the
> graph, tree and inspector, an entry's detail with its fields, Add entry, the review tray, nodes with their
> policy, seal and restore, grants, the audit trail, Verify, Doctor, Back up, root-key rotation, settings and
> About. There is no demo data and no local-only write path in a release build. The bridge beneath reaches
> **all 53 of the broker's operations** — eight hand-written (`vault.status`, `vault.unlock`,
> `vault.gate_verify`, `vault.lock`, `whoami`, `graph.snapshot`, `entry.list`, `entry.reveal`, `ADR-057`) and
> forty-five generated (`ADR-062`; five added for `ADR-071`…`ADR-073`, `maintenance.rotate_root` for `ADR-076`,
> five for `ADR-078`), with a typed client in `apps/desktop/src/lib/bridge.ts` — holding the session token in
> Rust and never returning it to the webview — and the shell's own three commands: the concealed clipboard
> (`entry_copy`, `copy_text`) and the local bulk-paste preview (`fields_preview`), plus lock-on-sleep
> (`02_ARCHITECTURE.md §6.2`). In the section headings below, `planned` was written when a screen was
> *not yet wired to the vault*; read it as **`built` in the app, with its real-app result recorded in
> `RELEASE_VERIFICATION.md`**, except for the pieces this callout lists as absent.
> **Where the shipped app differs from this specification** (`apps/desktop/design-upstream/PROVENANCE.md`, "Deliberate
> changes"): the Agents / LLM section, the machine lock, the duress code, per-node security levels, content search
> (search matches names only) and `--age` export are **not in the app** (no backing feature); there is no
> re-parent dialog and no approval prompt (no control calls `node.reparent` or `vault.approval_decide`); five
> operations are sent for real and refused with `presence_required` (grant creation, the full audit record, a TOTP
> field's seed, root-key rotation, a registry rebuild) and the app says so; the donation address is one static entry
> under About → Donate, never a banner; the design's "looks sensitive" hint is gone with its own inference (the
> preview shows the Rust inference); Settings keeps its preferences in `credmgr_prefs` (`PRIVACY.md`).
> `19_FRONTEND_DELIVERY_SCOPE.md` is the sibling document that scopes *how much* must be
> delivered and *what a screen may call today*; this one specifies *how each screen looks and
> behaves*, in full, so the two are read together rather than as duplicates.

---

## 1. Product posture — **`planned`**

**`planned`.** No home screen has been verified to embody these end to end yet (the hosted design's
home screen reads the vault through the broker and its actions write through it, but the control-by-control
pass of `RELEASE_VERIFICATION.md` has not been done) — the three sentences below are decided design principle, ratified across Pass 1
and the Pass 2 adversarial review, and every later section in this document exists to keep them
true once a screen is wired.

Three sentences that will decide every later argument:

1. **The vault is a map, not a list.** The home screen will show structure. Values will always
   be one deliberate step away.
2. **Quiet by default.** Nothing will blink, badge, nag, or suggest. A credential manager that
   demands attention gets ignored, and an ignored vault gets left unlocked.
3. **Lite hides levers, never safety.** Backups, integrity checks and auto-lock will run in both
   modes. Lite will remove *controls*, not *protection*.

---

## 2. The shell — **`planned`**

The hosted design (`v2/apps/desktop/src/design/`, `ADR-075`) renders a shell today; what it
shows comes from the broker where the status callout above names it, and nothing it writes reaches the
broker (`19_FRONTEND_DELIVERY_SCOPE.md §2`). This
section is the written specification of the three-pane layout; whether the hosted layout matches
it in every detail is not asserted here. The three-pane layout below is the target design in full.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  ⬢ vault-name        [ search…                    ]    ○ unlocked   ⌄ ⚙          │ 52px
├────────────────────┬──────────────────────────────────┬──────────────────────────┤
│  WORKTREE          │                                  │  NODE · linux            │
│  ● global      12  │            ● global              │  ─────────────────────   │
│  ○ acme        41  │           ╱   │   ╲              │  12 entries · 3 2FA      │
│  ○ globex      38  │      ○───┘    │    └───○         │                          │
│  ○ initech     22  │   acme        ○      initech     │  + New entry             │
│  ▾ linux       12  │             linux                │                          │
│    ○ dev        4  │            ╱  │  ╲               │  ⌗ vps-root       server │
│    ○ staging    3  │         ○    ○    ○              │  ⌗ deploy-key     ssh    │
│    ○ prod       5  │        dev staging prod          │  ⌗ grafana-admin  login  │
│  ⌗ orphaned     7  │                                  │  ⌗ backup-b2      api    │
│                    │   ┌ ─ ─ ─ ┐                      │  …                       │
│  [ graph | tree ]  │     orphan                       │                          │
│                    │   └ ─ ─ ─ ┘                      │  NOTES              ⌄    │
└────────────────────┴──────────────────────────────────┴──────────────────────────┘
   rail 300px               canvas (fluid)                    inspector 420px
```

- **Rail** — the worktree list: the same graph, as a tree. Selecting in either pane will sync the
  other.
- **Canvas** — the node graph. Full spec in `VAULT_GRAPH_SPEC.md` (built as a specification and
  as a vendored, sha384-pinned engine; not yet driven by any screen).
- **Inspector** — will show the selected node: its two counts, its entries, its notes.
- **`T`** will toggle the canvas between **graph** and **tree** view; the rail will stay either
  way, so a keyboard user is never dependent on the canvas.

### 2.1 The inspector will show one node's own data. Nothing else.

This is a **hard rule**, restated because it is the one most likely to be softened by a
well-meaning "helpful" change once a screen exists to soften it in:

> The inspector will list **only entries owned by the selected node**. Not the parent's. Not
> Global's. Not a child's. Not anything reachable through a grant.

If a user wants Global's credentials, they will click Global. The inheritance rules govern
*machine* access; the inspector is designed as a *human* view of one place. Mixing "what lives
here" with "what I could reach from here" is exactly the contamination the whole design exists to
prevent, and it is how a user ends up rotating the wrong secret.

Search (§6) will be the one place that spans nodes — and its results will always be labelled with
the owning node.

---

## 3. Node states, expressed without colour — **`planned`**

**`planned`** as a rendering. Some of the underlying data already exists: `graph.snapshot`
(built, `19_FRONTEND_DELIVERY_SCOPE.md §4`) already carries `gate.twofa` (`none` / `enrolled` /
`required`) and `counts`, which the "2FA required" and orphan rows below will read from directly.
`health` is `null` in every response today — no integrity or expiry computation exists behind
it — so the "expiring content" and "integrity failure" rows have no data source yet and are
target design in full.

| State | Rail | Canvas |
|---|---|---|
| normal | plain row | ring, per `VAULT_GRAPH_SPEC §3` |
| selected | filled row background | 2.5px ring + halo |
| locked (node-level) | keyhole glyph before the label | keyhole glyph inside the node |
| 2FA required | small notch after the count | notch at 12 o'clock on the ring |
| expiring content | count in `--warn` | ring recoloured `--warn` |
| integrity failure | count in `--danger` | ring recoloured `--danger` |
| orphaned | dashed row, hatched | dashed hatched node, docked bottom-left |

## 4. The hover card — exactly two numbers — **`planned`**

```
        ┌──────────────────┐
        │   12       3     │
        │  ENTRIES   2FA   │
        └──────────────────┘
```

Will appear after 180 ms over a node, in either view. Will contain **the count of entries owned
by that node** and **the count of stored TOTP items owned by that node** — nothing else: no name,
no path, no last-modified, no sensitivity breakdown, no "3 expiring". The card will be
`pointer-events: none` and will vanish on leave. `graph.snapshot`'s `counts` object already
carries exactly these two numbers and no third (built), which is why there is no third number to
design a slot for.

Locked vault → the same two numbers will show, unchanged — `graph.snapshot` already serves them
while locked, because it reads the plaintext registry and needs no root key
(`19_FRONTEND_DELIVERY_SCOPE.md §4`).
Orphan node → will show the entry count and `—` for 2FA, because the type of sealed content is
not enumerated.

---

## 5. Pro and Lite — **`planned`**

**`planned`.** Neither "Lite" nor "Pro" appears anywhere in `v2/crates/` — mode is a pure UI
feature-gate with no backend representation, by design: the broker enforces capabilities and node
scope, never a product tier. One toggle, `Settings → Mode`, will decide which controls a screen
offers, and switching will be instant, non-destructive, and will never hide data — only controls.
A Lite user's vault will be byte-identical to a Pro user's.

| Surface | Lite | Pro |
|---|---|---|
| Graph + tree + inspector | ✅ | ✅ |
| Add / edit / reveal / copy | ✅ | ✅ |
| Search | ✅ (see §6) | ✅ |
| Add + remove nodes | ✅ | ✅ |
| Grants — **view and revoke** | ✅ | ✅ |
| Grants — **create** | ❌ ("managed in Pro") | ✅ |
| Sealed-node **restore** (≤ 7 days) | ✅ | ✅ |
| Node policies (`descendantRead`, `siblingVisibility`, `agentAccess`) | ❌ hidden, defaults apply | ✅ |
| Automatic daily backup + before every destructive op | ✅ (shows only "last backup: 2h ago") | ✅ |
| Backup / restore controls | ✅ one button | ✅ + retention, destinations, `--age` export |
| Integrity check | ✅ **automatic**, surfaces only on failure | ✅ manual `verify`, `doctor`, repair |
| Audit log · access log | ❌ | ✅ |
| Operations panel (§6.2) | ❌ **does not exist** | ✅ |
| MCP / agent configuration | ❌ (agents still work on defaults) | ✅ |
| Machine lock · root-key rotation · node re-key | ❌ | ✅ |
| Import `.env` · export `.env` | ❌ | ✅ |
| Orphan reveal | ✅ (safety, not a lever) | ✅ |

Lite's Settings will be **four** sections: Security · Appearance · Backup · Mode.
Pro's will add: Nodes · Grants · Agents · Maintenance · Audit · Advanced.

> **The principle, applied strictly.** [Pass 2 · F-13] Pass 1 stated "Lite hides levers, never
> safety" in §1 and then hid grant management entirely four sections later — leaving a Lite
> user unable to remove a grant they had decided they no longer wanted. *Creating* a grant is
> a lever. *Revoking* one is safety. The same re-read moved sealed-node **restore** and
> **automatic backup** into Lite for the same reason. When a control is ambiguous, ask: does
> removing it make a bad situation harder to fix? If yes, it belongs in both modes.

---

## 6. Search, and the removal of the noisy palette — **`planned`**

### 6.1 What V1 did wrong

Clicking the search bar dropped 16 commands into view — *New credential, Batch import, Merge,
Vault stats, Run doctor, Back up, Verify integrity, Health audit, Changelog, Access log,
Toggle sidebar, Settings, Shortcuts, Theme, Lock* — before the user had typed anything. The
search bar was not a search bar; it was a menu wearing one.

### 6.2 What V2 will do

**Search will be for finding things.** Its empty state will be minimal:

| Mode | Empty-state rows |
|---|---|
| **Lite** | exactly one: **`+ Add new`** |
| **Pro** | `+ Add new`, then up to 5 recently-opened nodes/entries |

Typing will filter **nodes and entries only**. Every result will be labelled with its owning
node. No command, operation, or setting will ever appear in search results.

**What search will cover, by lock state** [Pass 2 · F-18]:

| | locked | unlocked |
|---|---|---|
| node labels | ✅ | ✅ |
| entry **names** | ✅ (plaintext manifest) | ✅ |
| field **labels** | ❌ | ✅ |
| note text | ❌ | ✅ |
| **values** | ❌ never | ❌ **never, in either state** |
| orphaned entries | by name only, never previewable | by name only, never previewable |

Values will never be indexed and never searched. A search that matched on a value would be a
side-channel that reveals secrets to anyone who can type — the row above is a hard limit, not a
scoping choice a later screen can loosen.

**Operations will live in their own panel** (Pro only): `⌘⇧O`, or `Settings → Operations`. It
will be a proper full-height list — a large, clickable inventory with a one-line description
each, not a dropdown:

```
  OPERATIONS
  ────────────────────────────────────────────────────────────
  Verify integrity     Check every envelope and manifest checksum.
  Doctor               Diagnose and repair registry, refs, manifests.
  Back up vault        Encrypted archive to the configured destination.
  Merge entries        Combine duplicates into one entry.  (rarely needed in V2)
  Re-key a node        Generate a new node key, re-encrypt its entries.
  Rotate root key       New root key; re-issues the recovery code.
  Export node           Write a .env for one node.  Requires 2FA.
  Import .env           Read a .env into a chosen node.
  Purge access log      Empty the access log.
  Audit report          Read/deny activity + stale grants, last 30 days.
```

The main interface will keep its own **`+ New entry`** button in the inspector. Search's
`+ Add new` will be a second doorway to the same flow, exactly as the brief asks — not a
replacement for the button.

---

## 7. Adding a credential — **`planned`**

One flow that will be reachable from the inspector button, search, `N`, or the node context menu.
The field-level mechanics this flow wraps — the add-field control, the bulk grammar, the preview
contract, and type inference across every field type (`password`, `api-key`, `private-key`,
`seed-phrase`, `totp-seed`, `username`, `host`, `port`, `url`, `certificate`, `text`) — are
`08_FIELD_MODEL.md §2`–`§6` in full and are not re-specified here; this section covers only the
surrounding flow: which node, what happens while locked, and what gets logged.

```
Step 1  ┌ WHERE ────────────────────────────────────────────┐
        │  Node:  [ linux ▾ ]            (pre-filled with   │
        │                                 the selected node)│
        └───────────────────────────────────────────────────┘
Step 2  ┌ WHAT ─────────────────────────────────────────────┐
        │  Name:  [ vps-root                              ] │
        │                                                   │
        │  + Add field        ● Single    ○ Bulk            │
        │  ┌──────────┐  ┌──────────────────────────────┐   │
        │  │ label    │  │ value                        │   │
        │  └──────────┘  └──────────────────────────────┘   │
        └───────────────────────────────────────────────────┘
Step 3  ┌ PREVIEW ──────────────────────────────────────────┐
        │  4 fields · 2 masked · type: server ▾ · crit ▾    │
        │  [ Save ]  [ Save and add another ]  [ Cancel ]   │
        └───────────────────────────────────────────────────┘
```

- The node will be chosen **first** and will always be visible. Saving to the wrong boundary is
  the mistake this product must make hard.
- **Adding a NEW entry to a locked vault will be supported** (asymmetric node keys, `04 §3`) —
  and the broker half of this is already real: `entry.create` is a built, dispatched op that
  accepts a write while the vault is locked and queues it (`crates/brokerd/src/ops.rs`). The
  header will show `will be held for review until unlock`, and the entry will land in the node's
  **pending tray** rather than the manifest. Editing an *existing* entry will require the vault
  open, and the UI will say so rather than offering a control that would fail. [Pass 2 · F-1]
- At unlock, a single non-modal banner will report the tray:
  `3 entries were added while locked — review`. Each will be accepted or discarded individually,
  with its node, name and field count shown. Accepting will be what writes it to the manifest.
  The tray itself is already real at the broker level — `vault.pending_list`,
  `vault.pending_accept` and `vault.pending_discard` are dispatched ops today
  (`crates/brokerd/src/ops.rs`) — what is missing is the banner and the per-item review screen.
- Values will never be echoed to the shell, never logged, never placed in a URL, and the whole
  add flow will be excluded from screen-capture where the OS permits it.

## 8. Revealing a value — **`planned`**

Masked by default per field type (`08_FIELD_MODEL.md §6`). Reveal will be per field, never per
entry.

`Reveal` → (node policy) → 2FA challenge if required → value visible for **20 seconds** with
a thin countdown rule, then re-masks. `Copy` will use the concealed clipboard (30 s clear, clear
on app switch) and will **never require reveal** — copying without looking is the safer path and
should be the easier one.

Every reveal will write an audit record. Copy will write one too.

### 8.1 A `totp-seed` field will reveal as a live code, not raw text — **`planned`**, gated on `partial` backend work

A field whose type infers as `totp-seed` (`08_FIELD_MODEL.md §6`, `03_DATA_MODEL.md §5`) will not
reveal the way every other field does. `07_TWO_FACTOR.md §6` names this document, by section, as
where "the countdown ring and the concealed-clipboard copy with a 30-second clear" belong — this
subsection is that design.

Revealing a stored TOTP item will show a rotating **six-digit code** with its own countdown ring,
not the base32 secret, because `totp.code` and `totp.seed` are two different capabilities with two
different gates (`07_TWO_FACTOR.md §6`): a code is cheap to hand out, a seed is not. The countdown
ring will track the TOTP period (30 s by convention) rather than the generic 20-second reveal
window in §8, and `Copy` on a TOTP field will copy the current code through the same concealed
clipboard as every other field.

This is designed against a backend that is honestly incomplete today, and the screen's job is to
say so rather than fail silently:

- `totp.code` is `built`, but decodes a stored secret with fixed SHA-1 / 6 digits / 30 seconds.
  The add-field flow correctly classifies a pasted `otpauth://` URI as `totp-seed`, but storing
  the whole URI **will not yet produce a working code** — the finished item support will parse the
  URI into issuer, account, secret, period and digits at add time, through the ordinary add flow,
  with no special screen. Until then, the reveal screen will show *"this code can't be generated
  yet"* rather than a blank ring or a silently wrong one.
- An item using 8 digits or SHA-256/SHA-512 cannot be served at all, because no op stores or reads
  per-item parameters today (`07_TWO_FACTOR.md §6`).
- A separate **"Show raw secret"** affordance — for exporting to another authenticator app — will
  route through `totp.seed`, which is gated on 2FA **and** presence and is unreachable end to end
  on every transport that exists, because `presence_attested` is hardcoded `false` at every call
  site (`crates/brokerd/src/ops.rs`). That affordance will fail closed exactly as `totp.seed` does
  today, and the screen will say why rather than presenting a button that cannot work.

---

### 8.2 The six unmasked types skip the dots, never the gate — **`planned`**

§8's generic reveal flow (`Reveal` → gate → 20-second window → re-mask) presumes there is
something masked to unmask. `08_FIELD_MODEL.md §6.1`'s table names six `FieldType`s that are
**not** masked by default — `host`, `port`, `url`, `username`, `certificate`, `text` — and §8 as
written leaves their behaviour unstated, in tension with §1's own unqualified promise that
"values will always be one deliberate step away."

**The authorisation half does not change by type, and this document must not claim it does.**
`entry.reveal` is the *only* dispatched op that returns a decrypted value at all —
`entry.list`/`search` return names and ids, never contents (`crates/brokerd/src/ops.rs`) — and it
gates on `Capability::Reveal` uniformly, with no branch anywhere that reads a field's `masked`
flag. Fetching an unmasked field's value therefore takes the **identical** gated round trip as a
masked one — the same node-lock check, the same `approval_pending` path on R1 (§8's flow, `07
§5a`), the same audit record. What changes for the six unmasked types is display only: once the
screen holds the fetched value, it will render directly in the field row with no dots and no
`Reveal` click needed to see it — but the fetch itself is never a lighter path, only a
same-request render decision on a value the round trip already required. `Copy` behaves
identically for both: the concealed clipboard, never a raw copy (§8).

**`certificate` is the one case worth stating explicitly, because it looks like it should be
masked and is not**: `high` sensitivity, unmasked-by-display, because a certificate is routinely
public material paired with a private key that is *not* (`08_FIELD_MODEL.md §6.1`, row 2). Its
sensitivity
border (§8.3) still renders at the `high` tier — sensitivity and masking are independent axes,
and this is the type that proves it.

### 8.3 Sensitivity will render as a border, not a label — **`planned`**

None of the four sensitivity tiers (`low`/`medium`/`high`/`critical`) has a stated UI treatment
today; §7's preview mockup shows only a bare, unexplained `crit ▾` abbreviation. The design system
already has the answer built and unconsumed: `design/tokens/keep.css` defines a four-step
`.sens-*` border ladder —

| Tier | Class | Treatment |
|---|---|---|
| `low` | `.sens-low` | 1px `--faint` left border |
| `medium` | `.sens-medium` | 2px `--mute` left border |
| `high` | `.sens-high` | 3px `--bone` left border |
| `critical` | `.sens-critical` | 3px `--danger` left border |

Every field row, in the add-flow preview (§7), the entry-detail screen (§8.4), and anywhere else
a field is listed, will carry its tier's border — never a text label, never a coloured fill, so
the treatment survives both themes and both colour-axis states (`20_THEMING.md §1`) without a
second design. The Step-3 preview's `crit ▾` is the sensitivity **override control** referenced
in `08_FIELD_MODEL.md §6.3` ("the UI does not allow lowering sensitivity below `high` without a
confirm"), not the display treatment — the two are different things and this document previously
conflated them by showing only one.

### 8.4 Entry detail — viewing and editing a saved entry — **`planned`**

The single most load-bearing screen in the product, and the one this document did not previously
specify: what a user sees after opening an entry that already exists. Reached from the inspector
(§2.1) or search (§6), replacing §7's add-flow preview once an entry has been saved at least once.

```
┌─────────────────────────────────────────────────────────┐
│  ← acme / prod-db                              ⋮ node   │
├─────────────────────────────────────────────────────────┤
│  ┃ host          db.example.com                    ⋮    │   ← .sens-medium, unmasked
│  ┃ port          5432                               ⋮    │   ← .sens-medium, unmasked
│  ┃ username      deploy-svc                          ⋮    │   ← .sens-medium, unmasked
│  ┃ password      ••••••••••••          Reveal   Copy ⋮  │   ← .sens-high, masked
├─────────────────────────────────────────────────────────┤
│  + Add field            Paste more                       │
└─────────────────────────────────────────────────────────┘
```

Each field row carries its own `⋮` menu — rename label, change type, toggle mask, reorder,
delete field — the exact set `08_FIELD_MODEL.md §7` designs at the field-mechanics level and
this screen is the first place to render. **`Paste more`** will reopen the bulk box (§7) and
append its result to the existing fields; it will never replace them. Deleting one field (not
the whole entry) will be soft for 7 days like every other deletion in this product, and will be
recorded in the audit log as a field-level change naming no value — the same redaction discipline
`08_FIELD_MODEL.md §7` already states for the entry-level log, extended to a granularity that
does not exist yet.

Masked and unmasked rows render identically except for the `Reveal`/`Copy` controls §8 and §8.2
already specify per type — this screen adds no new reveal mechanism, only the first place all of
them appear together, on real saved data rather than a pre-save preview.

`entry.update`/`entry.rotate` back the single-value edit today (`08_FIELD_MODEL.md §7`, `built`);
the per-field `⋮` menu depends on `field.add`/`update`/`remove`/`reorder`
(`10_API_AND_MCP.md §4.3`), all `planned` — designed, indexed, dispatched nowhere. Editing will
require the vault unlocked, and the screen will say so rather than offering a control that would
fail (§7).

---

## 9. Nodes: add and remove — **`planned`**

`Settings → Nodes`, and the canvas context menu.

**Add node**
```
  Name          [ Linux                          ]
  Parent        [ ● Global   ○ under: acme ▾ ]
  Work folders  [ ~/projects/Linux   ]  + add another
                  agents launched here will scope to this node automatically
  ─ advanced (Pro) ─────────────────────────────────────────
  Sub-nodes see each other        [✓]      2FA on reveal   [✓]
  This node can read its children [ ]      Agent access    [ read-write ▾ ]
```
Depth-2 nodes cannot have children (the registry enforces the cap); the parent picker will simply
not offer them.

**Remove node — the seal flow.** Destructive-looking, non-destructive in fact — and, unlike the
grant dialog in §10, this one is not blocked on a missing gate: `node.seal` is a built, dispatched
op that re-authenticates through the platform keystore rather than through the unbuilt presence
attestation, so it already works end to end from the CLI or MCP today. Only the confirmation
screen below is missing.

```
  ⚠  Remove node "linux"?

  Nothing is deleted.

  · 12 entries and 3 stored 2FA items move to ORPHANED
  · their names stay visible; their values become unreadable to every
    agent and every automated path
  · only you, at this machine, with Touch ID and a fresh 2FA code,
    can open them again
  · 3 sub-nodes (dev, staging, prod) are sealed with it
  · 1 grant (linux → globex) is revoked
  · the node key is destroyed after the 7-day recovery window

  Type the node name to confirm:  [            ]
  [ Seal node ]                                   [ Cancel ]
```

Will require: typed name · global 2FA · biometric presence. For the first 7 days a single
**Restore node** in `Settings → Nodes → Recently sealed` will put everything back intact — a move
from the retained archive, not an unseal, so it will cost one confirmation rather than one
biometric prompt per item (`04 §5`). Restore will be available in **both** Pro and Lite.

**Moving a node to a different parent** will not be an ordinary edit. [Pass 2 · F-8] It will
change the node's ancestor set and therefore what it can read, exactly as a grant would. It will
carry the full grant gate — 2FA, presence, a mandatory reason — and the dialog will enumerate by
name which nodes become newly readable and which stop being readable (`06 §6a`). Unlike node
seal, `node.reparent` is one of the five ops that return `PresenceRequired` unconditionally today
(`crates/brokerd/src/ops.rs`), so — exactly like grant creation in §10 — this dialog's confirm
button will reach a real refusal until presence attestation exists, not merely an unbuilt screen.

**Orphaned view** — reached from the rail or the docked canvas node:

```
  ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
      ORPHANED · 7 items · sealed

      ⌗ vps-root              from linux      2026-08-04
      ⌗ deploy-key            from linux      2026-08-04
      ⌗ grafana-admin         from linux      2026-08-04
      …

      Values are sealed. Opening one needs Touch ID and a fresh
      2FA code, every time. No agent can read this node.

      [ Open an item… ]   [ Restore to a node… ]   [ Destroy… ]
  └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
```

The panel will be drawn in the sealed style — dashed, hatched, colourless — so it will read as
*outside* the vault's live surface. **Destroy** will be the only truly irreversible action in the
product: typed confirmation, 2FA, presence, and a 10-second cooling delay with a Cancel.

---

## 10. Grants (Pro) — **`planned`**, over a **`partial`** backend

Will be created by dragging node → node on the canvas, or `Settings → Grants → New`.

```
  GRANT ACCESS

  From   ○ X  (the node that gains access)
  To     ○ B  (the node being opened)

  Allow  [✓] list   [✓] read   [ ] reveal values   [ ] notes
  Expiry [ 30 days ▾ ]         ← "Never" shows a warning chip
  Reason [ X's deploy job needs B's registry token             ]   (required)

  This creates a dashed line on the graph. Anyone working in X will be
  able to see the ticked things in B until this expires or is revoked.

  [ 2FA code ______ ]        [ Create grant ]     [ Cancel ]
```

`Settings → Grants` will list every grant with from/to, scope, reason, expiry, last used, and a
one-click **Revoke**. Grants unused for 30 days will be flagged.

**Listing and revoking are already real at the broker level** — `grant.list` and `grant.revoke`
are built, tested ops (`03_DATA_MODEL.md §6`, `crates/brokerd/tests/grant_ops.rs`); only the
screen above them is missing. **`grant.create` is different, and the `[ Create grant ]` button
will not simply be unwired — it will reach a real, working refusal.** Creating a grant requires a
presence attestation (`Origin::Native` with `presence_attested: true`), and no transport in this
build constructs one: `presence_attested` is hardcoded `false` at every call site
(`crates/brokerd/src/ops.rs`), including every one of the Tauri bridge's commands — `grant_create`
among them since `ADR-062`. Until presence
attestation exists on some transport, this dialog is complete design sitting in front of an
honest, unconditional `PresenceRequired` denial — not a stub waiting on UI work.

---

## 11. Lock and unlock — **`planned`**, over a `partial` node-lock and approval backend

**Locked screen** — no vault contents, no node names, no counts. Vault name, a keyhole, and
the unlock control. (The graph will render while *locked* in-session; the *lock screen itself*
will show nothing, because it is what a thief sees.)

```
        ⬢
   credmgr is locked

   [  Unlock with Touch ID  ]
     use passphrase instead

   ── then ──
   2FA code   [ _ _ _ _ _ _ ]
```

Auto-lock: 15 min idle (configurable 1–120, or never-with-warning), on sleep, on screen lock,
on `⌘L`. Locking will be instant and visible: the header pill will flip to `locked`, every
revealed value will re-mask, the clipboard will clear.

**A node can already be locked on its own at the broker level**, while the vault stays open —
`vault.node_lock` / `vault.node_unlock` are built, dispatched ops, and the per-node idle timer
(`policy.lockAfterSeconds`) already sweeps and locks a node on its own clock, independently of
the vault (`06_ACCESS_GRAPH.md §1a`). Its keys leave the hot set; `list` and `read` keep working
from the manifest; `reveal` does not — that part is already true today, driven from the CLI or
MCP. **What is missing is only the UI surface**: the `Lock now` item in the node context menu, the
control that sets `lockAfterSeconds` in the first place, and the keyhole glyph (§3) that shows the
state. Intended for the wallet node: the vault will stay open all day for ordinary work, and the
node holding seed phrases will be shut whenever it is idle. [Pass 2 · F-7]

**Approval on demand.** [Pass 2 · F-15] **`partial`** — the broker half is built and tested
(`ops::reveal_via_approval`, the `vault.approval_decide` op) and already works over the CLI or MCP
today: an agent that asks for a value while the vault is locked does not fail and does not force
an unlock. **Nothing shows the operator the notification, because no native app exists**
(`07_TWO_FACTOR.md §5a`). Once built, the native app will raise a notification naming the
requesting folder and the entry; one Touch ID tap will release **that one value** and the vault
will stay locked. It times out in 120 s, defaulting to deny — already true today, at the broker
(`07 §5a`). There is no "agent session" that holds the vault open.

---

## 12. First run — **`planned`**

Five screens are planned, and the flow will not let a user skip the two that matter.

1. **Create vault** — name.
2. **Protect it** — Touch ID enrolment + a passphrase (**mandatory**, it is the only
   portable escrow).
3. **Recovery code** — will be shown once, must be confirmed transcribed. The flow will not
   continue otherwise.
4. **Two-factor** — enrol the global gate, confirm one code, receive 10 recovery codes.
   *Skippable*, with the consequence stated plainly, and a persistent Pro banner until done.
5. **Your first nodes** — will offer `global` (created automatically) and a node per detected
   folder under `~/projects/`, each pre-filled with its `workdirs`. **No V1 credential is
   offered here, or anywhere else in first run.** V2 ships empty and imports nothing from V1 —
   a deliberate decision, not an omission (`11_MIGRATION.md §1`). A user who wants one specific
   V1 value will carry it across by hand, outside onboarding, in two commands
   (`11_MIGRATION.md §6`). *(This step previously said "This is where V1 migration is offered" —
   an operation that does not exist and was never designed to; `11_MIGRATION.md §3.2` names that
   line as residue from a retracted design and asks this document's own rewrite to fix it, which
   this pass does.)*

Mode will default to **Lite**. Pro will be a deliberate choice, not a default the user has to
escape.

---

## 13. States that must be designed, not improvised — **`planned`**

Every view specifies four states. A missing empty state will be a bug.

| View | Empty | Loading | Error | Denied |
|---|---|---|---|---|
| Canvas | "No nodes yet — add one" + button | skeleton ring, no spinner | "Registry signature failed. The vault will not open until this is resolved." + Doctor | n/a |
| Inspector | "No entries in this node" + `+ New entry` | 3 skeleton rows | retry | n/a |
| Search | "Nothing matches" | inline | inline | results the user cannot see will be **omitted silently** — the human sees their own vault; machine denials are the API's concern (`06 §5`) |
| Orphan | "Nothing sealed" | — | — | the whole panel is a denial state by design |
| Entry detail | "No fields" + `+ Add field` | — | "This entry failed integrity check" + `--danger` | 2FA prompt inline, not a modal |

---

## 14. Accessibility — non-negotiable — **`planned`**

- **The canvas will not be the only way to do anything.** Every graph action will have a
  tree/menu equivalent, including creating grants. A canvas-only feature will be a bug.
- A hidden `<ul role="tree">` will mirror the graph for screen readers, kept in sync.
- Full keyboard operation: `Tab` order will be rail → canvas → inspector; arrow keys will
  traverse the graph along edges; every dialog will trap focus and restore it on close.
- Contrast will be ≥ 4.5:1 for text and ≥ 3:1 for meaningful strokes, in **both** themes. The
  greyscale test is normative: printed in black and white, no state may become ambiguous.
- `prefers-reduced-motion` will disable the force simulation's animation (one settle pass, no
  transition), all reveals, and all countdown animations — countdowns will become a number.
- Hit targets will be ≥ 26 px, ≥ 34 px on touch.
- Every icon-only control will have a label; the two-number hover card will be `aria-hidden` and
  its content will also be on the node's accessible name
  (`"linux, 12 entries, 3 two-factor items"`).

## 15. Responsive — **`planned`**

| Width | Layout |
|---|---|
| ≥ 1180 px | three panes as drawn |
| 820–1180 | rail collapses to an overlay sheet; canvas + inspector |
| < 820 | single pane; canvas full-bleed, inspector slides over from the right; rail via a menu |

The graph will be usable at 820 px (fit-to-view on resize, larger hit radii). Below that, the
tree view will become the default and the graph will be opt-in — a force graph on a phone is a
toy.

---

## 16. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `08_FIELD_MODEL.md §2, §3, §5, §6` | the add-field control, the bulk grammar, the preview contract and type inference that §7 and §8 build the surrounding flow around, without re-specifying it |
| depends on | `04_CRYPTO_AND_KEYS.md §3` | the asymmetric node keys that let §7 accept a new entry while the vault is locked |
| depends on | `04_CRYPTO_AND_KEYS.md §5` | the seal/restore mechanics behind §9's remove-node and orphan-restore flows |
| depends on | `06_ACCESS_GRAPH.md §1a` | the built `vault.node_lock` that §11 designs a UI surface for |
| depends on | `06_ACCESS_GRAPH.md §5` | the rule that a denied search result is omitted silently, which §6 and §13 apply to the UI |
| depends on | `06_ACCESS_GRAPH.md §6a` | the scope-widening gate that §9's "moving a node" flow carries in full, and the reason its confirm button reaches a real refusal today |
| depends on | `07_TWO_FACTOR.md §5a` | the built approval-on-demand broker half that §11 designs the missing notification for |
| depends on | `07_TWO_FACTOR.md §6` | the seed/code split that §8.1's TOTP-field treatment is built around |
| depends on | `11_MIGRATION.md §1, §6` | the no-import decision and the two-command manual carry path that §12's first-run flow now states accurately, replacing the retracted "V1 migration is offered" residue this document used to carry |
| depends on | `19_FRONTEND_DELIVERY_SCOPE.md` | the accurate build status this document's own status callout and every `planned`/`partial` lead cite, and the sibling contract that specifies *how much* must ship rather than *how it looks* |
| depends on | `design/graph-engine/VAULT_GRAPH_SPEC.md` | the canvas rendering contract §2 points to rather than restates |
| depends on | `design/tokens/keep.tokens.json` | the KEEP design system values every screen in this document is specified against |
| feeds | `01_CONCEPT.md §6` | the Operations-panel redesign (§6.2) that replaced V1's 16-command search palette |
| feeds | `02_ARCHITECTURE.md §2.4` | the shell's visible lock state (§2, §11) that auto-lock is checked against |
| feeds | `06_ACCESS_GRAPH.md §10.6` | the grant dialog's required inputs (§10) and the revoke affordance (§6) the finished access graph will render against |
| feeds | `12_BUILD_PLAN.md §4, §5.1` | the Phase 6 and Phase 9 exit-gate checklists, which cite this document's hover card (§4), states (§13) and accessibility (§14) directly |
| feeds | `13_TEST_PLAN.md §7` | every UI test this document's rules will be asserted by — the hover card, the inspector's node scoping, the reveal timers, reduced-motion |
| feeds | `16_CROSS_PLATFORM.md §3` | the honesty rule §3 states — "no Security panel" because no screen reads a tier, never "because there is no application": the Tauri app, its 53-op bridge (`ADR-057`, `ADR-062`) and the hosted design (`ADR-075`) are real |
| feeds | `18_ENDPOINT_INDEX.md §5` | the UI route table this document's screens correspond to |
| feeds | `19_FRONTEND_DELIVERY_SCOPE.md §3.3, §5, §6, §7` | the route list, the state/theming/accessibility acceptance gates, and the op-family table that names this document's own sections as the screens driving each remaining broker operation |
| feeds | `22_ORG_VAULT_SYNC_AND_LICENSING.md §2` | the Pro/Lite table (§5) cited there as the actual node-hierarchy and grant view/revoke behaviour |

## 17. Source

**Design.** `01_CONCEPT.md §5–§6` (the decisions this posture and the Operations-panel redesign
follow from); `ADR-032` (naming, referenced via `11_MIGRATION.md §4`); `ADR-042` (approval on
demand, §11); `ADR-057` (the Tauri bridge's scope and token custody, cited throughout as the
reason each screen is `planned` rather than merely unstyled); `ADR-058` (this document's own
header contract); `ADR-059` (the status vocabulary every heading and inline note here applies);
Pass 2 findings F-1, F-7, F-8, F-13, F-15, F-18, cited inline where each changed the design.

**Code — what is built, cited per claim made above.** `v2/apps/desktop/src/vault/` (the model and the actions: every screen reads and writes through the broker) and
`v2/apps/desktop/src/design/` (the hosted design, its screens in `screens/*.html` and their logic in
`logic/*.js` — `apps/desktop/README.md`; `RELEASE_VERIFICATION.md` maps every control). `entry.create`,
`vault.pending_list`, `vault.pending_accept`, `vault.pending_discard` (§7's locked-add and
pending-tray claims); `totp.code`, `totp.seed` (§8.1); `vault.node_lock`, `vault.node_unlock`
(§11's node-lock claim); `ops::reveal_via_approval`, `vault.approval_decide` (§11's
approval-on-demand claim); `node.seal`, `node.reparent` (§9 — the seal/reparent contrast);
`grant.list`, `grant.revoke`, `grant.create` (§10) — all in `crates/brokerd/src/ops.rs`. The five
ops that return `PresenceRequired` unconditionally today — `audit.get`, `totp.seed`,
`node.reparent`, `grant.create`, `maintenance.doctor --rebuild-registry` — and the fact that
`presence_attested` is hardcoded `false` at every call site on every transport, including the
Tauri bridge's built commands, are the reason §9's reparent dialog and §10's grant dialog are
described as reaching a real refusal rather than an unbuilt screen. `graph.snapshot`'s `counts`
and `gate.twofa` fields (§3, §4) and the 53 built Tauri commands (status callout) are
`apps/desktop/src-tauri/src/commands.rs` and `crates/brokerd/src/ops.rs`, both re-read in this
pass.

**Design assets.** `design/tokens/keep.tokens.json`, `keep.css`, `keep-components.css`;
`design/graph-engine/VAULT_GRAPH_SPEC.md` and the vendored, sha384-pinned `force-graph@1` engine —
all confirmed present on disk in this pass.

**Tests.** `cargo test --workspace -- --list`: 813 tests in 50 test binaries (2026-10-03); the last full run recorded: 571 passing, 0 failing, 41 test binaries, exit 0 (2026-10-02; earlier: 448 passing, 37 test binaries on 2026-09-24, re-measured 2026-10-01; 406 passing, 35 test binaries on 2026-09-13, run
`34743281942`; 397 passing, 33 test binaries, verified 2026-08-18) — the broker-side evidence for every "built" claim above. `apps/desktop/src-tauri`:
40 passing, 0 failing on 2026-08-18; 65 passing, 0 failing on 2026-09-24, after `ADR-062`
(`19_FRONTEND_DELIVERY_SCOPE.md §12`); 186 tests listed in 12 test executables on 2026-10-03 — not part of the
workspace count (`ADR-035`). The front end itself (`apps/desktop`): 550 unit tests pass (21 files, vitest,
2026-10-03); the end-to-end specs list 552 tests (276 specs × WebKit and Chromium) and the real-broker suite 66.

**Verification.** `python3 -m tools.docgen.cli build v2/docs/09_UI_UX_SPEC.md --formats
html,json`. `python3 -m tools.corpus_check crossrefs` proves every `NN_NAME.md §S` reference
above resolves.
