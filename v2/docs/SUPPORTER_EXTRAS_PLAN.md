<!-- artifact-hardened: not applicable — front-end team record imported from the design project 2026-10-18; not a backend source-of-truth artifact, not hardened here -->
# Supporter extras and the milestone ask — plan for batch B14 / B15

**Written 2026-10-18** (planning session). Build sessions follow this file; where it is silent, the rules in `CLAUDE.md` win.
Read with: `CLAUDE.md` Rules, `DECISIONS_REGISTER.md` #3 #4 #6 #20, `LEGAL_REGISTER.md` L4 L5, `GAMES.md`, `ACCESSIBILITY.md`.

## 0. What exists today (audited 2026-10-18)
- Settings → Appearance → **S12a Supporter extras**: app mark (keep, cells, node, seal), node glyph weight (classic, fine,
  heavy), double halo, supporter ring. Stored in `credmgr_cosmetics`; gate `cosmOn()` = `credmgr_donate_unlocked` or session
  preview; `cosmEff()` returns defaults when off; `setCosm()` refuses writes when off.
- **S18a Donate toast**: shown 6 s after every unlock until a code is entered. Three views: main, donate in 3 steps, enter code.
- Code: one shared honour-system code the old public code (retired 2026-10-24) (owner, 2026-10-18). Public in the source by design.
- So: 4 extras exist. None of them changes the graph's shape or colour, and the toast asks on every session, which is the
  "pressure" the owner wants gone.

## 1. Principles (binding for every item below)
1. **Cosmetic only.** No extra changes what the app can do, how fast, how safely, or how much. Themes, colour tint, high
   contrast, greyscale proof, reduced motion, tree view, shortcuts and every op stay free forever.
2. **The free default is the designed product.** Each extra is a variation on a complete default, never a "fixed" version of
   a weakened one. Nothing currently free is moved behind the code.
3. **Seen, not dangled.** Locked extras are visible in one place only (S12a), with a "try this session" preview. No locked
   badge, teaser or upsell anywhere else: not on the graph, the header, dialogs, the Manual's main text, or the toast.
4. **Security surfaces stay sober.** Extras never appear on: entry detail, reveal, field dialog, grants, presence prompts,
   recovery, destroy, backups, Operations, agent / MCP screens. Lock screen gets the mark only.
5. **Accessibility wins.** High-contrast mode and greyscale proof force every graph extra back to its default while on.
   Reduced motion disables every animated extra. Every colour option keeps ≥ 3:1 against the canvas (WCAG 1.4.11) and never
   becomes the only carrier of meaning (orphan dash, sub-node thin ring, grant dash, 2FA tick and lock square all stay).
6. **KEEP tokens only.** Colours come from `--bone --ash --mute --sig --sig-hi --hair-strong` and the existing `entryColor`
   oklch formula (already documented). `--warn` and `--danger` are never offered: they mean 2FA and danger in this app.
7. **Do-not-touch list holds.** Graph physics, `nodeR`, ring spacing, collision, hit testing, `credmgr_gposV`, CredPong
   balance are unchanged. Every node shape fits **inside** the node's circle of radius `r` (all points ≤ r), so nothing that
   reads `r` changes.
8. **Global choices only.** No per-node shape or colour: that would store node ids in local storage (names leak to disk,
   conflicts with `privateNames`, D-9) or need a vault field the broker does not have. Deferred, see §9.
9. **Words.** In the product the people are "supporters" and the things are "extras". Never "paid", "premium", "pro tier",
   "unlock more", a price, a plan, a trial or a countdown.

## 2. The ask: when and how often (replaces "6 s after every unlock")

### Decision
The toast appears only at **entry milestones**, at most **three times in the life of the install**, and only after real use.

| Ask | Entries in the vault | And days in use | Shown |
|---|---|---|---|
| M1 | ≥ 50 | ≥ 14 | once, 6 s after the first unlock where both hold |
| M2 | ≥ 150 | ≥ 45 | once |
| M3 | ≥ 300 | ≥ 90 | once, then never again |

- **Entries** = sum of live entries over all nodes (the counts the graph already reads; no sealed, pending or trashed
  entries; no new op). **Days in use** = distinct local calendar days with at least one successful unlock.
- Never shown: before both thresholds hold, while the vault is locked, in Games, during first run, with a dialog open, after a
  supporter code, after "don't remind me", or twice in one day.
- If the user jumps past two milestones at once (bulk import), only the highest pending one shows; the lower ones are marked
  passed silently. Lifetime maximum stays three.
- About → Donate and S12a "Enter code" stay available at all times; they are not asks.

### Why these numbers
- **Entries carry the value.** A credential manager earns its keep by what is in it. 50 entries is roughly four or five
  real projects with their API keys, database URLs and tokens: the point where losing CredMgr would hurt. The owner's own
  vault (185) passes M1 and M2; the demo vault (about 140) passes M1 only, which is what a demo should show.
- **Days stop the import burst.** Most entries arrive in the first sessions (paste-in, `.env` import). Without the day floor,
  an import on day one would trigger the ask before any habit exists. 14 distinct days is about three working weeks of daily
  use; 45 and 90 put M2 and M3 one and three months later.
- **Three asks, spaced, then silence.** One ask is easy to miss; asking every session is the pressure the owner rejected.
  M3 at 300 entries reaches only heavy users, who are the most likely supporters.

### Toast content at a milestone
The existing S18a copy stays verbatim. One line is added above it, in `t-mono-label`: `50 entries` / `150 entries` /
`300 entries` (the milestone number, not the live count). One link is added at the bottom: **don't remind me** (sets the
opt-out; the toast closes with "Okay — About → Donate is always there."). ✕ dismisses this milestone only.

### Storage
`credmgr_usage` = `{"v":1,"days":17,"last":"2026-10-30","asked":["m1"],"optout":false}`. Calendar day only, no time, no
counts of entries, no names. Listed in About → Privacy and `v2/PRIVACY.md`. Dev handle: `__cm.usageSet({days,entries})` to
drive the gate.

### Price
No number appears in the app, ever (rule; `LEGAL_REGISTER.md` L5: no minimum, code to anyone who asks). If the owner wants a
suggested amount, it goes in `v2/DONATE.md` only, worded "suggested, not required". Recommended there: none, or "the price of
a coffee". Owner decision **O2**.

## 3. Ship bundled or download later — decision: **bundled and sealed, opened locally by the code**
**Owner amendment 2026-10-18 (built):** the extras ship inside the app from the first download, encrypted. The code is not in the source. Entering it derives an AES-GCM key (PBKDF2-SHA-256, 200 000 rounds), decrypts the pack once, and stores the key as `credmgr_extras_key`, so later launches open the pack without the code. The pack is data only (shape geometry, colour and backdrop tables), never code, so no `eval`. Wrong code: decryption fails, nothing is stored. The old session "Try" preview is dropped, since nothing can be shown without the pack. Legacy flag-only installs re-enter the code once. Cosmetic gating only: the MIT source is public.
| | Bundled, code unlocks (chosen) | Separate download after payment |
|---|---|---|
| Network | none (rule: zero network at runtime) | needs a fetch and a host |
| Payment proof | honour code, no server | needs a licence server, accounts or e-mail matching: PII, declined in #6 |
| Security | reviewed once with the app | a downloaded pack parsed inside a credential manager is new attack surface; needs signing |
| Open source | the MIT code is public either way; bundling is honest about it | a "locked" download is still buildable from source |
| Size | small: code paths plus six icon sets (~0.3 MB) | — |
| Updates | new extras arrive with normal app updates | two release trains |

So "add-on pack 2" means a normal app update that adds more extras behind the same code. No second download exists.

## 4. Catalogue — 12 extras (4 existing, 8 new)
Grouped in S12a under four headings. Each row: default (free, unchanged) → supporter options. Numbers are option counts
including the default.

### Graph
**X1 Node shape — NEW (5).** Circle (default) · hexagon · rounded square · octagon · diamond. Applies to project and
sub-node bodies in the graph, CredPong nodes and the tree view's node bullet. Global stays filled and orphan stays dashed, in
the chosen shape. Geometry: circumradius = `r` for hexagon / octagon / diamond; rounded square half-side 0.72 r, corner
radius 0.22 r (farthest point ≤ r). Stroke widths unchanged; inner glyph unchanged (`r*0.42` fits every shape). Hit test and
collision stay circular. Selection halo stays circular (it is a ring around the node, not its outline).

**X2 Global node colour — NEW (4).** Bone (default) · signal (`--sig-hi` dark / `--sig` light) · ash · tint
(`oklch(0.80 0.06 H)` dark / `oklch(0.45 0.07 H)` light, H = the colour-tint hue, or 211 when tint is off). The lock square
on global keeps `--void`. Must keep ≥ 3:1 against `--void`/`--night`.

**X3 Link colour — NEW (4).** Structural links: default (`--hair-strong`) · ash · bone at 0.5 alpha · signal at 0.7. Grant
links keep their own colour and dash pattern (the dash is the meaning). Dimming of non-selected links unchanged.

**X4 Entry dot palette — NEW (4).** Spectrum (default, current hash over 360°) · cool (hash mapped into 160–260°) · warm
(20–80°) · mono (ash). Same lightness and chroma as `entryColor`; only the hue range changes. Mono keeps dots readable in
greyscale proof (which already forces default).

**X5 Graph backdrop — NEW (4).** Plain (default) · dot grid · line grid · rings (circles around global at the existing ring
spacing). Drawn in `--hair` under everything, moves with pan and zoom, skipped at zoom < 0.4 for speed.

**X6 Glyph weight — EXISTING (3).** Classic · fine · heavy. Unchanged.

**X7 Double halo — EXISTING (on/off).** Unchanged; off under reduced motion.

### Identity
**X8 App mark — EXISTING (4).** Keep · cells · node · seal, in header, lock screen and About. Unchanged.

**X9 App icon — NEW (6).** The OS dock / taskbar / window icon. Keep on void (default) · keep on bone (inverted) · cells ·
node · seal · keep on signal. Drawn from the KEEP Identity marks; S12a shows 48 px tile previews in dark and light. Needs a
broker/shell op (`app.icon.set`, per-OS: Windows and Linux window icon at runtime; macOS dock icon needs native code). Until
the app team builds it the control works in preview only and carries `not in beta.1` with the op name in its title. The app
team produces the raster sets (1024 px PNG, ICNS, ICO) from our SVGs.

**X10 Header badge — EXISTING, extended (3).** None (default) · ring (existing supporter ring) · milestone stamp (the highest
milestone reached, e.g. `150`, in `t-mono-label` with a hairline box). Replaces the "Supporter ring" toggle with a 3-way pick.

### Motion
**X11 Unlock flourish — NEW (on/off).** On successful unlock the app mark's three parts draw in sequence (outer, inner,
core; 480 ms total, `--ease` from KEEP) on the lock screen before the app shows. Off under reduced motion; never delays
unlock input (the app is usable the moment unlock succeeds; the flourish overlays and fades).

### Games
**X12 CredPong trail — NEW (3).** None (default) · fine trail (6 fading ball positions) · comet (12, tapering). Drawn in
`palette.bone`; game balance, speeds and hit boxes untouched. Hosted games may read the choice later through `api` (add
`api.style.trail`, read-only) — note in `GAMES.md`.

### Considered and dropped
- Extra themes or accent colours: themes and tint are free and stay free (principle 1).
- Per-node shapes or colours: needs node ids on disk or a vault field (principle 8).
- Sounds: the app has none; adding audio for supporters only would be a new modality.
- Custom fonts: KEEP type only.
- Animated entry dots / particles: busy, costs frames on big vaults, fights the "near-static crawl" spec.
- Donor list, points, leaderboards: declined in #6 (server + PII).

### How many: 12, shipped in two waves
- **Wave 1 — B14:** the ask (§2), X1, X2, X3, X9 (design + preview), X10, S12a regrouped. These are the visible, eye-catching
  ones the owner asked for by name.
- **Wave 2 — B15:** X4, X5, X11, X12, Milestones panel (§5).
More than 12 makes S12a a shop; fewer leaves the graph, which is the app's face, with only weight and halo.

## 5. Milestones panel — free for everyone (proposed, owner decision O3)
Gamification that does not pressure: Settings → Appearance (or About) gets a short **Milestones** list, free, no ask inside:
first project · 10 / 50 / 150 / 300 entries · 5 projects · first grant · 30 / 90 days in use. Each shows a tick and the day it
was reached (`credmgr_usage.marks`, day only). The only supporter link is X10's "milestone stamp" option. If the owner says
no, X10 drops to two options and §2 is unchanged.

## 6. S12a layout after the change
Headings **Graph · Identity · Motion · Games**, each row: label, one-line caption, option picker (swatch / shape tiles / 2–4
segmented buttons). Top of the panel: the existing title and caption verbatim, then one line: "Try them for this session —
they reset when the vault locks." with a **Try** button (sets `cosmPreview`; preview ends on lock, as today). When locked,
pickers render at full contrast with the default selected and are disabled (`aria-disabled`, not greyed text below 4.5:1).
A small live preview canvas (240 × 140, three nodes, one link, global) at the top shows the current shape, colours and
backdrop, so a choice is visible without leaving Settings.

## 7. Storage schema
`credmgr_cosmetics` v2:
`{"v":2,"mark":"keep","glyph":"classic","halo":false,"badge":"none","shape":"circle","global":"bone","link":"default",`
`"dots":"spectrum","backdrop":"plain","icon":"keep","flourish":false,"trail":"none"}`
- Allow-list every field (pattern of `loadCosmetics`). Unknown → default.
- Migrate v1: `ring:true` → `badge:"ring"`; other v1 fields kept.
- `cosmEff()` returns all defaults when off, and graph fields default while `contrastMode==='high'` or greyscale proof is on;
  motion fields default under reduced motion.

## 8. Tasks
Status: OPEN unless stated. IDs go into `VERIFIED.md` when built. "Gate" = add an assertion to `audit-suite.js`.

### B14 — wave 1
| ID | Task | Done when |
|---|---|---|
| B14-0 | Owner answers O1–O6 (§10) or accepts the defaults | answers in `DECISIONS_REGISTER.md` |
| B14-1 | ADRs: milestone ask (amends #3), extras catalogue (amends #4), bundled delivery; amend `CLAUDE.md` rule "one dismissible toast" → "one dismissible toast, shown at most three times, at entry milestones" | registers updated |
| B14-2 | `credmgr_usage`: day counting on successful unlock, `asked`, `optout`; `__cm.usageSet` dev handle | gate: days increments once per day; no time stored |
| B14-3 | Replace the 6 s-every-unlock timer with the milestone rule (§2), highest-pending logic, never-shown list | gate: no toast at 49 entries / 30 days; none at 60 / 13; shows at 50 / 14 once; not again same day; never after code; never after opt-out; never in Games, first run, locked, dialog open |
| B14-4 | Toast: milestone label line, "don't remind me" link and its closing line; ✕ = this milestone only | gate: label text matches milestone; opt-out persists; 2.4.11 focus-yield still passes |
| B14-5 | Schema v2 + migration + allow-lists + HC/greyscale/reduced-motion overrides in `cosmEff()` | gate: v1 object migrates; junk values fall back; HC forces graph defaults |
| B14-6 | X1 node shapes in `paintNode` (graph), CredPong node draw, tree bullet; orphan dashed + global filled in every shape | gate: pixel sample inside r only (no stroke pixels beyond r+lineWidth); hit test unchanged; tree bullet shape matches |
| B14-7 | X2 global colour | gate: contrast ≥ 3:1 per option per theme (sample pixels) |
| B14-8 | X3 link colour, structural only | gate: grant link colour and dash unchanged in every option |
| B14-9 | X9 icon picker: 6 SVG tiles in dark/light, preview-only, `not in beta.1` badge naming `app.icon.set` | gate: badge present and names the op; selection persists |
| B14-10 | X10 header badge 3-way (none / ring / stamp); stamp shows highest milestone | gate: stamp hidden when no milestone |
| B14-11 | S12a regroup (Graph · Identity · Motion · Games), Try button copy, live preview canvas, disabled-state contrast | gate: every picker has a name (4.1.2), targets ≥ 24 px (2.5.8), 320 px reflow |
| B14-12 | About → Privacy lists `credmgr_usage`; cosmetics line lists the new fields | gate `domHas` |
| B14-13 | Copy sweep: no price, currency sign, "premium", "paid", "upgrade", "trial", "unlock more" in rendered text (exclude the existing lite/pro switch, see O5) | gate: grep rendered text and attributes |
| B14-14 | Manual: "reading the graph" stays true with shapes ("filled — global; ring — project…" without "circle"); new Extras section; retake affected figures | figures viewed before insert |
| B14-15 | `SCREENS.md` (S12a, S18a variants), `ACCESSIBILITY.md` rows, `FRONTEND_THREAT_MODEL.md` (new storage key), Component Sheet matrix, Index | files updated |
| B14-16 | `REPO_UPDATES.md`: `v2/DONATE.md` (milestone policy, no-nag wording, optional suggested amount per O2), `v2/PRIVACY.md` (`credmgr_usage`), `PROVENANCE.md`; app-team ask for `app.icon.set` + raster icon sets | listed for owner and app team |
| B14-17 | Gate in four themes, width sweep, `ready_for_verification`, `VERIFIED.md` | all green |

### B15 — wave 2
| ID | Task | Done when |
|---|---|---|
| B15-1 | X4 entry dot palette (hue range only) | gate: lightness/chroma identical to default |
| B15-2 | X5 backdrop, skipped below zoom 0.4 | gate: frame time not worse than +10 % on demo vault |
| B15-3 | X11 unlock flourish, never delays input | gate: input usable immediately; off under reduced motion |
| B15-4 | X12 CredPong trail; `GAMES.md` adds read-only `api.style.trail` | gate: CredPong speeds and hit boxes unchanged |
| B15-5 | Milestones panel (if O3 = yes), `credmgr_usage.marks` | gate: marks store day only |
| B15-6 | Docs, Manual, gate, verification, `VERIFIED.md` as B14-14…17 | all green |

### Elsewhere (not this project)
- App team: `app.icon.set` per OS; raster icon sets from our SVGs; merge both waves.
- Owner: `v2/DONATE.md`, `v2/PRIVACY.md`, `PROVENANCE.md` edits (still outstanding from B12a as well).

## 9. Deferred
Per-node shape / colour (needs a vault `node.style` field and `privateNames` settled). Extras in the CLI (`credmgr` output
colour) — no request yet.

## 10. Owner decisions — defaults apply if not answered
- **O1** Toast at three milestones (50/14, 150/45, 300/90) instead of every unlock. Default: yes.
- **O2** Suggested amount: none in the app (fixed by rule); optional line in `DONATE.md`. Default: no amount anywhere.
- **O3** Free Milestones panel (§5). Default: yes, in B15.
- **O4** App icon ships as preview-only with `not in beta.1` until the app team builds `app.icon.set`. Default: yes.
- **O5** The lite / pro switch: "pro" can read as a paid tier next to supporter extras. Default: keep it, note the risk; a
  rename to lite / full is one label.
- **O6** "don't remind me" opt-out in the toast. Default: yes.

## 11. Notes for the build session
- Start at `cosmOn` / `cosmEff` / `setCosm` / `loadCosmetics` (≈ line 2234), `paintNode` (≈ 1580), link painter (≈ 1621),
  `entryColor` (1553), `_donateTimer` (1323), S12a template (≈ 979), S18a (≈ 582), CredPong node draw (≈ 1988).
- Follow `CLAUDE.md` tooling notes: dev handle, MessageChannel timers, graph resize before captures, no template edits during
  a gate run.
- Keep the existing S12a and S18a copy verbatim; add only the lines specified here.


## 12. Built 2026-10-18 (B14 + B15, one pass)
Sealed pack; milestone ask M1–M3 with `credmgr_usage` and opt-out; X1 node shape (graph, worktree bullet, CredPong), X2, X3, X4, X5; X8 mark; X9 app icon picker (preview only, `not in beta.1`, names `app.icon.set`); X10 header badge (none, ring, stamp); X11 unlock flourish; X12 CredPong trail (standard, comet, dotted); free Milestones panel (S12b); S12a regrouped (Graph, Identity, Motion, Games) with a live preview canvas.
Dev handles: `__cm.usageSet({days,entries,reset})`, `__cm.packLoad(code)`.
**Changed from the plan:** the "try this session" preview is gone (nothing to show without the pack); the trail's default stays today's free trail, with comet and dotted as extras; the app icon tile shows the current theme only; `api.style.trail` for hosted games is not added (see `GAMES.md`).
**Not built, by decision:** an Undo for removed fields. The page never holds a field's value, so an undo needs a broker op; it is listed for the backend in `AUDIT_2026-10-18.md`.
