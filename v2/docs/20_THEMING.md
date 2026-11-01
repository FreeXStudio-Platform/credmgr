---
id: V2-020
classification: public
title: Theming
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-19
---

<!-- artifact-hardened: NEEDS RE-HARDENING — corrected 2026-08-18 (Session 21, after the same
     false freeze that withheld `17_AIRLOCK_AND_LLM.md` was lifted from this document too). The
     previous stamp (`Approved With Known Risks @ d15a5c7`, "reconciled" 2026-08-10 without the
     body being re-read) attested to a document that carried zero `built`/`partial`/`planned`
     markers anywhere across its six sections, describing a two-axis theme-and-colour system, an
     OKLCH derivation, a hue picker, a runtime contrast-repair guarantee and a persisted config
     field — all in the present tense, as though shipped. Almost none of it is built: the one
     part that exists is the static token pair for the two colour-off corners
     (`design/tokens/keep.tokens.json`, `design/tokens/keep.css`), and nothing consumes it.
     `19_FRONTEND_DELIVERY_SCOPE.md §2` already said this precisely — "built as a specification,
     planned as an implementation" — while this document itself said neither. This document was
     withheld from the 2026-08-18 corpus rewrite on the belief that an external front-end team
     was building from a byte-identical copy of it. That belief was false (`PROJECT_MAP.md §6`,
     `HANDOVER_STATE.md`, `ee59696`); nobody was desynchronised by leaving it stale, and nobody
     is now. A citation to `09_UI_UX_SPEC.md §1` for a "two-theme model" has been removed: that
     section is Product posture, not a theme model, and never described one. Hardening this
     stamp past NEEDS RE-HARDENING is the operator's review to make, not this session's to
     award.

     Round-2 verification backlog closed 2026-08-19: three findings, each re-derived from live
     source before the fix. (1) The claim "a switch exists in neither system" was wrong —
     `tools/docgen`'s renderer ships real toggle code (`components.py` `theme_toggle()`) on every
     document build, this one included; corrected, and a second, closer look found the toggle does
     not actually work (`generator.py:260` hardcodes `<body data-theme="dark">`, which wins over
     whatever the toggle sets on `<html>` — confirmed by loading this document's own built HTML and
     clicking it). (2) The `--void` table row's Light L (0.99) was contradicted by the checked-in
     hex (`#0B0C0E`, OKLCH L ≈ 0.15, byte-identical to `--bone` light) — a copy-paste bug in
     `design/tokens/keep.css` and `keep.tokens.json`, fixed the same day to `#FCFCFD`
     (OKLCH L ≈ 0.9913). (3) The
     `13_TEST_PLAN.md §7` citation claimed a "contrast-pair" test was listed as future work; the
     word "contrast" does not occur in that document at all — only the greyscale walk is planned
     there, corrected in both the body and the Connections table. Updated 2026-09-24 for
     ADR-062 (the bridge's command count). Updated 2026-09-24 for ADR-071…073 (the bridge's
     command count, 47). -->
# Theming — dark, light, and colour

`CredMgr V2` · Pass 3 · `2026-08-05`
Extends `design/tokens/keep.tokens.json`. Replaces the single dark/light toggle this system
started from with the two independent axes below.

---

> **Status.** This subsystem is **`partial`** (re-measured 2026-10-03). The static token values for the
> two colour-off themes are checked in (§2). Since ADR-075 the desktop app also has a runtime theme
> switch (`applyTheme` in `apps/desktop/src/design/logic/core.js` sets `data-theme`), a colour axis
> with a hue and an intensity that tint the grounds in OKLCH (chroma stays under 0.012), and greyscale,
> contrast and motion settings, all remembered in the window's local storage (`credmgr_prefs`, below).
> Still **`planned`**: a contrast-repair function (none exists in `apps/desktop/src/`), the per-hue
> token derivation and the greyscale screenshot pass of this document's target design, and a config
> field in the vault to persist any of it (`crates/store` has none). Every section below leads with a
> status word and cites what was actually checked, not what seems plausible.

---

## 1. Two independent axes, not three themes — **`planned`**

Pass 1 had one switch (dark / light). The brief asks for something more precise: a
black-and-white system where the two themes are a genuine **inversion**, *plus* an optional
colour layer that must never make text harder to read.

That is two orthogonal axes:

```
                       COLOUR  ──────────────────────────►
                     off (pure B/W)              on (tinted)
                ┌────────────────────┬────────────────────────┐
        dark    │   ██ Vault Dark    │   ▓▓ Vault Dark + hue  │
  THEME         │   near-black       │   near-black, tinted   │
        ────────┼────────────────────┼────────────────────────┤
        light   │   ░░ Vault Light   │   ▒▒ Vault Light + hue │
                │   paper white      │   paper white, tinted  │
                └────────────────────┴────────────────────────┘
```

`theme: 'dark' | 'light' | 'system'` × `colour: 'off' | <hue> | 'auto'` = four rendered
states, one token system. Default: **dark, colour off** — the vault will stay monochrome until
a user decides otherwise.

**The settings are wired, to the window's local storage and not to the vault.** No code in `v2/crates/**` reads a
`theme` or `colour` setting. The desktop app (`apps/desktop/src/vault/prefs.ts`, `ADR-075`) loads `keep.css` — generated
from the KEEP tokens — and remembers the Appearance settings (theme, colour, hue, intensity, greyscale, contrast, motion)
in one local-storage record, `credmgr_prefs` (`PRIVACY.md §2.1` lists the keys). The operating system's colour scheme,
contrast and reduced-motion settings are followed until a choice is made, and a choice wins afterwards
(`apps/desktop/tests/e2e/wp-d-prefs.spec.ts`); a webview that refuses storage still runs, and the setting applies for
the session. A theme is a local preference, not a broker op, so none of the broker's 53 operations carries one
(`theme get/set`, named in `02_ARCHITECTURE.md §6.2`, is not among the commands the Tauri bridge has).
What is not built is the rest of this document's target design — the per-hue tokens, the greyscale screenshot pass of
`13_TEST_PLAN.md §7` — stated in full below.

<!-- figure:theme-colour-axis-matrix -->
*Theme and colour are two independent settings, not three themes — every one of the four
combinations is legal, and only colour is optional. Only the two colour-off corners have any
real, checked-in value today.*

---

## 2. Dark ⇄ light is a real inversion — **`partial`**

The brief: *"the dark and light should be just a change of black to white, or vice versa."*
Taken literally that produces unreadable results (pure `#fff` on `#000` inverted gives
eye-searing white), so KEEP inverts **perceptually**, in OKLCH, preserving the *relationships*
rather than the raw values.

Each ground/ink token is defined once as an **OKLCH lightness anchor**. The light theme is the
same anchor reflected about L = 0.5, then nudged to the paper values already in `keep.css`.
That reflection is the method that produced the values below — a one-time design derivation
that already ran, not a runtime computation; nothing in this repository re-runs it for a value
that isn't already in the table.

| Token | Role | Dark L | Light L | Relationship preserved |
|---|---|---|---|---|
| `--void` | absolute floor | 0.00 | 0.99 | the extreme |
| `--night` | body | 0.04 | 0.98 | +0.04 from the floor |
| `--steel` | cards, rails | 0.09 | 0.95 | +0.05 |
| `--steel-2` | hover | 0.13 | 0.93 | +0.04 |
| `--steel-3` | pressed/selected | 0.17 | 0.90 | +0.04 |
| `--faint` | hairline | 0.24 | 0.85 | the first visible step |
| `--mute` | mono labels | 0.55 | 0.45 | crosses the midpoint |
| `--ash` | secondary text | 0.66 | 0.36 | |
| `--bone` | primary text | 0.93 | 0.06 | the opposite extreme |

**What exists.** Every value in that table is checked in twice — as the OKLCH-derived hex in
`design/tokens/keep.tokens.json`'s `grounds_dark`/`grounds_light`/`inks_dark`/`inks_light`
tables, and as a complete CSS custom-property implementation in `design/tokens/keep.css`:
`[data-theme="dark"]` at line 15, `[data-theme="light"]` at line 40, the universal focus ring at
line 131, the sealed-hatch pattern (`.is-sealed`) at line 188, and the sensitivity ladder
(`.sens-critical` etc.) at line 200 — all built on top of the same two token sets, plus a
`@media print` block that treats the light theme as the print theme.

**One row of that table used to not match what was checked in — fixed 2026-08-19.** The
light-theme `--void` in both files had been `#0B0C0E` (OKLCH lightness ≈ 0.15), byte-identical
to `--bone`'s own light-theme value (the primary-text ink the design intends to sit at the
*opposite* extreme) instead of the near-white 0.99 "paper floor" this table claims — a
copy-paste bug, not noise, since every other row above inverts to within roughly 0.02–0.09 of
its claimed lightness. Corrected in both `keep.css:41` and `keep.tokens.json`'s
`grounds_light.void` to `#FCFCFD` (OKLCH L ≈ 0.9913), consistent with the table and with the
cool-neutral hue the rest of the light `grounds_*` ramp uses.

**A working theme switch exists in one of the two systems, not both.** `apps/desktop/**` never
sets `data-theme` to anything at all — confirmed above, and it does not import `keep.css`.
`tools/docgen`'s own document renderer is different: it ships real toggle code
(`components.py:61-98`, `theme_toggle()` — a button plus inline JS reading
`localStorage`/`prefers-color-scheme` and calling
`document.documentElement.setAttribute('data-theme', theme)` on click), wired into every document
this corpus builds via `masthead()` (`components.py:113`, called by `generator.py:245`) — this
document's own built HTML included. **It was broken until fixed 2026-08-19:** `generator.py:260`
hardcoded `<body data-theme="dark">` permanently, and since the CSS declares its custom
properties with plain `[data-theme=...]` attribute selectors (`tools/docgen/tokens.py:162,166`)
rather than a selector scoped through `<body>`, `<body>`'s own hardcoded attribute won for every
property inherited by the content inside it — which is everything visible on the page — no
matter what the toggle script set on `document.documentElement` (the `<html>` tag). The fix
removed the hardcoded attribute from `<body>` (`generator.py:260` now emits plain `<body>`),
leaving `document.documentElement` as the sole place any `data-theme` attribute is ever set, so
the custom properties defined on `:root`/`[data-theme=...]` cascade down into `<body>` and its
descendants normally. Verified by rebuilding this document and clicking the toggle in a browser:
`<body>`'s computed `background-color` now flips with the click
(`rgb(5, 5, 6)` dark → `rgb(251, 251, 252)` light), where before only the button's own label text
visibly changed. The values still exist twice, via an architecturally identical but
separately-sourced token pair (`tools/docgen/assets/tokens.json`, explicitly documented as a
mirror rather than an import of KEEP — `tools/docgen/tokens.py:3`; `design/PROVENANCE.md`), kept
honest by discipline, not by import; the working switch is in the docgen system only — KEEP /
`apps/desktop/**` still has none.

**The invariant, and it is meant to be testable:** for every pair `(background, foreground)`
used together, `contrast(dark) ≈ contrast(light)` within ±0.4. The *feel* inverts; the
*legibility* is not meant to move. This is **`planned`** as an enforced property.
`13_TEST_PLAN.md §7` — "UI tests that encode product rules," not `§5`, which is crypto
conformance and has nothing to do with colour — lists the greyscale/desaturated-screenshot-diff
walk as future work ("a scripted screenshot pass will render the main views desaturated and diff
them against approved baselines"); it does not, anywhere, name a numeric contrast-ratio
("contrast-pair") test — the word "contrast" does not occur in that document at all. The
`±0.4` invariant stated above therefore has no planned test of its own yet, only the greyscale
walk, which checks a different (colour-independence) property. `09_UI_UX_SPEC.md §14` states the
same ≥4.5:1 (text) / ≥3:1 (meaningful strokes) floors as a non-negotiable requirement; neither
floor is enforced by any test anywhere in this corpus today.

**How much black and white each theme will use** is deliberately different, and that
difference is the design:

| | Vault Dark | Vault Light |
|---|---|---|
| Dominant surface | near-black (~92% of pixels) | paper white (~92%) |
| Ink | bone, sparse | near-black, sparse |
| Hairlines | light-on-dark at 7% alpha | dark-on-light at 10% alpha (dark hairlines need more presence) |
| Elevation | *lighter* than the base | *darker* than the base — shadow, not glow |
| Focus ring | bright | dark |
| Sealed hatch | light strokes at 5.5% | dark strokes at 5% |

Elevation flipping direction is meant to be the detail that makes an inversion feel *designed*
rather than computed: light UIs get depth from shadow, dark UIs from light. **This row is
`planned`, not `partial` like the rest of the section** — `keep.css`/`keep-components.css`
declare exactly one `box-shadow` in the whole design system (`.k-hover`, the graph node hover
card, `keep-components.css:138`), and it is a single fixed `var(--scrim)` value used in both
themes, not a direction that flips with `data-theme`. The alternating light-on-dark /
dark-on-light hairline alpha values in the table above, by contrast, are real — they are the
`--hair`/`--hair-strong` values already in `keep.css`'s two `[data-theme]` blocks.

---

## 3. Colour — the tricky part, solved by construction — **`planned`**

Nothing of this section exists. `grep -rn "oklch\|contrastAPCA\|enforceContrast\|color-mix"
v2/crates/` returns no matches at all, and no hue picker, intensity slider, or colour setting
of any kind appears anywhere in `apps/desktop/src/**`. The requirement — colour must "best
match the surrounding colour, while the text is visible and easy to read" — cannot be met by a
fixed palette, because the user picks the hue. So KEEP does not plan to ship a palette; it
plans to ship a **derivation** with a contrast guarantee. The target design, in full:

### 3.1 The user will pick one thing: a hue

```
  COLOUR     ○ Off — pure black & white
             ● On
                 hue  ├──────────●───────────────────────┤   198°
                 intensity   subtle ●──────── vivid          32%
                 [ ○ Vault  ○ Ink  ○ Moss  ○ Rust  ○ Slate  ○ Custom ]
```

One hue. Not a palette, not five pickers — every colour in the UI will be derived from it,
which is why the result will stay coherent whatever the user chooses.

### 3.2 Derivation (OKLCH, so lightness is perceptual)

```
given  H = hue (0–360), I = intensity (0–1)

grounds     stay at their theme lightness anchors; chroma = 0.012 · I
            → surfaces will be *tinted*, never coloured. At I = 1 the tint will still
              be barely a hue; a credential manager is not a mood lamp.

accent      L = dark ? 0.72 : 0.48      C = 0.11 · (0.4 + 0.6·I)     h = H
accent-dim  L = dark ? 0.24 : 0.92      C = 0.05 · I                 h = H

on-accent   = pick(bone, ink) maximising contrast against `accent`
              — computed, never declared

hairlines   will inherit ground chroma, so borders will belong to the surface
semantics   sig / warn / danger will keep their OWN hues, always. Health state must not
            become invisible because the user chose a green theme.
```

### 3.3 The guarantee

```ts
// Will run on every theme change. In dev it will throw; in release it will repair and warn.
function enforceContrast(tokens: Tokens): Tokens {
  for (const [bg, fg, min] of CONTRAST_PAIRS) {       // ~40 declared pairs
    let ratio = contrastAPCA(tokens[bg], tokens[fg]);
    while (ratio < min) {
      tokens[fg] = nudgeLightness(tokens[fg], awayFrom(tokens[bg]), 0.01);
      ratio = contrastAPCA(tokens[bg], tokens[fg]);
      if (exhausted()) { tokens[fg] = pickExtreme(tokens[bg]); break; }  // bone or ink
    }
  }
  return tokens;
}
```

**Once built, it will not be possible to choose a hue that makes text unreadable.** The worst
case will be that the accent stops being the user's exact hue and becomes the nearest legible
one — and the UI will say so (*"adjusted for contrast"*) rather than silently ignoring the
choice. Legibility is designed to outrank preference, visibly — a design intent today, since
neither `enforceContrast` nor `CONTRAST_PAIRS` exists anywhere in this repository yet; the code
block above is the complete specification, not a description of running code.

<!-- figure:hue-derivation-pipeline -->
*One hue and one intensity flow through a fixed set of formulas, then through a single repair
loop that can only move a colour toward legibility, never away from it — there is no designed
path from picking a hue to unreadable text. None of this runs today.*

### 3.4 `colour: 'auto'`

Will derive H from the OS accent colour (macOS `NSColor.controlAccentColor`, Windows
`UISettings.GetColorValue(Accent)`, GNOME accent) and follow it live. This is what "match the
surrounding colour" is meant to mean in practice: the vault will sit inside the desktop rather
than fighting it. Read-only, with one click to pin — none of it wired to anything today; no
platform-accent API call of any kind appears in `v2/crates/**`.

### 3.5 What colour will never touch

Node kinds · edge types · the sealed hatch · sensitivity levels · the graph's structural
language. Those are designed to stay achromatic in every mode, because they are the information
architecture (`design/graph-engine/VAULT_GRAPH_SPEC.md §3`, itself a spec — the vendored
`force-graph.min.js` it targets is not imported anywhere in `v2/apps/`, so the graph is exactly
as unbuilt as the colour axis it must stay independent of). Colour is meant to tint the *room*,
never the *map*.

---

## 4. Storage and precedence — **`planned`**

```
theme  : 'system' (default) → follows the OS; 'dark' | 'light' pins it
colour : 'off' (default) | { hue, intensity } | 'auto'
contrast: 'standard' (AA) | 'high' (AAA — raises every floor to 7:1)
motion : 'system' (default) | 'reduced'
```

Will be persisted in the vault **config**, not `localStorage` — so the setting will survive a
reinstall and will not be readable by a webview bug. Will be applied before first paint (the
shell will inject the resolved token block into the document head) so there will be no flash.

None of this exists today. `crates/store` has no struct carrying a `theme`, `colour`,
`contrast` or `motion` field anywhere in `manifest.rs`, `registry_file.rs`, or any other file in
the crate — checked directly, not inferred. `apps/desktop/src/app.html` is gone (ADR-075); the
hosted page, `apps/desktop/index.html`, sets `data-theme="dark"` as the first-paint value, the app
re-applies the resolved theme once it mounts, and the shell injects no token block. `apps/desktop/src/vault/prefs.ts`
is real and browser-side: it reads and writes one local-storage record (`PREFS_KEY`, `credmgr_prefs`), drops any
value outside its typed shape (`pick()`, over `PREF_KEYS`), and falls back to the defaults when storage is
refused (`PRIVACY.md` lists the storage keys). It is not the vault config this section specifies.
The schema above is the target shape a future `vault.config` op and its storage will need to
agree on.

---

## 5. Deliverables for Claude Design — **`planned`**, and not yet requested from anyone

These six renders describe what a design pass against this specification would need to
produce, once one is commissioned. **No such engagement exists.** `v2/design/handoff/` — the
path this corpus reserves for returned design work (`12_BUILD_PLAN.md`, `19_FRONTEND_DELIVERY_SCOPE.md §8`) — does not exist, because nothing has gone out for it to be a return address for.
An earlier session's claim that an external front-end team was mid-flight against a
byte-identical copy of this corpus was false; it is why this document was withheld from the
2026-08-18 rewrite in the first place, and the belief was corrected the same day (this
document's own stamp, above; `PROJECT_MAP.md §6`). The six items below are unstarted target
work, not a request in flight and not a delivery anyone is waiting on:

1. Vault Dark, colour **off** — the primary.
2. Vault Light, colour **off** — a true inversion, elevation flipped to shadow.
3. Vault Dark + colour at hue 198° / intensity 32% — showing how *little* tint is enough.
4. Vault Light + colour, same hue — proving the derivation holds both ways.
5. **A greyscale render of #3** — proving nothing was carried by hue alone.
6. A contrast plate: every declared pair with its measured ratio in both themes.

---

## 6. Risks

All three risks below describe the *planned* system in §2–§4; none has been realised, because
none of the code they describe exists yet. They are recorded now so the guarantee is judged
against them once something ships, not invented after the fact.

| ID | Risk | Mitigation |
|---|---|---|
| **AR-15** | Runtime contrast repair could shift the accent enough to look wrong | Bounded to ±0.12 L; beyond that it falls back to the extreme and tells the user |
| **AR-16** | OKLCH needs `color-mix`/`oklch()` support | The system webview on each target OS is expected to support both, at the versions Tauri 2 ships against (`16_CROSS_PLATFORM.md §2`, "System webview on every OS"); a build-time-computed sRGB fallback is planned for any older Linux WebKitGTK build still in use |
| **AR-17** | `colour: auto` following the OS could produce a near-invisible hue | The derivation fixes lightness itself and takes only the hue, so an OS accent can never set a lightness |

---

## 7. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `design/tokens/keep.tokens.json` | the `grounds_dark`/`grounds_light`/`inks_dark`/`inks_light`/`signal` tables §2 and §3's formulas are built on |
| depends on | `design/PROVENANCE.md` | what KEEP took structurally from its source system and what it deliberately did not — the achromatic-by-default identity this whole document extends |
| depends on | `design/graph-engine/VAULT_GRAPH_SPEC.md §3` | the graph's achromatic visual language, which §3.5 excludes from every colour rule above it |
| depends on | `09_UI_UX_SPEC.md §14` | the ≥4.5:1 / ≥3:1 contrast floors this document's own invariant (§2) restates for both themes |
| depends on | `16_CROSS_PLATFORM.md §2` | the system-webview-per-OS fact AR-16 relies on |
| depends on | `14_DECISIONS.md` | `ADR-058` (this document's own header contract), `ADR-059` (the `built`/`partial`/`planned` vocabulary applied here to a subsystem that is almost entirely unbuilt), `ADR-057` (the Tauri bridge that will eventually need to carry `theme get/set`, §1) |
| feeds | `13_TEST_PLAN.md §7` | the greyscale/desaturated-screenshot-diff check this document's invariant relies on, listed there as a planned UI test; the numeric contrast-ratio check this document also specifies has no home yet in `13_TEST_PLAN.md` |
| feeds | `19_FRONTEND_DELIVERY_SCOPE.md §2` | the "built as a specification, planned as an implementation" status that document already assigns this one |
| feeds | `02_ARCHITECTURE.md §6.2` | `theme get/set`, named there as a command the Tauri bridge will still need |

## 8. Source

**Design.** `ADR-058` (header contract), `ADR-059` (status vocabulary — applied here to a
subsystem that is almost entirely `planned`). `design/PROVENANCE.md` for what KEEP inherited
structurally and what it deliberately did not.

**Values that exist.** `design/tokens/keep.tokens.json` (`grounds_dark`, `grounds_light`,
`inks_dark`, `inks_light`, `signal`) and `design/tokens/keep.css` (line 15
`[data-theme="dark"]`, line 40 `[data-theme="light"]`, line 131 the universal focus ring, line
138 of `keep-components.css` the one `box-shadow` in the system, line 188 `.is-sealed`, line
200 `.sens-critical`) — a complete, checked-in static implementation of the colour-off corners
in §1's matrix, consumed by nothing.

**Code checked and found absent.** (As of 2026-08-19 `apps/desktop/src/routes/+page.svelte` — the
stock scaffold's inline styles, literal hex — and `src/app.html`; both are gone, ADR-075.) `crates/store/src/manifest.rs`,
`registry_file.rs` and every other file in that crate (no config struct carries a theme, colour,
contrast or motion field); `crates/brokerd/src/ops.rs` (no `theme.*` op); every `.rs` file under
`v2/crates/` (`grep -rn "oklch\|contrastAPCA\|enforceContrast\|color-mix"` returns nothing);
`v2/design/graph-engine/` (`force-graph.min.js` is not imported anywhere under `v2/apps/`).
Verified 2026-08-18, re-verified 2026-08-19 (round-2 backlog: the docgen toggle, the `--void`
token, and the `13_TEST_PLAN.md §7` citation).

**Figures.** `v2/docs/20_THEMING_spec.json` — two `docgen` `flowchart` figures, per
`tools/ENGINE_ROUTING_POLICY.md`: `theme-colour-axis-matrix` (§1, the four-state axis matrix,
built/planned split per corner) and `hue-derivation-pipeline` (§3.2/§3.3, the derivation +
repair-loop pipeline, planned end to end). Both cite the same token files and code-absence
greps as this section's own prose, re-verified 2026-08-23.

**Verification.** `tools/corpus_check.py stamps` (this document's own stamp against its body);
`python3 -m tools.docgen.cli build v2/docs/20_THEMING.md --formats html,json`.
