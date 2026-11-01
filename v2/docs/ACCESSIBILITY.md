<!-- artifact-hardened: not applicable — front-end team record imported from the design project 2026-10-24; not a backend source-of-truth artifact, not hardened here -->
# CredMgr — accessibility conformance (WCAG 2.2 AA)

**Written 2026-10-18 (batch B12).** Draft Accessibility Conformance Report for CredMgr 2.0.0-beta.1, design file
`CredMgr App.dc.html`. It covers the desktop window's interface; the CLI and the MCP server are out of scope. Evidence comes
from the regression gate (`audit-suite.js` + `audit-probe.js`), run in four themes (dark, light, dark high-contrast, light
high-contrast) over 55 states, and from reading the template. **No assistive-technology test has been done yet**: rows that
need one say so. Status words follow the VPAT: Supports, Partially supports, Does not support, Not applicable, Not tested.

What the gate measures in every state and theme: controls with no handler, controls with no accessible name, text below
4.5:1 (7:1 in high-contrast mode), targets under 24 × 24 px without the spacing exception, buttons whose name does not contain
their visible words, clipped dialog text, squashed controls. The graph `<canvas>` is not DOM and is not covered; the tree view
(`T`) is its accessible equivalent.

## Fixed in batch B13 (2026-10-18)
- 1.4.10: the inspector sheet was 420 px wide in a 320 px window; it now fits and long names end in an ellipsis.
- 1.4.10: Settings → Grants let an unbroken scope string run past a 320 px window; the header's gear button sat 15 px outside it. Search and the wordmark now shrink (the wordmark hides under 420 px).
- 1.4.12: new probe metric `clip`; run with the spacing overrides, 0.
- 2.4.11: gate assertion for the donation toast moving aside when focus lands under it.
- Graph pane: the canvas kept sizing itself to a pane that had been removed; it now follows the pane it lives in.

## Fixed in B12
- 2.5.8: seven undersized targets (✕ and ⋮ buttons, About links, Grant capability checkboxes) brought to 24 px. Gate count 0.
- 3.1.1: the document had no language; the app now sets `lang="en"`.
- 2.4.2: the document had no title; the app now sets `CredMgr`.
- 2.1.4: single-key shortcuts (`/ F G T N E`) can be turned off in Settings → Appearance, in Lite and Pro; they also ignore
  keys pressed with ⌘, Ctrl or Alt.
- 2.5.3: CredGames *Play* and Operations *Run* had names that did not contain their visible word.
- 4.1.2: the four on/off toggles had the name "on" or "off"; they now carry the setting's name and `aria-pressed`.
- 1.4.11: high-contrast mode raises control borders to at least 3:1 (gate assertion).
- 2.4.3: closing the Field dialog opened from a field menu returned focus to nothing; it now returns to that field's `⋮`.

## Table

| Criterion | Level | Status | Notes |
|---|---|---|---|
| 1.1.1 Non-text content | A | Supports | Icon buttons have names (gate: 0 unnamed). The graph canvas is `role="img"` with a label that points to the tree view |
| 1.2.1–1.2.5 Time-based media | A/AA | Not applicable | No audio or video |
| 1.3.1 Info and relationships | A | Supports, not tested with AT | `header`, `nav`, `main` landmarks; dialogs are `role="dialog"` + `aria-modal` with a title; inputs labelled. Tree rows need a screen-reader check |
| 1.3.2 Meaningful sequence | A | Not tested | DOM order follows the visual order by construction; needs an AT pass |
| 1.3.3 Sensory characteristics | A | Supports | Instructions name controls by text ("Review", "held"), never only by colour or position |
| 1.3.4 Orientation | AA | Supports | Desktop window; layout reflows, no orientation lock |
| 1.3.5 Identify input purpose | AA | Not applicable | No field asks for the user's own personal data (name, e-mail, address) |
| 1.4.1 Use of colour | A | Supports | Every state has a word or a glyph; Settings → Appearance → Greyscale proof renders without colour |
| 1.4.2 Audio control | A | Not applicable | No audio |
| 1.4.3 Contrast (minimum) | AA | Supports | Gate: 0 text below 4.5:1 in four themes (7:1 in high-contrast). Canvas labels use `--bone` / `--ash` on `--void` |
| 1.4.4 Resize text | AA | Supports | 200 % zoom at a 924 px window is a 462 px layout; the 480 px sweep is clean (rail and inspector become sheets) |
| 1.4.5 Images of text | AA | Supports | None |
| 1.4.10 Reflow | AA | Supports | Swept at 320 px (400 % zoom of a 1280 px window): 55 states, all counts 0, and no horizontal scroll on 15 app states, the lock screen and first run. The graph is a diagram and may scroll in two directions (exception) |
| 1.4.11 Non-text contrast | AA | Partially supports | Standard mode: control borders are `--faint`, about 1.5 : 1; inputs are identified by their fill and label, buttons by their text. High-contrast mode: borders ≥ 3 : 1 (gate). Raising them in standard mode is a KEEP decision (`KEEP_UPSTREAM_NOTES.md`) |
| 1.4.12 Text spacing | AA | Supports | The four WCAG values applied to every element (line height 1.5, letter spacing 0.12 em, word spacing 0.16 em, paragraph spacing 2 em): 55 states, 0 clipped, 0 overflowing, 0 squashed. The probe's `clip` metric (text cut off vertically) has a canary |
| 1.4.13 Content on hover or focus | AA | Supports | The hover card shows only on pointer hover, stays while hovered, and Esc dismisses it |
| 2.1.1 Keyboard | A | Supports | Every action has a keyboard path: tree view for the graph, context menu (tree row `⋮`) for node actions, the Grant dialog instead of drag, Tab inside dialogs. CredGames plays by keyboard |
| 2.1.2 No keyboard trap | A | Supports | Dialogs trap Tab on purpose and Esc always closes the top layer (gate) |
| 2.1.4 Character key shortcuts | A | Supports | Can be turned off (gate assertion); inactive while typing or with a dialog open |
| 2.2.1 Timing adjustable | A | Supports | Reveal window and auto-lock are user-set (Settings → Security). The 30 s clipboard clear is a security measure (essential exception). The donate toast has no time limit |
| 2.2.2 Pause, stop, hide | A | Supports | Pulsing marks and halos stop with Settings → Appearance → Motion: reduced, and with the OS setting. A game pauses with P |
| 2.3.1 Three flashes | A | Supports | Nothing flashes |
| 2.4.1 Bypass blocks | A | Supports | Landmarks; `/` goes to search |
| 2.4.2 Page titled | A | Supports | `CredMgr` |
| 2.4.3 Focus order | A | Supports, not tested with AT | Dialogs focus their first control on open and return focus to the opener on close (gate) |
| 2.4.4 Link purpose (in context) | A | Supports | The few links are named (Donate, Privacy, Licences) |
| 2.4.5 Multiple ways | AA | Not applicable | One window, not a set of pages |
| 2.4.6 Headings and labels | AA | Supports | Every dialog and settings section has a title |
| 2.4.7 Focus visible | AA | Supports | KEEP `:focus-visible` ring, 2 px `--sig-hi`, on every control |
| 2.4.11 Focus not obscured (minimum) | AA | Supports | The donate toast (bottom right, non-modal) moves to the bottom left when focus lands under it, and back when it would cover focus there; Esc is not needed because the ✕ is first in tab order inside it |
| 2.5.1 Pointer gestures | A | Supports | No path-based or multi-touch gesture is required; Fit (`F`) replaces pinch |
| 2.5.2 Pointer cancellation | A | Supports | Actions fire on click (up), not on down |
| 2.5.3 Label in name | A | Supports | Gate: 0 mismatches |
| 2.5.4 Motion actuation | A | Not applicable | No device motion |
| 2.5.7 Dragging movements | AA | Partially supports | Proposing a grant by drag has a menu path. Moving a node by hand has no alternative; positions are cosmetic and Fit restores a layout |
| 2.5.8 Target size (minimum) | AA | Supports | Gate: 0 targets under 24 px without spacing |
| 3.1.1 Language of page | A | Supports | `en` |
| 3.1.2 Language of parts | AA | Not applicable | English only |
| 3.2.1 On focus / 3.2.2 On input | A | Supports | Focus and input never open a dialog or move the view by themselves |
| 3.2.3 Consistent navigation / 3.2.4 Consistent identification | AA | Supports | One header, one vault menu, one name per action |
| 3.2.6 Consistent help | A | Supports | `?` in the header on every app screen |
| 3.3.1 Error identification | A | Supports | Errors are text next to the field (duplicate name, wrong code, field errors with `role="alert"`) |
| 3.3.2 Labels or instructions | A | Supports | Every input has a label or a name |
| 3.3.3 Error suggestion | AA | Supports | The duplicate-name message says what it compared and where |
| 3.3.4 Error prevention (legal, financial, data) | AA | Supports | Removing a node is a typed confirmation and reversible for 7 days; held writes are reviewed before they land |
| 3.3.7 Redundant entry | A | Supports | First run asks for the passphrase twice on purpose (security exception); nothing else is re-asked |
| 3.3.8 Accessible authentication (minimum) | AA | Supports | The beta unlocks by passphrase (Touch ID is not built); paste is not blocked in the design or in the desktop shell (checked in the real app, 2026-10-18). Second factor: a typed code, no transcription between devices is forced |
| 4.1.2 Name, role, value | A | Supports, not tested with AT | Gate: 0 unnamed controls; toggles expose `aria-pressed` |
| 4.1.3 Status messages | AA | Supports, not tested with AT | `aria-live` on reveal and copy, pending writes, backup, Operations results, supporter-code feedback |

## Open
1. Screen-reader pass (VoiceOver, NVDA): script in `NEXT_SESSION.md`. Turns five "not tested with AT" rows into results.
2. 1.4.11 in standard contrast: KEEP decision.

Legal scope (EAA, Section 508): `LEGAL_REGISTER.md` L7.

## B14 additions (2026-10-18)
| Criterion | Where | How it is met |
|---|---|---|
| 1.4.11, 1.4.1 | Node shape, global colour, link colour, dot palette | every colour option keeps ≥ 3:1 on the canvas; shape is never the only carrier of meaning (orphan dash, sub-node thin ring, grant dash, 2FA tick, lock square stay); high contrast and greyscale proof force the graph extras to default |
| 2.2.2, 2.3.3 | Unlock flourish, CredPong comet and dotted trail | off, and forced to default, under reduced motion; the flourish lasts one second, takes no input and the app is usable at once |
| 4.1.2 | Every extras picker | a `role="group"` named by its title; each option a button with `aria-pressed` |
| 2.5.8 | Extras options | minimum height 28 px |
| 1.1.1 | Extras preview canvas | `role="img"` with a text alternative |
| 1.4.3 | Header milestone stamp | `--ash` text on the header, `aria-label` names the milestone |

**2026-10-24.** The App icon group lost its `not in beta.1` badge; the radio group, its name and its focus order are unchanged. Window content protection (T10) blanks screen captures, including assistive screen-capture tools that read pixels; the screen-reader pass (O-1) is unaffected, since it reads the accessibility tree.
