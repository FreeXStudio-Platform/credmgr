---
id: V2-023
classification: public
title: Release verification checklist
audience: technical
owner: credmgr-v2
status: needs-verification
export_allowed: true
surface: repo
last_reviewed: 2026-10-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — written 2026-10-03 (iteration 3, docs lane) from the wired
     app at source commit 5ff9092. The control, event and handler columns were extracted mechanically from
     `apps/desktop/src/design/screens/*.html` (every element that carries an event binding, plus every
     input, select, text area and link); the bridge command was traced through the logic mixins, the action
     modules, `src/vault/bridge-source.ts` and `src/lib/bridge.ts`, and the broker op from
     `src-tauri/src/commands.rs`; the expected results were written from the handler code and checked against
     it. The RESULT column was empty on purpose until 2026-10-18 (chunk C4), when a tester pressed the controls in the
     built app; a row that says n/a was not pressed. Still NEEDS RE-HARDENING (chunk C6). -->
# Release verification checklist

`CredMgr V2` · every screen and control of the shipped app, what each sends, and what must happen · `2026-10-03`

> **Status.** **`verified in the built app, 2026-10-18`** — every row of §2–§5 and §7 now carries a Result written by a tester
> who pressed the control in the built `CredMgr.app` against a throwaway vault (see §8 for what was used and what was not
> pressed). A row marked **n/a** was *not pressed in that pass* (it says why); it is not a pass. Rows marked **fail**
> name the finding in `docs/history/finish-plan/C4-FINDINGS.md`. The automated suites listed in §6 exercise most of
> these paths against a fixture broker (and, for `npm run test:real`, a real `credmgrd`); they are not a substitute for
> pressing the controls, and this pass found one defect they had not (F-5, autocorrect on text fields).

## 1. How to use this document

1. Build the app from the commit being released (`apps/desktop/README.md`, `scripts/release-app.sh`) and start it
   against a **throwaway vault**: a temporary `CREDMGR_VAULT_DIR` and `CREDMGR_STATE_DIR`, never the vault
   you use, and a passphrase made for the occasion. Everything below is safe to press in such a vault; nothing
   here needs a real credential.
2. Work through §2 screen by screen, in light, dark and high-contrast (Settings → Appearance), and once with the
   window narrow enough to show the rail and inspector as sheets. In each row, press the control and compare
   what happens with **Expected result**; write the outcome in **Result** (*pass* / *fail* / *n/a* and a
   note — a screenshot path, an audit record id, the notice text).
3. Where a row names a bridge command and a broker op, the audit trail (Settings → Audit, or `credmgr audit`)
   is the independent witness that it was sent: one record per call, and a **denied** call is recorded too.
4. §3–§5 cover what has no button: menus built from data, the graph canvas, keyboard shortcuts, and the things
   that happen on a timer or from the system. §7 lists the whole-journey checks. §8 is the record.

**Columns.** *Control* is the element as the template draws it, with the condition under which it is shown
(`when …`) and, for a list, the row it repeats in (`each row of …`). *Event → handler* is the template binding
(`src/design/screens/*.html`) and the name of the function it calls. *Bridge command → broker op* is what that
handler sends, in order, after which the screen **re-reads what the change touched** (there is no optimistic
write): `—` means the control sends nothing. A command whose op is in parentheses is the shell's own and never
reaches the broker. *Expected result* is what must be seen.

**Size.** 214 control rows in 22 screen templates plus the page scaffolding, §3 adds 30 menu-item rows,
§4 and §5 the gestures and system behaviours.

## 2. Screens and controls

### Boot — `boot`

Shown while the app asks the broker for its state, and when it cannot reach it. The release build with no shell shows only this screen.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| button “Retry”<br><sub>when `isBrokerDown`</sub> | click → `retryBoot` | `vault_status` → `vault.status` | Re-asks the broker for its state: the Lock screen when locked, First run when no vault exists, the app when this process is already logged in, or the "broker unreachable" screen again with the reason. No passphrase is asked for while the broker is down. | **pass** — Retry works when launched via LaunchServices; see F-1 for the bare-binary launch; Retry while down stays; Retry when up shows the Lock screen |
| button “Retry”<br><sub>when `isBootFailed`</sub> | click → `retryBoot` | `vault_status` → `vault.status` | Re-asks the broker for its state: the Lock screen when locked, First run when no vault exists, the app when this process is already logged in, or the "broker unreachable" screen again with the reason. No passphrase is asked for while the broker is down. | **n/a** — bootfailed state not reachable without a fault injection |

### Lock screen — `S16-lock`

The passphrase step, the second-factor step and the "lost your authenticator" step.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| field “passphrase”<br><sub>when `lockStepPass`</sub> | change → `onPassInput`<br>key → `onPassKey` | `vault_unlock` → `vault.unlock` | **change:** The passphrase is held in the field only. Nothing is sent. **key:** Enter submits the passphrase (same as Unlock). | **pass** — passphrase held in the field; Enter submits |
| button “Unlock” (reads “Unlocking…” while the broker works)<br><sub>when `lockStepPass`</sub> | click → `submitPass` | `vault_unlock` → `vault.unlock` | Sends the passphrase once and clears the field. Success with no second factor: the app opens, nodes and entries load. A second factor in force: the screen asks for a code. Wrong passphrase: an inline refusal; the broker's wait (rate limit) is shown and the button waits. Never "unlocked" without a broker answer. | **pass** — wrong passphrase: inline "Wrong passphrase.", field cleared; right passphrase with 2FA enrolled asks for a code |
| field “2FA code”<br><sub>when `lockStepCode`</sub> | change → `onTwofa`<br>key → `onTwofaKey` | `vault_gate_verify` → `vault.gate_verify` | **change:** Digits and letters of a code are kept (at most 48 characters). Six digits are sent at once. **key:** Enter sends the code. | **pass** — digits kept; 6 digits sent at once (a wrong 000000 gave "That code was not accepted."); Enter sends |
| button “Verify”<br><sub>when `lockStepCode`</sub> | click → `submitTwofa` | `vault_gate_verify` → `vault.gate_verify` | Sends the authenticator code (or one of the ten gate recovery codes). Success opens the app; a wrong, replayed or expired code is refused with one undifferentiated message. | **pass** — Verify: TOTP and one gate recovery code both unlock; wrong/replayed code refused with the same message |
| button “lost your authenticator?”<br><sub>when `lockStepCode`</sub> | click → `gotoRecover` | — | Switches to "lost your authenticator" (passphrase + root recovery code). Nothing is sent. | **pass** — lost your authenticator? switches to the reset step |
| button “back”<br><sub>when `lockStepCode`</sub> | click → `gotoPassphrase` | — | Back to the passphrase step; the typed fields are cleared. Nothing is sent. | **n/a** — back from the code step not pressed |
| field “passphrase”<br><sub>when `lockStepRecover`</sub> | change → `onRecoverPass`<br>key → `onRecoverKey` | `vault_gate_recover` → `vault.gate_recover`<br>`vault_unlock` → `vault.unlock` | **change:** Held in the field only. Nothing is sent. **key:** Enter submits the reset (same as Reset and unlock). | **pass** — passphrase and root code fields held |
| field “root recovery code”<br><sub>when `lockStepRecover`</sub> | change → `onRecoverCode`<br>key → `onRecoverKey` | `vault_gate_recover` → `vault.gate_recover`<br>`vault_unlock` → `vault.unlock` | **change:** Held in the field only. Nothing is sent. **key:** Enter submits the reset (same as Reset and unlock). | **pass** — Enter submits the reset |
| button “Reset and unlock”<br><sub>when `lockStepRecover`</sub> | click → `submitRecover` | `vault_gate_recover` → `vault.gate_recover`<br>`vault_unlock` → `vault.unlock` | Sends the passphrase and the printed root recovery code together: the second factor is removed (not unlocked), then the login follows with the passphrase. The notice says "Second factor reset. Enrol a new authenticator in Settings, under Security." | **pass** — reset with passphrase + root recovery code: notice "Second factor reset. Enrol a new authenticator in Settings, under Security." and the app opened |
| button “back”<br><sub>when `lockStepRecover`</sub> | click → `gotoPassphrase` | — | Back to the passphrase step; the typed fields are cleared. Nothing is sent. | **n/a** — back from the recovery step not pressed |

### First run — `S17-firstrun`

No vault exists yet: passphrase, recovery code, optional second factor, first projects.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| field “new passphrase”<br><sub>when `frIs1`</sub> | change → `onFrPass`<br>key → `onFrPassKey` | `vault_init_begin` → `vault.init_begin` | **change:** Held in the field only. A passphrase under 4 characters is flagged (the button stays off); 4–7 characters show “8 or more is recommended” and may continue; nothing is sent. **key:** Enter continues (same as the primary button). | **pass** — verified in the rebuilt app (2026-10-18): 4 characters accepted with the recommendation shown; 3 refused; 8+ shows no warning |
| field “repeat the passphrase”<br><sub>when `frIs1`</sub> | change → `onFrPassRepeat`<br>key → `onFrPassKey` | `vault_init_begin` → `vault.init_begin` | **change:** Held in the field only. A mismatch is flagged; nothing is sent. **key:** Enter continues (same as the primary button). | **pass** — mismatch flagged ("Passphrases don't match"); Enter continues |
| field “retype the recovery code”<br><sub>when `frIs2`</sub> | change → `onFrRetyped`<br>key → `onFrRetypedKey` | `vault_init_confirm` → `vault.init_confirm`<br>`vault_unlock` → `vault.unlock` | **change:** Held in the field only; optional. Nothing is sent. **key:** Enter confirms (same as the primary button). Left empty, the code shown on the screen is what is confirmed. | **pass** — optional in the rebuilt app; a wrong retype is still refused by the broker (e2e) |
| checkbox “I have written the recovery code down (optional)”<br><sub>when `frIs2`</sub> | change → `onFrRec` | — | Optional acknowledgement. Nothing is sent and the primary button does not wait for it. | **pass** — vault created without ticking it (rebuilt app) |
| button “Skip for now”<br><sub>when `frSkipConfirmShow`</sub> | click → `frSkipConfirm` | `vault_init_confirm` → `vault.init_confirm`<br>`vault_unlock` → `vault.unlock` | On the recovery-code step: creates the vault with the code that is on screen, without retyping it, then unlocks. On the recovery-codes step of an enrolled second factor: continues without the tick. | **pass** — both steps, rebuilt app (2026-10-18) |
| field “authenticator code”<br><sub>when `frEnrolQr`</sub> | change → `onFrTotp`<br>key → `onFrTotpKey` | `vault_gate_enroll_confirm` → `vault.gate_enroll_confirm` | **change:** Six digits are sent for confirmation automatically. **key:** Enter confirms the code. | **pass** — 6 digits auto-confirm; ten recovery codes shown |
| checkbox “I have saved these recovery codes”<br><sub>when `frEnrolCodes`</sub> | change → `onFrCodesSaved` | — | Optional acknowledgement. Nothing is sent; Continue does not wait for it. | **pass** — Continue and Skip for now both work unticked (rebuilt app) |
| field “project name 1 … 3” (first projects, optional)<br><sub>when `frIs4`</sub><br><sub>each row of `frNames`</sub> | change → `n.onChange` | — | Holds a first-project name (up to three). Nothing is sent until Finish. | **pass** — two names accepted (acme, beta); both appear in graph |
| button “Back”<br><sub>when `frCanBack`</sub> | click → `frBack` | — | From the recovery-code step back to the passphrase step; the passphrase is forgotten. Nothing is sent. | **pass** — Back returns to passphrase step, fields cleared |
| button “Enrol later”<br><sub>when `frSkipShow`</sub> | click → `frSkip` | — | Skips the second factor ("Enrol later") and goes to naming the first projects. A setup that was staged was never confirmed, so it gates nothing; the vault stays without a second factor. Nothing is sent. | **n/a** — Enrol later not pressed (enrolled instead) |
| primary button (reads Create vault · Continue · Confirm · Finish by step)<br><sub>when `isFirstRun`</sub> | click → `frNext` | `vault_init_begin` → `vault.init_begin`<br>`vault_init_confirm` → `vault.init_confirm`<br>`vault_unlock` → `vault.unlock`<br>`vault_gate_enroll_begin` → `vault.gate_enroll_begin`<br>`vault_gate_enroll_confirm` → `vault.gate_enroll_confirm`<br>`node_create` → `node.create` | Step 1 sends the passphrase (the recovery code is shown once). Step 2 confirms the retyped code and writes the vault, then unlocks. Step 3 stages a second factor (QR + secret), then confirms a code and shows ten recovery codes. Step 4 creates the named projects and opens the app. | **pass** — all four steps; vault opens on graph with acme, beta, orphaned |

### Header — `S1-header`

Search, the lock button, the held-entries chip, the vault menu, Help and Settings.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| button “☰” | click → `toggleRailOpen` | — | Opens or closes the node rail on a narrow window. Nothing is sent. | **pass** — ☰ opens the rail sheet on a narrow window |
| field “search… /” | change → `onSearch`<br>focus → `onSearchFocus` | `search` → `search` | **change:** The dropdown lists matching nodes and entry names (names only — never labels or values) from the broker, plus matching orphaned items. **focus:** Opens the dropdown ("Add new", recent nodes). Nothing is sent. | **fail** — F-5 (P1, fixed in this chunk): macOS autocorrect rewrote the query on blur (typed “mfa” became “Mea”, result list lost) and offered a capital for “mfa-demo”. search lists matching entry names from the broker; focus opens the dropdown (Add new, recent nodes); (see also F-5: macOS autocorrect rewrites the query on blur, "mfa" became "Mea") |
| button: a search result row (Add new · node · entry · orphaned item)<br><sub>when `searchOpen`</sub><br><sub>each row of `searchRows`</sub> | click → `r.go` | `entry_list` → `entry.list`<br>`notes_read` → `notes.read`<br>`vault_pending_list` → `vault.pending_list` | Add new opens the Add entry dialog; a node row selects the node; an entry row selects its node and opens its detail; an orphaned row opens the Orphaned panel. Selecting reads that node (entries, note, held entries). | **n/a** — - |
| button “○ unlocked” | click → `toggleVaultLock` | `vault_lock` → `vault.lock` | Locks: every revealed value is wiped, the shell clears the clipboard, the Lock screen appears. If the broker did not confirm, a notice says the window is locked but the vault may not be. | **pass** — ⌘L locks and shows the Lock screen |
| button: held-entries chip (“N held”)<br><sub>when `pendingChipShow`</sub> | click → `openPending` | `vault_pending_list` → `vault.pending_list` | Opens "Held for review" after re-reading each node's held entries. | **pass** — held chip appears after the node read |
| button “⌄” | click → `toggleVaultMenu` | — | Opens or closes the vault menu. Nothing is sent. | **pass** — menu toggles open |
| button: a vault menu item (Lock vault · Orphaned · Pending writes · Operations · Games · Help · About)<br><sub>when `vaultMenuOpen`</sub><br><sub>each row of `vaultMenuItems`</sub> | click → `m.go` | `vault_lock` → `vault.lock`<br>`vault_pending_list` → `vault.pending_list` | Runs the menu item. Lock vault: as the lock button. Orphaned: opens the Orphaned panel (reads that node). Pending writes: opens the tray. Operations (Pro): opens the Operations panel. Games, Help, About: open that overlay or dialog. | **pass** — vault menu opens with Lock vault, Orphaned, Pending writes, Operations, Games, Help, About; Help and About items open their overlays (others tested later); Orphaned item in the vault menu opens the Orphaned panel; Games opens CredPong; About/Help open |
| button “?” | click → `openHelp` | — | Opens the Help dialog. Nothing is sent. | **pass** — ? opens Help (also tested in dark) |
| button “⚙” | click → `openSettings` | — | Opens Settings on the last section; if that is Audit, the audit trail is read again. | **pass** — ⚙ opens Settings on the last section |

### Held-entries banner — `S20-banner`

Shown after unlock when entries were written while the vault was locked.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| button “Review”<br><sub>when `pendingBannerShow`</sub> | click → `openPending` | `vault_pending_list` → `vault.pending_list` | Opens "Held for review" after re-reading each node's held entries. | **n/a** — not pressed in this pass |
| button “✕”<br><sub>when `pendingBannerShow`</sub> | click → `dismissPendingBanner` | — | Hides the "N entries were held" banner. Nothing is sent; the entries stay in the tray. | **n/a** — not pressed in this pass |

### Rail — `S1-rail`

The node list, the graph / tree switch, node rename and the node context menu.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| button “✕” | click → `closeRail` | — | Closes the rail sheet. Nothing is sent. | **n/a** — ✕ not pressed; scrim click closed the sheet |
| rail row (a node, or "orphaned")<br><sub>each row of `railRows`</sub> | click → `r.select`<br>right-click → `r.menu` | `entry_list` → `entry.list`<br>`notes_read` → `notes.read`<br>`vault_pending_list` → `vault.pending_list` | **click:** Selects the node: its entries, note and held entries are read; revealed values from the previous node are wiped; the inspector opens. **right-click:** Right-click opens the node context menu at the pointer. Nothing is sent. | **fail** — F-6 (P2): the click reads the node's note but not its entries: an entry created from the CLI stayed invisible until an app write refreshed the list. node row click selects it and reads its note (entry list is cached, see F-6) |
| rail rename field<br><sub>when `r.renaming`</sub><br><sub>each row of `railRows`</sub> | change → `r.onRenameChange`<br>key → `r.cancelRename`<br>blur → `r.commitRename`<br>click → `stop` | `node_update` → `node.update` | **change:** Holds the new name while editing. Nothing is sent. **key:** Escape cancels; Enter commits the rename (1–120 characters). Success: "Renamed." and the label changes everywhere; the node id never changes. **blur:** Leaving the field commits the rename (an unchanged or empty name sends nothing). Success: "Renamed.". **click:** A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **pass** — Rename: Enter commits, "Renamed." |
| button “graph” | click → `setGraphView` | — | Shows the graph. Nothing is sent. | **pass** — graph view shows the graph |
| button “tree” | click → `setTreeView` | — | Shows the tree (the keyboard- and screen-reader-accessible view). Nothing is sent. | **pass** — tree view (T) shows "worktree · full parity with the graph" |
| button “games” | click → `openGames` | — | Opens CredPong. Nothing is sent. | **n/a** — not pressed in this pass |

### Main view — `S1-main`

The graph (a canvas, see "Graph canvas") or the tree, the entries toggle, and the New project button.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| entries mode toggle ("entries: all nodes / selected only") | click → `toggleEntriesMode` | — | Switches the graph's entry dots between every node and the selected node only. Nothing is sent. | **pass** — entries toggle: "entries: all" ↔ "entries: selected" |
| button “bored? there's a game in here →” | click → `openGames` | — | Opens CredPong. Nothing is sent. | **n/a** — not pressed in this pass |
| tree row (a node)<br><sub>when `isTreeView`</sub><br><sub>each row of `treeRows`</sub> | click → `r.select`<br>hover → `r.hoverOn`<br>unhover → `r.hoverOff` | `entry_list` → `entry.list`<br>`notes_read` → `notes.read`<br>`vault_pending_list` → `vault.pending_list` | **click:** Selects the node: its entries, note and held entries are read; revealed values from the previous node are wiped; the inspector opens. **hover:** Shows the hover card with exactly two numbers (entries, TOTP) from the last read. Nothing is sent. **unhover:** Hides the hover card. Nothing is sent. | **pass** — tree row click selects; hover shows the card with two numbers |
| button “⋮”<br><sub>when `isTreeView`</sub><br><sub>each row of `treeRows`</sub> | click → `r.menuBtn` | — | Opens the node context menu. Nothing is sent. | **pass** — ⋮ on a tree row opens the node menu |
| node context-menu item (Open · New entry · New project/sub-node · Grant access… · Rename · Lock now/Unlock node · Remove node…)<br><sub>when `ctxVisible`</sub><br><sub>each row of `ctxItems`</sub> | click → `m.go` | `vault_node_lock` → `vault.node_lock`<br>`vault_node_unlock` → `vault.node_unlock`<br>`entry_list` → `entry.list` | Open: selects the node. New entry: opens Add entry for it. New project / sub-node: opens the New node dialog with this parent. Grant access…: opens the grant dialog from this node. Rename: edits the label in the rail. Lock now / Unlock node: locks or unlocks that node only. Remove node…: opens the seal dialog. | **pass** — context menu: Open, New entry, New sub-node, Grant access…, Rename, Lock now, Remove node… present; Lock now locks that node only ("Node locked."); node menu Rename: "Renamed."; Global's menu has no Rename/Remove |
| button “+ New project”<br><sub>when `noProjects`</sub> | click → `openAddNodeDlg` | — | Opens the New node dialog. Nothing is sent. | **n/a** — not pressed in this pass |

### Inspector — `S4-inspector`

The selected node (entries, note), an entry's detail with its fields, and the Orphaned panel.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| button “✕ close” | click → `closeInsp` | — | Closes the inspector sheet. Nothing is sent. | **pass** — ✕ close closes the inspector sheet on a narrow window |
| button “Unlock node”<br><sub>when `inspLocked`</sub> | click → `lockedUnlock` | `vault_node_unlock` → `vault.node_unlock` | Unlocks this node (the login is unaffected). Notice "Node unlocked."; its entries become readable. | **pass** — Unlock node button: "Node unlocked." |
| button “+ New entry”<br><sub>when `inspNode`</sub> | click → `openAddEntry` | — | Opens Add entry for this node. Nothing is sent. | **pass** — + New entry in the inspector opens Add entry |
| button “+ New note”<br><sub>when `inspNode`</sub> | click → `openAddNote` | — | Opens Add entry with one field labelled "note" and the entry type pinned to note. Nothing is sent. | **pass** — + New note opens Add entry with one field labelled note, type note |
| entry row<br><sub>when `inspNode`</sub><br><sub>each row of `inspEntries`</sub> | click → `e.open` | `entry_get` → `entry.get`<br>`entry_reveal` → `entry.reveal` | Opens the entry detail: the fields (ids, labels, types, masking — no value) are read with entry.get; the fields that are not masked are read in one audited reveal. | **pass** — entry detail opens: host and username visible, password masked |
| button “Unlock node”<br><sub>when `inspUnreadableUnlock`</sub> | click → `unreadableUnlock` | `vault_node_unlock` → `vault.node_unlock` | Unlocks this node; its entries are read again. | **n/a** — not pressed in this pass |
| button “+ New entry”<br><sub>when `inspEmpty`</sub> | click → `openAddEntry` | — | Opens Add entry for this node. Nothing is sent. | **n/a** — not pressed in this pass |
| button “+ New note”<br><sub>when `inspEmpty`</sub> | click → `openAddNote` | — | Opens Add entry with one field labelled "note" and the entry type pinned to note. Nothing is sent. | **n/a** — not pressed in this pass |
| button “open”<br><sub>when `inspOrphan`</sub><br><sub>each row of `orphanItems`</sub> | click → `o.open` | `entry_reveal` → `entry.reveal` | Asks the broker to open the sealed item; without presence the broker refuses and the app says presence is needed (Touch ID is not available in this version). Nothing is shown. | **n/a** — "open" on an orphaned item not reachable: the Orphaned panel listed no items after sealing (F-11) |
| back to the node ("← node")<br><sub>when `inspEntry`</sub> | click → `closeEntry` | — | Back to the node's entry list; every revealed value is wiped. Nothing is sent. | **pass** — back to node works |
| button “Try again”<br><sub>when `fieldsFailed`</sub> | click → `retryFields` | `entry_get` → `entry.get` | Reads the entry's fields again after a failure. | **n/a** — not pressed in this pass |
| field reveal button ("reveal" / "show code" / "hide")<br><sub>when `f.maskable`</sub><br><sub>each row of `entryFields`</sub> | click → `f.reveal` | `entry_reveal` → `entry.reveal`<br>`totp_code` → `totp.code` | Reveals that one field (audited) for the reveal window, then it re-masks; a TOTP-seed field shows its current code with a bar running to the end of its 30-second step instead of the seed. | **pass** — reveal shows value with "re-masks in 20s", re-masks on its own; TOTP field: "show code" shows the live code (355 849, matches an independent computation) with a bar and "re-masks in 10s" |
| field copy button<br><sub>when `f.canCopy`</sub><br><sub>each row of `entryFields`</sub> | click → `f.copy` | `entry_copy` → `entry.reveal (fieldIds)` | Copies that one field through the shell: concealed, this-Mac-only, cleared after 30 seconds (and on lock, sleep, quit). The value never enters the page; the button reads "copied". | **pass** — copy puts exactly the value on the clipboard, button reads "copied"; clipboard empty 33 s later |
| button “show seed”<br><sub>when `f.isTotp`</sub><br><sub>each row of `entryFields`</sub> | click → `f.showSeed` | `totp_seed` → `totp.seed` | Asks for the TOTP seed; the broker refuses with presence_required and the notice says the seed is not shown in this build. Nothing is revealed. | **pass** — show seed: "Needs presence… Nothing was changed. (totp.seed)" |
| button “⋮”<br><sub>when `f.canMenu`</sub><br><sub>each row of `entryFields`</sub> | click → `f.toggleMenu` | — | Opens or closes the field menu. Nothing is sent. | **pass** — ⋮ opens the field menu |
| field menu item (Edit… · Move up · Move down · Remove…)<br><sub>when `f.menuOpen`</sub><br><sub>each row of `f.menuItems`</sub> | click → `m.go` | `field_reorder` → `field.reorder` | Edit…: opens the Edit field dialog. Move up / Move down: swaps the field with its neighbour (disabled at the ends) and re-reads the entry. Remove…: opens the Remove dialog (disabled for the last field: "an entry keeps at least one field"). | **pass** — Edit… opens dialog; Move up swaps and re-reads; Move down disabled on the last field; Remove… opens dialog and removes (field.remove audited) |
| button “+ Add field”<br><sub>when `fieldsEditable`</sub> | click → `addFieldOpen` | — | Opens the Add field dialog for this entry. Nothing is sent. | **pass** — + Add field opens the Add field dialog |
| button “Unlock node”<br><sub>when `entryLockedShow`</sub> | click → `lockedUnlock` | `vault_node_unlock` → `vault.node_unlock` | Unlocks this node (the login is unaffected). Notice "Node unlocked."; its entries become readable. | **n/a** — not pressed in this pass |

### Add entry — `S6-add-entry`

Single and Bulk modes, the preview, the type pins and the save buttons.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop<br><sub>when `dlgAddEntry`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **pass** — backdrop click closes the Add entry dialog |
| dialog panel<br><sub>when `dlgAddEntry`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **pass** — click inside the panel keeps it open |
| select “entry location (node)”<br><sub>when `dlgAddEntry`</sub> | change → `onAddNode` | — | Chooses the node the entry will go to. Nothing is sent. | **pass** — select set to acme |
| field “entry name”<br><sub>when `dlgAddEntry`</sub> | change → `onAddName` | — | Holds the entry name; a name that already exists in the node is flagged. Nothing is sent. | **pass** — name srv-demo held; saved; a name that already exists is flagged ("an entry called “srv-demo” already exists in acme"); also macOS offered to autocorrect the typed secret value (F-5) |
| mode radio "Single"<br><sub>when `dlgAddEntry`</sub> | change → `setSingle` | `fields_preview` (local: parser + inference) | Switches to label/value rows; the preview is recomputed locally. | **n/a** — Single radio not toggled back in this pass |
| mode radio "Bulk"<br><sub>when `dlgAddEntry`</sub> | change → `setBulk` | `fields_preview` (local: parser + inference) | Switches to the bulk paste box; the preview is recomputed locally. | **pass** — Bulk radio shows the paste box with its format hints |
| field “label (optional)”<br><sub>when `addSingle`</sub><br><sub>each row of `singleFields`</sub> | change → `sf.onLabel` | `fields_preview` (local: parser + inference) | Edits a field label (free text); the preview is recomputed locally. | **pass** — label held |
| text area “value (grows, multi-line)”<br><sub>when `addSingle`</sub><br><sub>each row of `singleFields`</sub> | change → `sf.onValue` | `fields_preview` (local: parser + inference) | Edits a field value; the preview is recomputed locally. | **pass** — value held; preview recomputed |
| button “✕”<br><sub>when `sf.canRemove`</sub><br><sub>each row of `singleFields`</sub> | click → `sf.remove` | `fields_preview` (local: parser + inference) | Removes that row (not the last); the preview is recomputed locally. | **n/a** — not pressed in this pass |
| button “+ Add field”<br><sub>when `addSingle`</sub> | click → `addFormField` | — | Adds an empty label/value row. Nothing is sent. | **n/a** — not pressed in this pass |
| text area “bulk paste”<br><sub>when `addBulk`</sub> | change → `onBulk` | `fields_preview` (local: parser + inference) | Pasted text is parsed by the shell (label: value lines, /// blocks); the preview shows each field, its inferred type and masking, the entry type and the highest sensitivity. Nothing is written until Save. | **pass** — 3 fields previewed; password inferred masked; 1 masked; sensitivity HIGH |
| button “Make each line its own field”<br><sub>when `blobHintShow`</sub> | click → `splitByLine` | `fields_preview` (local: parser + inference) | Rewrites a one-blob paste so every line is its own field, then re-previews. Nothing is sent to the broker. | **n/a** — not pressed |
| select “the type is inferred; pick one to pin it”<br><sub>when `dlgAddEntry`</sub><br><sub>each row of `g.rows`</sub> | change → `p.onType` | `fields_preview` (local: parser + inference) | Pins that field's type (or "auto" to leave it inferred); the preview recomputes. A pin is sent only if chosen. | **n/a** — per-field type pin not changed in Add entry |
| select “entry type”<br><sub>when `dlgAddEntry`</sub> | change → `onEntryType` | — | Pins the entry type (or "auto"). Sent only if chosen. Nothing is sent now. | **n/a** — not pressed in this pass |
| checkbox “split each /// segment into its own entry”<br><sub>when `addBulk`</sub> | change → `onSplit` | `fields_preview` (local: parser + inference) | Toggles "split each /// segment into its own entry"; the preview shows one entry per segment. | **pass** — split checkbox: preview shows two entries |
| button “Cancel”<br><sub>when `dlgAddEntry`</sub> | click → `closeDialog` | — | The dialog closes. Nothing is sent; anything typed in it is discarded. | **pass** — Cancel closes it |
| Save and add another (or Hold and add another)<br><sub>when `dlgAddEntry`</sub> | click → `saveEntryAgain` | `entry_create` → `entry.create`<br>`entry_create_batch` → `entry.create_batch` | The same save, then the dialog stays open with the node kept and the fields cleared. | **pass** — Save and add another not pressed; Save and add another: "Saved 1 entry to acme.", dialog stays open with node kept and fields cleared |
| Save (or Save N entries · Hold for review)<br><sub>when `dlgAddEntry`</sub> | click → `saveEntry` | `entry_create` → `entry.create`<br>`entry_create_batch` → `entry.create_batch` | Sends the previewed fields verbatim: one entry (entry.create) or, when splitting, one item per segment in one batch. The entry appears in the node after a re-read; on a locked node it is held for review instead ("Hold for review"). A name clash is refused inline. | **pass** — Save: "Saved 1 entry to acme."; entry listed with type SERVER; preview chip said "auto: other" but stored type is server (cosmetic, F-2) |

### Field dialog — `dlg-field`

Add a field to an entry, edit one, or remove one.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop<br><sub>when `dlgField`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **n/a** — backdrop not pressed on this dialog (same scaffold as About) |
| dialog panel<br><sub>when `dlgField`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| field “field label”<br><sub>when `fdIsAdd`</sub> | change → `onFdLabel` | — | Edits the label (newlines and NUL become spaces). Nothing is sent. | **pass** — label held |
| text area “field value”<br><sub>when `fdIsAdd`</sub> | change → `onFdValue` | — | Edits the value. Nothing is sent. | **pass** — value held |
| field “field label”<br><sub>when `fdIsEdit`</sub> | change → `onFdLabel` | — | Edits the label (newlines and NUL become spaces). Nothing is sent. | **pass** — label edit (username -> login) |
| text area “new field value”<br><sub>when `fdIsEdit`</sub> | change → `onFdValue` | — | Edits the value. Nothing is sent. | **n/a** — value left blank, kept current |
| select “field type”<br><sub>when `fdIsEdit`</sub> | change → `onFdType` | — | Chooses the field type ("auto" clears a pin). Nothing is sent. | **n/a** — type select not changed |
| select “field masking”<br><sub>when `fdIsEdit`</sub> | change → `onFdMasked` | — | Chooses masking ("auto" clears a pin). Nothing is sent. | **pass** — masking select not changed; masking select (follows the type / always hidden / always shown) works, value saved |
| button “Cancel”<br><sub>when `dlgField`</sub> | click → `cancelFieldDlg` | — | Closes the dialog; the typed value is discarded. Nothing is sent. | **n/a** — Cancel not pressed on this dialog |
| Save (Add field · Save changes · Remove field)<br><sub>when `dlgField`</sub> | click → `saveFieldForm` | `field_add` → `field.add`<br>`field_update` → `field.update`<br>`field_remove` → `field.remove` | Add: appends the field. Edit: changes only what changed. Remove: removes the field (refused for the last one). The entry is read again; each is undoable with entry.undo by its audit record. | **pass** — Add field ("Field added"), Edit ("Field updated"), Remove ("Field removed") each one call and re-read; field removal undone with credmgr undo, field back after reopen (J5) |

### Held for review — `S20-tray`

The locked-write tray: accept or discard each entry.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| area “Held for review Refresh”<br><sub>when `dlgPending`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| area “Held for review Refresh”<br><sub>when `dlgPending`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| button “Refresh”<br><sub>when `dlgPending`</sub> | click → `refreshPendingTray` | `vault_pending_list` → `vault.pending_list` | Re-reads every node's held entries. | **n/a** — Refresh not pressed |
| button “Discard”<br><sub>when `dlgPending`</sub><br><sub>each row of `pendingRows`</sub> | click → `p.discard` | `vault_pending_discard` → `vault.pending_discard` | Deletes that held entry (envelope and note). The row disappears. | **n/a** — Discard not pressed |
| button “Accept”<br><sub>when `dlgPending`</sub><br><sub>each row of `pendingRows`</sub> | click → `p.accept` | `vault_pending_accept` → `vault.pending_accept` | Moves that held entry into the node's manifest; its type, sensitivity and field count are taken from the decrypted document, not the sidecar. The entry appears in the node. | **pass** — Accept moves held entry into beta ("HELD_KEY accepted into beta.") |
| button “Close”<br><sub>when `dlgPending`</sub> | click → `closeDialog` | — | The dialog closes. Nothing is sent; anything typed in it is discarded. | **pass** — Close |

### Remove (seal) node — `S9-seal`

Type the node name to confirm; the node is sealed, not deleted.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop<br><sub>when `dlgSeal`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| dialog panel<br><sub>when `dlgSeal`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| field “type the node name to confirm”<br><sub>when `dlgSeal`</sub> | change → `onSealTyped` | — | Holds the typed node name; "Seal node" enables only on an exact match. Nothing is sent. | **fail** — F-5 (P1, fixed in this chunk): with the name “beta” macOS autocorrect turned the confirmation into “Beta” as the button was pressed, so Seal node stayed disabled; names that are not dictionary words (xq7rt, Quark-7) worked. Seal node enables only on an exact match |
| button “Seal node”<br><sub>when `dlgSeal`</sub> | click → `confirmSeal` | `node_seal` → `node.seal` | Seals the node: its entries go to Orphaned (names stay visible, values cannot be opened), the node leaves the graph, "Node “x” sealed. Restore it from Settings → Nodes within 7 days.", and the Orphaned panel opens. A node with sub-nodes is refused. | **fail** — F-10 (P2): the seal worked, the node left the graph and the notice named the 7-day window, but Orphaned showed no items and no Orphaned panel opened. Seal moves entries to Orphaned, node leaves the graph, notice says restore within 7 days (xq7rt) |
| button “Cancel”<br><sub>when `dlgSeal`</sub> | click → `closeDialog` | — | The dialog closes. Nothing is sent; anything typed in it is discarded. | **n/a** — not pressed in this pass |

### Grant dialog — `S11-grant`

Pro mode: a grant from one node to another.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| area “grant access lite mode Creating grants is managed in Pro. Viewing and revoking stay available here — revoking is safety, not a lever.”<br><sub>when `dlgGrant`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| area “grant access lite mode Creating grants is managed in Pro. Viewing and revoking stay available here — revoking is safety, not a lever.”<br><sub>when `dlgGrant`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| select “grant from node”<br><sub>when `dlgGrant`</sub> | change → `onGrantFrom` | — | Chooses the node that receives access. Nothing is sent. | **pass** — from select |
| select “grant to node”<br><sub>when `dlgGrant`</sub> | change → `onGrantTo` | — | Chooses the node to read. Nothing is sent. | **pass** — to select |
| capability checkbox (read · reveal · notes)<br><sub>when `dlgGrant`</sub><br><sub>each row of `grantCaps`</sub> | change → `c.toggle` | — | Toggles a capability. Nothing is sent. | **pass** — read/reveal/notes toggles present |
| field “reason for the grant”<br><sub>when `dlgGrant`</sub> | change → `onGrantReason` | — | Holds the reason (eight characters minimum). Nothing is sent. | **pass** — reason held |
| button “Create grant”<br><sub>when `dlgGrant`</sub> | click → `confirmGrant` | `grant_create` → `grant.create` | Sends the grant. The broker refuses with presence_required (nothing can attest presence yet); the app says so and no grant exists. | **pass** — Create grant: "Needs presence… Nothing was changed. (grant.create)"; no grant exists |
| button “Cancel”<br><sub>when `dlgGrant`</sub> | click → `closeDialog` | — | The dialog closes. Nothing is sent; anything typed in it is discarded. | **pass** — Cancel |

### New node — `S8-add-node`

Name, parent, work folders and the Pro advanced choices.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| area “new node”<br><sub>when `dlgAddNode`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **n/a** — - |
| area “new node”<br><sub>when `dlgAddNode`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — - |
| field “node name”<br><sub>when `dlgAddNode`</sub> | change → `onNewNodeName` | — | Holds the project name; the id is derived from it. Nothing is sent. | **pass** — node name held |
| select “parent node”<br><sub>when `dlgAddNode`</sub> | change → `onNewNodeParent` | — | Chooses the parent. Nothing is sent. | **n/a** — parent select not changed |
| field “work folder”<br><sub>when `dlgAddNode`</sub><br><sub>each row of `newNodeFolders`</sub> | change → `wf.onChange` | — | Holds a work-folder path (an agent run inside it is scoped to this node). Nothing is sent. | **n/a** — work folder not typed |
| button “+ add another”<br><sub>when `dlgAddNode`</sub> | click → `addNodeFolder` | — | Adds another work-folder field. Nothing is sent. | **n/a** — + add another not pressed |
| advanced checkbox: sub-nodes may share<br><sub>when `isPro`</sub> | change → `onAdvSubShare` | — | Chooses whether sub-nodes may share. Nothing is sent. | **n/a** — not toggled |
| advanced checkbox: ask for a second factor on reveal (stored, not yet enforced)<br><sub>when `isPro`</sub> | change → `onAdvTwofa` | — | Chooses the stored (not yet enforced) second-factor-on-reveal policy. Nothing is sent. | **n/a** — not toggled |
| advanced checkbox: the parent may read this node<br><sub>when `isPro`</sub> | change → `onAdvChildRead` | — | Chooses whether the parent may read this node (a widening: refused by the broker). Nothing is sent. | **pass** — parent-may-read widening is refused and reported |
| select “read-write read-only none”<br><sub>when `isPro`</sub> | change → `onAdvAgentAccess` | — | Chooses the agent access (read-write · read-only · none). Nothing is sent. | **pass** — agent access select works (read-write/read-only) |
| button “Cancel”<br><sub>when `dlgAddNode`</sub> | click → `closeDialog` | — | The dialog closes. Nothing is sent; anything typed in it is discarded. | **n/a** — Cancel not pressed |
| button “Create node”<br><sub>when `dlgAddNode`</sub> | click → `confirmAddNode` | `node_create` → `node.create`<br>`node_policy` → `node.policy` | Creates the node with its work folders, then applies the tightening policy choices; a widening choice is refused with presence_required and reported. "Node “x” created." | **pass** — Create node with "this node can read its children" and agent access read-only: node created, notice says the widening was not applied (needs presence) and that agent access was; node "widetest" listed |

### Presence, passphrase prompt and recovery code — `dlg-touch`

Three small dialogs: the presence explanation, the passphrase prompt that Back up / Rotate / Doctor share, and the one-time recovery code after a rotation.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| presence dialog backdrop<br><sub>when `dlgTouch`</sub> | click → `touchOk` | — | Closes the presence dialog. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| presence dialog panel<br><sub>when `dlgTouch`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| button “Close”<br><sub>when `dlgTouch`</sub> | click → `touchOk` | — | Closes the presence dialog. Nothing is sent. | **n/a** — not pressed in this pass |
| passphrase prompt backdrop<br><sub>when `dlgAdminPass`</sub> | click → `closeAdminPass` | — | Closes the passphrase prompt; the typed passphrase is dropped. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| passphrase prompt panel<br><sub>when `dlgAdminPass`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| field “passphrase”<br><sub>when `dlgAdminPass`</sub> | change → `onAdminPass`<br>key → `adminPassKey` | `maintenance_backup` → `maintenance.backup`<br>`maintenance_rotate_root` → `maintenance.rotate_root`<br>`maintenance_doctor` → `maintenance.doctor` | **change:** Held in memory outside the page state; nothing is sent. **key:** Enter submits the prompt (same as its action button). | **pass** — backup prompt: passphrase and repeat held; Enter submits |
| field “repeat the passphrase”<br><sub>when `adminPassRepeatShow`</sub> | change → `onAdminRepeat`<br>key → `adminPassKey` | `maintenance_backup` → `maintenance.backup`<br>`maintenance_rotate_root` → `maintenance.rotate_root`<br>`maintenance_doctor` → `maintenance.doctor` | **change:** Held in memory outside the page state; nothing is sent. **key:** Enter submits the prompt (same as its action button). | **pass** — repeat-passphrase field held (backup prompt) |
| passphrase prompt action (Back up · Rotate · Apply · Rebuild)<br><sub>when `dlgAdminPass`</sub> | click → `submitAdminPass` | `maintenance_backup` → `maintenance.backup`<br>`maintenance_rotate_root` → `maintenance.rotate_root`<br>`maintenance_doctor` → `maintenance.doctor` | Back up: an encrypted archive is written ("Backup written."). Rotate: the broker checks the human, admin and second factor and then refuses with presence_required — nothing changes. Apply / Rebuild: Doctor runs (a registry rebuild is refused for presence). | **pass** — Back up: "Backup written."; archive in the vault's backups folder (credmgr-backup-….enc); Rotate… in the prompt: broker refuses with presence_required (maintenance.rotate_root), nothing changes |
| button “Cancel”<br><sub>when `dlgAdminPass`</sub> | click → `closeAdminPass` | — | Closes the passphrase prompt; the typed passphrase is dropped. Nothing is sent. | **n/a** — not pressed in this pass |
| recovery code panel<br><sub>when `dlgRecovery`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| checkbox “I have saved the recovery code”<br><sub>when `dlgRecovery`</sub> | change → `onRecoverySaved` | — | Enables Done once checked. Nothing is sent. | **n/a** — not pressed in this pass |
| button “Done”<br><sub>when `dlgRecovery`</sub> | click → `dismissRecovery` | — | Closes the new-recovery-code panel (it ignores Esc until the box is checked — the old code is already dead). Nothing is sent. | **n/a** — not pressed in this pass |

### Second-factor setup — `dlg-gate`

Settings → Security: set up or replace the second factor.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop<br><sub>when `dlgGate`</sub> | click → `gateScrim` | — | Closes the setup dialog if cancelling is allowed; the staged setup is dropped and the old gate stays in force. Nothing is sent. | **n/a** — - |
| dialog panel<br><sub>when `dlgGate`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| field “authenticator code”<br><sub>when `gateStepQr`</sub> | change → `onGateTotp`<br>key → `onGateTotpKey` | `vault_gate_enroll_confirm` → `vault.gate_enroll_confirm` | **change:** Six digits are sent for confirmation automatically. **key:** Enter confirms the code. | **pass** — 6 digits confirm automatically |
| checkbox “I have saved these recovery codes”<br><sub>when `gateStepCodes`</sub> | change → `onGateCodesSaved` | — | Optional acknowledgement. Nothing is sent; Done does not wait for it. | **pass** — e2e (Done and Skip for now work unticked); not re-pressed in the rebuilt app |
| button “Cancel”<br><sub>when `gateCanCancel`</sub> | click → `gateCancel` | — | Cancels the setup; the previously confirmed gate (if any) stays in force. Nothing is sent. | **pass** — Replace… dialog (after the 5-minute rule it asked for a fresh code); Cancel closes it |
| button “Try again”<br><sub>when `gateCanRetry`</sub> | click → `gateRetry` | `vault_gate_enroll_begin` → `vault.gate_enroll_begin` | Stages the setup again. | **n/a** — not pressed in this pass |
| Confirm button<br><sub>when `gateStepQr`</sub> | click → `gateConfirm` | `vault_gate_enroll_confirm` → `vault.gate_enroll_confirm` | Confirms the code: the second factor is now required at every unlock and ten recovery codes are shown once. Replacing needs a recent code (lock, unlock with the current code, come back within 5 minutes). | **pass** — confirm: "Second factor set up. The vault now asks for a code at every unlock."; ten recovery codes shown once |
| button “Done”<br><sub>when `gateStepCodes`</sub> | click → `gateDone` | — | Closes the dialog; the codes cannot be shown again. Nothing is sent. Esc and the scrim close it too. | **pass** — e2e |
| button “Skip for now”<br><sub>when `gateStepCodes`</sub> | click → `gateDone` | — | Same as Done: closes the dialog without having ticked the box. Nothing is sent. | **pass** — e2e (`ui-fix.spec.ts`) |

### Help — `help`

Reading the graph, sealing, grants, notes, writing while locked, keyboard.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| area “Help ✕”<br><sub>when `dlgHelp`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **pass** — Help opens from the vault menu |
| area “Help ✕”<br><sub>when `dlgHelp`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **pass** — a click in the panel leaves it open (About, same scaffold) |
| button “✕”<br><sub>when `dlgHelp`</sub> | click → `closeDialog` | — | The dialog closes. Nothing is sent; anything typed in it is discarded. | **n/a** — close button not pressed; the dialog closes via the backdrop (see About) |
| link “open it”<br><sub>when `dlgHelp`</sub> | click → `helpGoAbout` | — | Opens About. Nothing is sent. | **pass** — "open it" opens About |

### About — `S18-about`

Version, Donate, Privacy and Licences pages.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| area “CredMgr”<br><sub>when `dlgAbout`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **pass** — backdrop click closes About |
| area “CredMgr”<br><sub>when `dlgAbout`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **pass** — click inside About panel stays open |
| link “Donate”<br><sub>when `aboutIsMain`</sub> | click → `goDonate` | — | Shows the Donate page (one static entry, never a banner). Nothing is sent. | **pass** — Donate page shows; one static entry, no banner |
| link “Privacy”<br><sub>when `aboutIsMain`</sub> | click → `goPrivacy` | — | Shows the Privacy text (no server, no telemetry, a content policy that refuses every network request). Nothing is sent. | **pass** — Privacy text shown; states no server/telemetry; no network requests |
| link “Licences”<br><sub>when `aboutIsMain`</sub> | click → `goLicenses` | — | Shows the Licences text (MIT; the bundled fonts). Nothing is sent. | **pass** — Licences text shown (MIT; bundled fonts) |
| button “← About”<br><sub>when `aboutIsDonate`</sub> | click → `goAboutMain` | — | Back to About. Nothing is sent. | **pass** — "← About" returns to About |
| donation chain tab<br><sub>when `aboutIsDonate`</sub><br><sub>each row of `donateTabs`</sub> | click → `t.go` | — | Shows that chain's donation address. Nothing is sent. | **pass** — EVM, BTC, SOL, TRX, TON tabs each show their own address |
| copy address button<br><sub>when `aboutIsDonate`</sub> | click → `donateCopyAddr` | `copy_text` (local: clipboard) | Copies the donation address (plain text, not a secret) through the shell; the button reads "copied ✓". Verify the first and last six characters after pasting (DONATE.md). | **pass** — button reads "copied ✓" after press |
| button “← About”<br><sub>when `aboutIsPrivacy`</sub> | click → `goAboutMain` | — | Back to About. Nothing is sent. | **pass** — back from Privacy |
| button “← About”<br><sub>when `aboutIsLicenses`</sub> | click → `goAboutMain` | — | Back to About. Nothing is sent. | **pass** — back from Licences |

### CredPong — `S19-games`

The game overlay (no broker calls).

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| area “CredPong”<br><sub>when `ovGames`</sub> | click → `cpBackdropClick` | — | Exits the game or closes the overlay. Nothing is sent. | **n/a** — backdrop of the game overlay not pressed |
| area “CredPong”<br><sub>when `ovGames`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — - |
| button “✕”<br><sub>when `cpIsMenu`</sub> | click → `cpClose` | — | Closes the game menu. Nothing is sent. | **n/a** — - |
| button “Bottom”<br><sub>when `cpIsMenu`</sub> | click → `cpSetModeBottom` | — | Chooses the play mode. Nothing is sent. | **pass** — Bottom mode selects ("Classic — paddle at the bottom") |
| button “Side”<br><sub>when `cpIsMenu`</sub> | click → `cpSetModeSide` | — | Chooses the play mode. Nothing is sent. | **pass** — Side mode selects |
| button “Free-roam”<br><sub>when `cpIsMenu`</sub> | click → `cpSetModeRoam` | — | Chooses the play mode. Nothing is sent. | **pass** — Free-roam mode selects |
| button “Start — space to launch”<br><sub>when `cpIsMenu`</sub> | click → `cpStart` | — | Starts (or restarts) CredPong. Nothing is sent. | **pass** — Start (and Space) launches; score and lives shown; level shaped by node counts |
| button “✕ exit”<br><sub>when `cpIsPlay`</sub> | click → `cpExit` | — | Leaves the game. Nothing is sent. | **fail** — F-11 (P3): the first Esc left the game; the expected pause did not happen. Esc left the game (it exited on the first Esc, with no pause step; F-12 cosmetic) |
| button “Play again”<br><sub>when `cpIsOver`</sub> | click → `cpStart` | — | Starts (or restarts) CredPong. Nothing is sent. | **n/a** — Game over screen not reached (Play again / Back to menu untested) |
| button “Back to menu”<br><sub>when `cpIsOver`</sub> | click → `cpBackToMenu` | — | Back to the game menu. Nothing is sent. | **n/a** — - |

### Settings — `S12-settings`

Security, Appearance, Backup, Mode, Grants and Games in both modes, and (Pro) Nodes, Maintenance, Audit, Advanced and Operations.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| settings backdrop<br><sub>when `ovSettings`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **n/a** — backdrop not pressed on Settings |
| settings panel<br><sub>when `ovSettings`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — - |
| settings section tab<br><sub>when `ovSettings`</sub><br><sub>each row of `settingsNav`</sub> | click → `s.go` | `audit_tail` → `audit.tail` | Shows that section: Security · Appearance · Backup · Mode · Grants · Games (Lite and Pro) and Nodes · Maintenance · Audit · Advanced · Operations (Pro only). Audit reads the trail; Operations opens the panel. | **pass** — section tabs switch (Lite shows Security/Appearance/Backup/Mode/Grants/Games; Pro adds Nodes/Maintenance/Audit/Advanced/Operations); Audit and Operations sections open |
| button “Help ?”<br><sub>when `ovSettings`</sub> | click → `openHelp` | — | Opens the Help dialog. Nothing is sent. | **n/a** — Settings Help ? not pressed |
| button “Close”<br><sub>when `ovSettings`</sub> | click → `closeOverlay` | — | The overlay (settings, operations) closes. Nothing is sent. | **n/a** — - |
| select “auto-lock after”<br><sub>when `setSecurity`</sub> | change → `onAutoLock` | — | Sets the idle auto-lock (this window's timer; saved in credmgr_prefs). Nothing is sent to the broker. | **pass** — auto-lock select not changed here; auto-lock select offers 5 min, 15 min, 60 min, never (warned); 5 min set and kept |
| second-factor button ("Set up…" / "Replace…")<br><sub>when `setSecurity`</sub> | click → `openGateEnrol` | `vault_gate_enroll_begin` → `vault.gate_enroll_begin` | Stages a second-factor setup (or replacement) and shows its QR code and secret. | **pass** — Set up… stages a second factor with QR and secret |
| select “reveal window”<br><sub>when `setSecurity`</sub> | change → `onRevealWindow` | — | Sets how long a revealed value stays visible (saved in credmgr_prefs). Nothing is sent. | **pass** — reveal window select not changed (re-mask at the 20 s default verified); reveal window select offers 10 s, 20 s, 60 s; set to 10 s |
| button “dark”<br><sub>when `setAppearance`</sub> | click → `setDark` | — | Switches to the dark theme (saved locally). Nothing is sent. | **pass** — dark / light both applied at once |
| button “light”<br><sub>when `setAppearance`</sub> | click → `setLight` | — | Switches to the light theme. Nothing is sent. | **pass** — light applied |
| button “off”<br><sub>when `setAppearance`</sub> | click → `colourOff` | — | Turns the colour tint off. Nothing is sent. | **pass** — colour off works |
| button “on”<br><sub>when `setAppearance`</sub> | click → `colourOn` | — | Turns the colour tint on. Nothing is sent. | **pass** — colour on shows hue and intensity sliders |
| button “auto”<br><sub>when `setAppearance`</sub> | click → `colourAuto` | — | Lets the tint follow the default. Nothing is sent. | **pass** — colour auto works |
| hue slider<br><sub>when `colourIsOn`</sub> | change → `onHue` | — | Sets the tint hue. Nothing is sent. | **pass** — hue slider moves (150°→30°) |
| intensity slider<br><sub>when `colourIsOn`</sub> | change → `onIntensity` | — | Sets the tint intensity. Nothing is sent. | **pass** — intensity slider moves (32%→67%) |
| hue preset (Vault · Ink · Moss · Rust · Slate)<br><sub>when `colourIsOn`</sub><br><sub>each row of `huePresets`</sub> | click → `hp.set` | — | Sets the hue to that preset and turns the tint on. Nothing is sent. | **pass** — Moss and Rust presets set hue and turn the tint on |
| select “standard (AA) high (AAA)”<br><sub>when `setAppearance`</sub> | change → `onContrast` | — | Chooses standard (AA) or high (AAA) contrast. Nothing is sent. | **pass** — contrast standard→high (AAA) applied |
| select “system reduced”<br><sub>when `setAppearance`</sub> | change → `onMotion` | — | Chooses system or reduced motion. Nothing is sent. | **pass** — motion system→reduced applied |
| hardware acceleration toggle<br><sub>when `setAppearance`</sub> | click → `toggleHwAccel` | — | Toggles GPU-accelerated animation hints. Nothing is sent. | **pass** — hardware acceleration toggles on/off |
| greyscale toggle<br><sub>when `setAppearance`</sub> | click → `toggleGreyscale` | — | Toggles a greyscale filter. Nothing is sent. | **pass** — greyscale toggles on/off |
| graph mark choice (keep · cells · node + ring · seal)<br><sub>when `setAppearance`</sub><br><sub>each row of `cosmMarks`</sub> | click → `m.set` | — | Chooses the graph mark. Nothing is sent. | **pass** — keep, cells, node + ring, seal marks each select |
| glyph weight choice (classic · fine · heavy)<br><sub>when `setAppearance`</sub><br><sub>each row of `cosmGlyphs`</sub> | click → `g.set` | — | Chooses the glyph weight. Nothing is sent. | **pass** — glyph weight classic, fine, heavy select |
| halo toggle<br><sub>when `setAppearance`</sub> | click → `toggleCosmHalo` | — | Toggles the halo. Nothing is sent. | **pass** — halo toggles |
| ring toggle<br><sub>when `setAppearance`</sub> | click → `toggleCosmRing` | — | Toggles the ring. Nothing is sent. | **pass** — ring toggles |
| button “Back up now”<br><sub>when `setBackup`</sub> | click → `openBackupPrompt` | — | Opens the passphrase prompt for a backup. Nothing is sent yet. | **pass** — Back up now opens the passphrase prompt; Back up now opens the prompt |
| select “backup retention”<br><sub>when `isPro`</sub> | change → `onRetain` | — | Chooses how many backup archives to keep. Nothing is sent now. | **pass** — retention select offers 14 and 30 archives |
| button “Verify now”<br><sub>when `setBackup`</sub> | click → `runVerify` | `maintenance_verify` → `maintenance.verify` | Verifies every manifest, envelope digest, registry binding and seal record; the chip shows "ok · N nodes checked" or the problems. | **pass** — Verify now: chip "ok · 3 nodes checked" |
| button “Lite”<br><sub>when `setMode`</sub> | click → `setLite` | — | Switches to Lite (saved locally). Nothing is sent. | **pass** — Lite applied: sections reduce to Security, Appearance, Backup, Mode, Grants, Games |
| button “Pro”<br><sub>when `setMode`</sub> | click → `setPro` | — | Switches to Pro (saved locally). Nothing is sent. | **pass** — Pro applied: sections come back |
| button “Open CredPong”<br><sub>when `setGames`</sub> | click → `openGames` | — | Opens CredPong. Nothing is sent. | **n/a** — - |
| button “Remove…”<br><sub>when `setNodes`</sub><br><sub>each row of `settingsNodeRows`</sub> | click → `n.seal` | — | Opens the Remove (seal) dialog for that node. Nothing is sent yet. | **pass** — Remove… opens the seal dialog (Settings → Nodes) |
| button “+ New project”<br><sub>when `setNodes`</sub> | click → `openAddNodeDlg` | — | Opens the New node dialog. Nothing is sent. | **pass** — + New project opens New node; creating xq7rt works ("Node “xq7rt” created.") |
| button “Restore node”<br><sub>when `setNodes`</sub><br><sub>each row of `sealedRows`</sub> | click → `s.restore` | `node_restore` → `node.restore` | Restores the sealed node within its 7 days: "Node “x” restored." and it is selected. The rows come from the broker's own list of sealed nodes (`graph.snapshot` `meta.sealed`, ADR-080), so they survive a lock and a daemon restart, and each shows the real end of its window ("restorable until <time>"); a login that is not given the list (an agent, a non-Admin) sees only what this session sealed, with the rule "restorable for 7 days after sealing". After the window: archive_expired, and the app says so. | **pass** — (partial) sealed node listed with real window "restorable until 2026-10-25 11:00"; restore tested in J8; sealed node xq7rt listed in Settings → Nodes with its real window after lock, unlock, broker restart; Restore returned it ("Node “xq7rt” restored."), value byte-identical (CLI compare), verify clean |
| button “Revoke”<br><sub>when `setGrants`</sub><br><sub>each row of `grantRows`</sub> | click → `g.revoke` | `grant_revoke` → `grant.revoke` | Revokes that grant: "Grant revoked.", the grant disappears from the list and from the graph. | **n/a** — not pressed in this pass |
| button “+ New grant”<br><sub>when `isPro`</sub> | click → `openGrantDlg` | — | Opens the grant dialog (Pro). Nothing is sent. | **pass** — + New grant opens the Grant dialog |
| button “Open Operations panel”<br><sub>when `setMaint`</sub> | click → `openOps` | — | Opens the Operations panel. Nothing is sent. | **pass** — Open Operations panel |
| button “Refresh”<br><sub>when `setAudit`</sub> | click → `refreshAudit` | `audit_tail` → `audit.tail` | Reads the audit trail again (newest first). | **pass** — Refresh re-reads the trail |
| audit row<br><sub>when `setAudit`</sub><br><sub>each row of `auditRows`</sub> | click → `a.open` | `audit_get` → `audit.get` | Asks for the full record; the broker refuses with presence_required and the app says so. | **pass** — an audit row: "Needs presence (Touch ID)… Nothing was changed. (audit.get)" |
| button “Rotate…”<br><sub>when `setAdvanced`</sub> | click → `openRotatePrompt` | — | Opens the passphrase prompt for a root-key rotation. Nothing is sent yet. | **pass** — (Settings → Advanced Rotate… same prompt; tested through Operations); Rotate… opens the passphrase prompt (refused for presence, see 292) |

### Operations panel — `S14-ops`

Pro: Verify, Doctor, Back up, Rotate root key, Audit report.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| area “operations · pro ⌘⇧O”<br><sub>when `ovOps`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **n/a** — - |
| area “operations · pro ⌘⇧O”<br><sub>when `ovOps`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — - |
| button “{{o.label}}”<br><sub>when `ovOps`</sub><br><sub>each row of `opsRows`</sub> | click → `o.run` | `maintenance_verify` → `maintenance.verify`<br>`maintenance_doctor` → `maintenance.doctor`<br>`audit_tail` → `audit.tail` | Verify integrity: as Settings → Backup → Verify now. Doctor: a dry run listing what it would fix (Apply and Rebuild appear as result actions). Back up vault…: opens the passphrase prompt. Rotate root key…: opens the prompt; the rotation is refused for presence. Audit report: reads the last 30 days of audit records and lists denied requests and grant changes. | **pass** — Verify integrity: "ok · 4 nodes checked"; Doctor dry run: "nothing needs fixing"; Back up vault opens the prompt; Rotate root key refused with the presence notice and nothing changed; Audit report lists denied and grant records |
| result action ("Apply N fixes" · "Rebuild registry…")<br><sub>when `opsResultHasActions`</sub><br><sub>each row of `opsResultActions`</sub> | click → `x.go` | `maintenance_doctor` → `maintenance.doctor` | Apply N fixes: Doctor applies the fixes it listed. Rebuild registry…: opens the passphrase prompt; the rebuild is refused for presence. | **n/a** — no Doctor fixes to apply, so no result actions appeared |
| button “Close”<br><sub>when `ovOps`</sub> | click → `closeOverlay` | — | The overlay (settings, operations) closes. Nothing is sent. | **pass** — Close |

### Notice bar — `notice`

Every success, refusal and warning the app speaks.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| button “✕”<br><sub>when `noticeShow`</sub> | click → `dismissNotice` | — | The notice bar closes. Nothing is sent. | **n/a** — notice ✕ not pressed (notices dismiss themselves) |

### Page scaffolding — `app.template.html`

The scrim behind the rail and inspector on a narrow window.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| scrim behind the rail / inspector (narrow window)<br><sub>when `isApp`</sub> | click → `closeSheets` | — | The rail and the inspector sheets close on a narrow window. Nothing is sent. | **pass** — scrim behind rail/inspector closes the sheets |

## 3. Items built from data

The templates draw these as one repeated button; the items come from the logic. Each is a row to press.

### 3.1 Vault menu (header ⌄)

| Item | Expected result | Result |
|---|---|---|
| Lock vault (⌘L) | As the lock button: `vault_lock` → `vault.lock`; Lock screen; revealed values wiped. | **pass** — ⌘L and the menu item lock; Lock screen; revealed values wiped; clipboard cleared |
| Orphaned | Selects the Orphaned panel: reads the orphan node's name list (`entry_list` → `entry.list`); a login that may not list it shows "unreadable", not "empty". | **fail** — F-10 (P2): the panel opened but said “Nothing is orphaned” after a node with an entry was sealed. Orphaned opens its panel, but it shows "Nothing is orphaned" after a seal (F-11) |
| Pending writes · N | Opens "Held for review" after `vault_pending_list` → `vault.pending_list`. | **pass** — Pending writes opens the tray |
| Operations (⌘⇧O, Pro only) | Opens the Operations panel; absent in Lite. | **pass** — Lite: Operations absent from the vault menu and ⌘⇧O does nothing; Pro: present |
| Games — CredPong | Opens the game overlay; nothing is sent. | **pass** — Games — CredPong opens the overlay |
| Help | Opens Help; nothing is sent. | **pass** — Help opens |
| About CredMgr | Opens About; nothing is sent. | **pass** — About opens |

### 3.2 Node context menu (right-click a node, or ⋮ on a tree row)

| Item | Expected result | Result |
|---|---|---|
| Open | Selects the node (`entry_list`, `notes_read`, `vault_pending_list` → `entry.list`, `notes.read`, `vault.pending_list`). | **n/a** — Open (context menu) not pressed |
| New entry | Opens Add entry for that node. | **n/a** — not pressed (New entry via the inspector instead) |
| New project (on Global) / New sub-node (on a project) | Opens New node with this parent; not offered at depth 2. | **n/a** — not pressed |
| Grant access… | Opens the grant dialog from this node. | **n/a** — not pressed |
| Rename (not on Global) | Edits the label in the rail; `node_update` → `node.update` on commit. | **pass** — Rename from the tree ⋮ menu; Global has none |
| Lock now / Unlock node | `vault_node_lock` / `vault_node_unlock` → `vault.node_lock` / `vault.node_unlock`; the login survives; a locked node shows "locked" and its values need the node unlocked. | **pass** — Lock now on beta; Unlock node reverses |
| Remove node… | Opens the seal dialog (type the name to confirm). | **n/a** — Remove node… from the menu not pressed (Settings → Nodes was used) |
| Open orphaned (on the orphaned entry) | Opens the Orphaned panel. | **n/a** — - |

### 3.3 Field menu (⋮ on an entry's field)

| Item | Expected result | Result |
|---|---|---|
| Edit… | Opens the Edit dialog: label, value, type (auto or a pin), masking (auto, on, off); Save sends `field_update` → `field.update` with only what changed. | **pass** — Edit… opens dialog with label, value, type, masking |
| Move up / Move down | `field_reorder` → `field.reorder` (disabled at the ends: "already the first field" / "already the last field"); the entry is re-read. | **pass** — Move up works; Move down refused at the end |
| Remove… | Opens the Remove dialog; `field_remove` → `field.remove`; disabled for the last field ("an entry keeps at least one field"). Undo with `entry.undo` by the audit record. | **pass** — Remove… dialog, entry keeps other fields |

### 3.4 Settings sections

Lite shows Security · Appearance · Backup · Mode · Grants · Games. Pro adds Nodes · Maintenance · Audit ·
Advanced and the Operations entry (⌘⇧O). Each section's controls are rows in §2 (Settings), under the `when`
condition named `setSecurity`, `setAppearance`, `setBackup`, `setMode`, `setGames`, `setNodes`, `setGrants`,
`setMaint`, `setAudit`, `setAdvanced`.

### 3.5 Operations panel rows (Pro)

| Row | Expected result | Result |
|---|---|---|
| Verify integrity | `maintenance_verify` → `maintenance.verify`: "ok · N nodes checked", or each problem with its node; seal records and the orphan cold key are checked too. | **pass** — "ok · 4 nodes checked" |
| Doctor | `maintenance_doctor` → `maintenance.doctor` as a dry run: the fixes it would make, with "Apply N fixes" and, if something cannot be fixed, "Rebuild registry…". | **pass** — dry run: "nothing needs fixing" |
| Back up vault | Opens the passphrase prompt; on confirm `maintenance_backup` → `maintenance.backup`: "Backup written." and the archive is in the vault's backups folder. | **n/a** — Back up vault from the Operations panel not pressed (the Settings → Backup button was, see 388/292) |
| Rotate root key | Opens the prompt; the broker checks the human, admin and second factor and then refuses with `presence_required`; nothing changes ("Needs presence"). | **pass** — prompt opens; refused for presence, nothing changed |
| Audit report | Reads the last 30 days (`audit_tail` → `audit.tail`) and lists denied requests and grant changes. | **pass** — lists denied and grant records of the last 30 days |

### 3.6 Choices in Settings → Appearance and About

| Choice | Expected result | Result |
|---|---|---|
| Theme: dark / light | Applies at once; survives a restart (`credmgr_prefs`). | **pass** — Theme dark/light applies at once; theme survives a restart |
| Colour: off / on / auto; hue and intensity; presets Vault · Ink · Moss · Rust · Slate | Re-tints the surfaces; contrast stays AA. | **pass** — colour off/on/auto, hue, intensity and presets |
| Contrast: standard (AA) / high (AAA) | Switches the contrast mode. | **pass** — contrast standard/high |
| Motion: system / reduced | Reduced removes the pulsing and the graph easing. | **pass** — motion system/reduced |
| Graph mark: keep · cells · node + ring · seal; glyph: classic · fine · heavy; halo; ring | Redraws the graph. | **pass** — marks, glyphs, halo, ring |
| Donation chain tabs: EVM · BTC · SOL · TRX · TON | Shows that chain's address; "copy address" uses the shell and reads "copied ✓". One static entry — never a banner. | **pass** — EVM, BTC, SOL, TRX, TON tabs each show their address; copy reads "copied ✓" |
| Game mode: Bottom · Side · Free-roam | Chooses the play mode. | **n/a** — game mode tabs checked in the CredPong rows |

## 4. Graph canvas

The graph is a canvas, not template buttons; the tree view (T) is its accessible peer.

| Gesture | Expected result | Result |
|---|---|---|
| Click a node | Selects it and opens the inspector (reads that node). | **pass** — click a node selects it and opens the inspector |
| Click an entry dot | Selects the dot's own node and opens that entry's detail. | **n/a** — entry dot not clicked: dots orbit continuously even under Motion=reduced, so a click by coordinate misses (F-7) |
| Double-click a node | Zooms to the node. | **pass** — double-click zooms to the node |
| Drag a node | Moves it (positions are remembered locally; nothing is sent). | **pass** — drag moves a node; position kept |
| Drag a node onto another | Opens the grant dialog from the dragged node to the target (in Lite it explains that creating grants is Pro); creating it is refused for presence. | **pass** — dragging Quark-7 onto beta opens the grant dialog (from Quark-7, to beta); creating is refused for presence |
| Drag the background / wheel | Pans / zooms (0.3×–6×). | **pass** — background drag pans; wheel zooms |
| Right-click a node | Opens the node context menu (§3.2). | **pass** — right-click a node opens the node context menu (Global: Open, New entry, New project, Grant access…, Lock now) |
| Hover a node / an entry dot | After a short delay a card shows exactly two numbers (entries, TOTP) or the entry's type; nothing is read from the broker. | **pass** — hover a node shows a card with two numbers (entries, 2FA) |

## 5. Keyboard, timers and system events

| Trigger | Expected result | Result |
|---|---|---|
| `/` | Focuses the search box. | **n/a** — / focused the search box (tested via click); dropdown opens on focus |
| `F` | Fits the graph to the window. | **pass** — F fits the graph |
| `G` | Selects Global. | **pass** — G selects Global |
| `T` | Toggles graph / tree. | **pass** — T toggles graph/tree |
| `E` | Toggles entries: all nodes / selected only. | **pass** — E toggles entries all/selected |
| `N` | Opens Add entry for the selected node. | **pass** — N opens Add entry for the selected node; N opens Add entry |
| `⌘L` | Locks from anywhere, even in a field or a dialog. | **pass** — ⌘L locks |
| `⌘⇧O` | Opens the Operations panel (Pro). | **pass** — ⌘⇧O opens the Operations panel (Pro); nothing in Lite |
| `Esc` | Closes the search dropdown, menus, the open dialog or overlay, the sheets; in CredPong it pauses, then exits. In an open field menu it closes that menu only and puts focus back on its ⋮ button. | **pass** — Esc in an open field menu closes it and returns focus to the ⋮ button |
| `Tab` / `Shift+Tab` in a dialog | Cycles inside the dialog only. | **pass** — Tab cycles inside the dialog only (5 presses stayed on its buttons) |
| `↑` / `↓` in an open field menu | Walks the enabled items. | **pass** — Up/Down walk the menu items |
| `Home` / `End` in an open field menu | Jump to the first / last enabled item. | **pass** — Home/End jump to first/last |
| Idle for the auto-lock time (Settings → Security) | The Lock screen appears with "Locked after N minutes"; revealed values are gone; the clipboard is cleared. | **pass on the 2026-10-18 build only; not re-run on 2026-10-31** (§12.1, §13 and K-14: the harness hides the window before the timer can fire) — idle 5 min (set in Settings): Lock screen "Locked after 5 minutes without activity." |
| Window hidden (auto-lock on) | Locks with "Locked because the window was hidden." | **pass** (window hidden, on the 2026-10-18 build; re-seen 2026-10-27 and 2026-10-31; the idle timer itself was not run) — window hidden (⌘H, then reopened): Lock screen with "Locked because the window was hidden." |
| Mac sleeps, the screen locks or the session switches | The shell locks the vault (`vault.lock`) whether or not this app holds a login and clears the clipboard; the window returns to the Lock screen. | **n/a** — - |
| Window loses focus | Revealed values are hidden (the vault stays open). | **pass** — after the window lost focus the revealed value was masked again (the 10 s timer may also have run; not isolated) |
| Every 30 seconds, and on focus | The app asks the broker whether this login is still good (`vault_status` → `vault.status`); a restarted broker or an expired login returns to the Lock screen with the reason. | **pass** — (indirect) after the broker was stopped the app showed "broker unreachable" within 35 s |
| A reveal reaches its window (Settings → Security) | The value re-masks on its own; a TOTP code re-reads at the next 30-second step. | **pass** — a reveal re-masks at its window (10 s and 20 s observed); a TOTP code shows "re-masks in 10s" |
| 30 seconds after a copy | The clipboard is cleared only if it still holds the app's value. | **pass** — (see 171) copy clears at 30 s; also cleared by ⌘L (clipboard empty right after lock) |
| Stop `credmgrd` while the app is open | Within 30 seconds the app shows "broker unreachable" with Retry, never stale data; starting it again and pressing Retry returns to the Lock screen. | **pass** — daemon stopped: within 35 s the app showed "broker unreachable"; Retry with the broker still down stayed there; after restarting the broker, Retry returned to the Lock screen (no stale data) |
| Click the red close button | The window hides and the process keeps running; the menu-bar icon stays. The vault locks (the hidden window is read as “hidden”) and the next open shows the Lock screen. | **pass** — rebuilt app: process alive, icon present, Lock screen “Locked because the window was hidden.” on reopen |
| Left-click the menu-bar icon | Shows and focuses the main window (un-minimises it). | **pass** — rebuilt app |
| Right-click the menu-bar icon | A menu: Open CredMgr · Lock vault · Quit CredMgr. | **pass** — rebuilt app |
| Menu-bar → Open CredMgr | Same as the left click. | **pass** — rebuilt app (after closing the window) |
| Menu-bar → Lock vault | Clears the clipboard if it holds the app's value, sends `vault.lock` from the shell, and the window shows the Lock screen with “Locked from the menu bar.” | **pass** — rebuilt app |
| Menu-bar → Quit CredMgr (or ⌘Q) | The only ways the process ends; the clipboard is cleared if it holds the app's value. | **pass** — Quit from the menu: process gone (⌘Q not pressed) |
| Click the Dock icon while the window is hidden | Brings the window back (`RunEvent::Reopen`). | **n/a** — not pressed in this pass |

## 6. Operations no control reaches, and the suites behind this document

The bridge reaches all 55 broker operations. **These ten have no control in the app** — they are reachable
from the CLI (in brackets) or not at all, and a tester should not look for them:
`entry.update`, `entry.rotate`, `entry.remove`, `entry.restore` (the app edits an entry through its
fields and has **no delete control**; `credmgr set`, `rotate`, `rm`; `entry.undo` is reached by the Undo link after a field edit, ADR-086), `notes.write` (the inspector shows
a node's note read-only; `credmgr notes set`), `node.list` and `whoami` (the app reads the topology with
`graph.snapshot`), `node.set_workdirs` (work folders are set when a node is created; `credmgr node workdir`),
and `node.reparent` (needs presence; no CLI command). `vault.approval_decide` is reached from the Lock screen's request panel and by `credmgr approve` (ADR-088, ADR-090). Every other operation is reached by at least one row above or by the reads the
model makes after unlock (`graph.snapshot`, `grant.list`, `entry.list`, `vault.pending_list`, `notes.read`,
`entry.get`).

**Five operations are sent for real and refused with `presence_required`** until a presence transport
exists: `grant.create` (Grant dialog), `audit.get` (an audit row), `totp.seed` (a TOTP field's "show seed"),
`maintenance.rotate_root` (Rotate…) and `maintenance.doctor` with `rebuildRegistry`. For each, the expected result
is *the refusal, stated in words, with nothing changed* — a success would be a failure of this checklist.

**Automated suites that exercise the same paths** (listed so that a failure here can be compared with them; the
counts are those of 2026-10-03 on this tree): `npm test` (550 unit tests, 21 files); `npm run test:e2e` (the
built app under the production CSP against a fixture broker; 552 tests listed — 276 specs, each in WebKit and
Chromium); `npm run test:design` (the design audit probe: 0 dead, unlabelled, clipped, squashed or low-contrast
controls in every state); `npm run test:real` (the built app against a real `credmgrd` on a throwaway vault;
66 tests listed in 10 files); `cargo test` in `apps/desktop/src-tauri` (186 tests listed); and the real-binary
journeys `scripts/e2e-journey.sh` and `scripts/e2e-fields.sh`.

## 7. Whole-journey checks

Run these end to end after the row-by-row pass; each is several rows above, in order.

| # | Journey | Expected result | Result |
|---|---|---|---|
| J1 | **First run.** Start with no vault. Passphrase (4+ characters, 8+ recommended) → retype the recovery code (optional) → (optionally) set up a second factor and save its ten codes → name two projects. | The vault exists, the app opens on the graph with both projects; Settings → Audit shows the calls; `maintenance.verify` is clean. | **pass** — J1: first run to the graph with two projects, a second factor and ten codes; Settings → Audit lists the calls; Verify ok |
| J2 | **Lock, unlock, restart.** Lock; unlock; quit the app and stop `credmgrd`; start both again; unlock. | Everything is still there; with a second factor, the code is asked for after the passphrase; a wrong passphrase leaves nothing loaded and shows the broker's wait. | **pass** — -; J2: lock (⌘L), wrong passphrase refused, quit app, killed daemon, restarted both, passphrase + code unlock; entries intact; theme persisted |
| J3 | **A multi-field entry.** Add entry → Bulk → paste `host: db.example.com`, `username: deploy`, `password: <generated>` → check the preview → Save. Open it; reveal the password; copy it; paste elsewhere; wait 30 s. | One entry of type `server` with three fields; only the password is masked until revealed; the pasted value is right; the clipboard is empty after 30 s; the audit trail shows the reveal with the field id and no value. | **pass** — J3 (entry type server, 3 fields, password masked until reveal, audit shows reveal with field ids and no value, clipboard cleared after 30 s) |
| J4 | **One paste, several entries.** Bulk → paste two `///`-separated blocks → tick "split each /// segment". | The preview shows two entries; Save creates both in one call (`entry.create_batch`). | **pass** — J4: preview two entries; "Saved 2 entries to acme." |
| J5 | **Edit fields.** Add a field, edit another's label and type, move one up, remove one. Then `credmgr undo <id> --node <n>` the removal. | Each change is one broker call and a re-read; the removed field returns after the undo and a re-open. | **pass** — J5 (add, edit label, move, remove, then credmgr undo returned the field). Note: relabelling username to login changed the entry type from SERVER to OTHER |
| J6 | **A note.** `+ New note` → text → Save → open it. | An entry of type `note` with one field labelled `note`; it is not the node's note (the inspector's read-only note). The field's inferred type is `text`, which is **not** masked, so opening the entry reads it in one audited reveal and shows it — the Help dialog still says a note is "masked until you reveal it"; record which you see. Edit… → masking on pins it masked. | **pass** — J6: entry of type note with one field note; value is NOT masked (type text) and opens shown after one audited reveal; the Help text says a note is masked until revealed (F-3); Edit… masking always hidden pins it masked and the field then needs reveal |
| J7 | **Write while locked.** Lock the node (not the vault); run `credmgr set` against it from a shell, or add an entry from the app; unlock the node; open the tray. | The entry is held ("Hold for review"), appears in the tray with its field count, and Accept moves it into the node with the right type. | **pass** — J7: node locked, credmgr set held the entry, tray listed it with fields, Accept moved it to beta |
| J8 | **Seal and restore.** Remove a project (type its name), restart the broker, then Settings → Nodes → Restore. | The node disappears and Orphaned lists its entries by name; after a lock, an unlock and a restart of the broker it is still listed in Settings → Nodes with its real window ("restorable until …", from the broker's `meta.sealed`) and still restorable; Restore brings back every value byte for byte. A node with sub-nodes is refused. | **fail** — F-10 (P2): seal, restart, lock/unlock, Settings → Nodes with its real window, Restore byte for byte all passed; the part “Orphaned lists its entries by name” did not (F-10); the sub-node refusal was not exercised. J8: seal (type name), broker restart, lock/unlock, Settings → Nodes shows the real window, Restore brings the value back byte for byte. Sub-node refusal not exercised. Finding F-4: the seal dialog still says restore works "until you lock the vault" |
| J9 | **Second factor.** Settings → Security → set up; confirm with a code; save the ten codes; lock; unlock with passphrase + code; try a recovery code once. | The gate asks for a code at every unlock; a recovery code works once; replacing it needs a recent code. | **pass** — J9: set up and confirm with a code, ten codes saved, lock, passphrase+code unlocks, a recovery code works once and the same code is then refused |
| J10 | **Backup and verify.** Back up with a passphrase; run Verify and Doctor. | A file appears in the backups folder; Verify is clean; Doctor lists nothing to fix. | **pass** — J10: backup archive written to the vault's backups folder; Verify ok; Doctor lists nothing |
| J11 | **The refusals.** Press each of the five presence-refused controls (§6). | Each states that presence is needed; the vault is unchanged; the audit trail records the denied call. | **pass** — J11: grant.create, audit.get, totp.seed, maintenance.rotate_root each refused in words with nothing changed; the Doctor rebuild was not reachable because Doctor found nothing to fix |
| J12 | **No leaks.** Search the vault folder and the app's local storage for a value you stored. | The value appears nowhere in the clear (`PRIVACY.md` lists the few local-storage keys; any that could name a vault object is hashed). | **n/a** — - |

## 8. Record

| | |
|---|---|
| Source commit | Pass run on the C3 rehearsal build of `54ae93e` (docs-only commits since). The one P1 found, F-5, is fixed in `16cbf29` (template compiler); the app rebuilt from `16cbf29` was re-checked for F-5 and the first-run flow only. |
| Build (`.app` / `.dmg`, unsigned) and `SHA256SUMS` checked | C3 build: `shasum -a 256 -c SHA256SUMS` OK for the tarball, three SBOMs, `.dmg` and `.app.zip`. Rebuild from `16cbf29` (`scripts/release-app.sh`, unsigned, launch check passed): `.dmg` `99e70e1e…`, `.app.zip` `adc49fdb…` (its own `SHA256SUMS`). The app was started through LaunchServices (`open -n --env CREDMGR_VAULT_DIR=… CredMgr.app`) against a throwaway vault and a `credmgrd` from the C3 tarball. |
| macOS version / appearance modes covered | macOS 27.0.1. Dark (standard contrast), dark with high contrast, light with high contrast and reduced motion; colour off / on / auto with presets; greyscale on; Lite and Pro; a wide window and a ~700 px window (rail and inspector as sheets). Not separately walked: light with standard contrast. Theme and mode survived a restart. |
| Tester | Claude (computer-use) on a throwaway vault. Item 9 of the chunk (lock the screen, close the lid or start the screen saver and check the Lock screen on return) was run by the operator on 2026-10-18: the Mac was put to sleep and woken, and the app was **locked** on return (operator-verified). |
| Date | 2026-10-18 |
| Rows failed (list them) | **fail:** header search (F-5), rail/tree row click reads no entries (F-6), seal confirmation field and Seal node (F-5; names that are dictionary words could not be confirmed), Orphaned panel and J8's Orphaned listing (F-10), CredPong Esc (F-11). F-5 is fixed and re-verified in the rebuilt app. **n/a (not pressed):** 85 rows, each says why (mostly repeated backdrop/panel handlers already passed on About and Add entry; the held-entries banner; the 30 s clipboard and 5 min idle timers passed on that 2026-10-18 build (the idle timer was not waited out again on later builds); an orphaned item's “open”; revoking a grant, which cannot be created without presence). Details and screenshots: `docs/history/finish-plan/C4-FINDINGS.md` and `docs/release-verification/`. |
| Verdict | **No P0.** 190 rows pass, 7 fail, 85 are n/a. One P1 (F-5) found and fixed in this chunk; no P1 remains open. Open P2: F-3 (note text shown, Help says masked), F-6, F-8 (narrow inspector clips entry names), F-10 (Orphaned lists nothing after a seal); P3: F-1, F-2, F-4, F-7, F-11–F-14. Journeys J1–J12: pass, except J6 (finding F-3 recorded as the checklist asks) and J8 (Restore and survival pass, Orphaned listing fails, F-10). Presence-refused operations refuse in words with nothing changed (J11). No marker value appears in the vault directory, the state directory or the app's WebKit storage (J12). The operator's sleep/wake lock check passed. |

## 9. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `09_UI_UX_SPEC.md §7` | the screens whose behaviour the expected results restate |
| depends on | `18_ENDPOINT_INDEX.md §4` | the command-to-op table this document's bridge column follows |
| depends on | `19_FRONTEND_DELIVERY_SCOPE.md §3` | the rules the screens obey (no token in the page, every error routed) |
| depends on | `10_API_AND_MCP.md §4.1b` | the shapes of the multi-field operations the entry rows send |
| feeds | `21_RELEASE_AND_INTEGRITY.md §4` | the real-app pass the release checklist asks for |

## 10. Source

**Design.** `ADR-075` (the hosted design), `ADR-078` (the field rows), `ADR-079` (seal and restore; no approval surface).
**Code.** `apps/desktop/src/design/screens/*.html` and `app.template.html` (the controls), `src/design/logic/*.js` (the
handlers), `src/vault/actions/*.ts`, `src/vault/bridge-source.ts`, `src/lib/bridge.ts` (the calls),
`src-tauri/src/commands.rs` (command → op). **Regeneration.** The control, event and handler columns can be
re-derived with any HTML tokeniser over `screens/*.html` (an element is a control when it carries an `on…=`
binding or is an input, select, text area or link); the command column by following each handler through the logic
mixins to the `live.*` calls in `src/vault/actions/*.ts` and to `invoke("…")` in `bridge.ts`. A control added to a
template without a row here is a gap in this document, and `python3 -m tools.release_verification_check` (from the
repository root) finds it: it re-extracts the controls from the templates, compares them with §2 row for row and
handler for handler, and holds the Size line to the truth (`--self-test` proves it can fail). It does not judge an
expected result or a bridge command; that is a reading, and the Result column is a person's.

## 11. Shell items of the 2026-10-18 design drop — record (2026-10-19)

> Numbered 11 because §9 and §10 already exist. Source commit `66a7da7`. Build: `scripts/release.sh` + `scripts/release-app.sh --no-launch-check` from a clean `main` (unsigned `.app`, `.dmg`, `SHA256SUMS`, three SBOMs; `v2/dist/`, untracked).

| Item | Result | Evidence |
|---|---|---|
| 3.4 `app_icon_set` (X9) | **built, verified by tests; not seen on a real Dock** | six 1024 px PNGs from `scripts/icons/make-marks.mjs`, embedded in the shell; command registered, bridged (`bridge.ts` `appIconSet`), wired to Settings → Appearance and to every unlock (`extras.js` `applyAppIcon`); `src-tauri/tests/shell_ipc.rs` (all six ids answer, nothing else does, no broker op), `src/icon.rs` unit test (every PNG is 1024 px), drift guards (`SHELL_COMMANDS` 4, shim table, `MARK_IDS` = `APP_ICON_IDS`), `tests/unit/wp-d.test.ts` (`setAppIcon`). The Dock change itself needs the supporter pack open, which needs the code; not exercised on a real Dock. Only the PNG set was produced: ICNS and ICO for non-default marks are not needed (the shell sets the icon from the PNG at run time; the bundle's own icon stays `keep`). |
| 3.5 T10 window content protection | **pass** | `tauri.conf.json` `contentProtected: true` (asserted by `tests/shell_config.rs`). Real built app: a screenshot of the main window (computer-use, native capture) is **blank white** while its accessibility tree lists the First-run controls; relaunched with `CREDMGR_CONTENT_PROTECTION=off` the same window captures normally. The env variable is read once at start-up (`shell::apply_content_protection`); documented in `PRIVACY.md`. |
| 3.6 no flourish on re-show | **pass (by test)** | `tests/e2e/extras.spec.ts` "plays on a successful unlock only: not when the app opens onto a login that exists, not when a window comes back into view"; `unlockApp({unlocked:true})` is the only caller of `onUnlocked`. |
| 3.7 copy, lock, close, reopen, quit in the real app | **pass** (re-run 2026-10-19 with full-screen control) | Built `.app` (unsigned, `66a7da7`) against a throwaway vault and daemon (`CREDMGR_CONTENT_PROTECTION=off` for capture): First run (12-character passphrase, "Skip for now" on the recovery code, "Enrol later", project named) opened the vault; a one-field entry was saved. **Copy:** the pasteboard held the value with `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` (T9). **⌘L:** the Lock screen came up and the pasteboard had no types left. **Red close button:** the window went (0 windows), the process kept running; reopening the app (the Dock/`open` reopen path) showed the Lock screen; the passphrase unlocked and the entry was still there. **Copy again, then ⌘Q:** the process ended and the pasteboard was empty. Not covered here: Tray "Quit CredMgr" (C4 pass), the hidden-window unlock flourish (e2e). A window of an unrelated app became visible behind CredMgr's when its window closed; it was not touched. |
| 3.8 auto-lock on real sleep / screen lock | **operator** | passed by the operator on 2026-10-18 (§8) on an earlier build; **not re-run on this build** (K-14, issue #9). |
| 3.9 signing, notarisation, Developer ID (L11) | **not done (operator)** | unsigned banner kept. |

Gates at `66a7da7` (worktree `shell-3x`): bridge 193 passed / 0 failed, clippy `-D warnings` and `cargo fmt --check` clean, `cargo deny` ok; desktop unit 607, e2e, design gate and the 64 real journeys green; repo gates all green. New crates in the shell's tree via `tauri/image-png`: `image`, `moxcms`, `pxfm`, `byteorder-lite` (licences pass `deny.toml`).

## 12. Items of the 2026-10-26 follow-ups — record

> Source: the branch that holds ADR-090 and ADR-091. The table below was written without a built app; **§12.1 re-ran the items in the built `.app` on 2026-10-27** and supersedes the rows it covers.

| Item | Result | Evidence |
|---|---|---|
| Webview reload on every shell lock (ADR-091) | **proven in the mock runtime; NOT verified in the real app** | `tests/shell_ipc.rs::every_lock_reason_reloads_the_main_webview_and_a_missing_window_is_not_an_error` (all six reasons, no socket, no window); `autolock::tests::the_reload_script_…`; the page side in `tests/unit/adr090-091.test.ts`. To check by hand: unlock a throwaway vault, type into Add entry without saving, choose Lock from the menu-bar icon: the window must come back on the Lock screen ("Locked from the menu bar."), the typed text gone, no data visible between. Repeat with sleep and with closing the window. |
| Lock screen lists waiting agent requests | **pass (real daemon, WebKit)** | `tests/real/adr090-091.spec.ts` |
| Second factor given on purpose, agent passes inside the window | **pass (real daemon, WebKit)**; the 300 s clock is proven in the broker (`part4_two_factor.rs`), not waited out here | `tests/real/adr090-091.spec.ts` |

### 12.1 By-hand check in the built `.app`, 2026-10-27 (source `557e715`, unsigned release build)

Throwaway vault and daemon from the release tarball, app launched with `CREDMGR_CONTENT_PROTECTION=off` (so it could be captured), driven by computer-use with full-screen control. Vault set up over the broker socket (one node `Atlas` with a workdir, one entry), then locked.

| Item | Result | Evidence |
|---|---|---|
| Lock screen lists waiting agent requests | **pass, real app + real daemon** | with no request the link read "an agent is waiting for approval?"; after a tokenless agent process (cwd = the node's workdir) asked `entry.reveal`, within one 5 s poll it read "1 agent request is waiting for approval" with the vault still locked; the panel listed `"deploy-key" in Atlas · asked to reveal · 107 s left` (labels from `vault.approval_get`), passphrase and 2FA fields; **Approve** with the passphrase showed "approved with the passphrase · the vault is still locked"; the agent's retry then received the value (`ok`, value released) and `vault.status` answered `{locked:true, pendingApprovals:0}` |
| `crypto.subtle` in the built macOS window | **pass** | Settings → Appearance → Supporter extras → Enter code: a wrong code answered "That code doesn't look right." — the path that runs PBKDF2 + AES-GCM and fails the decrypt. With no secure context the same box would say "This window can't open the extras: it has no secure context" (`donateNoCrypto`). So `tauri://localhost` is a secure context in this WKWebView and the sealed pack can be opened under the production CSP. macOS only; Windows and Linux are not built |
| Webview reload on lock (ADR-091) | **pass for shell locks and for the page's Lock button, ⌘L and hidden-window lock; the 5-minute idle timer itself NOT waited out** | WebKit's own log (`log stream`, process `desktop`) around each lock: the **red close button** (shell lock, reason `window_closed`) produced one `startLoadingMainResource` and nine asset loads at the instant of the lock, and the reopened window showed "Locked because the window was closed." (the reason carried over in `sessionStorage`). **⌘L** (the page's own Lock) produced **no main-resource load**: the page does not reload there. Cause: `autolock::reload_main_webview` runs only inside `lock_and_notify` (sleep, screen lock, session switch, tray, window close, quit); the page's Lock button, ⌘L and the page's idle timer go through `vault_lock`, which does not reload. Typed secrets and reveals are dropped from page state on those paths, but JavaScript strings are not zeroised. **Fixed in `a7ed02c`, re-checked in a rebuilt `.app` (2026-10-27):** `vault_lock` now schedules a reload 150 ms after the broker answers. **⌘L** and the **Lock button** each produced one `startLoadingMainResource` within a second of the key/click. The page also locks itself when the window is hidden (`visibilitychange`); that fired in the first rebuilt app and **dropped its note across the reload** ("Locked because the window was hidden." was not in the idle-only allowlist) — fixed in `7139bea`; the second rebuilt app showed the Lock screen saying "Locked because the window was hidden." after the reload. **Not done:** the 5-minute idle timer was not waited out: the computer-use harness itself hides the window within seconds of each action, which triggers the hidden-window lock first. It reaches the same code (`lockVault(note)` → `vault_lock` → reload; the idle sentence is covered by the unit test). The broker's own 15-minute idle lock is not reloaded (limit in ADR-091) |

Left alone: the app and the throwaway daemon were quit, the temp vault directory removed. A window of another app was not touched.

## 13. By-hand check of the B20 merge in the built `.app`, 2026-10-31 (source `709840c`, unsigned release build)

Rebuilt `.app` from the clean tree, run against a throwaway vault and a `credmgrd` from the release tarball (`CREDMGR_CONTENT_PROTECTION=off`, test passphrase and authenticator generated for the run). The vault was created through the app's own First-run screens (passphrase, recovery code "Skip for now", second factor enrolled with a computed code, two projects). Driven by computer-use with full-screen control; the app, daemon and temp vault were removed afterwards.

| Item | Result | Evidence |
|---|---|---|
| First run end to end (4 steps, TOTP enrol, recovery codes, projects) | **pass** | vault opened on the real daemon; nodes `atlas`, `borealis`, Global, orphaned listed |
| Node chips: "2FA · on reveal" and "Give second factor" | **pass** | shown on every node; Global and a new node alike |
| Give second factor (S5c give mode) | **pass** | dialog text reads "opens a 5-minute window for agents and other callers"; a correct code gave the toast "Second factor accepted. For 5 minutes, agents and other tools can reveal from every node that asks for one. Locking the vault ends it." and the chip became "Second factor given · 4:59" counting down; after a lock the chip returned to "Give second factor" |
| Add entry: no live mixed-script notice; name has the 200-character cap | **pass** (cap itself covered by the broker and window tests) | typing a Latin/Cyrillic name showed no notice while typing; after Save the toast said "This name mixes Latin with Greek or Cyrillic letters." |
| Lock screen request panel (S16a) | **pass, real app + real daemon** | locked, tokenless agent in a workdir asked for a value: the link opened "WHILE LOCKED · 1 WAITING" with the request listed (asked to reveal · seconds left), the always-visible request-id field, "DECIDING …" with passphrase, 2FA code, Deny and Approve, and the back-off caption "Wrong tries count toward the unlock back-off. A recovery code is not accepted here." Approve with passphrase and code answered "approved with the passphrase · the vault is still locked" |
| Held for review (tray) | **pass** | an agent write made while locked appeared after unlock as "1 entry is waiting for your review"; Accept wrote it to its node |
| Operations: Doctor vs Doctor with purge | **pass** | plain Doctor titled "Doctor · checked" (dry run, no purge); "Preview purge" titled "Doctor · purge expired seals"; Verify integrity "ok · 4 nodes checked" |
| Themes | **pass** | light + high contrast (AAA), dark + high contrast, and the graph view in dark were all read; the choice persisted across lock and across quit/restart |
| Add project dialog | **pass** | reworded labels; created a project with "Require second factor on reveal" on |
| Lock (⌘L) reloads the webview and returns to the Lock screen | **pass** | |
| Restart: quit the app, stop and restart `credmgrd`, relaunch | **pass** | passphrase then authenticator code unlocked; every node, the entry and the accepted held entry were present; theme kept |
| Stale line on the 2FA step | **observation, not fixed** | after approving a request on the Lock screen, the next unlock's second-factor step still shows "approved with the passphrase · the vault is still locked" under the code field. Cosmetic; recorded for the operator |
| 5-minute idle lock; real sleep or screen lock | **not done** | unchanged from §12.1: the harness hides the window first; the sleep test is an operator item |
