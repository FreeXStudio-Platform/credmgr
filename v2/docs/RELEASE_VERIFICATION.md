---
id: V2-023
classification: public
title: Release verification checklist
audience: technical
owner: credmgr-v2
status: needs-verification
export_allowed: true
surface: repo
last_reviewed: 2026-11-07
---

<!-- artifact-hardened: NEEDS RE-HARDENING — revised 2026-11-07 for rc.1: §2 now lists every control of the 25 shipped templates
     (the checker `python3 -m tools.release_verification_check` reports 0 findings; it proves coverage, never that a control works);
     rows added since the 2026-10-18 pass say "not pressed" until the built-app re-walk (§15) is done by hand; the C4 findings are
     re-marked in §14a. Awaiting re-verification. -->
# Release verification checklist

`CredMgr V2` · every screen and control of the shipped app, what each sends, and what must happen · `2026-10-03`, rows brought up to the current templates `2026-11-07`

> **Update 2026-11-07 (rc.1).** The checklist was brought up to the templates that ship on `main` (2.0.0-rc.1): 302 control
> rows in 25 screen templates. Rows that existed on 2026-10-18 keep that pass's Result; every row added since says **not pressed**
> (with the automated spec that exercises it, where one does) and waits for the built-app re-walk in §15. The C4 findings F-1 to
> F-14 are re-marked in §14a: fixed in source and guarded by a test, **not** re-pressed in a built app yet.
>
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

**Size.** 426 control rows in 32 screen templates plus the page scaffolding, §3 adds 31 menu-item rows,
§4 and §5 the gestures and system behaviours.

## 2. Screens and controls

### Boot — `boot`

Shown while the app asks the broker for its state, and when it cannot reach it. The release build with no shell shows only this screen.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| button “Retry”<br><sub>when `isBrokerDown`</sub> | click → `retryBoot` | `vault_status` → `vault.status` | Re-asks the broker for its state: the Lock screen when locked, First run when no vault exists, the app when this process is already logged in, or the "broker unreachable" screen again with the reason. No passphrase is asked for while the broker is down. | **pass** — Retry works when launched via LaunchServices; see F-1 for the bare-binary launch; Retry while down stays; Retry when up shows the Lock screen |
| button “Retry”<br><sub>when `isBootFailed`</sub> | click → `retryBoot` | `vault_status` → `vault.status` | Re-asks the broker for its state: the Lock screen when locked, First run when no vault exists, the app when this process is already logged in, or the "broker unreachable" screen again with the reason. No passphrase is asked for while the broker is down. | **n/a** — bootfailed state not reachable without a fault injection |
| button “Start the broker at login” (macOS)<br><sub>when `bootLoginAgentShow`</sub> | click → `bootLoginAgent` | — (shell: `login_agent_install`) | Writes a launchd agent for this user only (never root) that starts `credmgrd` now and at every login, then re-asks the broker for its state. With no `credmgrd` beside the app, in /usr/local/bin or /opt/homebrew/bin it says so and changes nothing. | **not pressed** — new in ADR-156 (2026-11-09); covered by `tests/unit/quick-wins.test.ts` against the fixture broker, not yet pressed in a built app |
| button “Restore from a backup…” | click → `openRestore` | — | Opens the Restore from a backup dialog on the boot screen, which works while no broker is running. Nothing is sent until Restore is pressed in that dialog. | **not pressed** — new in ADR-166; not yet pressed in a built app |

### Lock screen — `S16-lock`

The passphrase step, the second-factor step, the "lost your authenticator" step and (ADR-163) the "Forgot passphrase?" steps: the recovery code alone opens the vault and sets a new passphrase, then the new recovery code is shown once.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| field “passphrase”<br><sub>when `lockStepPass`</sub> | change → `onPassInput`<br>key → `onPassKey` | `vault_unlock` → `vault.unlock` | **change:** The passphrase is held in the field only. Nothing is sent. **key:** Enter submits the passphrase (same as Unlock). | **pass** — passphrase held in the field; Enter submits |
| button: quick-unlock (Touch ID / Face ID / Mac password, named by `biometricLabel`)<br><sub>when `lockStepPass`</sub> | click → `submitTouch` | `vault_unlock` (method `device`) → `vault.unlock` | With the device wrap set up: asks the Mac for Touch ID and opens the app on success; a cancel leaves the screen as it is. Without it: the note “… is not set up yet. Unlock with your passphrase, then open Settings, Security, Set up …”. Nothing is typed or sent when it is not set up. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “Unlock” (reads “Unlocking…” while the broker works)<br><sub>when `lockStepPass`</sub> | click → `submitPass` | `vault_unlock` → `vault.unlock` | Sends the passphrase once and clears the field. Success with no second factor: the app opens, nodes and entries load. A second factor in force: the screen asks for a code. Wrong passphrase: an inline refusal; the broker's wait (rate limit) is shown and the button waits. Never "unlocked" without a broker answer. | **pass** — wrong passphrase: inline "Wrong passphrase.", field cleared; right passphrase with 2FA enrolled asks for a code |
| button “Forgot passphrase? Use recovery code”<br><sub>when `lockStepPass`</sub> | click → `gotoForgot` | — | With a recovery wrap on this vault (`vault.status` `recoveryUnlock`): switches to the recovery-code form. Without one: the note “This vault cannot be opened with its recovery code yet. That is set up the next time the passphrase is changed …” and the passphrase step stays. Nothing is sent. | **not pressed** — new in ADR-163 (2026-11-14); covered by `tests/unit/recover-unlock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` / `bridge_wire.rs` for the shell, not yet pressed in a built app |
| field “2FA code”<br><sub>when `lockStepCode`</sub> | change → `onTwofa`<br>key → `onTwofaKey` | `vault_gate_verify` → `vault.gate_verify` | **change:** Digits and letters of a code are kept (at most 48 characters). Six digits are sent at once. **key:** Enter sends the code. | **pass** — digits kept; 6 digits sent at once (a wrong 000000 gave "That code was not accepted."); Enter sends |
| button “Verify”<br><sub>when `lockStepCode`</sub> | click → `submitTwofa` | `vault_gate_verify` → `vault.gate_verify` | Sends the authenticator code (or one of the ten gate recovery codes). Success opens the app; a wrong, replayed or expired code is refused with one undifferentiated message. | **pass** — Verify: TOTP and one gate recovery code both unlock; wrong/replayed code refused with the same message |
| button “lost your authenticator?”<br><sub>when `lockStepCode`</sub> | click → `gotoRecover` | — | Switches to "lost your authenticator" (passphrase + root recovery code). Nothing is sent. | **pass** — lost your authenticator? switches to the reset step |
| button “back”<br><sub>when `lockStepCode`</sub> | click → `gotoPassphrase` | — | Back to the passphrase step; the typed fields are cleared. Nothing is sent. | **n/a** — back from the code step not pressed |
| field “passphrase”<br><sub>when `lockStepRecover`</sub> | change → `onRecoverPass`<br>key → `onRecoverKey` | `vault_gate_recover` → `vault.gate_recover`<br>`vault_unlock` → `vault.unlock` | **change:** Held in the field only. Nothing is sent. **key:** Enter submits the reset (same as Reset and unlock). | **pass** — passphrase and root code fields held |
| field “root recovery code”<br><sub>when `lockStepRecover`</sub> | change → `onRecoverCode`<br>key → `onRecoverKey` | `vault_gate_recover` → `vault.gate_recover`<br>`vault_unlock` → `vault.unlock` | **change:** Held in the field only. Nothing is sent. **key:** Enter submits the reset (same as Reset and unlock). | **pass** — Enter submits the reset |
| button “Reset and unlock”<br><sub>when `lockStepRecover`</sub> | click → `submitRecover` | `vault_gate_recover` → `vault.gate_recover`<br>`vault_unlock` → `vault.unlock` | Sends the passphrase and the printed root recovery code together: the second factor is removed (not unlocked), then the login follows with the passphrase. The notice says "Second factor reset. Enrol a new authenticator in Settings, under Security." | **pass** — reset with passphrase + root recovery code: notice "Second factor reset. Enrol a new authenticator in Settings, under Security." and the app opened |
| button “back”<br><sub>when `lockStepRecover`</sub> | click → `gotoPassphrase` | — | Back to the passphrase step; the typed fields are cleared. Nothing is sent. | **n/a** — back from the recovery step not pressed |
| field “recovery code”<br><sub>when `lockStepForgot`</sub> | change → `onForgotCode`<br>key → `onForgotKey` | `vault_recover` → `vault.recover` (on Enter) | **change:** Held in the field only (masked). Nothing is sent. **key:** Enter submits the form (same as the action button). | **not pressed** — new in ADR-163 (2026-11-14); covered by `tests/unit/recover-unlock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` / `bridge_wire.rs` for the shell, not yet pressed in a built app |
| field “new passphrase”<br><sub>when `lockStepForgot`</sub> | change → `onForgotPass`<br>key → `onForgotKey` | `vault_recover` → `vault.recover` (on Enter) | Holds the new passphrase; fewer than 4 characters says “At least 4 characters.” and nothing is sent. | **not pressed** — new in ADR-163 (2026-11-14); covered by `tests/unit/recover-unlock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` / `bridge_wire.rs` for the shell, not yet pressed in a built app |
| field “repeat the new passphrase”<br><sub>when `lockStepForgot`</sub> | change → `onForgotRepeat`<br>key → `onForgotKey` | `vault_recover` → `vault.recover` (on Enter) | Must match the new passphrase; a difference says “The two passphrases are not the same.” and nothing is sent. | **not pressed** — new in ADR-163 (2026-11-14); covered by `tests/unit/recover-unlock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` / `bridge_wire.rs` for the shell, not yet pressed in a built app |
| field “2FA code”<br><sub>when `lockStepForgot` · `forgotNeedFactor`</sub> | change → `onForgotFactor`<br>key → `onForgotKey` | `vault_recover` → `vault.recover` (on Enter) | Appears only after the broker answered `two_factor_required` (a second factor is enrolled): the 6 digits or one of the gate's recovery codes; the code and the new passphrase stay typed. Touch ID is never asked. | **not pressed** — new in ADR-163 (2026-11-14); covered by `tests/unit/recover-unlock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` / `bridge_wire.rs` for the shell, not yet pressed in a built app |
| button “Set the new passphrase and unlock” (reads “Opening…” while the broker works)<br><sub>when `lockStepForgot`</sub> | click → `submitForgot` | `vault_recover` → `vault.recover` | Sends the code, the new passphrase and (when asked) the second factor once. Success: the vault is re-keyed under the new passphrase, the old code and the old passphrase stop working, and the next step shows the new recovery code. A wrong code: “That recovery code does not open this vault. Nothing was changed.”, the code field cleared, counted in the unlock back-off (the broker's wait is shown and the button waits). A wrong factor: “That code was not accepted.” | **not pressed** — new in ADR-163 (2026-11-14); covered by `tests/unit/recover-unlock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` / `bridge_wire.rs` for the shell, not yet pressed in a built app |
| button “back”<br><sub>when `lockStepForgot`</sub> | click → `gotoPassphrase` | — | Back to the passphrase step; every field of the form is cleared. Nothing is sent. | **not pressed** — new in ADR-163 (2026-11-14); covered by `tests/unit/recover-unlock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` / `bridge_wire.rs` for the shell, not yet pressed in a built app |
| checkbox “I have saved the new recovery code”<br><sub>when `lockStepForgotDone`</sub> | change → `onForgotSaved` | — | Must be ticked before the vault opens: the new code is shown on this step only. Nothing is sent. | **not pressed** — new in ADR-163 (2026-11-14); covered by `tests/unit/recover-unlock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` / `bridge_wire.rs` for the shell, not yet pressed in a built app |
| button “Open the vault” (“Go to unlock” when the rotation's last moves are pending)<br><sub>when `lockStepForgotDone`</sub> | click → `finishForgot` | — | Opens the app (the login was made by the recovery) with the notice that the old code and passphrase no longer open the vault; the new code leaves the screen. Pending: back to the passphrase step with “The passphrase was changed. Unlock with the new passphrase to finish.” | **not pressed** — new in ADR-163 (2026-11-14); covered by `tests/unit/recover-unlock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` / `bridge_wire.rs` for the shell, not yet pressed in a built app |
| button: the waiting-requests link<br><sub>when `aprLinkShow`</sub> | click → `aprOpenPanel` | — | Opens the approval panel for agent requests that wait while the vault is locked. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/adr090-091.spec.ts`; built-app re-walk pending (§15) |
| radio: a waiting agent request<br><sub>when `aprShow` · `aprListShow`</sub><br><sub>each row of `aprWaiting`</sub> | change → `w.pick` | — | Selects that request (its id fills the request-id field) and shows the factors and the decision buttons. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/adr090-091.spec.ts`; built-app re-walk pending (§15) |
| field “request id”<br><sub>when `aprShow`</sub> | change → `onAprReq` | — | Holds the request id an agent printed (shown when no request is listed). Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/adr090-091.spec.ts`; built-app re-walk pending (§15) |
| field “passphrase for this decision”<br><sub>when `aprShow` · `aprSelShow`</sub> | change → `onAprPass` | — | Held in the field only; both Approve and Deny stay disabled until it is typed. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/adr090-091.spec.ts`; built-app re-walk pending (§15) |
| field “second factor code”<br><sub>when `aprShow` · `aprSelShow`</sub> | change → `onAprCode` | — | Keeps digits only (at most six); optional unless a second factor is in force. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/adr090-091.spec.ts`; built-app re-walk pending (§15) |
| button “Deny”<br><sub>when `aprShow` · `aprSelShow`</sub> | click → `aprDeny` | `vault_approval_decide` → `vault.approval_decide` | Sends the request id, the passphrase and the code once; they are wiped whatever the answer. Success: the vault stays locked and the list drops the request; a refusal is shown in words and nothing changes. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/adr090-091.spec.ts`; built-app re-walk pending (§15) |
| button “Approve”<br><sub>when `aprShow` · `aprSelShow`</sub> | click → `aprApprove` | `vault_approval_decide` → `vault.approval_decide` | As Deny, with approval: the agent's reveal is released on its next try; the vault stays locked. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/adr090-091.spec.ts`; built-app re-walk pending (§15) |
| button “Close”<br><sub>when `aprShow`</sub> | click → `aprClose` | — | Closes the panel and clears the request id, passphrase and code. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/adr090-091.spec.ts`; built-app re-walk pending (§15) |

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

Shown after unlock when entries were written while the vault was locked, and (ADR-156) while the broker holds an anomaly alarm the owner has not seen: five cross-node denials in ten minutes.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| button “Review”<br><sub>when `pendingBannerShow`</sub> | click → `openPending` | `vault_pending_list` → `vault.pending_list` | Opens "Held for review" after re-reading each node's held entries. | **n/a** — not pressed in this pass |
| button “✕”<br><sub>when `pendingBannerShow`</sub> | click → `dismissPendingBanner` | — | Hides the "N entries were held" banner. Nothing is sent; the entries stay in the tray. | **n/a** — not pressed in this pass |
| button “Open audit”<br><sub>when `anomalyBannerShow` · `anomalyAuditShow`</sub> | click → `anomalyOpenAudit` | `vault_anomalies_ack` → `vault.anomalies_ack`; `audit_tail` → `audit.tail` | Marks the anomaly alarm seen (the bar goes) and opens Settings › Audit on the newest records. | **not pressed** — new in ADR-156 (2026-11-09); covered by `tests/unit/quick-wins.test.ts` against the fixture broker, not yet pressed in a built app |
| button “✕” (dismiss the anomaly alarm)<br><sub>when `anomalyBannerShow`</sub> | click → `dismissAnomalyBanner` | `vault_anomalies_ack` → `vault.anomalies_ack` | Marks the alarm seen; the bar goes and `credmgr status` no longer counts it. The denials stay in the audit log. | **not pressed** — new in ADR-156 (2026-11-09); covered by `tests/unit/quick-wins.test.ts` against the fixture broker, not yet pressed in a built app |

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
| field “filter nodes” (filter nodes by name) | change → `onNodeFilter` | — | Narrows the rail's node list to the names that contain the typed text (at most 120 characters). When none match, the rail says “No node is called that.” Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “✕” (clear the node filter)<br><sub>when `nodeFilterOn`</sub> | click → `clearNodeFilter` | — | Empties the node filter and shows every node again. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |

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
| button “Give second factor”<br><sub>when `inspNode` · `inspTfBtn`</sub> | click → `inspTfGive` | — | Opens the second-factor dialog (§ dlg-field). Nothing is sent until a code is entered there. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| button: a security level (Open · Guarded · Strict)<br><sub>when `inspNode` · `lvlShow`</sub><br><sub>each row of `lvlOpts`</sub> | click → `o.set` | `node_policy` → `node.policy` (`securityLevel`) | Sets the node's level (ADR-140); the node is read again; notice “Security level is now …” (the third level reads Strict; its stored and sent value is `sealed`, ADR-152). Widening may need Touch ID: a refusal is shown in words and nothing changes. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| button “+ New entry”<br><sub>when `inspNode`</sub> | click → `openAddEntry` | — | Opens Add entry for this node. Nothing is sent. | **pass** — + New entry in the inspector opens Add entry |
| button “+ New note”<br><sub>when `inspNode`</sub> | click → `openAddNote` | — | Opens Add entry with one field labelled "note" and the entry type pinned to note. Nothing is sent. | **pass** — + New note opens Add entry with one field labelled note, type note |
| button “Import .env…”<br><sub>when `inspNode`</sub> | click → `openImportEnv` | — | Opens the import dialog for the selected node. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| entry row<br><sub>when `inspNode`</sub><br><sub>each row of `inspEntries`</sub> | click → `e.open` | `entry_get` → `entry.get`<br>`entry_reveal` → `entry.reveal` | Opens the entry detail: the fields (ids, labels, types, masking — no value) are read with entry.get; the fields that are not masked are read in one audited reveal. | **pass** — entry detail opens: host and username visible, password masked |
| button “Unlock node”<br><sub>when `inspUnreadableUnlock`</sub> | click → `unreadableUnlock` | `vault_node_unlock` → `vault.node_unlock` | Unlocks this node; its entries are read again. | **n/a** — not pressed in this pass |
| button “Give second factor” (a node whose entries cannot be read)<br><sub>when `inspNode` · `inspUnreadable` · `inspUnreadableFactor`</sub> | click → `unreadableFactor` | — | Opens the second-factor dialog; on success the node is read again. Nothing is sent until a code is entered. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| button “+ New entry”<br><sub>when `inspEmpty`</sub> | click → `openAddEntry` | — | Opens Add entry for this node. Nothing is sent. | **n/a** — not pressed in this pass |
| button “+ New note”<br><sub>when `inspEmpty`</sub> | click → `openAddNote` | — | Opens Add entry with one field labelled "note" and the entry type pinned to note. Nothing is sent. | **n/a** — not pressed in this pass |
| button “open”<br><sub>when `inspOrphan`</sub><br><sub>each row of `orphanItems`</sub> | click → `o.open` | `entry_reveal` → `entry.reveal` | Asks the broker to open the sealed item; without a presence key the broker refuses and the app says presence is needed and offers to set Touch ID up (Touch ID has been built since ADR-098; see section 14). Nothing is shown. | **n/a** — "open" on an orphaned item not reachable: the Orphaned panel listed no items after sealing (F-11) |
| back to the node ("← node")<br><sub>when `inspEntry`</sub> | click → `closeEntry` | — | Back to the node's entry list; every revealed value is wiped. Nothing is sent. | **pass** — back to node works |
| button “Try again”<br><sub>when `fieldsFailed`</sub> | click → `retryFields` | `entry_get` → `entry.get` | Reads the entry's fields again after a failure. | **n/a** — not pressed in this pass |
| field reveal button ("reveal" / "show code" / "hide")<br><sub>when `f.maskable`</sub><br><sub>each row of `entryFields`</sub> | click → `f.reveal` | `entry_reveal` → `entry.reveal`<br>`totp_code` → `totp.code` | Reveals that one field (audited) for the reveal window, then it re-masks; a TOTP-seed field shows its current code with a bar running to the end of its 30-second step instead of the seed. | **pass** — reveal shows value with "re-masks in 20s", re-masks on its own; TOTP field: "show code" shows the live code (355 849, matches an independent computation) with a bar and "re-masks in 10s" |
| field copy button<br><sub>when `f.canCopy`</sub><br><sub>each row of `entryFields`</sub> | click → `f.copy` | `entry_copy` → `entry.reveal (fieldIds)` | Copies that one field through the shell: concealed, this-Mac-only, cleared after 30 seconds (and on lock, sleep, quit). The value never enters the page; the button reads "copied". | **pass** — copy puts exactly the value on the clipboard, button reads "copied"; clipboard empty 33 s later |
| button “show seed” / “hide seed”<br><sub>when `f.isTotp`</sub><br><sub>each row of `entryFields`</sub> | click → `f.showSeed` | `totp_seed` → `totp.seed` (“show seed” only; “hide seed” sends nothing) | Asks for the TOTP seed (Touch ID proof attached by the shell). With Touch ID set up the seed shows in that field's row for the reveal window (the countdown runs, it re-masks by itself, hide and lock wipe it, no copy button); the audit trail records the read. While the seed shows, the same button reads “hide seed” and takes away the seed only: a code shown beside it stays until its own timer, and the reveal button's “hide” still takes both (design Q4, ADR-151; new 2026-11-08, not yet pressed in a built app). Without Touch ID, or on a cancelled prompt, the broker refuses with presence_required and the notice says how to set Touch ID up; nothing is revealed. | **pass** — show seed: "Needs presence… Nothing was changed. (totp.seed)" |
| button “⋮”<br><sub>when `f.canMenu`</sub><br><sub>each row of `entryFields`</sub> | click → `f.toggleMenu` | — | Opens or closes the field menu. Nothing is sent. | **pass** — ⋮ opens the field menu |
| field menu item (Edit… · Move up · Move down · Remove…)<br><sub>when `f.menuOpen`</sub><br><sub>each row of `f.menuItems`</sub> | click → `m.go` | `field_reorder` → `field.reorder` | Edit…: opens the Edit field dialog. Move up / Move down: swaps the field with its neighbour (disabled at the ends) and re-reads the entry. Remove…: opens the Remove dialog (disabled for the last field: "an entry keeps at least one field"). | **pass** — Edit… opens dialog; Move up swaps and re-reads; Move down disabled on the last field; Remove… opens dialog and removes (field.remove audited) |
| button “This is a 2FA seed”<br><sub>when `f.seedHint`</sub><br><sub>each row of `entryFields`</sub> | click → `f.seedMark` | `field_update` → `field.update` (type `totp-seed`) | Shown when the broker flags the field as a possible 2FA seed (ADR-111, #40); marks that field as a seed, which then gives codes and is never shown. Undo reverts it. | not pressed — automated: `tests/e2e/seed-hint.spec.ts`, `tests/real/seed-hint.spec.ts`; built-app re-walk pending (§15) |
| button “+ Add field”<br><sub>when `fieldsEditable`</sub> | click → `addFieldOpen` | — | Opens the Add field dialog for this entry. Nothing is sent. | **pass** — + Add field opens the Add field dialog |
| button “Aliases…”<br><sub>when `inspEntry` · `entryUnlocked` · `fieldsShow` · `fieldsEditable`</sub> | click → `aliasOpen` | — | Opens the aliases dialog for the open entry. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| button “Set expiry…” / “Change expiry…”<br><sub>when `inspEntry` · `entryUnlocked` · `expiryBtnShow`</sub> | click → `expiryOpen` | — | Opens the expiry dialog for the open entry, with its current date if it has one. Nothing is sent. Beside it, a chip shows the stored date (UTC): grey later than 30 days, amber within 30 days, red once the day has passed. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Move to project…”<br><sub>when `inspEntry` · `entryUnlocked` · `expiryBtnShow` · `moveBtnShow`</sub> | click → `moveOpen` | — | Opens the move dialog for the open entry. Offered only when another project is open to receive it. Nothing is sent. | **not pressed** — new in ADR-158 (2026-11-14); automated: `tests/unit/entry-move.test.ts` against the fixture broker; not yet pressed in a built app |
| tag “✕”<br><sub>when `inspEntry` · `tagsShow`</sub><br><sub>each row of `tagChips`</sub> | click → `t.remove` | `entry_tag_set` → `entry.tag_set` | Takes that tag off the open entry: one call with the whole remaining set and the node's generation; the entry is read again and the chips show what the broker stored. A stale generation is said in words. | **not pressed** — new in ADR-167 (2026-11-20); automated: `tests/unit/tags-merge.test.ts` against the fixture broker; not yet pressed in a built app |
| text box “+ tag”<br><sub>when `inspEntry` · `tagsShow`</sub> | type → `onTagDraft` · Enter → `onTagKey` | `entry_tag_set` → `entry.tag_set` | Enter adds the typed tag (lower-cased, spaces to `-`); a tag the broker would refuse (a comma, more than 32 characters, a 17th tag) is said in words and nothing is sent. | **not pressed** — new in ADR-167 (2026-11-20); automated: `tests/unit/tags-merge.test.ts` against the fixture broker; not yet pressed in a built app |
| tab “Fields”<br><sub>when `inspEntry` · `entryUnlocked` · `entryTabsShow`</sub> | click → `entryTabToFields` | — | Shows the entry's fields (the default tab). Nothing is sent. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| tab “History”<br><sub>when `inspEntry` · `entryUnlocked` · `entryTabsShow`</sub> | click → `entryTabToHistory` | `entry_history` → `entry.history` (`limit` 200) | Reads the entry's audit trail once and lists it newest first: time, what happened in words, who (you or an agent's session), and “refused” for a denied request. The entry's last change, rotation and expiry sit above. No value is ever shown. Another entry opens on Fields. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Try again” (history)<br><sub>when `inspEntry` · `entryUnlocked` · `entryTabHistory` · `histFailed`</sub> | click → `histRetry` | `entry_history` → `entry.history` | Reads the trail again after a refusal; the tab says in words why it could not read it and never shows a refusal as an empty trail. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Refresh” (history)<br><sub>when `inspEntry` · `entryUnlocked` · `entryTabHistory` · `histShow`</sub> | click → `histRefresh` | `entry_history` → `entry.history` | Reads the trail again. A change made from the entry's detail (an expiry) refreshes an open History tab by itself. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Undo …”<br><sub>when `inspEntry` · `entryUnlocked` · `fieldsShow` · `undoShow`</sub> | click → `undoField` | `entry_undo` → `entry.undo` | Undoes the last field change (add, edit, remove, reorder) within the broker's seven-day window; says what was restored; the old value is not shown. A refusal (`not_undoable`, `conflict`) is shown in words. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| button “Unlock node”<br><sub>when `entryLockedShow`</sub> | click → `lockedUnlock` | `vault_node_unlock` → `vault.node_unlock` | Unlocks this node (the login is unaffected). Notice "Node unlocked."; its entries become readable. | **n/a** — not pressed in this pass |
| field “find in this node”<br><sub>when `nodeFindShow`</sub> | change → `onNodeFind` | `entry_search` → `entry.search` | Searches the names and other names on this node, a short pause after typing; an empty box sends nothing. Matches are listed below the box, or “No name or other name on this node contains that.” No value is searched or shown. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button: a find result row<br><sub>when `nodeFindRowsShow` · each row of `nodeFindRows`</sub> | click → `h.open` | `entry_get` → `entry.get` | Closes the find box and opens that entry's detail, as an entry row in the node's list does. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Undo”<br><sub>when `removedBarShow`</sub> | click → `removedUndo` | `entry_restore` → `entry.restore` | Restores the entry removed a moment ago, as it was, and the bar goes. Undo is disabled while it works. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Restore as a copy”<br><sub>when `removedBarShow` · `removedCopyShow`</sub> | click → `removedCopy` | `entry_restore` (keep both) → `entry.restore` | Restores the removed entry under a free name, next to the entry that took its name. | **not pressed** — new in rc.2 §1 (undo a removal, keep both); not yet pressed in a built app |
| button “✕” (dismiss)<br><sub>when `removedBarShow`</sub> | click → `removedDismiss` | — | Hides the Undo bar. The entry stays removed and can still be restored for seven days from Settings › Audit. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Rotate…”<br><sub>when `rotateBtnShow`</sub> | click → `rotateOpen` | — | Opens the Rotate a value dialog for this entry. Nothing is sent until Rotate is pressed in it. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Remove…”<br><sub>when `removeBtnShow`</sub> | click → `removeOpen` | — | Opens the Remove entry dialog for this entry. Nothing is sent until Remove entry is pressed in it. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |

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
| drop zone “2FA QR”<br><sub>when `addSingle`</sub> | dragover → `onQrDragOver`<br>drop → `onQrDrop` | `fields_preview` (local: parser + inference) | **dragover:** lets an image be dropped here. Nothing is read. **drop:** the first dropped PNG or JPEG is decoded in the page (jsQR, no network); an `otpauth://` URI goes into the first empty value box (or a new row), the preview types it `totp-seed`, and nothing is saved until Save. Anything else is refused in words beside the control ("No QR code was found…", "…not an authenticator code…"); the image's content is never shown, logged or stored. A file dropped anywhere else in the window is not opened. | **not pressed** — new in ADR-160 (2026-11-14); covered by `tests/unit/qr-import.test.ts` against the fixture broker, not yet pressed in a built app |
| file input “choose a QR code image (PNG or JPEG)”<br><sub>when `addSingle`</sub> | change → `onQrFile` | `fields_preview` (local: parser + inference) | Opens the file picker for a PNG or JPEG; the chosen image is read as the drop zone reads it, and the input is emptied so the same file can be chosen again. The image is not uploaded or saved anywhere. | **not pressed** — new in ADR-160 (2026-11-14); covered by `tests/unit/qr-import.test.ts` against the fixture broker, not yet pressed in a built app |
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
| field “second factor code”<br><sub>when `dlgTf`</sub> | change → `onTfCode` | — | Keeps digits only (at most six). Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| button “Cancel”<br><sub>when `dlgTf`</sub> | click → `closeDialog` | — | Closes the dialog; nothing is revealed and nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| button “Verify and reveal” / “Give second factor”<br><sub>when `dlgTf`</sub> | click → `tfVerify` | `vault_gate_verify` → `vault.gate_verify` | Sends the six-digit code once; the broker opens a five-minute window, vault-wide and for every caller. Then the refused read is repeated once. A wrong code leaves the dialog open with the broker's reason and the digits cleared. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| dialog backdrop (field dialog)<br><sub>when `dlgField`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| dialog panel (field dialog)<br><sub>when `dlgField`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| field “field label”<br><sub>when `fdIsAdd`</sub> | change → `onFdLabel` | — | Edits the label (newlines and NUL become spaces). Nothing is sent. | **pass** — label held |
| text area “field value”<br><sub>when `fdIsAdd`</sub> | change → `onFdValue` | — | Edits the value. Nothing is sent. | **pass** — value held |
| field “generated length”<br><sub>when `dlgField` · `fdIsAdd`</sub> | change → `onFdGl` | — | Holds the length for a generated value. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| checkbox: symbols<br><sub>when `dlgField` · `fdIsAdd`</sub> | change → `onFdGs` | — | Includes symbols in the generated value; off when “pronounceable” is on. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| checkbox: pronounceable<br><sub>when `dlgField` · `fdIsAdd`</sub> | change → `onFdGp` | — | Chooses a pronounceable value. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| button “Generate”<br><sub>when `dlgField` · `fdIsAdd`</sub> | click → `fdGenerate` | `util_generate` → `util.generate` | Asks the broker for a random value of that length and fills the value box; shows its entropy. The value is not in a notice or a log. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| button “Clear”<br><sub>when `dlgField` · `fdIsAdd` · `fdGenOn`</sub> | click → `fdGenClear` | — | Empties the generated value. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/gates.spec.ts`; built-app re-walk pending (§15) |
| field “field label”<br><sub>when `fdIsEdit`</sub> | change → `onFdLabel` | — | Edits the label (newlines and NUL become spaces). Nothing is sent. | **pass** — label edit (username -> login) |
| text area “new field value”<br><sub>when `fdIsEdit`</sub> | change → `onFdValue` | — | Edits the value. Nothing is sent. | **n/a** — value left blank, kept current |
| select “field type”<br><sub>when `fdIsEdit`</sub> | change → `onFdType` | — | Chooses the field type ("auto" clears a pin). Nothing is sent. | **n/a** — type select not changed |
| select “field masking”<br><sub>when `fdIsEdit`</sub> | change → `onFdMasked` | — | Chooses masking ("auto" clears a pin). Nothing is sent. | **pass** — masking select not changed; masking select (follows the type / always hidden / always shown) works, value saved |
| button “Cancel”<br><sub>when `dlgField`</sub> | click → `cancelFieldDlg` | — | Closes the dialog; the typed value is discarded. Nothing is sent. | **n/a** — Cancel not pressed on this dialog |
| Save (Add field · Save changes · Remove field)<br><sub>when `dlgField`</sub> | click → `saveFieldForm` | `field_add` → `field.add`<br>`field_update` → `field.update`<br>`field_remove` → `field.remove` | Add: appends the field. Edit: changes only what changed. Remove: removes the field (refused for the last one). The entry is read again; each is undoable with entry.undo by its audit record. | **pass** — Add field ("Field added"), Edit ("Field updated"), Remove ("Field removed") each one call and re-read; field removal undone with credmgr undo, field back after reopen (J5) |

### Aliases and .env import — `dlg-names`

The aliases dialog of an entry (ADR-121) and the .env importer of a node (ADR-122).

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop (aliases)<br><sub>when `dlgAlias`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| dialog panel (aliases)<br><sub>when `dlgAlias`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| text area “aliases, one per line”<br><sub>when `dlgAlias`</sub> | change → `onAnText` | — | Holds the aliases; a name another entry already has is refused next to the form after Save. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| button “Cancel”<br><sub>when `dlgAlias`</sub> | click → `cancelAliasDlg` | — | Closes the dialog; nothing typed is kept. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| button “Save aliases”<br><sub>when `dlgAlias`</sub> | click → `saveAliasForm` | `entry_alias` → `entry.alias` | Replaces the entry's aliases (an empty list clears them). A taken name is refused with nothing changed; an alias that resembles another name is saved and the notice says so. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| dialog backdrop (.env import)<br><sub>when `dlgImport`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| dialog panel (.env import)<br><sub>when `dlgImport`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| text area “.env text”<br><sub>when `dlgImport` · `imIsInput`</sub> | change → `onImText` | — | Holds the pasted text; it is cleared by Cancel, Escape and a lock. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| file input “choose a .env file”<br><sub>when `dlgImport` · `imIsInput`</sub> | change → `onImFile` | — | Reads the chosen file into the same box in the page; the file is not uploaded anywhere. A bad line is named by number and never shown. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| radio: stop on a conflict<br><sub>when `dlgImport` · `imIsPreview` · `imConflict`</sub> | change → `onImStop` | — | Chooses that a conflict writes nothing (the default option). Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| radio: skip the conflicting names<br><sub>when `dlgImport` · `imIsPreview` · `imConflict`</sub> | change → `onImSkip` | — | Chooses that conflicting names are left out. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| button “Cancel”<br><sub>when `dlgImport`</sub> | click → `cancelImportDlg` | — | Closes the dialog and leaves nothing of the pasted text behind. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| button “Back”<br><sub>when `dlgImport` · `imIsPreview`</sub> | click → `imBack` | — | Returns from the preview to the input step. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| button “Preview”<br><sub>when `dlgImport` · `imIsInput`</sub> | click → `imPreview` | (shell: `env_preview`) → `entry_import_env` → `entry.import_env` (`dryRun`) | Names every pair and what it would become (new, exists, duplicate, empty, invalid) and which names it resembles. Writes nothing; no value is shown. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |
| button “Import N entries”<br><sub>when `dlgImport` · `imIsPreview`</sub> | click → `imRun` | `entry_import_env` → `entry.import_env` | Writes each new pair as its own entry with its own audit record; a conflict with the default choice writes nothing; a part-way failure says where it stopped. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |

### Expiry — `dlg-expiry`

The Set / Change expiry dialog of an entry (ADR-157, the desktop half of ADR-156's `entry.set_expiry`). A date is a calendar day in UTC, read as `credmgr expire --at` reads it.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop (expiry)<br><sub>when `dlgExpiry`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the dialog. Nothing is sent. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| dialog panel (expiry)<br><sub>when `dlgExpiry`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| text box “expiry date, YYYY-MM-DD in UTC”<br><sub>when `dlgExpiry`</sub> | change → `onExDate` | — | Holds the date. A date that is not a real calendar day is said under the box and Save stays off; a day already begun in UTC says the entry will show as expired. Nothing is sent. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “in 30 days”<br><sub>when `dlgExpiry`</sub> | click → `exIn30` | — | Puts today plus 30 days (UTC) in the box. Nothing is sent. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “in 90 days”<br><sub>when `dlgExpiry`</sub> | click → `exIn90` | — | Puts today plus 90 days (UTC) in the box. Nothing is sent. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “in a year”<br><sub>when `dlgExpiry`</sub> | click → `exIn365` | — | Puts today plus 365 days (UTC) in the box. Nothing is sent. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Remove expiry”<br><sub>when `dlgExpiry` · `exClearShow`</sub> | click → `clearExpiryForm` | `entry_set_expiry` → `entry.set_expiry` (`clear`) | Removes the entry's expiry; the chip goes; notice “… no longer expires.” Offered only when the entry has one. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Cancel”<br><sub>when `dlgExpiry`</sub> | click → `cancelExpiryDlg` | — | Closes the dialog; nothing typed is kept. Nothing is sent. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Save expiry”<br><sub>when `dlgExpiry`</sub> | click → `saveExpiryForm` | `entry_set_expiry` → `entry.set_expiry` (`expiresAt`, `generation`) | Stores the start of that UTC day as the entry's expiry with the node's generation; the entry is read again and the chip shows the stored date; notice “… expires on YYYY-MM-DD (UTC).” A stale generation re-reads the entry and keeps the dialog for a second Save; an entry that is gone closes it. Off while the date is empty, not a date, or unchanged. | **not pressed** — new in ADR-157 (2026-11-12); automated: `tests/unit/history-expiry.test.ts` against the fixture broker; not yet pressed in a built app |

### Move to project — `dlg-move`

Move one entry to another project (ADR-158, `entry.move`). The value is sealed again with that project's key inside the broker; the page never holds it.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop (move)<br><sub>when `dlgMove`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the dialog. Nothing is sent. | **not pressed** — new in ADR-158 (2026-11-14); automated: `tests/unit/entry-move.test.ts` against the fixture broker; not yet pressed in a built app |
| dialog panel (move)<br><sub>when `dlgMove`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new in ADR-158 (2026-11-14); automated: `tests/unit/entry-move.test.ts` against the fixture broker; not yet pressed in a built app |
| select “move to node”<br><sub>when `dlgMove`</sub> | change → `onMvTo` | — | Picks the destination among the other projects that are not locked; the entry's own project and a locked one are not offered. Nothing is sent. | **not pressed** — new in ADR-158 (2026-11-14); automated: `tests/unit/entry-move.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Cancel”<br><sub>when `dlgMove`</sub> | click → `cancelMoveDlg` | — | Closes the dialog. Nothing is sent. | **not pressed** — new in ADR-158 (2026-11-14); automated: `tests/unit/entry-move.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Move entry”<br><sub>when `dlgMove`</sub> | click → `saveMoveForm` | `entry_move` → `entry.move` (`node`, `entry`, `to`, `generation`) | Touch ID is asked for (and a fresh code when a second factor is on). The entry moves with its name, other names, expiry and reference number; both projects are read again and the inspector opens the entry in its new project; notice “… moved to …”, with how many grants were revoked and earlier values dropped when any. A name the destination already uses keeps the dialog and says so (nothing moved); a stale generation keeps it for a second press; an entry that is gone closes it. | **not pressed** — new in ADR-158 (2026-11-14); automated: `tests/unit/entry-move.test.ts` against the fixture broker; not yet pressed in a built app |

### Rotate a value and remove an entry — `dlg-lifecycle`

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop<br><sub>when `dlgRotate`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the dialog. Nothing is sent; the typed value is discarded. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| dialog panel<br><sub>when `dlgRotate`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| select “field to rotate”<br><sub>when `rtFieldPick`</sub> | change → `onRtField` | — | Chooses which field of the entry gets the new value. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| textarea “new value”<br><sub>within the rotate dialog</sub> | change → `onRtValue` | — | Holds the new value, typed or generated; it is read-only while a generated value is in place. The current value is never shown. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| input “generated length”<br><sub>within the generate options</sub> | change → `onRtGl` | — | Sets the length of a generated value (8 to 128). Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| checkbox “symbols”<br><sub>within the generate options</sub> | change → `onRtGs` | — | Includes symbols in a generated value. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| checkbox “pronounceable”<br><sub>within the generate options</sub> | change → `onRtGp` | — | Makes a generated value pronounceable. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Generate”<br><sub>within the generate options</sub> | click → `rtGenerate` | `util_generate` → `util.generate` | The broker makes a value with the chosen options and it is shown masked; a failure is said in words. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Clear”<br><sub>when `rtGenOn`</sub> | click → `rtGenClear` | — | Clears the generated value so a value can be typed. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Cancel”<br><sub>within the rotate dialog</sub> | click → `cancelRotateDlg` | — | Closes the Rotate dialog and discards the typed or generated value. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Rotate”<br><sub>within the rotate dialog</sub> | click → `saveRotateForm` | `entry_rotate` → `entry.rotate` | Gives the field its new value. The old value is kept as history for Undo, the entry records the rotation, and the entry is read again. The button reads “Rotating…” while it works. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| dialog backdrop<br><sub>when `dlgRemoveEntry`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the dialog. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| dialog panel<br><sub>when `dlgRemoveEntry`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Cancel”<br><sub>within the remove dialog</sub> | click → `cancelRemoveDlg` | — | Closes the dialog; the entry is not removed. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Remove entry”<br><sub>within the remove dialog</sub> | click → `saveRemoveForm` | `entry_remove` → `entry.remove` | Removes the entry from every list at once; it is kept for seven days, and Undo or Restore as a copy brings it back. The button reads “Removing…” while it works. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |

### Restore from a backup — `dlg-restore`

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop<br><sub>when `dlgRestore`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the dialog. Nothing is sent; the passphrase is discarded. | **not pressed** — new in ADR-166; not yet pressed in a built app |
| dialog panel<br><sub>when `dlgRestore`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new in ADR-166; not yet pressed in a built app |
| field “backup archive file” (the archive's full path)<br><sub>when `rsFormShow`</sub> | change → `onRsArchive` | — | Holds the path of the archive. Nothing is read until Restore is pressed. | **not pressed** — new in ADR-166; not yet pressed in a built app |
| field “folder to restore into”<br><sub>when `rsFormShow`</sub> | change → `onRsTarget` | — | Holds the folder to restore into; left empty, the vault's own folder. Nothing is sent. | **not pressed** — new in ADR-166; not yet pressed in a built app |
| password field “backup passphrase”<br><sub>when `rsFormShow`</sub> | change → `onRsPass` | — | Holds the backup's passphrase in the dialog only; it is cleared when the restore finishes or the dialog closes. Nothing is sent. | **not pressed** — new in ADR-166; not yet pressed in a built app |
| button “Cancel” (“Close” after a restore)<br><sub>within the restore dialog</sub> | click → `cancelRestoreDlg` | — | Closes the dialog and drops any passphrase held. Nothing is sent. | **not pressed** — new in ADR-166; not yet pressed in a built app |
| button “Restore”<br><sub>when `rsFormShow`</sub> | click → `saveRestoreForm` | `backup_restore` → `backup.restore` | Rebuilds the vault from the archive into the folder, all at once or not at all, then lists the files written. Refused while a broker is running. Disabled until the archive and the passphrase are filled. | **not pressed** — new in ADR-166; not yet pressed in a built app |

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
| button “Cancel”<br><sub>when `dlgGrant`</sub> | click → `closeGrantDlg` | — | The dialog closes and the reason and the code typed in it are cleared (C4 finding F-12), so a reopened dialog starts empty. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/rc1-ui.spec.ts`; built-app re-walk pending (§15) |

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
| checkbox “private names”<br><sub>when `dlgAddNode` · `isPro`</sub> | change → `onAdvPn` | — | Chooses `privateNames` for the new node (its names are hidden from nodes that may not see them, ADR-084). Held in the dialog; sent with Create node. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| advanced checkbox: the parent may read this node<br><sub>when `isPro`</sub> | change → `onAdvChildRead` | — | Chooses whether the parent may read this node (a widening: refused by the broker). Nothing is sent. | **pass** — parent-may-read widening is refused and reported |
| select “read-write read-only none”<br><sub>when `isPro`</sub> | change → `onAdvAgentAccess` | — | Chooses the agent access (read-write · read-only · none). Nothing is sent. | **pass** — agent access select works (read-write/read-only) |
| button “Cancel”<br><sub>when `dlgAddNode`</sub> | click → `closeDialog` | — | The dialog closes. Nothing is sent; anything typed in it is discarded. | **n/a** — Cancel not pressed |
| button “Create node”<br><sub>when `dlgAddNode`</sub> | click → `confirmAddNode` | `node_create` → `node.create`<br>`node_policy` → `node.policy` | Creates the node with its work folders, then applies the tightening policy choices; a widening choice is refused with presence_required and reported. "Node “x” created." | **pass** — Create node with "this node can read its children" and agent access read-only: node created, notice says the widening was not applied (needs presence) and that agent access was; node "widetest" listed |

### Confirm it is you — `dlg-confirm`

ADR-150, "Confirm before showing secrets". Opens when the broker answers `confirmation_required` to a reveal, a copy, a TOTP code or a loosening of the setting; after a confirmation the bridge sends the same request once more.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| confirm dialog backdrop<br><sub>when `dlgConfirm`</sub> | click → `confirmCancel` | — | Closes the dialog without confirming; notice “Not confirmed. Nothing was shown.” (or “…The setting was not changed.”). The request is not sent again. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |
| confirm dialog panel<br><sub>when `dlgConfirm`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the dialog stays open. Nothing is sent. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |
| button “Use Touch ID”<br><sub>when `dlgConfirm` · `confirmTouchShow`</sub> | click → `confirmWithTouch` | `session_confirm` → `session.confirm` (no passphrase; the shell shows the Touch ID prompt and attaches the proof) | Offered only when this Mac holds a presence key enrolled for this vault. On success the dialog closes and the secret shows; cancelled, the dialog says so and the passphrase still works. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |
| input “vault passphrase”<br><sub>when `dlgConfirm`</sub> | change → `onConfirmPass`; keydown → `confirmPassKey` | — (Enter sends, as Confirm) | Typing is kept in the input only, never in state; it is wiped when sent or when the dialog closes. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |
| button “Confirm”<br><sub>when `dlgConfirm`</sub> | click → `confirmWithPass` | `session_confirm` → `session.confirm` (`passphrase`) | Right passphrase: the dialog closes and the original request is sent again once. Wrong: “Wrong passphrase.” in the dialog (counts in the unlock back-off); too many: the wait is shown. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |
| button “Cancel”<br><sub>when `dlgConfirm`</sub> | click → `confirmCancel` | — | As the backdrop; Esc does the same. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |

### Presence, passphrase prompt and recovery code — `dlg-touch`

Three small dialogs: the presence explanation, the passphrase prompt that Back up / Rotate / Doctor share, and the one-time recovery code after a rotation.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| presence dialog backdrop<br><sub>when `dlgTouch`</sub> | click → `touchOk` | — | Closes the presence dialog. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| presence dialog panel<br><sub>when `dlgTouch`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| button “Close”<br><sub>when `dlgTouch`</sub> | click → `touchOk` | — | Closes the presence dialog. Nothing is sent. | **n/a** — not pressed in this pass |
| button “✕” (dismiss)<br><sub>when `donateToastVisible` · `donateViewMain`</sub> | click → `dismissDonateToast` | — | Closes the reminder for this milestone only. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button: a chain tab (one per coin)<br><sub>when `donateToastVisible` · `donateViewMain`</sub><br><sub>each row of `donateTabs`</sub> | click → `t.go` | — | Shows that chain's address. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “copy address”<br><sub>when `donateToastVisible` · `donateViewMain`</sub> | click → `donateCopyAddr` | — | Copies the address to the clipboard and says “copied ✓” only when the write really succeeded (“copy failed” otherwise). Nothing reaches the broker. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/donate-copy.spec.ts`; built-app re-walk pending (§15) |
| button “Donate”<br><sub>when `donateToastVisible` · `donateViewMain`</sub> | click → `goDonateGuide` | — | Shows the guide (verify the address, send a test amount first). Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “Enter code”<br><sub>when `donateToastVisible` · `donateViewMain`</sub> | click → `goDonateCode` | — | Shows the supporter-code step. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “don't remind me”<br><sub>when `donateToastVisible` · `donateViewMain` · `donateMsShow`</sub> | click → `optOutAsk` | — | Records the choice in this window's local storage, says where Donate is (About → Donate) and closes. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “← back” (guide)<br><sub>when `donateToastVisible` · `donateViewGuide`</sub> | click → `backDonateMain` | — | Back to the reminder. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “✕” (dismiss, guide)<br><sub>when `donateToastVisible` · `donateViewGuide`</sub> | click → `dismissDonateToast` | — | Closes the reminder for this milestone only. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button: a chain tab (guide)<br><sub>when `donateToastVisible` · `donateViewGuide`</sub><br><sub>each row of `donateTabs`</sub> | click → `t.go` | — | Shows that chain's address. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “copy address” (guide)<br><sub>when `donateToastVisible` · `donateViewGuide`</sub> | click → `donateCopyAddr` | — | Copies the address to the clipboard and says “copied ✓” only when the write really succeeded. Nothing reaches the broker. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/donate-copy.spec.ts`; built-app re-walk pending (§15) |
| button “Have a code already? →”<br><sub>when `donateToastVisible` · `donateViewGuide`</sub> | click → `goDonateCode` | — | Shows the supporter-code step. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “← back” (code)<br><sub>when `donateToastVisible` · `donateViewCode`</sub> | click → `backDonateMain` | — | Back to the reminder. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “✕” (dismiss, code)<br><sub>when `donateToastVisible` · `donateViewCode`</sub> | click → `dismissDonateToast` | — | Closes the reminder for this milestone only. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| field “supporter code”<br><sub>when `donateToastVisible` · `donateViewCode`</sub> | change → `onDonateCode` | — | Holds the code. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “Submit”<br><sub>when `donateToastVisible` · `donateViewCode`</sub> | click → `submitDonateCode` | — | Opens the sealed extras pack in the window (local; no network, no broker). A wrong code says “That code doesn't look right.”; a window with no secure context says so. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| passphrase prompt backdrop<br><sub>when `dlgAdminPass`</sub> | click → `closeAdminPass` | — | Closes the passphrase prompt; the typed passphrase is dropped. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| passphrase prompt panel<br><sub>when `dlgAdminPass`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — not pressed on this dialog; the same handler passed on About and Add entry |
| field “passphrase”<br><sub>when `dlgAdminPass`</sub> | change → `onAdminPass`<br>key → `adminPassKey` | `maintenance_backup` → `maintenance.backup`<br>`maintenance_rotate_root` → `maintenance.rotate_root`<br>`maintenance_doctor` → `maintenance.doctor` | **change:** Held in memory outside the page state; nothing is sent. **key:** Enter submits the prompt (same as its action button). | **pass** — backup prompt: passphrase and repeat held; Enter submits |
| field “repeat the passphrase”<br><sub>when `adminPassRepeatShow`</sub> | change → `onAdminRepeat`<br>key → `adminPassKey` | `maintenance_backup` → `maintenance.backup`<br>`maintenance_rotate_root` → `maintenance.rotate_root`<br>`maintenance_doctor` → `maintenance.doctor` | **change:** Held in memory outside the page state; nothing is sent. **key:** Enter submits the prompt (same as its action button). | **pass** — repeat-passphrase field held (backup prompt) |
| field “new passphrase”<br><sub>when `adminPassNewShow`</sub> | change → `onAdminNew`<br>key → `adminPassKey` | `vault_set_passphrase` → `vault.set_passphrase` (on Enter) | Holds the new passphrase for a passphrase change; Enter submits like the action button. Empty, different from the repeat, or the same as the current one is refused in the dialog and nothing is sent. | **not pressed** — new in ADR-156 (2026-11-09); covered by `tests/unit/quick-wins.test.ts` against the fixture broker, not yet pressed in a built app |
| field “repeat the new passphrase”<br><sub>when `adminPassNewShow`</sub> | change → `onAdminNewRepeat`<br>key → `adminPassKey` | `vault_set_passphrase` → `vault.set_passphrase` (on Enter) | Holds the repeat; it must match the new passphrase. | **not pressed** — new in ADR-156 (2026-11-09); covered by `tests/unit/quick-wins.test.ts` against the fixture broker, not yet pressed in a built app |
| passphrase prompt action (Back up · Rotate · Apply · Rebuild · Change passphrase)<br><sub>when `dlgAdminPass`</sub> | click → `submitAdminPass` | `maintenance_backup` → `maintenance.backup`<br>`maintenance_rotate_root` → `maintenance.rotate_root`<br>`maintenance_doctor` → `maintenance.doctor` | Back up: an encrypted archive is written ("Backup written."). Rotate: the broker checks the human, admin and second factor and then refuses with presence_required — nothing changes. Apply / Rebuild: Doctor runs (a registry rebuild is refused for presence). | **pass** — Back up: "Backup written."; archive in the vault's backups folder (credmgr-backup-….enc); Rotate… in the prompt: broker refuses with presence_required (maintenance.rotate_root), nothing changes |
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
| field “search help topics”<br><sub>when `dlgHelp`</sub> | change → `onHelpQ` | — | Filters the help topics as typed; nothing is sent and nothing typed is stored. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/help-search.spec.ts`; built-app re-walk pending (§15) |
| button “Clear”<br><sub>when `dlgHelp` · `helpHasQuery`</sub> | click → `helpClear` | — | Empties the search and shows all topics. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/help-search.spec.ts`; built-app re-walk pending (§15) |
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
| button “Play” (one per game)<br><sub>when `gmIsLibrary`</sub><br><sub>each row of `gamesRows`</sub> | click → `g.open` | — | Opens that game's menu. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “← all games” (CredPong menu)<br><sub>when `gmIsPongMenu`</sub> | click → `gmBackToLibrary` | — | Stops the game's listeners and returns to the list of games. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “✕” (close, CredPong menu)<br><sub>when `gmIsPongMenu`</sub> | click → `cpClose` | — | Closes the Games overlay. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “Bottom”<br><sub>when `cpIsMenu`</sub> | click → `cpSetModeBottom` | — | Chooses the play mode. Nothing is sent. | **pass** — Bottom mode selects ("Classic — paddle at the bottom") |
| button “Side”<br><sub>when `cpIsMenu`</sub> | click → `cpSetModeSide` | — | Chooses the play mode. Nothing is sent. | **pass** — Side mode selects |
| button “Free-roam”<br><sub>when `cpIsMenu`</sub> | click → `cpSetModeRoam` | — | Chooses the play mode. Nothing is sent. | **pass** — Free-roam mode selects |
| button “Start — space to launch”<br><sub>when `cpIsMenu`</sub> | click → `cpStart` | — | Starts (or restarts) CredPong. Nothing is sent. | **pass** — Start (and Space) launches; score and lives shown; level shaped by node counts |
| button “← all games” (other games' menu)<br><sub>when `gmIsGenericMenu`</sub> | click → `gmBackToLibrary` | — | As above. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “✕” (close, other games' menu)<br><sub>when `gmIsGenericMenu`</sub> | click → `cpClose` | — | Closes the Games overlay. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button: a choice of a game option<br><sub>when `gmIsGenericMenu`</sub><br><sub>each row of `gmOptions` · `o.choices`</sub> | click → `ch.go` | — | Selects that choice for the game's option; held in the window. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “Start”<br><sub>when `gmIsGenericMenu`</sub> | click → `gmStart` | — | Starts the game. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “✕ exit”<br><sub>when `cpIsPlay`</sub> | click → `cpExit` | — | Leaves the game. Nothing is sent. | **fail** — F-11 (P3): the first Esc left the game; the expected pause did not happen. Esc left the game (it exited on the first Esc, with no pause step; F-12 cosmetic) |
| button “Play again”<br><sub>when `gmIsOver`</sub> | click → `gmStart` | — | Starts the game again. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “Back to menu”<br><sub>when `gmIsOver`</sub> | click → `gmBackToMenu` | — | Returns to that game's menu. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |

### Settings — `S12-settings`

Security, Appearance, Backup, Mode, Grants and Games in both modes, and (Pro) Nodes, Maintenance, Audit, Advanced and Operations.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop<br><sub>when `dlgCaptureOff`</sub> | click → `cancelCaptureOff` | — | Clicking outside the “allow screen capture?” dialog closes it and keeps the window hidden from capture. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/capture-protection.spec.ts`; built-app re-walk pending (§15) |
| settings panel<br><sub>when `ovSettings`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — - |
| button “Keep it hidden”<br><sub>when `dlgCaptureOff`</sub> | click → `cancelCaptureOff` | — | Closes the dialog; the window stays hidden from screen capture and screen sharing. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/capture-protection.spec.ts`; built-app re-walk pending (§15) |
| button “Allow capture”<br><sub>when `dlgCaptureOff`</sub> | click → `confirmCaptureOff` | — (shell: `capture_protection_set`) | Turns the window's protection from capture off (the choice is kept for this install) and closes the dialog; the shell is told through `capture_protection_set`, which never reaches the broker. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/capture-protection.spec.ts`; built-app re-walk pending (§15) |
| settings backdrop<br><sub>when `ovSettings`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **n/a** — backdrop not pressed on Settings |
| dialog panel (the “allow screen capture?” confirmation)<br><sub>when `dlgCaptureOff`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/capture-protection.spec.ts`; built-app re-walk pending (§15) |
| settings section tab<br><sub>when `ovSettings`</sub><br><sub>each row of `settingsNav`</sub> | click → `s.go` | `audit_tail` → `audit.tail` | Shows that section: Security · Appearance · Backup · Mode · Grants · Games (Lite and Pro) and Nodes · Maintenance · Audit · Advanced · Operations (Pro only). Audit reads the trail; Operations opens the panel. | **pass** — section tabs switch (Lite shows Security/Appearance/Backup/Mode/Grants/Games; Pro adds Nodes/Maintenance/Audit/Advanced/Operations); Audit and Operations sections open |
| button “Help ?”<br><sub>when `ovSettings`</sub> | click → `openHelp` | — | Opens the Help dialog. Nothing is sent. | **n/a** — Settings Help ? not pressed |
| button “Close”<br><sub>when `ovSettings`</sub> | click → `closeOverlay` | — | The overlay (settings, operations) closes. Nothing is sent. | **n/a** — - |
| select “auto-lock after”<br><sub>when `setSecurity`</sub> | change → `onAutoLock` | — | Sets the idle auto-lock (this window's timer; saved in credmgr_prefs). Nothing is sent to the broker. | **pass** — auto-lock select not changed here; auto-lock select offers 5 min, 15 min, 60 min, never (warned); 5 min set and kept |
| second-factor button ("Set up…" / "Replace…")<br><sub>when `setSecurity`</sub> | click → `openGateEnrol` | `vault_gate_enroll_begin` → `vault.gate_enroll_begin` | Stages a second-factor setup (or replacement) and shows its QR code and secret. | **pass** — Set up… stages a second factor with QR and secret |
| select “reveal window”<br><sub>when `setSecurity`</sub> | change → `onRevealWindow` | — | Sets how long a revealed value stays visible (saved in credmgr_prefs). Nothing is sent. | **pass** — reveal window select not changed (re-mask at the 20 s default verified); reveal window select offers 10 s, 20 s, 60 s; set to 10 s |
| button “Turn off”<br><sub>when `setSecurity` · `touchShow` · `touchOn`</sub> | click → `touchTurnOff` | `device_remove` → `device.remove`; `presence_unenrol` → `presence.unenrol` (each key) | Stops unlocking with Touch ID and forgets this Mac's presence key; each removal asks for a Touch ID check. Notice “Touch ID is off.”; a refusal is shown in words and nothing is half-removed silently. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “Set up”<br><sub>when `setSecurity` · `touchShow` · `touchOff`</sub> | click → `touchSetUp` | (`presence_key_create` shell) → `presence_enrol` → `presence.enrol`; `device_enrol` → `device.enrol` | Creates this Mac's key in the Secure Enclave (Touch ID check), enrols its public key as a presence key and the device wrap for unlocking; notice “Touch ID is on. You can unlock with it from the Lock screen.” Passphrase and recovery code keep working. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “Change…” (passphrase)<br><sub>when `setSecurity`</sub> | click → `openChangePassphrase` | — | Opens the passphrase prompt in its change form: the current passphrase, then the new one twice. Nothing is sent yet; the action sends `vault_set_passphrase` → `vault.set_passphrase` and ends in the one-time recovery-code panel. | **not pressed** — new in ADR-156 (2026-11-09); covered by `tests/unit/quick-wins.test.ts` against the fixture broker, not yet pressed in a built app |
| button “on / off” (start the broker at login, macOS)<br><sub>when `setSecurity` · `loginAgentShow`</sub> | click → `toggleLoginAgent` | — (shell: `login_agent_install`) | Off → on: writes the per-user launchd agent and starts `credmgrd` ("The broker now starts when you log in."). On → off: asks once more first (the two buttons below). | **not pressed** — new in ADR-156 (2026-11-09); covered by `tests/unit/quick-wins.test.ts` against the fixture broker, not yet pressed in a built app |
| button “Turn off” (start at login)<br><sub>when `setSecurity` · `loginAgentShow` · `loginAgentOffAsk`</sub> | click → `confirmLoginAgentOff` | — (shell: `login_agent_uninstall`) | Removes the agent and stops the broker it started, which locks the vault. | **not pressed** — new in ADR-156 (2026-11-09); covered by `tests/unit/quick-wins.test.ts` against the fixture broker, not yet pressed in a built app |
| button “Keep it” (start at login)<br><sub>when `setSecurity` · `loginAgentShow` · `loginAgentOffAsk`</sub> | click → `keepLoginAgent` | — | Closes the question; the agent stays. Nothing is sent. | **not pressed** — new in ADR-156 (2026-11-09); covered by `tests/unit/quick-wins.test.ts` against the fixture broker, not yet pressed in a built app |
| button “Bind…” / “Unbind…” (machine lock)<br><sub>when `setSecurity` · `machineLockShow`</sub> | click → `toggleMachineLock` | — (opens the dialog) | Opens the machine-lock dialog: Bind… asks to lock the vault to this Mac, Unbind… asks to turn it off. Disabled while a change runs, and Bind… is disabled on a vault with no recovery code (the caption says to change the passphrase once). The row's caption and chip are read from `keystore_status` → `keystore.status` when Security opens: “on · file” names a device key file on this Mac, never the Secure Enclave. When status says a bind did not finish (projects still on a pre-bind key) the button reads Bind… again and the chip is amber; when it says an older plain passphrase file sits under a vault recorded as bound, the chip is red and the caption says so. Nothing is sent by this click. | **not pressed** — new in ADR-165 (2026-11-14); covered by `tests/unit/machine-lock.test.ts` against the fixture broker, not yet pressed in a built app |
| dialog backdrop (the machine-lock dialog)<br><sub>when `dlgMachineLock`</sub> | click → `cancelMachineLock` | `keystore_bind` → `keystore.bind` (`phase: "cancel"`, only when a bind was prepared) | Clicking outside the dialog closes it; nothing changes. Between the two bind steps it tells the broker to forget the prepared bind (re-review N1); otherwise nothing is sent. | **not pressed** — new in ADR-165 (2026-11-14); covered by `tests/unit/machine-lock.test.ts` against the fixture broker, not yet pressed in a built app |
| dialog panel (the machine-lock dialog)<br><sub>when `dlgMachineLock`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the dialog stays open. Nothing is sent. | **not pressed** — new in ADR-165 (2026-11-14); covered by `tests/unit/machine-lock.test.ts` against the fixture broker, not yet pressed in a built app |
| button “Next” / “Turn the lock on” / “Turn off” (machine lock)<br><sub>when `dlgMachineLock`</sub> | click → `confirmMachineLock` | `keystore_bind` → `keystore.bind` (`phase: "prepare"`, then `"commit"`); `keystore_unbind` → `keystore.unbind` | Bind, step one (“Next”): the dialog has said that copies made before now still open with the passphrase and show what they held, that a replaced Mac or another Mac sharing the folder needs the recovery code, that Time Machine, disk images, Migration Assistant and CredMgr backups are not covered (and that backups are kept outside the vault folder while the lock is on), and that a NEW recovery code is shown and must be typed back before anything changes. An empty passphrase or recovery code is refused in the dialog and nothing is sent. The broker proves the passphrase and the CURRENT recovery code (a wrong one: a notice, nothing changed, counted in the back-off) and answers the new code; **nothing has changed yet** and the row still reads “off”. Step two (“Turn the lock on”): the new code is shown with “Nothing has changed yet”; an empty retype is refused in the dialog, a wrong one says it is not the code shown and nothing changed (not counted), and the right one replaces the root key and every project key and seals the passphrase file; no recovery dialog follows (the code was just typed); the row turns “on · file”. A commit after the prepared bind ran out or was overtaken: a notice, nothing changed, the current code still works. Unbind: Touch ID is asked where it is set up and a fresh second factor where one is on; where neither is, the passphrase typed in the dialog (otherwise a notice, nothing changed); the row turns “off” and the device key stays. | **not pressed** — new in the ADR-165 review fixes (2026-11-14); covered by `tests/unit/machine-lock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` for the shell, not yet pressed in a built app |
| button “Cancel” / “Keep it on” (machine lock)<br><sub>when `dlgMachineLock`</sub> | click → `cancelMachineLock` | `keystore_bind` → `keystore.bind` (`phase: "cancel"`, only when a bind was prepared) | Closes the dialog; nothing changes. Between the two bind steps it tells the broker to forget the prepared bind, and the old recovery code stays the vault's (re-review N1); otherwise nothing is sent. | **not pressed** — new in ADR-165 (2026-11-14); covered by `tests/unit/machine-lock.test.ts` against the fixture broker, not yet pressed in a built app |
| field “vault passphrase” (machine lock, bind)<br><sub>when `machineLockBind`</sub> | change → `onMachineLockPass`<br>key → `machineLockKey` | `keystore_bind` → `keystore.bind` (on Enter) | **change:** Held in memory outside the page state (masked), wiped when the dialog closes or the vault locks; nothing is sent. **key:** Enter submits like “Next”. | **not pressed** — new in the ADR-165 review fixes (2026-11-14); covered by `tests/unit/machine-lock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` for the shell, not yet pressed in a built app |
| field “current recovery code” (machine lock, bind)<br><sub>when `machineLockBind`</sub> | change → `onMachineLockCode`<br>key → `machineLockKey` | `keystore_bind` → `keystore.bind` (on Enter) | **change:** Held in memory outside the page state (masked), wiped when the dialog closes or the vault locks; nothing is sent. **key:** Enter submits like “Next”. | **not pressed** — new in the ADR-165 review fixes (2026-11-14); covered by `tests/unit/machine-lock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` for the shell, not yet pressed in a built app |
| field “new recovery code, typed back” (machine lock, bind step two)<br><sub>when `machineLockConfirmStep`</sub> | change → `onMachineLockRetype`<br>key → `machineLockKey` | `keystore_bind` → `keystore.bind` (`phase: "commit"`, on Enter) | **change:** Held in memory outside the page state, wiped when the dialog closes or the vault locks; nothing is sent. Spaces around it are trimmed. **key:** Enter submits like “Turn the lock on”. | **not pressed** — new in the ADR-165 re-review fixes (2026-11-14); covered by `tests/unit/machine-lock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` for the shell, not yet pressed in a built app |
| field “vault passphrase” (machine lock, unbind)<br><sub>when `machineLockUnbind`</sub> | change → `onMachineLockPass`<br>key → `machineLockKey` | `keystore_unbind` → `keystore.unbind` (on Enter) | **change:** Held in memory outside the page state (masked); sent only when typed, and needed only where neither Touch ID nor a second factor is set up. **key:** Enter submits like “Turn off”. | **not pressed** — new in the ADR-165 review fixes (2026-11-14); covered by `tests/unit/machine-lock.test.ts` against the fixture broker and `src-tauri/tests/bridge_ops.rs` for the shell, not yet pressed in a built app |
| button “on / off” (confirm before showing secrets)<br><sub>when `setSecurity` · `rcShow`</sub> | click → `toggleRevealConfirm` | `node_policy` → `node.policy` (`node: global`, `revealConfirm`) | Default off. Turning it on saves at once (trust window 5 min). Turning it off asks for a confirmation first; cancelled, it stays on. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |
| select “trust window”<br><sub>when `setSecurity` · `rcShow` · `rcWindowShow`</sub> | change → `onRcWindow` | `node_policy` → `node.policy` | 1 / 5 / 15 / 60 min. A shorter window saves at once; a longer one asks for a confirmation first. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |
| select “when to ask” (Pro)<br><sub>when `setSecurity` · `rcShow` · `rcProShow`</sub> | change → `onRcMode` | `node_policy` → `node.policy` | Once per trust window, or every time (each secret asks). Every time saves at once; back to the window asks for a confirmation first. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |
| select “which secrets” (Pro)<br><sub>when `setSecurity` · `rcShow` · `rcProShow`</sub> | change → `onRcScope` | `node_policy` → `node.policy` | All secrets, or only high and critical (low and medium show without asking). Narrowing to high and critical asks for a confirmation first. | **not pressed** — new (ADR-150); automated: `tests/e2e/reveal-confirm.spec.ts`; built-app re-walk pending (§15) |
| button “on / off” (hide the window from screen capture and screen sharing)<br><sub>when `setSecurity`</sub> | click → `toggleCaptureProtection` | — (shell: `capture_protection_set`) | Turning protection OFF opens the confirmation dialog (focus on “Keep it hidden”); turning it ON applies at once. Nothing reaches the broker. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/capture-protection.spec.ts`; built-app re-walk pending (§15) |
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
| button “on / off” (single-key shortcuts)<br><sub>when `setAppearance`</sub> | click → `toggleSingleKeys` | — | Off keeps the modifier shortcuts only (WCAG 2.1.4); the choice is kept in this window's local storage (`credmgr_keys`), or until the window closes if storage refuses. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/wp-d-about.spec.ts`; built-app re-walk pending (§15) |
| greyscale toggle<br><sub>when `setAppearance`</sub> | click → `toggleGreyscale` | — | Toggles a greyscale filter. Nothing is sent. | **pass** — greyscale toggles on/off |
| button “Enter code”<br><sub>when `setAppearance` · `cosmLockedShow`</sub> | click → `cosmHowTo` | — | Closes Settings and opens the supporter reminder on its code step. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button: a graph look option (Appearance extras)<br><sub>when `setAppearance`</sub><br><sub>each row of `cosmGraph` · `g.opts`</sub> | click → `o.set` | — | Sets that graph option; options that belong to the supporter extras are disabled until a code is entered. Held in the window only; nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| glyph weight choice (classic · fine · heavy)<br><sub>when `setAppearance`</sub><br><sub>each row of `cosmGlyphs`</sub> | click → `g.set` | — | Chooses the glyph weight. Nothing is sent. | **pass** — glyph weight classic, fine, heavy select |
| halo toggle<br><sub>when `setAppearance`</sub> | click → `toggleCosmHalo` | — | Toggles the halo. Nothing is sent. | **pass** — halo toggles |
| graph mark choice (keep · cells · node + ring · seal)<br><sub>when `setAppearance`</sub><br><sub>each row of `cosmMarks`</sub> | click → `m.set` | — | Chooses the graph mark. Nothing is sent. | **pass** — keep, cells, node + ring, seal marks each select |
| button: an identity option (Appearance extras)<br><sub>when `setAppearance`</sub><br><sub>each row of `cosmIdentity` · `g.opts`</sub> | click → `o.set` | — | Sets that identity option (extras only when unlocked). Held in the window only; nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button: a motion option (Appearance extras)<br><sub>when `setAppearance`</sub><br><sub>each row of `cosmMotion` · `g.opts`</sub> | click → `o.set` | — | Sets that motion option (extras only when unlocked). Held in the window only; nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button: a games option (Appearance extras)<br><sub>when `setAppearance`</sub><br><sub>each row of `cosmGames` · `g.opts`</sub> | click → `o.set` | — | Sets that games option (extras only when unlocked). Held in the window only; nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/extras.spec.ts`; built-app re-walk pending (§15) |
| button “Back up now”<br><sub>when `setBackup`</sub> | click → `openBackupPrompt` | — | Opens the passphrase prompt for a backup. Nothing is sent yet. | **pass** — Back up now opens the passphrase prompt; Back up now opens the prompt |
| select “backup retention”<br><sub>when `isPro`</sub> | change → `onRetain` | — | Chooses how many backup archives to keep. Nothing is sent now. | **pass** — retention select offers 14 and 30 archives |
| button “Verify now”<br><sub>when `setBackup`</sub> | click → `runVerify` | `maintenance_verify` → `maintenance.verify` | Verifies every manifest, envelope digest, registry binding and seal record; the chip shows "ok · N nodes checked" or the problems. | **pass** — Verify now: chip "ok · 3 nodes checked" |
| button “Lite”<br><sub>when `setMode`</sub> | click → `setLite` | — | Switches to Lite (saved locally). Nothing is sent. | **pass** — Lite applied: sections reduce to Security, Appearance, Backup, Mode, Grants, Games |
| button “Pro”<br><sub>when `setMode`</sub> | click → `setPro` | — | Switches to Pro (saved locally). Nothing is sent. | **pass** — Pro applied: sections come back |
| button “Open” (one per game)<br><sub>when `setGames`</sub><br><sub>each row of `gamesRows`</sub> | click → `g.open` | — | Closes Settings' list and opens that game's menu (the Games overlay). Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; built-app re-walk pending (§15) |
| button “Remove…”<br><sub>when `setNodes`</sub><br><sub>each row of `settingsNodeRows`</sub> | click → `n.seal` | — | Opens the Remove (seal) dialog for that node. Nothing is sent yet. | **pass** — Remove… opens the seal dialog (Settings → Nodes) |
| button “+ New project”<br><sub>when `setNodes`</sub> | click → `openAddNodeDlg` | — | Opens the New node dialog. Nothing is sent. | **pass** — + New project opens New node; creating xq7rt works ("Node “xq7rt” created.") |
| button “Restore node”<br><sub>when `setNodes`</sub><br><sub>each row of `sealedRows`</sub> | click → `s.restore` | `node_restore` → `node.restore` | Restores the sealed node within its 7 days: "Node “x” restored." and it is selected. The rows come from the broker's own list of sealed nodes (`graph.snapshot` `meta.sealed`, ADR-080), so they survive a lock and a daemon restart, and each shows the real end of its window ("restorable until <time>"); a login that is not given the list (an agent, a non-Admin) sees only what this session sealed, with the rule "restorable for 7 days after sealing". After the window: archive_expired, and the app says so. | **pass** — (partial) sealed node listed with real window "restorable until 2026-10-25 11:00"; restore tested in J8; sealed node xq7rt listed in Settings → Nodes with its real window after lock, unlock, broker restart; Restore returned it ("Node “xq7rt” restored."), value byte-identical (CLI compare), verify clean |
| button “Revoke”<br><sub>when `setGrants`</sub><br><sub>each row of `grantRows`</sub> | click → `g.revoke` | `grant_revoke` → `grant.revoke` | Revokes that grant: "Grant revoked.", the grant disappears from the list and from the graph. | **n/a** — not pressed in this pass |
| button “+ New grant”<br><sub>when `isPro`</sub> | click → `openGrantDlg` | — | Opens the grant dialog (Pro). Nothing is sent. | **pass** — + New grant opens the Grant dialog |
| button “Open Operations panel”<br><sub>when `setMaint`</sub> | click → `openOps` | — | Opens the Operations panel. Nothing is sent. | **pass** — Open Operations panel |
| button “Tidy up…”<br><sub>when `setMaint`</sub> | click → `openTidy` | `vault_doctor_scan` → `vault.doctor_scan` | Opens Tidy up and runs a scan if no report is in memory (a report already read is shown as it is). No value is shown and nothing changes. | **not pressed** — new in ADR-161 (2026-11-14); automated: `tests/unit/doctor-scan.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Refresh”<br><sub>when `setAudit`</sub> | click → `refreshAudit` | `audit_tail` → `audit.tail` | Reads the audit trail again (newest first). | **pass** — Refresh re-reads the trail |
| audit row<br><sub>when `setAudit`</sub><br><sub>each row of `auditRows`</sub> | click → `a.open` | `audit_get` → `audit.get` | Asks for the full record; the broker refuses with presence_required and the app says so. | **pass** — an audit row: "Needs presence (Touch ID)… Nothing was changed. (audit.get)" |
| button “Rotate…”<br><sub>when `setAdvanced`</sub> | click → `openRotatePrompt` | — | Opens the passphrase prompt for a root-key rotation. Nothing is sent yet. | **pass** — (Settings → Advanced Rotate… same prompt; tested through Operations); Rotate… opens the passphrase prompt (refused for presence, see 292) |
| select “report range”<br><sub>Settings › Audit report</sub> | change → `onArRange` | — | Chooses the report's range: the last 24 hours, one of the offered day counts, or between two dates (UTC), which shows the two date boxes. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| select “report node”<br><sub>Settings › Audit report</sub> | change → `onArNode` | — | Limits the report to one node; the default covers every node. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Make report”<br><sub>Settings › Audit report</sub> | click → `arRun` | `audit_report` → `audit.report` | Reads the audit trail for the chosen range and node and shows the summary. The button reads “Reading…” while it works; a failure says the report could not be made. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| field “report from date” (YYYY-MM-DD)<br><sub>when `arDatesShow`</sub> | change → `onArFrom` | — | Holds the start day of a date range. A malformed day is said in words when Make report is pressed. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| field “report to date” (YYYY-MM-DD)<br><sub>when `arDatesShow`</sub> | change → `onArTo` | — | Holds the end day of a date range, checked the same way. Nothing is sent. | **not pressed** — new in rc.2 §1; not yet pressed in a built app |
| button “Restore”<br><sub>when `auditRemovedShow` · each row of `auditRemoved`</sub> | click → `r.restore` | `entry_restore` → `entry.restore` | Brings that entry, removed in the last seven days, back as it was; the list reads again. If its name has been taken, Restore as a copy is offered. | **not pressed** — new in ADR-166; not yet pressed in a built app |
| button “Restore as a copy”<br><sub>when `r.copyShow` · each row of `auditRemoved`</sub> | click → `r.copy` | `entry_restore` (keep both) → `entry.restore` | Restores the removed entry under a free name, next to the entry that took its name. | **not pressed** — new in rc.2 §1 (undo a removal, keep both); not yet pressed in a built app |
| button “Restore…”<br><sub>Settings › Backup</sub> | click → `openRestore` | — | Opens the Restore from a backup dialog. Nothing is sent until Restore is pressed in it. | **not pressed** — new in ADR-166; not yet pressed in a built app |

### Agents — `S21-agents`

Settings → Agents (ADR-143): which coding assistants are on this Mac, and how to wire them to CredMgr. Reads their configuration files and writes none until the review dialog's Write button.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| button “Copy configuration” / “Copy command” (one per assistant)<br><sub>when `setAgents`</sub><br><sub>each row of `agentRows`</sub> | click → `a.copy` | (shell: `agent_snippet`, `copy_text`) | Copies that assistant's configuration text (for Claude Code, the command to run) through the shell; the button says “copied ✓” or “copy failed”. Reads and writes no file; no vault value is in the text. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| button “Connect…” (an assistant found and not connected)<br><sub>when `setAgents` · `a.canConnect`</sub><br><sub>each row of `agentRows`</sub> | click → `a.connect` | (shell: `agent_plan`) | Draws the change as a diff in the review dialog; writes nothing. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| button “Disconnect…” (a connected assistant)<br><sub>when `setAgents` · `a.canDisconnect`</sub><br><sub>each row of `agentRows`</sub> | click → `a.disconnect` | (shell: `agent_plan`) | Draws the removal as a diff in the review dialog; writes nothing. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| button: copy the generic configuration<br><sub>when `setAgents`</sub> | click → `agentCopyGeneric` | (shell: `agent_snippet`, `copy_text`) | Copies the generic MCP configuration text through the shell. Nothing is written. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| button: copy the vault prompt<br><sub>when `setAgents`</sub> | click → `agentCopyPrompt` | (shell: `agent_prompt`, `copy_text`) | Copies a prompt built from the selected node's name, the nodes it reaches and its level: names only, never a value. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| button: copy `CREDMGR.md`<br><sub>when `setAgents`</sub> | click → `agentCopyMd` | (shell: `agent_prompt`, `copy_text`) | Copies the text of `CREDMGR.md` for that node through the shell. Nothing is written to disk. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| button “Approve” (an agent's waiting setting request)<br><sub>when `setAgents`</sub><br><sub>each row of `settingRequests`</sub> | click → `r.approve` | `settings_request_decide` → `settings.request_decide` | Approves the agent's request (ADR-155). A weakening change first asks the owner to confirm (Touch ID or passphrase); then the setting changes, the row leaves the list and the settings are read again. A cancelled confirmation changes nothing. | not looked at |
| button “Deny” (an agent's waiting setting request)<br><sub>when `setAgents`</sub><br><sub>each row of `settingRequests`</sub> | click → `r.deny` | `settings_request_decide` → `settings.request_decide` | Denies the request (ADR-155); nothing changes and the row leaves the list. | seen 2026-11-09 in the test build (§16a), not yet in the signed `.app` |
| button “Issue token…” (Agent tokens)<br><sub>when `setAgents`</sub> | click → `openAgentToken` | — | Opens the Issue dialog on the selected node (or the first project) with list and read ticked and one day. Nothing is sent. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Revoke” (one per live agent token)<br><sub>when `setAgents`</sub><br><sub>each row of `atRows`</sub> | click → `t.revoke` | `agent_token_revoke` → `agent.token_revoke` | Ends that token: notice “Revoked “…”. The next request with it is refused.” and the list is read again (`agent.token_status`). No Touch ID. A token that had already ended says so. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |

### Review the change to an assistant's file — `dlg-agent`

The dialog Connect… and Disconnect… open: the diff of the file CredMgr would write (ADR-142).

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog backdrop<br><sub>when `dlgAgent`</sub> | click → `agentCancel` | — | Closes the review dialog; nothing is written. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| dialog panel<br><sub>when `dlgAgent`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| button “Cancel”<br><sub>when `dlgAgent`</sub> | click → `agentCancel` | — | Closes the review dialog; nothing is written. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |
| button “Write this change” (reads “Writing…”)<br><sub>when `dlgAgent` · `agentDlgCanWrite`</sub> | click → `agentConfirm` | (shell: `agent_apply`) | The shell writes the file only if it is still what the diff showed (the plan's token is sent back), keeps a copy of the original beside it, and never edits Claude Code's own state file. Notice says to restart the assistant. | **not pressed** — new since the 2026-10-18 pass; automated: `tests/e2e/agents.spec.ts`; built-app re-walk pending (§15) |

### Issue an agent token — `dlg-agent-token`

The dialog “Issue token…” opens (ADR-164): a token for one node, shown once. The backdrop does not close it, so the token is not lost by a stray click.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| dialog panel (agent token)<br><sub>when `dlgAgentToken`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |
| select “the node the token is for”<br><sub>when `dlgAgentToken` · `atFormShow`</sub> | change → `onAtNode` | — | Chooses the node; neither the Orphaned node nor Global is offered (the broker refuses both). Nothing is sent. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |
| text box “a name for the agent that will hold the token”<br><sub>when `dlgAgentToken` · `atFormShow`</sub> | change → `onAtLabel` | — | Holds the label (at most 64 characters). Nothing is sent. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |
| checkbox per capability (list names · read metadata · reveal values · add entries · change entries)<br><sub>when `dlgAgentToken` · `atFormShow`</sub><br><sub>each row of `atCaps`</sub> | change → `c.toggle` | — | Ticks or unticks what the token may do. Nothing is sent. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |
| select “how long the token lasts”<br><sub>when `dlgAgentToken` · `atFormShow`</sub> | change → `onAtExpires` | — | 1 hour, 8 hours, 1 day (the default) or 7 days. Nothing is sent. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Cancel”<br><sub>when `dlgAgentToken` · `atFormShow`</sub> | click → `closeAgentToken` | — | Closes the dialog; nothing typed is kept. Nothing is sent. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Issue token” (reads “Waiting for Touch ID…”)<br><sub>when `dlgAgentToken` · `atFormShow`</sub> | click → `issueAgentToken` | `agent_token_issue` → `agent.token_issue` (the shell answers `presence_required` with Touch ID, then puts the token on the concealed clipboard) | With a name and at least one capability: Touch ID appears; on success the dialog says what the token allows and when it expires, and that the token is on the clipboard (concealed, cleared after 30 seconds and at lock) and is not shown anywhere: paste it into the agent's settings now. Paste once to check it arrives, and wait 30 seconds to check the clipboard empties. If the clipboard could not take it, the dialog says the token was revoked, or, when the vault locked in between, that it will be revoked at the next unlock (unlock and check the list). Touch ID names the project, the capabilities, the life and the label. The list is read again. A capability the node does not give agents is refused in the dialog; no Touch ID key means the presence notice and no token; a second factor that is not fresh asks for one. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Done”<br><sub>when `dlgAgentToken` · `atIssuedShow`</sub> | click → `closeAgentToken` | — | Closes the dialog; its form and summary leave the page (any other close, Escape or a lock, does the same). The token was never in the page. Nothing is sent. | **not pressed** — new in ADR-164 (2026-11-14); automated: `tests/unit/agent-tokens.test.ts` against the fixture broker; not yet pressed in a built app |

### Operations panel — `S14-ops`

Pro: Verify, Doctor, Back up, Rotate root key, Audit report, Tidy up.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| area “operations · pro ⌘⇧O”<br><sub>when `ovOps`</sub> | click → `scrimClose` | — | Clicking outside the panel closes the open dialog or overlay. Nothing is sent. Text typed in the dialog is discarded. | **n/a** — - |
| area “operations · pro ⌘⇧O”<br><sub>when `ovOps`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **n/a** — - |
| button “{{o.label}}”<br><sub>when `ovOps`</sub><br><sub>each row of `opsRows`</sub> | click → `o.run` | `maintenance_verify` → `maintenance.verify`<br>`maintenance_doctor` → `maintenance.doctor`<br>`audit_tail` → `audit.tail` | Verify integrity: as Settings → Backup → Verify now. Doctor: a dry run listing what it would fix (Apply and Rebuild appear as result actions). Back up vault…: opens the passphrase prompt. Rotate root key…: opens the prompt; the rotation is refused for presence. Audit report: reads the last 30 days of audit records and lists denied requests and grant changes. | **pass** — Verify integrity: "ok · 4 nodes checked"; Doctor dry run: "nothing needs fixing"; Back up vault opens the prompt; Rotate root key refused with the presence notice and nothing changed; Audit report lists denied and grant records |
| result action ("Apply N fixes" · "Rebuild registry…")<br><sub>when `opsResultHasActions`</sub><br><sub>each row of `opsResultActions`</sub> | click → `x.go` | `maintenance_doctor` → `maintenance.doctor` | Apply N fixes: Doctor applies the fixes it listed. Rebuild registry…: opens the passphrase prompt; the rebuild is refused for presence. | **n/a** — no Doctor fixes to apply, so no result actions appeared |
| button “Close”<br><sub>when `ovOps`</sub> | click → `closeOverlay` | — | The overlay (settings, operations) closes. Nothing is sent. | **pass** — Close |

### Tidy up — `S22-tidy`

The doctor's tidy-up scan, phase 1 (ADR-161, `vault.doctor_scan`): shared values, near-identical names, misfiled, weak, mistyped, expired, expiring and stale entries, each with what to do. It never shows a value and changes nothing; a "Move to …" opens the entry's own Move dialog (`dlg-move`, ADR-158), and "Apply all moves" (ADR-169, `vault.doctor_apply`) applies every move of the report after a confirm that lists each one.

| Control | Event | Bridge command → broker op | Expected result | Result |
|---|---|---|---|---|
| area “tidy up”<br><sub>when `ovTidy`</sub> | click → `scrimClose` | — | Clicking outside the panel closes Tidy up. Nothing is sent; the report stays in memory until the vault locks. | **not pressed** — new in ADR-161 (2026-11-14); automated: `tests/unit/doctor-scan.test.ts` against the fixture broker; not yet pressed in a built app |
| area “tidy up”<br><sub>when `ovTidy`</sub> | click → `stop` | — | A click inside the panel does not reach the backdrop, so the panel stays open. Nothing is sent. | **not pressed** — new in ADR-161 (2026-11-14); automated: `tests/unit/doctor-scan.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Scan” / “Scan again” / “Scanning…”<br><sub>when `ovTidy`</sub> | click → `tidyRescan` | `vault_doctor_scan` → `vault.doctor_scan` | Scans the vault and lists the findings by kind with how many entries, projects and values were read; nodes it could not read (locked, needs its second factor) are listed under “Not fully scanned”; a vault with nothing to tidy says so. Disabled while a scan runs; a scan already running says to try again in a few seconds. No value is ever shown. | **not pressed** — new in ADR-161 (2026-11-14); automated: `tests/unit/doctor-scan.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Move to <project>”<br><sub>when `ovTidy` · `r.moveShow`</sub><br><sub>each row of `g.rows`</sub><br><sub>each row of `tidyGroups`</sub> | click → `r.move` | — (then `entry_move` → `entry.move` from the dialog) | Opens the Move dialog for that entry with the proposed project chosen. Nothing is sent until the dialog's Move entry (Touch ID, and a fresh code when a second factor is on); after the move the scan runs again and the finding is gone. | **not pressed** — new in ADR-161 (2026-11-14); automated: `tests/unit/doctor-scan.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Merge into <name>”<br><sub>when `ovTidy` · `r.mergeShow`</sub><br><sub>each row of `g.rows`</sub><br><sub>each row of `tidyGroups`</sub> | click → `r.merge` | `merge_apply` → `merge.apply` | On copies (or near-identical names) inside one project: keeps the oldest entry, the others' names become its aliases and they are removed (each undoable for 7 days); a missing second factor is said and nothing changes; the scan runs again after. | **not pressed** — new in ADR-168 (2026-11-20); automated: `tests/unit/tags-merge.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Dismiss”<br><sub>when `ovTidy` · `r.mergeShow`</sub><br><sub>each row of `g.rows`</sub><br><sub>each row of `tidyGroups`</sub> | click → `r.dismiss` | `merge_dismiss` → `merge.dismiss` | Remembers that the group is not a duplicate (sealed with the project's key); merge suggestions leave it out; the scan runs again. | **not pressed** — new in ADR-168 (2026-11-20); automated: `tests/unit/tags-merge.test.ts` against the fixture broker; not yet pressed in a built app |
| button “Apply all moves (N)”<br><sub>when `ovTidy` · `tidyApplyShow`</sub> | click → `openTidyApply` | — | Shown when the report proposes at least one move. Opens the confirm list inside Tidy up: every move, numbered, each entry's name with the project it leaves and the one it joins, and what a move does not carry. Nothing is sent. | **not pressed** — new in ADR-169 (2026-11-20); automated: `tests/unit/doctor-apply.test.ts` against the fixture broker, `crates/brokerd/tests/doctor_apply.rs` against the real broker; not yet pressed in a built app |
| button “Apply N moves” / “Moving…”<br><sub>when `ovTidy` · `tidyApplyOpen`</sub> | click → `tidyApplyGo` | `vault_doctor_apply` → `vault.doctor_apply` | Sends exactly the listed moves (entry, from, to, the generation the scan read). One authenticator code (when a second factor is on) and one Touch ID check for the whole list. All applied: a notice says how many moved and the scan runs again. The vault changed since the scan, or a name clash: said in the list, nothing moved, the list stays open. Stopped part-way: a warning names where it stopped and how many were not made; the scan runs again. No value is shown. | **not pressed** — new in ADR-169 (2026-11-20); automated: `tests/unit/doctor-apply.test.ts` against the fixture broker, `crates/brokerd/tests/doctor_apply.rs` against the real broker; not yet pressed in a built app |
| button “Cancel”<br><sub>when `ovTidy` · `tidyApplyOpen`</sub> | click → `tidyApplyCancel` | — | The confirm list closes. Nothing is sent. | **not pressed** — new in ADR-169 (2026-11-20); automated: `tests/unit/doctor-apply.test.ts` against the fixture broker, `crates/brokerd/tests/doctor_apply.rs` against the real broker; not yet pressed in a built app |
| button “Close”<br><sub>when `ovTidy`</sub> | click → `closeOverlay` | — | Tidy up closes. Nothing is sent. | **not pressed** — new in ADR-161 (2026-11-14); automated: `tests/unit/doctor-scan.test.ts` against the fixture broker; not yet pressed in a built app |

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
| Tidy up | Opens Tidy up (`S22-tidy`) and runs `vault_doctor_scan` → `vault.doctor_scan` if no report is in memory. | **not pressed** — new in ADR-161 (2026-11-14); automated: `tests/unit/doctor-scan.test.ts` against the fixture broker; not yet pressed in a built app |

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
| An agent asks for a secret while the vault is locked, window hidden | A count appears beside the menu-bar icon (tooltip “CredMgr: 1 agent request waiting”) and one macOS notification: “An agent is waiting for your approval — It asks to read a secret in “<project>”. Open CredMgr to decide.” No value, entry name or id. A project with hidden names reads “a private project”. The Dock icon bounces once. | **not pressed** — new in ADR-173; needs a person and the bundled app; the text and the count rules are covered by `src-tauri` unit and integration tests |
| The same request on the next look, and two requests at once | No second notification for the same request; two arriving together are one notification “2 agent requests are waiting”. | **not pressed** — covered by `src-tauri/tests/approval_notify.rs`, not seen on screen |
| Click the notification | The window comes to the front; a locked vault shows the Lock screen with the request listed. | **not pressed** — new in ADR-173 |
| Refuse the macOS notification permission | The count and the Dock bounce still work; nothing else changes. | **not pressed** — new in ADR-173 |
| Approve an agent's request from an open vault with Touch ID set up (after `vault.node_lock`) | Touch ID is asked (“Approve an agent's request”); a cancel leaves the request waiting; with no key set up the login alone approves; Deny never asks. | **not pressed** — broker side proved by `crates/brokerd/tests/presence.rs` (3); not pressed in a built app |
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

## 14. By-hand check of Touch ID in the built `.app`, 2026-11-07 (unsigned release build, main at 374f112)

Run by hand on the built, unsigned app (the lock-screen icon is commit 817c106, pull request #53), against a throwaway vault. The sensor needs a human finger, so no automated test covers this section.

| Item | Result | Evidence |
|---|---|---|
| Lock screen before Touch ID is set up | **pass** | a fingerprint icon sits beside the passphrase field, dimmed, with a set-up hint |
| Touch ID setup (Settings > Security > Touch ID) | **pass** | the presence key was enrolled and Touch ID unlock turned on from the app |
| Fingerprint unlock from the Lock screen | **pass** | after locking, the fingerprint icon opened the vault with a fingerprint |
| `credmgr unlock --touch-id`, signed binaries, Windows, Linux | **not done on 2026-11-07** | not part of this check; the build is unsigned and macOS-only. The terminal command was run by hand on 2026-11-08: see §15. |

**2026-11-08 addition.** Touch ID was checked again by hand with the operator's finger (record in §15): Settings, Security, Set up (a fingerprint was asked for as proof of possession) turned the row ON; lock, icon, fingerprint, unlocked, with the macOS prompt naming the requester. In the terminal, `credmgr unlock --touch-id` from a normal folder gave a session token (rc 0) and from inside a registered project folder was refused at once with `capability_not_held` (no prompt).

## 14a. The C4 findings F-1 to F-14, re-marked for rc.1 (2026-11-07)

Source: `docs/history/finish-plan/C4-FINDINGS.md`. **Fixed** here means: the code at the location named does the right thing and a test
that would fail if it came back passes in the fixture-broker suite (`apps/desktop/tests/e2e/rc1-ui.spec.ts` unless another file is named).
None of these was pressed in a built `.app` after its fix; the by-hand check is the §15 row on the same line. Issues #23 to #27 on GitHub.

| Finding | Was | Code location | Test | Built-app re-walk |
|---|---|---|---|---|
| F-5 (P1) autocorrect, autocapitalisation and spellcheck on every text field | fix in `16cbf29` (template compiler) | `apps/desktop/scripts/dc/compile.mjs` (attributes added to every `<input>` / `<textarea>`) | `tests/unit/compile.test.ts`; the C4 re-check, §8 | done 2026-10-18 on the rebuilt app (§8) |
| F-6 selecting a node does not read its entries | fixed | `src/design/logic/inspector.js` `rereadEntries` (called from `select`) | `#23` “an entry written from outside the app shows up when its node is selected”, and the locked-node case | pending (§15) |
| F-8 narrow inspector sheet: three columns, clipped names | fixed | `src/design/app.css` `.cm-insp.is-open` (`flex-direction:column`) | `#24` “it is one column, and an entry's name is readable” | pending (§15) |
| F-10 Orphaned panel empty after a seal | fixed | `src/design/logic/inspector.js` (orphan node id fixed to `orphaned`); names come from the graph snapshot (ADR-120) | `#25` both tests: the sealed entries are listed, the rail count follows, no `entry_list` for the orphan node, no `entry_reveal` | pending (§15) |
| F-3 Help promises a mask a note does not have | fixed by the wording | `src/design/screens/help.html` (“Its text is not masked … always hidden”) | `#26` “Help no longer promises a mask a note does not have” | pending (§15) |
| F-4 seal dialog says “until you lock the vault” | fixed | `src/design/logic/write.js` (seal dialog line: restorable 7 days, also after a lock or a restart) | `#27` F-4 | pending (§15) |
| F-2 preview chip says “auto: other” for host/username/password | fixed | `src/design/logic/write.js` `typeOptsFor` (`'auto: '+f.inferredType`) | `#27` F-2 (“auto: server”) | pending (§15) |
| F-7 Motion = reduced still orbits the entry dots | fixed | `src/design/logic/graph.js` (`isReduced()` gives no drift) | `#27` F-7 (moves with Motion full, holds with reduced) | pending (§15) |
| F-11 first Esc in CredPong leaves instead of pausing | fixed | `src/design/logic/core.js` games keydown handler (first Esc pauses, second exits) | `#27` F-11 | pending (§15) |
| F-12 grant dialog keeps the old reason after Cancel | fixed | `src/design/logic/settings.js` `closeGrantDlg` (reason and code cleared) | `#27` F-12 (Cancel and Escape) | pending (§15) |
| F-13 Settings → Advanced shows a wrong socket path | fixed | `src/design/screens/S12-settings.html` (Advanced, “Socket”) | `#27` F-13 (`run/broker.sock`, not `credmgrd.sock`) | pending (§15) |
| F-14 “Concealed clipboard: ON” pill wraps at narrow width | fixed | `src/design/screens/S12-settings.html` (the pill carries `white-space:nowrap`) | `#27` F-14 (560 px) | pending (§15) |
| F-1 bare-executable launch shows “cannot reach its broker” | fixed by the wording (the launch path stays LaunchServices) | `src/design/screens/boot.html` (“open the app the usual way”) | `#27` F-1 | pending (§15) |

## 15. rc.1 built-app re-walk (2026-11-07 evening and 2026-11-08 morning)

A spot re-walk of every screen by hand, not a per-control re-walk: the 302 rows of §2 keep their earlier results. Not done by hand: VoiceOver (#22, done 2026-11-08: see docs/ACCESSIBILITY.md) and the per-control press of all 302 rows.

| | |
|---|---|
| Source commit and build (`.app` / `.dmg`, signed or unsigned) | unsigned 2.0.0-rc.1 app and CLI tarball built from `26da2d3`; the one defect found below is fixed in `d9e6c7c`, and that build was not re-walked by hand |
| macOS version / appearance modes covered | macOS on Apple Silicon; throwaway vault seeded with 4 nodes and 4 entries |
| Tester and date | the operator, 2026-11-07 evening and 2026-11-08 morning (Touch ID checks with the operator's finger on 2026-11-08) |

| Area | What was done | Observed |
|---|---|---|
| Lock screen | passphrase unlock, typed by the operator | unlocked. The fingerprint icon beside the field was dimmed with "Touch ID is not set up yet" before setup and labelled "Unlock with Touch ID" after. |
| Graph and tree views | looked at both | nodes Global, Acme web, Billing (child), Personal and orphaned, each with entry and 2FA counts; selecting a node lists its entries. |
| Search | typed "git" | GITHUB_TOKEN in Acme web is listed; choosing it opens the inspector. |
| Inspector | a multi-field entry (username, password, recovery) | password reveal shows the value with "re-masks in 20s"; recovery was inferred as totp-seed; "show code" shows a 6-digit code with a countdown. "+ Add field" (label, value, generator) adds a field, toast "Field added", "Undo add field" offered. A lowercase spaced base32 value was inferred as totp-seed directly, so the #40 "possible seed" warning correctly did not appear; that path is covered by `tests/e2e/seed-hint.spec.ts` and `tests/real/seed-hint.spec.ts`. |
| "show seed" | pressed on the TOTP field with Touch ID on | **defect in the `26da2d3` build:** it said "The seed is not shown in this build." Fixed in `d9e6c7c` (seed shown, re-masked after the reveal window, never copied, cleared on lock; e2e in `wp-b-entries.spec.ts`). The fixed build was **not re-walked by hand**. |
| Settings, Security | looked at every row | auto-lock, two-factor gate (NOT CONFIRMED on this vault), reveal window, concealed clipboard ON, Touch ID row, screen-capture protection row "on". |
| Settings, Agents | looked at every row | Claude Code: not connected, "Copy command", never writes `~/.claude.json`. Claude Desktop, Cursor and VS Code: paths under the throwaway HOME, "not found". |
| Settings, Audit | opened | 34 records, newest first, including `entry.reveal` and `totp.code`; no values. |
| Operations panel | ran three | Verify integrity "ok · 4 nodes checked"; Doctor runs; Audit report "0 denied or grant records in the 37 records read". |
| Help | opened, searched | 161 topics; searching "touch id" gives 26 matches, including the fingerprint-icon and named-requester text. |
| Touch ID (2026-11-08, operator's finger) | Settings, Security, Set up; lock; fingerprint icon | setup asked for the fingerprint as proof of possession and the row went ON; lock, icon, fingerprint, unlocked; the macOS prompt named the requester. |
| Terminal, `credmgr unlock --touch-id` | from a normal folder, then from inside a registered project folder | normal folder: fingerprint, session token, rc 0. Project folder: refused at once with `capability_not_held` and the explanation, no prompt. |
| Idle lock | auto-lock set to 5 minutes, window untouched | "Locked after 5 minutes without activity." |
| Real screen lock | Ctrl-Cmd-Q while unlocked | the vault locked; the audit log shows a new `vault.unlock` session after the screen was unlocked. |
| Capture protection | tried screenshot tools | with default settings the window could not be captured (protection on by default); the walk used `CREDMGR_CONTENT_PROTECTION=off`. |

Not done by hand: VoiceOver (#22, done 2026-11-08: see docs/ACCESSIBILITY.md); the per-control press of all 302 rows. Rows marked "pending (§15)" in §14a and "not pressed" in §2 stay as they are unless a line above names them.

**Addendum 2026-11-08 (build `5e9bb29`, unsigned).** "show seed" re-walked by hand after the two fixes (`d9e6c7c` seed display, `5e9bb29` ADR-149 blur grace): Touch ID unlock, then "show seed" on a TOTP field, fingerprint, the seed shown in the row with "re-masks in 3s", then masked again. The audit log shows `totp.seed` refused with `presence_required`, the presence challenge, and `totp.seed` allowed.

**Addendum 2026-11-08 (build `e0b0b2e`, unsigned) — "Confirm before showing secrets" (ADR-150) by hand.** Settings › Security showed the row **off** by default; turning it on needed no confirmation (toast "Saved. Secrets ask for Touch ID or your passphrase before they show."), with Trust window 5 min and the Pro rows "When to ask" / "Which secrets". Opening an entry then raised "Confirm it's you" (Touch ID or passphrase; "After this, secrets show without asking for 5 min, until the vault locks"); the audit shows `entry.reveal` refused with `confirmation_required`. With the operator's fingerprint the entry's values showed, and revealing the password within the window showed it at once with no prompt. Turning the setting off inside 60 seconds of that confirmation needed no new one (the documented freshness rule, ADR-150); the refusal after 60 seconds is covered by `crates/brokerd/tests/reveal_confirm.rs`, not by hand. A first attempt timed out while the operator was away (`presence.challenge` with no `session.confirm`, then the 5-minute auto-lock), which is the expected behaviour.

## 16. Items of the 2026-11-08 design drop (ADR-151) — to look at in the built app

Merged without a built app. 2026-11-09: checked in the built rc.1 app through its accessibility tree and the shipped bundle's strings; the Node inspector also reads Open / Guarded / Strict (ADR-152). The visual look still needs a person's eyes: the app's screen-capture protection blanks automated screenshots.

| Where | What to see | Result |
|---|---|---|
| Settings › Security | Three small labels, in this order: "unlock and confirmation" (Touch ID when this Mac has a Secure Enclave, Confirm before showing secrets with its child rows, Auto-lock, Reveal window), "on this screen" (Concealed clipboard, Screen capture), "who can read" (Two-factor gate). Every control works as before; only the order and the labels changed. | partly: built app 2026-11-09 (rc.1 from main 306b38a, throwaway vault) — accessibility tree shows the Security page with the Confirm before showing secrets toggle; both group labels are in the shipped bundle; the visual order not seen (the window's screen-capture protection blanks automated screenshots) |
| Operations panel, "Rotate root key" | The one-line description reads "A new root key and a new recovery code. Asks for Touch ID." (it said "Needs presence."). | partly: string check 2026-11-09 — the shipped bundle has "Asks for Touch ID." and no "Needs presence."; not seen on screen (capture protection) |
| Inspector, TOTP field | "show seed", then "hide seed" with a code shown beside it: the seed goes, the code stays; the reveal's "hide" takes both (the §2 row). | partly: string check 2026-11-09 — "show seed"/"hide seed" in the shipped bundle; the toggle behaviour is covered by the e2e Q4 test; not seen on screen (capture protection) |

## 16a. Switchboard visual check: Settings › Agents › "Requests from agents" and "Confirm it is you" (ADR-155), 2026-11-09

**How.** The e2e harness: the test build (`npm run build:test`), Playwright WebKit, the fixture broker, the setup of `tests/e2e/switchboard.spec.ts`. Captured with `apps/desktop/scripts/visual-capture.sh <dir>` (spec `tests/e2e/visual-capture-switchboard.spec.ts`). `page.screenshot` was **not** used: in WebKit every variant (plain, `caret: "initial"`, `animations: "allow"`, `scale: "css"`) injects a `<style>` that the CSP refuses (`style-src-elem inline`, two reports per capture), so the harness fails the test. Playwright's video screencast records without touching the DOM; each capture point holds still, its time is noted, and ffmpeg pulls that frame. The capture runs had no CSP report. The real app hides its window from capture, so this cannot be done on the built `.app` without turning that protection off.

**What.** 16 frames, each looked at by eye: 1 and 3 waiting requests (one with a 360-character reason and a 160-character folder, one on a project node), light and dark, at 1440×900 and at the window's minimum 640×480, plus the "Confirm it is you" dialog opened by Approve in each theme and size.

| Check | Before the fix | After the fix |
|---|---|---|
| Long reason | **Cut at 300 characters with "…"**: the owner could not read the agent's whole reason before approving (the request text went through the audit-text sanitiser, capped at 300) | Shown whole up to the broker's own 500-character limit (`REASON_MAX`); a token shape is still redacted |
| The "agent requests are waiting" notice in a narrow window | **Covered the list, including a reason, the folder and the Deny button, and the bottom edge of the confirm dialog** (for its 5 seconds) | Opening Settings › Agents clears it, and no notice is raised while that list is on screen; a new request is listed, not announced over it |
| Overflow (long id, reason, folder) | none: every line wraps inside the row at both widths | unchanged |
| Contrast (WCAG, from the tokens) | captions `--mute` 4.80:1 (dark, on `--steel`) and 5.40:1 (light); the countdown chip `--warn` 5.64:1 (dark) and 4.97:1 (light): all AA | unchanged |
| Alignment | id and countdown chip on one line; buttons left-aligned under the text; the list sits in the Agents column at both widths | unchanged |
| Noted, not changed | a long folder path wraps after a hyphen (`…long-project-` / `folder-name…`), the browser's ordinary line breaking; the text is not altered | — |

**Regression specs.** `tests/e2e/switchboard.spec.ts`: "a long reason is shown whole and a long folder wraps inside the row" (no "…", no element wider than its box) and "in a narrow window the requests notice never covers the list…" (640×480; the notice is cleared on opening Agents and not raised there; the Deny button of a request that arrives meanwhile is in view). `tests/unit/switchboard.test.ts`: the reason keeps 500 characters and still strips a token.

**Not covered.** The signed `.app` (screen-capture protection; a person's look at it is still part of K-B), VoiceOver reading of the new rows, and the per-second countdown (it refreshes on re-render and on the 30-second poll).

