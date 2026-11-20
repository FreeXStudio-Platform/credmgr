<!-- artifact-hardened: NEEDS RE-HARDENING — the ADR-167/ADR-168 entries (feat/rc2-v1-gaps, 2026-11-20), the rc.2 entries (feat/rc2-section1, 2026-11-20) and the ADR-162 to ADR-165 entries (feat/rc2-21-branches, 2026-11-20) were added after the last pass; that pass was Approved With Known Risks @ 3ba7435 on 2026-11-14 (its full evidence and the K-A..K-F risks are in git: `git show 3ba7435:v2/CHANGELOG.md`). Re-harden before rc.2 is published. -->

# Changelog — CredMgr V2 "Vault Next"

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html)

> **Corrected 2026-08-17:** this file's own top note used to say "V2 is not built" long after
> it was — the code-history section below was never added when Phase 1 landed, an omission
> found during a full-sweep verification pass. **V2's backend is now built, audited, and
> finished**: Phases 0–5 and 7 closed, Phase 8's adversarial audit closed Approved With Known
> Risks (2026-08-16), and Backend-finish closed all three of its named gaps (2026-08-17,
> concluding with the session/login mechanism, ADR-047 → ADR-056). No named backend item
> remains unbuilt. Phase 6 (the UI) was being designed externally via Claude Design — see
> `docs/00_README_START_HERE.md` for the current full
> picture. V1's own history is in `../v1/CHANGELOG.md`.
>
> **Updated 2026-10-31:** the UI is built, hosted in the desktop app and wired to the broker (see
> `[2.0.0-beta.1]`); the backend gained ops, policy enforcement and a field model after the closure described above.

---

## Timeline — what was added when, and what is coming

The table is newest first (the version sections below run oldest first, with `[Unreleased]` on top). Dates are when the work landed; no date after today is a promise. Each row links to the version section below.

| When | Version | What landed |
|---|---|---|
| 2026-11-20 | `2.0.0-rc.2` (local build, unsigned) | Forgot your passphrase? Open the vault with the recovery code, from the Lock screen or `credmgr recover` (ADR-163); the machine lock, which ties the passphrase to this Mac (ADR-165); node-scoped agent tokens for AI assistants, the secret shown once (ADR-164); the Mac App Store edition behind a build feature, not submitted (ADR-162); restore from a backup in the app (ADR-166) and the rc.2 app controls. |
| 2026-11-20 | `2.0.0-rc.2` (local build, unsigned) | Tags on entries (ADR-167) and merging duplicates inside one project, with suggestions, dismissals and undo (ADR-168). Broker operations 93 → 102, commands +2 (`tag`, `merge`); MCP tools 21 and error codes 27 unchanged. |
| 2026-11-14 | `2.0.0-rc.2` (local build, unsigned) | Move an entry to another project, sealed again with that project's key in one crash-safe step, from the entry detail or `credmgr move` (ADR-158); Tidy up, the doctor's scan of your entries (shared values, near-identical names, misfiled, weak, mistyped, expired, expiring and stale), never showing a value, its "Move to <project>" applied one entry at a time through Move (ADR-161); a diagnostic log with no names or values, off unless you turn it on (ADR-159); reading an authenticator QR-code image in Add entry (ADR-160). Broker operations 91 → 93, commands 45 → 46; MCP tools 21 and error codes 27 unchanged. |
| 2026-11-12 | `2.0.0-rc.2` (local build, unsigned) | The quick wins left for the app: the expiry chip and Set expiry dialog on an entry, the entry's History tab, and the broker carried inside `CredMgr.app` so Start at login starts it (ADR-157). Notes as MCP tools still waits on a decision. |
| 2026-11-09 | `2.0.0-rc.2` (local build, unsigned) | The switchboard: every setting readable and changeable by you and by AI assistants, weakening changes waiting for your approval (ADR-155). The post-launch quick wins: change the passphrase, expiry dates, entry history, search within a project, lookup by reference, the anomaly notice, start at login, the airlock check in CI, the I-10 isolation test and five hardening items (ADR-156; 84 → 91 broker operations). |
| 2026-11-08 | `2.0.0-rc.2` (local build, unsigned) | The 2.x plan (ADR-153) and the licence core, not wired (ADR-154); F01 recorded as known risk K-25. Confirm before showing secrets, a vault setting off by default, with the new `session.confirm` operation (75 → 76) and `confirmation_required` error (ADR-150); a Touch ID prompt no longer makes the app drop the seed it asked for (ADR-149); About shows the build commit; the design drop of 2026-11-08 merged (Settings › Security grouped, "hide seed"; ADR-151). |
| 2026-11-07 | `2.0.0-rc.2` (local build, unsigned until a Developer ID is applied) | Touch ID on the Mac: a Secure Enclave key proves presence for the gated operations, sealed entries open in the app, and the vault can be unlocked with Touch ID (ADR-098); agent security levels and client wiring (ADR-140 to ADR-143); twelve broker operations (63 → 75); `credmgr restore` and the rc.1 backend batch (ADR-110 to ADR-115); pre-stable security fixes (ADR-148); scope (ADR-147). |
| 2026-11-01 | `2.0.0-beta.1` (public repository) | The repository is public as a single neutral commit; first release built from it. Source-available licence (ADR-096). First hosted CI and CodeQL runs: the workspace on macOS 15 and Ubuntu 22.04, the desktop app also on Windows. |
| 2026-10-31 | `2.0.0-beta.1` | Screen-capture protection switch in Settings; searchable in-app Help; `HELP.md`; the LLM capabilities manifest; V1 copy tool and the hygiene design. |
| 2026-10 | `2.0.0-beta.1` | The desktop app wired to the real broker (zero mock screens); multi-field entries; sealing and restore; agent approvals, including while locked; two-factor with recovery; concealed clipboard; names and second factor per node; the final adversarial audit (one P0 and two P1 fixed). |
| 2026-09-24 | `2.0.0-alpha.6` | The first packaged release: the daemon opens its own vault; command line, broker and MCP server in one tarball. |
| 2026-08-17 | `2.0.0-alpha.3` to `alpha.5` | Maintenance operations and undo; the session and login mechanism (ADR-056); the documentation pipeline. |
| 2026-08-16 | `2.0.0-alpha.2` | Phase 8 adversarial audit. |
| 2026-08-05 to 08-10 | `2.0.0-alpha.1` | The Rust backend: core, keystore, store, broker, CLI, MCP (Phases 0 to 5 and 7). |

**Coming next, in order and without dates.** `2.0.0-rc.2` is built locally and unsigned (2026-11-20); publishing it waits on Developer ID signing and notarisation (Touch ID and presence checks are already built and wait in the tree, ADR-098). `2.0.0`: the first stable release, macOS on Apple Silicon only. `2.1`: the rest of the doctor, wallet bundling, merging duplicates and applying a whole plan (`docs/25_VAULT_HYGIENE.md`; its first scan, Tidy up, is built, ADR-161), the V1 copy folded into the app, the machine lock (ADR-144), the Windows and Linux keystores and the named pipe, the org vault, sync and licensing (the operator's scope decision of 2026-11-07, ADR-147); `2.1.0` also brings cross-device sync as ciphertext, and agents that use a credential without its value reaching the model. `2.2`: a signed, machine-bound, expiring licence (a failed licence never locks your vault). `2.3`: the first paid tier. **Future versions, platforms and devices may not be free; releases already published keep the licence they came with.** If CredMgr is useful to you, please keep using it, tell us what breaks, and consider a donation (`DONATE.md`): it is what lets us keep building it.

---

## [2.0.0-rc.2] — 2026-11-20 (local unsigned build; not published)

(This section was `2.0.0-rc.1` until 2026-11-20 and `2.0.0-beta.2` until 2026-11-07; neither number was ever published. Final pre-stable security fixes: ADR-148. Scope: ADR-147.)

Built from `feat/rc2-section1` and tagged `v2.0.0-rc.2` locally; unsigned and not notarised, no GitHub release. `2.0.0-beta.1` (published 2026-11-01) predates everything in this section. Broker operations: 55 in beta.1, 111 here. Error codes 28; MCP tools 21.

### Forgot your passphrase? Open the vault with the recovery code (`ADR-163`)

- **The recovery code alone opens the vault.** The Lock screen has "Forgot passphrase? Use recovery code": type the printed recovery code and a new passphrase, and the vault opens. The same step sets the new passphrase and shows a NEW recovery code once; the code you used and the old passphrase stop working. On the command line: `credmgr recover` (the code and the new passphrase are read from stdin, never the command line).
- **Every attempt is audited**, including one made while the vault is locked (it is written with the next record). A wrong code changes nothing and counts in the unlock back-off. No AI assistant can call it, and it is not an MCP tool.
- **One new broker operation:** `vault.recover`. One new command-line command, `recover`.

### Machine lock: tie the vault's passphrase to this Mac (`ADR-165`)

- **Settings › Security › Machine lock**, or `credmgr keystore status | bind | unbind`. While it is on, the passphrase opens the vault only on this Mac: the passphrase wrap is sealed to a device key file kept in CredMgr's state folder on this Mac, outside the vault folder. A copy of the vault folder on another computer opens only with the recovery code.
- **Turning it on is a root rotation in two steps.** It needs the passphrase and the CURRENT recovery code; the new recovery code is shown first and the lock goes on only once you type it back. While the lock is on, backups are written to the state folder on this Mac, outside the vault folder, with the passphrase file unsealed inside the archive's own encryption and the restore ticket of the `ADR-148` amendment beside it, so a restore on another Mac opens with the passphrase; a recovery says what it did to the lock.
- **Honest about what it is.** The device key is a file, not a Secure Enclave key; `status` says so. Windows and Linux keystores stay later work (ADR-147). No AI assistant can read, set or remove the lock.
- **Three new broker operations:** `keystore.status`, `keystore.bind`, `keystore.unbind`; one new error code, `machine_lock_refused`; one new command-line command, `keystore`.
- **A detached machine-lock record is said, never repaired** (ADR-165 M5). If the vault folder's `vault.id` is edited or removed, or the folder is put back to a copy from before the lock, this Mac's record no longer matches it; the owner's `credmgr status`, `credmgr keystore status` and the Machine lock row in Settings now say so (`vault.status` `warnings`, `keystore.status` `recordDetached`), and one audit record is written. An AI assistant's session is never told. Nothing is changed on disk.
- **A passphrase change or a recovery now gives every project a new key** (ADR-165 N5). Before, a copy of the vault folder from before the change, opened with the old passphrase or the used recovery code, still opened entries written after it; now every live project gets a new key and everything it holds is re-sealed in the same crash-safe step, so it opens nothing written after. A locked project or a waiting write does not refuse it. The answer names the projects re-keyed (`nodesRekeyed`) and counts the files re-sealed (`filesResealed`); the change now takes time in proportion to the number of entries (about 8 s for 300 entries in a debug build).

### Node-scoped agent tokens (`ADR-164`)

- **A token for one AI assistant, on one project.** `credmgr agent token issue <node> --label … --cap …`, `ls`, `rotate <id>`, `revoke <id>`, or Settings › Agents › Agent tokens in the app. A token reaches exactly its project (no Global, no parents, no children, no grants), with its capabilities checked against the project's agent access on every request. A token lasts 24 hours by default and 7 days at most (never "forever"); tokens live in the broker's memory only, so a broker restart ends them all, and sealing a project ends its tokens.
- **The secret is shown once.** The command line prints it once; the app never puts it on the page: it goes to the concealed clipboard, cleared after 30 seconds and at lock. Issuing needs your login, a second factor and Touch ID; no agent can issue, list, rotate or revoke a token, its own included.
- **Four new broker operations:** `agent.token_issue`, `agent.token_status`, `agent.token_rotate`, `agent.token_revoke`. No new top-level command (`agent token …` extends `agent`), MCP tool or error code.

### The Mac App Store edition, built but not submitted (`ADR-162`)

- **A second, sandboxed flavour behind the `mas` build feature.** The vault, socket and state folder live in the app-group container; the broker runs as an `SMAppService` agent; the bundled CLI refuses what a sandbox cannot do and says what to use instead. `scripts/release-app.sh --mas` builds it beside the Developer ID edition; every Apple identifier is in `packaging/mas/identity.conf`. A default build cannot reach any of it.
- **Not yet:** nothing is signed for or submitted to the App Store; the operator decisions and the review risks are in `docs/27_APP_STORE.md`.

### rc.2 leftovers: security-touching broker work (lane L2)

- **Apply all the moves Tidy up proposes, in one step (`ADR-169`).** New broker operation `vault.doctor_apply` (102 → 103, counted after the tags and merge operations): the exact moves the scan showed (entry, from, to, generation) are checked first, in order, against the vault as it is (a stale scan, a name clash or a locked project moves nothing), then moved one by one through Move's crash-safe step with one authenticator code and one Touch ID check for the whole list; it stops at the first move that fails and says which moved. In the app: Tidy up › Apply all moves, after a confirm that lists every move; on the command line: `credmgr doctor --scan --apply` (prints the plan and asks; `--yes` does not ask). Owner only, not an MCP tool; desktop bridge 103 commands.
- **Entry-level grants work, for exactly one entry (`ADR-172`, PHASE8 K-10 (b)).** A grant to one entry (`grant.create` with `to: {kind: "entry", …}`) now lets the granted project see that entry's name, and read and/or reveal that entry (its value, its 2FA code), and nothing else of the node: no other name, no other value, no notes. Such a grant is one-way; `grant.create` refuses `notes`, `mutual` or an entry that is not there for it, and still needs your Touch ID. Before, an entry grant was accepted but did nothing.
- **Backups no longer carry the rollback counter (`ADR-148` amendment, PHASE8 K-23 (e)).** A backup holds a restore ticket instead, signed with the vault's key for the exact registry it archives. `credmgr restore` (and the app's Restore) turns it into a one-time marker beside the restored vault when there is no counter yet; the first unlock accepts it only for that vault and that registry, sets the counter and deletes the marker. A missing counter with no matching marker is still refused, as are a marker from another vault, an edited one, or an old one put back later. `credmgr restore --json` answers `counter: "acceptMarker"` for it; backups made before this change restore as before.

### Tags and merging duplicates (`ADR-167`, `ADR-168`)

- **Tags (`ADR-167`).** Put lower-cased labels on an entry (`credmgr tag <name> --add prod`, or the chips under its name in the app) and list one project by tag (`credmgr list --node <id> --tag prod`); a tag is read like a name, is never searchable across projects, and only you set it. New broker operation `entry.tag_set`.
- **Merging duplicates (`ADR-168`).** Inside one project, `credmgr merge suggest` names entries with identical values, a value in common, or names one letter apart (values compared inside the broker, never shown); `merge apply` keeps one and turns the others' names into its aliases (each merged entry can be undone for 7 days), `merge auto-all` is a dry run unless `--apply`, and a dismissed suggestion never comes back; in the app, Tidy up gains Merge and Dismiss. Eight new broker operations `merge.*`, none an MCP tool (93 → 102 with tags; commands +2, `tag` and `merge`; MCP tools 21 and error codes 27 unchanged; desktop bridge 93 → 102).

### Agent requests that wait reach you, and approving needs your fingerprint (`ADR-173`)

- A count beside the menu-bar icon, one macOS notification per waiting agent request (naming the project only, never a value, an entry name or an id) and a Dock bounce, so a request no longer waits for you to open the window. Approving an agent's request from a login now needs Touch ID once a presence key is enrolled (`vault.approval_decide`, broker-side; denying never does; the locked-vault passphrase form is unchanged). No new network surface; one macOS framework binding added (`objc2-user-notifications`).

### Edit an entry's details in your editor

- `credmgr edit <name> --node <id> [--dry-run]` opens the entry's metadata (aliases, expiry, sensitivity, type, tags when the broker offers them, field labels, types and masking) in `$VISUAL`, `$EDITOR` or `vi`, and applies only the keys you changed through the existing operations (`entry.alias`, `entry.set_expiry`, `entry.update`, `entry.tag_set`, `field.update`). It never fetches, shows or changes a value, and renaming is refused. A conflict keeps your edited file for a retry; the temp file is private (0600) and removed otherwise. No new broker operation.

### App controls for operations the broker already had (rc.2 §1)

- **Rotate, Remove and Undo-remove on an entry.** The entry detail has Rotate… (one field, a typed or generated value; the old one is kept and Undo puts it back) and Remove… (a confirm that says the entry is kept, sealed, for seven days); after a removal the node's list offers Undo, and Settings › Audit lists entries removed in the last seven days with Restore, or Restore as a copy when the name was taken since. No new broker operation.
- **Restore from a backup in the app (`ADR-166`).** Settings › Backup › Restore…, and Restore from a backup… on the screen shown when no broker answers. The app runs the bundled `credmgr restore --json` (now inside `CredMgr.app`), so the app and the terminal share one restore and one refusal: a restore is refused while a broker answers on the vault's socket, before the passphrase is read. `credmgr restore` gains `--json`. Desktop shell commands 17 → 18 (`backup_restore`, local); four bridge-local error codes; no new broker operation or broker error code.
- **Find by reference, node search and the audit report.** A number typed in the search box (`1042` or `#1042`) is looked up as an entry's reference (`entry.get_by_ref`) and opens that entry; the rail has a filter that narrows the nodes by name, in the page; a selected node has Find in this node (`entry.search`: names and other names, never values); Settings › Audit report (Pro) summarises the audit log for the last 24 hours to 366 days or two dates, optionally for one node (`audit.report`: actions, sessions by their public id, nodes, refusals with reasons, Touch ID uses, whether the hash chain verified). No new broker operation.
- **A guard against bridged operations the app never calls.** `tests/unit/ui-callers.test.ts` fails when a command in `src/lib/bridge.ts` has no caller in the app and no `@no-ui-caller <reason>`; the 19 commands without a screen carry their reason (command-line only by design, covered by another command, driven by the shell, or not built yet).

### The login agent no longer keeps uncapped logs (`ADR-159` amendment)

- The broker's start-up and shutdown lines name no folder, socket or user, and the login agent sends its output to `/dev/null` instead of `brokerd.log` and `brokerd.err.log` (which launchd never rotates). The next "Start at login" install removes those two old files. The diagnostic log (off unless `CREDMGR_DIAG_LOG=1`) is unchanged.

### Destroying sealed entries removes a node's archive folder last (`ADR-148`, P3)

- A destroy of sealed entries now deletes a sealed node's removed-entry and history archives before the archive folder that keeps its id spoken for, so a new node cannot take the id while old files are still being deleted. No behaviour change otherwise.

### Tidy up: the doctor's scan of your entries (`ADR-161`)

- **What it finds.** Entries that hold the same value, exactly or once spaces and a web address's case are ignored; names one letter or separator apart; entries in Global named for one project; weak passwords (short, few kinds of character, a common pattern; no wordlist, nothing sent anywhere); values stored as the wrong kind (a whole `otpauth://` link saved as a password, or a live key in a test project and the reverse); and entries that have expired, expire soon (30 days by default; a token's own expiry date counts) or were not rotated for a year.
- **Never a value.** Shared values are found inside the broker by comparing keyed fingerprints, under a key made for that one scan and thrown away when it ends. No value, fingerprint or part of a value reaches the app, the terminal or the audit log.
- **It changes nothing.** Each finding says what to do. Where moving an entry fixes it (an entry in Global named for a project, or one value two sub-projects of a project share), **Move to <project>** opens the entry's Move dialog with that project chosen; the move asks for Touch ID as always, and the scan runs again after it. Merging entries, grants and a one-step "apply all" are later phases.
- **What it reads.** Projects that are locked, or waiting for their own second-factor code, are listed as not fully scanned. Values are compared only where you could reveal them right now.
- **Who and where.** Only you, from your own login: no AI assistant can run it or see its results, and it is not an MCP tool. In the app: Settings › Maintenance › Tidy up…, or Operations (Cmd+Shift+O) › Tidy up. On the command line: `credmgr doctor --scan [--stale-days N] [--expiring-days N] [--json]`, where a move proposal prints the `credmgr move` line that applies it. The plain `credmgr doctor` is unchanged.
- **One new broker operation (92 → 93):** `vault.doctor_scan`. No new command-line command (46; `doctor` gained `--scan`), MCP tool (21) or error code (27). Desktop bridge 92 → 93 commands, shell 17.
- **Not yet:** the Tidy up screen is tested against the fixture broker and the shell's bridge tests, not yet pressed in a built app. Wallet grouping, the breach-check helper, `merge.*`, applying a whole plan and its undo plan are later phases.

### Read a 2FA QR code from an image (`ADR-160`)

- **Add entry reads QR codes.** Drop a PNG or JPEG of an authenticator QR code on the new "2FA QR" area in Add entry, or choose one, and its `otpauth://` code goes into a field, shown as a 2FA seed, exactly as if you had pasted it. Nothing is saved until you press Save.
- **Read on your computer, then forgotten.** The image is decoded inside the app by jsQR (Apache-2.0), with no network. It is never saved to disk, logged or shown; its pixels are wiped and the drawing surface cleared as soon as it has been read. A QR code that is not an authenticator code is refused without showing what it says.
- **Not yet:** Google Authenticator's export codes (several accounts in one QR) are not read. The drop area has not been pressed in a built app.

### A diagnostic log with no names or values (`ADR-159`)

- **A log you can attach to a bug report.** When you are chasing a problem, start the broker with `CREDMGR_DIAG_LOG=1` (on a Mac, `launchctl setenv CREDMGR_DIAG_LOG 1` before starting it or the app) and it writes `credmgrd.log`; the app writes `desktop.log` beside it. Each line has a time, an operation's name, `ok` or an error code, and how long it took, plus start, stop and crash lines with the version. Never an entry or project name, a value, a note, a passphrase, a session token, a file path or anything you typed.
- **Off by default.** Even without names, a line per request is a record of when you used your vault, kept outside the encrypted vault. So nothing is written until you turn it on.
- **Where it is.** `~/Library/Logs/credmgr` on macOS, `%LOCALAPPDATA%\credmgr\logs` on Windows, `~/.local/state/credmgr/logs` on Linux (`CREDMGR_LOG_DIR` overrides). `credmgr status` now ends with the log's path, and `credmgr status --log` prints just that line, even when the broker will not start. It never grows past 3 MiB (three files of 1 MiB), readable only by you. Nothing is sent anywhere.
- **No new broker operation, command, MCP tool or error code** (`status` gained `--log`).
- **Not yet:** the login agent's own `brokerd.log` and `brokerd.err.log` (ADR-156) are separate files, not size-capped, and can contain your vault's path (and so your user name); making them name-free is a follow-up.

### Move an entry to another project (`ADR-158`)

- **Move to project.** An entry filed under the wrong project can now be moved: in the app, open the entry and choose "Move to project…", pick the project and choose Move entry; on the command line, `credmgr move <name> --node <from> --to <to>`. The value is sealed again with the new project's key inside the broker and never reaches the app or the terminal.
- **Safe if anything stops part-way.** The move is one step: if the app, the broker or the Mac stops in the middle, the next unlock finishes it or undoes it. The entry is never readable in both projects and never lost.
- **What goes with it.** Its name, other names, expiry, fields and reference number. **What does not:** grants on that entry are revoked (re-grant it in the new project if you need to), and earlier values kept for Undo are dropped; the app and the command line say how many. A name or other name the new project already uses is refused; rename one first.
- **Who can do it.** Only you, from your own login: Touch ID every time, and a fresh second-factor code when one is set up. No AI assistant can move an entry, so none can carry one out of the project it was given. The entry's history shows the move in both projects.
- **One new broker operation (91 → 92):** `entry.move`. One new command-line command (45 → 46): `move`. No new MCP tools (21) or error codes (27). Desktop bridge 91 → 92 commands, shell 17.
- **Not yet:** the "Move to project…" control is tested against the fixture broker and the shell's bridge tests, not yet pressed in a built app. The doctor's Tidy up (above) proposes moves through it.

### The quick wins left for the app (`ADR-157`)

- **Expiry on an entry.** An entry with an expiry shows a chip with the date: grey, amber within 30 days, red once it has passed. "Set expiry…" (or "Change expiry…") opens a dialog: type a date or pick in 30 days, in 90 days or in a year, or remove it. A date is a calendar day in UTC, read the way `credmgr expire --at` reads it. Nothing is locked or deleted when the day passes.
- **History tab.** An entry's detail has Fields and History tabs. History lists the entry's newest 200 audit records, newest first: when, what happened, who (you or an assistant's session) and whether it was refused, with the entry's last change, rotation and expiry. Never a value.
- **The app carries its broker.** `CredMgr.app` now contains `credmgrd` (`Contents/MacOS/credmgrd`), built from the same commit and stamped and checked like the tarball's, so Start at login works without installing the command-line tarball. `scripts/release-app.sh` builds it, the release verifier refuses an app without it or with one from another commit, and `scripts/sign-notarise.sh` signs it.
- **Not yet:** notes as MCP tools (needs a decision, ADR-072). The new screens and the login agent are tested against the fixture broker and in the shell's tests, not yet pressed in a built app.

### rc.2 command-line additions

- **`credmgr totp`.** `credmgr totp <name> [--node] [--field | --field-id] [--json]` prints the current one-time code (never the seed); `totp.code` now also answers `validForSeconds` (1–30).
- **`credmgr generate --hex` and `--copy`.** `util.generate` takes `hex` (lower-case hex, same length bounds). `--copy` on `generate`, `get` and `totp` puts the value on the macOS clipboard instead of stdout and clears it after 30 seconds only if the clipboard still holds it.
- **`credmgr import --format json`.** A `.json` file (or `--format json`) is an array of `{"name","value"}` or `{"name","fields":[{"label","value","type"}]}` entries, sent as one `entry.create_batch` call with the same 500-entry ceiling and partial-failure report.

### Post-launch quick wins (`ADR-156`)

- **Change your passphrase.** Settings › Security › "Change passphrase", or `credmgr passphrase` (both passphrases on stdin). It asks for the current passphrase, a second factor if you set one up, and Touch ID if it is enrolled; every entry stays readable and a new recovery code is shown once. A crash part-way leaves either the old or the new passphrase in force, never neither.
- **Expiry dates.** `credmgr expire` sets or clears an entry's expiry; `credmgr expiring` lists what expires soon or already has. Expiry dates are shown to people, not to AI assistants.
- **Entry history.** `credmgr history` lists an entry's create, update, rotate and expiry changes in order, never a value. Old retained versions are now pruned: an entry keeps its 20 most recent versions and anything from the last seven days.
- **Search one project, look up by reference.** `credmgr search --node` finds names and aliases in one project; `credmgr ref <number>` finds the entry a short reference number belongs to, among the entries you could already list.
- **Anomaly notice.** When an assistant is refused five times in ten minutes across projects, the app shows a notice bar (Open audit, or ✕ to dismiss) and `credmgr status` says so; `credmgr status --ack` clears it.
- **Start at login (macOS).** Settings, and the screen shown when the broker is not running, offer to start the broker when you log in (a per-user login item, never root). Turning it off asks first.
- **V1 copy tool carries more.** `tools/v1-to-v2/migrate.js` now carries each entry's expiry, aliases and sensitivity into V2 (sensitivity through the new `credmgr set --sensitivity low|medium|high|critical|auto`); a V1 description has no V2 home and is reported by name. An unknown V1 sensitivity is refused, not guessed. The tool has no built-in names or default vault path any more: it takes `V1_DIR`, `--exclude`, `--exclude-file` and `--exclude-project`.
- **Touch ID row on a Mac without Touch ID** stays visible, greyed, with a line saying what protects your vault.
- **Confirm before showing secrets** now also asks before a content search and before a note is read.
- **Seven new broker operations (84 → 91):** `vault.set_passphrase`, `vault.anomalies_ack`, `entry.set_expiry`, `entry.expiring`, `entry.history`, `entry.search`, `entry.get_by_ref`. Five new command-line commands (40 → 45): `passphrase`, `expire`, `expiring`, `history`, `ref`. No new MCP tools (21) or error codes (27). Desktop bridge 91 commands, shell 17.
- **Hardening.** The audit log is checked before each new record is signed, so a cut-off log stays visible to `credmgr verify` (K-9). One request is capped at 128 MiB and its strings are wiped after use (K-10 (a), K-23 (b)). The app honours the presence-helper override only in debug builds (K-23 (a)). `credmgr restore` refuses while a broker is running (K-23 (d)). Unlocked project keys sit on memory the system is asked not to swap or dump (`mlock`).
- **Proved, not assumed.** A CI check builds the broker and fails if it carries network or TLS code or holds any internet socket while it runs (`scripts/airlock-check.sh`, job `v2-airlock`). The I-10 isolation test is written: a sealed project's names stay listable and its values open only to the app with Touch ID (28 of 28 isolation tests; known risk K-1 closed).
- **Not yet:** the expiry chip on an entry and the History tab in the app (the command line has both; built since, ADR-157); notes as MCP tools (needs a decision).

### The switchboard: every setting, for you and for AI assistants (`ADR-155`)

- **One settings registry.** Every setting (25: the app's preferences, "confirm before showing secrets", and each project's policy) is described once, with what it is for, the values it takes, where it is stored and which direction is weaker. The app, the command line and the MCP server read and change the same values, so they can never disagree. The app's preferences now live in the signed vault registry, not only in the window.
- **Ask your assistant.** Six new MCP tools (15 → 21): `credmgr_settings_list`, `credmgr_settings_get`, `credmgr_settings_set`, `credmgr_settings_revert`, `credmgr_settings_request` and `credmgr_kb`. Eight new broker operations (76 → 84): `settings.list`, `settings.get`, `settings.set`, `settings.revert`, `settings.request_get`, `settings.request_list`, `settings.request_decide`, `settings.kb`.
- **Safety tiers.** An assistant's appearance change or a change that makes the vault stricter applies at once. A change that makes it less protected (a longer or no auto-lock, a looser reveal rule, a lower security level, more agent access, screen-capture protection off) waits as a request until you approve it in CredMgr, after confirming it is you (Touch ID or passphrase). Assistants can never approve, list or see others' requests; they reach only their own project's settings. Nothing is changed while the vault is locked.
- **Recorded and revertible.** Every change is kept with the value it replaced (`settings.get` shows them) and can be put back with `credmgr settings revert` or `credmgr_settings_revert`.
- **Command line.** `credmgr settings list|get|set|toggle|revert|requests|request|approve|deny` and `credmgr kb`.
- **Visual check fixes (2026-11-09).** In Settings › Agents an agent's reason is shown whole (it was cut at 300 characters), and the "agent requests are waiting" notice no longer covers the list in a narrow window: opening the list clears it.
- **Knowledge base for language models.** `docs/LLM_KB.md`: how to connect, where data lives, retention and backup, every feature and setting and how to change it, and the rules, generated from the registry and checked against it in the tests.


- The app locked the vault whenever the page reported itself hidden. macOS also reports that when the window is only covered, or sits on a display that is asleep or switched off, so a window on a second screen locked itself. Now revealed values are still wiped at once, but the vault locks only when the shell confirms the window was minimised or hidden (new shell command `window_state`, 13 → 14 shell commands). The idle auto-lock, sleep, screen lock and closing the window still lock as before.
- The screen-capture protection setting (Settings › Security) applies to the window on every display.

### The 2.x plan and the licence core (`ADR-153`, `ADR-154`)

- **Plan:** the order of work after 2.0.0 — agents that use a credential without receiving it, the doctor, licensing and the store editions, encrypted backup and sync, remote agents, more platforms (`ADR-153`). The 2026-10-30 sync and agent-use design is now in the tree as `docs/23`, marked historical.
- **Known risk recorded:** an agent that can reveal a value receives it into its model's context (F01, `PHASE8_AUDIT_REPORT.md` K-25, `SECURITY.md`).
- **Licence core (not wired, nothing gated):** `credmgr_core::licence` verifies one-time, offline-signed licences (ECDSA P-256) bound to one device or to the vault's licence identity, with a Free / Solo / Plus / Team entitlement table in which Free is the whole vault and no security control is ever sold (`ADR-154`). No operation, error code or MCP tool was added.

### The strictest security level is called "Strict" (`ADR-152`)

- The third per-node security level reads **Strict** in the window, in Help, in the agent prompt and `CREDMGR.md`, and in the docs. "Sealed" now means one thing: sealing a node into Orphaned.
- Nothing stored or sent changes: the value is still `sealed` in the registry, the broker, the bridge, MCP and `graph.snapshot`. `credmgr node policy --security-level strict` is accepted as an alias for `sealed` (either spelling works); `credmgr whoami` and the policy report print `strict`.
- Broker refusal text on a Strict node (rule `L1`) says "Strict (stored as sealed)". No operation, error code or MCP tool was added.

### Design drop of 2026-11-08 merged (`ADR-151`)

- **Settings › Security is grouped** under three labels: *unlock and confirmation*, *on this screen*, *who can read*. Same rows
  and controls, new order.
- **"hide seed".** While a TOTP seed is showing, its button reads *hide seed* and hides the seed only; a code shown beside it
  stays. The reveal's *hide* still hides both.
- The Operations panel's *Rotate root key* line says it asks for Touch ID.
- Not taken from the drop: its sample Help topics, a *Restore from backup* row (restore is the offline `credmgr restore`), and
  its mock data. Answers to the design side: `BACKEND_ANSWERS_2026-11-08.md`.

### Confirm before showing secrets (`ADR-150`)

- **A vault setting, off by default:** Settings → Security → *Confirm before showing secrets*. When it is on, revealing a value,
  copying one or showing a one-time code asks you to confirm it is you — Touch ID, or the vault passphrase — and then does not ask
  again for the trust window you choose (1, 5, 15 or 60 minutes; 5 by default). In Pro mode: *When to ask* (once per trust window, or
  every time) and *Which secrets* (all, or only high and critical). Locking ends the trust window. Turning it off or making it ask less
  needs a fresh confirmation; turning it on does not. Agents are not affected (their reads answer to the node's security level).
- **New broker operation `session.confirm`** (owner's login only; a wrong passphrase counts in the unlock backoff) and **new error code
  `confirmation_required`**, returned by `entry.reveal` (and the app's copy) and `totp.code`, by a change that weakens the setting,
  and, under "only high and critical", by an owner edit that lowers an entry's sensitivity out of that band. `totp.seed`,
  `orphan.reveal` and `node.export` are not asked again (each already needs a Touch ID proof); `search.content` and `notes.read`
  are not gated. Approving a waiting request (`vault.approval_decide`, from a login) asks too, and the value an approval
  released is gated when a login collects it; denying never asks, and the locked-vault form is authorised by the unlock factors.
- **Fixes from an independent adversarial review of ADR-150** (amendment in `docs/14_DECISIONS.md`, each with a refusal test in
  `crates/brokerd/tests/reveal_confirm.rs`): **P0** — locking a project, asking for a value and approving your own request handed the
  value over unconfirmed; the approval and the collection are now both gated (in "every time" mode that costs two confirmations).
  **P1** — a successful `session.confirm` reset the per-uid back-off, so a login could guess gate codes without limit; a confirm now
  records failures only. Also: a Touch ID confirmation proof that does not verify counts in the back-off; an entry with no manifest
  row is gated as critical; a confirmation is spent only after every other check passes (a bad field id, or a weakening refused for
  presence, keeps it); a stored policy with unknown keys still loads (a request naming one is refused); the CLI holds the confirm
  passphrase in a zeroised buffer; the Settings caption says it covers this app and your logged-in CLI, not agents (a token-less
  `credmgr` run from a registered project folder is an agent).
  The setting is kept in the signed registry on the `global` node's policy (`revealConfirm`, set with `node.policy`); an older registry
  reads as off. `graph.snapshot` tells the owner's login the setting. No new MCP tool.
- **CLI:** `credmgr get` (and any command that meets the refusal) asks at a terminal (Touch ID first, else the passphrase on
  stderr) and sends the request once more; from a pipe it says to run `credmgr confirm [--touch-id]` (passphrase from stdin)
  first. The CLI has no flag to turn the setting on; the app does.
- **About** shows the build's git commit next to the version.

### Agents: security levels, client wiring, the vault prompt

- **Per-node security levels** (`ADR-140`): Open, Guarded (the default) and Strict (stored as `sealed`; named "Sealed" until
  ADR-152). On a Guarded node an agent's read of a `high` or `critical` value waits for the owner's one-tap approval; Strict holds every read, holds an agent's new entries in the tray and
  refuses its changes. The owner is never held. Lowering a level needs presence. `credmgr node policy --security-level`, a control in
  the node inspector, `level` in `whoami`, `securityLevel` in `graph.snapshot`. **Existing nodes read as Guarded.**
- **Coding-assistant wiring** (`ADR-141`…`ADR-143`): `credmgr mcp --print-config [<client>]`; `credmgr agent detect|connect|disconnect|init`
  (shows a diff, backs the file up, writes only the `credmgr` entry on `--yes`; never Claude Code's `~/.claude.json`); Settings →
  Agents in the app; `credmgr prompt`; `CREDMGR.md`; `v2/docs/AGENT_CONTRACT.md`.
- **Decided, not built:** machine lock (`ADR-144`); **dropped:** the duress code (`ADR-145`) and the `llm.*` broker operations (`ADR-146`).
  This group adds no broker operation, error code or MCP tool of its own; five new shell commands and three bridge-local error codes.

### Twelve broker operations (63 → 75)

- `entry.alias`, `entry.similar` (near-duplicate names, `credmgr similar`, ADR-121), `entry.import_env` (`.env` importer, ADR-122), `node.rekey` (ADR-130), `orphan.destroy` (ADR-131), `search.content` (ADR-132), `node.export` (`credmgr export --age`, ADR-133), `audit.report` (ADR-134) and a node's own second factor, `node.gate_enroll_begin`, `node.gate_enroll_confirm`, `node.gate_verify` and `node.gate_remove` (ADR-135, `credmgr gate enroll|verify|remove --node <id>`). A node without its own gate shares the vault-wide window. Counted with `corpus_check.broker_ops()`.

### 2.0.0-rc.1 backend batch (issues #35 to #40)

- **A private-names node no longer tells a guesser a name exists** (ADR-110, #35): `entry.create` and `entry.create_batch` from a
  caller that may not see names create the entry under a free name (`name (2)`) instead of answering `entry_exists`, with the same
  reply shape either way. The owner and nodes without `privateNames` are unchanged.
- **`credmgr backup` is a complete archive and `credmgr restore` rebuilds the vault from it** (ADR-112, #36): notes, sealed-node
  and removed-entry archives, rotation history, the tray, the audit log and the generation counter are now in the archive, with a
  manifest; `credmgr restore <archive> [--to <empty dir>] [--state-dir <dir>]` validates the whole archive, writes all or nothing,
  never merges into or overwrites a vault, and never lowers an existing generation counter. A backup is refused while a root-key
  rotation is half finished. A version-1 archive still restores, with a note.
- **`graph.snapshot` says `gate.twofa: "none"` on a vault with no second factor** (ADR-115, #37); `enrolled` now means an
  enrolment begun and not confirmed.
- **`scripts/release.sh --verify` reads the build stamp, the minimum macOS version and the packaged documents from the bytes**
  (ADR-114, #38), without `--run-binaries`: the commit and dirty flag from a stamp built into each binary (`build.rs`),
  `LC_BUILD_VERSION` against the 13.1 limit, and each packaged document against the same file at the stamped commit. The
  self-test grew five cases.
- **An authenticator code is no longer a command-line argument** (ADR-113, #39): `credmgr gate verify` reads it from a prompt or
  stdin; `credmgr approve` reads the passphrase from the first stdin line and the code from the second, or asks at a terminal. The
  argument form is `--code-on-argv`, documented as visible to `ps`. **Breaking for scripts:** `gate verify <code>` and
  `approve --code` are refused.
- **A field that could be a 2FA seed but is not typed as one is named** (ADR-111, #40): replies gain `possibleSeedFields` and the
  `possible_totp_seed` warning, `entry.get` marks `possibleSeed`, and the command line warns, names `credmgr field set --type
  totp-seed` and offers to type it at a terminal. The window now warns on the flagged field and offers "This is a 2FA
  seed" (one click sends `field.update {type: totp-seed}`) (#40).

### Pre-stable security fixes (ADR-148 and its addendum)

- **Touch ID unlock is refused to a caller the broker recognises as an agent** (an agent token, or no token from inside a
  registered project folder), before any prompt. For anyone else the dialog names the requesting process, its parents and
  its folder (a hint, not proof), and a dismissed or timed-out prompt counts toward the unlock back-off.
- **The Touch ID unlock wrap is authenticated.** `keys/root.wrap.se` carries an HMAC tag under the root key; a root-key
  rotation re-seals only to a wrap whose tag verifies, and refuses an untagged one ("turn Touch ID unlock off and on
  again").
- **The signed registry holds `presenceKeys` and `deviceWraps`**, so deleting or putting back `keys/presence.enroll` or
  `keys/root.wrap.se` enrols, unenrols or re-enables nothing; enrolling a presence key needs proof of possession.
- **Agents cannot lower what they would need approval to read:** on a Guarded or Strict node an agent edit or undo that
  lowers an entry's sensitivity is refused (`node_access_denied`, rule `L1`). Accepting or discarding a held entry is the
  owner's alone. A node with its own second factor asks for that code before every reveal, whatever `requireTwoFactor`
  says. An agent's `search.content` skips every entry it could not reveal without approval.
- **Durability:** `node.gate_verify` is persisted (a spent code stays spent across a restart), and a rekey stage is
  removed crash-safely and never overwrites a later edit.
- **Hardening:** a release build ignores `CREDMGR_PRESENCE_HELPER` and accepts only the production helper; a `.env` line
  that is only base64 padding is refused by line number; `credmgr agent init` refuses a symlinked `CREDMGR.md`; restore
  refuses case-only name clashes and `keys/root.wrap.se`. No new broker operation, error code or MCP tool.

### Fixes from the rc.1 checks

- **Accessibility, from the VoiceOver pass (#22, 2026-11-08):** the header search field is named "search entries" (it had
  no accessible name), and revealing a value now announces "hide, re-masks in 20 seconds" once instead of an unannounced
  per-second countdown. Results in `docs/ACCESSIBILITY.md`.
- **QT-1:** the four quarantined WebKit specs wait for `data-focus-settled` and run again.
- **Text-input border is `--mute`, not `--faint`** (ADR-092 item 6, accepted in ADR-147).
- **An operation on a node that does not exist answers `not_found` "no node <id>"** (it said "locked" or "no public key
  registered"); **`credmgr backup` refuses a multi-line passphrase on stdin.**
- **"show seed" displays the seed** (`d9e6c7c`): the `26da2d3` build said "The seed is not shown in this build"; the app
  now holds the presence-gated seed in its private store, shows it with the re-mask countdown, never copies it and clears it
  on lock, node change or hide.
- **Built-app re-walk** (`docs/RELEASE_VERIFICATION.md` §15, 2026-11-07 and 2026-11-08, `26da2d3` build): a spot re-walk of
  every screen by hand; the idle lock and a real screen lock locked the vault; Touch ID setup (with proof of possession),
  fingerprint unlock and `credmgr unlock --touch-id` passed with the operator's finger, and the command was refused from a
  project folder. One defect (the seed display) was found and fixed in `d9e6c7c`.
- **A Touch ID prompt no longer makes the app drop its own answer** (ADR-149, `5e9bb29`): the system Touch ID sheet blurs
  the window, and the page wiped revealed values on blur, so a seed (or a sealed entry) asked for with a fingerprint was
  discarded on arrival. While a presence-gated request the page started is in flight (plus 1.5 s), a blur does not wipe;
  minimising, hiding and locking still wipe at once. Checked by hand on 2026-11-08: after a fingerprint, "show seed"
  displayed the seed and re-masked it on time.
  Later the same day the ADR-150 setting was checked by hand and the VoiceOver pass (#22) ran (above); the per-control
  press of every row and the built-app look of the design drop (ADR-151, `RELEASE_VERIFICATION.md` §16) remain.

### Touch ID on the Mac — presence proofs and Touch ID unlock (ADR-098, 2026-11-06)

- **A Secure Enclave key now proves that a person is present, and the gated operations run.** `audit.get`, `totp.seed`,
  `node.reparent`, `grant.create`, `node.policy` when it widens reach, `maintenance.rotate_root`, `maintenance.doctor` with
  `rebuildRegistry` and the sealed read no longer answer `presence_required` on a Mac with an enrolled key. The broker hands out
  a single-use 60-second challenge bound to the operation, its exact parameters and the login session; the Enclave signs it
  after Touch ID (or the device password where no fingerprint is enrolled); the broker verifies it against an enrolled public
  key and burns the nonce either way. (The broker releases a `totp.seed` to the owner with a proof; since `d9e6c7c` the desktop app's "show seed" displays it, re-masks it after the reveal window, never copies it and clears it on lock; the CLI has no command.) **Without an enrolled key the old `presence_required` refusals stand**, and agents and
  fixture tokens can never hold a proof.
- **Sealed ("Orphaned") entries can be opened, in the desktop app only.** `orphan.list` names them; `orphan.reveal` needs the
  owner's login, a fresh second factor **and** a Touch ID proof every time, and drops the second-factor window afterwards.
  There is no CLI command and no MCP tool for it.
- **Unlock the vault with Touch ID.** `credmgr touch-id enable` (and the app's Settings > Security > Touch ID) seals the root
  key to a Secure Enclave key into `keys/root.wrap.se`; `credmgr unlock --touch-id` and the Lock screen's fingerprint icon (beside the passphrase field, dimmed with a set-up hint until Touch ID is on; commit 817c106, PR #53) open it. Touch ID setup and fingerprint unlock were checked by hand in the built unsigned app on 2026-11-07 (`docs/RELEASE_VERIFICATION.md` section 14). The passphrase and recovery wraps stay, it works on this Mac only, and it is an extra door, not a replacement:
  a copy of the vault folder on another computer is still attackable offline by passphrase. The Enclave wrap is never in a backup;
  the enrolment file (public keys only) is.
- **Eight new broker ops** (55 → 63; 75 with the twelve in the batch above, 76 with `session.confirm`): `presence.status`, `presence.challenge`, `presence.enrol`, `presence.unenrol`,
  `device.enrol`, `device.remove`, `orphan.list`, `orphan.reveal`; one new error, `presence_failed` (reasons `not_enrolled`,
  `expired`, `invalid`, `cancelled`, `locked_out`, `unavailable`). New CLI: `presence status|enrol|unenrol`, `touch-id
  enable|disable`, `unlock --touch-id`, `node reparent`. The CLI and the desktop shell answer a `presence_required` themselves.
- **Touch ID does not need signing.** The Swift helper `credmgr-presence` uses a non-permanent Enclave key and works in an
  ad-hoc-signed binary. The build and the tarball are still unsigned and not notarised until the operator supplies an Apple
  Developer ID (`scripts/sign-notarise.sh`, #28). Windows Hello, TPM and Linux keystores are not built (#29).
- **Documentation honesty pass:** the README, SECURITY, RELEASE and corpus documents that said "no Touch ID" or "nothing is
  held in the Secure Enclave" now say what is built (macOS) and what is not (other platforms, signing).

## [2.0.0-alpha.1] — 2026-08-05 through 2026-08-10 · Backend, Phases 0–5 and 7

Six Rust crates (`credmgr-core`, `credmgr-keystore`, `credmgr-store`, `credmgr-brokerd`,
`credmgr-cli`, `credmgr-mcp`), built and gated phase by phase per `docs/12_BUILD_PLAN.md`:

- **Phase 0** — toolchain, workspace skeleton, CI, secret-scan hook.
- **Phase 1** — core primitives: the sealed-box envelope (X25519 → HKDF-SHA-512 →
  ChaCha20-Poly1305), node key generation, the access-graph `resolve()` function and its 8×8
  capability matrix.
- **Phase 2** — storage: manifests, the node registry, HMAC-signed cross-binding, generation
  tracking (rollback detection).
- **Phase 3** — the broker (`credmgrd`): the op-dispatch model, `entry.create/update`, the
  pending-write tray for locked-vault writes, the node isolation suite, auto-lock on
  idle/sleep/screen-lock, `graph.snapshot` (ADR-047), `audit.tail`/`audit.get` (ADR-049),
  `grant.list/create/revoke` (ADR-050).
- **Phase 4** — the CLI, `entry.rotate`/`entry.remove`/`entry.restore` (ADR-048), MCP tool
  registrations.
- **Phase 5** — gate 2FA (TOTP enrolment/verification), the `PlatformKeystore` trait.
- **Phase 7** — hardening and closeout: `node.create` (ADR-051), the success-criteria test
  suite run against a real compiled broker over a real socket (not mocks), the
  `guard-no-personal-data.mjs` script, semgrep in CI, doc-corpus stamp reconciliation
  (ADR-052). Exit gate green 2026-08-10.

Phase 6 (the UI) was pulled out of this build chain the same week — it runs externally via
Claude Design, not as versioned backend code; see `docs/00_README_START_HERE.md`.

## [2.0.0-alpha.2] — 2026-08-16 · Phase 8 — final adversarial audit

Opus, max effort, full-corpus re-verification — not a continuation of the sessions before it,
a deliberate second look. Found and fixed one real security bug: `node.restore` authorised
against the caller's token only, not the target node (`node.seal` correctly checks both) — a
cross-node integrity hole letting one project's Admin token restore another project's sealed
node. Fixed with a new `resolve_capability` check (ADR-053), proven with a failing test first.
Also corrected six stale claims across the doc corpus, including the entry-point doc's own
"DO NOT PUBLISH — NO GitHub remote" line, 45 commits and one real push after it stopped being
true. Status: **Approved With Known Risks** — full report in `docs/PHASE8_AUDIT_REPORT.md`.
333 tests passing (332 inherited + 1 new).

## [2.0.0-alpha.3] — 2026-08-17 · Backend-finish — `maintenance.*` and `entry.undo`

- **`maintenance.verify`** (ADR-054) — read-only integrity report: manifest HMAC + registry
  cross-binding checks (already enforced on write, now also checked proactively), plus a new
  dangling-envelope check (files with no manifest entry, or manifest entries with no file).
- **`maintenance.doctor`** (ADR-054) — resyncs a stale-but-self-valid cross-binding; explicitly
  refuses to "fix" a manifest that fails its own HMAC (that would launder a tamper, not repair
  one — the only path back from real tampering is `--rebuild-registry` from a backup, or a
  human). `--rebuild-registry` is `PresenceRequired`, matching `grant.create`/`node.reparent`.
- **`maintenance.backup`** (ADR-054) — real backup creation, wired to `store::backup`
  primitives that existed since ADR-039 but were never called by any op until now.
- **`entry.undo`** (ADR-055) — forward-only for both `remove` and `rotate`: a new mutation
  that puts content back and appends its own audit record, never a rewrite of the
  hash-chained audit log itself. Addressed by `{node, id}`, matching `audit.get`'s own
  authorize-before-confirm-existence shape.

~390 tests passing (333 inherited + ~57 new). The session/login mechanism (ADR-047) was the
one named backend gap still open at this point — closed the same day, see
`[2.0.0-alpha.4]` below.

## [2.0.0-alpha.4] — 2026-08-17 · Backend-finish — the session/login mechanism (ADR-056)

- **A real `vault.unlock`/`vault.gate_verify` success mints a real, non-fixture token** — the
  gap ADR-047 named and nothing but a test fixture could previously close. `Origin::HumanUi`,
  scoped to `global`, every capability, revoked on the next `vault.lock` — see ADR-056 for the
  full design and the deliberate limits it names.
- **`audit.tail`'s per-origin redaction is now reachable through a real transport** — closing
  `PHASE8_AUDIT_REPORT.md` C-2's own "re-check the moment ADR-047's session/login lands" note.
- **ADR-051's R3-universal-Admin question, answered**: `resolve()`'s R3 stays unqualified by
  capability, deliberately — after this change, `Capability::Admin` is reachable in real
  operation only via a token this mechanism mints, always scoped to `global`, so R3's
  admin-unqualified clause remains structurally inert by construction, not by absence of a
  mechanism.
- **CLI**: `credmgr unlock` now prints `export CREDMGR_TOKEN=<id>` on success
  (`eval "$(credmgr unlock <<< "$pw")"` captures it); a new `credmgr gate verify <code>`
  subcommand completes the two-factor path (previously unreachable from the compiled binary at
  all) and mints the token the same way.
- **A named, deliberate limitation, not silently left implicit**: a `global`-scoped session
  token cannot administer, list, or audit any node other than `global` itself — every
  per-node-Admin-gated op (seal/restore/reparent/grant/node.create's parent check) still needs
  its own, still-undesigned per-node elevation path. Handed forward exactly as ADR-047 already
  handed the same "whole vault graph" gap forward once.

Backend work is now complete — no named backend gap remains. Waiting on Phase 6 (the UI,
external via Claude Design) before a final, complete-backend Phase 8 pass.

---

## [2.0.0-alpha.5] — 2026-08-17 · Tooling + design-package — the documentation pipeline

No product-code change. This release is infrastructure for the documentation and design track,
plus the design-handoff package's own refresh.

### Added
- **`tools/visual-engine`** — Apache ECharts 6.1.0, server-side, deterministic. Renders
  quantitative data charts (compare/trend/distribute/relate/compose/flow/matrix/hierarchy) to
  SVG/PNG/self-contained-HTML from a validated job file. Same job + same pins ⇒ byte-identical
  output; zero LLM tokens to re-render. 30/30 unit tests, 22/22 acceptance simulations.
- **`tools/docgen`** — Python. Markdown → self-contained offline HTML + a machine-readable JSON
  sibling, behind a 9-gate sanitizer (tier/secret/PII/implementation-internal/manifest-drift/
  WCAG-AA-contrast/variant-overlap). Renders *structural* diagrams (architecture, sequence,
  flowchart, sankey, timeline, isometric) — deliberately not charts, which are the other
  engine's job.
- **`tools/ENGINE_ROUTING_POLICY.md`** — which of the four possible engines draws which picture
  (`docgen` structural · `visual-engine` quantitative · vendored `force-graph` for the product's
  own live in-app graph, unchanged by this · ephemeral chat visuals, never saved as docs).
- **`tools/PROVENANCE.md`** — full derivation record: what was copied, what was rebranded, what
  was deliberately excluded, and a same-day correction when the first sweep proved incomplete.
- **`docs/blueprints/session-login-mechanism.{md,html,json}`** — the first document built through
  the full pipeline, about ADR-056, embedding a real rendered figure. Proof the port works
  end to end, not just that files were copied.

### Fixed
- **A leftover upstream brand font** (`Space Grotesk`) hardcoded in `visual-engine`'s
  standalone-HTML export wrapper, missed by the port's original sweep because that sweep
  checked source only and no standalone HTML had yet been rendered. Now `Inter`, matching the
  rest of the theme. `tools/PROVENANCE.md` records the correction rather than quietly patching
  over its own earlier "removed outright" claim.

### Changed — design handoff (a separate local design repository, since deleted)
- **`03_ENDPOINTS_CURRENT.md` re-verified against source and re-stamped**: 31 → **38** broker
  ops, 10 → **11** MCP tools, 14 → **24** CLI subcommands, plus ADR-056's new session-token
  response shape. Also fixed a leftover upstream-branded node in its `graph.snapshot` example.
- **`VAULT_GRAPH_SPEC.md`** gained node-radius-by-entry-count sizing (§2, with an explicit
  non-leak justification and a linked blueprint figure), a tree-view visual language that
  distinguishes sections by weight/tone/shape rather than hue (§3a — reconciling the request
  for "colour to distinguish sections" with KEEP's own achromatic law), and liveness +
  gamification sections (§8/§9) that name what already qualifies and exclude decorative motion.
- **`04_CLAUDE_DESIGN_PROMPT_STRICT.md`** gained §10: graph/tree pointer, 2FA/settings/logging
  coverage confirmation, an About-screen version number, fixed discrete responsive breakpoints
  (not fluid reflow), and the personal-vs-organization two-bundle split.

---


## [2.0.0-alpha.6] — 2026-09-24 · The first packaged release — the daemon opens its own vault

The first version stamped into the binaries and packaged (`scripts/release.sh`, `RELEASE.md`).
**Unsigned and Software-tier — read `RELEASE.md` → Known limitations (K-5 … K-8) first.**

### Security and correctness — found by running the real binaries, not the tests
- **The shipped daemon could not open a vault.** `credmgr init` created one; `credmgr unlock`
  with the same passphrase answered `wrong_passphrase` — the broker unwrapped with the empty
  placeholder keystore it started with. Nothing loaded a vault after a restart, and every change
  lived only in memory: a restart kept the ciphertext and lost every name, node, grant and the
  2FA gate. All 406 tests passed throughout, because each builds its own correctly-keyed state.
  Fixed (ADR-063): `vault.unlock {passphrase}` builds the Software keystore from the passphrase,
  proves it, loads and verifies the vault from disk (HMAC, rollback counter, cross-bindings), and
  every successful change is written through in the crash-safe order.
- **The 2FA gate is persisted** (ADR-064) — its seed sealed under a root-derived key, recovery
  codes as hashes, the last accepted step so a code cannot be replayed across a restart. A
  re-enrolment that is started and abandoned no longer removes the gate.
- **The desktop bridge's own test suite had been red since 2026-08-31** (four ADR-061 error codes
  it did not know) and ran in no CI job; it now runs in `security.yml`.
- **The desktop window had no Content Security Policy** (`"csp": null`); it now has an absolute
  one, held by a test that fails closed on `null`.
- **Locking one node would have logged the user out of the vault** once `vault.node_lock` was
  reachable — the bridge read the node's `locked: true` as the vault's. Fixed before shipping.
- **Two MCP tools could never succeed.** `credmgr_search` advertised `query` while the broker reads
  `term`, and `credmgr_list` marked `node` optional while `entry.list` refuses without it — every
  agent search, and every list that took the advertised default, was `malformed_request`. Fixed,
  and every tool schema is now held against the arm it calls by
  `crates/mcp/tests/schemas_match_the_broker.rs`.
- **Every stored value's plaintext digest sat beside its ciphertext.** The manifest's `sha256`
  hashed the plaintext, so a guessable value (a PIN, a short token) could be confirmed offline from
  the vault directory alone. It is now the digest of the sealed envelope (ADR-067); a test asserts
  no file under the vault carries a plaintext digest.
- **A login that had expired was silently demoted instead of refused.** The broker resolved a token
  it no longer held from the caller's working directory, so an idled-out login kept "working" with
  fewer rights. It now answers `session_expired` (ADR-068), and the desktop bridge and the CLI treat
  that as "unlock again". `vault.status`, `unlock`, the gate ops, `init` and `lock` still accept a
  dead token.
- **Writes made while the vault was locked survive a restart** (ADR-069). The review tray used to
  keep its envelopes on disk and forget what they were; each now carries a small metadata file and
  the tray is rebuilt at the first unlock. Tray files are treated as untrusted — a malformed or
  planted one is skipped and can never stop an unlock.
- **`maintenance.verify` checks every envelope against its manifest digest**, with no key — a
  swapped, corrupted or half-updated envelope is reported as an error (ADR-067).
- **`deny.toml` bans every HTTP client and server crate** from the workspace, so "no network code in
  the broker" is enforced by `cargo deny`, not by review.

### Added
- **Vault bootstrap — `credmgr init`** (ADR-061, 2026-08-31, not previously recorded here).
- **The last door** (ADR-064): `vault.gate_recover` / `credmgr gate recover` — passphrase plus the
  root recovery code reset a lost gate. Closes Phase 5 exit-gate line 6.
- **`credmgr gate enroll`** — the CLI enrolment path `07_TWO_FACTOR.md §4` named.
- **A login reaches its owner's whole vault** (ADR-065) — every node but Orphaned; the gap ADR-047
  and ADR-056 named.
- **Directories can be bound to a node** (ADR-066): `node.create … workdirs`, `node.set_workdirs`,
  `credmgr node create --workdir`, `credmgr node workdir`.
- **The desktop bridge reaches all 42 broker ops** (ADR-062), with a typed TypeScript client
  (`apps/desktop/src/lib/bridge.ts`) held to the Rust table by drift guards.
- **`credmgr --version` / `credmgrd --version`**, stamped with the commit and target.
- **`credmgr pending`** — list, accept or discard writes made while the vault was locked. The CLI
  told users such a write was "pending review at next unlock" and had no command to review it.

### Counts
42 broker ops (40 + `vault.gate_recover` + `node.set_workdirs`) · 11 MCP tools, unchanged ·
24 broker error codes (19 + ADR-061's four + `session_expired`) · ADR-062…ADR-069.

---

## [2.0.0-beta.1] — 2026-09-24 through 2026-10-31 · since 2.0.0-alpha.6 · public repository 2026-11-01; tagged `v2.0.0-beta.1`

The first beta. **Unsigned and Software-tier — read `RELEASE.md` → "What this beta does not do" and Known limitations first.**
Worked from the Claude Design project's `BACKEND_HANDOFF_NOTES.md` (reported back in `BACKEND_REPORT.md`), from the
finish loops of 2026-10-02 and 2026-10-03, the finish plan C0–C4 (2026-10-17 and 2026-10-18), and the backend waves and
production-plan batches 1–4 of 2026-10-24 to 2026-10-31 (`docs/PRODUCTION_PLAN.md`). Every version stamp says
`2.0.0-beta.1`.

Counts at the head of this section, measured from code on 2026-10-31 at `b94443c`: **55 broker ops**
(`corpus_check.broker_ops()`) · **15** MCP tools · **25** broker error codes · **27** top-level CLI subcommands ·
ADR-070…ADR-097 (ADR-095 is a design record for the post-release licence; ADR-096 relicenses to source-available; ADR-097 records the V1 import and the planned hygiene scan; the next number is ADR-098). Tests, from the recorded runs and **not re-run for this entry**: the last
full workspace listing, on 2026-10-26, was **900 passing in 59 test binaries**, and ADR-093 added five since (905
`#[test]` functions in the crates); the desktop shell's bridge suite ran 200 tests; the front end ran 700 unit tests, the
Chromium and WebKit Playwright suites, 80 real-daemon journeys and the 87-state design audit, all green on 2026-10-30
(`docs/PRODUCTION_PLAN.md`, `BACKEND_REPORT.md`; the Playwright suites ran 658 passed and 2 skipped on 2026-10-26, the
skips being WebKit specs quarantined as QT-1 — there are four now). The alpha.6-era figures were 448 tests in 37
binaries and 65 shell tests. **None of it had run on GitHub when this was written** (correction: GitHub CI first ran on 2026-10-31 and 2026-11-01, pull request #41; see Known issues).

> **Upgrading from an alpha, and not going back.** A vault opens unchanged, with no migration step, and every
> existing entry is read in place as a single field. **A vault that 2.0.0-beta.1 has written to cannot be opened by
> an alpha build:** an alpha refuses a version-2 entry envelope (`UnsupportedVersion(2)`), reads a manifest carrying
> `hasTotp: true` as tampered, and drops the seal records of any sealed node. Back up the vault directory and
> `~/Library/Application Support/credmgr-state` first (`RELEASE.md`).

### Highlights — what this beta adds over 2.0.0-alpha.6

- **A desktop app that is the real thing.** Every screen reads from the `credmgrd` broker and every change goes to it; there is no demo data in a release build. First run, unlock, lock, two-factor enrolment and recovery, nodes (projects), entries, notes, search, undo, backup, verify and doctor all run against the real daemon.
- **Entries with any number of labelled fields** (ADR-078), masked values, generate-a-value with undo, bulk paste, and a copy that goes to a concealed, self-clearing clipboard.
- **Project isolation you can seal.** Seal a node and restore it within seven days; the seal survives a restart and a crash (ADR-079, ADR-089); private node names; a crash-safe root-key rotation.
- **Agents that ask, and a person who decides.** An agent's reveal waits for your decision, including while the vault is locked, and is released once, for the fields it asked for (ADR-088, ADR-090, ADR-094); a TOTP seed is never returned by a reveal, only the code it makes (ADR-094).
- **Two-factor that guards the door** with recovery codes and a root recovery code.
- **Security fixes found by the final audit**, all re-verified: no session token in the audit log (ADR-077), no seed readback, approvals taken only by the request they were given for (ADR-094).
- **Release tooling:** a deterministic tarball, SBOMs, a SHA-256 checksum list, the `.app`, `.dmg` and `.zip`; the binaries record macOS 13.1 as their minimum.
- **55 broker operations, 15 MCP tools, 27 CLI subcommands, 25 error codes**, endpoint matrix 55/55.
- **Licence: source-available, rights reserved (ADR-096, supersedes ADR-074).** The source is public to read, audit and report on; running the current stable release is free; copying, forks, modified builds and redistribution are not allowed without written permission; future versions may not be free. `LICENSE` is identical in `v1/` and `v2/`; `TRADEMARKS.md`, `CONTRIBUTING.md` (contribution terms), `DONATE.md`, `SUPPORT.md` and `THIRD_PARTY_NOTICES.md` (generated by `tools/gen_third_party.py`) follow it. The word "open source" is no longer used for CredMgr.
- **Repository moved to the FreexStudio enterprise:** `FreeXStudio-Platform/credmgr`. Secret scanning with push protection, Dependabot security updates and CodeQL (Rust, JavaScript/TypeScript, Python, Actions) are on; every workflow action is pinned to a commit SHA, as the organisation requires.
- **CodeQL triage.** Fixed: a polynomial regular expression in V1's field detector (a length cap) and an unescaped quote in the chart template. The remaining alerts are test code, zero-initialised key buffers and a local-only server, each dismissed with a reason on the alert.
- **A one-way V1→V2 copy tool** (`tools/v1-to-v2/migrate.js`): read-only on V1, never prints a value, verifies each copy by hash, idempotent, skips the operator-sealed targets by default (ADR-097). The doctor's duplicate and wallet-bundling scan is designed, not built (`docs/25_VAULT_HYGIENE.md`).
- **The donation dialog names the real proof address** (Admin@freexstudio.com) instead of a placeholder.
- **A setting for screen-capture protection.** Settings > Security: "Hide the window from screen capture and screen sharing", on by default, asks for confirmation before it is turned off, remembered across restarts (threat T10; the developer override `CREDMGR_CONTENT_PROTECTION=off` still wins).
- **Searchable help.** The Help dialog searches 142 records and says where each feature is (screen, button, menu, shortcut, CLI command); the same text is `HELP.md`.
- **A manifest for LLM agents.** `docs/llm/credmgr-capabilities.json` lists every feature, the 55 broker operations (with the agent-reachable subset), the 15 MCP tools with their input schemas, the error codes with what to do, the human-in-the-loop rules and an explicit never-list. It is generated by `tools/gen_help.py` from `docs/help/features.json` and the code, and `gen_help.py --check` catches drift. No operation, tool or error code was added: an agent keeps exactly the access it had (scoped to a node, sensitive values released only on approval).

### Security
- **The audit log no longer records a session's bearer token.** Since 2.0.0-alpha.4 (ADR-056) every
  audit record made under a login, and every token-workdir anomaly record, carried the token itself
  as `actor` (and, for the anomaly, inside `detail`) in the plaintext audit file and in `audit.tail`,
  so any process running as the owner could read the live token out of the feed and replay it as the
  owner. The actor is now `<Origin>:<session public id>`; bearer-shaped strings are redacted on the
  way into the log and on the way out of `audit.tail`; `Debug` on tokens, requests, scopes and the
  bridge session redacts. A vault written by an affected build still holds dead `cmt_…` strings in its
  audit files — see `SECURITY.md`, "Session token in the audit log". (ADR-077)

- **The release text now states what the Software tier protects and what it does not, in one place** (K-5,
  `docs/04_CRYPTO_AND_KEYS.md §2.4`, repeated in `README.md`, `RELEASE.md`, `SECURITY.md` and the two-factor and
  cross-platform documents): your passphrase is the key; nothing is held in the Secure Enclave; while unlocked
  `credmgrd` holds the root key and every unlocked project key in memory and does not lock its pages or block
  debuggers; there is no Touch ID or presence check; and **two-factor guards the door, not the safe** — it is
  enforced by `credmgrd`, not by the encryption, so someone with the passphrase or the recovery code and a copy of
  the vault folder can decrypt without the second factor. Earlier wording ("the root key alone opens nothing",
  "one TOTP code short of every credential") overclaimed and is withdrawn (ADR-079).
- **`approval-on-demand` no longer promises what it cannot keep.** A value approved for an agent is decrypted and
  staged when the decision is made, any lock drops it, a decision that races a lock stores nothing, and request ids
  are 128-bit (ADR-079). A request on a wholly locked vault used to answer `approval_pending` with nothing able to
  complete it, then `vault_locked`; it is now recorded and can be decided with the unlock factors while the vault
  stays locked (ADR-088, below).
- **Node ids are validated where they are chosen** (`[a-z0-9][a-z0-9_-]{0,63}`; `global`, `orphan`,
  `removed-entries` and `entry-history` reserved): an id such as `../x` used to leave the vault, and two reserved
  names aliased the entry archives onto a sealed node's archive, where a later restore could remove them. (ADR-079)
- **One canonical form for names (ADR-084, threat T4 closed).** `credmgr_core::names::canonical_name` — strip bidi
  and zero-width controls, NFKC, Unicode lower-case, then the look-alike table — is what every uniqueness check
  compares: `entry.create`, each `entry.create_batch` item, the locked-write tray, `entry.restore` / `entry.undo`,
  `vault.pending_accept`. A look-alike of an existing name (`payroll` with a Cyrillic `а`) is the existing
  `entry_exists` refusal, for an agent too; the stored name stays as typed; a name that mixes Latin with Greek or
  Cyrillic is accepted with an additive `warnings: ["mixed_script_name"]` (`credmgr` prints it on stderr). New
  dependency: `unicode-normalization` (pure tables). An older vault that holds two names differing only by case
  keeps both; only a new create is refused.
- **`privateNames` is enforced (ADR-083).** A reader that is not the owner's login sees an opaque node:
  `graph.snapshot` row `{id, nameHidden, name: null, entryCount}`, `entry.list` `{entries: [], nameHidden, count}`, a
  count below three hidden, no name or label through `search`, `entry.get`, the pending tray, `notes.read` or the
  audit feed. The owner sees everything. A node whose name is private gets an opaque id (`n_` + 12 hex) when the app
  creates it, because the id is shown to every reader who may list the node and never changes (ADR-091).
- **`requireTwoFactor` is enforced (ADR-085).** With a confirmed gate, `reveal` (the default) asks before a value
  leaves the vault and `always` before any read of the node; the answer is `two_factor_required` until a fresh gate
  verification. A logged-in owner steps up with `vault.gate_verify` (no token; `credmgr gate verify <code>`); the owner's
  own login is exempt. `node.policy` reports `notEnforced: []`. **The window is vault-wide** — one gate, one
  300-second elevation for every caller, ended by a lock or any node-policy change; a per-node secret is deferred to
  2.0.0 and recorded as a known risk (ADR-093).
- **Names have a length (ADR-093).** `entry.create` and each `entry.create_batch` item refuse a name over 200
  characters (`malformed_request`, naming the bound, never the text); `node.create` validates its label like
  `node.update` always did (1–120 characters, trimmed, no control characters). Existing names are untouched.
- **A decision made with the factors while locked finishes an interrupted root-key rotation first** (ADR-093), as
  unlock does; if that fails it decides nothing.

### Added
- **Entries with any number of fields, with labels you choose** (ADR-078). An entry's plaintext is a
  canonical-JSON field document `{v:1, entryType?, sensitivity?, fields:[{id,label,value,type?,masked?}]}` sealed as
  **envelope version 2**; the version byte is inside the AEAD's additional data, so the payload kind is
  authenticated. A legacy version-1 entry is read in place as one field (id `f_00000000`, empty label) with its
  projection unchanged — no migration. Field ids are `f_` plus eight hex digits; labels are free text (200
  characters, no control characters) with **no vocabulary anywhere**, and a test greps the product for a
  predefined field-name list. A document is at most 16 MiB and a batch at most 64 MiB. A type or sensitivity is
  stored only when you pinned it; `"auto"` clears the pin. The entry type `note` replaces `note-only`; inference
  gained R0 (one field labelled `note`/`notes` is a note) and R1 (a TOTP seed with at most two fields is a TOTP
  entry). `ManifestEntry.hasTotp` is skipped when false so alpha.6 manifests still verify.
- **Seven new broker ops** (48 → 55). ADR-078: `entry.get` (labels, types, masking and ids, **never a value**) and
  `field.add`, `field.update`, `field.remove`, `field.reorder` (48 → 53). Field edits keep the entry's history and are
  undoable with `entry.undo`; `entry.create`, `entry.create_batch`, `entry.update`, `entry.rotate`, `entry.reveal` and
  the review tray carry fields. The broker never parses the paste grammar — the CLI and the desktop shell do — and a
  field op needs the capability `entry.update` needs, under the same graph rules (isolation tests I-27…I-29).
  ADR-087: **`util.generate`** (the 54th), the password generator, in the broker (`credmgr generate`, bridge command
  `util_generate`): length 8–128, symbols, pronounceable; the value never exists in page JavaScript. Not an MCP tool.
  ADR-090: **`vault.approval_get`** (the 55th), below.
- **Approval while the vault is locked (ADR-088, ADR-090).** A reveal on a wholly locked vault records a request;
  `vault.approval_decide` with the passphrase (and the authenticator code) releases that one value while the vault
  stays locked (`credmgr approve <request> [--deny] [--code <n>]`). A recovery code is refused; wrong factors count
  toward the unlock back-off; the spent TOTP step survives a restart; the decision is audited under `Factors`.
  `vault.approval_get` lets the person see what a waiting request asks for before deciding: node and entry (by name
  when the broker holds the names and the node's name is not private), the command, the seconds left; with no
  `request`, the list of everything waiting. Read-only, works while the vault is locked, decrypts nothing; an unlocked
  vault answers only the owner's login. `vault.status` carries a bare `pendingApprovals` count. CLI:
  `credmgr approvals [<request>] [--json]`, and `credmgr status` prints the count. Neither op is an MCP tool; I-13 is
  unchanged.
- **Undo of a field change (ADR-086).** No new op: `entry.undo` already covered the four `field.*` ops; its answer
  gains `ok` and `restored`, and a field edit is undoable for seven days.
- **CLI** (21 → 27 top-level subcommands): `credmgr field ls|add|set|rm|mv`, `credmgr get --field <label>`,
  `--field-id`, `--all` and `--json` (an entry with several fields and no selector refuses and lists the labels),
  and `credmgr set --bulk` (one paste becomes one entry; on an existing entry it replaces the field list),
  `--field`, `--field-id` and `--label` (values still come only from stdin); `import`, `node rename`, `node policy`
  and `notes` (below); and `generate`, `approve` and `approvals` (above).
- **MCP** (11 → 15 tools): `credmgr_get_metadata`, `credmgr_field_add`, `credmgr_field_update`,
  `credmgr_field_remove`; `credmgr_create`, `credmgr_update` and `credmgr_rotate` take `fields`. No tool reorders,
  creates a grant or returns a value from the metadata call.
- **Sealing that survives a restart and a crash** (K-7, ADR-079). The orphan cold key (`keys/cold/orphan.key`, format
  `CMCK` v1, 98 bytes) is built and opened only by `node.seal`'s pre-flight; `credmgr init` creates the orphan node
  (an older vault gets one at its first seal or `maintenance.doctor`, never at unlock); seal records live in the
  signed registry (format 2) under the HMAC and the generation counter, and seal and restore are commit protocols
  with load-time roll-forward. `maintenance.rotate_root` re-seals the cold key and refreshes every seal record;
  `maintenance.backup` includes the cold key; `maintenance.verify` checks it. `node.seal` reports
  `archiveMovePending` and `node.restore` reports `workdirsDropped` when they apply.
- **Seal and restore are isolated from concurrent registry writes, and expired seals can be purged (ADR-089).** Both
  re-check under the persist lock; `node.create` and `node.set_workdirs` wait for it. `maintenance.doctor` with
  `purgeExpiredSeals` (`credmgr doctor --purge-expired-seals`, opt-in, Admin on `global`; `--dry-run` only lists)
  destroys the retained originals of nodes sealed more than seven days ago: the entries stay in Orphaned, sealed to
  the cold key, and only the way back to the live node ends. A plain Doctor run never purges.
- **Release tooling** (the 2.0.0-beta.1 line). `scripts/release.sh` writes a **deterministic** tarball, CycloneDX bills
  of materials with no build-machine paths, and a `SHA256SUMS` over every published file, and runs its own
  `--verify` (`--verify [DIR]` re-checks an existing `dist/`); `scripts/release-app.sh` builds the desktop app as an
  ad-hoc sealed `CredMgr.app`, `.dmg` and `.zip`, starting the built app and requiring a real window; `scripts/fresh-install-check.sh`
  installs the tarball the way a user would; `scripts/release-selftest.sh` corrupts copies of a good release and
  requires `--verify` to refuse each; a Homebrew formula is prepared under `packaging/homebrew/` and **not
  published**. Measured 2026-10-03: the same commit in the same checkout is byte-identical; in a second checkout the
  bills of materials are identical and the binaries differ in 47–48 bytes (the Mach-O UUID and the ad-hoc signature).
  Nothing signs, notarises, uploads or publishes (K-4, K-5). The artefacts in `dist/` on 2026-10-31 were built from
  `709840c`, and `release.sh --verify` passes on them.
- **`docs/RELEASE_VERIFICATION.md`** — a checklist of the controls of the built app (the event, the bridge command and
  broker op it reaches, the expected result): 214 control rows in 22 screen templates, derived from the shipped templates
  of 2026-10-03, plus 30 menu-item rows. Its result column was filled in by a tester pressing the controls in a built app
  on 2026-10-18 (190 pass, 7 fail, 85 not pressed, each saying why; no P0, the one P1 fixed), and §11–§13 record the
  later design drops and the built-app checks of 2026-10-19, 2026-10-27 and 2026-10-31. The rows were **not extended
  for the controls the later drops added**: `tools/release_verification_check.py` reports 48 findings against the current
  templates (a row missing for a new control, or naming a handler that moved), so its `--self-test` refuses to run until the rows are brought level.
- **`scripts/e2e-fields.sh`** — the multi-field entry through the real binaries (bulk paste, selection, field edits,
  undo, a seal and a restore with fields, a restart, then a vault written by 2.0.0-alpha.6 opened unchanged). The
  alpha.6 compatibility segment needs the alpha.6 binaries (`LEGACY_BIN_DIR`) and counts as a failure without them.
- **Rename a node** — `node.update` (ADR-071). The id never changes; only the label. Global and
  Orphan cannot be renamed.
- **Change a node's policy** — `node.policy` (ADR-071): a partial patch with a mandatory reason
  recorded in the audit. Tightening needs the admin gate; widening a node's reach needs presence and
  is refused until presence exists.
- **Node notes** — `notes.read` / `notes.write` (ADR-072): markdown sealed under the node key,
  reachable only with the `notes` capability, and refused if the file does not match the digest
  the signed manifest records. `maintenance.verify` checks it without a key. `notes.read` also
  returns the manifest generation a write must be based on, so a grantee holding `notes` without
  `list` can write (ADR-077).
- **Batch create** — `entry.create_batch` (ADR-073): up to 500 single-value entries in one call,
  all validated before any is written. Each item may carry several fields since ADR-078.
- **Replace the root key** — `maintenance.rotate_root` (ADR-076): a new root key, every
  node key re-wrapped, both root wraps rewritten, every root-signed file re-signed, and a new
  recovery code issued once. Crash-safe by a stage / commit / roll-forward journal whose recovery is
  key-free and runs at daemon start and at every unlock, serialised by a per-vault lock; the vault
  opens with the old key or the new one at every instant. The roll-forward checks every staged file
  against the commit record before it moves the first one; if the commit record cannot be proven
  durable it moves nothing, locks the broker and answers `completionPending` (the desktop bridge drops
  its login at once), and the next unlock finishes the move. A second `credmgrd` or broker state that
  starts mid-rotation waits on the per-vault lock (`run/rotation.lock`) instead of deleting the stage
  as a crash leftover, and the daemon skips recovery when a live broker already serves the vault. The
  wire answers `presence_required` (after the human, `admin` and second-factor checks) until presence
  attestation exists; the op is on the MCP forbidden list and the per-uid auth backoff, and the CLI
  has no command for it; the new recovery code is zeroised when the outcome is dropped.
  `scripts/emergency-decrypt.mjs` recognises a vault caught mid roll-forward and says what to do
  instead of "authentication failed".
- **CLI parity for the design side's asks**: `credmgr import <file|-> --node <id>` (an all-or-nothing
  `.env` import; a quoted value whose missing closing quote would swallow the next assignment is
  refused, naming both line numbers and never content; a batch that stops part-way exits non-zero),
  `credmgr node rename <id> <label>`, `credmgr node policy <id> --reason …`, and
  `credmgr notes show` / `set` / `clear`. Text comes from a file or stdin, never argv. `notes set`
  refuses empty input, so a failed pipe cannot destroy a sealed note; `notes clear` is the only
  deletion. `--reason` no longer swallows the next option. Top-level subcommands 21 → 23.
- **The desktop app is hosted and wired** (ADR-075): the stock SvelteKit scaffold is replaced by the KEEP design,
  precompiled at build time (React 19.3.0, Vite 8, TypeScript 7) and served under the unchanged strict CSP
  (`script-src 'self'`, `style-src 'self'`, no `unsafe-eval`, no `unsafe-inline`, no remote origin). Build-time gates:
  `verify-build` (no inline code, eval, Babel or remote URL), `verify-csp` (WebKit and Chromium, with canaries),
  `verify-parity` and `verify-design-audit` (against the design export). A sanitised upstream snapshot and its
  `PROVENANCE.md` sit under `design-upstream/`; its importer refuses to run without the project-name table kept outside
  the repository, and a render error shows "Something went wrong" instead of a blank window. **Every screen reads from
  the broker and every change goes to it** (`src/vault/`, one model, call-then-re-read, no optimistic write): first run,
  the lock screen with the second factor and recovery codes, the graph and tree, an entry's fields (add, edit, remove,
  reorder), the add-entry dialog with single and bulk modes and a live preview, the review tray, node create, rename,
  lock and seal, grants, search, settings, backup, verify, doctor and root-key rotation. A control with no operation
  behind it was removed rather than left mocked; a release build carries no demo data and no screen shows a "mock" or
  "not built" marker. Five operations are sent for real and refused with `presence_required` (grant creation, the full
  audit record, a TOTP seed, root-key rotation once its other checks pass, a registry rebuild). The app has **no
  control to delete an entry, to edit a node's note, or to decide an agent's request while the vault is unlocked**.
  Tested by the shell's bridge suite, by Vitest and by Playwright tests that run the app under the production CSP against
  a fixture broker held to `bridge.ts`'s declared shapes (0 CSP violations, 0 console errors, 0 external requests), a
  design audit probe, and a real-broker suite that drives the built app against a real `credmgrd` (counts above).
  What the later design drops and follow-ups added to it:
  - *Setup choices and a menu-bar icon (ADR-081).* The first run can skip the recovery-code retype, accepts a passphrase of
    four characters or more (eight or more recommended) and treats the second factor as optional; a menu-bar icon
    survives closing the window, and closing the window locks the vault first.
  - *UI hardening (chunk C2).* One open entry holds secrets at a time; Restore works from the broker's sealed list after a
    restart; a 2FA marker on entries; menu keys; the design project's `audit-probe.js` stays private (development only,
    not shipped).
  - *Design drop 2026-10-18.* The milestone reminder (50/14, 150/45, 300/90, at most three, "don't remind me"; ADR-082),
    the sealed supporter extras and their code prompt, the Graph / Identity / Motion / Games regroup of Settings →
    Appearance with a live preview, the free Milestones list, the header badge, the unlock flourish, CredPong node shapes
    and trail, node shapes in the worktree, single-key shortcuts that can be turned off, warnings on names that mix Latin
    with Greek or Cyrillic letters, 24 px targets, and a CredGames library (CredPong only; further titles are bundled,
    never loaded from a script). The flourish and the day count start only from a successful unlock. New window keys:
    `credmgr_donate_unlocked`, `credmgr_extras_key`, `credmgr_usage`, `credmgr_keys` (all in `PRIVACY.md`). Release builds
    have neither the test pack nor the test hooks; `scripts/verify-csp.mjs` asserts `crypto.subtle` in WebKit and
    Chromium, and in the built macOS window the extras prompt reached its decrypt step (`RELEASE_VERIFICATION.md` §12.1).
    `scripts/guard-no-secrets.mjs` gained a `base64-blob` rule (300+ base64 characters) that allows the extras pack by name
    only. Donation policy and the docs it changed (`DONATE.md`, `PRIVACY.md`, the design-upstream `PROVENANCE.md`) came
    with it, and so did the front-end records imported into `docs/` (`FRONTEND_THREAT_MODEL.md`, `ACCESSIBILITY.md`,
    `AUDIT_2026-10-18.md`, `SUPPORTER_EXTRAS_PLAN.md`).
  - *Design drops 2026-10-24 and 2026-10-25, wired to the broker.* Undo after Add field / Edit / Remove (`entry.undo`);
    Generate in Add field (the broker makes the value, the dialog shows it masked with its entropy, it enters the entry
    only through `field.add`); a dialog for `two_factor_required` and a step-up; a decision made on the Lock screen
    while locked (request id, passphrase, code); the privateNames checkbox on the node dialog and a "name hidden" chip on
    the owner's row; Doctor asking for `purgeExpiredSeals`. The "recorded, not enforced" wording is gone from the node
    dialog, the inspector and Help.
  - *Follow-ups of 2026-10-26 (ADR-090, ADR-091).* The Lock screen asks `vault.status` every five seconds and lists the
    waiting requests (the request-id field returns only when none is listed). The broker's `warnings` are shown
    (`mixed_script_name` on entries, batches, node creation and rename) in the same notice as the success, without
    blocking. The audit id passes through the shell into the answer of every changing op (24 ops), and Undo uses it and no
    longer reads `audit.tail`. **The shell reloads the main webview on every lock it sees** (sleep, screen lock, session
    switch, menu bar, window close, quit), after the broker lock, the clipboard clear and the `credmgr://locked` event,
    and the Lock screen's note survives the reload; the page's own locks (the Lock button, ⌘L and the idle timer) reload
    it too, 150 ms after `vault_lock` answers (2026-10-27). A lock the broker takes by itself is not seen by the shell and
    does not reload. The second factor is given on purpose: the chip on a node that asks for one opens "Give the second
    factor" (the owner's login is exempt). Four WebKit-only focus races are quarantined (`test.fixme` on WebKit, register
    row QT-1); Chromium still runs them.
  - *Design drop B20, merged (ADR-092).* **Doctor no longer purges by itself:** a plain Doctor run sends no
    `purgeExpiredSeals` (it used to, so its Apply destroyed seal originals without a separate ask); the new "Doctor with
    purge" row previews, then applies, the removal of originals of seals older than seven days. The inspector shows
    "2fa · on reveal", the action "Give second factor" and, while the 5-minute window is open, a countdown; a step-up with
    no gate enrolled says so. The Lock-screen approval shows a count, an always-visible request-id field and factors only
    after a request is chosen; a locked Deny needs the passphrase and code. The live mixed-script name notice is removed
    (the broker's `warnings` after saving remain). Design snapshot `design-upstream/2026-10-26/`; the contrast line for
    input borders was not taken (the owner's call). The Add entry name is capped at 200 characters (ADR-093).
- **A concealed, self-clearing clipboard and lock-on-sleep in the desktop shell.** `entry_copy` reveals
  the entry Rust-side (the value never reaches the window) and writes it concealed, transient and
  this-Mac-only (no Universal Clipboard or Handoff), cleared after 30 seconds only if the clipboard is
  still the app's own content, and at once on the Lock button, sleep, screen lock, session switch and
  quit; a copy in flight when a lock lands is refused. The app's Copy buttons use it, and `navigator.clipboard`
  appears nowhere in `src/` (a test fails if it does); `copy_text` puts non-secret text (a donation address, a
  node id) on the clipboard with no marker and no timer. The shell locks the vault on sleep, display
  sleep, screen lock and session switch whether or not it holds a login, and tells the window. The
  scaffold's `greet` command and the `opener` plugin are removed; the app's window content policy has
  no network origin, and `cargo deny` / `cargo audit` policies cover the shell's own dependency tree.
  A KEEP app icon, a production product name, a 1280×820 window and macOS 13.1 as the minimum
  replace the scaffold's defaults.
- **Small wire additions** (ADR-077, ADR-080, ADR-090): `vault.status` returns `initialized` and `pendingApprovals`;
  `entry.list` returns `entries` (type, sensitivity, field count, dates) to human sessions only — an agent or MCP caller
  keeps ids and names — and `hasTotp` on its rows; `graph.snapshot` carries `meta.sealed` for a non-agent caller holding
  Admin (ADR-080); a locked node on an unlocked vault answers the new `node_locked` instead of `vault_locked`, so the
  desktop app is not logged out (error codes 24 → 25).
- **`scripts/endpoint-matrix.py`**: calls every broker op over the real socket against the real `credmgrd` on a
  throwaway vault and asserts the documented success or refusal — 243 rows over 55 ops on 2026-10-26, with no
  known-gap or blocked row left (K-7 closed) — and invariants over every generated secret. Wired into `security.yml`,
  `build.yml` and the self-hosted evidence lane; never on push.
- **`scripts/e2e-journey.sh`** — the real-binary journey (init, unlock, restart, locked write, 2FA,
  the last door, a second daemon, imported values and a sealed note surviving restarts, a seal and a restore across a
  restart, generate and a decision while locked, no plaintext or bearer-shaped string on disk). Run it before a release.
- **Repository front door**: a public landing `README.md`, root `SECURITY.md`, `CONTRIBUTING.md` and
  `CODE_OF_CONDUCT.md`, `.github/CODEOWNERS`, V1/V2-aware issue and pull-request templates, and a
  `docs/history/` folder for finished handover and planning documents.

### Changed
- **Superseded by ADR-096 before release:** **Licence: MIT for everything and everyone, organisations included** (ADR-074). No licence key, seat
  limit or payment gate anywhere; money is voluntary donations plus an optional commercial licence
  (an invoice, a certificate, priority support) through the publisher. ADR-074's first wording had the desktop app
  with no donation toast and no supporter unlock code; ADR-082 (2026-10-18) superseded that part: the app shows a
  dismissible reminder at entry milestones and opens a pack of cosmetic extras with an e-mailed supporter code.
  **Nothing functional is gated.**
- **Unlock backoff caps at 1 hour** (was 15 minutes) — the operator's crypto spec (ADR-070).
- **CI:** `build.yml` and `security.yml` ran green on 2026-09-24 (7/7 and 8/8, on the alpha.6-era tree) and have not run on
  this release. The crates workspace is no longer built on Windows (the broker is Unix-socket only until the named-pipe
  transport exists); Argon2 is compiled optimised in dev and test builds, which brought the suite
  from past GitHub's 20-minute job limit to minutes without changing a parameter.
- **`VAULT_GRAPH_SPEC.md §7`** carries the signed-off entry-dots amendment.
- A vault holding key material a rotation cannot re-wrap (`root.wrap.se`, `keys/cold/*`) makes the
  rotation refuse, changing nothing. Every broker request now passes an internal request barrier
  (shared; exclusive for a rotation by a live owner session).
- **Dependencies** (all within the MSRV pins): the v2 workspace lock (`interprocess` 2.4.3 → 2.4.4 and eight transitive
  crates), the desktop shell's Rust lock (92 transitive crates), `vite` 8.3.5 (six advisories on 8.3.0–8.3.2), and the v1
  and visual-engine npm locks. On 2026-10-31 (`b94443c`) the fourteen Dependabot alerts were closed: `tools/visual-engine`'s
  `@modelcontextprotocol/sdk` 1.30.0 → 1.32.2 and `zod` 3.25.76 → 4.6.6 with their transitive packages, and v1's
  `body-parser` 1.20.8 → 1.20.9 and `qs` 6.16.0 → 6.16.2. The shell's `tauri` crate family moved to 2.12.1 with the shell
  lane, level with the desktop npm packages and the Tauri CLI. The rest of the v2 workspace waits on a newer compiler
  (RustCrypto 0.11 / 0.13 needs Rust 1.85, `totp-rs` 6 needs 1.88).
- **`tools/visual-engine`'s and `v1`'s package manifests state the licence** (MIT then; `SEE LICENSE IN LICENSE` since ADR-096) (the engine said
  `UNLICENSED`; `v1` said nothing).
- **`v2/RELEASE.md`'s checksum step could not pass on a genuine download.** `SHA256SUMS` listed the
  two binaries inside the tarball as well as the tarball, so checking it before extracting reported
  them `FAILED open or read`. It is now one line per published file, checked with
  `shasum -a 256 -c --ignore-missing SHA256SUMS` (which passes silently when nothing matched, so the guide demands the
  `OK` line) and the tarball carries its own manifest; `scripts/fresh-install-check.sh` runs exactly that against a
  folder holding only the tarball and `SHA256SUMS`. `RELEASE.md` also gained the no-downgrade box, the unsigned-app
  steps, the Software-tier disclosure, the multi-field and sealing walkthroughs, a Homebrew note, and, on 2026-10-31, a
  list of what the beta does not do.
- **`v2/PRIVACY.md` matches the shipped behaviour:** the app makes no network request (it had listed
  an opt-in update check and an allowlisted documentation link, neither of which exists), names the eleven
  local-storage keys the window writes (`credmgr_prefs` is the settings record) and that none holds a vault name in
  the clear, describes the clipboard, auto-lock and reveal behaviour, and no longer cites `credmgr where`, `credmgr export` or an LLM
  Integration setting that does not exist.

### Fixed
- `totp.code` on a short stored seed panicked the connection thread and left the client with a
  closed socket (MX-1). It now answers a code for any seed of at least 80 bits and a typed
  `malformed_request` below that; a panic inside any op is answered as `internal`; a persisted gate
  secret that is not usable is reported as a corrupt gate document instead of panicking. Padded,
  lower-case or grouped seeds are accepted. The 80-bit floor is a recorded deviation from RFC 4226's
  128 (a stored seed is issued by the verifying service, not chosen here). (ADR-077)
- A locked node on an unlocked vault answered `vault_locked`, which logged the desktop app out. (G3,
  ADR-077)
- `credmgr notes set` / `notes clear` no longer need the `list` capability. (ADR-077)
- **Seal and restore were not crash-safe** (ADR-079, F-a): files moved before the registry committed, so a crash in
  between left a registry naming a node whose manifest was gone and a vault that would not unlock. Also fixed there:
  orphan rows carried the original envelope's digest (F-b); a project with live sub-nodes could be sealed, leaving
  dangling parents (F-c); a sealed id could be re-created and its files collided with the archive (F-d); restore
  re-inserted without re-validating workdirs or parent (F-f); the hot key was removed without being zeroised (F-g).
- **Finish plan chunk C1 (ADR-079 amendment, ADR-080).** A write-through can no longer slip into the window of
  `node.seal` / `node.restore`; hot keys are zeroised where they sit, not on a moved copy; a malformed retry no longer
  burns a human's one-time approval. The release verifier never extracts a tarball whose member checks failed, extracts
  member-by-member after path validation on a Python without `tarfile` filters, and executes the binaries only with
  `--run-binaries`.
- **Review findings of the 2026-10-24 wave**, each fixed with a test: a private node's names reaching a non-owner through
  `entry.undo` / `entry.restore`; invisible characters (a variation selector after `payroll`) making a visible twin; an
  unbounded approvals table on a locked vault; a step-up with no gate enrolled feeding the unlock back-off.
- **WebKit autocorrect on every text field (F-5, `16cbf29`).** A typed `beta` became `Beta`, so the seal confirmation never
  matched; the template compiler now turns autocorrect, autocapitalise, autocomplete and spellcheck off on every input
  and textarea.
- **The final audit's two security findings (ADR-094).** A reveal returned a stored 2FA seed to any caller that could
  reveal the entry (an agent, an MCP client, the CLI): `entry.reveal` now answers a seed field with `value: null` and
  `redacted: "totp_seed"`, for every caller; the code still comes from `totp.code`. There is one seed class, shared by reveal and `totp.code` (an `otpauth://` URI, upper-case base32 at 16, 20, 24, 26, 32, 40, 52, 56 or 64 characters, groups of four in any case, or a field typed `totp-seed`); `totp.code` now refuses a field outside it (a change: type such a field `totp-seed` first), and only the owner can retype a seed field away from the class. An approval given for one caller's
  request was taken, whole, by another caller in reach: an approval is now one slot per (node, entry, requester),
  releases only the fields that request asked for, and the table is capped at 512 slots. Also: Doctor no longer advises `rebuildRegistry`, which
  needs presence; the documents that called the gate per-node, called the idle and sleep locks proven on this build,
  or described `credmgr backup` as restorable were corrected. Report: `docs/release-verification/AUDIT_2026-10-31.md`.
- **A stale line on the second-factor step (`b94443c`).** After a request was approved on the Lock screen, the next
  unlock's code step still showed "approved with the passphrase · the vault is still locked"; an unlock attempt now
  clears it.
- `docs/10_API_AND_MCP.md` showed `"scope": "vault"` in the `two_factor_required` example; the broker
  has always emitted `"global"`.

### Removed
- **Amplitude** — the uncommitted analytics instrumentation was dropped (operator); the app has no
  analytics or telemetry, as `PRIVACY.md` says. (`devalue` was patched 5.9.0 → 5.9.4 in the old scaffold's
  lockfile; it left the tree with the scaffold below.)
- The desktop scaffold's SvelteKit front end, the shell's `greet` command and the `opener` plugin
  (a test fails if either returns).

### Known issues
- **K-9 — a truncated audit tail is re-signed by the next request.** `audit::append` signs the tip over
  the log as it stands without verifying it first, so removing the final lines of the current month's
  log is detected by `credmgr verify` only until the next broker request. Pre-existing (Phase 3);
  recorded in `docs/PHASE8_AUDIT_REPORT.md §4`. The earlier K-5…K-8 stand.
- **The second factor is vault-wide (ADR-093).** One code given for one node opens the gate for every node that asks for
  one, for every caller (agents, MCP, CLI), for up to 300 seconds. Bound: the window cannot be extended and ends on a lock
  or any node-policy change; the nodes that ask are the ones the owner marked; the owner's own login is unaffected.
  Owner: the operator. Resolution: a per-node second factor, milestone `2.0.0`.
- **`vault.approval_get` tells a locked vault's neighbours more than an unlocked one's (ADR-090).** On a locked vault any
  same-user process (an agent included) can learn which nodes and entries other agents are asking for, and the names of
  nodes that are not private; an unlocked vault refuses the same caller. It cannot read a value, decide anything or see a
  private node's names. Accepted for the Lock screen's sake.
- **K-7 is closed in part; K-10 is new** (`docs/PHASE8_AUDIT_REPORT.md §4`). The factor-bearing approval
  (`vault.approval_decide`, `vault.approval_get`, `credmgr approve`), the purge of expired archives and `meta.sealed` in
  `graph.snapshot` are built (above). Not built: a `keystore` field in `vault.status` and offline recovery of orphaned
  entries; open: hot keys copied without a wipe on a whole-map replace, and an approval keyed by (node, entry) rather than
  by the requesting session. K-10: the broker reads one request line with no size cap (a 64 MiB batch is a same-user
  memory-exhaustion path), an entry-level `reveal` grant may never be usable, `search` matches names only, decoded field
  documents are not scrubbed from memory on drop, and rotation history is not pruned.
- **`credmgr get` on a multi-field entry with no selector reveals before it refuses.** It sends `entry.reveal` with no
  `fieldIds`, so every field value crosses the socket into the CLI process and one reveal of the entry is audited, and
  only then exits 2 with the labels (`crates/cli/src/main.rs`, `cmd_get`). Nothing is printed, but the refusal should
  list the labels from `entry.get` (a capability read, never a value) and reveal nothing. `credmgr field ls` already
  lists labels without a reveal.
- **The desktop app is unsigned and its per-control checklist was not re-walked against the final screens**
  (`docs/RELEASE_VERIFICATION.md`). It has no control to delete an entry, to edit a node's note or to decide an agent's
  request while the vault is unlocked. The Help dialog says a note is "masked until you reveal it", but a text field is
  not masked. The 5-minute idle lock (the window's idle lock, 15 minutes by default) and a real sleep or screen lock were
  not exercised by hand on this build; the operator's sleep-and-wake check of 2026-10-18 was on an earlier build.
- **The command-line binaries are not yet proven on a macOS older than the build machine's.** They record 13.1 as their
  minimum (`otool -l`, `LC_BUILD_VERSION`; `scripts/release.sh` pins `MACOSX_DEPLOYMENT_TARGET`, fixed after the claim
  check found 27.2, the build host's version, in the first beta.1 build).
- **The bundled fonts' licence texts are not copied into the built `.app`.** About → Licences names the three typefaces and
  says their SIL Open Font Licence texts ship in `third_party/fonts`, which is a folder of the repository, not of the app.
- **Superseded 2026-11-01: GitHub CI has not run on this release.** The account's GitHub billing blocked every GitHub-hosted job (issue #33): the account is on the Free plan with **no payment method on file**, October's included Actions minutes were used up and about $36 of overage was billed with nothing to charge it to, so GitHub refuses to start any job ("recent account payments have failed or your spending limit needs to be increased"); the included allowance resets on 1 November. So
  `build.yml` and `security.yml` could not be dispatched for 2.0.0-beta.1. The evidence is the local gate runs recorded in
  `docs/PRODUCTION_PLAN.md` and `BUILD_LOG.md`, and the built-app check in `docs/RELEASE_VERIFICATION.md` §13. The
  `security.yml` job is still named "isolation suite (I-1..I-25)" and also runs I-27…I-29.
- **Not built, and scheduled in the `2.0.0-rc.1` and `2.0.0` milestones** (`docs/PRODUCTION_PLAN.md`): presence and Touch ID,
  the Secure Enclave tier, signing and notarisation, aliases and near-duplicate detection, the `.env` importer's preview
  and collision options, `node.rekey`, a machine lock, a duress code, `llm.*`, security levels, content search, Windows and
  Linux keystores and the org vault.
- **Version skew (resolved in C3):** the workspace was `2.0.0-alpha.6` while the desktop app said `2.0.0-beta.1`; all manifests now agree, and `release.sh --verify` flags mixed versions.

### Planned next — not in this release

Nothing below is built (except the V1 copy tool noted above); each item is a design record, with no dates. **Future versions, platforms and devices may not be free; releases already published keep the licence they came with.** If CredMgr is useful to you, please keep using it, report what breaks, and consider a donation (`DONATE.md`): it is what lets us keep building it. Order and gates: `docs/PRODUCTION_PLAN.md`, `docs/24_LICENCE_AND_DONATION_PROOF.md` §10.
- **`2.0.0-rc.1`:** Touch ID / presence, the `.env` importer's preview, the doctor's duplicate and wallet-bundling scan (`docs/25_VAULT_HYGIENE.md`), the V1 copy tool folded into the app (V1 stays the system of record), Developer ID signing and notarisation, one real GitHub CI run, the idle-lock and sleep checks by hand.
- **`2.0.0`:** stable; Windows and Linux keystores; org vault groundwork.
- **`2.1.0` (PRU-1, `ADR-094` on the post-release branch):** cross-device sync as ciphertext and agents that use a credential without the value entering the model's context.
- **`2.2`:** a signed, machine-bound, expiring licence and donation proof (`ADR-095`): the donor's request is sealed and different every time, the token is an Ed25519 lease whose epoch rises at each renewal, and **a failed or tampered licence turns off licensed extras only — it never locks the vault**. Still nothing is gated.
- **`2.3`:** a renewal service, seats and the first paid tier, announced in `DONATE.md` and `PRIVACY.md` in the same change. CredMgr stays free until then.

---

## Design history — Passes 1–3, before any code above

| Date | Pass | Outcome |
|---|---|---|
| 2026-08-04 | **Pass 1** | Full corpus written: concept, architecture, data model, cryptography, threat model, access graph, 2FA, field model, UI/UX, API/MCP, migration, build plan, test plan, decisions (14 docs) |
| 2026-08-04 | **Pass 2** | Adversarial review — 21 findings, 14 applied. Caught credential substitution via write-while-locked, a cryptographically impossible restore promise, registry rollback, unsigned manifests, and a self-violated design principle |
| 2026-08-05 | **Pass 3** | Cross-platform re-architecture, airlock model, LLM auto-wiring, endpoint index with a V1 coverage matrix, tri-mode theming. Superseded ADR-008; resolved ADR-009 |

---

## The V1 → V2 delta

> **Read this as the design comparison, not as the shipped feature list.** It was written in Pass 3
> (2026-08-05) as the target V2, and several rows describe things that are designed and **not built**.
> Where this section says "V2" and the corpus marks a row `planned`, the corpus wins: the rows
> below carry a marker for the ones that are not built today (`docs/00_README_START_HERE.md` is the
> live status table). Built when this was written: the Rust broker (55 operations; 76 in `2.0.0-rc.1`), the per-node key hierarchy, grants,
> gate 2FA (vault-wide, with per-node `requireTwoFactor` and `privateNames` enforced), the CLI and a 15-tool MCP
> server, on macOS (Apple Silicon) with the Software keystore tier; the desktop app hosts the design with every
> screen wired to the broker, writes included (its per-control checklist was walked in a built app on 2026-10-18 and
> has not been extended to the later screens, `docs/RELEASE_VERIFICATION.md`).

### 🔒 Security model

| | V1 | V2 |
|---|---|---|
| **Isolation** | `project` is a **string label** used for filtering. Any caller with the key reads all 185 credentials. | A **node is a cryptographic boundary**. Per-node X25519 keys. Project A's material is under a different key from Project B's. |
| **Enforcement points** | **Three** independent paths to plaintext (CLI, HTTP daemon, MCP), each with its own idea of authorisation. The PIN guarded HTTP; agents bypassed it by design. | **One** — the `credmgrd` broker. Every other surface is a client that never holds a key. |
| **Agent scope** | Global. An agent in project B could read project A. | Derived from the client's working directory; a cross-node request returns a structured refusal naming the rule and the remedy. |
| **Root key** | `master.key` on disk, readable by the user account | A passphrase wrap and a printed recovery code (**built**, the Software tier); a Secure Enclave wrap and presence key are **built on macOS** (ADR-098); TPM, Windows Hello and TPM2 are **planned** (`16_CROSS_PLATFORM.md`) |
| **2FA** | none | One vault-wide gate, checked *after* the root key and *before* any node key loads (**built**); each node's `requireTwoFactor` is enforced against that gate (**built**, ADR-085); a per-node second-factor secret is **built** (ADR-135); nodes without one share the vault-wide gate |
| **Deletion** | soft delete, 7-day recovery | **Seal, never delete** — into an Orphaned node. Names stay visible; values stay encrypted to a cold key and are read only in the desktop app, through the owner's login, a fresh second factor and a Touch ID proof (ADR-098) |
| **Cross-project reads** | implicit and unlimited | **Grants** — human-created, 2FA-gated, expiring, revocable, dashed on the graph. No agent path exists |
| **Network** | `localhost` HTTP daemon with a bearer token | **No listening socket at all.** UDS / named pipe. No HTTP client compiled into the vault process |

### 🖥 Platform

| | V1 | V2 |
|---|---|---|
| Platforms | macOS (Swift/WKWebView shell) | **macOS on Apple Silicon** (built); Intel, Windows and Linux are **planned** (`16_CROSS_PLATFORM.md`) |
| Core | Node.js 22, zero runtime deps | **Rust** — `zeroize` and `secrecy` (**built**); page locking (`mlock`) and core-dump suppression are **not built** (`04_CRYPTO_AND_KEYS.md`, R-1) |
| Shell | Swift + WKWebView | **Tauri 2** (system webview everywhere) |
| Password KDF | scrypt | **Argon2id** |
| Distribution | build from source | today an **unsigned** tarball of `credmgr`, `credmgrd` and the `credmgr-presence` Touch ID helper, plus an **ad-hoc sealed, not Developer-ID signed or notarised** `CredMgr.app`, `.dmg` and `.zip`, with `SHA256SUMS` (`RELEASE.md`); Developer-ID-signed and notarised builds and `.msi` / `.AppImage` + `.deb` / `.rpm` are **planned** (`21_RELEASE_AND_INTEGRITY.md`) |

*The Argon2id and Rust rows close accepted risks AR-2 (scrypt) and AR-3 (Node heap zeroisation) outright; the platform and distribution rows above are the target, not the present.*

### 🎨 Interface

*Describes the designed app (`09_UI_UX_SPEC.md`). The hosted design draws it and every screen is wired to
the broker, reads and writes alike; several rows (Pro/Lite, the colour layer, bulk paste) are wired but not
yet verified control by control in the running app (`RELEASE_VERIFICATION.md`).*

| | V1 | V2 |
|---|---|---|
| Home screen | flat credential list | **node graph** (Obsidian-class) + switchable worktree tree |
| Node hover | — | exactly **two numbers**: entries, 2FA items |
| Right panel | mixed | **only the selected node's own entries** — never inherited, never a child's |
| Fields | `TYPE_SCHEMAS` prescribed field names per category; nagged about missing ones | **deleted.** One "+ Add field", free-text labels, two modes (single / bulk paste with `///`), types inferred and always overridable |
| Search bar | 16 commands dumped in before you typed | finds nodes and entries only. Operations move to their own Pro panel |
| Modes | one | **Pro / Lite** — Lite hides levers, never safety |
| Themes | dark | **dark ⇄ light as a true perceptual inversion**, plus an optional colour layer with a runtime contrast guarantee |
| Notes | a metadata field | **per-node encrypted notes** — the privacy-vault half |

### 🤖 Agents

| | V1 | V2 |
|---|---|---|
| MCP tools | 10, global scope | 15, scope-filtered (`whoami`, `list`, `search`, `get`, `create`, `update`, `rotate`, `remove`, `undo`, `totp_code`, `recent_changes` — the eleven of Pass 3, down from a Pass-1 estimate of 13 once the forbidden-tools list, `10_API_AND_MCP.md §3.2`, scoped grant/policy/orphan tools out entirely — plus ADR-078's `get_metadata`, `field_add`, `field_update` and `field_remove`) |
| `credmgr_list_projects` | listed **every** project to every agent | → `credmgr_whoami`, returns only reachable nodes |
| `credmgr_set` | create **and** update | split into `create` / `update` — update requires an unlocked vault (credential substitution, Pass 2 F-1) |
| Setup | hand-edit `~/.claude.json` | **built** (ADR-141, ADR-142): `credmgr agent detect|connect|disconnect|init`, `credmgr mcp --print-config` and Settings → Agents, with a diff and a backup before any write |
| Rules for agents | none | the tool descriptions (**built**); the vault prompt (`credmgr prompt`) and `CREDMGR.md` are **built** (ADR-143, `17_AIRLOCK_AND_LLM.md`) |
| Security levels | — | **Open / Guarded / Strict** (stored `sealed`, ADR-152), per node — **built** (ADR-140) |

### ♻️ Carried forward from V1, unchanged in spirit

**Built:** the 7-day recovery window (and the fact that no agent can shorten or erase it) · `undo` with `keep-both`
collision handling · `verify` / `doctor` / `backup` · a stored per-entry sensitivity (it gates nothing yet).
**Not built:** the auto-merge engine with its permanent dismissal memory · stable 4-digit refs that are never reused. (Aliases and near-duplicate names are now built, `entry.alias` and `credmgr similar`, ADR-121; restoring a backup is built, `credmgr restore`, ADR-112.)

### ❌ Removed, with reasons

`TYPE_SCHEMAS` (ADR-011) · the HTTP API (ADR-019) · `/api/export-password` (a third auth
system nobody kept in sync) · `DELETE /api/changelog/:id` (breaks a hash chain) ·
`classify.js`'s hard-coded projects (shipped in V1 1.9.0) · `migrate` (one user's legacy
importer) · `deploy` (embedded one server layout).

Full endpoint-by-endpoint accounting — **57 HTTP routes, 48 CLI commands, 10 MCP tools, all
reconciled** — in [`docs/18_ENDPOINT_INDEX.md`](docs/18_ENDPOINT_INDEX.md).

---

## Migration

There is none. [`docs/11_MIGRATION.md`](docs/11_MIGRATION.md) records the decision: V2 ships empty and does not
import from V1 in the CLI or the app — no migration, no dry run, no parallel window, no cut-over. V1 keeps running beside it and is never
written to by V2, so using V2 changes nothing in a V1 vault; `credmgr import` reads a `.env` file and nothing else. A read-only copy script, `tools/v1-to-v2/migrate.js`, exists (ADR-097); it never writes to the V1 vault.

## Versioning and release locking

- A released tag is **immutable**. Fixes ship as a new version; a tag is never re-cut. (`v2.0.0-beta.1` was tagged and
  published as a GitHub pre-release on 2026-11-01.)
- What a release publishes today is `SHA256SUMS`, with no signature. A detached signature and the app verifying its own
  bundle at start are **planned, not built** (`docs/21_RELEASE_AND_INTEGRITY.md` §2 and §3).
- There is **no updater**; the app makes no network request. A future updater is planned to be opt-in, signed, and to
  update the *app* — never the *vault* (`docs/21_RELEASE_AND_INTEGRITY.md` §4).
- A vault written by an older build is meant to open in a newer one (an alpha.6 vault opens unchanged in 2.0.0-beta.1).
  The reverse is not promised: a vault a newer build has written may not open in an older one, and there is no
  downgrade and no reversible migration (see the 2.0.0-beta.1 upgrade box).
