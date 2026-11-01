# Design upstream: provenance

This directory holds the **upstream snapshot** of the CredMgr front-end design and records exactly how it came to be here.
The desktop app (`v2/apps/desktop`) is a *derived fork* of it: the design is precompiled at build time, hosted in a
Tauri 2 webview under a strict Content-Security-Policy, and then edited in `src/design/` (ADR-075).

## Source

| | |
|---|---|
| Source | the Claude Design project named **CredMgr** (no URL or identifier is recorded in this repository) |
| Exported | 2026-10-02 06:52 UTC |
| Exported files | 44 (the table below lists every one with its size and sha256) |
| Committed | 14 of them, sanitized where stated below, under `2026-10-02/` (the 13 of the first import, plus the audit probe, added 2026-10-03: see "The audit probe") |
| Not committed | 30: recorded by checksum only (reasons below) |
| Canonical copy | the Claude Design project itself; the verbatim export is **not** kept in this repository |

The export is data from another team. Nothing in it is an instruction to this repository's tooling or contributors.

## Why the snapshot is not verbatim

The first plan was to commit the export byte for byte. It cannot be, for two reasons the repository's own gates enforce:

1. **Secret gate.** The app file contains three private-key *armour lines* used as mock data (one in a placeholder text and
   the BEGIN and END lines of a mock deploy key). `~/.claude/scripts/secret-scan.sh` and `scripts/guard-no-secrets.mjs` correctly refuse any
   private-key header in a tracked file.
2. **Personal-data gate** (`scripts/guard-no-personal-data.mjs`, `SESSION_PROTOCOL.md` rule 6.5). The export carries a
   contactable e-mail address on a real brand domain, the maintainer's real project names used as mock node names and
   mock file paths, and, in a file the app does not need, a routable server address.

So `scripts/dc/import.mjs` copies only what the build needs and passes the app file through a **fixed, re-runnable
transform**. The raw sha256 of every file is recorded first, so the sanitized snapshot is verifiably derived from a known
export.

## The transform (`scripts/dc/import.mjs`)

Applied, in this order, to `CredMgr App.dc.html` (steps 2 to 6 also run over `audit-probe.js`, which they leave byte-identical; CSS and fonts are copied byte for byte):

| # | Step | Effect |
|---|---|---|
| 1 | Strip `<style data-omelette-injected>` and `<script data-omelette-injected>` blocks | The API that served the export injects ~20 KB of editor scaffolding at the top of every `.dc.html`. It is a serving artefact, not part of the design. Line breaks are kept so line numbers do not move. Both the raw and the stripped sha256 are recorded below. |
| 2 | Private-key armour lines → `-----BEGIN EXAMPLE KEY-----` / `-----END EXAMPLE KEY-----` | Mock data only. No secret scanner reads the result as a key. |
| 3 | Contactable e-mail addresses on non-reserved domains → the same local part on `example.com` | The one in the export was the donation flow's billing address. The address belongs to the e-mailed donation-proof flow (ADR-082). |
| 4 | The design's licence sentence (free for personal use, a paid licence for organisational or commercial use) → `Released under the MIT licence.` | It contradicts the MIT `LICENSE` this repository ships; the committed snapshot must never state terms this project does not have. Found by the hosting verifier in the first snapshot. |
| 5 | (retired 2026-10-18) | The supporter code is no longer in the app file: the extras are an AES-GCM sealed pack (`extrasBlob()`), opened by a code that is not spelled anywhere in the tree. The importer no longer looks for `donateUnlockCodeVal()`. It fails if that name, or any 12-or-more-letter all-caps code constant, reappears in the app file. |
| 5b | IPv4 addresses outside the documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), loopback, unspecified, broadcast and link-local constants → `203.0.113.<same last octet>` (added 2026-10-30) | The public-export leak gate refuses any other address in a tracked file; mock data should not name a real network. |
| 6 | Real project names → neutral mock names (`atlas`, `beacon`, `cobalt`), including mock paths such as `~/projects/<name>` | The replacement table is **not stored in this repository**: writing it down would spell the names it exists to remove. It is supplied through `DC_SANITIZE_MAP` or `DC_SANITIZE_MAP_FILE` by whoever runs the import. This file records only how many tokens were replaced. |

**The importer fails closed.** It computes every output before writing any, and exits 1 with nothing written when no name map is supplied (unless `--no-name-map` is passed on purpose, which is then recorded in the summary below), when a supplied map replaces nothing in the app file, or when the export lacks an allowlisted file. The first version only printed a warning and exited 0, so an agent running it without the untracked map would have committed the real names into a repository that is about to become public: the later guards are structural and cannot see a project name. `tests/unit/import.test.ts` runs the script as a child process to prove each refusal.

Re-running `node scripts/dc/import.mjs <export-dir> --date 2026-10-02 --exported-at 2026-10-02T06:52Z` against the same
export reproduces the committed files byte for byte (checked when this snapshot was made, see the sha256 column
"sanitized" below). `scripts/dc/extract.mjs` then splits the sanitized app file into `2026-10-02/extracted/`:
`app.template.html`, `app.logic.js`, `app.helmet.css`, `app.props.json`. `extracted/` is the **three-way-merge base**:
`src/design/` started as a copy of it and is edited by hand from there on. When a newer upstream drop arrives, import and
extract it, then `git merge-file src/design/<file> <old extracted>/<file> <new extracted>/<file>` (`src/design/` is split
into `screens/` and `logic/`, so the template and the logic class are re-split by hand after a merge).

## What was committed, and what was only recorded

Committed (14): the app file (sanitized), `audit-probe.js` (see "The audit probe"), `assets/keep.css`, `assets/keep-components.css` and the ten `assets/fonts/*.woff2`
files (Inter 400/500/600/700, Inter Tight 600/700, JetBrains Mono 400/500/600/700; Fontsource builds of the latin subset, SIL Open
Font License 1.1). The licence texts are in `third_party/fonts/`, one per family, byte for byte the files the upstream projects
publish (not the Fontsource copies, which append the italic files' copyright lines):

| Family | Licence text | Copyright line | Upstream file |
|---|---|---|---|
| Inter | `third_party/fonts/OFL-Inter.txt` | Copyright (c) 2016 The Inter Project Authors (https://github.com/rsms/inter) | `LICENSE.txt` in `rsms/inter` |
| Inter Tight | `third_party/fonts/OFL-InterTight.txt` | Copyright 2022 The Inter Project Authors (https://github.com/rsms/inter-tight) | `ofl/intertight/OFL.txt` in `google/fonts` |
| JetBrains Mono | `third_party/fonts/OFL-JetBrainsMono.txt` | Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono) | `OFL.txt` in `JetBrains/JetBrainsMono` |

The OFL requires the licence text and copyright notice to travel with the font files. They travel with the source tree here.
Two follow-ups remain for the release work: the built app's About → Licences text does not yet name the bundled fonts, and the
texts are not yet copied into the `.app` bundle itself.

Recorded by checksum only (30):

* `support.js`, `image-slot.js`, `doc-page.js`: the design runtime and helpers. They carry no licence grant for
  redistribution in an MIT repository and are **not needed**: the app is precompiled and the runtime is replaced by
  `src/dc/runtime.ts`, a clean-room implementation of the documented contract (state, `setState`, lifecycle,
  `renderVals`).
* `audit-suite.js`, `harness.dc.html`: the design side's other development tools. Not redistributed, and no gate runs them
  (`audit-suite.js` is explained under "Gates"). The third tool, `audit-probe.js`, IS committed: see "The audit probe".
* `assets/force-graph.min.js` and `assets/keep-doc.css`: used by the design's documentation pages, not by the app (the app's
  graph is a hand-written canvas).
* The Manual, the Index, the four KEEP pages, the working notes (`*.md`), `github.md`, and the screenshots: not needed by
  the build; several carry forbidden data (for example the server address mentioned above in one KEEP page).

## Deliberate differences from the upstream runtime

| Area | Upstream | Here | Why |
|---|---|---|---|
| React | 18.3.1 UMD from a CDN, with Babel | React 19.3.0 from npm, bundled by Vite | strict CSP: no remote origin, no eval. While it existed, the parity gate (retired, see "Gates" below) rendered the same DOM in 52 states under both, in WebKit and Chromium, so React 19 stays (decision D9). |
| Template | parsed in the browser (`innerHTML` + a DOM walk) | compiled at build time to `React.createElement` calls (`scripts/dc/compile.mjs`) | no runtime parsing, no `new Function` |
| Logic class | evaluated with `new Function` | an ES module | no eval |
| `style-hover` | a `<style>` element built at runtime | a generated CSS rule | inline styles are blocked by `style-src 'self'` |
| `componentDidUpdate` | the host passes only the previous props | `src/dc/runtime.ts` also passes the **previous logic state** | the design's "a dialog just opened" check reads `prevState`; with `undefined` it re-ran its focus-first-field routine on every re-render while a dialog was open (decision D7; confirmation below) |
| Debug handle `window.__cm` | always present | present only in `--mode test` builds (with `usageSet` and `packLoad`, which are also absent from the release code) | a global handle onto app state does not ship |

### D7: the upstream `componentDidUpdate` defect (confirmed)

Measured 2026-10-02 with the parity gate's "D7 focus probe" (retired with the gate; `scripts/verify-csp.mjs` keeps the same assertion), in WebKit and in Chromium, against the
sanitized snapshot running under the upstream loader: open **New entry**, click the *name* field, type `abc` slowly.

| | focus after typing | text in the name field |
|---|---|---|
| upstream host (`componentDidUpdate(prevProps)`) | jumps to the first control of the dialog (the *where* `<select>`) after the first keystroke | `a` |
| this repository's host (`componentDidUpdate(prevProps, prevState)`) | stays in the name field | `abc` |

Cause: the design's own `componentDidUpdate(prevProps, prevState)` decides "a dialog just opened" from `prevState`; the
upstream host never passes it, so the answer is always "yes" and `focusModalFirst()` runs 30 ms after every re-render
while a dialog is open. `src/dc/runtime.ts` passes the real previous logic state. The same assertion runs in
`scripts/verify-csp.mjs` on every build (no export needed), so the fix cannot regress unnoticed.

## Deliberate changes to the design itself (not parity)

Made after the snapshot, in `src/design/`. While the parity gate existed it listed every screen they touch (`EXPECTED_CHANGES`, one reason
each; the reasons are in git history). All follow decisions recorded in the build log.

* The App icon choice (X9) is wired: `setCosm({icon})` and every unlock call the shell's `app_icon_set` (`src/design/logic/extras.js` `applyAppIcon`, `vault/actions/admin.ts` `setAppIcon`); the design's `not in beta.1` badge on that group is removed (2026-10-19).
* The donation toast and the supporter code are kept as the design has them (owner decision 2026-10-18, ADR-082, which
  supersedes the earlier removal). Cosmetic extras only; nothing functional is gated. The ask follows entry milestones (50 entries and 14 days, 150 and 45, 300 and 90; at most three; "don't remind me" turns it off) and the extras are an AES-GCM sealed pack inside the app that the code opens once (owner decision 2026-10-18, ADR-082 amended). **Status: merged** from the design drop of 2026-10-18 (`2026-10-18/`), see "Merged 2026-10-18" below. They live in `src/design/logic/extras.js`; the pack in the app is the design's own blob, untouched; a TEST build opens a stand-in pack sealed under a test-only code (`tests/fixtures/extras/seal-test-pack.mjs`) and a release build contains neither the stand-in nor the test hooks (`scripts/dc/release-bans.mjs`).
* About → Licences states the MIT licence (pointer to `LICENSE` and `TRADEMARKS.md`). About shows the real version
  (2.0.0-beta.1) and no supporter chip; its privacy text says what is true: no server, no telemetry, and a window content
  policy that refuses every network request (`cargo tree` over `src-tauri` links no HTTP client, only the `http` types crate).
* Removed from the UI for 2.0.0-beta.1 (no backing feature): the Agents / LLM section, the machine lock, the duress
  code, security levels, content search, `--age` export, "Destroy orphans", and the Operations rows for merge, re-key,
  export, import and purge.
* The field model (ADR-078), after the first wiring had removed what it could not back: Entry detail draws its fields from `entry.get`
  (ids, labels, types, masking; no value) with a per-field ⋮ menu (Edit…, Move up, Move down, Remove…), `+ Add field`, reveal and copy
  per field, a code per TOTP-seed field, and the fields that are not masked shown from one audited `entry.reveal`; the design's disabled
  `field menu` and `+ Add field · mock` are replaced by these controls (`screens/S4-inspector.html`, `screens/dlg-field.html`,
  `logic/inspector.js`, `logic/fields.js`). Add entry previews through the shell's `fields_preview` instead of the design's own `parseBulk`
  and `inferType` (both deleted: they disagreed with the Rust parser in three places), saves one multi-field entry per paste or, with the
  design's "split each /// segment" toggle, one per segment, offers a per-field type pin and an entry-type pin, and "+ New note" creates an
  entry of type `note`. The design's "looks sensitive" hint is gone with its inference.
* Settings and administration (package D): grants are listed and revoked from the broker (creating one is sent for real and the
  broker's `presence_required` is shown; the dialog has no `list` capability, no expiry and no 2FA code field, because the
  broker takes none); Verify, Doctor, Back up and Rotate root key end in the broker (the rotation, a registry rebuild,
  `grant.create` and `audit.get` need presence and say so); the passphrase prompt reads its inputs at the moment of the call and
  keeps nothing in the logic's state; the new recovery code is shown once, and its dialog ignores Esc until the code is
  acknowledged (the old code is already dead); the audit list is `audit.tail`; settings persist in `credmgr_prefs`; About reads
  its version from the shell and copies a donation address with the shell's `copy_text` (never the page's clipboard, never
  `entry_copy`); Privacy lists the storage keys; the presence notice dialog has no Touch ID button; Help's glyph legend matches what the rail draws; Lite mode keeps Grants reachable (revoking is safety).
* Graph positions and other local-storage keys are hashed (no node or entry id or name in clear in WebKit storage);
  `tests/unit/pstore.test.ts` fails if a key or a value ever carries an id.
* The lock screen no longer says "any 6 digits unlock this mock" / "any value unlocks this mock": both steps are wired to
  the broker (`lock2`, `lock3` in `EXPECTED_CHANGES`). Three screens are new and render nothing in any state the upstream has:
  `screens/boot.html` (the blank "starting" screen and the broker-down screen with Retry) and `screens/notice.html` (the
  global notice), plus the error panel the host's boundary draws.
* All vault data is read through `src/vault/` (the model); `mock-vault.js` is gone. The design's in-memory demo vault lives
  on as `src/vault/demo-source.ts`, rewritten with invented, documentation-range data and kept for development and test builds ONLY
  (`vite dev`, vitest, `build-test/`); a release build contains neither it nor the fixture broker (`scripts/dc/release-bans.mjs`), and
  with no Tauri shell answers "broker unreachable".
* `2026-10-02/CredMgr App.dc.html` and `2026-10-02/extracted/` are the **merge base** and stay as the upstream made them
  (apart from the sanitizing above, which now also removes the paid-licence sentence and the unlock code's value): they still
  contain the donation toast and the other things listed here. Only `src/design/` carries the changes. Do not "fix" the
  snapshot by hand; the next merge needs it as it was, and the importer reproduces it.

## Merged 2026-10-18 (what the three-way merge kept, took and changed)

Base `2026-10-02/extracted/`, theirs `2026-10-18/extracted/`, ours `src/design/` (template flattened with `compile.mjs --flatten`, merged with `git merge-file`, 37 conflicts, re-split along the old screen boundaries; the logic delta applied by hand into the mixins; the helmet CSS merged with `git merge-file` without conflict).

* **Taken from the design:** the milestone toast (three views, label, "don't remind me", steps aside from focus), the sealed pack and the code prompt, the S12a regroup (Graph, Identity, Motion, Games) with its live preview canvas, the free Milestones panel (S12b), the header badge (none, ring, stamp), the unlock flourish, CredPong node shapes and trail, node shapes in the worktree, the CredGames library, single-key shortcuts off (`credmgr_keys`), mixed-script warnings on node and entry names, the 24 px target sizes, the renamed screen labels (`S12 Settings`, `S21 Help`, `S19 CredGames`, `S1a Empty vault`, new `S23`/`S24`/`S25`/`S5b`/`S13`), the commercial-licence sentence in About (it matches `LICENSE`, `README.md` and `DONATE.md`: MIT for everyone, an optional paid licence for invoices and support).
* **Kept from `main` (the design cannot know it):** every broker-wired control, the sanitiser, hashed positions, `fields_preview` for Add entry, `copy_text` for the donation address, the shell's `entry_copy` for values, the first-run and second-factor skip options (ADR-081), tray and close-to-hide, the four-character passphrase floor, the Lock screen as the only locked state, Escape closing every open layer at once (the design's "close only the topmost" is not adopted; `ui-fix.spec.ts` pins the current behaviour).
* **Changed from the design, on purpose:**
  1. The CredGames host reads a module-level list (`BUNDLED_GAMES`, empty) and never `window.CredGames`: the production policy lets no script into the page, so a global list would only be a way for code already in the page to feed the games host.
  2. The unlock flourish, the day count and the ask's timer start only from a successful unlock (`unlockApp({unlocked:true})`: passphrase, second factor, recovery, first run). Opening onto a login that already exists, or a window coming back into view, does none of them. The reminder never survives a lock (`freshEphemeral`).
  3. `window.__cm.usageSet` and `window.__cm.packLoad` exist only in `--mode test` builds (a build-time constant; both names are release-banned). `marksSync` is an ordinary method: it is how the free Milestones list records the day a milestone was first reached.
  4. The pack is cleaned after decryption (`packClean`: numbers clamped, unknown keys and values dropped), and a code is normalised by removing all white space and upper-casing, so a code pasted with spaces or in lower case works.
  5. The reminder's third step still reads `billing@example.com`: the importer replaced the design's real address (transform 3) and the real one does not belong in the repository. **Owner action before a release:** decide how the donation-proof address reaches the build (the app makes no request, the donor mails it from their own client).
  6. About → Donate no longer says the extras are "free for everyone": they open with a supporter code; nothing functional is locked.
  7. The CredPong shapes, trail and the worktree bullet draw inside the existing radius; graph physics, node radius, ring spacing, `credmgr_gposV` and CredPong balance are untouched.
* **Not in this merge:** the app-icon setter (`app.icon.set`): the picker is there as the design draws it, preview only, with the dashed "not in beta.1" pill that names the op (the one pill `no-mock-badges.spec.ts` allows); `privateNames` (ADR-083) and `canonical_name` (ADR-084) are broker work.

## Drop 2026-10-18 (sealed extras, milestone ask)

What changes for the importer and the gates when this drop is imported into `2026-10-18/`:

* **Sealed pack.** `extrasBlob()` holds about 650 characters of base64 (salt, IV and AES-GCM ciphertext, PBKDF2-SHA-256 at 200 000 rounds). It is ciphertext only and holds data tables (shape geometry, colour and backdrop tables), never code. The secret scanners (`scripts/guard-no-secrets.mjs`, `~/.claude/scripts/secret-scan.sh`) may flag it as high-entropy: allow-list that one line.
* **Transform step 5 is retired** (see the table). `scripts/dc/import.mjs` and `tests/unit/import.test.ts` must accept zero unlock-code values; the generated summary reads "0 unlock-code value(s)".
* **New local-storage keys**: `credmgr_donate_unlocked`, `credmgr_extras_key`, `credmgr_usage`, `credmgr_keys` (a key of its own, not inside `credmgr_prefs`), and more fields in `credmgr_cosmetics`. All four are in `DOCUMENTED` in `tests/unit/pstore.test.ts`, which also proves no value carries a node or entry id. Values are dates, flags, option names and one derived key: never an id or a name.
* **Web Crypto.** The window needs a secure context for `crypto.subtle`; the Tauri origin is one. With none, entering a code shows "This window can't open the extras: it has no secure context." and nothing is stored. `scripts/verify-csp.mjs` asserts `crypto.subtle` (and `isSecureContext`) at start-up in WebKit and Chromium and has a canary that removes it. **Not verified here:** that the real macOS WKWebView treats the `tauri://` origin as a secure context; check it in the built app (`window.isSecureContext`).
* **Dev handle.** `window.__cm.usageSet({days, entries, reset})` drives the milestone ask; `__cm.packLoad(code)` opens the pack for a session without storing anything. Both exist only in `--mode test` builds, like the rest of `__cm`, and are release-banned by name.
* **Merge.** The 2026-10-02 snapshot stays as the upstream made it. Import the new export into `2026-10-18/`, extract, then `git merge-file` each of `src/design/` against the old and new `extracted/` files as described above.

**Follow-up drop 2026-10-24** (`design-upstream/2026-10-24/`, 14 of 57 files, same importer, `--no-name-map`): the design side re-sealed `extrasBlob()` under a fresh code (new salt, IV and ciphertext; 200 000 rounds and the data-only plaintext unchanged) and removed the `not in beta.1` badge from the App icon group (the caption now names `app_icon_set`). Those two lines are the whole difference from 2026-10-18 in the app file; `audit-probe.js` and the assets are byte-identical. Merged into `src/design/logic/extras.js` (`REAL_BLOB` and the caption). Checked 2026-10-24 with a throwaway script (not kept): the release bundle holds exactly one pack, the old public code no longer opens it, the new owner code does, and the plaintext is data only (keys `v, shapes, global, link, dots, backdrop`; no code-like content). The new code is held by the owner and is in no file.

**Follow-up drop 2026-10-25** (`design-upstream/2026-10-25/`, 14 of 63 files, same importer, `--no-name-map`; the export's `assets/` folder is the one in `2026-10-24/assets`, byte-identical): the design side wired its mock to the new broker answers of 2.0.0-beta.2 (ADR-083...089). Against 2026-10-24 the app file differs by 51 template lines and 34 logic lines; the helmet CSS is unchanged and `audit-probe.js` is byte-identical (its digest above still holds). New in the design: Undo after Add / Edit / Remove field (D10), Generate in Add field (D11), the second-factor dialog S5c and the inspector's second-factor chip (D12), the locked-approval panel S16a (D13), the `name hidden` chip and the node dialog's privateNames choice, and the Doctor result "doctor · purge expired seals". `extrasBlob()` is the 2026-10-24 re-sealed pack, unchanged.

## Merged 2026-10-25 (what the three-way merge kept, took and changed)

Base `2026-10-24/extracted/`, theirs `2026-10-25/extracted/`, ours `src/design/` (template flattened with `compile.mjs --flatten`, merged with `git merge-file`, 5 conflicts, resolved by hand and re-split along the old screen boundaries; the logic delta applied by hand into the mixins, as before). `compile.mjs --check` passes; the binding count went from 556 to 602.

| Control | What the design's mock did | What the window does now |
|---|---|---|
| D10 Undo | restored its own copy of the fields | `entry.undo {node, id, generation}` with the audit record of the change (read back from `audit.tail`: the shell hands the page only the answer's value), the node's current generation, and the words of the broker's reply |
| D11 Generate | a JavaScript generator in the page | `util.generate {length, symbols, pronounceable}`: the value is made in the broker, shown masked with the broker's entropy, never copied, and enters the entry only through `field.add` |
| D12 second factor | a local "code holds until the vault locks" flag | a read-path `two_factor_required` opens S5c with the refused call; the code goes as `vault.gate_verify` (the step-up, five minutes) and the call is repeated once; level `always` also shows an "unreadable" inspector with "Give second factor" |
| D13 approval while locked | a canned request, any passphrase | `vault.approval_decide {request, approved, passphrase, code?}`; the panel asks for the request id because `vault.approval_get` does not exist; the vault stays locked |
| privateNames | a mock flag | the owner's snapshot row carries `nameHidden`; the node dialog sends `node.policy {privateNames:true}` in the narrowing call |
| Doctor | a canned title and one fix line | the dry run sends `purgeExpiredSeals:true`; the fixes list `would-purge-expired-seal` / `purged-expired-seal` with the node and when it was sealed |

Changed on purpose, relative to the design's template: S16a gets a request-id field and a link on the Lock screen's passphrase step (the mock always showed it); S5c gets an inline error line and says "five minutes" where the mock said "until the vault locks"; the `insp2fa` "not enforced" chip and every "recorded, not enforced" caption are gone (the broker enforces the policy now); the inspector's unreadable panel gets "Give second factor"; the Add field row keeps its `fieldsEditable` gate. Kept from main: every broker-wired control, the sanitiser, hashed pstore keys, ADR-081/082, the extras pack.

## Changed in the window after the 2026-10-25 merge (2026-10-26, ADR-090 / ADR-091)

No new design drop: these are edits to `src/design/` (the derived fork) that serve the backend's follow-ups. The upstream snapshot under `2026-10-25/` is untouched.

| Where | Change |
|---|---|
| S16 Lock screen, S16a panel | the link says how many agent requests are waiting; the panel lists them (names from `vault.approval_get`, the node's id when its name is private) and the request-id field returns only when nothing is listed. Five new bindings (`aprLinkText`, `aprIntro`, `aprListShow`/`aprManualShow`/`aprWaiting`) |
| S5c dialog (`dlg-field.html`) | title, caption, intro, note and button label are bindings (`tfTitle`, `tfSub`, `tfIntro`, `tfNote`, `tfVerifyLabel`): the dialog says "Give the second factor" when the owner opens it from the node's chip, and keeps its old words for a refused call |
| S4 inspector | the node's "second factor required" chip is a button (`inspTfGive`) |
| Help legend | says the chip protects the node against agents and other callers and that the owner is past it |
| S8 add node | for a node whose name is private the id note says the id is chosen at random (no new binding) |

The compiler reports 612 bindings (602 before).

**Follow-up drop 2026-10-26** (`design-upstream/2026-10-26/`, 2 of the project's files imported plus the unchanged `assets/` of `2026-10-25`, same importer, `--no-name-map`; the importer's generated block was not allowed to overwrite the 63-file table above, so the table is kept as it was and only row 51 changed): the design side's batch B20, an answer to `BACKEND_ANSWERS_2026-10-26.md`. Raw `CredMgr App.dc.html` 332580 bytes, sha256 `278eb55081f53d42929b175e5378fde91c93bf370297500a0d9b7799bb670613`; `audit-probe.js` 11381 bytes, sha256 `83c5548cbcd85ad638e335e2934cbaf0419483d3bf0f47459d1fe7245234c69b` (byte-identical after the sanitiser). The sanitiser replaced 2 contactable addresses with `example.com` ones (as in the previous drops) and, with a step added on 2026-10-30 (see the transform: an IPv4 address outside the documentation, loopback and link-local constants becomes `203.0.113.<last octet>`), 1 mock server host (an RFC 1918 address, which the public-export leak gate refuses; it was also in the 2026-10-25 snapshot, which that gate does not scan once a newer one exists); no armour line, licence sentence, unlock code or project name. The committed app file therefore differs from the raw one in 3 places. Against 2026-10-25 the app file differs by 13 template hunks, 27 logic hunks and one helmet-CSS line; `props` unchanged. The design project's file listing was checked on 2026-10-30: nothing newer than this drop.

## Merged 2026-10-26 (B20; what the three-way merge kept, took and changed)

Base `2026-10-25/extracted/`, theirs `2026-10-26/extracted/`, ours `src/design/`. Most of the logic delta is the design's own mock (its fake approval list, its local second-factor flag, its local Undo and Generate), which the window already does against the real broker, so it was not taken. Taken: the template and wording, and the bindings they need.

| Item | What the design drew | What the window does now |
|---|---|---|
| S5c second factor | "Give second factor", a 5-minute window for agents and other callers, whole vault, 300 s, ended by a lock or a policy change; your own reveal never opens it | the dialog's give-mode words are the design's; the refused-call words are unchanged. A step-up with no gate enrolled answers `malformed_request` (B-11), shown as "No second factor is enrolled, so there is nothing to give." |
| Inspector chips | a static "2fa · on reveal" chip, a "Give second factor" button while no window is open, a countdown chip while one is | the same three, with `tfUntil` from the answer's `expiresIn`; the countdown is advisory (the broker decides) and ends on a lock or when this window creates a node with a policy |
| S16a locked approval | list of waiting requests, an always-visible request-id field, factors after a pick, error cases | kept our radio list and the Lock screen's rules (a pick is never changed under the person), added the count in the header, the always-visible id field ("Not listed? ..."), the factors only after a request is chosen, and the back-off line. Deny is **not** allowed without the passphrase and code while locked (B-10) |
| Mixed-script name notice | the live notice in Add entry / Add node is gone; the notice comes from the answer's `warnings` after saving | live notices and the window's own script test removed; the saved notice (ADR-091) stays |
| Doctor | plain Doctor purges nothing; a separate "Doctor with purge" row sends `purgeExpiredSeals` and is labelled irreversible | the plain Doctor sent `purgeExpiredSeals:true` before (a defect against B-7): now a plain run sends no purge flag; the new row ("Preview purge") does a dry run that lists the seals, and its Apply keeps the flag |
| Smaller | Undo one step (`conflict`, 7 days), Generate alphabet, private-node wording, labels | already how the broker answers; the wording on the Undo button, the Add node labels and the chip titles taken |

Not taken: the helmet CSS line `input,textarea,select{... border:1px solid var(--faint)}` to `var(--mute)` (a contrast change; the owner's decision, left as it was); the design's Security-level row (our Settings has no such row); the design's `entryWarn` banner (ours already says the broker's `warnings` in the save notice); the design's dev-only `audit-suite.js` (not committed, as before).

## The audit probe

`audit-probe.js` is the design team's in-page audit (dead controls, controls with no accessible name, clipped text, squashed
controls, text under WCAG contrast). `npm run test:design` runs it. It used to be read from a local copy of the export
(`DESIGN_EXPORT_DIR`) and the gate **skipped, exiting 0, when there was none**: on a fresh clone, and in any session without
the export, the design gate silently never ran, which is a gate that has not passed. So since 2026-10-03:

* `scripts/dc/import.mjs` has the probe on its allowlist and passes it through the same sanitizer as the app file. The
  sanitizer found nothing to change, so the committed `2026-10-02/audit-probe.js` is byte-identical to the raw download
  (raw sha256 `68d5e73a5dda81eb653b6c0eca9ea45311ee7492f7d84670e23c6a25468a4b91`, 7434 bytes; the row in "Files in the export" says
  the same). It was added by running the importer over the 2026-10-02 export into a scratch root and copying that one file: the
  other thirteen were not re-imported, because that needs the project-name map, which is deliberately not in this repository.
  Re-running the full import (with the map) reproduces every committed file and this one.
* `scripts/verify-design-audit.mjs` reads **only** that committed file, and checks its sha256 against the "committed" digest recorded
  in this document before it runs. It exits non-zero, saying what is missing, when the probe, this record, the digest or `build-test/`
  is absent, or when the digest does not match; it has no skip path. `tests/unit/design-audit.test.ts` proves each refusal.
* The file carries no licence statement of its own. It is the design side's tool for this project's own design, and it was
  committed as part of the iteration-3 front-end fixes (2026-10-03). Whether redistributing this one file in an MIT repository is
  intended is the maintainer's call, recorded here as such; the runtime files (`support.js`, `image-slot.js`, `doc-page.js`) stay
  out because the app does not need them, not because the probe is different in kind.
* **Public tree (decided 2026-10-17, the safe default while the licence question is open).** The file stays in the private repository and
  is on the public export's denylist (`tools/public-export/manifest/denylist.txt`), so the published tree does not carry it. There,
  `npm run test:design` is a **development-only gate**: it finds the `.public-export` marker, prints `NOT RUN` with the reason and exits 0,
  unless `DESIGN_EXPORT_DIR` names a directory holding the design team's `audit-probe.js`, in which case the same digest check above
  applies and the audit runs. A `DESIGN_EXPORT_DIR` that is set and wrong is an error. The private repository has no marker, so its gate is
  unchanged and still never skips. If the maintainer later grants a licence, remove the denylist line and nothing else changes.

## Gates

| Gate | Needs the export | What it proves now |
|---|---|---|
| `npm run test:design` | no (the probe is committed; see "The audit probe") | the design team's own audit over every state in `scripts/states.mjs`, in WebKit and in Chromium, against the **wired** app with the fixture broker (`tests/fixtures/broker`) answering in place of the Tauri shell: 0 dead, 0 unlabelled, 0 clipped, 0 squashed, 0 low-contrast; canary elements prove the probe can fail; it never skips |

**Retired: `npm run test:parity` (2026-10-02, ui-integ).** It compared the hosted app's DOM with the upstream mock runtime's, in 52
states, and pinned every deliberately changed state to a fingerprint (`scripts/parity-fingerprints.json`). Both sides of that
comparison ran on the design's in-memory mock vault. Once every screen reads from the broker the two legitimately differ in all
of them (names, counts, notes, the orphaned row), so the gate can no longer say anything true, and it was removed together with
its fingerprints and `scripts/verify-parity.mjs`. What it protected survives elsewhere: the compile step is checked by
`tests/unit/compile.test.ts`, every name the template reads exists in `renderVals()` in each state by `tests/unit/logic.test.ts`,
the focus behaviour of D7 by `scripts/verify-csp.mjs`, and every screen rendering from broker-shaped data by
`tests/e2e/screens.spec.ts`. The record of the last passing run (hosting time: 52 states, 29 identical to the upstream, 23
deliberately different, in both engines) is in git history before this change. Do not resurrect the gate: a comparison with the
upstream is only meaningful for a new design drop, and then it is a three-way merge (`git merge-file`), not a render comparison.

The design team's `audit-suite.js` is **not** run: its behaviour assertions drive the donation toast, the supporter code and
the Destroy dialog (all removed) and mutate the mock vault (which the wiring replaces), and its visual checks are the
ones `audit-probe.js` already performs. If the design side ships a newer suite, run it by hand against `build-test/`.

## Files in the export

<!-- BEGIN generated:files -->
Imported 14 of 63 files; export time 2026-10-24T17:30Z. Sanitized: 0 private-key armour string(s), 2 contactable e-mail address(es), 0 licence sentence(s), 0 unlock-code value(s), 0 project-name token(s) (NO name map was used: --no-name-map).

| # | file (relative to the export) | bytes | sha256 of the raw download | disposition |
|---|---|---:|---|---|
| 1 | `ACCESSIBILITY.md` | 11108 | `a2c79f22b7f2b5f058ded2e4a96428c0606bcf6ed2f41322b212f4bd8bbdd402` | checksum only |
| 2 | `AUDIT_2026-10-18.md` | 5181 | `963cbe13b7176ad02bc2c7d164df0bbf81815a4649448c995e933bdee1cfbfde` | checksum only |
| 3 | `BACKEND_HANDOFF_NOTES.md` | 18769 | `2d1370313994302e92d88f99e6c285c81c80c151cf89acd21327688813462bb9` | checksum only |
| 4 | `BACKEND_NOTE_2026-10-24_extras_code.md` | 844 | `5ca843308f9425274e87339f475c096eddf35e6cad7cc368f2d5c383a428a7a7` | checksum only |
| 5 | `BACKEND_PROMPT_REPO_UPDATES_2026-10-24.md` | 2985 | `30771bfcfd4b53852183b42b498a59c7f1d770a50717f7369e2be6c301cec820` | checksum only |
| 6 | `BACKEND_STATUS_PROMPT.md` | 2618 | `e8820825a3c041f7ef0466237b2a49ad03ce9af54448e49329af7fda606bf16e` | checksum only |
| 7 | `BACKEND_STATUS_REPLY_2026-10-24.md` | 1087 | `aded380b3f8ed1f93bd507eb47c8b923215a3745f62b28970682c5ad6db032de` | checksum only |
| 8 | `BACKEND_STATUS_REPLY_2026-10-24b.md` | 1166 | `a329fc3fae75614d8e0afa24e23b0bd5ec2e2fd4874a13103e9a7c833cedf74d` | checksum only |
| 9 | `BACKEND_TEAM_PROMPT.md` | 10080 | `939166ebd7901f46faaa89ecd0ec4ca0ba76f60b8127166b2d211e6252edcdaf` | checksum only |
| 10 | `BACKEND_TEAM_PROMPT_2026-10-18.md` | 14821 | `4bcc3667e83be46bb1f2d9ada926929cda787dd6491d7336aa5e61346e68041b` | checksum only |
| 11 | `BACKEND_TEAM_SCRIPT.md` | 13243 | `64c03f5e6a7a0afd75e8a83cdba34ac47575f0491139ab70369f772f37ca0e6b` | checksum only |
| 12 | `CLAUDE.md` | 9370 | `b091894bd6ca302816a791d4c0e8a51acf89e752520ddf1db3758a3e5fce5fd1` | checksum only |
| 13 | `Contrast Preview.dc.html` | 25251 | `f4187ecef876c1ce086a13c34d71f758f02582a103b3cd4c7712ab80ed637538` | checksum only |
| 14 | `CredMgr App.dc.html` | 324442 | `e0dd54e127dae274f0aa541055d71924bade8552106d60769aa81c3b11d4f2b0` | **committed**; stripped 2 injected blocks -> `4407af1356cc3769d0e8da86af651b17b10c9b8ff41ae8be120074b78f00f485`; sanitized -> `1646e183f7c56bf79574ab099d2f38d6d13ffbcb734f709d5d6a4996e68a39c8` (304187 B) |
| 15 | `CredMgr Manual.dc.html` | 41255 | `243430d0ac14e41251967e029800d25c6900faf1cd8dfdb1bcf59ca6dd8cb1be` | checksum only |
| 16 | `DECISIONS_REGISTER.md` | 5879 | `570ce1526276f8dfe496bf60eda0037fee05d4d6cb50013187eb74d922d1b5fa` | checksum only |
| 17 | `DEVIATIONS.md` | 2138 | `1851f6bb1e3a79eefc38869d26c8f0c62110af733e8cba2283bf8f9989917970` | checksum only |
| 18 | `ENDPOINT_MAP.md` | 9940 | `0733ea7f6dbc68a3fa53a2444faf90fa28ee8a62e6bcc028f7f96830b17fb6c0` | checksum only |
| 19 | `FRONTEND_THREAT_MODEL.md` | 7920 | `f3b5b0b597bac581561d6955b07d2fd50deb119b836974914c3ed7a60283ad32` | checksum only |
| 20 | `GAMES.md` | 4333 | `25d8508d488446e3656f6d1406cd5b9166472e66589bde1500b9921a58267c7b` | checksum only |
| 21 | `Index.dc.html` | 29682 | `5c9cb111ac6d2fe404f7915e0a4c6f61a361ce9a414b5671c5fc5bfdf8828386` | checksum only |
| 22 | `KEEP Blueprints.dc.html` | 43461 | `8131a3831f9cac399640cc4941726e80a813a096f501e8a0920943f07c3f23ff` | checksum only |
| 23 | `KEEP Component Sheet.dc.html` | 49675 | `1cbffee72f5d5c55d5005a91efcb0a23e8ed4b680bb9c26eea50f19afe02138f` | checksum only |
| 24 | `KEEP Design System.dc.html` | 64776 | `cbc2bf4f3569f4271fa0ac83550eb00de40325328014edfcb7810286dcf5cf1a` | checksum only |
| 25 | `KEEP Identity.dc.html` | 39521 | `bd856ae5f87377595ef5832d9666bfd86cb194dc767fb95d98ab626b23a7c005` | checksum only |
| 26 | `KEEP_UPSTREAM_NOTES.md` | 3328 | `97fd42f6e12e91a3f594b02be9d1067dba17f17d05f286f941f6e03bdd9762ad` | checksum only |
| 27 | `LEGAL_REGISTER.md` | 5606 | `8dff09884f79089339a44f2379295e8464746be6ec90094b8d7e586bcbb7b8ee` | checksum only |
| 28 | `NEXT_SESSION.md` | 1926 | `9fcf9c94c9b16a65deea2d65c9179806faa8ec7a958fc542014c22ed14718d87` | checksum only |
| 29 | `NEXT_SESSION_2026-10-24.md` | 3524 | `30830377ba42d89a3bed9c2a542f03cf05481f72c79e54309779807bd06e1982` | checksum only |
| 30 | `NEXT_SESSION_PROMPT.md` | 2049 | `7490a658b19c07fa4f6c1ccd22e67e6b87c7097ac4b0bf5fb12bf19b4fbb3a9b` | checksum only |
| 31 | `RELEASE_PLAN.md` | 39880 | `9e9f6378e3540be365182c04b435b5bc9dd3bf6ebf278f06e68fc5659c6c0256` | checksum only |
| 32 | `REPO_UPDATES.md` | 1884 | `6a8ba4f5ca38c98b7cc047c7a66676b25cca64580739ebc30b832d6e8049a7b0` | checksum only |
| 33 | `SCREENS.md` | 2817 | `825af9e7674e193e814e312e318ab4f95d2d80b8cd23eec8e9cd51a4085644cf` | checksum only |
| 34 | `SHIP_MANIFEST.md` | 3130 | `36e14e3944d555559887fcbb1027acb8cb035d18c985fd212ff251f4812e0844` | checksum only |
| 35 | `SKILL.md` | 1103 | `9103af1ceb06e791186938bd58088c4fb0c4159d7172eef74c4807977c633bae` | checksum only |
| 36 | `SUPPORTER_EXTRAS_PLAN.md` | 20807 | `a46a84bbbc7194ea1747166c9f560d793d3254ed832c1193a13ef4cddf27f258` | checksum only |
| 37 | `THIRD_PARTY.md` | 1895 | `b71128bcacbc9a3033709f0b8dc5e1eaea61acdfae083954434f8f7ff498a39b` | checksum only |
| 38 | `VERIFIED.md` | 19047 | `2345fdf1fbc03a2aa2bc0c80d53a9e40a1d4e45c5362d7d5db578b0da1afe4de` | checksum only |
| 39 | `assets/fonts/inter-latin-400.woff2` | 23664 | `8909904ab6c872eb994093482a88a28eca2cd95912d7b6fecd72103b0dc07edc` | **committed** (byte-identical to the raw download) |
| 40 | `assets/fonts/inter-latin-500.woff2` | 24272 | `f3779f1efccc4bdcdf9c0a02ab95bf6bd092ed09c48c08cedc725889edd1d19f` | **committed** (byte-identical to the raw download) |
| 41 | `assets/fonts/inter-latin-600.woff2` | 24452 | `f9a06e79cd3a2a20951c0f0e28f66dd0e6d3fda73911d640a2125c8fcb78f21a` | **committed** (byte-identical to the raw download) |
| 42 | `assets/fonts/inter-latin-700.woff2` | 24356 | `6f56409fd3d64bb85f7d070bce20749db2d66b6d63cec586cc22d1c761be2491` | **committed** (byte-identical to the raw download) |
| 43 | `assets/fonts/inter-tight-latin-600.woff2` | 22732 | `9af39dac0f6c6ecf01b9f8d280efaa772605d8b4db7e2fa54ba26cdab7532fa5` | **committed** (byte-identical to the raw download) |
| 44 | `assets/fonts/inter-tight-latin-700.woff2` | 22768 | `940a6fa4dfd202a3374a50e0d1148c47ea37aa3aa1044d2ea005473fbb3b21ed` | **committed** (byte-identical to the raw download) |
| 45 | `assets/fonts/jetbrains-mono-latin-400.woff2` | 21088 | `7c53386f55c866c1b4c9309c4bcf74eda10896aab3a1780b0af5cc4976e27a27` | **committed** (byte-identical to the raw download) |
| 46 | `assets/fonts/jetbrains-mono-latin-500.woff2` | 21820 | `4765dee1c0be507cde85c3de952bb24707b798f0e4002c360b9434d66c8bbc3c` | **committed** (byte-identical to the raw download) |
| 47 | `assets/fonts/jetbrains-mono-latin-600.woff2` | 21936 | `1cd6778760d101a5c522f5d1de6fe17efa9e66950bcd5fce274ae3b4f494f923` | **committed** (byte-identical to the raw download) |
| 48 | `assets/fonts/jetbrains-mono-latin-700.woff2` | 21956 | `ed8b8f71b22bf3b6e1ec1cf9b24dd999785aae33d6256950c1f86c97e423b6ef` | **committed** (byte-identical to the raw download) |
| 49 | `assets/keep-components.css` | 14003 | `e9a7adf0e1ec21b750c9fc18a79e983540f7c63c32ee1ff48eeb8f4dd4d586ee` | **committed** (byte-identical to the raw download) |
| 50 | `assets/keep.css` | 12394 | `e276987c2b4681b74653379d53fae04fcf850c816d0eb7c561fcc471ad2caed4` | **committed** (byte-identical to the raw download) |
| 51 | `audit-probe.js` | 11381 | `83c5548cbcd85ad638e335e2934cbaf0419483d3bf0f47459d1fe7245234c69b` | **committed** (byte-identical to the raw download; the 2026-10-26 drop's probe, which replaced the 2026-10-25 one, 10375 bytes, `3eea9069e5760bb62e73d1db29bddbcc0ee2a23f6144ef0f528a575e73097fec`) |
| 52 | `audit-suite.js` | 33814 | `71cf1d69a7e6878c8dc56b1d0d3299c2b3a141ea95dc8be53ca2b96c6e9df9be` | checksum only |
| 53 | `doc-page.js` | 38579 | `f52ae9c02fca7ab44c37f3ff363194fdf81caa20ae63e2fe1f518ed21133185e` | checksum only |
| 54 | `games/_template.js` | 2181 | `0fcb3a3a784864e381a536ee42b02e725ca344886b7ce54688728759fd808295` | checksum only |
| 55 | `github.md` | 12497 | `b33553ccaf65f1cadc50785440e4d1dc17cdab69e758336e1ca7f716e26b28aa` | checksum only |
| 56 | `harness.dc.html` | 21925 | `b29f9c9dd46897949c542f4600c4ac7d75b80f12b5efef3aa40844e0d0c66fb8` | checksum only |
| 57 | `image-slot.js` | 65350 | `fff26d081c8d9d60870f86c7539a5d179b9cdab15e67f2b205508a068e7c7ff6` | checksum only |
| 58 | `readme.md` | 7262 | `88221c6ca8232f1087b5d42cafbca06af077d9a343fed14ff3008faa5c008b4e` | checksum only |
| 59 | `styles.css` | 196 | `f0e9ba309a106a5d8a53ef6e6f3f8339844e315e4eb36dc34302d4f20c90b022` | checksum only |
| 60 | `support.js` | 69150 | `8fe7df74405f3c55f49b7249c74ea1397e65d07dea2b1bd3b4a489bec2e28cbe` | checksum only |
| 61 | `v2/DONATE.md` | 4137 | `80b068306f69c0f11fa84076fb65c74fdf19edd28f5e8d41eadc020ca3c37d6f` | checksum only |
| 62 | `v2/PRIVACY.md` | 10083 | `0a26f8cc2d5fc93a1554fe4af9e1024a92423a19ada13ed7bf1a5bd0cc4fadd5` | checksum only |
| 63 | `v2/apps/desktop/design-upstream/PROVENANCE.md` | 29188 | `d7187b546f4df011c4cab47b89e3ebe70b30b164f9d77e045749ced0b65741d5` | checksum only |
<!-- END generated:files -->
