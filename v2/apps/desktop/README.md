# CredMgr desktop

The CredMgr desktop app: the KEEP design, **precompiled**, hosted in a Tauri 2 webview under a strict
Content-Security-Policy (`script-src 'self'`, `style-src 'self'`, no `unsafe-eval`, no `unsafe-inline`, no remote
origin). The Rust shell in `src-tauri/` talks to the broker (`credmgrd`) through `src/lib/bridge.ts`.

> **Status (2.0.0-beta.1):** every screen reads from the broker and every change goes to it. Session (first run, the Lock
> screen with the second factor and recovery codes, locking in every way), the read path (graph, tree, rail, inspector, notes,
> reveal, concealed copy through the shell, TOTP codes, search, rename, per-node lock), the writes (entries of several fields, notes, a paste as one entry or split by `///`, the
> held-entry tray, nodes with their policy, seal and restore) and administration (grants, the audit trail, Verify, Doctor, Back up,
> Rotate root key, setting up or replacing the second factor, settings, About) are wired and covered by end-to-end specs against a fixture broker. Four operations are
> sent for real and refused by the broker with `presence_required` until presence can be attested (grant creation, the full audit
> record, root-key rotation, a registry rebuild); the app says so and changes nothing. **There is no demo data in a release build** and
> no local-only write path: a screen shows what the broker last said, and a change is a broker call followed by a re-read. When the
> broker did the work and only that re-read failed, the notice says what was saved and that the screen is out of date (never "Nothing
> was changed"), and a node this login cannot list is shown as unreadable, not as empty. The page
> never writes to the clipboard; a copied secret goes through the shell and never enters the webview.
> **Fields (ADR-078):** an entry's detail draws its fields from `entry.get` (ids, labels, types, masking; never a value), reveals and
> copies ONE field at a time (`entry.reveal` with `fieldIds`, `entry_copy` with `field`), shows the fields that are not masked from one
> audited read, and adds, edits, removes and reorders fields (`field.add / update / remove / reorder`, each echoing the node's
> generation). Add entry previews through the shell's own parser (`fields_preview`, local: no broker call, no audit record) and saves that
> preview verbatim; the page keeps no parser or type inference of its own. A note is an entry of type `note`.
> **Follow-ups (ADR-090, ADR-091):** the Lock screen asks `vault.status` every five seconds for the count of waiting agent requests and, when there is
> one, `vault.approval_get` for what they are (names when the broker gives them, the node's id when its name is private); a node created with
> "Hide this node's name" gets an opaque id (`n_` + 12 hex) chosen at creation; the broker's `warnings` (a name mixing Latin with Greek or
> Cyrillic) are said in the same notice, never blocking; the shell passes the broker envelope's `audit` id into the answer of every changing op
> (`AUDIT_PASSTHROUGH`) and Undo uses it; after every lock (sleep, screen lock, tray, window close, and the page's own Lock button, ⌘L and idle timer) the shell reloads the main webview,
> leaving the reason for the Lock screen's note; the node's second-factor chip gives the factor on purpose (the owner's own login is exempt).

## Build and run

Requirements: Node 22.12 or newer, Rust (the toolchain pinned in `src-tauri/rust-toolchain.toml`), and the Tauri 2
macOS prerequisites.

```bash
cd v2/apps/desktop
npm ci                 # exact versions from package-lock.json; never `npm install`
npm run build          # vite build, then scripts/dc/verify-build.mjs (fails on inline code, eval, Babel, remote URLs)
npm run tauri dev      # development window (devCsp is looser: it needs the Vite dev server)
npm run tauri build    # CredMgr.app / .dmg (runs `npm run build` first)
```

`@tauri-apps/api`, the CLI and the `tauri` crate (`src-tauri/Cargo.lock`) are all pinned or resolved at 2.12.1. The Tauri CLI
rejects a version mismatch, so a bump moves the two npm pins here and `cargo update -p tauri --precise <version>` in
`src-tauri/` together, followed by the whole `src-tauri` suite.

## Checks

| Command | What it proves | Needs |
|---|---|---|
| `npm run check` | TypeScript types; the template compiles (`scripts/dc/compile.mjs --check`) | nothing |
| `npm test` | the model, the error router, the bridge mapping, the importer's refusals, compiler semantics (the number of template bindings is pinned exactly), every name the template reads exists in `renderVals()` in each of 55 states (driven through the real bridge client against the fixture broker), local-storage keys are hashed, the fixture broker answers in exactly the shapes `src/lib/bridge.ts` declares (every handler needs a `B.examples` entry; see `tests/fixtures/broker/core.js`), the architecture rules (no logic file edits the view in place, `navigator.clipboard` appears nowhere in `src/`), and the release rules (`tests/unit/release-build.test.ts`: the release gate bans what it must, and a production-mode model has no demo vault) | nothing |
| `npm run test:csp` | loads the **release build** (`build/`) the way Tauri serves it, under the production CSP read from `tauri.conf.json`, in WebKit and Chromium, with the fixture broker standing in for the shell: 0 policy violations, 0 console errors, 0 external requests, an error-boundary panel counts as a failure; a page with no shell at all must show only the broker-unreachable screen; canaries prove the gate can fail | `npm run build`, Playwright browsers |
| `npm run test:e2e` | the Playwright specs in `tests/e2e/`: the **test build** (`build-test/`, which the script builds first) under the same CSP, with the Tauri shell's `invoke` replaced by the fixture broker. Each spec asserts the exact bridge commands and arguments the app sends and what it renders from the answers, including refusals; every spec also asserts 0 violations, 0 console errors and 0 external requests when it ends. `screens.spec.ts` puts the app into every screen, dialog, overlay and settings section from broker-shaped data and names any that lands on the error screen; in every build the broker-backed view is deep-frozen, so a screen that edits it in place throws. `no-mock-badges.spec.ts` walks the same states and fails on any visible "mock" / "not built" marker | Playwright browsers |
| `npm run build:test` | the same build plus the `window.__cm` test handle and the demo vault, into `build-test/` (never shipped) | nothing |
| `npm run test:design` | the design team's own audit probe: 0 dead controls, 0 unlabelled controls, 0 clipped text, 0 squashed controls, 0 low-contrast text, in every state of `scripts/states.mjs`, against the **wired** app with the fixture broker answering. It builds `build-test/` first and reads the probe from the committed `design-upstream/<date>/audit-probe.js`, checking its sha256 against `design-upstream/PROVENANCE.md`; a missing probe, record, digest or build is an **error** (exit 2), never a skip. **In the public tree** the probe is not shipped (licence): there this is a development-only gate that prints `NOT RUN` and exits 0 unless `DESIGN_EXPORT_DIR` points at the design export holding `audit-probe.js` (digest-checked the same way) | nothing (Playwright browsers) |
| `cd src-tauri && cargo test --locked` | the shell and the bridge (10 executables; `macos_pasteboard` writes the real pasteboard) | the Rust toolchain |

The audit probe is the one file of the design export that is committed alongside the snapshot (`design-upstream/PROVENANCE.md`,
"The audit probe"): a gate that reads its input from somewhere outside the repository skips on a fresh clone, and a skipped gate has
not passed. Playwright browsers: `npx playwright install webkit chromium`.

## Layout

```
index.html              Vite entry: #dc-root and one module script; no inline code
src/main.ts             mounts the error boundary and the host component
src/dc/runtime.ts       the small host the compiled design needs (clean-room; passes the previous logic state),
                        and the error boundary that shows "Something went wrong" instead of a blank window
src/design/             the derived fork of the design: app.template.html + screens/*.html (<sc-include>),
                        logic/*.js (one mixin per screen area; extras.js holds the supporter extras and the milestone ask), app.css,
                        assets/ (CSS and local fonts)
src/vault/              the model every screen reads through (see below)
src/lib/bridge.ts       the typed client for the broker (do not edit casually: src-tauri/tests/ts_client.rs reads it)
scripts/dc/             the build-time compiler: compile, extract, import, Vite plugin, verify-build (and release-bans.mjs: what a release
                        bundle must not contain)
scripts/states.mjs      the screens the headless gates walk, as state patches (fixture ids)
scripts/verify-*.mjs    the headless gates above
tests/unit/             vitest
tests/e2e/              Playwright specs and their harness
tests/fixtures/broker/  the fake broker the specs install in place of the Tauri shell's invoke (plain JS that runs in the page;
                        one file per work-package area: session, read, write, admin; each handler carries examples that
                        tests/unit/fixture-shape.test.ts checks against the declarations in bridge.ts)
design-upstream/        the sanitized upstream snapshot and PROVENANCE.md (where every file came from)
third_party/fonts/      the SIL OFL texts for the bundled fonts (Inter, Inter Tight, JetBrains Mono)
src-tauri/              the Tauri shell (Rust)
```

## The vault layer (`src/vault/`)

The logic class never talks to the broker. It reads `this.vault`, which is `model.view`: plain data (nodes, entries,
grants, the tray) that the model **replaces** whenever it refreshes. The model owns the session state machine, the caches
and a private store for revealed values; nothing secret is ever in the view.

| File | Role |
|---|---|
| `model.ts` | `VaultModel`: `boot`, `unlock`, `gateVerify`, `lock`, `clear`, `loadAll`, `refresh(spec)`, `mutate(action, spec)`, `reveal`/`holdFetched`/`plain`/`hide`/`wipeSecrets`, `subscribe` |
| `source.ts` | the seam: what the model reads through |
| `bridge-source.ts` | the real source: `src/lib/bridge.ts` answers mapped to view types |
| `no-shell-source.ts` | what answers when there is no Tauri shell in a build without a demo vault (every release build): "broker unreachable", never data |
| `demo-source.ts` | an in-memory example vault for development and test builds only (`vite dev`, vitest, `build-test/`); invented from documentation ranges and generated placeholders; dropped from release bundles, which `scripts/dc/verify-build.mjs` enforces |
| `errors.ts` | `routeError(e, ctx, host)`: what the UI does with every rejection (lock screen, node-locked, second factor, presence notice, inline, reload, notice) |
| `actions/session.ts`, `read.ts`, `write.ts`, `admin.ts`, `prefs.ts` | the operations, each one broker call (through `src/lib/bridge.ts`) followed by a re-read of what it touched |

How a screen uses it: `await action()` through the bridge, then `model.refresh({ ...what it touched })`, or on failure
`this.routeError(e, { op, node, field })`; `this.notify(kind, text)` raises the global notice. There are no optimistic
writes. A revealed value lives only in the model's secret store: it expires with the reveal window and is wiped on lock,
when the window is hidden and when the selected node changes.

Three rules the model keeps for every package, each proven in `tests/unit/model.test.ts` and `tests/e2e/session-boundary.spec.ts`:

* **A read that outlives its login publishes nothing.** `clear()` (every road to the Lock screen) starts a new epoch; a
  `loadAll`/`refresh` that began earlier resolves quietly without touching the view, and an `unlock` whose load was cut off
  rejects with `session_expired` instead of opening an empty app. A `reveal` still waiting on the broker when the field is
  hidden, the node changes, the window is hidden or the vault locks is dropped on arrival (`reveal()` resolves `false`).
* **Reads that publish run one at a time**, in the order asked, each from the view the one before left, so a slow refresh
  cannot overwrite a newer one.
* **A lock the broker did not confirm is said, not swallowed.** `lock()` always ends locked and empty, and returns
  `{ confirmed, code }`; when `confirmed` is false the user gets a warning chosen by code (`lockUnconfirmedText`), through the
  `notify` passed to `createModel`.

## Supporter extras and the milestone ask (ADR-082)

`src/design/logic/extras.js` is the whole feature; the broker is not involved and no request is made. **Nothing functional is ever gated.**

* **The ask.** A dismissible toast, at most three times in the life of an install: 50 entries and 14 distinct unlock days, 150 and 45, 300 and 90. It
  comes 6 s after a *successful unlock* (passphrase, second factor, recovery, first run; not a window coming back into view), never over a dialog, in a game,
  on the Lock screen, after a supporter code or "don't remind me", or twice in a day; a jump past two milestones asks once, for the highest.
  `credmgr_usage` keeps calendar days and flags only.
* **The extras.** Cosmetic data (shapes, colours, a backdrop, a trail) sealed in the app as AES-GCM ciphertext. The supporter code derives the key (PBKDF2-SHA-256,
  200 000 rounds; white space and case are ignored); the key is then kept (`credmgr_extras_key`) so later launches need no code. A wrong code stores nothing. The
  decrypted pack is cleaned (`packClean`) and never evaluated. The code is not in the repository.
* **In tests.** A test build (`--mode test`) opens a stand-in pack sealed under `TEST-EXTRAS-CODE` (`tests/fixtures/extras/seal-test-pack.mjs` makes one); it also has
  `__cm.usageSet({days, entries, last, reset})` and `__cm.packLoad(code)`. A release build has neither the stand-in nor those two names (`scripts/dc/release-bans.mjs`).
  `tests/e2e/extras.spec.ts` injects the date and the 6 s with Playwright's clock instead of waiting.
* **Secret scanners.** The pack is ~650 characters of base64, which is what `scripts/guard-no-secrets.mjs` calls a `base64-blob`; the guard allows it by name
  (a function called `extrasBlob`, or a `credmgr-allow` comment above it), not by length, and `tests/unit/guard-secrets.test.ts` proves a canary of the same size fails.

## Undo, Generate, the second factor after the login, a decision while locked (2026-10-25 drop; broker ADR-083...089)

Each is one broker call through the bridge; what the screen shows afterwards is the broker's answer, never a copy the page kept. `logic/gates.js` (new) holds the second-factor
dialog and the locked-approval panel; Undo and Generate are in `logic/fields.js`; the vault-layer functions are in `src/vault/actions/{write,session}.ts`.

| Control | Command | Notes |
|---|---|---|
| **Undo** after Add field / Edit / Remove | `entry.undo {node, id, generation}` | `id` is the audit record of the change. The shell hands the page only the answer's `value` (the broker's `audit` member is dropped), so the window reads the id back from `audit.tail` (the newest `field.*` record of that node and entry at the generation the change produced). If the trail does not show it, no Undo is offered. The message is the broker's reply (`restored.fieldCount`). The offer is tied to the entry, the node and the login (`model.epoch`). |
| **Generate** in Add field | `util.generate {length 8-128, symbols, pronounceable}` | The value is made in the broker (never in page JavaScript), shown masked with `entropyBits`, never copied, and enters the entry only through `field.add`. |
| **Second factor** (S5c) | `vault.gate_verify {code}` from the logged-in session, then the refused call once | A read-path `two_factor_required` (a reveal; at level `always` also a list, a get, a note) opens the dialog with a `retry` closure. There is no factor parameter on the reveal: the step-up opens a five-minute elevation. The window's own login is the owner's and is not normally asked (ADR-085 #3), so the dialog is covered by the fixture broker; the transport is covered against the real daemon. |
| **Approval while locked** (S16a) | `vault.approval_decide {request, approved, passphrase, code?}` | Lock screen, passphrase step. The request id is the agent's output (`vault.approval_get` does not exist), so the panel asks for it. The vault stays locked; a recovery code is not accepted; the passphrase and code are wiped after every attempt. |
| **privateNames** | `node.policy {privateNames:true}` in the narrowing call after `node.create` | The owner's snapshot row carries `nameHidden:true`; the inspector says "name hidden". |
| **Doctor** | `maintenance.doctor {apply, purgeExpiredSeals:true}` | The dry run lists `would-purge-expired-seal` with the node and when it was sealed; Apply removes the retained originals for good. |

Tests: `tests/unit/gates-actions.test.ts`, `gates-logic.test.ts`; `tests/e2e/gates.spec.ts` (fixture broker, which now answers `entry_undo`, `util_generate`, `vault_approval_decide`, a step-up
`vault_gate_verify`, `two_factor_required` with `broker.set({ factorGate: true, tfLevels })`, `nameHidden` and `purgeExpiredSeals`); `tests/real/gates.spec.ts` (a real `credmgrd`: Undo, Generate,
approval with and without a second factor, the step-up, privateNames, the doctor).

## Where the design came from, and how to take a newer drop

Read `design-upstream/PROVENANCE.md`. In short: `node scripts/dc/import.mjs <export-dir> --date <YYYY-MM-DD>`
writes a sanitized snapshot, `node scripts/dc/extract.mjs` splits it, and the new `extracted/` files are three-way
merged into `src/design/` (`git merge-file`). The project-name replacement table used by the importer is deliberately
kept outside the repository (`DC_SANITIZE_MAP_FILE`), and the importer **refuses to run without it** (exit 1, nothing
written) unless you pass `--no-name-map` on purpose.

## Rules for changes here

* Never add `unsafe-eval`, `unsafe-inline` or a remote origin to the production CSP, and never load a font, script or
  stylesheet from a CDN. `npm run build` and `npm run test:csp` fail if you do.
* No analytics, telemetry or crash reporting, ever.
* Anything the app writes to local storage must be listed in `src/design/logic/pstore.js`, in the `DOCUMENTED` list in
  `tests/unit/pstore.test.ts` and in `PRIVACY.md`, and must not contain a node or entry id or name in clear: use
  `hid(kind, id)`.
* All broker access goes through `src/lib/bridge.ts`, from `src/vault/`. No `invoke()` anywhere else. The two shell facts that are not
  broker calls (`getVersion`, `homeDir`) are typed in that file too; the only other module that imports the Tauri JavaScript API is
  `src/vault/shell-events.ts` (the event listener). `tests/unit/architecture.test.ts` holds every `@tauri-apps` import to that list.
* The view is the broker's last word and is deep-frozen in every build: nothing in the logic edits it, a change is a broker call and a
  re-read. A control with no real operation behind it is removed, not left mocked, and no screen carries a "mock" or "not built" marker.
* The page never touches the clipboard (`navigator.clipboard` appears nowhere in `src/`; a test fails if it does): a secret is copied by the
  shell (`entry_copy`) and never enters the webview, a donation address by the shell's `copy_text`.
* A release build contains no demo vault and no fixture broker (`scripts/dc/release-bans.mjs`).
* Every rejection goes through `routeError`; a control with no real operation behind it is removed, not left mocked.
