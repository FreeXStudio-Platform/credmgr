# Real-broker UI end-to-end suite

The built desktop app (`build/`, production Content-Security-Policy) driven by Playwright in front of a **real `credmgrd`** on a
throwaway vault. The other end-to-end suite (`tests/e2e/`) answers the app from an in-page fake; this one answers it from the actual
broker, so a screen that claims "Saved" while the vault holds nothing, or a bridge shape the broker does not send, fails here.

```bash
npm run test:real                       # builds credmgrd + build/, runs the drift guard, then every journey on WebKit and Chromium
npm run test:real -- --project=webkit   # Playwright arguments pass through
npm run test:real:drift                 # just the drift guard (no browser, no daemon)
```

## What is real, what is replaced

| Real | Replaced |
|---|---|
| the release bundle (`build/`: no demo vault, no `window.__cm`), the production CSP from `tauri.conf.json`, `src/lib/bridge.ts`, the model, the screens | the Tauri **shell** only |
| the wire protocol, `credmgrd`, the vault on disk, Argon2id, the second-factor gate, the audit trail | `entry_copy` / `copy_text` write an in-memory pasteboard (`FakeClipboard`), never the developer's |
| everything the page SENDS after a preview: the real broker validates and stores it | `fields_preview` (the shell's local bulk-paste preview, Rust in `credmgr-core`) is a Node port, `shim/preview.mjs`, held to the cases the Rust pins by `preview.test.mjs` |

`tests/real/shim/` is the Tauri command layer rewritten in Node: `window.__TAURI_INTERNALS__.invoke` in the page calls a Playwright
binding, which runs `Shim.invoke` — the same steps `src-tauri/src/commands.rs` runs (command → op table, optional arguments left out,
Tauri's argument checks, token custody and its reconciliation with lock state, `AuthState`, the lock sequence, the socket framing and
its id check) — over the daemon's **Unix socket**. The login token lives in the shim; the page never sees it (asserted at the end of
every test).

## Files

| File | Role |
|---|---|
| `shim/table.mjs` | the shim's command → op table, written by hand (the thing the shim dispatches from) |
| `shim/commands-rs.mjs`, `shim/drift.mjs`, `drift-guard.test.mjs` | the drift guard: parses `commands.rs`, `session.rs`, `error.rs`, `clipboard.rs`, `ops.rs` and `bridge.ts` as text and requires the table to agree in both directions (53 broker commands + 3 shell commands, argument by argument, including the frame `entry_copy` sends to the reveal), with canaries that break each thing and require the guard to object |
| `shim/preview.mjs`, `preview.test.mjs` | the shell's local `fields_preview` (bulk-paste parser, inference, projection) ported to Node, and the cases from the Rust unit tests it is held to |
| `shim/shim.mjs`, `session.mjs`, `transport.mjs`, `bridge-error.mjs`, `page.mjs` | the shim |
| `daemon.mjs` | starts / restarts / kills / disposes a `credmgrd` on a fresh `cmreal-*` temp root; builds its environment from scratch; reads its open files and sockets from `lsof` |
| `oracle.mjs`, `agent-client.mjs`, `totp.mjs` | an independent client of the same daemon (own login) for checking the vault without trusting the screens; an agent process with no token whose working directory scopes it; an RFC 6238 authenticator |
| `harness.ts`, `helpers.ts` | the `app` fixture and what a person does in the UI |
| `*.spec.ts` | the journeys (below) |

## Journeys

`core-journey` first run → project → single + bulk entries → reveal → search → notes → lock → unlock → daemon restart → unlock → data
still there, and no plaintext / passphrase / token on disk · `pending-tray` held entries (a locked node, and an agent while the vault is
locked), accept / discard · `second-factor` enrol with a real authenticator, a wrong and a right code, restart, recovery codes, "lost your
authenticator" · `presence` grant / rotate / audit record / TOTP seed / widening node choice (read back at the vault), each `presence_required`, each leaving the
vault unchanged · `node-lock` the locked-node panel from both directions · `session` every way a login ends · `lock-screen` the broker's
real backoff · `controls` rename, copy, Operations, About, seal · `isolation` the daemon sealed into its root, no network socket ·
`canary` a gate that never failed proves nothing: inline script, remote stylesheet, a control that sends the wrong command / argument, a token-shaped string on a page with no login, the daemon-binary exemption being exact.

## Expected failures (`test.fail`)

One test asserts the **intended** behaviour of a defect the front end exposes. It has a twin named `TODAY` that passes while the defect
stands and pins it EXACTLY (the broker's own answer, not a locator timing out), so the expected failure of the `INTENDED` test cannot
be caused by anything else: a broken locator or an unrelated regression fails the `TODAY` test as an ordinary red. The day a defect is
fixed, the `INTENDED` test starts passing, Playwright fails the run ("expected to fail, passed"), and the `TODAY` test fails too: flip
them, delete the annotation.

| Pair | Defect |
|---|---|
| `controls` backup count | `maintenance.backup` answers `pruned` as the archive names (an array); `bridge.ts` declares a number, so the line reads "· older archives removed" with no count. TODAY pins the answer's shape and the line |

Two pairs have been flipped this way since the suite was written, and are ordinary tests now: **`node-lock` 1b** (`unlock_node` did not
re-derive the node's hot key, so a reveal after "Unlock node" answered `not_found`; fixed in `state.rs`) and **`controls` seal** (K-7's
remainder: `node.seal` answered `internal` in a vault made by `vault.init_*`; closed by ADR-079, which writes the orphan node and its
cold key at init).

## Safety

Every daemon runs in a fresh temp root with `CREDMGR_VAULT_DIR`, `CREDMGR_STATE_DIR` and `HOME` inside it, and an environment built
from scratch (read back from the kernel with `ps -E` in `isolation.spec.ts`); that environment is what keeps the daemon off any real vault
path. Every test also ends with an `lsof` check of what the daemon holds open at that moment, and `isolation.spec.ts` repeats it after a
restart: a point-in-time CHECK on top of the sealed environment, not a recording of the whole run. Only the daemon's own executable
is exempted from it, by exact path, wherever it was built (`CREDMGRD_BIN`, `CARGO_TARGET_DIR`, `CREDMGR_REAL_PROFILE`). Nothing here
opens, lists or reads `~/.credmgr`, the live vault or any other real vault path. The harness refuses to run against a `build/` or `credmgrd` older than its sources
(`CREDMGR_REAL_SKIP_STALE_CHECK=1` to override). `CREDMGR_REAL_KEEP=1` keeps the temp roots for a post-mortem.
