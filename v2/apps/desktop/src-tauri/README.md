# The desktop shell's Rust side — the bridge to `credmgrd`

Read this before changing anything in `src/`. It is the note Session 21B left for whoever
picks the bridge up next; the decision record is **ADR-057** in `v2/docs/14_DECISIONS.md`.

## What this is

`credmgrd` is the single enforcement point (ADR-001). This crate is one of its socket
clients — like the CLI and the MCP server. It does not decrypt, does not read key files, and
makes no authorization decision of its own. It carries requests over the Unix socket and
answers back. The only state it owns is **custody of the session token**.

## What exists, and what does not

**Wired — 8 of 38 broker ops**, the read and authentication surface:
`vault.status` · `vault.unlock` · `vault.gate_verify` · `vault.lock` · `whoami` ·
`graph.snapshot` · `entry.list` · `entry.reveal`

**Not wired — the other 30.** Every mutating op (`entry.create`/`update`/`rotate`/`remove`/
`restore`/`undo`, and the `node.*`, `grant.*`, `totp.*`, `vault.pending_*`, `vault.node_*`,
`maintenance.*`, `audit.*`, `search` families). This is deliberate, not a backlog: each
mutating op carries an optimistic-concurrency `generation`, and several sit behind presence
or approval gates whose UX is Phase 6 work. Wiring them ahead of the screens that drive them
would be guessing at their shape.

| file | job |
|---|---|
| `src/vault_paths.rs` | resolve `<vault>/run/broker.sock` |
| `src/transport.rs` | one request, one response, over the UDS |
| `src/error.rs` | the single error shape; carries the broker's own vocabulary |
| `src/session.rs` | holds the ADR-056 token; never lets it reach the webview |
| `src/commands.rs` | the `#[tauri::command]` surface |

## Four things that will bite you

**1. The session token must never cross into the webview.** `vault.unlock`'s success body is
literally `{"locked": false, "token": "cmt_…"}` — a `global`-scoped token carrying every
capability including `Admin`. It is captured in `Session`, attached to outbound calls
Rust-side, and stripped from what the command returns. ADR-057 states the rule: *no value
derived from a session token — not the token, not a prefix, not a hash — crosses the IPC
boundary.* `tests/bridge_wire.rs` has two tests that fail if it ever does.

**2. A revoked token does not fail — it silently demotes you.** This is the subtle one.
`scope::resolve_scope` step 1 does not match an unknown token id, so it falls through to step
2 and resolves the caller from its cwd as `Origin::Agent`. The broker returns no error. A UI
holding a dead token keeps working with quietly fewer capabilities, and the damage surfaces
much later as inexplicable `capability_not_held` denials on a screen that worked a minute
ago. Three things revoke: `vault.lock`, ADR-043's **idle timer** (fires on a wall clock, with
no event delivered to any client), and restarting `credmgrd`.

The bridge therefore treats `locked: true` — from a response body, from `graph.snapshot`'s
`meta.vaultLocked`, or from a `vault_locked` denial — as proof its token is dead, and drops
it. **Anything you add must route through `Session::reconcile_ok`/`reconcile_err` too.** If
you add a command that bypasses `dispatch_at`, you have reintroduced this bug.

**3. Do not translate the broker's error vocabulary.** `code` is the wire discriminant
verbatim, so a denial rendered on screen is the same word `audit.tail` records for it.
`two_factor_required` is an *error*, because that is what it is on the wire — the UI branches
on the code. A friendlier vocabulary here puts the screen and the audit log into two
languages for one event.

**4. This crate is its own Cargo workspace** (ADR-035), on current stable, not the 1.78 MSRV
pin the security crates use. `cargo test --workspace` from `v2/` **does not build or test this
crate** — run `cargo test` from this directory. That is also why nothing here can
`use credmgr_brokerd::protocol`, which is what the drift guards exist for.

## The drift guards — do not "fix" them by editing the constant

`tests/drift_guards.rs` reads the real source off disk and compares:

- every `"error"` discriminant in `crates/brokerd/src/protocol.rs` against
  `error::BROKER_ERROR_CODES`, **both directions**;
- every op this bridge sends against the match arms in `crates/brokerd/src/ops.rs`;
- the `<vault>/run/broker.sock` rule, the `CREDMGR_VAULT_DIR` override and the four-branch
  platform table against `crates/store/src/paths.rs`.

A guard comparing a copied literal against itself passes on both sides of a divergence. These
read the original, so they cannot. **If one goes red, the broker changed — handle the new
case, then update the constant.** All three were deliberately falsified before being trusted
(drop a real code, invent one, claim a phantom op); each produced the expected red naming the
offender. A guard nobody has watched fail is not known to work.

## Adding an op

1. A `pub async fn <name>_at(session, socket, …)` core plus a thin `#[tauri::command]` wrapper
   that supplies `socket()?`. The socket is injected so the flow is testable against a real
   socket at a temp path — never mutate `CREDMGR_VAULT_DIR` in a test, `cargo test` runs unit
   tests on parallel threads in one process.
2. Add the op string to `OPS_THE_BRIDGE_SENDS` in `tests/drift_guards.rs`.
3. Add a case to `tests/bridge_wire.rs` against the fake broker in `tests/common/`.
4. For a **mutating** op: it must accept the caller's last-seen `generation` and surface
   `conflict` rather than retrying. `entry.list` already returns the `generation` a first
   update needs, and `error.rs` already maps `conflict` with both values in `detail`.
5. Update `v2/docs/18_ENDPOINT_INDEX.md §4`'s built/planned table.

## Two known limitations, named rather than hidden

- **The passphrase argument is inert.** `vault.unlock` ignores it — the broker's keystore is
  fixed at process start, and per-request passphrase wiring is Phase 5's `PlatformKeystore`
  work (ADR-041). It is sent anyway, exactly as `crates/cli`'s `cmd_unlock` does, so the call
  site needs no change the day that lands. It arrives as a JS string already copied by the IPC
  layer, and Rust does not guarantee the heap allocation is zeroised.
- **Unix only.** `credmgrd` binds a `UnixListener`, so there is no Windows named pipe to talk
  to yet (`16_CROSS_PLATFORM.md` plans one). Non-Unix builds compile and return
  `platform_unsupported` rather than failing to build.

## The shell's own commands, events and checks

Beyond the broker bridge, the shell does five things the webview cannot do for itself. Each has its design note in the
module's own doc comment; this is the map.

| file | job |
|---|---|
| `src/clipboard.rs` | `entry_copy` / `copy_text`: the concealed clipboard (markers, and `CurrentHostOnly` so a secret stays out of Universal Clipboard / Handoff), cleared after 30 s **only if still ours**, and on lock (the Lock button, sleep, screen lock, session switch) and quit under the same test. A copy whose reveal is still in flight when a lock lands is refused, not written afterwards. Never on focus loss (decision D5) |
| `src/autolock.rs` | lock the vault from Rust on sleep, screen lock and session switch; `vault.lock` is sent **whether or not this app holds a login** (the broker accepts it tokenless, and the vault is the broker's); the clipboard is cleared inside the OS notification block, the broker call and `credmgr://locked` are spawned |
| `src/shell.rs` | `credmgr://window-inactive` on focus loss; clears the clipboard on quit; window content protection (T10, on unless `CREDMGR_CONTENT_PROTECTION=off`) |
| `src/icon.rs`, `icons/marks/` | `app_icon_set` (X9): the Dock or window icon, one of six 1024 px marks made by `scripts/icons/make-marks.mjs`; macOS through AppKit, elsewhere the window icon |
| `src/fields_preview.rs` | `fields_preview` (ADR-078): the live preview of a bulk paste, parsed and inferred with `credmgr-core` (`parser`, `fields`, `inference` only - `tests/fields_preview.rs` fails on any other `credmgr_core::` path) and answered with **no broker call, no session and no audit record**. What it shows is what `entry_create` stores, label and value byte for byte |
| `deny.toml`, `.cargo/audit.toml` | `cargo deny` / `cargo audit` policy for this workspace (every exception is explained in place) |

`greet` and `tauri-plugin-opener` are gone (C13): nothing in the app opens an external URL, and
`tests/shell_config.rs` fails if either comes back. `tests/dependency_policy.rs` fails if an HTTP client, server or TLS
binding appears in the tree linked on macOS (C14). `tests/shell_ipc.rs` drives the shell's commands and events through
Tauri's real IPC dispatch on the mock runtime; `tests/macos_pasteboard.rs` checks the clipboard rules against a private
AppKit pasteboard (never the user's).
