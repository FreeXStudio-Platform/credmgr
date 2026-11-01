<!-- artifact-hardened: Approved With Known Risks @ 09721b5 on 2026-11-01 via three-pass-v1. Evidence: GitHub-hosted CI on pull request #41 (FreeXStudio-Platform/credmgr): all 17 checks green at ee08394, including security.yml (cargo audit, cargo deny, semgrep, isolation suite, endpoint matrix 55/55 operations, desktop bridge) and CodeQL for Rust, JavaScript/TypeScript, Python and Actions with no open alert on the PR; build.yml run 41243452910, all 7 jobs green (macOS 15, Ubuntu 22.04, Windows; Rust 1.78.0 and stable); desktop unit tests 706 passed at 930c502; Playwright 672 and 681 passed in the two lanes that were combined at 930c502 (not re-run together); strict public export PASS, 860 files, literal blocklist not loaded; by-hand click-through of the rebuilt app on a throwaway vault (unlock, lock, auto-lock, graph, tree, search, reveal, copy, add entry, settings, integrity, doctor, audit, backup, capture switch, searchable help); final adversarial audit v2/docs/release-verification/AUDIT_2026-10-31.md (the P0 and both P1 fixed); known risks K-1 to K-20 in v2/docs/PHASE8_AUDIT_REPORT.md sections 4 and 7, each with bound, owner and resolution. Known risks that bear on this document: K-14 the idle lock and a real sleep or screen lock were not exercised by hand on this build; K-19 a seed in an unrecognised shape is not protected until its owner types it; K-20 the licence text has not been reviewed by counsel. K-12 (CI had not run) is closed. Not signed or notarised; Windows and Linux built in CI but not run. Not a claim about anything after 09721b5. -->

# Privacy policy

**Short version: CredMgr collects nothing, sends nothing, and has no servers.**

Last updated: 2026-10-31 · Applies to: the CredMgr desktop app, CLI, and MCP server.

---

## 1. What we collect

Nothing.

There is no account, no sign-up, no licence key, no activation, no analytics, no telemetry,
no crash reporting, no A/B testing, no feature flags fetched from anywhere, and no
"anonymous usage statistics". (The optional supporter code in §2.1 is not an activation: it opens a
cosmetic pack that ships inside the app, on your machine, with no request to anyone.)

We do not know how many people use CredMgr. We do not know who you are. We have no way to
find out, and we built it so that we could not change our minds later without you noticing:
**the vault process contains no HTTP client at all.** It is not a setting you could flip — the
capability is absent, and the build checks it: `cargo deny` bans every HTTP client, HTTP server and TLS
binding in both Cargo workspaces (`v2/deny.toml`, `apps/desktop/src-tauri/deny.toml`), and a test in the
desktop shell (`tests/dependency_policy.rs`) fails if one reaches the macOS build.

## 2. What stays on your machine

Everything. Specifically:

| Data | Where it lives | Encrypted? |
|---|---|---|
| Credential values, notes, 2FA seeds | your platform's user-data directory | Yes, under per-node keys |
| Node/project names, entry names, counts, and per entry its type, sensitivity, field count and whether it holds a 2FA seed | the same directory | No: plaintext metadata, signed against tampering — this is what lets the app show you your vault while it is locked. Field labels are not in it: they are sealed with the values. A node's `privateNames` setting hides names from agents and other callers; it does not encrypt them on disk. Documented trade, not an oversight. |
| Audit log | the same directory | No: plaintext, `0600`, hash-chained, its tip signed. Records *decisions* (who, which operation, which node and entry id, allowed or denied, and the reason you typed for a policy change) — never a value, a label or a note. It is written with the root key, so a request made while the vault is locked leaves no record; the one exception is an approval decided with the unlock factors, which writes its own. |
| Rollback counter | `~/Library/Application Support/credmgr-state` (override `CREDMGR_STATE_DIR`) | No: plaintext `0600` number with a signature; holds no secret |
| Desktop window layout and cosmetic choices | the desktop window's own local storage (WebKit), eleven keys listed in §2.1, plus two short lock notes in session storage | No: plaintext, and holds no secret and no vault name — see §2.1 |
| Backups (`credmgr backup`, or Operations in the app) | the `backups/` folder inside the vault directory; copy them wherever you like | Yes: one file, encrypted under a separate backup passphrase you choose (Argon2id, 256 MiB, 3 passes). It is only as strong as that passphrase. |

Nothing in that table leaves your computer unless you personally copy it somewhere. The vault lives
in your platform's per-user data directory (macOS: `~/Library/Application Support/credmgr`;
override with `CREDMGR_VAULT_DIR`).

The audit log records the *origin* of a caller and, for a live session, a public session id
(`HumanUi:s_…`) — never the session's token. Builds before 2026-10-02 (2.0.0-alpha.4 to
2.0.0-alpha.6) wrote the token itself there; see `SECURITY.md`, "Session token in the audit log", for what a vault made by one of them still holds.

### 2.1 What the desktop window writes to its own local storage

The desktop window keeps a few preferences in the webview's local storage, and nothing else
(no cookies, no IndexedDB). The one other thing it writes is two short notes in the webview's session
storage, so the Lock screen can say why the vault locked after the page reloads: `cm.lockreason` (one of six
fixed words the shell chooses, such as `sleep` or `window_closed`) and `cm.locknote` (one of two fixed
sentences, "Locked after N minutes without activity." or "Locked because the window was hidden."). Each is
read once at the next start and deleted at once; anything else found under those keys is ignored
(`src/vault/shell-events.ts`). Nothing in either storage is a credential, and none of it names a
node or an entry in the clear: a position is stored under a hash of the node's or entry's id (16 hex
characters of a domain-separated SHA-256), because a node id is often a project name and WebKit keeps
local storage on disk in plain files. Hashing keeps the names out of the clear; ids are low-entropy,
so it is not a defence against someone who can already read your profile directory and guess project
names.

| Key | Holds |
|---|---|
| `credmgr_gposV` | the layout format version (`"3"`) |
| `credmgr_gpos` | where each node sits in the graph, keyed by a hash of the node id |
| `credmgr_gposEntry` | where each entry's dot sits, keyed by a hash of the entry id |
| `credmgr_cosmetics` | the app mark, glyph weight, double halo, header badge, node shape, node and link colours, entry-dot palette, graph backdrop, app icon, unlock flourish and CredPong trail you chose (supporter extras included) |
| `credmgr_donate_unlocked` | whether a supporter code was accepted on this machine (ADR-082) |
| `credmgr_extras_key` | the key that opens the encrypted cosmetic pack on this machine, stored once a supporter code is accepted. It opens nothing but cosmetics and is not a credential |
| `credmgr_usage` | how many different calendar days you unlocked on, the date of the last unlock, which reminders were shown, whether you turned them off, and the date each milestone was first reached. Dates only: no time, no entry count, no name |
| `credmgr_keys` | `off` only if you turn single-key shortcuts off |
| `credpong_best` | the best score in the built-in game |
| `credpong_level` | the highest level reached in the built-in game |
| `credmgr_prefs` | your settings, one record: theme, colour (on, off or automatic, with its hue and intensity), contrast, motion, greyscale, whether hardware acceleration is on, whether the window is hidden from screen capture (on unless you turn it off), graph or tree, Lite or Pro, whether the entries list shows all or only the selected node, how many minutes before the window locks itself (5, 15 or 60, or never), how long a revealed value stays visible (10, 20 or 60 seconds), and how many backups to keep (14 or 30). It holds a setting, never a node or entry id or name, hashed or not; anything in it that is not one of those settings is dropped when it is read, so a damaged or hand-edited value cannot crash the app or smuggle anything in. |

The donation proof (a screenshot and a transaction hash) is something you send yourself, from your own mail program, to the address the dialog shows; the app has no send button and makes no request, and holds none of it. The reminder that leads to that dialog appears at most three times in the life of an install, only after an unlock and only when the vault holds enough entries on enough different days (the entry count is read to decide and is not stored); "don't remind me" ends it (`DONATE.md`, ADR-082).

A test (`apps/desktop/tests/unit/pstore.test.ts`) drives the writers of these keys and fails if any
other key appears, or any key or value contains a node or entry id.

## 3. Network activity

The **vault process** makes no network connections. Ever.

Neither does anything else CredMgr ships. The **CLI** and the **MCP server** talk to the vault
process over a local Unix socket and nothing more (the MCP server also speaks standard input and output
to the agent program that started it; see §5). The **desktop shell** makes no network request
either: its window content policy allows only the Tauri IPC (`connect-src` names nothing else), the
shell links no HTTP client (a test fails if one appears in the macOS build, and `cargo deny` bans
them), and it has no updater and no plugin that opens a browser or an external link. **There is no
update check**, automatic or otherwise: you learn of a new version from the repository's releases and
verify it against the published checksums (`RELEASE.md`). No request carries an identifier, a vault
fingerprint, a machine ID, or a usage counter, because no request is made.

### 3.1 The clipboard and the lock

The desktop shell has a concealed-copy command (`entry_copy`): it reveals a secret itself (the value
never passes through the window's JavaScript) and puts it on the pasteboard marked concealed and
transient, for this Mac only, so clipboard managers that honour the marker skip it and Universal
Clipboard and Handoff cannot carry it. It is cleared 30 seconds later **only if the clipboard still
holds what CredMgr put there**, and at once when you press Lock (the button, ⌘L or the menu-bar icon's
"Lock vault"), when you close the window, when the Mac sleeps, when the displays sleep, when the screen
locks, when the user session switches, and when the app quits. It is never cleared merely because the
window lost focus. A clipboard manager that ignores the markers can still read the value during those 30
seconds, and so can any program running as you. A force-quit or a crash cannot run the clear, and the 30
second timer dies with the process, so a value copied just before one stays on the clipboard until
something else replaces it.

**The app's Copy buttons use that command.** A value you copy from the app goes from the broker to the
shell to the pasteboard and never through the window's JavaScript; the app contains no use of the browser
clipboard API at all (a test fails if one appears). A second shell command, `copy_text`, puts **non-secret**
text on the clipboard with no marker and no timer — a donation address, a node id — and has no way to tell a
secret from anything else, so only the places that copy non-secret text call it.

The shell also locks the vault when the Mac sleeps, the displays sleep, the screen locks or the
session switches, whether or not the app itself holds a login. A screensaver that does not require a
password does not lock it. The vault's own idle timeout still applies when the app is not running.

**Screen capture and the app icon.** The window is created content-protected (macOS `sharingType` none; the Windows equivalent is in the code, but no
Windows build ships), so a screen recording, a screenshot tool or a screen share that honours it shows the window
blank (threat T10). That is a request to the operating system, not a guarantee against every capture method, a
camera pointed at the screen, or a program that already runs as you. It is on by default, for every new install and
whenever your choice cannot be read, and you can switch it off in Settings → Security ("Hide the window from screen capture
and screen sharing"). Turning it off asks you first, because the window then appears in screenshots, recordings and screen
shares, and Settings shows "capture allowed" while it is off. The choice is one setting in `credmgr_prefs`; the window starts
protected and the page tells the shell to lift the protection only when your stored choice is off, and locking the vault does
not change it. Separately, the shell reads one environment variable at start-up, `CREDMGR_CONTENT_PROTECTION`, and only the
exact lower-case value `off` switches protection off, for a support screenshot or the real-app pass; any other value leaves
it as your setting says, and while it says `off` no setting turns protection back on. A shell command,
`app_icon_set`, changes the Dock or window icon to one of six bundled marks until the app quits; it sends and stores nothing
(the choice lives in `credmgr_cosmetics`).

**Auto-lock and reveal.** The window locks itself after the idle time you choose in Settings (5, 15 or 60
minutes; the default is 15) and whenever it is hidden (minimised, or the app hidden with ⌘H). Choosing "never"
turns both of the window's own locks off. The broker has an idle lock of its own (15 minutes by default), but
while the app is open and logged in its login check every 30 seconds counts as activity there, so in that state
it is the window's timer, not the broker's, that ends the session. With "never" the vault stays open until you
lock it, close the window, or the Mac sleeps, locks the screen or switches user; if the app is quit instead, the
broker's own idle lock then applies. Closing the window with the red button locks the vault and keeps the app
running in the menu bar. When the window or the shell locks the vault, the window also reloads itself, to drop
whatever typed text and revealed values the page held; the broker's own idle lock does not reload it. A value you reveal on screen is hidden again after 20 seconds by default (10, 20
or 60 in Settings), and selecting another node, losing focus or locking wipes it at once. A reveal is a broker
call: it leaves an audit record of the decision, never of the value.

## 4. What CredMgr does with other applications

CredMgr does not read or write any other application's configuration. To let an agent use a vault
you add `credmgr mcp` to that agent's own MCP configuration yourself. A one-click "LLM Integration"
setting that would do it for you, and a generated "Vault Protocol prompt", are designed
(`docs/17_AIRLOCK_AND_LLM.md`) and **not built**; the desktop app does not offer them.

## 5. What an AI agent can see

If you connect an LLM, that agent can read the credentials its node scope allows, and those
values then exist in that agent's context and may reach that vendor's servers. **That is a
consequence of asking an assistant to use a credential, and it is your decision, not ours.**

CredMgr's job is to bound it: an agent reaches one node, never the whole vault; it can be
required to ask your permission per value (approval on demand, which you decide in the app or with
`credmgr approve`); it can get a 2FA code but not a 2FA seed (a reveal withholds every field recognised as a seed, the MCP server has no tool for one, and the
broker refuses the operation); and every access made while the vault is unlocked is logged on a best-effort
basis, so you can see which values were released and when (the log holds the decision, not the value).

Read `docs/17_AIRLOCK_AND_LLM.md` before connecting an agent to a vault holding money keys.

## 6. Children

CredMgr is a developer tool and is not directed at children. We collect no data from anyone,
including children.

## 7. Your rights

Data-protection law grants rights of access, correction, deletion and portability. They are
satisfied trivially here because **we hold no data about you**:

- *Access* — it is all in your user-data directory (§2).
- *Portability* — `credmgr backup` writes an encrypted snapshot, and `scripts/emergency-decrypt.mjs`
  recovers one entry at a time from a vault folder, with its recovery code, without CredMgr. There is no
  plaintext export command.
- *Deletion* — delete the directory. There is nothing on our side to erase.

There is no data controller holding your information, no processor, and no third-party
sub-processor, because there is no transmission.

## 8. Changes

If this policy ever changes, the change ships in a release, appears in `CHANGELOG.md`, and is
visible in the commit history of this file. There is no server-side policy that can change
without a new version in your hands.

## 9. Contact

Open a GitHub issue. For anything security-sensitive, follow `SECURITY.md` instead.
