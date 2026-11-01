<!-- artifact-hardened: not applicable — front-end team record imported from the design project 2026-10-24; not a backend source-of-truth artifact, not hardened here -->
# CredMgr — front-end threat model

**Written 2026-10-18 (batch B12).** Scope: the desktop window's interface (`CredMgr App.dc.html`, hosted by
`v2/apps/desktop` under Tauri). Out of scope: the broker, the vault format, the CLI, the MCP server and the OS; `v2/SECURITY.md`
covers those. "Gate" means an assertion in `audit-suite.js` that runs on every batch.

## What the window holds
- **Revealed values**, in memory and in the DOM, for the reveal window (default 20 s) after the user presses Reveal.
- **Names and labels** of nodes, entries and fields, shown while the vault is unlocked.
- **Clipboard contents** for up to 30 s after Copy.
- **Local settings** in the webview's storage (listed in About → Privacy). None of them is a secret.

## Trust boundaries
1. Broker ↔ window, through the Tauri bridge. The session token stays in Rust; the window never sees key material.
2. Agent-written data ↔ window. Names, labels and notes written by an agent are rendered here.
3. Game code ↔ the rest of the window. Further CredGames titles are scripts in the same JavaScript realm.
4. The window ↔ other apps, through the clipboard and the screen.

## Threats

| ID | Threat | Mitigation in the design | Evidence | Residual risk, owner |
|---|---|---|---|---|
| T1 | A value stays visible or readable after the user is done | Masked by default; re-masks after the reveal window; every value leaves the DOM on lock and on re-mask; a locked entry shows no labels | gate: S-3, S-4, S-5 in `VERIFIED.md` | JavaScript strings cannot be zeroed; a revealed value can sit in the heap until garbage collection. Accepted |
| T2 | A value leaks through an attribute, a tooltip or an error | Values are never put in `title`, `aria-*` or `data-*`; the Field dialog never shows the current value; errors are fixed strings; search results never show the matching text | gate: "a revealed value never sits in an attribute" | — |
| T3 | Script injection through a name, label or note (boundary 2) | React renders every string as text; no `innerHTML` with data, no `dangerouslySetInnerHTML`, no `eval`; the app's CSP is `default-src 'self'; script-src 'self'` | grep: 0 of each (2026-10-18); `tauri.conf.json` (S-11) | — |
| T4 | Spoofed names: an agent writes `pay‮llor` or a look-alike of an existing entry | Bidi and zero-width controls are stripped from names and labels; duplicates are compared after NFKC and case folding | gate: S-1, S-2, confusables fold, mixed-script warning | Closed in the window (B13): the duplicate guard maps 26 Cyrillic, Greek and Latin look-alike letters to their Latin twin (`dupKey`), and a name that mixes Latin with Greek or Cyrillic shows a warning. Open for the backend, confirmed not built on 2026-10-18: uniqueness is an exact string compare (`ops.rs` 758, 1037, 2274 and the pending tray); it needs one canonical form shared by the broker, app and CLI, and an ADR. An agent can still write the twin through the broker. Backend |
| T5 | Data leaves the machine | No `fetch`, XHR, WebSocket or beacon in the window; fonts are local; the CSP refuses every request not to the app | grep: 0 network calls; Index offline note | — |
| T6 | Something sensitive is persisted by the window | Only the keys listed in About → Privacy are written; none holds a value or a name | `ENDPOINT_MAP.md` §7 | The design file keys graph positions by node id in clear; the desktop app hashes them (`pstore.js`). Fine while the design file never ships |
| T7 | A game reads the DOM while a value is revealed (boundary 3) | Games are first-party and reviewed (`GAMES.md`); the host hands a game a frozen, counts-only api; opening CredGames re-masks every revealed value first | gate: "the host hands a game counts only, frozen", "opening CredGames re-masks every revealed value first" | A game script shares the realm and could install a listener at load time. One title ships (CredPong, first-party). A second title is reviewed against `GAMES.md` and runs in a sandboxed iframe loaded from its own file (`sandbox="allow-scripts"`, no same-origin; `default-src 'self'` allows it, an inline `srcdoc` would not) that receives counts by `postMessage`. Whoever adds the second title |
| T8 | The debug handle exposes the app's state | `window.__cm` exists only with `?dev=1` or `credmgr_dev = '1'`; production builds have no handle at all | G-6, G-7, S-12 | — |
| T9 | Clipboard history or another app keeps a copied value (boundary 4) | A copied value is cleared after 30 s and when the vault locks; in the desktop app the shell does the clear | Settings → Security caption, matching the app's S12 | Closed by the app (backend answers, 2026-10-18): the shell sets `org.nspasteboard.ConcealedType` and `TransientType`, this-Mac-only, clears after 30 s and on lock, sleep and quit, and the value never enters the webview |
| T10 | Screen recording or screen sharing captures a revealed value | Values are masked by default and re-mask on a timer; the desktop shell turns window content protection on by default, so a capture of the window is blank (backend answer 2026-10-24, ADR-082 to 084 batch) | — | The user can switch it off in Settings → Security (default on, confirmed first, remembered in `credmgr_prefs`); the environment variable `CREDMGR_CONTENT_PROTECTION=off` is the developer override for support screenshots and wins over the setting. |
| T11 | A tampered build or clipboard malware changes the donation addresses | The addresses in the app match `v2/DONATE.md`; the text asks donors to verify each address | F-6 | Unsigned binaries (L11) make tampering easier to hide. Owner |
| T12 | The supporter code is shared | Honour system by design; the code opens a sealed cosmetic pack (the code is not in the source, see T16) and nothing else | owner decision 2026-10-18 | Accepted: nothing functional is ever gated; a shared word can be guessed offline |
| T13 | A held write carries a value nobody reviews | The pending tray shows node, name, field count, type, sensitivity, time and origin, never a value; nothing lands until Accept | Manual, S20 | — |
| T14 | Shoulder-surfing | Masked by default, reveal window, auto-lock on idle, sleep and screen lock, `⌘L` | Settings → Security | — |
| T15 | A presence-gated action looks like it succeeded | Presence-gated controls say `needs presence` or show the broker's refusal; nothing changes | gate: "Rotate root key shows the presence refusal and changes nothing" | Real presence attestation is open (O-2). Backend + hardware |
| T16 | The sealed extras pack or the usage record leaks or misleads | AES-GCM pack, data tables only, never evaluated; `credmgr_usage` holds dates and flags, no name, id or count | gate: sealed pack, usage dates only | Accepted: a shared code can be guessed offline; the pack is cosmetic |

## Look-alike table (T4)
Cyrillic: а→a е→e о→o р→p с→c у→y х→x і→i ј→j ѕ→s ԁ→d һ→h ԛ→q ԝ→w ӏ→l. Greek: ο→o α→a ν→v ρ→p ι→i κ→k υ→u χ→x. Other: ı→i ɡ→g ɢ→g. Applied after NFKC and lower-casing. ASCII pairs such as `0`/`o` and `1`/`l` are not folded: they are legitimate in real names.

## T16 Supporter pack and usage record (B14, 2026-10-18)
- **Assets:** `credmgr_extras_key` (an AES-GCM key), `credmgr_usage` (dates, flags), `credmgr_cosmetics` (option names).
- **Pack:** AES-GCM ciphertext inside the app, PBKDF2-SHA-256 at 200 000 rounds from a shared code. Data tables only; the page never evaluates anything from it. A wrong code fails to decrypt and stores nothing.
- **Accepted:** the code is a short shared word, so a determined reader of the file can guess it offline. The pack is cosmetic, so the loss is nothing functional. Do not put code, secrets or anything gated in it.
- **Local storage:** none of the three keys holds a node or entry id, a name or a count; `credmgr_usage` holds dates only. All three are allow-listed on read.
- **Network:** none. WebCrypto needs a secure context; without one the code is refused with a message.
