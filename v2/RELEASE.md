<!-- artifact-hardened: NEEDS RE-HARDENING — the diagnostic-log paragraph was edited 2026-11-20 (ADR-159 amendment, launchd output files); the last pass was Approved With Known Risks @ 3ba7435 on 2026-11-14 (its evidence and the K-A..K-F risks are in git: `git show 3ba7435:v2/RELEASE.md`). Re-harden before rc.2 is published. -->

# CredMgr V2 — release notes and install guide

**Pre-release** · macOS (Apple Silicon) · command line + broker + desktop app · **unsigned** (read [Known limitations](#known-limitations) first)

The version is whatever `credmgr --version` prints; the tarball is named
`credmgr-<version>-<target>.tar.gz`. This guide describes the 2.0.0-rc.1 build (see `CHANGELOG.md`). `2.0.0-beta.1`, published on 2026-11-01, lacks Touch ID, restore and the agent wiring, among other things; an
alpha tarball lacks much of what it describes (multi-field entries, `credmgr import`, `notes`, `generate`,
`approve` and most of the app's current screens, among others).

A build of CredMgr V2 is two programs and an app: the `credmgr` command line, `credmgrd`, the broker that
holds your vault's keys and makes every access decision, and the **desktop app**, which is one more client
of that broker. **The command-line tarball contains the first two and the Touch ID helper (`credmgr-presence`), and nothing else.** The app is built by
`scripts/release-app.sh` and ships beside the tarball as `CredMgr.app`, a `.dmg` and a `.zip`. Every screen of
the app reads from the broker and every change goes to it (`apps/desktop/README.md`); a release build has no
demo data and no "mock" badge. The app is **ad-hoc sealed, not signed or notarised** — see
[Opening the desktop app](#opening-the-desktop-app-unsigned). Its real-app verification checklist
(`docs/RELEASE_VERIFICATION.md`) was walked by hand in a built app on 2026-10-18 (190 rows pass, 7 fail, 85 not
pressed; no P0, and the one P1 was fixed), and the later changes were looked at in a built app on 2026-10-27 and
2026-10-31 (sections 12.1 and 13), Touch ID setup and fingerprint unlock on 2026-11-07 (section 14), and a spot re-walk of every screen by hand on 2026-11-07 and 2026-11-08 on the `26da2d3` build (section 15), with the idle lock, a real screen lock, Touch ID setup, fingerprint unlock and `credmgr unlock --touch-id` checked by hand on 2026-11-08; "show seed" was re-walked by hand on 2026-11-08 after its two fixes (`d9e6c7c`, and ADR-149's blur grace in `5e9bb29`; the addendum to section 15); the per-control rows were not pressed again; the "Confirm before showing secrets" setting (ADR-150, below) was checked by hand on 2026-11-08 (the second addendum to section 15), and VoiceOver on 2026-11-08 (`docs/ACCESSIBILITY.md`, two defects found and fixed); the 2026-11-08 design drop (ADR-151) has not yet been looked at in a built app (section 16); the controls added on 2026-11-09 to 2026-11-14 (ADR-156 to ADR-161: change passphrase, start at login, expiry, History, Move to project, Tidy up, the 2FA QR area) are tested against the fixture broker and the shell's bridge tests but have not been pressed in a built app (their rows say "not pressed"). The per-control rows were written from the 2026-10-03 screens and have not
been re-pressed against the final ones. Treat the app as a beta.

## What this pre-release does not do

Each item is explained under [Known limitations](#known-limitations) or in the box it points to.

- **It is not signed or notarised.** The binaries are unsigned and `CredMgr.app` is only sealed ad-hoc, so
  Gatekeeper refuses the app (`spctl --assess` answers "rejected") until the operator signs it with an Apple
  Developer ID. The only provenance is `SHA256SUMS`.
- **Touch ID is optional, macOS-only and needs setting up.** With a Secure Enclave presence key enrolled (ADR-098)
  the presence-gated operations run after a fresh Touch ID; with none enrolled they are still refused with
  `presence_required` (a sealed read with `node_access_denied`). Agents never hold a proof.
- **Your passphrase is still the key.** Touch ID unlock is a second door that works on this Mac only; the
  passphrase and recovery wraps stay, so a copy of the folder on another computer is attackable as before. No
  Windows Hello, TPM or Linux keystore tier exists.
- **No machine lock (ADR-144), no duress code (ADR-145); the `llm.*` broker operations were dropped (ADR-146).** None of these has a command, setting or screen. The coding-assistant wiring is built: `credmgr prompt`, `credmgr agent`, `credmgr mcp --print-config` and Settings → Agents (ADR-141 to ADR-143).
- **macOS on Apple Silicon only.** The tarball and the app are `aarch64-apple-darwin`; there is no Intel, Windows
  or Linux build. `CredMgr.app`, `credmgr` and `credmgrd` all record macOS 13.1 as their minimum
  (`otool -l`, `LC_BUILD_VERSION`; `scripts/release.sh` pins `MACOSX_DEPLOYMENT_TARGET`). None of them has been run on a
  macOS older than the build machine's.
- **A vault this build writes cannot be opened by an alpha build, and there is no downgrade** (first box below).
- **No V1 import in the CLI or the app.** V2 creates its own vault; `credmgr import` reads a `.env` file and nothing else. A read-only copy script, `tools/v1-to-v2/migrate.js`, exists (ADR-097) and never writes to the V1 vault.
- **GitHub CI first ran on 2026-10-31 and 2026-11-01** (pull request #41, `FreeXStudio-Platform/credmgr`, after the repository moved into the FreexStudio organisation, which cleared the billing block of issue #33). `security.yml` (cargo audit, cargo deny, semgrep, the isolation suite, the endpoint matrix, the desktop bridge, the credentials scan) and CodeQL for Rust, JavaScript/TypeScript, Python and Actions passed, with no open alert on the pull request. `build.yml` (dispatch-only) ran the workspace on macOS 15 and Ubuntu 22.04 and the desktop app also on Windows (the broker cannot compile on Windows yet); its first runs found a Windows build defect (CRLF line endings; path separators in the build verifier), a racy test and the retirement of the macOS 14 image, all fixed in the same pull request. The run ids and results are on the pull request. Those runs were the beta.1 tree; later changes (pull requests #44 to #53) were checked by the pull-request gates.
- **The window's idle lock and a real screen lock were checked by hand on 2026-11-08** (auto-lock set to 5 minutes;
  Ctrl-Cmd-Q), and both locked the vault (`docs/RELEASE_VERIFICATION.md` section 15). The "Confirm before showing secrets" setting (ADR-150) was checked by hand
  the same day (the addendum to section 15; the refusal after 60 seconds is covered by a broker test, not by hand), and a
  VoiceOver pass found and fixed two defects (#22, closed; `docs/ACCESSIBILITY.md`). NVDA waits for a Windows build (2.1).
- **No update mechanism and no published Homebrew tap.** Nothing in the app or the broker makes a network request.

> **Upgrading from a 2.0.0-alpha build — and not going back.** Your vault opens unchanged: there is no
> migration step, and every existing entry is read in place as a single field (`docs/03_DATA_MODEL.md`).
> **A vault that a beta.1 build has written to cannot be opened by an alpha build.** An alpha binary refuses a
> version-2 entry envelope (`UnsupportedVersion(2)`), and it reads a manifest that carries `hasTotp: true` as
> tampered, because it drops the key when it re-serialises and the signature no longer matches. A build
> older than beta.1 also drops the seal records of any node you sealed, because they now live in the signed
> registry (the archives stay on disk). The first edit of an entry re-seals just that entry; nothing else
> changes. **Before you upgrade, copy both the vault directory and
> `~/Library/Application Support/credmgr-state`** (copying both is the quickest backup; `credmgr backup` also writes a complete encrypted archive - entries, notes, sealed-node and removed-entry archives, rotation history, the audit log, the keys and the rollback counter - that `credmgr restore` rebuilds into an empty directory) somewhere an alpha build can use if you ever need to go back.

> **If you ran a 2.0.0-alpha.4, alpha.5 or alpha.6 build, read this too.** Those builds wrote each
> login's session token into the plaintext audit log, where any process running as you could read and
> replay it. Stop the old `credmgrd` (a restart destroys every login) and start the new one; the
> `cmt_…` strings the old audit files still contain are then dead credentials. Full detail, and what
> to do if you cannot upgrade at once: [`SECURITY.md`](SECURITY.md), "Session token in the audit log".

## What is in a release

The command-line tarball:

```
credmgr-<version>-<target>/
  bin/credmgr                       the CLI — talks to credmgrd, never decrypts anything itself
  bin/credmgrd                      the broker — the only process that ever holds a key
  bin/credmgr-presence              the Touch ID helper (Secure Enclave); without it beside the binaries Touch ID is unavailable
  packaging/com.credmgr.brokerd.plist   launchd unit that keeps credmgrd running
  sbom/                             CycloneDX bills of materials for both binaries
  RELEASE.md  CHANGELOG.md  SECURITY.md  LICENSE
  SHA256SUMS                        the tarball's own manifest: every file above except itself
```

and, beside it in `dist/` (the folder `scripts/release.sh` and `scripts/release-app.sh` fill):

```
credmgr-<version>-<target>.tar.gz              the command-line tarball
credmgr-desktop-<version>-<target>.dmg  and  ....app.zip  and  CredMgr.app    the desktop app
credmgr-<version>-sbom-{credmgr,credmgrd,desktop}.cdx.json    the bills of materials
SHA256SUMS                                     one line per file in the folder
```

## 1. Verify what you downloaded

The binaries are **not code-signed**, so the checksum file is the only provenance there is. Check
it against the copy published with the release — not a copy that came in the same download.

The folder's `SHA256SUMS` lists every file the release published. You will usually have only some of them,
so ask `shasum` to check just those, and require that the line for the file you care about says `OK`
(`--ignore-missing` passes silently when nothing matched):

```bash
# in the folder holding what you downloaded, and the published SHA256SUMS
shasum -a 256 -c --ignore-missing SHA256SUMS      # one OK line per file you have; any FAILED means stop
# the command-line tarball also carries its own manifest; after `tar -xzf`:
cd credmgr-<version>-*/ && shasum -a 256 -c SHA256SUMS
```

If any line says `FAILED`, stop: do not run the binaries. `scripts/fresh-install-check.sh` is this whole
procedure as a script: it copies only the tarball and `SHA256SUMS` into an empty folder, runs the commands
above, unpacks, runs `credmgr --version`, creates a throwaway vault and drives the real journey. The tarball
is written deterministically (sorted entries, a fixed timestamp, no user or group names), and
`scripts/release.sh --verify` re-checks a `dist/` folder — the sums, the tarball, the bills of materials, the
app's seal, and that no build-machine path survived in a binary; `scripts/release-selftest.sh` corrupts copies
of a good release in many different ways and requires `--verify` to refuse every one.

**Reproducibility, as measured on 2026-10-03:** rebuilding the same commit in the same checkout is
byte-identical; in a second checkout at another path the bills of materials are identical and the binaries
differ in 47–48 bytes — the Mach-O UUID and the ad-hoc code-signature hash that covers it — and nowhere else.
So the published `SHA256SUMS`, not a rebuild of your own, is the reference.

## 2. Install

```bash
tar -xzf credmgr-<version>-*.tar.gz
cd credmgr-<version>-*/
sudo cp bin/credmgr bin/credmgrd bin/credmgr-presence /usr/local/bin/
# Unsigned binaries arrive quarantined; macOS will refuse to run them until this is cleared.
# Do this only after step 1 passed.
sudo xattr -d com.apple.quarantine /usr/local/bin/credmgr /usr/local/bin/credmgrd /usr/local/bin/credmgr-presence 2>/dev/null || true
credmgr --version && credmgrd --version
```

Copy all three. `credmgr-presence` is the Touch ID helper: the binaries look for it next to themselves (then in
`../libexec` and `../Resources`). A release build of `credmgr` and `credmgrd` ignores `CREDMGR_PRESENCE_HELPER` and
accepts only the production helper (ADR-148); the desktop app still honours that variable (a deferred item, see
`SECURITY.md`). Without it, Touch ID presence and
Touch ID unlock are unavailable and the presence-gated operations answer `presence_required`.

**Homebrew** — a formula is prepared (`packaging/homebrew/`) that installs this same unsigned tarball on Apple
Silicon, including the `credmgr-presence` Touch ID helper, filled from the published `SHA256SUMS` by `fill-formula.sh`. **No tap exists yet and nothing is
published**; until the operator creates one, use the steps above.

### Opening the desktop app (unsigned)

`CredMgr.app` is sealed ad-hoc: the seal makes the bundle internally consistent, but it is not a Developer ID
signature and **Gatekeeper still refuses it** (K-5; an Apple Developer ID is an outstanding operator item).
After the checksums have passed, open the `.dmg` (or unzip the `.zip`) and drag `CredMgr.app` to
Applications. Then either try to open it once and approve it under *System Settings → Privacy & Security →
Open Anyway*, or clear the quarantine flag yourself:

```bash
xattr -dr com.apple.quarantine /Applications/CredMgr.app      # only after the checksums passed
```

The app talks to a running `credmgrd` (steps 3 and 4 below). With no broker it shows "broker unreachable"
and a Retry button, never stale data. The app carries its own `credmgrd` in `CredMgr.app/Contents/MacOS/`
(ADR-157), built from the same commit and stamped like the tarball's, and that screen offers "Start the broker
at login", which starts it now and at every login (step 3).

## 3. Start the broker

Either run it in a terminal you leave open:

```bash
credmgrd
```

or let the app do it: Settings › Security › Start at login (or the button on the "broker not running"
screen) writes a per-user LaunchAgent, `~/Library/LaunchAgents/com.credmgr.brokerd.plist`, that runs the
`credmgrd` inside `CredMgr.app` and loads it with `launchctl bootstrap gui/$(id -u)`; never root, and
turning it off asks first, because it stops the broker (ADR-156, ADR-157). Without the app, let launchd keep
the tarball's `credmgrd` running across logins and crashes by hand:

```bash
cp packaging/com.credmgr.brokerd.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.credmgr.brokerd.plist
```

The vault lives in `~/Library/Application Support/credmgr` (override with `CREDMGR_VAULT_DIR`).
It must not be inside a git working tree — `credmgr init` refuses that. Its rollback counter lives
in `~/Library/Application Support/credmgr-state`. If you move a vault to another machine or
account without that directory, the first unlock refuses (a missing counter looks exactly like a
rollback attack); start `credmgrd` once with `CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1` to accept
it, then restart it normally.

To attach a log to a bug report, start the broker with `CREDMGR_DIAG_LOG=1` (for the login agent,
`launchctl setenv CREDMGR_DIAG_LOG 1` first): it writes `~/Library/Logs/credmgr/credmgrd.log` and the app
`desktop.log` beside it, with operation names, results and timings but no names, values or paths, at most
3 MiB, off by default (ADR-159; `credmgr status --log` prints where). The login agent writes no output files of its own (its stdout and stderr go to `/dev/null`, ADR-159
amendment 2026-11-20); builds before that left `brokerd.log` and `brokerd.err.log` in the same folder, which
the next "Start at login" install deletes.

## 4. Create the vault

```bash
credmgr init
```

It asks for a passphrase, then prints a **root recovery code once**. Write it down on paper and
keep it offline — together with your passphrase it is the only way back in if you lose your
two-factor device. It then asks you to retype it; nothing is written until you do. The command line takes any
non-empty passphrase, so choose a long one (see K-5). The desktop app's first run shows the same code but lets
you skip the retype ("Skip for now"), accepts a passphrase of four characters or more (eight or more is only
recommended), and treats the second factor as optional. `init` also creates the vault's **Orphaned** node and its cold key, which is
what lets you seal a project later (step 9).

## 5. Unlock, and use it

```bash
eval "$(credmgr unlock <<< 'your passphrase')"     # exports CREDMGR_TOKEN for this shell
credmgr set API_KEY --node global <<< 'the-value'  # values come from stdin, never argv
credmgr get API_KEY --node global
credmgr lock
```

The token `unlock` exports is **your** login: it reaches every project in the vault until the
vault locks (explicitly, when the desktop app locks it on sleep, on a screen lock or when its window is closed, or when
the broker restarts) or until it goes 15 minutes unused. **Never
export it into a shell an AI agent runs in** — see K-6 below.

## 6. Projects, and scoping an agent to one

```bash
credmgr node create acme --parent global --label "Acme" --workdir ~/code/acme
credmgr set DEPLOY_TOKEN --node acme <<< 'the-value'
```

A process started inside `~/code/acme` (an AI coding agent, a script) is scoped to `acme`
automatically — it can read `acme` and `global`, never another project. Re-bind or add
directories later with `credmgr node workdir acme <dir>…`.

If such an agent writes a secret while the vault is locked, it is not stored yet — it waits for
you in the review tray, across restarts:

```bash
credmgr pending                                  # what is waiting, on every project
credmgr pending accept <entry> --node acme       # or: credmgr pending discard <entry> --node acme
```

## 7. Two-factor

```bash
credmgr gate enroll         # prints an otpauth:// URI for your authenticator, then asks for a code
```

It prints ten one-time recovery codes once — keep them offline. From then on `credmgr unlock`
answers `two_factor_required`; complete it with `credmgr gate verify` (it asks for the code, or reads it from stdin). To replace the
authenticator later, run `credmgr gate enroll` within five minutes of a `gate verify` — replacing
a gate needs its second factor, fresh.

Lost the authenticator **and** every recovery code? Your passphrase plus the root recovery code
from step 4 reset the gate:

```bash
credmgr gate recover        # asks for both, then: credmgr unlock, credmgr gate enroll
```

Two-factor stops `credmgrd` from unlocking your vault without a fresh code. It is **not** part of the
encryption: see "Two-factor guards the door, not the safe" under Known limitations.

Once a gate is enrolled it also guards the nodes that ask for it. A node's policy is `never`, `reveal` (the
default) or `always` (`credmgr node policy <id> --reason "..." --require-two-factor never|reveal|always`). At
`reveal`, an agent, an MCP tool or a grantee that asks for a value gets `two_factor_required` unless a person has
proved the second factor in the last five minutes; at `always` the same holds for reading the node at all. Your own
login is not asked. To open the window, run `credmgr gate verify` in the shell that holds your login, or choose
"Give second factor" in the app. The window is **vault-wide** for a node with no gate of its own: one code opens it for every such node that asks, for every
caller, for five minutes, and a lock or any node-policy change ends it. A node can have its own second-factor secret (ADR-135): `credmgr gate enroll --node <id>`, then `credmgr gate verify --node <id>` (the code is read from a prompt or stdin, like the vault-wide one) to open that node's window (see Known limitations).

## 8. Entries with several fields

An entry holds any number of fields, each with a free-text label you choose. Values come from stdin; labels and
ids may be flags.

```bash
credmgr set vps --node acme --bulk <<'EOF'          # one paste -> ONE entry; "label: value" per line
host: db.example.com
username: deploy
password: <the-value>
EOF
credmgr field ls vps --node acme                     # labels, types, masking and ids — never a value
credmgr get vps --node acme --field password         # one value
credmgr get vps --node acme --all                    # every field; --json for a machine-readable list
credmgr field add vps --label "recovery phrase" --node acme    # the value comes from stdin
credmgr field mv vps --field password --to 0 --node acme       # a position, counted from 0
credmgr field rm vps --field-id f_1a2b3c4d --node acme         # undoable: credmgr undo <audit id> --node acme
```

`credmgr get` on an entry with several fields and no selector refuses and lists the labels rather than
guessing (known issue: today it does so *after* asking the broker to reveal the entry, so every value reaches the CLI
process and one reveal of the entry is audited, though none is printed; `credmgr field ls` lists labels without one). `set --bulk` on an existing entry replaces its whole field list. A field edit keeps the entry's
history. AI agents get `credmgr_get_metadata` (labels, types, masking and ids, never a value) and
`credmgr_field_add` / `_update` / `_remove` (and `fields` on create, update and rotate) — never a reorder and
never a grant.

Names are compared in one canonical form (case, width and invisible characters folded, a table of look-alike
letters applied): a new name that differs from an existing one in the same node only in those ways is refused
as `entry_exists`, for an agent too, while the name you typed is stored as typed. A name that mixes Latin with
Greek or Cyrillic letters is accepted with a warning (`credmgr` prints it on stderr). An entry name is at most
200 characters and a node label 1 to 120; vaults written earlier are not re-checked.

## 9. Importing, notes, sealing and node settings

```bash
credmgr import ./service.env --node acme        # a .env file, all-or-nothing, values never printed
credmgr notes set acme --file ./notes.md        # a sealed markdown note on the node (stdin works too)
credmgr notes show acme
credmgr node rename acme "Acme (production)"    # the label only; the id never changes
credmgr node policy acme --reason "tighten after review" --agent-access read-only
credmgr node seal acme                          # moves the project's entries to Orphaned, re-encrypted to the cold key
credmgr node restore acme                       # within seven days, puts it back exactly as it was
credmgr move stripe-key --node acme --to billing # re-sealed to the other project's key; Touch ID every time
credmgr doctor --scan                           # Tidy up: duplicates, weak, misfiled, stale; never a value
```

`import` reads `NAME=value` lines (quotes, `export`, comments). A quoted value whose closing quote is
missing, or a name repeated inside the file, refuses the whole file and names the line number(s),
never what a line held. A name that already exists on the node refuses the whole batch too, and the
broker's answer names that entry, not a line; nothing is created. It does not touch your `.env` file — delete it yourself once you have checked the
import. `notes set` refuses empty input, so a failed pipe cannot erase a note; `notes clear` is the
only deletion. A `node policy` change that would *widen* who can read the node needs a live presence
check (a Touch ID proof, ADR-098); the CLI asks for it itself, and without an enrolled key it is refused. `credmgr help` lists every flag.

Sealing is not deleting. A project that still has sub-projects cannot be sealed (seal them first), a sealed
project's id cannot be reused while its archive exists, and after seven days it can no longer be restored (see K-7).
`credmgr doctor --purge-expired-seals` (with `--dry-run` it only lists) destroys, for good, the retained originals of
every project sealed more than seven days ago; a plain `credmgr doctor` never does, and neither does the app's plain
Doctor (its "Doctor with purge" row asks first).

`credmgr move` (or "Move to project…" on an entry in the app) moves one entry in one crash-safe step: grants on it are
revoked and the earlier values kept for Undo are dropped, and both are counted in the answer; a name the other project
already uses is refused (ADR-158). `credmgr doctor --scan` (Settings › Maintenance › Tidy up… in the app) reports shared
values, near-identical names, misfiled, weak, mistyped, expired, expiring and stale entries and changes nothing; a
misfiled entry's line is the `credmgr move` that fixes it (ADR-161). Both are yours alone: no agent or MCP tool can run them.

## 10. Touch ID (macOS)

Touch ID is optional and needs the `credmgr-presence` helper beside the binaries (step 2). Three things, in order:

```bash
credmgr presence enrol          # once, unlocked as the owner: enrols this Mac's Secure Enclave presence key
credmgr touch-id enable         # optional: seal the root key to the Secure Enclave as a third wrap
credmgr unlock --touch-id       # later: open the vault with a fingerprint instead of the passphrase
```

In the app the same steps are Settings > Security > Touch ID, and the Lock screen shows a fingerprint icon beside the
passphrase field (dimmed, with a set-up hint, until Touch ID is on). `credmgr presence status` lists the enrolled keys.
Your passphrase and recovery code remain valid (K-5).

`credmgr unlock --touch-id` is refused with an agent token or from inside a registered project folder; run it
elsewhere or use the passphrase. The Touch ID dialog names the process that asked: that is a hint, not proof, so
cancel any request you did not start. A dismissed or timed-out prompt counts toward the unlock back-off. If you set up
Touch ID unlock on a build from before ADR-148, turn it off and on again before the next root-key rotation.

### Confirm before showing secrets (optional, ADR-150)

Off by default. Turn it on in the app: Settings > Security > **Confirm before showing secrets**, then choose the
**trust window** (1, 5, 15 or 60 minutes; 5 by default). In Pro mode two more rows appear: **When to ask** (once per
trust window, or every time, where one confirmation covers one request made within 60 seconds) and **Which secrets**
(all, or only entries whose sensitivity is high or critical). The setting is stored in the signed registry on the
`global` node's policy (`revealConfirm`); the CLI has no flag for it.

While it is on, revealing a value, the app's copy and a one-time code (`entry.reveal`, `totp.code`) answer
`confirmation_required` until your login confirms, and so do approving a waiting request from a login (denying never
asks) and collecting the value an approval released:

```bash
credmgr get API_KEY --node global   # at a terminal: asks for Touch ID (if set up on this Mac), else the passphrase on stderr, then retries once
credmgr confirm <<< 'your passphrase'   # from a script or pipe: confirm first (the passphrase is the first line of stdin)
credmgr confirm --touch-id              # or with a fingerprint
```

From a pipe, or with `CREDMGR_NO_PROMPT` set, `credmgr get` does not prompt: it prints the refusal and says to run
`credmgr confirm` first. A wrong passphrase, or a Touch ID confirmation that does not verify, counts in the same back-off as a wrong unlock,
and a successful confirmation never resets it. In "every time" mode, locking a project, approving your own request and
collecting the value costs two confirmations. The confirmation belongs to
the login in `CREDMGR_TOKEN`, so later commands in any shell that holds that token use it; it lives in `credmgrd`'s
memory only and every lock ends it. Turning the setting off, choosing a longer window, going back from "every time"
or narrowing it to high and critical needs a confirmation made in the last 60 seconds; turning it on or making it ask
more does not. Under "only high and critical", lowering an entry's sensitivity out of that band also needs one.
Agents are not asked: their reads answer to the node's security level (an agent token, or a call with no token from
inside a registered project folder). The Touch ID seed display, a sealed entry and an export already need their own Touch ID proof
and are not asked again.

## 11. Backup and restore

```bash
credmgr backup [--retain N]                      # a complete encrypted archive of the vault; passphrase from stdin
credmgr restore <archive> --to <empty dir>       # rebuilds a vault from the archive; passphrase from stdin
```

`credmgr restore` is offline. Its target (`--to`, default the vault directory) must be empty or absent: it never
merges into or overwrites an existing vault (ADR-112). An existing rollback counter in the state directory is kept,
never lowered: if it is ahead of the restored vault, the first unlock refuses the vault as rolled back, so restore
with a fresh `--state-dir` when you mean to go back. After it, run `credmgr unlock` with the vault passphrase.

## Known limitations

Read these before trusting this build with anything that matters. Full detail, with bounds and
owners, is in `docs/PHASE8_AUDIT_REPORT.md §4`.

- **K-5 · Your passphrase is the key; Touch ID is an extra door, not a replacement. Unsigned binaries.**
  The vault's root key is stored in the vault folder encrypted two ways:
  under a key derived from your passphrase with Argon2id (256 MiB of memory, 3 passes, 4 lanes), and under the
  256-bit recovery code printed at `credmgr init`. If you turn on Touch ID unlock (`credmgr touch-id enable`, or
  Settings > Security > Touch ID) a third wrap seals the root key to this Mac's Secure Enclave (ADR-098); it opens
  only on this Mac. The first two wraps stay, so a copy of the vault folder can still be attacked offline on any
  other computer, slowed only by the Argon2id cost of each passphrase guess. Use a long, unique passphrase and
  keep the recovery code offline.
  While the vault is unlocked, `credmgrd` holds the root key and every unlocked project key in memory until it
  locks (idle timeout or `credmgr lock`; the desktop app also locks it when the Mac sleeps, the screen locks, the session switches or its window is closed, but a daemon running without the app does not); it does not lock its memory pages or block debuggers, so
  software able to read its memory — anything running as root, for example — can read those keys. The binaries and the app are not code-signed
  or notarised; check them against `SHA256SUMS`. Touch ID does not need signing; signing and notarisation
  (`scripts/sign-notarise.sh`) wait for the operator's Apple Developer ID. Windows Hello, TPM and Linux keystore
  wraps are planned and are not part of this release. Presence is covered under K-1 below.
- **Two-factor guards the door, not the safe.** With two-factor on, `credmgrd` will not unlock your vault
  without a fresh code. That check is made by `credmgrd`, not by the encryption: anyone who has your passphrase
  or your recovery code *and* a copy of your vault folder can decrypt it without the second factor (the
  disaster tool `scripts/emergency-decrypt.mjs` does exactly that, by design). Treat each of the passphrase and
  the recovery code as a complete key to your vault.
- **K-6 · An exported login reaches every project.** Keep `CREDMGR_TOKEN` out of shells where an
  AI agent runs; lock the vault when you are done.
- **K-7 · Sealing a project, and what is still missing.** `credmgr node seal <id>` moves a project's entries into
  the Orphaned node, re-encrypted to its cold key; the seal is recorded in the signed registry, so it survives a
  restart and a crash in the middle of it cannot lock you out. Within seven days `credmgr node restore <id>` puts
  the project back exactly as it was. After that it can no longer be restored: the Orphaned copies stay
  encrypted on disk and only the desktop app can read them, one entry at a time, after Touch ID, a fresh second
  factor and the owner's login (`orphan.reveal`; no CLI command, no MCP tool; ADR-098), and the retained originals stay on disk until you run `credmgr doctor --purge-expired-seals`,
  which destroys them. On this tier the cold key is protected by your vault's root key: "cold" means `credmgrd`
  never loads it and offers no way to use it, not that hardware guards it. Writes made while the vault was
  locked also survive a restart: they wait in the review tray until you accept or discard them. **A request for
  a value while the whole vault is locked** is recorded (`approval_pending`), not refused: `credmgr approvals`
  lists what waiting agents ask for (without decrypting anything), and `credmgr approve <request>` (or the Lock
  screen) releases that one value with your passphrase, plus your authenticator code when two-factor is on, while
  the vault stays locked; a recovery code is not accepted there, and wrong tries count toward the unlock back-off.
  A request nobody decides is denied after two minutes. There is no screen and no command to decide a request while
  the vault is unlocked: an agent's request to a locked *node* is decided by unlocking that node.
- **K-8 · Rollback protection is software-only.** Someone who has your passphrase *and* can
  restore an old copy of both the vault directory and `~/Library/Application Support/credmgr-state`
  can roll the vault back — including to before two-factor was on. Keep backups of both out of
  anyone else's reach.
- **The desktop app is unsigned and its per-control checklist has not been re-walked** (a spot re-walk of every screen is section 15 of `docs/RELEASE_VERIFICATION.md`). What the app does not have: a control to
  delete an entry (use `credmgr rm`; `credmgr undo <audit id> --node <id>` brings one back), a control to edit a
  node's note (the app reads it; use `credmgr notes set`), a screen for deciding an agent's request while the vault
  is unlocked (the Lock screen decides one while it is locked), and search that looks inside values (search
  matches names only). Its Help text says a note entry is "masked until you reveal it"; a note's text field is
  not masked. There is no import from V1: V2
  creates its own vault, there is no migration from V1, by design (`docs/11_MIGRATION.md`); `credmgr import`
  reads a `.env` file only.
- **Presence-gated operations need an enrolled Touch ID key (K-1, ADR-098).** Revealing a TOTP seed (the broker releases it to the owner; the app's "show seed" displays it and never copies it; the CLI has no command), creating
  grants, re-parenting nodes, reading a full audit record, widening a node's read reach, rebuilding the registry
  (`credmgr doctor --rebuild-registry`), **replacing the root key** (`maintenance.rotate_root`, from the app; the
  CLI has no command for it) and opening a sealed entry run after a Touch ID proof (or the device password where
  no fingerprint is enrolled): the CLI and the app ask for it themselves. **Without a presence key enrolled they
  answer `presence_required`**, and the app says so and offers to set Touch ID up. Agents and fixture tokens never
  hold a proof. macOS only. The sensor needs a human finger, so the automated tests use an unattended helper; the
  live checks (Touch ID setup and fingerprint unlock by hand in the built, unsigned app on 2026-11-07, and again with `credmgr unlock --touch-id` from a normal folder and from a project folder on 2026-11-08) are in `docs/RELEASE_VERIFICATION.md` sections 14 and 15.
- **Confirm before showing secrets guards an unlocked Mac, not a copied folder (ADR-150).** It does not stop malware
  running as you (it can wait for you to confirm, or read the screen or memory), someone who knows your passphrase,
  changes that are not reads (edits, grants, agent set-up), `search.content` (which answers ids and names only) or
  `notes.read` (context, not credentials). "Only high and critical" trusts the entries' sensitivity labels; a person
  who can confirm can relabel. It was checked by hand in the built app on 2026-11-08 (`docs/RELEASE_VERIFICATION.md`, the addendum to section 15).
- **The second factor is vault-wide for a node with no gate of its own.** A node can have its own second-factor secret (ADR-135, `credmgr gate enroll --node <id>`). A node without one shares the vault gate: a code given for one
  such node opens the window for every such node that asks, for every caller (agents, MCP, CLI),
  for up to five minutes. The
  window cannot be extended, ends on a lock or any node-policy change, and your own login is never asked.
- **K-9 · A truncated audit tail is re-signed by the next request.** Someone who can write to the audit file can
  remove its last lines, and `credmgr verify` notices only until the broker handles one more request. Editing or
  removing any earlier line is still detected. Nothing readable is exposed; the last few decisions can be hidden.
  Detail: `docs/PHASE8_AUDIT_REPORT.md §4`.
- **A beta.1 vault cannot go back to an alpha** — see the box at the top.
- **A stored two-factor seed shorter than 80 bits is refused** (`totp.code` answers
  `malformed_request` naming the length); 80 bits and up work. That floor is below RFC 4226's 128 on
  purpose — a seed is issued by the service that checks the codes (`docs/14_DECISIONS.md`, ADR-077).
- **A request line is read without a size limit,** so a process running as you could make `credmgrd` allocate
  without bound; the largest legitimate request is a 64 MiB batch. Open (`docs/PHASE8_AUDIT_REPORT.md §4`).

## Build it yourself

```bash
git clone https://github.com/FreeXStudio-Platform/credmgr.git && cd credmgr/v2
scripts/release.sh              # the CLI + broker tarball; refuses a dirty tree; --dev builds one stamped "dirty"
scripts/release-app.sh          # the desktop app (macOS): CredMgr.app, .dmg and .zip, added to the same dist/
scripts/release.sh --verify     # re-check dist/ without building anything
scripts/fresh-install-check.sh  # a fresh install of the tarball: checksums, unpack, a real vault, the whole journey
```

Needs Rust 1.78+ (the workspace's MSRV, pinned in `rust-toolchain.toml`) and the Xcode command-line tools (`swiftc`, which builds the Touch ID helper). The output lands in `v2/dist/`.
`release.sh` stamps each binary with the commit it was built from, remaps the build machine's paths out of the
binaries, writes CycloneDX bills of materials, and never signs, notarises, uploads or publishes anything. The
desktop app needs Node 22.12+, the Tauri 2 macOS prerequisites and its own pinned Rust toolchain
(`apps/desktop/README.md`). `release-app.sh` builds with `cargo build --locked`, bundles with `tauri bundle`
(not `npm run tauri build`: the reason is in the script's header), seals the bundle ad-hoc, and then **starts
the built app against a throwaway vault and requires a real window** before it passes.

Before calling a build good, run the whole workspace suite (`cargo test --workspace`), `cargo test` in
`apps/desktop/src-tauri`, the front-end gates in `apps/desktop` (`npm test`, `npm run test:e2e`,
`npm run test:design`, `npm run test:real`), the real-binary journeys (`scripts/e2e-journey.sh` and
`scripts/e2e-fields.sh`, which drive the real binaries through init, unlock, a restart, a locked write,
two-factor, a second daemon, an import, a note, a seal and a restore, and check that no plaintext secret or
bearer-shaped string reached the vault directory; the alpha.6 compatibility segment of `e2e-fields.sh` fails unless
the alpha.6 binaries are supplied through `LEGACY_BIN_DIR`; and `python3 scripts/endpoint-matrix.py`), and, last, the
real-app pass in `docs/RELEASE_VERIFICATION.md`.
