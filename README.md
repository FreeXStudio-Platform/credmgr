<!-- artifact-hardened: Approved With Known Risks @ 63bc0fc on 2026-11-08 via three-pass-v1. Evidence: this pass against 63bc0fc (ADR-153 plan and ADR-154 licence core: core tests 236 green incl. 12 licence tests, cargo fmt and clippy clean, corpus_check stamps only, gen_help --check and release_verification_check clean, secret scan clean; K-25 cross-checked against crates/mcp/src/tools.rs credmgr_get → entry.reveal); earlier: prior verifier passes (3abb4fe, 320a8f2) and this pass 3 against the code at 9bc33d7 (corpus_check broker_ops 76; 27 error codes; highest ADR 152; --security-level strict alias of stored sealed in cli main.rs; "Strict (stored as sealed)" in core agentcfg.rs and brokerd ops.rs; search entries, hide seed, re-masks in, Settings › Security groups in apps/desktop); independent ADR-150 review P0/P1 fixed with refusal tests (19ccf39); CI green on PRs #56–#60 (17 checks each); full gates.sh green at dbef0c7 incl. legacy alpha.6; VoiceOver pass 2026-11-08, two defects fixed (ACCESSIBILITY.md, #22 closed); Touch ID, idle and screen lock, ADR-150 confirm checked by hand (RELEASE_VERIFICATION §14, §15 and addenda); corpus_check, gen_help --check, release_verification_check clean; secret scan clean. Known risks: K-A not signed or notarised (bound: Gatekeeper quarantine, SHA256SUMS only provenance, Apple Silicon only; owner: operator; resolution: scripts/sign-notarise.sh with a Developer ID before publishing rc.1); K-B per-control re-press of all rows and the built-app look of the 2026-11-08 design merge (§16) not done by hand (bound: §15 spot re-walk of every screen plus e2e/design audit; owner: operator; resolution: record in RELEASE_VERIFICATION before publishing); K-D Touch ID dialog residual, PHASE8 K-21 (bound: refused to identified agents, dialog names the requester, back-off after five; owner: backend and the user at the dialog; resolution: stated in SECURITY.md, none planned for 2.0.0). K-E F01, an agent that can reveal a value receives it into its model context, PHASE8 K-25 (bound: Guarded default holds high/critical reveals for approval, Strict holds all, agents cannot lower sensitivity, own node only; owner: backend; resolution: use-without-reveal in 2.1, docs/26 Phase 1). Not a claim about anything after 63bc0fc. -->

<div align="center">

# CredMgr

**A local, offline credential vault built for the moment you hand credentials to an AI agent.**

Agents get only the project they are scoped to, and a sensitive value is released only when you approve it. Encrypted at rest · no account · no cloud · no telemetry · the V2 broker makes no network calls

[Install](#install) · [How it works](#how-it-works) · [Limitations](#what-the-current-build-does-and-does-not-do) · [Security](#security) · [License](#license) · [Support](#support)

**[FreexStudio](https://freexstudio.com)**

</div>

---

> **Pre-release software.** The current V2 build is **unsigned and not notarised** and your passphrase is the
> key. On a Mac with a Secure Enclave you can add Touch ID as a second door (presence checks and unlock; it is
> not a replacement for the passphrase, and two-factor guards the door, not the safe). Read
> [what the current build does and does not do](#what-the-current-build-does-and-does-not-do) before you
> store anything you cannot rotate.

## What it is

Every project you start, and every AI coding agent you point at it, produces credentials: API
keys, database URLs, deploy tokens, webhook secrets, SSH keys. They end up in `.env` files in a
dozen repositories, in a Notes app, in a screenshot, or typed straight into a chat window — and
an AI agent pointed at the repository can read all of it.

CredMgr replaces that with **one encrypted vault per machine and one boundary per project**.
Your shell, your scripts and your AI agents fetch a value **by name, at the moment they need
it**; nothing is copied somewhere it will be forgotten. The vault never leaves your machine. In
V2 the process that holds the keys, the broker, has no network client at all — it is not switched
off, it is not compiled in, and the dependency policy ([`v2/deny.toml`](v2/deny.toml)) turns
adding one into a build failure. (V1, the legacy line, serves a local dashboard on loopback and
has explicit commands that may contact a server *you* choose; its
[privacy policy](v1/PRIVACY.md) says exactly where.)

| | Version in this tree | What it is |
|---|---|---|
| **[V2](v2/)** — start here | `2.0.0-rc.1` ([`v2/Cargo.toml`](v2/Cargo.toml)) | A Rust rewrite. Each project is a real cryptographic boundary. Ships a command line (`credmgr`), a broker daemon (`credmgrd`) and an MCP server (`credmgr mcp`), and a desktop app wired to the broker. macOS (Apple Silicon) only. `2.0.0-beta.1` was published on 2026-11-01 as a [GitHub pre-release](https://github.com/FreeXStudio-Platform/credmgr/releases) (unsigned); it predates Touch ID, agent wiring, restore, node gates and twenty-one broker operations (55 → 76). This tree is `2.0.0-rc.1` (unreleased; see `[Unreleased]` in [`v2/CHANGELOG.md`](v2/CHANGELOG.md)), and a vault beta.1 or later has written to cannot be opened by an alpha build. |
| **[V1](v1/)** — legacy | `1.9.1` ([`v1/package.json`](v1/package.json)) | The original Node.js vault: CLI, local web dashboard, Node SDK and MCP server. Installed from source. |

V1 and V2 are separate products with separate vaults, and **there is no migration between them**
([`v2/docs/11_MIGRATION.md`](v2/docs/11_MIGRATION.md)). New users should start with V2. Existing V1
users are not forced to move; see [V1](#v1--the-legacy-nodejs-line) below.

## Roadmap

`2.0.0-beta.1` (published) and this tree, `2.0.0-rc.1`, are free and ungated. This tree is the rc.1 candidate: it is published only once it is signed and notarised with an Apple Developer ID. Next, in this order and with no dates: `2.0.0-rc.1` (this tree, signed and notarised; Touch ID, `credmgr similar` (ADR-121) and the read-only V1→V2 copy script `tools/v1-to-v2/migrate.js` (ADR-097) are already built),
`2.0.0` (the first stable release, macOS on Apple Silicon only), `2.1` (the doctor's duplicate and wallet-bundling scan, the V1 copy inside the app, the machine lock, the Windows and Linux keystores and named-pipe transport, the org vault with sync and licensing: moved here by [ADR-147](v2/docs/14_DECISIONS.md); agents that use a credential without the value reaching the model come first in 2.1),
then the licence and store editions, encrypted backup and cross-device sync as ciphertext, and remote agents (a one-time licence in tiers; a failed licence never locks your vault: [ADR-153, ADR-154](v2/docs/14_DECISIONS.md)).
**Future versions, extra platforms and devices may not be free.** Versions already released stay under the licence they came with. This list is a direction, not a promise; the licence, vault-hygiene and later items are not built yet: [`v2/docs/24_LICENCE_AND_DONATION_PROOF.md`](v2/docs/24_LICENCE_AND_DONATION_PROOF.md), [`v2/docs/25_VAULT_HYGIENE.md`](v2/docs/25_VAULT_HYGIENE.md) and [`v2/docs/PRODUCTION_PLAN.md`](v2/docs/PRODUCTION_PLAN.md).
If CredMgr is useful to you, please keep using it, tell us what breaks, and consider a donation: it is what lets us keep building it.

## How it works

In V1 a project is a *label* on a credential. In V2 a **node is a boundary**.

```
                    ┌───────────┐
                    │  GLOBAL   │        everything can read it
                    └─────┬─────┘
      ┌──────────┬────────┼────────┬──────────┐
   ┌──┴──┐   ┌───┴─┐  ┌───┴─┐  ┌───┴─┐   ┌────┴───┐
   │  A  │   │  B  │  │  C  │  │  D  │   │ Linux  │  projects — never read each other
   └──┬──┘   └─────┘  └─────┘  └─────┘   └────┬───┘
   ┌──┴───┐                          ┌────────┼────────┐
 ┌─┴─┐ ┌──┴┐                      ┌──┴─┐  ┌───┴┐  ┌────┴┐  sub-nodes — siblings share
 │ X │ │ Y │                      │dev │  │stg │  │prod │
 └───┘ └───┘                      └────┘  └────┘  └─────┘
```

- Every node has its **own encryption key**: an X25519 keypair, with values sealed in
  HKDF-SHA-512 / ChaCha20-Poly1305 envelopes.
- **Projects never read each other.** A child reads its ancestors; a parent does not read its
  children. Everything reads `global`.
- **One door in.** The CLI, the MCP server and the desktop shell are all *clients* of one
  process, the broker (`credmgrd`), which is the only thing that ever holds a key and makes an
  access decision. It listens on a local Unix-domain socket, not on a network port.
- **An agent is scoped by where it runs.** A process started inside a project's working
  directory is bound to that project and `global`; asking for another project's value gets a
  structured refusal, not a value.
- **Two factors, optionally.** A TOTP gate can be enrolled so that unlocking needs your
  passphrase *and* a fresh code, with recovery codes for a lost authenticator.
- **Secrets travel on stdin, never as a command-line argument.** The CLI has no flag that takes a
  secret value, so a value cannot show up in a process listing, and a test fails if one is added.
  (The one exception is the short-lived six-digit two-factor code.)

The design is written down in full in [`v2/docs/`](v2/docs/00_README_START_HERE.md): the
[concept](v2/docs/01_CONCEPT.md), [architecture](v2/docs/02_ARCHITECTURE.md),
[cryptography](v2/docs/04_CRYPTO_AND_KEYS.md) and [threat model](v2/docs/05_THREAT_MODEL.md),
with every real design decision and its reasoning in [`14_DECISIONS.md`](v2/docs/14_DECISIONS.md).
The threat model states plainly what CredMgr defends against and what it does not.

## What it is not

- **Not a cloud service.** No hosted server, no account, no sync. Your vault is a directory on
  your own disk.
- **Not a multi-user sync tool.** Each install is single-user and single-machine, by design — no
  real-time sharing between teammates' vaults. That is architectural, not a licensing
  restriction: a company's developers can each run their own instance, free under the
  [current licence](LICENSE); they just never sync with each other. A design for optional vault-to-vault sync is
  written down in [`v2/docs/22_ORG_VAULT_SYNC_AND_LICENSING.md`](v2/docs/22_ORG_VAULT_SYNC_AND_LICENSING.md);
  none of it is built.
- **Not tracking you.** No telemetry, no analytics, no crash reporting, no update ping.

## What the current build does, and does not, do

**What works.** Driven end to end against the real `credmgr` and `credmgrd` binaries by
[`v2/scripts/e2e-journey.sh`](v2/scripts/e2e-journey.sh) — not only by unit tests, which once
passed while the shipped daemon could not open a vault it had created:

- Create a vault (`credmgr init`), unlock and lock it; stored entries survive a broker restart.
- Create projects (nodes) bound to a working directory, so a process started there is scoped to
  that project automatically.
- Store and read secrets by name, per project. An entry can hold any number of fields with labels you
  choose, pasted as one block (`credmgr set --bulk`), listed without their values (`credmgr field ls`) and
  read one at a time (`credmgr get --field`).
- Seal a project and restore it within seven days, across restarts (`credmgr node seal`, `node restore`).
- A review tray: a secret an agent writes while the vault is locked waits for you to accept or
  discard it (`credmgr pending`), across restarts.
- Integrity verification (`credmgr verify`).
- Import a `.env` file into a project (`credmgr import`, all-or-nothing), keep a sealed markdown note
  on a project (`credmgr notes`), and rename a project or change its policy (`credmgr node rename`,
  `credmgr node policy`).
- A TOTP two-factor gate with recovery codes, and recovery from a lost authenticator using your
  passphrase plus the root recovery code.

**Also built, and covered by the test suite rather than that journey:** listing, searching,
rotating, removing and undoing entries; the audit trail (`credmgr audit`); `credmgr doctor`;
encrypted backups (`credmgr backup`); and the MCP server (`credmgr mcp`, over stdio) that lets an
agent fetch a credential at the moment it needs one. **Confirm before showing secrets** (ADR-150), a vault setting that
is off by default: when you turn it on (Settings > Security in the app), revealing, copying or showing a one-time code
for a saved secret, or approving a waiting request, asks for Touch ID or the vault passphrase first, then not again for the trust window you choose
(1, 5, 15 or 60 minutes; Pro mode can ask every time, or only for high and critical secrets). At a terminal
`credmgr get` asks by itself; a script runs `credmgr confirm` first. It protects a Mac left unlocked, not a copied
vault folder; it covers the app and your logged-in CLI, and agents are not asked (their reads answer to the node's
security level; a `credmgr` run from a registered project folder without your login is an agent).

**What it does not do yet** — each item is recorded with its bound, owner and resolution path
in [`v2/docs/PHASE8_AUDIT_REPORT.md §4`](v2/docs/PHASE8_AUDIT_REPORT.md):

- **The desktop app is unsigned and its per-control checklist was not re-walked on the final build.** `v2/apps/desktop/` hosts
  the finished app design under a strict content policy; every screen reads from the vault and every change goes
  to it ([`v2/apps/desktop/README.md`](v2/apps/desktop/README.md)). `scripts/release-app.sh` builds it as an
  ad-hoc sealed `CredMgr.app`, `.dmg` and `.zip` beside the command-line tarball. A tester walked
  [`v2/docs/RELEASE_VERIFICATION.md`](v2/docs/RELEASE_VERIFICATION.md) in the built app on 2026-10-18 (190 rows
  pass, 7 fail, 85 not pressed; the open findings are listed in its section 8) and re-checked the later
  changes by hand on 2026-10-19, 2026-10-27 and 2026-10-31, then a spot re-walk of every screen by hand on 2026-11-07 and 2026-11-08 on the `26da2d3` build (`docs/RELEASE_VERIFICATION.md` §15), with the idle lock, a real screen lock, Touch ID setup, fingerprint unlock and `credmgr unlock --touch-id` checked by hand on 2026-11-08; "show seed" was re-walked by hand on 2026-11-08 after its two fixes (`d9e6c7c`, and ADR-149's blur grace in `5e9bb29`; the addendum to §15); the per-control rows were not pressed again; the "Confirm before showing secrets" setting (ADR-150) was checked by hand on 2026-11-08 (the second addendum to §15), and VoiceOver on 2026-11-08 (`docs/ACCESSIBILITY.md`, two defects found and fixed); the 2026-11-08 design drop (ADR-151) has not yet been looked at in a built app (§16).
  It has no control to delete an entry (use `credmgr rm`; `credmgr undo` brings one back). An agent's request is
  decided from the Lock screen or with `credmgr approve`.
- **Your passphrase is still the key; Touch ID is an extra door (K-5, ADR-098).** The root key is stored in the
  vault folder under an Argon2id-derived key (256 MiB, 3 passes, 4 lanes) and under the recovery code, and a copy
  of the folder can be attacked offline on any computer by guessing the passphrase. If you turn on Touch ID
  unlock, a third wrap seals the root key to this Mac's Secure Enclave: it opens only on this Mac and only for
  you, but the passphrase and recovery wraps stay, so the folder copied elsewhere is exactly as attackable as
  before. While the vault is unlocked `credmgrd` holds the root key and every unlocked project key in memory and
  does not lock its pages or block debuggers. **Two-factor guards the door, not the safe:** `credmgrd` enforces
  it, the encryption does not, so someone with your passphrase or recovery code and a copy of the folder can
  decrypt without it. There is no Windows Hello or TPM binding and no Linux keystore yet. The binaries and the
  app are unsigned and not notarised (Touch ID does not need signing; Gatekeeper does). `SHA256SUMS` is the only provenance
  ([`v2/docs/04_CRYPTO_AND_KEYS.md §2.4`](v2/docs/04_CRYPTO_AND_KEYS.md) has the full statement).
- **macOS on Apple Silicon only.** The packaged build and the app target `aarch64-apple-darwin`; nothing else
  is built or tested. The Rust workspace is written to compile on Linux, but the workflow that tests it there
  (`build.yml`) is manual-dispatch only: it ran the workspace on Ubuntu 22.04 once, on the beta.1 tree (pull
  request #41), and has not run on this tree. Windows is not supported yet because the broker
  transport is Unix-socket only (the named-pipe transport is planned,
  [`v2/docs/16_CROSS_PLATFORM.md`](v2/docs/16_CROSS_PLATFORM.md) §5.3).
- **GitHub CI ran for the first time on 2026-10-31 and 2026-11-01 (pull request #41, the beta.1 tree) and runs on every pull request since (#44 onward).** Before that, the account's billing had blocked every GitHub-hosted job. The evidence for a release is the CI run plus the local gate run and the by-hand check of the built app ([`v2/docs/RELEASE_VERIFICATION.md`](v2/docs/RELEASE_VERIFICATION.md) section 13).
- **An exported login reaches every project (K-6).** Keep `CREDMGR_TOKEN` out of any shell an AI
  agent runs in, and lock the vault when you are done.
- **Sealing and locked requests (K-7).** A request from an agent while the whole vault is locked is recorded,
  not answered: you decide it with your passphrase (and your authenticator code, if two-factor is on) from the
  Lock screen or with `credmgr approve`, and the vault stays locked. A sealed project can be restored for seven
  days; after that `credmgr doctor --purge-expired-seals` destroys the retained originals, and the Orphaned
  copies stay encrypted, and only the desktop app (with your Touch ID, a fresh second factor and the owner's login) can read them.
- **Rollback protection is software-only (K-8).**
- **Presence-gated operations need a Touch ID key on this Mac (K-1, ADR-098).** On macOS you enrol this Mac's
  Secure Enclave key once (`credmgr presence enrol`, or Settings > Security > Touch ID in the app). From then on
  revealing a TOTP seed (the app's "show seed" displays it, re-masks it after the reveal window and never copies it; the CLI has no command), creating grants, re-parenting nodes, reading a full audit record, widening a project's
  read reach, rebuilding the registry, replacing the root key and opening a sealed (Orphaned) entry run, each
  after a fresh Touch ID (or the device password where no fingerprint is enrolled); the CLI and the app ask for
  it themselves. Unlock with Touch ID instead of the passphrase once it is on: `credmgr touch-id enable`, then
  `credmgr unlock --touch-id` or the fingerprint icon beside the passphrase field on the Lock screen (dimmed, with a
  set-up hint, until Touch ID is on). A sealed entry opens in the desktop app only (no CLI command, no MCP tool) and also costs a
  fresh second factor. **Without an enrolled key the old refusals still apply**: those operations answer
  `presence_required`. Agents and fixture tokens never hold a proof, so they always get that refusal.
  Touch ID unlock is refused to a caller the broker recognises as an agent (an agent token, or a call from inside a
  registered project folder); anyone else gets a dialog that names the process that asked, and that name is a hint,
  not proof. Cancel any request you did not start yourself ([`v2/SECURITY.md`](v2/SECURITY.md), ADR-148).
- **Not built:** the machine lock (its smallest safe version is `ADR-144`). **Dropped:** the duress code (`ADR-145`) and the
  `llm.*` broker operations (`ADR-146`; the coding-assistant wiring is built in the CLI and the app instead,
  [`v2/docs/17_AIRLOCK_AND_LLM.md`](v2/docs/17_AIRLOCK_AND_LLM.md)). Built: per-node security levels, `credmgr mcp --print-config`,
  Settings → Agents, `credmgr prompt`, `CREDMGR.md`.
- **No V1 import in the CLI or the app** (`credmgr import` reads a `.env` file only). A read-only copy script, `tools/v1-to-v2/migrate.js`, exists (ADR-097); it never writes to the V1 vault.
- **The alpha.4 to alpha.6 builds leaked each login's session token into the plaintext audit log.** Fixed in this
  tree (ADR-077); if you ran one of them, read [`SECURITY.md`](SECURITY.md) before continuing.

## Install

**Before you install this pre-release, know what it does not do.**

- **Unsigned and not notarised.** macOS Gatekeeper refuses the binaries and the app until they carry an Apple
  Developer ID signature and are notarised, which has not happened. Today they run only after you check the
  checksum and clear the quarantine flag yourself ([`v2/RELEASE.md`](v2/RELEASE.md)).
- **Touch ID is macOS-only and optional.** Without an enrolled presence key, presence-gated operations are
  still refused (K-1, above). The passphrase is always the key; Touch ID unlock adds a door that works on this
  Mac only. No Windows Hello, TPM or Linux keystore tier exists yet.
- **No machine lock (ADR-144) and no duress code (ADR-145); the `llm.*` broker operations were dropped (ADR-146).** The coding-assistant wiring is built: `credmgr prompt`, `credmgr agent`, `credmgr mcp --print-config` and Settings → Agents (ADR-141 to ADR-143).
- **macOS on Apple Silicon only.** No Windows or Linux build.
- **No way back to an alpha:** a vault beta.1 has written to cannot be opened by an alpha build, and there is
  no downgrade. There is no migration from the V1 vault.
- **GitHub CI ran on the beta.1 tree (pull request #41) and runs on every pull request since;** the local gate run and the by-hand check are recorded in
  [`v2/docs/RELEASE_VERIFICATION.md`](v2/docs/RELEASE_VERIFICATION.md) section 13.
- **Checked by hand on 2026-11-08:** the 5-minute auto-lock idle timer and a real screen lock both locked the vault
  ([`v2/docs/RELEASE_VERIFICATION.md`](v2/docs/RELEASE_VERIFICATION.md) §15); the "Confirm before showing secrets" setting (ADR-150; the addendum to §15) and a VoiceOver pass (#22, closed, two defects fixed; [`v2/docs/ACCESSIBILITY.md`](v2/docs/ACCESSIBILITY.md)) were checked too. Not done by hand: the per-control press of every row and the built-app look of the 2026-11-08 design drop (§16).

**From a release.** The [releases page](https://github.com/FreeXStudio-Platform/credmgr/releases) has `2.0.0-beta.1` (pre-release, 2026-11-01, unsigned). It predates Touch ID, agent wiring, restore and node gates; build `2.0.0-rc.1` from source, below, to get them. Releases carry a tarball, the desktop app, bills of
materials and a `SHA256SUMS` file. The binaries are not code-signed, so the checksum is the only
provenance — check it against the copy published with the release, not one that came in the same
download. `SHA256SUMS` has one line per published file, so check just the ones you downloaded:

```bash
shasum -a 256 -c --ignore-missing SHA256SUMS        # one OK line per file you have
tar -xzf credmgr-*.tar.gz && (cd credmgr-*/ && shasum -a 256 -c SHA256SUMS)   # the tarball's own manifest
```

If any line does not say OK, stop and do not run the binaries. Then follow the install,
Gatekeeper, broker, vault-creation and two-factor steps in **[`v2/RELEASE.md`](v2/RELEASE.md)**.

**From source.** You need Rust 1.78 (pinned by [`v2/rust-toolchain.toml`](v2/rust-toolchain.toml)) and the Xcode command-line tools (`swiftc`, which builds the Touch ID helper):

```bash
git clone https://github.com/FreeXStudio-Platform/credmgr.git
cd credmgr/v2
scripts/release.sh            # release build; refuses a dirty working tree
scripts/release.sh --dev      # same build from a dirty tree, stamped "dirty" — never publish one
```

Either way the binaries land in `v2/dist/credmgr-<version>-<target>/bin/`. Run the broker, then
create a vault:

```bash
dist/credmgr-*/bin/credmgrd &            # or let launchd keep it running — see RELEASE.md
dist/credmgr-*/bin/credmgr init          # asks for a passphrase, prints a recovery code once: write it down
dist/credmgr-*/bin/credmgr --version
```

The vault lives in your platform's user-data directory (macOS: `~/Library/Application Support/credmgr`),
never inside a repository — `credmgr init` refuses a git working tree. Override the location with
`CREDMGR_VAULT_DIR`.

> **If you also run V1:** both versions install a command named `credmgr` and both default to the
> same data directory on macOS. Do not put them on the same `PATH` entry or in the same directory.
> Give each its own vault with `CREDMGR_HOME` (V1) and `CREDMGR_VAULT_DIR` (V2), and call V2 by
> its full path until you have decided which one owns the name.

## V1 — the legacy Node.js line

V1 is the original product: a single encrypted file under one key, a `project` string used for
filtering (a filter, not a fence), a local web dashboard, a Node SDK and an MCP server. It
continues to receive security fixes; new development goes into V2.

```bash
git clone https://github.com/FreeXStudio-Platform/credmgr.git
cd credmgr/v1
npm ci
npm link                      # puts `credmgr` on your PATH
credmgr init
credmgr where                 # confirm the vault is OUTSIDE the repository
```

Requires Node 18 or newer and [`age`](https://github.com/FiloSottile/age). V1 is installed from
source: there is no signed release or npm package yet
([`v1/PUBLICATION_READINESS.md`](v1/PUBLICATION_READINESS.md)). Full documentation:
[`v1/README.md`](v1/README.md) · [changelog](v1/CHANGELOG.md) · [security](v1/SECURITY.md) ·
[privacy](v1/PRIVACY.md).

## Repository layout

| Path | What is in it |
|---|---|
| [`v2/`](v2/) | The V2 Rust workspace (`crates/`: core, keystore, store, brokerd, cli, mcp), the desktop app shell and its backend bridge (`apps/desktop/`), the design corpus (`docs/`), packaging, and the release and verification scripts (`scripts/`). |
| [`v1/`](v1/) | The V1 Node.js product, its tests, dashboard, SDK, MCP server and native macOS shell source. |
| [`tools/`](tools/) | Documentation tooling: `docgen` renders the Markdown corpus to self-contained HTML and JSON, `visual-engine` renders charts, and `corpus_check.py` cross-checks the docs against the code. |
| [`docs/`](docs/) | Generated blueprints and the document-system manifest. |
| [`.github/`](.github/) | Issue and pull-request templates, code owners, funding links and the CI workflows. |

## Security

CredMgr holds passwords, private keys and recovery phrases. **Report vulnerabilities privately** —
see [`SECURITY.md`](SECURITY.md), which routes V1 and V2 reports. Never open a public issue for a
security bug, and never include a real credential in a report.

The threat model puts one thing out of scope on purpose: an attacker with code execution as your
own user account on an *unlocked* vault. No user-space vault defends against that, and claiming
otherwise would be dishonest.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first — this is a credential vault, so the rules are
stricter than usual (no real credentials in tests, no network calls in the V2 broker, no
telemetry). Everyone taking part is expected to follow the
[code of conduct](CODE_OF_CONDUCT.md).

## License

CredMgr is **source-available, not open source**: the code is public so that you can read it, audit
it and check that it is safe. Everything not expressly granted stays reserved by FreexStudio. The
terms are in [`LICENSE`](LICENSE) (the same text ships as [`v1/LICENSE`](v1/LICENSE) and
[`v2/LICENSE`](v2/LICENSE)); in short:

- You may run the current stable release as published, read and audit the source, build the
  unmodified current version to check it against the official release, report problems, and send
  patches under the contribution terms in [`CONTRIBUTING.md`](CONTRIBUTING.md).
- You may not fork, copy, modify or redistribute it, or ship a modified or unofficial build. A
  GitHub fork is allowed only to prepare a contribution.
- It is free to use today. Future versions may be paid; a version you already hold stays under the
  licence it came with.
- The **CredMgr** and **FreexStudio** names and marks are covered by
  [`v2/TRADEMARKS.md`](v2/TRADEMARKS.md).

For permission to do something the licence does not allow, or for a commercial arrangement, write to
**Admin@freexstudio.com**.

## Support

Where to ask for help, and what is and is not supported, is in [`SUPPORT.md`](SUPPORT.md).

CredMgr is free today and has no telemetry. If it saved you from a leaked key, you can support the
work with a voluntary donation: the addresses and the steps for checking them before you send
anything are in **[`v2/DONATE.md`](v2/DONATE.md)**. Donations are not refundable, buy nothing, and
grant no licence, support agreement or influence over the roadmap. Verify an address against the
file in the version you are running, not a screenshot, a search result, or a message from anyone
claiming to be the maintainers.

Other things help just as much: report a security bug, test on Linux, or tell someone who still
keeps API keys in a Notes file.

---

Published by **[FreexStudio](https://freexstudio.com)**.
