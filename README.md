<!-- artifact-hardened: Approved With Known Risks @ 09721b5 on 2026-11-01 via three-pass-v1. Evidence: GitHub-hosted CI on pull request #41 (FreeXStudio-Platform/credmgr): all 17 checks green at ee08394, including security.yml (cargo audit, cargo deny, semgrep, isolation suite, endpoint matrix 55/55 operations, desktop bridge) and CodeQL for Rust, JavaScript/TypeScript, Python and Actions with no open alert on the PR; build.yml run 41243452910, all 7 jobs green (macOS 15, Ubuntu 22.04, Windows; Rust 1.78.0 and stable); desktop unit tests 706 passed at 930c502; Playwright 672 and 681 passed in the two lanes that were combined at 930c502 (not re-run together); strict public export PASS, 860 files, literal blocklist not loaded; by-hand click-through of the rebuilt app on a throwaway vault (unlock, lock, auto-lock, graph, tree, search, reveal, copy, add entry, settings, integrity, doctor, audit, backup, capture switch, searchable help); final adversarial audit v2/docs/release-verification/AUDIT_2026-10-31.md (the P0 and both P1 fixed); known risks K-1 to K-20 in v2/docs/PHASE8_AUDIT_REPORT.md sections 4 and 7, each with bound, owner and resolution. Known risks that bear on this document: K-14 the idle lock and a real sleep or screen lock were not exercised by hand on this build; K-19 a seed in an unrecognised shape is not protected until its owner types it; K-20 the licence text has not been reviewed by counsel. K-12 (CI had not run) is closed. Not signed or notarised; Windows and Linux built in CI but not run. Not a claim about anything after 09721b5. -->

<div align="center">

# CredMgr

**A local, offline credential vault built for the moment you hand credentials to an AI agent.**

Agents get only the project they are scoped to, and a sensitive value is released only when you approve it. Encrypted at rest · no account · no cloud · no telemetry · the V2 broker makes no network calls

[Install](#install) · [How it works](#how-it-works) · [Limitations](#what-the-current-build-does-and-does-not-do) · [Security](#security) · [License](#license) · [Support](#support)

**[FreexStudio](https://freexstudio.com)**

</div>

---

> **Pre-release software.** The current V2 build is **unsigned and not notarised** and your passphrase is the
> key (no Secure Enclave, no Touch ID; two-factor guards the door, not the safe). Read
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
| **[V2](v2/)** — start here | `2.0.0-beta.1` ([`v2/Cargo.toml`](v2/Cargo.toml)) | A Rust rewrite. Each project is a real cryptographic boundary. Ships a command line (`credmgr`), a broker daemon (`credmgrd`) and an MCP server (`credmgr mcp`), and a desktop app wired to the broker. macOS (Apple Silicon) only. No release has been published; this tree is `2.0.0-beta.1` (built and verified locally, not yet published), and a vault beta.1 has written to cannot be opened by an alpha build. |
| **[V1](v1/)** — legacy | `1.9.1` ([`v1/package.json`](v1/package.json)) | The original Node.js vault: CLI, local web dashboard, Node SDK and MCP server. Installed from source. |

V1 and V2 are separate products with separate vaults, and **there is no migration between them**
([`v2/docs/11_MIGRATION.md`](v2/docs/11_MIGRATION.md)). New users should start with V2. Existing V1
users are not forced to move; see [V1](#v1--the-legacy-nodejs-line) below.

## Roadmap

`2.0.0-beta.1` is free and ungated. Next, in this order and with no dates: `2.0.0-rc.1` (Touch ID, signing and notarisation, a read-only V1→V2 copy tool, the doctor's duplicate and wallet-bundling scan),
`2.0.0` (the first stable release, Windows and Linux), `2.1.0` (cross-device sync as ciphertext; agents that use a credential without the value reaching the model),
`2.2` (a signed, machine-bound, expiring licence; a failed licence never locks your vault), `2.3` (the first paid tier).
**Future versions, extra platforms and devices may not be free.** Versions already released stay under the licence they came with. This list is a direction, not a promise, and
nothing in it is built yet: [`v2/docs/24_LICENCE_AND_DONATION_PROOF.md`](v2/docs/24_LICENCE_AND_DONATION_PROOF.md), [`v2/docs/25_VAULT_HYGIENE.md`](v2/docs/25_VAULT_HYGIENE.md) and [`v2/docs/PRODUCTION_PLAN.md`](v2/docs/PRODUCTION_PLAN.md).
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
agent fetch a credential at the moment it needs one.

**What it does not do yet** — each item is recorded with its bound, owner and resolution path
in [`v2/docs/PHASE8_AUDIT_REPORT.md §4`](v2/docs/PHASE8_AUDIT_REPORT.md):

- **The desktop app is unsigned and its checklist was not re-walked on the final build.** `v2/apps/desktop/` hosts
  the finished app design under a strict content policy; every screen reads from the vault and every change goes
  to it ([`v2/apps/desktop/README.md`](v2/apps/desktop/README.md)). `scripts/release-app.sh` builds it as an
  ad-hoc sealed `CredMgr.app`, `.dmg` and `.zip` beside the command-line tarball. A tester walked
  [`v2/docs/RELEASE_VERIFICATION.md`](v2/docs/RELEASE_VERIFICATION.md) in the built app on 2026-10-18 (190 rows
  pass, 7 fail, 85 not pressed; the open findings are listed in its section 8) and re-checked the later
  changes by hand on 2026-10-19, 2026-10-27 and 2026-10-31; the whole list was not walked again on this tree.
  It has no control to delete an entry (use `credmgr rm`; `credmgr undo` brings one back). An agent's request is
  decided from the Lock screen or with `credmgr approve`.
- **Software tier, unsigned binaries (K-5).** Your passphrase is the key: the root key is stored in the vault
  folder under an Argon2id-derived key (256 MiB, 3 passes, 4 lanes) and under the recovery code, nothing is
  held in the Secure Enclave, and a copy of the folder can be attacked offline on any computer. While the vault
  is unlocked `credmgrd` holds the root key and every unlocked project key in memory and does not lock its pages
  or block debuggers. **Two-factor guards the door, not the safe:** `credmgrd` enforces it, the encryption does
  not, so someone with your passphrase or recovery code and a copy of the folder can decrypt without it. There
  is no Touch ID, Windows Hello or TPM binding yet. `SHA256SUMS` is the only provenance
  ([`v2/docs/04_CRYPTO_AND_KEYS.md §2.4`](v2/docs/04_CRYPTO_AND_KEYS.md) has the full statement).
- **macOS on Apple Silicon only.** The packaged build and the app target `aarch64-apple-darwin`; nothing else
  is built or tested. The Rust workspace is written to compile on Linux, but the workflow that tests it there is
  manual-dispatch only and has not run on this release. Windows is not supported yet because the broker
  transport is Unix-socket only (the named-pipe transport is planned,
  [`v2/docs/16_CROSS_PLATFORM.md`](v2/docs/16_CROSS_PLATFORM.md) §5.3).
- **GitHub CI has not run on this release.** The account's billing blocked every GitHub-hosted job, so the
  required checks never reported. The evidence for this release is the local gate run and the by-hand check of the
  built app ([`v2/docs/RELEASE_VERIFICATION.md`](v2/docs/RELEASE_VERIFICATION.md) section 13).
- **An exported login reaches every project (K-6).** Keep `CREDMGR_TOKEN` out of any shell an AI
  agent runs in, and lock the vault when you are done.
- **Sealing and locked requests (K-7).** A request from an agent while the whole vault is locked is recorded,
  not answered: you decide it with your passphrase (and your authenticator code, if two-factor is on) from the
  Lock screen or with `credmgr approve`, and the vault stays locked. A sealed project can be restored for seven
  days; after that `credmgr doctor --purge-expired-seals` destroys the retained originals, and the Orphaned
  copies stay encrypted with nothing in this release able to read them.
- **Rollback protection is software-only (K-8).**
- **Presence-gated operations are refused (K-1)**: revealing a TOTP seed, creating grants,
  re-parenting nodes, reading a full audit record, widening a project's read reach, rebuilding the registry
  and replacing the root key answer `presence_required` until a transport can attest a live user. Reading a
  sealed (Orphaned) entry is refused with `node_access_denied` for the same reason.
- **Not built:** LLM integration (`llm.*`), machine lock and the duress code are designed
  ([`v2/docs/17_AIRLOCK_AND_LLM.md`](v2/docs/17_AIRLOCK_AND_LLM.md)) but do not exist in this build.
- **No import from V1** (`credmgr import` reads a `.env` file only).
- **The alpha.4 to alpha.6 builds leaked each login's session token into the plaintext audit log.** Fixed in this
  tree (ADR-077); if you ran one of them, read [`SECURITY.md`](SECURITY.md) before continuing.

## Install

**Before you install this beta, know what it does not do.**

- **Unsigned and not notarised.** macOS Gatekeeper refuses the binaries and the app until they carry an Apple
  Developer ID signature and are notarised, which has not happened. Today they run only after you check the
  checksum and clear the quarantine flag yourself ([`v2/RELEASE.md`](v2/RELEASE.md)).
- **No Touch ID or presence attestation.** Presence-gated operations are refused (K-1, above).
- **Software keystore tier only:** your passphrase is the key; there is no Secure Enclave tier.
- **No LLM integration, machine lock or duress code.**
- **macOS on Apple Silicon only.** No Windows or Linux build.
- **No way back to an alpha:** a vault beta.1 has written to cannot be opened by an alpha build, and there is
  no downgrade. There is no migration from the V1 vault.
- **GitHub CI has not run on this release;** the evidence is the local gate run recorded in
  [`v2/docs/RELEASE_VERIFICATION.md`](v2/docs/RELEASE_VERIFICATION.md) section 13.
- **Not exercised by hand on this tree:** the auto-lock idle timer (5 minutes in the checklist run; the broker's
  default is 15) and a real sleep or screen lock. The maintainer checked a sleep and wake once, on 2026-10-18, on an
  earlier build.

**From a release (upcoming).** No GitHub release has been published yet, so there is nothing to
download today; build from source, below. Releases will carry a tarball, the desktop app, bills of
materials and a `SHA256SUMS` file. The binaries are not code-signed, so the checksum is the only
provenance — check it against the copy published with the release, not one that came in the same
download. `SHA256SUMS` has one line per published file, so check just the ones you downloaded:

```bash
shasum -a 256 -c --ignore-missing SHA256SUMS        # one OK line per file you have
tar -xzf credmgr-*.tar.gz && (cd credmgr-*/ && shasum -a 256 -c SHA256SUMS)   # the tarball's own manifest
```

If any line does not say OK, stop and do not run the binaries. Then follow the install,
Gatekeeper, broker, vault-creation and two-factor steps in **[`v2/RELEASE.md`](v2/RELEASE.md)**.

**From source.** You need Rust 1.78 (pinned by [`v2/rust-toolchain.toml`](v2/rust-toolchain.toml)):

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
