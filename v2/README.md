<!-- artifact-hardened: Approved With Known Risks @ 09721b5 on 2026-11-01 via three-pass-v1. Evidence: GitHub-hosted CI on pull request #41 (FreeXStudio-Platform/credmgr): all 17 checks green at ee08394, including security.yml (cargo audit, cargo deny, semgrep, isolation suite, endpoint matrix 55/55 operations, desktop bridge) and CodeQL for Rust, JavaScript/TypeScript, Python and Actions with no open alert on the PR; build.yml run 41243452910, all 7 jobs green (macOS 15, Ubuntu 22.04, Windows; Rust 1.78.0 and stable); desktop unit tests 706 passed at 930c502; Playwright 672 and 681 passed in the two lanes that were combined at 930c502 (not re-run together); strict public export PASS, 860 files, literal blocklist not loaded; by-hand click-through of the rebuilt app on a throwaway vault (unlock, lock, auto-lock, graph, tree, search, reveal, copy, add entry, settings, integrity, doctor, audit, backup, capture switch, searchable help); final adversarial audit v2/docs/release-verification/AUDIT_2026-10-31.md (the P0 and both P1 fixed); known risks K-1 to K-20 in v2/docs/PHASE8_AUDIT_REPORT.md sections 4 and 7, each with bound, owner and resolution. Known risks that bear on this document: K-14 the idle lock and a real sleep or screen lock were not exercised by hand on this build; K-19 a seed in an unrecognised shape is not protected until its owner types it; K-20 the licence text has not been reviewed by counsel. K-12 (CI had not run) is closed. Not signed or notarised; Windows and Linux built in CI but not run. Not a claim about anything after 09721b5. -->

# CredMgr V2 — "Vault Next"

**A local, offline, node-scoped credential vault for macOS, built to close the gap between giving an AI agent your credentials and keeping them secure: an agent is scoped to one project and a sensitive value is released only when you approve it.**

> **Status (2026-10-31): no release has been published; this tree is `2.0.0-beta.1`** (`CHANGELOG.md`, built and
> verified locally, not yet published; the earlier `2.0.0-alpha.6` package, also never published, held the CLI and
> broker only). Create a vault (`credmgr init`), unlock it, store and read secrets, split them into
> projects that AI agents are automatically scoped to, turn on two-factor, and recover from a
> lost authenticator — all through the real `credmgrd` daemon, with every change durable across a
> restart. **Unsigned, not notarised and Software-tier** (your passphrase is the key; no Secure Enclave, no Touch ID):
> read [Known limitations](#known-limitations) before trusting it with anything that matters.
>
> Until 2026-09-24 the backend passed all 406 of its tests and still could not open a vault it
> had created, or keep a change across a restart — every test built its own correctly-keyed
> state, and nothing ran the real binaries end to end. That is fixed (ADR-063 … ADR-066) and now
> proven with the real binaries. Since then: `credmgr import`, `notes` and `node rename` / `policy`;
> a crash-safe root-key rotation (`maintenance.rotate_root`, built, not yet reachable on the wire);
> a fix for a **high-severity** leak in the alpha.4 to alpha.6 builds — each login's session token was written
> to the plaintext audit log ([`SECURITY.md`](SECURITY.md)); an entry that holds **any number of
> fields with labels you choose** (ADR-078); sealing that survives a restart and a crash, with an
> orphan cold key (ADR-079); release tooling that writes a deterministic tarball, bills of materials and
> the desktop app bundle (`RELEASE.md`); and the **desktop app wired to the broker end to end** — every
> screen reads from it and every change goes to it, with no demo data in a release build
> (`apps/desktop/README.md`). **A vault that 2.0.0-beta.1 has written to cannot be opened by an alpha
> build** ([`RELEASE.md`](RELEASE.md), the box at the top). The **live** vault is V1, outside this repo, and is
> untouched by this project.

---

## The idea

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
 ┌ ─ ─ ─ ─ ─ ┐
   ORPHANED     sealed · names visible · values human-only
 └ ─ ─ ─ ─ ─ ┘
```

- Every node has its **own encryption key**, its own notes and its own agent scope. The second factor is one gate for the whole vault; a node's policy decides who is asked for it (a per-node secret is planned, known risk K-11).
- Projects **never** read each other. Children read ancestors. Parents do **not** read children.
- Cross-node access is a **grant** — human-only, 2FA-gated, expiring, revocable, dashed on the graph.
- Removing a node **seals** it, and a sealed node can be restored for seven days. Nothing is deleted on its own: expired seals are purged only when you run `credmgr doctor --purge-expired-seals`, and a held entry you discard is removed.
- One process (`credmgrd`) holds every key and makes every access decision.

## Why

An agent working on project B could read project A's production credentials, because
V1's `project` field is a filter, not a fence. V2 makes it a fence — and is honest, in
[`docs/05_THREAT_MODEL.md`](docs/05_THREAT_MODEL.md), about exactly which attacks that stops
and which it does not.

## Install, build and run

**Before you install this beta, know what it does not do.**

- **Unsigned and not notarised.** macOS Gatekeeper refuses the binaries and the app until they carry an Apple
  Developer ID signature and are notarised, which has not happened. Today they run only after you check the
  checksum and clear the quarantine flag yourself ([`RELEASE.md`](RELEASE.md)).
- **No Touch ID or presence attestation:** presence-gated operations are refused (K-1, below).
- **Software keystore tier only:** your passphrase is the key; there is no Secure Enclave tier.
- **No LLM integration, machine lock or duress code.**
- **macOS on Apple Silicon only.** No Windows or Linux build.
- **No way back to an alpha:** a vault beta.1 has written to cannot be opened by an alpha build, and there is no
  downgrade. There is no migration from the V1 vault.
- **GitHub CI has not run on this release.** The account's billing blocked every GitHub-hosted job; the evidence is
  the local gate run and the built-app check in [`docs/RELEASE_VERIFICATION.md`](docs/RELEASE_VERIFICATION.md)
  section 13.
- **Not exercised by hand on this tree:** the auto-lock idle timer (5 minutes in the checklist run; the broker's
  default is 15) and a real sleep or screen lock. The maintainer checked a sleep and wake once, on 2026-10-18, on an
  earlier build.

The full walkthrough — verify, install, start the broker, create, unlock, projects, two-factor,
recovery — is **[`RELEASE.md`](RELEASE.md)**. The short form, from a checkout:

```bash
cd v2
scripts/release.sh --dev                 # builds credmgr + credmgrd into dist/ (unsigned)
dist/credmgr-*/bin/credmgrd &            # the broker; or install the launchd unit
dist/credmgr-*/bin/credmgr init          # passphrase, then retype the printed recovery code
eval "$(dist/credmgr-*/bin/credmgr unlock <<< 'your passphrase')"
dist/credmgr-*/bin/credmgr set API_KEY --node global <<< 'the-value'
dist/credmgr-*/bin/credmgr get API_KEY --node global
```

Needs Rust 1.78+ (`rust-toolchain.toml`). Tests: `cargo test --workspace` (905 tests in 59 test
binaries, listed 2026-10-31; the last full run with a recorded count passed 900 of 900 on 2026-10-26, before the
later additions; the Argon2id-backed suites take minutes, by design), plus `cargo test` inside
`apps/desktop/src-tauri` for the desktop shell and bridge (202 tests in 13 executables, listed 2026-10-31), which
is its own workspace (ADR-035), and the front-end gates in `apps/desktop` (`npm test`, 700 unit tests as recorded
2026-10-30; `npm run test:e2e`, `test:csp`, `test:design`, `test:real`).

## Known limitations

Each is recorded with its bound, owner and resolution path in
[`docs/PHASE8_AUDIT_REPORT.md §4`](docs/PHASE8_AUDIT_REPORT.md).

- **K-5 — Software tier: your passphrase is the key. No Secure Enclave, no Touch ID, unsigned binaries.**
  The vault's root key is stored in the vault folder encrypted two ways: under a key derived from your
  passphrase with Argon2id (256 MiB of memory, 3 passes, 4 lanes), and under the 256-bit recovery code printed at
  `credmgr init`. Nothing is held in the Mac's Secure Enclave and nothing is tied to this Mac: a copy of the vault
  folder can be attacked offline on any computer, slowed only by the Argon2id cost of each passphrase guess. Use a
  long, unique passphrase and keep the recovery code offline. While the vault is unlocked, `credmgrd` holds the
  root key and every unlocked project key in memory until it locks (idle timeout or `credmgr lock`; the desktop app also locks it when the Mac sleeps, the screen locks or the session switches, but a daemon running without the app does not); it does
  not lock its memory pages or block debuggers, so software able to read its memory — anything running as root,
  for example — can read those keys. There is no Touch ID and no presence check: reading a sealed (Orphaned)
  entry is refused with `node_access_denied` (rule R0, which waits for a presence attestation nothing can give
  yet), and creating a grant, re-parenting a node and widening a node's sharing are refused with `presence_required`.
  The binaries and the app are not code-signed or notarised — `SHA256SUMS` is their only provenance, and
  Gatekeeper refuses them until you clear the quarantine flag yourself (`RELEASE.md`). Hardware-backed protection (Secure Enclave with Touch ID) is planned and is not part of this release.
- **Two-factor guards the door, not the safe.** With two-factor on, `credmgrd` will not unlock your vault without a
  fresh code. That check is made by `credmgrd`, not by the encryption: anyone who has your passphrase or your
  recovery code *and* a copy of your vault folder can decrypt it without the second factor. Treat each of the
  passphrase and the recovery code as a complete key to your vault.
- **K-6 — an exported login reaches every project.** `credmgr unlock` exports your login token;
  keep it out of any shell an AI agent runs in, and lock when done.
- **K-7 — sealing is durable.** A sealed project survives a restart and a crash and can be restored for seven days
  (ADR-079). An agent's request while the whole vault is locked is recorded, not answered: you decide it with your
  passphrase (and your authenticator code, if two-factor is on) from the app's Lock screen or with `credmgr approve`,
  and the vault stays locked (ADR-088). After seven days `credmgr doctor --purge-expired-seals` destroys the retained
  originals (ADR-089); the Orphaned copies stay encrypted and nothing in this release can read them.
- **K-8 — rollback protection is software-only.** Someone with your passphrase who can restore
  matched old copies of the vault and its state directory can roll the vault back.
- **K-1 — presence-gated operations are refused.** Revealing a TOTP seed, creating grants,
  re-parenting nodes, reading a full audit record, widening a node's read reach, rebuilding the registry
  (`maintenance.doctor` with `rebuildRegistry`) and replacing the root key (`maintenance.rotate_root`) answer
  `presence_required`: no transport can attest a live user presence yet.
- **No way back to an alpha, and no import from V1.** A vault beta.1 has written to cannot be opened by an alpha
  build (`RELEASE.md`). There is no migration from V1, by design — `docs/11_MIGRATION.md`; `credmgr import`
  reads a `.env` file only.
- **The desktop app is unsigned and its real-app checklist was not re-walked on the final build**
  (`docs/RELEASE_VERIFICATION.md`). A tester walked it in the built app on 2026-10-18 (190 rows pass, 7 fail, 85 not
  pressed) and re-checked the later changes by hand on 2026-10-19, 2026-10-27 and 2026-10-31. It has no control to
  delete an entry (use `credmgr rm`; `credmgr undo` brings one back). An agent's request is decided from the Lock
  screen or with `credmgr approve`.
- **macOS on Apple Silicon only.** The packaged build and the app target `aarch64-apple-darwin`. The workspace is
  written to compile on Linux, but the workflow that tests it there is manual-dispatch only and has not run on this
  release; Windows cannot compile the broker yet (Unix-socket transport only; the named pipe is planned,
  `docs/16_CROSS_PLATFORM.md` §5.3).
- **Not built:** LLM integration (`llm.*`), machine lock and the duress code are designed (`docs/17_AIRLOCK_AND_LLM.md`)
  but do not exist in this build.

## Read the docs

Start at **[`docs/00_README_START_HERE.md`](docs/00_README_START_HERE.md)** — the map and read
order for the full doc corpus (concept, architecture, data model, cryptography, threat model,
access graph, 2FA, field model, UI/UX, API & MCP, migration, build plan, test plan, decisions
— now ADR-001 through ADR-094 — theming, release/integrity, the frontend delivery scope, and the
org-vault design). `docs/14_DECISIONS.md` is the single most load-bearing file if you only read
one — every real design call, with its reasoning, lives there.

Design material for the UI (Phase 6) lives in this repository: the KEEP design system and the
graph-engine spec in `design/`, the screen, theming and delivery-scope specifications in `docs/09`,
`docs/20` and `docs/19`, and the finished app design itself as a sanitised snapshot under
`apps/desktop/design-upstream/` (`docs/14_DECISIONS.md`, ADR-075). (A staged hand-off copy that once
lived outside the repo was deleted on 2026-09-07 and was never sent to anyone.) The desktop app's
typed bridge client is `apps/desktop/src/lib/bridge.ts`.

## Stack

**Rust + Tauri 2, designed to be cross-platform; only macOS on Apple Silicon is built and tested**
(`docs/16_CROSS_PLATFORM.md` — this supersedes the original
Pass-1/Pass-2 plan of a Node.js broker with a Svelte + Swift/WKWebView shell; that plan was
macOS-only and was replaced before any of it was built). Six crates —
`credmgr-core` (pure, I/O-free crypto: X25519 + HKDF-SHA-512 + ChaCha20-Poly1305, envelope
sealing), `credmgr-keystore` (platform keystore trait), `credmgr-store` (manifests, registry,
audit log, backup/rebuild), `credmgr-brokerd` (the daemon — every op, every access decision),
`credmgr-cli`, `credmgr-mcp`. One local daemon (`credmgrd`), reached over a Unix domain socket
(a Windows named pipe is planned, not built) — newline-delimited JSON, never HTTP. No network
listener, no outbound network connection, ever (`docs/17_AIRLOCK_AND_LLM.md` A-1/A-2). The desktop app
(`apps/desktop/`) is Tauri 2 hosting the KEEP design, precompiled to React at build time (ADR-075) —
its Rust bridge reaches all 55 broker operations, it ships a strict Content Security Policy with no
network origin, and its shell has a concealed, self-clearing clipboard command (used by the Copy buttons)
and locks the vault when the Mac sleeps. The design draws its own graph canvas.

## License

CredMgr is **source-available, not open source**: the code is public so that you can read it, audit
it and check that it is safe, and every right not expressly granted stays reserved by FreexStudio.
See [`LICENSE`](LICENSE) (the same text ships at the repository root and in `v1/`). In short, you may
run the current stable release, read and audit the source, build the unmodified current version to
check it against the official release, and report problems or send patches under
[`CONTRIBUTING.md`](CONTRIBUTING.md). You may not fork, modify or redistribute it, or ship a modified
build. It is free to use today; future versions may be paid, and a version you already hold stays
under the licence it came with.

The **CredMgr** and **FreexStudio** names and marks are covered by [`TRADEMARKS.md`](TRADEMARKS.md).
For permission to do something the licence does not allow, or for a commercial arrangement, write to
**Admin@freexstudio.com**.

## Support

Where to ask for help is in [`../SUPPORT.md`](../SUPPORT.md). CredMgr is free today and is built by
the FreexStudio team. If it saved you from a leaked key, you can support the work with a donation:
[`DONATE.md`](DONATE.md) has the addresses and the steps to verify them. Donations are voluntary
gifts, buy no rights, and do not make any future version free. Other help counts just as much: a
security report ([`SECURITY.md`](SECURITY.md)), a test on Linux or Windows.
