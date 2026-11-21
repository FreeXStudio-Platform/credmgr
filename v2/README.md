<!-- artifact-hardened: NEEDS RE-HARDENING — the K-6 entry (ADR-174, feat/adr174-d3, 2026-11-20) was added after the last pass; that pass was: Approved With Known Risks @ 81c0134 on 2026-11-08 via three-pass-v1. Evidence: prior verifier passes (3abb4fe, 320a8f2) and this pass 3 against the code at 9bc33d7 (corpus_check broker_ops 76; 27 error codes; highest ADR 152; --security-level strict alias of stored sealed in cli main.rs; "Strict (stored as sealed)" in core agentcfg.rs and brokerd ops.rs; search entries, hide seed, re-masks in, Settings › Security groups in apps/desktop); independent ADR-150 review P0/P1 fixed with refusal tests (19ccf39); CI green on PRs #56–#60 (17 checks each); full gates.sh green at dbef0c7 incl. legacy alpha.6; VoiceOver pass 2026-11-08, two defects fixed (ACCESSIBILITY.md, #22 closed); Touch ID, idle and screen lock, ADR-150 confirm checked by hand (RELEASE_VERIFICATION §14, §15 and addenda); corpus_check, gen_help --check, release_verification_check clean; secret scan clean. Known risks: K-A not signed or notarised (bound: Gatekeeper quarantine, SHA256SUMS only provenance, Apple Silicon only; owner: operator; resolution: scripts/sign-notarise.sh with a Developer ID before publishing rc.1); K-B per-control re-press of all rows and the built-app look of the 2026-11-08 design merge (§16) not done by hand (bound: §15 spot re-walk of every screen plus e2e/design audit; owner: operator; resolution: record in RELEASE_VERIFICATION before publishing); K-D Touch ID dialog residual, PHASE8 K-21 (bound: refused to identified agents, dialog names the requester, back-off after five; owner: backend and the user at the dialog; resolution: stated in SECURITY.md, none planned for 2.0.0). Not a claim about anything after 81c0134. -->

# CredMgr V2 — "Vault Next"

**A local, offline, node-scoped credential vault for macOS, built to close the gap between giving an AI agent your credentials and keeping them secure: an agent is scoped to one project and a sensitive value is released only when you approve it.**

> **Status (2026-11-08): `2.0.0-beta.1` was published on 2026-11-01 (a GitHub pre-release, unsigned); this tree is `2.0.0-rc.1`, unreleased** (`CHANGELOG.md`; beta.1 predates Touch ID, agent wiring, restore and node gates; the earlier `2.0.0-alpha.6` package was never published and held the CLI and
> broker only). Create a vault (`credmgr init`), unlock it, store and read secrets, split them into
> projects that AI agents are automatically scoped to, turn on two-factor, and recover from a
> lost authenticator — all through the real `credmgrd` daemon, with every change durable across a
> restart. **Unsigned and not notarised; your passphrase is still the key** (on a Mac with a Secure Enclave you can add Touch ID as a second door, see K-5 and K-1):
> read [Known limitations](#known-limitations) before trusting it with anything that matters.
>
> Until 2026-09-24 the backend passed all 406 of its tests and still could not open a vault it
> had created, or keep a change across a restart — every test built its own correctly-keyed
> state, and nothing ran the real binaries end to end. That is fixed (ADR-063 … ADR-066) and now
> proven with the real binaries. Since then: `credmgr import`, `notes` and `node rename` / `policy`;
> a crash-safe root-key rotation (`maintenance.rotate_root`, which since ADR-098 runs after a Touch ID proof);
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

- Every node has its **own encryption key**, its own notes and its own agent scope. The second factor is one gate for the whole vault, and a node can have its own secret (ADR-135; `credmgr gate enroll --node <id>`, `node.gate_*`); a node without one shares the vault-wide window, and a node's policy decides who is asked for it.
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

**Before you install this pre-release, know what it does not do.**

- **Unsigned and not notarised.** macOS Gatekeeper refuses the binaries and the app until they carry an Apple
  Developer ID signature and are notarised, which has not happened. Today they run only after you check the
  checksum and clear the quarantine flag yourself ([`RELEASE.md`](RELEASE.md)).
- **Touch ID is optional, macOS-only and needs setting up (ADR-098):** with no presence key enrolled,
  presence-gated operations are still refused (K-1, below). Your passphrase is always the key; Touch ID unlock is an
  extra door that works on this Mac only. No Windows Hello, TPM or Linux keystore tier exists.
- **No machine lock (ADR-144) and no duress code (ADR-145); the `llm.*` broker operations were dropped (ADR-146).** The coding-assistant wiring is built: `credmgr prompt`, `credmgr agent`, `credmgr mcp --print-config` and Settings → Agents (ADR-141 to ADR-143).
- **macOS on Apple Silicon only.** No Windows or Linux build; both move to `2.1`, not `2.0.0` (`ADR-147`).
- **No way back to an alpha:** a vault beta.1 has written to cannot be opened by an alpha build, and there is no
  downgrade. There is no migration from the V1 vault.
- **GitHub CI ran for the first time on 2026-10-31 and 2026-11-01 (pull request #41, the beta.1 tree) and runs on every pull request since (#44 onward).** Before that the account's billing had blocked every GitHub-hosted job. The local gate run and the built-app check are in [`docs/RELEASE_VERIFICATION.md`](docs/RELEASE_VERIFICATION.md)
  section 13.
- **Checked by hand on 2026-11-08:** the 5-minute auto-lock idle timer and a real screen lock both locked the vault
  ([`docs/RELEASE_VERIFICATION.md`](docs/RELEASE_VERIFICATION.md) §15); the "Confirm before showing secrets" setting (ADR-150; the addendum to §15) and a VoiceOver pass (#22, closed, two defects fixed; [`docs/ACCESSIBILITY.md`](docs/ACCESSIBILITY.md)) were checked too. Not done by hand: the per-control press of every row and the built-app look of the 2026-11-08 design drop (§16).

The full walkthrough — verify, install, start the broker, create, unlock, projects, two-factor,
recovery — is **[`RELEASE.md`](RELEASE.md)**. The short form, from a checkout:

```bash
cd v2
scripts/release.sh --dev                 # builds credmgr, credmgrd and the credmgr-presence Touch ID helper into dist/ (unsigned)
dist/credmgr-*/bin/credmgrd &            # the broker; or install the launchd unit
dist/credmgr-*/bin/credmgr init          # passphrase, then retype the printed recovery code
eval "$(dist/credmgr-*/bin/credmgr unlock <<< 'your passphrase')"
dist/credmgr-*/bin/credmgr set API_KEY --node global <<< 'the-value'
dist/credmgr-*/bin/credmgr get API_KEY --node global
```

Needs Rust 1.78+ (`rust-toolchain.toml`) and the Xcode command-line tools (`swiftc`, for the Touch ID helper). Tests: `cargo test --workspace` (the Argon2id-backed suites take minutes, by design), plus `cargo test` inside
`apps/desktop/src-tauri` for the desktop shell and bridge, which
is its own workspace (ADR-035), and the front-end gates in `apps/desktop` (`npm test`; `npm run test:e2e`, `test:csp`, `test:design`, `test:real`). Counts change with every pull request; the dated counts are in `BUILD_LOG.md`.

## Known limitations

Each is recorded with its bound, owner and resolution path in
[`docs/PHASE8_AUDIT_REPORT.md §4`](docs/PHASE8_AUDIT_REPORT.md).

- **K-5 — your passphrase is the key; Touch ID is an extra door, not a replacement. Unsigned binaries.**
  The vault's root key is stored in the vault folder encrypted two ways: under a key derived from your
  passphrase with Argon2id (256 MiB of memory, 3 passes, 4 lanes), and under the 256-bit recovery code printed at
  `credmgr init`. If you turn on Touch ID unlock (`credmgr touch-id enable`, or Settings > Security > Touch ID in
  the app) a third wrap seals the root key to your Mac's Secure Enclave (ADR-098): it opens only on this Mac and
  only for you. The first two wraps stay, so a copy of the vault folder on another computer can still be
  attacked offline, slowed only by the Argon2id cost of each passphrase guess. Use a
  long, unique passphrase and keep the recovery code offline. While the vault is unlocked, `credmgrd` holds the
  root key and every unlocked project key in memory until it locks (idle timeout or `credmgr lock`; the desktop app also locks it when the Mac sleeps, the screen locks or the session switches, but a daemon running without the app does not); it does
  not lock its memory pages or block debuggers, so software able to read its memory — anything running as root,
  for example — can read those keys. Touch ID does not protect that: it is a presence check on this Mac (K-1,
  below), not an encryption of the folder against another computer. The binaries and the app are not
  code-signed or notarised — `SHA256SUMS` is their only provenance, and Gatekeeper refuses them until you clear
  the quarantine flag yourself (`RELEASE.md`); Touch ID itself does not need signing, and
  `scripts/sign-notarise.sh` waits for the operator's Apple Developer ID. A Windows Hello, TPM or Linux keystore
  wrap is planned for `2.1` (`ADR-147`) and is not part of this release.
- **Two-factor guards the door, not the safe.** With two-factor on, `credmgrd` will not unlock your vault without a
  fresh code. That check is made by `credmgrd`, not by the encryption: anyone who has your passphrase or your
  recovery code *and* a copy of your vault folder can decrypt it without the second factor. Treat each of the
  passphrase and the recovery code as a complete key to your vault.
- **K-6 — closed for an unlock inside a project's folder (ADR-174).** `credmgr unlock` from inside a project's
  folder exports a login that reaches that project only and works only from that folder. An unlock from anywhere
  else is your own whole-vault login: keep it out of any shell an AI agent runs in, and lock when done.
- **K-7 — sealing is durable.** A sealed project survives a restart and a crash and can be restored for seven days
  (ADR-079). An agent's request while the whole vault is locked is recorded, not answered: you decide it with your
  passphrase (and your authenticator code, if two-factor is on) from the app's Lock screen or with `credmgr approve`,
  and the vault stays locked (ADR-088). After seven days `credmgr doctor --purge-expired-seals` destroys the retained
  originals (ADR-089); the Orphaned copies stay encrypted and only the desktop app can read them (K-1: Touch ID, a fresh second factor and the owner's login every time).
- **K-8 — rollback protection is software-only.** Someone with your passphrase who can restore
  matched old copies of the vault and its state directory can roll the vault back.
- **K-1 — presence-gated operations need a Touch ID key on this Mac (ADR-098).** Revealing a TOTP seed (the broker releases it to the owner; the app's "show seed" displays it, re-masks it after the reveal window and never copies it), creating
  grants, re-parenting nodes, reading a full audit record, widening a node's read reach, rebuilding the registry
  (`maintenance.doctor` with `rebuildRegistry`), replacing the root key (`maintenance.rotate_root`) and opening a
  sealed (Orphaned) entry (`orphan.reveal`) run when a Secure Enclave key proves a person is present: the broker
  hands out a single-use challenge, Touch ID (or the device password where no fingerprint is enrolled) signs it,
  and the broker checks the signature against an enrolled public key. The CLI and the app ask for the fingerprint
  themselves. **With no presence key enrolled the old refusal stands** (`presence_required`), and agents and
  fixture tokens never hold a proof. A sealed entry opens only in the desktop app, never in the CLI or over MCP.
  Enrol this Mac's key once with `credmgr presence enrol` or Settings > Security > Touch ID.
  macOS only; Windows Hello, TPM and Linux keystores are not built. Touch ID unlock is refused to a caller the
  broker recognises as an agent (an agent token, or a call from inside a registered project folder); anyone else
  gets a dialog that names the process that asked, and that name is a hint, not proof. Cancel any request you did
  not start yourself ([`SECURITY.md`](SECURITY.md), ADR-148).
- **Confirm before showing secrets (ADR-150) is off by default and guards an unlocked Mac, not a copied folder.**
  Turned on in Settings > Security, the broker refuses to give your own login a value (`entry.reveal`, the app's
  copy, `totp.code`, a value an approval released) or to approve a waiting request with `confirmation_required` until you confirm with Touch ID or the passphrase
  (`session.confirm`; `credmgr get` asks at a terminal, a script runs `credmgr confirm` first); then it does not ask
  again for the trust window you chose (1, 5, 15 or 60 minutes, 5 by default; in Pro mode every time, or only for
  high and critical entries). A confirmation belongs to one login, lives only in `credmgrd`'s memory and ends at
  every lock. Not covered: malware running as you, someone who knows the passphrase, changes that are not reads,
  `search.content` (ids and names only) and `notes.read`; agents are not asked (a `credmgr` run from a registered
  project folder without your login is an agent). Turning it off or making it ask
  less needs a fresh confirmation (`SECURITY.md`).
- **No way back to an alpha, and no V1 import in the CLI or the app.** A vault beta.1 or later has written to cannot be opened by an alpha
  build (`RELEASE.md`). The CLI and the app do not import from V1, by design — `docs/11_MIGRATION.md`; `credmgr import`
  reads a `.env` file only. A read-only copy script, `tools/v1-to-v2/migrate.js`, exists (ADR-097).
- **The desktop app is unsigned and its per-control real-app checklist was not re-walked on the final build**
  (`docs/RELEASE_VERIFICATION.md`). A tester walked it in the built app on 2026-10-18 (190 rows pass, 7 fail, 85 not
  pressed) and re-checked the later changes by hand on 2026-10-19, 2026-10-27 and 2026-10-31, then a spot re-walk of every screen by hand on 2026-11-07 and 2026-11-08 on the `26da2d3` build (§15), with the idle lock, a real screen lock, Touch ID setup, fingerprint unlock and `credmgr unlock --touch-id` checked by hand on 2026-11-08; "show seed" was re-walked by hand on 2026-11-08 after its two fixes (`d9e6c7c`, and ADR-149's blur grace in `5e9bb29`; the addendum to §15); the per-control rows were not pressed again; the "Confirm before showing secrets" setting (ADR-150) was checked by hand on 2026-11-08 (the second addendum to §15), and VoiceOver on 2026-11-08 (`docs/ACCESSIBILITY.md`, two defects found and fixed); the 2026-11-08 design drop (ADR-151) has not yet been looked at in a built app (§16). It has no control to
  delete an entry (use `credmgr rm`; `credmgr undo` brings one back). An agent's request is decided from the Lock
  screen or with `credmgr approve`.
- **macOS on Apple Silicon only.** The packaged build and the app target `aarch64-apple-darwin`. The workspace is
  written to compile on Linux, but the workflow that tests it there (`build.yml`) is manual-dispatch only: it ran the
  workspace on Ubuntu 22.04 once, on the beta.1 tree (pull request #41), and has not run on this tree; Windows cannot compile the broker yet (Unix-socket transport only; the named pipe is planned for `2.1` (`ADR-147`),
  `docs/16_CROSS_PLATFORM.md` §5.3).
- **Not built:** the machine lock (a device-sealed passphrase wrap; its smallest safe version, and why it waits for a
  recovery-code unlock, is `ADR-144`; planned for `2.1`, `ADR-147`). **Dropped, not planned:** the duress code (`ADR-145`) and the `llm.*` broker
  operations (`ADR-146`; the coding-assistant wiring is built in the CLI and the app instead, `docs/17_AIRLOCK_AND_LLM.md`).
- **Agents:** per-node security levels (Open, Guarded by default, Strict, stored as `sealed`), `credmgr mcp --print-config`, Settings → Agents,
  `credmgr prompt` and `credmgr agent init` (`CREDMGR.md`) are built (`ADR-140`…`ADR-143`). A Guarded node makes an agent
  wait for your approval before it reads a high or critical value.

## Read the docs

Start at **[`docs/00_README_START_HERE.md`](docs/00_README_START_HERE.md)** — the map and read
order for the full doc corpus (concept, architecture, data model, cryptography, threat model,
access graph, 2FA, field model, UI/UX, API & MCP, migration, build plan, test plan, decisions
— now ADR-001 through ADR-152, with gaps (099–109, 116–119, 123–129, 136–139) — theming, release/integrity, the frontend delivery scope, and the
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
its Rust bridge reaches the broker's operations (76 of them in this tree, counted by `tools/corpus_check.py`; the endpoint matrix is in `docs/18_ENDPOINT_INDEX.md`), it ships a strict Content Security Policy with no
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
