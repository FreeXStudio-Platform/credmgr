<!-- artifact-hardened: Approved With Known Risks @ af0709a on 2026-11-01 via three-pass-v1. Evidence: GitHub-hosted CI on pull request #41 (FreeXStudio-Platform/credmgr): all 17 checks green at ee08394, including security.yml (cargo audit, cargo deny, semgrep, isolation suite, endpoint matrix 55/55 operations, desktop bridge) and CodeQL for Rust, JavaScript/TypeScript, Python and Actions with no open alert on the PR; build.yml run 41243452910, all 7 jobs green (macOS 15, Ubuntu 22.04, Windows; Rust 1.78.0 and stable); desktop unit tests 706 passed at 930c502; Playwright 672 and 681 passed in the two lanes that were combined at 930c502 (not re-run together); strict public export PASS, 860 files, literal blocklist not loaded; by-hand click-through of the rebuilt app on a throwaway vault (unlock, lock, auto-lock, graph, tree, search, reveal, copy, add entry, settings, integrity, doctor, audit, backup, capture switch, searchable help); final adversarial audit v2/docs/release-verification/AUDIT_2026-10-31.md (the P0 and both P1 fixed); known risks K-1 to K-20 in v2/docs/PHASE8_AUDIT_REPORT.md sections 4 and 7, each with bound, owner and resolution. Known risks that bear on this document: K-14 the idle lock and a real sleep or screen lock were not exercised by hand on this build; K-19 a seed in an unrecognised shape is not protected until its owner types it; K-20 the licence text has not been reviewed by counsel. K-12 (CI had not run) is closed. Not signed or notarised; Windows and Linux built in CI but not run. Not a claim about anything after af0709a. -->

# Changelog — CredMgr V2 "Vault Next"

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html)

> **Corrected 2026-08-17:** this file's own top note used to say "V2 is not built" long after
> it was — the code-history section below was never added when Phase 1 landed, an omission
> found during a full-sweep verification pass. **V2's backend is now built, audited, and
> finished**: Phases 0–5 and 7 closed, Phase 8's adversarial audit closed Approved With Known
> Risks (2026-08-16), and Backend-finish closed all three of its named gaps (2026-08-17,
> concluding with the session/login mechanism, ADR-047 → ADR-056). No named backend item
> remains unbuilt. Phase 6 (the UI) was being designed externally via Claude Design — see
> `docs/00_README_START_HERE.md` for the current full
> picture. V1's own history is in `../v1/CHANGELOG.md`.
>
> **Updated 2026-10-31:** the UI is built, hosted in the desktop app and wired to the broker (see
> `[2.0.0-beta.1]`); the backend gained ops, policy enforcement and a field model after the closure described above.

---

## Timeline — what was added when, and what is coming

Newest first. Dates are when the work landed; no date after today is a promise. Each row links to the version section below.

| When | Version | What landed |
|---|---|---|
| 2026-11-01 | `2.0.0-beta.1` (public repository) | The repository is public as a single neutral commit; first release built from it. Source-available licence (ADR-096). First hosted CI and CodeQL runs on all three platforms. |
| 2026-10-31 | `2.0.0-beta.1` | Screen-capture protection switch in Settings; searchable in-app Help; `HELP.md`; the LLM capabilities manifest; V1 copy tool and the hygiene design. |
| 2026-10 | `2.0.0-beta.1` | The desktop app wired to the real broker (zero mock screens); multi-field entries; sealing and restore; agent approvals, including while locked; two-factor with recovery; concealed clipboard; names and second factor per node; the final adversarial audit (one P0 and two P1 fixed). |
| 2026-09-24 | `2.0.0-alpha.6` | The first packaged release: the daemon opens its own vault; command line, broker and MCP server in one tarball. |
| 2026-08-17 | `2.0.0-alpha.3` to `alpha.5` | Maintenance operations and undo; the session and login mechanism (ADR-056); the documentation pipeline. |
| 2026-08-16 | `2.0.0-alpha.2` | Phase 8 adversarial audit. |
| 2026-08-05 to 08-10 | `2.0.0-alpha.1` | The Rust backend: core, keystore, store, broker, CLI, MCP (Phases 0 to 5 and 7). |

**Coming next, in order and without dates.** `2.0.0-rc.1`: Touch ID and presence checks, Developer ID signing and notarisation, the doctor's duplicate and wallet-bundling scan (`docs/25_VAULT_HYGIENE.md`), the V1 copy folded into the app. `2.0.0`: the first stable release, with Windows and Linux. `2.1.0`: cross-device sync as ciphertext, and agents that use a credential without its value reaching the model. `2.2`: a signed, machine-bound, expiring licence (a failed licence never locks your vault). `2.3`: the first paid tier. **Future versions, platforms and devices may not be free; releases already published keep the licence they came with.** If CredMgr is useful to you, please keep using it, tell us what breaks, and consider a donation (`DONATE.md`): it is what lets us keep building it.

---

## [2.0.0-alpha.1] — 2026-08-05 through 2026-08-10 · Backend, Phases 0–5 and 7

Six Rust crates (`credmgr-core`, `credmgr-keystore`, `credmgr-store`, `credmgr-brokerd`,
`credmgr-cli`, `credmgr-mcp`), built and gated phase by phase per `docs/12_BUILD_PLAN.md`:

- **Phase 0** — toolchain, workspace skeleton, CI, secret-scan hook.
- **Phase 1** — core primitives: the sealed-box envelope (X25519 → HKDF-SHA-512 →
  ChaCha20-Poly1305), node key generation, the access-graph `resolve()` function and its 8×8
  capability matrix.
- **Phase 2** — storage: manifests, the node registry, HMAC-signed cross-binding, generation
  tracking (rollback detection).
- **Phase 3** — the broker (`credmgrd`): the op-dispatch model, `entry.create/update`, the
  pending-write tray for locked-vault writes, the node isolation suite, auto-lock on
  idle/sleep/screen-lock, `graph.snapshot` (ADR-047), `audit.tail`/`audit.get` (ADR-049),
  `grant.list/create/revoke` (ADR-050).
- **Phase 4** — the CLI, `entry.rotate`/`entry.remove`/`entry.restore` (ADR-048), MCP tool
  registrations.
- **Phase 5** — gate 2FA (TOTP enrolment/verification), the `PlatformKeystore` trait.
- **Phase 7** — hardening and closeout: `node.create` (ADR-051), the success-criteria test
  suite run against a real compiled broker over a real socket (not mocks), the
  `guard-no-personal-data.mjs` script, semgrep in CI, doc-corpus stamp reconciliation
  (ADR-052). Exit gate green 2026-08-10.

Phase 6 (the UI) was pulled out of this build chain the same week — it runs externally via
Claude Design, not as versioned backend code; see `docs/00_README_START_HERE.md`.

## [2.0.0-alpha.2] — 2026-08-16 · Phase 8 — final adversarial audit

Opus, max effort, full-corpus re-verification — not a continuation of the sessions before it,
a deliberate second look. Found and fixed one real security bug: `node.restore` authorised
against the caller's token only, not the target node (`node.seal` correctly checks both) — a
cross-node integrity hole letting one project's Admin token restore another project's sealed
node. Fixed with a new `resolve_capability` check (ADR-053), proven with a failing test first.
Also corrected six stale claims across the doc corpus, including the entry-point doc's own
"DO NOT PUBLISH — NO GitHub remote" line, 45 commits and one real push after it stopped being
true. Status: **Approved With Known Risks** — full report in `docs/PHASE8_AUDIT_REPORT.md`.
333 tests passing (332 inherited + 1 new).

## [2.0.0-alpha.3] — 2026-08-17 · Backend-finish — `maintenance.*` and `entry.undo`

- **`maintenance.verify`** (ADR-054) — read-only integrity report: manifest HMAC + registry
  cross-binding checks (already enforced on write, now also checked proactively), plus a new
  dangling-envelope check (files with no manifest entry, or manifest entries with no file).
- **`maintenance.doctor`** (ADR-054) — resyncs a stale-but-self-valid cross-binding; explicitly
  refuses to "fix" a manifest that fails its own HMAC (that would launder a tamper, not repair
  one — the only path back from real tampering is `--rebuild-registry` from a backup, or a
  human). `--rebuild-registry` is `PresenceRequired`, matching `grant.create`/`node.reparent`.
- **`maintenance.backup`** (ADR-054) — real backup creation, wired to `store::backup`
  primitives that existed since ADR-039 but were never called by any op until now.
- **`entry.undo`** (ADR-055) — forward-only for both `remove` and `rotate`: a new mutation
  that puts content back and appends its own audit record, never a rewrite of the
  hash-chained audit log itself. Addressed by `{node, id}`, matching `audit.get`'s own
  authorize-before-confirm-existence shape.

~390 tests passing (333 inherited + ~57 new). The session/login mechanism (ADR-047) was the
one named backend gap still open at this point — closed the same day, see
`[2.0.0-alpha.4]` below.

## [2.0.0-alpha.4] — 2026-08-17 · Backend-finish — the session/login mechanism (ADR-056)

- **A real `vault.unlock`/`vault.gate_verify` success mints a real, non-fixture token** — the
  gap ADR-047 named and nothing but a test fixture could previously close. `Origin::HumanUi`,
  scoped to `global`, every capability, revoked on the next `vault.lock` — see ADR-056 for the
  full design and the deliberate limits it names.
- **`audit.tail`'s per-origin redaction is now reachable through a real transport** — closing
  `PHASE8_AUDIT_REPORT.md` C-2's own "re-check the moment ADR-047's session/login lands" note.
- **ADR-051's R3-universal-Admin question, answered**: `resolve()`'s R3 stays unqualified by
  capability, deliberately — after this change, `Capability::Admin` is reachable in real
  operation only via a token this mechanism mints, always scoped to `global`, so R3's
  admin-unqualified clause remains structurally inert by construction, not by absence of a
  mechanism.
- **CLI**: `credmgr unlock` now prints `export CREDMGR_TOKEN=<id>` on success
  (`eval "$(credmgr unlock <<< "$pw")"` captures it); a new `credmgr gate verify <code>`
  subcommand completes the two-factor path (previously unreachable from the compiled binary at
  all) and mints the token the same way.
- **A named, deliberate limitation, not silently left implicit**: a `global`-scoped session
  token cannot administer, list, or audit any node other than `global` itself — every
  per-node-Admin-gated op (seal/restore/reparent/grant/node.create's parent check) still needs
  its own, still-undesigned per-node elevation path. Handed forward exactly as ADR-047 already
  handed the same "whole vault graph" gap forward once.

Backend work is now complete — no named backend gap remains. Waiting on Phase 6 (the UI,
external via Claude Design) before a final, complete-backend Phase 8 pass.

---

## [2.0.0-alpha.5] — 2026-08-17 · Tooling + design-package — the documentation pipeline

No product-code change. This release is infrastructure for the documentation and design track,
plus the design-handoff package's own refresh.

### Added
- **`tools/visual-engine`** — Apache ECharts 6.1.0, server-side, deterministic. Renders
  quantitative data charts (compare/trend/distribute/relate/compose/flow/matrix/hierarchy) to
  SVG/PNG/self-contained-HTML from a validated job file. Same job + same pins ⇒ byte-identical
  output; zero LLM tokens to re-render. 30/30 unit tests, 22/22 acceptance simulations.
- **`tools/docgen`** — Python. Markdown → self-contained offline HTML + a machine-readable JSON
  sibling, behind a 9-gate sanitizer (tier/secret/PII/implementation-internal/manifest-drift/
  WCAG-AA-contrast/variant-overlap). Renders *structural* diagrams (architecture, sequence,
  flowchart, sankey, timeline, isometric) — deliberately not charts, which are the other
  engine's job.
- **`tools/ENGINE_ROUTING_POLICY.md`** — which of the four possible engines draws which picture
  (`docgen` structural · `visual-engine` quantitative · vendored `force-graph` for the product's
  own live in-app graph, unchanged by this · ephemeral chat visuals, never saved as docs).
- **`tools/PROVENANCE.md`** — full derivation record: what was copied, what was rebranded, what
  was deliberately excluded, and a same-day correction when the first sweep proved incomplete.
- **`docs/blueprints/session-login-mechanism.{md,html,json}`** — the first document built through
  the full pipeline, about ADR-056, embedding a real rendered figure. Proof the port works
  end to end, not just that files were copied.

### Fixed
- **A leftover upstream brand font** (`Space Grotesk`) hardcoded in `visual-engine`'s
  standalone-HTML export wrapper, missed by the port's original sweep because that sweep
  checked source only and no standalone HTML had yet been rendered. Now `Inter`, matching the
  rest of the theme. `tools/PROVENANCE.md` records the correction rather than quietly patching
  over its own earlier "removed outright" claim.

### Changed — design handoff (`<local checkout>`, separate local repo)
- **`03_ENDPOINTS_CURRENT.md` re-verified against source and re-stamped**: 31 → **38** broker
  ops, 10 → **11** MCP tools, 14 → **24** CLI subcommands, plus ADR-056's new session-token
  response shape. Also fixed a leftover upstream-branded node in its `graph.snapshot` example.
- **`VAULT_GRAPH_SPEC.md`** gained node-radius-by-entry-count sizing (§2, with an explicit
  non-leak justification and a linked blueprint figure), a tree-view visual language that
  distinguishes sections by weight/tone/shape rather than hue (§3a — reconciling the request
  for "colour to distinguish sections" with KEEP's own achromatic law), and liveness +
  gamification sections (§8/§9) that name what already qualifies and exclude decorative motion.
- **`04_CLAUDE_DESIGN_PROMPT_STRICT.md`** gained §10: graph/tree pointer, 2FA/settings/logging
  coverage confirmation, an About-screen version number, fixed discrete responsive breakpoints
  (not fluid reflow), and the personal-vs-organization two-bundle split.

---


## [2.0.0-alpha.6] — 2026-09-24 · The first packaged release — the daemon opens its own vault

The first version stamped into the binaries and packaged (`scripts/release.sh`, `RELEASE.md`).
**Unsigned and Software-tier — read `RELEASE.md` → Known limitations (K-5 … K-8) first.**

### Security and correctness — found by running the real binaries, not the tests
- **The shipped daemon could not open a vault.** `credmgr init` created one; `credmgr unlock`
  with the same passphrase answered `wrong_passphrase` — the broker unwrapped with the empty
  placeholder keystore it started with. Nothing loaded a vault after a restart, and every change
  lived only in memory: a restart kept the ciphertext and lost every name, node, grant and the
  2FA gate. All 406 tests passed throughout, because each builds its own correctly-keyed state.
  Fixed (ADR-063): `vault.unlock {passphrase}` builds the Software keystore from the passphrase,
  proves it, loads and verifies the vault from disk (HMAC, rollback counter, cross-bindings), and
  every successful change is written through in the crash-safe order.
- **The 2FA gate is persisted** (ADR-064) — its seed sealed under a root-derived key, recovery
  codes as hashes, the last accepted step so a code cannot be replayed across a restart. A
  re-enrolment that is started and abandoned no longer removes the gate.
- **The desktop bridge's own test suite had been red since 2026-08-31** (four ADR-061 error codes
  it did not know) and ran in no CI job; it now runs in `security.yml`.
- **The desktop window had no Content Security Policy** (`"csp": null`); it now has an absolute
  one, held by a test that fails closed on `null`.
- **Locking one node would have logged the user out of the vault** once `vault.node_lock` was
  reachable — the bridge read the node's `locked: true` as the vault's. Fixed before shipping.
- **Two MCP tools could never succeed.** `credmgr_search` advertised `query` while the broker reads
  `term`, and `credmgr_list` marked `node` optional while `entry.list` refuses without it — every
  agent search, and every list that took the advertised default, was `malformed_request`. Fixed,
  and every tool schema is now held against the arm it calls by
  `crates/mcp/tests/schemas_match_the_broker.rs`.
- **Every stored value's plaintext digest sat beside its ciphertext.** The manifest's `sha256`
  hashed the plaintext, so a guessable value (a PIN, a short token) could be confirmed offline from
  the vault directory alone. It is now the digest of the sealed envelope (ADR-067); a test asserts
  no file under the vault carries a plaintext digest.
- **A login that had expired was silently demoted instead of refused.** The broker resolved a token
  it no longer held from the caller's working directory, so an idled-out login kept "working" with
  fewer rights. It now answers `session_expired` (ADR-068), and the desktop bridge and the CLI treat
  that as "unlock again". `vault.status`, `unlock`, the gate ops, `init` and `lock` still accept a
  dead token.
- **Writes made while the vault was locked survive a restart** (ADR-069). The review tray used to
  keep its envelopes on disk and forget what they were; each now carries a small metadata file and
  the tray is rebuilt at the first unlock. Tray files are treated as untrusted — a malformed or
  planted one is skipped and can never stop an unlock.
- **`maintenance.verify` checks every envelope against its manifest digest**, with no key — a
  swapped, corrupted or half-updated envelope is reported as an error (ADR-067).
- **`deny.toml` bans every HTTP client and server crate** from the workspace, so "no network code in
  the broker" is enforced by `cargo deny`, not by review.

### Added
- **Vault bootstrap — `credmgr init`** (ADR-061, 2026-08-31, not previously recorded here).
- **The last door** (ADR-064): `vault.gate_recover` / `credmgr gate recover` — passphrase plus the
  root recovery code reset a lost gate. Closes Phase 5 exit-gate line 6.
- **`credmgr gate enroll`** — the CLI enrolment path `07_TWO_FACTOR.md §4` named.
- **A login reaches its owner's whole vault** (ADR-065) — every node but Orphaned; the gap ADR-047
  and ADR-056 named.
- **Directories can be bound to a node** (ADR-066): `node.create … workdirs`, `node.set_workdirs`,
  `credmgr node create --workdir`, `credmgr node workdir`.
- **The desktop bridge reaches all 42 broker ops** (ADR-062), with a typed TypeScript client
  (`apps/desktop/src/lib/bridge.ts`) held to the Rust table by drift guards.
- **`credmgr --version` / `credmgrd --version`**, stamped with the commit and target.
- **`credmgr pending`** — list, accept or discard writes made while the vault was locked. The CLI
  told users such a write was "pending review at next unlock" and had no command to review it.

### Counts
42 broker ops (40 + `vault.gate_recover` + `node.set_workdirs`) · 11 MCP tools, unchanged ·
24 broker error codes (19 + ADR-061's four + `session_expired`) · ADR-062…ADR-069.

---

## [2.0.0-beta.1] — 2026-09-24 through 2026-10-31 · since 2.0.0-alpha.6 · public repository 2026-11-01; tagged `v2.0.0-beta.1`

The first beta. **Unsigned and Software-tier — read `RELEASE.md` → "What this beta does not do" and Known limitations first.**
Worked from the Claude Design project's `BACKEND_HANDOFF_NOTES.md` (reported back in `BACKEND_REPORT.md`), from the
finish loops of 2026-10-02 and 2026-10-03, the finish plan C0–C4 (2026-10-17 and 2026-10-18), and the backend waves and
production-plan batches 1–4 of 2026-10-24 to 2026-10-31 (`docs/PRODUCTION_PLAN.md`). Every version stamp says
`2.0.0-beta.1`.

Counts at the head of this section, measured from code on 2026-10-31 at `b94443c`: **55 broker ops**
(`corpus_check.broker_ops()`) · **15** MCP tools · **25** broker error codes · **27** top-level CLI subcommands ·
ADR-070…ADR-097 (ADR-095 is a design record for the post-release licence; ADR-096 relicenses to source-available; ADR-097 records the V1 import and the planned hygiene scan; the next number is ADR-098). Tests, from the recorded runs and **not re-run for this entry**: the last
full workspace listing, on 2026-10-26, was **900 passing in 59 test binaries**, and ADR-093 added five since (905
`#[test]` functions in the crates); the desktop shell's bridge suite ran 200 tests; the front end ran 700 unit tests, the
Chromium and WebKit Playwright suites, 80 real-daemon journeys and the 87-state design audit, all green on 2026-10-30
(`docs/PRODUCTION_PLAN.md`, `BACKEND_REPORT.md`; the Playwright suites ran 658 passed and 2 skipped on 2026-10-26, the
skips being WebKit specs quarantined as QT-1 — there are four now). The alpha.6-era figures were 448 tests in 37
binaries and 65 shell tests. **None of it has run on GitHub for this release** (see Known issues).

> **Upgrading from an alpha, and not going back.** A vault opens unchanged, with no migration step, and every
> existing entry is read in place as a single field. **A vault that 2.0.0-beta.1 has written to cannot be opened by
> an alpha build:** an alpha refuses a version-2 entry envelope (`UnsupportedVersion(2)`), reads a manifest carrying
> `hasTotp: true` as tampered, and drops the seal records of any sealed node. Back up the vault directory and
> `~/Library/Application Support/credmgr-state` first (`RELEASE.md`).

### Highlights — what this beta adds over 2.0.0-alpha.6

- **A desktop app that is the real thing.** Every screen reads from the `credmgrd` broker and every change goes to it; there is no demo data in a release build. First run, unlock, lock, two-factor enrolment and recovery, nodes (projects), entries, notes, search, undo, backup, verify and doctor all run against the real daemon.
- **Entries with any number of labelled fields** (ADR-078), masked values, generate-a-value with undo, bulk paste, and a copy that goes to a concealed, self-clearing clipboard.
- **Project isolation you can seal.** Seal a node and restore it within seven days; the seal survives a restart and a crash (ADR-079, ADR-089); private node names; a crash-safe root-key rotation.
- **Agents that ask, and a person who decides.** An agent's reveal waits for your decision, including while the vault is locked, and is released once, for the fields it asked for (ADR-088, ADR-090, ADR-094); a TOTP seed is never returned by a reveal, only the code it makes (ADR-094).
- **Two-factor that guards the door** with recovery codes and a root recovery code.
- **Security fixes found by the final audit**, all re-verified: no session token in the audit log (ADR-077), no seed readback, approvals taken only by the request they were given for (ADR-094).
- **Release tooling:** a deterministic tarball, SBOMs, a SHA-256 checksum list, the `.app`, `.dmg` and `.zip`; the binaries record macOS 13.1 as their minimum.
- **55 broker operations, 15 MCP tools, 27 CLI subcommands, 25 error codes**, endpoint matrix 55/55.
- **Licence: source-available, rights reserved (ADR-096, supersedes ADR-074).** The source is public to read, audit and report on; running the current stable release is free; copying, forks, modified builds and redistribution are not allowed without written permission; future versions may not be free. `LICENSE` is identical in `v1/` and `v2/`; `TRADEMARKS.md`, `CONTRIBUTING.md` (contribution terms), `DONATE.md`, `SUPPORT.md` and `THIRD_PARTY_NOTICES.md` (generated by `tools/gen_third_party.py`) follow it. The word "open source" is no longer used for CredMgr.
- **Repository moved to the FreexStudio enterprise:** `FreeXStudio-Platform/credmgr`. Secret scanning with push protection, Dependabot security updates and CodeQL (Rust, JavaScript/TypeScript, Python, Actions) are on; every workflow action is pinned to a commit SHA, as the organisation requires.
- **CodeQL triage.** Fixed: a polynomial regular expression in V1's field detector (a length cap) and an unescaped quote in the chart template. The remaining alerts are test code, zero-initialised key buffers and a local-only server, each dismissed with a reason on the alert.
- **A one-way V1→V2 copy tool** (`tools/v1-to-v2/migrate.js`): read-only on V1, never prints a value, verifies each copy by hash, idempotent, skips the operator-sealed targets by default (ADR-097). The doctor's duplicate and wallet-bundling scan is designed, not built (`docs/25_VAULT_HYGIENE.md`).
- **The donation dialog names the real proof address** (Admin@freexstudio.com) instead of a placeholder.
- **A setting for screen-capture protection.** Settings > Security: "Hide the window from screen capture and screen sharing", on by default, asks for confirmation before it is turned off, remembered across restarts (threat T10; the developer override `CREDMGR_CONTENT_PROTECTION=off` still wins).
- **Searchable help.** The Help dialog searches 142 records and says where each feature is (screen, button, menu, shortcut, CLI command); the same text is `HELP.md`.
- **A manifest for LLM agents.** `docs/llm/credmgr-capabilities.json` lists every feature, the 55 broker operations (with the agent-reachable subset), the 15 MCP tools with their input schemas, the error codes with what to do, the human-in-the-loop rules and an explicit never-list. It is generated by `tools/gen_help.py` from `docs/help/features.json` and the code, and `gen_help.py --check` catches drift. No operation, tool or error code was added: an agent keeps exactly the access it had (scoped to a node, sensitive values released only on approval).

### Security
- **The audit log no longer records a session's bearer token.** Since 2.0.0-alpha.4 (ADR-056) every
  audit record made under a login, and every token-workdir anomaly record, carried the token itself
  as `actor` (and, for the anomaly, inside `detail`) in the plaintext audit file and in `audit.tail`,
  so any process running as the owner could read the live token out of the feed and replay it as the
  owner. The actor is now `<Origin>:<session public id>`; bearer-shaped strings are redacted on the
  way into the log and on the way out of `audit.tail`; `Debug` on tokens, requests, scopes and the
  bridge session redacts. A vault written by an affected build still holds dead `cmt_…` strings in its
  audit files — see `SECURITY.md`, "Session token in the audit log". (ADR-077)

- **The release text now states what the Software tier protects and what it does not, in one place** (K-5,
  `docs/04_CRYPTO_AND_KEYS.md §2.4`, repeated in `README.md`, `RELEASE.md`, `SECURITY.md` and the two-factor and
  cross-platform documents): your passphrase is the key; nothing is held in the Secure Enclave; while unlocked
  `credmgrd` holds the root key and every unlocked project key in memory and does not lock its pages or block
  debuggers; there is no Touch ID or presence check; and **two-factor guards the door, not the safe** — it is
  enforced by `credmgrd`, not by the encryption, so someone with the passphrase or the recovery code and a copy of
  the vault folder can decrypt without the second factor. Earlier wording ("the root key alone opens nothing",
  "one TOTP code short of every credential") overclaimed and is withdrawn (ADR-079).
- **`approval-on-demand` no longer promises what it cannot keep.** A value approved for an agent is decrypted and
  staged when the decision is made, any lock drops it, a decision that races a lock stores nothing, and request ids
  are 128-bit (ADR-079). A request on a wholly locked vault used to answer `approval_pending` with nothing able to
  complete it, then `vault_locked`; it is now recorded and can be decided with the unlock factors while the vault
  stays locked (ADR-088, below).
- **Node ids are validated where they are chosen** (`[a-z0-9][a-z0-9_-]{0,63}`; `global`, `orphan`,
  `removed-entries` and `entry-history` reserved): an id such as `../x` used to leave the vault, and two reserved
  names aliased the entry archives onto a sealed node's archive, where a later restore could remove them. (ADR-079)
- **One canonical form for names (ADR-084, threat T4 closed).** `credmgr_core::names::canonical_name` — strip bidi
  and zero-width controls, NFKC, Unicode lower-case, then the look-alike table — is what every uniqueness check
  compares: `entry.create`, each `entry.create_batch` item, the locked-write tray, `entry.restore` / `entry.undo`,
  `vault.pending_accept`. A look-alike of an existing name (`payroll` with a Cyrillic `а`) is the existing
  `entry_exists` refusal, for an agent too; the stored name stays as typed; a name that mixes Latin with Greek or
  Cyrillic is accepted with an additive `warnings: ["mixed_script_name"]` (`credmgr` prints it on stderr). New
  dependency: `unicode-normalization` (pure tables). An older vault that holds two names differing only by case
  keeps both; only a new create is refused.
- **`privateNames` is enforced (ADR-083).** A reader that is not the owner's login sees an opaque node:
  `graph.snapshot` row `{id, nameHidden, name: null, entryCount}`, `entry.list` `{entries: [], nameHidden, count}`, a
  count below three hidden, no name or label through `search`, `entry.get`, the pending tray, `notes.read` or the
  audit feed. The owner sees everything. A node whose name is private gets an opaque id (`n_` + 12 hex) when the app
  creates it, because the id is shown to every reader who may list the node and never changes (ADR-091).
- **`requireTwoFactor` is enforced (ADR-085).** With a confirmed gate, `reveal` (the default) asks before a value
  leaves the vault and `always` before any read of the node; the answer is `two_factor_required` until a fresh gate
  verification. A logged-in owner steps up with `vault.gate_verify` (no token; `credmgr gate verify <code>`); the owner's
  own login is exempt. `node.policy` reports `notEnforced: []`. **The window is vault-wide** — one gate, one
  300-second elevation for every caller, ended by a lock or any node-policy change; a per-node secret is deferred to
  2.0.0 and recorded as a known risk (ADR-093).
- **Names have a length (ADR-093).** `entry.create` and each `entry.create_batch` item refuse a name over 200
  characters (`malformed_request`, naming the bound, never the text); `node.create` validates its label like
  `node.update` always did (1–120 characters, trimmed, no control characters). Existing names are untouched.
- **A decision made with the factors while locked finishes an interrupted root-key rotation first** (ADR-093), as
  unlock does; if that fails it decides nothing.

### Added
- **Entries with any number of fields, with labels you choose** (ADR-078). An entry's plaintext is a
  canonical-JSON field document `{v:1, entryType?, sensitivity?, fields:[{id,label,value,type?,masked?}]}` sealed as
  **envelope version 2**; the version byte is inside the AEAD's additional data, so the payload kind is
  authenticated. A legacy version-1 entry is read in place as one field (id `f_00000000`, empty label) with its
  projection unchanged — no migration. Field ids are `f_` plus eight hex digits; labels are free text (200
  characters, no control characters) with **no vocabulary anywhere**, and a test greps the product for a
  predefined field-name list. A document is at most 16 MiB and a batch at most 64 MiB. A type or sensitivity is
  stored only when you pinned it; `"auto"` clears the pin. The entry type `note` replaces `note-only`; inference
  gained R0 (one field labelled `note`/`notes` is a note) and R1 (a TOTP seed with at most two fields is a TOTP
  entry). `ManifestEntry.hasTotp` is skipped when false so alpha.6 manifests still verify.
- **Seven new broker ops** (48 → 55). ADR-078: `entry.get` (labels, types, masking and ids, **never a value**) and
  `field.add`, `field.update`, `field.remove`, `field.reorder` (48 → 53). Field edits keep the entry's history and are
  undoable with `entry.undo`; `entry.create`, `entry.create_batch`, `entry.update`, `entry.rotate`, `entry.reveal` and
  the review tray carry fields. The broker never parses the paste grammar — the CLI and the desktop shell do — and a
  field op needs the capability `entry.update` needs, under the same graph rules (isolation tests I-27…I-29).
  ADR-087: **`util.generate`** (the 54th), the password generator, in the broker (`credmgr generate`, bridge command
  `util_generate`): length 8–128, symbols, pronounceable; the value never exists in page JavaScript. Not an MCP tool.
  ADR-090: **`vault.approval_get`** (the 55th), below.
- **Approval while the vault is locked (ADR-088, ADR-090).** A reveal on a wholly locked vault records a request;
  `vault.approval_decide` with the passphrase (and the authenticator code) releases that one value while the vault
  stays locked (`credmgr approve <request> [--deny] [--code <n>]`). A recovery code is refused; wrong factors count
  toward the unlock back-off; the spent TOTP step survives a restart; the decision is audited under `Factors`.
  `vault.approval_get` lets the person see what a waiting request asks for before deciding: node and entry (by name
  when the broker holds the names and the node's name is not private), the command, the seconds left; with no
  `request`, the list of everything waiting. Read-only, works while the vault is locked, decrypts nothing; an unlocked
  vault answers only the owner's login. `vault.status` carries a bare `pendingApprovals` count. CLI:
  `credmgr approvals [<request>] [--json]`, and `credmgr status` prints the count. Neither op is an MCP tool; I-13 is
  unchanged.
- **Undo of a field change (ADR-086).** No new op: `entry.undo` already covered the four `field.*` ops; its answer
  gains `ok` and `restored`, and a field edit is undoable for seven days.
- **CLI** (21 → 27 top-level subcommands): `credmgr field ls|add|set|rm|mv`, `credmgr get --field <label>`,
  `--field-id`, `--all` and `--json` (an entry with several fields and no selector refuses and lists the labels),
  and `credmgr set --bulk` (one paste becomes one entry; on an existing entry it replaces the field list),
  `--field`, `--field-id` and `--label` (values still come only from stdin); `import`, `node rename`, `node policy`
  and `notes` (below); and `generate`, `approve` and `approvals` (above).
- **MCP** (11 → 15 tools): `credmgr_get_metadata`, `credmgr_field_add`, `credmgr_field_update`,
  `credmgr_field_remove`; `credmgr_create`, `credmgr_update` and `credmgr_rotate` take `fields`. No tool reorders,
  creates a grant or returns a value from the metadata call.
- **Sealing that survives a restart and a crash** (K-7, ADR-079). The orphan cold key (`keys/cold/orphan.key`, format
  `CMCK` v1, 98 bytes) is built and opened only by `node.seal`'s pre-flight; `credmgr init` creates the orphan node
  (an older vault gets one at its first seal or `maintenance.doctor`, never at unlock); seal records live in the
  signed registry (format 2) under the HMAC and the generation counter, and seal and restore are commit protocols
  with load-time roll-forward. `maintenance.rotate_root` re-seals the cold key and refreshes every seal record;
  `maintenance.backup` includes the cold key; `maintenance.verify` checks it. `node.seal` reports
  `archiveMovePending` and `node.restore` reports `workdirsDropped` when they apply.
- **Seal and restore are isolated from concurrent registry writes, and expired seals can be purged (ADR-089).** Both
  re-check under the persist lock; `node.create` and `node.set_workdirs` wait for it. `maintenance.doctor` with
  `purgeExpiredSeals` (`credmgr doctor --purge-expired-seals`, opt-in, Admin on `global`; `--dry-run` only lists)
  destroys the retained originals of nodes sealed more than seven days ago: the entries stay in Orphaned, sealed to
  the cold key, and only the way back to the live node ends. A plain Doctor run never purges.
- **Release tooling** (the 2.0.0-beta.1 line). `scripts/release.sh` writes a **deterministic** tarball, CycloneDX bills
  of materials with no build-machine paths, and a `SHA256SUMS` over every published file, and runs its own
  `--verify` (`--verify [DIR]` re-checks an existing `dist/`); `scripts/release-app.sh` builds the desktop app as an
  ad-hoc sealed `CredMgr.app`, `.dmg` and `.zip`, starting the built app and requiring a real window; `scripts/fresh-install-check.sh`
  installs the tarball the way a user would; `scripts/release-selftest.sh` corrupts copies of a good release and
  requires `--verify` to refuse each; a Homebrew formula is prepared under `packaging/homebrew/` and **not
  published**. Measured 2026-10-03: the same commit in the same checkout is byte-identical; in a second checkout the
  bills of materials are identical and the binaries differ in 47–48 bytes (the Mach-O UUID and the ad-hoc signature).
  Nothing signs, notarises, uploads or publishes (K-4, K-5). The artefacts in `dist/` on 2026-10-31 were built from
  `709840c`, and `release.sh --verify` passes on them.
- **`docs/RELEASE_VERIFICATION.md`** — a checklist of the controls of the built app (the event, the bridge command and
  broker op it reaches, the expected result): 214 control rows in 22 screen templates, derived from the shipped templates
  of 2026-10-03, plus 30 menu-item rows. Its result column was filled in by a tester pressing the controls in a built app
  on 2026-10-18 (190 pass, 7 fail, 85 not pressed, each saying why; no P0, the one P1 fixed), and §11–§13 record the
  later design drops and the built-app checks of 2026-10-19, 2026-10-27 and 2026-10-31. The rows were **not extended
  for the controls the later drops added**: `tools/release_verification_check.py` reports 48 findings against the current
  templates (a row missing for a new control, or naming a handler that moved), so its `--self-test` refuses to run until the rows are brought level.
- **`scripts/e2e-fields.sh`** — the multi-field entry through the real binaries (bulk paste, selection, field edits,
  undo, a seal and a restore with fields, a restart, then a vault written by 2.0.0-alpha.6 opened unchanged). The
  alpha.6 compatibility segment needs the alpha.6 binaries (`LEGACY_BIN_DIR`) and counts as a failure without them.
- **Rename a node** — `node.update` (ADR-071). The id never changes; only the label. Global and
  Orphan cannot be renamed.
- **Change a node's policy** — `node.policy` (ADR-071): a partial patch with a mandatory reason
  recorded in the audit. Tightening needs the admin gate; widening a node's reach needs presence and
  is refused until presence exists.
- **Node notes** — `notes.read` / `notes.write` (ADR-072): markdown sealed under the node key,
  reachable only with the `notes` capability, and refused if the file does not match the digest
  the signed manifest records. `maintenance.verify` checks it without a key. `notes.read` also
  returns the manifest generation a write must be based on, so a grantee holding `notes` without
  `list` can write (ADR-077).
- **Batch create** — `entry.create_batch` (ADR-073): up to 500 single-value entries in one call,
  all validated before any is written. Each item may carry several fields since ADR-078.
- **Replace the root key** — `maintenance.rotate_root` (ADR-076): a new root key, every
  node key re-wrapped, both root wraps rewritten, every root-signed file re-signed, and a new
  recovery code issued once. Crash-safe by a stage / commit / roll-forward journal whose recovery is
  key-free and runs at daemon start and at every unlock, serialised by a per-vault lock; the vault
  opens with the old key or the new one at every instant. The roll-forward checks every staged file
  against the commit record before it moves the first one; if the commit record cannot be proven
  durable it moves nothing, locks the broker and answers `completionPending` (the desktop bridge drops
  its login at once), and the next unlock finishes the move. A second `credmgrd` or broker state that
  starts mid-rotation waits on the per-vault lock (`run/rotation.lock`) instead of deleting the stage
  as a crash leftover, and the daemon skips recovery when a live broker already serves the vault. The
  wire answers `presence_required` (after the human, `admin` and second-factor checks) until presence
  attestation exists; the op is on the MCP forbidden list and the per-uid auth backoff, and the CLI
  has no command for it; the new recovery code is zeroised when the outcome is dropped.
  `scripts/emergency-decrypt.mjs` recognises a vault caught mid roll-forward and says what to do
  instead of "authentication failed".
- **CLI parity for the design side's asks**: `credmgr import <file|-> --node <id>` (an all-or-nothing
  `.env` import; a quoted value whose missing closing quote would swallow the next assignment is
  refused, naming both line numbers and never content; a batch that stops part-way exits non-zero),
  `credmgr node rename <id> <label>`, `credmgr node policy <id> --reason …`, and
  `credmgr notes show` / `set` / `clear`. Text comes from a file or stdin, never argv. `notes set`
  refuses empty input, so a failed pipe cannot destroy a sealed note; `notes clear` is the only
  deletion. `--reason` no longer swallows the next option. Top-level subcommands 21 → 23.
- **The desktop app is hosted and wired** (ADR-075): the stock SvelteKit scaffold is replaced by the KEEP design,
  precompiled at build time (React 19.3.0, Vite 8, TypeScript 7) and served under the unchanged strict CSP
  (`script-src 'self'`, `style-src 'self'`, no `unsafe-eval`, no `unsafe-inline`, no remote origin). Build-time gates:
  `verify-build` (no inline code, eval, Babel or remote URL), `verify-csp` (WebKit and Chromium, with canaries),
  `verify-parity` and `verify-design-audit` (against the design export). A sanitised upstream snapshot and its
  `PROVENANCE.md` sit under `design-upstream/`; its importer refuses to run without the project-name table kept outside
  the repository, and a render error shows "Something went wrong" instead of a blank window. **Every screen reads from
  the broker and every change goes to it** (`src/vault/`, one model, call-then-re-read, no optimistic write): first run,
  the lock screen with the second factor and recovery codes, the graph and tree, an entry's fields (add, edit, remove,
  reorder), the add-entry dialog with single and bulk modes and a live preview, the review tray, node create, rename,
  lock and seal, grants, search, settings, backup, verify, doctor and root-key rotation. A control with no operation
  behind it was removed rather than left mocked; a release build carries no demo data and no screen shows a "mock" or
  "not built" marker. Five operations are sent for real and refused with `presence_required` (grant creation, the full
  audit record, a TOTP seed, root-key rotation once its other checks pass, a registry rebuild). The app has **no
  control to delete an entry, to edit a node's note, or to decide an agent's request while the vault is unlocked**.
  Tested by the shell's bridge suite, by Vitest and by Playwright tests that run the app under the production CSP against
  a fixture broker held to `bridge.ts`'s declared shapes (0 CSP violations, 0 console errors, 0 external requests), a
  design audit probe, and a real-broker suite that drives the built app against a real `credmgrd` (counts above).
  What the later design drops and follow-ups added to it:
  - *Setup choices and a menu-bar icon (ADR-081).* The first run can skip the recovery-code retype, accepts a passphrase of
    four characters or more (eight or more recommended) and treats the second factor as optional; a menu-bar icon
    survives closing the window, and closing the window locks the vault first.
  - *UI hardening (chunk C2).* One open entry holds secrets at a time; Restore works from the broker's sealed list after a
    restart; a 2FA marker on entries; menu keys; the design project's `audit-probe.js` stays private (development only,
    not shipped).
  - *Design drop 2026-10-18.* The milestone reminder (50/14, 150/45, 300/90, at most three, "don't remind me"; ADR-082),
    the sealed supporter extras and their code prompt, the Graph / Identity / Motion / Games regroup of Settings →
    Appearance with a live preview, the free Milestones list, the header badge, the unlock flourish, CredPong node shapes
    and trail, node shapes in the worktree, single-key shortcuts that can be turned off, warnings on names that mix Latin
    with Greek or Cyrillic letters, 24 px targets, and a CredGames library (CredPong only; further titles are bundled,
    never loaded from a script). The flourish and the day count start only from a successful unlock. New window keys:
    `credmgr_donate_unlocked`, `credmgr_extras_key`, `credmgr_usage`, `credmgr_keys` (all in `PRIVACY.md`). Release builds
    have neither the test pack nor the test hooks; `scripts/verify-csp.mjs` asserts `crypto.subtle` in WebKit and
    Chromium, and in the built macOS window the extras prompt reached its decrypt step (`RELEASE_VERIFICATION.md` §12.1).
    `scripts/guard-no-secrets.mjs` gained a `base64-blob` rule (300+ base64 characters) that allows the extras pack by name
    only. Donation policy and the docs it changed (`DONATE.md`, `PRIVACY.md`, the design-upstream `PROVENANCE.md`) came
    with it, and so did the front-end records imported into `docs/` (`FRONTEND_THREAT_MODEL.md`, `ACCESSIBILITY.md`,
    `AUDIT_2026-10-18.md`, `SUPPORTER_EXTRAS_PLAN.md`).
  - *Design drops 2026-10-24 and 2026-10-25, wired to the broker.* Undo after Add field / Edit / Remove (`entry.undo`);
    Generate in Add field (the broker makes the value, the dialog shows it masked with its entropy, it enters the entry
    only through `field.add`); a dialog for `two_factor_required` and a step-up; a decision made on the Lock screen
    while locked (request id, passphrase, code); the privateNames checkbox on the node dialog and a "name hidden" chip on
    the owner's row; Doctor asking for `purgeExpiredSeals`. The "recorded, not enforced" wording is gone from the node
    dialog, the inspector and Help.
  - *Follow-ups of 2026-10-26 (ADR-090, ADR-091).* The Lock screen asks `vault.status` every five seconds and lists the
    waiting requests (the request-id field returns only when none is listed). The broker's `warnings` are shown
    (`mixed_script_name` on entries, batches, node creation and rename) in the same notice as the success, without
    blocking. The audit id passes through the shell into the answer of every changing op (24 ops), and Undo uses it and no
    longer reads `audit.tail`. **The shell reloads the main webview on every lock it sees** (sleep, screen lock, session
    switch, menu bar, window close, quit), after the broker lock, the clipboard clear and the `credmgr://locked` event,
    and the Lock screen's note survives the reload; the page's own locks (the Lock button, ⌘L and the idle timer) reload
    it too, 150 ms after `vault_lock` answers (2026-10-27). A lock the broker takes by itself is not seen by the shell and
    does not reload. The second factor is given on purpose: the chip on a node that asks for one opens "Give the second
    factor" (the owner's login is exempt). Four WebKit-only focus races are quarantined (`test.fixme` on WebKit, register
    row QT-1); Chromium still runs them.
  - *Design drop B20, merged (ADR-092).* **Doctor no longer purges by itself:** a plain Doctor run sends no
    `purgeExpiredSeals` (it used to, so its Apply destroyed seal originals without a separate ask); the new "Doctor with
    purge" row previews, then applies, the removal of originals of seals older than seven days. The inspector shows
    "2fa · on reveal", the action "Give second factor" and, while the 5-minute window is open, a countdown; a step-up with
    no gate enrolled says so. The Lock-screen approval shows a count, an always-visible request-id field and factors only
    after a request is chosen; a locked Deny needs the passphrase and code. The live mixed-script name notice is removed
    (the broker's `warnings` after saving remain). Design snapshot `design-upstream/2026-10-26/`; the contrast line for
    input borders was not taken (the owner's call). The Add entry name is capped at 200 characters (ADR-093).
- **A concealed, self-clearing clipboard and lock-on-sleep in the desktop shell.** `entry_copy` reveals
  the entry Rust-side (the value never reaches the window) and writes it concealed, transient and
  this-Mac-only (no Universal Clipboard or Handoff), cleared after 30 seconds only if the clipboard is
  still the app's own content, and at once on the Lock button, sleep, screen lock, session switch and
  quit; a copy in flight when a lock lands is refused. The app's Copy buttons use it, and `navigator.clipboard`
  appears nowhere in `src/` (a test fails if it does); `copy_text` puts non-secret text (a donation address, a
  node id) on the clipboard with no marker and no timer. The shell locks the vault on sleep, display
  sleep, screen lock and session switch whether or not it holds a login, and tells the window. The
  scaffold's `greet` command and the `opener` plugin are removed; the app's window content policy has
  no network origin, and `cargo deny` / `cargo audit` policies cover the shell's own dependency tree.
  A KEEP app icon, a production product name, a 1280×820 window and macOS 13.1 as the minimum
  replace the scaffold's defaults.
- **Small wire additions** (ADR-077, ADR-080, ADR-090): `vault.status` returns `initialized` and `pendingApprovals`;
  `entry.list` returns `entries` (type, sensitivity, field count, dates) to human sessions only — an agent or MCP caller
  keeps ids and names — and `hasTotp` on its rows; `graph.snapshot` carries `meta.sealed` for a non-agent caller holding
  Admin (ADR-080); a locked node on an unlocked vault answers the new `node_locked` instead of `vault_locked`, so the
  desktop app is not logged out (error codes 24 → 25).
- **`scripts/endpoint-matrix.py`**: calls every broker op over the real socket against the real `credmgrd` on a
  throwaway vault and asserts the documented success or refusal — 243 rows over 55 ops on 2026-10-26, with no
  known-gap or blocked row left (K-7 closed) — and invariants over every generated secret. Wired into `security.yml`,
  `build.yml` and the self-hosted evidence lane; never on push.
- **`scripts/e2e-journey.sh`** — the real-binary journey (init, unlock, restart, locked write, 2FA,
  the last door, a second daemon, imported values and a sealed note surviving restarts, a seal and a restore across a
  restart, generate and a decision while locked, no plaintext or bearer-shaped string on disk). Run it before a release.
- **Repository front door**: a public landing `README.md`, root `SECURITY.md`, `CONTRIBUTING.md` and
  `CODE_OF_CONDUCT.md`, `.github/CODEOWNERS`, V1/V2-aware issue and pull-request templates, and a
  `docs/history/` folder for finished handover and planning documents.

### Changed
- **Licence: MIT for everything and everyone, organisations included** (ADR-074). No licence key, seat
  limit or payment gate anywhere; money is voluntary donations plus an optional commercial licence
  (an invoice, a certificate, priority support) through the publisher. ADR-074's first wording had the desktop app
  with no donation toast and no supporter unlock code; ADR-082 (2026-10-18) superseded that part: the app shows a
  dismissible reminder at entry milestones and opens a pack of cosmetic extras with an e-mailed supporter code.
  **Nothing functional is gated.**
- **Unlock backoff caps at 1 hour** (was 15 minutes) — the operator's crypto spec (ADR-070).
- **CI:** `build.yml` and `security.yml` ran green on 2026-09-24 (7/7 and 8/8, on the alpha.6-era tree) and have not run on
  this release. The crates workspace is no longer built on Windows (the broker is Unix-socket only until the named-pipe
  transport exists); Argon2 is compiled optimised in dev and test builds, which brought the suite
  from past GitHub's 20-minute job limit to minutes without changing a parameter.
- **`VAULT_GRAPH_SPEC.md §7`** carries the signed-off entry-dots amendment.
- A vault holding key material a rotation cannot re-wrap (`root.wrap.se`, `keys/cold/*`) makes the
  rotation refuse, changing nothing. Every broker request now passes an internal request barrier
  (shared; exclusive for a rotation by a live owner session).
- **Dependencies** (all within the MSRV pins): the v2 workspace lock (`interprocess` 2.4.3 → 2.4.4 and eight transitive
  crates), the desktop shell's Rust lock (92 transitive crates), `vite` 8.3.5 (six advisories on 8.3.0–8.3.2), and the v1
  and visual-engine npm locks. On 2026-10-31 (`b94443c`) the fourteen Dependabot alerts were closed: `tools/visual-engine`'s
  `@modelcontextprotocol/sdk` 1.30.0 → 1.32.2 and `zod` 3.25.76 → 4.6.6 with their transitive packages, and v1's
  `body-parser` 1.20.8 → 1.20.9 and `qs` 6.16.0 → 6.16.2. The shell's `tauri` crate family moved to 2.12.1 with the shell
  lane, level with the desktop npm packages and the Tauri CLI. The rest of the v2 workspace waits on a newer compiler
  (RustCrypto 0.11 / 0.13 needs Rust 1.85, `totp-rs` 6 needs 1.88).
- **`tools/visual-engine`'s and `v1`'s package manifests state the MIT licence** (the engine said
  `UNLICENSED`; `v1` said nothing).
- **`v2/RELEASE.md`'s checksum step could not pass on a genuine download.** `SHA256SUMS` listed the
  two binaries inside the tarball as well as the tarball, so checking it before extracting reported
  them `FAILED open or read`. It is now one line per published file, checked with
  `shasum -a 256 -c --ignore-missing SHA256SUMS` (which passes silently when nothing matched, so the guide demands the
  `OK` line) and the tarball carries its own manifest; `scripts/fresh-install-check.sh` runs exactly that against a
  folder holding only the tarball and `SHA256SUMS`. `RELEASE.md` also gained the no-downgrade box, the unsigned-app
  steps, the Software-tier disclosure, the multi-field and sealing walkthroughs, a Homebrew note, and, on 2026-10-31, a
  list of what the beta does not do.
- **`v2/PRIVACY.md` matches the shipped behaviour:** the app makes no network request (it had listed
  an opt-in update check and an allowlisted documentation link, neither of which exists), names the eleven
  local-storage keys the window writes (`credmgr_prefs` is the settings record) and that none holds a vault name in
  the clear, describes the clipboard, auto-lock and reveal behaviour, and no longer cites `credmgr where`, `credmgr export` or an LLM
  Integration setting that does not exist.

### Fixed
- `totp.code` on a short stored seed panicked the connection thread and left the client with a
  closed socket (MX-1). It now answers a code for any seed of at least 80 bits and a typed
  `malformed_request` below that; a panic inside any op is answered as `internal`; a persisted gate
  secret that is not usable is reported as a corrupt gate document instead of panicking. Padded,
  lower-case or grouped seeds are accepted. The 80-bit floor is a recorded deviation from RFC 4226's
  128 (a stored seed is issued by the verifying service, not chosen here). (ADR-077)
- A locked node on an unlocked vault answered `vault_locked`, which logged the desktop app out. (G3,
  ADR-077)
- `credmgr notes set` / `notes clear` no longer need the `list` capability. (ADR-077)
- **Seal and restore were not crash-safe** (ADR-079, F-a): files moved before the registry committed, so a crash in
  between left a registry naming a node whose manifest was gone and a vault that would not unlock. Also fixed there:
  orphan rows carried the original envelope's digest (F-b); a project with live sub-nodes could be sealed, leaving
  dangling parents (F-c); a sealed id could be re-created and its files collided with the archive (F-d); restore
  re-inserted without re-validating workdirs or parent (F-f); the hot key was removed without being zeroised (F-g).
- **Finish plan chunk C1 (ADR-079 amendment, ADR-080).** A write-through can no longer slip into the window of
  `node.seal` / `node.restore`; hot keys are zeroised where they sit, not on a moved copy; a malformed retry no longer
  burns a human's one-time approval. The release verifier never extracts a tarball whose member checks failed, extracts
  member-by-member after path validation on a Python without `tarfile` filters, and executes the binaries only with
  `--run-binaries`.
- **Review findings of the 2026-10-24 wave**, each fixed with a test: a private node's names reaching a non-owner through
  `entry.undo` / `entry.restore`; invisible characters (a variation selector after `payroll`) making a visible twin; an
  unbounded approvals table on a locked vault; a step-up with no gate enrolled feeding the unlock back-off.
- **WebKit autocorrect on every text field (F-5, `16cbf29`).** A typed `beta` became `Beta`, so the seal confirmation never
  matched; the template compiler now turns autocorrect, autocapitalise, autocomplete and spellcheck off on every input
  and textarea.
- **The final audit's two security findings (ADR-094).** A reveal returned a stored 2FA seed to any caller that could
  reveal the entry (an agent, an MCP client, the CLI): `entry.reveal` now answers a seed field with `value: null` and
  `redacted: "totp_seed"`, for every caller; the code still comes from `totp.code`. There is one seed class, shared by reveal and `totp.code` (an `otpauth://` URI, upper-case base32 at 16, 20, 24, 26, 32, 40, 52, 56 or 64 characters, groups of four in any case, or a field typed `totp-seed`); `totp.code` now refuses a field outside it (a change: type such a field `totp-seed` first), and only the owner can retype a seed field away from the class. An approval given for one caller's
  request was taken, whole, by another caller in reach: an approval is now one slot per (node, entry, requester),
  releases only the fields that request asked for, and the table is capped at 512 slots. Also: Doctor no longer advises `rebuildRegistry`, which
  needs presence; the documents that called the gate per-node, called the idle and sleep locks proven on this build,
  or described `credmgr backup` as restorable were corrected. Report: `docs/release-verification/AUDIT_2026-10-31.md`.
- **A stale line on the second-factor step (`b94443c`).** After a request was approved on the Lock screen, the next
  unlock's code step still showed "approved with the passphrase · the vault is still locked"; an unlock attempt now
  clears it.
- `docs/10_API_AND_MCP.md` showed `"scope": "vault"` in the `two_factor_required` example; the broker
  has always emitted `"global"`.

### Removed
- **Amplitude** — the uncommitted analytics instrumentation was dropped (operator); the app has no
  analytics or telemetry, as `PRIVACY.md` says. (`devalue` was patched 5.9.0 → 5.9.4 in the old scaffold's
  lockfile; it left the tree with the scaffold below.)
- The desktop scaffold's SvelteKit front end, the shell's `greet` command and the `opener` plugin
  (a test fails if either returns).

### Known issues
- **K-9 — a truncated audit tail is re-signed by the next request.** `audit::append` signs the tip over
  the log as it stands without verifying it first, so removing the final lines of the current month's
  log is detected by `credmgr verify` only until the next broker request. Pre-existing (Phase 3);
  recorded in `docs/PHASE8_AUDIT_REPORT.md §4`. The earlier K-5…K-8 stand.
- **The second factor is vault-wide (ADR-093).** One code given for one node opens the gate for every node that asks for
  one, for every caller (agents, MCP, CLI), for up to 300 seconds. Bound: the window cannot be extended and ends on a lock
  or any node-policy change; the nodes that ask are the ones the owner marked; the owner's own login is unaffected.
  Owner: the operator. Resolution: a per-node second factor, milestone `2.0.0`.
- **`vault.approval_get` tells a locked vault's neighbours more than an unlocked one's (ADR-090).** On a locked vault any
  same-user process (an agent included) can learn which nodes and entries other agents are asking for, and the names of
  nodes that are not private; an unlocked vault refuses the same caller. It cannot read a value, decide anything or see a
  private node's names. Accepted for the Lock screen's sake.
- **K-7 is closed in part; K-10 is new** (`docs/PHASE8_AUDIT_REPORT.md §4`). The factor-bearing approval
  (`vault.approval_decide`, `vault.approval_get`, `credmgr approve`), the purge of expired archives and `meta.sealed` in
  `graph.snapshot` are built (above). Not built: a `keystore` field in `vault.status` and offline recovery of orphaned
  entries; open: hot keys copied without a wipe on a whole-map replace, and an approval keyed by (node, entry) rather than
  by the requesting session. K-10: the broker reads one request line with no size cap (a 64 MiB batch is a same-user
  memory-exhaustion path), an entry-level `reveal` grant may never be usable, `search` matches names only, decoded field
  documents are not scrubbed from memory on drop, and rotation history is not pruned.
- **`credmgr get` on a multi-field entry with no selector reveals before it refuses.** It sends `entry.reveal` with no
  `fieldIds`, so every field value crosses the socket into the CLI process and one reveal of the entry is audited, and
  only then exits 2 with the labels (`crates/cli/src/main.rs`, `cmd_get`). Nothing is printed, but the refusal should
  list the labels from `entry.get` (a capability read, never a value) and reveal nothing. `credmgr field ls` already
  lists labels without a reveal.
- **The desktop app is unsigned and its per-control checklist was not re-walked against the final screens**
  (`docs/RELEASE_VERIFICATION.md`). It has no control to delete an entry, to edit a node's note or to decide an agent's
  request while the vault is unlocked. The Help dialog says a note is "masked until you reveal it", but a text field is
  not masked. The 5-minute idle lock (the window's idle lock, 15 minutes by default) and a real sleep or screen lock were
  not exercised by hand on this build; the operator's sleep-and-wake check of 2026-10-18 was on an earlier build.
- **The command-line binaries are not yet proven on a macOS older than the build machine's.** They record 13.1 as their
  minimum (`otool -l`, `LC_BUILD_VERSION`; `scripts/release.sh` pins `MACOSX_DEPLOYMENT_TARGET`, fixed after the claim
  check found 27.2, the build host's version, in the first beta.1 build).
- **The bundled fonts' licence texts are not copied into the built `.app`.** About → Licences names the three typefaces and
  says their SIL Open Font Licence texts ship in `third_party/fonts`, which is a folder of the repository, not of the app.
- **GitHub CI has not run on this release.** The account's GitHub billing blocked every GitHub-hosted job (issue #33): the account is on the Free plan with **no payment method on file**, October's included Actions minutes were used up and about $36 of overage was billed with nothing to charge it to, so GitHub refuses to start any job ("recent account payments have failed or your spending limit needs to be increased"); the included allowance resets on 1 November. So
  `build.yml` and `security.yml` could not be dispatched for 2.0.0-beta.1. The evidence is the local gate runs recorded in
  `docs/PRODUCTION_PLAN.md` and `BUILD_LOG.md`, and the built-app check in `docs/RELEASE_VERIFICATION.md` §13. The
  `security.yml` job is still named "isolation suite (I-1..I-25)" and also runs I-27…I-29.
- **Not built, and scheduled in the `2.0.0-rc.1` and `2.0.0` milestones** (`docs/PRODUCTION_PLAN.md`): presence and Touch ID,
  the Secure Enclave tier, signing and notarisation, aliases and near-duplicate detection, the `.env` importer's preview
  and collision options, `node.rekey`, a machine lock, a duress code, `llm.*`, security levels, content search, Windows and
  Linux keystores and the org vault.
- **Version skew (resolved in C3):** the workspace was `2.0.0-alpha.6` while the desktop app said `2.0.0-beta.1`; all manifests now agree, and `release.sh --verify` flags mixed versions.

### Planned next — not in this release

Nothing below is built (except the V1 copy tool noted above); each item is a design record, with no dates. **Future versions, platforms and devices may not be free; releases already published keep the licence they came with.** If CredMgr is useful to you, please keep using it, report what breaks, and consider a donation (`DONATE.md`): it is what lets us keep building it. Order and gates: `docs/PRODUCTION_PLAN.md`, `docs/24_LICENCE_AND_DONATION_PROOF.md` §10.
- **`2.0.0-rc.1`:** Touch ID / presence, the `.env` importer's preview, the doctor's duplicate and wallet-bundling scan (`docs/25_VAULT_HYGIENE.md`), the V1 copy tool folded into the app (V1 stays the system of record), Developer ID signing and notarisation, one real GitHub CI run, the idle-lock and sleep checks by hand.
- **`2.0.0`:** stable; Windows and Linux keystores; org vault groundwork.
- **`2.1.0` (PRU-1, `ADR-094` on the post-release branch):** cross-device sync as ciphertext and agents that use a credential without the value entering the model's context.
- **`2.2`:** a signed, machine-bound, expiring licence and donation proof (`ADR-095`): the donor's request is sealed and different every time, the token is an Ed25519 lease whose epoch rises at each renewal, and **a failed or tampered licence turns off licensed extras only — it never locks the vault**. Still nothing is gated.
- **`2.3`:** a renewal service, seats and the first paid tier, announced in `DONATE.md` and `PRIVACY.md` in the same change. CredMgr stays free until then.

---

## Design history — Passes 1–3, before any code above

| Date | Pass | Outcome |
|---|---|---|
| 2026-08-04 | **Pass 1** | Full corpus written: concept, architecture, data model, cryptography, threat model, access graph, 2FA, field model, UI/UX, API/MCP, migration, build plan, test plan, decisions (14 docs) |
| 2026-08-04 | **Pass 2** | Adversarial review — 21 findings, 14 applied. Caught credential substitution via write-while-locked, a cryptographically impossible restore promise, registry rollback, unsigned manifests, and a self-violated design principle |
| 2026-08-05 | **Pass 3** | Cross-platform re-architecture, airlock model, LLM auto-wiring, endpoint index with a V1 coverage matrix, tri-mode theming. Superseded ADR-008; resolved ADR-009 |

---

## The V1 → V2 delta

> **Read this as the design comparison, not as the shipped feature list.** It was written in Pass 3
> (2026-08-05) as the target V2, and several rows describe things that are designed and **not built**.
> Where this section says "V2" and the corpus marks a row `planned`, the corpus wins: the rows
> below carry a marker for the ones that are not built today (`docs/00_README_START_HERE.md` is the
> live status table). Built today: the Rust broker (55 operations), the per-node key hierarchy, grants,
> gate 2FA (vault-wide, with per-node `requireTwoFactor` and `privateNames` enforced), the CLI and a 15-tool MCP
> server, on macOS (Apple Silicon) with the Software keystore tier; the desktop app hosts the design with every
> screen wired to the broker, writes included (its per-control checklist was walked in a built app on 2026-10-18 and
> has not been extended to the later screens, `docs/RELEASE_VERIFICATION.md`).

### 🔒 Security model

| | V1 | V2 |
|---|---|---|
| **Isolation** | `project` is a **string label** used for filtering. Any caller with the key reads all 185 credentials. | A **node is a cryptographic boundary**. Per-node X25519 keys. Project A's material is under a different key from Project B's. |
| **Enforcement points** | **Three** independent paths to plaintext (CLI, HTTP daemon, MCP), each with its own idea of authorisation. The PIN guarded HTTP; agents bypassed it by design. | **One** — the `credmgrd` broker. Every other surface is a client that never holds a key. |
| **Agent scope** | Global. An agent in project B could read project A. | Derived from the client's working directory; a cross-node request returns a structured refusal naming the rule and the remedy. |
| **Root key** | `master.key` on disk, readable by the user account | A passphrase wrap and a printed recovery code (**built**, the Software tier); wrapped by the platform keystore (Secure Enclave / TPM+Windows Hello / TPM2) is **planned** (`16_CROSS_PLATFORM.md`) |
| **2FA** | none | One vault-wide gate, checked *after* the root key and *before* any node key loads (**built**); each node's `requireTwoFactor` is enforced against that gate (**built**, ADR-085); a per-node second-factor secret is **not built** (deferred to 2.0.0, ADR-093) |
| **Deletion** | soft delete, 7-day recovery | **Seal, never delete** — into an Orphaned node. Names stay visible; values stay encrypted to a cold key and, until presence attestation exists, nothing in this release can read them |
| **Cross-project reads** | implicit and unlimited | **Grants** — human-created, 2FA-gated, expiring, revocable, dashed on the graph. No agent path exists |
| **Network** | `localhost` HTTP daemon with a bearer token | **No listening socket at all.** UDS / named pipe. No HTTP client compiled into the vault process |

### 🖥 Platform

| | V1 | V2 |
|---|---|---|
| Platforms | macOS (Swift/WKWebView shell) | **macOS on Apple Silicon** (built); Intel, Windows and Linux are **planned** (`16_CROSS_PLATFORM.md`) |
| Core | Node.js 22, zero runtime deps | **Rust** — `zeroize` and `secrecy` (**built**); page locking (`mlock`) and core-dump suppression are **not built** (`04_CRYPTO_AND_KEYS.md`, R-1) |
| Shell | Swift + WKWebView | **Tauri 2** (system webview everywhere) |
| Password KDF | scrypt | **Argon2id** |
| Distribution | build from source | today an **unsigned** tarball of `credmgr` and `credmgrd`, plus an **ad-hoc sealed, not Developer-ID signed or notarised** `CredMgr.app`, `.dmg` and `.zip`, with `SHA256SUMS` (`RELEASE.md`); Developer-ID-signed and notarised builds and `.msi` / `.AppImage` + `.deb` / `.rpm` are **planned** (`21_RELEASE_AND_INTEGRITY.md`) |

*The Argon2id and Rust rows close accepted risks AR-2 (scrypt) and AR-3 (Node heap zeroisation) outright; the platform and distribution rows above are the target, not the present.*

### 🎨 Interface

*Describes the designed app (`09_UI_UX_SPEC.md`). The hosted design draws it and every screen is wired to
the broker, reads and writes alike; several rows (Pro/Lite, the colour layer, bulk paste) are wired but not
yet verified control by control in the running app (`RELEASE_VERIFICATION.md`).*

| | V1 | V2 |
|---|---|---|
| Home screen | flat credential list | **node graph** (Obsidian-class) + switchable worktree tree |
| Node hover | — | exactly **two numbers**: entries, 2FA items |
| Right panel | mixed | **only the selected node's own entries** — never inherited, never a child's |
| Fields | `TYPE_SCHEMAS` prescribed field names per category; nagged about missing ones | **deleted.** One "+ Add field", free-text labels, two modes (single / bulk paste with `///`), types inferred and always overridable |
| Search bar | 16 commands dumped in before you typed | finds nodes and entries only. Operations move to their own Pro panel |
| Modes | one | **Pro / Lite** — Lite hides levers, never safety |
| Themes | dark | **dark ⇄ light as a true perceptual inversion**, plus an optional colour layer with a runtime contrast guarantee |
| Notes | a metadata field | **per-node encrypted notes** — the privacy-vault half |

### 🤖 Agents

| | V1 | V2 |
|---|---|---|
| MCP tools | 10, global scope | 15, scope-filtered (`whoami`, `list`, `search`, `get`, `create`, `update`, `rotate`, `remove`, `undo`, `totp_code`, `recent_changes` — the eleven of Pass 3, down from a Pass-1 estimate of 13 once the forbidden-tools list, `10_API_AND_MCP.md §3.2`, scoped grant/policy/orphan tools out entirely — plus ADR-078's `get_metadata`, `field_add`, `field_update` and `field_remove`) |
| `credmgr_list_projects` | listed **every** project to every agent | → `credmgr_whoami`, returns only reachable nodes |
| `credmgr_set` | create **and** update | split into `create` / `update` — update requires an unlocked vault (credential substitution, Pass 2 F-1) |
| Setup | hand-edit `~/.claude.json` | **planned, not built:** auto-detect and wire Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Zed — with backup, atomic write, verify, and one-click undo. Today you add `credmgr mcp` to your agent's configuration yourself (`PRIVACY.md §4`) |
| Rules for agents | none | the tool descriptions (**built**); the **Vault Protocol** prompt and `CREDMGR.md` per node are **planned, not built** (`17_AIRLOCK_AND_LLM.md`) |
| Security levels | — | **Open / Guarded / Sealed**, global and per-node — **planned**; the broker has no per-node security level yet |

### ♻️ Carried forward from V1, unchanged in spirit

**Built:** the 7-day recovery window (and the fact that no agent can shorten or erase it) · `undo` with `keep-both`
collision handling · `verify` / `doctor` / `backup` · a stored per-entry sensitivity (it gates nothing yet).
**Not built:** the auto-merge engine with its permanent dismissal memory · stable 4-digit refs that are never reused ·
aliases surviving merges and renames and fuzzy near-name and near-duplicate detection (aliases and near-duplicates are
item 4.7 of the `2.0.0-rc.1` milestone, `docs/PRODUCTION_PLAN.md`) · restoring a backup (there is a `backup` command and
no restore command).

### ❌ Removed, with reasons

`TYPE_SCHEMAS` (ADR-011) · the HTTP API (ADR-019) · `/api/export-password` (a third auth
system nobody kept in sync) · `DELETE /api/changelog/:id` (breaks a hash chain) ·
`classify.js`'s hard-coded projects (shipped in V1 1.9.0) · `migrate` (one user's legacy
importer) · `deploy` (embedded one server layout).

Full endpoint-by-endpoint accounting — **57 HTTP routes, 48 CLI commands, 10 MCP tools, all
reconciled** — in [`docs/18_ENDPOINT_INDEX.md`](docs/18_ENDPOINT_INDEX.md).

---

## Migration

There is none. [`docs/11_MIGRATION.md`](docs/11_MIGRATION.md) records the decision: V2 ships empty and does not
import from V1 — no migration, no dry run, no parallel window, no cut-over. V1 keeps running beside it and is never
written to by V2, so using V2 changes nothing in a V1 vault; `credmgr import` reads a `.env` file and nothing else.

## Versioning and release locking

- A released tag is **immutable**. Fixes ship as a new version; a tag is never re-cut. (Policy: nothing is tagged or
  published yet.)
- What a release publishes today is `SHA256SUMS`, with no signature. A detached signature and the app verifying its own
  bundle at start are **planned, not built** (`docs/21_RELEASE_AND_INTEGRITY.md` §2 and §3).
- There is **no updater**; the app makes no network request. A future updater is planned to be opt-in, signed, and to
  update the *app* — never the *vault* (`docs/21_RELEASE_AND_INTEGRITY.md` §4).
- A vault written by an older build is meant to open in a newer one (an alpha.6 vault opens unchanged in 2.0.0-beta.1).
  The reverse is not promised: a vault a newer build has written may not open in an older one, and there is no
  downgrade and no reversible migration (see the 2.0.0-beta.1 upgrade box).
