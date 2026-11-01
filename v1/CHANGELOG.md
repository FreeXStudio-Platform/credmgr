# Changelog

All notable changes to **CredMgr** are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **About this file.** CredMgr was developed privately for two years before being opened. This
> changelog was reconstructed from the git history for the public release and **scrubbed**: the
> private repository's entries named real credentials, servers and projects. Every technical
> change is recorded; no operator-specific detail is.

---

## [Unreleased]

## [1.9.1] — 2026-10-01 — source security patch

- Reject non-boolean `requirePinForAgents` values instead of silently disabling
  the agent PIN gate; the independent review regression is covered.
- Preserve assertion counts when a test module exits unsuccessfully.

Publication is pending; this entry does not establish a public or signed release.

### Security

- Repair nested and standalone pre-commit installation, respect `core.hooksPath`,
  and scan Git's staged bytes with NUL-delimited paths. A sanitized or deleted
  working file cannot hide a staged secret. Keep all scans scoped to V1, refuse
  unreadable/oversized inputs, scan binary bytes, remove blanket filename
  exemptions, and detect renamed age identities.
- Close bearer, PIN, and export-password bypasses through case variants,
  trailing slashes, and HEAD requests. Validate default loopback Host headers
  against DNS rebinding and send no-store headers before authentication gates.
- Revoke unlock sessions on PIN rotation. Refuse malformed security configuration
  and malformed MCP integration registries instead of silently reopening access.
- Resolve vault-location symlinks and existing ancestors before refusing a new
  vault inside Git, including a not-yet-created directory below a symlink.
- Running daemons follow rotation/revocation of their selected saved token
  immediately and remain closed after revocation. Explicit `--token` and
  `CREDMGR_TOKEN` overrides retain their precedence and fixed-token behavior.
  CLI token commands respect the selected vault; existing default installs
  retain their legacy token-file location until replaced.

### Fixed

- The Node library's `getEnvObject()` returns plaintext values for child-process
  environment injection, including empty values and own keys such as `__proto__`,
  rather than store record objects in the returned environment bag.

### Tests

- 230 passing checks on Linux with Node 24.19.0 and age 1.2.1, including real Git
  hooks/index regressions, HTTP gate regressions, and disposable-vault stress.
- Bounded stress covers 256 staged files, a 256 KiB binary age payload with 16
  ciphertext alterations, 256 dry-run records, 64 stored Unicode records, and
  64 concurrent locked GET/HEAD route variants. These checks establish neither
  a throughput SLA nor native macOS/Windows readiness.

### Documentation

- Correct V1 privacy and security statements about vault encryption, plaintext
  metadata, project filters, MCP access, and the dashboard PIN's limits.
- Fix installation commands for the `v1/` directory and identify the checked-in
  1.9.0 version accurately.
- Record V1-only publication gates and current validation without asserting a
  public or signed release exists.

## [1.9.0] — 2026-08-05 — *"Open"*

The release that makes CredMgr publishable. Everything here is about the difference between
software that works for its author and software that is safe for strangers.

### Security

- **The vault no longer lives inside the repository.** `lib/paths.js` resolves the vault to
  the platform's user-data directory — `~/Library/Application Support/credmgr` (macOS),
  `%APPDATA%\credmgr` (Windows), `$XDG_DATA_HOME/credmgr` (Linux). Previously it defaulted to
  the checkout root, so a fresh clone + `credmgr init` wrote `master.key` and `vault.age`
  **into the git working tree** — one `git add -A` from publication. A path outside the repo is
  a guarantee; a `.gitignore` is only a promise.
- **`credmgr init` refuses to create a vault inside a git repository**, and every command
  warns if an existing vault is in one.
- **`scripts/guard-no-secrets.mjs`** — a pre-commit hook and CI gate that blocks commits
  containing credentials. 9 path rules, 13 content rules, fails closed, and never prints the
  matched value. Install with `npm run hooks:install`.
- **Hardened `.gitignore`** — deny-by-default for every known secret shape.

### Changed — breaking

- **`lib/classify.js` no longer hard-codes any project names.** The built-in rules are now
  vendor-neutral only (`SUPABASE_`, `AWS_`, `_PRIVATE_KEY`, …). Project-specific rules live in
  `<vault>/.credmgr/classify.rules.json`, are loaded ahead of the built-ins, and are never
  part of the repository. When no rule names a project, one is derived generically from the
  credential-name prefix (`ACME_API_KEY` → `acme`), which works for every user with zero
  configuration. *Previously the source shipped one user's private project inventory.*
- **`createEmptyIndex()` seeds only `global`.** It previously pre-populated six projects,
  complete with VPS usernames and deploy paths.
- **`credmgr migrate` and `lib/migrate.js` removed.** They imported one specific user's legacy
  plaintext files and had no meaning for anyone else.
- **`credmgr deploy` deprecated** — it embedded assumptions about one server layout.
- Dashboard project colours are now fully deterministic (hash → hue) instead of a hard-coded
  map of six project names.

### Added

- `credmgr where` (alias of `which` / `home`) now reports the resolved vault path, *why* it
  resolved there, the platform default, and a loud warning if it sits inside a repository.
- `npm run guard`, `npm run hooks:install`; `pretest` runs the guard.
- `engines.node >= 18`; `os: [darwin, linux, win32]` declared.
- Open-source scaffolding: `LICENSE` (MIT), `SECURITY.md`, `PRIVACY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `TRADEMARKS.md`, `ACKNOWLEDGEMENTS.md`, `DONATE.md`.

### Fixed

- **`classify.setUserConfig()` accepted unvalidated input** and could corrupt the classifier
  for the rest of the process (`{rules: 'oops'}` → `rule.tags is not iterable` on every
  subsequent call). It now normalises exactly like the disk loader, and `classify()` skips a
  malformed rule rather than throwing. *Reaching your credentials must never depend on a
  config file being well-formed.*
- The secret guard's `--all` mode scanned only **tracked** files, so in a freshly-initialised
  repository it scanned zero files and reported "clean" — failing open at exactly the moment
  it mattered most. It now includes untracked, non-ignored files.

### Tests

190 passing (was 184). The classifier gained coverage for user config, malformed config,
generic project derivation, and a guard test asserting no project name is ever hard-coded
into the source again.

---

## [1.8.0] — 2026-07-17 — *"Real lock"*

The release that replaced security theatre with enforcement.

### Security

- **Server-enforced vault lock** (`lib/lock.js`). scrypt-hashed PIN, in-memory sliding
  sessions, `POST /api/pin|unlock|lock`, `GET /api/lock-status`. The previous lock was
  `localStorage` plus a biometric animation — the API answered regardless. Removed, with a
  one-time migration prompt.
- **Changelog value leak fixed.** `/api/changelog` now always redacts; the full record is
  available only via `GET /api/changelog/:id?reveal=1`, behind the PIN. Previously the feed
  returned `previousValue` and `newValue` in the clear to any reader.
- **Auth rate limiting** on both the bearer token and the PIN: 5 failures → 30 s, doubling,
  with `Retry-After`. Shared counter, so an attacker cannot alternate between the two paths.
- **Token hygiene.** `GET /api/daemon-token` returns `{hasToken, last4}` instead of the token.
  Revealing requires rotating ("Rotate & show once").
- Native shell: `WKUIDelegate` JS panels routed to `NSAlert` (WKWebView silently no-ops
  `confirm`/`prompt`, so every dialog had been a no-op); JS→native concealed-clipboard bridge
  (`org.nspasteboard.ConcealedType`); clipboard clears after 30 s or on app switch.

### Added

- **Aliases.** Merges record their source names as aliases; `get()`, `search()` and
  `exportEnv()` resolve them, including field-level resolution (an old flat name resolves to
  that field's value). Collisions are rejected; aliases survive rename.
- **Fuzzy matching** — `near-name` (separator/filler drift, typo pairs) and
  `near-duplicate-value` (trim/quote drift) suggestion types. Review-only; never auto-merged.
- Backup retention (`--retain=N`, default 14); `.env` drag-and-drop as one batch request with
  a dry-run preview; `GET /api/status`; `access-log --purge`.

### Fixed

- Auto-lock TTL changes could be applied without authentication.

---

## [1.6.0 – 1.7.0] — 2026-07-16 — *"Engine"*

### Added

- **Auto-merge engine** — `autoMerge`, `autoMergeAll`, `findMergeSuggestions`,
  `splitNameStem`, `detectFieldLabelFromValue`. Scattered single-value credentials that belong
  to one real-world thing (a wallet, a server) are detected and combined into one structured
  entry. **Dismissals are remembered permanently** — a suggestion you rejected never returns.
- **Type schemas** — per-category field sets with completeness checks and add-column chips.
- **Batch merge**, with checkboxes and an "auto-merge all safe" path that always dry-runs first.
- **Sealed 7-day recovery archive** — filename-embedded timestamps for retention, strict
  change-id validation, `0700`/`0600` modes.
- Dashboard: header "+ New", ⌘K search back-navigation, native-safe `appConfirm`/`appPrompt`,
  archive "Empty archive", click-target fixes (no hover transforms, ≥26 px hit areas).

---

## [1.5.0] — 2026-07-03 — *"Polish"*

- Professional UI pass: refined palette, accessibility, elevation.
- Store consolidation tooling; wallet entries unified so a public key and its private key live
  in one entry rather than two.

## [1.4.0] — 2026-07-02 — *"Batch"*

- **Multi-field batch import** — `{name, fields:[{label,value}]}` creates one structured entry
  rather than N flat ones.
- Loose-secret consolidation tooling: hash-verify a plaintext file against the vault before
  deleting it.

## [1.3.0] — 2026-07-02 — *"Complete"*

- Dashboard feature-complete: rotate, history, generate, export, doctor, backup in the UI;
  search ↑↓ navigation; `#ref` jump.
- **Tests sandboxed** — the suite creates a `mkdtemp` `CREDMGR_HOME` and can no longer touch a
  real vault. (Before this, running tests operated on live data.)
- `verifyIntegrity` reduced to a single decrypt pass.

## [1.2.0] — 2026-07-02 — *"Integrity"*

- **Vault integrity checksum** — `store/vault.sha256` over the plaintext, written on every
  save; `verify`/`doctor` detect corruption and rollback.
- **Atomic writes** (temp + rename) everywhere.
- `credmgr doctor [--fix]` — repairs resurrected/duplicate refs, orphans, categories, checksum.
- `backup` / `restore` (age-encrypted tar), `generate`, `import` (dedupe-aware), `history`,
  `get --clipboard` with 30 s auto-clear.
- `secureTempFile` via `mkdtemp` — closes a symlink race in SSH-key and deploy paths.
- Dashboard CSP and security headers.

## [1.1.0] — 2026-04-17 — *"Platform"*

- CredMgr becomes multi-mode: CLI, local HTTP daemon, Node SDK, and **MCP server**, over one
  store.
- Stable 4-digit ref numbers, never reused after deletion.
- 7-day encrypted changelog with `undo`.

## [1.0.0] — 2026-04-06 — *"First"*

- Initial implementation: `age` (X25519) encryption at rest, unencrypted searchable metadata
  index, CLI with ~20 commands, name-pattern auto-classification, dark web dashboard.
- Sensitivity levels (`low` / `medium` / `high` / `critical`) with documented agent-handling
  rules.

---

## Versioning policy

- **Patch** — fixes, no behaviour change.
- **Minor** — new capability, backwards compatible.
- **Major** — a vault format change or a removed command. Any format change ships with a
  migration and a reversible path; a vault written by an older version is always readable, or
  the release does not go out.
- Every release is tagged, signed, and published with `SHA256SUMS`. A released tag is
  **immutable** — fixes go in a new version, never a re-cut tag.

[1.9.0]: #190--2026-08-05--open
[1.9.1]: #191--2026-10-01--source-security-patch
[1.8.0]: #180--2026-07-17--real-lock
