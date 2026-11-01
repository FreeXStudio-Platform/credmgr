<!-- artifact-hardened: Approved With Known Risks @ 09721b5 on 2026-11-01 via three-pass-v1. Evidence: GitHub-hosted CI on pull request #41 (FreeXStudio-Platform/credmgr): all 17 checks green at ee08394, including security.yml (cargo audit, cargo deny, semgrep, isolation suite, endpoint matrix 55/55 operations, desktop bridge) and CodeQL for Rust, JavaScript/TypeScript, Python and Actions with no open alert on the PR; build.yml run 41243452910, all 7 jobs green (macOS 15, Ubuntu 22.04, Windows; Rust 1.78.0 and stable); desktop unit tests 706 passed at 930c502; Playwright 672 and 681 passed in the two lanes that were combined at 930c502 (not re-run together); strict public export PASS, 860 files, literal blocklist not loaded; by-hand click-through of the rebuilt app on a throwaway vault (unlock, lock, auto-lock, graph, tree, search, reveal, copy, add entry, settings, integrity, doctor, audit, backup, capture switch, searchable help); final adversarial audit v2/docs/release-verification/AUDIT_2026-10-31.md (the P0 and both P1 fixed); known risks K-1 to K-20 in v2/docs/PHASE8_AUDIT_REPORT.md sections 4 and 7, each with bound, owner and resolution. Known risks that bear on this document: K-14 the idle lock and a real sleep or screen lock were not exercised by hand on this build; K-19 a seed in an unrecognised shape is not protected until its owner types it; K-20 the licence text has not been reviewed by counsel. K-12 (CI had not run) is closed. Not signed or notarised; Windows and Linux built in CI but not run. Not a claim about anything after 09721b5. -->

# Security policy

CredMgr holds passwords, private keys and recovery phrases. Security reports are the most
valuable contribution anyone can make to this project, and they are treated that way.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

Use **GitHub Security Advisories** — the *Security* tab → *Report a vulnerability*. That gives
us a private thread and, if you want it, a CVE and public credit when the fix ships.

If that is unavailable to you, open a public issue containing only the words
"security report, please open a private channel" and nothing else. No details.

**What to include:** what you found · how to reproduce it · what an attacker gains · the
version and OS · anything you think we will get wrong when we try to fix it.

**Never include a real credential in a report.** Use a throwaway vault. If you believe you
have found a way to read someone else's data, say so in words — do not attach it.

**What to expect:** acknowledgement within 72 hours · an assessment within 7 days · a fix or
a written plan within 30 days for anything that reaches a secret. You will be credited in the
release notes unless you prefer not to be. There is no bug bounty — this is a small project —
and that is stated up front rather than implied.

## Scope

**In scope — these are real bugs, please report them:**

- Any path that returns a credential value to a caller not entitled to it.
- Any way to read a *sealed* / orphaned entry without user presence.
- Any way an agent or MCP client escapes its scope, or widens its own permissions.
- Any way to obtain a stored 2FA seed rather than a generated code.
- Anything that writes a secret to disk in the clear, to a log, to argv, or to the clipboard
  without the concealed marker. (Known: `credmgr approve --code <n>` and `credmgr gate verify <code>` take the
  authenticator code as an argument, visible to same-user processes while they run; the code is single-use and the
  passphrase is still needed, so this is a disclosed limit, not a finding.)
- Anything that lets a credential reach a git repository.
- Weaknesses in the key hierarchy, envelope format, or the platform keystore integrations.
- Anything that survives `lock` and should not.

**Out of scope — documented, not defects** (see the threat model in the V2 design corpus):

- An attacker with code execution as your own user account while the vault is **unlocked**.
  No user-space vault defends against this, and claiming otherwise would be dishonest.
- A debugger attached to the running process, a core dump or swap file that captures its memory. Not defended:
  `credmgrd` neither locks its pages, suppresses core dumps nor refuses a debugger. Keys are zeroised on lock and
  the idle lock bounds the exposure, which is a mitigation and not a defence (`docs/04_CRYPTO_AND_KEYS.md`, R-1
  and R-3).
- Root, kernel, DMA, cold-boot, or physical attacks.
- The operator's own authority: a human with the factors can read anything. That is what a
  vault is.
- Vault *metadata* (node names, entry names, counts, each entry's type and sensitivity, and which entries hold a
  two-factor seed) being readable from disk. Field labels and values are sealed. This is a documented, bounded
  trade so that the app can show you your vault while locked.
- Weak passphrases. The app's floor is four characters and it recommends eight; the broker and the CLI accept any
  non-empty passphrase (ADR-081). We cannot fix a bad choice, and on the Software tier the passphrase is the only
  thing between a copy of your vault folder and its contents (below).

## What the Software tier protects, and what it does not

This release has **one** keystore tier, `Software`. The wording below is the product's own statement of it; the
canonical copy is `docs/04_CRYPTO_AND_KEYS.md §2.4`, repeated in `README.md`, `RELEASE.md`, `docs/07_TWO_FACTOR.md §3` and
`docs/16_CROSS_PLATFORM.md §3`.

- **Your passphrase is the key.** The vault's root key is stored in the vault folder encrypted two ways: under a
  key derived from your passphrase with Argon2id (256 MiB of memory, 3 passes, 4 lanes), and under the 256-bit
  recovery code printed at `credmgr init`. Nothing is held in the Mac's Secure Enclave and nothing is tied to
  this Mac: a copy of the vault folder can be attacked offline on any computer, slowed only by the Argon2id cost
  of each passphrase guess. Use a long, unique passphrase and keep the recovery code offline.
- **While the vault is unlocked,** `credmgrd` holds the root key and every unlocked project key in memory until
  it locks (idle timeout or `credmgr lock`; the desktop app also locks it when the Mac sleeps, the screen locks or the session switches, but a daemon running without the app does not). It does not lock its memory pages or block debuggers, so
  software able to read its memory — anything running as root, for example — can read those keys.
- **No Touch ID, no presence.** Reading a sealed (Orphaned) entry is refused with `node_access_denied` (rule R0:
  the sealed store opens only to a native caller with a live presence attestation, and none can give one yet);
  creating a grant, re-parenting a node and widening a node's sharing are refused with `presence_required`.
- **Two-factor guards the door, not the safe.** With two-factor on, `credmgrd` will not unlock your vault without
  a fresh code. That check is made by `credmgrd`, not by the encryption: anyone who has your passphrase or your
  recovery code *and* a copy of your vault folder can decrypt it without the second factor (the disaster tool
  `scripts/emergency-decrypt.mjs` does exactly that, by design). Treat each of the passphrase and the recovery
  code as a complete key to your vault. A report that "two-factor can be bypassed by decrypting the files
  directly" describes this, and is a documented limit rather than a defect; a way to get `credmgrd` itself to
  unlock, reveal or release a value without the factor **is** in scope.
- **The binaries and the app are not code-signed or notarised;** check them against `SHA256SUMS`. Hardware-backed
  protection (Secure Enclave with Touch ID) is planned and is not part of this release.

## Known limits of this beta

Read these before you trust this build with anything that matters. Bounds, owners and resolution paths are in
`docs/PHASE8_AUDIT_REPORT.md §4` (K-1 to K-19); the release notes are `RELEASE.md`.

- **A 2FA seed is withheld from agents only when it is recognised as one.** A reveal never returns a stored seed (an `otpauth://` URI, upper-case base32 at the usual lengths, groups of four, or a field you typed `totp-seed`), and an agent cannot retype one away; a seed in a shape that cannot be told from a word (a plain lower-case run) is read as text until you type the field `totp-seed`, and until then an agent that can reveal the entry can read it (K-19).
- **Unsigned, not notarised, one platform.** The binaries carry no code signature. `CredMgr.app` is sealed ad hoc,
  which makes the bundle consistent with itself and is not an identity, so macOS Gatekeeper refuses to open it until
  you approve it by hand (K-4, K-5). Only an Apple Silicon (`aarch64-apple-darwin`) build is made, for macOS 13.1 or
  later; there is no Intel, Windows or Linux build and no keystore for those. Check every download against
  `SHA256SUMS`, which is the only provenance there is.
- **No presence check, so these operations are refused outright (K-1).** Nothing can yet attest a person at a
  sensor (no Touch ID). Reading a sealed (Orphaned) entry answers `node_access_denied`; these answer
  `presence_required`: revealing a stored two-factor seed (`totp.seed`), creating a grant, re-parenting a node,
  widening a node's sharing, reading a full audit record (`audit.get`), replacing the root key
  (`maintenance.rotate_root`) and `maintenance.doctor --rebuild-registry`. The app says so and changes nothing.
- **Software keystore tier only (K-5).** No Secure Enclave, TPM or Windows Hello wrap exists. A copy of the vault
  folder is attacked offline against your passphrase, and the 256-bit recovery code is a complete key too.
- **The second factor is vault-wide for 300 seconds (ADR-093, a known risk).** A code given for one node opens the
  second-factor gate for every node that asks for one, for every caller (agents, MCP and CLI included), for up to 300
  seconds. The window cannot be extended and ends on a lock or any node policy change; the nodes that ask are the ones
  you marked. A per-node second factor is planned for 2.0.0.
- **Passphrase and recovery code are only as good as you make them.** The app accepts a passphrase of four
  characters and lets first-run skip retyping the recovery code (ADR-081); the CLI makes you retype it. A lost
  passphrase cannot be reset by the app or the CLI; the recovery code reads entries back one at a time through
  `scripts/emergency-decrypt.mjs`.
- **Rollback protection is only as strong as a user-writable file (K-8).** Someone who holds your passphrase and can
  put back an older copy of both the vault folder and `~/Library/Application Support/credmgr-state` can roll the vault
  back, including to before the second factor was enrolled.
- **A truncated audit tail is re-signed by the next request (K-9).** Cutting off the last lines of the current
  month's log, then letting the broker handle one more request, makes `credmgr verify` pass again. It needs write
  access to the file as you, and it hides the last few decisions without revealing a secret.
- **An exported login reaches every project (K-6).** `credmgr unlock` prints `export CREDMGR_TOKEN=…`; exported into a
  shell where an AI agent also runs, it hands that agent every non-sealed project. The desktop app never gives its
  login to its window.
- **Local denial of service (K-10).** The broker reads a request line without a size limit, so a process running as
  you can make it allocate without bound. Decoded entries are not scrubbed from the broker's memory when dropped.
- **The concealed clipboard is a convention.** The markers keep well-behaved clipboard managers and Universal
  Clipboard away from a copied value; a program that ignores them, or that runs as you, can read it for the 30
  seconds it stays. A force-quit or a crash cannot clear the clipboard, and the timer dies with the process.
- **Not built:** the LLM integration (`credmgr prompt`, `credmgr mcp --print-config`, a one-click setup), a machine
  lock, a duress passphrase, a per-node security level, hardware-backed keystores and an organisation vault. Nothing in
  the product claims them.
- **GitHub CI is new.** It first ran on 2026-10-31 and 2026-11-01 (pull request #41): the security workflow and CodeQL passed, and the build workflow's first runs found and fixed a Windows build defect and a racy test (`RELEASE.md`, Known limitations). A green run proves what the workflows check, not that the software is free of defects; the local gates and the by-hand check of the built `.app` in `docs/RELEASE_VERIFICATION.md` section 13 still stand.
- **Two timers were not exercised by hand on this build.** The 5-minute idle lock and a real sleep or screen lock were
  checked on the 2026-10-18 build (`docs/RELEASE_VERIFICATION.md` §5 and §8), but not again after the window began
  reloading itself on every lock (ADR-091); section 13 records both as not done. The code paths are covered by tests.

## Supported versions

V2 is **pre-release** (macOS on Apple Silicon only), with its own versioning separate from V1's (`1.x`, which is covered by
`v1/SECURITY.md` in the repository). Only the newest V2 build receives security fixes; an
older pre-release is not patched — which is why the alpha builds listed below stay affected. The build's version is the workspace version in
`v2/Cargo.toml` and is printed by `credmgr --version` and `credmgrd --version`. A vault that a
2.0.0-beta.1 build has written to cannot be opened by an alpha build (`RELEASE.md`), so "go back to the
older one" is not a mitigation for anything fixed in beta.1. No GitHub
release has been published yet, so there is no table of release lines to list; this section
will carry one once a stable `2.x` line exists.

## Known security issues, fixed

### Session token in the audit log — fixed by ADR-077

- **Severity:** high — local privilege escalation *within one user account*. It defeats the
  per-project isolation and the desktop bridge's rule that the token never reaches the window.
- **Affected:** every V2 build that can mint a login session: from **`2.0.0-alpha.4`** (2026-08-17,
  when `vault.unlock` first minted a real token, ADR-056) through `2.0.0-alpha.5` and
  **`2.0.0-alpha.6`** (2026-09-24, the only packaged tarball, and the first whose daemon opens a real
  vault), and every commit on `main` before the fix. No build before alpha.4 minted a token.
- **What happened:** each audit record made under a login carried the session's bearer token as its
  `actor`, and the token-workdir anomaly record repeated it in `detail`. The audit log is plaintext
  on disk, and `audit.tail` serves `actor` to any caller holding the `list` capability — including
  the redacted shape an agent receives, and a process whose working directory matches no bound
  directory. A process running as the owner could therefore read the live token out of the feed and
  present it: it then held all seven capabilities as the owner, could reveal another project's
  secret (a project's own scope is refused that by the default-deny rule R8), create a node and run admin
  operations.
- **Exposure window:** from a successful `vault.unlock` / `vault.gate_verify` until `vault.lock`, the
  idle expiry, or a daemon restart. Tokens exist only in the daemon's memory.
- **Not affected:** the vault's contents on disk (ciphertext), your passphrase, the root key, any
  node key and the recovery codes. None of those was ever written to the audit log.
- **Found:** by the endpoint-matrix check (`scripts/endpoint-matrix.py`) while it exercised every
  broker op against the real daemon, then reproduced end to end on a real daemon by an independent
  verifier, on 2026-10-02.
- **The fix (2.0.0-beta.1 line, `docs/14_DECISIONS.md` ADR-077):** an audit record now names a
  session by a *public id* (`HumanUi:s_<16 hex>`), drawn independently of the token and able to
  authenticate nothing; anything shaped like a token is redacted on the way into the log and again
  on the way out of `audit.tail`; and `Debug` output for tokens, requests, scopes and the bridge
  session no longer prints them. Tests: `crates/brokerd/tests/audit_actor.rs`, the endpoint matrix's
  feed rows and its all-secrets plaintext check, and a step of `scripts/e2e-journey.sh` that greps
  the vault directory for token-shaped strings.
- **What an existing vault still holds:** the audit files that an alpha build wrote still contain
  `cmt_<32 hex>` strings (as `actor`, and inside `anomaly.token_workdir_mismatch` details). After you
  upgrade, restarting the daemon has already destroyed every live token, so those strings are dead
  credentials — presenting one answers `session_expired` — that link records to past sessions and
  nothing more. The fixed build never serves them (they are redacted in `audit.tail`), but anyone who
  can read the files directly still sees them. They are deliberately **not** rewritten: the log is
  hash-chained and its tip is signed, and rewriting would destroy the evidence it exists to keep;
  verification passes over a log that mixes old and new lines
  (`audit_actor.rs::a_record_written_by_a_leaking_build_still_verifies_and_is_never_served`).
- **If you cannot upgrade at once:** run `credmgr lock` (it revokes every token), treat the vault's
  `audit/` directory as secret until the daemon is replaced, and never share an audit file from an
  alpha vault.
- **Fixed in the same change, not a disclosure:** a stored two-factor seed shorter than 128 bits made
  `totp.code` panic the connection thread (a crash, not a leak). It now answers a code for any seed of
  at least 80 bits and a typed refusal below that; the 80-bit floor is a deliberate deviation from
  RFC 4226's 128, recorded in ADR-077 (a stored seed is issued by the service that checks it).

## Our commitments

1. **No telemetry, ever.** No analytics, no crash reporting, no "anonymous usage stats", no
   phone-home update ping that carries an identifier. **Built** — `crates/` has no network
   client of any kind, and neither does the desktop shell: no update check, no plugin, and a
   window policy whose `connect-src` allows only the local IPC channel
   (`apps/desktop/src-tauri/tauri.conf.json`; `16_CROSS_PLATFORM.md §5.1`).
2. **No outbound network from the vault process.** Not disabled by a setting — the HTTP stack
   is not compiled in. **Built** — no `TcpListener`/`TcpStream`/`UdpSocket`/HTTP crate anywhere
   in `crates/` (ADR-019), `cargo deny` bans every HTTP client, HTTP server and TLS binding in
   both Cargo workspaces (`deny.toml`, `apps/desktop/src-tauri/deny.toml`), and a test in the
   desktop shell fails if one reaches the macOS build (`tests/dependency_policy.rs`). The only
   channel in is a Unix socket, `0600`, answered only to the owning user.
3. **CredMgr will not create a vault inside a repository.** **Built** — path resolution
   avoids the process's working directory (`crates/store/src/paths.rs` resolves from the OS's
   per-user data location, or from `CREDMGR_VAULT_DIR` if you set it), and `credmgr init` refuses
   to create a vault inside a git working tree — checked by the CLI for a fast refusal and again
   by the broker, which is the authority (`BrokerState::begin_init`, ADR-061). It cannot stop you
   moving an existing vault into a repository afterwards.
4. **Release builds are checksummed today; signing comes later.** `scripts/release.sh` writes a deterministic
   tarball, CycloneDX bills of materials with no build-machine paths, and a `SHA256SUMS` file over everything it
   publishes; `scripts/release-app.sh` adds the desktop app bundle (sealed ad-hoc, which is internal
   consistency and not an identity), and `scripts/release.sh --verify` re-checks the lot — **built**. Code-signing
   and notarisation — **planned, not built** (known risks K-4 and K-5; `RELEASE.md` and
   `docs/21_RELEASE_AND_INTEGRITY.md`). Until then the checksum file is the only provenance.
5. **Security fixes ship before features**, and the changelog says plainly what was wrong.

## If you think your vault is compromised

1. `credmgr lock` immediately.
2. Rotate, in this order: anything that moves money (wallets, exchange keys, payment
   providers) · cloud and server root access · CI/CD and deploy tokens · everything else.
3. `credmgr audit --limit 200` to see what was read, and when (the default is the latest 50). The
   log is written with the root key, so a request made while the vault was locked left no record.
4. Do **not** delete the audit log. It is hash-chained; a break in the chain is itself
   evidence. Run `credmgr verify` before you rely on it: the last few lines can be cut off without
   the check noticing until the next request (K-9, below).
