<!-- artifact-hardened: Approved With Known Risks @ 63bc0fc on 2026-11-08 via three-pass-v1. Evidence: this pass against 63bc0fc (ADR-153 plan and ADR-154 licence core: core tests 236 green incl. 12 licence tests, cargo fmt and clippy clean, corpus_check stamps only, gen_help --check and release_verification_check clean, secret scan clean; K-25 cross-checked against crates/mcp/src/tools.rs credmgr_get → entry.reveal); earlier: prior verifier passes (3abb4fe, 320a8f2) and this pass 3 against the code at 9bc33d7 (corpus_check broker_ops 76; 27 error codes; highest ADR 152; --security-level strict alias of stored sealed in cli main.rs; "Strict (stored as sealed)" in core agentcfg.rs and brokerd ops.rs; search entries, hide seed, re-masks in, Settings › Security groups in apps/desktop); independent ADR-150 review P0/P1 fixed with refusal tests (19ccf39); CI green on PRs #56–#60 (17 checks each); full gates.sh green at dbef0c7 incl. legacy alpha.6; VoiceOver pass 2026-11-08, two defects fixed (ACCESSIBILITY.md, #22 closed); Touch ID, idle and screen lock, ADR-150 confirm checked by hand (RELEASE_VERIFICATION §14, §15 and addenda); corpus_check, gen_help --check, release_verification_check clean; secret scan clean. Known risks: K-A not signed or notarised (bound: Gatekeeper quarantine, SHA256SUMS only provenance, Apple Silicon only; owner: operator; resolution: scripts/sign-notarise.sh with a Developer ID before publishing rc.1); K-B per-control re-press of all rows and the built-app look of the 2026-11-08 design merge (§16) not done by hand (bound: §15 spot re-walk of every screen plus e2e/design audit; owner: operator; resolution: record in RELEASE_VERIFICATION before publishing); K-D Touch ID dialog residual, PHASE8 K-21 (bound: refused to identified agents, dialog names the requester, back-off after five; owner: backend and the user at the dialog; resolution: stated in SECURITY.md, none planned for 2.0.0). K-E F01, an agent that can reveal a value receives it into its model context, PHASE8 K-25 (bound: Guarded default holds high/critical reveals for approval, Strict holds all, agents cannot lower sensitivity, own node only; owner: backend; resolution: use-without-reveal in 2.1, docs/26 Phase 1). Not a claim about anything after 63bc0fc. -->

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
- Any way to read a *sealed* / orphaned entry without user presence (`orphan.reveal` needs the owner's login, a fresh second factor and a Touch ID proof every time), or to make the broker accept a presence proof it should not (a replayed, edited, other-session or expired one).
- Any way an agent or MCP client escapes its scope, or widens its own permissions.
- Any way to obtain a stored 2FA seed rather than a generated code.
- Anything that writes a secret to disk in the clear, to a log, to argv, or to the clipboard
  without the concealed marker. (The authenticator code of `credmgr approve` and `credmgr gate verify` is read from a prompt or stdin,
  not an argument; the argument form survives only as `--code-on-argv`, which says it is visible to `ps`.)
- Anything that lets a credential reach a git repository.
- Weaknesses in the key hierarchy, envelope format, or the platform keystore integrations (on macOS: the Secure Enclave presence key, the `credmgr-presence` helper and the Touch ID unlock wrap, ADR-098).
- Anything that survives `lock` and should not.
- `credmgr agent connect` writing outside its single entry in another application's file, or without showing the diff and taking a backup first (ADR-142).
- `credmgr export --age`, `node.rekey` or `orphan.destroy` running without the factors and the presence proof they require (ADR-130, ADR-131, ADR-133, ADR-135).

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
  non-empty passphrase (ADR-081). We cannot fix a bad choice, and the passphrase (or the recovery code) is the only
  thing between a copy of your vault folder on another computer and its contents (below).

## What the Software tier protects, and what it does not

The vault's keys are wrapped in software, by your passphrase and the recovery code. On macOS, since ADR-098, there
is also a **Touch ID layer** on top of that: an optional presence key and an optional unlock wrap, both in this
Mac's Secure Enclave (below). The wording here is the product's own statement of both; the
canonical copy is `docs/04_CRYPTO_AND_KEYS.md §2.4`, repeated in `README.md`, `RELEASE.md`, `docs/07_TWO_FACTOR.md §3` and
`docs/16_CROSS_PLATFORM.md §3`.

- **Your passphrase is the key.** The vault's root key is stored in the vault folder encrypted two ways: under a
  key derived from your passphrase with Argon2id (256 MiB of memory, 3 passes, 4 lanes), and under the 256-bit
  recovery code printed at `credmgr init`. Those two wraps are the whole of the vault's protection against a copy
  of the folder: a copy on another computer can be attacked offline, slowed only by the Argon2id cost of each
  passphrase guess. Touch ID does not change that (next point). Use a long, unique passphrase and keep the
  recovery code offline.
- **Touch ID is an extra door, not a replacement (ADR-098).** If you turn on Touch ID unlock, a third wrap seals
  the root key to a key in this Mac's Secure Enclave (`keys/root.wrap.se`); it opens only on this Mac, for the
  person who passes Touch ID (or the device password where no fingerprint is enrolled). The passphrase and recovery
  wraps remain, so nothing about a copied folder gets harder, and the Enclave wrap is never part of a backup;
  the enrolment file (public keys only) is, and it is useless without this Mac's Secure Enclave. Separately, a Secure Enclave **presence key** lets a person approve the
  sensitive operations: the broker issues a single-use 60-second challenge bound to the operation, its exact
  parameters and the login session, the Enclave signs it after Touch ID, and the broker verifies the signature
  against an enrolled public key and burns the nonce. Agents and fixture tokens can never hold a proof.
  Since ADR-148: the enrolled presence keys are kept **inside the signed registry**, so deleting or putting back an
  older `keys/presence.enroll` unenrols nothing and re-enrols nothing; enrolling a key needs a signature by that key
  over a broker nonce (proof of possession); `keys/root.wrap.se` carries an HMAC under the root key, and a root-key
  rotation re-seals the new root key only to a wrap whose tag verifies (a Touch ID unlock set up before ADR-148 must
  be turned off and on again before the next rotation); the signed registry also names the Touch ID wraps this vault
  set up (`deviceWraps`), so a `keys/root.wrap.se` put back after Touch ID unlock was turned off gets no prompt and
  nothing is sealed to it; and a Touch ID unlock is **never** handed to a caller the
  broker identifies as an agent (an agent token, or no token from inside a registered project folder). For anyone
  else the Touch ID dialog names the process that asked ("Unlock CredMgr for credmgr (pid …) <- zsh <- … <- launchd,
  in /path"), and a dismissed or timed-out prompt counts against the same backoff as a wrong passphrase. The names
  in the dialog are a **hint, not proof**: they come from the process table, which the requester controls. Read the
  dialog, and cancel any request you did not make yourself. A registry written before ADR-148 takes both lists from
  the files on disk once and keeps them from its next write; a file deleted before that first write is not detected.
- **While the vault is unlocked,** `credmgrd` holds the root key and every unlocked project key in memory until
  it locks (idle timeout or `credmgr lock`; the desktop app also locks it when the Mac sleeps, the screen locks or the session switches, but a daemon running without the app does not). It does not lock its memory pages or block debuggers, so
  software able to read its memory — anything running as root, for example — can read those keys.
- **Presence gates what a stolen login could do, not what a stolen folder could.** With a presence key enrolled,
  the sealed store opens (rule R0, `orphan.reveal`) only to the owner's own login with a fresh second factor and a
  fresh Touch ID proof, in the desktop app only (no CLI command, no MCP tool); creating a grant, re-parenting a
  node, widening a node's sharing and the other gated operations run only with a proof. **Without a presence key
  enrolled these still answer `presence_required`** (a sealed read answers `node_access_denied`).
- **Confirm before showing secrets (ADR-150) is about an unlocked Mac, not a stolen folder.** Off by default. The threat
  it addresses is a person at a Mac whose vault is already unlocked (a desk left for a minute, a shared laptop). When it
  is on, `credmgrd` refuses to hand the owner's own login a value (`entry.reveal`, so also the app's copy,
  `totp.code`, and a value an approval released after a project was locked) with `confirmation_required` until the person confirms with Touch ID or the passphrase
  (`session.confirm`), per trust window (1, 5, 15 or 60 minutes) or, in "every time" mode, per request; approving a waiting request
  from a login asks too (denying never does). It is enforced
  in the broker for every client, after every other access check. A confirmation belongs to one login session, is kept
  only in `credmgrd`'s memory (never on disk) and every lock ends it; hiding or minimising the window does not (the app
  already wipes revealed values then). A wrong passphrase, or a Touch ID proof that does not verify, counts in the same backoff as a wrong unlock, and a
  successful confirmation never resets that backoff. The setting
  lives in the signed registry, so a file edit cannot turn it off, and turning it off or making it ask less needs a
  confirmation from the last 60 seconds, whichever client asks.
  **Residuals, by design:** it does not stop malware running as you (which can wait for you to confirm, or read the
  screen or memory) or someone who knows your passphrase; changes that are not reads (editing, removing, grants, agent
  tokens, project folders) are not gated; `search.content` (ADR-132; ids and names only, rate-limited) and
  `notes.read` (context, not credentials) are not gated; `totp.seed`, `orphan.reveal` and `node.export` are not asked
  again because each already needs a Touch ID proof for that exact request. Agents are not asked (a `credmgr` command run from a registered project folder without your login is an
  agent): their reads answer
  to the node's security level and the owner's approvals (ADR-140). "Only high and critical" (Pro) trusts the entries'
  sensitivity labels; lowering one out of that band needs a confirmation too, but a person who can confirm can
  relabel. A value already on screen or on the clipboard is outside it (the reveal window and the concealed clipboard
  handle that).
- **Two-factor guards the door, not the safe.** With two-factor on, `credmgrd` will not unlock your vault without
  a fresh code. That check is made by `credmgrd`, not by the encryption: anyone who has your passphrase or your
  recovery code *and* a copy of your vault folder can decrypt it without the second factor (the disaster tool
  `scripts/emergency-decrypt.mjs` does exactly that, by design). Treat each of the passphrase and the recovery
  code as a complete key to your vault. A report that "two-factor can be bypassed by decrypting the files
  directly" describes this, and is a documented limit rather than a defect; a way to get `credmgrd` itself to
  unlock, reveal or release a value without the factor **is** in scope.
- **The binaries and the app are not code-signed or notarised;** check them against `SHA256SUMS`. Touch ID does not
  need signing (ADR-098); signing and notarisation (`scripts/sign-notarise.sh`) wait for the operator's Apple
  Developer ID and are distribution, not capability. Windows Hello, TPM and Linux keystore wraps are planned and
  not part of this release.

## Known limits of this pre-release

Read these before you trust this build with anything that matters. Bounds, owners and resolution paths are in
`docs/PHASE8_AUDIT_REPORT.md §4` (K-1 to K-25); the release notes are `RELEASE.md`.

- **An agent that can reveal a value receives it (F01, K-25).** When a node lets an agent reveal an entry (`credmgr_get`), the value enters that agent's model context and may end up in its transcript or logs; CredMgr cannot take it back. Guarded, the default, holds high and critical reveals for your approval and Strict holds every reveal. Agents that use a credential without receiving it are planned for 2.1 (`docs/26` Phase 1).
- **A 2FA seed is withheld from agents only when it is recognised as one.** A reveal never returns a stored seed (an `otpauth://` URI, upper-case base32 at the usual lengths, groups of four, or a field you typed `totp-seed`), and an agent cannot retype one away; a seed in a shape that cannot be told from a word (a plain lower-case run) is read as text until you type the field `totp-seed`, and until then an agent that can reveal the entry can read it (K-19).
- **Unsigned, not notarised, one platform.** The binaries carry no code signature. `CredMgr.app` is sealed ad hoc,
  which makes the bundle consistent with itself and is not an identity, so macOS Gatekeeper refuses to open it until
  you approve it by hand (K-4, K-5). Only an Apple Silicon (`aarch64-apple-darwin`) build is made, for macOS 13.1 or
  later; there is no Intel, Windows or Linux build and no keystore for those. Check every download against
  `SHA256SUMS`, which is the only provenance there is.
- **Presence-gated operations need an enrolled Touch ID key (K-1, ADR-098).** Revealing a stored two-factor seed
  (`totp.seed`; the broker releases it to the owner, the app's "show seed" displays it, re-masks it after the reveal window and never copies it, and the CLI has no command), creating a grant, re-parenting a node, widening a node's sharing, reading a full audit record
  (`audit.get`), replacing the root key (`maintenance.rotate_root`), `maintenance.doctor --rebuild-registry` and
  reading a sealed (Orphaned) entry (`orphan.reveal`) run with a proof. **On a vault with no presence key (and on
  any platform but macOS) they are refused**: `presence_required`, or `node_access_denied` for a sealed read; the app
  says so and changes nothing. A failed proof answers `presence_failed` (`not_enrolled`, `expired`, `invalid`,
  `cancelled`, `locked_out`, `unavailable`). The sensor itself is the one thing a script cannot press: tests use an
  unattended helper that stands in for the finger, and the live checks (Touch ID setup and fingerprint unlock by hand in the built, unsigned app on 2026-11-07; setup with proof of possession, fingerprint unlock and `credmgr unlock --touch-id` from a normal folder and refused from a project folder on 2026-11-08) are recorded in `docs/RELEASE_VERIFICATION.md` sections 14 and 15.
- **Passphrase wraps are still the whole defence of a copied folder (K-5).** Touch ID is macOS-only and works on
  the Mac that enrolled it. No Windows Hello, TPM or Linux keystore wrap exists. A copy of the vault folder on
  another computer is attacked offline against your passphrase, and the 256-bit recovery code is a complete key too.
- **The second factor is vault-wide for 300 seconds for a node with no gate of its own (ADR-093, a known risk).** A node can have its own second-factor secret (ADR-135, `credmgr gate enroll --node <id>`). For the nodes that do not, a code given for one opens the
  second-factor gate for every such node that asks for one, for every caller (agents, MCP and CLI included), for up to 300
  seconds. The window cannot be extended and ends on a lock or any node policy change; the nodes that ask are the ones
  you marked.
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
- **Touch ID unlock trusts the dialog you read, and the dialog's "who asked" is a hint, not proof (ADR-148 and its
  addendum).** The broker cannot tell your own terminal from an agent that left its project folder before running
  `credmgr unlock --touch-id`; both reach it the same way. It refuses the callers it can identify as agents (an agent
  token, or no token from inside a registered project folder), names the requesting process, its ancestors up to
  `launchd` and its folder in the Touch ID dialog, and backs off after five dismissed or timed-out prompts. Those
  names are read from the process table and the requester chooses them: a program can copy itself to a file named
  `zsh`, `cd` to your home folder, or double-fork so that its parent is `launchd` (the chain then ends right after
  it, or says "chain cut short" when it could not be read). Cancel any Touch ID request you did not start yourself.
- **An agent cannot lower what it would need approval to read (ADR-148).** On a Guarded or Strict node an agent's
  edit, override or undo that would lower an entry's sensitivity is refused (`node_access_denied`, rule `L1`); a
  content search by an agent never matches a value it would need the owner's approval to reveal; accepting or
  discarding a held entry is the owner's alone; and a node with its own second factor asks for that factor's code
  before every reveal, whatever its `requireTwoFactor` setting says.
- **The desktop app still honours `CREDMGR_PRESENCE_HELPER` (ADR-148, deferred; K-23).** The release builds of
  `credmgr` and `credmgrd` ignore it and accept only the production helper. A process that can set the app's
  environment as you can point the app at another helper.
- **An exported login reaches every project (K-6).** `credmgr unlock` prints `export CREDMGR_TOKEN=…`; exported into a
  shell where an AI agent also runs, it hands that agent every non-sealed project. The desktop app never gives its
  login to its window.
- **Local denial of service (K-10).** The broker reads a request line without a size limit, so a process running as
  you can make it allocate without bound. Decoded entries are not scrubbed from the broker's memory when dropped.
- **The concealed clipboard is a convention.** The markers keep well-behaved clipboard managers and Universal
  Clipboard away from a copied value; a program that ignores them, or that runs as you, can read it for the 30
  seconds it stays. A force-quit or a crash cannot clear the clipboard, and the timer dies with the process.
- **Not built:** the machine lock (ADR-144), the duress passphrase (ADR-145, dropped), Windows Hello, TPM and Linux
  keystores, and an organisation vault. Nothing in the product claims them. **Built:** per-node security levels
  (ADR-140), `credmgr mcp --print-config`, `credmgr agent` and `credmgr prompt` (ADR-141 to ADR-143), and on macOS the
  Secure Enclave presence key and the unlock wrap (ADR-098).
- **GitHub CI is new.** It first ran on 2026-10-31 and 2026-11-01 (pull request #41): the security workflow and CodeQL passed, and the build workflow's first runs found and fixed a Windows build defect and a racy test on the beta.1 tree (`RELEASE.md`, Known limitations); later changes were checked on their own pull requests. A green run proves what the workflows check, not that the software is free of defects; the local gates and the by-hand check of the built `.app` in `docs/RELEASE_VERIFICATION.md` section 13 still stand.
- **The two timers were checked by hand again on 2026-11-08.** The idle lock (5 minutes in the run) and a real screen
  lock both locked the vault on the rc.1 build (`docs/RELEASE_VERIFICATION.md` §15); "Confirm before showing secrets"
  (ADR-150) was checked by hand the same day (the addendum to §15). A VoiceOver pass on 2026-11-08 found and fixed two defects (#22, closed;
  `docs/ACCESSIBILITY.md`).

## Supported versions

V2 is **pre-release** (macOS on Apple Silicon only), with its own versioning separate from V1's (`1.x`, which is covered by
`v1/SECURITY.md` in the repository). Only the newest V2 build receives security fixes; an
older pre-release is not patched — which is why the alpha builds listed below stay affected. The build's version is the workspace version in
`v2/Cargo.toml` and is printed by `credmgr --version` and `credmgrd --version`. A vault that a
2.0.0-beta.1 or later build has written to cannot be opened by an alpha build (`RELEASE.md`), so "go back to the
older one" is not a mitigation for anything fixed in beta.1.

| Line | Status |
|---|---|
| `2.0.0-rc.1` (unreleased, this tree) | built from source; fixes land here first |
| `2.0.0-beta.1` (pre-release, 2026-11-01) | receives security fixes until the next pre-release |
| `2.0.0-alpha.*` | not supported: the alpha.4 to alpha.6 builds leak the session token into the audit log (below) |

A table of stable `2.x` lines will replace this once a stable release exists.

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
