---
id: V2-021
classification: public
title: Release and integrity
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21). The previous stamp (Approved With Known Risks @ d15a5c7) had NOT
     drifted — `f2d0fd9` changed only the stamp line, and the drift check excludes it — but it
     attested to a body that described an entire release pipeline in the present tense when
     none of that pipeline exists in any form, and that overstated the supply-chain gates as
     running "on every push". `Approved` was therefore never defensible on content, whatever
     the stamp's provenance said. Every status claim below was computed from live source in
     this pass; the hardening verdict is the operator's to assign after their own review, not
     this session's to self-award.

     CORRECTED AGAIN 2026-08-18 (Session 21, verification-backlog pass, same day,
     `VERIFICATION_BACKLOG_S21.md`, `21_RELEASE_AND_INTEGRITY.md` section). Five false claims
     and two convention violations fixed against live source: four mis-citations of
     `16_CROSS_PLATFORM.md §7` (§2.1's body, the §2.4 figure brief's Source line, and the §10
     Connections row) and one of `16_CROSS_PLATFORM.md §9` (§7.3's `AR-8` reference), corrected
     to §8.3 ("Packaging and signing") and §10 ("Residual risks this architecture adds")
     respectively — §7 has no artefact/signing table and §9 has no `AR-8` row, confirmed by
     opening both sections. §4's claim that "the desktop shell is otherwise still the generated
     scaffold" was true of `tauri.conf.json`/`Cargo.toml` but false of the shell as a whole:
     `apps/desktop/src-tauri/src/` now holds five hand-written modules implementing a real
     Tauri↔broker bridge (`ADR-057`), which §4 now states alongside the still-true "no updater"
     finding. §7.2's claim that "nothing in the working tree records whether either workflow has
     ever actually run" overstated the gap for `build.yml`: `16_CROSS_PLATFORM.md §8.2` already
     records zero runs (`gh run list`, checked 2026-08-18); the claim now cites that finding
     instead of repeating it, and leaves `security.yml`'s run history unclaimed as before. §6.1's
     "every contributor and every CI leg compiles with one compiler" was corrected — `build.yml`'s
     matrix runs a `stable` leg alongside the pinned `1.78.0` one, and the `desktop-app` job
     installs `stable` outright. Two present-tense lines describing the `planned` self-integrity
     check as current behaviour — §3.1's "the check runs… is stopped" and §3.2's "the vault stays
     locked… the message names the file" — were converted to future tense per `ADR-059`.
     Updated 2026-09-24 for the `2.0.0-alpha.6` slice (a real workspace version, a minimal
     `--version` stamp, `scripts/release.sh`) and ADR-062 (the bridge job in `security.yml`).
     Updated 2026-09-24 for ADR-071…073 (the bridge's command count, 47). Updated 2026-10-03 for the release tooling of the
     2.0.0-beta.1 line (deterministic tarball, CycloneDX bills of materials, `--verify`, the app bundle, the fresh-install check,
     the Homebrew formula), the two new format versions (ADR-078, ADR-079) and the bridge at 53 ops. -->
# Release and integrity — versioning, signing, and the self-check

`CredMgr V2` · how a build becomes a release, and how a release proves it is the build that was reviewed · `2026-08-18`

> **Status.** **Almost none of the release pipeline described here exists.** There is no release
> workflow, no signing step, no notarisation, no update channel, no `BuildStamp` and no
> self-integrity check. `.github/workflows/` holds exactly two workflows — `security.yml` and
> `build.yml` — and neither produces, signs, or publishes an artefact; a grep across
> `v2/crates/` and `v2/apps/` for `ed25519`, `codesign`, `WinVerifyTrust`, `SecStaticCode`,
> `SOURCE_DATE_EPOCH` and `BuildStamp` returns nothing. **One minimal slice was built on
> 2026-09-24:** the workspace carries a real version, `2.0.0-alpha.6`; `credmgr --version` and
> `credmgrd --version` print a minimal stamp — version, commit, dirty flag, platform (§1.2); and
> `v2/scripts/release.sh` produces an **unsigned** tarball plus `SHA256SUMS` from a clean tree
> (§8), installed by hand per `v2/RELEASE.md`. **That slice grew on 2026-10-03** (§8): the tarball is now written
> deterministically, CycloneDX bills of materials ship beside it, `scripts/release-app.sh` adds an ad-hoc sealed
> `CredMgr.app` with a `.dmg` and a `.zip`, `release.sh --verify` re-checks the lot, `scripts/fresh-install-check.sh`
> installs it the way a user would, and a Homebrew formula is prepared and unpublished. None of that signs anything.
> That is accepted risk **K-5**
> (`PHASE8_AUDIT_REPORT.md §4`): the first release is Software-tier and unsigned, and its
> checksums are its only provenance. Two adjacent things **are** real: the
> **reproducibility groundwork** (`rust-toolchain.toml` pins the compiler, `Cargo.lock` is
> committed, CI builds `--locked`) and the **supply-chain gates** (`cargo deny`, `cargo audit`,
> `semgrep`, both secret guards and the isolation suite, declared in `security.yml`).
> Everything else below is the complete **target design**, written out in full and marked
> `planned` — including the one dependency this workspace does not have and will have to add:
> a signature primitive (§2.3). One further item is an operator purchase rather than a build
> task: the two code-signing certificates, recorded as **K-4** in `PHASE8_AUDIT_REPORT.md`.

> **The requirement this document answers**, verbatim: *"the system should be locked after each
> version stamp and not be changeable by users."* A released build must be the build that was
> reviewed — and must be able to prove it, to a user who has no way to inspect it.

Status words are used exactly as `ADR-059` defines them: **`built`** exists and is covered by a
passing test, **`partial`** exists but does not do everything this document specifies,
**`planned`** does not exist in any form. A `planned` mechanism is never written in the present
tense anywhere below.

---

## 1. Version stamping — **`partial`**

### 1.1 The rule, which is timeless

**A release is a git tag, and a tag is immutable.** There is no re-cutting. A mistake in `2.0.0`
becomes `2.0.1`; the bad tag stays as a historical fact with a `YANKED` note in `CHANGELOG.md`.
Deleting or moving a tag would invalidate every checksum anyone had already recorded against it,
which is the one thing a security tool must never do to its own users. Versioning is SemVer, as
`CHANGELOG.md` already declares.

### 1.2 What exists today

A minimal stamp, since 2026-09-24 — less than §1.3 designs, and more than nothing:

- `v2/Cargo.toml` sets `version = "2.0.0-alpha.6"` (and `license = "MIT"`) at the workspace
  level, and every crate inherits it with `version.workspace = true`. Until 2026-09-24 it was
  `0.0.0`.
- `credmgr --version` (also `-V`, `version`) and `credmgrd --version` (also `-V`) each print their
  own line — `credmgr 2.0.0-alpha.6 (commit <12 hex>[, dirty], <arch>-<os>)`, or `(development
  build, no commit stamp, …)` when built outside the release script. The commit and dirty flag are
  compile-time constants read with `option_env!` from `CREDMGR_BUILD_COMMIT`/`CREDMGR_BUILD_DIRTY`,
  which `v2/scripts/release.sh` sets; nothing shells out to git at run time
  (`crates/cli/src/main.rs::version_line`, `crates/brokerd/src/main.rs::version_line`).
- The MCP server's `serverInfo.version` is `env!("CARGO_PKG_VERSION")` in
  `crates/mcp/src/server.rs`, so it now reports `2.0.0-alpha.6`.
- **Not built:** the `BuildStamp` struct below (no `built_at`, no `vault_fmt`), and the stamp in
  `vault.status`. There is still no build script in the workspace — the only `build.rs` in the
  tree is the stock `tauri-build` shim inside `apps/desktop/src-tauri`, which `Cargo.toml`
  deliberately excludes from the workspace (`ADR-035`). The desktop app's `tauri.conf.json` and `package.json` say
  `2.0.0-beta.1` while the workspace still says `2.0.0-alpha.6`, and `release.sh --verify` flags assets of mixed
  versions as skew (`--allow-version-skew` accepts it and says never to publish such a set), so the workspace version
  is bumped as the release step, before the tarball and the app are built.

**Three format versions are built, and must not be confused with the app's.** `crates/core/src/envelope.rs` defines
`VERSION: u8 = 1` (a single raw value) and, since ADR-078, `VERSION_FIELD_DOCUMENT: u8 = 2` (a canonical-JSON field
document); it writes the version into every envelope header, binds it into the AEAD's additional data — so the payload
kind is authenticated — and refuses any other value on decrypt with `CryptoError::UnsupportedVersion`. That is the
*ciphertext* format. The signed registry carries its own `format` field, `REGISTRY_FORMAT = 2` since ADR-079, which a
build refuses when higher than its own (`RegistryFormatTooNew`); a build older than that ignores `sealed` on read and
drops it on its next write. Neither is the vault format or the application version. **Downgrade is one-way:** an alpha
build refuses a version-2 envelope and reads a manifest carrying `hasTotp: true` as tampered, so a vault a 2.0.0-beta.1
build has written to cannot go back (`RELEASE.md`). There is still no manifest format-version field.

### 1.3 The target design

Each build **will** embed a stamp fixed at compile time. The shape:

```rust
pub struct BuildStamp {
    pub version:    &'static str,   // "2.0.0"                    from Cargo.toml
    pub commit:     &'static str,   // full 40-char SHA
    pub built_at:   &'static str,   // RFC 3339, from SOURCE_DATE_EPOCH
    pub target:     &'static str,   // e.g. "aarch64-apple-darwin"
    pub vault_fmt:  u16,            // envelope/registry format version
    pub dirty:      bool,           // built from a modified tree
}
```

This type does not exist in the workspace. It will be produced by a build script that reads the
tag, the commit and `SOURCE_DATE_EPOCH` from the environment and emits constants — deliberately
*not* by shelling out to git at run time, which would make the value a property of the machine
running the binary rather than of the build.

Four rules will govern it:

1. **`dirty: true` will fail the release build outright.** A binary that cannot say exactly which
   commit it is should never be signed. It will remain legal for a development build, where it is
   the honest answer. (`scripts/release.sh` already applies this to its unsigned path: it refuses
   a dirty tree, and its `--dev` mode allows one and stamps such a build `dirty`.)
2. **The stamp will be per-binary, not per-system.** `credmgrd`, the `credmgr` CLI and the
   desktop shell are three separately-built artefacts, so "which version am I running" has three
   answers. Each will report its own; the broker will additionally surface its own stamp in the
   existing `vault.status` response so a client can detect that it is talking to a broker built
   from a different commit than itself. A user interface that shows one version number must say
   whose it is.
3. **`vault_fmt` will be versioned separately from the app**, because the two change for
   different reasons. The app will refuse to open a vault whose format is *newer* than it
   understands — that is a data-loss risk, not a compatibility inconvenience — and will migrate
   one that is older, reversibly, after an explicit confirmation (§4).
4. **The stamp will be inert data.** Nothing in the security model will depend on it being
   truthful, because a modified binary can print whatever it likes. It exists so an *honest*
   build can identify itself and so a support report can be acted on; the control that resists a
   dishonest build is the operating system's signature check (§3), not this field.

## 2. Signing and publication — **`planned`**, and it needs a primitive this workspace does not have

### 2.1 What a release will publish

```
credmgr_2.0.0_aarch64.dmg          codesigned (Developer ID) + notarised + stapled
credmgr_2.0.0_x64_en-US.msi        Authenticode signed
credmgr_2.0.0_amd64.AppImage       + .deb + .rpm, with detached signatures
credmgr-2.0.0-<target>             the CLI, per platform
SHA256SUMS                         every artefact
SHA256SUMS.asc                     detached signature over SHA256SUMS
SBOM.spdx.json                     full dependency inventory
```

The per-platform artefact and signing mechanisms are specified once, in `16_CROSS_PLATFORM.md §8.3`
("Packaging and signing — `planned`"); this document does not restate that table, it consumes it.

### 2.2 Key custody

**The signing key will not be in CI.** Releases will be signed on a machine the maintainer
controls, with the key hardware-backed; the CI job will build and attest only. The consequence
will be the property worth having: **a compromised CI will be able to produce an unsigned
artefact, never a signed one.** An unsigned artefact fails the user's own verification and the
app's self-check, so the worst outcome of a CI compromise would be a release that visibly does
not verify — not a release that verifies and is malicious.

### 2.3 The dependency gap — two different signature problems, one of which needs new code

This is the part of the release design that is not merely unimplemented but currently
*unimplementable*, and it is worth separating carefully because the two halves have different
costs.

**(a) Artefact signatures the operating system verifies.** Developer ID signing plus notarisation
on macOS, Authenticode on Windows, a detached signature on Linux. These are operations performed
by the platform's own tooling on the release machine. They will add **no** dependency to this
workspace, because the product will never verify them itself — the operating system does that, at
launch (§3 step 2).

**(b) Signatures the product itself must verify at run time.** There are two, plus one optional
third, and they all need the same primitive compiled into the shipped binary:

- the **update manifest** (§4), which must be rejected unless correctly signed;
- the **shipped-resource manifest** (§3 step 3), signed into the binary at build time and checked
  against the files on disk at start;
- *(optional)* the **commercial-licence certificate** in `22_ORG_VAULT_SYNC_AND_LICENSING.md §4.4`,
  which that document has decided would be Ed25519 if it is a signed file. Since `ADR-074` it
  gates nothing and no release depends on it.

**`crates/core` cannot do this today, and no document should imply otherwise.** It holds X25519
for key agreement and HMAC-SHA256 for symmetric authentication, and nothing else in the signature
family: `grep -rniE 'ed25519|eddsa' v2/crates/` returns no matches, and no crate manifest in the
workspace names a signature crate. `04_CRYPTO_AND_KEYS.md §1` is the authority on what the
primitives actually are. Any claim that release signing "reuses machinery the vault already has"
is false — the vault's asymmetric primitive encrypts *to* a node; it cannot sign *as* anyone.

**The constraint that makes adding one real work.** The workspace is pinned to Rust 1.78
(`rust-toolchain.toml`, `rust-version = "1.78"`), and the comment block at the top of
`crates/core/Cargo.toml` records why several crypto crates are held below their current majors:
those majors pull dependencies whose manifests require Cargo's `edition2024` feature, which is
unavailable below Rust 1.85. A signature crate must resolve inside that pin, or the pin must
move — and moving the MSRV is an architectural decision requiring a superseding ADR, not a build
fix. This is the same wall that produced `ADR-035`'s exclusion of the desktop workspace.

**Two design rules will bound the new dependency when it lands:**

1. **Verification only.** The shipped product will contain a public key and a verify path, and
   will never contain a signing key or any code that signs. One primitive, one direction, one
   place to get it wrong.
2. **One primitive, up to three consumers.** The update manifest, the resource manifest and — if
   it is ever built — the optional licence certificate will use the same verifier rather than
   three. This section and `22 §4.4` are the two places that name the choice; whichever lands
   first should record the crate selection as an ADR so the second does not choose again.

### 2.4 What is outstanding and is not code

An Apple Developer ID and a Windows code-signing certificate are required to sign anything at all.
Both are operator purchases, recorded as `K-4` in `PHASE8_AUDIT_REPORT.md` and as `O-3` in
`14_DECISIONS.md`. They block the first *binary* release and have never blocked source
publication or the build.

<!-- figure:release-trust-boundary -->

The signing key never enters CI, so the trust boundary sits between "built" and "signed": CI
(`build.yml` + `security.yml`, both real and running today) can build, test and scan an artefact
but has no signing step at all — it can only ever hand off an unsigned artefact. Signing happens
only on the maintainer's machine, per the per-platform mechanisms in `16_CROSS_PLATFORM.md §8.3`,
and every node on that side of the diagram is rendered `planned`, not built.

## 3. Self-integrity — the lock after the stamp — **`planned`**

### 3.1 The sequence

At every start, **before the vault directory is touched**, the app will:

```
1  read the embedded BuildStamp
2  verify the app bundle's own code signature via the operating system
       macOS    SecStaticCodeCheckValidity
       Windows  WinVerifyTrust
       Linux    verify the AppImage's detached signature, when present
3  hash the shipped resource set (UI bundle, vendored graph engine, fonts) and compare
   against the resource manifest signed into the binary
4  on any mismatch, refuse to unlock and state precisely what differs
```

The ordering is the point. The check will run before any key material is requested from the
platform keystore, so a modified build will be stopped before it can ask the operating system to
release the wrapped root key — not after. A check that runs *after* unlock protects nothing that
matters.

Step 3 is the one that needs the new primitive from §2.3: the manifest of shipped resource hashes
must be signed, or an attacker who can replace a resource file can replace the manifest beside it.

### 3.2 Failure will be loud and specific

Never silent, and never a warning the user can click past:

> *This copy of CredMgr has been modified since it was signed.*
> *`ui/index.js` does not match the released build (expected `a3f…`, found `91c…`).*
> *Your vault has not been opened. Reinstall from a signed release before continuing.*

The vault will stay locked. A modified credential manager is precisely the situation in which
"continue anyway" is the wrong affordance to offer, and the message will name the file rather than
saying "integrity check failed" because the first sentence a user reads decides whether they
reinstall or shrug.

### 3.3 Four integrity states, reported honestly

The Security panel will report exactly one of:

| State | Means |
|---|---|
| `verified` | Signature valid, resource manifest matches, stamp clean. |
| `self-built` | No release signature, and none expected. The honest answer for a build the user compiled. |
| `unverified (repackaged)` | A distribution rebuilt or re-signed this — an `.AppImage` extracted and re-packed, or a distro-packaged `.deb`. Not a failure, and distinguishable from one. |
| `FAILED` | A signature or hash that should have matched did not. The vault does not open. |

Collapsing the middle two into `FAILED` would train users to ignore the word, which is how an
integrity indicator stops working.

### 3.4 What this is not

`maintenance.verify` is **`built`** (`ADR-054`, dispatched by `crates/brokerd/src/ops.rs`) and
checks the *vault*: manifest HMACs, the registry cross-binding, and dangling envelopes. It says
nothing about the binary that is running. The two checks answer different questions — "is my data
intact" and "is this program the one that was reviewed" — and neither substitutes for the other.

**This section warrants no figure.** The sequence is four ordered steps with one branch, already
fully expressed above; a flowchart of it would restate the list without adding a claim.

## 4. Updates — **`planned`**

**Opt-in, and never a background task.** The app will not check for updates on its own.
`Settings → About → Check for updates` will be a button the user presses, which is the same
commitment `PRIVACY.md` makes and the reason there is no update ping carrying an identifier.

**The update manifest will be signed**, and an unsigned or badly-signed manifest will be ignored
rather than prompted about — a prompt is an invitation to click through the one control that
matters.

**Updates will replace the app, never the vault.** They will not touch the vault directory, will
not migrate data without an explicit confirmation, and will never run as part of an unlock. This
is invariant **A-6** in `17_AIRLOCK_AND_LLM.md §1`, and this document is where it is discharged.

**A downgrade will be permitted only while `vault_fmt` still matches.** Otherwise the app will
explain which format the vault is in, which the older build understands, and stop.

**The update check will not live in the broker.** `credmgrd` links no HTTP stack at all — that is
invariant **A-1**, the load-bearing one, and it is enforced by absence rather than by
configuration. The check will therefore run in the shell or CLI process, which is also the only
outbound connection the product will ever make. Putting an updater inside the vault process would
repeal A-1 to save a process boundary.

**What exists today, for updates specifically: nothing.** `apps/desktop/src-tauri/Cargo.toml`
declares `tauri`, `serde`, `serde_json`, `zeroize` and, on macOS only, the AppKit bindings the
concealed pasteboard and the sleep observers need — no updater plugin, and no `opener` (removed,
ADR-075); `tauri.conf.json` has no updater configuration and no public key. Its packaging metadata
is no longer the scaffold's — `productName` is `CredMgr`, the version `2.0.0-beta.1`, the identifier
`com.credmgr.desktop`, the icons the KEEP mark — and `Cargo.toml` names its authors "CredMgr
contributors"; what is still missing is signing: `apps/desktop/src-tauri/src/` holds the bridge
(`commands.rs`, `error.rs`, `session.rs`, `transport.rs`, `vault_paths.rs`) and the shell's own
modules (`autolock.rs`, `clipboard.rs`, `shell.rs`), registering a command for every one of the broker's 53 operations in
`tauri::generate_handler!` (`02_ARCHITECTURE.md §6.1`, `ADR-057`, `ADR-062`). None of that bridge touches updates or signing — it carries
no updater code and no signature check — so this paragraph's "nothing" verdict about updates still
holds; it was the *scaffold* characterisation of the shell overall, not the *updates* verdict, that
needed correcting.

## 5. What "not changeable by users" does and does not mean

**It will mean:** the app can prove it is the reviewed build; tampering is detected before any
key is unwrapped; and nobody can hand someone a modified "CredMgr" that looks official, because
the name is protected even though the code is not (`TRADEMARKS.md`). The first two clauses are
`planned` — §2 and §3 are what will deliver them. The third is in force today, because a
trademark policy needs no code to take effect.

**It does not mean the software is locked down against its owner.** The licence is MIT. You may
fork it, patch it, and build your own. A self-built binary will simply report `self-built` rather
than pretending to be a release. That is the honest position: **provenance is verified, obedience
is not enforced.** A vendor claiming a local tool its users cannot modify is describing DRM, and
DRM in a credential manager would be a way of preventing exactly the inspection that makes it
trustworthy.

The trademark is doing the work here, and `TRADEMARKS.md` says why in one line: it is the only
thing that lets a user know the CredMgr they installed is the CredMgr that was audited. Free
code, protected name — the same arrangement several long-lived free projects use, for the same
reason.

## 6. Reproducibility — **`partial`**

### 6.1 What is built

- **The toolchain is pinned for contributors, and for one of two CI legs — not for every leg that
  runs.** `rust-toolchain.toml` fixes channel `1.78.0` with `rustfmt` and `clippy`,
  `profile = "minimal"`, and every contributor who does not override it compiles with exactly that
  version. But `build.yml`'s `core-workspace` matrix is `rust: ['1.78.0', stable]`, and the
  `desktop-app` job installs `dtolnay/rust-toolchain@stable` outright; all three jobs install a
  toolchain explicitly, which overrides the pin file regardless of what it says. The `stable` leg
  is deliberate — the pin file's own comment says it exists "to catch forward drift" — but it means
  the pin governs the contributor default and one CI leg, not every CI leg.
- **The lockfile is committed** and CI builds against it: `build.yml` runs
  `cargo build --workspace --locked` and `cargo test --workspace --locked` across
  `{macOS, Windows, Linux} × {1.78.0, stable}`.
- **The release profile is fixed** in `Cargo.toml`: `opt-level = 3`, `lto = true`, `strip = true`.

### 6.2 What is planned

- **`SOURCE_DATE_EPOCH` derived from the tag date**, so timestamps are a function of the release
  rather than of the machine. Since 2026-09-24 `scripts/release.sh` exports it — from the last
  commit's time when it is not already set, not yet from a tag — and since 2026-10-03 the release scripts read it:
  it fixes the tarball's member times and the bills of materials' timestamps. Nothing in the Rust workspace reads it.
- **A published rebuild procedure** — the exact commands a third party runs to reproduce a tag. The
  expectation, as **measured on 2026-10-03** (`release.sh`'s own header records it): the same commit in the same
  checkout rebuilds byte-identically, even from an empty `target/`; in a second checkout at another path the bills of
  materials are still identical and the binaries differ in 47–48 bytes — the Mach-O `LC_UUID` and the ad-hoc
  code-signature hash that covers it — and nowhere else. Neither `-Wl,-reproducible` nor a shared target directory
  changed that, so neither is passed. The tarball is deterministic on one machine and may differ across machines
  (a different zlib may compress differently), which is why the published `SHA256SUMS`, not a rebuild, is the reference.
- **The goal:** a third party building the tag reproduces byte-identical **CLI** binaries, so the
  signature can be independently corroborated rather than merely trusted.

### 6.3 Two honest gaps

**Desktop bundles will not be bit-reproducible.** Installer metadata makes them non-deterministic,
and `12_BUILD_PLAN.md` already carries bit-reproducible desktop bundles as deferred work. This is
stated rather than quietly assumed away: the reproducibility claim will cover the CLI, and will
say so.

**There are two reproducibility stories, because there are two workspaces.** `ADR-035` excludes
`apps/desktop/src-tauri` from the MSRV-pinned workspace, so it has its own toolchain resolution
and its own lockfile. Reproducing "the release" will mean reproducing both, under two different
pins.

A third, smaller trade worth naming: `strip = true` removes symbols, which helps determinism and
shrinks the artefact, and also removes the debug information a crash report would otherwise carry.
Given that this project ships no crash reporting by policy (`SECURITY.md`), that cost is already
paid.

## 7. Supply chain — **`partial`**

### 7.1 What is declared

`.github/workflows/security.yml` triggers on push to `main`, on every pull request, on a weekly
cron floor and on dispatch — security checks are exempt from the portfolio's CI run-restraint —
and declares, for V2:

| Job | Command |
|---|---|
| `v2-deny` | `cargo deny check` (licences, bans, advisories, sources) |
| `v2-audit` | `cargo audit` |
| `v2-isolation` | `cargo test -p credmgr-brokerd --test isolation --locked` |
| `v2-desktop-bridge` | `cargo test --locked` inside `apps/desktop/src-tauri` — the bridge's token-custody tests and drift guards, since 2026-09-24 (`ADR-062`). Tests only: it is not a dependency audit of that workspace (§7.3) |
| `secrets` | both guard scripts in `--all` mode |
| `semgrep` | `p/security-audit` and `p/secrets`, `--error` |

`deny.toml` is real policy, not a stub: four target triples, an explicit licence allow-list,
`wildcards = "deny"`, `unknown-registry = "deny"`, `unknown-git = "deny"`, an empty
`allow-git` list, and a named ban on `openssl` because this workspace uses RustCrypto crates only.

**The rule that a new runtime dependency requires an ADR is already being practised**, and the
evidence is in the source rather than in a promise: the pinning comments at the top of
`crates/core/Cargo.toml` and `crates/keystore/Cargo.toml` record, per crate and per feature, why
a version was held back, and `ADR-035` records the workspace split that the same constraint
forced.

### 7.2 The honest caveat about "running"

`build.yml` is `workflow_dispatch` only — it triggers on no git event, by design. **For `build.yml`
specifically, the corpus already records the answer, so this document does not re-derive it**:
`16_CROSS_PLATFORM.md §8.2` is headed "The CI matrix — declared, and never run," and states that
`gh run list --workflow=build.yml` returned an empty list (checked 2026-08-18) — zero runs. This
document consumes that finding rather than restating it. Whether `security.yml` has ever actually
run is a separate question this document does not answer: §7.1 above states that job's declared
triggers and configuration, not its run history. Per the portfolio's CI rule, a gate that has never
run has not passed; this document's claim throughout §7 is that the declared jobs are *correctly
configured*, not that any of them is green.

### 7.3 What is planned

- **An SPDX SBOM published per release** (`SBOM.spdx.json` in §2.1). Since 2026-10-03 `release.sh` generates a
  **CycloneDX** bill of materials per binary and one for the app (`credmgr-<version>-sbom-{credmgr,credmgrd,desktop}.cdx.json`),
  sanitised of local paths and given a deterministic serial number; the SPDX form and the release-job generation remain `planned`.
- **Vendored dependencies for release builds**, so a release does not depend on a registry being
  reachable or unchanged at build time.
- **Coverage for the excluded desktop workspace.** `deny.toml`'s own header states that
  `apps/desktop/src-tauri` is audited independently — and no configuration or job in the tree
  audits it today. This is the concrete, current shape of risk `AR-8` in
  `16_CROSS_PLATFORM.md §10`, and it will close when the desktop workspace gains its own
  `deny.toml` and its own job.

## 8. The release runbook — **`planned`**, with a minimal unsigned path **`built`**

**What exists — the unsigned path, `built` 2026-09-24 and extended 2026-10-03** (`OPEN_WORK_REGISTER.md` M3; K-5). *The
paragraph that follows is the 2026-09-24 slice; the 2026-10-03 additions are listed after it.*
`v2/scripts/release.sh` refuses a dirty tree (`--dev` allows one and stamps such a build `dirty`),
builds `credmgr` and `credmgrd` with `cargo build --release --locked`, stamping each with the
commit and target; stages `dist/credmgr-<version>-<target>/` with both binaries, the launchd unit
`packaging/com.credmgr.brokerd.plist`, `RELEASE.md`, `CHANGELOG.md`, `SECURITY.md` and `LICENSE`;
tars it; writes `dist/SHA256SUMS` over the tarball and both loose binaries; and runs each staged
binary's `--version` to check its stamp names this commit. It **does not** sign, notarise, produce
a detached signature, and it runs on the maintainer's machine, not in CI.
`v2/RELEASE.md` is its install guide, verify-the-checksums step first. It is a release a user can
verify only against a `SHA256SUMS` fetched from somewhere other than the same download — which is
why K-5 is disclosed in every release note.

**What was added on 2026-10-03.** (1) `release.sh` writes a **deterministic** tarball (sorted members, mtime fixed to
`SOURCE_DATE_EPOCH`, owner 0:0 with no names, normalised modes, a gzip header without a name or time), stages the
bills of materials in `sbom/`, remaps the build machine's paths out of the binaries, puts a `SHA256SUMS` inside the
tarball as well, writes the folder's `dist/SHA256SUMS` over **every** published file, and runs its own `--verify`.
(2) `release.sh --verify [DIR]` re-checks an existing `dist/` and builds nothing: the sums, the tarball's members and
owners, the stamps, the bills of materials and their serial numbers, the app bundle's seal, and that no shipped binary
or bill of materials names a build-machine path; `--allow-dev-build` and `--allow-version-skew` exist and say never to
publish what they accept. (3) `scripts/release-app.sh` builds the desktop app (`cargo build --locked`, `tauri bundle`,
not `tauri build`), seals it **ad-hoc** — internal consistency, not an identity — writes `credmgr-desktop-<version>-<target>.dmg`
and `.app.zip`, and **starts the built app against a throwaway vault, requiring a real window**, before it calls the build
good. (4) `scripts/fresh-install-check.sh` copies only the tarball and `SHA256SUMS` into an empty folder and runs the
documented verification, unpack, `--version` and a real journey against a throwaway vault. (5) `scripts/release-selftest.sh`
corrupts copies of a good release in many ways and requires `--verify` to refuse each. (6) A Homebrew formula is prepared
under `packaging/homebrew/` (`fill-formula.sh` fills it from the published `SHA256SUMS`; style-clean and audit-clean in a
throwaway tap; **not published**, no tap exists; Apple Silicon only). The human pass over the built app is
`RELEASE_VERIFICATION.md`. None of this signs, notarises, uploads or publishes anything.

**The complete signed procedure — `planned`**, written out so that the first signed release is
executed rather than improvised. Every step below is future work; none of it has been performed.

**Preconditions.** The tag's tree builds clean on all three platforms at both toolchain legs; the
full workspace suite passes; the isolation suite passes; `cargo deny check` and `cargo audit` are
clean; both guard scripts pass in `--all` mode; `CHANGELOG.md` has a dated section for the
version; the two signing certificates from §2.4 are in hand.

1. **Cut the tag.** Annotated, signed, named `v<semver>`. The tag date becomes
   `SOURCE_DATE_EPOCH` for every artefact in the release.
2. **Build, in CI, from the tag.** The workspace and the desktop workspace, per platform. CI
   emits unsigned artefacts and the SBOM, and nothing else — it holds no key.
3. **Verify the stamp.** Every artefact's embedded `BuildStamp` must name the tag's commit and
   carry `dirty: false`. A dirty stamp aborts the release; it means the build did not come from
   the tag.
4. **Sign, on the maintainer's machine.** Developer ID plus notarisation and stapling for macOS;
   Authenticode for Windows; detached signatures for the Linux artefacts and the CLI binaries.
5. **Checksum and sign the checksums.** `SHA256SUMS` over every published file, then
   `SHA256SUMS.asc` over that. The detached signature over the checksum file will be what a user
   actually verifies; the individual artefact signatures will be what the operating systems check.
6. **Verify as a user would, on a clean machine.** Download the published artefacts, check the
   detached signature, check the hashes, install, and confirm the app reports `verified` in §3.3's
   vocabulary. A release nobody has verified from the outside has not been tested.
7. **Publish.** Artefacts, `SHA256SUMS`, `SHA256SUMS.asc`, the SBOM, and release notes that say
   plainly what was fixed — security fixes first, in the wording `SECURITY.md` commits to.
8. **Only then, the update manifest.** Signed, and published last, so that no client is offered an
   update before the artefacts it points at are verifiably in place.

**Abort conditions, each of which stops the release rather than being worked around:** a dirty
stamp; a notarisation rejection; a checksum that does not match between the build machine and the
published file; any supply-chain job failing on the tagged tree; a `verified` state that does not
appear on the clean-machine check in step 6.

**After the release.** The tag is never moved. If the release is bad, the next tag supersedes it
and the changelog marks the old one `YANKED` with the reason (§1.1). If the signing key is
believed compromised, the revocation and advisory path is `SECURITY.md`'s reporting process, and
the practical remedy is a new key and a new release — the old signatures cannot be un-issued.

## 9. Risks

Three risks belong to this document. They are stated as they will apply once the pipeline exists;
today the pipeline's absence is itself the larger exposure, and that is what the Status block at
the top says.

| ID | Risk | Bound | Mitigation |
|---|---|---|---|
| **AR-18** | Signing-key compromise, allowing signed malicious releases | Does not affect vaults already on disk — the key signs artefacts, not data, and no vault content is encrypted to it | Key held off CI and hardware-backed (§2.2); revocation and advisory path in `SECURITY.md`; the practical remedy is a new key plus a new release, stated plainly rather than implied |
| **AR-19** | The self-integrity check can be patched out of a modified binary | Bounded to builds the user already installed from an unofficial source; it does not weaken an official build | True and unavoidable — a modified binary can remove its own check. The control is the operating-system signature, which the attacker cannot forge, plus the trademark that tells a user what an official build is (§5) |
| **AR-20** | Distribution repackaging breaks verification | Not a security failure and not a tamper signal | Reported as `unverified (repackaged)`, distinct from `FAILED` (§3.3) |

**Two further exposures, named without identifiers.** They are deliberately not assigned `AR-`
numbers in this pass, because the corpus's `AR-` space is allocated across several documents and a
parallel session is editing one of them; naming them here without minting an id is honest and
avoids a collision.

- **The signature primitive is a new dependency in the trust base.** Whichever crate is chosen for
  §2.3 becomes code that verifies the update path — the highest-leverage verification in the
  product. Bound: it is verification-only and holds no key material, so a bug in it cannot leak a
  secret; it can only cause a bad update to be accepted or a good one to be rejected. Path: choose
  it once, for all three consumers, and record the choice as an ADR (§2.3).
- **The desktop workspace is not covered by any dependency audit today** (§7.3). Bound: it is the
  shell, not the vault — it holds no node key and mints no capability (`ADR-057`) — so a
  compromised dependency there reaches the UI process, not the broker's key material. Path: its
  own `deny.toml` and its own CI job.

## 10. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `16_CROSS_PLATFORM.md §8.3` | the per-platform artefact, signing mechanism and updater that §2.1's release manifest instantiates |
| depends on | `04_CRYPTO_AND_KEYS.md §1` | the actual primitive set — X25519 and HMAC-SHA256, no signature primitive — which is why §2.3 is new work rather than reuse |
| depends on | `22_ORG_VAULT_SYNC_AND_LICENSING.md §4.4` | the Ed25519 decision for the optional licence certificate (`ADR-074`); the same verifier §2.3 needs, chosen once for both |
| depends on | `14_DECISIONS.md` | `ADR-035` (the desktop shell is a separate workspace, hence a separate artefact and a second reproducibility story), `ADR-054` (`maintenance.verify`, the vault check §3.4 distinguishes this one from), `ADR-059` (the status vocabulary this document uses) |
| feeds | `RELEASE_VERIFICATION.md` | the built `CredMgr.app` (§8) is the artefact that checklist is walked against |
| feeds | `17_AIRLOCK_AND_LLM.md §1` | invariant `A-6` — the updater updates the app, never the vault, and is signed and opt-in — discharged by §4 |
| feeds | `05_THREAT_MODEL.md §6` | the signed, hardened release build that §6 of that document names as absent today |
| feeds | `10_API_AND_MCP.md §5` | `app_integrity()`, the shell command that will surface §3's result to the UI |
| feeds | `02_ARCHITECTURE.md §6` | the self-integrity check the desktop shell defers to this document, including the missing signing primitive |

## 11. Source

**Design.** `ADR-035` (desktop workspace excluded from the MSRV pin), `ADR-054`
(`maintenance.verify`), `ADR-057` (the shell holds no key), `ADR-059` (status vocabulary),
`ADR-062` (the bridge's CI job). `K-5` in `PHASE8_AUDIT_REPORT.md` for the unsigned first release.
`22_ORG_VAULT_SYNC_AND_LICENSING.md §4.4` for the Ed25519 decision about the optional licence
certificate (`ADR-074`) that shares this document's missing primitive. `O-3` in `14_DECISIONS.md` and `K-4` in `PHASE8_AUDIT_REPORT.md` for
the outstanding certificates.

**Code.** `v2/Cargo.toml` (workspace `version = "2.0.0-alpha.6"`, `license = "MIT"`, release
profile, workspace exclusion); `v2/scripts/release.sh`, `release-lib.sh`, `release-app.sh`, `release-selftest.sh`, `fresh-install-check.sh`, `v2/packaging/homebrew/` and `v2/RELEASE.md` (§8's unsigned path);
`v2/packaging/com.credmgr.brokerd.plist` (the launchd unit it ships);
`rust-toolchain.toml` (channel `1.78.0`); `crates/core/Cargo.toml` and `crates/keystore/Cargo.toml`
(the MSRV pinning comments that constrain §2.3); `crates/core/src/envelope.rs` (`VERSION = 1`, the
one built format version); `crates/mcp/src/server.rs` (`SERVER_VERSION`);
`crates/cli/src/main.rs` and `crates/brokerd/src/main.rs` (`version_line`, the `--version` stamp
of §1.2); `apps/desktop/src-tauri/Cargo.toml` and `tauri.conf.json` (no updater plugin, no
signing configuration, version `0.1.0`).

**CI.** `.github/workflows/security.yml` (the V2 security jobs — six since 2026-09-24 added
`v2-desktop-bridge` — triggers, and the semgrep
rulesets); `.github/workflows/build.yml` (`workflow_dispatch` only, three platforms, two toolchain
legs); `deny.toml` (targets, licence allow-list, bans, source policy).

**Tests.** None in the workspace. No test exercises any behaviour specified in this document,
which is the correct consequence of the pipeline not existing — and is stated here so that no
future reader infers coverage from the corpus's general test count. The one adjacent check is
`scripts/release.sh`'s own final step, which runs both staged binaries' `--version` and compares
the stamp to the commit; it is a release-time assertion, not a test. The adjacent built
check is `maintenance.verify` (§3.4), which verifies the vault rather than the binary.

**Figure.** §2.4's `release-trust-boundary` diagram: `v2/docs/21_RELEASE_AND_INTEGRITY_spec.json`
(`docgen`, `kind: "flowchart"`) — built and security CI nodes cited straight from
`.github/workflows/{build,security}.yml` above; every node past the "Unsigned artefact" hand-off is
rendered `fallback`/dashed per `tools/ENGINE_ROUTING_POLICY.md`'s convention for target design with
no code path yet.

**Verification.** The absences asserted in the Status block were established by grepping
`v2/crates/` and `v2/apps/` for `ed25519`, `eddsa`, `codesign`, `WinVerifyTrust`, `SecStaticCode`,
`SOURCE_DATE_EPOCH` and `BuildStamp` (no matches), by listing `.github/workflows/` (two files), and
by reading both crate manifests of the desktop shell. `python3 -m tools.corpus_check crossrefs`
proves every `NN_NAME.md §S` reference in §10 resolves to a section that exists.
