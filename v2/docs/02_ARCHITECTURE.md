---
id: V2-002
classification: public
title: Architecture
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-19
---

<!-- artifact-hardened: NEEDS RE-HARDENING — corrected 2026-08-18 (Session 21, closing this
     document's entry in VERIFICATION_BACKLOG_S21.md). The previous stamp (rewritten the same
     day, pre-verification) attested to a body that an independent skeptic pass then found six
     surviving defects in: a claim that the day-7 archive trees are covered by `verify` and
     destroyed on schedule (neither is true — see §7); a present-tense claim that any node
     holding critical material auto-locks in five minutes, when nothing in `crates/` ever sets
     that policy field (§2.4); a claim that `nodes/<nodeId>/notes.env` has no writer in
     `crates/`, when the same backup test fixture that writes `root.wrap.se` also writes it
     (§7); and a present-tense statement of the still-`planned` twelve-month audit-retention
     figure, cited to a test that proves a day-8 restore is refused, not that anything is
     destroyed. All four, plus the two convention violations bound up in the same passages, are
     corrected below, each re-derived from live source rather than patched from the finding
     text. Re-verifying every `## Connections` citation in the same pass found four more
     pointing at a section that exists but is the wrong one for the content claimed (in `05`,
     `13`, `16`, `19`) — corrected alongside them. Nothing here overturns the built/partial/
     planned split; it corrects the evidence under six of its claims. Still needs an operator
     hardening pass. Updated 2026-09-24 for ADR-062…066 (the live unlock and write-through, the
     root key resident while unlocked, 42 ops, the bridge at 42/42 and its CSP).

     Updated 2026-08-19 (Session 21, round 2 of VERIFICATION_BACKLOG_S21_ROUND2.md): five more
     defects found and corrected, each re-derived from live source. §7's on-disk tree mislabelled
     `totp/<nodeId>/<itemId>.env` as built storage for 2FA seeds; it has no reader or writer
     anywhere in `crates/` — `totp_item(` occurs only in its own definition in `paths.rs` — and a
     stored TOTP seed is an ordinary entry instead (`ops.rs`'s `totp.code`/`totp.seed` arms, via
     the same envelope machinery as any other credential). §7's own accounting of code-less
     leaves named four files and should have named five; it now does. §1 quoted V1's own agent
     notes as *"Agent calls bypass PIN sessions by design."* — that exact phrase is not V1 source
     text (`git log --all -S"Agent calls bypass"` matches only the commit that added this
     document); replaced with the real comment in `v1/lib/lock.js` lines 8-9, which is
     config-gated rather than absolute. Three more wrong-section citations survived the round-1
     pass above despite it naming this exact defect class: `16_CROSS_PLATFORM.md §4.2`
     (macOS/Secure-Enclave content, cited for the Windows named-pipe design that actually lives at
     §5.3), `13_TEST_PLAN.md §2` (a runner-type table, cited for the access-rule property tests
     that actually live at §3), and `09_UI_UX_SPEC.md §2` (a static layout with no locked-state
     content, cited for the locked-rendering claim that actually lives at §4 and §11) — all three
     corrected to their real destinations. Every other `NN_NAME.md §S` citation in this document
     was independently re-opened and confirmed on-topic in this pass. Still needs an operator
     hardening pass. Updated 2026-09-24 for ADR-071…073 (47 ops, the bridge at 47/47; `notes.env`
     now has a product writer, `notes.write`, so §7's code-less leaves are four again; the CLI
     count in §11 corrected from 20 to 21). Updated 2026-10-02 for ADR-075…077 (48 ops and the bridge at
     48/48; §5 rewritten for the hosted, precompiled design; §6 for the shell's concealed clipboard and
     lock-on-sleep; the unsafe-code exception and the vault layout gain the rotation lock and stage).
     Updated 2026-10-03 for ADR-078/079 (53 ops and the bridge at 53/53 plus three shell commands; 24 CLI
     subcommands and 15 MCP tools; §5 rewritten — every screen is wired; §2.1 and §7 for the durable seal
     records, the orphan node made by `credmgr init` and its cold key, and the envelope's version 2). -->
# Architecture — one enforcement point, and the processes around it

`CredMgr V2` · the process topology, the transport, the crates, and what of each exists today · `2026-08-18`

> **Status.** The **enforcement architecture is built**. The broker library serves the real
> newline-delimited-JSON protocol over a Unix domain socket, identifies its peer before it
> reads a single frame, resolves every request through one access resolver, and dispatches 53
> operations; the CLI (24 top-level subcommands) and the MCP server (15 tools) are socket
> clients that hold no key material. One claim this document carried is **false and is
> corrected here rather than quietly dropped**: the runtime is **Rust, not Node.js**. Two more
> were true when this document was written and **stopped being true on 2026-08-31** (ADR-061),
> and are corrected in place rather than left standing: `credmgrd`'s binary is no longer a stub
> — `crates/brokerd/src/main.rs` resolves the vault path and serves the socket — and vault
> bootstrap exists, as `credmgr init` over the two-phase `vault.init_begin`/`vault.init_confirm`
> pair. What was left open after that — a long-running broker's `vault.unlock` **ignoring
> `params.passphrase`**, nothing loading an existing vault after a restart, and every change
> living only in memory — **stopped being true on 2026-09-24** (ADR-063): the live unlock builds
> the Software keystore from the passphrase, loads and verifies the vault from disk, and every
> change is written through (§2.1). Nothing *installs* the launchd unit; `RELEASE.md` has the
> operator copy it by hand. The desktop shell is **built**: a Tauri bridge exposing all 53
> operations exists and is tested, behind a real Content Security Policy (ADR-062), and the window
> hosts the precompiled design (ADR-075) with every screen wired to the broker — reads and writes
> alike, with no demo data and no local-only write path in a release build (§5). Hardware keystores, user presence, memory locking, the
> Windows transport and release self-integrity are **planned**, and are designed in full
> below. Evidence for every marking is cited in place and collected in §11.

---

## 1. The central change: one enforcement point — **built**

**Evidence.** `crates/brokerd/src/server.rs` (`serve_connection`, `handle_request`),
`crates/brokerd/src/ops.rs` (53 dispatched ops), `crates/core/src/access.rs` (the one resolver);
proven end to end over a real socket by `crates/cli/tests/broker_integration.rs` and by the
isolation suite `crates/brokerd/tests/isolation.rs` (I-1…I-25, I-10 excepted, and I-27…I-29).

V1 has **three** independent paths to plaintext:

```
bin/credmgr  ─┐
lib/server.js ├─► lib/store.js ─► lib/crypto.js ─► age -d -i master.key ─► plaintext
mcp/server.js ┘
```

Each re-implements its own idea of authorisation. The PIN lock guards the HTTP surface; the
bearer token guards agents; the CLI guards nothing, because it holds the key. V1's own source
records the consequence, in a comment above the lock module: headless agents "authenticate with
the daemon bearer token and bypass PIN sessions, unless `requirePinForAgents: true` is set in
config" (`v1/lib/lock.js` lines 8-9) — a config-gated exception, not an absolute one, but still a
second gate that disagrees with the first by default. Three gates that disagree is not a policy,
it is three policies.

V2 collapses this into a **broker**. The diagram is the shipped topology, annotated with what
exists:

```
   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
   │ credmgr CLI  │  │  MCP server  │  │ Tauri bridge │  │  UI screens  │
   │   (built)    │  │   (built)    │  │  (partial)   │  │  (planned)   │
   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
          │                 │                 │                 │
          └────── scoped capability token over a local socket ───┘
                                    │
                        ┌───────────▼────────────┐
                        │      credmgrd          │  ← the ONLY process that
                        │  · peer identification │    ever holds node keys
                        │  · scope resolution    │
                        │  · access graph check  │
                        │  · 2FA gate            │
                        │  · rate limit + backoff│
                        │  · audit append        │
                        │  · decrypt / encrypt   │
                        └───────────┬────────────┘
                                    │
                        ┌───────────▼────────────┐
                        │   vault on disk        │
                        │   (per-node envelopes) │
                        └────────────────────────┘
```

**Consequences that make this worth the rewrite:**

- One place to audit, one place to fix, one place that can be property-tested. No dispatch arm
  re-implements authorisation; every one of them calls `credmgr_core::access::resolve`.
- Clients never possess key material. A compromised MCP process leaks only what its own token
  was scoped to — which is what makes I-1 (cross-node reveal denied with no leak) and I-11
  (a cwd-scoped agent cannot reach another node under any argument) testable statements rather
  than aspirations.
- The access graph is enforced *below* every client, so a bug in a UI cannot widen scope. The
  Tauri bridge is deliberately a pass-through for exactly this reason (§6).
- Locking is real: `BrokerState::lock` zeroises the hot key bytes in place and, on a live
  vault, the resident root key (ADR-063), clears every elevation, and revokes every session
  token minted by the unlock it is ending (ADR-056).

Exactly one process holds node keys; every other surface is a socket peer holding only a path
and, for two of the three, a token — so a compromised client leaks no more than its own scope,
and the built/partial/planned split runs *across the clients*, never through the broker:

<!-- figure:broker-trust-boundary -->

---

## 2. Processes and transport — **partial**

### 2.1 The process table

| Process | Artifact | Lifetime | Started by | Holds node keys? | Status |
|---|---|---|---|---|---|
| **`credmgrd`** (broker) | `crates/brokerd`, bin `credmgrd` | long-running, auto-locks | launchd user agent `com.credmgr.brokerd` *(the unit ships in `packaging/`; nothing installs it — `RELEASE.md` has the operator copy it)* | **Yes**, only between unlock and lock — node keys and, on a live vault, the root key; zeroised on lock | **`partial`** — `src/main.rs` runs and serves the socket (ADR-061); since ADR-063 it unlocks an existing vault by passphrase, loads it from disk, and writes every change through. Hardware keystores and presence are `planned` (§6.3) |
| **`credmgr`** (CLI) | `crates/cli`, bin `credmgr` | per invocation | user shell | No | **`built`** — 24 top-level subcommands |
| **`credmgr mcp`** (MCP stdio) | `crates/mcp`, hosted by the same binary | per agent session | an agent's MCP config | No | **`built`** — 15 tools |
| **CredMgr desktop** (Tauri 2) | `apps/desktop` | user session | user | No — it will broker presence, never keys | **`partial`** — 56 registered commands: all 53 broker ops bridged plus the shell's own three (ADR-062, ADR-075, ADR-078), and the hosted design with every screen wired to the broker, writes included. `partial` because presence attestation (Touch ID) and signing are not built (§6.3) |

**The stub was the load-bearing caveat of this document, and it is gone.** Until 2026-08-31
`crates/brokerd/src/main.rs` printed one line and exited, and `credmgr_brokerd::server::run`
was reachable only from test fixtures. ADR-061 ended that: `main` resolves the vault path
(`CREDMGR_VAULT_DIR` or the OS default), creates `run/` at `0700` before anything binds, and
serves the socket. The protocol, the peer gate, the dispatcher and the client transports are
therefore proven against each other over a real Unix socket by a real daemon as well as by the
four fixtures that still stand up their own broker
(`crates/cli/tests/{broker_integration,success_criteria,mcp_integration,vault_init}.rs`).

**Bootstrap — `built`.** `credmgr init` creates a vault, in two broker operations rather than
one so the recovery code can be shown and retyped *before* anything reaches disk (ADR-061).
`vault.init_begin` generates the root key, wraps it under Argon2id(passphrase) and under a
freshly generated recovery code, generates the Global node's keypair, wraps that under the root
key, and holds all of it in memory under a TTL — touching no disk, and refusing outright if a
registry already exists or if the vault path is inside a git working tree.
`vault.init_confirm`, on a matching retyped code, writes the key files, then Global's (empty)
manifest, then the `registry.json` that cross-binds it, then the external generation counter —
the crash-safe order `04_CRYPTO_AND_KEYS.md §2.3` specifies — and commits the same material into
the running `BrokerState`, so the vault the daemon just created is usable without a restart.
Neither passphrase nor recovery code is ever read from argv. Test: `crates/cli/tests/vault_init.rs`.

**What bootstrap does not cover, precisely.** Two steps this section once listed as part of a
target `init` are still unbuilt, and the operation existing does not hide them:
`keys/root.wrap.se` is not written, because no platform keystore exists to produce one (§6.3),
so a new vault has two root wraps rather than three; and **nothing installs the launchd unit** —
`crates/brokerd/packaging/` carries it, and the release tarball carries a copy under
`packaging/` with `RELEASE.md`'s instructions to copy it into `~/Library/LaunchAgents/` by hand.

**The live unlock — `built`** (ADR-063, as amended after review on 2026-09-24). Until that date
the sharper limit was in the daemon rather than in `init`: a long-running `credmgrd`'s
`vault.unlock` ignored `params.passphrase` and unwrapped against the placeholder keystore the
process built at startup from an empty passphrase, so it answered `wrong_passphrase` to the
right passphrase; nothing loaded an existing vault after a restart; and every mutation lived only
in memory. Now `vault.unlock {passphrase}` builds a request-scoped `Software` keystore from the
passphrase (ADR-041's permanent tier), proves it against `keys/root.wrap.pass`, and — if this
process has not yet — loads and verifies the vault from disk: **one read of each file, all or
nothing**, checking the registry's HMAC, the external rollback counter, and every manifest's
cross-binding, then every node's wrapped and public key and the persisted gate, before anything
is committed to the running state. A **missing** rollback counter is refused, unless `credmgrd`
was started with `CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1` for a vault moved between machines.
A write interrupted between its manifests and its registry is recovered from the previous signed
registry pair (`registry.json.prev`/`registry.sig.prev`, §7) and a manifest exactly one
generation ahead of its binding; the counter only moves forward. Vault files that are symlinks
or FIFOs are refused (`crates/store/src/atomic.rs`). Only then is the gate consulted. The
passphrase keystore is dropped at once — the passphrase is never resident — and the unwrapped
**root key stays resident until `lock()`** (`04_CRYPTO_AND_KEYS.md §6`), which is what every
write re-derives node keys from. A passphrase-less `vault.unlock` is refused on any disk-backed
vault. `main` still does not load a vault at startup — an unverified registry is never shown —
so after a restart the graph is empty until the first unlock. **Write-through:** after any op in
`ops::PERSISTED_OPS` succeeds on a disk-backed vault, the live state is written in
`04_CRYPTO_AND_KEYS.md §2.3`'s crash-safe order — node key files, every manifest, the signed
registry, then the external counter — and a failed write answers `internal` naming the op rather
than `ok`. Code: `crates/brokerd/src/state/durable.rs`; test:
`crates/brokerd/tests/durable_vault.rs`. Nothing that matters to a restart is memory-only any more: the locked-write tray is
rebuilt from `pending/` at unlock (ADR-069), and the sealed-node records `node.restore` reads live in the signed
registry (`sealed`, ADR-079, §7) — a seal, a restart and a restore on a vault `credmgr init` made work end to
end, and a crash at any step of either leaves a vault that unlocks.

### 2.2 Transport — **built**

The broker binds a Unix domain socket at **`<vault>/run/broker.sock`**, and chmods it `0600`
immediately after bind. The run directory is `0700`, like every directory the vault owns
(`crates/store/src/atomic.rs::ensure_dir` chmods each component it creates). `credmgrd`'s
`main` creates that directory itself before binding (ADR-061); the test fixtures create their
own under a temporary directory.

`<vault>` resolves in this order (`crates/store/src/paths.rs::default_vault_dir`, ADR-039):
`CREDMGR_VAULT_DIR` when set, overriding everything; otherwise the per-OS application-support
location on macOS, `%APPDATA%\credmgr` on Windows, and `$XDG_DATA_HOME/credmgr` — falling back
to the per-user `.local/share` path — elsewhere. The socket is always `run/broker.sock` beneath
whichever of those wins. That rule is duplicated in the desktop shell, which lives in a
separate Cargo workspace and cannot link the store crate (ADR-035); the duplication is held
honest by a test that reads `crates/store/src/paths.rs` off disk and compares
(`apps/desktop/src-tauri/tests/drift_guards.rs::the_per_platform_vault_defaults_still_match_crates_store`).

**There is no listening TCP socket anywhere in `crates/`** — verified, not assumed: the
workspace contains no `TcpListener`, no `TcpStream`, and no HTTP client crate at all. That is
ADR-019 (no HTTP surface) and ADR-025 (no listening socket) as a property of the code rather
than a promise about it, and it is also what makes `17_AIRLOCK_AND_LLM.md`'s rule A-1 (no
outbound network, ever) checkable.

**The one loopback caveat, stated rather than hidden.** The desktop shell's development
configuration (`tauri dev`) points the webview at a Vite dev server on a fixed loopback port, as
`create-tauri-app` generates it, under a looser `devCsp` that allows that origin and
`unsafe-inline` styles. That is a development-only listener; the production `csp` allows neither.
The shipped app serves its bundle from disk (`frontendDist` is the built output) and the release
build must fail closed if a dev URL survives into it. That build-time check is **planned**; it does
not exist.

**Windows transport — `planned`.** The design is a named pipe `\\.\pipe\credmgr-<sid-hash>`
with a DACL granting only the current user's SID, and peer identity by
`GetNamedPipeClientProcessId` → `OpenProcess` → token SID comparison, refusing any SID that is
not the owner (`16_CROSS_PLATFORM.md §5.3`). The `interprocess` crate is already a declared
dependency of `credmgr-brokerd` for exactly this and is currently unused: the Unix transport is
written directly against `std::os::unix::net` so that the raw peer-credential syscalls are
unambiguous about which file descriptor they are interrogating.

### 2.3 Write serialisation — **built**

The CLI, the desktop shell and one MCP server per agent session can all mutate concurrently.
The broker holds an exclusive in-process write lock **per node**
(`BrokerState::node_write_lock`, an `Arc<Mutex<()>>` held across an entire mutating op), and
every mutating request carries the caller's last-seen `generation`; a stale generation returns
`conflict` carrying both generations and the current state, rather than silently overwriting.
Reads are never blocked by a write. Test: `isolation.rs::i25_concurrent_writers_same_starting_generation_exactly_one_wins`.

One counter deliberately sits outside that per-node lock: the vault-global entry `ref` counter
is a single atomic, because refs are unique vault-wide and a per-node lock cannot by itself
stop two concurrent creates *on different nodes* from computing the same next value.

### 2.4 Auto-lock — **partial**

- **Idle timeout — built.** A ticker thread started by `server::run` wakes every 30 seconds and
  calls `BrokerState::tick_autolock`, which enforces the vault-wide idle limit — fifteen minutes
  by default — and, for any node that carries one, that node's own `lock_after_seconds`. Two
  separate limits, because ADR-030 rejected making one number serve both. **What is built is the
  mechanism, not the policy default.** `NodePolicy::lock_after_seconds` is `Option<u32>` and
  defaults to `None`; nothing in `crates/` ever sets it to anything else — the only assignment
  anywhere in the workspace is a test fixture (`phase3_exit_gate.rs:461`, `Some(300)`) that
  exists to prove the mechanism, not to model production data. ADR-030's "five minutes for any
  node holding critical material" is target policy: no code derives `lock_after_seconds` from an
  entry's criticality, so until something sets the field, every real node auto-locks only on the
  vault-wide idle timer. Every request, allowed or denied, touches the activity clocks before
  dispatch, so a denied request still counts as a human being present. Tests:
  `phase3_exit_gate.rs::{idle_past_the_vault_threshold_locks_on_tick, activity_resets_the_idle_clock, a_nodes_own_lock_after_seconds_locks_only_that_node_not_the_vault}`.
- **Sleep, screen lock and session end — partial.** `BrokerState::external_lock_signal` exists
  and is tested (`external_lock_signal_locks_immediately_regardless_of_any_timer_state`), and
  **nothing in the product calls it.** The observer that would — the native shell noticing
  `NSWorkspace` sleep/screen-lock notifications, or the Windows/Linux equivalents — is part of
  the desktop app and does not exist. ADR-043 split it this way on purpose: build the half that
  needs no native code, and do not pretend the other half is wired.
- **Explicit lock — built.** `vault.lock` calls `BrokerState::lock` directly.

**What locking does, precisely.** It zeroises each hot node key's bytes in place and, on a live
vault, the resident root key (ADR-063), sets the locked flag, clears any in-flight two-step
unlock, clears every gate elevation, and revokes every session token registered by the unlock
that opened it. A login session is also revoked on its own when unused for the vault idle
timeout, even while agent traffic keeps the vault itself unlocked (ADR-065). It does **not** touch the registry
or the per-node manifests: topology and counts must stay renderable while locked
(`09_UI_UX_SPEC.md §4, §11`), and the access resolver's rule R1 denies `reveal`/`update` while locked
regardless of what is in the hot set — the empty hot set is what makes that denial airtight
rather than merely policy. It also does **not** increment `vaultGeneration`; that counter is the
registry's external freshness counter (ADR-024), and an earlier version of this document wrongly
described it as a lock counter.

---

## 3. Peer identification — how the broker knows who is asking — **built** on macOS, **partial** elsewhere

Every connection is identified before the token is even read, in `serve_connection`, and a
connection that cannot be identified is closed silently without a frame being parsed.

1. `getsockopt(LOCAL_PEERCRED)` → uid. **Reject anything that is not the owning uid.** Hard
   gate, no exceptions, no error frame — the connection simply closes
   (`10_API_AND_MCP.md §1`'s "connection closed before the first frame is read").
2. `getsockopt(LOCAL_PEERPID)` → pid, then `proc_pidinfo(PROC_PIDVNODEPATHINFO)` → the peer's
   **current working directory**. Best-effort: a failure yields `None`, never an error, so a
   sandboxed or already-exited peer still gets a scope, it just loses the convenience.
3. The cwd is matched against the node registry's `workdirs[]` to derive a **suggested scope**,
   so an MCP server launched inside a project directory resolves to that project's node with no
   configuration at all (`06_ACCESS_GRAPH.md §4`).

**Honest limits, stated because a reader will otherwise assume more:**

- A process can `chdir`. **The bound is narrower than a blanket "cwd is never authoritative"
  would suggest:** when a token *is* presented, it overrides cwd entirely and is the sole
  authority — a token/cwd disagreement is logged as an anomaly and allowed to proceed rather
  than blocked (`isolation.rs::i12_token_workdir_mismatch_proceeds_and_writes_an_anomaly_to_the_audit_log`).
  But when *no* token is presented — the ordinary case for an agent launched in a project
  directory — cwd itself is directly authoritative: `resolve_scope` step 2 derives the caller's
  node and `agentAccess` capabilities from cwd alone (`06_ACCESS_GRAPH.md §4`). This is accepted
  risk AR-5, permanently, on the tokenless path (`05_THREAT_MODEL.md`, the AR-5 row).
- **The peer's executable path is not captured today.** `PeerInfo` carries uid, pid and cwd, and
  nothing else. Resolving the executable via `proc_pidpath` and recording it on every decision is
  **planned**; until it lands, any statement elsewhere in this corpus that a denial is logged
  with the requesting process's executable path describes the target design, not the code.
  When it does land it will be an audit field only — an executable-path check is advisory on an
  unsigned machine and the broker must not pretend to verify it.
- What this genuinely delivers today: correct-by-default scoping for agents, and an audit line
  that says *"a process whose cwd was `…/projectA` asked for a `projectB` secret"* — precisely
  the anomaly worth seeing.

**Linux — `partial`.** The `SO_PEERCRED` path compiles and follows the same contract (uid hard
gate, pid recorded, cwd best-effort). It has never been exercised against a real Unix socket on
Linux: the only workflow that runs `cargo test --workspace` (`.github/workflows/build.yml`,
which is what would exercise the real-socket peer-identification tests in
`crates/cli/tests/{broker_integration,success_criteria,mcp_integration}.rs`) triggers on
`workflow_dispatch` only and has zero recorded runs. `security.yml`'s Linux CI jobs (`v2-isolation`,
`v2-deny`, `v2-audit`, all `runs-on: ubuntu-latest`) do run routinely, but `isolation.rs` builds
`BrokerState` in-process rather than over a real socket, so they never reach `peer.rs` either.
**Windows — `planned`,** per §2.2.

---

## 4. Runtime and language — **built** (Rust), and the record of how it changed

**Rust, 2021 edition, MSRV 1.78, in two Cargo workspaces.**

This section previously specified Node.js 22 with a zero-dependency core, and recorded a Rust
broker as deferred. That was ADR-008 and ADR-009, and **both were resolved on 2026-08-05** by
`16_CROSS_PLATFORM.md §2`: ADR-008 is superseded, ADR-009 is adopted. The document was not
updated for two weeks and read as current the whole time. It is recorded here rather than
deleted, because the failure mode — a superseding decision that lands in one document and never
propagates — is the one this whole rewrite exists to end.

| Considered | Verdict |
|---|---|
| **Rust** | ✅ Chosen. Real `zeroize` on drop, no GC copies of a secret, no runtime to ship, one static binary per platform, and identical behaviour on all three OSes. It also closed accepted risk AR-3 outright and made AR-2's bound tighter. |
| Node.js 22 | ❌ Superseded (ADR-008). It could not zeroise its heap, its strings are immutable and freely copied by the GC, and the whole key hierarchy would have rested on that. |
| Go | ❌ Same objection as Node on memory, fewer benefits than Rust. |
| Keeping the `age` binary on the hot path | ❌ Rejected. Shelling out per decrypt means plaintext through a pipe, a temp identity file on disk, a process spawn in a hot loop, and a hard dependency on a package manager. `age` is retained as an export/backup format only. |

**Two workspaces, deliberately (ADR-035).** `v2/Cargo.toml` pins the six security crates to
MSRV 1.78 and excludes `apps/desktop/src-tauri`, which tracks current stable, because Tauri 2's
dependency tree transitively requires Cargo's `edition2024` feature. Several crypto and dev
dependencies are pinned *below* their latest majors for the same reason (ADR-036, ADR-038); each
pin carries its reason in `crates/core/Cargo.toml` next to the version, which is the only place
a future reader will look. The cost of the split is that the shell cannot link the broker's
types, so a handful of constants are hand-copied across the boundary — paid for by the drift
guards named in §2.2 and §6.

**Memory hygiene — `partial`, and stated precisely.**

- **Built:** `unsafe_code = "forbid"` at the workspace level, relaxed to `deny` in exactly one
  crate (`credmgr-brokerd`) so that exactly two modules can carry a scoped, justified
  `#[allow(unsafe_code)]`: `peer.rs` for the peer-credential syscalls, and
  `state/rotate/vault_lock.rs` for the per-vault `flock(2)` and `O_NOFOLLOW` calls of ADR-076
  (`File::lock` needs Rust 1.89; the MSRV is 1.78). Secrets are held in
  `secrecy::SecretBox`, wiped by `zeroize` on drop. The hot key set is stored as raw `[u8; 32]`
  rather than an opaque secret type for one specific reason: `lock()` zeroises those bytes **in
  place** and leaves them inspectable, so the Phase 3 exit gate can prove zeroisation by reading
  the buffer rather than by inferring it from a later request being denied.
- **Planned:** `mlock`/`VirtualLock` on the pages holding key material. `16_CROSS_PLATFORM.md §2.2`
  independently retracts the claim that this is already done ("nothing in this workspace calls
  `mlock`") — both documents now agree nothing exists yet. Until it does, a swapped page can
  carry a node key to disk, and the mitigation is the short auto-lock default, not the OS.

---

## 5. Frontend stack — **partial**: the design is hosted and every screen is wired to the broker; real-app verification is the open step

### 5.1 What exists

`apps/desktop/` hosts the finished app design (ADR-075): the Claude Design export, **precompiled at
build time** into an ES module of `React.createElement` calls (`scripts/dc/compile.mjs`), bundled by
Vite and served under the unchanged strict CSP (`script-src 'self'`, `style-src 'self'`, no
`unsafe-eval`, no `unsafe-inline`, no remote origin). The stock `create-tauri-app` scaffold — the
SvelteKit page and its `greet` command — is gone. Every read of vault data goes through one model
(`src/vault/`, the `VaultModel`), and **boot, unlock with the second factor, lock and every read —
the graph, the grants, each node's entries, the review tray and reveal — are wired to the broker**
through the typed client `src/lib/bridge.ts`; **every screen is wired, writes included**: an action in
`src/vault/actions/*` makes one bridge call and then re-reads what it touched, so the screen shows what the
broker last said and never an optimistic edit. A release build carries no demo vault and no fixture broker
(`scripts/dc/release-bans.mjs`, asserted on the built bundle by `scripts/dc/verify-build.mjs`); with no shell it
shows only the broker-unreachable screen, and the demo source exists in development and test builds alone.
Entries are shown as their **fields** (ADR-078): the detail view draws labels, types and masking from
`entry.get`, reveals and copies one field at a time, and previews a paste through the shell's own parser
(`fields_preview`) so what was previewed is what is saved. `RELEASE_VERIFICATION.md` maps every control to its
bridge command and broker op. `19_FRONTEND_DELIVERY_SCOPE.md` owns the delivery
scope; `apps/desktop/README.md` is the build and gate reference.

### 5.2 The stack

Svelte 5 was this section's target through Pass 3. It was dropped when the design arrived as a
finished artefact (ADR-075): re-implementing 19 screens in another framework would have forked the
design the product is held to.

| Layer | Choice | Why, and why not the alternative |
|---|---|---|
| Framework | **The KEEP design, precompiled to `React.createElement` at build time** (React 19.3.0 from npm, a clean-room host of about 200 lines in `src/dc/runtime.ts`) | The design is the artefact the product is held to (`parity` and `design-audit` gates compare against it). The upstream loader compiles with `new Function`, fetches React from a CDN and loads Babel for `.jsx` — every one refused by the production CSP — so the compile moved to build time. |
| App shell | **Vite 8 static bundle, Tauri 2 `frontendDist`** | A fully static bundle with no Node server, which is the only shape a Tauri `frontendDist` can take. |
| Build | **Vite 8** + **TypeScript 7** strict, `scripts/dc/verify-build.mjs` as the last build step | Fails on inline script or style, `style=`/`on*=` attributes, eval, `new Function`, Babel, a CDN host, a source map, or a missing font. |
| Graph | **the design's own hand-written canvas** (`src/design/logic/graph.js`); the vendored `force-graph@1` of `ADR-022` is **not loaded by the app** | The hosted design draws its graph itself; the upstream `force-graph` file is used only by the design's documentation pages. `design/graph-engine/` keeps the sha384-pinned engine and `VAULT_GRAPH_SPEC.md` as the spec the canvas is held to — whether to adopt the engine or retire it is open (`ADR-075`). |
| Styling | **plain CSS + KEEP tokens** | No utility framework. A 200-class utility layer on top of a strict token system is a second source of truth; `design/tokens/` is the whole design system. |
| Icons | **inline SVG, hand-authored** | About a dozen icons. A library is overhead with a supply chain attached. |
| Fonts | **vendored woff2, `@font-face` from local files** | Never a CDN: the app must be byte-identical offline and must pass a CSP with no remote origins. **Not yet vendored** — see §8. |
| State | **`VaultModel` (`src/vault/`) + a typed bridge client** | No state library. The model replaces a plain-data view whenever it refreshes; the logic class reads only `this.vault`, and the bridge is the only source of server state. |
| Tests | **Vitest** (units) + **Playwright** (flows, WebKit and Chromium, under the production CSP) | The Rust side is covered by `cargo test`; these cover what only a browser can. The specs run against a fixture broker held to `bridge.ts` by a shape test. |

### 5.3 What had to change before the hosted design was the product

Each of these was a gate rather than a nicety. Items 1–3 and 5 are built; item 4 is open:

1. **A real CSP — `built`** (ADR-062, 2026-09-24). `tauri.conf.json` carried `"csp": null`
   until then. Production is now `default-src 'self'`, no `unsafe-*`, no origin but Tauri's own
   IPC, `data:` for images only; only the development policy (`devCsp`) may reach the local Vite
   server. `apps/desktop/src-tauri/tests/shell_config.rs` fails closed on `null` or on any remote
   origin — the vendored-fonts and vendored-engine decisions above exist so that policy can stay
   absolute rather than negotiated.
2. **Remove the scaffold's `greet` command and page — `built`** (ADR-075, 2026-10-02). The page left
   with the hosted design; the shell's `greet` command and the `opener` plugin were removed in the
   same change, and `tests/shell_config.rs` fails if either comes back.
3. **A production identifier, product name, and window sizing — `built`** (ADR-075):
   `productName` and window title `CredMgr`, a 1280×820 window (minimum 640×480), macOS 13.1 as the
   minimum system version.
4. **A build-time refusal** if a development URL or a development-vault pointer survives into a
   release build (§2.2) — **open**.
5. **No plugin that can reach out — `built`.** The capability file grants `core:default` only.
   `fs`, `shell`, `http` and `opener` are all absent, and nothing in the app opens an external URL;
   `tests/dependency_policy.rs` fails if an HTTP client, server or TLS binding appears in the tree
   linked on macOS.

---

## 6. Desktop shell and platform integration — **partial**

### 6.1 The bridge — **built**

The shell's JS↔Rust boundary is an allowlist: anything not registered in
`tauri::generate_handler!` is not callable from the webview, which is the boundary that keeps a
UI bug from becoming a vault bug. **All 53 of the broker's operations are bridged** — one command
per op, named with dots replaced by underscores: eight hand-written by ADR-057 (`vault.status`,
`vault.unlock`, `vault.gate_verify`, `vault.lock`, `whoami`, `graph.snapshot`, `entry.list`,
`entry.reveal`), and forty-five generated from one `bridge_ops!` table — thirty-four by ADR-062,
five more for ADR-071…073, `maintenance.rotate_root` for ADR-076, and `entry.get` and the four
`field.*` operations for ADR-078 — with a typed TypeScript client
(`apps/desktop/src/lib/bridge.ts`) held to the same table. `generate_handler!` registers **56**
commands in all: those 53 plus the shell's own three that are not broker ops (`entry_copy`,
`copy_text`, `fields_preview`, §6.2).

Three properties of that bridge are worth stating because they are what make a pass-through
safe:

- **It does not reshape responses.** The broker is the single enforcement point and
  `10_API_AND_MCP.md §1` is the contract; a bridge that "helpfully" normalised responses would
  become a second, undocumented API that drifts from the first. `two_factor_required` therefore
  reaches the UI as the broker's own error code, not as a friendlier success state.
- **The session token never crosses into the webview.** It is captured Rust-side on unlock,
  attached to subsequent calls, and stripped from anything returned — asserted by
  `bridge_wire.rs::{the_session_token_is_captured_attached_and_never_returned, no_command_result_ever_serialises_a_token_shaped_string}`,
  and a token that arrives unexpectedly on a read response is not adopted as a session.
- **Cross-workspace constants are guarded, not trusted.** Because ADR-035 puts the shell in its
  own workspace, the broker's error vocabulary and the socket-path rule are hand-copied.
  `drift_guards.rs` reads the real files off disk and compares —
  `the_bridges_error_vocabulary_matches_the_brokers_exactly` and
  `the_bridge_covers_every_op_the_broker_dispatches_and_nothing_else`. That is the shape of a guard
  that is actually true, as opposed to the phantom test `I-26` three documents in this corpus
  cited for months.

These tests live in the desktop workspace and are therefore **not** part of the count
`cargo test --workspace` reports; they run under the shell's own manifest — 65 passing on
2026-09-24, 156 listed in 10 test binaries on 2026-10-02 and 186 listed in 12 test executables on 2026-10-03
(`cargo test -- --list` from `apps/desktop/src-tauri`), and in CI as `security.yml` → `v2-desktop-bridge` (ADR-062).

### 6.2 The shell's own commands — **partly built**

Beyond the broker bridge the shell does what the webview cannot do for itself:

- **`entry_copy`, `copy_text` and `fields_preview` — `built` and wired to the app** (the three commands registered beside the 53 broker ops, §6.1).
  `fields_preview` (ADR-078) parses and types a bulk paste locally with `credmgr-core`'s own parser and
  inference, makes no broker call and writes no audit record, so the preview a screen shows is the
  document that is stored (`08_FIELD_MODEL.md §5`). `copy_text` puts a non-secret string (a donation
  address, a node id) on the clipboard, at most 4096 bytes, with no concealment and no timer.
  `entry_copy` is the concealed clipboard: the shell reveals the entry itself (the value never reaches the webview) and writes it with the
  `org.nspasteboard.ConcealedType` and `TransientType` markers and `NSPasteboardContentsCurrentHostOnly`
  (so it stays out of Universal Clipboard and Handoff), cleared 30 seconds later **only if the
  clipboard is still ours**, and cleared at once on a lock (the Lock button, sleep, screen lock,
  session switch) and on quit under the same test. A copy whose reveal is still in flight when a lock
  lands is refused rather than written afterwards. Never cleared on focus loss. A refusal carries no
  value. For an entry with several fields the caller names the field to copy (the reveal is narrowed to
  it); without one the shell answers `field_required` and copies nothing. **Wired:** the app's Copy
  buttons go through `entry_copy` (`src/vault/actions/read.ts`, `copyEntry`), and
  `tests/unit/architecture.test.ts` fails if `navigator.clipboard` (or `execCommand('copy')`, or a
  `clipboardData` write) appears anywhere in `src/`, so the concealment, the this-Mac-only flag and the
  clear on lock apply to every secret the app puts on the pasteboard. With no shell (the demo vault of
  the headless gates) there is nothing to copy with and the action reports that.
- **Lock on sleep — `built`** (`src/autolock.rs`). On the Mac going to sleep, the displays sleeping, a
  session switch, or the screen locking, the shell sends `vault.lock` **whether or not this app holds
  a login** (the vault is the broker's, and the broker accepts a tokenless lock), clears the clipboard
  inside the OS notification block, and tells the window with `credmgr://locked`. A screensaver that
  does not require a password does not lock the vault.
- **`credmgr://window-inactive`** on focus loss, so the window can hide revealed values.

`10_API_AND_MCP.md §5` specifies the allowlist. Still **planned**: `presence_verify(reason)` returning
a `PresenceProof`; `keystore_status()` for an honest Security panel; `notify_approval(request)` for
approval-on-demand; the LLM detect/connect pair; theme get/set; and `app_integrity()`. The earlier
design's `open_external(url)` is **withdrawn**, not planned: nothing in the app opens an external
URL, `tauri-plugin-opener` was removed, and a test fails if it returns. Explicitly **not** exposed,
then or ever: filesystem, shell, HTTP, process spawn, arbitrary path read or write — Tauri's `fs`,
`shell`, `http` and `opener` plugins are not compiled in.

### 6.3 Platform keystores and presence — **partial**, and narrower than this corpus says elsewhere

`crates/keystore` ships the `PlatformKeystore` trait, the `Capabilities`/`Tier` vocabulary, and
**one** implementation: `SoftwareKeystore`, Argon2id over an operator passphrase with
ChaCha20-Poly1305 sealing, plus an HMAC-sealed counter file. That is `16_CROSS_PLATFORM.md §4.4`'s
universal escrow wrap, and ADR-041 scoped it deliberately as the only tier to build first.

**No hardware backend exists.** `KeystoreId` names `MacosSecureEnclave`, `WindowsHello`,
`WindowsDpapi`, `LinuxTpm` and `LinuxSecretService`, and all five are enum variants with no
implementation behind them — grepping `crates/` for Secure Enclave, `LAContext` or any
platform crypto API returns the enum variant and nothing else. Any statement in this corpus that
"the macOS keystore path is built" is wrong; the macOS *vault path* is built, the macOS
*keystore* is not.

`SoftwareKeystore::verify_presence` returns `PresenceUnavailable` rather than succeeding, and
that is the correct behaviour rather than a gap: a caller that skips the capability check and
relies on presence for an orphan reveal or a grant must get a hard error, never a free pass.
The consequence runs all the way up — `maintenance.doctor --rebuild-registry`, `node.reparent`
and `audit.get`'s full-record path are wired end to end and then refused unconditionally with
`presence_required`, because no surface in this build can attest presence. When a real
implementation lands, those dispatch arms do not change; only the hardcoded refusal is removed.

**The target design, in full.** Each platform will get one implementation behind the same trait,
and the UI will state the resulting tier in plain words rather than showing a lock icon that
implies more than is true:

- **macOS — `Tier::Hardware`.** A P-256 key generated in the Secure Enclave with
  `biometryCurrentSet | privateKeyUsage`, non-exportable, wrapping the vault root key; presence
  via `LocalAuthentication`; counters as a Keychain generic password. Enrolling a new fingerprint
  will invalidate the key — which is the desired behaviour, and precisely why the passphrase
  escrow wrap is mandatory on every platform.
- **Windows — `Tier::Hardware` (Hello) or `OsProtected` (DPAPI).** Windows Hello via
  `KeyCredentialManager` preferred, with CNG against the Platform Crypto Provider and DPAPI for
  counters as the fallback.
- **Linux — `Tier::Hardware` (TPM 2.0) / `OsProtected` (Secret Service) / `Software`,** probed in
  that order, with the result reported rather than assumed. An optional FIDO2 token will supply
  real presence via touch, since no biometric standard exists to rely on.
- **Every platform — `Tier::Software`, which already exists,** stays present unconditionally as
  the escrow wrap, because a vault whose only key lives in hardware is one failed motherboard
  away from gone.

### 6.4 Release self-integrity — **planned**

`21_RELEASE_AND_INTEGRITY.md §3` specifies that at every start, before the vault is touched, the
app will read its embedded build stamp, verify its own code signature through the OS, hash the
shipped resource set against a manifest signed into the binary, and **refuse to unlock** on any
mismatch, naming exactly what differs. None of this exists, and one prerequisite is worth naming
because it is easy to assume away: **`crates/core` has X25519 and HMAC-SHA256 and no signature
primitive at all** — no Ed25519, no EdDSA. Release signing and update-manifest verification will
need a signing primitive this workspace does not currently contain, in addition to the code-
signing certificates recorded as open item O-3 and accepted risk K-4.

---

## 7. On-disk layout — **built**

**Evidence.** `crates/store/src/paths.rs` is the authority for every path below; each is a method
returning a `PathBuf` beneath a base directory, which is why every test constructs a whole vault
over a throwaway temporary directory rather than touching a real one.

```
<vault>/                               (0700)
├── config.json                        vault config, non-secret
├── registry.json                      NODE REGISTRY — unencrypted metadata (03 §2); `format: 2` and `sealed`
│                                      {id → seal record} since ADR-079
├── registry.sig                       HMAC over registry.json, keyed by a root-derived subkey
├── registry.json.prev, registry.sig.prev   the previous signed pair, kept to recover an
│                                      interrupted write (ADR-063)
├── keys/
│   ├── root.wrap.se                   root key wrapped by the platform keystore
│   ├── root.wrap.pass                 root key wrapped by Argon2id(passphrase)   ← escrow
│   ├── root.wrap.recovery             root key wrapped by the printed recovery code
│   ├── nodes/<nodeId>.key             node key, wrapped to the root key
│   └── cold/orphan.key                the orphan node's private half, sealed under a root-derived key; never hot,
│                                      never opened by unlock (CMCK v1, 98 bytes; ADR-079)
├── nodes/
│   └── <nodeId>/
│       ├── entries/<entryId>.env      one envelope per credential entry: version 1 = one raw value
│       │                              (alpha.6), version 2 = a field document (ADR-078)
│       ├── pending/<entryId>.env      created while locked; awaits review at unlock (F-1)
│       ├── pending/<entryId>.meta.json   its name/type/created — untrusted, rebuilt at unlock (ADR-069)
│       ├── notes.env                  the node's note (encrypted; notes.write, ADR-072)
│       └── manifest.json              entry ids, checksums, counts (unencrypted, HMAC'd)
├── rotation-pending/                  TRANSIENT: the stage + COMMIT record of a root-key rotation
│                                      (exists only during one or after a crash; ADR-076)
├── totp/<nodeId>/<itemId>.env         RESERVED, unused — no reader/writer anywhere in
│                                      crates/; a stored TOTP seed is an ordinary entry instead
├── audit/YYYY-MM.log                  append-only, hash-chained
├── backups/credmgr-backup-<epoch>.enc maintenance.backup output (ADR-054)
├── archive/
│   ├── <sealedId>/                    7-day whole-node seal archive: node/, node.key, meta.json — bound by
│   │                                  the signed `registry.sealed[<sealedId>]` record (ADR-079)
│   ├── removed-entries/<node>/<id>/   7-day single-entry soft delete (ADR-048)
│   └── entry-history/<node>/<id>/     retained pre-rotation ciphertext + signed
│                                      field snapshot per generation (ADR-048, ADR-055)
└── run/
    ├── broker.sock                    (0600)
    └── rotation.lock                  empty advisory-lock file (0600): held across a rotation and
                                       every recovery of one (ADR-076)
```

One thing lives deliberately **outside** this tree: the external `vaultGeneration` counter, in a
per-user state directory (`CREDMGR_STATE_DIR`, else the per-OS state location). An HMAC on
`registry.json` proves *who* wrote it and never *when*, so a validly-signed but rolled-back
registry has to be caught by something the roll-back cannot also restore. ADR-024 and ADR-039;
test `isolation.rs::i20_rolled_back_registry_is_refused_on_the_generation_check`.

**Not every path above has code behind it yet.** `paths.rs` declares the whole tree, and two
leaves currently have no reader or writer anywhere in `crates/`: `config.json` (its path is
declared in `paths.rs` and referenced nowhere else — `credmgr init` creates a vault without one,
§2.1) and `totp/<nodeId>/<itemId>.env` — `totp_item(` occurs exactly
once in the whole workspace, its own definition in `paths.rs`, because a stored TOTP seed is an
ordinary entry instead, read through the same envelope machinery as any other credential by
`ops.rs`'s `totp.code` and `totp.seed` arms. One more is written only by a backup test fixture,
never by product code: `keys/root.wrap.se`, because no platform keystore exists to produce a real
one (§6.3). `keys/cold/orphan.key` was the third until 2026-10-03: `credmgr init` writes it with the orphan
node, an older vault gets it with its first `node.seal`, and the backup includes it (ADR-079).
`nodes/<nodeId>/notes.env` was the fifth until 2026-09-24; `notes.write` writes it
since ADR-072 (`03_DATA_MODEL.md §4`), and `store::backup::select_files` still deliberately leaves
it out of what it collects. The tree is the contract; those three files are the part of it the
code has not reached.

**Why files, not SQLite.** A credential vault must survive its own software. Any of these files
can be decrypted by a short standalone script with no CredMgr binary present:
`scripts/emergency-decrypt.mjs` recovers a value from the printed recovery code alone, and
`crates/cli/tests/emergency_decrypt.rs` builds a real fixture vault with the Rust crypto and
then shells out to that script, so the two implementations cannot silently disagree about the
wrap and envelope formats. A database, by contrast, is one opaque blob whose recovery path is
"hope the schema is documented". Files also make the atomic-write story simple
(`write temp → fsync → rename`, `crates/store/src/atomic.rs`) and let manifest counts be read
while the vault is locked, which the graph screen requires.

**One envelope per entry, not one vault blob.** V1's single `vault.age` means every write
rewrites everything and every read decrypts everything. Per-entry envelopes give constant-time
single-entry reads, per-node key separation, and a corruption blast radius of one credential.

**Two different seven-day windows, and one twelve-month one.** `archive/<sealedId>/`
retains a sealed node's original envelopes *and* its private key for 7 days, so "restore node" is
a move rather than a re-encryption of everything (F-4, ADR-027); `archive/removed-entries/` does
the same for a single removed entry (ADR-048). **Neither is covered by `verify` or included in a
backup.** `maintenance.verify` reads only the registry and each reachable node's manifest and
entry envelopes — since ADR-067 hashing each envelope against its manifest digest — and, apart from
checking each seal record against its archived node key and manifest (ADR-079), never walks
`archive/`, and `store::backup::select_files`'s own module
doc names "archived (sealed-but-not-yet-purged) node contents" among what it deliberately
excludes. **The day-7 line is half-built.** `archive::purge_if_expired` and its
`entry_archive::purge_if_expired` counterpart correctly destroy the retained ciphertexts and the
retained node key when called and are covered by their own tests, and `node.restore` correctly
refuses past the window — but nothing outside those tests ever calls either purge function, so a
sealed node's private key can sit on disk past its stated seven-day lifetime
(`04_CRYPTO_AND_KEYS.md §5.1`). What
`isolation.rs::i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone` actually proves
is the refusal half, not the destruction half: a day-8 restore returns `OpError::ArchiveExpired`
rather than quietly succeeding, and its own comment says restore "must refuse rather than
quietly succeed" — it asserts nothing about anything being deleted. The audit log is a
**different** mechanism with a **different**, still-`planned` retention: it will be rotated
monthly and kept **12 months**, with purge gated to a human-only, 2FA-required command
(`03_DATA_MODEL.md §9`). Conflating the two is easy and this corpus has done it before.

### 7a. Fail-closed needs a door — **partial**

A registry that fails its HMAC or its generation check means the broker **refuses to open the
vault**. That is correct, and on its own it leaves the operator with no way back: a corrupted or
rolled-back registry would mean a vault that never opens again.

`maintenance.doctor --rebuild-registry` is the door, and it is honestly half-built:

1. **Built.** The reconstruction itself — rebuilding a candidate registry from the per-node
   manifests plus the most recent signed backup, diffing it against what is on disk, and applying
   it with the generation advanced past every generation the rebuild has seen — is real and
   independently tested in `crates/store/src/rebuild.rs` and `crates/brokerd/src/maintenance.rs`.
   The diff is the point: a rebuild that would resurrect a revoked grant says so in words before
   writing anything.
2. **Built.** The CLI flag exists and reaches the broker, and the broker checks that the caller
   holds `Capability::Admin` resolved against Global, and requires the passphrase in the request.
3. **Refused.** The dispatch arm then returns `presence_required` unconditionally, because
   §6.3's presence attestation does not exist on any surface in this build. The rebuild logic is
   therefore reachable only from its own tests today.
4. **Planned.** Gate 2FA in addition to presence, and a rebuild record appended to the audit log.

Fail-closed with a documented, gated, diff-first recovery path — with the door's last bolt not
yet fitted, and said so.

---

## 8. Dependencies — **built**

**Runtime, per crate, exactly as the manifests declare them.** No transitive list; these are the
direct dependencies that constitute a decision.

| Crate | Direct third-party runtime dependencies |
|---|---|
| `credmgr-core` | `chacha20poly1305`, `x25519-dalek`, `hkdf`, `hmac`, `sha2`, `base32`, `totp-rs`, `rand_core`, `secrecy`, `zeroize`(+`zeroize_derive`), `serde` |
| `credmgr-store` | `serde`, `serde_json`, `sha2`, and `libc` on Unix for file-mode assertions |
| `credmgr-keystore` | `argon2`(+pinned `base64ct`), `chacha20poly1305`, `rand_core`, `secrecy`, `serde`, `serde_json`, `zeroize` |
| `credmgr-brokerd` | `interprocess` (declared for the future Windows pipe, currently unused), `x25519-dalek`, `sha2`, `rand_core`, `secrecy`, `serde`, `serde_json`, `zeroize`, and `libc` on Unix |
| `credmgr-cli` | `serde_json` |
| `credmgr-mcp` | `serde_json` |

Pass 1's "zero runtime dependencies" target came from a Node core where the standard library
already carried the primitives. In Rust it would have meant hand-rolling AEAD and X25519, which
is strictly worse than depending on the audited RustCrypto and dalek crates. The rule that
replaced it is narrower and enforceable: **every runtime dependency needs a reason recorded next
to its version**, and `crates/core/Cargo.toml` is where that convention is visible — several
crates are pinned below their latest majors, each with the MSRV wall that forced the pin written
out beside it (ADR-036, ADR-038).

**Vendored, never fetched at runtime:** `design/graph-engine/force-graph.min.js`, recorded in
`design/PROVENANCE.md` with its byte count and a sha384 verified against upstream. It is the
**only** vendored asset today — no font file exists anywhere under `design/`, so the
local-`@font-face` decision in §5.2 is still a decision rather than a fact, and the fonts must
join the same provenance table when they land. **Supply chain:** `deny.toml` configures `cargo deny`
across all four target triples with an explicit license allowlist, so a new dependency carrying
an unexpected license fails CI rather than being noticed in an audit six months later; it runs in
`.github/workflows/security.yml`. **External tools:** `age` is optional, off the hot path, and
exists only so an exported archive is readable without CredMgr.

---

## 9. Repository layout and the crate graph — **built**

```
<repo>/v2/
├── CLAUDE.md                agent rules + Project Surface
├── docs/                    this corpus
├── design/                  KEEP design system (tokens, template, graph engine spec)
├── crates/                  the MSRV-1.78 workspace
│   ├── core/                crypto, envelopes, registry types, access graph, parser — pure, no I/O
│   ├── store/               on-disk layout, atomic writes, manifests, audit log, archives
│   ├── keystore/            PlatformKeystore trait + the software implementation
│   ├── brokerd/             the daemon: socket, peer identification, sessions, scope, 2FA, audit
│   ├── cli/                 `credmgr`
│   └── mcp/                 MCP stdio server, hosted by the CLI binary
├── apps/desktop/            Tauri 2 shell + the precompiled KEEP design (ADR-075) — its own Cargo workspace (ADR-035)
├── tests/                   EMPTY — every integration test lives in its own crate's tests/
└── scripts/                 the two commit guards, emergency-decrypt.mjs, the build runner
```

`tests/` is listed because it exists and is empty, not because it is pending: integration tests
turned out to belong beside the crate that owns the surface they drive (`crates/cli/tests/` holds
the ones that stand up a real broker), and a shared directory would only have hidden which crate
each test was actually about.

**The dependency graph, as the manifests actually declare it:**

```
                    ┌──────────┐
                    │   core   │   pure, I/O-free, no internal dependencies
                    └────┬─────┘
             ┌───────────┼───────────┐
             ▼           ▼           ▼
        ┌────────┐  ┌────────┐  ┌─────────┐
        │keystore│  │ store  │  │   mcp   │──► core, store
        └───┬────┘  └───┬────┘  └────┬────┘
            └─────┬─────┘            │
                  ▼                  │
             ┌─────────┐             │
             │ brokerd │◄────────────┘  (dev-dependency only)
             └─────────┘
                  ▲
                  │ (dev-dependency only)
             ┌─────────┐
             │   cli   │──► core, mcp, store
             └─────────┘
```

Runtime edges, exhaustively: `keystore → core`; `store → core`; `brokerd → {core, keystore,
store}`; `cli → {core, mcp, store}`; `mcp → {core, store}`. **`cli → brokerd` and `mcp → brokerd`
are dev-dependencies only** — the shipped clients do not link the broker, and cannot, because
each talks to it over the socket like any other peer. The integration tests do link it, on
purpose: that is how they stand up a real broker on a temporary socket and drive the actual wire.

**`crates/core` is deliberately pure and I/O-free**: it takes bytes and returns bytes, and takes
a graph and a request and returns allow or deny. That is what makes the access rules exhaustively
property-testable (`13_TEST_PLAN.md §3`), and it is why `mcp` can depend on `core` without
inheriting any capability to touch a file. `credmgr-mcp`'s transport is duplicated from
`credmgr-cli`'s rather than shared, because `cli` already depends on `mcp` (it hosts the
`credmgr mcp` subcommand) and the reverse edge would be circular.

`core` is the only crate with no internal dependencies and every other crate depends on it; and
the only edges from the client crates into `brokerd` are dev-dependencies — so no shipped client
can link the enforcement point even by accident. Parsed straight from the six manifests, not
redrawn from the ASCII graph above, so it cannot drift from the build the way this document's
prose once did — and it also surfaces two real dev-only edges (`cli`/`mcp` → `keystore`) the
prose above never mentioned:

<!-- figure:crate-dependency-graph -->

---

## 10. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `01_CONCEPT.md §2` | node-as-boundary — the model the single enforcement point in §1 exists to make enforceable |
| depends on | `04_CRYPTO_AND_KEYS.md §2` | the root-key hierarchy and the three root wraps that §7's `keys/` tree stores and §6.3's keystore tiers protect |
| depends on | `06_ACCESS_GRAPH.md §4` | subject-scope resolution — what §3's peer identification feeds into, and why cwd is advisory rather than authoritative |
| depends on | `10_API_AND_MCP.md §1` | the wire protocol §2.2's transport carries and §6.1's bridge passes through unreshaped |
| depends on | `16_CROSS_PLATFORM.md §3` | the `PlatformKeystore` trait and tier vocabulary §6.3 reports against |
| depends on | `16_CROSS_PLATFORM.md §6` | the per-OS vault, state and log locations §2.2 resolves |
| feeds | `03_DATA_MODEL.md §8` | the manifest and generation counter §2.3's conflict detection is written against |
| feeds | `13_TEST_PLAN.md §4` | the isolation suite's subject — the broker, its peer gate, and its per-node write lock |
| feeds | `10_API_AND_MCP.md §5` | the Tauri IPC allowlist §6.1 partially implements and §6.2 completes |
| feeds | `05_THREAT_MODEL.md §7` | AR-2 (broker memory holds unlocked node keys — and, on a live vault, the root key, ADR-063) and AR-5 (cwd is spoofable), both bounded by mechanisms specified here |
| feeds | `21_RELEASE_AND_INTEGRITY.md §3` | the self-integrity check §6.4 defers, including the signing primitive `crates/core` does not yet have |
| feeds | `19_FRONTEND_DELIVERY_SCOPE.md §3` | what a delivered screen can actually call today: all 53 bridged operations (ADR-062, ADR-078) |

## 11. Source

**Design.** `ADR-001` (a broker process is the single enforcement point) · `ADR-008` superseded
and `ADR-009` adopted by `16_CROSS_PLATFORM.md §2` (Rust) · `ADR-019` (no HTTP surface) ·
`ADR-024`/`ADR-039` (freshness enforced outside the vault directory; store-owned counter) ·
`ADR-025` (no listening socket) · `ADR-027`/`ADR-048`/`ADR-055` (the archive and history trees) ·
`ADR-030`/`ADR-043` (auto-lock thresholds; idle built, external signals unwired) · `ADR-035`
(the desktop shell is a separate Cargo workspace) · `ADR-036`/`ADR-038` (MSRV-forced version
pins) · `ADR-041` (software keystore tier only) · `ADR-054` (`maintenance.*`) · `ADR-056`
(session tokens, revoked on lock) · `ADR-057` (the Tauri↔broker bridge; the session token is
held in Rust and never crosses into the webview) · `ADR-061` (two-phase vault bootstrap;
`credmgrd` serves the socket for real; until ADR-063 a live daemon's `vault.unlock` ignored its
passphrase parameter) · `ADR-062` (every op bridged; the CSP) · `ADR-063` (the live unlock,
load-from-disk and write-through; the root key resident while unlocked) · `ADR-065` (a login's
reach, and its own idle revocation) · `ADR-072` (`notes.env`'s writer, §7).

**Code.** `crates/brokerd/src/server.rs` (bind, `0600` chmod, peer gate, dispatch, auto-lock
ticker) · `crates/brokerd/src/peer.rs` (`LOCAL_PEERCRED`/`LOCAL_PEERPID`/`PROC_PIDVNODEPATHINFO`,
and the Linux `SO_PEERCRED` path) · `crates/brokerd/src/state.rs` (hot key set, `lock`,
`node_write_lock`, `tick_autolock`, `external_lock_signal`; `begin_init`/`confirm_init` for
§2.1) · `crates/brokerd/src/state/durable.rs` (§2.1's live unlock, load and write-through) ·
`crates/brokerd/src/ops.rs` (53 dispatched ops, including the `vault.init_begin` and
`vault.init_confirm` pair; `PERSISTED_OPS`; the `maintenance.doctor` arm for §7a) ·
`crates/brokerd/src/entry_doc.rs` (ADR-078) · `crates/brokerd/src/state/seal.rs` (ADR-079) ·
`crates/brokerd/src/main.rs` (vault-path resolution, `run/` creation, `server::run`, and the
placeholder keystore a passphrase-less unlock meets) ·
`crates/brokerd/packaging/com.credmgr.brokerd.plist` and `v2/packaging/com.credmgr.brokerd.plist`
(the launchd unit, installed by hand per `RELEASE.md`) ·
`crates/store/src/paths.rs` (§7's entire tree and §2.2's resolution order) ·
`crates/store/src/atomic.rs` (`0700` directories, `write temp → fsync → rename`) ·
`crates/store/src/rebuild.rs` (§7a's diff/apply) · `crates/keystore/src/{lib,software}.rs` (the
trait, the one implementation, and `PresenceUnavailable`) · `crates/cli/src/main.rs` (24
top-level subcommands; `cmd_init`, and `cmd_unlock`), `crates/cli/src/fields.rs` and
`crates/cli/src/transport.rs` · `crates/mcp/src/tools.rs` (15 tools) ·
`apps/desktop/src-tauri/src/{lib,commands}.rs` (the 56-command allowlist: 53 broker ops and three shell commands) ·
`apps/desktop/src-tauri/tauri.conf.json` (the CSP) · the six
`crates/*/Cargo.toml` manifests (§8, §9) · `v2/Cargo.toml` and `v2/rust-toolchain.toml` (the
MSRV pin) · `v2/deny.toml`.

**Tests.** `crates/brokerd/tests/isolation.rs` — I-1…I-25 with **I-10 implemented nowhere**
(accepted risk K-1), and I-27…I-29 (ADR-078; there is no I-26); specifically `i25_concurrent_writers_same_starting_generation_exactly_one_wins`
(§2.3), `i12_token_workdir_mismatch_proceeds_and_writes_an_anomaly_to_the_audit_log` (§3),
`i20_rolled_back_registry_is_refused_on_the_generation_check` (§7),
`i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone` (§7) ·
`crates/brokerd/tests/phase3_exit_gate.rs` (§2.4's four auto-lock tests) ·
`crates/brokerd/src/server.rs`'s own `peer_uid_gate_rejects_any_non_owning_uid` (§3) ·
`crates/cli/tests/broker_integration.rs`, `success_criteria.rs`, `mcp_integration.rs`,
`vault_init.rs` (the fixtures that stand up their own `server::run`; since ADR-061
`crates/brokerd/src/main.rs` calls it too) · `crates/cli/tests/emergency_decrypt.rs` (§7's
survivability claim) ·
`crates/mcp/tests/i13_tool_registry.rs` · `crates/brokerd/tests/durable_vault.rs` (§2.1's live
unlock, restart and reload, and write-through) · and, in the desktop workspace and therefore
outside the workspace count, `apps/desktop/src-tauri/tests/bridge_wire.rs`, `bridge_ops.rs` and
`drift_guards.rs` (§6.1) and `shell_config.rs` (§5.3's CSP). `cargo test --workspace -- --list`: 813 tests in 50 test binaries (2026-10-03; the last full pass/fail run recorded: 571 passing, 0 failing, 41 test binaries on 2026-10-02; earlier: 448 passing, 37 test binaries on 2026-09-24, re-measured 2026-10-01; 406 passing, 35 test binaries as of 2026-09-13, run `34743281942`; 397 passing, 33 test binaries, verified 2026-08-18).

**Verification.** `python3 -m tools.corpus_check crossrefs` proves every `NN_NAME.md §S`
reference in §10 resolves; `stamps` proves this document's stamp still matches its body.
The counts quoted here — 38 ops, 11 MCP tools, 19 CLI subcommands, I-1…I-25 — were re-derived
from source in this pass, not carried forward (re-measured against live source 2026-09-13: 40
ops, 11 MCP tools, 20 CLI subcommands — ADR-061 added `vault.init_begin`, `vault.init_confirm`
and `init` on 2026-08-31; re-measured 2026-09-24: 42 ops — ADR-064 and ADR-066 added
`vault.gate_recover` and `node.set_workdirs`; re-measured again 2026-09-24: 47 ops — ADR-071…073
added `node.update`, `node.policy`, `notes.read`, `notes.write` and `entry.create_batch`;
re-measured 2026-10-02: 48 ops, 23 CLI subcommands — ADR-076 added `maintenance.rotate_root`;
re-measured 2026-10-03: 53 ops, 24 CLI subcommands, 15 MCP tools — ADR-078 added `entry.get`, the four
`field.*` operations, the `field` subcommand and four tools; the figures above are those earlier passes'
record, not a current count).

**Figures.** Both are `docgen` structural figures (`tools/ENGINE_ROUTING_POLICY.md`), specs at
`v2/docs/02_ARCHITECTURE_spec.json` (a two-entry array): `broker-trust-boundary`
(`kind: "system_map"`) re-derived from `crates/brokerd/src/state.rs` (`hot_keys`),
`crates/cli/src/transport.rs` and `crates/mcp/src/transport.rs` (socket + token handling),
`apps/desktop/src-tauri/src/{commands,session}.rs` (8 bridged commands when rendered — 42 since
ADR-062, 47 since ADR-071…073, 48 since ADR-076, 53 since ADR-078; the token never leaves Rust) and `apps/desktop/src/` (the scaffold's `routes/` is gone, ADR-075); `crate-dependency-graph`
(`kind: "dependency_graph"`) parsed from the `[dependencies]`/`[dev-dependencies]` blocks of all
six `crates/*/Cargo.toml` files, verified 2026-08-23.
